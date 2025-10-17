#REvised Location Updated as Per CycloneDX @ https://cyclonedx-python-library.readthedocs.io/en/stable/autoapi/cyclonedx/model/bom/
import json
import os
import sys

from decimal import Decimal

from cyclonedx.model.bom import Bom
from cyclonedx.builder.this import this_component as cdx_lib_component
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.vulnerability import (BomTarget, Vulnerability,
                                           VulnerabilityRating,
                                           VulnerabilityReference,
                                           VulnerabilitySeverity,
                                           VulnerabilityScoreSource,
                                           VulnerabilitySource,
                                           BomTargetVersionRange)
from cyclonedx.model.impact_analysis import ImpactAnalysisAffectedStatus
from cyclonedx.output.json import JsonV1Dot6
from cyclonedx.validation.json import JsonStrictValidator
from cyclonedx.schema import SchemaVersion
from cyclonedx.exception import MissingOptionalDependencyException
from packageurl import PackageURL

from .cvss_utils import CVSSExtractor


def _get_purl_type(ecosystem: str) -> str:
    """
    Map ecosystem name to PackageURL type.

    Args:
        ecosystem: Ecosystem name (e.g., "python", "npm", "java")

    Returns:
        PackageURL type string
    """
    ecosystem_to_purl = {
        "python": "pypi",
        "npm": "npm",
        "java": "maven",
        "maven": "maven",
        "go": "golang",
        "golang": "golang",
        "rust": "cargo",
        "cargo": "cargo",
        "ruby": "gem",
    }

    return ecosystem_to_purl.get(ecosystem.lower(), "generic")


SEVERITY_MAP = {
    "critical": VulnerabilitySeverity.CRITICAL,
    "high": VulnerabilitySeverity.HIGH,
    "medium": VulnerabilitySeverity.MEDIUM,
    "low": VulnerabilitySeverity.LOW,
    "unknown": VulnerabilitySeverity.UNKNOWN,
    None: VulnerabilitySeverity.UNKNOWN,
}



def generate(transitive_analysis: dict, config: dict, ecosystem_mapping: dict = None):
    """Generate SBOM from ecosystem-aware transitive analysis data.

    Args:
        transitive_analysis: Transitive analysis results with nested ecosystem data
        config: Configuration dictionary
        ecosystem_mapping: Legacy parameter (deprecated, maintained for compatibility)
    """
    bom = Bom()
    bom.metadata.tools.components.add(cdx_lib_component())
    component_map = {}

    # Extract ecosystem data from transitive analysis
    ecosystems_data = transitive_analysis.get("resolution_details", {})

    if not ecosystems_data:
        print("⚠️ No ecosystem data found in transitive analysis")
        return

    # Add components to BOM for each ecosystem
    for ecosystem, packages in ecosystems_data.items():
        if not isinstance(packages, dict) or not packages:
            continue

        print(f"📦 Adding {len(packages)} {ecosystem} packages to SBOM")

        # Get the correct PURL type for this ecosystem
        purl_type = _get_purl_type(ecosystem)

        for dep, ver in packages.items():
            component = Component(
                name=dep,
                version=ver,
                type=ComponentType.LIBRARY,
                purl=PackageURL(type=purl_type, name=dep, version=ver)
            )
            bom.components.add(component)
            # Key includes ecosystem for uniqueness across ecosystems
            component_map[f"{ecosystem}:{dep.lower()}=={ver}"] = component

    # Add vulnerabilities to BOM using enhanced_data
    enhanced_data = transitive_analysis.get("enhanced_data", {})
    if enhanced_data:
        print("🔍 Processing vulnerabilities from enhanced data")
        process_cve_data(enhanced_data, component_map, bom)
    else:
        print("⚠️ No enhanced data found for vulnerability processing")

    # Export SBOM as JSON
    sbom = JsonV1Dot6(bom=bom)
    validate_json_format(sbom)
    output_path = os.path.abspath(config["output"]["sbom_file"])
    with open(output_path, "w") as f:
        f.write(sbom.output_as_string())

    print(f"SBOM report exported to: {output_path}")


# Backwards compatibility
generate_sbom = generate

def validate_json_format(sbom):
    serialized_json = sbom.output_as_string(indent=2)
    my_json_validator = JsonStrictValidator(SchemaVersion.V1_6)
    try:
        json_validation_errors = my_json_validator.validate_str(serialized_json)
        if json_validation_errors:
            print('JSON invalid', 'ValidationError:', repr(json_validation_errors), sep='\n', file=sys.stderr)
            sys.exit(2)
    except MissingOptionalDependencyException as error:
        print('JSON-validation was skipped due to', error)


def _create_vulnerability_rating(severity: VulnerabilitySeverity, score: float, cvss_vector: list) -> VulnerabilityRating:
    """Create VulnerabilityRating with CVSS vector support.

    Args:
        severity: VulnerabilitySeverity enum value
        score: CVSS base score
        cvss_vector: List of severity objects with 'type' and 'score' fields
                    Example: [{"type": "CVSS_V3", "score": "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H"}]

    Returns:
        VulnerabilityRating: Configured rating object
    """
    rating_kwargs = {
        "severity": severity,
        "source": VulnerabilitySource(name="OSV.dev")
    }

    if score:
        rating_kwargs["score"] = Decimal(score)

    # Use unified CVSS extractor to get best vector
    vector_data = CVSSExtractor.extract_best_cvss_vector(cvss_vector)

    if vector_data:
        vector_string, cvss_type = vector_data

        # Map CVSS type to CycloneDX VulnerabilityScoreSource
        cvss_type_to_method = {
            "CVSS_V4": VulnerabilityScoreSource.CVSS_V4,
            "CVSS_V3": VulnerabilityScoreSource.CVSS_V3_1 if vector_string.startswith("CVSS:3.1") else VulnerabilityScoreSource.CVSS_V3,
            "CVSS_V2": VulnerabilityScoreSource.CVSS_V2,
        }

        method = cvss_type_to_method.get(cvss_type)
        if method:
            rating_kwargs["vector"] = vector_string
            rating_kwargs["method"] = method

    return VulnerabilityRating(**rating_kwargs)


def _create_version_ranges(installed_version: str, fix_versions: list[str] | None) -> list:
    """Create version ranges with multiple fix versions support.

    Args:
        installed_version: Currently installed version
        fix_versions: List of fix versions if available (e.g. ["2.5.4", "3.0.4", "4.0.4"])

    Returns:
        list: List of BomTargetVersionRange objects with affected and unaffected ranges
    """
    # Create affected version range
    version_ranges = [
        BomTargetVersionRange(version=installed_version, status=ImpactAnalysisAffectedStatus.AFFECTED)
    ]

    # Add unaffected ranges for fix versions
    if fix_versions:
        version_ranges.extend([
            BomTargetVersionRange(version=f">={fix_version}", status=ImpactAnalysisAffectedStatus.UNAFFECTED)
            for fix_version in fix_versions
        ])

    return version_ranges


def _add_alias_references(vulnerability: Vulnerability, aliases: list) -> None:
    """Add aliases as additional references for cross-referencing.

    Args:
        vulnerability: Vulnerability object to add references to
        aliases: List of vulnerability aliases (CVE, GHSA, etc.)
    """
    for alias in aliases:
        if alias.startswith("CVE-"):
            vulnerability.references.add(VulnerabilityReference(
                source=VulnerabilitySource(name="nvd", url=f"https://nvd.nist.gov/vuln/detail/{alias}"),
                id=alias
            ))
        elif alias.startswith("GHSA-"):
            vulnerability.references.add(VulnerabilityReference(
                source=VulnerabilitySource(name="github", url=f"https://github.com/advisories/{alias}"),
                id=alias
            ))


def process_cve_data(enhanced_data: dict, component_map: dict, bom: Bom):
    """Process vulnerability data from enhanced_data structure and add to SBOM."""
    all_vulnerabilities = []

    for ecosystem, packages in enhanced_data.items():
        if not isinstance(packages, dict):
            continue

        for package_key, package_data in packages.items():
            if not isinstance(package_data, dict):
                continue

            # Extract package name and version from key
            if "==" in package_key:
                package_name, version = package_key.split("==", 1)
            else:
                package_name = package_key
                version = package_data.get("version", "unknown")

            # Get vulnerability data from enhanced structure
            vulnerability_data = package_data.get("vulnerability", {})
            vulnerabilities = vulnerability_data.get("vulnerabilities", [])

            # Process each vulnerability
            for vuln in vulnerabilities:
                vuln_copy = vuln.copy()
                vuln_copy["package_name"] = package_name
                vuln_copy["installed_version"] = version
                vuln_copy["ecosystem"] = ecosystem
                all_vulnerabilities.append(vuln_copy)

    # Process each vulnerability for SBOM generation
    for vuln in all_vulnerabilities:
        package_name = vuln.get("package_name")
        installed_version = vuln.get("installed_version")
        ecosystem = vuln.get("ecosystem", "python")

        if not package_name or not installed_version:
            continue

        # Use ecosystem-aware key format
        key = f"{ecosystem}:{package_name.lower()}=={installed_version}"
        component = component_map.get(key)
        if not component:
            continue  # Skip if not matched to any component

        vuln_id = vuln.get("vuln_id", vuln.get("id"))
        if not vuln_id:
            continue

        # Extract and normalize severity using unified utilities
        severity_raw = vuln.get("severity", "UNKNOWN")
        severity_normalized = CVSSExtractor.normalize_severity(severity_raw)
        severity = SEVERITY_MAP.get(severity_normalized.lower(), VulnerabilitySeverity.UNKNOWN)


        # Extract other fields from enhanced structure
        cwe_ids = vuln.get("cwe_ids", [])
        summary = vuln.get("summary", "")
        references = vuln.get("references", [])
        aliases = vuln.get("aliases", [])
        cvss_vector = vuln.get("cvss_vector", [])
        score = vuln.get("cvss_score", 0.0)

        # Extract fix versions from vulnerability data
        fixed = vuln.get("fixed", [])

        # Construct Vulnerability object
        v = Vulnerability(
            id=vuln_id,
            bom_ref=component.bom_ref
        )
        
        v.source = VulnerabilitySource(name="OSV.dev", url=f"https://osv.dev/vulnerability/{vuln_id}")
        v.description = summary

        # Enhanced rating with CVSS vector support
        rating = _create_vulnerability_rating(severity, score, cvss_vector)
        v.ratings.add(rating)

        # Convert CWE IDs to CWE objects
        v.cwes = parse_cwes(cwe_ids)

        # Add references from vulnerability data
        for ref in references:
            ref_url = ref.get("url", "")
            ref_type = ref.get("type", "WEB").lower()
            if ref_url:
                v.references.add(VulnerabilityReference(
                    source=VulnerabilitySource(name=ref_type, url=ref_url),
                    id=ref_url
                ))

        # Enhanced version range handling with fix version support
        version_ranges = _create_version_ranges(installed_version, fixed)
        v.affects.add(BomTarget(
            ref=component.bom_ref,
            versions=version_ranges
        ))

        # Add aliases as additional references for cross-referencing
        _add_alias_references(v, aliases)

        bom.vulnerabilities.add(v)

def parse_cwes(cwe_list):
    cwe_ints = set()
    for cwe_str in cwe_list:
        if isinstance(cwe_str, str) and cwe_str.startswith("CWE-"):
            try:
                cwe_id = int(cwe_str.split("-")[1])
                cwe_ints.add(cwe_id)
            except ValueError:
                # handle or skip invalid formats
                pass
    return cwe_ints

def read_json_file(file_path: str):
    """
    Reads a JSON file and returns the data as a Python dictionary.
    """
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            return data
    except FileNotFoundError:
        print(f"❌ Error: Validation report file not found at {file_path}")
    except json.JSONDecodeError:
        print(f"❌ Error: Invalid JSON format in {file_path}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
    return None
