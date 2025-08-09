#REvised Location Updated as Per CycloneDX @ https://cyclonedx-python-library.readthedocs.io/en/stable/autoapi/cyclonedx/model/bom/ 
import json
import os
import sys

from cyclonedx.model.bom import Bom
from cyclonedx.builder.this import this_component as cdx_lib_component
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.vulnerability import (BomTarget, Vulnerability,
                                           VulnerabilityRating,
                                           VulnerabilityReference,
                                           VulnerabilitySeverity,
                                           VulnerabilityScoreSource,
                                           VulnerabilitySource,
                                           BomTargetVersionRange,
                                           ImpactAnalysisAffectedStatus)
from cyclonedx.output.json import JsonV1Dot6
from cyclonedx.validation.json import JsonStrictValidator
from cyclonedx.schema import SchemaVersion
from cyclonedx.exception import MissingOptionalDependencyException
from packageurl import PackageURL

SEVERITY_MAP = {
    "critical": VulnerabilitySeverity.CRITICAL,
    "high": VulnerabilitySeverity.HIGH,
    "medium": VulnerabilitySeverity.MEDIUM,
    "low": VulnerabilitySeverity.LOW,
    "unknown": VulnerabilitySeverity.UNKNOWN,
    None: VulnerabilitySeverity.UNKNOWN,
}



def generate(dependencies: dict, cve_data: dict, config: dict):
    bom = Bom()
    bom.metadata.tools.components.add(cdx_lib_component())
    component_map = {}

    # Add components to BOM
    for dep, ver in dependencies.items():
        component = Component(
            name=dep,
            version=ver,
            type=ComponentType.LIBRARY,
            purl=PackageURL(type="pypi", name=dep, version=ver)
        )
        bom.components.add(component)
        component_map[f"{dep.lower()}=={ver}"] = component

    # Add vulnerabilities to BOM
    process_cve_data(cve_data, component_map, bom)

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


def process_cve_data(cve_data: dict, component_map: dict, bom: Bom):
    for vuln in cve_data.get("cve_issues", []):
        package_name = vuln.get("package_name")
        installed_version = vuln.get("installed_version")
        if not package_name or not installed_version:
            continue

        key = f"{package_name.lower()}=={installed_version}"
        component = component_map.get(key)
        if not component:
            continue  # Skip if not matched to any component

        vuln_id = vuln.get("vuln_id")
        if not vuln_id:
            continue

        # Enhanced severity and CVSS handling
        cvss_vector = vuln.get("cvss_vector", "")
        score = vuln.get("score")
        if score and cvss_vector:
            severity = VulnerabilitySeverity.get_from_cvss_scores(scores=(score,))
        else:
            severity = SEVERITY_MAP.get(vuln.get("severity", "").lower(), VulnerabilitySeverity.UNKNOWN)
        
        cwes = vuln.get("cwes") or []
        summary = vuln.get("summary", "")
        references = vuln.get("references", [])
        reference_types = vuln.get("reference_types", {})
        fix_version = vuln.get("fix_version", "")
        aliases = vuln.get("aliases", [])

        # Construct Vulnerability object
        v = Vulnerability(
            id=vuln_id,
            bom_ref=component.bom_ref
        )
        
        v.source = VulnerabilitySource(name="OSV.dev", url=f"https://osv.dev/vulnerability/{vuln_id}")
        v.description = summary

        # Enhanced rating with CVSS vector support
        rating_kwargs = {
            "severity": severity,
            "source": VulnerabilitySource(name="OSV.dev")
        }
        
        if score:
            rating_kwargs["score"] = score
        
        if cvss_vector:
            rating_kwargs["vector"] = cvss_vector
            # Determine CVSS method from vector
            if cvss_vector.startswith("CVSS:3.1"):
                rating_kwargs["method"] = VulnerabilityScoreSource.CVSS_V3_1
            elif cvss_vector.startswith("CVSS:3.0"):
                rating_kwargs["method"] = VulnerabilityScoreSource.CVSS_V3
            elif cvss_vector.startswith("CVSS:2.0"):
                rating_kwargs["method"] = VulnerabilityScoreSource.CVSS_V2

        v.ratings.add(VulnerabilityRating(**rating_kwargs))

        v.cwes = parse_cwes(cwes)

        # Enhanced reference handling with types
        for ref_url in references:
            ref_type = reference_types.get(ref_url, "WEB")
            v.references.add(VulnerabilityReference(
                source=VulnerabilitySource(name=ref_type.lower(), url=ref_url),
                id=ref_url
            ))

        # Enhanced version range handling with fix version support
        version_ranges = [
            BomTargetVersionRange(
                version=installed_version, 
                status=ImpactAnalysisAffectedStatus.AFFECTED
            )
        ]
        
        # Add fix version range if available
        if fix_version:
            version_ranges.append(
                BomTargetVersionRange(
                    version=f">={fix_version}",
                    status=ImpactAnalysisAffectedStatus.UNAFFECTED
                )
            )

        v.affects.add(BomTarget(
            ref=component.bom_ref,
            versions=version_ranges
        ))

        # Add aliases as additional references for cross-referencing
        for alias in aliases:
            if alias.startswith("CVE-"):
                v.references.add(VulnerabilityReference(
                    source=VulnerabilitySource(name="nvd", url=f"https://nvd.nist.gov/vuln/detail/{alias}"),
                    id=alias
                ))
            elif alias.startswith("GHSA-"):
                v.references.add(VulnerabilityReference(
                    source=VulnerabilitySource(name="github", url=f"https://github.com/advisories/{alias}"),
                    id=alias
                ))

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


# Old version - retained here for Historical debugging reasons
# from cyclonedx.model import Bom
# from cyclonedx.output import get_instance
# def generate_sbom(dependencies):
#    bom = Bom()
#    for dep, ver in dependencies.get("requirements.txt", {}).items():
#        bom.add_component({"name": dep, "version": ver, "type": "library"})
#    outputter = get_instance(bom, output_format='json')
#    with open("sbom.json", "w") as f:
#        f.write(outputter.output_as_string())

