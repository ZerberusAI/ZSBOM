#REvised Location Updated as Per CycloneDX @ https://cyclonedx-python-library.readthedocs.io/en/stable/autoapi/cyclonedx/model/bom/ 
import json
import os

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.vulnerability import (BomTarget, Vulnerability,
                                           VulnerabilityRating,
                                           VulnerabilityReference,
                                           VulnerabilitySeverity,
                                           VulnerabilitySource,
                                           BomTargetVersionRange)
from cyclonedx.output.json import JsonV1Dot5

SEVERITY_MAP = {
    "critical": VulnerabilitySeverity.CRITICAL,
    "high": VulnerabilitySeverity.HIGH,
    "medium": VulnerabilitySeverity.MEDIUM,
    "low": VulnerabilitySeverity.LOW,
    "unknown": VulnerabilitySeverity.UNKNOWN,
    None: VulnerabilitySeverity.UNKNOWN,
}



def generate_sbom(dependencies: dict, cve_data: dict, config: dict):
    bom = Bom()
    component_map = {}

    # Add components to BOM
    for dep, ver in dependencies.items():
        component = Component(name=dep, version=ver, type=ComponentType.LIBRARY)
        bom.components.add(component)
        component_map[f"{dep.lower()}=={ver}"] = component

    # Add vulnerabilities to BOM
    process_cve_data(cve_data, component_map, bom)

    # Export SBOM as JSON
    outputter = JsonV1Dot5(bom=bom)
    output_path = os.path.abspath(config["output"]["sbom_file"])
    with open(output_path, "w") as f:
        f.write(outputter.output_as_string())
    
    print(f"SBOM report exported to: {output_path}")


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

        if vuln.get('score', None):
            severity = VulnerabilitySeverity.get_from_cvss_scores(scores=(vuln.get('score')))
        else:
            severity = SEVERITY_MAP.get(vuln.get("severity", "").lower(), VulnerabilitySeverity.UNKNOWN)
        cwes = vuln.get("cwes") or []
        summary = vuln.get("summary", "")
        references = vuln.get("references", [])

        # Construct Vulnerability object
        v = Vulnerability(
            id=vuln_id,
            bom_ref=component.bom_ref
        )
        
        # v.component = component
        v.source = VulnerabilitySource(name="OSV.dev", url=f"https://osv.dev/vulnerability/{vuln_id}")
        v.description = summary

        v.ratings.add(
            VulnerabilityRating(
                score=None,
                severity=severity,
                method=None,
                source=VulnerabilitySource(name="OSV.dev")
            )
        )

        v.cwes = parse_cwes(cwes)

        for ref_url in references:
            v.references.add(VulnerabilityReference(
                source=VulnerabilitySource(name="external", url=ref_url),
                id=ref_url  # you can extract a meaningful ID if needed
            ))

        v.affects.add(BomTarget(
            ref=component.bom_ref,
            versions=[BomTargetVersionRange(version=installed_version)]
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

def read_json_file(file_path: str) -> dict | None:
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
