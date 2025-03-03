import yaml
import json
import requests
import pkg_resources
from safety.safety import get_vulnerabilities

# Load validation configuration
def load_config(config_file="config.yaml"):
    with open(config_file, "r") as f:
        return yaml.safe_load(f)

# Get installed dependencies
def get_installed_packages():
    return {pkg.key: pkg.version for pkg in pkg_resources.working_set}

# Check for CVEs using `safety`
def check_cves(dependencies, enable_check):
    if not enable_check:
        return []
    print("🔍 Checking for CVEs...")
    vulns = get_vulnerabilities(dependencies)
    return [
        {
            "package": v.package_name,
            "cve": v.cve_id,
            "severity": v.severity,
            "description": v.advisory
        }
        for v in vulns
    ] if vulns else []

# Check for abandoned packages
def check_abandoned(dependencies, abandoned_list, enable_check):
    if not enable_check:
        return []
    print("🔍 Checking for abandoned packages...")
    return [pkg for pkg in dependencies if pkg in abandoned_list]

# Check for typosquatting risks
def check_typosquatting(dependencies, blacklist, enable_check):
    if not enable_check:
        return []
    print("🔍 Checking for typosquatting risks...")
    return [pkg for pkg in dependencies if pkg in blacklist]

# Check if installed versions meet minimum requirements
def check_versions(dependencies, min_versions, enable_check):
    if not enable_check:
        return {}
    print("🔍 Checking version compliance...")
    issues = {}
    for pkg, min_version in min_versions.items():
        if pkg in dependencies and pkg_resources.parse_version(dependencies[pkg]) < pkg_resources.parse_version(min_version):
            issues[pkg] = {"installed": dependencies[pkg], "required": min_version}
    return issues

# Fetch MITRE Python Weaknesses
def check_mitre_weaknesses(dependencies, mitre_source, mitre_list, enable_check):
    if not enable_check:
        return []
    print("🔍 Checking against MITRE Python weaknesses...")
    try:
        response = requests.get(mitre_source)
        mitre_data = response.json()
    except Exception as e:
        print(f"⚠️ MITRE fetch failed: {e}")
        return []

    found_weaknesses = []
    for pkg in dependencies:
        for cwe in mitre_list:
            if cwe in mitre_data.get(pkg, []):  # Assume MITRE data maps package -> CWE list
                found_weaknesses.append({"package": pkg, "CWE": cwe})
    
    return found_weaknesses

# Main validation function
def validate():
    config = load_config()
    dependencies = get_installed_packages()
    
    results = {
        "cve_issues": check_cves(dependencies, config["validation_rules"]["enable_cve_check"]),
        "abandoned_packages": check_abandoned(dependencies, config["abandoned_packages"], config["validation_rules"]["enable_abandoned_check"]),
        "typosquatting_issues": check_typosquatting(dependencies, config["typosquatting_blacklist"], config["validation_rules"]["enable_typosquatting_check"]),
        "version_issues": check_versions(dependencies, config["min_versions"], config["validation_rules"]["enable_version_check"]),
        "mitre_weaknesses": check_mitre_weaknesses(
            dependencies, config["sources"]["mitre_weaknesses"], config["mitre_weaknesses"], config["validation_rules"]["enable_mitre_check"]
        ),
    }

    # Save results to JSON file
    with open(config["output"]["report_file"], "w") as f:
        json.dump(results, f, indent=4)

    print(f"✅ Validation completed. Results saved in `{config['output']['report_file']}`.")

if __name__ == "__main__":
    validate()
