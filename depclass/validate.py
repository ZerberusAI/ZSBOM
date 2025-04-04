"""
ZSBOM Dependency Validation Module

This script validates Python dependencies against:
1. Known **CVEs (using Safety DB)**
2. **Abandoned packages**
3. **Typosquatting risks**
4. **Version compliance**
5. **CWE Weaknesses (using MITRE/NIST CWE Data)**

---
**TODO: Externalize Resources for Future Scalability**
 **CWE Data Source:**
   - Currently using **NIST CWE API** (fallback from MITRE).
   - Future enhancement: 
     - Allow configuring the API URL via `config.yaml` instead of hardcoding it.
     - Support downloading and caching **MITRE CWE JSON** for offline analysis.
  
 **Safety DB (CVE Checks)**
   - Current source: **PyUp Safety DB (GitHub)**
   - Future enhancements:
     - Allow users to specify **custom Safety DB URLs** via `config.yaml`.
     - Implement **local caching** of Safety DB to reduce network dependency.
     - Add support for **NVD CVE API** as an alternative.

 **Local Database Support**
   - Instead of making **live API calls every time**, enable:
     - **Local SQLite/PostgreSQL DB** for caching vulnerability data.
     - Automatic **periodic sync jobs** to refresh local CVE and CWE data.
     - A structured way to store **scan results** for audit tracking.

 **SAFE List & Custom Blocklists**
   - Currently, **abandoned packages and typosquatting lists** are hardcoded.
   - Future improvements:
     - Support fetching **SAFE lists** (known good packages) from an external source.
     - Allow **user-defined blacklists** via `config.yaml` or API.

 **Logging & Alerting**
   - Add **verbose logging** for better debugging.
   - Option to **email/slack alerts** when vulnerabilities are found.

---

"""

import os
import yaml
import json
import requests
import importlib.metadata  # Replaces deprecated pkg_resources
from safety.safety import get_vulnerabilities
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional
from datetime import datetime
import tempfile
import zipfile
import io

from .notification.gchat import GChatNotifier
from .db.vulnerability import VulnerabilityCache


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("zsbom.log"),
        logging.StreamHandler()
    ]
)

# Update fetch_safety_db function
def fetch_safety_db(config):
    """Fetch Safety DB with caching support"""
    cache = VulnerabilityCache(config['caching']['path'])
    
    if config['caching']['enabled']:
        cached_data = cache.get_cached_data('safety_db', config['caching']['ttl_hours'])
        if cached_data:
            logging.info("✅ Using cached Safety DB")
            return cached_data

    logging.info("🔍 Fetching fresh Safety DB...")
    try:
        response = requests.get(config['api_endpoints']['safety_db'], timeout=10)
        response.raise_for_status()
        data = response.json()
        vulnerabilities_count = len(data.get('vulnerabilities', []))
        logging.info(f"✅ Safety DB fetched successfully, {vulnerabilities_count} vulnerabilities found")
        if config['caching']['enabled']:
            cache.cache_data('safety_db', data)
            
        return data
    except requests.exceptions.RequestException as e:
        logging.error(f"⚠️ Failed to fetch Safety DB: {e}")
        return None


# Resolve path to config.yaml in the root directory
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_PATH = os.path.join(BASE_DIR, "config.yaml")

# Alternative CWE Source (TODO: Support MITRE CWE when available)
NIST_CWE_URL = "https://services.nvd.nist.gov/rest/json/cwe/list/2.0"

# Load validation configuration
def load_config(config_file=CONFIG_PATH):
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"⚠️ config.yaml not found at {config_file}. Make sure it's in the project root.")
    
    with open(config_file, "r") as f:
        return yaml.safe_load(f)

# Get installed dependencies
def get_installed_packages():
    return {pkg.metadata["Name"].lower(): pkg.version for pkg in importlib.metadata.distributions()}

# Check for CVEs using Safety DB
def check_cves(dependencies, enable_check, config):
    if not enable_check:
        return []
    
    print("🔍 Checking for CVEs...")
    db = fetch_safety_db(config)
    if not db:
        return []

    vulns = []
    for package, version in dependencies.items():
        package_data = db.get(package, [])

        # Ensure package_data is a list
        if not isinstance(package_data, list):
            print(f"⚠️ Unexpected format for package {package}: {package_data}")
            continue

        for vuln in package_data:
            if isinstance(vuln, dict):
                specs = vuln.get("specs", [])
                
                # Check if the installed version falls within the vulnerable range
                for spec in specs:
                    if version in spec:  # This is a rough check, might need more logic
                        vulns.append({
                            "package": package,
                            "cve": vuln.get("cve", "Unknown"),
                            "severity": vuln.get("severity", "Unknown"),
                            "description": vuln.get("advisory", "No details available")
                        })
                        break  # Stop after first match

    return vulns

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
        installed_version = dependencies.get(pkg)
        if installed_version and importlib.metadata.version(pkg) < min_version:
            issues[pkg] = {"installed": installed_version, "required": min_version}
    return issues

def parse_weakness(weakness, ns):
    """Parse a single weakness from XML"""
    weakness_data = {
        "cwe_id": f"CWE-{weakness.get('ID', 'Unknown')}",
        "name": weakness.get('Name', 'Unknown'),
        "abstraction": weakness.get('Abstraction', ''),
        "status": weakness.get('Status', ''),
        "description": "",
        "extended_description": "",
        "likelihood": weakness.get('Likelihood', 'Unknown'),
        "platforms": [],
        "consequences": [],
        "examples": [],
        "observed_examples": [],
        "mitigations": []
    }
    
    # Get descriptions
    desc = weakness.find('.//cwe:Description', ns)
    if desc is not None and desc.text:
        weakness_data["description"] = desc.text.strip()
    
    ext_desc = weakness.find('.//cwe:Extended_Description', ns)
    if ext_desc is not None and ext_desc.text:
        weakness_data["extended_description"] = ext_desc.text.strip()
    
    # Get platforms
    platforms = weakness.find('.//cwe:Applicable_Platforms', ns)
    if platforms is not None:
        for platform in platforms.findall('.//cwe:Language', ns):
            if platform.text or platform.get('Class'):
                weakness_data["platforms"].append({
                    "language": platform.get('Class', ''),
                    "prevalence": platform.get('Prevalence', 'Unknown')
                })
    
    # Get consequences
    consequences = weakness.find('.//cwe:Common_Consequences', ns)
    if consequences is not None:
        for consequence in consequences.findall('.//cwe:Consequence', ns):
            impact = [imp.text for imp in consequence.findall('.//cwe:Impact', ns) if imp.text]
            scope = [s.text for s in consequence.findall('.//cwe:Scope', ns) if s.text]
            note = consequence.find('.//cwe:Note', ns)
            weakness_data["consequences"].append({
                "scope": scope,
                "impact": impact,
                "note": note.text.strip() if note is not None and note.text else ""
            })
    
    # Get examples
    examples = weakness.find('.//cwe:Demonstrative_Examples', ns)
    if examples is not None:
        for example in examples.findall('.//cwe:Demonstrative_Example', ns):
            code = example.find('.//cwe:Example_Code', ns)
            weakness_data["examples"].append({
                "language": code.get('Language', '') if code is not None else "",
                "nature": code.get('Nature', '') if code is not None else "",
                "intro": example.findtext('.//cwe:Intro_Text', '', ns),
                "body": example.findtext('.//cwe:Body_Text', '', ns)
            })
    
    # Get observed examples (CVEs)
    observed = weakness.find('.//cwe:Observed_Examples', ns)
    if observed is not None:
        for example in observed.findall('.//cwe:Observed_Example', ns):
            weakness_data["observed_examples"].append({
                "cve": example.findtext('.//cwe:Reference', '', ns),
                "description": example.findtext('.//cwe:Description', '', ns),
                "link": example.findtext('.//cwe:Link', '', ns)
            })
    
    return weakness_data

# Fetch MITRE CWE Weaknesses (Fallback to NIST if MITRE is down)
def fetch_cwe_data(config: Dict[str, Any]) -> Optional[Dict]:
    """Fetch and parse CWE data with streaming XML support"""
    cache = VulnerabilityCache(config['caching']['path'])
    
    if config['caching']['enabled']:
        cached_data = cache.get_cached_data('cwe', config['caching']['ttl_hours'])
        if cached_data:
            logging.info("✅ Using cached CWE data")
            return cached_data

    logging.info("🔍 Fetching fresh CWE data...")
    
    try:
        # Try downloading MITRE XML
        response = requests.get(
            "https://cwe.mitre.org/data/xml/cwec_v4.9.xml.zip",  # Updated URL to explicitly request zip
            stream=True,
            timeout=30,
            headers={
                'User-Agent': 'ZSBOM-SecurityScanner/1.0',
                'Accept': 'application/zip'
            }
        )
        response.raise_for_status()

        # Process zip file directly from memory
        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
            xml_files = [f for f in zip_file.namelist() if f.endswith('.xml')]
            if not xml_files:
                raise ValueError("No XML file found in ZIP archive")
            
            with zip_file.open(xml_files[0]) as xml_file:
                tree = ET.parse(xml_file)
                root = tree.getroot()
        
        # Extract namespace more robustly
        ns = {'cwe': 'http://cwe.mitre.org/cwe-6'}
        
        weaknesses = []
        for weakness in root.findall('.//cwe:Weakness', ns):
            weakness_data = parse_weakness(weakness, ns)
            
            # Include Python-relevant and generic weaknesses
            if any(p.get('language') in ['Python', 'Not Language-Specific'] 
                  for p in weakness_data["platforms"]):
                weaknesses.append(weakness_data)

        data = {
            "cwe_list": {
                "CWE_Items": weaknesses,
                "source": "MITRE",
                "timestamp": datetime.now().isoformat()
            }
        }
        
        logging.info(f"✅ Successfully parsed {len(weaknesses)} CWE entries from MITRE")
        
    except (requests.exceptions.RequestException, ET.ParseError, ValueError) as e:
        logging.warning(f"⚠️ MITRE fetch failed, falling back to NIST: {e}")
        
        try:
            # Updated NIST API endpoint
            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cwe/1.0",  # Updated to v1.0 endpoint
                timeout=10,
                headers={
                    'User-Agent': 'ZSBOM-SecurityScanner/1.0',
                    'Accept': 'application/json'
                }
            )
            response.raise_for_status()
            data = response.json()
            logging.info("✅ Successfully fetched NIST CWE data")
            
        except requests.exceptions.RequestException as e:
            logging.error(f"⚠️ Both MITRE and NIST CWE fetches failed: {e}")
            
            # Use minimal hardcoded dataset as last resort
            data = {
                "cwe_list": {
                    "CWE_Items": [
                        {
                            "cwe_id": "CWE-79",
                            "name": "Cross-site Scripting",
                            "description": "Improper Neutralization of Input During Web Page Generation",
                            "likelihood": "High",
                            "platforms": ["Python"]
                        }
                    ],
                    "source": "local_fallback",
                    "timestamp": datetime.now().isoformat()
                }
            }
            logging.warning("⚠️ Using minimal fallback CWE data")

    if config['caching']['enabled'] and data:
        cache.cache_data('cwe', data)
    
    return data

# Check against CWE Weaknesses
def check_cwe_weaknesses(dependencies, enable_check, config):
    """Check dependencies against CWE weaknesses with specific focus on Python packages."""
    if not enable_check:
        return []
    
    logging.info("🔍 Checking against CWE weaknesses...")
    cwe_data = fetch_cwe_data(config)
    if not cwe_data:
        return []

    found_weaknesses = []
    
    # Get list of Python-specific CWEs from config
    targeted_cwes = set(str(cwe).replace('CWE-', '') for cwe in config.get('mitre_weaknesses', []))
    
    for weakness in cwe_data.get("cwe_list", {}).get("CWE_Items", []):
        cwe_id = weakness.get("cwe_id", "Unknown").replace('CWE-', '')
        
        # Only process CWEs that are in our target list
        if cwe_id not in targeted_cwes:
            continue
            
        affected_packages = []
        
        # Check each package against the weakness
        for package_name, version in dependencies.items():
            is_vulnerable = False
            
            # Check if any example code matches the package
            for example in weakness.get("examples", []):
                if example.get("language") == "Python":
                    code_sample = example.get("body", "")
                    if package_name in code_sample.lower():
                        is_vulnerable = True
                        break
            
            # Check observed CVEs for the package
            for cve_example in weakness.get("observed_examples", []):
                if package_name in cve_example.get("description", "").lower():
                    is_vulnerable = True
                    break
            
            if is_vulnerable:
                affected_packages.append(package_name)
        
        if affected_packages:
            found_weaknesses.append({
                "cwe_id": f"CWE-{cwe_id}",
                "name": weakness.get("name"),
                "description": weakness.get("description"),
                "affected_packages": affected_packages,
                "likelihood": weakness.get("likelihood"),
                "consequences": weakness.get("consequences", []),
                "examples": [
                    ex for ex in weakness.get("examples", [])
                    if ex.get("language") == "Python"
                ],
                "mitigations": weakness.get("mitigations", []),
                "observed_cves": [
                    cve for cve in weakness.get("observed_examples", [])
                    if any(pkg in cve.get("description", "").lower() 
                          for pkg in affected_packages)
                ]
            })
    
    if found_weaknesses:
        logging.info(f"⚠️ Found {len(found_weaknesses)} relevant CWE weaknesses")
    else:
        logging.info("✅ No relevant CWE weaknesses found")
    
    return found_weaknesses

# Main validation function
def validate():
    config = load_config()
    dependencies = get_installed_packages()

    if config['caching']['enabled']:
        os.makedirs(os.path.dirname(config['caching']['path']), exist_ok=True)
        cache = VulnerabilityCache(config['caching']['path'])
    
    
    results = {
        "cve_issues": check_cves(dependencies, config["validation_rules"]["enable_cve_check"], config),
        "abandoned_packages": check_abandoned(dependencies, config["abandoned_packages"], config["validation_rules"]["enable_abandoned_check"]),
        "typosquatting_issues": check_typosquatting(dependencies, config["typosquatting_blacklist"], config["validation_rules"]["enable_typosquatting_check"]),
        "version_issues": check_versions(dependencies, config["min_versions"], config["validation_rules"]["enable_version_check"]),
        # "cwe_weaknesses": check_cwe_weaknesses(config["validation_rules"]["enable_mitre_check"]),
        "cwe_weaknesses": check_cwe_weaknesses(dependencies, config["validation_rules"]["enable_mitre_check"], config),

    }

    if config['caching']['enabled']:
        scan_id = cache.store_scan_result(results)
        logging.info(f"Scan results stored with ID: {scan_id}")

    # Save results to JSON file
    with open(config["output"]["report_file"], "w") as f:
        json.dump(results, f, indent=4)
    
    print(f"✅ Validation completed. Results saved in `{config['output']['report_file']}`.")
    if config['notifications']['gchat']['enabled']:
        notifier = GChatNotifier(config)
        notifier.send(results)

if __name__ == "__main__":
    validate()
