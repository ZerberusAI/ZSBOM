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
     - Note: Typosquatting detection is now handled by the risk scoring system.

 **Logging & Alerting**
   - Add **verbose logging** for better debugging.
   - Option to **email/slack alerts** when vulnerabilities are found.

---

"""

import os
import yaml
import json
import importlib.metadata  # Replaces deprecated pkg_resources
import logging
import time
from rich.console import Console
from rich.spinner import Spinner
from rich.live import Live

from .notification.gchat import GChatNotifier
from .db.vulnerability import VulnerabilityCache
from depclass.vulnerability_sources.osv_source import OSVSource
from depclass.vulnerability_sources.safety_db import SafetyDBSource
from depclass.weakness_sources.mitre import MitreSource
from depclass.weakness_sources.nvd import NvdSource


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("zsbom.log"),
        logging.StreamHandler()
    ]
)

# Resolve path to config.yaml in the root directory
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_PATH = os.path.join(BASE_DIR, "config.yaml")

# Load validation configuration
def load_config(config_file=CONFIG_PATH):
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"⚠️ config.yaml not found at {config_file}. Make sure it's in the project root.")
    
    with open(config_file, "r") as f:
        return yaml.safe_load(f)

# Get installed dependencies
def get_installed_packages():
    return {pkg.metadata["Name"].lower(): pkg.version for pkg in importlib.metadata.distributions()}

# Check for abandoned packages
def check_abandoned(dependencies, abandoned_list, enable_check):
    if not enable_check:
        return []
    print("🔍 Checking for abandoned packages...")
    return [pkg for pkg in dependencies if pkg in abandoned_list]


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

def check_cve(config, dependencies, cache):
    result = []
    cve_sources = {
        "osv_dev": OSVSource,
        "safety_db": SafetyDBSource
    }

    # Idea is to get CVE data from all the enabled sources and consolidate it in the result
    for cve_source, value in config['sources']['cve'].items():
        if value.get('enabled', False):
            cve = cve_sources[cve_source](config, dependencies, cache)
            result = cve.fetch_vulnerabilities()

    # TODO
    # Append result and consolidation

    return result

def _fetch_weakness_with_spinner(cwe_instance, cwe_source_name: str):
    """Wrapper that adds Rich spinner to CWE database download."""
    console = Console()
    with Live(Spinner("dots", text=f"[bold yellow]Downloading {cwe_source_name} database...[/bold yellow]"), 
              console=console, refresh_per_second=4) as live:
        try:
            result = cwe_instance.fetch_weakness()
            live.update("[bold green]✔ Download completed[/bold green]")
            time.sleep(0.5)  # Brief pause to show completion
            return result
        except Exception as e:
            live.update("[bold red]✗ Download failed[/bold red]")
            time.sleep(0.5)
            raise

def check_cwe(config, cache):
    result = []
    cwe_sources = {
        "mitre_weaknesses": MitreSource,
        "nvd_weaknesses": NvdSource
    }

    for cwe_source, value in config['sources']['cwe'].items():
        if value.get('enabled', False):
            try:
                cwe = cwe_sources[cwe_source](config, cache)
                # TODO
                # Append result and consolidation
                result = _fetch_weakness_with_spinner(cwe, cwe_source.replace('_', ' ').title())
            except Exception as e:
                logging.warning(f"⚠️ MITRE fetch failed, falling back to NIST: {e}")
                cwe = cwe_sources['nvd_weaknesses'](config, cache)
                result = _fetch_weakness_with_spinner(cwe, "NVD Weaknesses")

    return result

# Main validation function
def validate(config, cache=None, transitive_analysis=None):
    # If transitive analysis is available and transitive validation is enabled, use resolved packages
    include_transitive = config.get('transitive_analysis', {}).get('include_in_validation', True)
    if transitive_analysis and include_transitive:
        resolved_packages = transitive_analysis.get("resolution_details", {})
        if resolved_packages:
            # Use only resolved packages from pip-compile (declared + transitive dependencies)
            dependencies = resolved_packages
            logging.info(f"🔍 Validating {len(dependencies)} packages (including transitive dependencies)")
        else:
            logging.warning("⚠️ No resolved packages found in transitive analysis, cannot validate without dependency resolution")
            dependencies = {}
    else:
        # For backward compatibility when transitive analysis is disabled
        logging.warning("⚠️ Transitive analysis disabled, validation limited to resolved packages only")  
        dependencies = transitive_analysis.get("resolution_details", {}) if transitive_analysis else {}
    
    # Use provided cache or create new one if caching is enabled
    if cache is None and config['caching']['enabled']:
        os.makedirs(os.path.dirname(config['caching']['path']), exist_ok=True)
        cache = VulnerabilityCache(config['caching']['path'])

    results = {
        "cve_issues": check_cve(config, dependencies, cache),
        "abandoned_packages": check_abandoned(dependencies, config["abandoned_packages"], config["validation_rules"]["enable_abandoned_check"]),
        "version_issues": check_versions(dependencies, config["min_versions"], config["validation_rules"]["enable_version_check"]),
        "cwe_weaknesses": check_cwe(config, cache),
    }
    
    # Add package classification if transitive analysis is available
    if transitive_analysis and include_transitive:
        classification = transitive_analysis.get("classification", {})
        # Tag each CVE issue with dependency type
        for cve in results["cve_issues"]:
            package_name = cve.get("package_name", "")
            cve["dependency_type"] = classification.get(package_name, "unknown")

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

    return results

