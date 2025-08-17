import json
import os
import sys
from typing import Optional

import typer
import yaml
from depclass.rich_utils.ui_helpers import get_console
try:
    import pkg_resources
except ImportError:
    import importlib.resources as pkg_resources

from depclass.db.vulnerability import VulnerabilityCache
from depclass.extract import extract
from depclass.risk import score_packages
from depclass.risk_model import load_model
from depclass.sbom import generate, read_json_file
from depclass.validate import validate

# Initialize Typer app
app = typer.Typer(help="ZSBOM - Zerberus SBOM Automation Framework")

def load_config(path: str) -> dict:
    """Load configuration from YAML file."""
    with open(path, "r") as f:
        return yaml.safe_load(f)

def deep_merge(default: dict, user: dict) -> dict:
    """Deep merge user config into default config."""
    result = default.copy()
    for key, value in user.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result

def load_package_default_config() -> dict:
    """Load default config from package."""
    try:
        # Try pkg_resources first (setuptools)
        default_config_path = pkg_resources.resource_filename('depclass', 'config/default.yaml')
        return load_config(default_config_path)
    except Exception:
        # Fallback for newer Python versions with importlib.resources
        try:
            import depclass.config
            config_files = pkg_resources.files(depclass.config)
            default_config_path = config_files / 'default.yaml'
            with default_config_path.open('r') as f:
                return yaml.safe_load(f)
        except Exception:
            # Last resort - try relative path
            import depclass
            package_path = os.path.dirname(depclass.__file__)
            default_config_path = os.path.join(package_path, 'config', 'default.yaml')
            return load_config(default_config_path)

def load_and_merge_config(user_config_path: str) -> dict:
    """Load user config and merge with package default."""
    default_config = load_package_default_config()
    user_config = load_config(user_config_path)
    return deep_merge(default_config, user_config)

def discover_and_load_config(config_arg: Optional[str]) -> dict:
    """Discover config file with priority order."""
    
    # Priority 1: --config argument
    if config_arg:
        if os.path.exists(config_arg):
            return load_and_merge_config(config_arg)
        else:
            raise FileNotFoundError(f"Config file not found: {config_arg}")
    
    # Priority 2: zsbom.config.yaml in current directory
    if os.path.exists("zsbom.config.yaml"):
        return load_and_merge_config("zsbom.config.yaml")
    
    # Priority 3: Package default config
    return load_package_default_config()

def merge_config_and_args(config: dict, output: Optional[str], ignore_conflicts: bool) -> dict:
    """Merge configuration with CLI arguments."""
    if output is not None:
        config["output"]["sbom_file"] = output
    
    config["ignore_conflicts"] = ignore_conflicts
    
    return config

@app.command()
def main(
    config_path: Optional[str] = typer.Option(None, "-c", "--config", help="Path to config YAML"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file override"),
    skip_sbom: bool = typer.Option(False, "-sb", "--skip-sbom", help="Skip the SBOM report generation"),
    ignore_conflicts: bool = typer.Option(False, "--ignore-conflicts", help="Continue analysis even when dependency conflicts are detected"),
    ecosystem: str = typer.Option("python", "--ecosystem", help="Target dependency ecosystem")
):
    """Run ZSBOM security analysis and generate Software Bill of Materials."""

    # Use new discovery logic instead of hardcoded config.yaml
    config = discover_and_load_config(config_path)
    config = merge_config_and_args(config, output, ignore_conflicts)
    
    # Detect environment and setup console
    console = get_console()

    # Initialize cache if enabled
    cache = None
    if config['caching']['enabled']:
        os.makedirs(os.path.dirname(config['caching']['path']), exist_ok=True)
        cache = VulnerabilityCache(config['caching']['path'])

    # Extract dependencies using enhanced parser with transitive analysis
    dependencies = extract(config=config, cache=cache, ecosystem=ecosystem)
    
    # Extract the dependencies dict from the new dependencies analysis format
    dependency_data = dependencies.get("dependencies", dependencies)
    dependencies_analysis = dependencies.get("dependencies_analysis", {})

    # Calculate dependency counts from new format
    dependency_tree = dependencies_analysis.get("dependency_tree", {})
    total_packages = dependencies_analysis.get("total_packages", 0)
    
    direct_count = len([pkg for pkg, info in dependency_tree.items() if info.get("type") == "direct"])
    transitive_count = total_packages - direct_count
    print(f"{direct_count} direct dependencies")
    print(f"{transitive_count} transitive dependencies")

    # Pass dependencies analysis to validation for comprehensive security checking
    results = validate(config, cache, dependencies_analysis)
    
    # Use enhanced scoring with full 3-factor declared vs installed analysis
    model = load_model(config.get("risk_model"))
    
    print("\n🎯 Running risk assessment...")
    scores = score_packages(results, dependency_data, dependencies_analysis, model, config)

    # Display individual package risk results
    if scores:
        print("\n📊 Risk Assessment Results:")
        print("=" * 80)
        for score in scores:
            package = score['package']
            final_score = score['final_score'] 
            risk_level = score['risk_level']
            dependency_type = score.get('dependency_type', 'unknown')

            if risk_level == "high":
            
                # Display package header with risk emoji and dependency type
                risk_emoji = "🔴" if risk_level == "high" else "🟡" if risk_level == "medium" else "🟢"
                type_indicator = "📦" if dependency_type == "direct" else "⬇️" if dependency_type == "transitive" else "❓"
                print(f"{risk_emoji} {type_indicator} {package} - Score: {final_score}/100 ({risk_level.upper()} RISK, {dependency_type.upper()})")
                
                # Display dimension breakdown
                dimensions = score['dimension_scores']
                print(f"   • Declared vs Installed: {dimensions['declared_vs_installed']}/10")
                print(f"   • Known CVEs: {dimensions['known_cves']}/10") 
                print(f"   • CWE Coverage: {dimensions['cwe_coverage']}/10")
                print(f"   • Package Abandonment: {dimensions['package_abandonment']}/10")
                print(f"   • Typosquat Heuristics: {dimensions['typosquat_heuristics']}/10")
                print()
        
        # Calculate and display summary statistics
        high_risk = [s for s in scores if s['risk_level'] == 'high']
        medium_risk = [s for s in scores if s['risk_level'] == 'medium'] 
        low_risk = [s for s in scores if s['risk_level'] == 'low']
        
        # Calculate breakdown by dependency type
        direct_packages = [s for s in scores if s.get('dependency_type') == 'direct']
        transitive_packages = [s for s in scores if s.get('dependency_type') == 'transitive']
        
        print("📈 Risk Assessment Summary:")
        print(f"   🔴 High Risk: {len(high_risk)} packages")
        print(f"   🟡 Medium Risk: {len(medium_risk)} packages") 
        print(f"   🟢 Low Risk: {len(low_risk)} packages")
        print(f"   📦 Direct Dependencies: {len(direct_packages)} packages")
        print(f"   ⬇️ Transitive Dependencies: {len(transitive_packages)} packages")
        print(f"   📊 Total Analyzed: {len(scores)} packages")
        print()

    with open(config["output"].get("risk_file", "risk_report.json"), "w") as fp:
        json.dump(scores, fp, indent=4)
    
    print(f"✅ Risk assessment completed. Results saved in `{config['output'].get('risk_file', 'risk_report.json')}`.")

    # Save dependencies analysis results if available
    if "dependencies_analysis" in dependencies:
        dependencies_output_file = config["output"].get("dependencies_file", "dependencies.json")
        with open(dependencies_output_file, "w") as fp:
            json.dump(dependencies["dependencies_analysis"], fp, indent=4)
        print(f"📊 Dependencies analysis results saved to {dependencies_output_file}")

    if not skip_sbom:
        cve_data = read_json_file("validation_report.json")
        if cve_data:
            # Use total packages from dependencies analysis for complete dependency coverage
            # We need to extract resolved versions from the dependency tree
            sbom_dependencies = {}
            for pkg_key, pkg_info in dependencies_analysis.get("dependency_tree", {}).items():
                if "==" in pkg_key:
                    pkg_name, pkg_version = pkg_key.split("==", 1)
                    sbom_dependencies[pkg_name.lower()] = pkg_version
            
            # Fallback to original dependency data if no resolved versions found
            if not sbom_dependencies:
                sbom_dependencies = dependency_data
            
            generate(sbom_dependencies, cve_data, config)

if __name__ == "__main__":
    app()