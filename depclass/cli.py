import json
import os
import sys
from typing import Optional

import typer
import yaml
from depclass.rich_utils.ui_helpers import get_console

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

def merge_config_and_args(config: dict, output: Optional[str], ignore_conflicts: bool) -> dict:
    """Merge configuration with CLI arguments."""
    if output is not None:
        config["output"]["sbom_file"] = output
    
    config["ignore_conflicts"] = ignore_conflicts
    
    return config

@app.command()
def main(
    config_path: str = typer.Option("config.yaml", "-c", "--config", help="Path to config YAML"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file override"),
    skip_sbom: bool = typer.Option(False, "-sb", "--skip-sbom", help="Skip the SBOM report generation"),
    ignore_conflicts: bool = typer.Option(False, "--ignore-conflicts", help="Continue analysis even when dependency conflicts are detected"),
    ecosystem: str = typer.Option("python", "--ecosystem", help="Target dependency ecosystem")
):
    """Run ZSBOM security analysis and generate Software Bill of Materials."""

    # Load and merge configuration
    config = load_config(config_path)
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
    
    # Extract the dependencies dict from the new transitive analysis format
    dependency_data = dependencies.get("dependencies", dependencies)
    transitive_data = dependencies.get("transitive_analysis", {})

    # Calculate dependency counts
    classification = transitive_data.get("classification", {})
            
    direct_count = sum(1 for dep_type in classification.values() if dep_type == "direct")
    transitive_count = sum(1 for dep_type in classification.values() if dep_type == "transitive")
    print(f"{direct_count} direct dependencies")
    print(f"{transitive_count} transitive dependencies")

    # Pass transitive analysis to validation for comprehensive security checking
    results = validate(config, cache, transitive_data)
    
    # Use enhanced scoring with full 3-factor declared vs installed analysis
    model = load_model(config.get("risk_model"))
    
    print("\n🎯 Running risk assessment...")
    scores = score_packages(results, dependency_data, transitive_data, model, config)

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

    # Save transitive analysis results if available
    if "transitive_analysis" in dependencies:
        transitive_output_file = config["output"].get("transitive_file", "transitive_analysis.json")
        with open(transitive_output_file, "w") as fp:
            json.dump(dependencies["transitive_analysis"], fp, indent=4)
        print(f"📊 Transitive analysis results saved to {transitive_output_file}")

    if not skip_sbom:
        cve_data = read_json_file("validation_report.json")
        if cve_data:
            # Use resolution details from transitive analysis for complete dependency coverage
            sbom_dependencies = transitive_data.get("resolution_details", dependency_data)
            generate(sbom_dependencies, cve_data, config)

if __name__ == "__main__":
    app()