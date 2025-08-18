import json
import os
import sys
from typing import Optional

import typer
import yaml
from depclass.rich_utils.ui_helpers import get_console
try:
    # Use modern importlib.resources (Python 3.9+)
    import importlib.resources as importlib_resources
    pkg_resources = None
except ImportError:
    # Fallback to pkg_resources for older Python versions
    import pkg_resources
    importlib_resources = None

from depclass.db.vulnerability import VulnerabilityCache
from depclass.extract import extract
from depclass.risk import score_packages
from depclass.risk_model import load_model
from depclass.sbom import generate, read_json_file
from depclass.validate import validate

# Phase 3: Import metadata collection framework
from depclass.metadata import MetadataCollector
from depclass.metadata.error_tracker import ErrorSeverity, ErrorCategory

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
        # Try modern importlib.resources first (Python 3.9+)
        if importlib_resources:
            import depclass.config
            config_files = importlib_resources.files(depclass.config)
            default_config_path = config_files / 'default.yaml'
            with default_config_path.open('r') as f:
                return yaml.safe_load(f)
        else:
            raise ImportError("importlib.resources not available")
    except Exception:
        # Fallback to pkg_resources for older Python versions
        try:
            if pkg_resources:
                default_config_path = pkg_resources.resource_filename('depclass', 'config/default.yaml')
                return load_config(default_config_path)
            else:
                raise ImportError("pkg_resources not available")
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


def collect_generated_files(config: dict) -> list:
    """Collect list of generated output files."""
    generated_files = []
    
    # Standard output files from config
    output_config = config.get("output", {})
    file_mappings = {
        "validation_report.json": output_config.get("report_file", "validation_report.json"),
        "risk_report.json": output_config.get("risk_file", "risk_report.json"),
        "dependencies.json": output_config.get("dependencies_file", "dependencies.json"),
        "sbom.json": output_config.get("sbom_file", "sbom.json")
    }
    
    # Check which files actually exist
    for file_type, file_path in file_mappings.items():
        if os.path.exists(file_path):
            generated_files.append(file_path)
    
    return generated_files


def collect_scan_files_for_upload(config: dict) -> dict:
    """Collect generated files for upload with proper renaming."""
    file_mapping = {
        # ZSBOM file -> Upload name (according to API specification)
        "dependencies.json": "dependencies.json",
        "validation_report.json": "vulnerabilities.json",  # Rename
        "sbom.json": "sbom.json", 
        "risk_report.json": "risk_analysis.json",  # Rename
        "scan_metadata.json": "scan_metadata.json"
    }
    
    available_files = {}
    output_config = config.get("output", {})
    
    for zsbom_file, upload_name in file_mapping.items():
        # Get file path from config or use default
        config_key = zsbom_file.replace(".json", "_file")
        file_path = output_config.get(config_key, zsbom_file)
        
        if os.path.exists(file_path):
            available_files[upload_name] = file_path
    
    return available_files


def calculate_scan_statistics(
    dependencies_analysis: dict, 
    results: dict, 
    scores: list
) -> dict:
    """Calculate comprehensive scan statistics."""
    statistics = {}
    
    # Dependency statistics
    dependency_tree = dependencies_analysis.get("dependency_tree", {})
    statistics["total_dependencies"] = dependencies_analysis.get("total_packages", 0)
    statistics["direct_dependencies"] = len([
        pkg for pkg, info in dependency_tree.items() 
        if info.get("type") == "direct"
    ])
    statistics["transitive_dependencies"] = (
        statistics["total_dependencies"] - statistics["direct_dependencies"]
    )
    
    # Vulnerability statistics from validation results
    if results and "vulnerabilities" in results:
        vulnerabilities = results["vulnerabilities"]
        statistics["vulnerabilities_found"] = len(vulnerabilities)
        
        # Count by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        statistics["critical_vulnerabilities"] = severity_counts.get("critical", 0)
        statistics["high_vulnerabilities"] = severity_counts.get("high", 0)
        statistics["medium_vulnerabilities"] = severity_counts.get("medium", 0)
        statistics["low_vulnerabilities"] = severity_counts.get("low", 0)
    else:
        statistics["vulnerabilities_found"] = 0
        statistics["critical_vulnerabilities"] = 0
        statistics["high_vulnerabilities"] = 0
        statistics["medium_vulnerabilities"] = 0
        statistics["low_vulnerabilities"] = 0
    
    # Risk assessment statistics
    if scores:
        risk_counts = {}
        for score in scores:
            risk_level = score.get("risk_level", "unknown")
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        statistics["high_risk_packages"] = risk_counts.get("high", 0)
        statistics["medium_risk_packages"] = risk_counts.get("medium", 0)
        statistics["low_risk_packages"] = risk_counts.get("low", 0)
    else:
        statistics["high_risk_packages"] = 0
        statistics["medium_risk_packages"] = 0
        statistics["low_risk_packages"] = 0
    
    return statistics

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

    # Phase 3: Initialize metadata collection framework
    metadata_collector = MetadataCollector(config, console)
    scan_id = metadata_collector.start_collection()
    
    # Track CLI configuration details
    metadata_collector.update_statistics({
        "cli_config": {
            "config_path": config_path,
            "output_override": output,
            "skip_sbom": skip_sbom,
            "ignore_conflicts": ignore_conflicts,
            "ecosystem": ecosystem
        }
    })
    
    exit_code = 0
    dependencies_analysis = {}
    results = {}
    scores = []
    
    try:
        console.print(f"🚀 ZSBOM scan started (ID: {scan_id[:8]})", style="bold blue")
        
        # Initialize cache if enabled
        cache = None
        if config['caching']['enabled']:
            os.makedirs(os.path.dirname(config['caching']['path']), exist_ok=True)
            cache = VulnerabilityCache(config['caching']['path'])

        # Phase 3: Track dependency extraction stage
        metadata_collector.track_stage_start("dependency_extraction", {
            "ecosystem": ecosystem,
            "cache_enabled": config['caching']['enabled']
        })
        
        try:
            dependencies = extract(config=config, cache=cache, ecosystem=ecosystem)
            dependency_data = dependencies.get("dependencies", dependencies)
            dependencies_analysis = dependencies.get("dependencies_analysis", {})
            metadata_collector.track_stage_end("dependency_extraction", success=True)
        except Exception as e:
            metadata_collector.capture_error(e, "dependency_extraction", 
                                           ErrorCategory.DEPENDENCY_EXTRACTION, ErrorSeverity.CRITICAL)
            metadata_collector.track_stage_end("dependency_extraction", success=False, error_message=str(e))
            raise

        # Calculate and display dependency counts
        dependency_tree = dependencies_analysis.get("dependency_tree", {})
        total_packages = dependencies_analysis.get("total_packages", 0)
        
        direct_count = len([pkg for pkg, info in dependency_tree.items() if info.get("type") == "direct"])
        transitive_count = total_packages - direct_count
        print(f"{direct_count} direct dependencies")
        print(f"{transitive_count} transitive dependencies")

        # Phase 3: Track validation stage
        metadata_collector.track_stage_start("validation", {
            "total_packages": total_packages,
            "direct_packages": direct_count,
            "transitive_packages": transitive_count
        })
        
        try:
            results = validate(config, cache, dependencies_analysis)
            metadata_collector.track_stage_end("validation", success=True)
        except Exception as e:
            metadata_collector.capture_error(e, "validation", 
                                           ErrorCategory.VALIDATION, ErrorSeverity.ERROR)
            metadata_collector.track_stage_end("validation", success=False, error_message=str(e))
            # Continue with degraded functionality
            results = {}

        # Phase 3: Track risk assessment stage
        metadata_collector.track_stage_start("risk_assessment")
        
        try:
            model = load_model(config.get("risk_model"))
            print("\n🎯 Running risk assessment...")
            scores = score_packages(results, dependency_data, dependencies_analysis, model, config)
            metadata_collector.track_stage_end("risk_assessment", success=True)
        except Exception as e:
            metadata_collector.capture_error(e, "risk_assessment", 
                                           ErrorCategory.RISK_ASSESSMENT, ErrorSeverity.ERROR)
            metadata_collector.track_stage_end("risk_assessment", success=False, error_message=str(e))
            # Continue with empty scores
            scores = []

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

        # Save risk assessment results
        try:
            risk_file = config["output"].get("risk_file", "risk_report.json")
            with open(risk_file, "w") as fp:
                json.dump(scores, fp, indent=4)
            metadata_collector.add_generated_file(risk_file)
            print(f"✅ Risk assessment completed. Results saved in `{risk_file}`.")
        except Exception as e:
            metadata_collector.capture_error(e, "output_generation", 
                                           ErrorCategory.SYSTEM, ErrorSeverity.ERROR)

        # Save dependencies analysis results if available
        if "dependencies_analysis" in dependencies:
            try:
                dependencies_output_file = config["output"].get("dependencies_file", "dependencies.json")
                with open(dependencies_output_file, "w") as fp:
                    json.dump(dependencies["dependencies_analysis"], fp, indent=4)
                metadata_collector.add_generated_file(dependencies_output_file)
                print(f"📊 Dependencies analysis results saved to {dependencies_output_file}")
            except Exception as e:
                metadata_collector.capture_error(e, "output_generation", 
                                               ErrorCategory.SYSTEM, ErrorSeverity.ERROR)

        # Phase 3: Track SBOM generation stage
        if not skip_sbom:
            metadata_collector.track_stage_start("sbom_generation")
            
            try:
                cve_data = read_json_file("validation_report.json")
                if cve_data:
                    # Use total packages from dependencies analysis for complete dependency coverage
                    sbom_dependencies = {}
                    for pkg_key, pkg_info in dependencies_analysis.get("dependency_tree", {}).items():
                        if "==" in pkg_key:
                            pkg_name, pkg_version = pkg_key.split("==", 1)
                            sbom_dependencies[pkg_name.lower()] = pkg_version
                    
                    # Fallback to original dependency data if no resolved versions found
                    if not sbom_dependencies:
                        sbom_dependencies = dependency_data
                    
                    generate(sbom_dependencies, cve_data, config)
                    sbom_file = config["output"].get("sbom_file", "sbom.json")
                    metadata_collector.add_generated_file(sbom_file)
                    metadata_collector.track_stage_end("sbom_generation", success=True)
                else:
                    metadata_collector.capture_message(
                        "No validation report found, skipping SBOM generation",
                        "sbom_generation", ErrorSeverity.WARNING
                    )
                    metadata_collector.track_stage_end("sbom_generation", success=False, 
                                                     error_message="No validation report available")
            except Exception as e:
                metadata_collector.capture_error(e, "sbom_generation", 
                                               ErrorCategory.SBOM_GENERATION, ErrorSeverity.ERROR)
                metadata_collector.track_stage_end("sbom_generation", success=False, error_message=str(e))
        else:
            metadata_collector.skip_stage("sbom_generation", "User requested skip via --skip-sbom")

    except KeyboardInterrupt:
        metadata_collector.capture_message(
            "Scan interrupted by user (Ctrl+C)", "system", ErrorSeverity.WARNING
        )
        exit_code = 130
        console.print("\n⚠️ Scan interrupted by user", style="bold yellow")
    except Exception as e:
        metadata_collector.capture_error(e, "system", ErrorCategory.SYSTEM, ErrorSeverity.CRITICAL)
        exit_code = 1
        console.print(f"\n❌ Scan failed: {str(e)}", style="bold red")
    finally:
        # Phase 3: Always finalize and save metadata
        try:
            # Calculate comprehensive statistics
            scan_statistics = calculate_scan_statistics(dependencies_analysis, results, scores)
            metadata_collector.update_statistics(scan_statistics)
            
            # Collect all generated files
            generated_files = collect_generated_files(config)
            
            # Finalize metadata collection
            metadata = metadata_collector.finalize_metadata(
                output_files=generated_files,
                final_statistics=scan_statistics,
                exit_code=exit_code
            )
            
            # Save metadata file
            metadata_file = "scan_metadata.json"
            metadata_collector.save_metadata_file(metadata, metadata_file)
            
            if exit_code == 0:
                console.print(f"\n✅ ZSBOM scan completed successfully (ID: {scan_id[:8]})", style="bold green")
                console.print(f"📋 Scan metadata saved to {metadata_file}", style="dim")
            else:
                console.print(f"\n⚠️ ZSBOM scan completed with errors (ID: {scan_id[:8]})", style="bold yellow")
                console.print(f"📋 Scan metadata saved to {metadata_file}", style="dim")
        
        except Exception as meta_error:
            # Fallback: if metadata saving fails, try to save minimal metadata
            console.print(f"⚠️ Failed to save metadata: {str(meta_error)}", style="bold yellow")
            try:
                fallback_metadata = {
                    "scan_id": scan_id,
                    "execution": {
                        "status": "failed" if exit_code != 0 else "completed",
                        "exit_code": exit_code,
                        "metadata_error": str(meta_error)
                    }
                }
                with open("scan_metadata_fallback.json", "w") as f:
                    json.dump(fallback_metadata, f, indent=2)
                console.print("📋 Fallback metadata saved to scan_metadata_fallback.json", style="dim")
            except Exception:
                pass
        
        # NEW: Trace-AI Upload Integration (Phase 5)
        try:
            from depclass.upload import TraceAIUploadManager
            
            upload_manager = TraceAIUploadManager()
            if upload_manager.is_upload_enabled():
                console.print("\n🚀 Uploading to Zerberus Trace-AI...", style="bold blue")
                
                # Collect scan files with proper renaming
                scan_files = collect_scan_files_for_upload(config)
                
                if scan_files:
                    # Get final metadata for upload
                    final_metadata = metadata_collector.get_final_metadata() if hasattr(metadata_collector, 'get_final_metadata') else {}
                    
                    upload_result = upload_manager.execute_upload_workflow(
                        scan_files=scan_files,
                        scan_metadata=final_metadata
                    )
                    
                    if upload_result.success:
                        # Success message is displayed by orchestrator
                        pass
                    else:
                        if upload_result.skip_reason:
                            # Silent skip for missing environment
                            pass
                        else:
                            console.print(f"⚠️ Upload failed: {upload_result.error}", style="bold yellow")
                            console.print("ZSBOM completed normally despite upload failure", style="dim")
                else:
                    console.print("⚠️ No files available for upload", style="yellow")
                    
        except ImportError:
            # Upload module not available - silently continue
            pass
        except Exception as upload_error:
            console.print(f"⚠️ Upload failed: {str(upload_error)}", style="bold yellow")
            console.print("ZSBOM completed normally despite upload failure", style="dim")
        
        # Cleanup resources
        metadata_collector.cleanup()
    
    # Exit with appropriate code
    if exit_code != 0:
        sys.exit(exit_code)

if __name__ == "__main__":
    app()