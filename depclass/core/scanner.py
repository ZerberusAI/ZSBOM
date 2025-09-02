"""
Scanner service implementation for ZSBOM.

"""
import json
import os
import sys
from typing import Dict, List, Optional, Tuple

from depclass.db.vulnerability import VulnerabilityCache
from depclass.extract import extract
from depclass.risk import score_packages
from depclass.risk_model import load_model
from depclass.sbom import generate, read_json_file
from depclass.validate import validate
from depclass.metadata import MetadataCollector
from depclass.metadata.error_tracker import ErrorSeverity, ErrorCategory
from depclass.rich_utils.ui_helpers import get_console

from depclass.core.config_manager import ConfigManager
from depclass.core.file_manager import FileManager
from depclass.core.statistics import StatisticsCalculator


class ScannerService:
    """Concrete implementation of scanner service."""
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.file_manager = FileManager()
        self.statistics_calculator = StatisticsCalculator()
        self.console = get_console()
    
    def initialize_scan(
        self, 
        config_path: Optional[str],
        output: Optional[str],
        skip_sbom: bool,
        ignore_conflicts: bool,
        ecosystem: str
    ) -> Tuple[dict, str]:
        """Initialize scan with configuration and parameters."""
        
        # Load and merge configuration
        config = self.config_manager.discover_and_load_config(config_path)
        config = self.config_manager.merge_config_and_args(config, output, ignore_conflicts)
        
        # Initialize metadata collection framework
        metadata_collector = MetadataCollector(config, self.console)
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
        
        return config, scan_id
    
    def extract_dependencies(
        self, 
        config: dict, 
        cache: Optional[object], 
        ecosystem: str
    ) -> Tuple[dict, dict]:
        """Extract dependencies from the project."""
        
        dependencies = extract(config=config, cache=cache, ecosystem=ecosystem)
        dependency_data = dependencies.get("dependencies", dependencies)
        dependencies_analysis = dependencies.get("dependencies_analysis", {})
        
        return dependency_data, dependencies_analysis
    
    def validate_security(
        self, 
        config: dict, 
        cache: Optional[object], 
        dependencies_analysis: dict
    ) -> dict:
        """Validate dependencies for security issues."""
        
        try:
            return validate(config, cache, dependencies_analysis)
        except Exception:
            # Return empty results if validation fails
            return {}
    
    def assess_risk(
        self, 
        config: dict,
        results: dict, 
        dependency_data: dict, 
        dependencies_analysis: dict
    ) -> list:
        """Assess risk for dependencies."""
        
        try:
            model = load_model(config.get("risk_model"))
            return score_packages(results, dependency_data, dependencies_analysis, model, config)
        except Exception:
            # Return empty scores if risk assessment fails
            return []
    
    def generate_sbom(
        self, 
        config: dict,
        dependencies_analysis: dict, 
        dependency_data: dict
    ) -> bool:
        """Generate Software Bill of Materials."""
        
        try:
            cve_data = read_json_file("validation_report.json")
            if cve_data:
                # Use total packages from dependencies analysis for complete dependency coverage
                sbom_dependencies = {}
                for pkg_key, pkg_version in dependencies_analysis.get("resolution_details", {}).items():
                    sbom_dependencies[pkg_key.lower()] = pkg_version
                
                # Fallback to original dependency data if no resolved versions found
                if not sbom_dependencies:
                    sbom_dependencies = dependency_data
                
                generate(sbom_dependencies, cve_data, config)
                return True
            return False
        except Exception:
            return False
    
    def save_results(
        self, 
        config: dict,
        results: dict,
        scores: list, 
        dependencies_analysis: dict,
        metadata_collector: MetadataCollector
    ) -> List[str]:
        """Save scan results to files."""
        
        generated_files = []
        
        # Save risk assessment results
        try:
            risk_file = config["output"].get("risk_file", "risk_report.json")
            with open(risk_file, "w") as fp:
                json.dump(scores, fp, indent=4)
            metadata_collector.add_generated_file(risk_file)
            generated_files.append(risk_file)
            self.console.print(f"✅ Risk assessment completed. Results saved in `{risk_file}`.")
        except Exception as e:
            metadata_collector.capture_error(e, "output_generation", 
                                           ErrorCategory.SYSTEM, ErrorSeverity.ERROR)
        
        # Save dependencies analysis results if available
        if "dependencies_analysis" in dependencies_analysis or dependencies_analysis:
            try:
                dependencies_output_file = config["output"].get("dependencies_file", "dependencies.json")
                # Handle case where dependencies_analysis might be nested
                analysis_data = dependencies_analysis.get("dependencies_analysis", dependencies_analysis)
                with open(dependencies_output_file, "w") as fp:
                    json.dump(analysis_data, fp, indent=4)
                metadata_collector.add_generated_file(dependencies_output_file)
                generated_files.append(dependencies_output_file)
                self.console.print(f"📊 Dependencies analysis results saved to {dependencies_output_file}")
            except Exception as e:
                metadata_collector.capture_error(e, "output_generation", 
                                               ErrorCategory.SYSTEM, ErrorSeverity.ERROR)
        
        return generated_files
    
    def _display_scan_progress(self, scan_id: str, dependencies_analysis: dict):
        """Display scan progress information."""
        self.console.print(f"🚀 ZSBOM scan started (ID: {scan_id[:8]})", style="bold blue")
        
        # Calculate and display dependency counts
        dependency_tree = dependencies_analysis.get("dependency_tree", {})
        total_packages = dependencies_analysis.get("total_packages", 0)
        
        direct_count = len([pkg for pkg, info in dependency_tree.items() if info.get("type") == "direct"])
        transitive_count = total_packages - direct_count
        print(f"{direct_count} direct dependencies")
        print(f"{transitive_count} transitive dependencies")
    
    def _display_risk_results(self, scores: list, dependencies_analysis: dict):
        """Display risk assessment results."""
        if not scores:
            return
            
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
        dependency_tree = dependencies_analysis.get("dependency_tree", {})
        total_packages = dependencies_analysis.get("total_packages", 0)
        
        direct_count = len([pkg for pkg, info in dependency_tree.items() if info.get("type") == "direct"])
        transitive_count = total_packages - direct_count
        
        print("📈 Risk Assessment Summary:")
        print(f"   🔴 High Risk: {len(high_risk)} packages")
        print(f"   🟡 Medium Risk: {len(medium_risk)} packages") 
        print(f"   🟢 Low Risk: {len(low_risk)} packages")
        print(f"   📦 Direct Dependencies: {direct_count} packages")
        print(f"   ⬇️ Transitive Dependencies: {transitive_count} packages")
        print(f"   📊 Total Analyzed: {len(scores)} packages")
        print()

    def execute_scan(
        self, 
        config_path: Optional[str] = None,
        output: Optional[str] = None,
        skip_sbom: bool = False,
        ignore_conflicts: bool = False,
        ecosystem: str = "python"
    ) -> Tuple[int, dict]:
        """Execute complete scan workflow."""
        
        exit_code = 0
        dependencies_analysis = {}
        results = {}
        scores = []
        metadata_collector = None
        
        try:
            # Initialize scan
            config, scan_id = self.initialize_scan(
                config_path, output, skip_sbom, ignore_conflicts, ecosystem
            )
            
            # Initialize metadata collector
            metadata_collector = MetadataCollector(config, self.console)
            metadata_collector.start_collection()
            
            # Initialize cache if enabled
            cache = None
            if config['caching']['enabled']:
                os.makedirs(os.path.dirname(config['caching']['path']), exist_ok=True)
                cache = VulnerabilityCache(config['caching']['path'])
            
            # Track dependency extraction stage
            metadata_collector.track_stage_start("dependency_extraction", {
                "ecosystem": ecosystem,
                "cache_enabled": config['caching']['enabled']
            })
            
            try:
                dependency_data, dependencies_analysis = self.extract_dependencies(config, cache, ecosystem)
                metadata_collector.track_stage_end("dependency_extraction", success=True)
            except Exception as e:
                metadata_collector.capture_error(e, "dependency_extraction", 
                                               ErrorCategory.DEPENDENCY_EXTRACTION, ErrorSeverity.CRITICAL)
                metadata_collector.track_stage_end("dependency_extraction", success=False, error_message=str(e))
                raise
            
            # Display progress
            self._display_scan_progress(scan_id, dependencies_analysis)
            
            # Track validation stage
            metadata_collector.track_stage_start("validation", {
                "total_packages": dependencies_analysis.get("total_packages", 0),
                "direct_packages": len([pkg for pkg, info in dependencies_analysis.get("dependency_tree", {}).items() if info.get("type") == "direct"]),
                "transitive_packages": dependencies_analysis.get("total_packages", 0) - len([pkg for pkg, info in dependencies_analysis.get("dependency_tree", {}).items() if info.get("type") == "direct"])
            })
            
            try:
                results = self.validate_security(config, cache, dependencies_analysis)
                metadata_collector.track_stage_end("validation", success=True)
            except Exception as e:
                metadata_collector.capture_error(e, "validation", 
                                               ErrorCategory.VALIDATION, ErrorSeverity.ERROR)
                metadata_collector.track_stage_end("validation", success=False, error_message=str(e))
                results = {}
            
            # Track risk assessment stage
            metadata_collector.track_stage_start("risk_assessment")
            
            try:
                print("\n🎯 Running risk assessment...")
                scores = self.assess_risk(config, results, dependency_data, dependencies_analysis)
                metadata_collector.track_stage_end("risk_assessment", success=True)
            except Exception as e:
                metadata_collector.capture_error(e, "risk_assessment", 
                                               ErrorCategory.RISK_ASSESSMENT, ErrorSeverity.ERROR)
                metadata_collector.track_stage_end("risk_assessment", success=False, error_message=str(e))
                scores = []
            
            # Display risk results
            self._display_risk_results(scores, dependencies_analysis)
            
            # Save results
            generated_files = self.save_results(config, results, scores, dependencies_analysis, metadata_collector)
            
            # Generate SBOM if not skipped
            if not skip_sbom:
                metadata_collector.track_stage_start("sbom_generation")
                
                try:
                    if self.generate_sbom(config, dependencies_analysis, dependency_data):
                        sbom_file = config["output"].get("sbom_file", "sbom.json")
                        metadata_collector.add_generated_file(sbom_file)
                        generated_files.append(sbom_file)
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
            if metadata_collector:
                metadata_collector.capture_message(
                    "Scan interrupted by user (Ctrl+C)", "system", ErrorSeverity.WARNING
                )
            exit_code = 130
            self.console.print("\n⚠️ Scan interrupted by user", style="bold yellow")
        except Exception as e:
            if metadata_collector:
                metadata_collector.capture_error(e, "system", ErrorCategory.SYSTEM, ErrorSeverity.CRITICAL)
            exit_code = 1
            self.console.print(f"\n❌ Scan failed: {str(e)}", style="bold red")
        finally:
            # Finalize metadata collection
            if metadata_collector:
                try:
                    # Calculate comprehensive statistics
                    scan_statistics = self.statistics_calculator.calculate_scan_statistics(
                        dependencies_analysis, results, scores
                    )
                    metadata_collector.update_statistics(scan_statistics)
                    
                    # Collect all generated files
                    generated_files = self.file_manager.collect_generated_files(config)
                    
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
                        self.console.print(f"\n✅ ZSBOM scan completed successfully (ID: {scan_id[:8]})", style="bold green")
                        self.console.print(f"📋 Scan metadata saved to {metadata_file}", style="dim")
                        self.console.print("\n💡 To upload results to Zerberus platform, run: zsbom upload", style="dim")
                    else:
                        self.console.print(f"\n⚠️ ZSBOM scan completed with errors (ID: {scan_id[:8]})", style="bold yellow")
                        self.console.print(f"📋 Scan metadata saved to {metadata_file}", style="dim")
                
                except Exception as meta_error:
                    # Fallback: if metadata saving fails, try to save minimal metadata
                    self.console.print(f"⚠️ Failed to save metadata: {str(meta_error)}", style="bold yellow")
                    try:
                        fallback_metadata = {
                            "scan_id": scan_id if 'scan_id' in locals() else "unknown",
                            "execution": {
                                "status": "failed" if exit_code != 0 else "completed",
                                "exit_code": exit_code,
                                "metadata_error": str(meta_error)
                            }
                        }
                        with open("scan_metadata_fallback.json", "w") as f:
                            json.dump(fallback_metadata, f, indent=2)
                        self.console.print("📋 Fallback metadata saved to scan_metadata_fallback.json", style="dim")
                    except Exception:
                        pass
                
                # Cleanup resources
                metadata_collector.cleanup()
        
        return exit_code, metadata.get('metadata', {}) if 'metadata' in locals() else {}