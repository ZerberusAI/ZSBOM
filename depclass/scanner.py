"""
Simplified scanner service implementation for ZSBOM.
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
from depclass.rich_utils.ui_helpers import get_console
from depclass.config_manager import ConfigManager
from depclass.threshold_checker import ThresholdChecker, ThresholdConfig


class ScannerService:
    """Simplified scanner service implementation."""
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.console = get_console()
    
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
        metadata_collector = None
        
        try:
            # Load configuration
            config = self.config_manager.discover_and_load_config(config_path)
            config = self.config_manager.merge_config_and_args(config, output, ignore_conflicts)
            
            # Initialize metadata collection
            metadata_collector = MetadataCollector(config, self.console)
            scan_id = metadata_collector.start_collection()
            
            # Initialize cache if enabled
            cache = None
            if config['caching']['enabled']:
                os.makedirs(os.path.dirname(config['caching']['path']), exist_ok=True)
                cache = VulnerabilityCache(config['caching']['path'])
            
            # Extract dependencies
            try:
                dependencies = extract(config=config, cache=cache, ecosystem=ecosystem)
                dependency_data = dependencies.get("dependencies", dependencies)
                dependencies_analysis = dependencies.get("dependencies_analysis", {})
                
                # Display progress
                self._display_scan_progress(scan_id, dependencies_analysis)
                
            except Exception as e:
                metadata_collector.add_error("dependency_extraction", e)
                raise
            
            # Validate security
            try:
                results = validate(config, cache, dependencies_analysis)
            except Exception as e:
                metadata_collector.add_error("validation", e)
                results = {}
            
            # Check vulnerability thresholds
            threshold_result = self._check_vulnerability_thresholds(results)
            if threshold_result and threshold_result.should_fail_build:
                exit_code = 1
                self.console.print(f"\n❌ Build failed: {threshold_result.failure_reason}", style="bold red")
                metadata_collector.add_error("threshold_check", Exception(threshold_result.failure_reason))
                # Store threshold results for data-prefect-flow processing
                metadata_collector.set_threshold_failure(threshold_result)
            
            # Assess risk
            try:
                print("\n🎯 Running risk assessment...")
                scores = self.assess_risk(config, results, dependency_data, dependencies_analysis)
            except Exception as e:
                metadata_collector.add_error("risk_assessment", e)
                scores = []
            
            # Display risk results
            self._display_risk_results(scores, dependencies_analysis)
            
            # Save results
            self._save_results(config, results, scores, dependencies_analysis, metadata_collector)
            
            # Generate SBOM if not skipped
            if not skip_sbom:
                try:
                    if self.generate_sbom(config, dependencies_analysis, dependency_data):
                        sbom_file = config["output"].get("sbom_file", "sbom.json")
                        metadata_collector.add_generated_file(sbom_file)
                except Exception as e:
                    metadata_collector.add_error("sbom_generation", e)
            
        except KeyboardInterrupt:
            exit_code = 130
            self.console.print("\n⚠️ Scan interrupted by user", style="bold yellow")
        except Exception as e:
            exit_code = 1
            self.console.print(f"\n❌ Scan failed: {str(e)}", style="bold red")
        finally:
            # Save metadata
            if metadata_collector:
                try:
                    metadata_file = metadata_collector.save_metadata()
                    if exit_code == 0:
                        self.console.print(f"\n✅ ZSBOM scan completed successfully (ID: {scan_id[:8]})", style="bold green")
                    else:
                        self.console.print(f"\n⚠️ ZSBOM scan completed with errors (ID: {scan_id[:8]})", style="bold yellow")
                    self.console.print(f"📋 Scan metadata saved to {metadata_file}", style="dim")
                except Exception as e:
                    self.console.print(f"⚠️ Failed to save metadata: {str(e)}", style="bold yellow")
        
        return exit_code, metadata_collector.finalize_collection(exit_code) if metadata_collector else {}
    
    def _check_vulnerability_thresholds(self, validation_results: dict):
        """Check vulnerability thresholds from API configuration."""
        try:
            # Get threshold configuration from environment variables (set by GitHub Actions)
            import os
            api_url = os.getenv("ZERBERUS_API_URL")
            if not api_url:
                # No API URL configured, skip threshold checking
                return None
            
            # Load scan metadata to get threshold configuration
            try:
                with open("scan_metadata.json", "r") as f:
                    scan_metadata = json.load(f)
                    
                threshold_config_data = scan_metadata.get("threshold_config")
                if not threshold_config_data or not threshold_config_data.get("enabled", False):
                    # Threshold checking not enabled
                    return None
                    
                # Create threshold configuration
                threshold_config = ThresholdConfig(
                    enabled=threshold_config_data.get("enabled", False),
                    high_severity_weight=threshold_config_data.get("high_severity_weight", 5),
                    medium_severity_weight=threshold_config_data.get("medium_severity_weight", 3),
                    low_severity_weight=threshold_config_data.get("low_severity_weight", 1),
                    max_score_threshold=threshold_config_data.get("max_score_threshold", 50),
                    fail_on_critical=threshold_config_data.get("fail_on_critical", True),
                )
                
                # Create threshold checker and check thresholds
                checker = ThresholdChecker(threshold_config)
                result = checker.check_thresholds(validation_results)
                
                # Display threshold checking results
                if result:
                    self._display_threshold_results(result)
                
                return result
                
            except FileNotFoundError:
                # No scan metadata file, skip threshold checking
                return None
                
        except Exception as e:
            self.console.print(f"⚠️ Threshold checking failed: {str(e)}", style="bold yellow")
            return None
    
    def _display_threshold_results(self, result):
        """Display threshold checking results."""
        self.console.print("\n🎯 Vulnerability Threshold Check:", style="bold blue")
        self.console.print("=" * 50)
        
        counts = result.vulnerability_counts
        self.console.print(f"   🔴 Critical: {counts.critical}")
        self.console.print(f"   🟠 High: {counts.high}")  
        self.console.print(f"   🟡 Medium: {counts.medium}")
        self.console.print(f"   🟢 Low: {counts.low}")
        
        self.console.print(f"\n   📊 Calculated Score: {result.calculated_score}")
        self.console.print(f"   🎯 Max Threshold: {result.max_threshold}")
        
        if result.should_fail_build:
            if result.critical_vulnerabilities_found:
                self.console.print("   ❌ CRITICAL VULNERABILITIES DETECTED - Build will fail", style="bold red")
            if result.threshold_exceeded:
                self.console.print(f"   ❌ THRESHOLD EXCEEDED ({result.calculated_score} > {result.max_threshold}) - Build will fail", style="bold red")
        else:
            self.console.print("   ✅ Vulnerability thresholds PASSED", style="bold green")
        
        print()
    
    def assess_risk(self, config: dict, results: dict, dependency_data: dict, dependencies_analysis: dict) -> list:
        """Assess risk for dependencies."""
        try:
            model = load_model(config.get("risk_model"))
            return score_packages(results, dependency_data, dependencies_analysis, model, config)
        except Exception:
            return []
    
    def generate_sbom(self, config: dict, dependencies_analysis: dict, dependency_data: dict) -> bool:
        """Generate Software Bill of Materials."""
        try:
            cve_data = read_json_file("validation_report.json")
            if cve_data:
                # Use total packages from dependencies analysis
                sbom_dependencies = {}
                for pkg_key, pkg_version in dependencies_analysis.get("resolution_details", {}).items():
                    sbom_dependencies[pkg_key.lower()] = pkg_version
                
                if not sbom_dependencies:
                    sbom_dependencies = dependency_data
                
                generate(sbom_dependencies, cve_data, config)
                return True
            return False
        except Exception:
            return False
    
    def _save_results(self, config: dict, results: dict, scores: list, dependencies_analysis: dict, metadata_collector: MetadataCollector):
        """Save scan results to files."""
        # Save risk assessment results
        try:
            risk_file = config["output"].get("risk_file", "risk_report.json")
            with open(risk_file, "w") as fp:
                json.dump(scores, fp, indent=4)
            metadata_collector.add_generated_file(risk_file)
            self.console.print(f"✅ Risk assessment completed. Results saved in `{risk_file}`.")
        except Exception as e:
            metadata_collector.add_error("output_generation", e)
        
        # Save dependencies analysis results if available
        if dependencies_analysis:
            try:
                dependencies_output_file = config["output"].get("dependencies_file", "dependencies.json")
                analysis_data = dependencies_analysis.get("dependencies_analysis", dependencies_analysis)
                with open(dependencies_output_file, "w") as fp:
                    json.dump(analysis_data, fp, indent=4)
                metadata_collector.add_generated_file(dependencies_output_file)
                self.console.print(f"📊 Dependencies analysis results saved to {dependencies_output_file}")
            except Exception as e:
                metadata_collector.add_error("output_generation", e)
    
    def _display_scan_progress(self, scan_id: str, dependencies_analysis: dict):
        """Display scan progress information."""
        self.console.print(f"🚀 ZSBOM scan started (ID: {scan_id[:8]})", style="bold blue")
        
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
        
        # Calculate summary statistics
        high_risk = [s for s in scores if s['risk_level'] == 'high']
        medium_risk = [s for s in scores if s['risk_level'] == 'medium'] 
        low_risk = [s for s in scores if s['risk_level'] == 'low']
        
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