"""
Simplified scanner service implementation for ZSBOM.
"""
import json
import os
from typing import Optional, Tuple

from rich.table import Table

from depclass.db.vulnerability import VulnerabilityCache
from depclass.extract import extract
from depclass.enhancers.orchestrator import EnhancerOrchestrator
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
        ignore_conflicts: bool = False
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
                dependencies = extract(config=config, cache=cache)
                dependency_data = dependencies.get("dependencies", dependencies)
                dependencies_analysis = dependencies.get("dependencies_analysis", {})

                # Check if repository uses unsupported ecosystems
                if dependencies_analysis.get("unsupported_repo", False):
                    self.console.print("\nℹ️  This repository does not contain supported package ecosystems", style="bold blue")
                    self.console.print(f"📦 Currently supported: {', '.join(dependencies_analysis.get('supported_ecosystems', []))}", style="dim")
                    self.console.print("💡 ZSBOM will skip security analysis for this repository", style="dim")

                    # Save metadata with unsupported repo status
                    metadata_collector.update_statistics({
                        "repository_status": "unsupported_ecosystems",
                        "unsupported_repo": True,
                        "supported_ecosystems": dependencies_analysis.get('supported_ecosystems', []),
                        "status_message": dependencies_analysis.get('status_message', 'No supported ecosystems detected')
                    })
                    metadata_file = metadata_collector.save_metadata()

                    self.console.print(f"\n✅ Scan completed - No supported ecosystems detected (ID: {scan_id[:8]})", style="bold green")
                    self.console.print(f"📋 Scan metadata saved to {metadata_file}", style="dim")

                    # Return exit code 0 (success) with metadata indicating unsupported repo
                    return 0, metadata_collector.finalize_collection(0)

                # Display progress
                self._display_scan_progress(scan_id, dependencies_analysis)

            except Exception as e:
                metadata_collector.add_error("dependency_extraction", e)
                raise

            # Enhance dependencies with external data (NEW PHASE)
            try:
                print("\n🔍 Enhancing dependencies with external data...")
                enhanced_dependencies = self._enhance_dependencies(dependencies_analysis, config, cache)

                # Merge enhanced data back into dependencies analysis
                dependencies_analysis["enhanced_data"] = enhanced_dependencies.get("enhanced_data", {})
                dependencies_analysis["enhancement_metadata"] = enhanced_dependencies.get("enhancement_metadata", {})


            except Exception as e:
                import traceback
                traceback.print_exc()
                metadata_collector.add_error("dependency_enhancement", e)
                self.console.print(f"⚠️ Dependency enhancement failed: {e}", style="yellow")
                # Continue with unenhanced data
                dependencies_analysis["enhanced_data"] = {}
                dependencies_analysis["enhancement_metadata"] = {}

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
            # Load scan metadata to get threshold configuration from API
            try:
                with open("scan_metadata.json", "r") as f:
                    scan_metadata = json.load(f)

                threshold_config_data = scan_metadata.get("threshold_config")
                if not threshold_config_data or not threshold_config_data.get("enabled", False):
                    # Threshold checking not enabled by API
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
                # No scan metadata file - unable to reach Zerberus server
                self.console.print("⚠️  Unable to reach Zerberus server for threshold validation", style="bold yellow")
                self.console.print("   Pipeline will continue without threshold checks", style="dim")
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
    
    def _enhance_dependencies(self, dependencies_analysis: dict, config: dict, cache) -> dict:
        """Enhance dependencies with external data using the enhancer system."""
        try:
            # Initialize enhancer orchestrator with full config
            orchestrator = EnhancerOrchestrator(config, cache)

            # Enhance all dependencies
            enhanced_data = orchestrator.enhance_dependencies(dependencies_analysis)

            # Display enhancement statistics
            stats = orchestrator.get_enhancement_statistics()
            self.console.print(f"   📦 Enhanced {stats['enhanced_packages']}/{stats['total_packages']} packages")
            self.console.print(f"   🎯 Success rate: {stats['success_rate']:.1f}%")
            if stats['cache_hits'] > 0:
                self.console.print(f"   💾 Cache hits: {stats['cache_hits']} ({stats['cache_hit_rate']:.1f}%)")

            return enhanced_data

        except Exception as e:
            import traceback
            traceback.print_exc()
            self.console.print(f"⚠️ Enhancement failed: {e}", style="yellow")
            return {"enhanced_data": {}, "enhancement_metadata": {}}

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
            # Pass transitive analysis directly to the ecosystem-aware generate function
            generate(dependencies_analysis, config)
            return True
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

    def _get_classification(self, dependencies_analysis: dict) -> dict:
        """Get or build classification dictionary from dependency_tree structure (cached).

        Args:
            dependencies_analysis: Dependencies analysis data containing dependency_tree

        Returns:
            Dictionary mapping ecosystem -> package_name -> dependency_type (direct/transitive)
        """
        # Build classification once from dependency_tree
        classification = {}
        dependency_tree = dependencies_analysis.get("dependency_tree", {})
        for ecosystem, packages in dependency_tree.items():
            classification[ecosystem] = {}
            for pkg_key, pkg_info in packages.items():
                pkg_name = pkg_key.split("==")[0] if "==" in pkg_key else pkg_key
                classification[ecosystem][pkg_name] = pkg_info.get("type", "unknown")
        return classification

    def _count_dependencies(self, classification: dict) -> tuple:
        """Count total, direct, and transitive dependencies from classification.

        Args:
            classification: Classification dictionary

        Returns:
            Tuple of (total_packages, direct_count, transitive_count)
        """
        total_packages = 0
        direct_count = 0
        transitive_count = 0

        for ecosystem, packages in classification.items():
            if isinstance(packages, dict):
                for pkg, dep_type in packages.items():
                    total_packages += 1
                    if dep_type == "direct":
                        direct_count += 1
                    elif dep_type == "transitive":
                        transitive_count += 1

        return total_packages, direct_count, transitive_count

    def _display_scan_progress(self, scan_id: str, dependencies_analysis: dict):
        """Display scan progress information."""
        self.console.print(f"🚀 ZSBOM scan started (ID: {scan_id[:8]})", style="bold blue")

        # Get classification and count dependencies
        classification = self._get_classification(dependencies_analysis)
        total_packages, direct_count, transitive_count = self._count_dependencies(classification)

        print(f"{direct_count} direct dependencies")
        print(f"{transitive_count} transitive dependencies")
    
    def _display_risk_results(self, scores: list, dependencies_analysis: dict):
        """Display risk assessment results using Rich table."""
        if not scores:
            return

        # Filter high risk packages for table display
        high_risk_scores = [s for s in scores if s['risk_level'] == 'high']

        if high_risk_scores:
            self.console.print("\n📊 Risk Assessment Results:", style="bold blue")

            # Create table
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Package", style="white", no_wrap=False, width=25)
            table.add_column("Score", justify="right", style="white", width=7)
            table.add_column("Risk", justify="center", style="white", width=6)
            table.add_column("Type", justify="center", style="white", width=15)
            table.add_column("Decl/In", justify="right", style="white", width=7)
            table.add_column("CVEs", justify="right", style="white", width=6)
            table.add_column("CWE", justify="right", style="white", width=5)
            table.add_column("Abandon", justify="right", style="white", width=8)
            table.add_column("Typosquat", justify="right", style="white", width=9)

            # Add rows for each high-risk package
            for score in high_risk_scores:
                package = score['package']
                final_score = score['final_score']
                risk_level = score['risk_level']
                dependency_type = score.get('dependency_type', 'unknown')
                dimensions = score['dimension_scores']

                # Risk emoji and styling
                risk_emoji = "🔴" if risk_level == "high" else "🟡" if risk_level == "medium" else "🟢"
                type_indicator = "📦" if dependency_type == "direct" else "⬇️" if dependency_type == "transitive" else "❓"

                # Add row
                table.add_row(
                    f"{risk_emoji} {package}",
                    f"{final_score:.1f}",
                    risk_level.upper(),
                    f"{type_indicator} {dependency_type.upper()}",
                    f"{dimensions['declared_vs_installed']:.1f}",
                    f"{dimensions['known_cves']:.1f}",
                    f"{dimensions['cwe_coverage']:.1f}",
                    f"{dimensions['package_abandonment']:.1f}",
                    f"{dimensions['typosquat_heuristics']:.1f}"
                )

            self.console.print(table)

        # Calculate summary statistics
        high_risk = [s for s in scores if s['risk_level'] == 'high']
        medium_risk = [s for s in scores if s['risk_level'] == 'medium']
        low_risk = [s for s in scores if s['risk_level'] == 'low']

        # Get classification and count dependencies
        classification = self._get_classification(dependencies_analysis)
        total_packages, direct_count, transitive_count = self._count_dependencies(classification)

        self.console.print("\n📈 Risk Assessment Summary:", style="bold blue")
        self.console.print(f"   🔴 High Risk: {len(high_risk)} packages")
        self.console.print(f"   🟡 Medium Risk: {len(medium_risk)} packages")
        self.console.print(f"   🟢 Low Risk: {len(low_risk)} packages")
        self.console.print(f"   📦 Direct Dependencies: {direct_count} packages")
        self.console.print(f"   ⬇️ Transitive Dependencies: {transitive_count} packages")
        self.console.print(f"   📊 Total Analyzed: {len(scores)} packages")
        self.console.print()
