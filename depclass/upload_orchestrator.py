"""
Simplified Upload Orchestrator for Trace-AI with Rich UI.
"""
import time
import os
import json
import re
from dataclasses import asdict
from datetime import datetime
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from depclass.upload.models import (
    TraceAIConfig,
    UploadResult,
    ThresholdResult,
    RepositoryMetadata,
    ScanMetadata,
    ScanInitiationRequest,
    CompletionRequest,
    UploadStatus,
    UploadSummary
)
from depclass.upload.api_client import ZerberusAPIClient
from depclass.threshold_checker import ThresholdChecker, ThresholdConfig as ZSBOMThresholdConfig
from depclass.github.pr_comment_generator import PRCommentGenerator



def _s3_error_reason(response) -> str:
    """S3 explains presigned POST rejections in an XML <Error> body."""
    body = response.text or ""
    parts = [
        match.group(1)
        for match in (
            re.search(r"<Code>(.*?)</Code>", body),
            re.search(r"<Message>(.*?)</Message>", body),
        )
        if match
    ]
    return ": ".join(parts) if parts else (body[:300] or response.reason or "no details")


class UploadOrchestrator:
    """Simplified upload orchestrator with Rich UI progress tracking."""
    
    def __init__(self, config: TraceAIConfig, console: Console = None):
        self.config = config
        self.console = console or Console()
        self.metadata_collector = None
    
    def set_metadata_collector(self, metadata_collector):
        """Set the metadata collector to update with remote scan ID."""
        self.metadata_collector = metadata_collector
    
    def execute_upload_workflow(self, scan_files: Dict[str, str], scan_metadata: dict) -> UploadResult:
        """Upload the scan files, acknowledge the upload, and report exactly what happened."""
        start_time = time.time()
        threshold_result = None
        report_url = None
        scan_id = None
        file_results: List[Dict] = []

        try:
            # Basic file validation
            valid_files = {k: v for k, v in scan_files.items() if os.path.exists(v)}
            if not valid_files:
                return UploadResult(success=False, error="No valid files found for upload")

            # Phase 1: Initiate scan
            self.console.print("🚀 Initiating scan with Zerberus...", style="cyan")
            scan_id = self._initiate_scan(scan_metadata)
            self.console.print(f"✅ Scan initiated: {scan_id[:8]}...", style="green")

            # Update scan_metadata.json with API scan_id and threshold config before uploading
            if "scan_metadata.json" in valid_files:
                self._update_metadata_file(valid_files["scan_metadata.json"], scan_id, scan_metadata)

            # Phase 2: Upload files with progress
            self.console.print("📤 Uploading files...", style="cyan")
            file_results = self._upload_files_with_progress(scan_id, valid_files)
            failed_files = [f for f in file_results if not f.get("success")]
            if failed_files:
                self.console.print(
                    f"❌ Upload incomplete ({len(file_results) - len(failed_files)}/{len(file_results)} files):",
                    style="bold red",
                )
                for failed in failed_files:
                    self.console.print(f"   • {failed['filename']}: {failed.get('error', 'unknown error')}", style="red")

            # Phase 3: The threshold check reads the local validation report,
            # so it doesn't depend on the upload having worked.
            threshold_result = self._run_threshold_validation()

            # Phase 4: Always acknowledge, so the server records a failed
            # upload and why, instead of leaving the scan in progress.
            report_url = self._complete_upload(scan_id, file_results)

            if failed_files:
                return UploadResult(
                    success=False,
                    scan_id=scan_id,
                    report_url=report_url,
                    error=f"Upload incomplete: {len(failed_files)} of {len(file_results)} files failed",
                    file_results=file_results,
                    total_time_seconds=time.time() - start_time,
                    threshold_result=threshold_result,
                )

            self.console.print("✅ Upload completed successfully!", style="bold green")
            self.console.print(f"📊 Report URL: {report_url}", style="green")

            if threshold_result:
                if threshold_result.should_fail_build:
                    self.console.print(f"❌ Threshold exceeded: {threshold_result.failure_reason}", style="bold red")
                else:
                    self.console.print(
                        f"✅ CVE threshold passed (CVE severity score: {threshold_result.calculated_score}/{threshold_result.max_threshold})",
                        style="green",
                    )

            return UploadResult(
                success=True,
                scan_id=scan_id,
                report_url=report_url,
                file_results=file_results,
                total_time_seconds=time.time() - start_time,
                threshold_result=threshold_result,
            )

        except Exception as e:
            self.console.print(f"❌ Upload failed: {str(e)}", style="red")
            return UploadResult(
                success=False,
                scan_id=scan_id,
                error=str(e),
                file_results=file_results or None,
                threshold_result=threshold_result,
            )

        finally:
            # Phase 5: Generate PR comment for GitHub Actions (only for pull requests)
            if scan_metadata.get("ci_context", {}).get("is_ci") and \
               scan_metadata.get("ci_context", {}).get("event_type") == "pull_request":
                try:
                    # Use fallback URL if report_url wasn't set (upload failed)
                    # Read dashboard URL from environment or use default
                    dashboard_base_url = os.getenv("ZERBERUS_DASHBOARD_URL", "https://app.zerberus.ai")
                    final_report_url = report_url if report_url else f"{dashboard_base_url}/trace-ai/dashboard"
                    self._generate_pr_comment_file(scan_metadata, threshold_result, final_report_url)
                except Exception as comment_error:
                    # Don't fail the entire upload if PR comment generation fails
                    self.console.print(f"⚠️ Failed to generate PR comment: {str(comment_error)}", style="yellow")

    def _initiate_scan(self, scan_metadata: dict) -> str:
        """Initiate scan using enhanced metadata and proper dataclass objects."""
        
        # Use repository info from enhanced metadata if available
        repo_info = scan_metadata.get("repository", {})
        ci_context = scan_metadata.get("ci_context", {})
        
        # Extract repository name and namespace from remote URL or use current directory
        repo_name = os.path.basename(os.getcwd())
        scm_namespace = "local"
        scm_platform = "local"
        
        if repo_info.get("remote_url"):
            remote_url = repo_info["remote_url"]
            
            # Parse Git remote URL patterns
            # git@github.com:ZerberusAI/ZSBOM.git or https://github.com/ZerberusAI/ZSBOM.git
            if "github.com" in remote_url:
                scm_platform = "github"
                # Extract namespace and repo name
                match = re.search(r"[:/]([^/]+)/([^/]+?)(?:\.git)?$", remote_url)
                if match:
                    scm_namespace = match.group(1)
                    repo_name = match.group(2)
            elif "gitlab.com" in remote_url:
                scm_platform = "gitlab"
                match = re.search(r"[:/]([^/]+)/([^/]+?)(?:\.git)?$", remote_url)
                if match:
                    scm_namespace = match.group(1)
                    repo_name = match.group(2)
        
        # Create RepositoryMetadata object
        repo_metadata = RepositoryMetadata(
            name=repo_name,
            scm_platform=scm_platform,
            scm_namespace=scm_namespace,
            scm_repository=repo_name,
            scm_url=repo_info.get("remote_url", f"file://{os.getcwd()}"),
            default_branch="main"
        )
        
        # Determine trigger type based on CI context
        trigger_type = "manual"
        if ci_context.get("is_ci"):
            # Get the raw trigger type from CI context
            raw_trigger_type = ci_context.get("event_type", "push")

            # Map CI platform event types to backend's expected enum values
            trigger_type_mapping = {
                # GitHub Actions events
                "pull_request": "pull_request",
                "push": "push",
                "schedule": "schedule",
                "workflow_dispatch": "manual",
                
                # GitLab CI events
                "merge_request": "pull_request",
                
                # Default for other CI events
                "release": "push",
                "deployment": "push",
            }
            
            # Default to "push" for unknown CI events (not "automated")
            trigger_type = trigger_type_mapping.get(raw_trigger_type, "push")
        
        # Parse started_at timestamp
        started_at = None
        if scan_metadata.get("execution", {}).get("started_at"):
            try:
                started_at_str = scan_metadata["execution"]["started_at"]
                # Handle both with and without microseconds
                if "." in started_at_str:
                    started_at = datetime.fromisoformat(started_at_str.replace('Z', '+00:00'))
                else:
                    started_at = datetime.fromisoformat(started_at_str + "+00:00")
            except ValueError:
                started_at = datetime.utcnow()
        else:
            started_at = datetime.utcnow()
        
        # Create ScanMetadata object with Git and CI info
        scan_meta = ScanMetadata(
            branch=repo_info.get("branch"),
            commit_sha=repo_info.get("commit_sha"),
            trigger_type=trigger_type,
            started_at=started_at,
            environment=scan_metadata.get("environment", {}),
            local_execution=not ci_context.get("is_ci", False),
            pr_number=ci_context.get("pr_number")
        )
        
        # Create request object
        request = ScanInitiationRequest(
            repository_metadata=repo_metadata,
            scan_metadata=scan_meta
        )
        
        with ZerberusAPIClient(self.config) as client:
            response = client.initiate_scan(request)
            remote_scan_id = response.scan_id
            
            # Store threshold configuration for later use
            self._threshold_config = response.threshold_config
            
            # Update metadata collector with API scan_id
            if self.metadata_collector:
                self.metadata_collector.update_scan_id(remote_scan_id)
            
            return remote_scan_id
    
    def _upload_files_with_progress(self, scan_id: str, file_paths: Dict[str, str]) -> List[Dict]:
        """Upload files in parallel with Rich progress visualization."""
        file_results = []
        
        try:
            # Get upload URLs for all files at once
            with ZerberusAPIClient(self.config) as client:
                upload_urls_response = client.get_upload_urls(scan_id, list(file_paths.keys()))
                upload_urls = upload_urls_response.upload_urls
            
            # Use Rich progress bar for visual feedback
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                upload_task = progress.add_task("Uploading files...", total=len(file_paths))
                
                # Upload files in parallel using ThreadPoolExecutor
                max_workers = min(self.config.parallel_uploads, len(file_paths))
                
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    # Submit all upload tasks
                    future_to_filename = {}
                    
                    for filename, filepath in file_paths.items():
                        if filename not in upload_urls:
                            file_results.append({
                                "filename": filename,
                                "success": False,
                                "error": f"No upload URL provided for {filename}"
                            })
                            progress.advance(upload_task)
                            continue
                        
                        presigned_url = upload_urls[filename]
                        future = executor.submit(self._upload_single_file, filename, filepath, presigned_url)
                        future_to_filename[future] = filename
                    
                    # Process completed uploads
                    for future in as_completed(future_to_filename):
                        filename = future_to_filename[future]
                        
                        try:
                            result = future.result()
                            file_results.append(result)
                            
                            # Update progress with current file
                            status = "✅" if result["success"] else "❌"
                            progress.update(upload_task, description=f"{status} {filename}")
                            
                        except Exception as e:
                            file_results.append({
                                "filename": filename,
                                "success": False,
                                "error": str(e)
                            })
                            progress.update(upload_task, description=f"❌ {filename}")
                        
                        progress.advance(upload_task)
            
        except Exception as e:
            # If getting upload URLs fails, mark all files as failed
            for filename in file_paths.keys():
                file_results.append({
                    "filename": filename,
                    "success": False,
                    "error": f"Failed to get upload URLs: {str(e)}"
                })
        
        return file_results
    
    def _upload_single_file(self, filename: str, filepath: str, presigned_url) -> Dict:
        """Upload a single file to S3 using presigned URL."""
        try:
            # Read file data
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            # Prepare the upload data
            files = {'file': (filename, file_data)}
            data = presigned_url.fields if presigned_url.fields else {}

            # Upload to S3
            response = requests.post(presigned_url.url, data=data, files=files)
            if not response.ok:
                return {
                    "filename": filename,
                    "success": False,
                    "error": f"S3 rejected the upload ({response.status_code}): {_s3_error_reason(response)}",
                }
            
            return {
                "filename": filename,
                "success": True,
                "size_bytes": len(file_data)
            }
            
        except Exception as e:
            return {
                "filename": filename,
                "success": False,
                "error": str(e)
            }
    
    def _complete_upload(self, scan_id: str, file_results: List[Dict]) -> str:
        """Complete upload and return report URL using proper API client method."""
        successful_files = [f for f in file_results if f.get("success")]
        failed_files = [f for f in file_results if not f.get("success")]
        
        # Create upload summary
        upload_summary = UploadSummary(
            total_files=len(file_results),
            successful_uploads=len(successful_files),
            failed_uploads=len(failed_files),
            total_size_bytes=sum(f.get("size_bytes", 0) for f in successful_files)
        )
        
        # Create completion request
        completion_request = CompletionRequest(
            upload_status=(
                UploadStatus.COMPLETED if not failed_files
                else UploadStatus.FAILED if not successful_files
                else UploadStatus.PARTIAL
            ),
            uploaded_files=[f["filename"] for f in successful_files],
            failed_files=[f["filename"] for f in failed_files],
            completed_at=datetime.utcnow(),
            upload_summary=upload_summary
        )
        
        with ZerberusAPIClient(self.config) as client:
            completion_response = client.acknowledge_completion(scan_id, completion_request)
            return completion_response.report_url
    
    def _update_metadata_file(self, metadata_file_path: str, api_scan_id: str, scan_metadata: dict):
        """Update scan_metadata.json file with API scan_id and threshold config before uploading."""
        try:
            # Read the current metadata file
            with open(metadata_file_path, 'r') as f:
                metadata = json.load(f)
            
            # Update with API scan_id
            metadata["scan_id"] = api_scan_id
            
            # Add threshold configuration if received from API
            if hasattr(self, '_threshold_config') and self._threshold_config:
                metadata["threshold_config"] = {
                    "enabled": self._threshold_config.enabled,
                    "high_severity_weight": self._threshold_config.high_severity_weight,
                    "medium_severity_weight": self._threshold_config.medium_severity_weight,
                    "low_severity_weight": self._threshold_config.low_severity_weight,
                    "max_score_threshold": self._threshold_config.max_score_threshold,
                    "fail_on_critical": self._threshold_config.fail_on_critical,
                }
                self.console.print("🎯 Threshold configuration received from API", style="dim")
            
            # Write back to file
            with open(metadata_file_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self.console.print(f"📋 Updated scan_metadata.json with API scan_id: {api_scan_id[:8]}...", style="dim")
            
        except Exception as e:
            self.console.print(f"⚠️ Failed to update metadata file: {str(e)}", style="yellow")
            # Continue with upload even if metadata update fails
    
    def _run_threshold_validation(self) -> Optional[ThresholdResult]:
        """Run threshold validation if threshold config is available."""
        if not hasattr(self, '_threshold_config') or not self._threshold_config or not self._threshold_config.enabled:
            return None
        
        try:
            # Load validation report
            with open("validation_report.json", "r") as f:
                validation_report = json.load(f)
            
            # Convert API threshold config to ZSBOM threshold config
            zsbom_threshold_config = ZSBOMThresholdConfig(
                enabled=self._threshold_config.enabled,
                high_severity_weight=self._threshold_config.high_severity_weight,
                medium_severity_weight=self._threshold_config.medium_severity_weight,
                low_severity_weight=self._threshold_config.low_severity_weight,
                max_score_threshold=self._threshold_config.max_score_threshold,
                fail_on_critical=self._threshold_config.fail_on_critical,
            )
            
            # Run threshold validation
            checker = ThresholdChecker(zsbom_threshold_config)
            zsbom_result = checker.check_thresholds(validation_report)
            
            # Convert to our result format
            threshold_result = ThresholdResult(
                threshold_exceeded=zsbom_result.threshold_exceeded,
                should_fail_build=zsbom_result.should_fail_build,
                calculated_score=zsbom_result.calculated_score,
                max_threshold=zsbom_result.max_threshold,
                failure_reason=zsbom_result.failure_reason,
                critical_vulnerabilities_found=zsbom_result.critical_vulnerabilities_found,
                critical_count=zsbom_result.vulnerability_counts.critical,
            )
            
            # Update scan_metadata.json with threshold results
            self._update_metadata_with_threshold_results(threshold_result)
            
            return threshold_result
            
        except FileNotFoundError:
            self.console.print("⚠️ No validation report found for threshold checking", style="yellow")
            return None
        except Exception as e:
            self.console.print(f"⚠️ Failed to run threshold validation: {str(e)}", style="yellow")
            return None
    
    def _update_metadata_with_threshold_results(self, threshold_result: ThresholdResult):
        """Update scan_metadata.json with threshold validation results."""
        try:
            with open("scan_metadata.json", "r") as f:
                metadata = json.load(f)
            
            metadata["threshold_validation"] = {
                "threshold_exceeded": threshold_result.threshold_exceeded,
                "should_fail_build": threshold_result.should_fail_build,
                "calculated_score": threshold_result.calculated_score,
                "max_threshold": threshold_result.max_threshold,
                "failure_reason": threshold_result.failure_reason,
                "validated_at": datetime.utcnow().isoformat()
            }
            
            with open("scan_metadata.json", "w") as f:
                json.dump(metadata, f, indent=2)
                
        except Exception as e:
            self.console.print(f"⚠️ Failed to update metadata with threshold results: {str(e)}", style="yellow")

    def _generate_pr_comment_file(
        self,
        scan_metadata: dict,
        threshold_result: Optional[ThresholdResult],
        report_url: str
    ) -> None:
        """Generate PR comment markdown file for GitHub Actions."""
        try:
            threshold_config = getattr(self, "_threshold_config", None)
            generator = PRCommentGenerator(
                validation_report_path="validation_report.json",
                risk_report_path="risk_report.json",
                scan_metadata=scan_metadata,
                threshold_result=threshold_result,
                report_url=report_url,
                threshold_config=asdict(threshold_config) if threshold_config else None,
            )

            comment_content = generator.generate()

            # Write to file for GitHub workflow to read
            with open("pr_comment.md", "w", encoding="utf-8") as f:
                f.write(comment_content)

            self.console.print("📝 Generated PR comment file: pr_comment.md", style="dim")

        except Exception as e:
            self.console.print(f"⚠️ Failed to generate PR comment: {str(e)}", style="yellow")