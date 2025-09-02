"""
Simplified Upload Orchestrator for Trace-AI with Rich UI.
"""
import time
import os
import json
import re
from datetime import datetime
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from depclass.upload.models import (
    TraceAIConfig, 
    UploadResult, 
    RepositoryMetadata, 
    ScanMetadata, 
    ScanInitiationRequest,
    CompletionRequest,
    UploadStatus,
    UploadSummary
)
from depclass.upload.api_client import ZerberusAPIClient


class UploadOrchestrator:
    """Simplified upload orchestrator with Rich UI progress tracking."""
    
    def __init__(self, config: TraceAIConfig, console: Console = None):
        self.config = config
        self.console = console or Console()
    
    def execute_upload_workflow(self, scan_files: Dict[str, str], scan_metadata: dict) -> UploadResult:
        """Execute simplified upload workflow with Rich progress."""
        start_time = time.time()
        
        try:
            # Basic file validation
            valid_files = {k: v for k, v in scan_files.items() if os.path.exists(v)}
            if not valid_files:
                return UploadResult(success=False, error="No valid files found for upload")
            
            # Phase 1: Initiate scan
            self.console.print("🚀 Initiating scan with Zerberus...", style="cyan")
            scan_id = self._initiate_scan(scan_metadata)
            self.console.print(f"✅ Scan initiated: {scan_id[:8]}...", style="green")
            
            # Phase 2: Upload files with progress
            self.console.print("📤 Uploading files...", style="cyan")
            file_results = self._upload_files_with_progress(scan_id, valid_files)
            
            # Phase 3: Complete upload
            report_url = self._complete_upload(scan_id, file_results)
            
            # Success message
            self.console.print(f"✅ Upload completed successfully!", style="bold green")
            self.console.print(f"📊 Report URL: {report_url}", style="green")
            
            total_time = time.time() - start_time
            return UploadResult(
                success=True,
                scan_id=scan_id,
                report_url=report_url,
                file_results=file_results,
                total_time_seconds=total_time
            )
            
        except Exception as e:
            self.console.print(f"❌ Upload failed: {str(e)}", style="red")
            return UploadResult(success=False, error=str(e))
    
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
            if ci_context.get("pr_number"):
                trigger_type = "pull_request"
            elif ci_context.get("event_type") == "push":
                trigger_type = "push"
            elif ci_context.get("event_type") == "merge_request":
                trigger_type = "merge_request"
        
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
            local_execution=not ci_context.get("is_ci", False)
        )
        
        # Create request object
        request = ScanInitiationRequest(
            repository_metadata=repo_metadata,
            scan_metadata=scan_meta
        )
        
        with ZerberusAPIClient(self.config) as client:
            response = client.initiate_scan(request)
            return response.scan_id
    
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
            response.raise_for_status()
            
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
            upload_status=UploadStatus.COMPLETED if not failed_files else UploadStatus.PARTIAL,
            uploaded_files=[f["filename"] for f in successful_files],
            failed_files=[f["filename"] for f in failed_files],
            completed_at=datetime.utcnow(),
            upload_summary=upload_summary
        )
        
        with ZerberusAPIClient(self.config) as client:
            completion_response = client.acknowledge_completion(scan_id, completion_request)
            return completion_response.report_url