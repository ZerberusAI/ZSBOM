"""
Upload Orchestrator for Trace-AI

Coordinates the complete 3-phase upload workflow with Rich progress visualization,
error handling, and user feedback.
"""

import asyncio
import time
import os
from datetime import datetime
from typing import Dict, List

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.text import Text

from .models import (
    TraceAIConfig,
    ScanInitiationRequest,
    UploadUrlsRequest, 
    CompletionRequest,
    UploadResult,
    UploadSummary,
    UploadStatus,
    FileUploadResult
)
from .api_client import ZerberusAPIClient
from .file_validator import FileValidator
from .repository import RepositoryMetadataCollector
from .exceptions import (
    TraceAIUploadError,
    EnvironmentValidationError,
    FileValidationError,
    APIConnectionError,
    AuthenticationError,
    UploadError
)


class UploadOrchestrator:
    """Coordinates the complete upload workflow with progress tracking"""
    
    def __init__(self, config: TraceAIConfig, console: Console = None):
        self.config = config
        self.console = console or Console()
        self.validator = FileValidator()
        self.repo_collector = RepositoryMetadataCollector()
    
    def execute_upload_workflow(self, scan_files: Dict[str, str], scan_metadata: dict) -> UploadResult:
        """Execute complete 3-phase upload workflow"""
        start_time = time.time()
        
        try:
            # Phase 0: Validation
            validation_result = self._validate_prerequisites(scan_files)
            if not validation_result.success:
                return validation_result
            
            # Get valid files after validation
            valid_files = self.validator.filter_valid_files(scan_files)
            if not valid_files:
                return UploadResult(
                    success=False,
                    error="No valid files found for upload after validation"
                )
            
            # Phase 1: Scan Initiation
            self.console.print("🚀 Initiating scan with Zerberus...", style="cyan")
            scan_response = self._initiate_scan(scan_metadata)
            scan_id = scan_response.scan_id
            
            # Update scan_metadata.json with server-provided scan_id
            self._update_scan_metadata_with_server_id(scan_id)
            
            self.console.print(f"✅ Scan initiated: {scan_id[:8]}...", style="green")
            
            # Phase 2: Get Upload URLs and Upload Files
            self.console.print("📡 Getting upload URLs...", style="cyan")
            upload_urls_response = self._get_upload_urls(scan_id, list(valid_files.keys()))
            
            self.console.print(f"🔗 Got {len(upload_urls_response.upload_urls)} upload URLs", style="green")
            
            # Upload files with progress tracking
            file_results = self._upload_files_with_progress(upload_urls_response.upload_urls, valid_files)
            
            # Phase 3: Acknowledge Completion
            completion_response = self._acknowledge_completion(scan_id, file_results, valid_files)
            
            # Display success message
            self._display_success_message(completion_response)
            
            total_time = time.time() - start_time
            
            return UploadResult(
                success=True,
                scan_id=scan_id,
                report_url=completion_response.report_url,
                file_results=file_results,
                total_time_seconds=total_time
            )
            
        except EnvironmentValidationError as e:
            return UploadResult(success=False, skip_reason=e.message)
            
        except FileValidationError as e:
            self.console.print(f"📁 File validation issue: {e.message}", style="yellow")
            return UploadResult(success=False, error=str(e))
            
        except AuthenticationError as e:
            self.console.print(f"🔐 Authentication failed: {e.message}", style="red")
            self.console.print("Please verify your ZERBERUS_LICENSE_KEY", style="red")
            return UploadResult(success=False, error=str(e))
            
        except APIConnectionError as e:
            self.console.print(f"🌐 Connection failed: {e.message}", style="red")
            return UploadResult(success=False, error=str(e))
            
        except Exception as e:
            self.console.print(f"💥 Unexpected error: {str(e)}", style="red")
            return UploadResult(success=False, error=str(e))
    
    def _validate_prerequisites(self, scan_files: Dict[str, str]) -> UploadResult:
        """Validate files and environment before upload"""
        # Validate files
        validation_result = self.validator.validate_all_files(scan_files)
        
        if not validation_result.is_valid:
            # Try to continue with valid files
            valid_files = self.validator.filter_valid_files(scan_files)
            
            if valid_files:
                invalid_count = len(scan_files) - len(valid_files)
                self.console.print(
                    f"⚠️  {invalid_count} files failed validation, continuing with {len(valid_files)} valid files",
                    style="yellow"
                )
                return UploadResult(success=True)
            else:
                return UploadResult(
                    success=False,
                    error=f"All files failed validation: {validation_result.error_message}"
                )
        
        return UploadResult(success=True)
    
    def _initiate_scan(self, scan_metadata: dict) -> 'ScanInitiationResponse':
        """Phase 1: Initiate scan"""
        repo_metadata = self.repo_collector.collect_repository_metadata()
        scan_meta = self.repo_collector.collect_scan_metadata()
        
        # Override with provided metadata
        if scan_metadata:
            if 'started_at' in scan_metadata:
                scan_meta.started_at = scan_metadata['started_at']
            if 'environment' in scan_metadata:
                scan_meta.environment.update(scan_metadata['environment'])
        
        # Ensure started_at is set
        if not scan_meta.started_at:
            scan_meta.started_at = datetime.utcnow()
        
        request = ScanInitiationRequest(
            repository_metadata=repo_metadata,
            scan_metadata=scan_meta
        )
        
        with ZerberusAPIClient(self.config) as client:
            return client.initiate_scan(request)
    
    def _get_upload_urls(self, scan_id: str, files: List[str]) -> 'UploadUrlsResponse':
        """Phase 2a: Get presigned upload URLs"""
        request = UploadUrlsRequest(files=files)
        
        with ZerberusAPIClient(self.config) as client:
            return client.get_upload_urls(scan_id, files)
    
    def _upload_files_with_progress(self, upload_urls: Dict, file_paths: Dict[str, str]) -> List[FileUploadResult]:
        """Phase 2b: Upload files with Rich progress bars"""
        
        if not upload_urls:
            return []
        
        self.console.print(f"📤 Uploading {len(upload_urls)} files...", style="cyan")
        
        # Use Rich progress bar for visual feedback
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            
            upload_task = progress.add_task("Uploading files...", total=len(upload_urls))
            
            # Run async upload
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                with ZerberusAPIClient(self.config) as client:
                    # Create a wrapper to update progress
                    async def upload_with_progress():
                        results = await client.upload_files_parallel(upload_urls, file_paths)
                        
                        # Update progress for each completed file
                        for i, result in enumerate(results):
                            progress.update(upload_task, advance=1)
                            
                            if result.success:
                                file_name = result.file_path.split('/')[-1]
                                size_mb = (result.size_bytes or 0) / (1024 * 1024)
                                progress.update(
                                    upload_task, 
                                    description=f"✅ {file_name} ({size_mb:.1f}MB)"
                                )
                            else:
                                file_name = result.file_path.split('/')[-1]
                                progress.update(
                                    upload_task,
                                    description=f"❌ {file_name} failed"
                                )
                        
                        return results
                    
                    results = loop.run_until_complete(upload_with_progress())
                    
            finally:
                loop.close()
        
        # Show upload summary
        successful = sum(1 for r in results if r.success)
        failed = len(results) - successful
        
        if failed > 0:
            self.console.print(f"📊 Upload complete: {successful} succeeded, {failed} failed", style="yellow")
        else:
            self.console.print(f"📊 Upload complete: {successful} files uploaded successfully", style="green")
        
        return results
    
    def _acknowledge_completion(self, scan_id: str, file_results: List[FileUploadResult], file_paths: Dict[str, str]) -> 'CompletionResponse':
        """Phase 3: Acknowledge upload completion"""
        
        successful_files = [os.path.basename(r.file_path) for r in file_results if r.success]
        failed_files = [os.path.basename(r.file_path) for r in file_results if not r.success]
        
        total_size = sum(r.size_bytes or 0 for r in file_results if r.success)
        
        upload_summary = UploadSummary(
            total_files=len(file_results),
            successful_uploads=len(successful_files),
            failed_uploads=len(failed_files),
            total_size_bytes=total_size
        )
        
        status = UploadStatus.COMPLETED if len(failed_files) == 0 else UploadStatus.PARTIAL
        
        request = CompletionRequest(
            upload_status=status,
            uploaded_files=successful_files,
            failed_files=failed_files,
            completed_at=datetime.utcnow(),
            upload_summary=upload_summary
        )
        
        with ZerberusAPIClient(self.config) as client:
            return client.acknowledge_completion(scan_id, request)
    
    def _display_success_message(self, response: 'CompletionResponse'):
        """Display fancy completion message to user"""
        
        # Create a styled panel with the success message
        message_text = Text()
        message_text.append("🎉 ", style="bold green")
        message_text.append("Upload completed successfully!\n", style="bold green")
        message_text.append("Your Trace-AI security report will be ready in ", style="green")
        message_text.append(response.estimated_processing_time, style="bold green")
        message_text.append(".\n\n", style="green")
        message_text.append("📊 View your results: ", style="blue")
        message_text.append(response.report_url, style="bold blue underline")
        
        panel = Panel(
            message_text,
            title="🔒 Zerberus Trace-AI",
            border_style="green",
            padding=(1, 2)
        )
        
        self.console.print(panel)
    
    def display_error_message(self, error: str, error_type: str = "error"):
        """Display styled error message"""
        if error_type == "warning":
            emoji = "⚠️"
            style = "yellow"
        else:
            emoji = "❌"
            style = "red"
        
        self.console.print(f"{emoji} {error}", style=style)
    
    def _update_scan_metadata_with_server_id(self, server_scan_id: str):
        """Update scan_metadata.json with the server-provided scan_id"""
        import json
        import os
        
        metadata_file = "scan_metadata.json"
        
        if not os.path.exists(metadata_file):
            self.console.print(f"⚠️ {metadata_file} not found, skipping scan_id update", style="yellow")
            return
        
        try:
            # Read current metadata
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            # Update scan_id
            old_scan_id = metadata.get('scan_id', 'unknown')
            metadata['scan_id'] = server_scan_id
            
            # Write back to file
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self.console.print(f"📝 Updated scan_id in {metadata_file}: {old_scan_id[:8]}... → {server_scan_id[:8]}...", style="dim")
            
        except Exception as e:
            self.console.print(f"⚠️ Failed to update scan_id in {metadata_file}: {str(e)}", style="yellow")