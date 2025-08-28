"""
Upload service for ZSBOM.

Handles uploading scan results to Zerberus platform
with single responsibility for upload operations.
"""
import json
import os
import sys
from typing import Optional

from depclass.rich_utils.ui_helpers import get_console
from depclass.core.config_manager import ConfigManager
from depclass.core.file_manager import FileManager


class UploadService:
    """Service for uploading scan results to Zerberus platform."""
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.file_manager = FileManager()
        self.console = get_console()
    
    def configure_environment_variables(
        self, 
        api_url: Optional[str], 
        license_key: Optional[str]
    ) -> None:
        """Override environment variables if CLI parameters are provided."""
        if api_url:
            os.environ["ZERBERUS_API_URL"] = api_url
        if license_key:
            os.environ["ZERBERUS_LICENSE_KEY"] = license_key
    
    def validate_upload_configuration(self) -> bool:
        """Validate that upload configuration is available."""
        try:
            from depclass.upload import TraceAIUploadManager
            
            upload_manager = TraceAIUploadManager()
            return upload_manager.is_upload_enabled()
        except ImportError:
            self.console.print("❌ Upload module not available", style="bold red")
            self.console.print("   Install with upload dependencies: pip install -e .", style="dim")
            return False
    
    def load_scan_metadata(self, metadata_file: str = "scan_metadata.json") -> dict:
        """Load scan metadata if available."""
        scan_metadata = {}
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    scan_metadata = json.load(f)
            except Exception as e:
                self.console.print(f"⚠️ Could not read scan metadata: {e}", style="yellow")
        return scan_metadata
    
    def execute_upload(
        self,
        api_url: Optional[str] = None,
        license_key: Optional[str] = None,
        config_path: Optional[str] = None
    ) -> int:
        """Execute upload workflow and return exit code."""
        
        # Configure environment variables
        self.configure_environment_variables(api_url, license_key)
        
        try:
            from depclass.upload import TraceAIUploadManager
            
            upload_manager = TraceAIUploadManager()
            
            # Check if upload is enabled
            if not upload_manager.is_upload_enabled():
                self.console.print("❌ Upload not configured. Missing environment variables:", style="bold red")
                self.console.print("   Required: ZERBERUS_API_URL, ZERBERUS_LICENSE_KEY", style="dim")
                self.console.print("\n💡 Set environment variables or use CLI parameters:", style="dim")
                self.console.print("   zsbom upload --api-url 'https://api.zerberus.ai' --license-key 'ZRB-gh-xxxxxx-xxxx'", style="dim")
                return 1
            
            self.console.print("🚀 Uploading to Zerberus Trace-AI...", style="bold blue")
            
            # Load config for file paths
            config = self.config_manager.discover_and_load_config(config_path)
            
            # Collect scan files with proper renaming
            scan_files = self.file_manager.collect_scan_files_for_upload(config)
            
            if not scan_files:
                self.console.print("❌ No scan files found to upload", style="bold red")
                self.console.print("   Run 'zsbom scan' first to generate scan results", style="dim")
                return 1
            
            # Read scan metadata if available
            scan_metadata = self.load_scan_metadata()
            
            # Execute upload workflow
            upload_result = upload_manager.execute_upload_workflow(
                scan_files=scan_files,
                scan_metadata=scan_metadata
            )
            
            if upload_result.success:
                self.console.print("✅ Upload completed successfully", style="bold green")
                return 0
            else:
                if upload_result.skip_reason:
                    self.console.print(f"ℹ️ Upload skipped: {upload_result.skip_reason}", style="blue")
                    return 0
                else:
                    self.console.print(f"❌ Upload failed: {upload_result.error}", style="bold red")
                    return 1
                    
        except ImportError:
            self.console.print("❌ Upload module not available", style="bold red")
            self.console.print("   Install with upload dependencies: pip install -e .", style="dim")
            return 1
        except Exception as e:
            self.console.print(f"❌ Upload failed: {str(e)}", style="bold red")
            return 1