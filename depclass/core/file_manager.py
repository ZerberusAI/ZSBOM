"""
File management for ZSBOM.

Handles collection and management of generated output files following
SOLID principles with single responsibility for file operations.
"""
import os


class FileManager:
    """Manages ZSBOM file collection and operations."""
    
    def collect_generated_files(self, config: dict) -> list:
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

    def collect_scan_files_for_upload(self, config: dict) -> dict:
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