"""
Simple environment detector for ZSBOM.
"""
import os
import glob
from typing import Dict, List


class EnvironmentDetector:
    """Simple environment detector for scan files."""
    
    def detect_scan_files(self) -> Dict[str, str]:
        """Detect common scan output files in current directory."""
        scan_files = {}
        
        # Common scan output patterns
        patterns = {
            "risk_report.json": "risk_report.json",
            "dependencies.json": "dependencies.json", 
            "sbom.json": "sbom.json",
            "sbom.json.sig": "sbom.json.sig",
            "sbom.json.cert": "sbom.json.cert",
            "validation_report.json": "validation_report.json",
            "scan_metadata.json": "scan_metadata.json"
        }
        
        for file_type, pattern in patterns.items():
            matches = glob.glob(pattern)
            if matches:
                # Use the first match
                scan_files[file_type] = matches[0]
        
        return scan_files
    
    def get_environment_info(self) -> Dict:
        """Get basic environment information."""
        return {
            "working_directory": os.getcwd(),
            "python_executable": os.sys.executable if hasattr(os, 'sys') else None,
            "environment_variables": {
                "CI": os.getenv("CI"),
                "GITHUB_ACTIONS": os.getenv("GITHUB_ACTIONS"),
                "USER": os.getenv("USER")
            }
        }