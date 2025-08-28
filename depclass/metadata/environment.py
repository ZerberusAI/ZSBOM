"""
Environment Detection Module for ZSBOM Metadata Collection

This module detects system environment, Python runtime information, and execution context
for comprehensive metadata collection following SOLID principles.

Classes:
    EnvironmentDetector: Main environment detection orchestrator
    SystemEnvironmentDetector: OS and hardware detection
    PythonEnvironmentDetector: Python runtime information
    ZSBOMEnvironmentDetector: ZSBOM-specific environment details
"""

import os
import sys
import platform
import socket
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, Optional, Any
from pathlib import Path

try:
    import importlib.metadata as metadata
except ImportError:
    import importlib_metadata as metadata


class BaseEnvironmentDetector(ABC):
    """Abstract base class for environment detectors following SOLID principles."""
    
    @abstractmethod
    def detect(self) -> Dict[str, Any]:
        """Detect environment information."""
        pass
    
    @abstractmethod
    def get_detector_name(self) -> str:
        """Return the name of this detector."""
        pass


class SystemEnvironmentDetector(BaseEnvironmentDetector):
    """Detects system-level environment information."""
    
    def detect(self) -> Dict[str, Any]:
        """Detect system environment details."""
        try:
            return {
                "os": platform.system().lower(),
                "os_version": platform.release(),
                "architecture": platform.machine(),
                "platform": platform.platform(),
                "hostname": socket.gethostname(),
                "cpu_count": os.cpu_count(),
                "timezone": str(datetime.now(timezone.utc).astimezone().tzinfo),
                "utc_offset": datetime.now().astimezone().strftime('%z')
            }
        except Exception as e:
            return {
                "os": "unknown",
                "os_version": "unknown", 
                "architecture": "unknown",
                "platform": "unknown",
                "hostname": "unknown",
                "cpu_count": None,
                "timezone": "UTC",
                "utc_offset": "+0000",
                "detection_error": str(e)
            }
    
    def get_detector_name(self) -> str:
        return "system_environment"


class PythonEnvironmentDetector(BaseEnvironmentDetector):
    """Detects Python runtime environment information."""
    
    def detect(self) -> Dict[str, Any]:
        """Detect Python environment details."""
        try:
            return {
                "version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                "version_info": {
                    "major": sys.version_info.major,
                    "minor": sys.version_info.minor,
                    "micro": sys.version_info.micro,
                    "releaselevel": sys.version_info.releaselevel,
                    "serial": sys.version_info.serial
                },
                "implementation": platform.python_implementation(),
                "compiler": platform.python_compiler(),
                "executable": sys.executable,
                "path": sys.path[:5],  # First 5 paths to avoid too much data
                "prefix": sys.prefix,
                "base_prefix": getattr(sys, 'base_prefix', sys.prefix),
                "real_prefix": getattr(sys, 'real_prefix', None),  # For virtualenv
                "in_virtualenv": hasattr(sys, 'real_prefix') or (
                    hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
                )
            }
        except Exception as e:
            return {
                "version": "unknown",
                "implementation": "unknown",
                "detection_error": str(e)
            }
    
    def get_detector_name(self) -> str:
        return "python_environment"


class ZSBOMEnvironmentDetector(BaseEnvironmentDetector):
    """Detects ZSBOM-specific environment information."""
    
    def detect(self) -> Dict[str, Any]:
        """Detect ZSBOM environment details."""
        try:
            # Try to get ZSBOM version from package metadata
            zsbom_version = self._get_zsbom_version()
            
            # Get working directory
            working_dir = str(Path.cwd().resolve())
            
            # Detect if running in CI
            ci_environment = self._detect_ci_environment()
            
            return {
                "zsbom_version": zsbom_version,
                "working_directory": working_dir,
                "ci_environment": ci_environment,
                "execution_mode": "ci" if ci_environment != "local" else "local",
                "environment_variables": self._get_relevant_env_vars()
            }
        except Exception as e:
            return {
                "zsbom_version": "unknown",
                "working_directory": str(Path.cwd()),
                "ci_environment": "unknown",
                "execution_mode": "unknown",
                "detection_error": str(e)
            }
    
    def _get_zsbom_version(self) -> str:
        """Get ZSBOM version from package metadata."""
        try:
            return metadata.version("zsbom")
        except Exception:
            # Fallback: try to read version from setup files
            try:
                setup_py = Path("setup.py")
                if setup_py.exists():
                    with open(setup_py, 'r') as f:
                        content = f.read()
                        import re
                        match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                        if match:
                            return match.group(1)
                
                pyproject_toml = Path("pyproject.toml")
                if pyproject_toml.exists():
                    # Simple regex-based parsing for version
                    with open(pyproject_toml, 'r') as f:
                        content = f.read()
                        import re
                        match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                        if match:
                            return match.group(1)
                            
                return "development"
            except Exception:
                return "unknown"
    
    def _detect_ci_environment(self) -> str:
        """Detect CI environment type."""
        ci_indicators = {
            "github_actions": "GITHUB_ACTIONS",
            "gitlab_ci": "GITLAB_CI", 
            "jenkins": "JENKINS_URL",
            "travis": "TRAVIS",
            "circleci": "CIRCLECI",
            "azure_pipelines": "TF_BUILD",
            "buildkite": "BUILDKITE",
            "drone": "DRONE",
            "aws_codebuild": "CODEBUILD_BUILD_ID"
        }
        
        for ci_name, env_var in ci_indicators.items():
            if os.getenv(env_var):
                return ci_name
        
        # Generic CI detection
        if os.getenv("CI") == "true" or os.getenv("CONTINUOUS_INTEGRATION") == "true":
            return "generic_ci"
            
        return "local"
    
    def _get_relevant_env_vars(self) -> Dict[str, str]:
        """Get relevant environment variables (excluding sensitive data)."""
        relevant_vars = [
            "CI", "CONTINUOUS_INTEGRATION", 
            "GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_SHA",
            "GITLAB_CI", "CI_PROJECT_NAME", "CI_COMMIT_REF_NAME", "CI_COMMIT_SHA",
            "BUILD_NUMBER", "JOB_NAME", "BRANCH_NAME",
            "PYTHON_VERSION", "PIP_INDEX_URL",
            "VIRTUAL_ENV", "CONDA_DEFAULT_ENV"
        ]
        
        env_vars = {}
        for var in relevant_vars:
            value = os.getenv(var)
            if value:
                env_vars[var] = value
                
        return env_vars
    
    def get_detector_name(self) -> str:
        return "zsbom_environment"


class EnvironmentDetector:
    """Main environment detector orchestrator following SOLID principles."""
    
    def __init__(self):
        self.detectors = [
            SystemEnvironmentDetector(),
            PythonEnvironmentDetector(), 
            ZSBOMEnvironmentDetector()
        ]
    
    def detect_all(self) -> Dict[str, Any]:
        """Detect all environment information."""
        environment_info = {
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "timezone": "UTC"
        }
        
        for detector in self.detectors:
            try:
                detector_info = detector.detect()
                detector_name = detector.get_detector_name()
                environment_info[detector_name] = detector_info
            except Exception as e:
                # Ensure resilience - if one detector fails, others can still work
                environment_info[detector.get_detector_name()] = {
                    "detection_failed": True,
                    "error": str(e)
                }
        
        # Flatten some commonly used fields to top level for convenience
        environment_info.update(self._extract_common_fields(environment_info))
        
        return environment_info
    
    def _extract_common_fields(self, env_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract commonly used fields to top level."""
        common_fields = {}
        
        # Extract OS info
        system_info = env_info.get("system_environment", {})
        common_fields["os"] = system_info.get("os", "unknown")
        common_fields["architecture"] = system_info.get("architecture", "unknown")
        
        # Extract Python info
        python_info = env_info.get("python_environment", {})
        common_fields["python_version"] = python_info.get("version", "unknown")
        
        # Extract ZSBOM info
        zsbom_info = env_info.get("zsbom_environment", {})
        common_fields["zsbom_version"] = zsbom_info.get("zsbom_version", "unknown")
        common_fields["working_directory"] = zsbom_info.get("working_directory", str(Path.cwd()))
        
        return common_fields
    
    def add_detector(self, detector: BaseEnvironmentDetector):
        """Add a custom environment detector."""
        self.detectors.append(detector)
    
    def get_detector_names(self) -> list:
        """Get names of all registered detectors."""
        return [detector.get_detector_name() for detector in self.detectors]