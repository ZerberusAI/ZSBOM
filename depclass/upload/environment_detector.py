"""
Trace-AI Environment Detector

Detects and validates environment variables required for Trace-AI upload
functionality. Provides comprehensive validation and configuration extraction.
"""

import os
import re
from typing import List, Optional
from urllib.parse import urlparse

from .models import TraceAIConfig, ValidationResult
from .exceptions import EnvironmentValidationError


class TraceAIEnvironmentDetector:
    """Detects and validates Trace-AI upload environment"""
    
    REQUIRED_VARS = [
        "ZERBERUS_API_URL",
        "ZERBERUS_ORG_KEY", 
        "ZERBERUS_PROJECT_KEY"
    ]
    
    OPTIONAL_VARS = {
        "TRACE_AI_UPLOAD_TIMEOUT": (300, int),
        "TRACE_AI_MAX_RETRIES": (3, int),
        "TRACE_AI_PARALLEL_UPLOADS": (3, int),
        "TRACE_AI_CHUNK_SIZE": (8192, int)
    }
    
    def is_upload_enabled(self) -> bool:
        """Check if all required environment variables are present"""
        return all(os.getenv(var) for var in self.REQUIRED_VARS)
    
    def get_missing_variables(self) -> List[str]:
        """Get list of missing required environment variables"""
        return [var for var in self.REQUIRED_VARS if not os.getenv(var)]
    
    def validate_environment(self) -> ValidationResult:
        """Comprehensive environment validation"""
        missing_vars = self.get_missing_variables()
        
        if missing_vars:
            error_msg = f"Missing required environment variables: {', '.join(missing_vars)}"
            return ValidationResult(
                is_valid=False,
                error_message=error_msg,
                validation_type="environment"
            )
        
        # Validate API URL format
        api_url = os.getenv("ZERBERUS_API_URL")
        if not self._validate_api_url(api_url):
            return ValidationResult(
                is_valid=False,
                error_message=f"Invalid API URL format: {api_url}",
                validation_type="environment"
            )
        
        # Validate key formats
        org_key = os.getenv("ZERBERUS_ORG_KEY")
        if not self._validate_key_format(org_key, "org"):
            return ValidationResult(
                is_valid=False,
                error_message="Invalid ZERBERUS_ORG_KEY format",
                validation_type="environment"
            )
        
        project_key = os.getenv("ZERBERUS_PROJECT_KEY")
        if not self._validate_key_format(project_key, "proj"):
            return ValidationResult(
                is_valid=False,
                error_message="Invalid ZERBERUS_PROJECT_KEY format",
                validation_type="environment"
            )
        
        return ValidationResult(is_valid=True)
    
    def get_upload_config(self) -> TraceAIConfig:
        """Extract and validate configuration from environment"""
        validation = self.validate_environment()
        if not validation.is_valid:
            raise EnvironmentValidationError(
                validation.error_message,
                missing_vars=self.get_missing_variables()
            )
        
        # Extract required configuration
        api_url = os.getenv("ZERBERUS_API_URL")
        org_key = os.getenv("ZERBERUS_ORG_KEY")
        project_key = os.getenv("ZERBERUS_PROJECT_KEY")
        
        # Extract optional configuration with defaults
        config_kwargs = {}
        for var_name, (default_value, var_type) in self.OPTIONAL_VARS.items():
            env_value = os.getenv(var_name)
            if env_value:
                try:
                    config_kwargs[self._env_var_to_param(var_name)] = var_type(env_value)
                except ValueError:
                    # Use default if conversion fails
                    config_kwargs[self._env_var_to_param(var_name)] = default_value
            else:
                config_kwargs[self._env_var_to_param(var_name)] = default_value
        
        return TraceAIConfig(
            api_url=api_url,
            org_key=org_key,
            project_key=project_key,
            **config_kwargs
        )
    
    def _validate_api_url(self, url: Optional[str]) -> bool:
        """Validate API URL format"""
        if not url:
            return False
        
        try:
            parsed = urlparse(url)
            return all([
                parsed.scheme in ['http', 'https'],
                parsed.netloc,
                not parsed.path or parsed.path == '/'
            ])
        except Exception:
            return False
    
    def _validate_key_format(self, key: Optional[str], key_type: str) -> bool:
        """Validate key format (basic length and pattern check)"""
        if not key:
            return False
        
        # Expected format: {prefix}_{32_hex_characters}
        expected_prefix = key_type
        pattern = rf"^{expected_prefix}_[a-fA-F0-9]{{32}}$"
        
        return bool(re.match(pattern, key))
    
    def _env_var_to_param(self, env_var: str) -> str:
        """Convert environment variable name to parameter name"""
        # TRACE_AI_UPLOAD_TIMEOUT -> upload_timeout
        return env_var.replace("TRACE_AI_", "").lower()
    
    def get_environment_summary(self) -> dict:
        """Get summary of environment configuration for debugging"""
        summary = {
            "upload_enabled": self.is_upload_enabled(),
            "missing_variables": self.get_missing_variables(),
            "detected_variables": {}
        }
        
        # Show which variables are set (but mask sensitive values)
        for var in self.REQUIRED_VARS:
            value = os.getenv(var)
            if value:
                if "KEY" in var:
                    summary["detected_variables"][var] = f"{value[:8]}...{value[-4:]}"
                else:
                    summary["detected_variables"][var] = value
            else:
                summary["detected_variables"][var] = None
        
        # Add optional variables
        for var in self.OPTIONAL_VARS:
            value = os.getenv(var)
            if value:
                summary["detected_variables"][var] = value
        
        return summary