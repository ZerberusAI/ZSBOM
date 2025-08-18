"""
Tests for Trace-AI Environment Detector

Tests environment variable detection, validation, and configuration extraction
for the upload functionality.
"""

import os
import pytest
from unittest.mock import patch

from depclass.upload.environment_detector import TraceAIEnvironmentDetector
from depclass.upload.exceptions import EnvironmentValidationError


class TestTraceAIEnvironmentDetector:
    """Test cases for environment detection and validation"""
    
    def setup_method(self):
        """Setup for each test"""
        self.detector = TraceAIEnvironmentDetector()
    
    def test_is_upload_enabled_with_all_vars(self):
        """Test upload enabled when all required vars are present"""
        with patch.dict(os.environ, {
            'ZERBERUS_API_URL': 'https://api.test.com',
            'ZERBERUS_ORG_KEY': 'org_1234567890abcdef1234567890abcdef',
            'ZERBERUS_PROJECT_KEY': 'proj_abcdef1234567890abcdef1234567890'
        }):
            assert self.detector.is_upload_enabled() == True
    
    def test_is_upload_enabled_missing_vars(self):
        """Test upload disabled when required vars are missing"""
        with patch.dict(os.environ, {}, clear=True):
            assert self.detector.is_upload_enabled() == False
    
    def test_is_upload_enabled_partial_vars(self):
        """Test upload disabled when only some vars are present"""
        with patch.dict(os.environ, {
            'ZERBERUS_API_URL': 'https://api.test.com'
        }, clear=True):
            assert self.detector.is_upload_enabled() == False
    
    def test_get_missing_variables(self):
        """Test identification of missing variables"""
        with patch.dict(os.environ, {
            'ZERBERUS_API_URL': 'https://api.test.com'
        }, clear=True):
            missing = self.detector.get_missing_variables()
            assert 'ZERBERUS_ORG_KEY' in missing
            assert 'ZERBERUS_PROJECT_KEY' in missing
            assert 'ZERBERUS_API_URL' not in missing
    
    def test_validate_environment_success(self):
        """Test successful environment validation"""
        with patch.dict(os.environ, {
            'ZERBERUS_API_URL': 'https://api.test.com',
            'ZERBERUS_ORG_KEY': 'org_1234567890abcdef1234567890abcdef',
            'ZERBERUS_PROJECT_KEY': 'proj_abcdef1234567890abcdef1234567890'
        }):
            result = self.detector.validate_environment()
            assert result.is_valid == True
            assert result.error_message is None
    
    def test_validate_environment_missing_vars(self):
        """Test environment validation with missing variables"""
        with patch.dict(os.environ, {}, clear=True):
            result = self.detector.validate_environment()
            assert result.is_valid == False
            assert "Missing required environment variables" in result.error_message
    
    def test_validate_environment_invalid_url(self):
        """Test environment validation with invalid API URL"""
        with patch.dict(os.environ, {
            'ZERBERUS_API_URL': 'not-a-valid-url',
            'ZERBERUS_ORG_KEY': 'org_1234567890abcdef1234567890abcdef',
            'ZERBERUS_PROJECT_KEY': 'proj_abcdef1234567890abcdef1234567890'
        }):
            result = self.detector.validate_environment()
            assert result.is_valid == False
            assert "Invalid API URL format" in result.error_message
    
    def test_validate_environment_invalid_org_key(self):
        """Test environment validation with invalid org key format"""
        with patch.dict(os.environ, {
            'ZERBERUS_API_URL': 'https://api.test.com',
            'ZERBERUS_ORG_KEY': 'invalid-key-format',
            'ZERBERUS_PROJECT_KEY': 'proj_abcdef1234567890abcdef1234567890'
        }):
            result = self.detector.validate_environment()
            assert result.is_valid == False
            assert "Invalid ZERBERUS_ORG_KEY format" in result.error_message
    
    def test_validate_environment_invalid_project_key(self):
        """Test environment validation with invalid project key format"""
        with patch.dict(os.environ, {
            'ZERBERUS_API_URL': 'https://api.test.com',
            'ZERBERUS_ORG_KEY': 'org_1234567890abcdef1234567890abcdef',
            'ZERBERUS_PROJECT_KEY': 'invalid-key-format'
        }):
            result = self.detector.validate_environment()
            assert result.is_valid == False
            assert "Invalid ZERBERUS_PROJECT_KEY format" in result.error_message
    
    def test_get_upload_config_success(self):
        """Test successful configuration extraction"""
        with patch.dict(os.environ, {
            'ZERBERUS_API_URL': 'https://api.test.com',
            'ZERBERUS_ORG_KEY': 'org_1234567890abcdef1234567890abcdef',
            'ZERBERUS_PROJECT_KEY': 'proj_abcdef1234567890abcdef1234567890',
            'TRACE_AI_UPLOAD_TIMEOUT': '600',
            'TRACE_AI_MAX_RETRIES': '5'
        }):
            config = self.detector.get_upload_config()
            
            assert config.api_url == 'https://api.test.com'
            assert config.org_key == 'org_1234567890abcdef1234567890abcdef'
            assert config.project_key == 'proj_abcdef1234567890abcdef1234567890'
            assert config.upload_timeout == 600
            assert config.max_retries == 5
            assert config.parallel_uploads == 3  # Default value
    
    def test_get_upload_config_with_defaults(self):
        """Test configuration extraction with default values"""
        with patch.dict(os.environ, {
            'ZERBERUS_API_URL': 'https://api.test.com',
            'ZERBERUS_ORG_KEY': 'org_1234567890abcdef1234567890abcdef',
            'ZERBERUS_PROJECT_KEY': 'proj_abcdef1234567890abcdef1234567890'
        }):
            config = self.detector.get_upload_config()
            
            # Should use default values
            assert config.upload_timeout == 300
            assert config.max_retries == 3
            assert config.parallel_uploads == 3
            assert config.chunk_size == 8192
    
    def test_get_upload_config_invalid_environment(self):
        """Test configuration extraction with invalid environment"""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(EnvironmentValidationError) as exc_info:
                self.detector.get_upload_config()
            
            assert "Missing required environment variables" in str(exc_info.value)
    
    def test_get_environment_summary(self):
        """Test environment summary generation"""
        with patch.dict(os.environ, {
            'ZERBERUS_API_URL': 'https://api.test.com',
            'ZERBERUS_ORG_KEY': 'org_1234567890abcdef1234567890abcdef',
            'TRACE_AI_UPLOAD_TIMEOUT': '600'
        }, clear=True):
            summary = self.detector.get_environment_summary()
            
            assert summary["upload_enabled"] == False  # Missing project key
            assert len(summary["missing_variables"]) == 1
            assert summary["detected_variables"]["ZERBERUS_API_URL"] == 'https://api.test.com'
            # Should mask sensitive keys
            assert summary["detected_variables"]["ZERBERUS_ORG_KEY"].startswith("org_1234")
            assert summary["detected_variables"]["ZERBERUS_ORG_KEY"].endswith("...cdef")
    
    @pytest.mark.parametrize("url,expected", [
        ("https://api.zerberus.ai", True),
        ("http://localhost:8000", True),
        ("https://api.test.com/", True),
        ("not-a-url", False),
        ("ftp://invalid.com", False),
        ("", False),
        (None, False)
    ])
    def test_validate_api_url(self, url, expected):
        """Test API URL validation with various inputs"""
        result = self.detector._validate_api_url(url)
        assert result == expected
    
    @pytest.mark.parametrize("key,key_type,expected", [
        ("org_1234567890abcdef1234567890abcdef", "org", True),
        ("proj_abcdef1234567890abcdef1234567890", "proj", True),
        ("org_invalid", "org", False),
        ("proj_toolong1234567890abcdef1234567890abcdefgh", "proj", False),
        ("wrong_1234567890abcdef1234567890abcdef", "org", False),
        ("", "org", False),
        (None, "org", False)
    ])
    def test_validate_key_format(self, key, key_type, expected):
        """Test key format validation with various inputs"""
        result = self.detector._validate_key_format(key, key_type)
        assert result == expected