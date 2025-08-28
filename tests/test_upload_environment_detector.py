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
            'ZERBERUS_LICENSE_KEY': 'ZRB-gh-a3f2d5e8b9c14f7a-2e3a'
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
            assert 'ZERBERUS_LICENSE_KEY' in missing
            assert 'ZERBERUS_API_URL' not in missing
    
    def test_validate_environment_success(self):
        """Test successful environment validation"""
        with patch.dict(os.environ, {
            'ZERBERUS_API_URL': 'https://api.test.com',
            'ZERBERUS_LICENSE_KEY': 'ZRB-gh-a3f2d5e8b9c14f7a-2e3a'
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
            'ZERBERUS_LICENSE_KEY': 'ZRB-gh-a3f2d5e8b9c14f7a-2e3a'
        }):
            result = self.detector.validate_environment()
            assert result.is_valid == False
            assert "Invalid API URL format" in result.error_message
    
    def test_validate_environment_invalid_license_key(self):
        """Test environment validation with invalid license key format"""
        with patch.dict(os.environ, {
            'ZERBERUS_API_URL': 'https://api.test.com',
            'ZERBERUS_LICENSE_KEY': 'invalid-key-format'
        }):
            result = self.detector.validate_environment()
            assert result.is_valid == False
            assert "Invalid ZERBERUS_LICENSE_KEY format" in result.error_message
    
    def test_get_upload_config_success(self):
        """Test successful configuration extraction"""
        with patch.dict(os.environ, {
            'ZERBERUS_API_URL': 'https://api.test.com',
            'ZERBERUS_LICENSE_KEY': 'ZRB-gh-a3f2d5e8b9c14f7a-2e3a',
            'TRACE_AI_UPLOAD_TIMEOUT': '600',
            'TRACE_AI_MAX_RETRIES': '5'
        }):
            config = self.detector.get_upload_config()
            
            assert config.api_url == 'https://api.test.com'
            assert config.license_key == 'ZRB-gh-a3f2d5e8b9c14f7a-2e3a'
            assert config.upload_timeout == 600
            assert config.max_retries == 5
            assert config.parallel_uploads == 3  # Default value
    
    def test_get_upload_config_with_defaults(self):
        """Test configuration extraction with default values"""
        with patch.dict(os.environ, {
            'ZERBERUS_API_URL': 'https://api.test.com',
            'ZERBERUS_LICENSE_KEY': 'ZRB-gh-a3f2d5e8b9c14f7a-2e3a'
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
            'ZERBERUS_LICENSE_KEY': 'ZRB-gh-a3f2d5e8b9c14f7a-2e3a',
            'TRACE_AI_UPLOAD_TIMEOUT': '600'
        }, clear=True):
            summary = self.detector.get_environment_summary()
            
            assert summary["upload_enabled"] == True
            assert len(summary["missing_variables"]) == 0
            assert summary["detected_variables"]["ZERBERUS_API_URL"] == 'https://api.test.com'
            # Should mask sensitive keys (first 8 chars + ... + last 4 chars)
            assert summary["detected_variables"]["ZERBERUS_LICENSE_KEY"] == "ZRB-gh-a...2e3a"
    
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
    
    @pytest.mark.parametrize("license_key,expected", [
        ("ZRB-gh-a3f2d5e8b9c14f7a-2e3a", True),
        ("ZRB-gl-1234567890abcdef-9876", True),
        ("ZRB-bb-abcdef1234567890-5432", True),
        ("ZRB-invalid-format", False),
        ("WRONG-gh-a3f2d5e8b9c14f7a-2e3a", False),
        ("ZRB-gh-toolong1234567890abcdefgh-2e3a", False),
        ("ZRB-gh-short-2e3a", False),
        ("", False),
        (None, False)
    ])
    def test_validate_license_key_format(self, license_key, expected):
        """Test license key format validation with various inputs"""
        result = self.detector._validate_license_key_format(license_key)
        assert result == expected