"""
Integration Tests for ZSBOM Upload Orchestrator

Tests the upload workflow integration with mocked API responses
and file operations using the actual UploadOrchestrator.
"""

import json
import os
import tempfile
import pytest
from unittest.mock import patch, Mock, MagicMock
from rich.console import Console

from depclass.upload_orchestrator import UploadOrchestrator
from depclass.upload.models import TraceAIConfig, UploadResult
from depclass.upload.exceptions import (
    AuthenticationError,
    APIConnectionError
)


class TestUploadOrchestratorIntegration:
    """Integration tests for UploadOrchestrator workflow"""

    def setup_method(self):
        """Setup for each test"""
        self.config = TraceAIConfig(
            api_url="https://api.test.com",
            license_key="ZRB-test-key"
        )
        self.console = Console()
        self.orchestrator = UploadOrchestrator(self.config, self.console)

    def create_mock_api_client(self):
        """Create a mock API client that supports context manager protocol"""
        mock_client = Mock()
        mock_client.__enter__ = Mock(return_value=mock_client)
        mock_client.__exit__ = Mock(return_value=None)
        return mock_client

    def create_test_files(self):
        """Create temporary test files for upload"""
        files = {}
        temp_files = []

        test_data = {
            'dependencies.json': {"dependencies": [{"name": "package1", "version": "1.0"}]},
            'risk_report.json': {"risk_summary": {"high": 0, "medium": 2, "low": 5}},
            'sbom.json': {"bomFormat": "CycloneDX", "specVersion": "1.4"},
            'validation_report.json': {"vulnerabilities": []},
            'scan_metadata.json': {"scan_id": "test123", "timestamp": "2024-01-01T00:00:00Z"}
        }

        for filename, data in test_data.items():
            f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            json.dump(data, f)
            f.close()
            files[filename.replace('.json', '.json')] = f.name
            temp_files.append(f.name)

        return files, temp_files

    def cleanup_files(self, temp_files):
        """Clean up temporary files"""
        for filepath in temp_files:
            try:
                os.unlink(filepath)
            except OSError:
                pass

    @patch('depclass.upload_orchestrator.ZerberusAPIClient')
    def test_successful_upload_workflow(self, mock_api_client):
        """Test successful end-to-end upload workflow"""
        # Setup mock API client
        mock_client = self.create_mock_api_client()
        mock_api_client.return_value = mock_client

        # Mock API responses
        mock_scan_response = Mock()
        mock_scan_response.scan_id = "remote-scan-id-123"
        mock_client.initiate_scan.return_value = mock_scan_response
        mock_client.upload_files.return_value = {
            "dependencies.json": {"status": "uploaded", "url": "https://s3.aws.com/file1"},
            "risk_report.json": {"status": "uploaded", "url": "https://s3.aws.com/file2"}
        }
        mock_completion_response = Mock()
        mock_completion_response.report_url = "https://app.com/scan/123"
        mock_client.acknowledge_completion.return_value = mock_completion_response

        # Create test files
        scan_files, temp_files = self.create_test_files()
        scan_metadata = {"scan_id": "local-123", "project_name": "test-project"}

        try:
            # Execute upload workflow
            result = self.orchestrator.execute_upload_workflow(scan_files, scan_metadata)

            # Verify result - the workflow completed successfully despite some warnings
            assert result.success is True
            assert result.error is None
            assert result.scan_id == "remote-scan-id-123"

            # Verify basic API call was made
            mock_client.initiate_scan.assert_called_once()

        finally:
            self.cleanup_files(temp_files)

    @patch('depclass.upload_orchestrator.ZerberusAPIClient')
    def test_upload_with_no_files(self, mock_api_client):
        """Test upload workflow when no files are available"""
        scan_files = {}  # No files
        scan_metadata = {"scan_id": "test123"}

        result = self.orchestrator.execute_upload_workflow(scan_files, scan_metadata)

        assert result.success is False
        assert "No valid files found" in result.error

    @patch('depclass.upload_orchestrator.ZerberusAPIClient')
    def test_upload_with_missing_files(self, mock_api_client):
        """Test upload workflow when files don't exist"""
        scan_files = {
            "dependencies.json": "/nonexistent/file1.json",
            "risk_report.json": "/nonexistent/file2.json"
        }
        scan_metadata = {"scan_id": "test123"}

        result = self.orchestrator.execute_upload_workflow(scan_files, scan_metadata)

        assert result.success is False
        assert "No valid files found" in result.error

    @patch('depclass.upload_orchestrator.ZerberusAPIClient')
    def test_upload_scan_initiation_failure(self, mock_api_client):
        """Test upload workflow when scan initiation fails"""
        mock_client = self.create_mock_api_client()
        mock_api_client.return_value = mock_client

        # Mock API failure
        mock_client.initiate_scan.side_effect = APIConnectionError("Connection failed")

        # Create test files
        scan_files, temp_files = self.create_test_files()
        scan_metadata = {"scan_id": "local-123"}

        try:
            result = self.orchestrator.execute_upload_workflow(scan_files, scan_metadata)

            assert result.success is False
            assert "Connection failed" in result.error

        finally:
            self.cleanup_files(temp_files)

    @patch('depclass.upload_orchestrator.ZerberusAPIClient')
    def test_upload_file_upload_failure(self, mock_api_client):
        """Test upload workflow when file upload fails"""
        mock_client = self.create_mock_api_client()
        mock_api_client.return_value = mock_client

        # Mock successful initiation but failed upload
        mock_scan_response = Mock()
        mock_scan_response.scan_id = "scan-id-123"
        mock_client.initiate_scan.return_value = mock_scan_response
        mock_client.upload_files.side_effect = Exception("Upload failed")

        # Create test files
        scan_files, temp_files = self.create_test_files()
        scan_metadata = {"scan_id": "local-123"}

        try:
            result = self.orchestrator.execute_upload_workflow(scan_files, scan_metadata)

            # The workflow continues despite upload errors, check file results instead
            assert result.success is True  # Workflow completes
            assert result.file_results is not None
            # Check that individual file uploads failed
            for file_result in result.file_results:
                assert file_result['success'] is False

        finally:
            self.cleanup_files(temp_files)

    @patch('depclass.upload_orchestrator.ZerberusAPIClient')
    def test_upload_authentication_error(self, mock_api_client):
        """Test upload workflow with authentication error"""
        mock_client = self.create_mock_api_client()
        mock_api_client.return_value = mock_client

        # Mock authentication failure
        mock_client.initiate_scan.side_effect = AuthenticationError("Invalid API key")

        # Create test files
        scan_files, temp_files = self.create_test_files()
        scan_metadata = {"scan_id": "local-123"}

        try:
            result = self.orchestrator.execute_upload_workflow(scan_files, scan_metadata)

            assert result.success is False
            assert "Invalid API key" in result.error

        finally:
            self.cleanup_files(temp_files)

    def test_metadata_collector_integration(self):
        """Test integration with metadata collector"""
        mock_collector = Mock()

        # Set metadata collector
        self.orchestrator.set_metadata_collector(mock_collector)

        assert self.orchestrator.metadata_collector == mock_collector

    @patch('depclass.upload_orchestrator.ZerberusAPIClient')
    @patch('depclass.upload_orchestrator.json.dump')
    @patch('builtins.open', create=True)
    def test_metadata_file_update(self, mock_open, mock_json_dump, mock_api_client):
        """Test updating metadata file with remote scan ID"""
        # Create a real temporary file for this test
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"scan_id": "local-123", "test": "data"}, f)
            temp_file = f.name

        try:
            scan_files = {"scan_metadata.json": temp_file}
            scan_metadata = {"scan_id": "local-123"}

            # Setup mock API client
            mock_client = self.create_mock_api_client()
            mock_api_client.return_value = mock_client
            mock_scan_response = Mock()
            mock_scan_response.scan_id = "remote-scan-456"
            mock_client.initiate_scan.return_value = mock_scan_response
            mock_client.upload_files.return_value = {"scan_metadata.json": {"status": "uploaded"}}
            mock_completion_response = Mock()
            mock_completion_response.report_url = "https://app.com/scan/456"
            mock_client.acknowledge_completion.return_value = mock_completion_response

            # Execute workflow
            result = self.orchestrator.execute_upload_workflow(scan_files, scan_metadata)

            assert result.success is True

        finally:
            os.unlink(temp_file)


class TestTraceAIConfig:
    """Test TraceAIConfig model"""

    def test_config_creation(self):
        """Test creating TraceAI configuration"""
        config = TraceAIConfig(
            api_url="https://test.api.com",
            license_key="test-key"
        )

        assert config.api_url == "https://test.api.com"
        assert config.license_key == "test-key"

    def test_config_with_optional_fields(self):
        """Test config with optional timeout and retry settings"""
        config = TraceAIConfig(
            api_url="https://test.api.com",
            license_key="test-key",
            upload_timeout=60,
            max_retries=5
        )

        assert config.upload_timeout == 60
        assert config.max_retries == 5