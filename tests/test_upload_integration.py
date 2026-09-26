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
from depclass.upload.models import ThresholdConfig, TraceAIConfig, UploadResult, UploadStatus
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

    def mock_upload_urls(self, mock_client, filenames):
        """Hand back a presigned POST for every file, like the server does."""
        mock_client.get_upload_urls.return_value.upload_urls = {
            name: Mock(url="https://s3.test/bucket", fields={"key": name}) for name in filenames
        }

    def cleanup_files(self, temp_files):
        """Clean up temporary files"""
        for filepath in temp_files:
            try:
                os.unlink(filepath)
            except OSError:
                pass

    @patch('depclass.upload_orchestrator.requests.post')
    @patch('depclass.upload_orchestrator.ZerberusAPIClient')
    def test_successful_upload_workflow(self, mock_api_client, mock_post):
        """Every file uploads and the acknowledge succeeds."""
        mock_client = self.create_mock_api_client()
        mock_api_client.return_value = mock_client
        mock_client.initiate_scan.return_value = Mock(scan_id="remote-scan-id-123", threshold_config=None)
        mock_client.acknowledge_completion.return_value = Mock(
            report_url="https://app.zerberus.ai/trace-ai/dashboard"
        )
        mock_post.return_value = Mock(ok=True, status_code=204)
        scan_files, temp_files = self.create_test_files()
        self.mock_upload_urls(mock_client, scan_files)

        try:
            result = self.orchestrator.execute_upload_workflow(scan_files, {"scan_id": "local-123"})
        finally:
            self.cleanup_files(temp_files)

        assert result.success is True
        assert result.error is None
        assert result.scan_id == "remote-scan-id-123"
        completion = mock_client.acknowledge_completion.call_args.args[1]
        assert completion.upload_status == UploadStatus.COMPLETED

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
    def test_upload_url_refusal_fails_every_file_and_still_acknowledges(self, mock_api_client):
        """A 403 on upload-urls is reported with its reason, and the server still hears about it."""
        mock_client = self.create_mock_api_client()
        mock_api_client.return_value = mock_client
        mock_client.initiate_scan.return_value = Mock(scan_id="scan-id-123", threshold_config=None)
        mock_client.get_upload_urls.side_effect = AuthenticationError(
            "403 Forbidden: Tool integration is not active"
        )
        mock_client.acknowledge_completion.return_value = Mock(report_url="https://app/x")
        scan_files, temp_files = self.create_test_files()

        try:
            result = self.orchestrator.execute_upload_workflow(scan_files, {"scan_id": "local-123"})
        finally:
            self.cleanup_files(temp_files)

        assert result.success is False
        assert result.error == "Upload incomplete: 5 of 5 files failed"
        assert all("Tool integration is not active" in f["error"] for f in result.file_results)
        completion = mock_client.acknowledge_completion.call_args.args[1]
        assert completion.upload_status == UploadStatus.FAILED

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

    @patch('depclass.upload_orchestrator.requests.post')
    @patch('depclass.upload_orchestrator.ZerberusAPIClient')
    @patch('depclass.upload_orchestrator.json.dump')
    @patch('builtins.open', create=True)
    def test_metadata_file_update(self, mock_open, mock_json_dump, mock_api_client, mock_post):
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
            mock_scan_response.threshold_config = None
            mock_client.initiate_scan.return_value = mock_scan_response
            mock_post.return_value = Mock(ok=True, status_code=204)
            self.mock_upload_urls(mock_client, scan_files)
            mock_client.upload_files.return_value = {"scan_metadata.json": {"status": "uploaded"}}
            mock_completion_response = Mock()
            mock_completion_response.report_url = "https://app.zerberus.ai/trace-ai/dashboard"
            mock_client.acknowledge_completion.return_value = mock_completion_response

            # Execute workflow
            result = self.orchestrator.execute_upload_workflow(scan_files, scan_metadata)

            assert result.success is True

        finally:
            os.unlink(temp_file)


    @patch('depclass.upload_orchestrator.requests.post')
    @patch('depclass.upload_orchestrator.ZerberusAPIClient')
    def test_s3_rejection_reports_the_s3_reason(self, mock_api_client, mock_post):
        """One file refused by S3: not a success, S3's reason shown, ack says partial."""
        console = Console(record=True, width=200)
        orchestrator = UploadOrchestrator(self.config, console)
        mock_client = self.create_mock_api_client()
        mock_api_client.return_value = mock_client
        mock_client.initiate_scan.return_value = Mock(scan_id="scan-id-123", threshold_config=None)
        mock_client.acknowledge_completion.return_value = Mock(report_url="https://app/x")
        scan_files, temp_files = self.create_test_files()
        self.mock_upload_urls(mock_client, scan_files)

        def s3(url, data=None, files=None):
            if files["file"][0] == "dependencies.json":
                return Mock(
                    ok=False,
                    status_code=403,
                    reason="Forbidden",
                    text="<Error><Code>AccessDenied</Code><Message>Invalid according to Policy: Policy Condition failed</Message></Error>",
                )
            return Mock(ok=True, status_code=204)

        mock_post.side_effect = s3

        try:
            result = orchestrator.execute_upload_workflow(scan_files, {"scan_id": "local-123"})
        finally:
            self.cleanup_files(temp_files)

        assert result.success is False
        assert result.error == "Upload incomplete: 1 of 5 files failed"
        failed = [f for f in result.file_results if not f["success"]]
        assert failed[0]["filename"] == "dependencies.json"
        assert "AccessDenied: Invalid according to Policy" in failed[0]["error"]
        completion = mock_client.acknowledge_completion.call_args.args[1]
        assert completion.upload_status == UploadStatus.PARTIAL
        assert "Upload completed successfully" not in console.export_text()

    @patch('depclass.upload_orchestrator.requests.post')
    @patch('depclass.upload_orchestrator.ZerberusAPIClient')
    def test_rejected_acknowledge_returns_the_server_reason(self, mock_api_client, mock_post):
        mock_client = self.create_mock_api_client()
        mock_api_client.return_value = mock_client
        mock_client.initiate_scan.return_value = Mock(scan_id="scan-id-123", threshold_config=None)
        mock_client.acknowledge_completion.side_effect = APIConnectionError(
            "422 error from ack: Upload incomplete: missing required file(s): dependencies.json. Re-run the ZSBOM workflow.",
            status_code=422,
        )
        mock_post.return_value = Mock(ok=True, status_code=204)
        scan_files, temp_files = self.create_test_files()
        self.mock_upload_urls(mock_client, scan_files)

        try:
            result = self.orchestrator.execute_upload_workflow(scan_files, {"scan_id": "local-123"})
        finally:
            self.cleanup_files(temp_files)

        assert result.success is False
        assert "missing required file(s): dependencies.json" in result.error

    def test_threshold_result_says_when_criticals_blocked_the_build(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "validation_report.json").write_text(json.dumps(
            {"ecosystems": {"python": {"cve_issues": [{"severity": "CRITICAL"}, {"severity": "CRITICAL"}]}}}
        ))
        (tmp_path / "scan_metadata.json").write_text("{}")
        self.orchestrator._threshold_config = ThresholdConfig(
            enabled=True, high_severity_weight=5, medium_severity_weight=3,
            low_severity_weight=1, max_score_threshold=50, fail_on_critical=True,
        )

        result = self.orchestrator._run_threshold_validation()

        assert result.should_fail_build is True
        assert result.threshold_exceeded is False
        assert result.critical_vulnerabilities_found is True
        assert result.critical_count == 2


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