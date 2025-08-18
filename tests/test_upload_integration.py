"""
Integration Tests for Trace-AI Upload

Tests the complete upload workflow integration with mocked API responses
and file operations.
"""

import json
import os
import tempfile
import pytest
from unittest.mock import patch, Mock, AsyncMock
import responses

from depclass.upload import TraceAIUploadManager
from depclass.upload.exceptions import (
    EnvironmentValidationError,
    AuthenticationError,
    APIConnectionError
)


class TestTraceAIUploadIntegration:
    """Integration tests for upload workflow"""
    
    def setup_method(self):
        """Setup for each test"""
        self.upload_manager = TraceAIUploadManager()
        
        # Common test environment variables
        self.test_env = {
            'ZERBERUS_API_URL': 'https://api.test.com',
            'ZERBERUS_ORG_KEY': 'org_1234567890abcdef1234567890abcdef',
            'ZERBERUS_PROJECT_KEY': 'proj_abcdef1234567890abcdef1234567890'
        }
    
    def create_test_files(self):
        """Create temporary test files for upload"""
        files = {}
        temp_files = []
        
        test_data = {
            'dependencies.json': {"dependencies": ["package1", "package2"]},
            'vulnerabilities.json': {"vulnerabilities": []},
            'sbom.json': {"bomFormat": "CycloneDX", "specVersion": "1.4"},
            'risk_analysis.json': {"risk_scores": []},
            'scan_metadata.json': {"scan_id": "test", "timestamp": "2024-01-01T00:00:00Z"}
        }
        
        for filename, data in test_data.items():
            f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            json.dump(data, f)
            f.flush()
            files[filename] = f.name
            temp_files.append(f.name)
        
        return files, temp_files
    
    def cleanup_test_files(self, temp_files):
        """Clean up temporary test files"""
        for temp_file in temp_files:
            try:
                os.unlink(temp_file)
            except:
                pass
    
    def test_upload_manager_not_enabled(self):
        """Test upload manager when environment is not configured"""
        with patch.dict(os.environ, {}, clear=True):
            assert self.upload_manager.is_upload_enabled() == False
    
    def test_upload_manager_enabled(self):
        """Test upload manager when environment is properly configured"""
        with patch.dict(os.environ, self.test_env):
            assert self.upload_manager.is_upload_enabled() == True
    
    def test_upload_workflow_missing_environment(self):
        """Test upload workflow with missing environment variables"""
        with patch.dict(os.environ, {}, clear=True):
            files, temp_files = self.create_test_files()
            
            try:
                with pytest.raises(EnvironmentValidationError):
                    self.upload_manager.execute_upload_workflow(files, {})
                    
            finally:
                self.cleanup_test_files(temp_files)
    
    @responses.activate
    def test_upload_workflow_success(self):
        """Test successful complete upload workflow"""
        with patch.dict(os.environ, self.test_env):
            # Mock API responses
            responses.add(
                responses.POST,
                'https://api.test.com/trace-ai/scans/initiate',
                json={
                    'scan_id': 'test-scan-id',
                    'project_id': 'test-project-id',
                    'status': 'in_progress',
                    'message': 'Scan initiated',
                    'created_at': '2024-01-01T00:00:00Z'
                },
                status=201
            )
            
            responses.add(
                responses.POST,
                'https://api.test.com/trace-ai/scans/test-scan-id/upload-urls',
                json={
                    'scan_id': 'test-scan-id',
                    'upload_urls': {
                        'dependencies.json': {
                            'url': 'https://s3.test.com/upload1',
                            'expires_at': '2024-01-01T01:00:00Z',
                            'fields': {}
                        },
                        'vulnerabilities.json': {
                            'url': 'https://s3.test.com/upload2',
                            'expires_at': '2024-01-01T01:00:00Z',
                            'fields': {}
                        }
                    },
                    'upload_deadline': '2024-01-01T01:00:00Z'
                },
                status=200
            )
            
            responses.add(
                responses.POST,
                'https://api.test.com/trace-ai/scans/test-scan-id/complete',
                json={
                    'scan_id': 'test-scan-id',
                    'status': 'completed',
                    'report_url': 'https://app.test.com/reports/test-scan-id',
                    'message': 'Upload completed successfully',
                    'processing_status': 'queued',
                    'estimated_processing_time': '2-5 minutes'
                },
                status=200
            )
            
            # Create test files
            files, temp_files = self.create_test_files()
            
            # Mock S3 uploads
            with patch('depclass.upload.api_client.ZerberusAPIClient.upload_files_parallel') as mock_upload:
                mock_upload.return_value = [
                    Mock(success=True, file_path=files['dependencies.json'], size_bytes=100),
                    Mock(success=True, file_path=files['vulnerabilities.json'], size_bytes=50)
                ]
                
                try:
                    # Execute upload workflow
                    result = self.upload_manager.execute_upload_workflow(
                        scan_files={k: v for k, v in files.items() if k in ['dependencies.json', 'vulnerabilities.json']},
                        scan_metadata={'test': 'metadata'}
                    )
                    
                    # Verify success
                    assert result.success == True
                    assert result.scan_id == 'test-scan-id'
                    assert result.report_url == 'https://app.test.com/reports/test-scan-id'
                    
                finally:
                    self.cleanup_test_files(temp_files)
    
    @responses.activate 
    def test_upload_workflow_authentication_error(self):
        """Test upload workflow with authentication failure"""
        with patch.dict(os.environ, self.test_env):
            # Mock authentication error
            responses.add(
                responses.POST,
                'https://api.test.com/trace-ai/scans/initiate',
                json={'message': 'Invalid API keys'},
                status=401
            )
            
            files, temp_files = self.create_test_files()
            
            try:
                result = self.upload_manager.execute_upload_workflow(files, {})
                
                # Should handle authentication error gracefully
                assert result.success == False
                assert "Authentication failed" in result.error or "Invalid API keys" in result.error
                
            finally:
                self.cleanup_test_files(temp_files)
    
    @responses.activate
    def test_upload_workflow_partial_upload_success(self):
        """Test upload workflow with some file upload failures"""
        with patch.dict(os.environ, self.test_env):
            # Mock successful API responses
            responses.add(
                responses.POST,
                'https://api.test.com/trace-ai/scans/initiate',
                json={
                    'scan_id': 'test-scan-id',
                    'project_id': 'test-project-id',
                    'status': 'in_progress',
                    'message': 'Scan initiated',
                    'created_at': '2024-01-01T00:00:00Z'
                },
                status=201
            )
            
            responses.add(
                responses.POST,
                'https://api.test.com/trace-ai/scans/test-scan-id/upload-urls',
                json={
                    'scan_id': 'test-scan-id',
                    'upload_urls': {
                        'dependencies.json': {
                            'url': 'https://s3.test.com/upload1',
                            'expires_at': '2024-01-01T01:00:00Z',
                            'fields': {}
                        }
                    },
                    'upload_deadline': '2024-01-01T01:00:00Z'
                },
                status=200
            )
            
            responses.add(
                responses.POST,
                'https://api.test.com/trace-ai/scans/test-scan-id/complete',
                json={
                    'scan_id': 'test-scan-id',
                    'status': 'partial',
                    'report_url': 'https://app.test.com/reports/test-scan-id',
                    'message': 'Upload partially completed',
                    'processing_status': 'queued',
                    'estimated_processing_time': '2-5 minutes'
                },
                status=200
            )
            
            files, temp_files = self.create_test_files()
            
            # Mock partial upload success (one success, one failure)
            with patch('depclass.upload.api_client.ZerberusAPIClient.upload_files_parallel') as mock_upload:
                mock_upload.return_value = [
                    Mock(success=True, file_path=files['dependencies.json'], size_bytes=100),
                    Mock(success=False, file_path=files['vulnerabilities.json'], error_message='Upload failed')
                ]
                
                try:
                    result = self.upload_manager.execute_upload_workflow(
                        scan_files={'dependencies.json': files['dependencies.json']},
                        scan_metadata={}
                    )
                    
                    # Should still report success for partial uploads
                    assert result.success == True
                    assert result.scan_id == 'test-scan-id'
                    
                finally:
                    self.cleanup_test_files(temp_files)
    
    def test_upload_workflow_invalid_files(self):
        """Test upload workflow with invalid files"""
        with patch.dict(os.environ, self.test_env):
            # Create invalid files (wrong extension)
            invalid_files = {}
            temp_files = []
            
            try:
                f = tempfile.NamedTemporaryFile(suffix='.txt', delete=False)
                f.write(b'invalid file')
                f.flush()
                invalid_files['invalid.json'] = f.name
                temp_files.append(f.name)
                
                result = self.upload_manager.execute_upload_workflow(invalid_files, {})
                
                # Should fail due to file validation
                assert result.success == False
                assert "validation" in result.error.lower() or "No valid files" in result.error
                
            finally:
                self.cleanup_test_files(temp_files)
    
    @responses.activate
    def test_upload_workflow_network_error(self):
        """Test upload workflow with network connectivity issues"""
        with patch.dict(os.environ, self.test_env):
            # Don't add any responses - this will trigger connection errors
            
            files, temp_files = self.create_test_files()
            
            try:
                result = self.upload_manager.execute_upload_workflow(files, {})
                
                # Should handle network errors gracefully
                assert result.success == False
                assert "connection" in result.error.lower() or "failed" in result.error.lower()
                
            finally:
                self.cleanup_test_files(temp_files)