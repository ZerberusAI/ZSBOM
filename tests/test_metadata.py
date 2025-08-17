"""
Comprehensive test suite for ZSBOM metadata collection framework.

Tests all components of the Phase 3 metadata collection system including:
- MetadataCollector integration
- EnvironmentDetector functionality
- PerformanceTracker accuracy
- ErrorTracker categorization
- RepositoryDetector SCM detection
- End-to-end metadata generation

Run with: pytest tests/test_metadata.py -xvs
"""

import json
import os
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import pytest

from depclass.metadata import MetadataCollector
from depclass.metadata.environment import EnvironmentDetector, SystemEnvironmentDetector, PythonEnvironmentDetector
from depclass.metadata.performance import PerformanceTracker, StageStatus
from depclass.metadata.error_tracker import ErrorTracker, ErrorSeverity, ErrorCategory
from depclass.metadata.repository import RepositoryDetector, GitRepositoryDetector


class TestEnvironmentDetector:
    """Test suite for environment detection functionality."""
    
    def test_system_environment_detection(self):
        """Test system environment detection."""
        detector = SystemEnvironmentDetector()
        env_info = detector.detect()
        
        assert detector.get_detector_name() == "system_environment"
        assert "os" in env_info
        assert "architecture" in env_info
        assert "platform" in env_info
        assert env_info["os"] in ["windows", "linux", "darwin", "unknown"]
    
    def test_python_environment_detection(self):
        """Test Python environment detection."""
        detector = PythonEnvironmentDetector()
        env_info = detector.detect()
        
        assert detector.get_detector_name() == "python_environment"
        assert "version" in env_info
        assert "implementation" in env_info
        assert "executable" in env_info
        assert isinstance(env_info["in_virtualenv"], bool)
    
    def test_environment_detector_integration(self):
        """Test full environment detector integration."""
        detector = EnvironmentDetector()
        env_info = detector.detect_all()
        
        assert "detected_at" in env_info
        assert "timezone" in env_info
        assert "system_environment" in env_info
        assert "python_environment" in env_info
        assert "zsbom_environment" in env_info
        
        # Check flattened common fields
        assert "os" in env_info
        assert "python_version" in env_info
        assert "working_directory" in env_info
    
    @patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "test/repo"})
    def test_ci_environment_detection(self):
        """Test CI environment detection."""
        detector = EnvironmentDetector()
        env_info = detector.detect_all()
        
        zsbom_env = env_info.get("zsbom_environment", {})
        assert zsbom_env.get("ci_environment") in ["github_actions", "generic_ci"]


class TestPerformanceTracker:
    """Test suite for performance tracking functionality."""
    
    def test_stage_timing_basic(self):
        """Test basic stage timing functionality."""
        tracker = PerformanceTracker(enable_resource_monitoring=False)
        
        # Start overall timing
        tracker.start_overall_timing()
        
        # Test stage timing
        tracker.start_stage("test_stage")
        time.sleep(0.1)  # Small delay for measurable timing
        tracker.end_stage("test_stage", success=True)
        
        # End overall timing
        tracker.end_overall_timing()
        
        # Verify results
        stage_metrics = tracker.get_stage_metrics("test_stage")
        assert stage_metrics is not None
        assert stage_metrics.status == StageStatus.COMPLETED
        assert stage_metrics.duration_seconds is not None
        assert stage_metrics.duration_seconds > 0.05  # Should be at least 50ms
        
        overall_duration = tracker.get_overall_duration()
        assert overall_duration is not None
        assert overall_duration > 0
    
    def test_stage_failure_tracking(self):
        """Test stage failure tracking."""
        tracker = PerformanceTracker(enable_resource_monitoring=False)
        
        tracker.start_stage("failing_stage")
        time.sleep(0.05)
        tracker.end_stage("failing_stage", success=False, error_message="Test error")
        
        stage_metrics = tracker.get_stage_metrics("failing_stage")
        assert stage_metrics.status == StageStatus.FAILED
        assert stage_metrics.error_message == "Test error"
        assert stage_metrics.duration_seconds is not None
    
    def test_stage_skipping(self):
        """Test stage skipping functionality."""
        tracker = PerformanceTracker()
        
        tracker.skip_stage("skipped_stage", "Test skip reason")
        
        stage_metrics = tracker.get_stage_metrics("skipped_stage")
        assert stage_metrics.status == StageStatus.SKIPPED
        assert "skip_reason" in stage_metrics.custom_metrics
    
    def test_performance_summary(self):
        """Test performance summary generation."""
        tracker = PerformanceTracker(enable_resource_monitoring=False)
        
        tracker.start_overall_timing()
        tracker.start_stage("stage1")
        tracker.end_stage("stage1", success=True)
        tracker.start_stage("stage2")
        tracker.end_stage("stage2", success=False, error_message="Error")
        tracker.skip_stage("stage3", "Skipped")
        tracker.end_overall_timing()
        
        summary = tracker.get_performance_summary()
        
        assert summary["total_stages"] == 3
        assert summary["completed_stages"] == 1
        assert summary["failed_stages"] == 1
        assert summary["skipped_stages"] == 1
        assert summary["overall_duration_seconds"] is not None
        assert "stages" in summary
        assert len(summary["stages"]) == 3


class TestErrorTracker:
    """Test suite for error tracking and categorization."""
    
    def test_error_capture_basic(self):
        """Test basic error capture functionality."""
        tracker = ErrorTracker()
        
        test_exception = ValueError("Test error message")
        tracker.capture_error(test_exception, "test_stage")
        
        errors = tracker.get_all_errors()
        assert len(errors) == 1
        
        error = errors[0]
        assert error["stage"] == "test_stage"
        assert error["message"] == "Test error message"
        assert error["exception_type"] == "ValueError"
        assert error["level"] == ErrorSeverity.ERROR.value
    
    def test_error_categorization(self):
        """Test automatic error categorization."""
        tracker = ErrorTracker()
        
        # Test network error
        network_error = ConnectionError("Connection timeout")
        tracker.capture_error(network_error, "validation")
        
        # Test file system error
        fs_error = FileNotFoundError("Config file not found")
        tracker.capture_error(fs_error, "configuration")
        
        # Test dependency error
        dep_error = Exception("Package conflict detected")
        tracker.capture_error(dep_error, "dependency_extraction")
        
        errors = tracker.get_all_errors()
        assert len(errors) == 3
        
        # Check categorization
        network_error_record = errors[0]
        assert network_error_record["category"] == ErrorCategory.NETWORK.value
        
        fs_error_record = errors[1]
        assert fs_error_record["category"] == ErrorCategory.SYSTEM.value
    
    def test_error_severity_levels(self):
        """Test error severity level handling."""
        tracker = ErrorTracker()
        
        # Test different severity levels
        tracker.capture_message("Info message", "test", ErrorSeverity.INFO)
        tracker.capture_message("Warning message", "test", ErrorSeverity.WARNING)
        tracker.capture_message("Error message", "test", ErrorSeverity.ERROR)
        tracker.capture_message("Critical message", "test", ErrorSeverity.CRITICAL)
        
        summary = tracker.get_error_summary()
        assert summary["error_counts"]["info"] == 1
        assert summary["error_counts"]["warning"] == 1
        assert summary["error_counts"]["error"] == 1
        assert summary["error_counts"]["critical"] == 1
        
        assert tracker.has_errors() == True
        assert tracker.has_critical_errors() == True
    
    def test_error_filtering(self):
        """Test error filtering by category and severity."""
        tracker = ErrorTracker()
        
        tracker.capture_error(ValueError("Test 1"), "stage1", ErrorCategory.VALIDATION, ErrorSeverity.ERROR)
        tracker.capture_error(ConnectionError("Test 2"), "stage2", ErrorCategory.NETWORK, ErrorSeverity.WARNING)
        tracker.capture_error(FileNotFoundError("Test 3"), "stage1", ErrorCategory.SYSTEM, ErrorSeverity.CRITICAL)
        
        # Test filtering by severity
        critical_errors = tracker.get_errors_by_severity(ErrorSeverity.CRITICAL)
        assert len(critical_errors) == 1
        assert critical_errors[0].message == "Test 3"
        
        # Test filtering by category
        network_errors = tracker.get_errors_by_category(ErrorCategory.NETWORK)
        assert len(network_errors) == 1
        assert network_errors[0].message == "Test 2"
        
        # Test filtering by stage
        stage1_errors = tracker.get_errors_by_stage("stage1")
        assert len(stage1_errors) == 2


class TestRepositoryDetector:
    """Test suite for repository and SCM detection."""
    
    def test_git_detector_no_repo(self):
        """Test Git detector when not in a Git repository."""
        with tempfile.TemporaryDirectory() as temp_dir:
            detector = GitRepositoryDetector(temp_dir)
            
            assert detector.is_available() == False
            
            git_info = detector.detect()
            assert git_info["available"] == False
            assert "error" in git_info
    
    @patch("subprocess.run")
    def test_git_detector_with_repo(self, mock_run):
        """Test Git detector with mocked Git repository."""
        # Mock Git commands - note: is_available() calls git rev-parse --git-dir first
        mock_run.side_effect = [
            # git rev-parse --git-dir (is_available check)
            Mock(returncode=0, stdout=".git\n"),
            # git rev-parse --git-dir (detect method is_available check)
            Mock(returncode=0, stdout=".git\n"),
            # git rev-parse --abbrev-ref HEAD (branch)
            Mock(returncode=0, stdout="main\n"),
            # git rev-parse HEAD (commit)
            Mock(returncode=0, stdout="abc123def456\n"),
            # git rev-parse --short HEAD (short commit)
            Mock(returncode=0, stdout="abc123d\n"),
            # git status --porcelain (dirty check)
            Mock(returncode=0, stdout=""),
            # git remote get-url origin (remote URL)
            Mock(returncode=0, stdout="https://github.com/user/repo.git\n"),
            # git remote (list remotes)
            Mock(returncode=0, stdout="origin\n"),
            # git tag --points-at HEAD (tags)
            Mock(returncode=0, stdout="v1.0.0\n"),
            # git log -1 --format... (commit info)
            Mock(returncode=0, stdout="abc123|John Doe|john@example.com|Mon Jan 1 00:00:00 2024|Initial commit\n"),
            # git rev-list --count HEAD (commit count)
            Mock(returncode=0, stdout="42\n"),
            # git shortlog -sn --all (contributors)
            Mock(returncode=0, stdout="   5\tJohn Doe\n   3\tJane Smith\n")
        ]
        
        detector = GitRepositoryDetector()
        assert detector.is_available() == True
        
        git_info = detector.detect()
        assert git_info["available"] == True
        assert git_info["branch"] == "main"
        assert git_info["commit_sha"] == "abc123def456"
        assert git_info["commit_short_sha"] == "abc123d"
        assert git_info["is_dirty"] == False
        assert git_info["remote_url"] == "https://github.com/user/repo.git"
        assert git_info["tags"] == ["v1.0.0"]
    
    @patch.dict(os.environ, {"CI": "true"})
    def test_ci_environment_detection(self):
        """Test CI environment detection."""
        detector = RepositoryDetector()
        repo_info = detector.detect_all()
        
        # ci_environment is a string containing the platform name
        ci_environment = repo_info.get("ci_environment", "local")
        assert ci_environment in ["generic_ci", "local"]
    
    @patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/pull/123/merge"})
    def test_pull_request_detection(self):
        """Test pull request detection."""
        detector = RepositoryDetector()
        repo_info = detector.detect_all()
        
        pr_info = repo_info.get("pull_request", {})
        # Note: This might not detect PR in test environment without full GitHub context
        assert "available" in pr_info


class TestMetadataCollector:
    """Test suite for the main metadata collector integration."""
    
    def test_metadata_collector_initialization(self):
        """Test metadata collector initialization."""
        config = {"output": {"sbom_file": "test.json"}}
        collector = MetadataCollector(config)
        
        assert collector.config == config
        assert collector.scan_id is not None
        assert len(collector.scan_id) == 36  # UUID4 length
    
    def test_metadata_collection_lifecycle(self):
        """Test complete metadata collection lifecycle."""
        config = {
            "output": {
                "sbom_file": "sbom.json",
                "risk_file": "risk.json",
                "dependencies_file": "deps.json"
            },
            "ecosystem": "python"
        }
        
        collector = MetadataCollector(config)
        
        # Start collection
        scan_id = collector.start_collection()
        assert scan_id == collector.scan_id
        
        # Simulate pipeline stages
        collector.track_stage_start("dependency_extraction")
        time.sleep(0.05)
        collector.track_stage_end("dependency_extraction", success=True)
        
        collector.track_stage_start("validation")
        time.sleep(0.03)
        collector.track_stage_end("validation", success=True)
        
        # Add some statistics
        collector.update_statistics({
            "total_dependencies": 50,
            "vulnerabilities_found": 5
        })
        
        # Add generated files
        collector.add_generated_file("test_output.json")
        
        # Finalize metadata
        metadata = collector.finalize_metadata(
            output_files=["sbom.json", "risk.json"],
            exit_code=0
        )
        
        # Validate metadata structure
        assert "scan_id" in metadata
        assert "execution" in metadata
        assert "environment" in metadata
        assert "repository" in metadata
        assert "performance" in metadata
        assert "configuration" in metadata
        assert "outputs" in metadata
        assert "errors" in metadata
        assert "statistics" in metadata
        
        # Validate execution metadata
        execution = metadata["execution"]
        assert execution["status"] == "completed"
        assert execution["exit_code"] == 0
        assert execution["started_at"] is not None
        assert execution["completed_at"] is not None
        assert execution["duration_seconds"] is not None
    
    def test_error_capture_integration(self):
        """Test error capture integration."""
        config = {"output": {}}
        collector = MetadataCollector(config)
        collector.start_collection()
        
        # Capture different types of errors
        collector.capture_error(
            ValueError("Test validation error"), 
            "validation", 
            ErrorCategory.VALIDATION,
            ErrorSeverity.ERROR
        )
        
        collector.capture_message(
            "Test warning message",
            "risk_assessment",
            ErrorSeverity.WARNING
        )
        
        # Finalize and check errors
        metadata = collector.finalize_metadata(exit_code=0)
        errors = metadata["errors"]
        
        assert len(errors) >= 2
        assert any(e["message"] == "Test validation error" for e in errors)
        assert any(e["message"] == "Test warning message" for e in errors)
    
    def test_metadata_file_saving(self):
        """Test metadata file saving functionality."""
        config = {"output": {}}
        collector = MetadataCollector(config)
        
        collector.start_collection()
        metadata = collector.finalize_metadata(exit_code=0)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            metadata_file = os.path.join(temp_dir, "test_metadata.json")
            collector.save_metadata_file(metadata, metadata_file)
            
            assert os.path.exists(metadata_file)
            
            # Validate JSON structure
            with open(metadata_file, 'r') as f:
                loaded_metadata = json.load(f)
            
            assert loaded_metadata["scan_id"] == metadata["scan_id"]
            assert "execution" in loaded_metadata
            assert "environment" in loaded_metadata
    
    def test_fallback_metadata_generation(self):
        """Test fallback metadata generation on errors."""
        config = {"output": {}}
        collector = MetadataCollector(config)
        
        # Don't start collection to simulate error state
        metadata = collector.finalize_metadata(exit_code=1)
        
        # Should still have basic structure
        assert "scan_id" in metadata
        assert "execution" in metadata
        assert metadata["execution"]["exit_code"] == 1


class TestEndToEndIntegration:
    """End-to-end integration tests for metadata collection."""
    
    def test_metadata_schema_compliance(self):
        """Test that generated metadata complies with Phase 3 schema."""
        config = {
            "output": {
                "sbom_file": "sbom.json",
                "risk_file": "risk_report.json",
                "dependencies_file": "dependencies.json",
                "report_file": "validation_report.json"
            },
            "validation_rules": {"enable_cve_check": True},
            "risk_model": {"weights": {"known_cves": 30}},
            "ecosystem": "python"
        }
        
        collector = MetadataCollector(config)
        collector.start_collection()
        
        # Simulate complete pipeline execution
        stages = ["dependency_extraction", "validation", "risk_assessment", "sbom_generation"]
        
        for stage in stages:
            collector.track_stage_start(stage)
            time.sleep(0.02)  # Small delay for timing
            collector.track_stage_end(stage, success=True)
        
        # Add comprehensive statistics
        collector.update_statistics({
            "total_dependencies": 100,
            "direct_dependencies": 25,
            "transitive_dependencies": 75,
            "vulnerabilities_found": 15,
            "critical_vulnerabilities": 2,
            "high_vulnerabilities": 5,
            "medium_vulnerabilities": 8,
            "low_vulnerabilities": 0
        })
        
        # Add some files
        test_files = ["dependencies.json", "sbom.json", "risk_report.json"]
        for file in test_files:
            collector.add_generated_file(file)
        
        # Finalize metadata
        metadata = collector.finalize_metadata(
            output_files=test_files,
            exit_code=0
        )
        
        # Validate complete schema compliance
        required_top_level_keys = [
            "scan_id", "execution", "environment", "repository", 
            "performance", "configuration", "outputs", "errors", "statistics"
        ]
        
        for key in required_top_level_keys:
            assert key in metadata, f"Missing required key: {key}"
        
        # Validate execution section
        execution = metadata["execution"]
        required_execution_keys = ["started_at", "completed_at", "duration_seconds", "status", "exit_code"]
        for key in required_execution_keys:
            assert key in execution, f"Missing execution key: {key}"
        
        # Validate environment section
        environment = metadata["environment"]
        assert "os" in environment
        assert "python_version" in environment
        
        # Validate performance section
        performance = metadata["performance"]
        for stage in stages:
            stage_key = f"{stage}_seconds"
            assert stage_key in performance, f"Missing performance timing: {stage_key}"
        
        # Validate statistics section
        statistics = metadata["statistics"]
        assert statistics["total_dependencies"] == 100
        assert statistics["vulnerabilities_found"] == 15
        
        # Validate outputs section
        outputs = metadata["outputs"]
        assert "generated_files" in outputs
        assert "file_sizes" in outputs
        assert len(outputs["generated_files"]) == len(test_files)
    
    def test_metadata_collection_with_errors(self):
        """Test metadata collection when errors occur during pipeline."""
        config = {"output": {}}
        collector = MetadataCollector(config)
        collector.start_collection()
        
        # Simulate pipeline with errors
        collector.track_stage_start("dependency_extraction")
        collector.capture_error(
            FileNotFoundError("requirements.txt not found"),
            "dependency_extraction",
            ErrorCategory.SYSTEM,
            ErrorSeverity.CRITICAL
        )
        collector.track_stage_end("dependency_extraction", success=False, 
                                error_message="File not found")
        
        # Continue with degraded functionality
        collector.track_stage_start("validation")
        collector.capture_message(
            "Running with reduced dependency set",
            "validation",
            ErrorSeverity.WARNING
        )
        collector.track_stage_end("validation", success=True)
        
        # Finalize with error exit code
        metadata = collector.finalize_metadata(exit_code=1)
        
        # Validate error handling
        assert metadata["execution"]["status"] == "failed"
        assert metadata["execution"]["exit_code"] == 1
        assert len(metadata["errors"]) >= 2
        
        # Should still have performance data
        performance = metadata["performance"]
        assert "dependency_extraction_seconds" in performance
        assert "validation_seconds" in performance


# Pytest configuration and fixtures
@pytest.fixture
def temp_directory():
    """Provide a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as temp_dir:
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        try:
            yield temp_dir
        finally:
            os.chdir(original_cwd)


@pytest.fixture
def mock_console():
    """Provide a mock console for testing."""
    return Mock()


@pytest.fixture
def sample_config():
    """Provide a sample configuration for testing."""
    return {
        "output": {
            "sbom_file": "sbom.json",
            "risk_file": "risk_report.json",
            "dependencies_file": "dependencies.json",
            "report_file": "validation_report.json"
        },
        "validation_rules": {
            "enable_cve_check": True,
            "enable_abandoned_check": True
        },
        "risk_model": {
            "weights": {
                "known_cves": 30,
                "package_abandonment": 20
            }
        },
        "ecosystem": "python",
        "ignore_conflicts": False
    }


if __name__ == "__main__":
    # Run tests if executed directly
    pytest.main([__file__, "-v"])