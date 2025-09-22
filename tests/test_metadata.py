"""
Test suite for ZSBOM metadata collection.

Tests the simplified MetadataCollector implementation including:
- Metadata collection and generation
- Error tracking and reporting
- Statistics management
- Git repository detection
- CI/PR context detection

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


class TestMetadataCollector:
    """Test suite for MetadataCollector."""

    def test_metadata_collector_initialization(self):
        """Test MetadataCollector initialization."""
        config = {"test": "config"}
        console = Mock()

        collector = MetadataCollector(config, console)

        assert collector.config == config
        assert collector.console == console
        assert isinstance(collector.scan_id, str)
        assert collector.started_at is None
        assert collector.completed_at is None
        assert collector.errors == []
        assert collector.statistics == {}
        assert collector.generated_files == []

    def test_start_collection(self):
        """Test starting metadata collection."""
        config = {}
        collector = MetadataCollector(config)

        scan_id = collector.start_collection()

        assert scan_id == collector.scan_id
        assert collector.started_at is not None
        assert isinstance(collector.started_at, datetime)

    def test_add_error(self):
        """Test adding errors to collection."""
        config = {}
        collector = MetadataCollector(config)

        test_error = ValueError("test error")
        collector.add_error("test_stage", test_error, {"extra": "data"})

        assert len(collector.errors) == 1
        error_entry = collector.errors[0]
        assert error_entry["stage"] == "test_stage"
        assert error_entry["error"] == "test error"
        assert error_entry["error_type"] == "ValueError"
        assert error_entry["details"]["extra"] == "data"
        assert "timestamp" in error_entry

    def test_update_statistics(self):
        """Test updating statistics."""
        config = {}
        collector = MetadataCollector(config)

        stats = {"total_dependencies": 10, "vulnerabilities": 2}
        collector.update_statistics(stats)

        assert collector.statistics == stats

    def test_add_generated_file(self):
        """Test adding generated files."""
        config = {}
        collector = MetadataCollector(config)

        collector.add_generated_file("test.json")
        collector.add_generated_file("report.pdf")

        assert "test.json" in collector.generated_files
        assert "report.pdf" in collector.generated_files
        assert len(collector.generated_files) == 2

    def test_set_threshold_failure(self):
        """Test setting threshold failure results."""
        config = {}
        collector = MetadataCollector(config)

        # Test with simple threshold result
        threshold_result = Mock()
        threshold_result.failure_reason = "Risk score too high"
        collector.set_threshold_failure(threshold_result)

        assert collector.threshold_result == threshold_result
        assert collector.threshold_failure_message == "Risk score too high"

        # Test with threshold result without failure_reason
        simple_result = {"passed": False, "score": 95}
        collector.set_threshold_failure(simple_result)
        assert collector.threshold_result == simple_result

    @patch('depclass.metadata.subprocess.run')
    def test_get_git_info_success(self, mock_subprocess):
        """Test successful Git information retrieval."""
        config = {}
        collector = MetadataCollector(config)

        # Mock successful git commands - need to mock all the git calls in order:
        # rev-parse --git-dir, branch --show-current, rev-parse HEAD,
        # log -1 --pretty=format:%s, log -1 --pretty=format:%ae, remote get-url origin, status --porcelain
        mock_subprocess.side_effect = [
            Mock(returncode=0, stdout=".git", stderr=""),           # rev-parse --git-dir
            Mock(returncode=0, stdout="main", stderr=""),           # branch --show-current
            Mock(returncode=0, stdout="abc123def456", stderr=""),   # rev-parse HEAD
            Mock(returncode=0, stdout="Initial commit", stderr=""), # log -1 --pretty=format:%s
            Mock(returncode=0, stdout="user@example.com", stderr=""), # log -1 --pretty=format:%ae
            Mock(returncode=0, stdout="https://github.com/user/repo.git", stderr=""), # remote get-url origin
            Mock(returncode=0, stdout=" M file1.py\n?? file2.py", stderr=""), # status --porcelain
        ]

        git_info = collector._collect_git_info()

        assert git_info["available"] is True
        assert git_info["branch"] == "main"
        assert git_info["commit_sha"] == "abc123def456"
        assert git_info["commit_short_sha"] == "abc123de"
        assert git_info["commit_message"] == "Initial commit"
        assert git_info["author_email"] == "user@example.com"
        assert git_info["remote_url"] == "https://github.com/user/repo.git"
        assert git_info["is_dirty"] is True

    @patch('depclass.metadata.subprocess.run')
    def test_get_git_info_not_git_repo(self, mock_subprocess):
        """Test Git info when not in a Git repository."""
        config = {}
        collector = MetadataCollector(config)

        # Mock git command failure (not a git repo)
        mock_subprocess.return_value = Mock(returncode=128, stdout="", stderr="not a git repository")

        git_info = collector._collect_git_info()

        assert git_info["available"] is False
        assert git_info["branch"] is None
        assert git_info["commit_sha"] is None
        assert git_info["remote_url"] is None
        assert git_info["is_dirty"] is False

    @patch.dict(os.environ, {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "user/test-repo",
        "GITHUB_RUN_ID": "12345",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF_NAME": "feature-branch"
    })
    def test_get_ci_info_github_actions(self):
        """Test CI information detection for GitHub Actions."""
        config = {}
        collector = MetadataCollector(config)

        ci_info = collector._collect_ci_info()

        assert ci_info["is_ci"] is True
        assert ci_info["platform"] == "github_actions"
        assert ci_info["repository"] == "user/test-repo"
        assert ci_info["run_id"] == "12345"
        assert ci_info["event_type"] == "push"
        assert ci_info["source_branch"] == "feature-branch"

    def test_get_ci_info_not_ci(self):
        """Test CI information when not in CI environment."""
        config = {}
        collector = MetadataCollector(config)

        with patch.dict(os.environ, {}, clear=True):
            ci_info = collector._collect_ci_info()

        assert ci_info["is_ci"] is False
        assert ci_info["platform"] == "local"

    @patch('depclass.metadata.subprocess.run')
    @patch.dict(os.environ, {"GITHUB_ACTIONS": "true"})
    def test_finalize_collection(self, mock_subprocess):
        """Test completing metadata collection."""
        config = {"test": "config"}
        collector = MetadataCollector(config)

        # Mock git commands - same as successful git info test
        mock_subprocess.side_effect = [
            Mock(returncode=0, stdout=".git", stderr=""),           # rev-parse --git-dir
            Mock(returncode=0, stdout="main", stderr=""),           # branch --show-current
            Mock(returncode=0, stdout="abc123def456", stderr=""),   # rev-parse HEAD
            Mock(returncode=0, stdout="Initial commit", stderr=""), # log -1 --pretty=format:%s
            Mock(returncode=0, stdout="user@example.com", stderr=""), # log -1 --pretty=format:%ae
            Mock(returncode=0, stdout="https://github.com/test/repo.git", stderr=""), # remote get-url origin
            Mock(returncode=0, stdout="", stderr=""), # status --porcelain
        ]

        # Start collection and add some data
        collector.start_collection()
        collector.update_statistics({"dependencies": 5})
        collector.add_generated_file("test.json")
        collector.add_error("test", Exception("test error"))

        metadata = collector.finalize_collection()

        # Verify structure
        assert "scan_id" in metadata
        assert "execution" in metadata
        assert "repository" in metadata
        assert "ci_context" in metadata
        assert "environment" in metadata
        assert "statistics" in metadata
        assert "errors" in metadata
        assert "generated_files" in metadata

        # Verify execution info structure
        execution = metadata["execution"]
        assert "started_at" in execution
        assert "completed_at" in execution
        assert "duration_seconds" in execution
        assert "exit_code" in execution

        # Verify data
        assert metadata["statistics"]["dependencies"] == 5
        assert len(metadata["errors"]) == 1
        assert "test.json" in metadata["generated_files"]
        assert metadata["repository"]["branch"] == "main"
        assert metadata["ci_context"]["is_ci"] is True


    def test_save_metadata(self):
        """Test saving metadata to file."""
        config = {}
        collector = MetadataCollector(config)

        collector.start_collection()
        collector.update_statistics({"test": 456})

        with tempfile.TemporaryDirectory() as temp_dir:
            # Complete collection first
            metadata = collector.finalize_collection()

            # Save metadata - method returns the path where it was saved
            saved_path = collector.save_metadata(temp_dir + "/test_metadata.json")

            # Verify file was created and contains correct data
            assert os.path.exists(saved_path)

            with open(saved_path, 'r') as f:
                saved_data = json.load(f)

            assert saved_data["statistics"]["test"] == 456
            assert "scan_id" in saved_data