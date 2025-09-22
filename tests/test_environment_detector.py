"""
Test suite for EnvironmentDetector.

Tests the EnvironmentDetector functionality including:
- Scan file detection
- Environment information gathering

Run with: pytest tests/test_environment_detector.py -xvs
"""

import os
import tempfile
import pytest
from unittest.mock import patch, Mock

from depclass.environment_detector import EnvironmentDetector


class TestEnvironmentDetector:
    """Test suite for EnvironmentDetector."""

    def test_environment_detector_initialization(self):
        """Test EnvironmentDetector initialization."""
        detector = EnvironmentDetector()
        assert detector is not None

    def test_detect_scan_files_with_existing_files(self):
        """Test detecting scan files when they exist."""
        detector = EnvironmentDetector()

        # Create temporary files that match the patterns
        temp_files = []
        expected_files = ["risk_report.json", "dependencies.json", "sbom.json"]

        try:
            for filename in expected_files:
                with tempfile.NamedTemporaryFile(mode='w', suffix=filename, delete=False) as f:
                    f.write('{"test": "data"}')
                    temp_files.append(f.name)

            # Change to the directory containing the temp files
            original_dir = os.getcwd()
            temp_dir = os.path.dirname(temp_files[0])

            # Copy files to current directory for the test
            for temp_file in temp_files:
                filename = os.path.basename(temp_file).replace('tmp', '').lstrip('_')
                # Extract the actual filename from the temp file
                for expected in expected_files:
                    if expected.replace('.json', '') in temp_file:
                        target = expected
                        break
                else:
                    continue

                import shutil
                shutil.copy2(temp_file, target)

            scan_files = detector.detect_scan_files()

            # Should detect the files we created
            for expected_file in expected_files:
                if os.path.exists(expected_file):
                    assert expected_file in scan_files
                    os.unlink(expected_file)  # Clean up

        finally:
            # Clean up temp files
            for temp_file in temp_files:
                try:
                    os.unlink(temp_file)
                except OSError:
                    pass

    def test_detect_scan_files_no_files(self):
        """Test detecting scan files when none exist."""
        detector = EnvironmentDetector()

        # Ensure we're in a clean directory
        original_dir = os.getcwd()

        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)

            scan_files = detector.detect_scan_files()

            # Should return empty dict when no files exist
            assert scan_files == {}

        os.chdir(original_dir)

    def test_detect_scan_files_partial_files(self):
        """Test detecting scan files when only some exist."""
        detector = EnvironmentDetector()

        original_dir = os.getcwd()

        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)

            # Create only some of the expected files
            with open("dependencies.json", "w") as f:
                f.write('{"dependencies": []}')

            with open("sbom.json", "w") as f:
                f.write('{"bomFormat": "CycloneDX"}')

            scan_files = detector.detect_scan_files()

            # Should only detect the files that exist
            assert "dependencies.json" in scan_files
            assert "sbom.json" in scan_files
            assert "risk_report.json" not in scan_files
            assert "validation_report.json" not in scan_files

        os.chdir(original_dir)

    @patch.dict(os.environ, {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "USER": "testuser"
    })
    def test_get_environment_info(self):
        """Test getting environment information."""
        detector = EnvironmentDetector()

        env_info = detector.get_environment_info()

        assert "working_directory" in env_info
        assert env_info["working_directory"] == os.getcwd()

        assert "environment_variables" in env_info
        env_vars = env_info["environment_variables"]
        assert env_vars["CI"] == "true"
        assert env_vars["GITHUB_ACTIONS"] == "true"
        assert env_vars["USER"] == "testuser"

    @patch.dict(os.environ, {}, clear=True)
    def test_get_environment_info_no_env_vars(self):
        """Test getting environment information when env vars are not set."""
        detector = EnvironmentDetector()

        env_info = detector.get_environment_info()

        assert "working_directory" in env_info
        assert "environment_variables" in env_info

        env_vars = env_info["environment_variables"]
        assert env_vars["CI"] is None
        assert env_vars["GITHUB_ACTIONS"] is None
        assert env_vars["USER"] is None

    @patch('os.sys.executable', '/usr/bin/python3')
    def test_get_environment_info_python_executable(self):
        """Test getting Python executable path."""
        detector = EnvironmentDetector()

        env_info = detector.get_environment_info()

        assert env_info["python_executable"] == "/usr/bin/python3"

    def test_scan_file_patterns(self):
        """Test that all expected scan file patterns are checked."""
        detector = EnvironmentDetector()

        # This is a bit of a white-box test to ensure we're checking for all expected patterns
        # by looking at the detect_scan_files method implementation

        original_dir = os.getcwd()

        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)

            # Create all possible scan files
            expected_files = [
                "risk_report.json",
                "dependencies.json",
                "sbom.json",
                "validation_report.json",
                "scan_metadata.json"
            ]

            for filename in expected_files:
                with open(filename, "w") as f:
                    f.write(f'{{"type": "{filename}"}}')

            scan_files = detector.detect_scan_files()

            # Should detect all files
            for expected_file in expected_files:
                assert expected_file in scan_files
                assert scan_files[expected_file] == expected_file

        os.chdir(original_dir)