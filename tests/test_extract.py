"""Tests for enhanced dependency extraction functionality."""

import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from packaging.specifiers import SpecifierSet

from depclass.extract import DependencyFileParser, extract


class TestDependencyFileParser:
    """Test the enhanced DependencyFileParser class."""

    def test_requirements_txt_parsing(self):
        """Test parsing of requirements.txt files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            req_file = Path(temp_dir) / "requirements.txt"
            req_file.write_text("""
# Test requirements file
requests==2.28.0
numpy>=1.21.0,<2.0.0
flask>=2.0.0
# Comment line
-e git+https://github.com/user/repo.git#egg=mypackage
django
            """.strip())
            
            parser = DependencyFileParser(temp_dir)
            deps = parser._parse_requirements_txt(req_file)
            
            assert deps["requests"] == "==2.28.0"
            assert deps["numpy"] == "<2.0.0,>=1.21.0"  # packaging reorders specifiers
            assert deps["flask"] == ">=2.0.0"
            assert deps["django"] == ""
            assert "mypackage" not in deps  # Editable installs should be skipped

    def test_pyproject_toml_pep621_parsing(self):
        """Test parsing of pyproject.toml files with PEP 621 format."""
        with tempfile.TemporaryDirectory() as temp_dir:
            toml_file = Path(temp_dir) / "pyproject.toml"
            toml_file.write_text("""
[project]
name = "test-project"
dependencies = [
    "requests>=2.28.0,<3.0.0",
    "numpy==1.21.5",
    "flask>=2.0.0"
]
            """.strip())
            
            parser = DependencyFileParser(temp_dir)
            deps = parser._parse_pyproject_toml(toml_file)
            
            assert deps["requests"] == "<3.0.0,>=2.28.0"  # packaging reorders specifiers
            assert deps["numpy"] == "==1.21.5"
            assert deps["flask"] == ">=2.0.0"

    def test_pyproject_toml_poetry_parsing(self):
        """Test parsing of pyproject.toml files with Poetry format."""
        with tempfile.TemporaryDirectory() as temp_dir:
            toml_file = Path(temp_dir) / "pyproject.toml"
            toml_file.write_text("""
[tool.poetry]
name = "test-project"

[tool.poetry.dependencies]
python = "^3.8"
requests = "^2.28.0"
numpy = "~1.21.0"
flask = {version = ">=2.0.0", optional = false}
pytest = {version = "^7.0.0", optional = true}
            """.strip())
            
            parser = DependencyFileParser(temp_dir)
            deps = parser._parse_pyproject_toml(toml_file)
            
            assert deps["requests"] == ">=2.28.0,<3.0.0"  # Converted from ^2.28.0
            assert deps["numpy"] == ">=1.21.0,<1.22.0"   # Converted from ~1.21.0
            assert deps["flask"] == ">=2.0.0"
            assert "pytest" not in deps  # Optional dependencies should be skipped
            assert "python" not in deps  # Python version constraint should be skipped

    def test_setup_py_parsing(self):
        """Test parsing of setup.py files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            setup_file = Path(temp_dir) / "setup.py"
            setup_file.write_text("""
from setuptools import setup

setup(
    name="test-package",
    version="1.0.0",
    install_requires=[
        "requests>=2.28.0",
        "numpy==1.21.5",
        "flask>=2.0.0,<3.0.0",
    ],
    extras_require={
        "dev": ["pytest>=7.0.0"],
    }
)
            """.strip())
            
            parser = DependencyFileParser(temp_dir)
            deps = parser._parse_setup_py(setup_file)
            print(deps)
            
            assert deps["requests"] == ">=2.28.0"
            assert deps["numpy"] == "==1.21.5"
            assert SpecifierSet(deps["flask"]) == SpecifierSet(">=2.0.0,<3.0.0")

    def test_setup_cfg_parsing(self):
        """Test parsing of setup.cfg files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cfg_file = Path(temp_dir) / "setup.cfg"
            cfg_file.write_text("""
[metadata]
name = test-package
version = 1.0.0

[options]
install_requires =
    requests>=2.28.0
    numpy==1.21.5
    flask>=2.0.0,<3.0.0

[options.extras_require]
dev = 
    pytest>=7.0.0
            """.strip())
            
            parser = DependencyFileParser(temp_dir)
            deps = parser._parse_setup_cfg(cfg_file)
            
            assert deps["requests"] == ">=2.28.0"
            assert deps["numpy"] == "==1.21.5"
            assert SpecifierSet(deps["flask"]) == SpecifierSet(">=2.0.0,<3.0.0")

    def test_pipfile_parsing(self):
        """Test parsing of Pipfile files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            pipfile = Path(temp_dir) / "Pipfile"
            pipfile.write_text("""
[packages]
requests = ">=2.28.0"
numpy = {version = "==1.21.5"}
flask = "*"
django = {version = ">=3.0.0", markers="python_version >= '3.8'"}

[dev-packages]
pytest = ">=7.0.0"
            """.strip())
            
            parser = DependencyFileParser(temp_dir)
            deps = parser._parse_pipfile(pipfile)
            
            assert deps["requests"] == ">=2.28.0"
            assert deps["numpy"] == "==1.21.5"
            assert deps["flask"] == ""  # "*" converts to empty string
            assert deps["django"] == ">=3.0.0"

    def test_file_priority_order(self):
        """Test that files are processed in correct priority order."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create multiple files with same package but different versions
            req_file = Path(temp_dir) / "requirements.txt"
            req_file.write_text("requests==2.25.0")
            
            toml_file = Path(temp_dir) / "pyproject.toml"
            toml_file.write_text("""
[project]
dependencies = ["requests>=2.28.0"]
            """)
            
            parser = DependencyFileParser(temp_dir)
            deps = parser.extract_dependencies()
            
            # pyproject.toml should have higher priority than requirements.txt
            assert "pyproject.toml" in deps
            assert "requirements.txt" in deps
            assert deps["pyproject.toml"]["requests"] == ">=2.28.0"
            assert deps["requirements.txt"]["requests"] == "==2.25.0"

    def test_poetry_version_conversion(self):
        """Test Poetry version constraint conversion."""
        parser = DependencyFileParser()
        
        # Test caret constraints
        assert parser._convert_poetry_spec("^1.2.3") == ">=1.2.3,<2.0.0"
        assert parser._convert_poetry_spec("^0.2.3") == ">=0.2.3,<1.0.0"
        
        # Test tilde constraints
        assert parser._convert_poetry_spec("~1.2.3") == ">=1.2.3,<1.3.0"
        assert parser._convert_poetry_spec("~0.2.3") == ">=0.2.3,<0.3.0"
        
        # Test standard constraints
        assert parser._convert_poetry_spec(">=1.0.0") == ">=1.0.0"
        assert parser._convert_poetry_spec("==1.2.3") == "==1.2.3"


    def test_error_handling(self):
        """Test error handling for malformed files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create malformed requirements.txt
            req_file = Path(temp_dir) / "requirements.txt"
            req_file.write_text("""
requests==2.28.0
#invalid-requirement-line-without-proper-format
numpy>=1.21.0
            """)
            
            parser = DependencyFileParser(temp_dir)
            deps = parser._parse_requirements_txt(req_file)
            
            # Should parse valid lines and skip invalid ones
            assert deps["requests"] == "==2.28.0"
            assert deps["numpy"] == ">=1.21.0"
            assert len(deps) == 2  # Invalid line should be skipped

    def test_empty_and_missing_files(self):
        """Test handling of empty and missing dependency files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create empty requirements.txt
            req_file = Path(temp_dir) / "requirements.txt"
            req_file.write_text("")
            
            parser = DependencyFileParser(temp_dir)
            deps = parser.extract_dependencies()
            print(deps)
            
            assert "requirements.txt" not in deps

    def test_comments_and_whitespace_handling(self):
        """Test proper handling of comments and whitespace."""
        with tempfile.TemporaryDirectory() as temp_dir:
            req_file = Path(temp_dir) / "requirements.txt"
            req_file.write_text("""
# This is a comment
   requests==2.28.0   # Inline comment
   
numpy>=1.21.0

# Another comment
flask>=2.0.0
            """)
            
            parser = DependencyFileParser(temp_dir)
            deps = parser._parse_requirements_txt(req_file)
            
            assert deps["requests"] == "==2.28.0"
            assert deps["numpy"] == ">=1.21.0"
            assert deps["flask"] == ">=2.0.0"
            assert len(deps) == 3


class TestExtractDependenciesFunction:
    """Test the main extract_dependencies function."""

    def test_extract_dependencies_integration(self):
        """Test the main extract_dependencies function."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a simple requirements.txt
            req_file = Path(temp_dir) / "requirements.txt"
            req_file.write_text("requests==2.28.0\nnumpy>=1.21.0")
            
            result = extract(project_path=temp_dir)
            
            # New format includes both dependencies and dependencies_analysis
            assert "dependencies" in result
            assert "dependencies_analysis" in result
            
            deps = result["dependencies"]
            assert "requirements.txt" in deps
            assert deps["requirements.txt"]["requests"] == "==2.28.0"
            assert deps["requirements.txt"]["numpy"] == ">=1.21.0"

    def test_extract_dependencies_current_directory(self):
        """Test extract_dependencies with default current directory."""
        # This should run without errors
        result = extract()

        assert "dependencies" in result
        assert "dependencies_analysis" in result

    def test_multiple_file_formats(self):
        """Test extraction from multiple file formats simultaneously."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create requirements.txt
            req_file = Path(temp_dir) / "requirements.txt"
            req_file.write_text("requests==2.25.0")
            
            # Create pyproject.toml with higher priority
            toml_file = Path(temp_dir) / "pyproject.toml"
            toml_file.write_text("""
[project]
dependencies = ["requests>=2.28.0", "flask>=2.0.0"]
            """)
            
            result = extract(project_path=temp_dir)
            
            # New format includes both dependencies and dependencies_analysis
            assert "dependencies" in result
            assert "dependencies_analysis" in result
            
            deps = result["dependencies"]
            # Should have both files
            assert "requirements.txt" in deps
            assert "pyproject.toml" in deps
            
            # Each file should have its own version
            assert deps["requirements.txt"]["requests"] == "==2.25.0"
            assert deps["pyproject.toml"]["requests"] == ">=2.28.0"
            assert deps["pyproject.toml"]["flask"] == ">=2.0.0"