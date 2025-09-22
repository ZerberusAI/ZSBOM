"""Tests for transitive dependency analysis functionality."""

import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from depclass.extract import DependencyFileParser, extract_dependencies
from depclass.db.vulnerability import VulnerabilityCache


class TestTransitiveDependencyAnalysis:
    """Test the transitive dependency analysis functionality."""

    def test_extract_dependencies_with_transitive_analysis_no_pip_tools(self):
        """Test behavior when pip-tools is not available."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a simple requirements.txt
            req_file = Path(temp_dir) / "requirements.txt"
            req_file.write_text("requests==2.28.0\nnumpy>=1.21.0")
            
            parser = DependencyFileParser(temp_dir)
            
            # Mock pip-tools not being available
            with patch.object(parser, '_check_pip_tools_available', return_value=False):
                result = parser.extract_dependencies_with_transitive_analysis({})
            
            # Should have dependencies but dependencies analysis should be empty
            assert "dependencies" in result
            assert "dependencies_analysis" in result
            assert result["dependencies_analysis"]["total_packages"] == 0
            assert "requests" in result["dependencies"]["requirements.txt"]

    def test_extract_dependencies_with_transitive_analysis_no_requirements(self):
        """Test behavior when no requirements are found."""
        with tempfile.TemporaryDirectory() as temp_dir:
            parser = DependencyFileParser(temp_dir)
            
            # Mock pip-tools being available
            with patch.object(parser, '_check_pip_tools_available', return_value=True):
                result = parser.extract_dependencies_with_transitive_analysis({})
            
            # Should have empty dependencies and empty dependencies analysis
            assert "dependencies" in result
            assert "dependencies_analysis" in result
            assert result["dependencies_analysis"]["total_packages"] == 0
            assert result["dependencies_analysis"]["dependency_tree"] == {}

    def test_consolidate_requirements_with_file_priority(self):
        """Test requirement consolidation respects file priority."""
        parser = DependencyFileParser()
        
        dependencies = {
            "requirements.txt": {"requests": "==2.25.0", "numpy": ">=1.20.0"},
            "pyproject.toml": {"requests": ">=2.28.0", "flask": ">=2.0.0"},
            "runtime": {"requests": "2.28.1", "numpy": "1.21.5", "flask": "2.1.0"}
        }
        
        config = {
            "version_consistency": {
                "file_priority": ["pyproject.toml", "requirements.txt", "setup.py"]
            }
        }
        
        consolidated = parser._consolidate_requirements(dependencies, config)
        
        # pyproject.toml should have higher priority
        assert "requests>=2.28.0" in consolidated
        assert "numpy>=1.20.0" in consolidated  # Only in requirements.txt
        assert "flask>=2.0.0" in consolidated   # Only in pyproject.toml

    def test_build_pip_compile_args_with_private_repos(self):
        """Test pip-compile argument building with private repository configuration."""
        parser = DependencyFileParser()
        
        config = {
            "private_repositories": {
                "index_url": "https://private-pypi.company.com/simple",
                "extra_index_urls": ["https://extra1.com/simple", "https://extra2.com/simple"],
                "trusted_hosts": ["private-pypi.company.com", "extra1.com"],
                "find_links": ["/local/packages", "https://downloads.company.com"],
                "no_index": False
            }
        }
        
        args = parser._build_pip_compile_args(config)
        
        # Check basic args
        assert "pip-compile" in args
        assert "--dry-run" in args
        assert "--quiet" in args
        assert "--strip-extras" in args
        
        # Check private repo args
        assert "--index-url" in args
        assert "https://private-pypi.company.com/simple" in args
        
        assert "--extra-index-url" in args
        assert "https://extra1.com/simple" in args
        assert "https://extra2.com/simple" in args
        
        assert "--trusted-host" in args
        assert "private-pypi.company.com" in args
        assert "extra1.com" in args
        
        assert "--find-links" in args
        assert "/local/packages" in args
        assert "https://downloads.company.com" in args

    def test_build_pip_compile_args_with_no_index(self):
        """Test pip-compile argument building with no_index enabled."""
        parser = DependencyFileParser()
        
        config = {
            "private_repositories": {
                "no_index": True,
                "find_links": ["/local/packages"]
            }
        }
        
        args = parser._build_pip_compile_args(config)
        
        assert "--no-index" in args
        assert "--find-links" in args
        assert "/local/packages" in args

    def test_cache_key_generation(self):
        """Test cache key generation includes all relevant configuration."""
        parser = DependencyFileParser()
        
        requirements = "requests>=2.28.0\nnumpy>=1.21.0"
        config = {
            "private_repositories": {
                "index_url": "https://pypi.org/simple",
                "extra_index_urls": ["https://extra.com/simple"],
                "trusted_hosts": ["pypi.org"],
                "find_links": [],
                "no_index": False
            }
        }
        
        key1 = parser._get_cache_key(requirements, config)
        
        # Modify config slightly
        config["private_repositories"]["trusted_hosts"] = ["pypi.org", "extra.com"]
        key2 = parser._get_cache_key(requirements, config)
        
        # Keys should be different
        assert key1 != key2
        assert len(key1) == 64  # SHA256 hex digest length
        assert len(key2) == 64

    def test_parse_dependency_tree_basic(self):
        """Test parsing of pip-compile output for dependency tree."""
        parser = DependencyFileParser()
        
        pip_output = """# This file is autogenerated by pip-compile with python 3.8
# To update, run:
#
#    pip-compile
#
certifi==2022.12.7
    # via requests
charset-normalizer==3.1.0
    # via requests
idna==3.4
    # via requests
requests==2.28.2
    # via -r requirements.in
urllib3==1.26.15
    # via requests
"""
        
        original_dependencies = {
            "requirements.txt": {"requests": ">=2.28.0"},
            "runtime": {"requests": "2.28.2", "certifi": "2022.12.7"}
        }
        
        result = parser._parse_dependency_tree(pip_output, original_dependencies, {})
        
        # Check classification
        assert result["classification"]["requests"] == "direct"
        assert result["classification"]["certifi"] == "transitive"
        assert result["classification"]["urllib3"] == "transitive"
        
        # Check dependency tree
        assert "requests" in result["dependency_tree"]["certifi"]
        assert "requests" in result["dependency_tree"]["urllib3"]
        
        # Check depth levels
        assert result["depth_levels"]["requests"] == 0  # Direct dependency
        assert result["depth_levels"]["certifi"] == 1   # First level transitive
        
        # Check direct sources
        assert "requirements.txt" in result["direct_sources"]["requests"]

    def test_calculate_depth_levels(self):
        """Test depth level calculation for complex dependency trees."""
        parser = DependencyFileParser()
        
        dependency_tree = {
            "certifi": ["requests"],
            "urllib3": ["requests"],
            "click": ["flask"],
            "jinja2": ["flask"],
            "markupsafe": ["jinja2"],
            "itsdangerous": ["flask"]
        }
        
        direct_packages = {"requests", "flask"}
        
        depth_levels = parser._calculate_depth_levels(dependency_tree, direct_packages)
        
        # Direct packages should be depth 0
        assert depth_levels["requests"] == 0
        assert depth_levels["flask"] == 0
        
        # First level dependencies should be depth 1
        assert depth_levels["certifi"] == 1
        assert depth_levels["click"] == 1
        assert depth_levels["jinja2"] == 1
        
        # Second level dependencies should be depth 2
        assert depth_levels["markupsafe"] == 2

    def test_build_dependencies_structure(self):
        """Test building the new hierarchical dependencies.json structure."""
        parser = DependencyFileParser()
        
        pip_output = """# This file is autogenerated by pip-compile with python 3.8
# To update, run:
#
#    pip-compile
#
certifi==2022.12.7
    # via requests
charset-normalizer==3.1.0
    # via requests
idna==3.4
    # via requests
requests==2.28.2
    # via -r requirements.in
urllib3==1.26.15
    # via requests
flask==2.1.0
jinja2==3.1.2
    # via flask
click==8.1.0
    # via flask
"""
        
        original_dependencies = {
            "requirements.txt": {"requests": ">=2.28.0", "flask": ">=2.0.0"},
            "pyproject.toml": {"click": ">=8.0.0"}
        }
        
        result = parser._build_dependencies_structure(pip_output, original_dependencies, {})
        
        # Check total packages count
        assert result["total_packages"] == 8  # requests, certifi, charset-normalizer, idna, urllib3, flask, jinja2, click
        
        # Check hierarchical dependency tree structure
        dependency_tree = result["dependency_tree"]
        
        # Should have direct dependencies as top-level keys with resolved versions
        assert "requests==2.28.2" in dependency_tree
        assert "flask==2.1.0" in dependency_tree
        
        # Check direct dependency structure
        requests_info = dependency_tree["requests==2.28.2"]
        assert requests_info["type"] == "direct"
        assert "requirements.txt" in requests_info["declared_in"]
        assert "children" in requests_info
        
        # Check transitive dependencies as children
        children = requests_info["children"]
        assert "certifi==2022.12.7" in children
        assert "urllib3==1.26.15" in children
        
        # Check child structure
        certifi_info = children["certifi==2022.12.7"]
        assert certifi_info["type"] == "transitive"
        assert certifi_info["depth"] == 1
        
        # Check package_files structure
        package_files = result["package_files"]
        assert len(package_files) == 2  # requirements.txt and pyproject.toml
        
        req_file = next(f for f in package_files if f["path"] == "requirements.txt")
        assert "requests>=2.28.0" in req_file["packages"]
        assert "flask>=2.0.0" in req_file["packages"]


class TestVulnerabilityCacheExtension:
    """Test the extended VulnerabilityCache functionality."""

    def test_pip_compile_cache_operations(self):
        """Test pip-compile cache storage and retrieval."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "test_cache.db"
            cache = VulnerabilityCache(str(cache_path))
            
            cache_key = "test_key_123"
            requirements_hash = "hash_456"
            resolved_output = "requests==2.28.0\ncertifi==2022.12.7"
            
            # Store result
            success = cache.cache_pip_compile_result(cache_key, requirements_hash, resolved_output)
            assert success
            
            # Retrieve result (should be found within TTL)
            cached_result = cache.get_cached_pip_compile(cache_key, ttl_hours=24)
            assert cached_result == resolved_output
            
            # Test TTL expiration (simulate expired cache)
            cached_result_expired = cache.get_cached_pip_compile(cache_key, ttl_hours=0)
            assert cached_result_expired is None


class TestIntegrationWithConfig:
    """Test integration with configuration and CLI."""

    def test_extract_dependencies_with_config(self):
        """Test the main extract_dependencies function with configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            req_file = Path(temp_dir) / "requirements.txt"
            req_file.write_text("requests>=2.28.0")
            
            config = {
                "transitive_analysis": {"pip_compile_timeout": 30},
                "private_repositories": {"index_url": "", "extra_index_urls": []},
                "caching": {"enabled": False}
            }
            
            # Mock pip-tools not available for this test
            with patch('depclass.extract.DependencyFileParser._check_pip_tools_available', return_value=False):
                result = extract_dependencies(temp_dir, config)
            
            # Should return new format with both dependencies and dependencies_analysis
            assert isinstance(result, dict)
            assert "dependencies" in result
            assert "dependencies_analysis" in result
            assert result["dependencies_analysis"]["total_packages"] == 0
            
            # Dependencies should still be extracted
            assert "requirements.txt" in result["dependencies"]
            assert "requests" in result["dependencies"]["requirements.txt"]

    def test_backwards_compatibility_fallback(self):
        """Test that the function gracefully handles new format expectations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            req_file = Path(temp_dir) / "requirements.txt"
            req_file.write_text("requests>=2.28.0")
            
            # Test without config (should still work)
            with patch('depclass.extract.DependencyFileParser._check_pip_tools_available', return_value=False):
                result = extract_dependencies(temp_dir)
            
            # Should return new format even without config
            assert "dependencies" in result
            assert "dependencies_analysis" in result