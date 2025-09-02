"""Comprehensive unit tests for dimension scorers."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from unittest.mock import patch, MagicMock

from depclass.dimension_scorers import (
    DeclaredVsInstalledScorer,
    KnownCVEsScorer,
    CWECoverageScorer,
    PackageAbandonmentScorer,
    TyposquatHeuristicsScorer,
)


class TestDeclaredVsInstalledScorer:
    """Test the enhanced DeclaredVsInstalledScorer dimension with 3-factor scoring."""
    
    def test_perfect_match_exact_version(self):
        """Test Factor 1: Exact version match (4 points)."""
        scorer = DeclaredVsInstalledScorer()
        score = scorer.score("test_package", "1.0.0", "1.0.0")
        assert score == 10.0  # 4 + 3 + 3 (perfect match + fully pinned + consistent)
    
    def test_no_declared_version(self):
        """Test Factor 1: No declared version (0 points)."""
        scorer = DeclaredVsInstalledScorer()
        score = scorer.score("test_package", "1.0.0", None)
        assert score == 3.0  # 0 + 0 + 3 (no spec + no constraint + consistent)
    
    def test_range_satisfied(self):
        """Test Factor 1: Range constraint satisfied (3 points)."""
        scorer = DeclaredVsInstalledScorer()
        score = scorer.score("test_package", "1.5.0", ">=1.0.0,<2.0.0")
        assert score == 8.0  # 3 + 2 + 3 (range satisfied + bounded range + consistent)
    
    def test_range_violated(self):
        """Test Factor 1: Range constraint violated (1 point)."""
        scorer = DeclaredVsInstalledScorer()
        score = scorer.score("test_package", "2.0.0", ">=1.0.0,<2.0.0")
        assert score == 6.0  # 1 + 2 + 3 (range violated + bounded range + consistent)
    
    def test_specification_completeness_fully_pinned(self):
        """Test Factor 2: Fully pinned specification (3 points)."""
        scorer = DeclaredVsInstalledScorer()
        score = scorer.score("test_package", "1.0.0", "==1.0.0")
        assert score == 10.0  # 4 + 3 + 3 (exact match + fully pinned + consistent)
    
    def test_specification_completeness_bounded_range(self):
        """Test Factor 2: Bounded range specification (2 points)."""
        scorer = DeclaredVsInstalledScorer()
        score = scorer.score("test_package", "1.5.0", ">=1.0.0,<2.0.0")
        assert score == 8.0  # 3 + 2 + 3 (range satisfied + bounded range + consistent)
    
    def test_specification_completeness_minimum_only(self):
        """Test Factor 2: Minimum only specification (1 point)."""
        scorer = DeclaredVsInstalledScorer()
        score = scorer.score("test_package", "1.5.0", ">=1.0.0")
        assert score == 7.0  # 3 + 1 + 3 (range satisfied + minimum only + consistent)
    
    def test_specification_completeness_no_constraint(self):
        """Test Factor 2: No constraint (0 points)."""
        scorer = DeclaredVsInstalledScorer()
        score = scorer.score("test_package", "1.0.0", None)
        assert score == 3.0  # 0 + 0 + 3 (no spec + no constraint + consistent)
    
    def test_cross_file_consistency_with_specs(self):
        """Test Factor 3: Cross-file consistency analysis."""
        scorer = DeclaredVsInstalledScorer()
        
        # Test with consistent specs across files
        package_specs = {
            "pyproject.toml": {"test_package": ">=1.0.0,<2.0.0"},
            "requirements.txt": {"test_package": ">=1.0.0,<2.0.0"}
        }
        
        score = scorer.score(
            "test_package", "1.5.0", ">=1.0.0,<2.0.0",
            package_specs=package_specs
        )
        assert score == 8.0  # 3 + 2 + 3 (range satisfied + bounded range + consistent)
    
    def test_cross_file_consistency_with_conflicts(self):
        """Test Factor 3: Cross-file consistency with conflicts."""
        scorer = DeclaredVsInstalledScorer()
        
        # Test with incompatible specs across files
        package_specs = {
            "pyproject.toml": {"test_package": ">=1.0.0,<2.0.0"},
            "requirements.txt": {"test_package": ">=3.0.0,<4.0.0"}
        }
        
        score = scorer.score(
            "test_package", "1.5.0", ">=1.0.0,<2.0.0",
            package_specs=package_specs
        )
        assert score == 5.0  # 3 + 2 + 0 (range satisfied + bounded range + major conflicts)
    
    def test_cross_file_consistency_minor_conflicts(self):
        """Test Factor 3: Cross-file consistency with minor conflicts."""
        scorer = DeclaredVsInstalledScorer()
        
        # Test with compatible but different specs
        package_specs = {
            "pyproject.toml": {"test_package": ">=1.0.0,<3.0.0"},
            "requirements.txt": {"test_package": ">=1.5.0,<2.0.0"}
        }
        
        score = scorer.score(
            "test_package", "1.8.0", ">=1.0.0,<3.0.0",
            package_specs=package_specs
        )
        assert score == 6.0  # 3 + 2 + 1 (range satisfied + bounded range + minor conflicts)
    
    def test_poetry_constraints(self):
        """Test Poetry-style constraints (^, ~)."""
        scorer = DeclaredVsInstalledScorer()
        
        # Test caret constraint
        score = scorer.score("test_package", "1.5.0", "^1.0.0")
        assert score == 8.0  # 3 + 2 + 3 (range satisfied + bounded range + consistent)
        
        # Test tilde constraint
        score = scorer.score("test_package", "1.2.5", "~1.2.0")
        assert score == 8.0  # 3 + 2 + 3 (range satisfied + bounded range + consistent)
    
    def test_get_details_comprehensive(self):
        """Test detailed scoring information."""
        scorer = DeclaredVsInstalledScorer()
        
        package_specs = {
            "pyproject.toml": {"test_package": ">=1.0.0,<2.0.0"},
            "requirements.txt": {"test_package": ">=1.5.0,<2.0.0"}
        }
        
        details = scorer.get_details(
            "test_package", "1.8.0", ">=1.0.0,<2.0.0",
            package_specs=package_specs
        )
        
        assert details["dimension"] == "declared_vs_installed"
        assert "factors" in details
        assert details["factors"]["version_match_precision"] == 3.0
        assert details["factors"]["specification_completeness"] == 2.0
        assert details["factors"]["cross_file_consistency"] == 1.0
        assert details["package_details"]["match_status"] == "range_satisfied"
        assert details["details"]["specification_quality"] == "bounded_range"
        assert details["details"]["consistency_status"] == "minor_conflicts"
        assert "files_found" in details["details"]
    
    def test_invalid_version_handling(self):
        """Test handling of invalid version strings."""
        scorer = DeclaredVsInstalledScorer()
        
        # Invalid installed version - should still score specification and consistency
        score = scorer.score("test_package", "invalid.version", "1.0.0")
        assert score == 6.0  # 0 + 3 + 3 (invalid precision + fully pinned + consistent)
        
        # Invalid declared version - should score only consistency
        score = scorer.score("test_package", "1.0.0", "invalid.spec")
        assert score == 3.0  # 0 + 0 + 3 (unspecified + no constraint + consistent)
    
    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        scorer = DeclaredVsInstalledScorer()
        
        # Empty string declared version
        score = scorer.score("test_package", "1.0.0", "")
        assert score == 3.0  # 0 + 0 + 3 (no spec + no constraint + consistent)
        
        # Very specific constraint that's violated
        score = scorer.score("test_package", "1.0.1", "==1.0.0")
        assert score == 7.0  # 1 + 3 + 3 (range violated + fully pinned + consistent)
        
        # Single file specification
        package_specs = {
            "pyproject.toml": {"test_package": ">=1.0.0"}
        }
        score = scorer.score(
            "test_package", "1.5.0", ">=1.0.0",
            package_specs=package_specs
        )
        assert score == 7.0  # 3 + 1 + 3 (range satisfied + minimum only + consistent)


class TestKnownCVEsScorer:
    """Test the KnownCVEsScorer dimension."""
    
    def test_no_cves(self):
        scorer = KnownCVEsScorer()
        score = scorer.score("test_package", "1.0.0", cve_list=[])
        assert score == 10.0
    
    def test_critical_cve(self):
        scorer = KnownCVEsScorer()
        cve_list = [{
            "package_name": "test_package",
            "vuln_id": "CVE-2023-1234",
            "severity": "CRITICAL",
            "cvss_score": 9.8
        }]
        score = scorer.score("test_package", "1.0.0", cve_list=cve_list)
        assert score == 0.0
    
    def test_high_severity_cve(self):
        scorer = KnownCVEsScorer()
        cve_list = [{
            "package_name": "test_package",
            "vuln_id": "CVE-2023-1234",
            "severity": "HIGH",
            "cvss_score": 8.5
        }]
        score = scorer.score("test_package", "1.0.0", cve_list=cve_list)
        assert score <= 2.0  # HIGH severity should give low score
    
    def test_medium_severity_cve(self):
        scorer = KnownCVEsScorer()
        cve_list = [{
            "package_name": "test_package",
            "vuln_id": "CVE-2023-1234",
            "severity": "MEDIUM",
            "cvss_score": 5.5
        }]
        score = scorer.score("test_package", "1.0.0", cve_list=cve_list)
        assert score <= 5.0  # MEDIUM severity should give moderate score
    
    def test_multiple_cves(self):
        scorer = KnownCVEsScorer()
        cve_list = [
            {
                "package_name": "test_package",
                "vuln_id": "CVE-2023-1234",
                "severity": "HIGH",
                "cvss_score": 8.5
            },
            {
                "package_name": "test_package",
                "vuln_id": "CVE-2023-5678",
                "severity": "MEDIUM",
                "cvss_score": 5.0
            }
        ]
        score = scorer.score("test_package", "1.0.0", cve_list=cve_list)
        assert score <= 2.0  # Multiple CVEs should reduce score
    
    def test_wrong_package_cves(self):
        scorer = KnownCVEsScorer()
        cve_list = [{
            "package_name": "other_package",
            "vuln_id": "CVE-2023-1234",
            "severity": "CRITICAL"
        }]
        score = scorer.score("test_package", "1.0.0", cve_list=cve_list)
        assert score == 10.0
    
    def test_get_details(self):
        scorer = KnownCVEsScorer()
        cve_list = [{
            "package_name": "test_package",
            "vuln_id": "CVE-2023-1234",
            "severity": "HIGH",
            "summary": "Test vulnerability"
        }]
        details = scorer.get_details("test_package", "1.0.0", cve_list=cve_list)
        assert details["dimension"] == "known_cves"
        assert details["cve_count"] == 1
        assert len(details["cves"]) == 1
        assert details["worst_severity"] == "HIGH"


class TestCWECoverageScorer:
    """Test the CWECoverageScorer dimension."""
    
    def test_no_cwes(self):
        scorer = CWECoverageScorer()
        score = scorer.score("test_package", "1.0.0", cve_list=[])
        assert score == 10.0
    
    def test_high_severity_cwe(self):
        scorer = CWECoverageScorer()
        cve_list = [{
            "package_name": "test_package",
            "vuln_id": "CVE-2023-1234",
            "cwes": ["CWE-78"]  # OS Command Injection - HIGH severity
        }]
        score = scorer.score("test_package", "1.0.0", cve_list=cve_list)
        assert score <= 1.0  # HIGH severity CWE should give low score
    
    def test_medium_severity_cwe(self):
        scorer = CWECoverageScorer()
        cve_list = [{
            "package_name": "test_package",
            "vuln_id": "CVE-2023-1234",
            "cwes": ["CWE-200"]  # Information Disclosure - MEDIUM severity
        }]
        score = scorer.score("test_package", "1.0.0", cve_list=cve_list)
        assert score == 4.0
    
    def test_multiple_cwes(self):
        scorer = CWECoverageScorer()
        cve_list = [{
            "package_name": "test_package",
            "vuln_id": "CVE-2023-1234",
            "cwes": ["CWE-78", "CWE-79"]  # Multiple high severity CWEs
        }]
        score = scorer.score("test_package", "1.0.0", cve_list=cve_list)
        assert score < 1.0  # Multiple CWEs should reduce score further
    
    def test_get_details(self):
        scorer = CWECoverageScorer()
        cve_list = [{
            "package_name": "test_package",
            "vuln_id": "CVE-2023-1234",
            "cwes": ["CWE-78"]
        }]
        details = scorer.get_details("test_package", "1.0.0", cve_list=cve_list)
        assert details["dimension"] == "cwe_coverage"
        assert details["cwe_count"] == 1
        assert len(details["cwes"]) == 1
        assert details["worst_severity"] == "HIGH"


class TestPackageAbandonmentScorer:
    """Test the PackageAbandonmentScorer dimension."""
    
    @patch('depclass.services.pypi_service.PyPIMetadataService.get_repository_url')
    def test_no_repo_url(self, mock_get_repo_url):
        """Test scoring when no repository URL is available."""
        mock_get_repo_url.return_value = None
        
        scorer = PackageAbandonmentScorer()
        score = scorer.score("test_package", "1.0.0")
        # Should get default scores: 2.5 (commit) + 1.5 (frequency) + 1.0 (release) = 5.0
        assert score == 5.0
    
    @patch('depclass.services.pypi_service.PyPIMetadataService.get_repository_url')
    @patch('requests.Session.get')
    def test_recent_commit(self, mock_session_get, mock_get_repo_url):
        """Test scoring with recent commit activity via GitHub API."""
        mock_get_repo_url.return_value = "https://github.com/test/repo.git"
        
        # Mock GitHub API response for recent commit (15 days ago)
        from datetime import datetime, timezone, timedelta
        recent_date = datetime.now(timezone.utc) - timedelta(days=15)
        
        mock_commit_response = MagicMock()
        mock_commit_response.status_code = 200
        mock_commit_response.json.return_value = {
            'commit': {
                'committer': {
                    'date': recent_date.isoformat().replace('+00:00', 'Z')
                }
            }
        }
        
        # Mock git ls-remote response
        with patch('subprocess.check_output') as mock_subprocess:
            mock_subprocess.return_value = "abc123def456 refs/heads/main"
            mock_session_get.return_value = mock_commit_response
            
            scorer = PackageAbandonmentScorer()
            score = scorer.score("test_package", "1.0.0")
            # Should get 5 points for recent commit + 1 point for release frequency default
            assert score >= 5.0
    
    @patch('depclass.services.pypi_service.PyPIMetadataService.get_repository_url')
    def test_old_commit(self, mock_get_repo_url):
        """Test scoring with no repository available (simulates old/inaccessible repo)."""
        mock_get_repo_url.return_value = None
        
        scorer = PackageAbandonmentScorer()
        score = scorer.score("test_package", "1.0.0")
        # Should get default scores: 2.5 (commit) + 1.5 (frequency) + 1.0 (release) = 5.0
        assert score == 5.0
    
    @patch('depclass.services.pypi_service.PyPIMetadataService.get_repository_url')
    @patch('depclass.services.pypi_service.PyPIMetadataService.get_package_metadata')
    def test_recent_release(self, mock_get_metadata, mock_get_repo_url):
        """Test scoring with recent PyPI release."""
        mock_get_repo_url.return_value = None  # No repository available
        
        # Mock recent PyPI release
        from datetime import datetime, timezone
        recent_date = datetime.now(timezone.utc).replace(day=1)  # 1 month ago
        mock_get_metadata.return_value = {
            'pypi_data_available': True,
            'metadata': {
                "releases": {
                    "1.0.0": [{
                        "upload_time": recent_date.isoformat()
                    }]
                }
            }
        }
        
        scorer = PackageAbandonmentScorer()
        score = scorer.score("test_package", "1.0.0")
        # Should get 2 points for recent release
        assert score >= 2.0
    
    @patch('depclass.services.pypi_service.PyPIMetadataService.get_repository_url')
    def test_get_details(self, mock_get_repo_url):
        mock_get_repo_url.return_value = None  # No repository available
        
        scorer = PackageAbandonmentScorer()
        details = scorer.get_details("test_package", "1.0.0")
        assert details["dimension"] == "package_abandonment"
        assert "components" in details
        assert details["repository_available"] == False
        assert details["repository_url"] is None
        assert "last_commit" in details["components"]
        assert "commit_frequency" in details["components"]
        assert "release_frequency" in details["components"]


class TestTyposquatHeuristicsScorer:
    """Test the TyposquatHeuristicsScorer dimension with 5-factor analysis."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Mock data for testing
        self.mock_top_packages = [
            {"project": "requests", "download_count": 1000000},
            {"project": "numpy", "download_count": 800000},
            {"project": "flask", "download_count": 600000},
            {"project": "django", "download_count": 500000},
            {"project": "pandas", "download_count": 400000},
        ]
        
        self.mock_pypi_metadata = {
            "metadata": {"info": {"name": "test_package"}},
            "download_count": 1500,
            "creation_date": "2023-01-01T00:00:00Z"
        }
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_factor1_string_distance_no_similarity(self, mock_metadata, mock_top_packages):
        """Test Factor 1: String distance with no similarity (3 points)."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = self.mock_pypi_metadata
        
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("completely_unique_name_12345", "1.0.0")
        
        # Should get 3 points for string distance + other factors
        assert score >= 3.0
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_factor1_string_distance_high_similarity(self, mock_metadata, mock_top_packages):
        """Test Factor 1: String distance with high similarity (0 points)."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = self.mock_pypi_metadata
        
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("requsts", "1.0.0")  # Distance 1 from "requests"
        
        # Should get 0 points for string distance factor
        assert score <= 7.0  # Max without string distance points
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_factor1_string_distance_moderate_similarity(self, mock_metadata, mock_top_packages):
        """Test Factor 1: String distance with moderate similarity (1-2 points)."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = self.mock_pypi_metadata
        
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("reqests", "1.0.0")  # Distance 2 from "requests"
        
        # Should get 1 point for string distance factor
        assert score <= 8.0  # Max with 1 point for string distance
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_factor2_downloads_high_downloads(self, mock_metadata, mock_top_packages):
        """Test Factor 2: Downloads + similarity with high downloads (3 points)."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = {
            "metadata": {"info": {"name": "test_package"}},
            "download_count": 2000,  # High downloads
            "creation_date": "2023-01-01T00:00:00Z"
        }
        
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("completely_unique_name_12345", "1.0.0")
        
        # Should get 3 points for downloads factor + other factors
        assert score >= 6.0
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_factor2_downloads_low_downloads_similar(self, mock_metadata, mock_top_packages):
        """Test Factor 2: Downloads + similarity with low downloads and similar name (0 points)."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = {
            "metadata": {"info": {"name": "test_package"}},
            "download_count": 50,  # Very low downloads
            "creation_date": "2023-01-01T00:00:00Z"
        }
        
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("requsts", "1.0.0")  # Similar to "requests"
        
        # Should get 0 points for downloads factor due to low downloads + similarity
        assert score <= 7.0  # Max without downloads factor points
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_factor3_character_substitution_no_substitutions(self, mock_metadata, mock_top_packages):
        """Test Factor 3: Character substitution with no substitutions (2 points)."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = self.mock_pypi_metadata
        
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("clean_package_name", "1.0.0")
        
        # Should get 2 points for character substitution factor
        assert score >= 2.0
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_factor3_character_substitution_multiple_substitutions(self, mock_metadata, mock_top_packages):
        """Test Factor 3: Character substitution with multiple substitutions (0 points)."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = self.mock_pypi_metadata
        
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("requ3st5", "1.0.0")  # Multiple substitutions: 3->e, 5->s
        
        # Should get 0 points for character substitution factor
        assert score <= 8.0  # Max without character substitution points
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_factor4_keyboard_proximity_no_typos(self, mock_metadata, mock_top_packages):
        """Test Factor 4: Keyboard proximity with no typos (1 point)."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = self.mock_pypi_metadata
        
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("clean_package_name", "1.0.0")
        
        # Should get 1 point for keyboard proximity factor
        assert score >= 1.0
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_factor4_keyboard_proximity_with_typos(self, mock_metadata, mock_top_packages):
        """Test Factor 4: Keyboard proximity with typos (0 points)."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = self.mock_pypi_metadata
        
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("requets", "1.0.0")  # 'ue' is keyboard proximity typo
        
        # Should get 0 points for keyboard proximity factor
        assert score <= 9.0  # Max without keyboard proximity points
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_factor5_creation_date_old_package(self, mock_metadata, mock_top_packages):
        """Test Factor 5: Creation date with old package (1 point)."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = {
            "metadata": {"info": {"name": "test_package"}},
            "download_count": 1500,
            "creation_date": "2020-01-01T00:00:00Z"  # Old package
        }
        
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("clean_package_name", "1.0.0")
        
        # Should get 1 point for creation date factor
        assert score >= 1.0
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_factor5_creation_date_new_package_similar(self, mock_metadata, mock_top_packages):
        """Test Factor 5: Creation date with new package + similar name (0 points)."""
        mock_top_packages.return_value = self.mock_top_packages
        
        from datetime import datetime, timedelta
        recent_date = (datetime.now() - timedelta(days=30)).isoformat() + "Z"
        
        mock_metadata.return_value = {
            "metadata": {"info": {"name": "test_package"}},
            "download_count": 1500,
            "creation_date": recent_date  # New package
        }
        
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("requsts", "1.0.0")  # Similar to "requests"
        
        # Should get 0 points for creation date factor
        assert score <= 9.0  # Max without creation date points
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_whitelist_functionality(self, mock_metadata, mock_top_packages):
        """Test whitelist functionality returns max score."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = self.mock_pypi_metadata
        
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score(
            "requsts", "1.0.0",
            typosquatting_whitelist=["requsts", "another_package"]
        )
        
        # Whitelisted package should get max score
        assert score == 10.0
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_api_failure_handling(self, mock_metadata, mock_top_packages):
        """Test handling of API failures."""
        mock_top_packages.return_value = []  # Empty list simulates API failure
        mock_metadata.return_value = None  # None simulates API failure
        
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("test_package", "1.0.0")
        
        # Should return default moderate score on API failure
        assert score == 5.0
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_perfect_score_scenario(self, mock_metadata, mock_top_packages):
        """Test scenario that should yield perfect score."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = {
            "metadata": {"info": {"name": "test_package"}},
            "download_count": 2000,  # High downloads
            "creation_date": "2020-01-01T00:00:00Z"  # Old package
        }
        
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("completely_unique_clean_name", "1.0.0")
        
        # Should get perfect score: 3 + 3 + 2 + 1 + 1 = 10
        assert score == 10.0
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_worst_score_scenario(self, mock_metadata, mock_top_packages):
        """Test scenario that should yield worst score."""
        mock_top_packages.return_value = self.mock_top_packages
        
        from datetime import datetime, timedelta
        recent_date = (datetime.now() - timedelta(days=30)).isoformat() + "Z"
        
        mock_metadata.return_value = {
            "metadata": {"info": {"name": "test_package"}},
            "download_count": 50,  # Very low downloads
            "creation_date": recent_date  # New package
        }
        
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("requ3st5", "1.0.0")  # Similar + substitutions + proximity
        
        # Should get very low score - actual: 1 + 0 + 0 + 0 + 0 = 1
        # Factor breakdown:
        # - String distance: 1 (distance 2 to "requests")
        # - Downloads + similarity: 0 (low downloads + similar)
        # - Character substitution: 0 (has substitutions: 3→e, 5→s)
        # - Keyboard proximity: 0 (has proximity typos)
        # - Creation date: 0 (new package + similar)
        assert score == 1.0
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_get_details_comprehensive(self, mock_metadata, mock_top_packages):
        """Test detailed scoring information."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = self.mock_pypi_metadata
        
        scorer = TyposquatHeuristicsScorer()
        details = scorer.get_details("requsts", "1.0.0")
        
        # Check structure
        assert details["dimension"] == "typosquat_heuristics"
        assert details["package_name"] == "requsts"
        assert "score" in details
        assert "risk_indicators" in details
        assert "factors" in details
        assert "in_whitelist" in details
        
        # Check factors
        factors = details["factors"]
        assert "string_distance" in factors
        assert "downloads_similarity" in factors
        assert "character_substitution" in factors
        assert "keyboard_proximity" in factors
        assert "creation_date" in factors
        
        # Each factor should have score and details
        for factor_name, factor_data in factors.items():
            assert "score" in factor_data
            assert "details" in factor_data
        
        assert details["total_max_score"] == 10
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_get_details_whitelist(self, mock_metadata, mock_top_packages):
        """Test detailed scoring information for whitelisted package."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = self.mock_pypi_metadata
        
        scorer = TyposquatHeuristicsScorer()
        details = scorer.get_details(
            "requsts", "1.0.0",
            typosquatting_whitelist=["requsts"]
        )
        
        assert details["in_whitelist"] == True
        assert details["score"] == 10.0
        assert details["risk_indicators"] == []
        
        # All factors should show whitelisted
        for factor_name, factor_data in details["factors"].items():
            assert factor_data["details"] == "whitelisted"
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._init_cache')
    def test_cache_initialization(self, mock_init_cache):
        """Test cache initialization."""
        scorer = TyposquatHeuristicsScorer()
        mock_init_cache.assert_called_once()
    
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_requestd_typosquatting_case(self, mock_metadata, mock_top_packages):
        """Test the specific 'requestd' typosquatting case for framework compliance."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = None  # Simulate metadata unavailable
        
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("requestd", "1.0.0")
        
        # With fixes, should be High Risk (≤3 pts): 
        # String Distance: 0pts, Downloads+Similarity: 0pts, Character Sub: 2pts, 
        # Keyboard Proximity: 0pts, Creation Date: 0pts = 2 pts total
        assert score <= 3.0, f"Expected ≤3.0 for High Risk, got {score}"
        
        # Get detailed breakdown
        details = scorer.get_details("requestd", "1.0.0")
        assert "very_similar_to_popular_package" in details["risk_indicators"]
        assert details["factors"]["string_distance"]["score"] == 0  # Distance 1 from "requests"
        assert details["factors"]["downloads_similarity"]["score"] == 0  # No metadata + similarity
        assert details["factors"]["keyboard_proximity"]["score"] == 0  # s→d proximity
        assert details["factors"]["creation_date"]["score"] == 0  # No date + similarity
        
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_metadata_unavailable_with_similarity(self, mock_metadata, mock_top_packages):
        """Test downloads + similarity factor when metadata unavailable with high similarity."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = None
        
        scorer = TyposquatHeuristicsScorer()
        details = scorer.get_details("requsts", "1.0.0")  # Distance 1 from "requests"
        
        # Should get 0 points for downloads_similarity due to metadata unavailable + similarity
        downloads_factor = details["factors"]["downloads_similarity"]
        assert downloads_factor["score"] == 0
        assert downloads_factor["details"]["reason"] == "metadata_unavailable_with_similarity"
        assert downloads_factor["details"]["has_similarity"] == True
        
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')  
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_creation_date_unavailable_with_similarity(self, mock_metadata, mock_top_packages):
        """Test creation date factor when date unavailable with high similarity.""" 
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = {"metadata": {"info": {"name": "test_package"}}}  # No creation_date
        
        scorer = TyposquatHeuristicsScorer()
        details = scorer.get_details("requsts", "1.0.0")  # Distance 1 from "requests"
        
        # Should get 0 points for creation_date due to date unavailable + similarity
        creation_factor = details["factors"]["creation_date"]
        assert creation_factor["score"] == 0
        assert creation_factor["details"]["reason"] == "date_unavailable_with_similarity"
        assert creation_factor["details"]["has_similarity"] == True
        
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata') 
    def test_keyboard_proximity_sd_substitution(self, mock_metadata, mock_top_packages):
        """Test keyboard proximity detection for s→d substitution."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = self.mock_pypi_metadata
        
        scorer = TyposquatHeuristicsScorer()
        details = scorer.get_details("requestd", "1.0.0")
        
        # Should detect s→d keyboard proximity error
        proximity_factor = details["factors"]["keyboard_proximity"]
        assert proximity_factor["score"] == 0
        assert len(proximity_factor["details"]["proximity_typos"]) > 0
        assert any("s→d substitution" in typo for typo in proximity_factor["details"]["proximity_typos"])
        
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_top_packages')
    @patch('depclass.dimension_scorers.typosquat_heuristics.TyposquatHeuristicsScorer._get_pypi_metadata')
    def test_no_similarity_metadata_unavailable(self, mock_metadata, mock_top_packages):
        """Test that packages with no similarity get neutral scores even when metadata unavailable."""
        mock_top_packages.return_value = self.mock_top_packages
        mock_metadata.return_value = None
        
        scorer = TyposquatHeuristicsScorer()
        details = scorer.get_details("completely_unique_package_name_xyz", "1.0.0")
        
        # Should get neutral scores when no similarity detected
        downloads_factor = details["factors"]["downloads_similarity"]
        assert downloads_factor["score"] == 1  # Neutral score for no similarity
        assert downloads_factor["details"]["reason"] == "metadata_unavailable"
        assert downloads_factor["details"]["has_similarity"] == False
        
        creation_factor = details["factors"]["creation_date"]
        assert creation_factor["score"] == 1  # Neutral score for no similarity
        assert creation_factor["details"]["reason"] == "date_unavailable"  
        assert creation_factor["details"]["has_similarity"] == False
    
    def test_character_substitution_patterns(self):
        """Test character substitution pattern detection."""
        scorer = TyposquatHeuristicsScorer()
        
        # Test bidirectional substitutions
        assert '0' in scorer.char_substitutions
        assert 'o' in scorer.char_substitutions
        assert scorer.char_substitutions['0'] == 'o'
        assert scorer.char_substitutions['o'] == '0'
        
        # Test all expected substitutions
        expected_substitutions = {
            '0': 'o', 'o': '0',
            '1': 'l', 'l': '1',
            '5': 's', 's': '5',
            '3': 'e', 'e': '3',
            '8': 'b', 'b': '8',
            '4': 'a', 'a': '4',
            '7': 't', 't': '7',
            '6': 'g', 'g': '6'
        }
        
        for char, expected in expected_substitutions.items():
            assert scorer.char_substitutions[char] == expected
    
    def test_keyboard_proximity_patterns(self):
        """Test keyboard proximity pattern detection."""
        scorer = TyposquatHeuristicsScorer()
        
        # Test some key adjacencies
        assert 'w' in scorer.qwerty_proximity['q']
        assert 'a' in scorer.qwerty_proximity['q']
        assert 'e' in scorer.qwerty_proximity['w']
        assert 's' in scorer.qwerty_proximity['w']
        
        # Test number row proximity
        assert '1' in scorer.qwerty_proximity['q']
        assert '2' in scorer.qwerty_proximity['w']
        
        # Test shift key mappings
        assert '@' in scorer.qwerty_proximity['!']
        assert '#' in scorer.qwerty_proximity['@']
    
    def test_download_thresholds(self):
        """Test download threshold configuration."""
        scorer = TyposquatHeuristicsScorer()
        
        assert scorer.download_thresholds['high'] == 1000
        assert scorer.download_thresholds['medium'] == 500
        assert scorer.download_thresholds['low'] == 100
        
        # Test logical ordering
        assert scorer.download_thresholds['high'] > scorer.download_thresholds['medium']
        assert scorer.download_thresholds['medium'] > scorer.download_thresholds['low']
    
    def test_configuration_parameters(self):
        """Test configuration parameter defaults."""
        scorer = TyposquatHeuristicsScorer()
        
        assert scorer.new_package_days == 90
        assert scorer.similarity_threshold == 2
        assert scorer.top_packages_url == "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"


class TestDimensionScorerBase:
    """Test the base DimensionScorer functionality."""
    
    def test_score_validation(self):
        """Test that all scorers validate their scores to 0-10 range."""
        scorers = [
            DeclaredVsInstalledScorer(),
            KnownCVEsScorer(),
            CWECoverageScorer(),
            PackageAbandonmentScorer(),
            TyposquatHeuristicsScorer(),
        ]
        
        for scorer in scorers:
            # Test that validate_score works correctly
            assert scorer.validate_score(-1.0) == 0.0
            assert scorer.validate_score(11.0) == 10.0
            assert scorer.validate_score(5.0) == 5.0
    
    def test_score_range_compliance(self):
        """Test that all scorers return scores in the 0-10 range."""
        test_cases = [
            ("test_package", "1.0.0", None, []),
            ("test_package", "1.0.0", "1.0.0", []),
            ("test_package", "1.0.0", "2.0.0", []),
        ]
        
        scorers = [
            DeclaredVsInstalledScorer(),
            KnownCVEsScorer(),
            CWECoverageScorer(),
            PackageAbandonmentScorer(),
            TyposquatHeuristicsScorer(),
        ]
        
        for scorer in scorers:
            for package, installed, declared, cves in test_cases:
                score = scorer.score(package, installed, declared, cve_list=cves)
                assert 0.0 <= score <= 10.0, f"{scorer.__class__.__name__} returned score {score} outside range [0, 10]"