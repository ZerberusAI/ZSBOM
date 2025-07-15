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
    """Test the DeclaredVsInstalledScorer dimension."""
    
    def test_perfect_match(self):
        scorer = DeclaredVsInstalledScorer()
        score = scorer.score("test_package", "1.0.0", "1.0.0")
        assert score == 10.0
    
    def test_no_declared_version(self):
        scorer = DeclaredVsInstalledScorer()
        score = scorer.score("test_package", "1.0.0", None)
        assert score == 5.0
    
    def test_major_version_difference(self):
        scorer = DeclaredVsInstalledScorer()
        score = scorer.score("test_package", "2.0.0", "1.0.0")
        assert score == 3.0
    
    def test_minor_version_difference(self):
        scorer = DeclaredVsInstalledScorer()
        score = scorer.score("test_package", "1.1.0", "1.0.0")
        assert score == 8.0
    
    def test_patch_version_difference(self):
        scorer = DeclaredVsInstalledScorer()
        score = scorer.score("test_package", "1.0.1", "1.0.0")
        assert score == 9.0
    
    def test_get_details(self):
        scorer = DeclaredVsInstalledScorer()
        details = scorer.get_details("test_package", "1.1.0", "1.0.0")
        assert details["dimension"] == "declared_vs_installed"
        assert details["exact_match"] == False
        assert details["has_declared_version"] == True
        assert "version_diff" in details


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
    
    def test_no_repo_path(self):
        scorer = PackageAbandonmentScorer()
        score = scorer.score("test_package", "1.0.0", repo_path=None)
        assert score == 0.0
    
    @patch('subprocess.check_output')
    def test_recent_commit(self, mock_subprocess):
        """Test scoring with recent commit activity."""
        scorer = PackageAbandonmentScorer()
        
        # Mock recent commit (15 days ago)
        import time
        recent_timestamp = int(time.time() - (15 * 24 * 3600))  # 15 days ago
        mock_subprocess.return_value = str(recent_timestamp)
        
        with patch('os.path.exists', return_value=True):
            score = scorer.score("test_package", "1.0.0", repo_path="/fake/repo")
            # Should get 5 points for recent commit, but may lose points for other factors
            assert score >= 5.0
    
    @patch('subprocess.check_output')
    def test_old_commit(self, mock_subprocess):
        """Test scoring with old commit activity."""
        scorer = PackageAbandonmentScorer()
        
        # Mock old commit (200 days ago)
        import time
        old_timestamp = int(time.time() - (200 * 24 * 3600))  # 200 days ago
        mock_subprocess.return_value = str(old_timestamp)
        
        with patch('os.path.exists', return_value=True):
            score = scorer.score("test_package", "1.0.0", repo_path="/fake/repo")
            # Should get 0 points for old commit
            assert score <= 5.0
    
    @patch('requests.Session.get')
    def test_recent_release(self, mock_get):
        """Test scoring with recent PyPI release."""
        scorer = PackageAbandonmentScorer()
        
        # Mock recent PyPI release
        from datetime import datetime, timezone
        recent_date = datetime.now(timezone.utc).replace(day=1)  # 1 month ago
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "releases": {
                "1.0.0": [{
                    "upload_time": recent_date.isoformat()
                }]
            }
        }
        mock_get.return_value = mock_response
        
        score = scorer.score("test_package", "1.0.0", repo_path=None)
        # Should get 2 points for recent release
        assert score >= 2.0
    
    def test_get_details(self):
        scorer = PackageAbandonmentScorer()
        details = scorer.get_details("test_package", "1.0.0", repo_path=None)
        assert details["dimension"] == "package_abandonment"
        assert "components" in details
        assert "last_commit" in details["components"]
        assert "commit_frequency" in details["components"]
        assert "release_frequency" in details["components"]


class TestTyposquatHeuristicsScorer:
    """Test the TyposquatHeuristicsScorer dimension."""
    
    def test_clean_package_name(self):
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("unique_package_name", "1.0.0")
        assert score == 10.0
    
    def test_known_typosquat_pattern(self):
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("reqquests", "1.0.0")  # Known typosquat of "requests"
        assert score == 0.0
    
    def test_user_blacklist(self):
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("suspicious_package", "1.0.0", typosquat_blacklist=["suspicious_package"])
        assert score == 0.0
    
    def test_high_similarity_to_popular_package(self):
        scorer = TyposquatHeuristicsScorer()
        # This should be similar to "requests"
        score = scorer.score("requestss", "1.0.0")
        assert score < 5.0  # High similarity should give low score
    
    def test_moderate_similarity(self):
        scorer = TyposquatHeuristicsScorer()
        # This should have moderate similarity to "flask"
        score = scorer.score("flaskk", "1.0.0")
        assert score < 8.0  # Moderate similarity
    
    def test_no_similarity(self):
        scorer = TyposquatHeuristicsScorer()
        score = scorer.score("completely_unique_name_12345", "1.0.0")
        assert score == 10.0
    
    def test_get_details(self):
        scorer = TyposquatHeuristicsScorer()
        details = scorer.get_details("requestss", "1.0.0")
        assert details["dimension"] == "typosquat_heuristics"
        assert "similarity_analysis" in details
        assert "pattern_checks" in details
        assert "risk_indicators" in details


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