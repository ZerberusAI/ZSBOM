"""
Repository Detection Module for ZSBOM Metadata Collection

This module detects and extracts repository information including Git details,
CI environment context, and pull request metadata following SOLID principles.

Classes:
    RepositoryDetector: Main repository detection orchestrator
    GitRepositoryDetector: Git-specific repository information
    CIEnvironmentDetector: CI platform detection and metadata
    PullRequestDetector: PR/MR metadata extraction
"""

import os
import re
import subprocess
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse


class BaseRepositoryDetector(ABC):
    """Abstract base class for repository detectors."""
    
    @abstractmethod
    def detect(self) -> Dict[str, Any]:
        """Detect repository information."""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if this detector can operate in current environment."""
        pass
    
    @abstractmethod
    def get_detector_name(self) -> str:
        """Return name of this detector."""
        pass


class GitRepositoryDetector(BaseRepositoryDetector):
    """Git repository information detection."""
    
    def __init__(self, working_directory: Optional[str] = None):
        self.working_directory = working_directory or os.getcwd()
    
    def is_available(self) -> bool:
        """Check if Git is available and we're in a Git repository."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                cwd=self.working_directory,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False
    
    def detect(self) -> Dict[str, Any]:
        """Detect Git repository information."""
        if not self.is_available():
            return {
                "available": False,
                "error": "Git not available or not in a Git repository"
            }
        
        try:
            git_info = {
                "available": True,
                "branch": self._get_current_branch(),
                "commit_sha": self._get_current_commit(),
                "commit_short_sha": self._get_current_commit(short=True),
                "is_dirty": self._is_working_directory_dirty(),
                "remote_url": self._get_remote_url(),
                "remote_origin": self._get_remote_origin(),
                "tags": self._get_current_tags(),
                "commit_info": self._get_commit_info(),
                "repository_stats": self._get_repository_stats()
            }
            
            # Sanitize sensitive information
            git_info["remote_url_sanitized"] = self._sanitize_url(git_info["remote_url"])
            
            return git_info
            
        except Exception as e:
            return {
                "available": True,
                "error": f"Git detection failed: {str(e)}",
                "partial_info": True
            }
    
    def _get_current_branch(self) -> Optional[str]:
        """Get current Git branch name."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=self.working_directory,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                branch = result.stdout.strip()
                return None if branch == "HEAD" else branch  # Detached head
            return None
        except Exception:
            return None
    
    def _get_current_commit(self, short: bool = False) -> Optional[str]:
        """Get current commit SHA."""
        try:
            cmd = ["git", "rev-parse"]
            if short:
                cmd.append("--short")
            cmd.append("HEAD")
            
            result = subprocess.run(
                cmd,
                cwd=self.working_directory,
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except Exception:
            return None
    
    def _is_working_directory_dirty(self) -> bool:
        """Check if working directory has uncommitted changes."""
        try:
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=self.working_directory,
                capture_output=True,
                text=True,
                timeout=5
            )
            return bool(result.stdout.strip()) if result.returncode == 0 else False
        except Exception:
            return False
    
    def _get_remote_url(self) -> Optional[str]:
        """Get remote origin URL."""
        try:
            result = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                cwd=self.working_directory,
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except Exception:
            return None
    
    def _get_remote_origin(self) -> Optional[str]:
        """Get remote origin name."""
        try:
            result = subprocess.run(
                ["git", "remote"],
                cwd=self.working_directory,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                remotes = result.stdout.strip().split('\n')
                return remotes[0] if remotes and remotes[0] else None
            return None
        except Exception:
            return None
    
    def _get_current_tags(self) -> List[str]:
        """Get tags pointing to current commit."""
        try:
            result = subprocess.run(
                ["git", "tag", "--points-at", "HEAD"],
                cwd=self.working_directory,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                tags = result.stdout.strip().split('\n')
                return [tag for tag in tags if tag]
            return []
        except Exception:
            return []
    
    def _get_commit_info(self) -> Dict[str, Any]:
        """Get detailed commit information."""
        try:
            result = subprocess.run(
                ["git", "log", "-1", "--format=%H|%an|%ae|%ad|%s"],
                cwd=self.working_directory,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                parts = result.stdout.strip().split('|', 4)
                if len(parts) == 5:
                    return {
                        "sha": parts[0],
                        "author_name": parts[1],
                        "author_email": parts[2],
                        "date": parts[3],
                        "message": parts[4]
                    }
            return {}
        except Exception:
            return {}
    
    def _get_repository_stats(self) -> Dict[str, Any]:
        """Get basic repository statistics."""
        try:
            # Get commit count
            commit_count_result = subprocess.run(
                ["git", "rev-list", "--count", "HEAD"],
                cwd=self.working_directory,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            stats = {}
            if commit_count_result.returncode == 0:
                stats["total_commits"] = int(commit_count_result.stdout.strip())
            
            # Get contributor count
            contributors_result = subprocess.run(
                ["git", "shortlog", "-sn", "--all"],
                cwd=self.working_directory,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if contributors_result.returncode == 0:
                contributors = contributors_result.stdout.strip().split('\n')
                stats["total_contributors"] = len([c for c in contributors if c.strip()])
            
            return stats
        except Exception:
            return {}
    
    def _sanitize_url(self, url: Optional[str]) -> Optional[str]:
        """Sanitize Git URL to remove credentials."""
        if not url:
            return url
        
        try:
            # Parse URL to remove credentials
            parsed = urlparse(url)
            if parsed.scheme in ['http', 'https']:
                # Remove username and password
                clean_netloc = parsed.hostname
                if parsed.port:
                    clean_netloc += f":{parsed.port}"
                sanitized = f"{parsed.scheme}://{clean_netloc}{parsed.path}"
            else:
                # For SSH URLs (git@github.com:user/repo.git)
                sanitized = url
            
            return sanitized
        except Exception:
            # If parsing fails, return original URL
            return url
    
    def get_detector_name(self) -> str:
        return "git_repository"


class CIEnvironmentDetector(BaseRepositoryDetector):
    """CI/CD environment detection and metadata extraction."""
    
    CI_PLATFORMS = {
        "github_actions": {
            "indicator": "GITHUB_ACTIONS",
            "metadata_vars": [
                "GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_SHA", "GITHUB_ACTOR",
                "GITHUB_WORKFLOW", "GITHUB_RUN_ID", "GITHUB_RUN_NUMBER",
                "GITHUB_EVENT_NAME", "GITHUB_HEAD_REF", "GITHUB_BASE_REF"
            ]
        },
        "gitlab_ci": {
            "indicator": "GITLAB_CI",
            "metadata_vars": [
                "CI_PROJECT_NAME", "CI_PROJECT_NAMESPACE", "CI_COMMIT_REF_NAME",
                "CI_COMMIT_SHA", "CI_COMMIT_SHORT_SHA", "CI_PIPELINE_ID",
                "CI_JOB_ID", "CI_JOB_NAME", "CI_MERGE_REQUEST_IID"
            ]
        },
        "jenkins": {
            "indicator": "JENKINS_URL",
            "metadata_vars": [
                "JOB_NAME", "BUILD_NUMBER", "BUILD_ID", "BUILD_URL",
                "GIT_BRANCH", "GIT_COMMIT", "BRANCH_NAME", "CHANGE_ID"
            ]
        },
        "travis_ci": {
            "indicator": "TRAVIS",
            "metadata_vars": [
                "TRAVIS_REPO_SLUG", "TRAVIS_BRANCH", "TRAVIS_COMMIT",
                "TRAVIS_BUILD_NUMBER", "TRAVIS_JOB_NUMBER", "TRAVIS_PULL_REQUEST"
            ]
        },
        "circleci": {
            "indicator": "CIRCLECI",
            "metadata_vars": [
                "CIRCLE_PROJECT_REPONAME", "CIRCLE_BRANCH", "CIRCLE_SHA1",
                "CIRCLE_BUILD_NUM", "CIRCLE_JOB", "CIRCLE_PULL_REQUEST"
            ]
        },
        "azure_pipelines": {
            "indicator": "TF_BUILD",
            "metadata_vars": [
                "BUILD_REPOSITORY_NAME", "BUILD_SOURCEBRANCH", "BUILD_SOURCEVERSION",
                "BUILD_BUILDNUMBER", "BUILD_BUILDID", "SYSTEM_PULLREQUEST_PULLREQUESTID"
            ]
        }
    }
    
    def is_available(self) -> bool:
        """Check if running in any known CI environment."""
        return self._detect_ci_platform() != "local"
    
    def detect(self) -> Dict[str, Any]:
        """Detect CI environment information."""
        platform = self._detect_ci_platform()
        
        ci_info = {
            "platform": platform,
            "is_ci": platform != "local",
            "metadata": {}
        }
        
        if platform != "local" and platform in self.CI_PLATFORMS:
            # Extract platform-specific metadata
            metadata_vars = self.CI_PLATFORMS[platform]["metadata_vars"]
            for var in metadata_vars:
                value = os.getenv(var)
                if value:
                    ci_info["metadata"][var] = value
            
            # Extract common CI information
            ci_info.update(self._extract_common_ci_info(platform))
        
        return ci_info
    
    def _detect_ci_platform(self) -> str:
        """Detect which CI platform is running."""
        for platform, config in self.CI_PLATFORMS.items():
            if os.getenv(config["indicator"]):
                return platform
        
        # Generic CI detection
        if os.getenv("CI") == "true" or os.getenv("CONTINUOUS_INTEGRATION") == "true":
            return "generic_ci"
        
        return "local"
    
    def _extract_common_ci_info(self, platform: str) -> Dict[str, Any]:
        """Extract common CI information across platforms."""
        common_info = {}
        
        if platform == "github_actions":
            common_info.update({
                "repository": os.getenv("GITHUB_REPOSITORY"),
                "branch": os.getenv("GITHUB_REF_NAME") or self._extract_branch_from_ref(os.getenv("GITHUB_REF")),
                "commit": os.getenv("GITHUB_SHA"),
                "actor": os.getenv("GITHUB_ACTOR"),
                "workflow": os.getenv("GITHUB_WORKFLOW"),
                "run_id": os.getenv("GITHUB_RUN_ID"),
                "event_name": os.getenv("GITHUB_EVENT_NAME")
            })
        elif platform == "gitlab_ci":
            common_info.update({
                "repository": f"{os.getenv('CI_PROJECT_NAMESPACE')}/{os.getenv('CI_PROJECT_NAME')}",
                "branch": os.getenv("CI_COMMIT_REF_NAME"),
                "commit": os.getenv("CI_COMMIT_SHA"),
                "pipeline_id": os.getenv("CI_PIPELINE_ID"),
                "job_name": os.getenv("CI_JOB_NAME")
            })
        elif platform == "jenkins":
            common_info.update({
                "job_name": os.getenv("JOB_NAME"),
                "build_number": os.getenv("BUILD_NUMBER"),
                "branch": os.getenv("GIT_BRANCH") or os.getenv("BRANCH_NAME"),
                "commit": os.getenv("GIT_COMMIT")
            })
        
        return common_info
    
    def _extract_branch_from_ref(self, ref: Optional[str]) -> Optional[str]:
        """Extract branch name from Git ref."""
        if not ref:
            return None
        
        if ref.startswith("refs/heads/"):
            return ref[11:]  # Remove "refs/heads/"
        elif ref.startswith("refs/pull/"):
            return ref  # Keep full PR ref
        
        return ref
    
    def get_detector_name(self) -> str:
        return "ci_environment"


class PullRequestDetector(BaseRepositoryDetector):
    """Pull request/merge request detection and metadata extraction."""
    
    def is_available(self) -> bool:
        """Check if PR information is available."""
        return self._detect_pr_context() is not None
    
    def detect(self) -> Dict[str, Any]:
        """Detect pull request information."""
        pr_context = self._detect_pr_context()
        
        if not pr_context:
            return {"available": False}
        
        return {
            "available": True,
            "platform": pr_context["platform"],
            "pr_number": pr_context.get("pr_number"),
            "source_branch": pr_context.get("source_branch"),
            "target_branch": pr_context.get("target_branch"),
            "pr_title": pr_context.get("pr_title"),
            "pr_url": pr_context.get("pr_url"),
            "metadata": pr_context.get("metadata", {})
        }
    
    def _detect_pr_context(self) -> Optional[Dict[str, Any]]:
        """Detect pull request context from environment."""
        # GitHub Actions
        if os.getenv("GITHUB_ACTIONS"):
            return self._get_github_pr_context()
        
        # GitLab CI
        if os.getenv("GITLAB_CI"):
            return self._get_gitlab_mr_context()
        
        # Jenkins (various PR plugins)
        if os.getenv("JENKINS_URL"):
            return self._get_jenkins_pr_context()
        
        # Azure Pipelines
        if os.getenv("TF_BUILD"):
            return self._get_azure_pr_context()
        
        return None
    
    def _get_github_pr_context(self) -> Optional[Dict[str, Any]]:
        """Extract GitHub PR context."""
        event_name = os.getenv("GITHUB_EVENT_NAME")
        
        if event_name in ["pull_request", "pull_request_target"]:
            pr_number = os.getenv("GITHUB_REF")
            if pr_number and pr_number.startswith("refs/pull/"):
                pr_num = pr_number.split("/")[2]
                
                return {
                    "platform": "github",
                    "pr_number": pr_num,
                    "source_branch": os.getenv("GITHUB_HEAD_REF"),
                    "target_branch": os.getenv("GITHUB_BASE_REF"),
                    "repository": os.getenv("GITHUB_REPOSITORY"),
                    "metadata": {
                        "event_name": event_name,
                        "actor": os.getenv("GITHUB_ACTOR"),
                        "run_id": os.getenv("GITHUB_RUN_ID")
                    }
                }
        
        return None
    
    def _get_gitlab_mr_context(self) -> Optional[Dict[str, Any]]:
        """Extract GitLab MR context."""
        mr_iid = os.getenv("CI_MERGE_REQUEST_IID")
        
        if mr_iid:
            return {
                "platform": "gitlab",
                "pr_number": mr_iid,
                "source_branch": os.getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"),
                "target_branch": os.getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"),
                "repository": f"{os.getenv('CI_PROJECT_NAMESPACE')}/{os.getenv('CI_PROJECT_NAME')}",
                "metadata": {
                    "project_id": os.getenv("CI_PROJECT_ID"),
                    "pipeline_id": os.getenv("CI_PIPELINE_ID"),
                    "job_id": os.getenv("CI_JOB_ID")
                }
            }
        
        return None
    
    def _get_jenkins_pr_context(self) -> Optional[Dict[str, Any]]:
        """Extract Jenkins PR context."""
        change_id = os.getenv("CHANGE_ID")  # GitHub PR plugin
        
        if change_id:
            return {
                "platform": "jenkins",
                "pr_number": change_id,
                "source_branch": os.getenv("CHANGE_BRANCH"),
                "target_branch": os.getenv("CHANGE_TARGET"),
                "metadata": {
                    "job_name": os.getenv("JOB_NAME"),
                    "build_number": os.getenv("BUILD_NUMBER"),
                    "change_url": os.getenv("CHANGE_URL")
                }
            }
        
        return None
    
    def _get_azure_pr_context(self) -> Optional[Dict[str, Any]]:
        """Extract Azure Pipelines PR context."""
        pr_id = os.getenv("SYSTEM_PULLREQUEST_PULLREQUESTID")
        
        if pr_id:
            return {
                "platform": "azure_pipelines",
                "pr_number": pr_id,
                "source_branch": os.getenv("SYSTEM_PULLREQUEST_SOURCEBRANCH"),
                "target_branch": os.getenv("SYSTEM_PULLREQUEST_TARGETBRANCH"),
                "metadata": {
                    "build_id": os.getenv("BUILD_BUILDID"),
                    "build_number": os.getenv("BUILD_BUILDNUMBER"),
                    "repository": os.getenv("BUILD_REPOSITORY_NAME")
                }
            }
        
        return None
    
    def get_detector_name(self) -> str:
        return "pull_request"


class RepositoryDetector:
    """Main repository detection orchestrator following SOLID principles."""
    
    def __init__(self, working_directory: Optional[str] = None):
        self.working_directory = working_directory or os.getcwd()
        self.detectors = [
            GitRepositoryDetector(self.working_directory),
            CIEnvironmentDetector(),
            PullRequestDetector()
        ]
    
    def detect_all(self) -> Dict[str, Any]:
        """Detect all repository information."""
        repository_info = {}
        
        for detector in self.detectors:
            try:
                detector_name = detector.get_detector_name()
                if detector.is_available():
                    repository_info[detector_name] = detector.detect()
                else:
                    repository_info[detector_name] = {
                        "available": False,
                        "reason": "Detector not available in current environment"
                    }
            except Exception as e:
                repository_info[detector.get_detector_name()] = {
                    "available": False,
                    "error": str(e)
                }
        
        # Extract common repository information
        repository_info.update(self._extract_common_repository_info(repository_info))
        
        return repository_info
    
    def _extract_common_repository_info(self, repo_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract commonly used repository fields."""
        common_info = {}
        
        # Determine SCM type
        git_info = repo_info.get("git_repository", {})
        if git_info.get("available"):
            common_info["detected_scm"] = "git"
            common_info["branch"] = git_info.get("branch")
            common_info["commit_sha"] = git_info.get("commit_sha")
            common_info["is_dirty"] = git_info.get("is_dirty", False)
            common_info["remote_url"] = git_info.get("remote_url_sanitized")
        else:
            common_info["detected_scm"] = None
        
        # Extract CI information
        ci_info = repo_info.get("ci_environment", {})
        common_info["ci_environment"] = ci_info.get("platform", "local")
        
        # Extract PR information
        pr_info = repo_info.get("pull_request", {})
        if pr_info.get("available"):
            common_info["pr_number"] = pr_info.get("pr_number")
            common_info["is_pull_request"] = True
        else:
            common_info["is_pull_request"] = False
        
        return common_info
    
    def add_detector(self, detector: BaseRepositoryDetector):
        """Add custom repository detector."""
        self.detectors.append(detector)
    
    def get_detector_names(self) -> List[str]:
        """Get names of all registered detectors."""
        return [detector.get_detector_name() for detector in self.detectors]