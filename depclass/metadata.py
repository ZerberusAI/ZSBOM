"""
Simple metadata collector for ZSBOM scans.

Replaces the complex multi-module metadata collection system with a focused,
minimal implementation that captures essential information including Git and CI/PR context.
"""
import json
import os
import sys
import time
import uuid
import platform
import subprocess
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from pathlib import Path


class MetadataCollector:
    """Simple metadata collector for ZSBOM scans."""
    
    def __init__(self, config: Dict[str, Any], console: Any = None):
        self.config = config
        self.console = console
        self.scan_id = str(uuid.uuid4())  # Generate initial scan_id
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.errors: List[Dict[str, Any]] = []
        self.statistics: Dict[str, Any] = {}
        self.generated_files: List[str] = []
    
    def start_collection(self) -> str:
        """Start metadata collection and return scan ID."""
        self.started_at = datetime.now(timezone.utc)
        return self.scan_id
    
    def add_error(self, stage: str, error: Exception, details: Optional[Dict[str, Any]] = None):
        """Add an error to the collection."""
        self.errors.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "error": str(error),
            "error_type": type(error).__name__,
            "details": details or {}
        })
    
    def update_statistics(self, stats: Dict[str, Any]):
        """Update scan statistics."""
        self.statistics.update(stats)
    
    def add_generated_file(self, file_path: str):
        """Track a generated file."""
        self.generated_files.append(file_path)
    
    def update_scan_id(self, scan_id: str):
        """Update scan_id with the one from meta-guard service."""
        self.scan_id = scan_id
    
    def _run_git_command(self, args: List[str]) -> Optional[str]:
        """Run a git command and return output, None if failed."""
        try:
            result = subprocess.run(
                ["git"] + args,
                capture_output=True,
                text=True,
                timeout=10,
                cwd=os.getcwd()
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None
    
    def _collect_git_info(self) -> Dict[str, Any]:
        """Collect Git repository information."""
        git_info = {
            "available": False,
            "branch": None,
            "commit_sha": None,
            "commit_message": None,
            "author_email": None,
            "remote_url": None,
            "is_dirty": False
        }
        
        # Check if we're in a Git repository
        if self._run_git_command(["rev-parse", "--git-dir"]) is None:
            return git_info
        
        git_info["available"] = True
        
        # Get current branch
        branch = self._run_git_command(["branch", "--show-current"])
        if branch:
            git_info["branch"] = branch
        
        # Get commit SHA
        commit_sha = self._run_git_command(["rev-parse", "HEAD"])
        if commit_sha:
            git_info["commit_sha"] = commit_sha
            git_info["commit_short_sha"] = commit_sha[:8]
        
        # Get commit message
        commit_message = self._run_git_command(["log", "-1", "--pretty=format:%s"])
        if commit_message:
            git_info["commit_message"] = commit_message
        
        # Get author email
        author_email = self._run_git_command(["log", "-1", "--pretty=format:%ae"])
        if author_email:
            git_info["author_email"] = author_email
        
        # Get remote URL
        remote_url = self._run_git_command(["remote", "get-url", "origin"])
        if remote_url:
            git_info["remote_url"] = remote_url
        
        # Check if working directory is dirty
        status = self._run_git_command(["status", "--porcelain"])
        git_info["is_dirty"] = bool(status and status.strip())
        
        return git_info
    
    def _collect_ci_info(self) -> Dict[str, Any]:
        """Collect CI/PR context information."""
        ci_info = {
            "is_ci": False,
            "platform": "local",
            "event_type": None,
            "run_id": None,
            "pr_number": None,
            "source_branch": None,
            "target_branch": None,
            "repository": None
        }
        
        # Check for GitHub Actions
        if os.getenv("GITHUB_ACTIONS") == "true":
            ci_info["is_ci"] = True
            ci_info["platform"] = "github_actions"
            ci_info["run_id"] = os.getenv("GITHUB_RUN_ID")
            ci_info["repository"] = os.getenv("GITHUB_REPOSITORY")
            
            event_name = os.getenv("GITHUB_EVENT_NAME")
            ci_info["event_type"] = event_name
            
            if event_name == "pull_request":
                # PR context
                ci_info["source_branch"] = os.getenv("GITHUB_HEAD_REF")
                ci_info["target_branch"] = os.getenv("GITHUB_BASE_REF")
                
                # Extract PR number from GITHUB_REF (format: refs/pull/123/merge)
                github_ref = os.getenv("GITHUB_REF", "")
                pr_match = re.search(r"refs/pull/(\d+)/merge", github_ref)
                if pr_match:
                    ci_info["pr_number"] = int(pr_match.group(1))
            
            elif event_name == "push":
                # Regular branch push
                ci_info["source_branch"] = os.getenv("GITHUB_REF_NAME")
        
        # Check for other CI platforms
        elif os.getenv("JENKINS_URL"):
            ci_info["is_ci"] = True
            ci_info["platform"] = "jenkins"
            ci_info["run_id"] = os.getenv("BUILD_NUMBER")
        
        elif os.getenv("GITLAB_CI") == "true":
            ci_info["is_ci"] = True
            ci_info["platform"] = "gitlab_ci"
            ci_info["run_id"] = os.getenv("CI_PIPELINE_ID")
            ci_info["repository"] = os.getenv("CI_PROJECT_PATH")
            
            # GitLab merge request detection
            if os.getenv("CI_MERGE_REQUEST_ID"):
                ci_info["event_type"] = "merge_request"
                ci_info["pr_number"] = int(os.getenv("CI_MERGE_REQUEST_ID"))
                ci_info["source_branch"] = os.getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME")
                ci_info["target_branch"] = os.getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
            else:
                ci_info["event_type"] = "push"
                ci_info["source_branch"] = os.getenv("CI_COMMIT_REF_NAME")
        
        elif os.getenv("CIRCLECI") == "true":
            ci_info["is_ci"] = True
            ci_info["platform"] = "circleci"
            ci_info["run_id"] = os.getenv("CIRCLE_BUILD_NUM")
            ci_info["repository"] = os.getenv("CIRCLE_PROJECT_REPONAME")
            ci_info["source_branch"] = os.getenv("CIRCLE_BRANCH")
            
            # CircleCI PR detection
            if os.getenv("CIRCLE_PULL_REQUEST"):
                ci_info["event_type"] = "pull_request"
                pr_url = os.getenv("CIRCLE_PULL_REQUEST", "")
                pr_match = re.search(r"/pull/(\d+)", pr_url)
                if pr_match:
                    ci_info["pr_number"] = int(pr_match.group(1))
        
        return ci_info
    
    def finalize_collection(self, exit_code: int = 0) -> Dict[str, Any]:
        """Finalize collection and return enhanced metadata."""
        self.completed_at = datetime.now(timezone.utc)
        
        duration = 0
        if self.started_at and self.completed_at:
            duration = (self.completed_at - self.started_at).total_seconds()
        
        # Collect Git repository information
        repository_info = self._collect_git_info()
        
        # Collect CI/PR context information  
        ci_info = self._collect_ci_info()
        
        # Get basic environment info
        environment = {
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "platform": platform.system(),
            "working_directory": os.getcwd()
        }
        
        return {
            "scan_id": self.scan_id,
            "execution": {
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "completed_at": self.completed_at.isoformat() if self.completed_at else None,
                "duration_seconds": duration,
                "exit_code": exit_code
            },
            "repository": repository_info,
            "ci_context": ci_info,
            "environment": environment,
            "statistics": self.statistics,
            "generated_files": self.generated_files,
            "errors": self.errors,
            "error_count": len(self.errors)
        }
    
    def save_metadata(self, output_path: Optional[str] = None) -> str:
        """Save metadata to file."""
        metadata = self.finalize_collection()
        
        if not output_path:
            output_path = "scan_metadata.json"
        
        with open(output_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
        return output_path