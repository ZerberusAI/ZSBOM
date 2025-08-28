"""
Repository Metadata Collector

Collects Git repository information for scan metadata including
branch, commit SHA, remote URL, and platform detection.
"""

import os
import re
import subprocess
from pathlib import Path
from typing import Optional, Dict
from urllib.parse import urlparse

from .models import RepositoryMetadata, ScanMetadata
from .exceptions import TraceAIUploadError


class RepositoryMetadataCollector:
    """Collect Git repository information for scan metadata"""
    
    def __init__(self):
        self.repo_root = self._find_repo_root()
    
    def collect_repository_metadata(self) -> RepositoryMetadata:
        """Extract repository information from Git"""
        try:
            if self.repo_root and self._is_git_repo():
                return self._collect_git_metadata()
            else:
                return self._generate_fallback_metadata()
        except Exception:
            # Fall back to basic metadata if Git operations fail
            return self._generate_fallback_metadata()
    
    def collect_scan_metadata(self) -> ScanMetadata:
        """Collect scan-specific metadata"""
        environment = self._collect_environment_info()
        
        if self.repo_root and self._is_git_repo():
            branch = self._get_git_branch()
            commit_sha = self._get_git_commit_sha()
        else:
            branch = None
            commit_sha = None
        
        return ScanMetadata(
            branch=branch,
            commit_sha=commit_sha,
            trigger_type="manual",
            environment=environment,
            local_execution=True
        )
    
    def _find_repo_root(self) -> Optional[str]:
        """Find the root of the Git repository"""
        current_path = Path.cwd()
        
        # Walk up the directory tree looking for .git
        for path in [current_path] + list(current_path.parents):
            if (path / '.git').exists():
                return str(path)
        
        return None
    
    def _is_git_repo(self) -> bool:
        """Check if current directory is in a Git repository"""
        if not self.repo_root:
            return False
        
        try:
            result = subprocess.run(
                ['git', 'rev-parse', '--git-dir'],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _collect_git_metadata(self) -> RepositoryMetadata:
        """Collect metadata from Git repository"""
        # Get remote URL
        remote_url = self._get_git_remote_url()
        
        if remote_url:
            platform = self._detect_scm_platform(remote_url)
            namespace, repository = self._parse_git_url(remote_url)
            name = repository or self._get_directory_name()
        else:
            platform = "unknown"
            namespace = "unknown"
            repository = self._get_directory_name()
            name = repository
            remote_url = f"file://{self.repo_root}"
        
        return RepositoryMetadata(
            name=name,
            scm_platform=platform,
            scm_namespace=namespace,
            scm_repository=repository,
            scm_url=remote_url,
            default_branch=self._get_git_default_branch()
        )
    
    def _generate_fallback_metadata(self) -> RepositoryMetadata:
        """Generate fallback metadata for non-Git directories"""
        directory_name = self._get_directory_name()
        
        return RepositoryMetadata(
            name=directory_name,
            scm_platform="local",
            scm_namespace="local",
            scm_repository=directory_name,
            scm_url=f"file://{os.getcwd()}",
            default_branch="main"
        )
    
    def _get_git_remote_url(self) -> Optional[str]:
        """Get the remote URL of the Git repository"""
        try:
            result = subprocess.run(
                ['git', 'remote', 'get-url', 'origin'],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return None
    
    def _get_git_branch(self) -> Optional[str]:
        """Get current Git branch"""
        try:
            result = subprocess.run(
                ['git', 'branch', '--show-current'],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                branch = result.stdout.strip()
                return branch if branch else None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return None
    
    def _get_git_commit_sha(self) -> Optional[str]:
        """Get current Git commit SHA"""
        try:
            result = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return None
    
    def _get_git_default_branch(self) -> str:
        """Get the default branch name"""
        try:
            # Try to get the default branch from remote
            result = subprocess.run(
                ['git', 'symbolic-ref', 'refs/remotes/origin/HEAD'],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                ref = result.stdout.strip()
                # Extract branch name from refs/remotes/origin/branch_name
                if ref.startswith('refs/remotes/origin/'):
                    return ref.replace('refs/remotes/origin/', '')
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Fallback to common default branch names
        return "main"
    
    def _detect_scm_platform(self, url: str) -> str:
        """Detect SCM platform from repository URL"""
        url_lower = url.lower()
        
        if 'github.com' in url_lower:
            return 'github'
        elif 'gitlab.com' in url_lower or 'gitlab' in url_lower:
            return 'gitlab'
        elif 'bitbucket.org' in url_lower or 'bitbucket' in url_lower:
            return 'bitbucket'
        elif 'azure.com' in url_lower or 'visualstudio.com' in url_lower:
            return 'azure_devops'
        else:
            return 'git'
    
    def _parse_git_url(self, url: str) -> tuple[str, str]:
        """Parse Git URL to extract namespace and repository"""
        try:
            # Handle SSH URLs (git@github.com:user/repo.git)
            ssh_match = re.match(r'git@([^:]+):(.+)', url)
            if ssh_match:
                path = ssh_match.group(2)
            else:
                # Handle HTTPS URLs
                parsed = urlparse(url)
                path = parsed.path.lstrip('/')
            
            # Remove .git suffix
            if path.endswith('.git'):
                path = path[:-4]
            
            # Split into namespace and repository
            parts = path.split('/')
            if len(parts) >= 2:
                namespace = '/'.join(parts[:-1])
                repository = parts[-1]
                return namespace, repository
            elif len(parts) == 1:
                return 'unknown', parts[0]
            
        except Exception:
            pass
        
        return 'unknown', 'unknown'
    
    def _get_directory_name(self) -> str:
        """Get the current directory name as fallback"""
        return os.path.basename(os.getcwd()) or "zsbom-scan"
    
    def _collect_environment_info(self) -> Dict:
        """Collect environment information"""
        try:
            import platform
            import sys
            
            # Get ZSBOM version
            zsbom_version = "unknown"
            try:
                import depclass
                if hasattr(depclass, '__version__'):
                    zsbom_version = depclass.__version__
                else:
                    # Try to read from setup.py or pyproject.toml
                    zsbom_version = "0.1.0"  # Default version
            except:
                zsbom_version = "0.1.0"
            
            return {
                "os": platform.system().lower(),
                "arch": platform.machine(),
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                "zsbom_version": zsbom_version,
                "platform": platform.platform(),
                "working_directory": os.getcwd()
            }
        except Exception:
            return {
                "os": "unknown",
                "arch": "unknown", 
                "python_version": "unknown",
                "zsbom_version": "unknown"
            }