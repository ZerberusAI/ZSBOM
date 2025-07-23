"""Shared PyPI metadata service with caching for ZSBOM risk scorers."""

import json
import sqlite3
import requests
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class PyPIMetadataService:
    """Shared service for PyPI metadata with SQLite caching.
    
    This service consolidates PyPI API calls used by both PackageAbandonmentScorer
    and TyposquatHeuristicsScorer to eliminate duplicate requests and improve performance.
    """

    def __init__(self, cache_db_path: str = ".cache/pypi_metadata.db"):
        """Initialize the PyPI metadata service.
        
        Args:
            cache_db_path: Path to SQLite cache database
        """
        self.cache_db_path = cache_db_path
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ZSBOM/1.0 (Package Risk Assessment)'
        })
        
        # Connection pooling for better performance
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(
            pool_connections=20,  # Number of connection pools
            pool_maxsize=20,      # Max connections per pool
            max_retries=retry_strategy
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self._init_cache_db()

    def _init_cache_db(self) -> None:
        """Initialize SQLite cache database."""
        # Ensure cache directory exists
        cache_dir = Path(self.cache_db_path).parent
        cache_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            conn = sqlite3.connect(self.cache_db_path)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS pypi_metadata (
                    package_name TEXT PRIMARY KEY,
                    metadata TEXT,
                    download_count INTEGER,
                    creation_date TEXT,
                    cached_at TIMESTAMP,
                    ttl_hours INTEGER DEFAULT 1
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f"Failed to initialize PyPI metadata cache: {e}")

    def _is_cache_valid(self, cached_at: str, ttl_hours: int) -> bool:
        """Check if cached data is still valid.
        
        Args:
            cached_at: ISO timestamp when data was cached
            ttl_hours: Time-to-live in hours
            
        Returns:
            True if cache is still valid
        """
        try:
            cached_time = datetime.fromisoformat(cached_at)
            expiry_time = cached_time + timedelta(hours=ttl_hours)
            return datetime.now() < expiry_time
        except Exception:
            return False

    def get_package_metadata(self, package_name: str, ttl_hours: int = 1, top_packages: Optional[List[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
        """Get package metadata from PyPI with caching.
        
        Args:
            package_name: Name of the package
            ttl_hours: Cache time-to-live in hours
            top_packages: Optional list of top packages with download counts to reuse
            
        Returns:
            Dictionary with metadata, download_count, creation_date, or None if failed
        """
        try:
            # Check cache first
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT metadata, download_count, creation_date, cached_at, ttl_hours
                FROM pypi_metadata
                WHERE package_name = ?
            ''', (package_name,))
            
            cached_data = cursor.fetchone()
            
            if cached_data and self._is_cache_valid(cached_data[3], cached_data[4]):
                conn.close()
                return {
                    'metadata': json.loads(cached_data[0]),
                    'download_count': cached_data[1],
                    'creation_date': cached_data[2],
                    'pypi_data_available': True
                }
            
            conn.close()
            
            # Cache miss or expired, fetch from PyPI API
            response = self.session.get(
                f"https://pypi.org/pypi/{package_name}/json",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract download count from top_packages list if provided, otherwise from PyPI API
                download_count = 0
                info = data.get('info', {})
                
                # First try to get download count from top_packages list (reuse existing data)
                if top_packages:
                    for pkg in top_packages:
                        if pkg.get('project', '').lower() == package_name.lower():
                            download_count = pkg.get('download_count', 0)
                            break
                
                # Fallback to PyPI API downloads field (currently disabled, returns -1)
                if download_count == 0:
                    pypi_downloads = info.get('downloads', {})
                    if isinstance(pypi_downloads, dict):
                        # Try different download count fields
                        last_month = pypi_downloads.get('last_month', -1)
                        if last_month > 0:
                            download_count = last_month
                
                # Extract creation date from first release
                creation_date = None
                releases = data.get('releases', {})
                if releases:
                    earliest_release = None
                    for version, release_info in releases.items():
                        if release_info:  # Skip empty releases
                            for release_file in release_info:
                                upload_time = release_file.get('upload_time')
                                if upload_time:
                                    try:
                                        release_date = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                                        if earliest_release is None or release_date < earliest_release:
                                            earliest_release = release_date
                                    except ValueError:
                                        continue
                    
                    if earliest_release:
                        creation_date = earliest_release.isoformat()
                
                # Cache the result
                conn = sqlite3.connect(self.cache_db_path)
                conn.execute('''
                    INSERT OR REPLACE INTO pypi_metadata 
                    (package_name, metadata, download_count, creation_date, cached_at, ttl_hours)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    package_name,
                    json.dumps(data),
                    download_count,
                    creation_date,
                    datetime.now().isoformat(),
                    ttl_hours
                ))
                conn.commit()
                conn.close()
                
                return {
                    'metadata': data,
                    'download_count': download_count,
                    'creation_date': creation_date,
                    'pypi_data_available': True
                }
            else:
                # Package not found on PyPI
                return {'pypi_data_available': False}
                
        except (requests.RequestException, ValueError, KeyError) as e:
            logger.warning(f"Failed to fetch PyPI metadata for {package_name}: {e}")
            return {'pypi_data_available': False}

    def get_release_info(self, package_name: str) -> Dict[str, Any]:
        """Get release information for package abandonment scoring.
        
        Args:
            package_name: Name of the package
            
        Returns:
            Dictionary with release frequency information
        """
        metadata = self.get_package_metadata(package_name)
        
        if not metadata or not metadata.get('pypi_data_available'):
            return {'pypi_data_available': False}
        
        data = metadata['metadata']
        releases = data.get('releases', {})
        
        if not releases:
            return {'pypi_data_available': False}
        
        # Find the most recent release
        release_dates = []
        for version, release_info in releases.items():
            if release_info:  # Skip empty releases
                for release_file in release_info:
                    upload_time = release_file.get('upload_time')
                    if upload_time:
                        try:
                            release_date = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                            release_dates.append(release_date)
                        except ValueError:
                            continue
        
        if release_dates:
            last_release_date = max(release_dates)
            # Ensure both datetime objects are timezone-aware
            if last_release_date.tzinfo is None:
                from datetime import timezone
                last_release_date = last_release_date.replace(tzinfo=timezone.utc)
            
            from datetime import timezone
            days_since_last_release = (datetime.now(timezone.utc) - last_release_date).days
            
            return {
                'days_since_last_release': days_since_last_release,
                'last_release_date': last_release_date.isoformat(),
                'pypi_data_available': True
            }
        
        return {'pypi_data_available': False}

    def get_repository_url(self, package_name: str) -> Optional[str]:
        """Extract repository URL from PyPI package metadata.
        
        Args:
            package_name: Name of the package
            
        Returns:
            Repository URL string or None if not found
        """
        metadata = self.get_package_metadata(package_name)
        
        if not metadata or not metadata.get('pypi_data_available'):
            return None
        
        data = metadata['metadata']
        info = data.get('info', {})
        
        # Check project_urls first (preferred source)
        project_urls = info.get('project_urls') or {}
        
        # Common repository keys in order of preference
        repo_keys = [
            'Repository', 'Source', 'Source Code', 'Code', 'GitHub', 'GitLab',
            'Homepage', 'Home', 'repository', 'source', 'github', 'gitlab'
        ]
        
        for key in repo_keys:
            url = project_urls.get(key)
            if url and self._is_valid_repository_url(url):
                return self._normalize_repository_url(url)
        
        # Fallback to home_page if project_urls didn't work
        home_page = info.get('home_page')
        if home_page and self._is_valid_repository_url(home_page):
            return self._normalize_repository_url(home_page)
        
        # Additional fallback to download_url (rare but possible)
        download_url = info.get('download_url')
        if download_url and self._is_valid_repository_url(download_url):
            return self._normalize_repository_url(download_url)
        
        return None

    def _is_valid_repository_url(self, url: str) -> bool:
        """Check if URL appears to be a valid git repository.
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL appears to be a repository
        """
        if not url or not isinstance(url, str):
            return False
        
        # Common repository hosting patterns
        repo_patterns = [
            r'github\.com',
            r'gitlab\.com',
            r'bitbucket\.org',
            r'codeberg\.org',
            r'git\..*',
            r'.*\.git$',
            r'.*\.git/',
        ]
        
        url_lower = url.lower()
        return any(re.search(pattern, url_lower) for pattern in repo_patterns)

    def _normalize_repository_url(self, url: str) -> str:
        """Normalize repository URL for consistent format.
        
        Args:
            url: Repository URL to normalize
            
        Returns:
            Normalized repository URL
        """
        if not url:
            return url
        
        # Remove trailing slashes and fragments
        url = url.rstrip('/').split('#')[0].split('?')[0]
        
        # Convert GitHub/GitLab URLs to HTTPS if needed
        if 'github.com' in url or 'gitlab.com' in url:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url.lstrip('/')
            
            # Convert SSH to HTTPS for broader compatibility
            if url.startswith('git@'):
                if 'github.com' in url:
                    url = re.sub(r'^git@github\.com:', 'https://github.com/', url)
                elif 'gitlab.com' in url:
                    url = re.sub(r'^git@gitlab\.com:', 'https://gitlab.com/', url)
            
            # Ensure .git suffix for clone operations
            if not url.endswith('.git') and ('github.com' in url or 'gitlab.com' in url):
                url += '.git'
        
        return url


# Global shared instance
_pypi_service = None


def get_pypi_service() -> PyPIMetadataService:
    """Get the global PyPI metadata service instance."""
    global _pypi_service
    if _pypi_service is None:
        _pypi_service = PyPIMetadataService()
    return _pypi_service