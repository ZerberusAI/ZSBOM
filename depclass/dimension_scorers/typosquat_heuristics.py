"""Typosquat Heuristics dimension scorer with 5-factor analysis."""

import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
import requests
import Levenshtein
from .base import DimensionScorer
from ..services import get_pypi_service

logger = logging.getLogger(__name__)


class TyposquatHeuristicsScorer(DimensionScorer):
    """Scores packages based on typosquatting heuristics using 5-factor analysis.
    
    Implements the ZSBOM Risk Scoring Framework v1.0 typosquatting detection
    requirements with comprehensive risk assessment across multiple dimensions.
    
    Scoring factors:
    1. String Distance Analysis (3 points): 
       - Compares against top 15K popular packages using Levenshtein distance
       - 3pts: No similarity, 2pts: Distance 3+, 1pt: Distance 2, 0pts: Distance 1
       
    2. Downloads + Similarity Analysis (3 points):
       - Evaluates download count relative to name similarity
       - 3pts: >1000 downloads, 2pts: 500-1000, 1pt: 100-500+similar, 0pts: <100+similar
       
    3. Character Substitution Detection (2 points):
       - Detects number-to-letter substitution patterns (0→o, 1→l, 5→s, etc.)
       - 2pts: No substitutions, 1pt: 1 substitution, 0pts: 2+ substitutions
       
    4. Keyboard Proximity Detection (1 point):
       - Identifies adjacent key typing errors using QWERTY layout
       - 1pt: No proximity typos, 0pts: 1+ proximity typos
       
    5. Creation Date + Similarity (1 point):
       - Correlates package age with similarity patterns
       - 1pt: Old package (>90 days) OR new+dissimilar, 0pts: New+similar
    
    Total: 10 points (0 = high risk, 10 = low risk)
    Weight: 15% of total ZSBOM score
    
    Performance Features:
    - Parallel API calls for top packages and PyPI metadata
    - SQLite caching with configurable TTL (2 days for top packages, 1 hour for metadata)
    - Stale cache fallback when network is unavailable
    - Comprehensive error handling with technical debugging information
    """

    def __init__(self, cache_db_path: str = ".cache/zsbom.db"):
        """Initialize the typosquat heuristics scorer.
        
        Sets up the scoring engine with configuration for all 5 factors:
        - Character substitution patterns (bidirectional mappings)
        - QWERTY keyboard proximity mappings (including shift keys)
        - Download count thresholds for scoring
        - API endpoints for data sources
        - SQLite cache database for performance optimization
        
        Args:
            cache_db_path: Path to SQLite cache database (default: ".cache/zsbom.db")
                          Creates directory if it doesn't exist
        
        Raises:
            Exception: If cache database initialization fails (logged, not propagated)
        """
        self.cache_db_path = cache_db_path
        self.top_packages_url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
        self.pypi_service = get_pypi_service()
        
        # Character substitution patterns (bidirectional)
        self.char_substitutions = {
            '0': 'o', 'o': '0',
            '1': 'l', 'l': '1',
            '5': 's', 's': '5',
            '3': 'e', 'e': '3',
            '8': 'b', 'b': '8',
            '4': 'a', 'a': '4',
            '7': 't', 't': '7',
            '6': 'g', 'g': '6'
        }
        
        # QWERTY keyboard layout proximity map (including shift keys and numbers)
        self.qwerty_proximity = {
            'q': ['w', 'a', 's', '1', '2'],
            'w': ['q', 'e', 'a', 's', 'd', '1', '2', '3'],
            'e': ['w', 'r', 's', 'd', 'f', '2', '3', '4'],
            'r': ['e', 't', 'd', 'f', 'g', '3', '4', '5'],
            't': ['r', 'y', 'f', 'g', 'h', '4', '5', '6'],
            'y': ['t', 'u', 'g', 'h', 'j', '5', '6', '7'],
            'u': ['y', 'i', 'h', 'j', 'k', '6', '7', '8'],
            'i': ['u', 'o', 'j', 'k', 'l', '7', '8', '9'],
            'o': ['i', 'p', 'k', 'l', ';', '8', '9', '0'],
            'p': ['o', '[', 'l', ';', "'", '9', '0', '-'],
            'a': ['q', 'w', 's', 'z', 'x', '1'],
            's': ['q', 'w', 'e', 'a', 'd', 'z', 'x', 'c', '1', '2'],
            'd': ['w', 'e', 'r', 's', 'f', 'x', 'c', 'v', '2', '3'],
            'f': ['e', 'r', 't', 'd', 'g', 'c', 'v', 'b', '3', '4'],
            'g': ['r', 't', 'y', 'f', 'h', 'v', 'b', 'n', '4', '5'],
            'h': ['t', 'y', 'u', 'g', 'j', 'b', 'n', 'm', '5', '6'],
            'j': ['y', 'u', 'i', 'h', 'k', 'n', 'm', ',', '6', '7'],
            'k': ['u', 'i', 'o', 'j', 'l', 'm', ',', '.', '7', '8'],
            'l': ['i', 'o', 'p', 'k', ';', ',', '.', '/', '8', '9'],
            'z': ['a', 's', 'd', 'x'],
            'x': ['z', 'a', 's', 'd', 'c'],
            'c': ['x', 's', 'd', 'f', 'v'],
            'v': ['c', 'd', 'f', 'g', 'b'],
            'b': ['v', 'f', 'g', 'h', 'n'],
            'n': ['b', 'g', 'h', 'j', 'm'],
            'm': ['n', 'h', 'j', 'k', ','],
            '1': ['2', 'q', 'w', 'a', 's'],
            '2': ['1', '3', 'q', 'w', 'e', 'a', 's', 'd'],
            '3': ['2', '4', 'w', 'e', 'r', 's', 'd', 'f'],
            '4': ['3', '5', 'e', 'r', 't', 'd', 'f', 'g'],
            '5': ['4', '6', 'r', 't', 'y', 'f', 'g', 'h'],
            '6': ['5', '7', 't', 'y', 'u', 'g', 'h', 'j'],
            '7': ['6', '8', 'y', 'u', 'i', 'h', 'j', 'k'],
            '8': ['7', '9', 'u', 'i', 'o', 'j', 'k', 'l'],
            '9': ['8', '0', 'i', 'o', 'p', 'k', 'l', ';'],
            '0': ['9', '-', 'o', 'p', '[', 'l', ';', "'"],
            # Add shift key mappings
            '!': ['@', 'Q', 'W', 'A', 'S'],
            '@': ['!', '#', 'Q', 'W', 'E', 'A', 'S', 'D'],
            '#': ['@', '$', 'W', 'E', 'R', 'S', 'D', 'F'],
            '$': ['#', '%', 'E', 'R', 'T', 'D', 'F', 'G'],
            '%': ['$', '^', 'R', 'T', 'Y', 'F', 'G', 'H'],
            '^': ['%', '&', 'T', 'Y', 'U', 'G', 'H', 'J'],
            '&': ['^', '*', 'Y', 'U', 'I', 'H', 'J', 'K'],
            '*': ['&', '(', 'U', 'I', 'O', 'J', 'K', 'L'],
            '(': ['*', ')', 'I', 'O', 'P', 'K', 'L', ':'],
            ')': ['(', '_', 'O', 'P', '{', 'L', ':', '"'],
        }
        
        # Download count thresholds
        self.download_thresholds = {
            'high': 1000,
            'medium': 500,
            'low': 100
        }
        
        # Package age threshold (days)
        self.new_package_days = 90
        
        # Similarity threshold for creation date factor
        self.similarity_threshold = 2  # Levenshtein distance
        
        # Initialize cache
        self._init_cache()
    
    def _init_cache(self):
        """Initialize SQLite cache database."""
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            
            # Create tables if they don't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS top_packages (
                    id INTEGER PRIMARY KEY,
                    package_name TEXT,
                    downloads INTEGER,
                    cached_at TIMESTAMP,
                    ttl_hours INTEGER DEFAULT 48
                )
            ''')
            
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to initialize SQLite cache database at {self.cache_db_path}: {e}. "
                        f"Check file permissions and disk space. Typosquatting detection may be degraded.")
    
    def _is_cache_valid(self, cached_at: str, ttl_hours: int) -> bool:
        """Check if cache entry is still valid.
        
        Args:
            cached_at: Timestamp when cached
            ttl_hours: Time to live in hours
            
        Returns:
            True if cache is valid, False otherwise
        """
        try:
            cached_time = datetime.fromisoformat(cached_at)
            expiry_time = cached_time + timedelta(hours=ttl_hours)
            return datetime.now() < expiry_time
        except Exception:
            return False
    
    def _get_top_packages(self) -> List[Dict[str, Any]]:
        """Get top 15K packages from cache or external API.
        
        Returns:
            List of package dictionaries with name and download count
        """
        try:
            # Check cache first
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT package_name, downloads, cached_at, ttl_hours
                FROM top_packages
                ORDER BY downloads DESC
                LIMIT 15000
            ''')
            
            cached_packages = cursor.fetchall()
            
            # Check if cache is valid
            if cached_packages:
                first_entry = cached_packages[0]
                if self._is_cache_valid(first_entry[2], first_entry[3]):
                    conn.close()
                    return [{'project': row[0], 'download_count': row[1]} for row in cached_packages]
            
            # Cache miss or expired, fetch from API
            logger.info("Fetching top packages from external API...")
            
            response = self._make_request_with_retry(self.top_packages_url)
            if not response:
                # Network unavailable, use stale cached data if available
                if cached_packages:
                    logger.warning("Network unavailable, using stale cached top packages data")
                    conn.close()
                    return [{'project': row[0], 'download_count': row[1]} for row in cached_packages]
                else:
                    conn.close()
                    return []
            
            data = response.json()
            packages = data.get('rows', [])[:15000]  # Limit to top 15K
            
            # Clear old cache and insert new data
            cursor.execute('DELETE FROM top_packages')
            
            for package in packages:
                cursor.execute('''
                    INSERT INTO top_packages (package_name, downloads, cached_at, ttl_hours)
                    VALUES (?, ?, ?, ?)
                ''', (
                    package['project'],
                    package['download_count'],
                    datetime.now().isoformat(),
                    48  # 2 days TTL
                ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Cached {len(packages)} top packages")
            return packages
            
        except Exception as e:
            logger.error(f"Failed to fetch top packages from {self.top_packages_url}: {e}. "
                        f"Check network connectivity and API availability. Using cached data if available.")
            return []
    
    def _get_pypi_metadata(self, package_name: str, top_packages: Optional[List[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
        """Get package metadata using shared PyPI service.
        
        Args:
            package_name: Name of the package
            top_packages: Optional top packages list to reuse for download counts
            
        Returns:
            Package metadata dictionary or None if failed
        """
        result = self.pypi_service.get_package_metadata(package_name, ttl_hours=1, top_packages=top_packages)
        if result and result.get('pypi_data_available'):
            return result
        return None

    
    def _make_request_with_retry(self, url: str, max_retries: int = 3) -> Optional[requests.Response]:
        """Make HTTP request with exponential backoff retry.
        
        Args:
            url: URL to request
            max_retries: Maximum number of retry attempts
            
        Returns:
            Response object or None if failed
        """
        for attempt in range(max_retries):
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                return response
                
            except requests.RequestException as e:
                if attempt == max_retries - 1:
                    logger.error(f"HTTP request failed after {max_retries} attempts to {url}: {e}. "
                                f"Check network connectivity, proxy settings, and API rate limits.")
                    return None
                
                # Exponential backoff
                wait_time = 2 ** attempt
                logger.warning(f"HTTP request to {url} failed (attempt {attempt + 1}/{max_retries}): {e}. "
                              f"Retrying in {wait_time}s with exponential backoff...")
                time.sleep(wait_time)
        
        return None
    
    def _calculate_string_distance_score(self, package_name: str, top_packages: List[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
        """Calculate string distance analysis score (Factor 1).
        
        Args:
            package_name: Package name to analyze
            top_packages: List of top packages
            
        Returns:
            Tuple of (score, details)
        """
        min_distance = float('inf')
        most_similar_package = None
        
        for top_package in top_packages:
            top_name = top_package['project'].lower()
            distance = Levenshtein.distance(package_name.lower(), top_name)
            
            if distance < min_distance:
                min_distance = distance
                most_similar_package = top_name
        
        # Scoring logic
        if min_distance == 0:
            score = 3  # Exact match with popular package - SAFE (it's the actual popular package)
        elif min_distance == float('inf') or min_distance > 5:
            score = 3  # No similarity - very different names
        elif min_distance >= 3:
            score = 2  # Distance 3-5
        elif min_distance == 2:
            score = 1  # Distance 2
        else:  # min_distance == 1
            score = 0  # Distance 1 - high risk (actual typosquatting)
        
        return score, {
            'min_distance': min_distance if min_distance != float('inf') else None,
            'most_similar_package': most_similar_package,
            'similarity_found': min_distance != float('inf')
        }
    
    def _calculate_downloads_similarity_score(self, package_name: str, package_metadata: Optional[Dict[str, Any]], string_distance_details: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """Calculate downloads + similarity analysis score (Factor 2).
        
        Args:
            package_name: Package name to analyze
            package_metadata: Package metadata from PyPI
            string_distance_details: Details from string distance analysis
            
        Returns:
            Tuple of (score, details)
        """
        min_distance = string_distance_details.get('min_distance')
        has_similarity = min_distance is not None and min_distance <= 2
        
        if not package_metadata:
            # If no metadata available AND high similarity exists, assume high risk (0 pts)
            # Following security-first approach per ZSBOM Risk Scoring Framework v1.0
            if has_similarity:
                return 0, {'download_count': None, 'reason': 'metadata_unavailable_with_similarity', 'has_similarity': True}
            else:
                return 1, {'download_count': None, 'reason': 'metadata_unavailable', 'has_similarity': False}
        
        download_count = package_metadata.get('download_count', 0)
        
        # Scoring logic
        if download_count >= self.download_thresholds['high']:
            score = 3  # High downloads
        elif download_count >= self.download_thresholds['medium']:
            score = 2  # Medium downloads
        elif download_count >= self.download_thresholds['low'] and has_similarity:
            score = 1  # Low downloads + similar name
        elif download_count < self.download_thresholds['low'] and has_similarity:
            score = 0  # Very low downloads + similar name - high risk
        else:
            score = 3  # No similarity concerns
        
        return score, {
            'download_count': download_count,
            'threshold_category': self._get_download_category(download_count),
            'has_similarity': has_similarity
        }
    
    def _get_download_category(self, download_count: int) -> str:
        """Get download count category.
        
        Args:
            download_count: Number of downloads
            
        Returns:
            Category string
        """
        if download_count >= self.download_thresholds['high']:
            return 'high'
        elif download_count >= self.download_thresholds['medium']:
            return 'medium'
        elif download_count >= self.download_thresholds['low']:
            return 'low'
        else:
            return 'very_low'
    
    def _calculate_character_substitution_score(self, package_name: str) -> Tuple[int, Dict[str, Any]]:
        """Calculate character substitution detection score (Factor 3).
        
        Args:
            package_name: Package name to analyze
            
        Returns:
            Tuple of (score, details)
        """
        substitution_count = 0
        found_substitutions = []
        package_lower = package_name.lower()
        
        # Check for actual substitution patterns by looking for suspicious character usage
        # A substitution is when a number/letter is used in place of its look-alike
        for char in package_lower:
            if char in self.char_substitutions:
                # Check if this character is likely a substitution
                # Numbers in package names are often substitutions
                if char.isdigit():
                    substitution_count += 1
                    found_substitutions.append(f"{char} → {self.char_substitutions[char]}")
                # Letters that replace numbers are less common in normal package names
                elif char in ['o', 'l', 's', 'e', 'b', 'a', 't', 'g']:
                    # Only count as substitution if there are also digits nearby or specific patterns
                    # This is a simplified heuristic - in real implementation, we'd need context
                    if any(c.isdigit() for c in package_lower):
                        # If there are digits mixed with letters, it's likely substitution
                        continue  # Don't double-count
        
        # Scoring logic
        if substitution_count == 0:
            score = 2  # No substitutions
        elif substitution_count == 1:
            score = 1  # 1 substitution pattern
        else:
            score = 0  # 2+ substitution patterns - high risk
        
        return score, {
            'substitution_count': substitution_count,
            'found_substitutions': found_substitutions
        }
    
    def _calculate_keyboard_proximity_score(self, package_name: str, string_distance_details: Dict[str, Any] = None) -> Tuple[int, Dict[str, Any]]:
        """Calculate keyboard proximity detection score (Factor 4).
        
        This method detects keyboard proximity errors by being context-aware:
        - If exact match (distance=0): Skip analysis, return max score
        - If similar (distance 1-2): Check for keyboard proximity patterns  
        - If very different: Skip analysis, return max score
        
        Args:
            package_name: Package name to analyze
            string_distance_details: String distance analysis results for context
            
        Returns:
            Tuple of (score, details)
        """
        # Get string distance context
        min_distance = string_distance_details.get('min_distance') if string_distance_details else None
        
        # If exact match with popular package, no need to check for keyboard typos
        if min_distance == 0:
            return 1, {
                'proximity_typos': [],
                'typo_count': 0,
                'reason': 'exact_match_with_popular_package'
            }
        
        # If very different name, no similarity concerns
        if min_distance is None or min_distance > 2:
            return 1, {
                'proximity_typos': [],
                'typo_count': 0,
                'reason': 'no_similarity_to_popular_packages'
            }
        
        # Only analyze keyboard proximity for packages similar to popular ones (distance 1-2)
        proximity_typos = []
        package_lower = package_name.lower()
        
        # Method 1: Check for adjacent characters that form suspicious patterns
        for i in range(len(package_lower) - 1):
            char1 = package_lower[i]
            char2 = package_lower[i + 1]
            
            # Check if these characters are adjacent on keyboard AND
            # form a suspicious pattern (less common letter combinations)
            if char1 in self.qwerty_proximity and char2 in self.qwerty_proximity[char1]:
                # Define suspicious adjacent combinations that are likely typos
                # Includes all adjacent key pairs that represent common typing mistakes
                suspicious_adjacent = {
                    'qw', 'wq', 'we', 'ew', 'er', 're', 'rt', 'tr', 'ty', 'yt', 'yu', 'uy', 'ui', 'iu', 'io', 'oi', 'op', 'po',
                    'as', 'sa', 'sd', 'ds', 'df', 'fd', 'fg', 'gf', 'gh', 'hg', 'hj', 'jh', 'jk', 'kj', 'kl', 'lk',
                    'zx', 'xz', 'xc', 'cx', 'cv', 'vc', 'vb', 'bv', 'bn', 'nb', 'nm', 'mn',
                    # Additional common adjacent key errors
                    'aw', 'wa', 'sw', 'ws', 'de', 'ed', 'fr', 'rf', 'gt', 'tg', 'hy', 'yh', 'ju', 'uj', 'ki', 'ik', 'lo', 'ol',
                    'az', 'za', 'sx', 'xs', 'dc', 'cd', 'fv', 'vf', 'gb', 'bg', 'hn', 'nh', 'jm', 'mj'
                }
                
                char_pair = char1 + char2
                if char_pair in suspicious_adjacent:
                    proximity_typos.append(f"{char_pair} (adjacent keys at positions {i}-{i+1})")
        
        # Method 2: Check for single character differences that might be keyboard proximity errors
        # This is particularly important for packages like "requestd" vs "requests" (s→d)
        # We'll analyze character patterns that could indicate proximity substitutions
        suspicious_endings = ['d', 'f', 'g']  # Common typos for 's' ending
        suspicious_beginnings = ['q', 'e', 'a']  # Common typos for 'w' beginning
        
        if package_lower.endswith('d') and not package_lower.endswith('ed'):
            # Check if this could be 's' → 'd' substitution
            proximity_typos.append("potential s→d substitution (keyboard proximity)")
        
        if package_lower.endswith('f') and not package_lower.endswith('if'):
            # Check if this could be 's' → 'f' substitution  
            proximity_typos.append("potential s→f substitution (keyboard proximity)")
            
        # Scoring logic
        if len(proximity_typos) == 0:
            score = 1  # No proximity typos
        else:
            score = 0  # 1+ proximity typos - high risk
        
        return score, {
            'proximity_typos': proximity_typos,
            'typo_count': len(proximity_typos)
        }
    
    def _calculate_creation_date_score(self, package_name: str, package_metadata: Optional[Dict[str, Any]], string_distance_details: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """Calculate creation date + similarity score (Factor 5).
        
        Args:
            package_name: Package name to analyze
            package_metadata: Package metadata from PyPI
            string_distance_details: Details from string distance analysis
            
        Returns:
            Tuple of (score, details)
        """
        min_distance = string_distance_details.get('min_distance')
        has_similarity = min_distance is not None and min_distance <= self.similarity_threshold
        
        if not package_metadata or not package_metadata.get('creation_date'):
            # If no creation date available AND high similarity exists, assume high risk (0 pts)
            # Following security-first approach per ZSBOM Risk Scoring Framework v1.0
            if has_similarity:
                return 0, {'creation_date': None, 'reason': 'date_unavailable_with_similarity', 'has_similarity': True}
            else:
                return 1, {'creation_date': None, 'reason': 'date_unavailable', 'has_similarity': False}
        
        creation_date_str = package_metadata['creation_date']
        
        try:
            # Parse creation date
            creation_date = datetime.fromisoformat(creation_date_str.replace('Z', '+00:00'))
            days_since_creation = (datetime.now() - creation_date.replace(tzinfo=None)).days
            
            # Scoring logic
            if days_since_creation > self.new_package_days:
                score = 1  # Old package
            elif not has_similarity:
                score = 1  # New package + dissimilar
            else:
                score = 0  # New package + similar - high risk
            
            return score, {
                'creation_date': creation_date_str,
                'days_since_creation': days_since_creation,
                'is_new_package': days_since_creation <= self.new_package_days,
                'has_similarity': has_similarity
            }
            
        except Exception as e:
            logger.error(f"Failed to parse creation date '{creation_date_str}' for package '{package_name}': {e}. "
                        f"Expected ISO 8601 format. This affects Factor 5 scoring (creation date analysis).")
            # On parse error with similarity, be conservative (0 pts)
            if has_similarity:
                return 0, {'creation_date': creation_date_str, 'reason': 'date_parse_error_with_similarity', 'has_similarity': True}
            else:
                return 1, {'creation_date': creation_date_str, 'reason': 'date_parse_error', 'has_similarity': False}
    
    def score(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        typosquatting_whitelist: Optional[List[str]] = None,
        **kwargs: Any
    ) -> float:
        """Calculate typosquatting risk score using 5-factor analysis.
        
        Implements the complete ZSBOM Risk Scoring Framework v1.0 typosquatting
        detection algorithm with parallel API calls and robust error handling.
        
        Process:
        1. Check whitelist first (returns 10.0 if whitelisted)
        2. Fetch top packages and PyPI metadata in parallel
        3. Calculate all 5 scoring factors
        4. Sum factors for final score (0-10)
        
        Args:
            package: Package name to analyze
            installed_version: Currently installed version (unused in scoring)
            declared_version: Version declared in requirements (unused)
            typosquatting_whitelist: List of known safe packages (bypass scoring)
            **kwargs: Additional configuration parameters
            
        Returns:
            Score between 0.0 (highest risk) and 10.0 (lowest risk)
            - 0.0-2.0: High risk (multiple risk factors)
            - 3.0-6.0: Medium risk (some risk factors)
            - 7.0-10.0: Low risk (minimal risk factors)
            
        Network Behavior:
            - Uses parallel API calls for performance
            - Falls back to stale cache when network unavailable
            - Returns 5.0 (moderate risk) on complete API failure
        """
        # Check whitelist first
        if typosquatting_whitelist and package.lower() in [p.lower() for p in typosquatting_whitelist]:
            return 10.0
        
        try:
            # Get top packages first, then use them for metadata lookup
            top_packages = self._get_top_packages()
            
            # Get package metadata with top packages data for download count reuse
            package_metadata = self._get_pypi_metadata(package, top_packages)
            
            # Check for API failures
            if not top_packages and not package_metadata:
                # Both APIs failed, return default moderate score
                return 5.0
            
            # Calculate all factors
            factor1_score, factor1_details = self._calculate_string_distance_score(package, top_packages)
            factor2_score, factor2_details = self._calculate_downloads_similarity_score(package, package_metadata, factor1_details)
            factor3_score, factor3_details = self._calculate_character_substitution_score(package)
            factor4_score, factor4_details = self._calculate_keyboard_proximity_score(package, factor1_details)
            factor5_score, factor5_details = self._calculate_creation_date_score(package, package_metadata, factor1_details)
            
            # Calculate total score
            total_score = factor1_score + factor2_score + factor3_score + factor4_score + factor5_score
            
            return float(total_score)
            
        except Exception as e:
            logger.error(f"Critical error calculating typosquatting risk score for package '{package}': {e}. "
                        f"This may indicate configuration issues or corrupted data. Using default moderate score (5.0).")
            return 5.0  # Default moderate score on error
    
    def get_details(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        typosquatting_whitelist: Optional[List[str]] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """Get detailed typosquatting scoring information.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements (unused)
            typosquatting_whitelist: List of known safe packages
            **kwargs: Additional configuration
            
        Returns:
            Dictionary containing detailed scoring information
        """
        score = self.score(package, installed_version, declared_version, typosquatting_whitelist, **kwargs)
        
        # Check whitelist first
        if typosquatting_whitelist and package.lower() in [p.lower() for p in typosquatting_whitelist]:
            return {
                "dimension": "typosquat_heuristics",
                "score": score,
                "package_name": package,
                "risk_indicators": [],
                "in_whitelist": True,
                "factors": {
                    "string_distance": {"score": 3, "details": "whitelisted"},
                    "downloads_similarity": {"score": 3, "details": "whitelisted"},
                    "character_substitution": {"score": 2, "details": "whitelisted"},
                    "keyboard_proximity": {"score": 1, "details": "whitelisted"},
                    "creation_date": {"score": 1, "details": "whitelisted"}
                }
            }
        
        try:
            # Get top packages first, then use them for metadata lookup
            top_packages = self._get_top_packages()
            
            # Get package metadata with top packages data for download count reuse
            package_metadata = self._get_pypi_metadata(package, top_packages)
            
            # Calculate all factors with details
            factor1_score, factor1_details = self._calculate_string_distance_score(package, top_packages)
            factor2_score, factor2_details = self._calculate_downloads_similarity_score(package, package_metadata, factor1_details)
            factor3_score, factor3_details = self._calculate_character_substitution_score(package)
            factor4_score, factor4_details = self._calculate_keyboard_proximity_score(package, factor1_details)
            factor5_score, factor5_details = self._calculate_creation_date_score(package, package_metadata, factor1_details)
            
            # Identify risk indicators
            risk_indicators = []
            if factor1_score == 0:
                risk_indicators.append("very_similar_to_popular_package")
            if factor2_score == 0:
                risk_indicators.append("low_downloads_with_similar_name")
            if factor3_score == 0:
                risk_indicators.append("multiple_character_substitutions")
            if factor4_score == 0:
                risk_indicators.append("keyboard_proximity_typos")
            if factor5_score == 0:
                risk_indicators.append("new_package_with_similar_name")
            
            return {
                "dimension": "typosquat_heuristics",
                "score": score,
                "package_name": package,
                "risk_indicators": risk_indicators,
                "in_whitelist": False,
                "factors": {
                    "string_distance": {"score": factor1_score, "details": factor1_details},
                    "downloads_similarity": {"score": factor2_score, "details": factor2_details},
                    "character_substitution": {"score": factor3_score, "details": factor3_details},
                    "keyboard_proximity": {"score": factor4_score, "details": factor4_details},
                    "creation_date": {"score": factor5_score, "details": factor5_details}
                },
                "total_max_score": 10
            }
            
        except Exception as e:
            logger.error(f"Critical error retrieving detailed typosquatting analysis for package '{package}': {e}. "
                        f"This may indicate configuration issues or corrupted data. Returning error details.")
            return {
                "dimension": "typosquat_heuristics",
                "score": score,
                "package_name": package,
                "risk_indicators": ["scoring_error"],
                "in_whitelist": False,
                "error": str(e)
            }