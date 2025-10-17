"""Typosquat Heuristics dimension scorer with 5-factor analysis."""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import Levenshtein
from .base import DimensionScorer
from .enhanced_data_utils import get_package_data, extract_package_metadata_field

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


    def __init__(self):
        """Initialize the typosquat heuristics scorer.

        Sets up the scoring engine with configuration for all 5 factors:
        - Character substitution patterns (bidirectional mappings)
        - QWERTY keyboard proximity mappings (including shift keys)
        - Download count thresholds for scoring
        """
        
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
        
        # No longer need cache initialization - using enhanced data
    
    def _extract_top_packages_data(self, enhanced_data: Optional[Dict], ecosystem: str = "python") -> List[Dict[str, Any]]:
        """Extract top packages data from enhanced dependency data.

        Top packages are stored separately from individual package data.
        They represent the most popular packages in the ecosystem used for typosquatting detection.

        Args:
            enhanced_data: Enhanced dependency data from enhancers
            ecosystem: Package ecosystem

        Returns:
            List of top package dictionaries with name and download count
        """
        if not enhanced_data:
            return []

        # Top packages should be stored in a separate section
        top_packages_data = enhanced_data.get("top_packages", {})
        if not isinstance(top_packages_data, dict):
            return []

        # Get top packages for the specific ecosystem
        ecosystem_top_packages = top_packages_data.get(ecosystem, [])
        if not isinstance(ecosystem_top_packages, list):
            return []

        return ecosystem_top_packages
    
    
    

    
    
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
    
    def _calculate_downloads_similarity_score(self, package_name: str, package_metadata: Optional[Dict[str, Any]], top_packages, string_distance_details: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
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
        
        download_count = package_metadata.get('download_count') or 0

        if download_count == 0:
            # Try to get download count from top packages list
            top_package_match = next(
                (pkg for pkg in top_packages if pkg['project'].lower() == package_name),
                None
            )
            if top_package_match:
                download_count = top_package_match.get('download_count') or 0

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
        download_count = download_count or 0

        if download_count >= self.download_thresholds['high']:
            return 'high'
        elif download_count >= self.download_thresholds['medium']:
            return 'medium'
        elif download_count >= self.download_thresholds['low']:
            return 'low'
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
        ecosystem: str = "python",
        **kwargs: Any
    ) -> float:
        """Calculate typosquatting risk score using 5-factor analysis.

        Implements the complete ZSBOM Risk Scoring Framework v1.0 typosquatting
        detection algorithm using enhanced data from the TopPackagesEnhancer.

        Process:
        1. Check whitelist first (returns 10.0 if whitelisted)
        2. Extract top packages and metadata from enhanced data
        3. Calculate all 5 scoring factors
        4. Sum factors for final score (0-10)

        Args:
            package: Package name to analyze
            installed_version: Currently installed version (unused in scoring)
            declared_version: Version declared in requirements (unused)
            typosquatting_whitelist: List of known safe packages (bypass scoring)
            ecosystem: Package ecosystem
            **kwargs: Additional configuration parameters including enhanced_data

        Returns:
            Score between 0.0 (highest risk) and 10.0 (lowest risk)
            - 0.0-2.0: High risk (multiple risk factors)
            - 3.0-6.0: Medium risk (some risk factors)
            - 7.0-10.0: Low risk (minimal risk factors)
        """
        # Check whitelist first
        if typosquatting_whitelist and package.lower() in [p.lower() for p in typosquatting_whitelist]:
            return 10.0

        # Extract enhanced data from kwargs
        enhanced_data = kwargs.get("enhanced_data", {})

        try:
            # Extract data from enhanced data
            top_packages = self._extract_top_packages_data(enhanced_data, ecosystem)
            package_metadata = extract_package_metadata_field(enhanced_data, package, ecosystem, installed_version)

            # Check for data availability
            if not top_packages and not package_metadata:
                # No enhanced data available, return default moderate score
                return 5.0

            # Calculate all factors
            factor1_score, factor1_details = self._calculate_string_distance_score(package, top_packages)
            factor2_score, factor2_details = self._calculate_downloads_similarity_score(package, package_metadata, top_packages, factor1_details)
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
        ecosystem: str = "python",
        **kwargs: Any
    ) -> Dict[str, Any]:
        """Get detailed typosquatting scoring information.

        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements (unused)
            typosquatting_whitelist: List of known safe packages
            ecosystem: Package ecosystem
            **kwargs: Additional configuration including enhanced_data from enhancers

        Returns:
            Dictionary containing detailed scoring information
        """
        # Extract enhanced data from kwargs
        enhanced_data = kwargs.get("enhanced_data", {})

        score = self.score(package, installed_version, declared_version, typosquatting_whitelist, ecosystem, **kwargs)

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
            # Extract data from enhanced data
            top_packages = self._extract_top_packages_data(enhanced_data, ecosystem)
            package_metadata = extract_package_metadata_field(enhanced_data, package, ecosystem, installed_version)

            # Calculate all factors with details
            factor1_score, factor1_details = self._calculate_string_distance_score(package, top_packages)
            factor2_score, factor2_details = self._calculate_downloads_similarity_score(package, package_metadata, top_packages, factor1_details)
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