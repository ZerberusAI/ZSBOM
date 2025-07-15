"""Typosquat Heuristics dimension scorer."""

import difflib
from typing import Any, Dict, List, Optional, Set

from .base import DimensionScorer


class TyposquatHeuristicsScorer(DimensionScorer):
    """Scores packages based on typosquatting heuristics.
    
    Scoring criteria:
    - Clean package name (no typosquatting indicators): 10.0
    - Minor similarity to popular packages: 6.0-8.0
    - Moderate similarity indicators: 3.0-5.0
    - High similarity to known packages: 1.0-2.0
    - Exact match to known typosquatting patterns: 0.0
    
    Uses fuzzy matching and pattern detection against known safe packages.
    """

    def __init__(self):
        # Popular Python packages that are commonly typosquatted
        self.popular_packages = {
            "requests", "urllib3", "certifi", "charset-normalizer", "idna",
            "numpy", "pandas", "matplotlib", "scipy", "scikit-learn",
            "django", "flask", "fastapi", "tornado", "aiohttp",
            "pytest", "setuptools", "wheel", "pip", "virtualenv",
            "boto3", "botocore", "aws-cli", "awscli", "s3transfer",
            "click", "colorama", "tqdm", "rich", "typer",
            "pydantic", "sqlalchemy", "alembic", "redis", "celery",
            "pillow", "opencv-python", "imageio", "matplotlib",
            "tensorflow", "torch", "keras", "transformers",
            "pytz", "python-dateutil", "arrow", "pendulum",
            "pyyaml", "toml", "configparser", "python-dotenv",
            "bcrypt", "cryptography", "passlib", "pyjwt",
            "beautifulsoup4", "lxml", "html5lib", "scrapy",
            "jinja2", "mako", "chameleon", "genshi"
        }
        
        # Common typosquatting patterns
        self.known_typosquat_patterns = {
            "reqquests", "requets", "request", "reuqests",
            "numpyy", "numy", "numpi", "numpy2",
            "dj4ngo", "djang0", "django2", "djangoo",
            "flaskk", "flask2", "falsk", "flaks",
            "pytho", "python3", "pythoon", "pyton",
            "pip3", "pipi", "pipp", "pi-p",
            "setuptols", "setuptools2", "setup-tools",
            "wheel2", "whell", "wheell", "wh33l",
            "panda", "pandass", "pandas2", "pands",
            "boto", "boto33", "botoo", "bot03",
            "clickk", "clik", "click2", "cl1ck",
            "tqdmm", "tqdm2", "tdqm", "tq-dm",
            "pilloww", "pilow", "pillow2", "pil10w",
            "bcryp", "bcrypt2", "bcryp7", "bcrytp",
            "beautifuloup", "beautifulsoup", "bsoup4", "bs4soup",
            "cryptographyy", "cryptography2", "crypto-graphy",
            "pyjw7", "pyjwt2", "py-jwt", "pyjwtt",
            "tensorfloww", "tensorflow2", "tensor-flow", "tf2",
            "scipyy", "scipy2", "sci-py", "scipi",
            "matplotlibm", "matplotlib2", "mat-plotlib", "mpl",
            "sqlalchmy", "sqlalchemy2", "sql-alchemy", "sqlalch",
            "alembicm", "alembic2", "al-embic", "alemb1c",
            "rediss", "redis2", "red-is", "red1s",
            "celeryy", "celery2", "cel-ery", "celeri",
            "fastapii", "fastapi2", "fast-api", "f4stapi",
            "tornadoo", "tornado2", "torn-ado", "t0rnado",
            "aiohttpp", "aiohttp2", "aio-http", "aioh7tp",
            "pytestt", "pytest2", "py-test", "pyt3st",
            "jinja22", "jinja2-2", "jin-ja2", "j1nja2",
            "pytz2", "py-tz", "pyt2", "p7tz",
            "python-dateutill", "python-dateutil2", "date-util", "dateut1l",
            "arroww", "arrow2", "arr-ow", "arr0w",
            "pendulumm", "pendulum2", "pend-ulum", "pendul",
            "pyyamll", "pyyaml2", "py-yaml", "pyy4ml",
            "tomll", "toml2", "t0ml", "tom-l",
            "configparserr", "configparser2", "config-parser", "confparser",
            "python-dotenvv", "python-dotenv2", "python-env", "py-dotenv",
            "passlibb", "passlib2", "pass-lib", "passl1b",
            "lxmll", "lxml2", "l-xml", "lxm1",
            "html5libb", "html5lib2", "html5-lib", "html51ib",
            "scrapyy", "scrapy2", "scr-apy", "scr4py",
            "makoo", "mako2", "ma-ko", "m4ko",
            "chameleoon", "chameleon2", "chameleon-2", "chame1eon",
            "genshii", "genshi2", "gen-shi", "g3nshi"
        }

    def score(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        typosquat_blacklist: Optional[List[str]] = None,
        **kwargs: Any
    ) -> float:
        """Calculate typosquatting risk score.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            typosquat_blacklist: List of known typosquatting packages
            **kwargs: Additional data (unused)
            
        Returns:
            Score between 0.0 (highest risk) and 10.0 (lowest risk)
        """
        package_lower = package.lower()
        
        # Check against known typosquatting patterns
        if package_lower in self.known_typosquat_patterns:
            return 0.0  # Exact match to known typosquat
        
        # Check against user-provided blacklist
        if typosquat_blacklist:
            if package_lower in [p.lower() for p in typosquat_blacklist]:
                return 0.0  # In user blacklist
        
        # Calculate similarity to popular packages
        max_similarity = 0.0
        most_similar_package = None
        
        for popular_package in self.popular_packages:
            similarity = self._calculate_similarity(package_lower, popular_package)
            if similarity > max_similarity:
                max_similarity = similarity
                most_similar_package = popular_package
        
        # Score based on similarity
        if max_similarity >= 0.9:
            return 0.0  # Very high similarity - likely typosquat
        elif max_similarity >= 0.8:
            return 1.0  # High similarity - suspicious
        elif max_similarity >= 0.7:
            return 2.0  # Moderate-high similarity
        elif max_similarity >= 0.6:
            return 4.0  # Moderate similarity
        elif max_similarity >= 0.5:
            return 6.0  # Some similarity
        elif max_similarity >= 0.4:
            return 8.0  # Minor similarity
        else:
            return 10.0  # No significant similarity
    
    def get_details(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        typosquat_blacklist: Optional[List[str]] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """Get detailed typosquatting scoring information.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            typosquat_blacklist: List of known typosquatting packages
            **kwargs: Additional data (unused)
            
        Returns:
            Dictionary containing scoring details
        """
        score = self.score(package, installed_version, declared_version, typosquat_blacklist, **kwargs)
        package_lower = package.lower()
        
        # Find most similar popular package
        max_similarity = 0.0
        most_similar_package = None
        
        for popular_package in self.popular_packages:
            similarity = self._calculate_similarity(package_lower, popular_package)
            if similarity > max_similarity:
                max_similarity = similarity
                most_similar_package = popular_package
        
        # Check various risk indicators
        in_known_patterns = package_lower in self.known_typosquat_patterns
        in_user_blacklist = False
        if typosquat_blacklist:
            in_user_blacklist = package_lower in [p.lower() for p in typosquat_blacklist]
        
        # Find potential typosquatting indicators
        indicators = []
        if in_known_patterns:
            indicators.append("matches_known_typosquat_pattern")
        if in_user_blacklist:
            indicators.append("in_user_blacklist")
        if max_similarity >= 0.7:
            indicators.append("high_similarity_to_popular_package")
        
        # Check for suspicious patterns
        suspicious_patterns = self._check_suspicious_patterns(package_lower)
        indicators.extend(suspicious_patterns)
        
        return {
            "dimension": "typosquat_heuristics",
            "score": score,
            "package_name": package,
            "risk_indicators": indicators,
            "similarity_analysis": {
                "max_similarity": max_similarity,
                "most_similar_package": most_similar_package,
                "similarity_threshold": 0.7,
            },
            "pattern_checks": {
                "in_known_patterns": in_known_patterns,
                "in_user_blacklist": in_user_blacklist,
                "suspicious_patterns": suspicious_patterns,
            },
        }

    def _calculate_similarity(self, package1: str, package2: str) -> float:
        """Calculate similarity between two package names.
        
        Args:
            package1: First package name
            package2: Second package name
            
        Returns:
            Similarity score between 0.0 and 1.0
        """
        # Use difflib for sequence matching
        matcher = difflib.SequenceMatcher(None, package1, package2)
        sequence_ratio = matcher.ratio()
        
        # Also calculate Levenshtein-like distance
        levenshtein_ratio = self._levenshtein_similarity(package1, package2)
        
        # Use the higher of the two ratios
        return max(sequence_ratio, levenshtein_ratio)

    def _levenshtein_similarity(self, s1: str, s2: str) -> float:
        """Calculate Levenshtein similarity between two strings.
        
        Args:
            s1: First string
            s2: Second string
            
        Returns:
            Similarity score between 0.0 and 1.0
        """
        if len(s1) == 0:
            return 0.0 if len(s2) > 0 else 1.0
        if len(s2) == 0:
            return 0.0
        
        # Create distance matrix
        distance_matrix = [[0] * (len(s2) + 1) for _ in range(len(s1) + 1)]
        
        # Initialize first row and column
        for i in range(len(s1) + 1):
            distance_matrix[i][0] = i
        for j in range(len(s2) + 1):
            distance_matrix[0][j] = j
        
        # Fill the matrix
        for i in range(1, len(s1) + 1):
            for j in range(1, len(s2) + 1):
                if s1[i-1] == s2[j-1]:
                    distance_matrix[i][j] = distance_matrix[i-1][j-1]
                else:
                    distance_matrix[i][j] = min(
                        distance_matrix[i-1][j] + 1,      # deletion
                        distance_matrix[i][j-1] + 1,      # insertion
                        distance_matrix[i-1][j-1] + 1     # substitution
                    )
        
        # Convert distance to similarity
        max_len = max(len(s1), len(s2))
        distance = distance_matrix[len(s1)][len(s2)]
        similarity = 1.0 - (distance / max_len)
        
        return max(0.0, similarity)

    def _check_suspicious_patterns(self, package_name: str) -> List[str]:
        """Check for suspicious patterns in package name.
        
        Args:
            package_name: Package name to check
            
        Returns:
            List of suspicious pattern descriptions
        """
        patterns = []
        
        # Handle empty package name
        if not package_name:
            return patterns
        
        # Check for common typosquatting patterns
        if any(char in package_name for char in "0123456789"):
            if any(char in package_name for char in "o01il"):
                patterns.append("contains_confusing_characters")
        
        # Check for doubled characters
        for i in range(len(package_name) - 1):
            if package_name[i] == package_name[i + 1] and package_name[i].isalpha():
                patterns.append("contains_doubled_characters")
                break
        
        # Check for hyphens/underscores in unusual positions
        if package_name.startswith("-") or package_name.startswith("_"):
            patterns.append("starts_with_separator")
        if package_name.endswith("-") or package_name.endswith("_"):
            patterns.append("ends_with_separator")
        
        # Check for numeric suffixes (common in typosquats)
        if package_name and package_name[-1].isdigit():
            patterns.append("ends_with_digit")
        
        # Check for common typosquat suffixes
        typosquat_suffixes = ["2", "3", "lib", "py", "tool", "utils", "pkg"]
        for suffix in typosquat_suffixes:
            if package_name.endswith(suffix) and len(package_name) > len(suffix):
                patterns.append(f"suspicious_suffix_{suffix}")
        
        return patterns