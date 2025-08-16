"""Configuration validation for ZSBOM risk scoring."""

from typing import Any, Dict, List, Optional
import re

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yaml = None

from .risk_model import RiskModel


class ConfigValidator:
    """Validates ZSBOM configuration for risk scoring compliance."""
    
    def __init__(self):
        self.required_dimensions = {
            "declared_vs_installed",
            "known_cves",
            "cwe_coverage",
            "package_abandonment",
            "typosquat_heuristics",
        }
    
    def validate_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate complete configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Validate risk model section
        if "risk_model" not in config:
            errors.append("Missing 'risk_model' section in configuration")
            return errors
        
        risk_model_config = config["risk_model"]
        
        # Validate weights
        weights_errors = self.validate_weights(risk_model_config.get("weights", {}))
        errors.extend(weights_errors)
        
        # Validate thresholds
        thresholds_errors = self.validate_thresholds(risk_model_config.get("risk_thresholds", {}))
        errors.extend(thresholds_errors)
        
        # Validate typosquat_detection section
        if "typosquat_detection" in config:
            typosquat_errors = self.validate_typosquat_detection(config["typosquat_detection"])
            errors.extend(typosquat_errors)
        
        # Validate typosquatting_whitelist
        if "typosquatting_whitelist" in config:
            whitelist_errors = self.validate_typosquatting_whitelist(config["typosquatting_whitelist"])
            errors.extend(whitelist_errors)
        
        return errors
    
    def validate_typosquat_detection(self, typosquat_config: Dict[str, Any]) -> List[str]:
        """Validate typosquat_detection configuration.
        
        Args:
            typosquat_config: Typosquat detection configuration dictionary
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        # Check enabled flag
        if "enabled" not in typosquat_config:
            errors.append("Missing 'enabled' flag in typosquat_detection configuration")
        elif not isinstance(typosquat_config["enabled"], bool):
            errors.append("'enabled' flag in typosquat_detection must be boolean")
        
        # Check top_packages_url
        if "top_packages_url" not in typosquat_config:
            errors.append("Missing 'top_packages_url' in typosquat_detection configuration")
        else:
            url = typosquat_config["top_packages_url"]
            if not isinstance(url, str):
                errors.append("'top_packages_url' must be a string")
            elif not self._is_valid_url(url):
                errors.append(f"'top_packages_url' is not a valid URL: {url}")
        
        # Check download_thresholds
        if "download_thresholds" not in typosquat_config:
            errors.append("Missing 'download_thresholds' in typosquat_detection configuration")
        else:
            thresholds = typosquat_config["download_thresholds"]
            threshold_errors = self._validate_download_thresholds(thresholds)
            errors.extend(threshold_errors)
        
        # Check similarity_threshold
        if "similarity_threshold" not in typosquat_config:
            errors.append("Missing 'similarity_threshold' in typosquat_detection configuration")
        else:
            threshold = typosquat_config["similarity_threshold"]
            if not isinstance(threshold, (int, float)):
                errors.append("'similarity_threshold' must be numeric")
            elif threshold < 0 or threshold > 10:
                errors.append(f"'similarity_threshold' must be between 0 and 10, got {threshold}")
        
        # Check new_package_days
        if "new_package_days" not in typosquat_config:
            errors.append("Missing 'new_package_days' in typosquat_detection configuration")
        else:
            days = typosquat_config["new_package_days"]
            if not isinstance(days, int):
                errors.append("'new_package_days' must be an integer")
            elif days <= 0:
                errors.append(f"'new_package_days' must be positive, got {days}")
        
        # Check cache_ttl
        if "cache_ttl" not in typosquat_config:
            errors.append("Missing 'cache_ttl' in typosquat_detection configuration")
        else:
            cache_ttl = typosquat_config["cache_ttl"]
            ttl_errors = self._validate_cache_ttl(cache_ttl)
            errors.extend(ttl_errors)
        
        return errors
    
    def validate_typosquatting_whitelist(self, whitelist: Any) -> List[str]:
        """Validate typosquatting_whitelist configuration.
        
        Args:
            whitelist: Whitelist configuration
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        if not isinstance(whitelist, list):
            errors.append("'typosquatting_whitelist' must be a list")
        else:
            for i, package in enumerate(whitelist):
                if not isinstance(package, str):
                    errors.append(f"Package at index {i} in typosquatting_whitelist must be a string")
                elif not package.strip():
                    errors.append(f"Package at index {i} in typosquatting_whitelist cannot be empty")
                elif not self._is_valid_package_name(package):
                    errors.append(f"Invalid package name at index {i} in typosquatting_whitelist: {package}")
        
        return errors
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if a URL is valid.
        
        Args:
            url: URL to validate
            
        Returns:
            True if valid, False otherwise
        """
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return url_pattern.match(url) is not None
    
    def _is_valid_package_name(self, name: str) -> bool:
        """Check if a package name is valid.
        
        Args:
            name: Package name to validate
            
        Returns:
            True if valid, False otherwise
        """
        # Basic package name validation (alphanumeric, hyphens, underscores, dots)
        package_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$')
        return package_pattern.match(name) is not None
    
    def _validate_download_thresholds(self, thresholds: Any) -> List[str]:
        """Validate download thresholds configuration.
        
        Args:
            thresholds: Download thresholds configuration
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        if not isinstance(thresholds, dict):
            errors.append("'download_thresholds' must be a dictionary")
            return errors
        
        required_keys = {"high", "medium", "low"}
        missing_keys = required_keys - set(thresholds.keys())
        if missing_keys:
            errors.append(f"Missing keys in download_thresholds: {', '.join(missing_keys)}")
        
        # Check that all values are positive integers
        for key, value in thresholds.items():
            if not isinstance(value, int):
                errors.append(f"Download threshold '{key}' must be an integer, got {type(value)}")
            elif value < 0:
                errors.append(f"Download threshold '{key}' must be non-negative, got {value}")
        
        # Check logical ordering (high > medium > low)
        if all(k in thresholds for k in required_keys):
            high = thresholds["high"]
            medium = thresholds["medium"]
            low = thresholds["low"]
            
            if all(isinstance(v, int) for v in [high, medium, low]):
                if high <= medium:
                    errors.append(f"High threshold ({high}) must be greater than medium threshold ({medium})")
                if medium <= low:
                    errors.append(f"Medium threshold ({medium}) must be greater than low threshold ({low})")
        
        return errors
    
    def _validate_cache_ttl(self, cache_ttl: Any) -> List[str]:
        """Validate cache TTL configuration.
        
        Args:
            cache_ttl: Cache TTL configuration
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        if not isinstance(cache_ttl, dict):
            errors.append("'cache_ttl' must be a dictionary")
            return errors
        
        required_keys = {"top_packages_hours", "pypi_metadata_hours"}
        missing_keys = required_keys - set(cache_ttl.keys())
        if missing_keys:
            errors.append(f"Missing keys in cache_ttl: {', '.join(missing_keys)}")
        
        # Check that all values are positive integers
        for key, value in cache_ttl.items():
            if not isinstance(value, int):
                errors.append(f"Cache TTL '{key}' must be an integer, got {type(value)}")
            elif value <= 0:
                errors.append(f"Cache TTL '{key}' must be positive, got {value}")
        
        return errors
    
    def validate_weights(self, weights: Dict[str, Any]) -> List[str]:
        """Validate risk scoring weights.
        
        Args:
            weights: Weights dictionary
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        # Check that all required dimensions are present
        missing_dimensions = self.required_dimensions - set(weights.keys())
        if missing_dimensions:
            errors.append(f"Missing weights for dimensions: {', '.join(missing_dimensions)}")
        
        # Check that weights are numeric and non-negative
        for dimension, weight in weights.items():
            if not isinstance(weight, (int, float)):
                errors.append(f"Weight for '{dimension}' must be numeric, got {type(weight)}")
            elif weight < 0:
                errors.append(f"Weight for '{dimension}' cannot be negative, got {weight}")
        
        # Check that weights sum to 100% (with small tolerance for floating point errors)
        numeric_weights = {k: v for k, v in weights.items() if isinstance(v, (int, float))}
        if numeric_weights:
            total_weight = sum(numeric_weights.values())
            if abs(total_weight - 100.0) > 0.01:
                errors.append(f"Weights must sum to 100%, got {total_weight}%")
        
        # Check for unknown dimensions
        unknown_dimensions = set(weights.keys()) - self.required_dimensions
        if unknown_dimensions:
            errors.append(f"Unknown dimensions in weights: {', '.join(unknown_dimensions)}")
        
        return errors
    
    def validate_thresholds(self, thresholds: Dict[str, Any]) -> List[str]:
        """Validate risk thresholds.
        
        Args:
            thresholds: Thresholds dictionary
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        # Check required thresholds
        required_thresholds = {"low_risk_threshold", "medium_risk_threshold"}
        missing_thresholds = required_thresholds - set(thresholds.keys())
        if missing_thresholds:
            errors.append(f"Missing thresholds: {', '.join(missing_thresholds)}")
        
        # Check that thresholds are numeric and in valid range
        for threshold_name, threshold_value in thresholds.items():
            if not isinstance(threshold_value, (int, float)):
                errors.append(f"Threshold '{threshold_name}' must be numeric, got {type(threshold_value)}")
            elif threshold_value < 0 or threshold_value > 100:
                errors.append(f"Threshold '{threshold_name}' must be between 0 and 100, got {threshold_value}")
        
        # Check threshold ordering (low > medium)
        if all(k in thresholds for k in ["low_risk_threshold", "medium_risk_threshold"]):
            low_threshold = thresholds["low_risk_threshold"]
            medium_threshold = thresholds["medium_risk_threshold"]
            
            if isinstance(low_threshold, (int, float)) and isinstance(medium_threshold, (int, float)):
                if low_threshold <= medium_threshold:
                    errors.append(f"Low risk threshold ({low_threshold}) must be higher than medium risk threshold ({medium_threshold})")
        
        return errors
    
    def validate_risk_model(self, model: RiskModel) -> List[str]:
        """Validate a RiskModel instance.
        
        Args:
            model: RiskModel instance
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        # Validate weights
        weights = model.get_weights_dict()
        weight_errors = self.validate_weights(weights)
        errors.extend(weight_errors)
        
        # Validate thresholds
        thresholds = model.get_thresholds_dict()
        threshold_errors = self.validate_thresholds(thresholds)
        errors.extend(threshold_errors)
        
        return errors
    
    def load_and_validate_config(self, config_path: str) -> tuple[Dict[str, Any], List[str]]:
        """Load configuration from file and validate it.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Tuple of (config_dict, validation_errors)
        """
        try:
            if yaml is None:
                return {}, ["PyYAML library is not installed"]

            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)

            if not isinstance(config, dict):
                return {}, ["Configuration file must contain a dictionary"]

            validation_errors = self.validate_config(config)
            return config, validation_errors

        except FileNotFoundError:
            return {}, [f"Configuration file not found: {config_path}"]
        except Exception as e:
            return {}, [f"Error loading configuration: {e}"]
    
    def suggest_fixes(self, errors: List[str]) -> List[str]:
        """Suggest fixes for common configuration errors.
        
        Args:
            errors: List of validation error messages
            
        Returns:
            List of suggested fixes
        """
        suggestions = []
        
        for error in errors:
            if "must sum to 100%" in error:
                suggestions.append("Adjust weights so they total exactly 100%. For example: declared_vs_installed=15, known_cves=30, cwe_coverage=20, package_abandonment=20, typosquat_heuristics=15")
            elif "Missing weights for dimensions" in error:
                suggestions.append("Add missing dimension weights to the 'weights' section in your config.yaml")
            elif "Low risk threshold" in error and "must be higher than medium risk threshold" in error:
                suggestions.append("Ensure low_risk_threshold (e.g., 80) is higher than medium_risk_threshold (e.g., 50)")
            elif "must be between 0 and 100" in error:
                suggestions.append("Risk thresholds should be percentages between 0 and 100")
        
        return suggestions