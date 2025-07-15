"""Configuration validation for ZSBOM risk scoring."""

from typing import Any, Dict, List, Optional
import yaml

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
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if not isinstance(config, dict):
                return {}, ["Configuration file must contain a dictionary"]
            
            validation_errors = self.validate_config(config)
            return config, validation_errors
            
        except FileNotFoundError:
            return {}, [f"Configuration file not found: {config_path}"]
        except yaml.YAMLError as e:
            return {}, [f"Error parsing YAML configuration: {e}"]
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