"""
Configuration management for ZSBOM.

Handles loading, merging, and discovery of configuration files following
SOLID principles with single responsibility for config operations.
"""
import os
from typing import Optional

import yaml

try:
    # Use modern importlib.resources (Python 3.9+)
    import importlib.resources as importlib_resources
    pkg_resources = None
except ImportError:
    # Fallback to pkg_resources for older Python versions
    import pkg_resources
    importlib_resources = None


class ConfigManager:
    """Manages ZSBOM configuration loading and merging operations."""
    
    def load_config(self, path: str) -> dict:
        """Load configuration from YAML file."""
        with open(path, "r") as f:
            return yaml.safe_load(f)

    def deep_merge(self, default: dict, user: dict) -> dict:
        """Deep merge user config into default config."""
        result = default.copy()
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self.deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def load_package_default_config(self) -> dict:
        """Load default config from package."""
        try:
            # Try modern importlib.resources first (Python 3.9+)
            if importlib_resources:
                import depclass.config
                config_files = importlib_resources.files(depclass.config)
                default_config_path = config_files / 'default.yaml'
                with default_config_path.open('r') as f:
                    return yaml.safe_load(f)
            else:
                raise ImportError("importlib.resources not available")
        except Exception:
            # Fallback to pkg_resources for older Python versions
            try:
                if pkg_resources:
                    default_config_path = pkg_resources.resource_filename('depclass', 'config/default.yaml')
                    return self.load_config(default_config_path)
                else:
                    raise ImportError("pkg_resources not available")
            except Exception:
                # Last resort - try relative path
                import depclass
                package_path = os.path.dirname(depclass.__file__)
                default_config_path = os.path.join(package_path, 'config', 'default.yaml')
                return self.load_config(default_config_path)

    def load_and_merge_config(self, user_config_path: str) -> dict:
        """Load user config and merge with package default."""
        default_config = self.load_package_default_config()
        user_config = self.load_config(user_config_path)
        return self.deep_merge(default_config, user_config)

    def discover_and_load_config(self, config_arg: Optional[str]) -> dict:
        """Discover config file with priority order."""
        
        # Priority 1: --config argument
        if config_arg:
            if os.path.exists(config_arg):
                return self.load_and_merge_config(config_arg)
            else:
                raise FileNotFoundError(f"Config file not found: {config_arg}")
        
        # Priority 2: zsbom.config.yaml in current directory
        if os.path.exists("zsbom.config.yaml"):
            return self.load_and_merge_config("zsbom.config.yaml")
        
        # Priority 3: Package default config
        return self.load_package_default_config()

    def merge_config_and_args(self, config: dict, output: Optional[str], ignore_conflicts: bool) -> dict:
        """Merge configuration with CLI arguments."""
        if output is not None:
            config["output"]["sbom_file"] = output
        
        config["ignore_conflicts"] = ignore_conflicts
        
        return config