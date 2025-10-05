"""
Simplified configuration management for ZSBOM.
"""
import os
from typing import Optional
import yaml

try:
    import importlib.resources as importlib_resources
except ImportError:
    import pkg_resources
    importlib_resources = None


class ConfigManager:
    """Simplified configuration manager."""
    
    def load_config(self, path: str) -> dict:
        """Load configuration from YAML file."""
        with open(path, "r") as f:
            return yaml.safe_load(f)

    def load_package_default_config(self) -> dict:
        """Load default config from package."""
        try:
            # Try modern approach first
            if importlib_resources:
                import depclass.config
                config_files = importlib_resources.files(depclass.config)
                default_config_path = config_files / 'default.yaml'
                with default_config_path.open('r') as f:
                    return yaml.safe_load(f)
            else:
                # Fallback for older Python
                default_config_path = pkg_resources.resource_filename('depclass', 'config/default.yaml')
                return self.load_config(default_config_path)
        except Exception:
            # Last resort - try relative path
            import depclass
            package_path = os.path.dirname(depclass.__file__)
            default_config_path = os.path.join(package_path, 'config', 'default.yaml')
            return self.load_config(default_config_path)

    def discover_and_load_config(self, config_arg: Optional[str]) -> dict:
        """Discover config file with simple priority order."""
        
        # Priority 1: --config argument
        if config_arg and os.path.exists(config_arg):
            user_config = self.load_config(config_arg)
            default_config = self.load_package_default_config()
            return self._merge_configs(default_config, user_config)
        
        # Priority 2: zsbom.config.yaml in current directory
        if os.path.exists("zsbom.config.yaml"):
            user_config = self.load_config("zsbom.config.yaml")
            default_config = self.load_package_default_config()
            return self._merge_configs(default_config, user_config)
        
        # Priority 3: Package default config
        return self.load_package_default_config()

    def merge_config_and_args(self, config: dict, output: Optional[str], ignore_conflicts: bool) -> dict:
        """Merge configuration with CLI arguments."""
        if output is not None:
            config["output"]["sbom_file"] = output
        
        config["ignore_conflicts"] = ignore_conflicts
        return config
    
    def _merge_configs(self, default: dict, user: dict) -> dict:
        """Simple config merge."""
        result = default.copy()
        if user is None:
            return result
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        return result