"""
Enhanced dependency extraction module for ZSBOM.

Supports parsing of multiple dependency file formats:
- requirements.txt
- pyproject.toml (PEP 621 and Poetry formats)
- setup.py/setup.cfg
- Pipfile

Includes proper version constraint parsing using the packaging library.
"""

import os
import re
import ast
import configparser
import importlib.metadata
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # Fallback for older Python versions
    except ImportError:
        tomllib = None

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version


class DependencyFileParser:
    """Unified dependency file parser supporting multiple formats."""
    
    def __init__(self, project_path: str = "."):
        self.project_path = Path(project_path)
        self.file_priority = [
            "pyproject.toml",
            "requirements.txt", 
            "setup.py",
            "setup.cfg",
            "Pipfile"
        ]
    
    def extract_dependencies(self) -> Dict[str, Dict[str, str]]:
        """Extract dependencies from all found dependency files.
        
        Returns:
            Dictionary mapping file names to package specifications
        """
        dependencies = {}
        
        # Parse each dependency file format
        for file_name in self.file_priority:
            file_path = self.project_path / file_name
            if file_path.exists():
                try:
                    deps = self._parse_file(file_path)
                    if deps:
                        dependencies[file_name] = deps
                except Exception as e:
                    print(f"⚠️ Error parsing {file_name}: {e}")
        
        # Add runtime (installed) packages
        dependencies["runtime"] = self._get_installed_packages()
        
        return dependencies
    
    def _parse_file(self, file_path: Path) -> Optional[Dict[str, str]]:
        """Parse a single dependency file."""
        if file_path.name == "requirements.txt":
            return self._parse_requirements_txt(file_path)
        elif file_path.name == "pyproject.toml":
            return self._parse_pyproject_toml(file_path)
        elif file_path.name == "setup.py":
            return self._parse_setup_py(file_path)
        elif file_path.name == "setup.cfg":
            return self._parse_setup_cfg(file_path)
        elif file_path.name == "Pipfile":
            return self._parse_pipfile(file_path)
        
        return None
    
    def _parse_requirements_txt(self, file_path: Path) -> Dict[str, str]:
        """Parse requirements.txt file."""
        dependencies = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue

                    # Remove inline comments
                    line = line.split('#', 1)[0].strip()
                    
                    # Skip -r includes, -e editable installs, etc.
                    if line.startswith('-'):
                        continue
                    
                    # Parse requirement
                    try:
                        req = Requirement(line)
                        dependencies[req.name.lower()] = str(req.specifier) if req.specifier else ""
                    except Exception as e:
                        print(f"⚠️ Error parsing requirement '{line}' at line {line_num}: {e}")
        
        except Exception as e:
            print(f"⚠️ Error reading {file_path}: {e}")
        
        return dependencies
    
    def _parse_pyproject_toml(self, file_path: Path) -> Dict[str, str]:
        """Parse pyproject.toml file (both PEP 621 and Poetry formats)."""
        if not tomllib:
            print("⚠️ TOML parsing library not available")
            return {}
        
        dependencies = {}
        
        try:
            with open(file_path, 'rb') as f:
                data = tomllib.load(f)
            
            # Try PEP 621 format first
            project_deps = data.get("project", {}).get("dependencies", [])
            for dep in project_deps:
                try:
                    req = Requirement(dep)
                    dependencies[req.name.lower()] = str(req.specifier) if req.specifier else ""
                except Exception as e:
                    print(f"⚠️ Error parsing PEP 621 dependency '{dep}': {e}")
            
            # Try Poetry format
            poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            for name, spec in poetry_deps.items():
                if name == "python":  # Skip Python version constraint
                    continue
                
                # Convert Poetry format to standard format
                if isinstance(spec, str):
                    # Handle Poetry version specs like "^1.0.0" or ">=1.0.0"
                    dependencies[name.lower()] = self._convert_poetry_spec(spec)
                elif isinstance(spec, dict):
                    # Handle Poetry dict format: {"version": "^1.0.0", "optional": true}
                    version_spec = spec.get("version", "")
                    if version_spec and not spec.get("optional", False):
                        dependencies[name.lower()] = self._convert_poetry_spec(version_spec)
        
        except Exception as e:
            print(f"⚠️ Error parsing {file_path}: {e}")
        
        return dependencies
    
    def _parse_setup_py(self, file_path: Path) -> Dict[str, str]:
        """Parse setup.py file."""
        dependencies = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse AST to find setup() call
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and hasattr(node.func, 'id') and node.func.id == 'setup':
                    # Find install_requires argument
                    for keyword in node.keywords:
                        if keyword.arg == 'install_requires':
                            deps = self._extract_list_from_ast(keyword.value)
                            for dep in deps:
                                try:
                                    req = Requirement(dep)
                                    dependencies[req.name.lower()] = str(req.specifier) if req.specifier else ""
                                except Exception as e:
                                    print(f"⚠️ Error parsing setup.py dependency '{dep}': {e}")
        
        except Exception as e:
            print(f"⚠️ Error parsing {file_path}: {e}")
        
        return dependencies
    
    def _parse_setup_cfg(self, file_path: Path) -> Dict[str, str]:
        """Parse setup.cfg file."""
        dependencies = {}
        
        try:
            config = configparser.ConfigParser()
            config.read(file_path)
            
            # Look for install_requires in [options] section
            if config.has_section('options') and config.has_option('options', 'install_requires'):
                install_requires = config.get('options', 'install_requires')
                
                # Parse multi-line install_requires
                for line in install_requires.strip().split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            req = Requirement(line)
                            dependencies[req.name.lower()] = str(req.specifier) if req.specifier else ""
                        except Exception as e:
                            print(f"⚠️ Error parsing setup.cfg dependency '{line}': {e}")
        
        except Exception as e:
            print(f"⚠️ Error parsing {file_path}: {e}")
        
        return dependencies
    
    def _parse_pipfile(self, file_path: Path) -> Dict[str, str]:
        """Parse Pipfile."""
        if not tomllib:
            print("⚠️ TOML parsing library not available for Pipfile")
            return {}
        
        dependencies = {}
        
        try:
            with open(file_path, 'rb') as f:
                data = tomllib.load(f)
            
            # Parse [packages] section
            packages = data.get("packages", {})
            for name, spec in packages.items():
                if isinstance(spec, str):
                    if spec == "*":
                        dependencies[name.lower()] = ""
                    else:
                        # Convert Pipfile format to standard format
                        dependencies[name.lower()] = self._convert_pipfile_spec(spec)
                elif isinstance(spec, dict):
                    version_spec = spec.get("version", "")
                    if version_spec and version_spec != "*":
                        dependencies[name.lower()] = self._convert_pipfile_spec(version_spec)
        
        except Exception as e:
            print(f"⚠️ Error parsing {file_path}: {e}")
        
        return dependencies
    
    def _get_installed_packages(self) -> Dict[str, str]:
        """Get currently installed packages and their versions."""
        installed = {}
        
        try:
            for dist in importlib.metadata.distributions():
                name = dist.metadata["Name"].lower()
                version = dist.version
                installed[name] = version
        except Exception as e:
            print(f"⚠️ Error getting installed packages: {e}")
        
        return installed
    
    def _convert_poetry_spec(self, spec: str) -> str:
        """Convert Poetry version specification to standard format."""
        if spec.startswith("^"):
            # Caret constraint: ^1.2.3 means >=1.2.3,<2.0.0
            version = spec[1:]
            try:
                v = Version(version)
                return f">={version},<{v.major + 1}.0.0"
            except:
                return spec
        elif spec.startswith("~"):
            # Tilde constraint: ~1.2.3 means >=1.2.3,<1.3.0
            version = spec[1:]
            try:
                v = Version(version)
                return f">={version},<{v.major}.{v.minor + 1}.0"
            except:
                return spec
        else:
            # Standard constraint
            return spec
    
    def _convert_pipfile_spec(self, spec: str) -> str:
        """Convert Pipfile version specification to standard format."""
        # Pipfile uses mostly standard format, but may have quotes
        return spec.strip('"\'')
    
    def _extract_list_from_ast(self, node: ast.AST) -> List[str]:
        """Extract list of strings from AST node."""
        result = []
        
        if isinstance(node, ast.List):
            for item in node.elts:
                if isinstance(item, ast.Str):
                    result.append(item.s)
                elif isinstance(item, ast.Constant) and isinstance(item.value, str):
                    result.append(item.value)
        
        return result


def extract_dependencies(project_path: str = ".") -> Dict[str, Dict[str, str]]:
    """Extract dependencies from all supported file formats.
    
    Args:
        project_path: Path to the project directory
        
    Returns:
        Dictionary mapping file names to package specifications
    """
    parser = DependencyFileParser(project_path)
    return parser.extract_dependencies()


def get_installed_packages() -> Dict[str, str]:
    """Get currently installed packages and their versions."""
    return DependencyFileParser()._get_installed_packages()


if __name__ == "__main__":
    deps = extract_dependencies()
    for file_name, packages in deps.items():
        print(f"\n{file_name}:")
        for package, version in packages.items():
            print(f"  {package}: {version}")
