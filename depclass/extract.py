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
import subprocess
import hashlib
import json
import tempfile
import time
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
    
    def extract_dependencies_with_transitive_analysis(self, config: Dict, cache=None) -> Dict[str, Any]:
        """Extract dependencies with comprehensive transitive analysis.
        
        Returns:
            Dictionary containing both dependencies and transitive analysis results
        """
        # Extract base dependencies
        dependencies = self.extract_dependencies()
        
        # Initialize transitive analysis result
        transitive_analysis = {
            "status": "unknown",
            "classification": {},
            "dependency_tree": {},
            "depth_levels": {},
            "direct_sources": {},
            "resolution_details": {},
            "conflicts": {}
        }
        
        try:
            # Check if pip-tools is available
            if not self._check_pip_tools_available():
                transitive_analysis["status"] = "pip_tools_unavailable"
                print("⚠️ pip-tools not available. Install with: pip install pip-tools>=7.4.1")
                return {"dependencies": dependencies, "transitive_analysis": transitive_analysis}
            
            # Consolidate requirements from all dependency files
            consolidated_requirements = self._consolidate_requirements(dependencies, config)
            if not consolidated_requirements:
                transitive_analysis["status"] = "no_requirements"
                return {"dependencies": dependencies, "transitive_analysis": transitive_analysis}
            
            # Run pip-compile to resolve transitive dependencies
            resolved_output = self._run_pip_compile_with_cache(consolidated_requirements, config, cache)
            
            # Parse the dependency tree and classification
            tree_data = self._parse_dependency_tree(resolved_output, dependencies, config)
            transitive_analysis.update(tree_data)
            transitive_analysis["status"] = "resolved"
            
        except subprocess.CalledProcessError as e:
            if "could not find a version that satisfies" in str(e.stderr).lower() or "no matching distribution" in str(e.stderr).lower():
                transitive_analysis["status"] = "conflict_detected"
                transitive_analysis["conflicts"] = self._generate_conflict_recommendations(str(e.stderr), dependencies)
                
                if not config.get("ignore_conflicts", False):
                    print(f"❌ Dependency conflicts detected. Use --ignore-conflicts to continue with degraded analysis.")
                    print(f"Error: {e.stderr}")
                    raise RuntimeError("Dependency resolution failed due to conflicts")
            else:
                transitive_analysis["status"] = "resolution_failed"
                print(f"⚠️ Failed to resolve dependencies: {e}")
                
        except Exception as e:
            transitive_analysis["status"] = "analysis_failed"
            print(f"⚠️ Transitive analysis failed: {e}")
        
        return {"dependencies": dependencies, "transitive_analysis": transitive_analysis}
    
    def _check_pip_tools_available(self) -> bool:
        """Check if pip-tools is available."""
        try:
            result = subprocess.run(["pip-compile", "--version"], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _consolidate_requirements(self, dependencies: Dict[str, Dict[str, str]], config: Dict) -> str:
        """Consolidate requirements from multiple files using file priority."""
        consolidated = {}
        conflicts = {}
        
        # Use existing file priority from config or default
        file_priority = config.get("version_consistency", {}).get("file_priority", self.file_priority)
        
        # Process files in priority order (reverse to get highest priority last)
        for file_name in reversed(file_priority):
            if file_name in dependencies and dependencies[file_name]:
                for package, version_spec in dependencies[file_name].items():
                    package_lower = package.lower()
                    
                    if package_lower in consolidated:
                        # Record conflict if different specifications
                        if consolidated[package_lower] != version_spec:
                            if package_lower not in conflicts:
                                conflicts[package_lower] = []
                            conflicts[package_lower].append({
                                "file": file_name,
                                "spec": version_spec,
                                "previous_spec": consolidated[package_lower]
                            })
                    
                    # Higher priority file overwrites (since we're going in reverse)
                    consolidated[package_lower] = version_spec
        
        # Generate requirements.txt format string
        requirements_lines = []
        for package, version_spec in consolidated.items():
            if version_spec:
                requirements_lines.append(f"{package}{version_spec}")
            else:
                requirements_lines.append(package)
        
        return "\n".join(requirements_lines)
    
    def _get_cache_key(self, requirements_content: str, config: Dict) -> str:
        """Generate cache key based on requirements and config."""
        # Include private repo config in cache key
        repo_config = config.get("private_repositories", {})
        cache_data = {
            "requirements": requirements_content,
            "index_url": repo_config.get("index_url", ""),
            "extra_index_urls": repo_config.get("extra_index_urls", []),
            "trusted_hosts": repo_config.get("trusted_hosts", []),
            "find_links": repo_config.get("find_links", []),
            "no_index": repo_config.get("no_index", False)
        }
        return hashlib.sha256(json.dumps(cache_data, sort_keys=True).encode()).hexdigest()
    
    def _build_pip_compile_args(self, config: Dict) -> List[str]:
        """Build pip-compile arguments with private repository support."""
        args = ["pip-compile", "--dry-run", "--quiet", "--strip-extras"]
        
        # Add private repository configuration
        repo_config = config.get("private_repositories", {})
        
        if repo_config.get("index_url"):
            args.extend(["--index-url", repo_config["index_url"]])
        
        for extra_url in repo_config.get("extra_index_urls", []):
            args.extend(["--extra-index-url", extra_url])
        
        for trusted_host in repo_config.get("trusted_hosts", []):
            args.extend(["--trusted-host", trusted_host])
        
        for find_link in repo_config.get("find_links", []):
            args.extend(["--find-links", find_link])
        
        if repo_config.get("no_index", False):
            args.append("--no-index")
        
        return args
    
    def _run_pip_compile_with_cache(self, requirements_content: str, config: Dict, cache=None) -> str:
        """Run pip-compile with SQLite caching and retry logic."""
        cache_key = self._get_cache_key(requirements_content, config)
        
        # Check cache if available and enabled
        if cache and config.get("caching", {}).get("enabled", False):
            ttl_hours = config.get("caching", {}).get("ttl_hours", 24)
            cached_result = cache.get_cached_pip_compile(cache_key, ttl_hours)
            if cached_result:
                print(f"📋 Using cached dependency resolution")
                return cached_result
        
        # Create temporary requirements file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
            temp_file.write(requirements_content)
            temp_file_path = temp_file.name
        
        # Create temporary output file for pip-compile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as output_file:
            output_file_path = output_file.name
        
        try:
            # Build pip-compile command
            args = self._build_pip_compile_args(config)
            args.extend(["--output-file", output_file_path])
            args.append(temp_file_path)
            
            # Get timeout from config
            timeout = config.get("transitive_analysis", {}).get("pip_compile_timeout", 60)
            
            print(f"🔍 Resolving transitive dependencies...")
            
            # Run pip-compile with retry logic
            for attempt in range(3):
                try:
                    result = subprocess.run(
                        args,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        check=True
                    )
                    
                    # With --dry-run, pip-compile outputs to stderr instead of the output file
                    output_content = result.stderr if result.stderr else result.stdout
                    
                    # If neither stderr nor stdout has content, try reading the output file
                    if not output_content.strip():
                        try:
                            with open(output_file_path, 'r', encoding='utf-8') as f:
                                output_content = f.read()
                        except Exception:
                            pass
                    
                    # Cache successful result if cache is available and enabled
                    if cache and config.get("caching", {}).get("enabled", False):
                        requirements_hash = hashlib.sha256(requirements_content.encode()).hexdigest()
                        cache.cache_pip_compile_result(cache_key, requirements_hash, output_content)
                    
                    return output_content
                    
                except subprocess.TimeoutExpired:
                    if attempt < 2:
                        print(f"⏱️ Timeout on attempt {attempt + 1}, retrying...")
                        time.sleep(2 ** attempt)  # Exponential backoff
                    else:
                        raise
                except subprocess.CalledProcessError as e:
                    # Add better error reporting
                    error_msg = f"pip-compile failed with exit code {e.returncode}"
                    if e.stderr:
                        error_msg += f"\nstderr: {e.stderr}"
                    if e.stdout:
                        error_msg += f"\nstdout: {e.stdout}"
                    print(f"⚠️ Error on attempt {attempt + 1}: {error_msg}")
                    
                    # Don't retry on resolution conflicts
                    if attempt < 2 and "could not find a version" not in str(e.stderr).lower():
                        print(f"⚠️ Retrying...")
                        time.sleep(2 ** attempt)
                    else:
                        raise
                        
        finally:
            # Clean up temporary files
            try:
                os.unlink(temp_file_path)
            except OSError:
                pass
            try:
                os.unlink(output_file_path)
            except OSError:
                pass
    
    def _parse_dependency_tree(self, pip_output: str, original_dependencies: Dict[str, Dict[str, str]], config: Dict) -> Dict[str, Any]:
        """Parse pip-compile output to build dependency tree and classification."""
        lines = pip_output.strip().split('\n')
        
        # Find direct dependencies (those that appear in original requirements)
        all_original_packages = set()
        direct_sources = {}
        
        for file_name, packages in original_dependencies.items():
            if file_name != "runtime":  # Skip runtime packages for direct classification
                for package in packages.keys():
                    package_lower = package.lower()
                    all_original_packages.add(package_lower)
                    if package_lower not in direct_sources:
                        direct_sources[package_lower] = []
                    direct_sources[package_lower].append(file_name)
        
        # Parse resolved dependencies
        resolved_packages = {}
        dependency_tree = {}
        classification = {}
        depth_levels = {}
        resolution_details = {}
        
        # Two-pass parsing to handle pip-compile format where package and via comment are on separate lines
        current_package = None
        
        for i, line in enumerate(lines):
            stripped_line = line.strip()
            original_line = line  # Keep original for indentation checking
            
            if not stripped_line or stripped_line.startswith('#') or stripped_line.startswith('-'):
                # Check if this is a "# via" comment that belongs to the previous package
                if current_package and original_line.startswith('    #') and 'via' in stripped_line:
                    via_match = stripped_line.split('via', 1)
                    if len(via_match) > 1:
                        via_part = via_match[1].strip()
                        # Filter out "-r requirements.in" style entries and focus on actual package names
                        parents = []
                        for parent in via_part.split(','):
                            parent = parent.strip()
                            # Skip file references like "-r requirements.in"
                            if parent and not parent.startswith('-') and not parent.endswith('.in') and not parent.endswith('.txt'):
                                parents.append(parent.lower())
                        
                        if parents:
                            dependency_tree[current_package] = parents
                            classification[current_package] = "transitive"
                            depth_levels[current_package] = 1  # Will be refined below
                continue
            
            # Parse package line: "package==1.0.0"
            try:
                req = Requirement(stripped_line)
                package_name = req.name.lower()
                package_version = stripped_line.split('==')[1] if '==' in stripped_line else ""
                
                resolved_packages[package_name] = package_version
                resolution_details[package_name] = package_version
                current_package = package_name
                
                # Default classification (may be updated by following via comment)
                classification[package_name] = "direct" if package_name in all_original_packages else "transitive"
                depth_levels[package_name] = 0 if package_name in all_original_packages else 1
                    
            except Exception as e:
                print(f"⚠️ Failed to parse requirement line: {stripped_line} - {e}")
                current_package = None
                continue
        
        # Ensure all original packages are marked as direct
        for package in all_original_packages:
            if package in classification:
                classification[package] = "direct"
                depth_levels[package] = 0
        
        # Calculate proper depth levels
        depth_levels = self._calculate_depth_levels(dependency_tree, all_original_packages)
        
        return {
            "classification": classification,
            "dependency_tree": dependency_tree,
            "depth_levels": depth_levels,
            "direct_sources": direct_sources,
            "resolution_details": resolution_details
        }
    
    def _calculate_depth_levels(self, dependency_tree: Dict[str, List[str]], direct_packages: set) -> Dict[str, int]:
        """Calculate depth levels for packages in dependency tree."""
        depth_levels = {}
        
        # Set direct packages to depth 0
        for package in direct_packages:
            depth_levels[package] = 0
        
        # Calculate depths iteratively
        changed = True
        max_iterations = 10  # Prevent infinite loops
        iteration = 0
        
        while changed and iteration < max_iterations:
            changed = False
            iteration += 1
            
            for package, parents in dependency_tree.items():
                if package not in depth_levels:
                    # Find minimum parent depth
                    parent_depths = []
                    for parent in parents:
                        parent = parent.lower()
                        if parent in depth_levels:
                            parent_depths.append(depth_levels[parent])
                    
                    if parent_depths:
                        new_depth = min(parent_depths) + 1
                        depth_levels[package] = new_depth
                        changed = True
        
        return depth_levels
    
    def _generate_conflict_recommendations(self, error_output: str, dependencies: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
        """Generate conflict resolution recommendations."""
        conflicts = {
            "error_summary": "Dependency version conflicts detected",
            "recommendations": [],
            "conflicting_packages": []
        }
        
        # Parse error output to identify conflicting packages
        # This is a simplified implementation
        if "could not find a version" in error_output.lower():
            conflicts["recommendations"].append(
                "Review version constraints in your dependency files for compatibility"
            )
            conflicts["recommendations"].append(
                "Consider using more flexible version ranges (e.g., >=1.0.0 instead of ==1.0.0)"
            )
        
        return conflicts
    
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


def extract_dependencies(project_path: str = ".", config: Optional[Dict] = None, cache=None) -> Dict[str, Any]:
    """Extract dependencies with transitive analysis from all supported file formats.
    
    Args:
        project_path: Path to the project directory
        config: Configuration dictionary containing transitive analysis settings
        cache: VulnerabilityCache instance for SQLite caching
        
    Returns:
        Dictionary containing dependencies and transitive analysis results
    """
    parser = DependencyFileParser(project_path)
    return parser.extract_dependencies_with_transitive_analysis(config or {}, cache)


def get_installed_packages() -> Dict[str, str]:
    """Get currently installed packages and their versions."""
    return DependencyFileParser()._get_installed_packages()


if __name__ == "__main__":
    deps = extract_dependencies()
    for file_name, packages in deps.items():
        print(f"\n{file_name}:")
        for package, version in packages.items():
            print(f"  {package}: {version}")
