"""
Scalibr wrapper for multi-language dependency extraction.

This wrapper provides a Python interface to the OSV Scalibr shared library for
extracting dependencies from various package ecosystems.
"""

import json
import ctypes
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Dict, Any


def get_platform_library_name() -> str:
    """Get the expected library filename for current platform."""
    system = platform.system().lower()

    if system == "darwin":
        return "scalibr.dylib"
    elif system == "linux":
        return "scalibr.so"
    elif system == "windows":
        return "scalibr.dll"
    else:
        # Default to .so for unknown Unix-like systems
        return "scalibr.so"


def get_platform_specific_library_name() -> str:
    """Get platform-specific library filename."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Normalize OS names
    if system == "darwin":
        os_name = "darwin"
        extension = "dylib"
    elif system == "linux":
        os_name = "linux"
        extension = "so"
    elif system == "windows":
        os_name = "windows"
        extension = "dll"
    else:
        os_name = "linux"  # Default fallback
        extension = "so"

    # Normalize architecture names
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        arch = "amd64"  # Default fallback

    return f"scalibr-{os_name}-{arch}.{extension}"


def try_build_library(build_dir: Path) -> bool:
    """Try to build the library using the build script."""
    try:
        build_script = build_dir / "build.py"
        if build_script.exists():
            print("🔨 Attempting to build Scalibr library...")
            result = subprocess.run(
                [sys.executable, str(build_script)],
                cwd=build_dir,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes
            )
            return result.returncode == 0
    except Exception:
        pass
    return False


def load_scalibr_library():
    """Load the Scalibr shared library with multi-platform support."""
    build_dir = Path(__file__).parent

    # Try different library names in order of preference
    library_candidates = [
        build_dir / get_platform_library_name(),  # Generic name (scalibr.so/dylib/dll)
        build_dir / get_platform_specific_library_name(),  # Platform-specific name
    ]

    # Also check for the old location for backward compatibility
    old_scalibr_path = build_dir.parent.parent.parent.parent / "scalibr" / get_platform_library_name()
    if old_scalibr_path.exists():
        library_candidates.append(old_scalibr_path)

    # Try to find existing library
    for lib_path in library_candidates:
        if lib_path.exists():
            try:
                lib = ctypes.CDLL(str(lib_path))
                print(f"✅ Loaded Scalibr library: {lib_path}")
                break
            except OSError as e:
                print(f"⚠️  Failed to load library {lib_path}: {e}")
                continue
    else:
        # No library found, try to build it
        print("📦 Scalibr library not found, attempting to build...")

        if try_build_library(build_dir):
            # Try loading the newly built library
            for lib_path in library_candidates:
                if lib_path.exists():
                    try:
                        lib = ctypes.CDLL(str(lib_path))
                        print(f"✅ Built and loaded Scalibr library: {lib_path}")
                        break
                    except OSError as e:
                        print(f"⚠️  Failed to load newly built library {lib_path}: {e}")
                        continue
            else:
                raise FileNotFoundError(
                    f"Failed to build or load Scalibr library. Tried: {[str(p) for p in library_candidates]}"
                )
        else:
            # Build failed, provide helpful error message
            error_msg = (
                f"Scalibr library not found and build failed.\n"
                f"Searched for: {[str(p) for p in library_candidates]}\n"
                f"To resolve this issue:\n"
                f"1. Install Go: https://golang.org/dl/\n"
                f"2. Run: cd {build_dir} && make\n"
                f"3. Or manually build: go build -buildmode=c-shared -o {get_platform_library_name()} scalibr_wrapper.go"
            )
            raise FileNotFoundError(error_msg)

    # Define function signatures

    # GetAllPlugins() -> *char
    lib.GetAllPlugins.restype = ctypes.c_char_p
    lib.GetAllPlugins.argtypes = []

    # GetPluginAliases() -> *char
    lib.GetPluginAliases.restype = ctypes.c_char_p
    lib.GetPluginAliases.argtypes = []

    # Scan(root *char, pluginsJSON *char, mode *char) -> *char
    lib.Scan.restype = ctypes.c_char_p
    lib.Scan.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

    # ScanDirectory(path *char) -> *char
    lib.ScanDirectory.restype = ctypes.c_char_p
    lib.ScanDirectory.argtypes = [ctypes.c_char_p]

    # FreeString(str *char)
    lib.FreeString.restype = None
    lib.FreeString.argtypes = [ctypes.c_char_p]

    return lib


def call_and_decode(lib, func, *args):
    """Call a library function and decode the result."""
    try:
        # Call the function
        if args:
            result_ptr = func(*args)
        else:
            result_ptr = func()

        if result_ptr:
            # Create a copy of the string
            result = ctypes.string_at(result_ptr).decode('utf-8')
            # NOTE: Skipping FreeString for now due to memory issues
            # TODO: Fix memory management in a future version
            return result
        return None
    except Exception as e:
        print(f"Error in call_and_decode: {e}")
        return None


class ScalibrWrapper:
    """Python wrapper for the OSV Scalibr shared library."""

    def __init__(self):
        """Initialize the wrapper by loading the shared library."""
        self.lib = load_scalibr_library()

    def get_all_plugins(self) -> List[Dict[str, Any]]:
        """Get information about all available plugins."""
        result = call_and_decode(self.lib, self.lib.GetAllPlugins)
        if result:
            return json.loads(result)
        return []

    def get_plugin_aliases(self) -> Dict[str, str]:
        """Get plugin aliases and their descriptions."""
        result = call_and_decode(self.lib, self.lib.GetPluginAliases)
        if result:
            return json.loads(result)
        return {}

    def scan(self, root: str = ".", plugins: Optional[List[str]] = None, mode: str = "auto") -> Optional[Dict[str, Any]]:
        """
        Scan a directory with flexible plugin configuration.

        Args:
            root: Directory to scan (default: current directory)
            plugins: List of plugin names/aliases to use (None = use defaults)
                    Examples: ["python"], ["python", "enrichers/all"], ["java", "vulnmatch"]
            mode: Capability mode - "auto" (default), "online", or "offline"

        Returns:
            Scan results as dictionary, or None if scan failed
        """
        root_bytes = str(root).encode('utf-8')
        mode_bytes = mode.encode('utf-8')

        # Convert plugins list to JSON if provided
        plugins_json = None
        if plugins:
            plugins_json = json.dumps(plugins).encode('utf-8')

        result = call_and_decode(self.lib, self.lib.Scan, root_bytes, plugins_json, mode_bytes)
        if result:
            return json.loads(result)
        return None

    def scan_directory(self, path: str) -> Optional[Dict[str, Any]]:
        """Scan a directory with default settings (backward compatibility)."""
        path_bytes = path.encode('utf-8')
        result = call_and_decode(self.lib, self.lib.ScanDirectory, path_bytes)
        if result:
            return json.loads(result)
        return None


# Convenience functions for common use cases

def scan_javascript(root: str = ".", with_vulns: bool = True) -> Optional[Dict[str, Any]]:
    """Scan for JavaScript/Node.js packages with optional vulnerability enrichment."""
    scalibr = ScalibrWrapper()
    plugins = ["javascript"]
    if with_vulns:
        plugins.extend(["enrichers/vulnmatch", "enrichers/license"])
    return scalibr.scan(root, plugins)


def scan_npm(root: str = ".", with_vulns: bool = True) -> Optional[Dict[str, Any]]:
    """Scan for NPM packages (alias for scan_javascript)."""
    return scan_javascript(root, with_vulns)


def scan_all_languages(root: str = ".", with_enrichment: bool = True) -> Optional[Dict[str, Any]]:
    """Scan for all supported language packages with optional enrichment."""
    scalibr = ScalibrWrapper()
    plugins = ["extractors/default"]
    if with_enrichment:
        plugins.extend(["enrichers/all", "annotators/all"])
    return scalibr.scan(root, plugins)