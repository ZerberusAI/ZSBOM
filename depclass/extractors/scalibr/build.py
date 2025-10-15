#!/usr/bin/env python3
"""
Scalibr shared library build script.

Automatically builds the Scalibr Go wrapper for the current platform,
with fallback to pre-built binaries if Go is not available.
"""

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple


def get_platform_info() -> Tuple[str, str, str]:
    """
    Get platform information for determining build target.

    Returns:
        Tuple of (os_name, architecture, file_extension)
    """
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
        raise RuntimeError(f"Unsupported operating system: {system}")

    # Normalize architecture names
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        raise RuntimeError(f"Unsupported architecture: {machine}")

    return os_name, arch, extension


def check_go_available() -> bool:
    """Check if Go compiler is available."""
    try:
        result = subprocess.run(
            ["go", "version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def get_library_name(os_name: str, arch: str, extension: str) -> str:
    """Get the expected library filename for platform."""
    return f"scalibr-{os_name}-{arch}.{extension}"


def get_current_platform_library(extension: str) -> str:
    """Get the library name for current platform (generic name)."""
    if extension == "dylib":
        return "scalibr.dylib"
    elif extension == "dll":
        return "scalibr.dll"
    else:
        return "scalibr.so"


def build_scalibr(build_dir: Path) -> bool:
    """
    Build Scalibr shared library for current platform.

    Args:
        build_dir: Directory containing Go source files

    Returns:
        True if build successful, False otherwise
    """
    try:
        os_name, arch, extension = get_platform_info()

        # Check if Go is available
        if not check_go_available():
            print("⚠️  Go compiler not found. Cannot build Scalibr shared library.")
            print("   Install Go from https://golang.org/dl/ to build from source.")
            return False

        print(f"🔨 Building Scalibr for {os_name}-{arch}...")

        # Change to build directory
        original_dir = os.getcwd()
        os.chdir(build_dir)

        try:
            # Set environment variables for cross-compilation
            env = os.environ.copy()
            env["GOOS"] = os_name
            env["GOARCH"] = arch

            # For Windows, we need additional setup
            if os_name == "windows":
                env["CGO_ENABLED"] = "1"
                # Note: This requires mingw-w64 to be installed
                env["CC"] = "x86_64-w64-mingw32-gcc"

            # Build command
            output_name = get_library_name(os_name, arch, extension)
            cmd = [
                "go", "build",
                "-buildmode=c-shared",
                f"-o={output_name}",
                "scalibr_wrapper.go"
            ]

            print(f"   Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )

            if result.returncode != 0:
                print(f"❌ Build failed:")
                print(f"   stdout: {result.stdout}")
                print(f"   stderr: {result.stderr}")
                return False

            # Create generic symlink/copy for current platform
            current_lib = get_current_platform_library(extension)
            if Path(output_name).exists():
                # Create a copy with generic name for easier loading
                if Path(current_lib).exists():
                    Path(current_lib).unlink()

                # On Unix systems, create symlink; on Windows, copy
                if os_name == "windows":
                    subprocess.run(["copy", output_name, current_lib], shell=True)
                else:
                    Path(current_lib).symlink_to(output_name)

                print(f"✅ Successfully built {output_name}")
                print(f"   Created {current_lib} -> {output_name}")
                return True
            else:
                print(f"❌ Build completed but {output_name} not found")
                return False

        finally:
            os.chdir(original_dir)

    except Exception as e:
        print(f"❌ Build failed with error: {e}")
        return False


def check_existing_library(build_dir: Path) -> Optional[str]:
    """
    Check if a compatible pre-built library exists.

    Returns:
        Path to existing library if found, None otherwise
    """
    try:
        os_name, arch, extension = get_platform_info()
        current_lib = get_current_platform_library(extension)
        platform_lib = get_library_name(os_name, arch, extension)

        # Check for generic library name first
        generic_path = build_dir / current_lib
        if generic_path.exists():
            return str(generic_path)

        # Check for platform-specific library
        platform_path = build_dir / platform_lib
        if platform_path.exists():
            return str(platform_path)

        return None

    except Exception:
        return None


def main():
    """Main build function."""
    # Determine build directory (where this script is located)
    build_dir = Path(__file__).parent

    print("🏗️  Scalibr Library Build")
    print("=" * 50)

    try:
        os_name, arch, extension = get_platform_info()
        print(f"Platform: {os_name}-{arch}")
        print(f"Target: {get_library_name(os_name, arch, extension)}")
        print()

        # Check if library already exists
        existing_lib = check_existing_library(build_dir)
        if existing_lib:
            print(f"✅ Found existing library: {existing_lib}")
            print("   Skipping build (use --force to rebuild)")
            return True

        # Try to build
        success = build_scalibr(build_dir)

        if not success:
            print()
            print("❌ Build failed. Possible solutions:")
            print("   1. Install Go: https://golang.org/dl/")
            print("   2. For Windows: Install mingw-w64")
            print("   3. Use pre-built binaries if available")
            return False

        print()
        print("✅ Scalibr library build completed successfully!")
        return True

    except Exception as e:
        print(f"❌ Platform detection failed: {e}")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)