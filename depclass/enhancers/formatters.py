"""
Package key formatting utilities for unified package representation.

This module provides utilities to convert ecosystem-specific package formats
to a unified format (package==version) used throughout the enhancer system.
"""

import re
from typing import Tuple, Optional


class PackageKeyFormatter:
    """
    Utility class for converting ecosystem-specific package formats to unified format.

    The unified format is: package==version for all ecosystems
    This simplifies processing and avoids ecosystem-specific parsing logic.
    """

    # Ecosystem-specific parsing patterns
    PATTERNS = {
        "npm": re.compile(r"^(.+?)@(.+)$"),          # package@version
        "go": re.compile(r"^(.+?)@v?(.+)$"),         # module@version or module@vversion
        "maven": re.compile(r"^(.+?):(.+)$"),        # group:artifact:version
        "cargo": re.compile(r"^(.+?)\s+(.+)$"),      # package version (space-separated)
        "python": re.compile(r"^(.+?)==(.+)$"),      # package==version
        "rubygems": re.compile(r"^(.+?)\s+\((.+?)\)$"),  # gem (version)
    }

    @staticmethod
    def to_unified(package: str, version: str, ecosystem: str) -> str:
        """
        Convert package and version to unified package==version format.

        Args:
            package: Package name
            version: Package version
            ecosystem: Package ecosystem

        Returns:
            Unified format string: package==version
        """
        # Clean up package name (remove any existing version info)
        clean_package = PackageKeyFormatter._clean_package_name(package, ecosystem)
        clean_version = PackageKeyFormatter._clean_version(version)

        return f"{clean_package}=={clean_version}"

    @staticmethod
    def from_ecosystem_format(package_spec: str, ecosystem: str) -> Tuple[str, str]:
        """
        Parse ecosystem-specific format to (package, version) tuple.

        Args:
            package_spec: Package specification in ecosystem format
            ecosystem: Package ecosystem

        Returns:
            Tuple of (package_name, version)

        Raises:
            ValueError: If package_spec cannot be parsed for the ecosystem
        """
        ecosystem = ecosystem.lower().strip()

        # Handle each ecosystem's format
        if ecosystem in ["npm", "javascript", "node"]:
            return PackageKeyFormatter._parse_npm_format(package_spec)

        elif ecosystem in ["python", "pypi"]:
            return PackageKeyFormatter._parse_python_format(package_spec)

        elif ecosystem in ["go", "golang"]:
            return PackageKeyFormatter._parse_go_format(package_spec)

        elif ecosystem in ["maven", "gradle", "java"]:
            return PackageKeyFormatter._parse_maven_format(package_spec)

        elif ecosystem in ["cargo", "rust", "crates.io"]:
            return PackageKeyFormatter._parse_cargo_format(package_spec)

        elif ecosystem in ["rubygems", "ruby"]:
            return PackageKeyFormatter._parse_rubygems_format(package_spec)

        elif ecosystem in ["nuget", "dotnet", "csharp"]:
            return PackageKeyFormatter._parse_nuget_format(package_spec)

        elif ecosystem in ["php", "packagist"]:
            return PackageKeyFormatter._parse_packagist_format(package_spec)

        else:
            # Default: try common patterns
            return PackageKeyFormatter._parse_default_format(package_spec)

    @staticmethod
    def get_original_format(package: str, version: str, ecosystem: str) -> str:
        """
        Get the original ecosystem-specific format for reference.

        Args:
            package: Package name
            version: Package version
            ecosystem: Package ecosystem

        Returns:
            Original ecosystem format string
        """
        ecosystem = ecosystem.lower().strip()

        if ecosystem in ["npm", "javascript", "node"]:
            return f"{package}@{version}"

        elif ecosystem in ["go", "golang"]:
            # Go uses v prefix for semantic versions
            version_with_v = version if version.startswith("v") else f"v{version}"
            return f"{package}@{version_with_v}"

        elif ecosystem in ["maven", "gradle", "java"]:
            # Maven format: group:artifact:version
            # Assume package contains group:artifact
            return f"{package}:{version}"

        elif ecosystem in ["cargo", "rust", "crates.io"]:
            return f"{package} {version}"

        elif ecosystem in ["rubygems", "ruby"]:
            return f"{package} ({version})"

        elif ecosystem in ["nuget", "dotnet", "csharp"]:
            return f"{package}.{version}"

        elif ecosystem in ["php", "packagist"]:
            return f"{package}:{version}"

        else:
            # Default: use == format
            return f"{package}=={version}"

    @staticmethod
    def _parse_npm_format(package_spec: str) -> Tuple[str, str]:
        """Parse npm package@version format."""
        match = PackageKeyFormatter.PATTERNS["npm"].match(package_spec.strip())
        if match:
            package, version = match.groups()
            return package.strip(), version.strip()

        # Fallback: assume no version specified
        return package_spec.strip(), "unknown"

    @staticmethod
    def _parse_python_format(package_spec: str) -> Tuple[str, str]:
        """Parse Python package==version format."""
        if "==" in package_spec:
            parts = package_spec.split("==", 1)
            return parts[0].strip(), parts[1].strip()

        # Handle other Python version specifiers
        for op in [">=", "<=", "!=", ">", "<", "~=", "===", "="]:
            if op in package_spec:
                parts = package_spec.split(op, 1)
                return parts[0].strip(), parts[1].strip()

        return package_spec.strip(), "unknown"

    @staticmethod
    def _parse_go_format(package_spec: str) -> Tuple[str, str]:
        """Parse Go module@version format."""
        match = PackageKeyFormatter.PATTERNS["go"].match(package_spec.strip())
        if match:
            module, version = match.groups()
            # Remove 'v' prefix from version if present
            version = version.lstrip("v")
            return module.strip(), version.strip()

        return package_spec.strip(), "unknown"

    @staticmethod
    def _parse_maven_format(package_spec: str) -> Tuple[str, str]:
        """Parse Maven group:artifact:version format."""
        parts = package_spec.split(":")
        if len(parts) >= 3:
            # group:artifact:version
            group_artifact = ":".join(parts[:-1])
            version = parts[-1]
            return group_artifact.strip(), version.strip()

        return package_spec.strip(), "unknown"

    @staticmethod
    def _parse_cargo_format(package_spec: str) -> Tuple[str, str]:
        """Parse Cargo 'package version' format."""
        match = PackageKeyFormatter.PATTERNS["cargo"].match(package_spec.strip())
        if match:
            package, version = match.groups()
            return package.strip(), version.strip()

        return package_spec.strip(), "unknown"

    @staticmethod
    def _parse_rubygems_format(package_spec: str) -> Tuple[str, str]:
        """Parse RubyGems 'gem (version)' format."""
        match = PackageKeyFormatter.PATTERNS["rubygems"].match(package_spec.strip())
        if match:
            gem, version = match.groups()
            return gem.strip(), version.strip()

        return package_spec.strip(), "unknown"

    @staticmethod
    def _parse_nuget_format(package_spec: str) -> Tuple[str, str]:
        """Parse NuGet package.version format."""
        parts = package_spec.rsplit(".", 1)
        if len(parts) == 2:
            package, version = parts
            # Simple heuristic: if last part looks like version, split there
            if re.match(r"^\d+", version):
                return package.strip(), version.strip()

        return package_spec.strip(), "unknown"

    @staticmethod
    def _parse_packagist_format(package_spec: str) -> Tuple[str, str]:
        """Parse Packagist vendor/package:version format."""
        if ":" in package_spec:
            parts = package_spec.rsplit(":", 1)
            return parts[0].strip(), parts[1].strip()

        return package_spec.strip(), "unknown"

    @staticmethod
    def _parse_default_format(package_spec: str) -> Tuple[str, str]:
        """Default parsing for unknown ecosystems."""
        # Try common patterns
        for pattern in PackageKeyFormatter.PATTERNS.values():
            match = pattern.match(package_spec.strip())
            if match:
                return match.groups()

        # No pattern matched
        return package_spec.strip(), "unknown"

    @staticmethod
    def _clean_package_name(package: str, ecosystem: str) -> str:
        """Clean package name from any version information."""
        # Remove common version patterns, but be careful with npm scoped packages
        if ecosystem in ["npm", "javascript", "node"]:
            # For npm, only remove @version if it's not a scoped package
            # Scoped packages start with @scope/ so we need to preserve those
            if package.startswith("@") and "/" in package:
                # This is a scoped package like @alloc/quick-lru
                # Only remove @version pattern if there's no slash
                pass  # Keep the full scoped package name
            else:
                # Regular package, safe to remove @version
                package = re.sub(r"@[^/]+$", "", package)
        else:
            # For other ecosystems, remove @version patterns
            package = re.sub(r"@.*$", "", package)

        package = re.sub(r"==.*$", "", package)    # Remove ==version
        package = re.sub(r"\s+\(.*\)$", "", package)  # Remove (version)

        return package.strip()

    @staticmethod
    def _clean_version(version: str) -> str:
        """Clean and normalize version string."""
        # Remove common prefixes
        version = version.lstrip("v")
        version = version.strip()

        # Remove version range operators if present
        version = re.sub(r"^[><=~^!]+", "", version)

        return version.strip() or "unknown"

    @staticmethod
    def create_batch_key(packages: list, ecosystem: str) -> str:
        """
        Create a cache key for batch operations.

        Args:
            packages: List of package names or (name, version) tuples
            ecosystem: Package ecosystem

        Returns:
            Hash-based cache key for the batch
        """
        # Create deterministic key from sorted package list
        if packages and isinstance(packages[0], tuple):
            # List of (name, version) tuples
            sorted_packages = sorted(packages)
            key_parts = [f"{name}=={version}" for name, version in sorted_packages]
        else:
            # List of package names
            key_parts = sorted(packages)

        key_string = f"batch:{ecosystem}:" + ",".join(key_parts)

        # Use hash for long keys
        if len(key_string) > 200:
            import hashlib
            return f"batch:{ecosystem}:" + hashlib.sha256(key_string.encode()).hexdigest()

        return key_string