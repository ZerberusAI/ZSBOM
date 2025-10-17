"""
Shared constants for enhancer providers.

This module contains common constants used across multiple enhancer providers
to avoid duplication and ensure consistency.
"""

# Ecosystem mapping for OSV.dev API
# Maps internal ecosystem names to OSV.dev ecosystem identifiers
OSV_ECOSYSTEM_MAPPING = {
    "python": "PyPI",
    "pypi": "PyPI",
    "npm": "npm",
    "javascript": "npm",
    "node": "npm",
    "go": "Go",
    "golang": "Go",
    "maven": "Maven",
    "gradle": "Maven",
    "java": "Maven",
    "cargo": "crates.io",
    "rust": "crates.io",
    "crates.io": "crates.io",
    "rubygems": "RubyGems",
    "ruby": "RubyGems",
    "nuget": "NuGet",
    "dotnet": "NuGet",
    "csharp": "NuGet",
    "packagist": "Packagist",
    "php": "Packagist",
}

# Ecosystem mapping for deps.dev API
# Maps internal ecosystem names to deps.dev system identifiers
DEPSDEV_ECOSYSTEM_MAPPING = {
    "python": "PYPI",
    "pypi": "PYPI",
    "npm": "NPM",
    "javascript": "NPM",
    "node": "NPM",
    "go": "GO",
    "golang": "GO",
    "maven": "MAVEN",
    "gradle": "MAVEN",
    "java": "MAVEN",
    "cargo": "CARGO",
    "rust": "CARGO",
    "crates.io": "CARGO",
    "rubygems": "RUBYGEMS",
    "ruby": "RUBYGEMS",
    "nuget": "NUGET",
    "dotnet": "NUGET",
    "csharp": "NUGET",
}
