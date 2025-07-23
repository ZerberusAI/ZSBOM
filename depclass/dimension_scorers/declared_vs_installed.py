"""Declared vs Installed version dimension scorer implementing ZSBOM requirements."""

import re
from typing import Any, Dict, Optional, List, Union
from pathlib import Path

from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier

from .base import DimensionScorer


class DeclaredVsInstalledScorer(DimensionScorer):
    """Scores packages based on declared vs installed version consistency.
    
    Implements the 3-factor scoring system from ZSBOM requirements:
    1. Version Match Precision Analysis (4 points)
    2. Specification Completeness Analysis (3 points)  
    3. Cross-File Consistency Analysis (3 points)
    
    Total: 10 points (0 = highest risk, 10 = lowest risk)
    """

    def __init__(self):
        """Initialize the scorer."""
        self.file_priority = [
            "pyproject.toml",
            "requirements.txt",
            "setup.py",
            "setup.cfg",
            "Pipfile"
        ]

    def score(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        **kwargs: Any
    ) -> float:
        """Calculate version consistency score using 3-factor system.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            **kwargs: Additional data including dependency_files, package_specs
            
        Returns:
            Score between 0.0 (highest risk) and 10.0 (lowest risk)
        """
        # Get additional data from kwargs
        dependency_files = kwargs.get('dependency_files', {})
        package_specs = kwargs.get('package_specs', {})
        dependency_tree = kwargs.get('dependency_tree', {})
        classification = kwargs.get('classification', {})
        
        # Resolve effective declared version for transitive dependencies
        effective_declared_version = self._resolve_effective_declared_version(
            package, declared_version, dependency_tree, classification
        )
        
        # If no additional data, use effective declared_version
        if not dependency_files and not package_specs:
            package_specs = {package: {"declared": effective_declared_version}} if effective_declared_version else {}
        
        # Factor 1: Version Match Precision (4 points)
        precision_score = self._calculate_version_match_precision(
            package, installed_version, effective_declared_version, package_specs
        )
        
        # Factor 2: Specification Completeness (3 points)
        completeness_score = self._calculate_specification_completeness(
            package, effective_declared_version, package_specs
        )
        
        # Factor 3: Cross-File Consistency (3 points)
        consistency_score = self._calculate_cross_file_consistency(
            package, package_specs
        )
        
        # Total score (0-10)
        total_score = precision_score + completeness_score + consistency_score
        
        return self.validate_score(total_score)

    def get_details(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """Get detailed scoring information.
        
        Args:
            package: Package name
            installed_version: Currently installed version
            declared_version: Version declared in requirements
            **kwargs: Additional data
            
        Returns:
            Dictionary containing scoring details
        """
        # Get additional data from kwargs
        dependency_files = kwargs.get('dependency_files', {})
        package_specs = kwargs.get('package_specs', {})
        dependency_tree = kwargs.get('dependency_tree', {})
        classification = kwargs.get('classification', {})
        
        # Resolve effective declared version for transitive dependencies
        effective_declared_version = self._resolve_effective_declared_version(
            package, declared_version, dependency_tree, classification
        )
        
        # If no additional data, use effective declared_version
        if not dependency_files and not package_specs:
            package_specs = {package: {"declared": effective_declared_version}} if effective_declared_version else {}
        
        # Calculate individual factor scores
        precision_score = self._calculate_version_match_precision(
            package, installed_version, effective_declared_version, package_specs
        )
        completeness_score = self._calculate_specification_completeness(
            package, effective_declared_version, package_specs
        )
        consistency_score = self._calculate_cross_file_consistency(
            package, package_specs
        )
        
        total_score = precision_score + completeness_score + consistency_score
        
        # Get match status
        match_status = self._get_match_status(installed_version, effective_declared_version)
        
        # Get specification quality
        spec_quality = self._get_specification_quality(effective_declared_version)
        
        # Get consistency status
        consistency_status = self._get_consistency_status(package, package_specs)
        
        # Get files where package is found
        files_found = self._get_files_found(package, package_specs)
        
        return {
            "dimension": "declared_vs_installed",
            "score": self.validate_score(total_score),
            "factors": {
                "version_match_precision": precision_score,
                "specification_completeness": completeness_score,
                "cross_file_consistency": consistency_score
            },
            "package_details": {
                "package": package,
                "declared_version": effective_declared_version,
                "installed_version": installed_version,
                "match_status": match_status,
                "files_found": files_found
            },
            "details": {
                "match_status": match_status,
                "specification_quality": spec_quality,
                "consistency_status": consistency_status,
                "files_found": files_found
            }
        }

    def _calculate_version_match_precision(
        self,
        package: str,
        installed_version: str,
        declared_version: Optional[str],
        package_specs: Dict[str, Any]
    ) -> float:
        """Calculate Version Match Precision score (0-4 points).
        
        Scoring logic:
        - Exact match (requests==2.28.0 declared, 2.28.0 installed) = 4 pts
        - Range satisfied (requests>=2.0.0,<3.0.0 declared, 2.28.0 installed) = 3 pts
        - Range violated (requests>=2.0.0,<2.25.0 declared, 2.28.0 installed) = 1 pt
        - Unspecified (requests declared, 2.28.0 installed) = 0 pts
        """
        if not declared_version:
            return 0.0  # Unspecified
        
        try:
            installed_ver = Version(installed_version)
        except InvalidVersion:
            return 0.0  # Invalid installed version
        
        # Convert Poetry-style constraints to standard format
        normalized_spec = self._normalize_version_spec(declared_version)
        
        # Handle version constraints first
        try:
            spec_set = SpecifierSet(normalized_spec)
            if installed_ver in spec_set:
                # Check if it's an exact match constraint
                if normalized_spec.startswith('==') and normalized_spec[2:].strip() == installed_version:
                    return 4.0  # Exact match
                else:
                    return 3.0  # Range satisfied
            else:
                return 1.0  # Range violated
                
        except InvalidSpecifier:
            # Handle simple string equality for non-constraint formats
            if declared_version == installed_version:
                return 4.0  # Exact match
            return 0.0  # Unspecified/invalid
    
    def _calculate_specification_completeness(
        self,
        package: str,
        declared_version: Optional[str],
        package_specs: Dict[str, Any]
    ) -> float:
        """Calculate Specification Completeness score (0-3 points).
        
        Scoring logic:
        - Fully pinned (requests==2.28.0) = 3 pts
        - Bounded range (requests>=2.0.0,<3.0.0) = 2 pts
        - Minimum only (requests>=2.0.0) = 1 pt
        - No constraint (requests) = 0 pts
        """
        if not declared_version:
            return 0.0  # No constraint
        
        # Clean and normalize the version spec
        spec = declared_version.strip()
        normalized_spec = self._normalize_version_spec(spec)
        
        # Fully pinned (exact version)
        if spec.startswith('==') or re.match(r'^\d+\.\d+\.\d+$', spec):
            return 3.0
        
        # Check for bounded range (both upper and lower bounds)
        if ('>' in normalized_spec or '>=' in normalized_spec) and ('<' in normalized_spec or '<=' in normalized_spec):
            return 2.0
        
        # Check for minimum only
        if normalized_spec.startswith('>=') or normalized_spec.startswith('>'):
            return 1.0
        
        # Check for Poetry-style constraints (now converted to bounded ranges)
        if spec.startswith('^') or spec.startswith('~'):
            return 2.0  # These are effectively bounded ranges
        
        # No meaningful constraint
        return 0.0
    
    def _calculate_cross_file_consistency(
        self,
        package: str,
        package_specs: Dict[str, Any]
    ) -> float:
        """Calculate Cross-File Consistency score (0-3 points).
        
        Scoring logic:
        - Consistent across all files = 3 pts
        - Minor conflicts (different but compatible ranges) = 1 pt
        - Major conflicts (incompatible specifications) = 0 pts
        """
        # Get all specifications for this package across files
        specs = []
        for file_name in self.file_priority:
            if file_name in package_specs and package in package_specs[file_name]:
                spec = package_specs[file_name][package]
                if spec:  # Only add non-empty specs
                    specs.append(spec)
        
        # If only one or no specs, consider it consistent
        if len(specs) <= 1:
            return 3.0
        
        # Check if all specs are identical
        if len(set(specs)) == 1:
            return 3.0  # All identical
        
        # Check for compatibility between different specs
        try:
            # Try to create SpecifierSet for each spec and check compatibility
            spec_sets = []
            for spec in specs:
                try:
                    spec_sets.append(SpecifierSet(spec))
                except InvalidSpecifier:
                    # If can't parse, check for simple equality
                    if len(set(specs)) > 1:
                        return 0.0  # Different unparseable specs = major conflict
            
            # Check if there's any version that satisfies all specs
            if self._check_spec_compatibility(spec_sets):
                return 1.0  # Minor conflicts but compatible
            else:
                return 0.0  # Major conflicts
                
        except Exception:
            return 0.0  # Error in processing = major conflict
    
    def _check_spec_compatibility(self, spec_sets: List[SpecifierSet]) -> bool:
        """Check if multiple SpecifierSets are compatible using sampling approach.
        
        This method determines if there exists ANY version that satisfies ALL 
        the different version specifications simultaneously. Rather than doing
        complex mathematical intersection of version ranges, we use a pragmatic
        sampling approach.
        
        Algorithm:
        1. Test a representative sample of version numbers against all specs
        2. If any test version satisfies ALL specs → compatible
        3. If no test version satisfies ALL specs → incompatible
        
        Args:
            spec_sets: List of SpecifierSet objects to check for compatibility
            
        Returns:
            True if compatible, False if incompatible
            
        Examples:
            Compatible case:
                - Spec A: ">=2.0.0,<3.0.0" 
                - Spec B: ">=2.25.0"
                - Test version "2.25.0" satisfies both → Compatible
                
            Incompatible case:
                - Spec A: ">=2.0.0,<2.25.0"
                - Spec B: ">=2.28.0"
                - No test version satisfies both → Incompatible
                
            Edge case:
                - Spec A: ">=1.5.0,<2.0.0"
                - Spec B: ">=1.8.0,<1.9.0"
                - Narrow compatibility window exists but might be missed
        """
        if not spec_sets:
            return True
        
        # Strategic test versions covering common version boundaries
        # These values are chosen to detect most real-world compatibility issues
        test_versions = [
            "0.1.0",        # Early development versions
            "0.9.0",        # Pre-1.0 release candidates  
            "1.0.0",        # Major milestone - first stable release
            "1.1.0",        # Minor updates in v1
            "1.9.0",        # Late v1 versions
            "2.0.0",        # Major version 2 - breaking changes
            "2.1.0",        # Early v2 versions
            "2.9.0",        # Late v2 versions
            "3.0.0",        # Major version 3
            "10.0.0"        # Much later major version
        ]
        
        # Test each version against all specifications
        for version_str in test_versions:
            try:
                version = Version(version_str)
                # Check if this version satisfies ALL specs
                if all(version in spec_set for spec_set in spec_sets):
                    return True  # Found a compatible version
            except InvalidVersion:
                continue
        
        # No test version satisfied all specs
        return False
    
    def _get_match_status(self, installed_version: str, declared_version: Optional[str]) -> str:
        """Get match status string."""
        if not declared_version:
            return "unspecified"
        
        if declared_version == installed_version:
            return "exact_match"
        
        try:
            installed_ver = Version(installed_version)
            spec_set = SpecifierSet(declared_version)
            
            if installed_ver in spec_set:
                return "range_satisfied"
            else:
                return "range_violated"
                
        except (InvalidVersion, InvalidSpecifier):
            return "unspecified"
    
    def _get_specification_quality(self, declared_version: Optional[str]) -> str:
        """Get specification quality description."""
        if not declared_version:
            return "no_constraint"
        
        spec = declared_version.strip()
        
        if spec.startswith('==') or re.match(r'^\d+\.\d+\.\d+$', spec):
            return "fully_pinned"
        
        if ('>' in spec or '>=' in spec) and ('<' in spec or '<=' in spec):
            return "bounded_range"
        
        if spec.startswith('>=') or spec.startswith('>'):
            return "minimum_only"
        
        if spec.startswith('^') or spec.startswith('~'):
            return "bounded_range"
        
        return "no_constraint"
    
    def _get_consistency_status(self, package: str, package_specs: Dict[str, Any]) -> str:
        """Get consistency status across files."""
        specs = []
        for file_name in self.file_priority:
            if file_name in package_specs and package in package_specs[file_name]:
                spec = package_specs[file_name][package]
                if spec:
                    specs.append(spec)
        
        if len(specs) <= 1:
            return "consistent"
        
        if len(set(specs)) == 1:
            return "consistent"
        
        # Check for compatibility
        try:
            spec_sets = []
            for spec in specs:
                try:
                    spec_sets.append(SpecifierSet(spec))
                except InvalidSpecifier:
                    return "major_conflicts"
            
            if self._check_spec_compatibility(spec_sets):
                return "minor_conflicts"
            else:
                return "major_conflicts"
                
        except Exception:
            return "major_conflicts"
    
    def _get_files_found(self, package: str, package_specs: Dict[str, Any]) -> List[str]:
        """Get list of files where package is found."""
        files = []
        for file_name in self.file_priority:
            if file_name in package_specs and package in package_specs[file_name]:
                files.append(file_name)
        return files
    
    def _normalize_version_spec(self, spec: str) -> str:
        """Convert Poetry-style constraints to standard format."""
        if not spec:
            return spec
        
        spec = spec.strip()
        
        if spec.startswith("^"):
            # Caret constraint: ^1.2.3 means >=1.2.3,<2.0.0
            version = spec[1:]
            try:
                v = Version(version)
                return f">={version},<{v.major + 1}.0.0"
            except InvalidVersion:
                return spec
        elif spec.startswith("~"):
            # Tilde constraint: ~1.2.3 means >=1.2.3,<1.3.0
            version = spec[1:]
            try:
                v = Version(version)
                return f">={version},<{v.major}.{v.minor + 1}.0"
            except InvalidVersion:
                return spec
        else:
            # Standard constraint
            return spec
    
    def _resolve_effective_declared_version(
        self, 
        package: str, 
        declared_version: Optional[str], 
        dependency_tree: Dict[str, List[str]], 
        classification: Dict[str, str]
    ) -> Optional[str]:
        """Resolve effective declared version for transitive dependencies.
        
        For transitive dependencies, attempts to derive the effective version constraint
        from their parent dependencies' requirements.
        
        Args:
            package: Package name
            declared_version: Original declared version (None for transitive deps)
            dependency_tree: Maps package -> list of parent packages
            classification: Maps package -> "direct" or "transitive"
            
        Returns:
            Effective declared version or None if not resolvable
        """
        # If already has a declared version, use it (direct dependency)
        if declared_version is not None:
            return declared_version
        
        # Check if this is a transitive dependency
        package_type = classification.get(package, "unknown")
        if package_type != "transitive":
            return declared_version
        
        # Get parent packages for this transitive dependency
        parents = dependency_tree.get(package, [])
        if not parents:
            return declared_version
        
        # Try to resolve constraint from each parent
        effective_constraints = []
        
        for parent in parents:
            constraint = self._get_parent_constraint(parent, package)
            if constraint:
                effective_constraints.append(constraint)
        
        # If we found constraints, use the first one (could be enhanced to merge multiple)
        if effective_constraints:
            return effective_constraints[0]
        
        return declared_version
    
    def _get_parent_constraint(self, parent_package: str, child_package: str) -> Optional[str]:
        """Get the version constraint that parent_package places on child_package.
        
        Args:
            parent_package: Name of the parent package
            child_package: Name of the child package
            
        Returns:
            Version constraint string or None if not found
        """
        try:
            import importlib.metadata
            
            # Get metadata for the parent package
            dist = importlib.metadata.distribution(parent_package)
            
            # Look through its requirements for the child package
            if dist.requires:
                for req_str in dist.requires:
                    try:
                        from packaging.requirements import Requirement
                        req = Requirement(req_str)
                        
                        # Check if this requirement is for our child package
                        if req.name.lower() == child_package.lower():
                            # Return the specifier as a string
                            return str(req.specifier) if req.specifier else ""
                    except Exception:
                        # Skip malformed requirements
                        continue
        
        except Exception:
            # Package not found or other error - return None
            pass
        
        return None