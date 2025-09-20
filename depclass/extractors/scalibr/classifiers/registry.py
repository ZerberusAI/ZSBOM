"""
Classifier registry for ecosystem-specific dependency classification.

Provides a simple factory pattern for getting the appropriate classifier
for each ecosystem.
"""

from typing import Optional

from .base import BaseDependencyClassifier
from .npm import NPMDependencyClassifier


# Registry mapping ecosystem names to classifier classes
# Following YAGNI: Only NPM for now, easy to extend for Java, Go, etc.
DEPENDENCY_CLASSIFIERS = {
    "npm": NPMDependencyClassifier,
    # Future ecosystems:
    # "java": JavaDependencyClassifier,
    # "go": GoDependencyClassifier,
    # "python": PythonDependencyClassifier,  # If needed in future
}


def get_classifier(ecosystem: str) -> Optional[BaseDependencyClassifier]:
    """
    Get a dependency classifier for the specified ecosystem.

    Args:
        ecosystem: Name of the ecosystem (e.g., "npm", "java", "go")

    Returns:
        Classifier instance if available for ecosystem, None otherwise
    """
    classifier_class = DEPENDENCY_CLASSIFIERS.get(ecosystem)
    return classifier_class() if classifier_class else None