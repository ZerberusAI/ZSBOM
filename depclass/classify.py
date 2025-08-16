"""Simple dependency classifier used in tests.

The classification logic is intentionally lightweight.  It accepts the Python
style mapping of ``{file_name: {package: version}}`` as well as the tuple form
returned by the NPM extractor ``(packages, metadata)``.
"""


def classify_dependencies(dependencies):
    classified = {}

    if isinstance(dependencies, tuple):
        packages, meta = dependencies
        source = meta.get("ecosystem", "unknown")
        classified[source] = {dep: "third-party" for dep in packages}
        return classified

    for source, deps in dependencies.items():
        classified[source] = {dep: "third-party" for dep in deps}

    return classified