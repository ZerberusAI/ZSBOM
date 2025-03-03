def classify_dependencies(dependencies):
    classified = {}
    for source, deps in dependencies.items():
        classified[source] = {dep: "third-party" for dep in deps}  # Placeholder classification
    return classified