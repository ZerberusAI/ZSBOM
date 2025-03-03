import os
import toml
import pkg_resources
def extract_dependencies():
    dependencies = {}
    if os.path.exists("requirements.txt"):
        with open("requirements.txt") as f:
            dependencies["requirements.txt"] = [line.strip() for line in f if line.strip()]
    if os.path.exists("pyproject.toml"):
        pyproject = toml.load("pyproject.toml")
        dependencies["pyproject.toml"] = pyproject.get("tool", {}).get("poetry", {}).get("dependencies", {})
    dependencies["runtime"] = [str(pkg) for pkg in pkg_resources.working_set]
    return dependencies
if __name__ == "__main__":
    print(extract_dependencies())