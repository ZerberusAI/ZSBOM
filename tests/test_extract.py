import importlib
import pkg_resources
import sys
import types
import tomllib
from pathlib import Path


def test_extract_dependencies(tmp_path, monkeypatch):
    # Provide a stub 'toml' module using built-in tomllib
    toml_stub = types.ModuleType("toml")

    def load(filename):
        with open(filename, "rb") as f:
            return tomllib.load(f)

    toml_stub.load = load
    monkeypatch.setitem(sys.modules, "toml", toml_stub)

    # Ensure repository root is on sys.path
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    # Import after stubbing
    extract = importlib.import_module("depclass.extract")

    # Create temporary requirements.txt
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.25.1\nnumpy>=1.19.0\n")

    # Create temporary pyproject.toml
    pyproject_content = """
[tool.poetry.dependencies]
python = "^3.10"
flask = "^2.0"
"""
    pyproject_file = tmp_path / "pyproject.toml"
    pyproject_file.write_text(pyproject_content)

    monkeypatch.chdir(tmp_path)

    runtime_pkgs = ["flask 2.1.0", "requests 2.25.1"]
    monkeypatch.setattr(pkg_resources, "working_set", runtime_pkgs, raising=False)

    deps = extract.extract_dependencies()

    expected = {
        "requirements.txt": ["requests==2.25.1", "numpy>=1.19.0"],
        "pyproject.toml": {"python": "^3.10", "flask": "^2.0"},
        "runtime": runtime_pkgs,
    }

    assert deps == expected
