"""When the Scalibr library can't be loaded or built, the scan must fail
loudly instead of reporting "No supported ecosystems detected" (which made
the CI job pass green while scanning nothing)."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from depclass.extract import extract
from depclass.extractors.scalibr import wrapper
from depclass.extractors.scalibr.wrapper import ScalibrUnavailableError


@pytest.fixture
def npm_project(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo", "dependencies": {"lodash": "4.17.20"}})
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"name": "demo", "lockfileVersion": 3, "packages": {}})
    )
    return tmp_path


def test_an_unavailable_extractor_is_an_error_not_no_ecosystems(npm_project):
    with patch(
        "depclass.extractors.scalibr.extractor.ScalibrWrapper",
        side_effect=ScalibrUnavailableError("build failed"),
    ):
        with pytest.raises(ScalibrUnavailableError):
            extract(project_path=str(npm_project))


def test_other_scalibr_errors_still_degrade_to_no_ecosystems(npm_project):
    with patch(
        "depclass.extractors.scalibr.extractor.ScalibrWrapper"
    ) as scalibr:
        scalibr.return_value.scan.side_effect = RuntimeError("bad output")
        result = extract(project_path=str(npm_project))
    assert result["dependencies_analysis"]["unsupported_repo"] is True


def test_a_failed_build_raises_scalibr_unavailable(tmp_path):
    with (
        patch.object(wrapper, "Path") as path_cls,
        patch.object(wrapper, "try_build_library", return_value=False),
    ):
        path_cls.return_value.parent = tmp_path
        with pytest.raises(ScalibrUnavailableError):
            wrapper.load_scalibr_library()


def test_the_build_log_shows_the_end_of_the_compiler_output(tmp_path, capsys):
    (tmp_path / "build.py").write_text("")
    noise = "go: downloading example.com/module v1.0.0\n" * 50
    error = "oci/spec_opts.go:1527:34: cannot use limit as *int64 value"
    failed = SimpleNamespace(returncode=1, stdout=noise + error, stderr="")
    with patch.object(wrapper.subprocess, "run", return_value=failed):
        assert wrapper.try_build_library(Path(tmp_path)) is False
    assert error in capsys.readouterr().out
