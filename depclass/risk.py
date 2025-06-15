"""Risk scoring utilities for ZSBOM."""

from __future__ import annotations

import importlib.metadata
import os
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .risk_model import RiskModel


def parse_declared_versions(dependencies: Dict[str, Any]) -> Dict[str, str]:
    """Extract a mapping of package name to declared version."""
    versions: Dict[str, str] = {}

    reqs = dependencies.get("requirements.txt", [])
    for line in reqs:
        if "==" in line:
            name, version = line.split("==", 1)
            versions[name.lower()] = version.strip()

    pyproject = dependencies.get("pyproject.toml", {})
    if isinstance(pyproject, dict):
        for name, value in pyproject.items():
            if isinstance(value, str):
                versions[name.lower()] = value
            elif isinstance(value, dict) and "version" in value:
                versions[name.lower()] = value["version"]

    return versions


def _package_cve_issues(package: str, cve_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [cve for cve in cve_list if cve.get("package_name") == package]


def _get_distribution_path(package: str) -> Optional[str]:
    try:
        dist = importlib.metadata.distribution(package)
        path = str(dist.locate_file(""))
        if os.path.isdir(os.path.join(path, ".git")):
            return path
    except importlib.metadata.PackageNotFoundError:
        pass
    return None


def _last_commit_date(repo_path: str) -> Optional[datetime]:
    for branch in ("main", "master"):
        try:
            ts = (
                subprocess.check_output(
                    ["git", "-C", repo_path, "log", branch, "-1", "--format=%ct"],
                    text=True,
                )
                .strip()
            )
            if ts:
                return datetime.fromtimestamp(int(ts), timezone.utc)
        except subprocess.CalledProcessError:
            continue
    return None


def _abandonment_score(repo_path: Optional[str], model: RiskModel) -> tuple[int, Optional[int]]:
    if not repo_path:
        return 0, None
    last = _last_commit_date(repo_path)
    if not last:
        return 0, None
    days = (datetime.now(timezone.utc) - last).days
    if days > 730:
        return model.weight_abandonment * 2, days
    if days > 365:
        return model.weight_abandonment, days
    return 0, days


def compute_package_score(
    package: str,
    installed_version: str,
    declared_version: str | None,
    cve_list: List[Dict[str, Any]],
    typos: List[str],
    repo_path: Optional[str] = None,
    model: Optional[RiskModel] = None,
) -> Dict[str, Any]:
    """Compute a risk score for a package using the provided model."""
    if model is None:
        model = RiskModel()

    score = 0
    details: Dict[str, Any] = {}

    if declared_version and installed_version != declared_version:
        score += model.weight_version_mismatch
        details["version_mismatch"] = {
            "declared": declared_version,
            "installed": installed_version,
        }

    if cve_list:
        score += model.weight_cve
        details["cves"] = [c.get("vuln_id") for c in cve_list]
        if any(c.get("cwes") for c in cve_list):
            score += model.weight_cwe

    ab_score, days = _abandonment_score(repo_path, model)
    if ab_score:
        score += ab_score
        details["abandoned"] = True
        if days is not None:
            details["last_activity_days"] = days

    if package in typos:
        score += model.weight_typosquat
        details["typosquatting"] = True

    if score >= model.high_threshold:
        risk = "high"
    elif score >= model.medium_threshold:
        risk = "medium"
    else:
        risk = "low"

    return {
        "package": package,
        "installed_version": installed_version,
        "declared_version": declared_version,
        "score": score,
        "risk": risk,
        "details": details,
    }


def score_packages(
    validation_results: Dict[str, Any],
    declared_versions: Dict[str, str],
    installed_packages: Dict[str, str],
    model: Optional[RiskModel] = None,
) -> List[Dict[str, Any]]:
    """Return risk scores for all installed packages."""
    if model is None:
        model = RiskModel()

    scores = []
    cve_data = validation_results.get("cve_issues", [])
    typos = validation_results.get("typosquatting_issues", [])

    for pkg, inst_ver in installed_packages.items():
        dec_ver = declared_versions.get(pkg)
        cves = _package_cve_issues(pkg, cve_data)
        repo_path = _get_distribution_path(pkg)
        scores.append(
            compute_package_score(
                pkg, inst_ver, dec_ver, cves, typos, repo_path, model
            )
        )

    return scores
