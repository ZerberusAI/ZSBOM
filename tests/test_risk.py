import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import depclass.risk as risk
from depclass.risk_model import RiskModel


def test_compute_package_score_high():
    pkg = 'foo'
    res = risk.compute_package_score(
        package=pkg,
        installed_version='1.0',
        declared_version='0.9',
        cve_list=[{'package_name': pkg, 'vuln_id': 'CVE-1', 'cwes': ['CWE-79']}],
        typos=['foo'],
        repo_path=None,
        model=RiskModel()
    )
    assert res['risk'] == 'high'
    assert res['score'] >= 6


def test_parse_declared_versions():
    deps = {
        'requirements.txt': ['foo==1.2'],
        'pyproject.toml': {'bar': '2.0'}
    }
    versions = risk.parse_declared_versions(deps)
    assert versions['foo'] == '1.2'
    assert versions['bar'] == '2.0'
