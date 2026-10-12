"""Test suite for xBOUNDARY Wave 2 source-security rules:

- xbnd.unsafe-deserialization (CWE-502)
- xbnd.ssrf (CWE-918)
"""

from __future__ import annotations

from pathlib import Path

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers


def scan(tmp_path: Path, source: str):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return run_providers(AnalysisTask(tmp_path), [XBoundaryProvider()]).report()


# ==============================================================================
# 1. Unsafe Deserialization Tests (CWE-502)
# ==============================================================================


def test_pickle_loads_with_input_detected(tmp_path: Path):
    source = "import pickle\npayload = input()\ndata = pickle.loads(payload)\n"
    report = scan(tmp_path, source)
    assert report.scan_status == "complete"
    assert len(report.findings_unified) == 1
    finding = report.findings_unified[0]
    assert finding.rule_id == "xbnd.unsafe-deserialization"
    assert finding.cwe == ["CWE-502"]
    assert finding.owasp == ["A08:2025"]
    assert finding.severity == "critical"


def test_yaml_load_untrusted_detected(tmp_path: Path):
    source = "import yaml\nfrom flask import request\nraw = request.args['data']\nparsed = yaml.load(raw)\n"
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].rule_id == "xbnd.unsafe-deserialization"


def test_marshal_loads_detected(tmp_path: Path):
    source = "import marshal\nstream = input()\nmarshal.loads(stream)\n"
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].rule_id == "xbnd.unsafe-deserialization"


def test_yaml_safe_load_sanitizes(tmp_path: Path):
    source = "import yaml\npayload = input()\ndata = yaml.safe_load(payload)\n"
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_yaml_load_with_safe_loader_kw_sanitizes(tmp_path: Path):
    source = "import yaml\npayload = input()\ndata = yaml.load(payload, Loader=yaml.SafeLoader)\n"
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_json_loads_sanitizes(tmp_path: Path):
    source = "import json\npayload = input()\ndata = json.loads(payload)\n"
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_deserialization_suppression(tmp_path: Path):
    source = "import pickle\npickle.loads(input())  # plex: ignore[xbnd.unsafe-deserialization]\n"
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


# ==============================================================================
# 2. Server-Side Request Forgery (SSRF) Tests (CWE-918)
# ==============================================================================


def test_urlopen_with_input_detected(tmp_path: Path):
    source = (
        "import urllib.request\n"
        "target = input()\n"
        "resp = urllib.request.urlopen(target)\n"
    )
    report = scan(tmp_path, source)
    assert report.scan_status == "complete"
    assert len(report.findings_unified) == 1
    finding = report.findings_unified[0]
    assert finding.rule_id == "xbnd.ssrf"
    assert finding.cwe == ["CWE-918"]
    assert finding.owasp == ["A10:2025"]
    assert finding.severity == "high"


def test_requests_get_with_flask_request_detected(tmp_path: Path):
    source = (
        "import requests\n"
        "from flask import request\n"
        "endpoint = request.args['url']\n"
        "res = requests.get(endpoint)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].rule_id == "xbnd.ssrf"


def test_requests_post_detected(tmp_path: Path):
    source = (
        "import requests\n"
        "target = input()\n"
        "requests.post(target, json={'data': 1})\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].rule_id == "xbnd.ssrf"


def test_requests_request_method_second_arg_detected(tmp_path: Path):
    source = (
        "import requests\n"
        "target = input()\n"
        "requests.request('GET', target)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].rule_id == "xbnd.ssrf"


def test_httpx_get_detected(tmp_path: Path):
    source = (
        "import httpx\n"
        "url = input()\n"
        "httpx.get(url)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].rule_id == "xbnd.ssrf"


def test_requests_get_kwarg_url_detected(tmp_path: Path):
    source = (
        "import requests\n"
        "target = input()\n"
        "requests.get(url=target)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 1
    assert report.findings_unified[0].rule_id == "xbnd.ssrf"


def test_constant_url_is_clean(tmp_path: Path):
    source = (
        "import requests\n"
        "res = requests.get('https://api.github.com/zen')\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_url_sanitizer_cleans_ssrf(tmp_path: Path):
    source = (
        "import requests\n"
        "def validate_url(u):\n"
        "    return 'https://trusted.local'\n"
        "target = input()\n"
        "safe = validate_url(target)\n"
        "requests.get(safe)\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0


def test_ssrf_suppression(tmp_path: Path):
    source = (
        "import requests\n"
        "requests.get(input())  # plex: ignore[xbnd.ssrf]\n"
    )
    report = scan(tmp_path, source)
    assert len(report.findings_unified) == 0
