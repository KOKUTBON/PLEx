from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


class TestCLIAnalyze:
    def _setup_repo(self, path: Path) -> Path:
        src = path / "src"
        src.mkdir(parents=True)
        (path / ".plex.yml").write_text("include: ['src']")

        (src / "good.py").write_text("def f(xs):\n    return sum(xs)\n")

        (src / "db.py").write_text(
            "class User:\n    objects = None\n\n"
            "def f(items):\n"
            "    for item in items:\n"
            "        User.objects.filter(id=item)\n"
        )

        (src / "concat.py").write_text(
            "def g(items):\n"
            "    s = ''\n"
            "    for item in items:\n"
            "        s += str(item)\n"
            "    return s\n"
        )

        return path

    def test_analyze_json_output(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        out_file = tmp_path / "out" / "report.json"

        res = subprocess.run(
            [sys.executable, "-m", "plex", "analyze", "--json", str(out_file)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode in (0, 1)
        assert out_file.exists()

        data = json.loads(out_file.read_text())
        assert "schema_version" in data
        assert "findings" in data
        assert "regressions" in data
        assert "stats" in data

    def test_analyze_sarif_output(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        out_file = tmp_path / "out" / "report.sarif.json"

        res = subprocess.run(
            [sys.executable, "-m", "plex", "analyze", "--sarif", str(out_file)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode in (0, 1)
        assert out_file.exists()

        data = json.loads(out_file.read_text())
        assert "$schema" in data
        assert "runs" in data

    def test_analyze_html_output(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        out_file = tmp_path / "out" / "report.html"

        res = subprocess.run(
            [sys.executable, "-m", "plex", "analyze", "--html", str(out_file)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode in (0, 1)
        assert out_file.exists()
        content = out_file.read_text()
        assert "<html" in content.lower()
        assert "PLEx" in content

    def test_analyze_md_path(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        out_file = tmp_path / "out" / "report.md"

        res = subprocess.run(
            [sys.executable, "-m", "plex", "analyze", "--md", str(out_file)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode in (0, 1)
        assert out_file.exists()
        assert out_file.stat().st_size > 0

    def test_analyze_multiple_outputs(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        out_dir = tmp_path / "out"
        json_file = out_dir / "report.json"
        sarif_file = out_dir / "report.sarif.json"
        html_file = out_dir / "report.html"

        res = subprocess.run(
            [
                sys.executable,
                "-m",
                "plex",
                "analyze",
                "--json",
                str(json_file),
                "--sarif",
                str(sarif_file),
                "--html",
                str(html_file),
            ],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode in (0, 1)
        assert json_file.exists()
        assert sarif_file.exists()
        assert html_file.exists()

    def test_analyze_gating_max_findings(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        res = subprocess.run(
            [sys.executable, "-m", "plex", "analyze", "--max-findings", "0"],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 1

    def test_analyze_gating_max_findings_passes(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        res = subprocess.run(
            [sys.executable, "-m", "plex", "analyze", "--max-findings", "100"],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0

    def test_analyze_language_filter(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        (tmp_path / "src" / "test.js").write_text("console.log('js');")

        out_file = tmp_path / "out.json"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "plex",
                "analyze",
                "--language",
                "python",
                "--json",
                str(out_file),
            ],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        if out_file.exists():
            data = json.loads(out_file.read_text())
            for finding in data.get("findings", []):
                assert not finding.get("file", "").endswith(".js")

    def test_analyze_min_confidence(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        subprocess.run(
            [sys.executable, "-m", "plex", "analyze", "--min-confidence", "1.0"],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )

    def test_analyze_rules_disabled(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        out_file = tmp_path / "out.json"
        res = subprocess.run(
            [sys.executable, "-m", "plex", "analyze", "--no-rules", "--json", str(out_file)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        # --no-rules means no rule findings (rule_id should be empty on all findings)
        data = json.loads(out_file.read_text())
        for finding in data.get("findings", []):
            assert finding.get("rule_id", "") == ""

    def test_analyze_specific_rule(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        out_file = tmp_path / "out.json"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "plex",
                "analyze",
                "--rule",
                "plex.db-in-loop",
                "--json",
                str(out_file),
            ],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        if out_file.exists():
            data = json.loads(out_file.read_text())
            rule_findings = [f for f in data.get("findings", []) if f.get("rule_id")]
            for finding in rule_findings:
                assert finding["rule_id"] == "plex.db-in-loop"

    def test_analyze_disable_specific_rule(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        out_file = tmp_path / "out.json"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "plex",
                "analyze",
                "--disable-rule",
                "plex.db-in-loop",
                "--json",
                str(out_file),
            ],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        if out_file.exists():
            data = json.loads(out_file.read_text())
            for finding in data.get("findings", []):
                assert finding.get("rule_id") != "plex.db-in-loop"

    def test_analyze_empty_repo(self, tmp_path: Path) -> None:
        (tmp_path / ".plex.yml").write_text("include: []")
        res = subprocess.run(
            [sys.executable, "-m", "plex", "analyze"],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0

    def test_analyze_stability_filters(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        # Add an experimental rule violation (json-in-loop)
        (tmp_path / "src" / "exp.py").write_text(
            "import json\ndef h(items):\n    for item in items:\n        json.dumps(item)\n"
        )
        out_stable = tmp_path / "out_stable.json"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "plex",
                "analyze",
                "--stability",
                "stable",
                "--json",
                str(out_stable),
            ],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert out_stable.exists()
        stable_data = json.loads(out_stable.read_text())
        stable_rule_ids = {
            f["rule_id"] for f in stable_data.get("findings", []) if f.get("rule_id")
        }
        assert "plex.db-in-loop" in stable_rule_ids
        assert "plex.json-in-loop" not in stable_rule_ids

        out_exp = tmp_path / "out_exp.json"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "plex",
                "analyze",
                "--stability",
                "experimental",
                "--json",
                str(out_exp),
            ],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert out_exp.exists()
        exp_data = json.loads(out_exp.read_text())
        exp_rule_ids = {f["rule_id"] for f in exp_data.get("findings", []) if f.get("rule_id")}
        assert "plex.json-in-loop" in exp_rule_ids
        assert "plex.db-in-loop" not in exp_rule_ids

    def test_analyze_config_stability(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        (tmp_path / ".plex.yml").write_text("include: ['src']\nrule_stability: 'stable'\n")
        (tmp_path / "src" / "exp.py").write_text(
            "import json\ndef h(items):\n    for item in items:\n        json.dumps(item)\n"
        )
        out_cfg = tmp_path / "out_cfg.json"
        subprocess.run(
            [sys.executable, "-m", "plex", "analyze", "--json", str(out_cfg)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert out_cfg.exists()
        data = json.loads(out_cfg.read_text())
        rule_ids = {f["rule_id"] for f in data.get("findings", []) if f.get("rule_id")}
        assert "plex.db-in-loop" in rule_ids
        assert "plex.json-in-loop" not in rule_ids

    def test_analyze_checks_default_is_performance(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        out_file = tmp_path / "out.json"
        res = subprocess.run(
            [sys.executable, "-m", "plex", "analyze", "--json", str(out_file)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        engines = [e["engine"] for e in data.get("engines", [])]
        assert engines == ["performance"]

    def test_analyze_checks_performance_explicit(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        out_file = tmp_path / "out.json"
        res = subprocess.run(
            [
                sys.executable,
                "-m",
                "plex",
                "analyze",
                "--checks",
                "performance",
                "--json",
                str(out_file),
            ],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        engines = [e["engine"] for e in data.get("engines", [])]
        assert engines == ["performance"]

    def test_analyze_checks_security_only(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir(parents=True)
        (src / "app.py").write_text(
            "import os\ndef run(cmd):\n    os.system(cmd)\n\ndef view():\n    run(input())\n"
        )
        out_file = tmp_path / "out.json"
        res = subprocess.run(
            [
                sys.executable,
                "-m",
                "plex",
                "analyze",
                "--checks",
                "security",
                "--json",
                str(out_file),
            ],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        engines = [e["engine"] for e in data.get("engines", [])]
        assert engines == ["xboundary"]
        categories = {f.get("category") for f in data.get("findings_unified", [])}
        assert "security" in categories

    def test_analyze_checks_multi_engine(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        (tmp_path / "src" / "sec.py").write_text(
            "import os\ndef handle(val):\n    os.system(input())\n"
        )
        out_json = tmp_path / "out.json"
        out_sarif = tmp_path / "out.sarif"
        res = subprocess.run(
            [
                sys.executable,
                "-m",
                "plex",
                "analyze",
                "--checks",
                "performance,security",
                "--json",
                str(out_json),
                "--sarif",
                str(out_sarif),
            ],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        assert out_json.exists()
        assert out_sarif.exists()

        data = json.loads(out_json.read_text())
        engines = [e["engine"] for e in data.get("engines", [])]
        assert "performance" in engines
        assert "xboundary" in engines
        categories = {f.get("category") for f in data.get("findings_unified", [])}
        assert "performance" in categories
        assert "security" in categories

        sarif_data = json.loads(out_sarif.read_text())
        assert sarif_data.get("runs")
        all_rules = {r.get("ruleId") for run in sarif_data["runs"] for r in run.get("results", [])}
        assert any("xbnd" in str(r) for r in all_rules)

    def test_analyze_checks_invalid_engine(self, tmp_path: Path) -> None:
        self._setup_repo(tmp_path)
        res = subprocess.run(
            [sys.executable, "-m", "plex", "analyze", "--checks", "performance,invalid_engine"],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 1
        assert "Unknown check engine" in res.stderr

    def test_analyze_checks_severity_gate(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir(parents=True)
        (src / "app.py").write_text("import os\nos.system(input())\n")
        res_fail = subprocess.run(
            [
                sys.executable,
                "-m",
                "plex",
                "analyze",
                "--checks",
                "security",
                "--fail-on-severity",
                "high",
            ],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_fail.returncode == 1

        res_pass = subprocess.run(
            [
                sys.executable,
                "-m",
                "plex",
                "analyze",
                "--checks",
                "security",
                "--fail-on-severity",
                "critical",
            ],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_pass.returncode == 0

    def test_analyze_checks_legacy_schema_rejects_security(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir(parents=True)
        (src / "app.py").write_text("import os\nos.system(input())\n")
        out_json = tmp_path / "out.json"
        res = subprocess.run(
            [
                sys.executable,
                "-m",
                "plex",
                "analyze",
                "--checks",
                "security",
                "--legacy-schema",
                "7",
                "--json",
                str(out_json),
            ],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 1
        assert "Cannot export report as v7" in res.stderr
