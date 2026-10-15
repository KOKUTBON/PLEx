"""CLI integration tests for ``plex fix`` command."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _run_cli(
    *args: str, cwd: Path | None = None, input: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "plex", *args],
        cwd=str(cwd) if cwd else None,
        input=input,
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestCliFix:
    def test_cli_fix_in_place(self, tmp_path: Path) -> None:
        file_path = tmp_path / "app.py"
        file_path.write_text(
            "def f(items):\n    s = ''\n    for x in items:\n        s += str(x)\n    return s\n",
            encoding="utf-8",
        )
        res = _run_cli("fix", str(file_path))
        assert res.returncode == 0
        assert "Fixed 1 file(s)" in res.stdout

        modified = file_path.read_text(encoding="utf-8")
        assert "s_chunks = []" in modified
        assert "s = ''.join(s_chunks)" in modified

    def test_cli_fix_dry_run_leaves_disk_untouched(self, tmp_path: Path) -> None:
        original = (
            "def f(items):\n    s = ''\n    for x in items:\n        s += str(x)\n    return s\n"
        )
        file_path = tmp_path / "app.py"
        file_path.write_text(original, encoding="utf-8")

        res = _run_cli("fix", "--dry-run", str(file_path))
        assert res.returncode == 0
        assert "Dry-run: 1 file(s) would be modified" in res.stdout
        assert file_path.read_text(encoding="utf-8") == original

    def test_cli_fix_check_mode(self, tmp_path: Path) -> None:
        # Dirty file should exit 1
        file_path = tmp_path / "app.py"
        file_path.write_text(
            "def f(items):\n    s = ''\n    for x in items:\n        s += str(x)\n    return s\n",
            encoding="utf-8",
        )
        res_fail = _run_cli("fix", "--check", str(file_path))
        assert res_fail.returncode == 1
        assert "Check failed" in res_fail.stdout

        # Clean file should exit 0
        clean_file = tmp_path / "clean.py"
        clean_file.write_text("def f(x):\n    return x * 2\n", encoding="utf-8")
        res_pass = _run_cli("fix", "--check", str(clean_file))
        assert res_pass.returncode == 0
        assert "No fixable PLEx violations found." in res_pass.stdout

    def test_cli_fix_diff_output(self, tmp_path: Path) -> None:
        file_path = tmp_path / "app.py"
        file_path.write_text(
            "def f(items):\n    s = ''\n    for x in items:\n        s += str(x)\n    return s\n",
            encoding="utf-8",
        )
        res = _run_cli("fix", "--diff", "--dry-run", str(file_path))
        assert res.returncode == 0
        assert "--- a/" in res.stdout
        assert "+++ b/" in res.stdout
        assert "+    s_chunks = []" in res.stdout

    def test_cli_fix_rule_filter(self, tmp_path: Path) -> None:
        file_path = tmp_path / "app.py"
        # Code has both linear search and string concat
        file_path.write_text(
            "def f(items, targets):\n    s = ''\n    for x in items:\n        if x in targets:\n            s += str(x)\n    return s\n",
            encoding="utf-8",
        )
        res = _run_cli("fix", "--rule", "plex.linear-search-in-loop", str(file_path))
        assert res.returncode == 0
        assert "Fixed 1 file(s)" in res.stdout

        modified = file_path.read_text(encoding="utf-8")
        # linear search was fixed
        assert "targets_set = set(targets)" in modified
        # string concat was NOT fixed because of rule filter
        assert "s_chunks = []" not in modified

    def test_cli_fix_clean_directory(self, tmp_path: Path) -> None:
        clean_file = tmp_path / "clean.py"
        clean_file.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

        res = _run_cli("fix", str(tmp_path))
        assert res.returncode == 0
        assert "No fixable PLEx violations found." in res.stdout

    def test_cli_fix_multiple_paths(self, tmp_path: Path) -> None:
        f1 = tmp_path / "a.py"
        f1.write_text(
            "def f(items):\n    s = ''\n    for x in items:\n        s += str(x)\n    return s\n",
            encoding="utf-8",
        )
        f2 = tmp_path / "b.py"
        f2.write_text(
            "def g(items, target):\n    for x in items:\n        if x in target:\n            pass\n",
            encoding="utf-8",
        )
        res = _run_cli("fix", str(f1), str(f2))
        assert res.returncode == 0
        assert "Fixed 2 file(s)" in res.stdout
        assert "s_chunks = []" in f1.read_text(encoding="utf-8")
        assert "target_set = set(target)" in f2.read_text(encoding="utf-8")

    def test_cli_fix_redundant_comprehension_and_dict_keys(self, tmp_path: Path) -> None:
        test_file = tmp_path / "clean_me.py"
        test_file.write_text(
            """def optimize(d, items):
    nums = list([x * 2 for x in items])
    for k in d.keys():
        if k in d.keys():
            pass
    return nums
""",
            encoding="utf-8",
        )
        res = _run_cli("fix", str(test_file))
        assert res.returncode == 0
        assert "Fixed 1 file(s)" in res.stdout
        fixed_text = test_file.read_text(encoding="utf-8")
        assert "nums = [x * 2 for x in items]" in fixed_text
        assert "for k in d:" in fixed_text
        assert "if k in d:" in fixed_text

    def test_cli_fix_wave3_rules(self, tmp_path: Path) -> None:
        test_file = tmp_path / "wave3.py"
        test_file.write_text(
            """import math

def calculate(items, d, k):
    if len(items) > 0:
        pass
    if len(items) == 0:
        pass
    results = []
    for x in items:
        results.append(math.pow(x, 2))
    if k in d:
        v = d[k]
    else:
        v = "default"
    return v, results
""",
            encoding="utf-8",
        )
        res = _run_cli("fix", str(test_file))
        assert res.returncode == 0
        assert "Fixed 1 file(s)" in res.stdout
        fixed_text = test_file.read_text(encoding="utf-8")
        assert "if items:" in fixed_text
        assert "if not items:" in fixed_text
        assert "results.append(x * x)" in fixed_text
        assert 'v = d.get(k, "default")' in fixed_text or "v = d.get(k, 'default')" in fixed_text

    def test_cli_fix_wave4_rules(self, tmp_path: Path) -> None:
        test_file = tmp_path / "wave4.py"
        test_file.write_text(
            """def process(items, options=[]):
    out = []
    for x in items:
        out.append(x)
    return out
""",
            encoding="utf-8",
        )
        res = _run_cli("fix", str(test_file))
        assert res.returncode == 0
        assert "Fixed 1 file(s)" in res.stdout
        fixed_text = test_file.read_text(encoding="utf-8")
        assert "def process(items, options=None):" in fixed_text
        assert "if options is None:\n        options = []" in fixed_text
        assert "out.extend(items)" in fixed_text

    def test_cli_fix_wave5_rules(self, tmp_path: Path) -> None:
        test_file = tmp_path / "wave5.py"
        test_file.write_text(
            """def optimize_ops(items):
    has_any = any([x > 0 for x in items])
    low = sorted(items)[0]
    total = sum([x for x in items])
    return has_any, low, total
""",
            encoding="utf-8",
        )
        res = _run_cli("fix", str(test_file))
        assert res.returncode == 0
        assert "Fixed 1 file(s)" in res.stdout
        fixed_text = test_file.read_text(encoding="utf-8")
        assert (
            "any((x > 0 for x in items))" in fixed_text or "any(x > 0 for x in items)" in fixed_text
        )
        assert "low = min(items)" in fixed_text
        assert (
            "total = sum((x for x in items))" in fixed_text
            or "total = sum(x for x in items)" in fixed_text
        )

    def test_cli_fix_wave6_rules(self, tmp_path: Path) -> None:
        test_file = tmp_path / "wave6.py"
        test_file.write_text(
            """def optimize_collections(items, d, k):
    if k in ['a', 'b', 'c']:
        pass
    m = map(lambda x: int(x), items)
    v = d.get(k, None)
    return m, v
""",
            encoding="utf-8",
        )
        res = _run_cli("fix", str(test_file))
        assert res.returncode == 0
        assert "Fixed 1 file(s)" in res.stdout
        fixed_text = test_file.read_text(encoding="utf-8")
        assert "if k in {'a', 'b', 'c'}:" in fixed_text or 'if k in {"a", "b", "c"}:' in fixed_text
        assert "m = map(int, items)" in fixed_text
        assert "v = d.get(k)" in fixed_text

    def test_cli_fix_interactive_accept(self, tmp_path: Path) -> None:
        file_path = tmp_path / "app.py"
        file_path.write_text("def f(k, d):\n    return d.get(k, None)\n", encoding="utf-8")
        res = _run_cli("fix", "-i", str(file_path), input="y\n")
        assert res.returncode == 0
        assert "Fixed 1 file(s)" in res.stdout
        assert "d.get(k)" in file_path.read_text(encoding="utf-8")

    def test_cli_fix_interactive_reject(self, tmp_path: Path) -> None:
        original = "def f(k, d):\n    return d.get(k, None)\n"
        file_path = tmp_path / "app.py"
        file_path.write_text(original, encoding="utf-8")
        res = _run_cli("fix", "-i", str(file_path), input="n\n")
        assert res.returncode == 0
        assert "No fixable PLEx violations found." in res.stdout
        assert file_path.read_text(encoding="utf-8") == original
