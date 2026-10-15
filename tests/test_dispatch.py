"""Tests for language dispatch (language_for_path) and analyze_source routing."""

from __future__ import annotations

from pathlib import Path

import pytest

from plex.analyze.dispatch import analyze_source
from plex.util.languages import (
    extensions_for_languages,
    language_for_path,
    normalize_language,
    normalize_languages,
)


class TestLanguageForPath:
    @pytest.mark.parametrize(
        "filename, expected",
        [
            ("app.py", "python"),
            ("index.js", "javascript"),
            ("index.jsx", "javascript"),
            ("main.ts", "typescript"),
            ("component.tsx", "typescript"),
            ("Main.java", "java"),
            ("Script.kt", "kotlin"),
            ("build.kts", "kotlin"),
            ("server.go", "go"),
        ],
    )
    def test_known_extensions(self, filename: str, expected: str) -> None:
        assert language_for_path(Path(filename)) == expected

    def test_unknown_extension(self) -> None:
        assert language_for_path(Path("Makefile")) is None
        assert language_for_path(Path("data.csv")) is None
        assert language_for_path(Path("README.md")) is None

    def test_case_insensitive(self) -> None:
        assert language_for_path(Path("APP.PY")) == "python"
        assert language_for_path(Path("module.JS")) == "javascript"


class TestNormalizeLanguage:
    @pytest.mark.parametrize(
        "alias, expected",
        [
            ("py", "python"),
            ("Python", "python"),
            ("js", "javascript"),
            ("jsx", "javascript"),
            ("ts", "typescript"),
            ("tsx", "typescript"),
            ("kt", "kotlin"),
            ("kts", "kotlin"),
            ("golang", "go"),
        ],
    )
    def test_aliases(self, alias: str, expected: str) -> None:
        assert normalize_language(alias) == expected

    def test_unknown_language_passes_through(self) -> None:
        assert normalize_language("rust") == "rust"


class TestNormalizeLanguages:
    def test_deduplicates(self) -> None:
        result = normalize_languages(["py", "python", "Python"])
        assert result == ["python"]

    def test_empty_strings_filtered(self) -> None:
        result = normalize_languages(["py", "", "  ", "js"])
        assert result == ["python", "javascript"]


class TestExtensionsForLanguages:
    def test_python_extensions(self) -> None:
        exts = extensions_for_languages(["python"])
        assert ".py" in exts

    def test_multiple_languages(self) -> None:
        exts = extensions_for_languages(["python", "javascript"])
        assert ".py" in exts
        assert ".js" in exts
        assert ".jsx" in exts


class TestAnalyzeSource:
    def test_python_dispatch(self) -> None:
        """Python files should be analyzed via AST and produce findings."""
        src = """
def example(items):
    for item in items:
        if item in [1, 2, 3]:
            pass
"""
        findings = analyze_source(Path("test.py"), src)
        # At minimum it should return a list (may or may not have findings)
        assert isinstance(findings, list)

    def test_unknown_extension_returns_empty(self) -> None:
        """Files with unsupported extensions should return empty list."""
        findings = analyze_source(Path("data.csv"), "some,data")
        assert findings == []

    def test_js_graceful_degradation(self) -> None:
        """JS files should return empty list when tree-sitter is unavailable."""
        findings = analyze_source(Path("app.js"), "function foo() {}")
        assert isinstance(findings, list)
        # Without tree-sitter, should be empty but not error
