from __future__ import annotations

import pytest

from plex.report.severity import (
    check_run_annotation_level,
    github_annotation_level,
    normalize_severity,
    sarif_level,
    score_from_severity,
    severity_from_score,
    severity_rank,
)


class TestReportSeverity:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (3.0, "high"),
            (4.0, "high"),
            (2.0, "medium"),
            (2.5, "medium"),
            (1.0, "low"),
            (1.9, "low"),
            (0.9, "info"),
            (0.0, "info"),
            (-1.0, "info"),
        ],
    )
    def test_severity_from_score(self, score: float, expected: str) -> None:
        assert severity_from_score(score) == expected

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            ("critical", 3.4),
            ("high", 2.6),
            ("medium", 1.6),
            ("low", 0.9),
            ("info", 0.3),
            ("unknown", 0.3),
        ],
    )
    def test_score_from_severity(self, severity: str, expected: float) -> None:
        assert score_from_severity(severity) == expected

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            ("CRITICAL", "critical"),
            ("  high  ", "high"),
            ("Medium", "medium"),
            ("low", "low"),
            ("info", "info"),
            ("invalid", "info"),
        ],
    )
    def test_normalize_severity(self, severity: str, expected: str) -> None:
        assert normalize_severity(severity) == expected

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            ("info", 0),
            ("low", 1),
            ("medium", 2),
            ("high", 3),
            ("critical", 4),
        ],
    )
    def test_severity_rank(self, severity: str, expected: int) -> None:
        assert severity_rank(severity) == expected

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            ("critical", "error"),
            ("high", "error"),
            ("medium", "warning"),
            ("low", "note"),
            ("info", "note"),
        ],
    )
    def test_sarif_level(self, severity: str, expected: str) -> None:
        assert sarif_level(severity) == expected

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            ("critical", "error"),
            ("high", "error"),
            ("medium", "warning"),
            ("low", "notice"),
            ("info", "notice"),
        ],
    )
    def test_github_annotation_level(self, severity: str, expected: str) -> None:
        assert github_annotation_level(severity) == expected

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            ("critical", "failure"),
            ("high", "failure"),
            ("medium", "warning"),
            ("low", "notice"),
            ("info", "notice"),
        ],
    )
    def test_check_run_annotation_level(self, severity: str, expected: str) -> None:
        assert check_run_annotation_level(severity) == expected
