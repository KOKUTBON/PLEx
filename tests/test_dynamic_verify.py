"""Tests for dynamic verification helpers (pure functions, no subprocess probes)."""

from __future__ import annotations

import pytest

from plex.analyze.dynamic_verify import (
    _DYNAMIC_SCORES,
    _HINT_RANK,
    _dynamic_status,
    dynamic_risk_score,
)


class TestDynamicRiskScore:
    @pytest.mark.parametrize("label,expected", list(_DYNAMIC_SCORES.items()))
    def test_known_labels(self, label: str, expected: float) -> None:
        assert dynamic_risk_score(label) == expected

    def test_unknown_label(self) -> None:
        assert dynamic_risk_score("unknown label") is None

    def test_unknown_returns_none(self) -> None:
        assert dynamic_risk_score("definitely not a label") is None


class TestDynamicStatus:
    def test_confirmed(self) -> None:
        """Static O(n^2), dynamic also O(n^2) with high confidence -> confirmed."""
        status = _dynamic_status("O(n^2) candidate", "O(n^2) candidate", 0.9, 0.6)
        assert status == "confirmed"

    def test_downgraded(self) -> None:
        """Static O(n^2), dynamic O(n) with high confidence -> downgraded."""
        status = _dynamic_status("O(n^2) candidate", "O(n) candidate", 0.9, 0.6)
        assert status == "downgraded"

    def test_inconclusive_low_confidence(self) -> None:
        """Low confidence below threshold -> inconclusive."""
        status = _dynamic_status("O(n) candidate", "O(n) candidate", 0.3, 0.6)
        assert status == "inconclusive"

    def test_inconclusive_unknown_static_hint(self) -> None:
        """Unknown static hint not in _HINT_RANK -> inconclusive."""
        status = _dynamic_status("unknown_hint", "O(n) candidate", 0.9, 0.6)
        assert status == "inconclusive"

    def test_inconclusive_unknown_dynamic_label(self) -> None:
        """Unknown dynamic label not in _HINT_RANK -> inconclusive."""
        status = _dynamic_status("O(n) candidate", "unknown_label", 0.9, 0.6)
        assert status == "inconclusive"

    def test_confirmed_same_rank(self) -> None:
        """Same static and dynamic rank with good confidence -> confirmed."""
        status = _dynamic_status("O(n) candidate", "O(n) candidate", 0.8, 0.6)
        assert status == "confirmed"

    def test_confirmed_higher_dynamic(self) -> None:
        """Dynamic worse than static (higher rank) -> confirmed."""
        status = _dynamic_status("O(n) candidate", "O(n^2) candidate", 0.9, 0.6)
        assert status == "confirmed"


class TestHintRank:
    def test_ordering(self) -> None:
        """_HINT_RANK values should be monotonically increasing from simple to complex."""
        ordered_labels = [
            "O(1) / O(log n) candidate",
            "O(n) candidate",
            "O(n log n) candidate",
            "O(n log n) + loop",
            "O(n^2) candidate",
            "O(n^3) or worse",
            "potentially exponential / high",
        ]
        ranks = [_HINT_RANK[label] for label in ordered_labels]
        for i in range(len(ranks) - 1):
            assert ranks[i] < ranks[i + 1], (
                f"{ordered_labels[i]} should rank lower than {ordered_labels[i + 1]}"
            )

    def test_all_labels_present(self) -> None:
        """Verify all expected labels are in _HINT_RANK."""
        expected = {
            "O(1) / O(log n) candidate",
            "O(n) candidate",
            "O(n log n) candidate",
            "O(n log n) + loop",
            "O(n^2) candidate",
            "O(n^3) or worse",
            "potentially exponential / high",
        }
        assert expected == set(_HINT_RANK.keys())
