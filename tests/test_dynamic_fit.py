"""Tests for ``simple_curve_fit`` and dynamic verification helpers."""

from __future__ import annotations

import math

from plex.util.math import FitResult, simple_curve_fit


class TestSimpleCurveFit:
    def test_constant_data(self) -> None:
        """Flat timings should fit O(1)/O(log n)."""
        sizes = [100, 200, 400, 800, 1600]
        times = [1.0, 1.0, 1.0, 1.0, 1.0]
        result = simple_curve_fit(sizes, times)
        assert isinstance(result, FitResult)
        assert "O(1)" in result.label or "log" in result.label

    def test_linear_data(self) -> None:
        """Linearly scaling timings should fit O(n)."""
        sizes = [100, 200, 400, 800, 1600]
        times = [float(n) for n in sizes]
        result = simple_curve_fit(sizes, times)
        assert "O(n)" in result.label
        assert result.confidence > 0.9

    def test_quadratic_data(self) -> None:
        """Quadratically scaling timings should fit O(n^2)."""
        sizes = [10, 20, 40, 80, 160]
        times = [float(n * n) for n in sizes]
        result = simple_curve_fit(sizes, times)
        assert "O(n^2)" in result.label
        assert result.confidence > 0.9

    def test_nlogn_data(self) -> None:
        """n*log(n) timings should fit O(n log n)."""
        sizes = [100, 200, 400, 800, 1600]
        times = [n * math.log(n) for n in sizes]
        result = simple_curve_fit(sizes, times)
        assert "n log n" in result.label or "O(n)" in result.label
        assert result.confidence > 0.8

    def test_cubic_data(self) -> None:
        """Cubic timings should fit O(n^3) or worse."""
        sizes = [10, 20, 40, 80, 160]
        times = [float(n**3) for n in sizes]
        result = simple_curve_fit(sizes, times)
        assert "n^3" in result.label
        assert result.confidence > 0.9

    def test_too_few_samples(self) -> None:
        """Fewer than 2 valid samples should return 'unknown'."""
        result = simple_curve_fit([100], [1.0])
        assert result.label == "unknown"
        assert result.confidence == 0.0

    def test_empty_input(self) -> None:
        """Empty input should return 'unknown'."""
        result = simple_curve_fit([], [])
        assert result.label == "unknown"
        assert result.confidence == 0.0

    def test_negative_values_filtered(self) -> None:
        """Negative sizes/times should be filtered, leaving insufficient data."""
        result = simple_curve_fit([-1, -2], [-1.0, -2.0])
        assert result.label == "unknown"

    def test_two_samples_sufficient(self) -> None:
        """Exactly two valid samples should produce a fit (not 'unknown')."""
        result = simple_curve_fit([100, 200], [1.0, 2.0])
        assert result.label != "unknown"

    def test_confidence_bounded(self) -> None:
        """Confidence should always be in [0.0, 1.0]."""
        for sizes, times in [
            ([10, 100, 1000], [0.1, 10.0, 1000.0]),
            ([10, 20, 30], [1.0, 1.5, 2.0]),
        ]:
            result = simple_curve_fit(sizes, times)
            assert 0.0 <= result.confidence <= 1.0
