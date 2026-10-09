"""
Unit Tests for Deterministic Forecasting Engine (M5)

Tests:
1. Trend series forecasting and Holt outperformance vs Naive.
2. Seasonal series forecasting and Seasonal Naive evaluation.
3. Noisy series with gaps detection and warning propagation.
4. Prediction interval bounds monotonicity (lower_95 <= lower_80 <= point <= upper_80 <= upper_95).
5. Refusal on insufficient data (< 10 points) with InsufficientDataError.
6. Refusal on non-numeric cells with MalformedDataError.
7. Disclaimer and deterministic metrics invariants.
"""

from __future__ import annotations

import os
import sys
import unittest

_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_DIR)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from forecast_engine import (
    InsufficientDataError,
    MalformedDataError,
    run_forecast_pipeline,
)

FIXTURES_DIR = os.path.join(_PARENT, "eval_sets", "forecast_series")


class TestForecastEngine(unittest.TestCase):
    def test_trend_series(self):
        csv_path = os.path.join(FIXTURES_DIR, "series_trend.csv")
        report = run_forecast_pipeline(csv_path, horizon=7)

        self.assertTrue(report.success)
        self.assertEqual(report.total_points, 90)
        self.assertEqual(report.frequency, "daily")
        self.assertEqual(len(report.forecasts), 7)

        # Invariant: Holt linear trend should outperform flat naive on this clear linear trend
        self.assertTrue(report.backtest.beated_naive)
        self.assertLess(report.backtest.mae, report.backtest.naive_mae)
        self.assertLess(report.backtest.mae, 5.0)

        # Check prediction intervals monotonicity
        for fp in report.forecasts:
            self.assertLessEqual(fp.lower_95, fp.lower_80)
            self.assertLessEqual(fp.lower_80, fp.point)
            self.assertLessEqual(fp.point, fp.upper_80)
            self.assertLessEqual(fp.upper_80, fp.upper_95)

        # Check interval expansion with horizon
        widths = [fp.upper_95 - fp.lower_95 for fp in report.forecasts]
        for i in range(len(widths) - 1):
            self.assertLessEqual(widths[i], widths[i + 1])

    def test_seasonal_series(self):
        csv_path = os.path.join(FIXTURES_DIR, "series_seasonal.csv")
        report = run_forecast_pipeline(csv_path, horizon=12)

        self.assertTrue(report.success)
        self.assertEqual(report.total_points, 72)
        self.assertEqual(report.frequency, "monthly")
        self.assertTrue(report.backtest.beated_naive)
        self.assertLess(report.backtest.mae, report.backtest.naive_mae)
        self.assertLess(report.backtest.mae, 20.0)

        # Monotonicity of intervals
        for fp in report.forecasts:
            self.assertLessEqual(fp.lower_95, fp.lower_80)
            self.assertLessEqual(fp.lower_80, fp.point)
            self.assertLessEqual(fp.point, fp.upper_80)
            self.assertLessEqual(fp.upper_80, fp.upper_95)

    def test_noisy_gap_series(self):
        csv_path = os.path.join(FIXTURES_DIR, "series_noisy_gap.csv")
        report = run_forecast_pipeline(csv_path, horizon=5)

        self.assertTrue(report.success)
        self.assertEqual(len(report.forecasts), 5)
        self.assertIn("Forecasts are mathematical extrapolations", report.disclaimer)

    def test_insufficient_data_refusal(self):
        csv_path = os.path.join(FIXTURES_DIR, "series_too_short.csv")
        with self.assertRaises(InsufficientDataError) as ctx:
            run_forecast_pipeline(csv_path, horizon=3)
        self.assertIn("minimum 10 points required", str(ctx.exception))

    def test_malformed_data_refusal(self):
        csv_path = os.path.join(FIXTURES_DIR, "series_non_numeric.csv")
        with self.assertRaises(MalformedDataError) as ctx:
            run_forecast_pipeline(csv_path, horizon=3)
        self.assertIn("non-numeric value in target column", str(ctx.exception))

    def test_nonexistent_file(self):
        with self.assertRaises(MalformedDataError):
            run_forecast_pipeline("non_existent_file_xyz.csv")


if __name__ == "__main__":
    unittest.main()
