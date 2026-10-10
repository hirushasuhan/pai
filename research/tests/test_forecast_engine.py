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
import tempfile
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
        self.assertTrue(any("Irregular timestamp gaps detected" in w for w in report.data_warnings))

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

    def test_invalid_calendar_date_refusal(self):
        # Finding 1: Strict calendar validation using strptime rejects invalid days (e.g. 2026-02-29, 2026-02-30)
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="") as tf:
            tf.write("date,value\n")
            tf.write("2026-02-27,10.0\n")
            tf.write("2026-02-28,11.0\n")
            tf.write("2026-02-29,12.0\n")  # 2026 is not a leap year!
            for d in range(1, 10):
                tf.write(f"2026-03-0{d},{12.0 + d}\n")
            tf_path = tf.name

        try:
            with self.assertRaises(MalformedDataError) as ctx:
                run_forecast_pipeline(tf_path, horizon=3)
            self.assertIn("Invalid calendar date '2026-02-29'", str(ctx.exception))
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_non_date_label_ordering_preserved(self):
        # Finding 2: Non-date labels like x0..x29 must remain in original sequence order, not sorted lexicographically
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="") as tf:
            tf.write("step,val\n")
            for i in range(30):
                tf.write(f"x{i},{float(i * 2)}\n")
            tf_path = tf.name

        try:
            from forecast_engine import parse_csv_series
            dates, vals, _, is_dt, _ = parse_csv_series(tf_path)
            self.assertFalse(is_dt)
            # Ensure order is x0, x1, x2 ... not x0, x1, x10, x11
            expected_dates = [f"x{i}" for i in range(30)]
            self.assertEqual(dates, expected_dates)
            self.assertEqual(vals, [float(i * 2) for i in range(30)])
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_duplicate_timestamp_refusal(self):
        # Finding 3: Exact duplicate timestamps must raise MalformedDataError rather than inventing step_0d frequency
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="") as tf:
            tf.write("date,value\n")
            for d in range(1, 10):
                tf.write(f"2026-01-0{d},{10.0 + d}\n")
            tf.write("2026-01-05,99.0\n")  # Duplicate
            tf.write("2026-01-10,20.0\n")
            tf_path = tf.name

        try:
            with self.assertRaises(MalformedDataError) as ctx:
                run_forecast_pipeline(tf_path, horizon=3)
            self.assertIn("Duplicate timestamp detected", str(ctx.exception))
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_horizon_bounds_validation(self):
        # Finding 4: Validate horizon (0, negative, > 100 rejected)
        csv_path = os.path.join(FIXTURES_DIR, "series_trend.csv")
        for bad_h in [0, -1, 100000, None]:
            with self.assertRaises(MalformedDataError) as ctx:
                run_forecast_pipeline(csv_path, horizon=bad_h)  # type: ignore
            self.assertIn("Horizon must be an integer between 1 and 100", str(ctx.exception))

    def test_empty_cell_refusal(self):
        # Finding 6: Empty cells raise MalformedDataError to prevent time-index shifting
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="") as tf:
            tf.write("date,value\n")
            for d in range(1, 6):
                tf.write(f"2026-01-0{d},{10.0 + d}\n")
            tf.write("2026-01-06,\n")  # Empty value
            for d in range(7, 12):
                tf.write(f"2026-01-0{d},{10.0 + d}\n")
            tf_path = tf.name

        try:
            with self.assertRaises(MalformedDataError) as ctx:
                run_forecast_pipeline(tf_path, horizon=3)
            self.assertIn("empty cell detected", str(ctx.exception))
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_rolling_origin_validation_and_residual_floor(self):
        # Finding 5: Rolling origin validation, distinct training vs holdout, and non-zero interval floor
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="") as tf:
            tf.write("date,value\n")
            # Perfectly deterministic linear sequence
            for d in range(1, 31):
                tf.write(f"2026-01-{d:02d},{float(2 * d + 10)}\n")
            tf_path = tf.name

        try:
            report = run_forecast_pipeline(tf_path, horizon=5)
            self.assertTrue(report.success)
            self.assertGreaterEqual(report.backtest.validation_origins, 1)
            self.assertGreaterEqual(report.backtest.residual_sample_size, report.backtest.holdout_size)
            self.assertIsNotNone(report.backtest.uncertainty_notes)
            self.assertIn("zero residual variance", report.backtest.uncertainty_notes.lower())

            # Monotonicity and non-zero intervals even on deterministic series
            for fp in report.forecasts:
                self.assertLess(fp.lower_95, fp.point)
                self.assertGreater(fp.upper_95, fp.point)
                self.assertGreater(fp.upper_95 - fp.lower_95, 0.05)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_daily_five_day_gap_warning(self):
        # Reviewer defect 2: Daily series with a 5-day gap must emit an irregular timestamp gap warning
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="") as tf:
            tf.write("date,value\n")
            for d in range(1, 10):
                tf.write(f"2026-01-{d:02d},{float(10 + d)}\n")
            # Skip 5 days: jump from 2026-01-09 to 2026-01-15
            for d in range(15, 25):
                tf.write(f"2026-01-{d:02d},{float(10 + d)}\n")
            tf_path = tf.name

        try:
            report = run_forecast_pipeline(tf_path, horizon=3)
            self.assertTrue(report.success)
            self.assertTrue(any("Irregular timestamp gaps detected" in w for w in report.data_warnings))
            self.assertTrue(any("2026-01-09 to 2026-01-15" in w for w in report.data_warnings))
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)


if __name__ == "__main__":
    unittest.main()
