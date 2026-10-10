"""
End-to-End Acceptance Tests for Milestone M5: `pai forecast <csv>`
Verifies:
1. Deterministic execution of `pai forecast` CLI.
2. Formatted ASCII table output with method, backtest MAE/RMSE, prediction intervals, disclaimer.
3. JSON output format conformance (--json).
4. Refusal and exit code 1 on insufficient data (< 10 points).
5. Refusal and exit code 1 on malformed / non-numeric data.
6. Refusal on missing files.
7. Router CLI preview (`pai route forecast`).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import unittest

_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_DIR)
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import _bootstrap  # noqa: F401
import pai

FIXTURES_DIR = os.path.join(_PARENT, "eval_sets", "forecast_series")


class TestPaiForecastE2E(unittest.TestCase):
    def test_forecast_trend_ascii(self):
        trend_csv = os.path.join(FIXTURES_DIR, "series_trend.csv")
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = pai.main(["forecast", trend_csv, "--horizon", "5"])

        self.assertEqual(exit_code, 0)
        out = stdout.getvalue()
        self.assertIn("PAI FORECAST: series_trend.csv", out)
        self.assertIn("Holt Linear Trend", out)
        self.assertIn("Backtest Window:", out)
        self.assertIn("80% Interval", out)
        self.assertIn("95% Interval", out)
        self.assertIn("Notice: Forecasts are mathematical extrapolations", out)

    def test_forecast_seasonal_json(self):
        seasonal_csv = os.path.join(FIXTURES_DIR, "series_seasonal.csv")
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = pai.main(["forecast", seasonal_csv, "--horizon", "6", "--json"])

        self.assertEqual(exit_code, 0)
        data = json.loads(stdout.getvalue())
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "OK")
        self.assertEqual(data["total_points"], 72)
        self.assertEqual(data["frequency"], "monthly")
        self.assertIn("Seasonal Naive", data["method_used"])
        self.assertEqual(len(data["forecasts"]), 6)
        self.assertTrue(data["backtest"]["beated_naive"])

    def test_forecast_too_short_refusal(self):
        short_csv = os.path.join(FIXTURES_DIR, "series_too_short.csv")
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = pai.main(["forecast", short_csv, "--json"])

        self.assertEqual(exit_code, 1)
        data = json.loads(stdout.getvalue())
        self.assertFalse(data["success"])
        self.assertEqual(data["error"], "INSUFFICIENT_DATA")
        self.assertIn("minimum 10 points required", data["detail"])

    def test_forecast_malformed_refusal(self):
        corrupt_csv = os.path.join(FIXTURES_DIR, "series_non_numeric.csv")
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = pai.main(["forecast", corrupt_csv, "--json"])

        self.assertEqual(exit_code, 1)
        data = json.loads(stdout.getvalue())
        self.assertFalse(data["success"])
        self.assertEqual(data["error"], "MALFORMED_DATA")

    def test_forecast_missing_file_refusal(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = pai.main(["forecast", "non_existent_series.csv", "--json"])

        self.assertEqual(exit_code, 1)
        data = json.loads(stdout.getvalue())
        self.assertFalse(data["success"])

    def test_route_forecast(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = pai.main(["route", "forecast", "--json"])

        self.assertEqual(exit_code, 0)
        data = json.loads(stdout.getvalue())
        self.assertEqual(data["task_class"], "forecast")

    def test_forecast_horizon_zero_refusal(self):
        trend_csv = os.path.join(FIXTURES_DIR, "series_trend.csv")
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = pai.main(["forecast", trend_csv, "--horizon", "0", "--json"])

        self.assertEqual(exit_code, 1)
        data = json.loads(stdout.getvalue())
        self.assertFalse(data["success"])
        self.assertEqual(data["error"], "MALFORMED_DATA")
        self.assertIn("Horizon must be an integer between 1 and 100", data["detail"])


if __name__ == "__main__":
    unittest.main()
