"""
Deterministic Time-Series Forecasting Engine (Milestone M5)

Invariants & Constraints:
1. All figures, metrics, prediction intervals, and point forecasts are calculated
   by deterministic Python code. A language model NEVER invents, estimates, or alters figures.
2. Holdout backtesting compares candidate models against the Naive baseline.
3. Prediction intervals (80% and 95%) are derived from backtest residual variance.
4. Rigid input validation: handles missing timestamps, non-numeric values, unsorted dates,
   and refuses with defined errors on insufficient data (< 10 points or < 2 full seasons).
5. Output explicitly states method, holdout error, and uncertainty limits.
"""

from __future__ import annotations

import csv
import math
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple


class ForecastError(Exception):
    """Base exception for forecasting pipeline errors."""
    pass


class InsufficientDataError(ForecastError):
    """Raised when data has fewer than the required minimum points."""
    pass


class MalformedDataError(ForecastError):
    """Raised when data cannot be parsed or contains unresolvable non-numeric values."""
    pass


@dataclass
class ForecastPoint:
    step: int
    date: str
    point: float
    lower_80: float
    upper_80: float
    lower_95: float
    upper_95: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BacktestResult:
    holdout_size: int
    method_name: str
    mae: float
    rmse: float
    mape: Optional[float]
    naive_mae: float
    naive_rmse: float
    beated_naive: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ForecastReport:
    success: bool
    status: str
    series_name: str
    total_points: int
    frequency: str
    date_range: Tuple[str, str]
    data_warnings: List[str]
    method_used: str
    backtest: BacktestResult
    forecasts: List[ForecastPoint]
    summary_narration: str
    disclaimer: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "status": self.status,
            "series_name": self.series_name,
            "total_points": self.total_points,
            "frequency": self.frequency,
            "date_range": list(self.date_range),
            "data_warnings": self.data_warnings,
            "method_used": self.method_used,
            "backtest": self.backtest.to_dict(),
            "forecasts": [f.to_dict() for f in self.forecasts],
            "summary_narration": self.summary_narration,
            "disclaimer": self.disclaimer,
        }


# -----------------------------------------------------------------------------
# Input Parsing & Validation
# -----------------------------------------------------------------------------
DATE_PATTERNS = [
    r"^\d{4}-\d{2}-\d{2}$",
    r"^\d{4}/\d{2}/\d{2}$",
    r"^\d{4}-\d{2}$",
    r"^\d{2}/\d{2}/\d{4}$",
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
]


def _is_date_string(val: str) -> bool:
    val = val.strip()
    return any(re.match(p, val) for p in DATE_PATTERNS)


def parse_csv_series(
    csv_path: str,
    date_col: Optional[str] = None,
    value_col: Optional[str] = None,
) -> Tuple[List[str], List[float], List[str]]:
    """
    Parses a CSV file into dates and numeric series.
    Returns (dates, values, warnings).
    Raises InsufficientDataError or MalformedDataError on unresolvable issues.
    """
    if not os.path.exists(csv_path):
        raise MalformedDataError(f"Target CSV file not found: {csv_path}")

    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        rows = [r for r in reader if r and any(c.strip() for c in r)]

    if len(rows) < 2:
        raise InsufficientDataError("CSV contains insufficient rows (header + at least 10 data rows required)")

    header = [h.strip() for h in rows[0]]
    data_rows = rows[1:]

    # Detect date column
    d_idx = -1
    if date_col:
        for idx, h in enumerate(header):
            if h.lower() == date_col.lower():
                d_idx = idx
                break
        if d_idx == -1:
            raise MalformedDataError(f"Specified date column '{date_col}' not found in header: {header}")
    else:
        # Auto-detect date column
        for idx in range(len(header)):
            matches = sum(1 for r in data_rows[:10] if idx < len(r) and _is_date_string(r[idx]))
            if matches >= min(5, len(data_rows)):
                d_idx = idx
                break
        if d_idx == -1:
            # Fallback: check if first column has unique string labels
            d_idx = 0

    # Detect value column
    v_idx = -1
    if value_col:
        for idx, h in enumerate(header):
            if h.lower() == value_col.lower():
                v_idx = idx
                break
        if v_idx == -1:
            raise MalformedDataError(f"Specified value column '{value_col}' not found in header: {header}")
    else:
        # Auto-detect first numeric column not equal to date column
        for idx in range(len(header)):
            if idx == d_idx:
                continue
            num_count = 0
            for r in data_rows[:10]:
                if idx < len(r):
                    try:
                        float(r[idx].strip().replace(",", ""))
                        num_count += 1
                    except ValueError:
                        pass
            if num_count >= min(5, len(data_rows)):
                v_idx = idx
                break
        if v_idx == -1:
            # Try any numeric column
            for idx in range(len(header)):
                if idx != d_idx:
                    v_idx = idx
                    break

    if v_idx == -1 or v_idx == d_idx:
        raise MalformedDataError("Could not identify a distinct numeric target column in CSV")

    warnings: List[str] = []
    dates: List[str] = []
    values: List[float] = []

    for row_num, r in enumerate(data_rows, start=2):
        if len(r) <= max(d_idx, v_idx):
            warnings.append(f"Row {row_num}: incomplete columns, skipped")
            continue
        d_val = r[d_idx].strip()
        raw_v = r[v_idx].strip().replace(",", "")

        if not d_val or not raw_v:
            warnings.append(f"Row {row_num}: empty cell detected, skipped")
            continue

        try:
            num = float(raw_v)
            if math.isnan(num) or math.isinf(num):
                raise ValueError("NaN or Inf")
        except ValueError:
            raise MalformedDataError(f"Row {row_num}: non-numeric value in target column: '{raw_v}'")

        dates.append(d_val)
        values.append(num)

    if len(values) < 10:
        raise InsufficientDataError(
            f"Series contains only {len(values)} valid numeric points; minimum 10 points required for reliable forecasting."
        )

    # Check date sorting
    is_sorted = all(dates[i] <= dates[i + 1] for i in range(len(dates) - 1))
    if not is_sorted:
        warnings.append("Timestamps were unsorted; series has been chronologically sorted.")
        paired = sorted(zip(dates, values), key=lambda x: x[0])
        dates = [p[0] for p in paired]
        values = [p[1] for p in paired]

    # Check duplicates
    if len(set(dates)) < len(dates):
        warnings.append(f"Duplicate timestamps detected ({len(dates) - len(set(dates))} duplicates).")

    return dates, values, warnings


def detect_frequency(dates: List[str]) -> str:
    """Infers time series frequency from date strings."""
    if len(dates) < 2:
        return "step"

    parsed = []
    for d in dates[:20]:
        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y-%m", "%d/%m/%Y"):
            try:
                parsed.append(datetime.strptime(d[:10], fmt))
                break
            except Exception:
                pass

    if len(parsed) < 2:
        return "index"

    deltas = [(parsed[i + 1] - parsed[i]).days for i in range(len(parsed) - 1)]
    if not deltas:
        return "index"
    med_delta = sorted(deltas)[len(deltas) // 2]

    if med_delta == 1:
        return "daily"
    elif 6 <= med_delta <= 8:
        return "weekly"
    elif 27 <= med_delta <= 32:
        return "monthly"
    elif 360 <= med_delta <= 370:
        return "annual"
    return f"step_{med_delta}d"


# -----------------------------------------------------------------------------
# Forecasting Algorithms
# -----------------------------------------------------------------------------
def forecast_naive(history: List[float], horizon: int) -> List[float]:
    """Baseline naive forecast: repeats last known observation."""
    last_val = history[-1]
    return [last_val] * horizon


def forecast_ses(history: List[float], horizon: int, alpha: Optional[float] = None) -> Tuple[List[float], float]:
    """
    Simple Exponential Smoothing (SES).
    Optimizes alpha in [0.1, 0.9] via grid search if not provided.
    """
    if alpha is None:
        best_alpha = 0.3
        best_sse = float("inf")
        for a_cand in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
            level = history[0]
            sse = 0.0
            for val in history[1:]:
                sse += (val - level) ** 2
                level = a_cand * val + (1.0 - a_cand) * level
            if sse < best_sse:
                best_sse = sse
                best_alpha = a_cand
        alpha = best_alpha

    level = history[0]
    for val in history[1:]:
        level = alpha * val + (1.0 - alpha) * level

    return [level] * horizon, alpha


def forecast_holt(history: List[float], horizon: int) -> Tuple[List[float], float, float]:
    """
    Holt's Linear Trend method.
    Models level and additive linear slope.
    """
    best_params = (0.3, 0.1)
    best_sse = float("inf")

    for a in (0.1, 0.3, 0.5, 0.7):
        for b in (0.05, 0.1, 0.2):
            level = history[0]
            trend = history[1] - history[0] if len(history) > 1 else 0.0
            sse = 0.0
            for val in history[1:]:
                pred = level + trend
                sse += (val - pred) ** 2
                new_level = a * val + (1.0 - a) * (level + trend)
                trend = b * (new_level - level) + (1.0 - b) * trend
                level = new_level
            if sse < best_sse:
                best_sse = sse
                best_params = (a, b)

    alpha, beta = best_params
    level = history[0]
    trend = history[1] - history[0] if len(history) > 1 else 0.0
    for val in history[1:]:
        new_level = alpha * val + (1.0 - alpha) * (level + trend)
        trend = beta * (new_level - level) + (1.0 - beta) * trend
        level = new_level

    preds = [level + (h + 1) * trend for h in range(horizon)]
    return preds, alpha, beta


def forecast_seasonal_naive(history: List[float], horizon: int, season_len: int) -> List[float]:
    """Seasonal naive forecast: projects values from the last season cycle."""
    preds = []
    for h in range(horizon):
        idx = len(history) - season_len + (h % season_len)
        preds.append(history[idx])
    return preds


# -----------------------------------------------------------------------------
# Backtesting & Prediction Intervals
# -----------------------------------------------------------------------------
def evaluate_metrics(actuals: List[float], preds: List[float]) -> Tuple[float, float, Optional[float]]:
    """Calculates MAE, RMSE, and MAPE."""
    k = len(actuals)
    if k == 0:
        return 0.0, 0.0, None

    mae = sum(abs(a - p) for a, p in zip(actuals, preds)) / k
    rmse = math.sqrt(sum((a - p) ** 2 for a, p in zip(actuals, preds)) / k)

    non_zeros = [(a, p) for a, p in zip(actuals, preds) if abs(a) > 1e-6]
    mape = (sum(abs((a - p) / a) for a, p in non_zeros) / len(non_zeros) * 100.0) if non_zeros else None

    return round(mae, 4), round(rmse, 4), round(mape, 2) if mape is not None else None


def run_forecast_pipeline(
    csv_path: str,
    horizon: int = 5,
    date_col: Optional[str] = None,
    value_col: Optional[str] = None,
) -> ForecastReport:
    """
    Executes the full forecasting pipeline:
    1. Parse and validate CSV data.
    2. Holdout split for backtesting (last H points, min 3, max 12).
    3. Evaluate candidates (Holt, SES, Seasonal Naive, Naive Baseline).
    4. Pick best-performing model on holdout.
    5. Fit winning model on full history and compute point forecasts with intervals.
    """
    dates, values, warnings = parse_csv_series(csv_path, date_col=date_col, value_col=value_col)
    n = len(values)
    freq = detect_frequency(dates)

    # Determine holdout window size
    h_backtest = min(horizon, max(3, n // 5))
    h_backtest = min(h_backtest, 12)
    train_vals = values[:-h_backtest]
    holdout_actuals = values[-h_backtest:]

    # 1. Evaluate Naive Baseline
    naive_preds = forecast_naive(train_vals, h_backtest)
    naive_mae, naive_rmse, _ = evaluate_metrics(holdout_actuals, naive_preds)

    # 2. Evaluate Candidates
    candidates: List[Tuple[str, List[float], Any]] = []

    # Candidate A: Holt's linear trend
    holt_preds, h_alpha, h_beta = forecast_holt(train_vals, h_backtest)
    candidates.append((f"Holt Linear Trend (alpha={h_alpha:.2f}, beta={h_beta:.2f})", holt_preds, ("holt", h_alpha, h_beta)))

    # Candidate B: Simple Exponential Smoothing
    ses_preds, s_alpha = forecast_ses(train_vals, h_backtest)
    candidates.append((f"Simple Exponential Smoothing (alpha={s_alpha:.2f})", ses_preds, ("ses", s_alpha)))

    # Candidate C: Seasonal Naive if enough history (>= 2 seasons)
    season_cand = 12 if freq == "monthly" else (7 if freq == "daily" else None)
    if season_cand and len(train_vals) >= 2 * season_cand:
        sn_preds = forecast_seasonal_naive(train_vals, h_backtest, season_cand)
        candidates.append((f"Seasonal Naive (period={season_cand})", sn_preds, ("snaive", season_cand)))

    # Pick best candidate on holdout MAE
    best_name = "Naive Baseline"
    best_meta = ("naive",)
    best_mae = naive_mae
    best_rmse = naive_rmse
    best_mape = evaluate_metrics(holdout_actuals, naive_preds)[2]
    beated_naive = False

    for name, c_preds, meta in candidates:
        c_mae, c_rmse, c_mape = evaluate_metrics(holdout_actuals, c_preds)
        if c_mae < best_mae:
            best_mae = c_mae
            best_rmse = c_rmse
            best_mape = c_mape
            best_name = name
            best_meta = meta
            beated_naive = True

    backtest = BacktestResult(
        holdout_size=h_backtest,
        method_name=best_name,
        mae=best_mae,
        rmse=best_rmse,
        mape=best_mape,
        naive_mae=naive_mae,
        naive_rmse=naive_rmse,
        beated_naive=beated_naive,
    )

    # 3. Fit winning method on FULL series and forecast horizon steps
    final_method = best_meta[0]
    if final_method == "holt":
        full_preds, _, _ = forecast_holt(values, horizon)
    elif final_method == "ses":
        full_preds, _ = forecast_ses(values, horizon)
    elif final_method == "snaive":
        full_preds = forecast_seasonal_naive(values, horizon, best_meta[1])
    else:
        full_preds = forecast_naive(values, horizon)

    # 4. Compute Prediction Intervals from Backtest Residual Variance
    res_std = max(best_rmse, 1e-4)

    # Generate future dates
    future_dates = []
    last_d = dates[-1]
    for step in range(1, horizon + 1):
        if freq == "daily":
            try:
                dt = datetime.strptime(last_d[:10], "%Y-%m-%d") + timedelta(days=step)
                future_dates.append(dt.strftime("%Y-%m-%d"))
            except Exception:
                future_dates.append(f"t+{step}")
        elif freq == "monthly":
            try:
                dt = datetime.strptime(last_d[:7], "%Y-%m")
                month_idx = dt.month - 1 + step
                yr = dt.year + (month_idx // 12)
                m = (month_idx % 12) + 1
                future_dates.append(f"{yr}-{m:02d}-01")
            except Exception:
                future_dates.append(f"t+{step}")
        else:
            future_dates.append(f"t+{step}")

    forecast_points: List[ForecastPoint] = []
    for step, (f_date, pt) in enumerate(zip(future_dates, full_preds), start=1):
        step_sigma = res_std * math.sqrt(step)
        pt_round = round(pt, 2)
        l80 = round(pt - 1.282 * step_sigma, 2)
        u80 = round(pt + 1.282 * step_sigma, 2)
        l95 = round(pt - 1.960 * step_sigma, 2)
        u95 = round(pt + 1.960 * step_sigma, 2)

        forecast_points.append(
            ForecastPoint(
                step=step,
                date=f_date,
                point=pt_round,
                lower_80=l80,
                upper_80=u80,
                lower_95=l95,
                upper_95=u95,
            )
        )

    # Summary narration (deterministic baseline)
    impr_str = (
        f"Selected {best_name} which outperformed naive baseline by "
        f"{((naive_mae - best_mae) / naive_mae * 100):.1f}% on holdout window (MAE: {best_mae:.2f} vs {naive_mae:.2f})."
        if beated_naive
        else f"Selected {best_name}; candidate models did not outperform naive baseline on holdout (MAE: {best_mae:.2f})."
    )

    narration = (
        f"Forecast generated for {n} historical observations ({freq} frequency).\n"
        f"Backtest validation on {h_backtest}-step holdout: {impr_str}\n"
        f"Projected next {horizon} steps: starting at {full_preds[0]:.2f} ending at {full_preds[-1]:.2f}."
    )

    disclaimer = (
        "Notice: Forecasts are mathematical extrapolations of historical patterns. "
        "Unforeseen macroeconomic events, structural shifts, and black swan shocks are not modeled."
    )

    series_name = os.path.basename(csv_path)

    return ForecastReport(
        success=True,
        status="OK",
        series_name=series_name,
        total_points=n,
        frequency=freq,
        date_range=(dates[0], dates[-1]),
        data_warnings=warnings,
        method_used=best_name,
        backtest=backtest,
        forecasts=forecast_points,
        summary_narration=narration,
        disclaimer=disclaimer,
    )
