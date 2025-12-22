"""Helpers for aggregating scan history into dashboard-friendly trends."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Scan
from app.utils.timezone import get_now


@dataclass(frozen=True)
class _TrendPoint:
    day: date
    payload: dict[str, Any]


def _percent_change(previous: float | int | None, current: float | int | None) -> float | None:
    """Compute percent change guarding division edge cases."""
    if previous in (None, 0):
        return None
    if current is None:
        return None
    return ((current - previous) / previous) * 100.0


def _sum_period(points: Iterable[_TrendPoint], start: date, end: date) -> dict[str, Any]:
    """Aggregate point metrics between two dates (inclusive)."""
    totals = {
        "completed_scans": 0,
        "fixable_vulns": 0,
        "total_vulns": 0,
        "duration_total": 0.0,
        "duration_samples": 0,
    }

    for entry in points:
        if start <= entry.day <= end:
            data = entry.payload
            totals["completed_scans"] += data["completed_scans"]
            totals["fixable_vulns"] += data["fixable_vulns"]
            totals["total_vulns"] += data["total_vulns"]
            totals["duration_total"] += data["duration_seconds_total"]
            totals["duration_samples"] += data["duration_samples"]

    return totals


async def build_scan_trends(db: AsyncSession, *, window_days: int = 30) -> dict[str, Any]:
    """Return aggregated scan trends for the requested time window."""
    window_days = max(1, min(window_days, 90))
    now = get_now()
    start_at = now - timedelta(days=window_days - 1)

    day_expr = func.date(Scan.scan_date).label("day")
    completed_case = case((Scan.scan_status == "completed", 1), else_=0)
    failed_case = case((Scan.scan_status == "failed", 1), else_=0)

    stmt = (
        select(
            day_expr,
            func.count(Scan.id).label("total_scans"),
            func.sum(completed_case).label("completed_scans"),
            func.sum(failed_case).label("failed_scans"),
            func.sum(Scan.total_vulns).label("total_vulns"),
            func.sum(Scan.fixable_vulns).label("fixable_vulns"),
            func.sum(Scan.critical_count).label("critical_vulns"),
            func.sum(Scan.high_count).label("high_vulns"),
            func.sum(Scan.scan_duration_seconds).label("duration_total"),
            func.count(Scan.scan_duration_seconds).label("duration_samples"),
        )
        .where(Scan.scan_date >= start_at)
        .group_by(day_expr)
        .order_by(day_expr)
    )

    result = await db.execute(stmt)
    rows = result.all()

    trend_points: list[_TrendPoint] = []
    public_series: list[dict[str, Any]] = []

    summary = {
        "total_scans": 0,
        "completed_scans": 0,
        "failed_scans": 0,
        "total_vulns": 0,
        "fixable_vulns": 0,
        "critical_vulns": 0,
        "high_vulns": 0,
        "duration_total": 0.0,
        "duration_samples": 0,
    }

    for row in rows:
        day_value = row.day
        if isinstance(day_value, date):
            day_obj = day_value
        else:
            # SQLite returns ISO strings from date() extraction
            day_obj = date.fromisoformat(str(day_value))

        duration_total = float(row.duration_total or 0.0)
        duration_samples = int(row.duration_samples or 0)
        avg_duration = duration_total / duration_samples if duration_samples > 0 else None

        payload = {
            "date": day_obj.isoformat(),
            "total_scans": int(row.total_scans or 0),
            "completed_scans": int(row.completed_scans or 0),
            "failed_scans": int(row.failed_scans or 0),
            "total_vulns": int(row.total_vulns or 0),
            "fixable_vulns": int(row.fixable_vulns or 0),
            "critical_vulns": int(row.critical_vulns or 0),
            "high_vulns": int(row.high_vulns or 0),
            "avg_duration_seconds": avg_duration,
            "duration_seconds_total": duration_total,
            "duration_samples": duration_samples,
        }

        trend_points.append(_TrendPoint(day=day_obj, payload=payload))
        public_series.append(
            {
                k: v
                for k, v in payload.items()
                if k not in {"duration_seconds_total", "duration_samples"}
            }
        )

        summary["total_scans"] += payload["total_scans"]
        summary["completed_scans"] += payload["completed_scans"]
        summary["failed_scans"] += payload["failed_scans"]
        summary["total_vulns"] += payload["total_vulns"]
        summary["fixable_vulns"] += payload["fixable_vulns"]
        summary["critical_vulns"] += payload["critical_vulns"]
        summary["high_vulns"] += payload["high_vulns"]
        summary["duration_total"] += duration_total
        summary["duration_samples"] += duration_samples

    summary_avg_duration = (
        summary["duration_total"] / summary["duration_samples"]
        if summary["duration_samples"] > 0
        else None
    )

    # Calculate velocity insights using the last 7 days vs the preceding 7 days.
    today = now.date()
    current_period_end = today
    current_period_start = today - timedelta(days=6)
    previous_period_end = current_period_start - timedelta(days=1)
    previous_period_start = previous_period_end - timedelta(days=6)

    current_stats = _sum_period(trend_points, current_period_start, current_period_end)
    previous_stats = _sum_period(trend_points, previous_period_start, previous_period_end)

    current_duration_avg = (
        current_stats["duration_total"] / current_stats["duration_samples"]
        if current_stats["duration_samples"] > 0
        else None
    )
    previous_duration_avg = (
        previous_stats["duration_total"] / previous_stats["duration_samples"]
        if previous_stats["duration_samples"] > 0
        else None
    )

    velocity = {
        "completed_scans": {
            "current": current_stats["completed_scans"],
            "previous": previous_stats["completed_scans"],
            "delta": current_stats["completed_scans"] - previous_stats["completed_scans"],
            "percent_change": _percent_change(
                previous_stats["completed_scans"], current_stats["completed_scans"]
            ),
        },
        "fixable_vulns": {
            "current": current_stats["fixable_vulns"],
            "previous": previous_stats["fixable_vulns"],
            "delta": current_stats["fixable_vulns"] - previous_stats["fixable_vulns"],
            "percent_change": _percent_change(
                previous_stats["fixable_vulns"], current_stats["fixable_vulns"]
            ),
        },
        "avg_duration_seconds": {
            "current": current_duration_avg,
            "previous": previous_duration_avg,
            "delta": (
                (current_duration_avg - previous_duration_avg)
                if current_duration_avg is not None and previous_duration_avg is not None
                else None
            ),
            "percent_change": _percent_change(previous_duration_avg, current_duration_avg),
        },
    }

    return {
        "window_days": window_days,
        "series": public_series,
        "summary": {
            "total_scans": summary["total_scans"],
            "completed_scans": summary["completed_scans"],
            "failed_scans": summary["failed_scans"],
            "total_vulns": summary["total_vulns"],
            "fixable_vulns": summary["fixable_vulns"],
            "critical_vulns": summary["critical_vulns"],
            "high_vulns": summary["high_vulns"],
            "avg_duration_seconds": summary_avg_duration,
        },
        "velocity": velocity,
    }
