"""Shared constants used across repositories and services."""

# Vulnerability statuses excluded from actionable counts and default list views.
# Scan row counts (Scan.critical_count etc.) are immutable historical snapshots
# and are NEVER resynced — only Container counts are actionable.
NON_ACTIONABLE_STATUSES = frozenset({"false_positive", "accepted"})
