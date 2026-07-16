"""
Business metrics computed from SessionDecision results. Shared by the CLI
demo (run_vault_demo.py) and the Streamlit dashboard (app.py) so the two
never drift apart - one computation, two views.
"""
from __future__ import annotations

import pandas as pd


def compute_quarantine_precision(test_sessions: pd.DataFrame, decisions: list) -> dict:
    """decisions: list of access_control.policy.SessionDecision, one per
    row of test_sessions (same order). Precision = fraction of everyone
    actually locked out who was truly malicious per ground truth - shown
    both blended (Critical + High-escalated) and Critical-tier alone,
    since they can differ meaningfully."""
    malicious_lookup = {
        (row["user"], str(row["date"])): bool(row["is_malicious"])
        for row in test_sessions.to_dict("records")
    }

    quarantined = [d for d in decisions if d.quarantined]
    n_quarantined = len(quarantined)
    n_malicious_quarantined = sum(1 for d in quarantined if malicious_lookup.get((d.user, str(d.date)), False))

    critical_only = [d for d in quarantined if d.action == "auto_quarantined"]
    n_mal_critical_only = sum(1 for d in critical_only if malicious_lookup.get((d.user, str(d.date)), False))

    escalated_high = [d for d in quarantined if d.action == "quarantined_after_failed_stepup"]

    return {
        "n_quarantined": n_quarantined,
        "n_malicious_quarantined": n_malicious_quarantined,
        "blended_precision": (n_malicious_quarantined / n_quarantined) if n_quarantined else None,
        "n_critical_only": len(critical_only),
        "n_malicious_critical_only": n_mal_critical_only,
        "critical_only_precision": (n_mal_critical_only / len(critical_only)) if critical_only else None,
        "n_escalated_high": len(escalated_high),
    }
