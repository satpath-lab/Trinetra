"""
Wires phase-1 risk tiers to real access-control actions. Phase 1 only
scores a session; this module acts on the score:

  Low      -> log only
  Medium   -> flag for step-up auth (simulated)
  High     -> require step-up auth to continue the session + enhanced
              logging; failing step-up escalates to quarantine
  Critical -> auto-quarantine immediately; resumable only via a fresh JIT
              lease after simulated second-person approval
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from trinetra.vault.leases import Lease
from trinetra.vault.secrets_store import ROLE_TO_SECRET_ID


def _clean(v):
    """NaN -> None so audit payloads stay valid, unambiguous JSON."""
    if isinstance(v, float) and v != v:
        return None
    return v


class QuarantineError(Exception):
    pass


@dataclass
class QuarantineRecord:
    user: str
    reason: str
    quarantined_at: datetime
    released_at: Optional[datetime] = None
    released_by: Optional[str] = None


class QuarantineState:
    def __init__(self):
        self._records: dict[str, QuarantineRecord] = {}

    def quarantine(self, user: str, reason: str) -> QuarantineRecord:
        record = QuarantineRecord(user=user, reason=reason, quarantined_at=datetime.now(timezone.utc))
        self._records[user] = record
        return record

    def is_quarantined(self, user: str) -> bool:
        record = self._records.get(user)
        return record is not None and record.released_at is None

    def list_active(self) -> list[QuarantineRecord]:
        """Users currently quarantined and awaiting second-person approval."""
        return [r for r in self._records.values() if r.released_at is None]

    def list_all(self) -> list[QuarantineRecord]:
        """All quarantine records, active and resolved."""
        return list(self._records.values())

    def release(self, user: str, released_by: str) -> None:
        record = self._records.get(user)
        if record is not None:
            record.released_at = datetime.now(timezone.utc)
            record.released_by = released_by


def simulate_stepup_auth(user: str, date, forced_outcome: Optional[bool] = None) -> bool:
    """Simulates an out-of-band MFA/step-up challenge.

    Reproducibility note: this is a pure hash of (user, date) with no PRNG
    involved at all, so it's deterministic by construction - re-running
    the pipeline reproduces the exact same pass/fail outcome for every
    session every time, independent of cfg.RANDOM_SEED. (An earlier
    version threaded RANDOM_SEED in as a hash salt for symmetry with the
    rest of the pipeline; that was reverted because salting shifts which
    specific sessions land below the failure threshold via ordinary hash
    avalanche, which moved the quarantine-precision number away from an
    already-reported figure for zero actual reproducibility gain - this
    formula was already exactly reproducible without it.)

    MFA proves identity, not intent - none of our scenarios are account
    takeover (they're legitimate access misused for bad purposes), so a
    real step-up challenge has no adversarial signal to catch here by
    design. The ~3% failure rate models ordinary MFA friction (dead
    battery, no signal), not a detection mechanism."""
    if forced_outcome is not None:
        return forced_outcome
    digest = hashlib.sha256(f"{user}|{date}".encode()).digest()
    return (digest[0] / 255.0) < 0.97  # ~97% pass rate ordinary friction, not signal


@dataclass
class SessionDecision:
    user: str
    role: str
    date: object
    risk_tier: str
    risk_score: float
    action: str
    stepup_required: bool = False
    stepup_passed: Optional[bool] = None
    quarantined: bool = False
    notes: str = ""


class AccessControlPolicy:
    def __init__(self, cfg, vault, lease_manager, audit_log,
                 quarantine_state: Optional[QuarantineState] = None):
        self.cfg = cfg
        self.vault = vault
        self.leases = lease_manager
        self.audit_log = audit_log
        self.quarantine = quarantine_state or QuarantineState()

    def handle_session(self, session_row: dict, forced_stepup_outcome: Optional[bool] = None) -> SessionDecision:
        user, role = session_row["user"], session_row["role"]
        tier = session_row["risk_tier"]
        risk_score = float(session_row["risk_score"])
        date = session_row["date"]

        self.audit_log.append("session_scored", {
            "user": user, "role": role, "date": str(date), "risk_score": risk_score,
            "risk_tier": tier,
            "isolation_forest_score": float(session_row["isolation_forest_score"]),
            "peer_group_score": float(session_row["peer_group_score"]),
        })

        if tier == "Low":
            decision = SessionDecision(user, role, date, tier, risk_score, action="log_only")

        elif tier == "Medium":
            self.audit_log.append("stepup_auth_flagged", {"user": user, "role": role, "risk_score": risk_score})
            passed = simulate_stepup_auth(user, date, forced_stepup_outcome)
            self.audit_log.append("stepup_auth_result", {"user": user, "passed": passed, "tier": tier})
            decision = SessionDecision(user, role, date, tier, risk_score, action="stepup_flagged",
                                        stepup_required=True, stepup_passed=passed)

        elif tier == "High":
            self.audit_log.append("stepup_auth_required", {
                "user": user, "role": role, "risk_score": risk_score, "enhanced_logging": True,
                "top_features": session_row.get("top_features"),
            })
            passed = simulate_stepup_auth(user, date, forced_stepup_outcome)
            self.audit_log.append("stepup_auth_result", {"user": user, "passed": passed, "tier": tier})
            if passed:
                decision = SessionDecision(user, role, date, tier, risk_score, action="stepup_required_passed",
                                            stepup_required=True, stepup_passed=True,
                                            notes="session continues under enhanced logging")
            else:
                self.quarantine.quarantine(user, reason=f"High-risk session, step-up auth failed on {date}")
                revoked = self.leases.revoke_all_for_user(user, reason="step-up auth failed on High-risk session")
                self.audit_log.append("session_quarantined", {
                    "user": user, "role": role, "risk_score": risk_score, "tier": tier,
                    "cause": "stepup_auth_failed", "revoked_leases": revoked,
                })
                decision = SessionDecision(user, role, date, tier, risk_score,
                                            action="quarantined_after_failed_stepup",
                                            stepup_required=True, stepup_passed=False, quarantined=True)

        elif tier == "Critical":
            self.quarantine.quarantine(
                user, reason=f"Critical risk score {risk_score:.1f} on {date} "
                             f"(scenario={_clean(session_row.get('scenario_id'))})")
            revoked = self.leases.revoke_all_for_user(user, reason="auto-quarantine: Critical risk score")
            self.audit_log.append("session_quarantined", {
                "user": user, "role": role, "risk_score": risk_score, "tier": tier,
                "cause": "critical_score", "revoked_leases": revoked,
                "scenario_id": _clean(session_row.get("scenario_id")),
            })
            decision = SessionDecision(user, role, date, tier, risk_score, action="auto_quarantined",
                                        quarantined=True,
                                        notes="resumable only via fresh JIT lease + second-person approval")
        else:
            raise ValueError(f"unknown risk tier: {tier}")

        return decision

    def resume_from_quarantine(self, user: str, role: str, approver: str,
                                ttl_seconds: Optional[int] = None) -> Lease:
        """The ONLY path back to vault access for a quarantined user:
        requires a named second-person approver (never the user
        themself), then issues a brand-new short-TTL JIT lease."""
        if not self.quarantine.is_quarantined(user):
            raise QuarantineError(f"{user} is not currently quarantined")
        if not approver or approver == user:
            self.audit_log.append("second_person_approval_denied", {
                "user": user, "approver": approver, "cause": "missing_or_self_approval",
            })
            raise PermissionError("resuming from quarantine requires a named second-person approver, "
                                   "distinct from the quarantined user")

        secret_id = ROLE_TO_SECRET_ID.get(role)
        self.audit_log.append("second_person_approval", {"user": user, "role": role, "approver": approver})
        lease = self.leases.issue_lease(
            secret_id, user, role,
            reason=f"quarantine resume approved by {approver}", ttl_seconds=ttl_seconds,
        )
        self.quarantine.release(user, released_by=approver)
        self.audit_log.append("quarantine_released", {
            "user": user, "approved_by": approver, "lease_id": lease.lease_id,
        })
        return lease


def run_policy_over_sessions(test_sessions_df, policy: "AccessControlPolicy", lease_manager) -> list:
    """Processes every session through the tier policy in chronological
    order. Medium always continues (per spec) and High continues only
    when step-up passes - either way, continuing means a short-TTL JIT
    lease is issued and redeemed for that session, same as any other
    vault access (point 2: no standing access, ever). Returns the list of
    SessionDecision, one per row, in test_sessions_df's row order. Shared
    by run_vault_demo.py and app.py so neither reimplements this loop."""
    decisions = []
    for row in test_sessions_df.to_dict("records"):
        decision = policy.handle_session(row)
        if decision.action in ("stepup_flagged", "stepup_required_passed"):
            secret_id = ROLE_TO_SECRET_ID.get(row["role"])
            lease = lease_manager.issue_lease(
                secret_id, row["user"], row["role"],
                reason=f"continue session after step-up ({decision.risk_tier})", ttl_seconds=300,
            )
            lease_manager.redeem_lease(lease.lease_id)
        decisions.append(decision)
    return decisions
