#!/usr/bin/env python3
"""
Trinetra - Phase 2: quantum-safe vault + tamper-evident audit log, wired
to the phase-1 risk tiers.

Run: python3 run_vault_demo.py
"""
from collections import Counter

import config
from trinetra.pipeline import run_pipeline
from trinetra.audit.log import AuditLog
from trinetra.vault.secrets_store import seed_demo_vault
from trinetra.vault.leases import LeaseManager, LeaseAlreadyRedeemedError
from trinetra.access_control.policy import AccessControlPolicy, run_policy_over_sessions
from trinetra.access_control.metrics import compute_quarantine_precision


def _print_header(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def main():
    print("Trinetra - Phase 2: Quantum-Safe Vault + Tamper-Evident Audit Log")
    print("Wiring phase-1 risk tiers to real access-control actions, over the")
    print("test/held-out split (the 'live monitoring' period after baseline calibration).")

    print("\nRunning phase-1 pipeline...")
    out = run_pipeline(config)
    result = out["result"]
    test_sessions_df = result[result["split"] == "test"].sort_values("date")
    test_sessions = test_sessions_df.to_dict("records")
    print(f"  {len(test_sessions)} held-out sessions to process.")

    _print_header("VAULT SETUP - hybrid ML-KEM-768 + X25519 envelope encryption")
    vault = seed_demo_vault(config)
    for meta in vault.list_secrets():
        print(f"  {meta.secret_id:28s} ({meta.system:20s}) - role: {meta.required_role}")

    audit_log = AuditLog()  # generates its own ML-DSA-65 signing key
    print("\n  Audit log signing key: ML-DSA-65 (every entry individually signed + hash-chained)")

    lease_manager = LeaseManager(vault, audit_log, default_ttl_seconds=300)
    policy = AccessControlPolicy(config, vault, lease_manager, audit_log)

    _print_header("PROCESSING SESSIONS THROUGH THE RISK-TIER POLICY")
    decisions = run_policy_over_sessions(test_sessions_df, policy, lease_manager)
    action_counts = Counter(d.action for d in decisions)
    tier_counts = Counter(d.risk_tier for d in decisions)
    quarantine_decisions = [d for d in decisions if d.quarantined]

    print(f"  Processed {len(test_sessions)} sessions.")
    print(f"  Risk tiers:     {dict(tier_counts)}")
    print(f"  Actions taken:")
    for action, count in action_counts.most_common():
        print(f"    - {action:32s} {count}")

    _print_header(f"QUARANTINE EVENTS ({len(quarantine_decisions)})")
    for d in quarantine_decisions[:10]:
        print(f"  {d.user:10s} | {d.role:38s} | {d.date} | tier={d.risk_tier:8s} "
              f"score={d.risk_score:5.1f} | {d.action}")
    if len(quarantine_decisions) > 10:
        print(f"  ... and {len(quarantine_decisions) - 10} more")

    _print_header("LIVE DEMO: QUARANTINE RESUME REQUIRES SECOND-PERSON APPROVAL")
    if quarantine_decisions:
        d = quarantine_decisions[-1]
        user, role = d.user, d.role
        print(f"  {user} ({role}) is quarantined - tier={d.risk_tier}, score={d.risk_score:.1f}, action={d.action}")

        print("\n  Attempt 1: resume with self-approval (must be rejected)")
        try:
            policy.resume_from_quarantine(user, role, approver=user)
            print("    UNEXPECTED: this should have failed")
        except PermissionError as e:
            print(f"    DENIED (as expected): {e}")

        print("\n  Attempt 2: resume with a named second-person approver")
        lease = policy.resume_from_quarantine(user, role, approver="security_lead_priya", ttl_seconds=120)
        print(f"    APPROVED. Fresh JIT lease issued: {lease.lease_id} (TTL 120s, single-use)")
        secret = lease_manager.redeem_lease(lease.lease_id)
        print(f"    Lease redeemed - secret released for this one use: {secret[:45]}...")

        print("\n  Attempt 3: redeem the SAME lease again (must fail - single-use)")
        try:
            lease_manager.redeem_lease(lease.lease_id)
            print("    UNEXPECTED: replay should have failed")
        except LeaseAlreadyRedeemedError as e:
            print(f"    DENIED (as expected): {e}")
    else:
        print("  No quarantine events in this run - nothing to resume.")

    _print_header("AUDIT LOG INTEGRITY - BEFORE TAMPERING")
    print(f"  Total signed entries: {len(audit_log.records)}")
    results = audit_log.verify_all()
    ok_count = sum(1 for _, ok, _ in results if ok)
    print(f"  Verified OK: {ok_count}/{len(results)}")

    _print_header("LIVE DEMO: TAMPERING WITH ONE PAST LOG ENTRY")
    target = next(
        (r for r in audit_log.records
         if r.event_type == "session_scored" and r.payload.get("risk_tier") == "Critical"),
        audit_log.records[0],
    )
    original_score = target.payload.get("risk_score")
    print(f"  Entry #{target.seq}: {target.event_type}  user={target.payload.get('user')}  "
          f"risk_score={original_score}  tier={target.payload.get('risk_tier')}")
    print("  Simulating an attacker editing the log file at rest - e.g. hiding a Critical")
    print("  finding as harmless - WITHOUT access to the ML-DSA-65 signing key:")
    target.payload["risk_score"] = 1.0
    print(f"    entry #{target.seq}.payload['risk_score']: {original_score} -> 1.0 (tampered)")

    print(f"\n  Re-verifying entry #{target.seq}...")
    try:
        audit_log.verify_record(target)
        print("    UNEXPECTED: tampering was not detected!")
    except Exception as e:
        print(f"    TAMPER DETECTED - {type(e).__name__}")
        print("    The stored ML-DSA-65 signature no longer matches this entry's content.")
        print("    An attacker without the signing key cannot edit the log undetected.")

    print("\n  Full-log re-verification after tampering:")
    results_after = audit_log.verify_all()
    failures = [(seq, err) for seq, ok, err in results_after if not ok]
    print(f"    {len(results_after) - len(failures)}/{len(results_after)} entries still verify correctly")
    print(f"    {len(failures)} entry flagged as tampered: {failures}")

    target.payload["risk_score"] = original_score
    assert all(ok for _, ok, _ in audit_log.verify_all()), "restore failed to fully undo the tamper"

    _print_header("LIVE DEMO: DELETING A PAST LOG ENTRY ENTIRELY (not just editing a field)")
    print("  A field-edit is caught by the signature check on that one entry. Deletion is a")
    print("  different attack - the entry itself is gone, so there's no signature left to check.")
    print("  This is caught instead by re-walking the prev_hash chain: the next surviving entry's")
    print("  prev_hash no longer matches its new (different) predecessor.")
    delete_idx = len(audit_log.records) // 2
    deleted = audit_log.records[delete_idx]
    print(f"\n  Deleting entry #{deleted.seq} ({deleted.event_type}, user={deleted.payload.get('user')}) "
          f"from the log entirely...")
    del audit_log.records[delete_idx]

    results_after_delete = audit_log.verify_all()
    chain_breaks = [(seq, err) for seq, ok, err in results_after_delete if not ok]
    print(f"\n  Full-log re-verification after deletion:")
    print(f"    {len(results_after_delete) - len(chain_breaks)}/{len(results_after_delete)} entries still verify correctly")
    print(f"    {len(chain_breaks)} chain break(s) detected: {chain_breaks}")
    print("    (each flagged entry's OWN signature is still valid - the break is in prev_hash")
    print("     linkage to its predecessor, which is exactly what a deleted-entry attack breaks)")

    _print_header("BUSINESS METRIC: PRECISION WITHIN THE AUTO-QUARANTINE POPULATION")
    m = compute_quarantine_precision(test_sessions_df, quarantine_decisions)
    print(f"  Total quarantined (Critical auto-quarantine + High escalated-from-failed-stepup): {m['n_quarantined']}")
    print(f"    - Critical auto-quarantine:              {m['n_critical_only']}")
    print(f"    - High, escalated after failed step-up:  {m['n_escalated_high']}  "
          f"(step-up outcome is a random ~3% simulated failure rate - ordinary MFA friction, "
          f"NOT tied to ground truth)")
    print(f"  Truly malicious among all quarantined: {m['n_malicious_quarantined']}/{m['n_quarantined']} "
          f"= {m['blended_precision']:.1%} precision")
    print(f"  False lockouts (legitimate employees quarantined): {m['n_quarantined'] - m['n_malicious_quarantined']} "
          f"({1 - m['blended_precision']:.1%})")
    print(f"\n  For comparison, Critical-tier-only precision: {m['n_malicious_critical_only']}/{m['n_critical_only']} "
          f"= {m['critical_only_precision']:.1%}")
    print(f"  The escalated-from-High group contributes 0 additional true positives here (step-up")
    print(f"  failure is uncorrelated with actual risk in this simulation), which is why blended")
    print(f"  precision is lower than Critical-only - an honest number, not a rounding artifact.")

    _print_header("Done - phase-2 vault + audit log wired to phase-1 risk tiers.")


if __name__ == "__main__":
    main()
