"""
Trinetra dashboard - live view over phase-1 risk scoring and phase-2
vault/lease/audit-log enforcement.

Every number here is computed live by calling the same trinetra functions
used by run_pipeline.py and run_vault_demo.py: run_pipeline(), the
AccessControlPolicy/LeaseManager/AuditLog classes, and
compute_quarantine_precision(). Nothing is hardcoded or reimplemented.

Run: streamlit run app.py
"""
import json
from collections import Counter

import pandas as pd
import streamlit as st
from cryptography.exceptions import InvalidSignature

import config
from trinetra.pipeline import run_pipeline
from trinetra.audit.log import AuditLog, TamperDetected
from trinetra.vault.secrets_store import seed_demo_vault
from trinetra.vault.leases import LeaseManager
from trinetra.access_control.policy import AccessControlPolicy, run_policy_over_sessions, QuarantineError
from trinetra.access_control.metrics import compute_quarantine_precision

st.set_page_config(page_title="Trinetra", layout="wide", page_icon="\U0001F53A")

ACTION_LABELS = {
    "log_only": "Logged",
    "stepup_flagged": "Step-up flagged",
    "stepup_required_passed": "Step-up required (passed)",
    "quarantined_after_failed_stepup": "Quarantined (step-up failed)",
    "auto_quarantined": "Auto-quarantined",
}
TIER_COLORS = {"Low": "#1e8e3e", "Medium": "#b8860b", "High": "#d2691e", "Critical": "#c0392b"}


@st.cache_resource(show_spinner="Building phase-2 state: running phase-1 pipeline, sealing the vault, "
                                 "and processing every held-out session through the risk-tier policy "
                                 "(one-time, ~45s)...")
def build_state():
    out = run_pipeline(config)
    result = out["result"]
    directory = out["dataset"]["directory"]
    test_sessions_df = result[result["split"] == "test"].sort_values("date").reset_index(drop=True)

    vault = seed_demo_vault(config)
    audit_log = AuditLog()
    lease_manager = LeaseManager(vault, audit_log, default_ttl_seconds=300)
    policy = AccessControlPolicy(config, vault, lease_manager, audit_log)
    decisions = run_policy_over_sessions(test_sessions_df, policy, lease_manager)

    return {
        "eval_metrics": out["eval_metrics"],
        "test_sessions_df": test_sessions_df,
        "vault": vault,
        "audit_log": audit_log,
        "lease_manager": lease_manager,
        "policy": policy,
        "decisions": decisions,
        "user_to_role": dict(zip(directory["user"], directory["role"])),
    }


state = build_state()
test_sessions_df = state["test_sessions_df"]
decisions = state["decisions"]
audit_log = state["audit_log"]
lease_manager = state["lease_manager"]
policy = state["policy"]
eval_metrics = state["eval_metrics"]
user_to_role = state["user_to_role"]

with st.sidebar:
    st.title("\U0001F53A Trinetra")
    st.caption("Insider-threat risk scoring + quantum-safe enforcement")
    st.caption(f"{len(test_sessions_df)} held-out sessions | {len(audit_log.records)} signed audit entries")
    if st.button("\U0001F504 Reset demo state", help="Regenerate a fresh vault, audit log, and re-process all sessions"):
        build_state.clear()
        st.session_state.pop("verify_results", None)
        st.rerun()

st.header("Trinetra - Live Risk Scoring & Quantum-Safe Enforcement")

tier_counts = Counter(d.risk_tier for d in decisions)
precision = compute_quarantine_precision(test_sessions_df, decisions)

tier_cols = st.columns(4)
for i, tier in enumerate(["Low", "Medium", "High", "Critical"]):
    tier_cols[i].metric(f"Tier: {tier}", tier_counts.get(tier, 0))

metric_cols = st.columns(4)
metric_cols[0].metric("ROC-AUC", f"{eval_metrics['roc_auc']:.3f}", help="Held-out test split")
metric_cols[1].metric("PR-AUC", f"{eval_metrics['pr_auc']:.3f}", help="Held-out test split")
metric_cols[2].metric(
    "Quarantine precision - blended",
    f"{precision['blended_precision']:.1%}" if precision["blended_precision"] is not None else "n/a",
    help=f"{precision['n_malicious_quarantined']}/{precision['n_quarantined']} quarantined sessions were "
         f"truly malicious (Critical auto-quarantine + High escalated-from-failed-step-up)",
)
metric_cols[3].metric(
    "Quarantine precision - Critical only",
    f"{precision['critical_only_precision']:.1%}" if precision["critical_only_precision"] is not None else "n/a",
    help=f"{precision['n_malicious_critical_only']}/{precision['n_critical_only']} Critical-tier "
         f"auto-quarantines were truly malicious",
)

st.divider()

tab_feed, tab_quarantine, tab_integrity = st.tabs(
    ["\U0001F4CB Session Feed", "\U0001F512 Quarantine (Maker-Checker)", "\U0001F6E1️ Audit Log Integrity"]
)

# ---------------------------------------------------------------------------
# Tab 1: Session feed
# ---------------------------------------------------------------------------
with tab_feed:
    st.subheader("Held-out sessions")
    tiers_selected = st.multiselect(
        "Filter by tier", ["Low", "Medium", "High", "Critical"],
        default=["Medium", "High", "Critical"],
    )

    tier_series = test_sessions_df["risk_tier"]
    filtered_positions = [i for i, t in enumerate(tier_series) if t in tiers_selected]
    filtered_df = test_sessions_df.iloc[filtered_positions].reset_index(drop=True)
    filtered_decisions = [decisions[i] for i in filtered_positions]

    display_df = pd.DataFrame({
        "date": filtered_df["date"].astype(str).str.slice(0, 10),
        "user": filtered_df["user"],
        "role": filtered_df["role"],
        "risk_score": filtered_df["risk_score"].round(1),
        "risk_tier": filtered_df["risk_tier"],
        "outcome": [ACTION_LABELS.get(d.action, d.action) for d in filtered_decisions],
    })

    def _tier_bg(val):
        color = TIER_COLORS.get(val, "")
        return f"background-color: {color}; color: white" if color else ""

    styled = display_df.style.map(_tier_bg, subset=["risk_tier"])
    event = st.dataframe(
        styled, hide_index=True, on_select="rerun", selection_mode="single-row",
        key="session_feed", height=420, width="stretch",
        column_config={"risk_score": st.column_config.NumberColumn("risk_score", format="%.1f")},
    )

    selected_rows = list(getattr(getattr(event, "selection", None), "rows", []) or [])
    st.caption(f"Showing {len(display_df)} sessions. Click a row to see its feature-contribution breakdown.")

    if selected_rows:
        pos = selected_rows[0]
        full_row = filtered_df.iloc[pos]
        st.markdown(f"### {full_row['user']} --- {full_row['role']} --- {str(full_row['date'])[:10]}")
        st.markdown(
            f"**Risk score:** {full_row['risk_score']:.1f}  |  **Tier:** {full_row['risk_tier']}  |  "
            f"**Isolation Forest:** {full_row['isolation_forest_score']:.1f}  |  "
            f"**Peer-group:** {full_row['peer_group_score']:.1f}"
        )
        feats = full_row["top_features"]
        if feats:
            feat_df = pd.DataFrame(feats).rename(columns={
                "feature": "Feature", "pct_contribution": "Contribution %",
                "z_score": "Raw Z-score", "z_capped_for_display": "Capped for display",
                "direction": "Direction",
            })
            c1, c2 = st.columns([3, 2])
            with c1:
                st.dataframe(feat_df, hide_index=True, width="stretch")
            with c2:
                st.bar_chart(feat_df.set_index("Feature")["Contribution %"])
        else:
            st.caption("No contribution breakdown recorded for this session.")

# ---------------------------------------------------------------------------
# Tab 2: Quarantine maker-checker
# ---------------------------------------------------------------------------
with tab_quarantine:
    st.subheader("Pending quarantine actions")
    active = policy.quarantine.list_active()
    all_records = policy.quarantine.list_all()

    if not active:
        st.success("No sessions currently quarantined.")
    else:
        labels = [f"{r.user}  |  quarantined {r.quarantined_at.strftime('%H:%M:%S')}  |  {r.reason}" for r in active]
        idx = st.selectbox("Select a quarantined session", range(len(active)), format_func=lambda i: labels[i])
        record = active[idx]
        user = record.user
        role = user_to_role.get(user, "Unknown")

        st.info(f"**{user}** ({role}) is quarantined.\n\n**Reason:** {record.reason}")

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Maker-checker guard: self-approval**")
            st.caption("A quarantined user can never approve their own resume.")
            if st.button(f"Attempt self-approval as {user}", key=f"self_{user}_{idx}"):
                try:
                    policy.resume_from_quarantine(user, role, approver=user)
                    st.error("UNEXPECTED: self-approval succeeded (this should never happen)")
                except PermissionError as e:
                    st.warning(f"DENIED (as expected): {e}")

        with col2:
            st.markdown("**Second-person approval**")
            approver = st.text_input(
                "Approver name (must differ from the quarantined user)", key=f"approver_{user}_{idx}"
            )
            if st.button("Approve & issue fresh JIT lease", key=f"approve_{user}_{idx}"):
                try:
                    lease = policy.resume_from_quarantine(user, role, approver=approver, ttl_seconds=120)
                    secret = lease_manager.redeem_lease(lease.lease_id)
                    st.success(
                        f"Approved by {approver}. Fresh lease `{lease.lease_id}` issued (TTL 120s, single-use) "
                        f"and redeemed once: `{secret[:40].decode(errors='replace')}...`"
                    )
                    st.session_state.pop("verify_results", None)
                    st.rerun()
                except PermissionError as e:
                    st.error(f"DENIED: {e}")
                except QuarantineError as e:
                    st.error(f"ERROR: {e}")

    st.divider()
    st.caption(f"Quarantine events so far: {len(all_records)} total "
               f"({len(active)} pending, {len(all_records) - len(active)} resolved)")

# ---------------------------------------------------------------------------
# Tab 3: Audit log integrity
# ---------------------------------------------------------------------------
with tab_integrity:
    st.subheader("Audit log integrity")

    if "verify_results" not in st.session_state:
        with st.spinner(f"Verifying all {len(audit_log.records)} entries..."):
            st.session_state.verify_results = audit_log.verify_all()

    results = st.session_state.verify_results
    ok_count = sum(1 for _, ok, _ in results if ok)
    total = len(results)

    c1, c2, c3 = st.columns(3)
    c1.metric("Total signed entries", total)
    c2.metric("Verified OK", f"{ok_count}/{total}")
    c3.metric("Flagged tampered", total - ok_count)

    if st.button("\U0001F501 Re-verify entire log now"):
        with st.spinner("Re-verifying..."):
            st.session_state.verify_results = audit_log.verify_all()
        st.rerun()

    if total - ok_count > 0:
        st.error(f"Tampering detected in {total - ok_count} entry(ies):")
        for seq, ok, err in results:
            if not ok:
                st.code(f"entry #{seq}: {err}")

    st.divider()
    tamper_col, delete_col = st.columns(2)

    with tamper_col:
        st.markdown("#### ✏️ Tamper with a field (edit in place)")
        st.caption(
            "Edits an entry's payload directly, without re-signing - simulating an attacker who can "
            "edit the log file at rest but doesn't hold the ML-DSA-65 signing key."
        )
        search1 = st.text_input("Search entries by user or event type", key="tamper_search")
        candidates1 = (
            [r for r in audit_log.records
             if search1.lower() in r.event_type.lower() or search1.lower() in str(r.payload.get("user", "")).lower()]
            if search1 else audit_log.records[-30:]
        )[:100]

        if not candidates1:
            st.caption("No matching entries.")
        else:
            labels1 = [f"#{r.seq} {r.event_type} (user={r.payload.get('user', '-')})" for r in candidates1]
            sel1 = st.selectbox("Pick an entry", range(len(candidates1)), format_func=lambda i: labels1[i], key="tamper_pick")
            target = candidates1[sel1]
            edited = st.text_area(
                "Edit payload JSON, then apply", value=json.dumps(target.payload, indent=2, default=str),
                height=160, key=f"tamper_text_{target.seq}",
            )
            if st.button("Apply tamper & re-verify this entry", key="apply_tamper"):
                try:
                    new_payload = json.loads(edited)
                except json.JSONDecodeError as e:
                    st.error(f"Invalid JSON: {e}")
                else:
                    target.payload = new_payload
                    try:
                        audit_log.verify_record(target)
                        st.warning("No tampering detected on this entry (content matches what was signed).")
                    except InvalidSignature:
                        st.error(
                            f"\U0001F6A8 TAMPER DETECTED on entry #{target.seq}: InvalidSignature - the stored "
                            f"ML-DSA-65 signature no longer matches this entry's content."
                        )
                    except TamperDetected as e:
                        st.error(f"\U0001F6A8 TAMPER DETECTED on entry #{target.seq}: {e}")
                    st.session_state.verify_results = audit_log.verify_all()
                    st.rerun()

    with delete_col:
        st.markdown("#### \U0001F5D1️ Delete an entry entirely")
        st.caption(
            "Removes an entry from the log outright. Its own signature is irrelevant since it's gone - "
            "this is caught instead by the NEXT entry's prev_hash no longer matching (a broken hash chain)."
        )
        search2 = st.text_input("Search entries by user or event type", key="delete_search")
        candidates2 = (
            [r for r in audit_log.records
             if search2.lower() in r.event_type.lower() or search2.lower() in str(r.payload.get("user", "")).lower()]
            if search2 else audit_log.records[-30:]
        )[:100]

        if not candidates2:
            st.caption("No matching entries.")
        else:
            labels2 = [f"#{r.seq} {r.event_type} (user={r.payload.get('user', '-')})" for r in candidates2]
            sel2 = st.selectbox("Pick an entry", range(len(candidates2)), format_func=lambda i: labels2[i], key="delete_pick")
            target2 = candidates2[sel2]
            if st.button("Delete this entry & re-verify full chain", key="apply_delete"):
                audit_log.records.remove(target2)
                st.session_state.verify_results = audit_log.verify_all()
                st.rerun()
