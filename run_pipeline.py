#!/usr/bin/env python3
"""
Trinetra - Phase 1: data + detection pipeline.

Run: python3 run_pipeline.py
"""
import pandas as pd

import config
from trinetra.pipeline import run_pipeline


def _print_header(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def _print_top_sessions(result: pd.DataFrame, n: int):
    subset = result.head(n)
    for _, row in subset.iterrows():
        gt = "MALICIOUS (ground truth)" if row["is_malicious"] else "normal (ground truth)"
        print(f"\n  {row['user']:10s} | {row['role']:38s} | {row['date'].date()} [{row['split']}] "
              f"| risk={row['risk_score']:5.1f} [{row['risk_tier']:8s}] | {gt}")
        print(f"    IF={row['isolation_forest_score']:.1f}  Peer={row['peer_group_score']:.1f}  "
              f"scenario={row['scenario_id']}")
        for feat in row["top_features"]:
            cap_note = ", capped for display" if feat["z_capped_for_display"] else ""
            print(f"      - {feat['feature']:22s} {feat['pct_contribution']:5.1f}%  "
                  f"(raw z={feat['z_score']:+.2f}, {feat['direction']}{cap_note})")


def main():
    print("Trinetra - Phase 1: Data + Detection Pipeline")
    print(f"Data source: {'REAL CMU CERT r4.2' if config.USE_REAL_CERT_DATA else 'SYNTHETIC stand-in'}")
    if not config.USE_REAL_CERT_DATA:
        print("  Reason: r4.2 is a 4.82GB archive; at measured ~696KB/s throughput a full fetch")
        print("  would take ~115 min (budget was ~20 min). Kaggle mirrors require an authenticated")
        print("  login unavailable in this environment. Generating a realistic synthetic stand-in.")

    out = run_pipeline(config)
    result = out["result"]
    metrics = out["eval_metrics"]
    directory = out["dataset"]["directory"]
    train_fpr = out["train_false_positive_rate"]

    n_train = int((result["split"] == "train").sum())
    n_test = int((result["split"] == "test").sum())

    _print_header("DATASET SUMMARY")
    print(f"  Users:                 {len(directory)}  across {len(config.BANKING_ROLES)} banking roles")
    for role in config.BANKING_ROLES:
        print(f"    - {role:38s} {int((directory['role'] == role).sum()):4d} users")
    print(f"  Sessions (user-days):  {len(result)}  total")
    print(f"  Malicious-labeled:     {int(result['is_malicious'].sum())}")

    _print_header("TRAIN / TEST SPLIT (chronological)")
    print(f"  Split date:            {out['split_date'].date()}  (day {config.TRAIN_DAYS} of {config.SIM_DAYS})")
    print(f"  Train (baseline) period: {n_train} sessions - model fit here ONLY, and this period")
    print(f"                           is guaranteed malicious-free by the generator's injection")
    print(f"                           window buffer, so it's a genuine clean baseline.")
    print(f"  Test (held-out) period:  {n_test} sessions, scored out-of-sample using train-fitted")
    print(f"                           IsolationForest + peer-group baselines only.")
    print(f"  Sanity check - false positive rate on the clean train period:")
    print(f"    {train_fpr:.2%} of train-period sessions scored High/Critical despite zero")
    print(f"    injected malicious activity there (lower is better; this is NOT a detection metric,")
    print(f"    it's a specificity check on data known to be clean).")

    _print_header("RISK TIER DISTRIBUTION (test / held-out split only)")
    test_result = result[result["split"] == "test"]
    tier_counts = test_result["risk_tier"].value_counts()
    for _, _, label in config.RISK_TIERS:
        print(f"  {label:10s}: {tier_counts.get(label, 0)}")
    high_risk = test_result[test_result["risk_tier"].isin(["High", "Critical"])]
    print(f"\n  >> {len(high_risk)} held-out sessions scored HIGH-RISK (High or Critical tier)")

    _print_header("DETECTION QUALITY - HELD-OUT TEST SPLIT ONLY (never seen during fit/calibration)")
    for k, v in metrics.items():
        print(f"  {k:28s}: {v}")

    _print_header(f"TOP {min(15, len(test_result))} HIGHEST-RISK SESSIONS (test split only)")
    _print_top_sessions(test_result.sort_values("risk_score", ascending=False), n=15)

    n_mal = int(result["is_malicious"].sum())
    _print_header(f"ALL {n_mal} GROUND-TRUTH MALICIOUS SESSIONS - SCORE + WHY")
    mal_sorted = result[result["is_malicious"]].sort_values("risk_score", ascending=False)
    _print_top_sessions(mal_sorted, n=n_mal)

    print("\n" + "=" * 78)
    print("Done.")


if __name__ == "__main__":
    main()
