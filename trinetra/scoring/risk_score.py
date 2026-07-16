"""Final scoring layer: risk tiers, per-feature contribution breakdown
("why did this score high"), and evaluation against ground-truth labels.

Labels are used here ONLY for evaluation/validation of detection quality
- never for fitting the models - since a real deployment won't have
confirmed insider-threat labels to train on.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, average_precision_score


def _risk_tier(score: float, tiers: list) -> str:
    for lo, hi, label in tiers:
        if lo <= score < hi:
            return label
    return tiers[-1][2]


def _compress_z(z: np.ndarray, threshold: float) -> np.ndarray:
    """Soft-compress |z| above threshold: unchanged below it, grows ~log
    past it instead of linearly. Used only for the pct_contribution split
    below - the raw z-score is preserved separately for display."""
    abs_z = np.abs(z)
    compressed_abs = np.minimum(abs_z, threshold + np.log1p(np.maximum(abs_z - threshold, 0.0)))
    return np.sign(z) * compressed_abs


def compute_feature_contributions(X: pd.DataFrame, roles: pd.Series, peer_model, cfg) -> list:
    """Per-row weighted feature-contribution breakdown, relative to the
    row's own role centroid. Returns a list (aligned to X's row order) of
    lists of {feature, pct_contribution, z_score, z_capped_for_display, direction}.
    z_score is always the raw, uncapped value; only pct_contribution is
    computed from a display-compressed z (see _compress_z)."""
    n = len(X)
    pct_all = np.zeros((n, X.shape[1]))
    z_all = np.zeros((n, X.shape[1]))  # raw, uncapped for display
    weights = np.array([cfg.FEATURE_WEIGHTS[c] for c in X.columns])
    threshold = cfg.CONTRIBUTION_Z_CAP_THRESHOLD

    # Floor a role's per-feature std at a fraction of that feature's
    # population-wide (cross-role) std, not a bare epsilon - otherwise a
    # role with near-zero natural variance for some feature (e.g. Vendor
    # Engineer + export_volume_mb) produces a z-score in the thousands that
    # swamps every other feature in the breakdown. This only affects the
    # explanation below, not risk_score/isolation_forest_score/peer_group_score.
    population_floor = cfg.PEER_GROUP_STD_FLOOR_FRACTION * peer_model.population_std
    population_floor = np.where(population_floor < 1e-9, 1e-9, population_floor)

    for role in roles.unique():
        mask = (roles == role).values
        stats = peer_model.role_stats[role]
        std = np.maximum(stats["std"], population_floor)
        z = (X.loc[mask].values - stats["mean"]) / std
        capped_z = _compress_z(z, threshold)
        weighted = np.abs(capped_z) * weights
        row_sums = weighted.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1.0
        pct = weighted / row_sums * 100
        pct_all[mask] = pct
        z_all[mask] = z  # raw, NOT capped_z

    top_n = cfg.TOP_N_CONTRIBUTING_FEATURES
    columns = list(X.columns)
    contributions = []
    for i in range(n):
        order = np.argsort(-pct_all[i])[:top_n]
        contributions.append([
            {
                "feature": columns[j],
                "pct_contribution": round(float(pct_all[i, j]), 1),
                "z_score": round(float(z_all[i, j]), 2),
                "z_capped_for_display": bool(abs(z_all[i, j]) > threshold),
                "direction": "above peer norm" if z_all[i, j] > 0 else "below peer norm",
            }
            for j in order
        ])
    return contributions


def finalize_scores(features_df: pd.DataFrame, feature_cols: list, ensemble_scores: pd.DataFrame,
                     peer_model, cfg) -> pd.DataFrame:
    X = features_df[feature_cols].reset_index(drop=True)
    roles = features_df["role"].reset_index(drop=True)

    id_cols = ["user", "role", "date", "is_malicious", "scenario_id"]
    if "split" in features_df.columns:
        id_cols.append("split")
    result = features_df[id_cols].reset_index(drop=True).copy()
    result = pd.concat([result, ensemble_scores.reset_index(drop=True)], axis=1)
    result["risk_tier"] = result["risk_score"].apply(lambda s: _risk_tier(s, cfg.RISK_TIERS))
    result["top_features"] = compute_feature_contributions(X, roles, peer_model, cfg)
    return result.sort_values("risk_score", ascending=False).reset_index(drop=True)


def evaluate_against_labels(result: pd.DataFrame) -> dict:
    """Precision/recall-oriented metrics appropriate for a ~240:1 class
    imbalance NOT accuracy, which would be misleadingly high for a
    model that just predicts "normal" for everyone."""
    y_true = result["is_malicious"].astype(int).values
    y_score = result["risk_score"].values
    n = len(result)
    n_malicious = int(y_true.sum())

    metrics = {
        "n_sessions": n,
        "n_malicious_labeled": n_malicious,
        "imbalance_ratio": f"1:{round((n - n_malicious) / max(n_malicious, 1))}",
        "roc_auc": round(float(roc_auc_score(y_true, y_score)), 4) if n_malicious else None,
        "pr_auc": round(float(average_precision_score(y_true, y_score)), 4) if n_malicious else None,
    }

    ordered = result.sort_values("risk_score", ascending=False).reset_index(drop=True)
    for pct in (0.01, 0.02, 0.05):
        k = max(1, int(round(n * pct)))
        top_k = ordered.iloc[:k]
        recall = top_k["is_malicious"].sum() / max(n_malicious, 1)
        precision = top_k["is_malicious"].sum() / k
        metrics[f"recall@top{int(pct*100)}pct"] = round(float(recall), 3)
        metrics[f"precision@top{int(pct*100)}pct"] = round(float(precision), 3)

    return metrics
