"""Peer-group deviation model: users are grouped by their assigned banking
role (the role IS the peer group - no clustering needed), and each
session is scored by its Mahalanobis distance from that role's behavioral
centroid. This catches "normal for the org, abnormal for a Branch Ops
Manager" cases that a global-only model would miss.

Fit uses the full population (labels aren't available at fit time in a
real deployment); the injected malicious rate (~0.4%) is too small to
meaningfully distort a role's centroid.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .calibration import robust_baseline_scale, excess_over_baseline_score


def _mahalanobis(X: np.ndarray, mean: np.ndarray, cov_inv: np.ndarray) -> np.ndarray:
    diff = X - mean
    return np.sqrt(np.maximum(np.einsum("ij,jk,ik->i", diff, cov_inv, diff), 0))


class PeerGroupModel:
    def __init__(self, cfg):
        self.cfg = cfg
        self.role_stats: dict[str, dict] = {}
        self.population_std: np.ndarray | None = None

    def fit(self, X: pd.DataFrame, roles: pd.Series) -> "PeerGroupModel":
        # Cross-role std, used only downstream (scoring/risk_score.py) as a
        # floor on a role's own std in the feature-contribution breakdown -
        # never in Mahalanobis distance / risk_score itself.
        self.population_std = X.values.std(axis=0)
        for role in roles.unique():
            Xr = X.loc[(roles == role).values].values
            mean = Xr.mean(axis=0)
            std = Xr.std(axis=0)
            cov = np.cov(Xr, rowvar=False)
            cov = cov + np.eye(cov.shape[0]) * self.cfg.PEER_GROUP_COV_REGULARIZATION
            cov_inv = np.linalg.inv(cov)
            dists = _mahalanobis(Xr, mean, cov_inv)
            baseline, scale = robust_baseline_scale(dists)
            self.role_stats[role] = {
                "mean": mean, "std": std, "cov_inv": cov_inv,
                "baseline": baseline, "scale": scale,
            }
        return self

    def score(self, X: pd.DataFrame, roles: pd.Series) -> np.ndarray:
        """0-100, calibrated against the robust (median/MAD) baseline of
        each role's fit-time distance distribution - not a percentile
        rank, so tier membership reflects genuine rarity."""
        out = np.zeros(len(X))
        for role in roles.unique():
            mask = (roles == role).values
            stats = self.role_stats[role]
            d = _mahalanobis(X.loc[mask].values, stats["mean"], stats["cov_inv"])
            out[mask] = excess_over_baseline_score(d, stats["baseline"], stats["scale"], self.cfg.PEER_GROUP_RISK_K)
        return out
