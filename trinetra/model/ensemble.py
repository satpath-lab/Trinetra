"""Combines the IsolationForest global anomaly score and the peer-group
role-deviation score into one 0-100 risk score."""
from __future__ import annotations

import pandas as pd

from .isolation_forest import IsolationForestModel
from .peer_group import PeerGroupModel


class EnsembleRiskModel:
    def __init__(self, cfg):
        self.cfg = cfg
        self.if_model = IsolationForestModel(cfg)
        self.peer_model = PeerGroupModel(cfg)

    def fit(self, X: pd.DataFrame, roles: pd.Series) -> "EnsembleRiskModel":
        self.if_model.fit(X)
        self.peer_model.fit(X, roles)
        return self

    def score(self, X: pd.DataFrame, roles: pd.Series) -> pd.DataFrame:
        if_score = self.if_model.score(X)
        peer_score = self.peer_model.score(X, roles)
        w = self.cfg.ENSEMBLE_WEIGHTS
        risk_score = w["isolation_forest"] * if_score + w["peer_group"] * peer_score
        return pd.DataFrame({
            "isolation_forest_score": if_score,
            "peer_group_score": peer_score,
            "risk_score": risk_score,
        }, index=X.index)
