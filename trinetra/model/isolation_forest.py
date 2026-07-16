"""Global point-anomaly detector: IsolationForest over the scaled feature
matrix, normalized to a 0-100 score via percentile rank against the
fit-time score distribution."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .calibration import robust_baseline_scale, excess_over_baseline_score


class IsolationForestModel:
    def __init__(self, cfg):
        self.cfg = cfg
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=cfg.ISOLATION_FOREST_N_ESTIMATORS,
            contamination=cfg.ISOLATION_FOREST_CONTAMINATION,
            random_state=cfg.RANDOM_SEED,
        )
        self._baseline = None
        self._scale = None

    def fit(self, X: pd.DataFrame) -> "IsolationForestModel":
        Xs = self.scaler.fit_transform(X.values)
        self.model.fit(Xs)
        raw = -self.model.score_samples(Xs)  # higher = more anomalous
        self._baseline, self._scale = robust_baseline_scale(raw)
        return self

    def raw_anomaly_score(self, X: pd.DataFrame) -> np.ndarray:
        Xs = self.scaler.transform(X.values)
        return -self.model.score_samples(Xs)

    def score(self, X: pd.DataFrame) -> np.ndarray:
        """0-100, calibrated against the robust (median/MAD) baseline of
        the fit-time anomaly-score distribution - not a percentile rank,
        so the fraction of any given batch that scores high reflects how
        anomalous it actually is, not a fixed top-K%."""
        raw = self.raw_anomaly_score(X)
        return excess_over_baseline_score(raw, self._baseline, self._scale, self.cfg.ISOLATION_FOREST_RISK_K)
