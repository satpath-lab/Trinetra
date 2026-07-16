"""Shared score calibration for the ensemble's two components.

Percentile-rank scoring against the same batch being scored guarantees a
fixed fraction of any batch lands above a given threshold, regardless of
how anomalous it actually is - useless for an "is this actually rare"
risk tier. Instead we calibrate against a robust (median/MAD) baseline of
the fit-time distribution and squash the excess above it, so a score only
approaches 100 when a session is genuinely far outside its reference
distribution, not merely "in the worse 15% of today's batch".
"""
from __future__ import annotations

import numpy as np


def robust_baseline_scale(values: np.ndarray) -> tuple[float, float]:
    median = float(np.median(values))
    mad = float(np.median(np.abs(values - median)))
    scale = mad * 1.4826 if mad > 0 else (float(np.std(values)) or 1.0)
    return median, scale


def excess_over_baseline_score(raw: np.ndarray, baseline: float, scale: float, k: float) -> np.ndarray:
    """0 at/below baseline, approaching 100 as raw grows many scale
    (robust-sigma-equivalent) units past it. `k` sets how many such units
    are needed before the score meaningfully takes off."""
    excess = np.maximum(0.0, raw - baseline) / (k * max(scale, 1e-9))
    return np.clip(100 * (1 - np.exp(-excess)), 0, 100)
