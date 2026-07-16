"""End-to-end orchestration: load data -> engineer features -> fit the
ensemble -> produce final risk scores. Kept as a single function so later
phases (step-up auth, quarantine, JIT credentials, PQC audit trail) can
call `run_pipeline(cfg)` and consume `result` without knowing internals.

Train/test split: the ensemble is fit ONLY on the training window
(cfg.TRAIN_DAYS, a period the data generator keeps genuinely malicious-free
- see trinetra.data.synthetic). The test window is scored purely
out-of-sample using those fitted baselines. Detection-quality metrics are
computed on the test split only; train-split metrics would be in-sample
and misleadingly optimistic.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from trinetra.data.loader import load_dataset
from trinetra.features.engineer import build_feature_matrix
from trinetra.model.ensemble import EnsembleRiskModel
from trinetra.scoring.risk_score import finalize_scores, evaluate_against_labels


def run_pipeline(cfg) -> dict:
    dataset = load_dataset(cfg)
    features_df = build_feature_matrix(dataset["user_day"], cfg)

    split_date = pd.Timestamp(cfg.SIM_START_DATE) + pd.Timedelta(days=cfg.TRAIN_DAYS)
    features_df["split"] = np.where(features_df["date"] < split_date, "train", "test")
    train_mask = features_df["split"] == "train"

    model = EnsembleRiskModel(cfg)
    model.fit(features_df.loc[train_mask, cfg.FEATURE_COLUMNS], features_df.loc[train_mask, "role"])

    ensemble_scores = model.score(features_df[cfg.FEATURE_COLUMNS], features_df["role"])
    result = finalize_scores(features_df, cfg.FEATURE_COLUMNS, ensemble_scores, model.peer_model, cfg)

    test_result = result[result["split"] == "test"]
    train_result = result[result["split"] == "train"]
    eval_metrics = evaluate_against_labels(test_result)
    train_false_positive_rate = float((train_result["risk_tier"].isin(["High", "Critical"])).mean())

    return {
        "dataset": dataset,
        "features_df": features_df,
        "model": model,
        "result": result,
        "eval_metrics": eval_metrics,
        "split_date": split_date,
        "train_false_positive_rate": train_false_positive_rate,
    }
