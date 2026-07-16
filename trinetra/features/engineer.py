"""
Per-user-day feature engineering.

Turns the aggregated `user_day` table (from trinetra.data.loader) into a
numeric feature matrix. Every feature here is a *behavioral* signal, not a
label - deviation is judged later by the model layer (IsolationForest for
global point anomalies, peer-group centroid distance for role-normalized
deviation), so a feature being "high" isn't itself flagged as bad here.
"""
from __future__ import annotations

import math
from collections import Counter, deque

import numpy as np
import pandas as pd


def _shannon_entropy(values) -> float:
    if len(values) == 0:
        return 0.0
    counts = Counter(values)
    total = sum(counts.values())
    h = 0.0
    for c in counts.values():
        p = c / total
        h -= p * math.log2(p)
    return h


def _rolling_hour_entropy(user_day: pd.DataFrame, window_days: int) -> pd.Series:
    out = np.zeros(len(user_day))
    for user, grp in user_day.groupby("user"):
        idx = grp.index.to_numpy()
        dates = grp["date"].to_numpy()
        hours_lists = grp["hours"].tolist()
        window = deque()  # holds (date, hours_list)
        for i, (date, hours) in enumerate(zip(dates, hours_lists)):
            window.append((date, hours))
            cutoff = date - np.timedelta64(window_days, "D")
            while window[0][0] <= cutoff:
                window.popleft()
            all_hours = [h for _, hl in window for h in hl]
            out[idx[i]] = _shannon_entropy(all_hours)
    return pd.Series(out, index=user_day.index)


def _rolling_dow_entropy(user_day: pd.DataFrame, window_days: int) -> pd.Series:
    out = np.zeros(len(user_day))
    for user, grp in user_day.groupby("user"):
        idx = grp.index.to_numpy()
        dates = grp["date"].to_numpy()
        dows = pd.to_datetime(grp["date"]).dt.dayofweek.to_numpy()
        window = deque()  # holds (date, dow)
        for i, (date, dow) in enumerate(zip(dates, dows)):
            window.append((date, dow))
            cutoff = date - np.timedelta64(window_days, "D")
            while window[0][0] <= cutoff:
                window.popleft()
            all_dows = [d for _, d in window]
            out[idx[i]] = _shannon_entropy(all_dows)
    return pd.Series(out, index=user_day.index)


def _after_hours_ratio(user_day: pd.DataFrame, business_hours) -> pd.Series:
    lo, hi = business_hours

    def ratio(hours):
        if not hours:
            return 0.0
        outside = sum(1 for h in hours if h < lo or h >= hi)
        return outside / len(hours)

    return user_day["hours"].apply(ratio)


def _new_host_device_flags(user_day: pd.DataFrame, warmup_days: int) -> pd.DataFrame:
    new_host = np.zeros(len(user_day), dtype=int)
    new_device = np.zeros(len(user_day), dtype=int)
    for user, grp in user_day.groupby("user"):
        idx = grp.index.to_numpy()
        dates = grp["date"].tolist()
        pcs_lists = grp["pcs_used"].tolist()
        dev_lists = grp["devices_used"].tolist()
        first_date = dates[0]
        seen_pcs, seen_devices = set(), set()
        for i in range(len(idx)):
            in_warmup = (dates[i] - first_date).days < warmup_days
            today_pcs = set(pcs_lists[i])
            today_devs = set(dev_lists[i])
            if not in_warmup:
                if today_pcs - seen_pcs:
                    new_host[idx[i]] = 1
                if today_devs - seen_devices:
                    new_device[idx[i]] = 1
            seen_pcs |= today_pcs
            seen_devices |= today_devs
    return pd.DataFrame({"new_host_flag": new_host, "new_device_flag": new_device}, index=user_day.index)


def _bigram_rarity(sequences: pd.Series) -> pd.Series:
    """Population-wide bigram frequency -> mean rarity per row.
    Rarity of a bigram = -log2(count / total_count); rows with fewer than
    two events in the sequence get 0.0 (no signal, not "safe")."""
    counter = Counter()
    row_bigrams = []
    for seq in sequences:
        bigrams = list(zip(seq[:-1], seq[1:])) if len(seq) >= 2 else []
        row_bigrams.append(bigrams)
        counter.update(bigrams)
    total = sum(counter.values())
    if total == 0:
        return pd.Series(0.0, index=sequences.index)

    def rarity(bigrams):
        if not bigrams:
            return 0.0
        scores = [-math.log2(counter[b] / total) for b in bigrams]
        return float(np.mean(scores))

    return pd.Series([rarity(b) for b in row_bigrams], index=sequences.index)


def build_feature_matrix(user_day: pd.DataFrame, cfg) -> pd.DataFrame:
    df = user_day.sort_values(["user", "date"]).reset_index(drop=True)

    df["hour_entropy_7d"] = _rolling_hour_entropy(df, cfg.HOUR_ENTROPY_WINDOW_DAYS)
    df["dow_entropy_30d"] = _rolling_dow_entropy(df, cfg.DOW_ENTROPY_WINDOW_DAYS)
    df["after_hours_ratio"] = _after_hours_ratio(df, cfg.BUSINESS_HOURS)
    # session_duration_min already present from loader

    df["data_volume_mb"] = df["file_volume_mb"] + df["email_volume_mb"] + df["http_export_mb"]
    df["export_volume_mb"] = df["export_volume_mb"] + df["http_export_mb"]

    flags = _new_host_device_flags(df, cfg.WARMUP_DAYS)
    df["new_host_flag"] = flags["new_host_flag"]
    df["new_device_flag"] = flags["new_device_flag"]

    df["url_bigram_rarity"] = _bigram_rarity(df["url_sequence"])
    df["file_bigram_rarity"] = _bigram_rarity(df["file_activity_sequence"])

    id_cols = ["user", "role", "date", "is_malicious", "scenario_id"]
    keep = id_cols + cfg.FEATURE_COLUMNS
    return df[keep].copy()
