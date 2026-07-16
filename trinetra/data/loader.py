"""
Turns raw event logs (logon/device/file/http/email + directory + answers)
into one row per user-day "session" - the unit the rest of the pipeline
scores. Works identically whether the events came from the synthetic
generator or (in a later phase) parsed real CERT CSVs, as long as they
match the schema documented below.

Expected raw schemas
---------------------
logon:  date(ts), user, pc, activity in {Logon, Logoff}
device: date(ts), user, pc, activity in {Connect}, device_id
file:   date(ts), user, pc, filename, activity in {Open,Write,Copy,Delete},
        size_mb, to_removable_media(bool)
http:   date(ts), user, pc, url, domain, category, upload_mb
email:  date(ts), user, pc, to_domain_type in {internal,external}, size_mb, attachments
directory: user, role, hire_date, is_night_shift
answers:   user, role, scenario_id, date
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from . import synthetic as synth


def _calendar_date(series: pd.Series) -> pd.Series:
    return series.dt.normalize()


def _collect_all_user_days(events: dict) -> pd.DataFrame:
    frames = []
    for name, df in events.items():
        if df.empty:
            continue
        frames.append(pd.DataFrame({"user": df["user"], "date": _calendar_date(df["date"])}))
    combined = pd.concat(frames, ignore_index=True).drop_duplicates()
    return combined


def _session_duration(logon: pd.DataFrame, all_user_days: pd.DataFrame) -> pd.DataFrame:
    if logon.empty:
        out = all_user_days.copy()
        out["session_duration_min"] = 0.0
        return out
    l = logon.copy()
    l["cal_date"] = _calendar_date(l["date"])
    grp = l.groupby(["user", "cal_date"])["date"]
    span = grp.agg(["min", "max"]).reset_index()
    span["session_duration_min"] = (span["max"] - span["min"]).dt.total_seconds() / 60.0
    span = span.rename(columns={"cal_date": "date"})[["user", "date", "session_duration_min"]]
    out = all_user_days.merge(span, on=["user", "date"], how="left")
    out["session_duration_min"] = out["session_duration_min"].fillna(0.0)
    return out


def _pcs_used(events: dict, all_user_days: pd.DataFrame) -> pd.DataFrame:
    frames = []
    for name in ("logon", "file", "http", "email", "device"):
        df = events[name]
        if df.empty or "pc" not in df.columns:
            continue
        frames.append(pd.DataFrame({"user": df["user"], "date": _calendar_date(df["date"]), "pc": df["pc"]}))
    combined = pd.concat(frames, ignore_index=True)
    grp = combined.groupby(["user", "date"])["pc"].agg(lambda s: sorted(set(s))).reset_index()
    grp = grp.rename(columns={"pc": "pcs_used"})
    grp["n_pcs_used"] = grp["pcs_used"].apply(len)
    out = all_user_days.merge(grp, on=["user", "date"], how="left")
    out["pcs_used"] = out["pcs_used"].apply(lambda v: v if isinstance(v, list) else [])
    out["n_pcs_used"] = out["n_pcs_used"].fillna(0).astype(int)
    return out


def _device_stats(device: pd.DataFrame, all_user_days: pd.DataFrame) -> pd.DataFrame:
    if device.empty:
        out = all_user_days.copy()
        out["devices_used"] = [[] for _ in range(len(out))]
        out["n_device_connects"] = 0
        return out
    d = device.copy()
    d["date_only"] = _calendar_date(d["date"])
    grp = d.groupby(["user", "date_only"])["device_id"].agg(lambda s: sorted(set(s))).reset_index()
    grp = grp.rename(columns={"date_only": "date", "device_id": "devices_used"})
    grp["n_device_connects"] = grp["devices_used"].apply(len)
    out = all_user_days.merge(grp, on=["user", "date"], how="left")
    out["devices_used"] = out["devices_used"].apply(lambda v: v if isinstance(v, list) else [])
    out["n_device_connects"] = out["n_device_connects"].fillna(0).astype(int)
    return out


def _file_stats(file_df: pd.DataFrame, all_user_days: pd.DataFrame) -> pd.DataFrame:
    if file_df.empty:
        out = all_user_days.copy()
        for col, default in [("n_file_events", 0), ("file_volume_mb", 0.0), ("export_volume_mb", 0.0)]:
            out[col] = default
        out["file_activity_sequence"] = [[] for _ in range(len(out))]
        return out
    f = file_df.sort_values("date").copy()
    f["date_only"] = _calendar_date(f["date"])
    agg = f.groupby(["user", "date_only"]).agg(
        n_file_events=("activity", "count"),
        file_volume_mb=("size_mb", "sum"),
    ).reset_index()
    export = f[f["to_removable_media"]].groupby(["user", "date_only"])["size_mb"].sum().reset_index()
    export = export.rename(columns={"size_mb": "export_volume_mb"})
    seq = f.groupby(["user", "date_only"])["activity"].apply(list).reset_index()
    seq = seq.rename(columns={"activity": "file_activity_sequence"})

    merged = agg.merge(export, on=["user", "date_only"], how="left").merge(seq, on=["user", "date_only"], how="left")
    merged["export_volume_mb"] = merged["export_volume_mb"].fillna(0.0)
    merged = merged.rename(columns={"date_only": "date"})
    out = all_user_days.merge(merged, on=["user", "date"], how="left")
    out["n_file_events"] = out["n_file_events"].fillna(0).astype(int)
    out["file_volume_mb"] = out["file_volume_mb"].fillna(0.0)
    out["export_volume_mb"] = out["export_volume_mb"].fillna(0.0)
    out["file_activity_sequence"] = out["file_activity_sequence"].apply(lambda v: v if isinstance(v, list) else [])
    return out


def _http_stats(http_df: pd.DataFrame, all_user_days: pd.DataFrame) -> pd.DataFrame:
    if http_df.empty:
        out = all_user_days.copy()
        out["n_http_events"] = 0
        out["http_export_mb"] = 0.0
        out["url_sequence"] = [[] for _ in range(len(out))]
        return out
    h = http_df.sort_values("date").copy()
    h["date_only"] = _calendar_date(h["date"])
    agg = h.groupby(["user", "date_only"]).agg(
        n_http_events=("url", "count"),
        http_export_mb=("upload_mb", "sum"),
    ).reset_index()
    seq = h.groupby(["user", "date_only"])["domain"].apply(list).reset_index()
    seq = seq.rename(columns={"domain": "url_sequence"})
    merged = agg.merge(seq, on=["user", "date_only"], how="left").rename(columns={"date_only": "date"})
    out = all_user_days.merge(merged, on=["user", "date"], how="left")
    out["n_http_events"] = out["n_http_events"].fillna(0).astype(int)
    out["http_export_mb"] = out["http_export_mb"].fillna(0.0)
    out["url_sequence"] = out["url_sequence"].apply(lambda v: v if isinstance(v, list) else [])
    return out


def _email_stats(email_df: pd.DataFrame, all_user_days: pd.DataFrame) -> pd.DataFrame:
    if email_df.empty:
        out = all_user_days.copy()
        out["n_email_events"] = 0
        out["email_volume_mb"] = 0.0
        out["email_external_count"] = 0
        return out
    e = email_df.copy()
    e["date_only"] = _calendar_date(e["date"])
    agg = e.groupby(["user", "date_only"]).agg(
        n_email_events=("size_mb", "count"),
        email_volume_mb=("size_mb", "sum"),
        email_external_count=("to_domain_type", lambda s: int((s == "external").sum())),
    ).reset_index().rename(columns={"date_only": "date"})
    out = all_user_days.merge(agg, on=["user", "date"], how="left")
    out["n_email_events"] = out["n_email_events"].fillna(0).astype(int)
    out["email_volume_mb"] = out["email_volume_mb"].fillna(0.0)
    out["email_external_count"] = out["email_external_count"].fillna(0).astype(int)
    return out


def _hours_list(events: dict, all_user_days: pd.DataFrame) -> pd.DataFrame:
    frames = []
    for name, df in events.items():
        if df.empty:
            continue
        frames.append(pd.DataFrame({"user": df["user"], "date": _calendar_date(df["date"]), "hour": df["date"].dt.hour}))
    combined = pd.concat(frames, ignore_index=True)
    grp = combined.groupby(["user", "date"])["hour"].apply(list).reset_index()
    grp = grp.rename(columns={"hour": "hours"})
    out = all_user_days.merge(grp, on=["user", "date"], how="left")
    out["hours"] = out["hours"].apply(lambda v: v if isinstance(v, list) else [])
    return out


def _attach_labels(user_day: pd.DataFrame, answers: pd.DataFrame) -> pd.DataFrame:
    if answers.empty:
        user_day["is_malicious"] = False
        user_day["scenario_id"] = None
        return user_day
    ans = answers[["user", "date", "scenario_id"]].copy()
    ans["date"] = _calendar_date(ans["date"])
    ans["is_malicious"] = True
    out = user_day.merge(ans, on=["user", "date"], how="left")
    out["is_malicious"] = out["is_malicious"].fillna(False)
    return out


def build_user_day_table(events: dict, directory: pd.DataFrame, answers: pd.DataFrame) -> pd.DataFrame:
    all_user_days = _collect_all_user_days(events)
    user_day = all_user_days.merge(directory[["user", "role"]], on="user", how="left")
    user_day = user_day.merge(_session_duration(events["logon"], all_user_days), on=["user", "date"])
    user_day = user_day.merge(_pcs_used(events, all_user_days), on=["user", "date"])
    user_day = user_day.merge(_device_stats(events["device"], all_user_days), on=["user", "date"])
    user_day = user_day.merge(_file_stats(events["file"], all_user_days), on=["user", "date"])
    user_day = user_day.merge(_http_stats(events["http"], all_user_days), on=["user", "date"])
    user_day = user_day.merge(_email_stats(events["email"], all_user_days), on=["user", "date"])
    user_day = user_day.merge(_hours_list(events, all_user_days), on=["user", "date"])
    user_day = _attach_labels(user_day, answers)
    user_day = user_day.sort_values(["user", "date"]).reset_index(drop=True)
    return user_day


def load_dataset(cfg) -> dict:
    """Entry point. Loads real CERT CSVs if cfg.USE_REAL_CERT_DATA is set
    and the directory exists; otherwise generates the synthetic stand-in."""
    if cfg.USE_REAL_CERT_DATA and cfg.CERT_DATA_DIR.exists():
        raise NotImplementedError(
            "Real CERT CSV parsing is not wired up in this phase - "
            f"{cfg.CERT_DATA_DIR} exists but USE_REAL_CERT_DATA path is unimplemented. "
            "Set USE_REAL_CERT_DATA = False to use the synthetic dataset."
        )

    raw = synth.generate_synthetic_cert_dataset(cfg)
    user_day = build_user_day_table(raw["events"], raw["directory"], raw["answers"])
    return {
        "user_day": user_day,
        "directory": raw["directory"],
        "answers": raw["answers"],
        "events": raw["events"],
    }
