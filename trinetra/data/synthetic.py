"""
Synthetic stand-in for the CMU CERT Insider Threat dataset (r4.2 style),
relabeled onto banking privileged-access roles.

Why synthetic: the real r4.2 release is a 4.82GB archive behind CMU's
figshare/kilthub host. This generator reproduces the same *shape* of data
CERT r4.2 provides - logon/device/file/http/email event logs, an
LDAP-style user directory, and a ground-truth "answers" table of labeled
malicious user-days - parameterized by role so behavior is realistic
and malicious scenarios read as a clear deviation from a believable
baseline, not an arbitrary spike.

Output granularity: one "session" == one user-day. CERT logs support
finer-grained multi-session-per-day modeling; that's a reasonable
extension for a later phase, not needed to validate the detection
approach here.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .roles import (
    ROLE_PROFILES, NIGHT_SHIFT_ROLES, NIGHT_SHIFT_FRACTION,
    NIGHT_SHIFT_LOGIN_HOUR_MEAN, HTTP_DOMAINS,
)

FILE_ACTIVITY_WEIGHTS = {"Open": 0.60, "Write": 0.25, "Copy": 0.10, "Delete": 0.05}
RARE_MALICIOUS_DOMAINS = {
    "admin_export": "admin.cbs.bank",       # only ever touched maliciously
    "tool_download": "freetoolz-download.net",
}


def build_directory(rng: np.random.Generator, role_headcount: dict, sim_start: pd.Timestamp) -> pd.DataFrame:
    rows = []
    for role, n in role_headcount.items():
        prefix = ROLE_PROFILES[role]["prefix"]
        for i in range(1, n + 1):
            user = f"{prefix}{i:03d}"
            hire_offset_days = int(rng.integers(200, 2000))  # all hired well before sim window
            hire_date = sim_start - pd.Timedelta(days=hire_offset_days)
            is_night_shift = role in NIGHT_SHIFT_ROLES and rng.random() < NIGHT_SHIFT_FRACTION
            rows.append({
                "user": user, "role": role, "hire_date": hire_date,
                "is_night_shift": is_night_shift,
            })
    return pd.DataFrame(rows)


def assign_hosts_and_devices(rng: np.random.Generator, directory: pd.DataFrame) -> dict:
    """Set up per-user primary PC, a small legitimate rotation pool of PCs,
    and (for the minority who ever use removable media) a regular device id.
    Keeping these pools small and mostly-fixed means any genuinely new
    host/device later is a meaningful signal, not noise."""
    setup = {}
    pcs_by_role = {}
    for role in ROLE_PROFILES:
        n_users_role = int((directory.role == role).sum())
        pool_size = n_users_role + 5  # a few spare/shared hosts per role
        pcs_by_role[role] = [f"PC-{ROLE_PROFILES[role]['prefix']}-{i:03d}" for i in range(1, pool_size + 1)]

    role_counters = {role: 0 for role in ROLE_PROFILES}
    for _, row in directory.iterrows():
        role, user = row["role"], row["user"]
        pool = pcs_by_role[role]
        primary_pc = pool[role_counters[role]]
        role_counters[role] += 1

        rotation_extra = list(rng.choice([p for p in pool if p != primary_pc],
                                          size=min(2, max(0, len(pool) - 1)), replace=False))
        rotation_pool = [primary_pc] + rotation_extra

        has_regular_device = rng.random() < 0.15  # a minority legitimately use one regular USB
        regular_device = f"USB-{user}-01" if has_regular_device else None

        setup[user] = {
            "primary_pc": primary_pc,
            "rotation_pool": rotation_pool,
            "regular_device": regular_device,
        }
    return {"per_user": setup, "pcs_by_role": pcs_by_role}


def _sample_http(rng, category_weights):
    cats = list(category_weights.keys())
    weights = np.array(list(category_weights.values()))
    weights = weights / weights.sum()
    cat = rng.choice(cats, p=weights)
    domain = rng.choice(HTTP_DOMAINS[cat])
    return cat, domain


def simulate_normal_events(rng: np.random.Generator, directory: pd.DataFrame,
                            sim_dates: pd.DatetimeIndex, host_setup: dict) -> dict:
    logon_rows, device_rows, file_rows, http_rows, email_rows = [], [], [], [], []
    per_user = host_setup["per_user"]

    for _, urow in directory.iterrows():
        user, role = urow["user"], urow["role"]
        profile = ROLE_PROFILES[role]
        setup = per_user[user]
        login_hour_mean = profile["login_hour_mean"]
        if urow.get("is_night_shift"):
            login_hour_mean = NIGHT_SHIFT_LOGIN_HOUR_MEAN

        for date in sim_dates:
            is_weekday = date.dayofweek < 5
            works_today = is_weekday or (rng.random() < profile["weekend_work_prob"])
            if not works_today:
                continue

            start_hour = float(np.clip(rng.normal(login_hour_mean, profile["login_hour_std"]), 0, 22))
            duration = float(np.clip(rng.normal(profile["duration_hours_mean"], profile["duration_hours_std"]), 0.5, 13))
            end_hour = min(start_hour + duration, 23.98)

            pc = setup["primary_pc"]
            if rng.random() < profile["secondary_pc_prob"] and len(setup["rotation_pool"]) > 1:
                pc = rng.choice(setup["rotation_pool"])

            logon_ts = date + pd.Timedelta(hours=start_hour)
            logoff_ts = date + pd.Timedelta(hours=end_hour)
            logon_rows.append({"date": logon_ts, "user": user, "pc": pc, "activity": "Logon"})
            logon_rows.append({"date": logoff_ts, "user": user, "pc": pc, "activity": "Logoff"})

            device_connected_today = False
            if setup["regular_device"] and rng.random() < profile["device_use_prob"]:
                device_connected_today = True
                t = logon_ts + pd.Timedelta(hours=rng.uniform(0.2, duration * 0.6))
                device_rows.append({"date": t, "user": user, "pc": pc, "activity": "Connect",
                                     "device_id": setup["regular_device"]})

            n_file = rng.poisson(profile["n_file_events_mean"])
            for _ in range(n_file):
                activity = rng.choice(list(FILE_ACTIVITY_WEIGHTS.keys()),
                                       p=list(FILE_ACTIVITY_WEIGHTS.values()))
                size_mb = float(rng.uniform(*profile["file_size_mb_range"]))
                to_removable = bool(device_connected_today and activity == "Copy" and rng.random() < 0.3)
                t = logon_ts + pd.Timedelta(hours=rng.uniform(0, duration))
                file_rows.append({
                    "date": t, "user": user, "pc": pc,
                    "filename": f"{profile['prefix'].lower()}/file_{rng.integers(1, 500)}.dat",
                    "activity": activity, "size_mb": size_mb,
                    "to_removable_media": to_removable,
                })

            n_http = rng.poisson(profile["n_http_events_mean"])
            for _ in range(n_http):
                cat, domain = _sample_http(rng, profile["http_categories"])
                upload_mb = 0.0
                if cat in ("webmail", "cloud_storage") and rng.random() < 0.05:
                    upload_mb = float(rng.uniform(0.01, 0.5))
                t = logon_ts + pd.Timedelta(hours=rng.uniform(0, duration))
                http_rows.append({
                    "date": t, "user": user, "pc": pc,
                    "url": f"https://{domain}/path{int(rng.integers(1, 9999))}",
                    "domain": domain, "category": cat, "upload_mb": upload_mb,
                })

            n_email = rng.poisson(profile["n_email_events_mean"])
            for _ in range(n_email):
                external = rng.random() < profile["email_external_ratio"]
                size_mb = float(rng.uniform(*profile["email_size_mb_range"]))
                t = logon_ts + pd.Timedelta(hours=rng.uniform(0, duration))
                email_rows.append({
                    "date": t, "user": user, "pc": pc,
                    "to_domain_type": "external" if external else "internal",
                    "size_mb": size_mb, "attachments": int(rng.poisson(0.3)),
                })

    return {
        "logon": pd.DataFrame(logon_rows),
        "device": pd.DataFrame(device_rows),
        "file": pd.DataFrame(file_rows),
        "http": pd.DataFrame(http_rows),
        "email": pd.DataFrame(email_rows),
    }


def _malicious_day_offsets(rng, window_len, n_days):
    n_days = min(n_days, window_len)
    return sorted(rng.choice(window_len, size=n_days, replace=False))


def inject_malicious_scenarios(rng: np.random.Generator, directory: pd.DataFrame,
                                events: dict, sim_dates: pd.DatetimeIndex,
                                host_setup: dict, scenarios: list,
                                min_window_start_idx: int) -> pd.DataFrame:
    """Mutates events in place by appending malicious rows for one
    randomly-picked user per scenario tuple, over a randomly-placed window.
    min_window_start_idx confines every window to the test/held-out
    period (see config.TRAIN_DAYS) so the training period stays a
    genuinely clean baseline. Returns the ground-truth answers table."""
    per_user = host_setup["per_user"]
    answers = []
    n_sim_days = len(sim_dates)
    used_users = set()

    for role, scenario_id, _desc in scenarios:
        candidates = directory[(directory.role == role) & (~directory.user.isin(used_users))]
        user = rng.choice(candidates["user"].values)
        used_users.add(user)
        setup = per_user[user]
        profile = ROLE_PROFILES[role]

        latest_start = n_sim_days - 15
        window_start_idx = int(rng.integers(min_window_start_idx, max(min_window_start_idx + 1, latest_start)))
        window_len = 12
        n_malicious_days = int(rng.integers(6, 9))
        offsets = _malicious_day_offsets(rng, window_len, n_malicious_days)
        mal_dates = [sim_dates[window_start_idx + o] for o in offsets if window_start_idx + o < n_sim_days]

        for i, date in enumerate(mal_dates):
            ramp = (i + 1) / len(mal_dates)
            answers.append({"user": user, "role": role, "scenario_id": scenario_id, "date": date})

            if scenario_id == "DBA_EXFIL":
                # Bounded so logon + the largest downstream offset (100 min
                # http upload) can never cross midnight into the next
                # calendar day - otherwise those events would land on an
                # unlabeled day and silently mislabel real attack activity
                # as "normal".
                late_hour = float(np.clip(rng.normal(21.5, 0.6), 20, 22.2))
                t_logon = date + pd.Timedelta(hours=late_hour)
                t_logoff = t_logon + pd.Timedelta(hours=rng.uniform(0.5, 1.5))
                pc = setup["primary_pc"]
                events["logon"].loc[len(events["logon"])] = [t_logon, user, pc, "Logon"]
                events["logon"].loc[len(events["logon"])] = [t_logoff, user, pc, "Logoff"]
                new_device = f"USB-EXFIL-{user}"
                if rng.random() < 0.3 + 0.6 * ramp:
                    events["device"].loc[len(events["device"])] = [t_logon + pd.Timedelta(minutes=10), user, pc, "Connect", new_device]
                    for _ in range(int(rng.integers(2, 5))):
                        size_mb = float(rng.uniform(50, 400) * ramp)
                        events["file"].loc[len(events["file"])] = [
                            t_logon + pd.Timedelta(minutes=int(rng.integers(15, 90))), user, pc,
                            f"core_banking/export_{int(rng.integers(1,999))}.dat", "Copy", size_mb, True,
                        ]
                if ramp > 0.7:
                    events["http"].loc[len(events["http"])] = [
                        t_logon + pd.Timedelta(minutes=100), user, pc,
                        "https://drive.google.com/upload", "drive.google.com", "cloud_storage",
                        float(rng.uniform(100, 800)),
                    ]

            elif scenario_id == "VENDOR_MISUSE":
                unrecognized_pc = f"PC-EXT-{user}"
                early_hour = float(np.clip(rng.normal(2.5, 0.8), 0, 5))
                t_logon = date + pd.Timedelta(hours=early_hour)
                t_logoff = t_logon + pd.Timedelta(hours=rng.uniform(2, 4))
                events["logon"].loc[len(events["logon"])] = [t_logon, user, unrecognized_pc, "Logon"]
                events["logon"].loc[len(events["logon"])] = [t_logoff, user, unrecognized_pc, "Logoff"]
                for _ in range(int(rng.integers(5, 12))):
                    size_mb = float(rng.uniform(5, 60) * (0.5 + ramp))
                    to_removable = rng.random() < 0.2 * ramp
                    events["file"].loc[len(events["file"])] = [
                        t_logon + pd.Timedelta(minutes=int(rng.integers(5, 150))), user, unrecognized_pc,
                        f"core_banking/scope_{int(rng.integers(1,999))}.dat", "Copy", size_mb, to_removable,
                    ]
                events["http"].loc[len(events["http"])] = [
                    t_logon + pd.Timedelta(minutes=30), user, unrecognized_pc,
                    f"https://{RARE_MALICIOUS_DOMAINS['admin_export']}/export",
                    RARE_MALICIOUS_DOMAINS['admin_export'], "internal_tool", 0.0,
                ]

            elif scenario_id == "ADMIN_SABOTAGE":
                pc = setup["primary_pc"]
                # Bounded so the largest downstream offset (+40 min email)
                # can't cross midnight into the next, unlabeled day.
                t = date + pd.Timedelta(hours=float(np.clip(rng.normal(20.5, 0.8), 19, 21.5)))
                events["http"].loc[len(events["http"])] = [
                    t, user, pc, f"https://{RARE_MALICIOUS_DOMAINS['tool_download']}/get",
                    RARE_MALICIOUS_DOMAINS['tool_download'], "tool_download", 0.0,
                ]
                if ramp > 0.4:
                    other_role_users = directory[directory.user != user]["user"].values
                    colleague = rng.choice(other_role_users)
                    colleague_pc = per_user[colleague]["primary_pc"]
                    events["device"].loc[len(events["device"])] = [
                        t + pd.Timedelta(minutes=20), user, colleague_pc, "Connect", f"USB-SABOTAGE-{user}",
                    ]
                for act, mins in [("Write", 25), ("Copy", 27), ("Delete", 29)]:
                    events["file"].loc[len(events["file"])] = [
                        t + pd.Timedelta(minutes=mins), user, pc,
                        f"sys/keylog_{int(rng.integers(1,999))}.dat", act, float(rng.uniform(0.01, 0.2)), False,
                    ]
                if ramp > 0.6:
                    events["email"].loc[len(events["email"])] = [
                        t + pd.Timedelta(minutes=40), user, pc, "external", float(rng.uniform(0.5, 3.0)), 1,
                    ]

            elif scenario_id == "OPS_JOBHUNT_EXFIL":
                pc = setup["primary_pc"]
                base_hour = profile["login_hour_mean"] + 8 * ramp  # creeping later
                t = date + pd.Timedelta(hours=float(np.clip(base_hour, 9, 21)))
                for _ in range(int(2 + 4 * ramp)):
                    events["http"].loc[len(events["http"])] = [
                        t, user, pc, "https://naukri.com/jobs", "naukri.com", "job_site", 0.0,
                    ]
                if ramp > 0.6:
                    new_device = f"USB-JOBHUNT-{user}"
                    events["device"].loc[len(events["device"])] = [t + pd.Timedelta(minutes=15), user, pc, "Connect", new_device]
                    events["file"].loc[len(events["file"])] = [
                        t + pd.Timedelta(minutes=25), user, pc,
                        f"branch/customer_export_{int(rng.integers(1,999))}.dat", "Copy",
                        float(rng.uniform(20, 150)), True,
                    ]
                    events["http"].loc[len(events["http"])] = [
                        t + pd.Timedelta(minutes=35), user, pc, "https://mail.yahoo.com/upload",
                        "mail.yahoo.com", "webmail", float(rng.uniform(20, 150)),
                    ]

            elif scenario_id == "SOC_SNOOPING":
                pc = setup["primary_pc"]
                t = date + pd.Timedelta(hours=float(np.clip(rng.normal(9, 1), 7, 11)))
                for _ in range(int(10 + 30 * ramp)):
                    events["http"].loc[len(events["http"])] = [
                        t + pd.Timedelta(minutes=int(rng.integers(0, 480))), user, pc,
                        f"https://core.cbs.bank/vip_lookup/{int(rng.integers(1,999))}",
                        "core.cbs.bank", "banking_core_app", 0.0,
                    ]
                if ramp > 0.5:
                    t2 = date + pd.Timedelta(hours=float(np.clip(rng.normal(1, 0.7), 0, 3)))
                    events["logon"].loc[len(events["logon"])] = [t2, user, pc, "Logon"]
                    events["logon"].loc[len(events["logon"])] = [t2 + pd.Timedelta(hours=1.5), user, pc, "Logoff"]

    return pd.DataFrame(answers)


def generate_synthetic_cert_dataset(cfg) -> dict:
    rng = np.random.default_rng(cfg.RANDOM_SEED)
    sim_start = pd.Timestamp(cfg.SIM_START_DATE)
    sim_dates = pd.date_range(sim_start, periods=cfg.SIM_DAYS, freq="D")

    directory = build_directory(rng, cfg.ROLE_HEADCOUNT, sim_start)
    host_setup = assign_hosts_and_devices(rng, directory)
    events = simulate_normal_events(rng, directory, sim_dates, host_setup)
    min_window_start_idx = cfg.TRAIN_DAYS + cfg.MALICIOUS_WINDOW_BUFFER_DAYS
    answers = inject_malicious_scenarios(rng, directory, events, sim_dates, host_setup,
                                         cfg.MALICIOUS_SCENARIOS, min_window_start_idx)

    for key in ("logon", "device", "file", "http", "email"):
        events[key] = events[key].sort_values("date").reset_index(drop=True)

    return {"events": events, "directory": directory, "answers": answers}
