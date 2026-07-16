"""
Central configuration for Trinetra.

Phase 1 scope: data + detection pipeline. Later phases (step-up auth,
auto-quarantine, JIT credentials, PQC-protected audit trail).
"""
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Data source
# ---------------------------------------------------------------------------
# CMU CERT r4.2 was not fetchable. Using a realistic synthetic stand-in
# instead. Flip USE_REAL_CERT_DATA + set CERT_DATA_DIR if real CSVs
# (logon.csv, device.csv, file.csv, http.csv, email.csv, LDAP/*.csv) become
# available later.
USE_REAL_CERT_DATA = False
CERT_DATA_DIR = Path("./data/cert_r4.2")

# Governs every seeded source of randomness in the pipeline: synthetic
# data generation (trinetra.data.synthetic) and IsolationForest fitting.
# The step-up auth simulation (trinetra.access_control.policy) is a
# separate, unrelated source of determinism - a pure hash of (user,
# date) with no PRNG involved - so it's already exactly reproducible
# without reading this value at all. Re-running run_pipeline.py or
# run_vault_demo.py reproduces identical numbers either way - verified
# across independent process runs, not just within one session.
RANDOM_SEED = 42

# ---------------------------------------------------------------------------
# Banking privileged-role tiers (relabeled from the generic CERT org roles)
# ---------------------------------------------------------------------------
BANKING_ROLES = [
    "Core-Banking DBA",
    "Network/Infra Admin",
    "Vendor/Third-Party Support Engineer",
    "Branch Ops Manager",
    "SOC Analyst",
]

# Approximate headcount per role in the synthetic org (sums to NUM_USERS)
ROLE_HEADCOUNT = {
    "Core-Banking DBA": 25,
    "Network/Infra Admin": 20,
    "Vendor/Third-Party Support Engineer": 20,
    "Branch Ops Manager": 55,
    "SOC Analyst": 20,
}
NUM_USERS = sum(ROLE_HEADCOUNT.values())  # 140

# ---------------------------------------------------------------------------
# Synthetic log generation window
# ---------------------------------------------------------------------------
SIM_START_DATE = "2026-01-05"   # a Monday
SIM_DAYS = 90                   # ~3 months of activity -> fast iteration

# Chronological train/test split for model fitting + evaluation. The
# ensemble (IsolationForest + peer-group centroids) is fit ONLY on the
# training window; the test window is scored purely out-of-sample. All
# malicious scenario windows are placed inside the test period (with a
# buffer) so the training period is a genuinely clean baseline and
# reported detection-quality metrics are a real held-out evaluation, not
# in-sample.
TRAIN_DAYS = 50  # first 50 of SIM_DAYS=90 form the training/baseline period
MALICIOUS_WINDOW_BUFFER_DAYS = 5  # keep malicious windows this far past the split

# Number of distinct malicious insiders injected (one scenario each, roughly
# one per role). Malicious user-days land at ~1:240 vs normal user-days.
MALICIOUS_SCENARIOS = [
    # (role, scenario_id, description)
    ("Core-Banking DBA", "DBA_EXFIL", "After-hours ramp, USB exfil, cloud upload before exit"),
    ("Vendor/Third-Party Support Engineer", "VENDOR_MISUSE", "New/unrecognized host, out-of-window access, large export"),
    ("Network/Infra Admin", "ADMIN_SABOTAGE", "Unauthorized tool download, targets colleague's PC, rare commands"),
    ("Branch Ops Manager", "OPS_JOBHUNT_EXFIL", "Job-site browsing, after-hours shift, USB + webmail exfil"),
    ("SOC Analyst", "SOC_SNOOPING", "Elevated out-of-scope record lookups, after-hours spikes"),
    ("Core-Banking DBA", "DBA_EXFIL", "Second DBA insider, later in the window"),
]

# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------
HOUR_ENTROPY_WINDOW_DAYS = 7
DOW_ENTROPY_WINDOW_DAYS = 30
BUSINESS_HOURS = (8, 18)  # 8am - 6pm treated as "normal"
# First N calendar days of each user's activity are used only to warm up
# the "known hosts/devices" baseline, not scored - avoids flagging every
# user's very first day as a fake "new host".
WARMUP_DAYS = 14

FEATURE_COLUMNS = [
    "hour_entropy_7d",
    "dow_entropy_30d",
    "after_hours_ratio",
    "session_duration_min",
    "data_volume_mb",
    "export_volume_mb",
    "new_host_flag",
    "new_device_flag",
    "url_bigram_rarity",
    "file_bigram_rarity",
]

# Business-informed weights for the feature-contribution breakdown. Not
# used for model fitting - only for explaining *why* a score is high.
FEATURE_WEIGHTS = {
    "hour_entropy_7d": 1.0,
    "dow_entropy_30d": 0.7,
    "after_hours_ratio": 1.0,
    "session_duration_min": 0.6,
    "data_volume_mb": 1.2,
    "export_volume_mb": 1.6,
    "new_host_flag": 1.3,
    "new_device_flag": 1.3,
    "url_bigram_rarity": 1.1,
    "file_bigram_rarity": 1.1,
}

# ---------------------------------------------------------------------------
# Model / ensemble
# ---------------------------------------------------------------------------
# Expected malicious fraction fed to IsolationForest's contamination.
# Set a bit above the true injected rate (~1/240 ~= 0.0042) so the model
# has room to score borderline sessions instead of clamping everything to
# "normal".
ISOLATION_FOREST_CONTAMINATION = 0.01
ISOLATION_FOREST_N_ESTIMATORS = 200

PEER_GROUP_COV_REGULARIZATION = 1e-3  # ridge term for covariance stability

# Calibration steepness for the 0-100 mapping (see model/calibration.py).
# Score = 0 at the robust baseline, approaching 100 as the raw anomaly
# metric grows many scale (robust-sigma-equivalent) units past it; k
# sets how many such units it takes before the score meaningfully rises.
ISOLATION_FOREST_RISK_K = 2.5
PEER_GROUP_RISK_K = 2.5

# Ensemble weights: IsolationForest (global point-anomaly) vs peer-group
# (role-normalized) distance.
ENSEMBLE_WEIGHTS = {
    "isolation_forest": 0.5,
    "peer_group": 0.5,
}

# 0-100 risk score -> tier thresholds
RISK_TIERS = [
    (0, 40, "Low"),
    (40, 65, "Medium"),
    (65, 85, "High"),
    (85, 101, "Critical"),
]

TOP_N_CONTRIBUTING_FEATURES = 4

# Feature-contribution breakdown ("why did this score high") is explanation
# only - it does not feed back into risk_score/isolation_forest_score/
# peer_group_score. Per-feature z-scores there are (value - role_mean) /
# role_std; a role with near-zero natural variance for some feature (e.g.
# Vendor Engineer + export_volume_mb, which they almost never touch) would
# otherwise produce z-scores in the thousands off a bare epsilon floor,
# swamping the other features in the breakdown. Floor each role's std at
# this fraction of that feature's population-wide (cross-role) std instead.
PEER_GROUP_STD_FLOOR_FRACTION = 0.15

# Even with the std floor above, a genuinely rare feature (nobody in any
# role normally exports meaningful data volume) can still produce a
# |z-score| in the thousands - factually accurate, but it swamps the
# other features in the pct_contribution split. Soft-compress |z| above
# this threshold (grows ~log past it instead of linearly) for the
# percentage math only; the raw z-score is still shown in the output.
CONTRIBUTION_Z_CAP_THRESHOLD = 15.0
