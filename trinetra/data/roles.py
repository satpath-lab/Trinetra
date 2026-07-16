"""
Banking privileged-role behavioral profiles for the synthetic log generator.

Each profile parameterizes what "normal" looks like for that role so the
generator can produce realistic baselines, and so malicious injections read
as a clear deviation rather than an arbitrary spike.
"""

# category weights must sum to 1.0 per role
ROLE_PROFILES = {
    "Core-Banking DBA": {
        "prefix": "DBA",
        "login_hour_mean": 9.0,
        "login_hour_std": 0.7,
        "duration_hours_mean": 8.5,
        "duration_hours_std": 1.2,
        "weekend_work_prob": 0.03,
        "secondary_pc_prob": 0.05,
        "device_use_prob": 0.004,
        "n_file_events_mean": 14,
        "file_size_mb_range": (0.05, 8.0),
        "n_http_events_mean": 8,
        "http_categories": {
            "internal_tool": 0.45, "banking_core_app": 0.35, "vendor_portal": 0.10,
            "news": 0.08, "job_site": 0.01, "webmail": 0.005, "cloud_storage": 0.005,
            "social_media": 0.0,
        },
        "n_email_events_mean": 6,
        "email_external_ratio": 0.10,
        "email_size_mb_range": (0.01, 1.5),
    },
    "Network/Infra Admin": {
        "prefix": "NET",
        "login_hour_mean": 8.5,
        "login_hour_std": 1.0,
        "duration_hours_mean": 9.0,
        "duration_hours_std": 1.5,
        "weekend_work_prob": 0.08,  # legit scheduled maintenance windows
        "secondary_pc_prob": 0.20,  # admins routinely touch many hosts
        "device_use_prob": 0.006,
        "n_file_events_mean": 10,
        "file_size_mb_range": (0.02, 4.0),
        "n_http_events_mean": 9,
        "http_categories": {
            "internal_tool": 0.50, "vendor_portal": 0.20, "news": 0.15,
            "banking_core_app": 0.10, "job_site": 0.02, "webmail": 0.01,
            "cloud_storage": 0.01, "social_media": 0.01,
        },
        "n_email_events_mean": 7,
        "email_external_ratio": 0.15,
        "email_size_mb_range": (0.01, 1.0),
    },
    "Vendor/Third-Party Support Engineer": {
        "prefix": "VEN",
        "login_hour_mean": 10.0,
        "login_hour_std": 1.3,
        "duration_hours_mean": 6.0,
        "duration_hours_std": 1.5,
        "weekend_work_prob": 0.02,
        "secondary_pc_prob": 0.30,  # rotates jump-hosts routinely
        "device_use_prob": 0.003,
        "n_file_events_mean": 6,
        "file_size_mb_range": (0.02, 3.0),
        "n_http_events_mean": 6,
        "http_categories": {
            "vendor_portal": 0.55, "internal_tool": 0.30, "news": 0.05,
            "banking_core_app": 0.05, "job_site": 0.02, "webmail": 0.01,
            "cloud_storage": 0.01, "social_media": 0.01,
        },
        "n_email_events_mean": 8,
        "email_external_ratio": 0.55,  # vendor org correspondence
        "email_size_mb_range": (0.01, 2.0),
    },
    "Branch Ops Manager": {
        "prefix": "OPS",
        "login_hour_mean": 9.2,
        "login_hour_std": 0.4,
        "duration_hours_mean": 8.0,
        "duration_hours_std": 0.6,
        "weekend_work_prob": 0.01,
        "secondary_pc_prob": 0.01,  # essentially one branch workstation
        "device_use_prob": 0.001,
        "n_file_events_mean": 5,
        "file_size_mb_range": (0.01, 1.0),
        "n_http_events_mean": 5,
        "http_categories": {
            "banking_core_app": 0.55, "internal_tool": 0.30, "news": 0.10,
            "job_site": 0.01, "vendor_portal": 0.02, "webmail": 0.01,
            "cloud_storage": 0.01, "social_media": 0.0,
        },
        "n_email_events_mean": 9,
        "email_external_ratio": 0.20,
        "email_size_mb_range": (0.01, 0.8),
    },
    "SOC Analyst": {
        "prefix": "SOC",
        "login_hour_mean": 9.0,  # overridden per-user for night-shift analysts
        "login_hour_std": 1.0,
        "duration_hours_mean": 8.5,
        "duration_hours_std": 1.0,
        "weekend_work_prob": 0.10,  # shift rotation is legitimately variable
        "secondary_pc_prob": 0.05,
        "device_use_prob": 0.003,
        "n_file_events_mean": 8,
        "file_size_mb_range": (0.02, 2.0),
        "n_http_events_mean": 20,  # investigating alerts/cases all day
        "http_categories": {
            "banking_core_app": 0.50, "internal_tool": 0.40, "news": 0.05,
            "vendor_portal": 0.02, "job_site": 0.01, "webmail": 0.01,
            "cloud_storage": 0.005, "social_media": 0.005,
        },
        "n_email_events_mean": 5,
        "email_external_ratio": 0.10,
        "email_size_mb_range": (0.01, 1.0),
    },
}

NIGHT_SHIFT_ROLES = {"SOC Analyst"}
NIGHT_SHIFT_FRACTION = 0.30
NIGHT_SHIFT_LOGIN_HOUR_MEAN = 22.0

HTTP_DOMAINS = {
    "internal_tool": ["ops.intranet.bank", "jira.intranet.bank", "wiki.intranet.bank"],
    "banking_core_app": ["core.cbs.bank", "accounts.cbs.bank", "ledger.cbs.bank"],
    "vendor_portal": ["support.vendorportal.com", "tickets.corevendor.com"],
    "news": ["news.example.com", "moneycontrol.com", "livemint.com"],
    "job_site": ["naukri.com", "linkedin.com/jobs", "indeed.com"],
    "webmail": ["mail.yahoo.com", "gmail.com", "outlook.live.com"],
    "cloud_storage": ["drive.google.com", "dropbox.com", "wetransfer.com"],
    "social_media": ["facebook.com", "instagram.com", "twitter.com"],
    "tool_download": ["freetoolz-download.net", "cracked-utils.ru"],
}
