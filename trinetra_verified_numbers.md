# Trinetra — verified numbers (final, as of last full audit)

## Core detection performance (held-out test split, 4165 sessions)
- ROC-AUC: 0.9188
- PR-AUC: 0.7072
- Recall / precision @ top 1%: 0.651 / 0.667
- Recall / precision @ top 2%: 0.744 / 0.386
- Recall / precision @ top 5%: 0.837 / 0.173

## Dataset
- 140 synthetic users, 5 banking roles (Core-Banking DBA, Network/Infra Admin,
  Vendor/Third-Party Support Engineer, Branch Ops Manager, SOC Analyst)
- 90-day window; chronological split at TRAIN_DAYS=50 (2026-02-24)
- Train: 5171 sessions / Test: 4165 sessions (9336 total)
- 43 labeled-malicious sessions in the test split (~1:96 imbalance within test)

## Tier distribution, full test split (4165 sessions)
- Low 3703 / Medium 331 / High 87 / Critical 44

## Detection among the 43 labeled-malicious sessions
- Critical 30 / Medium 4 / High 2 / Low 7
- **36 of 43 (83.7%) score Medium-or-above**
- All 7 Low-tier misses are concentrated in the first 3-4 sessions of exactly two
  slow-ramp campaigns (Admin Sabotage, Ops Job-Hunt+Exfil) — both escalate to
  Critical by session 4-5

## False positive rate — use the held-out number
- **Held-out test (4122 non-malicious sessions): 2.40% score High-or-Critical**
  (10.33% if using the broader Medium-or-above cut — label which cut you're using)
- Train-period figure (6.03%) is a calibration-window proxy, not a true held-out
  measurement — don't use it as the headline FPR claim

## Quarantine / maker-checker (final state, step-up pass rate = 97%)
- At a 97% step-up pass rate, 0 of 87 High-tier sessions fail step-up, so High
  contributes no escalations to quarantine
- 44 sessions auto-quarantined (Critical tier only)
- **30 of 44 truly malicious = 68.2% precision** (blended = Critical-only, since
  High contributes nothing)

## Signed, hash-chained audit log
- 5881 entries from a plain pipeline run; 5887 including the scripted
  resume-from-quarantine demo
- Signing covers the entire canonical record (all fields except the signature
  itself and its own hash) — hardened from an earlier hand-maintained 5-field list
- Tamper detection confirmed working in a fresh, restarted process — both a large
  edit and a single-last-decimal-digit edit are caught
- Deletion/reordering caught independently via hash-chain re-walk (a distinct
  mechanism from signature verification on content edits)

## Post-quantum cryptography
- Vault: ML-KEM-768 encapsulation + fresh X25519 ECDH per secret, combined via
  HKDF-SHA384 into an AES-256-GCM key (HPKE-style direct construction, not a
  DEK/KEK two-layer scheme — call it "hybrid KEM-derived authenticated encryption")
- Audit log: ML-DSA-65 signatures
- Library: pyca/cryptography >= 48

## Explainability example -
DBA001, Core-Banking DBA, 2026-03-23, DBA_EXFIL scenario, risk score 95.3 (Critical):

| Feature | Contribution | Raw z-score | Capped? |
|---|---|---|---|
| export_volume_mb | 43.6% | +9045.39 | Yes |
| new_device_flag | 31.1% | +479.44 | Yes |
| data_volume_mb | 16.0% | +11.78 | No |
| session_duration_min | 3.1% | +4.61 | No |

## MITRE ATT&CK mapping (5 scenario types, 6 instances)
- DBA exfiltration (DBA001, DBA002) — T1078 -> T1052.001 -> T1567.002 — caught session 1
- Vendor remote-access misuse (VEN008) — T1199 + T1078 -> T1052.001 (partial) — caught session 1
- Admin sabotage (NET010) — T1105 + T1200 + T1056.001 + T1070.004 — Low for 3 sessions, Critical by session 4
- Ops job-hunt + exfiltration (OPS032) — T1052.001 + T1567 + T1078 — flat/near-zero for 4 sessions, Critical by session 5
- SOC snooping (SOC010) — T1213 + T1078 — the one gradual climb: Medium -> High -> Critical over 7 sessions, never missed