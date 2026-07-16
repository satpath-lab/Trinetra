"""
Append-only, individually-signed audit log for every risk-engine and
vault event (session scored, lease issued/redeemed, session quarantined,
second-person approval, ...).

Each entry is ML-DSA-65 signed at write time over its own canonical bytes
(which include the previous entry's hash), so two independent tamper
detectors apply:
  1. Signature check - editing an entry's payload without re-signing
     (which requires the private key) makes `public_key.verify(...)`
     raise InvalidSignature.
  2. Hash-chain check - even a re-signed edit (if someone had the key)
     breaks prev_hash linkage for every later entry, revealing insertion/
     deletion/reordering.
Verification only ever needs the log's PUBLIC key, matching how a real
auditor or SIEM would consume this log without holding the signing key.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa

GENESIS_HASH = "0" * 64


class TamperDetected(Exception):
    """Raised for hash-chain breaks; signature failures raise the
    underlying cryptography.exceptions.InvalidSignature instead, so
    callers can distinguish "this entry's signature is wrong" from
    "the chain doesn't line up"."""


def _canonical_bytes(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


# The only fields ever excluded from the signed/hashed representation of a
# record and they're excluded for a structural reason, not curation:
# both are OUTPUTS of signing this exact record, so they cannot also be
# inputs to it without a circular dependency. Every other field, present
# or future, is covered automatically (see LogRecord.signed_bytes) this
# is a deny-list of exactly these two, not a hand-picked allow-list of
# "the fields we remembered to include".
_UNSIGNED_FIELDS = {"entry_hash", "signature_hex"}


@dataclass
class LogRecord:
    seq: int
    timestamp: str
    event_type: str
    payload: dict
    prev_hash: str
    entry_hash: str
    signature_hex: str

    def signed_bytes(self) -> bytes:
        """Exactly what was (or will be) passed to signing_key.sign() for
        this record - every field of LogRecord except entry_hash/
        signature_hex themselves. AuditLog.append builds a draft record
        and calls this same method to get the bytes to sign, so signing
        time and verify time can never drift apart into covering
        different field sets - there is only one definition of "the
        canonical record", used both places."""
        entry = {k: v for k, v in asdict(self).items() if k not in _UNSIGNED_FIELDS}
        return _canonical_bytes(entry)


class AuditLog:
    def __init__(self, signing_key: Optional[mldsa.MLDSA65PrivateKey] = None):
        self.signing_key = signing_key or mldsa.MLDSA65PrivateKey.generate()
        self.public_key = self.signing_key.public_key()
        self.records: list[LogRecord] = []

    def append(self, event_type: str, payload: dict) -> LogRecord:
        seq = len(self.records)
        prev_hash = self.records[-1].entry_hash if self.records else GENESIS_HASH
        timestamp = datetime.now(timezone.utc).isoformat()

        # Build a draft with placeholder entry_hash/signature_hex, then
        # derive the bytes to sign from draft.signed_bytes() the exact
        # same method verify_record() calls later. There is no second,
        # separately-maintained field list here to drift out of sync.
        draft = LogRecord(seq=seq, timestamp=timestamp, event_type=event_type, payload=payload,
                           prev_hash=prev_hash, entry_hash="", signature_hex="")
        entry_bytes = draft.signed_bytes()
        draft.entry_hash = hashlib.sha256(entry_bytes).hexdigest()
        draft.signature_hex = self.signing_key.sign(entry_bytes).hex()

        self.records.append(draft)
        return draft

    def verify_record(self, record: LogRecord) -> None:
        """Raises InvalidSignature if the signature doesn't match the
        record's current (possibly tampered) content - checked first,
        since it's the strongest guarantee and the one an attacker who
        edited the log file (but doesn't hold the signing key) will trip.
        Only if the signature checks out do we also confirm entry_hash is
        self-consistent (TamperDetected otherwise), which mainly matters
        for an attacker who somehow holds the signing key too."""
        entry_bytes = record.signed_bytes()
        self.public_key.verify(bytes.fromhex(record.signature_hex), entry_bytes)
        recomputed_hash = hashlib.sha256(entry_bytes).hexdigest()
        if recomputed_hash != record.entry_hash:
            raise TamperDetected(
                f"entry {record.seq}: recomputed hash {recomputed_hash} != stored entry_hash {record.entry_hash}"
            )

    def verify_all(self) -> list[tuple[int, bool, Optional[str]]]:
        """Walks the full chain. Returns (seq, ok, error) per record; does
        not raise, so a demo can show every failure at once."""
        results = []
        expected_prev = GENESIS_HASH
        for record in self.records:
            error = None
            try:
                if record.prev_hash != expected_prev:
                    raise TamperDetected(
                        f"entry {record.seq}: prev_hash {record.prev_hash} != expected {expected_prev} (chain break)"
                    )
                self.verify_record(record)
            except (InvalidSignature, TamperDetected) as e:
                error = str(e) if str(e) else type(e).__name__
                results.append((record.seq, False, error))
                expected_prev = record.entry_hash
                continue
            results.append((record.seq, True, None))
            expected_prev = record.entry_hash
        return results

    def to_jsonl(self, path: str) -> None:
        with open(path, "w") as f:
            for r in self.records:
                f.write(json.dumps(asdict(r), sort_keys=True) + "\n")

    @classmethod
    def from_jsonl(cls, path: str, public_key: mldsa.MLDSA65PublicKey) -> "AuditLog":
        """Load a log for verification only - an auditor never needs (or
        gets) the signing key, only the public key."""
        log = cls.__new__(cls)
        log.signing_key = None
        log.public_key = public_key
        log.records = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    log.records.append(LogRecord(**json.loads(line)))
        return log
