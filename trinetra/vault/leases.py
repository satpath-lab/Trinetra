"""
Just-in-time access to vault secrets: every grant is a short-TTL,
single-use lease. There is no standing/persistent access to any secret -
issuing a lease does not itself decrypt anything; only redeem_lease
does, exactly once, and only before the lease expires or is revoked.
Every lifecycle event (issue, redeem, denial, revoke) is written to the
audit log.
"""
from __future__ import annotations

import secrets as _secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional


class LeaseError(Exception):
    pass


class LeaseExpiredError(LeaseError):
    pass


class LeaseAlreadyRedeemedError(LeaseError):
    pass


class LeaseRevokedError(LeaseError):
    pass


@dataclass
class Lease:
    lease_id: str
    secret_id: str
    user: str
    role: str
    reason: str
    issued_at: datetime
    expires_at: datetime
    redeemed_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revoke_reason: Optional[str] = None

    @property
    def is_live(self) -> bool:
        return (self.redeemed_at is None and self.revoked_at is None
                and datetime.now(timezone.utc) <= self.expires_at)


class LeaseManager:
    def __init__(self, vault, audit_log, default_ttl_seconds: int = 300):
        self.vault = vault
        self.audit_log = audit_log
        self.default_ttl_seconds = default_ttl_seconds
        self._leases: dict[str, Lease] = {}

    def issue_lease(self, secret_id: str, user: str, role: str, reason: str,
                     ttl_seconds: Optional[int] = None) -> Lease:
        """Grants a claim, NOT the secret itself - redeem_lease is a
        separate step so single-use and TTL enforcement are independently
        demoable."""
        now = datetime.now(timezone.utc)
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        lease = Lease(
            lease_id=_secrets.token_hex(8), secret_id=secret_id, user=user, role=role,
            reason=reason, issued_at=now, expires_at=now + timedelta(seconds=ttl),
        )
        self._leases[lease.lease_id] = lease
        self.audit_log.append("lease_issued", {
            "lease_id": lease.lease_id, "secret_id": secret_id, "user": user, "role": role,
            "reason": reason, "ttl_seconds": ttl, "expires_at": lease.expires_at.isoformat(),
        })
        return lease

    def redeem_lease(self, lease_id: str) -> bytes:
        """Consumes the lease exactly once and returns the plaintext
        secret. Raises on replay, expiry, or revocation - each denial is
        itself an audit event."""
        lease = self._leases.get(lease_id)
        if lease is None:
            raise LeaseError(f"unknown lease {lease_id}")

        if lease.revoked_at is not None:
            self.audit_log.append("lease_redeem_denied", {"lease_id": lease_id, "cause": "revoked"})
            raise LeaseRevokedError(f"lease {lease_id} was revoked: {lease.revoke_reason}")
        if lease.redeemed_at is not None:
            self.audit_log.append("lease_redeem_denied", {"lease_id": lease_id, "cause": "already_redeemed"})
            raise LeaseAlreadyRedeemedError(
                f"lease {lease_id} was already redeemed at {lease.redeemed_at.isoformat()} - single-use only"
            )
        if datetime.now(timezone.utc) > lease.expires_at:
            self.audit_log.append("lease_redeem_denied", {"lease_id": lease_id, "cause": "expired"})
            raise LeaseExpiredError(f"lease {lease_id} expired at {lease.expires_at.isoformat()}")

        plaintext = self.vault.decrypt_secret(lease.secret_id)
        lease.redeemed_at = datetime.now(timezone.utc)
        self.audit_log.append("lease_redeemed", {
            "lease_id": lease_id, "secret_id": lease.secret_id, "user": lease.user,
        })
        return plaintext

    def revoke_lease(self, lease_id: str, reason: str) -> None:
        lease = self._leases[lease_id]
        if lease.redeemed_at is None and lease.revoked_at is None:
            lease.revoked_at = datetime.now(timezone.utc)
            lease.revoke_reason = reason
        self.audit_log.append("lease_revoked", {"lease_id": lease_id, "reason": reason})

    def revoke_all_for_user(self, user: str, reason: str) -> list[str]:
        """Used by Critical-tier auto-quarantine: kill every live (not yet
        redeemed/expired/revoked) lease for a user immediately."""
        revoked = []
        for lease in self._leases.values():
            if lease.user == user and lease.is_live:
                lease.revoked_at = datetime.now(timezone.utc)
                lease.revoke_reason = reason
                revoked.append(lease.lease_id)
        if revoked:
            self.audit_log.append("leases_revoked_bulk", {"user": user, "lease_ids": revoked, "reason": reason})
        return revoked
