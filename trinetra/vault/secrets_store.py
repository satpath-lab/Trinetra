"""
In-memory encrypted vault for privileged banking secrets (simulated DB
passwords, SSH keys, SWIFT-equivalent API tokens). Every secret is sealed
at rest with hybrid ML-KEM-768 + X25519 envelope encryption (crypto.py);
nothing is ever held decrypted except for the instant a JIT lease is
redeemed (see leases.py) - there is no standing plaintext copy anywhere.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from . import crypto


@dataclass(frozen=True)
class SecretMeta:
    secret_id: str
    description: str
    system: str          # the privileged system this secret unlocks
    required_role: str   # which banking role is entitled to request it


class Vault:
    def __init__(self):
        self.keypair = crypto.VaultKeyPair.generate()
        self._sealed: dict[str, crypto.SealedBlob] = {}
        self._meta: dict[str, SecretMeta] = {}

    def store_secret(self, meta: SecretMeta, plaintext: bytes) -> None:
        self._sealed[meta.secret_id] = crypto.seal(self.keypair, plaintext, aad=meta.secret_id.encode())
        self._meta[meta.secret_id] = meta

    def meta(self, secret_id: str) -> SecretMeta:
        return self._meta[secret_id]

    def has_secret(self, secret_id: str) -> bool:
        return secret_id in self._sealed

    def list_secrets(self) -> list[SecretMeta]:
        return list(self._meta.values())

    def decrypt_secret(self, secret_id: str) -> bytes:
        """Not for direct use - only LeaseManager.redeem_lease should call
        this, so every decryption is tied to a short-TTL single-use lease."""
        blob = self._sealed[secret_id]
        meta = self._meta[secret_id]
        return crypto.unseal(self.keypair, blob, aad=meta.secret_id.encode())


ROLE_TO_SECRET_ID = {
    "Core-Banking DBA": "core_banking_db_prod",
    "Network/Infra Admin": "infra_root_ssh_key",
    "Vendor/Third-Party Support Engineer": "vendor_swift_gateway_token",
    "Branch Ops Manager": "branch_teller_override_key",
    "SOC Analyst": "soc_siem_admin_token",
}


def seed_demo_vault(cfg) -> Vault:
    """Populate a vault with one plausible privileged secret per banking
    role, matching config.BANKING_ROLES."""
    vault = Vault()
    demo_secrets = [
        SecretMeta("core_banking_db_prod", "Core Banking prod DB password",
                   "CBS-PROD-ORA19C", "Core-Banking DBA"),
        SecretMeta("infra_root_ssh_key", "Root SSH private key for core infra hosts",
                   "INFRA-JUMPHOST-01", "Network/Infra Admin"),
        SecretMeta("vendor_swift_gateway_token", "SWIFT-equivalent gateway API token",
                   "SWIFT-GATEWAY", "Vendor/Third-Party Support Engineer"),
        SecretMeta("branch_teller_override_key", "Branch teller override signing key",
                   "BRANCH-OPS-CONSOLE", "Branch Ops Manager"),
        SecretMeta("soc_siem_admin_token", "SOC SIEM admin API token",
                   "SIEM-CONSOLE", "SOC Analyst"),
    ]
    for meta in demo_secrets:
        fake_secret = f"SIMULATED-SECRET::{meta.secret_id}::{os.urandom(8).hex()}".encode()
        vault.store_secret(meta, fake_secret)
    return vault
