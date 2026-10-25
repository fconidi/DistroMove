"""Preflight and creation of destination storage.

All mutating commands in this module must follow a durable journal intent.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .model import Keyslot, LuksInfo, Source
from .probe import classify_keys


class UnsupportedKdf(ValueError):
    """A source keyslot or boot-time decryption mode cannot be recreated."""


class UnsafeKeyfile(ValueError):
    """A key needed in an unencrypted initramfs would leak its secret."""


@dataclass(frozen=True)
class GrubCaps:
    luks_versions: frozenset[int]
    kdfs: frozenset[str]
    ciphers: frozenset[str]


@dataclass(frozen=True)
class CryptoPlan:
    per_volume: dict[str, list[Keyslot]]
    keyfiles: dict[str, str]
    boot_in_luks: dict[str, bool]
    key_class: dict[str, Literal["initramfs", "after-root"]]
    luks_by_volume: dict[str, LuksInfo]


def validate_crypto_plan(source: Source, grub_caps: GrubCaps) -> CryptoPlan:
    """Select a KDF for each new container before any destination write.

    GRUB can open LUKS2 only through PBKDF2. Its installed capabilities are
    supplied by the caller rather than assumed from a version string.
    """
    boot = next((v for v in source.volumes if v.role == "boot"), None)
    root = next((v for v in source.volumes if v.role == "root"), None)
    boot_encrypted = ((boot.luks is not None) if boot is not None else
                      (root is not None and root.luks is not None))
    classes = classify_keys(source)
    if not boot_encrypted and any(value == "initramfs" for value in classes.values()):
        raise UnsafeKeyfile("an initramfs keyfile would be exposed on unencrypted /boot")

    per_volume: dict[str, list[Keyslot]] = {}
    keyfiles: dict[str, str] = {}
    boot_flags: dict[str, bool] = {}
    luks_by_volume: dict[str, LuksInfo] = {}
    for item in [*source.volumes, *source.swaps]:
        luks = item.luks
        if luks is None:
            continue
        volume_id = item.volume_id
        if volume_id in per_volume:
            raise ValueError(f"duplicate encrypted volume id: {volume_id}")
        if luks.version not in (1, 2):
            raise UnsupportedKdf(f"{volume_id}: unsupported LUKS version")
        candidates = [slot for slot in luks.keyslots
                      if slot.kdf in {"pbkdf2", "argon2i", "argon2id"}]
        if not candidates:
            raise UnsupportedKdf(f"{volume_id}: no supported source keyslot")
        role = getattr(item, "role", "swap")
        needs_grub = ((role == "boot" or (role == "root" and boot is None))
                      and boot_encrypted)
        if needs_grub:
            if luks.version not in grub_caps.luks_versions or luks.cipher not in grub_caps.ciphers:
                raise UnsupportedKdf(f"{volume_id}: GRUB cannot read this LUKS container")
            selected = next((slot for slot in candidates
                             if slot.kdf == "pbkdf2" and slot.kdf in grub_caps.kdfs), None)
            if selected is None:
                raise UnsupportedKdf(f"{volume_id}: GRUB requires a PBKDF2 keyslot")
        else:
            selected = candidates[0]
        if luks.version == 1 and selected.kdf != "pbkdf2":
            raise UnsupportedKdf(f"{volume_id}: LUKS1 requires PBKDF2")
        per_volume[volume_id] = [selected]
        luks_by_volume[volume_id] = luks
        boot_flags[volume_id] = bool(needs_grub)
        if luks.keyfile:
            keyfiles[volume_id] = luks.keyfile
    return CryptoPlan(per_volume, keyfiles, boot_flags, classes, luks_by_volume)
