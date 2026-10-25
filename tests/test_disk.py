"""Destination creation is tested with command recorders, never real disks."""

from dataclasses import replace

import pytest

from distromove.disk import GrubCaps, UnsafeKeyfile, UnsupportedKdf, validate_crypto_plan
from distromove.model import Esp, Keyslot, LuksInfo, Partition, Source, SwapRef, Volume


def partition():
    return Partition("/dev/vda2", "vda2", "/dev/vda", 2, 8 * 1024**3, "crypto_LUKS",
                     "old-luks", "old-part", None, "/", "wwn-1", "serial-1", None,
                     2048, 16 * 1024**3, 512)


def luks(*kdfs, keyfile=None, version=2):
    return LuksInfo(version, "aes-xts-plain64", 512, 512,
                    [Keyslot(i, kdf, "aes-xts-plain64") for i, kdf in enumerate(kdfs)],
                    "old-luks", "old-root", keyfile)


def source(*, root_luks=None, boot=None, swaps=(), boot_inside_luks=False):
    root = Volume("root", "root", "/", partition(), root_luks, "btrfs", "old-fs",
                  1024, 1024, 1, None, boot_inside_luks)
    vols = [root] + ([boot] if boot else [])
    return Source("btrfs", "debian", vols, [], Esp(partition(), "/boot/efi", [], []),
                  list(swaps), "old-fs", False)


CAPS = GrubCaps(frozenset({1, 2}), frozenset({"pbkdf2"}),
                frozenset({"aes-xts-plain64"}))


def test_preflight_refuses_argon2_only_with_boot_in_luks_before_any_call():
    with pytest.raises(UnsupportedKdf, match="PBKDF2"):
        validate_crypto_plan(source(root_luks=luks("argon2id"), boot_inside_luks=True), CAPS)


def test_crypto_plan_has_pbkdf2_slot_when_boot_in_luks():
    plan = validate_crypto_plan(source(root_luks=luks("argon2id", "pbkdf2"),
                                       boot_inside_luks=True), CAPS)
    assert [slot.kdf for slot in plan.per_volume["root"]] == ["pbkdf2"]
    assert plan.boot_in_luks == {"root": True}
    assert plan.luks_by_volume["root"].sector_size == 512


def test_preflight_rejects_grub_without_luks2_support():
    limited = replace(CAPS, luks_versions=frozenset({1}))
    with pytest.raises(UnsupportedKdf, match="GRUB"):
        validate_crypto_plan(source(root_luks=luks("pbkdf2"), boot_inside_luks=True), limited)


def test_initramfs_key_on_unencrypted_boot_refused_in_preflight():
    boot = Volume("boot", "boot", "/boot", partition(), None, "ext4", "boot-fs",
                  1024, 1024, 1, None, False)
    with pytest.raises(UnsafeKeyfile, match="unencrypted"):
        validate_crypto_plan(source(root_luks=luks("pbkdf2", keyfile="/etc/root.key"),
                                    boot=boot), CAPS)


def test_key_class_and_encrypted_swap_are_keyed_by_volume_id():
    swap = SwapRef("swap-1", "partition", "/dev/vda3", None, "old-swap", 1024**3,
                   luks("argon2id", keyfile="/etc/swap.key"), False)
    plan = validate_crypto_plan(source(root_luks=luks("pbkdf2"), swaps=[swap]), CAPS)
    assert set(plan.per_volume) == {"root", "swap-1"}
    assert plan.keyfiles == {"swap-1": "/etc/swap.key"}
    assert plan.key_class == {"swap-1": "after-root"}
