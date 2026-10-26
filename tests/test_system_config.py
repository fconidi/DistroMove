"""Configuration tests use only copied trees in pytest's local cache."""
from pathlib import Path
from dataclasses import replace
import json
import os
import subprocess

import pytest

from distromove.disk import CryptoPlan
from distromove.journal import Journal
from distromove.model import UuidMap
from distromove.swap import SwapResult
from distromove.system_config import (OldUuidLeft, apply_configs, assert_identities,
                                      install_crypt_hooks, rebuild_initramfs,
                                      reset_snapper)


class Copy:
    def __init__(self, root, journal):
        self.root = root
        self.journal = journal
        self.calls = []

    def run(self, argv):
        self.calls.append(argv)
        if argv[:1] == ["update-initramfs"]:
            (self.root / "boot" / f"initrd.img-{argv[-1]}").write_bytes(b"new initrd")
        return subprocess.CompletedProcess(argv, 0, "", "")


def copied_root(tmp_path):
    root = tmp_path / "root"
    (root / "etc/default").mkdir(parents=True)
    (root / "etc/initramfs-tools/conf.d").mkdir(parents=True)
    (root / "etc/fstab").write_text("UUID=old-root / ext4 defaults 0 1\n")
    (root / "etc/crypttab").write_text("root UUID=old-luks none luks\n")
    (root / "etc/default/grub").write_text('GRUB_CMDLINE_LINUX_DEFAULT="root=UUID=old-root"\n')
    (root / "etc/initramfs-tools/conf.d/resume").write_text("RESUME=UUID=old-swap\n")
    journal = Journal(tmp_path / "journal", host_root_uuid="host")
    return Copy(root, journal)


def mapping():
    return UuidMap({"old-root": "new-root"}, {"old-luks": "new-luks"}, {}, {}, {},
                   {"old-swap": "new-swap"})


def swap():
    return SwapResult("swap-one", "partition", "/dev/vda3", "old-swap", "/dev/vdb3",
                      "new-swap", None, None, None, False, True)


def test_apply_configs_raises_on_old_uuid_left(tmp_path):
    copy = copied_root(tmp_path)
    grub = copy.root / "etc/default/grub"
    grub.write_text('GRUB_CMDLINE_LINUX_DEFAULT="root=UUID=old-root other=old-luks"\n')
    with pytest.raises(OldUuidLeft):
        apply_configs(copy, mapping(), [swap()], boot_in_luks=False)
    assert "old-root" in (copy.root / "etc/fstab").read_text()


def test_apply_configs_requires_boot_crypto_classification(tmp_path):
    copy = copied_root(tmp_path)
    with pytest.raises(ValueError, match="boot encryption"):
        apply_configs(copy, mapping(), [swap()])


def test_random_key_swap_has_no_persistent_uuid_reference(tmp_path):
    copy = copied_root(tmp_path)
    with pytest.raises(ValueError, match="random-key"):
        apply_configs(copy, mapping(), [replace(swap(), random_key=True, uuid=None)],
                      boot_in_luks=False)


def test_cryptodisk_flag_only_when_boot_in_luks(tmp_path):
    copy = copied_root(tmp_path)
    apply_configs(copy, mapping(), [swap()], boot_in_luks=True)
    grub = (copy.root / "etc/default/grub").read_text()
    assert "GRUB_ENABLE_CRYPTODISK=y" in grub
    assert "old-root" not in grub
    assert "new-swap" in (copy.root / "etc/initramfs-tools/conf.d/resume").read_text()
    apply_configs(copy, mapping(), [swap()], boot_in_luks=False)
    assert "GRUB_ENABLE_CRYPTODISK=n" in (copy.root / "etc/default/grub").read_text()


@pytest.mark.skipif(os.geteuid() != 0,
                    reason="the early key file must be owned by root; a test file is not")
def test_initramfs_hook_copies_crypttab_and_keyfile(tmp_path):
    copy = copied_root(tmp_path)
    key = copy.root / "etc/cryptsetup-keys.d/root.key"
    key.parent.mkdir()
    key.write_bytes(b"dummy secret")
    key.chmod(0o600)
    crypto = CryptoPlan({}, {"root": "/etc/cryptsetup-keys.d/root.key"}, {},
                        {"root": "initramfs"}, {})
    install_crypt_hooks(copy, crypto, boot_in_luks=True)
    hook = copy.root / "etc/initramfs-tools/hooks/distromove-crypt"
    assert hook.stat().st_mode & 0o777 == 0o700
    assert "copy_file config /etc/crypttab" in hook.read_text()
    assert "/etc/cryptsetup-keys.d/root.key" in hook.read_text()
    subprocess.run(["sh", "-n", str(hook)], check=True)


def test_keyfile_not_in_unencrypted_boot(tmp_path):
    copy = copied_root(tmp_path)
    crypto = CryptoPlan({}, {"root": "/etc/root.key"}, {}, {"root": "initramfs"}, {})
    with pytest.raises(ValueError, match="unencrypted"):
        install_crypt_hooks(copy, crypto, boot_in_luks=False)
    assert not (copy.root / "etc/initramfs-tools/hooks/distromove-crypt").exists()


def test_initramfs_keyfile_must_be_private(tmp_path):
    copy = copied_root(tmp_path)
    key = copy.root / "etc/root.key"
    key.write_bytes(b"dummy secret")
    key.chmod(0o644)
    crypto = CryptoPlan({}, {"root": "/etc/root.key"}, {}, {"root": "initramfs"}, {})
    with pytest.raises(ValueError, match="other users"):
        install_crypt_hooks(copy, crypto, boot_in_luks=True)


def test_keyfile_after_root_not_in_initramfs(tmp_path):
    copy = copied_root(tmp_path)
    crypto = CryptoPlan({}, {"home": "/etc/home.key"}, {}, {"home": "after-root"}, {})
    install_crypt_hooks(copy, crypto, boot_in_luks=False)
    assert "/etc/home.key" not in (copy.root / "etc/initramfs-tools/hooks/distromove-crypt").read_text()


def test_unclassified_crypttab_keyfile_is_refused(tmp_path):
    copy = copied_root(tmp_path)
    (copy.root / "etc/crypttab").write_text("root UUID=old-luks /etc/root.key luks\n")
    with pytest.raises(ValueError, match="classification"):
        install_crypt_hooks(copy)


def test_all_kernels_rebuilt(tmp_path):
    copy = copied_root(tmp_path)
    for version in ("6.1.0-a", "6.1.0-b"):
        (copy.root / "boot").mkdir(exist_ok=True)
        (copy.root / "boot" / f"vmlinuz-{version}").write_bytes(b"kernel")
        (copy.root / "lib/modules" / version).mkdir(parents=True)
    (copy.root / "boot/initrd.img-6.1.0-a").write_bytes(b"old")
    images = rebuild_initramfs(copy)
    assert [path.name for path in images] == ["initrd.img-6.1.0-a", "initrd.img-6.1.0-b"]
    assert ["update-initramfs", "-u", "-k", "6.1.0-a"] in copy.calls
    assert ["update-initramfs", "-c", "-k", "6.1.0-b"] in copy.calls


def test_snapper_reset_only_syslinuxos(tmp_path):
    copy = copied_root(tmp_path)
    (copy.root / "etc/os-release").write_text("ID=debian\n")
    assert not reset_snapper(copy)
    (copy.root / "etc/os-release").write_text("ID=syslinuxos\n")
    (copy.root / ".snapshots").mkdir()
    config = copy.root / "etc/snapper/configs/root"
    config.parent.mkdir(parents=True)
    config.write_text('SUBVOLUME="/old"\nTIMELINE_CREATE="yes"\n')
    assert reset_snapper(copy)
    assert 'SUBVOLUME="/"' in config.read_text()
    assert 'TIMELINE_CREATE="yes"' in config.read_text()


def test_assert_identities_fails_on_old_device(tmp_path):
    copy = copied_root(tmp_path)

    class Runner:
        def run(self, argv, **kwargs):
            if argv[0] == "findmnt":
                return subprocess.CompletedProcess(argv, 0, json.dumps({"filesystems": [
                    {"target": str(copy.root), "source": "/dev/vda2", "fstype": "ext4"}]}), "")
            if argv[0] == "blkid":
                return subprocess.CompletedProcess(argv, 0, "old-root\n", "")
            raise AssertionError(argv)

    copy.r = Runner()
    with pytest.raises(ValueError, match="identity"):
        assert_identities(copy, {"/": "new-root"})


def test_assert_identities_accepts_new_root(tmp_path):
    copy = copied_root(tmp_path)

    class Runner:
        def run(self, argv, **kwargs):
            if argv[0] == "findmnt":
                return subprocess.CompletedProcess(argv, 0, json.dumps({"filesystems": [
                    {"target": str(copy.root), "source": "UUID=new-root", "fstype": "ext4"}]}), "")
            raise AssertionError(argv)

    copy.r = Runner()
    assert assert_identities(copy, {"/": "new-root"}) is None
