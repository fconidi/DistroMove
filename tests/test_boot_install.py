"""EFI installation tests use copied trees in the host-local pytest cache."""
from pathlib import Path
import json
import subprocess

import pytest

from distromove.boot_install import (ID_CONFIG, OLD_ENTRY, install_grub,
    install_old_entry, old_system_entry, persist_bootloader_id,
    preflight_signed_chain, remove_old_entry, update_grub)
from distromove.esp import SecureBootUnsupported
from distromove.esp import choose_bootloader_id
from distromove.model import LoaderInfo


ESP_UUID = "ABCD-1234"
LOADER = LoaderInfo("debian", "\\EFI\\debian\\shimx64.efi", True, ESP_UUID)


class Journal:
    def __init__(self):
        self.events = []

    def intend(self, name, identity):
        self.events.append(("intend", name))
        return name

    def done(self, op, outcome):
        self.events.append(("done", op, outcome))


class Copy:
    def __init__(self, root):
        self.root = root
        self.esp = root / "boot/efi"
        self.esp.mkdir(parents=True)
        self.journal = Journal()
        self.calls = []

    def run(self, argv):
        self.calls.append(argv)
        if "--uefi-secure-boot" in argv:
            dest = self.esp / "EFI" / argv[3].split("=", 1)[1]
            dest.mkdir(parents=True)
            (dest / "shimx64.efi").write_bytes(
                (self.root / "usr/lib/shim/shimx64.efi.signed").read_bytes())
            (dest / "grubx64.efi").write_bytes(
                (self.root / "usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed").read_bytes())
        return subprocess.CompletedProcess(argv, 0, "", "")


class SecureRunner:
    def __init__(self, old_esp, uuid=ESP_UUID):
        self.old_esp = old_esp
        self.uuid = uuid

    def run(self, argv, readonly=False):
        assert readonly
        if argv[:2] == ["mokutil", "--sb-state"]:
            output = "SecureBoot enabled\n"
        elif argv[0] == "findmnt":
            output = json.dumps({"filesystems": [{"target": str(self.old_esp),
                         "source": "/dev/vda1", "fstype": "vfat"}]})
        elif argv[0] == "blkid":
            output = self.uuid + "\n"
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, output, "")


def test_entry_chainloads_real_old_loader_incl_shim(tmp_path):
    script = old_system_entry(LOADER, ESP_UUID, True, False)
    assert "search --no-floppy --fs-uuid --set=root ABCD-1234" in script
    assert "chainloader /EFI/debian/shimx64.efi" in script
    path = tmp_path / "old"
    path.write_text(script)
    rendered = subprocess.run(["sh", str(path)], check=True, text=True,
                              capture_output=True).stdout
    assert rendered.startswith("menuentry 'Previous system'")
    assert "chainloader /EFI/debian/shimx64.efi" in rendered
    assert old_system_entry(LoaderInfo("debian", "\\EFI\\debian\\grubx64.efi",
                                       False, ESP_UUID), ESP_UUID, True, False)


def test_entry_none_when_unencrypted_and_osprober_sees_it():
    assert old_system_entry(LOADER, ESP_UUID, False, True) is None


def test_order_entry_then_install_then_update(tmp_path):
    copy = Copy(tmp_path / "root")
    script = old_system_entry(LOADER, ESP_UUID, True, False)
    install_old_entry(copy, script)
    assert (copy.root / OLD_ENTRY).read_text() == script
    install_grub(copy, "debian-moved")
    update_grub(copy)
    assert copy.journal.events[:2] == [("intend", "old_grub_entry"),
                                      ("done", "old_grub_entry", "installed")]
    assert copy.calls[0][0] == "grub-install"
    assert copy.calls[1] == ["update-grub"]


def test_no_nvram_and_distinct_id(tmp_path):
    copy = Copy(tmp_path / "root")
    assert choose_bootloader_id(set(), "Debian") == "debian-moved"
    old = copy.esp / "EFI" / "Debian"
    old.mkdir(parents=True)
    with pytest.raises(ValueError, match="occupied"):
        install_grub(copy, "debian")
    install_grub(copy, "debian-moved")
    assert copy.calls == [["grub-install", "--target=x86_64-efi",
                           "--efi-directory=/boot/efi", "--bootloader-id=debian-moved",
                           "--no-nvram"]]
    with pytest.raises(ValueError):
        install_grub(copy, "../../debian")


def test_id_persisted_for_future_updates(tmp_path):
    copy = Copy(tmp_path / "root")
    persist_bootloader_id(copy, "debian-moved")
    config = copy.root / ID_CONFIG
    assert config.read_text().endswith('GRUB_DISTRIBUTOR="debian-moved"\n')
    assert config.stat().st_mode & 0o777 == 0o644


def test_update_after_entry_removal(tmp_path):
    copy = Copy(tmp_path / "root")
    install_old_entry(copy, old_system_entry(LOADER, ESP_UUID, True, False))
    remove_old_entry(copy)
    assert not (copy.root / OLD_ENTRY).exists()
    assert copy.calls == [["update-grub"]]
    remove_old_entry(copy)
    assert copy.calls == [["update-grub"], ["update-grub"]]


def _signed_fixture(tmp_path):
    copy = Copy(tmp_path / "root")
    old = tmp_path / "old-esp" / "EFI/debian"
    old.mkdir(parents=True)
    (old / "shimx64.efi").write_bytes(b"trusted shim")
    (old / "grubx64.efi").write_bytes(b"trusted grub")
    shim = copy.root / "usr/lib/shim/shimx64.efi.signed"
    grub = copy.root / "usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed"
    shim.parent.mkdir(parents=True)
    grub.parent.mkdir(parents=True)
    shim.write_bytes(b"trusted shim")
    grub.write_bytes(b"trusted grub")
    return copy, tmp_path / "old-esp"


def test_secure_boot_uses_signed_chain(tmp_path):
    copy, old_esp = _signed_fixture(tmp_path)
    chain = preflight_signed_chain(SecureRunner(old_esp), old_esp, copy.root, LOADER)
    install_grub(copy, "debian-moved", secure_boot=True, signed_chain=chain)
    assert "--uefi-secure-boot" in copy.calls[0]
    assert "--no-nvram" in copy.calls[0]


def test_secure_boot_refuses_unproven_or_changed_chain(tmp_path):
    copy, old_esp = _signed_fixture(tmp_path)
    with pytest.raises(SecureBootUnsupported):
        install_grub(copy, "debian-moved", secure_boot=True)
    chain = preflight_signed_chain(SecureRunner(old_esp), old_esp, copy.root, LOADER)
    (copy.root / "usr/lib/shim/shimx64.efi.signed").write_bytes(b"changed")
    with pytest.raises(SecureBootUnsupported):
        install_grub(copy, "debian-moved", secure_boot=True, signed_chain=chain)
    assert copy.calls == []


def test_secure_boot_refuses_mismatched_existing_binary(tmp_path):
    copy, old_esp = _signed_fixture(tmp_path)
    (old_esp / "EFI/debian/grubx64.efi").write_bytes(b"different")
    with pytest.raises(SecureBootUnsupported):
        preflight_signed_chain(SecureRunner(old_esp), old_esp, copy.root, LOADER)


def test_secure_boot_preflight_rejects_wrong_esp(tmp_path):
    copy, old_esp = _signed_fixture(tmp_path)
    with pytest.raises(SecureBootUnsupported, match="UUID"):
        preflight_signed_chain(SecureRunner(old_esp, "FFFF-FFFF"), old_esp,
                               copy.root, LOADER)
