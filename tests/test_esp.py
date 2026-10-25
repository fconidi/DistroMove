"""ESP and firmware operations are tested with command recorders and local fixtures."""

from pathlib import Path
import json
import subprocess

import pytest

from distromove.esp import (PartialRegistration, SecureBootUnsupported, choose_bootloader_id,
                            copy_esp, create_esp, detect_loader, firmware_uses_esp,
                            foreign_entries, parse_efibootmgr, register_new_entry,
                            remove_entry, secure_boot_enabled)
from distromove.journal import Journal
from distromove.model import CreatedPartition, PlannedIdentity


FIXTURE = Path(__file__).parent / "fixtures/efibootmgr_shared.txt"


def test_parse_efibootmgr():
    state = parse_efibootmgr(FIXTURE.read_text())
    assert state.current == "0001"
    assert state.order == ("0001", "0000", "0002")
    assert set(state.entries) == {"0000", "0001", "0002"}


def test_detect_loader_shim_and_plain_grub():
    state = parse_efibootmgr(FIXTURE.read_text())
    loader = detect_loader(state, {"6a4b0f1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b": {"debian": {"shimx64.efi", "grubx64.efi"}}})
    assert loader.via_shim and loader.bootloader_id == "debian"
    plain = FIXTURE.read_text().replace("shimx64.efi", "grubx64.efi")
    assert not detect_loader(parse_efibootmgr(plain), {"6a4b0f1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b": {"debian": {"grubx64.efi"}}}).via_shim


def test_bootloader_id_unique_case_insensitive():
    assert choose_bootloader_id({"Debian", "debian-moved"}, "debian") == "debian-moved-2"


class FirmwareRunner:
    def __init__(self, before, *, fail_order=False):
        self.before = before
        self.created = False
        self.ordered = False
        self.fail_order = fail_order
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[:2] == ["lsblk", "--json"]:
            return subprocess.CompletedProcess(argv, 0, json.dumps({"blockdevices": [
                {"partn": 3, "partuuid": "11111111-2222-3333-4444-555555555555"}]}), "")
        if argv == ["efibootmgr", "-v"]:
            text = self.before
            if self.created:
                text += "\nBoot0003* DistroMove\tHD(3,GPT,11111111-2222-3333-4444-555555555555,0x800,0x100000)/File(\\EFI\\moved\\shimx64.efi)\n"
                if self.ordered:
                    text = text.replace("BootOrder: 0001,0000,0002", "BootOrder: 0003,0001,0000,0002")
            return subprocess.CompletedProcess(argv, 0, text, "")
        if "--create-only" in argv:
            self.created = True
        elif argv[:2] == ["efibootmgr", "-o"]:
            if self.fail_order:
                raise RuntimeError("firmware rejected order")
            self.ordered = True
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")


def test_new_entry_first_others_kept_windows_untouched(tmp_path):
    r = FirmwareRunner(FIXTURE.read_text())
    j = Journal(tmp_path / "journal", host_root_uuid="host")
    number = register_new_entry(r, "/dev/nvme0n1", 3, "\\EFI\\moved\\shimx64.efi", "DistroMove", j)
    assert number == "0003"
    assert ["efibootmgr", "-o", "0003,0001,0000,0002"] in r.calls
    assert ["efibootmgr", "--create-only", "--disk", "/dev/nvme0n1", "--part", "3", "--loader", "\\EFI\\moved\\shimx64.efi", "--label", "DistroMove"] in r.calls


def test_partial_registration_reported(tmp_path):
    r = FirmwareRunner(FIXTURE.read_text(), fail_order=True)
    j = Journal(tmp_path / "journal", host_root_uuid="host")
    with pytest.raises(PartialRegistration) as exc:
        register_new_entry(r, "/dev/mmcblk0", 3, "\\EFI\\moved\\shimx64.efi", "DistroMove", j)
    assert exc.value.bootnum == "0003" and not exc.value.ordered


def test_secure_boot_without_signed_chain_refused():
    class Runner:
        def run(self, argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, "SecureBoot enabled\n", "")
    assert secure_boot_enabled(Runner())
    with pytest.raises(SecureBootUnsupported):
        detect_loader(parse_efibootmgr(FIXTURE.read_text()), {"6a4b0f1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b": {"debian": {"shimx64.efi"}}}, secure_boot=True)
    with pytest.raises(SecureBootUnsupported):
        detect_loader(parse_efibootmgr(FIXTURE.read_text()), {"6a4b0f1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b": {"debian": {"shimx64.efi", "grubx64.efi"}}}, secure_boot=True)


def test_foreign_entries_detected():
    state = parse_efibootmgr(FIXTURE.read_text())
    dirs = {"6a4b0f1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b":
            {"debian": {"shimx64.efi"}, "Recovery": {"bootx64.efi"}}}
    assert foreign_entries(state, dirs) == ["0000", "EFI/Recovery"]


def test_firmware_uses_esp_differs_from_mounted_esp():
    state = parse_efibootmgr(FIXTURE.read_text())
    assert firmware_uses_esp(state, "5d0b6f1a-3c2e-4b8d-9f7a-1e2d3c4b5a69")
    assert not firmware_uses_esp(state, "11111111-2222-3333-4444-555555555555")


def test_copy_esp_never_deletes_source(tmp_path):
    old, new = tmp_path / "old", tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (old / "EFI").mkdir()
    (old / "EFI" / "boot.efi").write_text("old")
    (new / "EFI").mkdir()
    (new / "EFI" / "boot.efi").write_text("bad")

    class Runner:
        def __init__(self):
            self.calls = []

        def run(self, argv, **kwargs):
            self.calls.append(argv)
            if argv[0] == "findmnt":
                path = argv[argv.index("--mountpoint") + 1]
                device = "/dev/vda1" if path == str(old) else "/dev/vdb1"
                fs_uuid = "1111-2222" if path == str(old) else "3333-4444"
                return subprocess.CompletedProcess(argv, 0, json.dumps({"filesystems": [
                    {"target": path, "fstype": "vfat", "source": device,
                     "uuid": fs_uuid}]}), "")
            if argv[0] == "rsync":
                from distromove.runner import Runner as RealRunner
                return RealRunner().run(argv)
            raise AssertionError(argv)

    r = Runner()
    j = Journal(tmp_path / "journal", host_root_uuid="host")
    with pytest.raises(ValueError, match="owned"):
        copy_esp(r, old, new, j)
    op = j.intend("create_esp", {"esp_partuuid": "new-part", "fs_uuid": "3333-4444"},
                  creates="filesystem", device="/dev/vdb1")
    j.done(op, "created", device="/dev/vdb1")
    copy_esp(r, old, new, j)
    assert (old / "EFI" / "boot.efi").read_text() == "old"
    assert (new / "EFI" / "boot.efi").read_text() == "old"
    assert "--delete" not in r.calls[-3]


def test_create_esp_uses_planned_fat_id_and_requires_journal_ownership(tmp_path):
    created = CreatedPartition("esp", "/dev/vdb3", "new-part", 2048, 1000000,
                               None, "ABCD-1234")
    planned = PlannedIdentity("new-part", None, "ABCD-1234")

    class Runner:
        def __init__(self):
            self.calls = []

        def run(self, argv, **kwargs):
            self.calls.append(argv)
            if argv[:2] == ["lsblk", "--json"]:
                out = json.dumps({"blockdevices": [{"path": "/dev/vdb3", "type": "part",
                    "partuuid": "new-part", "start": 2048, "size": 512000000,
                    "log-sec": 512}]})
            elif argv[:2] == ["wipefs", "-J"]:
                out = '{"signatures": []}'
            elif argv[:2] == ["blkid", "-p"]:
                out = "ABCD-1234\n" if "UUID" in argv else "vfat\n"
            elif argv[0] == "mkfs.vfat":
                out = ""
            else:
                raise AssertionError(argv)
            return subprocess.CompletedProcess(argv, 0, out, "")

    r = Runner()
    j = Journal(tmp_path / "journal", host_root_uuid="host")
    with pytest.raises(ValueError, match="journal"):
        create_esp(r, created, planned, j)
    op = j.intend("create_partition", {"partuuid": "new-part", "fs_uuid": "ABCD-1234"},
                  creates="partition")
    j.done(op, "created", path="/dev/vdb3")
    assert create_esp(r, created, planned, j) == "ABCD-1234"
    assert ["mkfs.vfat", "-F", "32", "-i", "ABCD1234", "/dev/vdb3"] in r.calls


def test_remove_entry_keeps_others_and_current(tmp_path):
    before = FIXTURE.read_text()

    class Runner:
        def __init__(self):
            self.removed = False
            self.calls = []

        def run(self, argv, **kwargs):
            self.calls.append(argv)
            if argv == ["efibootmgr", "-v"]:
                text = before
                if self.removed:
                    text = text.replace("BootOrder: 0001,0000,0002", "BootOrder: 0001,0002")
                    text = "\n".join(line for line in text.splitlines()
                                     if not line.startswith("Boot0000"))
                return subprocess.CompletedProcess(argv, 0, text, "")
            if argv == ["efibootmgr", "-b", "0000", "-B"]:
                self.removed = True
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise AssertionError(argv)

    r = Runner()
    j = Journal(tmp_path / "journal", host_root_uuid="host")
    with pytest.raises(ValueError, match="current"):
        remove_entry(r, "0001", j)
    remove_entry(r, "0000", j)
    assert r.removed
