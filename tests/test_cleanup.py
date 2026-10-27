"""Cleanup tests mutate only fake snapshots and files under the host-local cache."""
from dataclasses import replace
import json
import subprocess

import pytest

from distromove.cleanup import _locate, delete_old_system, deletion_recovery_tokens
from distromove.journal import Journal
from distromove.safety import can_delete_old, confirmation_text
from distromove.state import load_state, save_state
from test_safety import OLD_ESP, OLD_PART, live, state


class System:
    def __init__(self, snapshot, *, fail_after_delete=False, fail_uefi=False):
        self.snapshot = snapshot
        self.calls = []
        self.rechecks = 0
        self.fail_after_delete = fail_after_delete
        self.fail_uefi = fail_uefi

    def recheck(self):
        self.rechecks += 1
        return self.snapshot

    def run(self, argv, **kwargs):
        self.calls.append(argv)
        if argv == ["efibootmgr", "-v"]:
            order = ",".join(self.snapshot.boot_entries)
            output = (f"BootCurrent: {self.snapshot.boot_current}\nBootOrder: {order}\n" +
                      "\n".join(self.snapshot.boot_entries.values()) + "\n")
            return subprocess.CompletedProcess(argv, 0, output, "")
        if argv[:3] == ["efibootmgr", "-b", "0001"]:
            if self.fail_uefi:
                self.fail_uefi = False
                raise RuntimeError("injected firmware failure")
            entries = dict(self.snapshot.boot_entries)
            entries.pop("0001")
            self.snapshot = replace(self.snapshot, boot_entries=entries)
        elif argv[:3] == ["lsblk", "--json", "--nodeps"]:
            return subprocess.CompletedProcess(argv, 0, json.dumps({"blockdevices": [
                {"path": "/dev/vdb", "wwn": "wwn-disk", "serial": "serial-disk",
                 "log-sec": 512}]}), "")
        elif argv[:2] == ["lsblk", "--json"]:
            rows = []
            if any(i.partuuid == OLD_PART for i in self.snapshot.identities):
                rows.append({"path": "/dev/vdb1", "pkname": "vdb", "partn": 1,
                             "partuuid": OLD_PART, "start": 2048})
            if any(i.partuuid == OLD_ESP for i in self.snapshot.identities):
                rows.append({"path": "/dev/vdb2", "pkname": "vdb", "partn": 2,
                             "partuuid": OLD_ESP, "start": 8192})
            return subprocess.CompletedProcess(argv, 0, json.dumps({"blockdevices": rows}), "")
        elif argv[:2] == ["sgdisk", "--delete=1"]:
            self.snapshot = replace(self.snapshot, identities=[i for i in self.snapshot.identities
                                                                if i.partuuid != OLD_PART])
            if self.fail_after_delete:
                self.fail_after_delete = False
                raise RuntimeError("killed after partition removal")
        elif argv[:2] == ["sgdisk", "--delete=2"]:
            self.snapshot = replace(self.snapshot, identities=[i for i in self.snapshot.identities
                                                                if i.partuuid != OLD_ESP],
                                    esp_contents={k: v for k, v in self.snapshot.esp_contents.items()
                                                  if k != OLD_ESP})
        elif argv[:2] == ["cryptsetup", "luksErase"]:
            pass
        elif argv[:1] in (["update-grub"], ["partprobe"]) or argv == ["udevadm", "settle"]:
            pass
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")


def setup(tmp_path, **kwargs):
    root = tmp_path / "new-root"
    root.mkdir()
    s = state()
    save_state(s, root)
    script = root / "etc/grub.d/40_distromove_old"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\n# DistroMove old-system entry\n")
    journal = Journal(tmp_path / "journal", migration_id=s.migration_id + "-delete",
                      host_root_uuid=s.new_root_uuid)
    system = System(live(s), **kwargs)
    return root, s, script, journal, system


def cleanup(root, s, journal, system, **kwargs):
    erase = kwargs.pop("erase_luks_header", False)
    delete_esp = kwargs.pop("delete_old_esp", False)
    def resolver(path):
        if path == f"/dev/disk/by-partuuid/{OLD_PART}":
            return "/dev/vdb1"
        if path == "/dev/disk/by-id/disk":
            return "/dev/vdb"
        if path == f"/dev/disk/by-partuuid/{OLD_ESP}":
            return "/dev/vdb2"
        return path
    return delete_old_system(system, s, erase_luks_header=erase,
                             delete_old_esp=delete_esp, journal=journal,
                             recheck=system.recheck, state_root=root,
                             confirmation=confirmation_text(s, delete_old_esp=delete_esp,
                                                            erase_luks_header=erase),
                             lock_path=root / "cleanup.lock", resolve=resolver, **kwargs)


def test_order_grub_entry_uefi_entry_partitions(tmp_path):
    root, s, script, journal, system = setup(tmp_path)
    result = cleanup(root, s, journal, system)
    assert result.phase == "DELETED"
    commands = [call[0] for call in system.calls]
    assert commands.index("update-grub") < commands.index("efibootmgr")
    assert ["efibootmgr", "-b", "0001", "-B"] in system.calls
    assert ["sgdisk", "--delete=1", "/dev/disk/by-id/disk"] in system.calls
    assert not script.exists()
    assert load_state(root, "new-root").phase == "DELETED"


def test_delete_rechecks_before_each_step(tmp_path):
    root, s, _, journal, system = setup(tmp_path)
    cleanup(root, s, journal, system)
    assert system.rechecks >= 5


def test_delete_interrupted_then_resumed_skips_done_steps(tmp_path):
    root, s, _, journal, system = setup(tmp_path, fail_uefi=True)
    with pytest.raises(RuntimeError, match="firmware failure"):
        cleanup(root, s, journal, system)
    saved = load_state(root, "new-root")
    assert "grub_entry" in saved.deletion_done
    assert saved.phase == "DELETING"
    cleanup(root, saved, journal, system)
    assert sum(call == ["update-grub"] for call in system.calls) == 1


def test_resume_refuses_reappeared_grub_entry(tmp_path):
    root, s, script, journal, system = setup(tmp_path, fail_uefi=True)
    with pytest.raises(RuntimeError):
        cleanup(root, s, journal, system)
    script.write_text("#!/bin/sh\n# DistroMove old-system entry\n")
    with pytest.raises(ValueError, match="old GRUB entry returned"):
        cleanup(root, load_state(root, "new-root"), journal, system)


def test_interruption_between_removal_and_outcome_line_reconciled_by_absence(tmp_path):
    root, s, _, journal, system = setup(tmp_path, fail_after_delete=True)
    with pytest.raises(RuntimeError, match="killed"):
        cleanup(root, s, journal, system)
    saved = load_state(root, "new-root")
    assert f"partition:{OLD_PART}" not in saved.deletion_done
    result = cleanup(root, saved, journal, system)
    assert result.phase == "DELETED"
    assert sum(call[0] == "sgdisk" for call in system.calls) == 1


def test_delete_rejects_changed_identity_before_mutation(tmp_path):
    root, s, _, journal, system = setup(tmp_path)
    system.snapshot = replace(system.snapshot, identities=[
        replace(system.snapshot.identities[0], disk_serial="changed"),
        *system.snapshot.identities[1:]])
    with pytest.raises(ValueError, match="guard"):
        cleanup(root, s, journal, system)
    assert system.calls == []
    assert (root / "etc/grub.d/40_distromove_old").exists()


def test_delete_requires_exact_confirmation(tmp_path):
    root, s, _, journal, system = setup(tmp_path)
    with pytest.raises(ValueError, match="confirmation"):
        delete_old_system(system, s, erase_luks_header=False, delete_old_esp=False,
                          journal=journal, recheck=system.recheck, state_root=root,
                          confirmation="yes", lock_path=root / "cleanup.lock")
    assert system.calls == []


def test_old_esp_deleted_only_when_requested_and_separate(tmp_path):
    root, s, _, journal, system = setup(tmp_path)
    result = cleanup(root, s, journal, system, delete_old_esp=True)
    assert f"old_esp:{OLD_ESP}" in result.deletion_done
    assert ["sgdisk", "--delete=2", "/dev/disk/by-id/disk"] in system.calls


def test_optional_luks_erase_precedes_partition_delete(tmp_path):
    root, s, _, journal, system = setup(tmp_path)
    result = cleanup(root, s, journal, system, erase_luks_header=True)
    assert f"luks:{OLD_PART}" in result.deletion_done
    commands = [call[0] for call in system.calls]
    assert commands.index("cryptsetup") < commands.index("sgdisk")


def test_partition_lookup_converts_512_unit_start_on_4k_disk():
    class FourK:
        def run(self, argv, **kwargs):
            if "--nodeps" in argv:
                rows = [{"path": "/dev/vdb", "wwn": "wwn-disk",
                         "serial": "serial-disk", "log-sec": 4096}]
            else:
                rows = [{"path": "/dev/vdb1", "pkname": "vdb", "partn": 1,
                         "partuuid": OLD_PART, "start": 16384}]
            return subprocess.CompletedProcess(argv, 0, json.dumps({"blockdevices": rows}), "")
    def resolve(path):
        return {f"/dev/disk/by-partuuid/{OLD_PART}": "/dev/vdb1",
                "/dev/disk/by-id/disk": "/dev/vdb"}.get(path, path)
    assert _locate(FourK(), state().old_volumes[0], resolve) == (
        "/dev/disk/by-id/disk", 1, f"/dev/disk/by-partuuid/{OLD_PART}")


def test_a_partition_removed_without_its_mark_is_recoverable_and_allowed(tmp_path):
    """The deletion stopped between the removal and its record; the retry must be offered."""
    root, s, _, journal, system = setup(tmp_path)
    s = replace(s, phase="DELETING", deletion_done=["grub_entry", "uefi_entry",
                                                    f"luks:{OLD_PART}"])
    save_state(s, root)
    journal.intend("delete_old_partition",
                   {"partuuid": OLD_PART, "disk_wwn": s.old_volumes[0].disk_wwn,
                    "start_sectors": s.old_volumes[0].start_sectors})
    snapshot = replace(system.snapshot,
                       identities=[i for i in system.snapshot.identities
                                   if i.partuuid != OLD_PART],
                       boot_entries={k: v for k, v in system.snapshot.boot_entries.items()
                                     if k != "0001"})
    # Without the pending intent the guard can only say the partition disappeared.
    assert not can_delete_old(s, snapshot).ok
    tokens = deletion_recovery_tokens(s, journal, snapshot, delete_old_esp=False,
                                      resolve=lambda path: path)
    assert [token for _, token in tokens] == [f"partition:{OLD_PART}"]
    recovered = replace(s, deletion_done=[*s.deletion_done, f"partition:{OLD_PART}"])
    assert can_delete_old(recovered, snapshot).ok


def test_present_refuses_an_unreadable_identity_at_the_sector_it_asks_about():
    from distromove.cleanup import _present
    snap = live()
    snap = replace(snap, identities=[replace(snap.identities[0], partuuid=None),
                                     *snap.identities[1:]])
    with pytest.raises(ValueError, match="partition identity unreadable"):
        _present(snap, state().old_volumes[0])


def test_present_ignores_an_unreadable_identity_of_another_partition():
    from distromove.cleanup import _present
    old = state().old_volumes[0]
    snap = live()
    # The partition asked about is gone; an unrelated one is momentarily unreadable.
    others = [replace(item, partuuid=None) if item.start_sectors != old.start_sectors
              else None for item in snap.identities]
    snap = replace(snap, identities=[item for item in others if item is not None])
    assert _present(snap, old) is False


def test_remove_partition_waits_for_the_kernel_to_drop_the_partition(tmp_path):
    from distromove.cleanup import _remove_partition
    system = System(live())
    _remove_partition(system, state().old_volumes[0],
                      lambda path: {f"/dev/disk/by-partuuid/{OLD_PART}": "/dev/vdb1",
                                    "/dev/disk/by-id/disk": "/dev/vdb"}.get(path, path))
    tail = [call for call in system.calls if call[0] in {"sgdisk", "partprobe", "udevadm"}]
    assert tail == [["sgdisk", "--delete=1", "/dev/disk/by-id/disk"],
                    ["partprobe", "/dev/disk/by-id/disk"], ["udevadm", "settle"]]


def test_delete_stops_when_a_live_partition_identity_is_unreadable(tmp_path):
    root, s, _, journal, system = setup(tmp_path)
    system.snapshot = replace(system.snapshot, identities=[
        replace(system.snapshot.identities[0], partuuid=None), *system.snapshot.identities[1:]])
    with pytest.raises(ValueError, match="partition identity unreadable"):
        cleanup(root, s, journal, system)
    assert not any(call[:1] == ["sgdisk"] for call in system.calls)
