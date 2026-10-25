"""Journaled, resumable removal of a migrated system after booting the new root."""
from __future__ import annotations

from dataclasses import replace
from contextlib import nullcontext
import json
import os
from pathlib import Path
import re
from typing import Callable

from .esp import remove_entry
from .journal import DEFAULT_LOCK, Journal, Lock, fsync_dir, read_journal
from .model import SystemSnapshot, VolumeIdentity
from .probe_parse import loader_of
from .safety import can_delete_old, confirmation_text
from .state import MigrationState, load_state, save_state


def _guard(state: MigrationState, recheck: Callable[[], SystemSnapshot], *,
           delete_old_esp: bool, resolve: Callable[[str], str]) -> SystemSnapshot:
    live = recheck()
    decision = can_delete_old(state, live, delete_old_esp=delete_old_esp, resolve=resolve)
    if not decision.ok:
        raise ValueError("deletion guard refused: " + "; ".join(decision.reasons))
    return live


def _mark(state: MigrationState, root: Path, token: str) -> MigrationState:
    if token in state.deletion_done:
        return state
    updated = replace(state, deletion_done=[*state.deletion_done, token])
    save_state(updated, root)
    return updated


def _pending(journal: Journal) -> list[dict]:
    entries = read_journal(journal.path)
    closed = {item["op_id"] for item in entries if item["type"] == "outcome"}
    return [item for item in entries if item["type"] == "intent" and
            item["op_id"] not in closed and item["op"] in {
                "delete_old_partition", "delete_old_uefi", "delete_old_esp"}]


def _present(live: SystemSnapshot, partuuid: str) -> bool:
    return any(item.partuuid.casefold() == partuuid.casefold() for item in live.identities)


def _reconcile(state: MigrationState, root: Path, journal: Journal,
               live: SystemSnapshot, *, delete_old_esp: bool,
               resolve: Callable[[str], str]) -> MigrationState:
    """Close an intent only when its exact former identity is now absent."""
    if (live.running_root_uuid.casefold() != state.new_root_uuid.casefold()
            or (state.uefi_entry and (live.boot_current or "").upper() != state.uefi_entry.upper())):
        raise ValueError("deletion guard refused: running system changed")
    for intent in _pending(journal):
        identity = intent["identity"]
        if intent["op"] == "delete_old_uefi":
            bootnum = identity.get("bootnum")
            if (not isinstance(bootnum, str) or not re.fullmatch(r"[0-9A-Fa-f]{4}", bootnum)
                    or identity.get("esp_partuuid", "").casefold() !=
                    state.old_esp.partuuid.casefold()):
                raise ValueError("pending firmware deletion has a different identity")
            token = "uefi_entry"
            absent = bootnum not in live.boot_entries
        else:
            partuuid = identity.get("partuuid", "")
            token = ("old_esp:" if intent["op"] == "delete_old_esp" else "partition:") + partuuid
            candidates = [state.old_esp] if intent["op"] == "delete_old_esp" else state.old_volumes
            target = next((v for v in candidates
                           if v.partuuid.casefold() == partuuid.casefold()), None)
            if (target is None or identity.get("disk_wwn") != target.disk_wwn
                    or identity.get("start_sectors") != target.start_sectors):
                raise ValueError("pending partition deletion has a different identity")
            absent = bool(target and not _present(live, partuuid))
            if absent and any(v.start_sectors == target.start_sectors and
                              (v.disk_wwn, v.disk_serial, v.disk_by_id) ==
                              (target.disk_wwn, target.disk_serial, target.disk_by_id)
                              for v in live.identities):
                raise ValueError("deleted partition was replaced at the same sector")
        if absent:
            candidate = (state if token in state.deletion_done else
                         replace(state, deletion_done=[*state.deletion_done, token]))
            decision = can_delete_old(candidate, live, delete_old_esp=delete_old_esp,
                                      resolve=resolve)
            if not decision.ok:
                raise ValueError("deletion guard refused during reconciliation: " +
                                 "; ".join(decision.reasons))
            state = _mark(state, root, token)
            journal.done(intent["op_id"], "reconciled")
    return state


def _old_bootnum(state: MigrationState, live: SystemSnapshot) -> str:
    matches = []
    for number, line in live.boot_entries.items():
        target = loader_of(line)
        if target is None or target[0].casefold() != state.old_esp.partuuid.casefold():
            continue
        path = target[1].replace("/", "\\").casefold()
        if path.startswith(f"\\efi\\{state.bootloader_id_old.casefold()}\\"):
            matches.append(number)
    if len(matches) != 1:
        raise ValueError("old UEFI entry is missing or ambiguous")
    return matches[0]


def _verify_completed_entries(state: MigrationState, root: Path,
                              live: SystemSnapshot) -> None:
    if "grub_entry" in state.deletion_done and (
            root / "etc/grub.d/40_distromove_old").exists():
        raise ValueError("deletion guard refused: old GRUB entry returned")
    if "uefi_entry" in state.deletion_done:
        for line in live.boot_entries.values():
            target = loader_of(line)
            if target and target[0].casefold() == state.old_esp.partuuid.casefold():
                path = target[1].replace("/", "\\").casefold()
                if path.startswith(f"\\efi\\{state.bootloader_id_old.casefold()}\\"):
                    raise ValueError("deletion guard refused: old firmware entry returned")


def _locate(r, volume: VolumeIdentity, resolve: Callable[[str], str]) -> tuple[str, int, str]:
    by_part = f"/dev/disk/by-partuuid/{volume.partuuid}"
    result = r.run(["lsblk", "--json", "--list", "--output",
                    "PATH,PKNAME,PARTN,PARTUUID,START"], readonly=True)
    try:
        rows = json.loads(result.stdout)["blockdevices"]
        matches = [row for row in rows if (row.get("partuuid") or "").casefold() ==
                   volume.partuuid.casefold()]
        if len(matches) != 1:
            raise ValueError
        row = matches[0]
        part = str(row["path"])
        parent = str(row["pkname"])
        number = int(row["partn"])
        if (not part.startswith("/dev/") or not re.fullmatch(r"[A-Za-z0-9._-]+", parent)
                or number < 1 or number > 128 or resolve(by_part) != part):
            raise ValueError
        disk = f"/dev/{parent}"
        disk_rows = json.loads(r.run(["lsblk", "--json", "--nodeps", "--output",
                                     "PATH,WWN,SERIAL,LOG-SEC", disk], readonly=True).stdout)["blockdevices"]
        if len(disk_rows) != 1 or disk_rows[0].get("path") != disk:
            raise ValueError
        logical = int(disk_rows[0]["log-sec"])
        start_bytes = int(row["start"]) * 512  # lsblk START is in 512-byte units
        if logical <= 0 or start_bytes % logical or start_bytes // logical != volume.start_sectors:
            raise ValueError
        for key, field in (("disk_wwn", "wwn"), ("disk_serial", "serial")):
            wanted = getattr(volume, key)
            if wanted and wanted.casefold() != str(disk_rows[0].get(field) or "").casefold():
                raise ValueError
        if volume.disk_by_id:
            if resolve(volume.disk_by_id) != disk:
                raise ValueError
            disk = volume.disk_by_id
        return disk, number, by_part
    except (ValueError, KeyError, TypeError, IndexError) as exc:
        raise ValueError(f"cannot locate old partition by identity: {volume.partuuid}") from exc


def _remove_grub(root: Path, r) -> None:
    path = root / "etc/grub.d/40_distromove_old"
    if path.is_symlink() or not path.parent.resolve().is_relative_to(root):
        raise ValueError("unsafe old-system GRUB script")
    if path.exists():
        if not path.read_text().startswith("#!/bin/sh\n# DistroMove old-system entry\n"):
            raise ValueError("old-system GRUB script was replaced")
        path.unlink()
        fsync_dir(path.parent)
    r.run(["update-grub"])


def _remove_partition(r, volume: VolumeIdentity, resolve: Callable[[str], str]) -> None:
    disk, number, _ = _locate(r, volume, resolve)
    r.run(["sgdisk", f"--delete={number}", disk])
    r.run(["partprobe", disk])


def delete_old_system(r, state: MigrationState, *, erase_luks_header: bool,
                      delete_old_esp: bool, journal: Journal,
                      recheck: Callable[[], SystemSnapshot], state_root: Path,
                      confirmation: str, lock_path: Path = DEFAULT_LOCK,
                      lock: Lock | None = None,
                      resolve: Callable[[str], str] = os.path.realpath) -> MigrationState:
    """Remove only old identities after exact confirmation and a fresh guard per step."""
    if confirmation != confirmation_text(state, delete_old_esp=delete_old_esp,
                                         erase_luks_header=erase_luks_header):
        raise ValueError("deletion confirmation does not match the old partitions")
    root = Path(state_root)
    if lock is not None and lock._fd is None:
        raise ValueError("deletion lock is not held")
    with nullcontext(lock) if lock is not None else Lock(lock_path):
        current = load_state(root, recheck().running_root_uuid)
        cleanup_ids = {state.migration_id, f"{state.migration_id}-delete"}
        if (current != state or not journal.is_current()
                or journal.migration_id not in cleanup_ids
                or (journal.host_root_uuid or "").casefold() != state.new_root_uuid.casefold()):
            raise ValueError("saved state or migration journal changed")
        if state.phase not in {"ACTIVATED", "DELETING"}:
            raise ValueError("deletion guard refused: migration is not activated")
        state = _reconcile(state, root, journal, recheck(),
                           delete_old_esp=delete_old_esp, resolve=resolve)
        live = _guard(state, recheck, delete_old_esp=delete_old_esp, resolve=resolve)
        _verify_completed_entries(state, root, live)
        if state.phase == "ACTIVATED":
            state = replace(state, phase="DELETING")
            save_state(state, root)

        if "grub_entry" not in state.deletion_done:
            _guard(state, recheck, delete_old_esp=delete_old_esp, resolve=resolve)
            op = journal.intend("delete_old_grub", {"migration_id": state.migration_id})
            _remove_grub(root, r)
            state = _mark(state, root, "grub_entry")
            journal.done(op, "removed")

        if "uefi_entry" not in state.deletion_done:
            live = _guard(state, recheck, delete_old_esp=delete_old_esp, resolve=resolve)
            bootnum = _old_bootnum(state, live)
            op = journal.intend("delete_old_uefi", {"bootnum": bootnum,
                                                    "esp_partuuid": state.old_esp.partuuid})
            remove_entry(r, bootnum, journal)
            after = recheck()
            if bootnum in after.boot_entries:
                raise RuntimeError("old firmware entry remains after removal")
            state = _mark(state, root, "uefi_entry")
            journal.done(op, "removed")

        for volume in state.old_volumes:
            token = f"partition:{volume.partuuid}"
            if token in state.deletion_done:
                continue
            if erase_luks_header and volume.luks_uuid and f"luks:{volume.partuuid}" not in state.deletion_done:
                _guard(state, recheck, delete_old_esp=delete_old_esp, resolve=resolve)
                _, _, device = _locate(r, volume, resolve)
                op = journal.intend("erase_old_luks", {"partuuid": volume.partuuid,
                                                      "luks_uuid": volume.luks_uuid})
                r.run(["cryptsetup", "luksErase", "--batch-mode", device])
                state = _mark(state, root, f"luks:{volume.partuuid}")
                journal.done(op, "erased")
            _guard(state, recheck, delete_old_esp=delete_old_esp, resolve=resolve)
            _locate(r, volume, resolve)
            op = journal.intend("delete_old_partition", {"partuuid": volume.partuuid,
                                                          "disk_wwn": volume.disk_wwn,
                                                          "start_sectors": volume.start_sectors})
            _remove_partition(r, volume, resolve)
            if _present(recheck(), volume.partuuid):
                raise RuntimeError("old partition remains after table update")
            state = _mark(state, root, token)
            journal.done(op, "removed")

        if delete_old_esp:
            token = f"old_esp:{state.old_esp.partuuid}"
            if token not in state.deletion_done:
                _guard(state, recheck, delete_old_esp=True, resolve=resolve)
                _locate(r, state.old_esp, resolve)
                op = journal.intend("delete_old_esp", {"partuuid": state.old_esp.partuuid,
                                                      "disk_wwn": state.old_esp.disk_wwn,
                                                      "start_sectors": state.old_esp.start_sectors})
                _remove_partition(r, state.old_esp, resolve)
                if _present(recheck(), state.old_esp.partuuid):
                    raise RuntimeError("old ESP remains after table update")
                state = _mark(state, root, token)
                journal.done(op, "removed")

        _guard(state, recheck, delete_old_esp=delete_old_esp, resolve=resolve)
        state = replace(state, phase="DELETED")
        save_state(state, root)
        return state
