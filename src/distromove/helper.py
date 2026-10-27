"""Privileged, length-framed request channel for the desktop process.

Control messages are UTF-8 JSON. A passphrase, when required, occupies the
following frame and is passed as bytes only to the storage operation.
"""
from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime
import json
import os
from pathlib import Path
import re
import shlex
import sys
from types import SimpleNamespace
from typing import BinaryIO, Callable
import uuid

from .cleanup import delete_old_system
from .engine import (MigrationContext, Secrets, reconcile_on_start,
                     rollback_destination, run_migration)
from .disk import GrubCaps
from .layout import (EspChoice, InitGpt, MigrationPlan, NoTable, Partplan,
                     VolumeTarget, disk_info, fingerprint_tables, plan_init_gpt,
                     plan_layout, scan_disk)
from .model import LoaderInfo, PlannedIdentity
from .probe_parse import loader_of
from .journal import DEFAULT_ROOT, Journal, Lock, current_journal, read_journal, recover
from .probe import collect_snapshot, database_activity, discover_source
from .runner import Runner, RunnerError
from .state import load_state
from .safety import can_delete_old, confirmation_text

SECRET_MAX = 1024
CONTROL_MAX = 16 * 1024 * 1024
GRUB_EFI_MODULES = Path("/usr/lib/grub/x86_64-efi")
_OPS = frozenset({"probe", "plan", "migrate", "preview_delete",
                  "delete_old", "recover", "reconcile"})


def write_frame(stream: BinaryIO, payload: bytes) -> None:
    if not isinstance(payload, bytes) or len(payload) > CONTROL_MAX:
        raise ValueError("invalid frame payload")
    stream.write(len(payload).to_bytes(4, "big"))
    stream.write(payload)
    stream.flush()


def _exact(stream: BinaryIO, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = stream.read(length - len(result))
        if not chunk:
            raise EOFError("truncated frame")
        result.extend(chunk)
    return bytes(result)


def read_frame(stream: BinaryIO, max_len: int) -> bytes:
    if max_len < 0 or max_len > CONTROL_MAX:
        raise ValueError("invalid frame limit")
    length = int.from_bytes(_exact(stream, 4), "big")
    if length > max_len:
        raise ValueError("frame exceeds limit")
    return _exact(stream, length)


def emit_event(stream: BinaryIO, event: dict) -> None:
    payload = json.dumps(event, ensure_ascii=True, separators=(",", ":"),
                         allow_nan=False).encode("ascii")
    write_frame(stream, payload)


def _request(stream: BinaryIO) -> tuple[dict, bytes | None]:
    data = json.loads(read_frame(stream, CONTROL_MAX).decode("utf-8"))
    if not isinstance(data, dict) or data.get("op") not in _OPS:
        raise ValueError("invalid operation")
    if data.get("has_secret") not in (None, False, True):
        raise ValueError("invalid secret flag")
    secret = read_frame(stream, SECRET_MAX) if data.get("has_secret") else None
    if secret is not None and data["op"] != "migrate":
        raise ValueError("unexpected secret")
    return data, secret


def record_failure(exc: BaseException, *, op: str, root: Path = DEFAULT_ROOT) -> None:
    """Keep the last failure where only root can read it.

    The control channel carries exception types alone, which is not enough to
    tell why a command refused.  A failed command, its exit code and its output
    are written here instead; the Runner has already removed the passphrase.
    A diagnostic must never replace the outcome, so every error is swallowed.
    """
    lines = [f"time: {datetime.now().astimezone().isoformat(timespec='seconds')}",
             f"operation: {op}", f"error: {type(exc).__name__}"]
    if isinstance(exc, RunnerError):
        if exc.argv:
            lines.append(f"command: {shlex.join(exc.argv)}")
        lines.append(f"exit code: {exc.returncode}")
        for name, text in (("stdout", exc.stdout), ("stderr", exc.stderr)):
            if text:
                lines.append(f"{name}:\n" + "\n".join(text.splitlines()[-20:]))
    try:
        fd = os.open(root / "last-error.log",
                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, ("\n".join(lines) + "\n").encode("utf-8", "replace"))
        finally:
            os.close(fd)
    except OSError:
        pass


def serve(stdin: BinaryIO, stdout: BinaryIO,
          operation: Callable[[dict, bytes | None, Callable[[dict], None]], dict],
          *, before: Callable[[], None] | None = None) -> int:
    """Process one request; expose only exception types on the control channel."""
    data = None
    try:
        data, secret = _request(stdin)
        if before is not None:
            before()
        result = operation(data, secret, lambda event: emit_event(stdout, event))
        emit_event(stdout, result)
        return 0 if result.get("ok") is True else 1
    except Exception as exc:
        # Exception messages can contain command output or user supplied text.
        record_failure(exc, op=str((data or {}).get("op", "unknown")))
        emit_event(stdout, {"ok": False, "error": type(exc).__name__})
        return 1


def _current(running_uuid: str) -> Journal | None:
    path = current_journal(DEFAULT_ROOT, running_uuid)
    if path is None:
        return None
    entries = read_journal(path)
    return Journal(DEFAULT_ROOT, entries[0]["migration_id"], host_root_uuid=running_uuid)


def _reconcile(r: Runner) -> list[dict]:
    live = collect_snapshot(r)
    journal = _current(live.running_root_uuid)
    if journal is None:
        # The copied migration journal belongs to the old root. The durable
        # state on the new root can still need activation reconciliation.
        view = SimpleNamespace(is_current=lambda: False)
        return [asdict(action) for action in reconcile_on_start(
            r, view, state_root=Path("/"))]
    if journal.migration_id.endswith("-delete"):
        return []
    return [asdict(action) for action in reconcile_on_start(r, journal,
                                                             state_root=Path("/"))]


def _plan(raw: dict, source, r: Runner) -> MigrationPlan:
    """Replace GUI device names and volume objects with freshly observed ones."""
    if not isinstance(raw, dict) or not isinstance(raw.get("disks"), dict):
        raise ValueError("plan lacks disk identities")
    disks = {}
    for gui_path, identity in raw["disks"].items():
        if not isinstance(identity, dict) or not gui_path.startswith("/dev/"):
            raise ValueError("invalid disk identity")
        stable = identity.get("by_id")
        if not isinstance(stable, str) or not stable.startswith("/dev/disk/by-id/"):
            raise ValueError("stable disk identity is required")
        local = os.path.realpath(stable)
        if not local.startswith("/dev/") or not Path(local).exists():
            raise ValueError("disk identity is unavailable")
        info = disk_info(r, local)
        if (info.by_id != stable or not (info.wwn or info.serial)
                or info.wwn != identity.get("wwn")
                or info.serial != identity.get("serial")):
            raise ValueError("disk identity changed")
        disks[gui_path] = local

    def disk(value):
        if value not in disks:
            raise ValueError("unverified destination disk")
        return disks[value]

    volumes = {v.volume_id: v for v in source.volumes}
    targets = []
    for item in raw["targets"]:
        volume_id = item.get("volume_id") or item.get("volume", {}).get("volume_id")
        if volume_id not in volumes:
            raise ValueError("plan refers to another source volume")
        targets.append(VolumeTarget(volumes[volume_id], disk(item["disk"]),
                                    int(item["size_bytes"])))
    esp = raw["esp"]
    esp_choice = (EspChoice("reuse", source.esp.partition.parent_disk, 0)
                  if esp["mode"] == "reuse" else
                  EspChoice("new", disk(esp["disk"]), int(esp["size_bytes"])))

    def partitions(key):
        return [Partplan(disk(item["disk"]), int(item["start_sectors"]),
                         int(item["size_sectors"]), item["role"],
                         PlannedIdentity(**item["planned"]), item.get("volume_id", ""),
                         int(item.get("logical_sector", 512))) for item in raw[key]]

    init = [InitGpt(disk(item["disk"]), item["disk_identity"],
                    item["confirmation"], int(item["size_bytes"]),
                    int(item["logical_sector"]),
                    item.get("no_recognised_signatures", True),
                    item.get("basis", "no recognised signatures"),
                    item.get("typed_confirmation")) for item in raw.get("init_gpt", [])]
    approved = {disk(path): value for path, value in raw["approved_tables"].items()}
    return MigrationPlan(targets, esp_choice, partitions("partitions"),
                         partitions("swaps"), approved, init)


def _source_tops(source, scratch: Path, r: Runner, journal: Journal) -> dict[str, Path]:
    """Mount each Btrfs source's top level by its freshly probed filesystem UUID."""
    tops = {}
    for volume in source.volumes:
        if volume.btrfs is None:
            continue
        link = Path("/dev/disk/by-uuid") / volume.fs_uuid
        if not link.is_symlink():
            raise ValueError("source filesystem identity is unavailable")
        device = os.path.realpath(link)
        if not device.startswith("/dev/"):
            raise ValueError("unsafe source filesystem device")
        actual = r.run(["blkid", "-p", "-o", "value", "-s", "UUID", device],
                       readonly=True).stdout.strip()
        if actual.casefold() != volume.fs_uuid.casefold():
            raise ValueError("source filesystem identity changed")
        top = scratch / ("source-" + volume.volume_id)
        if top.is_symlink():
            raise ValueError("unsafe source top-level mount")
        top.mkdir(mode=0o700, exist_ok=True)
        if any(top.iterdir()):
            raise ValueError("source top-level directory is occupied")
        op = journal.intend("mount_destination", {"fs_uuid": volume.fs_uuid},
                            device=device, path=str(top))
        r.run(["mount", "-t", "btrfs", "-o", "rw,subvolid=5", device, str(top)])
        options = r.run(["findmnt", "--noheadings", "--output", "OPTIONS",
                         "--mountpoint", str(top)], readonly=True).stdout.strip().split(",")
        actual = r.run(["blkid", "-p", "-o", "value", "-s", "UUID", device],
                       readonly=True).stdout.strip()
        if "rw" not in options or "subvolid=5" not in options or actual.casefold() != volume.fs_uuid.casefold():
            raise ValueError("source top-level mount changed")
        journal.done(op, "mounted")
        tops[volume.volume_id] = top
    return tops


def _grub_caps(modules: Path = GRUB_EFI_MODULES) -> GrubCaps:
    """Advertise only encrypted boot formats with the installed EFI modules.

    GRUB implements XTS inside ``cryptodisk`` itself, so no module carries it.
    """
    common = all((modules / name).is_file() for name in
                 ("cryptodisk.mod", "pbkdf2.mod", "gcry_rijndael.mod", "afsplitter.mod"))
    versions = {version for version, name in ((1, "luks.mod"), (2, "luks2.mod"))
                if common and (modules / name).is_file()}
    return GrubCaps(frozenset(versions),
                    frozenset({"pbkdf2"}) if versions else frozenset(),
                    frozenset({"aes-xts-plain64"}) if versions else frozenset())


def _disk_inventory(r: Runner) -> list[dict]:
    raw = r.run(["lsblk", "--json", "--nodeps", "--output", "PATH,TYPE"],
                readonly=True).stdout
    entries = json.loads(raw).get("blockdevices", [])
    return [asdict(disk_info(r, item["path"])) for item in entries
            if item.get("type") == "disk" and isinstance(item.get("path"), str)]


def _planned(data: dict, r: Runner) -> dict:
    """Read-only plan from local disks and source, never GUI supplied geometry."""
    include = data.get("include_mounts", [])
    if not isinstance(include, list) or any(not isinstance(item, str) for item in include):
        raise ValueError("invalid mount selection")
    base = discover_source(r)
    offered = {item.target for item in base.unmigrated_mounts}
    if not set(include) <= offered:
        raise ValueError("mount selection changed")
    source = discover_source(r, extra_mounts=include)
    choices = data.get("targets")
    if not isinstance(choices, list) or not choices:
        raise ValueError("missing volume targets")
    volumes = {item.volume_id: item for item in source.volumes}
    if len(choices) != len(volumes):
        raise ValueError("every source volume needs a target")
    targets = []
    selected = set()
    for item in choices:
        if not isinstance(item, dict) or item.get("volume_id") not in volumes:
            raise ValueError("unknown volume target")
        path = item.get("disk")
        if not isinstance(path, str) or not path.startswith("/dev/"):
            raise ValueError("invalid disk choice")
        size = item.get("size_bytes")
        if type(size) is not int or size <= 0:
            raise ValueError("invalid target size")
        targets.append(VolumeTarget(volumes[item["volume_id"]], path, size))
        selected.add(path)
    if len({item.volume.volume_id for item in targets}) != len(volumes):
        raise ValueError("duplicate volume target")
    esp_request = data.get("esp")
    if not isinstance(esp_request, dict) or esp_request.get("mode") not in {"reuse", "new"}:
        raise ValueError("invalid ESP choice")
    if esp_request["mode"] == "new":
        esp_disk = esp_request.get("disk")
        if not isinstance(esp_disk, str) or not esp_disk.startswith("/dev/"):
            raise ValueError("invalid ESP disk")
        selected.add(esp_disk)
        esp = EspChoice("new", esp_disk, 512 * 1024**2)
    else:
        esp = EspChoice("reuse", source.esp.partition.parent_disk, 0)
    inventory = {item["path"]: item for item in _disk_inventory(r)}
    if not selected <= inventory.keys():
        raise ValueError("selected disk is no longer available")
    regions, init = [], []
    confirmations = data.get("gpt_confirmations", {})
    if not isinstance(confirmations, dict):
        raise ValueError("invalid GPT confirmations")
    needed = []
    for path in sorted(selected):
        info = disk_info(r, path)
        if not info.by_id or not (info.wwn or info.serial):
            raise ValueError("destination disk has no stable identity")
        try:
            regions.extend(scan_disk(r, path))
        except NoTable as missing:
            proposal = plan_init_gpt(info) if missing.can_init else None
            if proposal is None:
                raise ValueError("destination disk has no usable GPT")
            if confirmations.get(path) != proposal.confirmation:
                needed.append({"disk": path, "disk_identity": proposal.disk_identity,
                               "confirmation": proposal.confirmation,
                               "signatures": list(info.signatures or ())})
            else:
                init.append(replace(proposal, typed_confirmation=proposal.confirmation))
    if needed:
        return {"ok": True, "needs_gpt_confirmation": needed}
    approved = fingerprint_tables(r, selected)
    plan = plan_layout(source, targets, esp, regions, init_gpt=init,
                       approved_tables=approved)
    disks = {path: {"by_id": inventory[path]["by_id"],
                    "wwn": inventory[path]["wwn"], "serial": inventory[path]["serial"]}
             for path in selected}
    return {"ok": True, "source": asdict(source),
            "plan": {**asdict(plan), "disks": disks}}


_USAGE_FIELDS = frozenset({"used_bytes", "apparent_bytes", "used_inodes"})


def _stable_source(value):
    """The source description without usage counters, which move on any live system."""
    if isinstance(value, dict):
        return {key: _stable_source(item) for key, item in value.items()
                if key not in _USAGE_FIELDS}
    if isinstance(value, list):
        return [_stable_source(item) for item in value]
    return value


def _migration_result(result) -> dict:
    """The outcome for the GUI.  A failure names its kind, never a secret-bearing message."""
    out = {"ok": result.ok, "phase": result.phase,
           "warnings": result.warnings, "bootnum": result.new_bootnum}
    if not result.ok and result.warnings:
        out["error"] = result.warnings[0]
    return out


def _migration(data: dict, secret: bytes | None, emit, r: Runner) -> dict:
    migration_id = data.get("migration_id")
    if not isinstance(migration_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", migration_id):
        raise ValueError("invalid migration ID")
    with Lock() as lock:
        actions = _reconcile(r)
        for action in actions:
            emit({"phase": "reconcile", **action})
        include = data.get("include_mounts", [])
        if not isinstance(include, list) or any(not isinstance(item, str) for item in include):
            raise ValueError("invalid mount selection")
        base_source = discover_source(r)
        if not set(include) <= {item.target for item in base_source.unmigrated_mounts}:
            raise ValueError("mount selection changed")
        source = discover_source(r, extra_mounts=include)
        fresh_source = json.loads(json.dumps(asdict(source)))
        if _stable_source(data.get("source")) != _stable_source(fresh_source):
            raise ValueError("source changed since planning")
        if current_journal(DEFAULT_ROOT, source.running_root_uuid) is not None:
            raise ValueError("unfinished migration requires recovery")
        plan = _plan(data["plan"], source, r)
        live = collect_snapshot(r)
        entry = live.boot_entries.get(live.boot_current or "", "")
        loader = loader_of(entry)
        if loader is None or loader[0].casefold() != source.esp.partition.partuuid.casefold():
            raise ValueError("current boot loader cannot be verified")
        match = re.fullmatch(r"\\EFI\\([^\\]+)\\(shimx64|grubx64)\.efi", loader[1], re.I)
        if match is None:
            raise ValueError("unsupported boot loader")
        old_id = match[1]
        boot_id = "distromove-" + migration_id[:8].lower()
        if boot_id.casefold() == old_id.casefold() or boot_id.casefold() in {
                name.casefold() for name in source.esp.loader_dirs}:
            raise ValueError("new boot loader identifier collides")
        base = Path("/run/distromove")
        if base.is_symlink():
            raise ValueError("unsafe staging base")
        base.mkdir(mode=0o700, exist_ok=True)
        staging, scratch = base / "staging", base / "scratch"
        for path in (staging, scratch):
            if path.is_symlink():
                raise ValueError("unsafe staging directory")
            path.mkdir(mode=0o700, exist_ok=True)
        swapfile_uuids = {item.volume_id: str(uuid.uuid5(
            uuid.NAMESPACE_URL, f"distromove:{migration_id}:swap:{item.volume_id}"))
            for item in source.swaps if item.kind == "file"}
        context = MigrationContext(staging, scratch,
                                   _grub_caps(),
                                   LoaderInfo(old_id, loader[1], match[2].lower() == "shimx64",
                                              source.esp.partition.uuid or ""), boot_id,
                                   swapfile_uuids=swapfile_uuids)
        journal = Journal(DEFAULT_ROOT, migration_id,
                          host_root_uuid=source.running_root_uuid)
        try:
            tops = _source_tops(source, scratch, r, journal)
        except Exception:
            rollback_destination(r, journal)
            raise
        context = replace(context, btrfs_source_tops=tops)
        result = run_migration(plan, source, Secrets(secret), r, emit, journal, lock,
                               context=context,
                               on_failure=lambda exc: record_failure(exc, op="migrate"))
        return _migration_result(result)


def system_operation(data: dict, secret: bytes | None,
                     emit: Callable[[dict], None]) -> dict:
    """Dispatch operations using fresh local observations and a single lock."""
    r = Runner()
    op = data["op"]
    if op == "probe":
        with Lock():
            actions = _reconcile(r)
            live = collect_snapshot(r)
            state = load_state(Path("/"), live.running_root_uuid)
            base = discover_source(r)
            include = data.get("include_mounts", [])
            if (not isinstance(include, list) or any(not isinstance(item, str) for item in include)
                    or not set(include) <= {item.target for item in base.unmigrated_mounts}):
                raise ValueError("invalid mount selection")
            source = discover_source(r, extra_mounts=include) if include else base
            return {"ok": True, "actions": actions, "source": asdict(source),
                    "disks": _disk_inventory(r), "activity": database_activity(r),
                    "state": asdict(state) if state else None}
    if op == "plan":
        with Lock():
            _reconcile(r)
            return _planned(data, r)
    if op == "preview_delete":
        if (type(data.get("erase_luks_header", False)) is not bool
                or type(data.get("delete_old_esp", False)) is not bool):
            raise ValueError("invalid deletion options")
        with Lock():
            _reconcile(r)
            live = collect_snapshot(r)
            state = load_state(Path("/"), live.running_root_uuid)
            if state is None:
                raise ValueError("no state for running root")
            old_esp = data.get("delete_old_esp", False)
            decision = can_delete_old(state, live, delete_old_esp=old_esp)
            return {"ok": True, "allowed": decision.ok, "reasons": decision.reasons,
                    "state": asdict(state),
                    "confirmation": confirmation_text(
                        state, delete_old_esp=old_esp,
                        erase_luks_header=data.get("erase_luks_header", False))}
    if op == "recover":
        with Lock():
            actions = _reconcile(r)
            live = collect_snapshot(r)
            return {"ok": True, "actions": actions,
                    "residue": [asdict(item) for item in
                                recover(DEFAULT_ROOT, live, live.running_root_uuid)]}
    if op == "reconcile":
        with Lock():
            return {"ok": True, "actions": _reconcile(r)}
    if op == "delete_old":
        if (type(data.get("erase_luks_header", False)) is not bool
                or type(data.get("delete_old_esp", False)) is not bool):
            raise ValueError("invalid deletion options")
        with Lock() as lock:
            live = collect_snapshot(r)
            state = load_state(Path("/"), live.running_root_uuid)
            if state is None:
                raise ValueError("no state for running root")
            erase = data.get("erase_luks_header", False)
            old_esp = data.get("delete_old_esp", False)
            if data.get("confirmation") != confirmation_text(
                    state, delete_old_esp=old_esp, erase_luks_header=erase):
                raise ValueError("confirmation mismatch")
            existing = current_journal(DEFAULT_ROOT, live.running_root_uuid)
            expected = f"journal-{state.migration_id}-delete.jsonl"
            if existing is not None and existing.name != expected:
                _reconcile(r)
                existing = current_journal(DEFAULT_ROOT, live.running_root_uuid)
                if existing is not None:
                    raise ValueError("another operation is current")
            journal = Journal(DEFAULT_ROOT, state.migration_id + "-delete",
                              host_root_uuid=live.running_root_uuid)
            entries = read_journal(journal.path)
            options = {"erase_luks_header": erase, "delete_old_esp": old_esp}
            saved = [entry for entry in entries if entry["type"] == "intent"
                     and entry["op"] == "delete_options"]
            if saved:
                if len(saved) != 1 or saved[0]["fields"] != options:
                    raise ValueError("deletion options changed during resume")
            else:
                token = journal.intend("delete_options", {"migration_id": state.migration_id},
                                       **options)
                journal.done(token, "saved")
            updated = delete_old_system(
                r, state, erase_luks_header=erase,
                delete_old_esp=old_esp, journal=journal,
                recheck=lambda: collect_snapshot(r), state_root=Path("/"),
                confirmation=data.get("confirmation", ""), lock=lock)
            if updated.phase == "DELETED":
                journal.finish("deleted")
            return {"ok": True, "phase": updated.phase}
    if op == "migrate":
        return _migration(data, secret, emit, r)
    raise ValueError("invalid operation")


def main(stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> int:
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    if os.geteuid() != 0:
        emit_event(stdout, {"ok": False, "error": "RootRequired"})
        return 1
    return serve(stdin, stdout, system_operation)


if __name__ == "__main__":
    raise SystemExit(main())
