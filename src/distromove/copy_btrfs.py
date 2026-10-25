"""Btrfs copy from short-lived read-only snapshots and the live swapfile branch."""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Callable, Literal

from .copy_ext4 import RSYNC_ARGS, PassStats, _escape_filter, _manifest_excludes, volume_filters
from .journal import Journal, read_journal
from .layout import SpaceWatch
from .manifest import build_manifest
from .model import Manifest, SnapshotRef, Subvol, Volume
from .runner import Runner


class SnapshotIdentityChanged(RuntimeError):
    """A snapshot path no longer names the subvolume created by this migration."""


@dataclass(frozen=True)
class BtrfsDestination:
    path: Path
    fs_uuid: str
    subvolid: int


@dataclass(frozen=True)
class LiveCopy:
    fs_uuid: str
    subvol_path: str
    source: Path
    destination: Path
    started_at: float
    manifest: Manifest


def branch(subvol: Subvol) -> Literal["snapshot", "swap-only", "live"]:
    if subvol.only_swapfile and not subvol.has_active_swapfile:
        raise ValueError("swap-only subvolume has no active swapfile")
    if not subvol.has_active_swapfile:
        return "snapshot"
    return "swap-only" if subvol.only_swapfile else "live"


def _subvol_path(path: str) -> Path:
    rel = Path(path)
    if not path or rel.is_absolute() or any(item in {"", ".", ".."} for item in path.split("/")):
        raise ValueError(f"unsafe btrfs subvolume path: {path!r}")
    return rel


def _rootid(r: Runner, path: Path) -> int:
    raw = r.run(["btrfs", "inspect-internal", "rootid", str(path)], readonly=True).stdout.strip()
    try:
        return int(raw)
    except ValueError as exc:
        raise SnapshotIdentityChanged(f"cannot read subvolume ID: {path}") from exc


def _mount_uuid(r: Runner, path: Path, *, exact: bool) -> tuple[str, str]:
    option = "--mountpoint" if exact else "--target"
    raw = r.run(["findmnt", "--json", "--nofsroot", option, str(path),
                 "--output", "TARGET,SOURCE,FSTYPE"], readonly=True).stdout
    try:
        rows = json.loads(raw)["filesystems"]
        if len(rows) != 1 or rows[0]["fstype"] != "btrfs":
            raise ValueError
        target, source = rows[0]["target"], rows[0]["source"]
        if exact and target != str(path):
            raise ValueError
        if source.startswith("UUID="):
            uuid = source[5:]
        elif source.startswith("/dev/"):
            uuid = r.run(["blkid", "-p", "-o", "value", "-s", "UUID", source],
                         readonly=True).stdout.strip()
        else:
            raise ValueError
        if not uuid:
            raise ValueError
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        raise SnapshotIdentityChanged(f"cannot verify btrfs mount: {path}") from exc
    return uuid, target


def _show(r: Runner, path: Path) -> tuple[str, int]:
    out = r.run(["btrfs", "subvolume", "show", str(path)], readonly=True).stdout
    uuid = re.search(r"^\s*UUID:\s*(\S+)\s*$", out, re.M)
    sid = re.search(r"^\s*Subvolume ID:\s*(\d+)\s*$", out, re.M)
    if not uuid or not sid or uuid.group(1) == "-":
        raise SnapshotIdentityChanged(f"cannot identify snapshot: {path}")
    return uuid.group(1), int(sid.group(1))


def _readonly(r: Runner, path: Path) -> bool:
    out = r.run(["btrfs", "property", "get", "-ts", str(path), "ro"],
                readonly=True).stdout.strip()
    return out == "ro=true"


def _snapshot_name(migration_id: str, subvol_path: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]", "-", subvol_path).strip(".-") or "top"
    digest = hashlib.sha256(subvol_path.encode("utf-8")).hexdigest()[:10]
    name = f"distromove-{migration_id}-{slug[:32]}-{digest}"
    if len(name) > 127:
        raise ValueError("snapshot name is too long")
    return name


def _exclusions(path: str, subvols: list[Subvol]) -> tuple[str, ...]:
    prefix = "" if path == "." else path + "/"
    return tuple(sorted({s.path[len(prefix):] for s in subvols
                         if s.path != path and s.path.startswith(prefix)}))


def _active_swap_paths(r: Runner, fs_uuid: str) -> dict[int, set[Path]]:
    out = r.run(["swapon", "--show=NAME,TYPE", "--noheadings", "--raw"],
                readonly=True).stdout
    found: dict[int, set[Path]] = {}
    for line in out.splitlines():
        fields = line.rsplit(maxsplit=1)
        if len(fields) != 2 or fields[1] not in {"file", "partition", "virtual"}:
            raise ValueError("cannot classify an active swap area")
        if fields[1] != "file":
            continue
        path = Path(fields[0])
        if not path.is_file():
            raise ValueError(f"active swapfile is not readable: {path}")
        path = path.resolve(strict=True)
        actual, _ = _mount_uuid(r, path, exact=False)
        if actual.casefold() == fs_uuid.casefold():
            found.setdefault(_rootid(r, path), set()).add(path)
    return found


def take_snapshots(r: Runner, volume: Volume, journal: Journal, watch: SpaceWatch,
                   *, top_level: Path | str | None = None,
                   include_top_level: bool = True) -> list[SnapshotRef]:
    """Snapshot top level and every non-swap subvolume in one command burst."""
    info = volume.btrfs
    if volume.fs != "btrfs" or info is None or info.fs_uuid.casefold() != volume.fs_uuid.casefold():
        raise ValueError("volume has no consistent btrfs description")
    if not journal.is_current():
        raise ValueError("migration journal is not current")
    top = Path(top_level or volume.mountpoint).resolve(strict=True)
    if not top.is_dir() or top.is_symlink():
        raise ValueError("btrfs top-level mount is not a directory")
    actual_fs, _ = _mount_uuid(r, top, exact=True)
    if actual_fs.casefold() != info.fs_uuid.casefold() or _rootid(r, top) != 5:
        raise SnapshotIdentityChanged("source is not the expected btrfs top level")
    all_subvols = list(info.subvolumes)
    if len({s.path for s in all_subvols}) != len(all_subvols):
        raise ValueError("duplicate source subvolume path")
    candidates = ([(".", 5)] if include_top_level else []) + [(s.path, s.id) for s in all_subvols
                              if branch(s) == "snapshot" and ".snapshots" not in s.path.split("/")]
    active_ids = _active_swap_paths(r, info.fs_uuid)
    if any(sid in active_ids for _, sid in candidates):
        raise ValueError("active swapfile classification changed before snapshot")
    prepared: list[tuple[str, Path, SnapshotRef]] = []
    for path, sid in candidates:
        source = top if path == "." else top / _subvol_path(path)
        if not source.is_dir() or source.is_symlink() or _rootid(r, source) != sid:
            raise SnapshotIdentityChanged(f"source subvolume changed: {source}")
        destination = top / _snapshot_name(journal.migration_id, path)
        if destination.exists() or destination.is_symlink():
            raise ValueError(f"snapshot destination already exists: {destination}")
        ref = SnapshotRef(info.fs_uuid, path, str(destination), "",
                          _exclusions(path, all_subvols))
        prepared.append((path, source, ref))
    watch.check()
    planned = []
    for path, source, ref in prepared:
        op = journal.intend("btrfs_snapshot", {"fs_uuid": info.fs_uuid,
                                                "subvol_path": path,
                                                "snapshot_path": ref.snapshot_path},
                            creates="btrfs_snapshot", source=str(source))
        planned.append((source, SnapshotRef(ref.fs_uuid, ref.subvol_path,
                                             ref.snapshot_path, op, ref.exclude_paths)))
    made: list[SnapshotRef] = []
    confirmed: list[SnapshotRef] = []
    try:
        for source, ref in planned:
            r.run(["btrfs", "subvolume", "snapshot", "-r", str(source), ref.snapshot_path])
            made.append(ref)
        for ref in made:
            uuid, sid = _show(r, Path(ref.snapshot_path))
            if sid <= 5 or not _readonly(r, Path(ref.snapshot_path)):
                raise SnapshotIdentityChanged(f"snapshot is not read-only: {ref.snapshot_path}")
            journal.done(ref.owner_op, "created", snapshot_uuid=uuid, subvolid=sid)
            confirmed.append(ref)
        watch.check()
    except BaseException:
        for ref in made:
            if ref in confirmed:
                continue
            try:
                uuid, sid = _show(r, Path(ref.snapshot_path))
                if sid <= 5 or not _readonly(r, Path(ref.snapshot_path)):
                    continue
                journal.done(ref.owner_op, "created", snapshot_uuid=uuid, subvolid=sid)
                confirmed.append(ref)
            except Exception:
                # An unverified path stays in the journal for conservative recovery.
                continue
        release_snapshots(r, confirmed, journal)
        raise
    return confirmed


def _owned_snapshot(ref: SnapshotRef, journal: Journal) -> tuple[str, bool] | None:
    entries = read_journal(journal.path)
    owner = next((e for e in entries if e["type"] == "intent" and e["op_id"] == ref.owner_op), None)
    if (owner is None or owner["op"] != "btrfs_snapshot" or
            owner["identity"].get("fs_uuid", "").casefold() != ref.fs_uuid.casefold() or
            owner["identity"].get("subvol_path") != ref.subvol_path or
            owner["identity"].get("snapshot_path") != ref.snapshot_path):
        return None
    created = next((e for e in entries if e["type"] == "outcome" and
                    e["op_id"] == ref.owner_op and e["outcome"] == "created"), None)
    if created is None:
        return None
    uuid = created["fields"].get("snapshot_uuid")
    released = any(e["type"] == "outcome" and e["outcome"] == "deleted" and
                   e["fields"].get("snapshot_uuid") == uuid for e in entries)
    return (uuid, released) if uuid else None


def release_snapshots(r: Runner, snaps: list[SnapshotRef], journal: Journal) -> None:
    """Delete only snapshots with matching journal ownership and on-disk UUID."""
    if not journal.is_current():
        raise ValueError("migration journal is not current")
    for ref in reversed(snaps):
        owned = _owned_snapshot(ref, journal)
        if owned is None:
            raise ValueError(f"snapshot is not owned by this migration: {ref.snapshot_path}")
        expected, released = owned
        if released:
            continue
        path = Path(ref.snapshot_path)
        source_fs, _ = _mount_uuid(r, path, exact=False)
        if source_fs.casefold() != ref.fs_uuid.casefold():
            raise SnapshotIdentityChanged(f"snapshot filesystem changed: {path}")
        actual, _ = _show(r, path)
        if actual.casefold() != expected.casefold() or not _readonly(r, path):
            raise SnapshotIdentityChanged(f"snapshot changed before release: {path}")
        op = journal.intend("delete_btrfs_snapshot", {"fs_uuid": ref.fs_uuid,
                                                       "snapshot_uuid": expected,
                                                       "snapshot_path": str(path)},
                            owner_op=ref.owner_op)
        r.run(["btrfs", "subvolume", "delete", "--commit-after", str(path)])
        journal.done(op, "deleted", snapshot_uuid=expected)


@contextmanager
def managed_snapshots(r: Runner, volume: Volume, journal: Journal, watch: SpaceWatch,
                      *, top_level: Path | str | None = None):
    """Keep snapshots available to the caller, and release them even on error."""
    refs = take_snapshots(r, volume, journal, watch, top_level=top_level)
    try:
        yield refs
    finally:
        release_snapshots(r, refs, journal)


def _destination(r: Runner, destination: BtrfsDestination, journal: Journal) -> Path:
    path = Path(destination.path).resolve(strict=True)
    if not path.is_dir() or path.is_symlink() or not destination.fs_uuid or destination.subvolid < 5:
        raise ValueError("invalid btrfs destination")
    actual, mountpoint = _mount_uuid(r, path, exact=False)
    if actual.casefold() != destination.fs_uuid.casefold() or _rootid(r, path) != destination.subvolid:
        raise SnapshotIdentityChanged(f"destination subvolume changed: {path}")
    entries = read_journal(journal.path)
    intents = {e["op_id"]: e for e in entries if e["type"] == "intent"}
    if not any(e["type"] == "outcome" and e["outcome"] == "mounted" and
               e["op_id"] in intents and intents[e["op_id"]]["op"] == "mount_destination" and
               intents[e["op_id"]]["fields"].get("path") == mountpoint and
               intents[e["op_id"]]["identity"].get("fs_uuid", "").casefold() ==
               destination.fs_uuid.casefold() for e in entries):
        raise ValueError("destination is not a verified mount of this migration")
    return path


def _rsync(r: Runner, source: Path, destination: Path, flags: list[str],
           on_progress: Callable[[PassStats], None] | None,
           watch: SpaceWatch | None) -> PassStats:
    started = time.time()
    began = time.monotonic()
    out = r.run(["rsync", *RSYNC_ARGS, *flags, "--stats",
                 str(source).rstrip("/") + "/", str(destination).rstrip("/") + "/"],
                periodic_check=watch.check if watch is not None else None).stdout
    match = re.search(r"^Number of regular files transferred:\s*([\d,]+)", out, re.M)
    if not match:
        raise ValueError("rsync did not report the transfer count")
    result = PassStats(time.monotonic() - began, int(match.group(1).replace(",", "")), started)
    if on_progress is not None:
        on_progress(result)
    return result


def _snapshot_filters(ref: SnapshotRef, migration_id: str) -> list[str]:
    filters = ["--exclude=.snapshots/"]
    filters += ["--exclude=/" + _escape_filter(path) + "/***" for path in ref.exclude_paths]
    if ref.subvol_path == ".":
        filters.append("--exclude=/distromove-" + migration_id + "-*/***")
    return filters


def copy_from_snapshots(r: Runner, snaps: list[SnapshotRef],
                        dst_mounts: dict[tuple[str, str], BtrfsDestination],
                        on_progress: Callable[[PassStats], None] | None = None,
                        *, journal: Journal, watch: SpaceWatch | None = None) -> None:
    """Copy stable trees; keep snapshots until verification or caller's finally."""
    if not journal.is_current():
        raise ValueError("migration journal is not current")
    try:
        prepared = []
        for ref in snaps:
            owned = _owned_snapshot(ref, journal)
            if owned is None or owned[1]:
                raise ValueError(f"snapshot is not owned and live: {ref.snapshot_path}")
            source = Path(ref.snapshot_path).resolve(strict=True)
            source_fs, _ = _mount_uuid(r, source, exact=False)
            if (source_fs.casefold() != ref.fs_uuid.casefold() or
                    _show(r, source)[0].casefold() != owned[0].casefold() or
                    not _readonly(r, source)):
                raise SnapshotIdentityChanged(f"snapshot changed before copy: {source}")
            dest = _destination(r, dst_mounts[(ref.fs_uuid, ref.subvol_path)], journal)
            if source == dest or source in dest.parents or dest in source.parents:
                raise ValueError("source and destination overlap")
            prepared.append((ref, source, dest))
        for ref, source, dest in prepared:
            if watch is not None:
                watch.check()
            current_fs, _ = _mount_uuid(r, source, exact=False)
            owner = _owned_snapshot(ref, journal)
            if (owner is None or owner[1] or current_fs.casefold() != ref.fs_uuid.casefold() or
                    _show(r, source)[0].casefold() != owner[0].casefold() or
                    not _readonly(r, source)):
                raise SnapshotIdentityChanged(f"snapshot changed before rsync: {source}")
            _destination(r, dst_mounts[(ref.fs_uuid, ref.subvol_path)], journal)
            _rsync(r, source, dest, _snapshot_filters(ref, journal.migration_id), on_progress, watch)
            if watch is not None:
                watch.check()
    except BaseException:
        release_snapshots(r, snaps, journal)
        raise


def copy_live_swap_subvolume(r: Runner, subvol: Subvol, dst: BtrfsDestination,
                             old_swapfiles: list[str | Path],
                             on_progress: Callable[[PassStats], None] | None = None,
                             *, journal: Journal, source_fs_uuid: str,
                             source_top_level: Path | str | None = None,
                             watch: SpaceWatch | None = None,
                             excluded_subvols: tuple[str, ...] = ()) -> LiveCopy:
    """Reconcile the data around an active swapfile without snapshotting it."""
    if branch(subvol) != "live" or not journal.is_current():
        raise ValueError("live copy requires a mixed swapfile subvolume and current journal")
    if subvol.mountpoint:
        source = Path(subvol.mountpoint).resolve(strict=True)
    elif source_top_level is not None:
        source = (Path(source_top_level) / _subvol_path(subvol.path)).resolve(strict=True)
    else:
        raise ValueError("live subvolume is not reachable")
    if not source.is_dir() or source.is_symlink() or _rootid(r, source) != subvol.id:
        raise SnapshotIdentityChanged("live source subvolume changed")
    source_fs, _ = _mount_uuid(r, source, exact=False)
    if source_fs.casefold() != source_fs_uuid.casefold():
        raise SnapshotIdentityChanged("live source filesystem changed")
    active = _active_swap_paths(r, source_fs).get(subvol.id, set())
    excluded_files = [Path(path) for path in old_swapfiles]
    if (not active or not excluded_files or
            any(not any(excluded.is_file() and excluded.resolve(strict=True).is_relative_to(source)
                        and excluded.samefile(path) for excluded in excluded_files)
                    for path in active)):
        raise ValueError("active swapfile is not excluded from the live copy")
    destination = _destination(r, dst, journal)
    if source == destination or source in destination.parents or destination in source.parents:
        raise ValueError("source and destination overlap")
    child_mounts = [source / _subvol_path(p) for p in excluded_subvols]
    filters = volume_filters(source, child_mounts, old_swapfiles)
    filters.append("--exclude=.snapshots/")
    if watch is not None:
        watch.check()
    start = _rsync(r, source, destination, filters, on_progress, watch).started_at
    if watch is not None:
        watch.check()
    _destination(r, dst, journal)
    _rsync(r, source, destination, [*filters, "--delete"], on_progress, watch)
    if watch is not None:
        watch.check()
    manifest = build_manifest(source, kind="btrfs-live",
                              exclude_paths=_manifest_excludes(tuple(filters[:-1])),
                              exclude_names=(".snapshots",), ctime_before=start)
    return LiveCopy(source_fs, subvol.path, source, destination, start, manifest)


def reference_manifests(snaps: list[SnapshotRef],
                        live_copies: list[LiveCopy]) -> dict[str, Manifest]:
    """Build stable snapshot references and include already captured live references."""
    result = {}
    for ref in snaps:
        key = f"{ref.fs_uuid}:{ref.subvol_path}"
        if key in result:
            raise ValueError("duplicate btrfs reference")
        result[key] = build_manifest(ref.snapshot_path, kind="btrfs-snapshot",
                                     exclude_paths=ref.exclude_paths,
                                     exclude_names=(".snapshots",))
    for item in live_copies:
        key = f"{item.fs_uuid}:{item.subvol_path}"
        if key in result or item.manifest.kind != "btrfs-live":
            raise ValueError("duplicate or invalid live btrfs reference")
        result[key] = item.manifest
    return result
