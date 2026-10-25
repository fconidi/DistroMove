"""Create destination swap areas after the filesystem copy."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re

from .config_rewrite import ResumeTarget
from .disk import (CryptoPlan, _assert_created, _journal_allows_fs, _require_no_signature,
                   luks_format, luks_open)
from .journal import Journal
from .model import CreatedPartition, SwapRef
from .runner import Runner


@dataclass(frozen=True)
class SwapMount:
    path: Path
    fs: str
    fs_uuid: str


@dataclass(frozen=True)
class SwapPlan:
    source: SwapRef
    created: CreatedPartition | None = None
    swap_uuid: str | None = None
    containing_volume_id: str | None = None
    relative_path: str | None = None


@dataclass(frozen=True)
class SwapResult:
    volume_id: str
    kind: str
    source_path: str
    source_uuid: str | None
    path: str
    uuid: str | None
    containing_device_uuid: str | None
    offset: int | None
    luks_uuid: str | None
    random_key: bool = False
    source_resume: bool = False


def _mount_uuid(r: Runner, mount: SwapMount) -> None:
    path = mount.path
    if not path.is_absolute() or not path.is_dir() or path.is_symlink() or path.resolve() != path:
        raise ValueError(f"unsafe swap containing mount: {path}")
    proc = r.run(["findmnt", "--json", "--nofsroot", "--mountpoint", str(path),
                  "--output", "TARGET,SOURCE,FSTYPE"], readonly=True)
    try:
        rows = json.loads(proc.stdout)["filesystems"]
        if len(rows) != 1 or rows[0]["target"] != str(path) or rows[0]["fstype"] != mount.fs:
            raise ValueError
        source = str(rows[0]["source"])
        if source.startswith("UUID="):
            actual = source[5:]
        elif source.startswith("/dev/"):
            actual = r.run(["blkid", "-p", "-o", "value", "-s", "UUID", source],
                           readonly=True).stdout.strip()
        else:
            raise ValueError
        if actual.casefold() != mount.fs_uuid.casefold():
            raise ValueError
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        raise ValueError(f"swap containing mount changed: {path}") from exc


def _file_target(plan: SwapPlan, mounts: dict[str, SwapMount]) -> tuple[Path, SwapMount]:
    if plan.containing_volume_id not in mounts or not plan.relative_path:
        raise ValueError("swapfile needs a containing destination volume and relative path")
    rel = Path(plan.relative_path)
    if (rel.is_absolute() or rel.parts[0] in {".", ".."} or ".." in rel.parts
            or any(part in {"", "."} for part in plan.relative_path.split("/"))):
        raise ValueError("unsafe swapfile path")
    mount = mounts[plan.containing_volume_id]
    if mount.fs not in {"ext4", "btrfs"} or not mount.fs_uuid:
        raise ValueError("unsupported swapfile filesystem")
    target = mount.path / rel
    if (not target.parent.is_dir() or target.parent.is_symlink()
            or target.parent.resolve() != target.parent):
        raise ValueError("swapfile parent is not a safe directory")
    if target.exists() or target.is_symlink():
        raise ValueError(f"swapfile already exists: {target}")
    return target, mount


def _swap_uuid(r: Runner, path: str, expected: str) -> None:
    actual = r.run(["blkid", "-p", "-o", "value", "-s", "UUID", path],
                   readonly=True).stdout.strip()
    kind = r.run(["blkid", "-p", "-o", "value", "-s", "TYPE", path],
                 readonly=True).stdout.strip()
    if actual.casefold() != expected.casefold() or kind != "swap":
        raise RuntimeError(f"swap identity differs on {path}")


def _ext4_offset(text: str) -> int:
    # filefrag -b<page size> -v prints the first physical page in the 0: extent.
    match = re.search(r"^\s*0:\s*0\.\.\s*\d+:\s*(\d+)\.\.\s*\d+:", text, re.M)
    if not match:
        raise ValueError("cannot find swapfile's first physical page")
    return int(match[1])


def make_swaps(r: Runner, plans: list[SwapPlan], mounts: dict[str, SwapMount],
               crypto: CryptoPlan | None, passphrase: bytes, journal: Journal) -> list[SwapResult]:
    """Make planned swap areas. The caller must first finish copying all volumes."""
    if not journal.is_current():
        raise ValueError("migration journal is not current")
    ids = [plan.source.volume_id for plan in plans]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate swap volume_id")
    prepared = []
    for plan in plans:
        source = plan.source
        if source.kind == "partition":
            part = plan.created
            if (part is None or part.volume_id != source.volume_id or not part.fs_uuid
                    or plan.relative_path is not None or plan.containing_volume_id is not None
                    or plan.swap_uuid not in (None, part.fs_uuid)):
                raise ValueError("swap partition differs from planned identity")
            _assert_created(r, part)
            if not _journal_allows_fs(journal, part.path, part.fs_uuid):
                raise ValueError("journal does not own swap partition")
            _require_no_signature(r, part.path)
            if source.luks and (not crypto or source.volume_id not in crypto.per_volume
                                or not part.luks_uuid or source.random_key):
                raise ValueError("encrypted swap has no approved crypto plan")
            if not source.luks and part.luks_uuid and not source.random_key:
                raise ValueError("unexpected encrypted swap partition")
            prepared.append((plan, part.path, None))
        elif source.kind == "file":
            if plan.created is not None or source.luks or source.random_key:
                raise ValueError("unsupported swapfile encryption plan")
            if not plan.swap_uuid or source.size_bytes <= 0:
                raise ValueError("swapfile lacks a planned UUID or size")
            target, mount = _file_target(plan, mounts)
            _mount_uuid(r, mount)
            prepared.append((plan, str(target), mount))
        else:
            raise ValueError("unsupported swap kind")

    results = []
    for plan, target, mount in prepared:
        source = plan.source
        if source.kind == "partition":
            part = plan.created
            if source.random_key:
                results.append(SwapResult(source.volume_id, source.kind, source.path, source.uuid,
                                          part.path, None, None, None, None, True, source.resume))
                continue
            if source.luks:
                luks_format(r, {source.volume_id: part}, crypto, source.volume_id,
                            passphrase, journal)
                target = luks_open(r, part, passphrase, journal)
            op = journal.intend("make_swap", {"partuuid": part.partuuid,
                                              "fs_uuid": part.fs_uuid},
                                creates="filesystem", device=target)
            r.run(["mkswap", "-U", part.fs_uuid, target])
            _swap_uuid(r, target, part.fs_uuid)
            journal.done(op, "created", device=target)
            results.append(SwapResult(source.volume_id, source.kind, source.path, source.uuid,
                                      target, part.fs_uuid, None, None, part.luks_uuid,
                                      False, source.resume))
        else:
            _mount_uuid(r, mount)
            op = journal.intend("make_swapfile", {"fs_uuid": mount.fs_uuid,
                                                   "swap_uuid": plan.swap_uuid},
                                path=target, volume_id=source.volume_id)
            if mount.fs == "btrfs":
                r.run(["btrfs", "filesystem", "mkswapfile", "-s", str(source.size_bytes),
                       "-U", plan.swap_uuid, target])
                _swap_uuid(r, target, plan.swap_uuid)
                offset_text = r.run(["btrfs", "inspect-internal", "map-swapfile", "-r",
                                     target], readonly=True).stdout.strip()
                if not re.fullmatch(r"\d+", offset_text):
                    raise ValueError("invalid btrfs swapfile resume offset")
                offset = int(offset_text)
            else:
                r.run(["mkswap", "--file", "--size", str(source.size_bytes),
                       "-U", plan.swap_uuid, target])
                _swap_uuid(r, target, plan.swap_uuid)
                page_size = os.sysconf("SC_PAGE_SIZE")
                text = r.run(["filefrag", f"-b{page_size}", "-v", target],
                             readonly=True).stdout
                offset = _ext4_offset(text)
            _mount_uuid(r, mount)
            journal.done(op, "created", path=target, offset=offset)
            results.append(SwapResult(source.volume_id, source.kind, source.path, source.uuid,
                                      target, plan.swap_uuid, mount.fs_uuid, offset, None,
                                      False, source.resume))
    return results


def resume_target(swaps: list[SwapResult], original_resume: str | None) -> ResumeTarget | None:
    """Resolve only the original persistent resume swap to its new backing device."""
    ids = [swap.volume_id for swap in swaps]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate swap volume_id")
    if original_resume is None:
        matches = [swap for swap in swaps if swap.source_resume]
    elif original_resume.casefold() == "none":
        return None
    elif original_resume.upper().startswith("UUID="):
        old_uuid = original_resume[5:]
        matches = [swap for swap in swaps if swap.source_uuid and
                   swap.source_uuid.casefold() == old_uuid.casefold()]
    else:
        matches = [swap for swap in swaps if swap.source_path == original_resume]
    if not matches and original_resume is None:
        return None
    if len(matches) != 1:
        raise ValueError("original resume swap is absent or ambiguous")
    selected = matches[0]
    if selected.random_key:
        raise ValueError("random-key swap cannot be a resume target")
    if selected.kind == "file":
        if not selected.containing_device_uuid or selected.offset is None:
            raise ValueError("swapfile has no verified resume offset")
        return ResumeTarget(selected.containing_device_uuid, selected.offset)
    if not selected.uuid:
        raise ValueError("swap partition has no UUID")
    return ResumeTarget(selected.uuid, None)
