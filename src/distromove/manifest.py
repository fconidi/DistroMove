"""Reference manifests: the single producer of the description a copy is verified against.

A manifest is taken from a tree that does not change while it is read: a frozen ext4
filesystem, a read-only btrfs snapshot, or a btrfs subvolume right after a reconciliation
pass (then restricted with ``files_from``). Reading never modifies the tree: files and
directories are opened with ``O_NOATIME`` when allowed and symbolic links are never followed.
Like the copy (``rsync --one-file-system``), the walk does not descend into other
filesystems or btrfs subvolumes; their mount point directory is recorded.
"""
from __future__ import annotations

import hashlib
import os
import stat
import typing
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .model import Manifest, ManifestEntry, ManifestKind

_O_NOATIME = getattr(os, "O_NOATIME", 0)
_CHUNK = 1 << 20
_KINDS = typing.get_args(ManifestKind)


def _open_noatime(path: str, flags: int) -> int:
    if _O_NOATIME:
        try:
            return os.open(path, flags | _O_NOATIME)
        except PermissionError:  # O_NOATIME needs file ownership or CAP_FOWNER
            pass
    return os.open(path, flags)


def _normalise(rel: str) -> str | None:
    """Relative POSIX path inside the tree; None for the tree root itself."""
    p = PurePosixPath(rel.lstrip("/"))
    if ".." in p.parts:
        raise ValueError(f"path outside the tree: {rel!r}")
    s = str(p)
    return None if s in ("", ".") else s


def _walk(root: str, root_dev: int, excludes: tuple[str, ...] = (),
          exclude_names: tuple[str, ...] = ()) -> dict[str, os.stat_result]:
    found: dict[str, os.stat_result] = {}
    stack = [""]
    while stack:
        rel = stack.pop()
        full = os.path.join(root, rel) if rel else root
        try:
            fd = _open_noatime(full, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            continue
        try:
            with os.scandir(fd) as it:
                names = [e.name for e in it]
        finally:
            os.close(fd)
        for name in names:
            child = f"{rel}/{name}" if rel else name
            if name in exclude_names or any(child == excluded or child.startswith(excluded + "/")
                                            for excluded in excludes):
                continue
            try:
                st = os.lstat(os.path.join(full, name))
            except FileNotFoundError:
                continue
            found[child] = st
            if stat.S_ISDIR(st.st_mode) and st.st_dev == root_dev:
                stack.append(child)
    return found


def _listed(root: str, root_dev: int, files_from: list[str]) -> dict[str, os.stat_result]:
    found: dict[str, os.stat_result] = {}
    for item in files_from:
        rel = _normalise(item)
        if rel is None:
            continue
        parts = rel.split("/")
        inside = True
        for n in range(1, len(parts)):  # every parent must be a real directory of this tree
            try:
                pst = os.lstat(os.path.join(root, *parts[:n]))
            except FileNotFoundError:
                inside = False
                break
            if not stat.S_ISDIR(pst.st_mode) or pst.st_dev != root_dev:
                inside = False
                break
        if not inside:
            continue
        try:
            found[rel] = os.lstat(os.path.join(root, rel))
        except FileNotFoundError:
            continue
    return found


def _under(rel: str, prefixes: list[str | None]) -> bool:
    return any(p is None or rel == p or rel.startswith(p + "/") for p in prefixes)


def _hash_file(path: str) -> str | None:
    try:
        fd = _open_noatime(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        h = hashlib.sha256()
        while True:
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                return h.hexdigest()
            h.update(chunk)
    finally:
        os.close(fd)


def _hash_link(path: str) -> str | None:
    try:
        return hashlib.sha256(os.fsencode(os.readlink(path))).hexdigest()
    except FileNotFoundError:
        return None


def build_manifest(root: Path | str, hash_paths: tuple[str, ...] = ("etc", "boot"),
                   sample: int = 200, files_from: list[str] | None = None,
                   kind: ManifestKind = "ext4-frozen",
                   exclude_paths: tuple[str, ...] = (),
                   exclude_names: tuple[str, ...] = (),
                   ctime_before: float | None = None) -> Manifest:
    """Describe the tree at ``root``.

    Every entry records size, mtime (ns), mode, uid and gid. Contents are hashed (SHA-256)
    for regular files and symbolic links under ``hash_paths`` (relative to ``root``;
    ``"."`` means the whole tree) and for ``sample`` further regular files, chosen
    deterministically so that two runs on the same tree pick the same files.
    With ``files_from`` (paths relative to ``root``, as given to ``rsync --files-from``)
    only those paths are described; missing ones are left out.
    """
    if kind not in _KINDS:
        raise ValueError(f"unknown manifest kind: {kind!r}")
    taken_at = datetime.now(timezone.utc).isoformat()
    root_s = os.path.realpath(os.fspath(root))
    root_st = os.lstat(root_s)
    if not stat.S_ISDIR(root_st.st_mode):
        raise ValueError(f"not a directory: {root_s}")

    excludes = tuple(p for item in exclude_paths if (p := _normalise(item)) is not None)
    if files_from is None:
        found = _walk(root_s, root_st.st_dev, excludes, exclude_names)
    else:
        found = _listed(root_s, root_st.st_dev, files_from)
        found = {rel: st for rel, st in found.items()
                 if not any(rel == p or rel.startswith(p + "/") for p in excludes)}
        found = {rel: st for rel, st in found.items()
                 if not any(component in exclude_names for component in rel.split("/"))}
    if ctime_before is not None:
        cutoff = int(ctime_before * 1_000_000_000)
        found = {rel: st for rel, st in found.items() if st.st_ctime_ns < cutoff}

    prefixes = [_normalise(p) for p in hash_paths]
    to_hash = {rel for rel, st in found.items()
               if (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)) and _under(rel, prefixes)}
    others = sorted((hashlib.sha256(os.fsencode(rel)).hexdigest(), rel)
                    for rel, st in found.items()
                    if stat.S_ISREG(st.st_mode) and rel not in to_hash)
    to_hash.update(rel for _, rel in others[:max(sample, 0)])

    entries: dict[str, ManifestEntry] = {}
    for rel in sorted(found):
        st = found[rel]
        is_reg, is_lnk = stat.S_ISREG(st.st_mode), stat.S_ISLNK(st.st_mode)
        digest = None
        if rel in to_hash:
            full = os.path.join(root_s, rel)
            digest = _hash_file(full) if is_reg else _hash_link(full)
        if ctime_before is not None:
            try:
                latest = os.lstat(os.path.join(root_s, rel))
            except FileNotFoundError:
                continue
            if latest.st_ctime_ns != st.st_ctime_ns or latest.st_ctime_ns >= cutoff:
                continue
        entries[rel] = ManifestEntry(
            size=st.st_size if (is_reg or is_lnk) else 0,
            mtime=st.st_mtime_ns, mode=st.st_mode, uid=st.st_uid, gid=st.st_gid,
            sha256=digest)
    if ctime_before is not None:
        entries = {rel: entry for rel, entry in entries.items()
                   if all(str(parent) in entries for parent in PurePosixPath(rel).parents
                          if str(parent) != ".")}
    return Manifest(entries=entries, taken_at=taken_at, kind=kind)
