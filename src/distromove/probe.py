"""Read-only probing of the running system: what to migrate, and one picture for the guards.

Every external command goes through ``Runner.run(..., readonly=True)``. Files (fstab,
crypttab, os-release, the dpkg database, the initramfs resume setting, the kernel command
line, /sys, /dev/disk/by-id, the ESP, /proc) are read below ``root`` so that the whole probe
can run against a prepared directory tree. The parsers live in ``probe_parse`` and are
re-exported here.
"""
from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Literal

from .model import (BtrfsInfo, Esp, MountInfo, Partition, Source, Subvol, SwapRef,
                    SystemSnapshot, Volume, VolumeIdentity)
from .probe_parse import (CrypttabEntry, enrich_luks, installed_packages, is_syslinuxos,
                          loader_of, parse_crypttab, parse_dm_table, parse_efibootmgr,
                          parse_fstab, parse_lsblk, parse_luks_dump, parse_resume, parse_swapon,
                          partition_from_row, same, subvol_name)
from .runner import Runner, RunnerError

__all__ = [
    "SYSTEM_MOUNTPOINTS", "ESP_TYPE", "ESP_MOUNTPOINTS", "LSBLK", "FINDMNT", "SWAPON",
    "Unsupported", "CrypttabEntry", "check_tools", "discover_source", "collect_snapshot",
    "classify_keys", "database_activity", "enrich_luks", "installed_packages", "is_syslinuxos",
    "loader_of", "parse_crypttab", "parse_dm_table", "parse_efibootmgr", "parse_fstab",
    "parse_lsblk", "parse_luks_dump", "parse_resume", "parse_swapon", "partition_from_row",
    "same", "subvol_name",
]

SYSTEM_MOUNTPOINTS = {"/": "root", "/boot": "boot", "/usr": "usr", "/var": "var",
                      "/home": "home", "/opt": "opt", "/srv": "srv"}
_ROLE_ORDER = ("root", "boot", "usr", "var", "home", "opt", "srv", "extra")
ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
ESP_MOUNTPOINTS = ("/boot/efi", "/efi")
_RANDOM_KEYS = {"/dev/urandom", "/dev/random", "/dev/hw_random"}
_NETWORK_FS = {"nfs", "nfs4", "cifs", "smb3", "fuse.sshfs", "9p", "virtiofs", "glusterfs", "ceph"}
# kernel and runtime filesystems: nothing in them is data to copy (snap images come back
# from /var/lib/snapd, overlay layers from the directories below them)
_PSEUDO_FS = {"proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "ramfs", "overlay", "cgroup",
              "cgroup2", "securityfs", "debugfs", "tracefs", "configfs", "fusectl", "pstore",
              "bpf", "mqueue", "hugetlbfs", "autofs", "binfmt_misc", "efivarfs", "nsfs",
              "rpc_pipefs", "selinuxfs", "squashfs"}
_BY_ID_ORDER = ("wwn-", "nvme-eui.", "nvme-nvme.", "ata-", "nvme-", "scsi-", "usb-", "mmc-")
_SB_VAR = "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

LSBLK = ["lsblk", "--json", "--list", "--bytes", "--output",
         "NAME,KNAME,PATH,PKNAME,TYPE,SIZE,FSTYPE,UUID,PARTUUID,PARTTYPE,START,LOG-SEC,WWN,SERIAL,"
         "MOUNTPOINT"]
FINDMNT = ["findmnt", "--json", "--list", "--nofsroot", "--output",
           "SOURCE,TARGET,FSTYPE,OPTIONS,FSROOT"]
SWAPON = ["swapon", "--show=NAME,TYPE,SIZE,UUID", "--raw", "--bytes", "--noheadings"]

# package shown to the user, command, version pattern, minimum version
_TOOLS = (
    ("btrfs-progs", ["btrfs", "--version"], r"btrfs-progs v(\d+(?:\.\d+)*)", (6, 1)),
    ("cryptsetup", ["cryptsetup", "--version"], r"cryptsetup (\d+(?:\.\d+)*)", (2, 1)),
    ("rsync", ["rsync", "--version"], r"rsync\s+version (\d+(?:\.\d+)*)", (3, 1)),
    ("util-linux", ["sfdisk", "--version"], r"util-linux (\d+(?:\.\d+)*)", (2, 35)),
    ("e2fsprogs", ["mke2fs", "-V"], r"mke2fs (\d+(?:\.\d+)*)", (1, 46)),
    ("GRUB", ["grub-install", "--version"], r"\(GRUB\) (\d+(?:\.\d+)*)", (2, 6)),
    ("efibootmgr", ["efibootmgr", "--version"], r"version (\d+)", (17,)),
)


class Unsupported(Exception):
    """The running system is outside what can be migrated; ``reason`` says why."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------- small helpers

def _out(r: Runner, argv: list[str]) -> str:
    return r.run(argv, readonly=True).stdout


def _read(root: Path, rel: str) -> str | None:
    try:
        return (root / rel.lstrip("/")).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _listdir(directory: Path) -> list[str]:
    try:
        return os.listdir(directory)
    except OSError:
        return []


def _within(path: str, directory: str) -> bool:
    return directory == "/" or path == directory or path.startswith(directory.rstrip("/") + "/")


def _ci_child(directory: Path | None, name: str | None) -> Path | None:
    """The entry of ``directory`` called ``name``, ignoring case (FAT keeps any case)."""
    if directory is None or not name:
        return None
    names = _listdir(directory)
    hit = next((n for n in names if n == name), None) or next(
        (n for n in names if n.lower() == name.lower()), None)
    return directory / hit if hit else None


def _volume_id(role: str, part: Partition) -> str:
    return f"{role}-{(part.partuuid or part.name).split('-')[0].lower()}"


def _unique_ids(ids: list[str], used: set[str]) -> list[str]:
    out = []
    for base in ids:
        vid, n = base, 2
        while vid in used:
            vid, n = f"{base}-{n}", n + 1
        used.add(vid)
        out.append(vid)
    return out


def _unique(items: list, used: set[str]) -> list:
    ids = _unique_ids([it.volume_id for it in items], used)
    return [replace(it, volume_id=vid) if vid != it.volume_id else it
            for it, vid in zip(items, ids)]


def _mountinfo(m: dict) -> MountInfo:
    return MountInfo(source=m.get("source") or "", target=m.get("target") or "",
                     fstype=m.get("fstype") or "", options=m.get("options") or "")


# --------------------------------------------------------------------------- tools

def _version(text: str, pattern: str) -> tuple[int, ...] | None:
    m = re.search(pattern, text)
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def check_tools(r: Runner) -> None:
    """Raise ``Unsupported`` when a needed program is missing or too old."""
    for name, argv, pattern, minimum in _TOOLS:
        try:
            res = r.run(argv, check=False, readonly=True)
        except RunnerError:
            raise Unsupported(f"{name} is not installed") from None
        found = _version(f"{res.stdout}\n{res.stderr}", pattern)
        if found is None:
            raise Unsupported(f"cannot tell the version of {name}")
        if found < minimum:
            raise Unsupported(f"{name} {'.'.join(map(str, found))} is too old "
                              f"(at least {'.'.join(map(str, minimum))} is needed)")


# --------------------------------------------------------------------------- the live system

@dataclass
class _Live:
    rows: dict[str, dict]            # kernel name -> lsblk row
    parents: dict[str, list[str]]    # kernel name -> parent kernel names
    by_path: dict[str, str]          # /dev path (PATH and /dev/<kname>) -> kernel name
    parts: dict[str, Partition]      # kernel name -> partition
    mounts: list[dict]               # findmnt rows
    crypttab: list[CrypttabEntry]
    dm_text: str                     # "<name> <dm-uuid>" lines
    swaps: list[tuple[str, str, int, str | None]]


def _disk_links(root: Path) -> dict[str, str]:
    """Disk kernel name -> preferred /dev/disk/by-id link (WWN first)."""
    base = root / "dev/disk/by-id"
    best: dict[str, tuple[tuple, str]] = {}
    for n in sorted(_listdir(base)):
        if re.search(r"-part\d+$", n):
            continue
        try:
            target = os.path.basename(os.readlink(base / n))
        except OSError:
            continue
        rank = next((i for i, p in enumerate(_BY_ID_ORDER) if n.startswith(p)), len(_BY_ID_ORDER))
        key = (rank, len(n), n)
        if target not in best or key < best[target][0]:
            best[target] = (key, f"/dev/disk/by-id/{n}")
    return {k: v[1] for k, v in best.items()}


def _dm_text(root: Path) -> str:
    """Device-mapper devices as ``"<name> <dm-uuid>"`` lines (name alone without a UUID)."""
    lines = []
    base = root / "sys/block"
    for k in _listdir(base):
        if not k.startswith("dm-"):
            continue
        name = (_read(base, f"{k}/dm/name") or "").strip()
        uuid = (_read(base, f"{k}/dm/uuid") or "").strip()
        if name:
            lines.append(f"{name} {uuid}".strip())
    return "".join(f"{line}\n" for line in sorted(lines))


def _gather(r: Runner, root: Path) -> _Live:
    rows: dict[str, dict] = {}
    parents: dict[str, list[str]] = {}
    by_path: dict[str, str] = {}
    for row in json.loads(_out(r, LSBLK)).get("blockdevices") or []:
        k = row["kname"]
        rows.setdefault(k, row)
        if row.get("pkname") and row["pkname"] not in parents.setdefault(k, []):
            parents[k].append(row["pkname"])
        by_path[row["path"]] = by_path[f"/dev/{k}"] = k
    by_id = _disk_links(root)
    parts = {k: partition_from_row(row, rows.get(row.get("pkname")) or {}, by_id)
             for k, row in rows.items() if row.get("type") == "part"}
    return _Live(rows=rows, parents=parents, by_path=by_path, parts=parts,
                 mounts=json.loads(_out(r, FINDMNT)).get("filesystems") or [],
                 crypttab=parse_crypttab(_read(root, "etc/crypttab") or ""),
                 dm_text=_dm_text(root), swaps=parse_swapon(_out(r, SWAPON)))


def _chain(live: _Live, source: str) -> list[dict]:
    """The device behind ``source`` and every device below it (crypt, LVM, RAID, partition)."""
    todo, seen, out = [live.by_path.get(source)], set(), []
    while todo:
        k = todo.pop(0)
        if k is None or k in seen or k not in live.rows:
            continue
        seen.add(k)
        out.append(live.rows[k])
        todo += live.parents.get(k, [])
    return out


def _partition_of(live: _Live, source: str) -> Partition | None:
    chain = _chain(live, source)
    return next((live.parts[c["kname"]] for c in chain if c["kname"] in live.parts), None)


def _mounted_on(live: _Live, m: dict, kname: str) -> bool:
    part = _partition_of(live, m.get("source") or "")
    return part is not None and part.name == kname


def _check_chain(chain: list[dict], what: str) -> None:
    for c in chain:
        t, fs = c.get("type") or "", c.get("fstype") or ""
        if t == "lvm" or fs == "LVM2_member":
            raise Unsupported(f"{what} is on LVM, which is not supported")
        if t.startswith("raid") or t == "md" or fs == "linux_raid_member":
            raise Unsupported(f"{what} is on software RAID, which is not supported")


def _volume_groups(live: _Live, extra: set[str], strict: bool) -> dict[str, tuple[str, str]]:
    """Partition kernel name -> (role, mountpoint) of every volume to migrate.

    In ``strict`` mode a system mountpoint that is not a block device is refused, so that
    nothing is left out without a word: an automount not triggered yet, ZFS, overlay and
    the like. A network filesystem stays where it is and is listed as not migrated.
    """
    found: dict[str, tuple[str, str]] = {}
    mounted = {m.get("target") for m in live.mounts if m.get("fstype") != "autofs"}
    for m in live.mounts:
        target, source, fstype = m.get("target") or "", m.get("source") or "", m.get("fstype") or ""
        role = SYSTEM_MOUNTPOINTS.get(target) or ("extra" if target in extra else None)
        if role is None:
            continue
        if not source.startswith("/dev/"):
            if not strict or (fstype == "autofs" and target in mounted):
                continue  # the automount point of a filesystem that is mounted
            if fstype == "autofs":
                raise Unsupported(f"{target} is an automount that is not mounted yet; "
                                  "mount/trigger it first")
            if fstype in _NETWORK_FS and role != "extra" and target != "/":
                continue
            raise Unsupported(f"{target} is on {fstype or 'an unknown filesystem'} ({source}), "
                              "which is not supported")
        if fstype != "btrfs" and (m.get("fsroot") or "/") != "/":
            continue  # a bind mount of a directory, not a filesystem of its own
        chain = _chain(live, source)
        part = _partition_of(live, source)
        if strict:
            _check_chain(chain, target)
            if part is None:
                raise Unsupported(f"{target} is not on a disk partition")
        if part is None:
            continue
        cur = found.get(part.name)
        if cur is None or _ROLE_ORDER.index(role) < _ROLE_ORDER.index(cur[0]):
            found[part.name] = (role, target)
    missing = sorted(extra - mounted)
    if strict and missing:
        raise Unsupported(f"{missing[0]} is not mounted")
    return found


def _check_no_zfs(live: _Live) -> None:
    for m in live.mounts:
        if m.get("fstype") == "zfs":
            raise Unsupported(f"{m.get('target')} is on ZFS ({m.get('source')}), "
                              "which is not supported")


def _parent_mount(live: _Live, m: dict) -> dict | None:
    """The mount that directly contains the mountpoint of ``m``."""
    target, best = m.get("target") or "", None
    for o in live.mounts:
        t = o.get("target") or ""
        if t != target and _within(target, t) and (
                best is None or len(t) > len(best.get("target") or "")):
            best = o
    return best


def _unmigrated(live: _Live, groups: dict[str, tuple[str, str]], esp: Partition) -> list[MountInfo]:
    """Mounts whose data the copy leaves where it is: block devices that are not volumes
    (nor the ESP), network filesystems, and any other real filesystem (FUSE and the like)
    unless it sits on a kernel or runtime filesystem such as /run or /tmp."""
    out = []
    for m in live.mounts:
        source, fstype = m.get("source") or "", m.get("fstype") or ""
        if fstype in _PSEUDO_FS:
            continue
        if source.startswith("/dev/"):
            part = _partition_of(live, source)
            if part is not None and (part.name in groups or part.name == esp.name):
                continue
        elif fstype not in _NETWORK_FS:
            parent = _parent_mount(live, m)
            if parent is not None and parent.get("fstype") in _PSEUDO_FS:
                continue
        out.append(_mountinfo(m))
    return out


def _ordered(groups: dict[str, tuple[str, str]]) -> list[tuple[str, str, str]]:
    """(kernel name, role, mountpoint) in the order of ``Source.volumes``."""
    return sorted(((k, role, mp) for k, (role, mp) in groups.items()),
                  key=lambda x: (_ROLE_ORDER.index(x[1]), x[2]))


def _holding_mount(live: _Live, path: str) -> dict | None:
    """The mount the file ``path`` lives on (the longest mountpoint above it)."""
    best = None
    for m in live.mounts:
        t = m.get("target") or ""
        if _within(path, t) and (best is None or len(t) > len(best.get("target") or "")):
            best = m
    return best


def _role_holding(live: _Live, groups: dict[str, tuple[str, str]], path: str) -> str | None:
    best = _holding_mount(live, path)
    part = _partition_of(live, best.get("source") or "") if best else None
    return groups[part.name][0] if part is not None and part.name in groups else None


def _swap_refs(r: Runner, live: _Live, groups: dict[str, tuple[str, str]],
               strict: bool) -> list[SwapRef]:
    refs = []
    for name, kind, size, uuid in live.swaps:
        if kind == "file":
            slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
            refs.append(SwapRef(f"swapfile-{slug}", "file", name, _role_holding(live, groups, name),
                                uuid, size, None, False))
            continue
        if name.startswith("/dev/zram"):
            continue  # compressed RAM, nothing on disk
        chain = _chain(live, name)
        part = _partition_of(live, name)
        if strict:
            _check_chain(chain, f"swap {name}")
            if part is None:
                raise Unsupported(f"swap {name} is not on a disk partition")
        if part is None:
            continue
        luks, random_key = None, False
        dev = chain[0] if chain else {}
        if part.fstype == "crypto_LUKS":
            luks = enrich_luks(parse_luks_dump(_out(r, ["cryptsetup", "luksDump", part.path])),
                               live.crypttab, live.dm_text)
        elif dev.get("type") == "crypt":
            entry = next((e for e in live.crypttab if e.name == dev.get("name")), None)
            random_key = entry is not None and entry.keyfile in _RANDOM_KEYS
            if strict and not random_key:
                raise Unsupported(f"swap {name} is encrypted without LUKS and without a random key")
        refs.append(SwapRef(_volume_id("swap", part), "partition", part.path, None,
                            None if random_key else uuid, size, luks, random_key))
    return refs


def _resume_names(live: _Live, swap: SwapRef) -> set[str]:
    """Every way ``RESUME=``/``resume=`` can name this swap (its device, for a swap file)."""
    if swap.kind == "file":
        m = _holding_mount(live, swap.path) or {}
        source = m.get("source") or ""
        chain, part = _chain(live, source), _partition_of(live, source)
        uuids, partuuids = [chain[0].get("uuid") if chain else None], []
        devices = [source] + [c.get("path") for c in chain]
    else:
        part = _partition_of(live, swap.path)
        uuids, partuuids = [swap.uuid], [part.partuuid if part else None]
        devices = [swap.path] + [c.get("path") for c in _chain(live, swap.path)]
        if swap.luks is not None and swap.luks.mapper_name:
            devices.append(f"/dev/mapper/{swap.luks.mapper_name}")
    names = {d for d in devices if d}
    names |= {f"UUID={u}" for u in uuids if u} | {f"/dev/disk/by-uuid/{u}" for u in uuids if u}
    names |= {f"PARTUUID={p}" for p in partuuids if p}
    names |= {f"/dev/disk/by-partuuid/{p}" for p in partuuids if p}
    return {n.lower() for n in names}


def _mark_resume(root: Path, live: _Live, swaps: list[SwapRef]) -> list[SwapRef]:
    """Mark the swaps the initramfs resumes from: ``resume=`` of the kernel command line and
    initramfs-tools ``RESUME``; unset, ``auto`` or naming no swap means what initramfs-tools
    picks then, the largest swap partition without a random key."""
    cmdline, conf = parse_resume(_read(root, "etc/initramfs-tools/conf.d/resume") or "",
                                 _read(root, "proc/cmdline") or "")

    def named(spec: str | None) -> set[int]:
        if not spec or spec in ("none", "auto"):
            return set()
        spec = spec.strip().strip('"').lower()
        return {i for i, s in enumerate(swaps) if spec in _resume_names(live, s)}

    hits = named(cmdline) | named(conf)
    if conf != "none" and not named(conf):
        lasting = [(s.size_bytes, i) for i, s in enumerate(swaps)
                   if s.kind == "partition" and not s.random_key]
        if lasting:
            hits.add(max(lasting)[1])
    return [replace(s, resume=True) if i in hits and not s.random_key else s
            for i, s in enumerate(swaps)]


# --------------------------------------------------------------------------- btrfs

def _subvol_of(m: dict) -> str:
    opt = re.search(r"(?:^|,)subvol=([^,]*)", m.get("options") or "")
    return subvol_name(opt.group(1) if opt else (m.get("fsroot") or "/"))


def _reach(path: str, mounted: list[tuple[str, dict]]) -> str | None:
    """Where subvolume ``path`` can be reached in the live tree, through its mounts."""
    best = None
    for p, m in mounted:
        target = m["target"]
        if path == p:
            cand = target
        elif p == "" or path.startswith(p + "/"):
            cand = target.rstrip("/") + "/" + path[len(p):].lstrip("/")
        else:
            continue
        if best is None or len(cand) < len(best):
            best = cand
    return best


def _is_snapshot(path: str) -> bool:
    return ".snapshots" in path.split("/")


def _btrfs(r: Runner, root: Path, mp: str, mounts: list[dict],
           swapfiles: list[str]) -> tuple[BtrfsInfo, list[str]]:
    """The filesystem mounted on ``mp`` and the paths whose size counts for the copy."""
    show = _out(r, ["btrfs", "filesystem", "show", mp])
    n = int(m.group(1)) if (m := re.search(r"Total devices (\d+)", show)) else 0
    if n != 1:
        raise Unsupported(f"the btrfs filesystem of {mp} spans {n} devices; only one is supported")
    fs_uuid = m.group(1) if (m := re.search(r"uuid:\s*([0-9A-Fa-f-]{36})", show)) else ""
    listing = _out(r, ["btrfs", "subvolume", "list", mp])
    listed = [(int(m.group(1)), subvol_name(m.group(2))) for m in re.finditer(
        r"^ID (\d+) gen \d+ top level \d+ path (.+?)\s*$", listing, re.M)]
    default_m = re.match(r"\s*ID (\d+)", _out(r, ["btrfs", "subvolume", "get-default", mp]))
    mounted = [(_subvol_of(m), m) for m in mounts]
    reach = {path: _reach(path, mounted) for _, path in listed}
    holder = {}
    for f in swapfiles:
        hits = [(len(p), path) for path, p in reach.items() if p and _within(f, p)]
        if hits:
            holder[max(hits)[1]] = f
    subvols = []
    # files kept directly in the top level (id 5) count too when it is mounted
    measured = [m["target"] for p, m in mounted if p == ""][:1]
    for sid, path in listed:
        where, own = reach[path], next((m for p, m in mounted if p == path), None)
        swap = holder.get(path)
        only = False
        if swap is not None and os.path.dirname(swap) == where:
            only = _listdir(root / where.lstrip("/")) == [os.path.basename(swap)]
        properties: dict[str, str] = {}
        if where and not _is_snapshot(path):
            for kind in ("subvol", "inode"):
                for line in _out(r, ["btrfs", "property", "get", "-t", kind, where]).splitlines():
                    k, sep, v = line.partition("=")
                    if sep:
                        properties[k.strip()] = v.strip()
            if not only:
                measured.append(where)
        subvols.append(Subvol(sid, path, own["target"] if own else None,
                              own.get("options") if own else None, properties,
                              swap is not None, only))
    return BtrfsInfo(fs_uuid, int(default_m.group(1)) if default_m else 5, subvols), measured


# --------------------------------------------------------------------------- discovery

def _volume(r: Runner, live: _Live, root: Path, kname: str, role: str, mp: str,
            swapfiles: list[str]) -> Volume:
    part = live.parts[kname]
    mounts = [m for m in live.mounts if _mounted_on(live, m, kname)]
    main = next(m for m in mounts if m["target"] == mp)
    fs = main.get("fstype") or ""
    if fs not in ("ext4", "btrfs"):
        raise Unsupported(f"{fs} on {mp} is not supported (only ext4 and btrfs)")
    chain = _chain(live, main["source"])
    luks = None
    if part.fstype == "crypto_LUKS":
        luks = enrich_luks(parse_luks_dump(_out(r, ["cryptsetup", "luksDump", part.path])),
                           live.crypttab, live.dm_text)
    elif any(c.get("type") == "crypt" for c in chain):
        raise Unsupported(f"{mp} is encrypted without LUKS")
    own_files = [f for f in swapfiles if any(_holding_mount(live, f) is m for m in mounts)]
    btrfs, paths = (None, [mp]) if fs == "ext4" else _btrfs(r, root, mp, mounts, own_files)
    used, inodes = (int(x) for x in _out(r, ["df", "-B1", "--output=used,iused", mp]).split()[-2:])
    apparent = sum(int(_out(r, ["du", "-sxb", p]).split()[0]) for p in paths)
    return Volume(_volume_id(role, part), role, mp, part, luks, fs, chain[0].get("uuid") or "",
                  used, apparent, inodes, btrfs, False)


def _efi_dirs(root: Path, mountpoint: str) -> list[str]:
    efi = _ci_child(root / mountpoint.lstrip("/"), "EFI")
    if efi is None:
        return []
    return sorted(e.name for e in efi.iterdir() if e.is_dir())


def _spec_is(spec: str, part: Partition) -> bool:
    s = spec.strip().strip('"')
    key, sep, val = s.partition("=")
    if sep and key in ("UUID", "PARTUUID"):
        return same(val.strip('"'), part.uuid if key == "UUID" else part.partuuid)
    for prefix, value in (("/dev/disk/by-uuid/", part.uuid),
                          ("/dev/disk/by-partuuid/", part.partuuid)):
        if s.startswith(prefix):
            return same(s[len(prefix):], value)
    return s == part.path


def _choose_esp(live: _Live, fstab: list[MountInfo]) -> tuple[Partition, str]:
    mounted = []
    for m in live.mounts:
        p = _partition_of(live, m.get("source") or "")
        if m.get("target") in ESP_MOUNTPOINTS and p is not None and (
                p.parttype or "").lower() == ESP_TYPE:
            mounted.append((p, m["target"]))
    listed = [(p, t) for p, t in mounted
              if any(e.target == t and _spec_is(e.source, p) for e in fstab)]
    picks = listed or mounted
    if len(picks) != 1:
        raise Unsupported("cannot tell which EFI system partition the system uses "
                          "(it must be mounted on /boot/efi or /efi)")
    return picks[0]


def _own_loader(root: Path, esp: Partition, esp_mp: str, current: str | None,
                entries: dict[str, str], packages: set[str]) -> tuple[str, bool]:
    """(loader folder of this system under EFI/, started through shim). Fails closed.

    GRUB is accepted on evidence only: the entry the firmware booted is
    ``EFI/<id>/grubx64.efi`` or ``shimx64.efi`` on this ESP; or, when it booted another way
    (no BootCurrent, a firmware device entry, the removable path ``EFI/BOOT``, another ESP),
    GRUB for UEFI is installed, exactly one ``EFI/<id>/grubx64.efi`` is on this ESP and
    nothing of systemd-boot or of a unified kernel image is there.
    """
    booted = loader_of(entries.get(current or ""))
    if booted and same(booted[0], esp.partuuid):
        pieces = booted[1].split("\\")  # "\EFI\debian\shimx64.efi" -> "", EFI, debian, file
        fallback = len(pieces) >= 3 and pieces[1].upper() == "EFI" and pieces[2].upper() == "BOOT"
        if (len(pieces) == 4 and pieces[1].upper() == "EFI" and not fallback
                and pieces[3].lower() in ("grubx64.efi", "shimx64.efi")):
            return pieces[2], pieces[3].lower() == "shimx64.efi"
        if not fallback:
            raise Unsupported(f"the system was not started by GRUB ({booted[1]}); "
                              "only GRUB is supported")
    base = root / esp_mp.lstrip("/")
    efi = _ci_child(base, "EFI")
    linux = _ci_child(efi, "Linux")
    ukis = [n for n in _listdir(linux) if n.lower().endswith(".efi")] if linux else []
    if _ci_child(efi, "systemd") or ukis or _ci_child(_ci_child(base, "loader"), "loader.conf"):
        raise Unsupported("systemd-boot or a unified kernel image is on the EFI system partition; "
                          "only GRUB is supported")
    if not any(p.startswith("grub-efi-amd64") for p in packages):
        raise Unsupported("GRUB for UEFI (grub-efi-amd64) is not installed")
    grubs = [d for d in _efi_dirs(root, esp_mp)
             if d.upper() != "BOOT" and _ci_child(efi / d, "grubx64.efi")]
    if len(grubs) != 1:
        raise Unsupported("cannot tell which GRUB on the EFI system partition started the system")
    return grubs[0], False


def _secure_boot(r: Runner, root: Path) -> bool:
    try:
        res = r.run(["mokutil", "--sb-state"], check=False, readonly=True)
        text = f"{res.stdout}\n{res.stderr}"
    except RunnerError:
        text = ""
    if "SecureBoot enabled" in text:
        return True
    if "SecureBoot disabled" in text:
        return False
    try:
        data = (root / _SB_VAR).read_bytes()
    except OSError:
        return False
    return len(data) >= 5 and data[4] == 1


def _check_platform(r: Runner, root: Path) -> str:
    arch = _out(r, ["uname", "-m"]).strip()
    if arch != "x86_64":
        raise Unsupported(f"only x86-64 systems are supported (this one is {arch})")
    if not (root / "sys/firmware/efi").is_dir():
        raise Unsupported("the system was started in BIOS/legacy mode; only UEFI is supported")
    dpkg = _read(root, "var/lib/dpkg/status")
    if dpkg is None:
        raise Unsupported("not a Debian-based system (no dpkg database)")
    pkgs = installed_packages(dpkg)
    if pkgs & {"dracut", "dracut-core"}:
        raise Unsupported("dracut is not supported; initramfs-tools is needed")
    if "initramfs-tools" not in pkgs:
        raise Unsupported("initramfs-tools is not installed")
    return dpkg


def _os_id(root: Path) -> str:
    text = _read(root, "etc/os-release") or _read(root, "usr/lib/os-release") or ""
    m = re.search(r'^ID=("?)([^"\n]*)\1\s*$', text, re.M)
    return m.group(2) if m else "linux"


def discover_source(r: Runner, root: Path = Path("/"), *,
                    extra_mounts: Iterable[str] = ()) -> Source:
    """The running system to migrate; ``extra_mounts`` are mountpoints the user includes."""
    root = Path(root)
    dpkg = _check_platform(r, root)
    packages = installed_packages(dpkg)
    check_tools(r)
    live = _gather(r, root)
    _check_no_zfs(live)
    groups = _volume_groups(live, set(extra_mounts), strict=True)
    if not any(mp == "/" for _, mp in groups.values()):
        raise Unsupported("the root filesystem was not found")
    swaps = _mark_resume(root, live, _swap_refs(r, live, groups, strict=True))
    files = [s.path for s in swaps if s.kind == "file"]
    volumes = [_volume(r, live, root, k, role, mp, files) for k, role, mp in _ordered(groups)]
    root_vol = next(v for v in volumes if v.role == "root")
    holder = next((v for v in volumes if v.role == "boot"), root_vol)
    volumes = [replace(v, boot_inside_luks=True) if v is holder and v.luks else v for v in volumes]
    used: set[str] = set()
    volumes, swaps = _unique(volumes, used), _unique(swaps, used)

    esp_part, esp_mp = _choose_esp(live, parse_fstab(_read(root, "etc/fstab") or ""))
    current, entries = parse_efibootmgr(_out(r, ["efibootmgr", "-v"]))
    own, via_shim = _own_loader(root, esp_part, esp_mp, current, entries, packages)
    secure_boot = _secure_boot(r, root)
    if secure_boot:
        folder = _ci_child(_ci_child(root / esp_mp.lstrip("/"), "EFI"), own)
        signed = folder is not None and all(_ci_child(folder, f)
                                            for f in ("shimx64.efi", "grubx64.efi"))
        if not (via_shim and signed and {"shim-signed", "grub-efi-amd64-signed"} <= packages):
            raise Unsupported("Secure Boot is on and the signed boot chain (shim and signed GRUB) "
                              "cannot be preserved")
    dirs = _efi_dirs(root, esp_mp)
    esp = Esp(esp_part, esp_mp, dirs, [d for d in dirs if d.upper() != "BOOT" and not same(d, own)])

    unmigrated = _unmigrated(live, groups, esp_part)

    paths = [s.path for v in volumes if v.btrfs for s in v.btrfs.subvolumes]
    kind = ("ext4" if root_vol.fs == "ext4"
            else "syslinuxos" if is_syslinuxos(dpkg, paths) else "btrfs")
    return Source(kind, _os_id(root), volumes, unmigrated, esp, swaps, root_vol.fs_uuid,
                  secure_boot)


# --------------------------------------------------------------------------- snapshot

def _source_roles(live: _Live, source: Source | None) -> dict[str, tuple[str, str]]:
    """Partition kernel name -> (volume_id, role) of the volumes and swaps of ``source``."""
    out: dict[str, tuple[str, str]] = {}
    if source is None:
        return out
    for p in live.parts.values():
        v = next((v for v in source.volumes if same(v.partition.partuuid, p.partuuid)), None)
        s = next((s for s in source.swaps if s.kind == "partition" and (
            same(s.luks.luks_uuid if s.luks else s.uuid, p.uuid))), None)
        if v is not None:
            out[p.name] = (v.volume_id, v.role)
        elif s is not None:
            out[p.name] = (s.volume_id, "swap")
    return out


def collect_snapshot(r: Runner, root: Path = Path("/"),
                     source: Source | None = None) -> SystemSnapshot:
    """One coherent picture of the live system (see ``SystemSnapshot``).

    With ``source`` (the migrated system), its volumes, including those the user included by
    hand, keep their ``volume_id`` and role. Partitions that are neither a volume, a swap nor
    an ESP have role ``foreign`` and no ``volume_id``.
    """
    root = Path(root)
    live = _gather(r, root)
    extra = {v.mountpoint for v in source.volumes if v.role == "extra"} if source else set()
    groups = _volume_groups(live, extra, strict=False)
    swaps = _mark_resume(root, live, _swap_refs(r, live, groups, strict=False))
    ordered = _ordered(groups)  # same ids, in the same order, as discover_source
    used: set[str] = set()
    ids = _unique_ids([_volume_id(role, live.parts[k]) for k, role, _ in ordered], used)
    swaps = _unique(swaps, used)
    roles = {k: (vid, role) for (k, role, _), vid in zip(ordered, ids)}
    for s in swaps:
        k = live.by_path.get(s.path) if s.kind == "partition" else None
        if k is not None:
            roles.setdefault(k, (s.volume_id, "swap"))
    roles |= _source_roles(live, source)
    current, entries = parse_efibootmgr(_out(r, ["efibootmgr", "-v"]))
    esp_contents: dict[str, list[str]] = {}
    identities = []
    for p in live.parts.values():
        is_esp = (p.parttype or "").lower() == ESP_TYPE
        targets = [m["target"] for m in live.mounts if _mounted_on(live, m, p.name)]
        if is_esp and targets:
            esp_contents[p.partuuid] = _efi_dirs(root, targets[0])
        vid, role = roles.get(p.name) or (
            (_volume_id("esp", p), "esp") if is_esp else ("", "foreign"))
        child = next((live.rows[k] for k, ps in live.parents.items()
                      if p.name in ps and live.rows[k].get("type") == "crypt"), None)
        luks_uuid = p.uuid if p.fstype == "crypto_LUKS" else None
        fs_uuid = (child.get("uuid") if child else None) if luks_uuid else p.uuid
        identities.append(VolumeIdentity(vid, role, p.disk_wwn, p.disk_serial, p.disk_by_id,
                                         p.partuuid, p.start_sectors, p.size_sectors, luks_uuid,
                                         fs_uuid))
    root_mount = next((m for m in live.mounts if m.get("target") == "/"), {})
    root_chain = _chain(live, root_mount.get("source") or "")
    root_uuid = (root_chain[0].get("uuid") or "") if root_chain else ""
    return SystemSnapshot(
        fstab=_read(root, "etc/fstab") or "", crypttab=_read(root, "etc/crypttab") or "",
        mounts=[_mountinfo(m) for m in live.mounts],
        mappers=[line for line in live.dm_text.splitlines() if line],
        swaps=swaps, esp_contents=esp_contents, boot_current=current, boot_entries=entries,
        identities=identities, running_root_uuid=root_uuid)


# --------------------------------------------------------------------------- keys and databases

def classify_keys(source: Source) -> dict[str, Literal["initramfs", "after-root"]]:
    """volume_id -> where each key file is needed.

    In the initramfs: the root and a separate /usr, the resume device (or the volume holding
    the resume swap file), and any container whose crypttab line has the ``initramfs``
    option. Everything else only after the root is mounted.
    """
    early_roles = {"root", "usr"} | {s.containing_volume_role for s in source.swaps
                                     if s.kind == "file" and s.resume}
    out: dict[str, Literal["initramfs", "after-root"]] = {}
    for item, early in [(v, v.role in early_roles) for v in source.volumes] + [
            (s, s.resume) for s in source.swaps]:
        luks = item.luks
        if luks is not None and luks.keyfile:
            needed = early or "initramfs" in luks.crypttab_options
            out[item.volume_id] = "initramfs" if needed else "after-root"
    return out


def _sqlite_writers(root: Path) -> list[tuple[str, str]]:
    """(database path, process name) for SQLite files some process holds open for writing."""
    proc, found = root / "proc", {}
    for pid in sorted((p for p in _listdir(proc) if p.isdigit()), key=int):
        for fd in _listdir(proc / pid / "fd"):
            try:
                target = os.readlink(proc / pid / "fd" / fd)
                info = (proc / pid / "fdinfo" / fd).read_text()
            except OSError:
                continue
            flags = re.search(r"^flags:\s*([0-7]+)", info, re.M)
            if not target.startswith("/") or not flags or int(flags.group(1), 8) & 3 == 0:
                continue
            db = re.sub(r"-(wal|journal|shm)$", "", target)
            if db in found:
                continue
            path = root / db.lstrip("/")
            try:
                if not stat.S_ISREG(path.stat().st_mode):
                    continue
                with open(path, "rb") as fh:
                    if fh.read(16) != b"SQLite format 3\x00":
                        continue
            except OSError:
                continue
            found[db] = (_read(proc, f"{pid}/comm") or "").strip()
    return list(found.items())


def database_activity(r: Runner, root: Path = Path("/")) -> list[str]:
    """Running databases and containers whose files a live copy may catch mid-write."""
    names = {line.strip() for line in _out(r, ["ps", "-e", "-o", "comm="]).splitlines()}
    found = []
    if "postgres" in names:
        found.append("PostgreSQL")
    if names & {"mysqld", "mariadbd"}:
        found.append("MySQL/MariaDB")
    found += [f"SQLite: {db} ({name})" for db, name in _sqlite_writers(Path(root))]
    if "dockerd" in names:
        found.append("Docker")
    return found
