"""Read-only probing of the running system: what to migrate, and one picture for the guards.

Every external command goes through ``Runner.run(..., readonly=True)``. Files (fstab,
crypttab, os-release, the dpkg database, /sys, /dev/disk/by-id, the ESP, /proc) are read
below ``root`` so that the whole probe can run against a prepared directory tree.
"""
from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Literal

from .model import (BtrfsInfo, Esp, Keyslot, LuksInfo, MountInfo, Partition, Source, Subvol,
                    SwapRef, SystemSnapshot, Volume, VolumeIdentity)
from .runner import Runner, RunnerError

SYSTEM_MOUNTPOINTS = {"/": "root", "/boot": "boot", "/usr": "usr", "/var": "var",
                      "/home": "home", "/opt": "opt", "/srv": "srv"}
_ROLE_ORDER = ("root", "boot", "usr", "var", "home", "opt", "srv", "extra")
ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
ESP_MOUNTPOINTS = ("/boot/efi", "/efi")
_RANDOM_KEYS = {"/dev/urandom", "/dev/random", "/dev/hw_random"}
_NETWORK_FS = {"nfs", "nfs4", "cifs", "smb3", "fuse.sshfs", "9p", "virtiofs"}
_BY_ID_ORDER = ("wwn-", "nvme-eui.", "nvme-nvme.", "ata-", "nvme-", "scsi-", "usb-", "mmc-")
_GRUB_LOADERS = ("shimx64.efi", "grubx64.efi", "bootx64.efi")
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


@dataclass(frozen=True)
class CrypttabEntry:
    name: str
    device: str
    keyfile: str | None            # None when the volume is unlocked with a passphrase
    options: str


# --------------------------------------------------------------------------- small helpers

def _out(r: Runner, argv: list[str]) -> str:
    return r.run(argv, readonly=True).stdout


def _read(root: Path, rel: str) -> str | None:
    try:
        return (root / rel.lstrip("/")).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _same(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and a.strip().lower() == b.strip().lower()


def _within(path: str, directory: str) -> bool:
    return directory == "/" or path == directory or path.startswith(directory.rstrip("/") + "/")


def _ci_child(directory: Path, name: str) -> Path | None:
    """The entry of ``directory`` called ``name``, ignoring case (FAT keeps any case)."""
    try:
        names = os.listdir(directory)
    except OSError:
        return None
    hit = next((n for n in names if n == name), None) or next(
        (n for n in names if n.lower() == name.lower()), None)
    return directory / hit if hit else None


def _volume_id(role: str, part: Partition) -> str:
    return f"{role}-{(part.partuuid or part.name).split('-')[0].lower()}"


def _mountinfo(m: dict) -> MountInfo:
    return MountInfo(source=m.get("source") or "", target=m.get("target") or "",
                     fstype=m.get("fstype") or "", options=m.get("options") or "")


# --------------------------------------------------------------------------- parsers

def _part_number(name: str, parent: str | None) -> int:
    rest = name[len(parent):] if parent and name.startswith(parent) else name
    m = re.search(r"(\d+)$", rest)  # sda10 -> 10, nvme0n1p2 -> p2 -> 2, mmcblk0p1 -> 1
    if not m:
        raise ValueError(f"cannot tell the partition number of {name}")
    return int(m.group(1))


def _partition(row: dict, disk: dict, by_id: dict[str, str]) -> Partition:
    log = int(disk.get("log-sec") or row.get("log-sec") or 512)
    size = int(row.get("size") or 0)
    parent = row.get("pkname")
    return Partition(
        path=row["path"], name=row["kname"], parent_disk=disk.get("path") or f"/dev/{parent}",
        number=_part_number(row["kname"], parent), size_bytes=size, fstype=row.get("fstype"),
        uuid=row.get("uuid"), partuuid=row.get("partuuid") or "", parttype=row.get("parttype"),
        mountpoint=row.get("mountpoint"), disk_wwn=disk.get("wwn"),
        disk_serial=disk.get("serial"), disk_by_id=by_id.get(parent or ""),
        start_sectors=int(row.get("start") or 0) * 512 // log,  # lsblk START is in 512-byte units
        size_sectors=size // log, logical_sector=log)


def parse_lsblk(text: str, by_id: dict[str, str] | None = None) -> list[Partition]:
    """Partitions in the output of ``LSBLK``; ``by_id`` maps a disk name to its by-id link."""
    rows = json.loads(text).get("blockdevices") or []
    others = {r["kname"]: r for r in rows if r.get("type") != "part"}
    return [_partition(r, others.get(r.get("pkname")) or {}, by_id or {})
            for r in rows if r.get("type") == "part"]


def _unoctal(s: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def parse_fstab(text: str) -> list[MountInfo]:
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 3 or f[0].startswith("#"):
            continue
        out.append(MountInfo(source=_unoctal(f[0]), target=_unoctal(f[1]), fstype=f[2],
                             options=f[3] if len(f) > 3 else "defaults"))
    return out


def parse_crypttab(text: str) -> list[CrypttabEntry]:
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 2 or f[0].startswith("#"):
            continue
        key = f[2] if len(f) > 2 and f[2] not in ("none", "-") else None
        out.append(CrypttabEntry(name=f[0], device=f[1], keyfile=key,
                                 options=f[3] if len(f) > 3 else ""))
    return out


def _field(text: str, name: str) -> str | None:
    m = re.search(rf"^{re.escape(name)}:\s*(.*?)\s*$", text, re.M)
    return m.group(1) if m else None


def _luks2_sections(text: str) -> dict[str, list[dict[str, str]]]:
    """``Section:`` headers -> items (``  N: type``) with their tab-indented fields."""
    sections: dict[str, list[dict[str, str]]] = {}
    current, item = None, None
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            name, _, rest = line.partition(":")
            current = name.strip() if not rest.strip() else None
            if current:
                sections[current] = []
            item = None
            continue
        if current is None:
            continue
        m = re.match(r"^ +(\d+): (\S+)", line)
        if m:
            item = {"index": m.group(1), "type": m.group(2)}
            sections[current].append(item)
        elif item is not None and ":" in line:
            k, _, v = line.strip().partition(":")
            item.setdefault(k.strip(), v.strip())
    return sections


def parse_luks_dump(text: str) -> LuksInfo:
    """The output of ``cryptsetup luksDump`` (LUKS1 or LUKS2)."""
    version = int(_field(text, "Version") or 0)
    uuid = _field(text, "UUID") or ""
    if version == 1:
        cipher = f"{_field(text, 'Cipher name')}-{_field(text, 'Cipher mode')}"
        bits = int(_field(text, "MK bits") or 0)
        slots = [Keyslot(int(m.group(1)), "pbkdf2", f"{cipher} {bits} bits")
                 for m in re.finditer(r"^Key Slot (\d+): ENABLED", text, re.M)]
        return LuksInfo(1, cipher, bits, 512, slots, uuid, None)
    if version != 2:
        raise ValueError("not a LUKS header dump")
    sections = _luks2_sections(text)
    segment = next((s for s in sections.get("Data segments", []) if s["type"] == "crypt"), {})
    slots = [s for s in sections.get("Keyslots", []) if s["type"] == "luks2"]
    keys = [Keyslot(int(s["index"]), s.get("PBKDF", ""),
                    f"{s.get('Cipher', '')} {s.get('Cipher key', '')}") for s in slots]
    bits = int(slots[0].get("Key", "0").split()[0]) if slots else 0
    sector = int((segment.get("sector") or "512").split()[0])
    return LuksInfo(2, segment.get("cipher", ""), bits, sector, keys, uuid, None)


def _dm_table(text: str) -> list[tuple[str, str | None]]:
    out = []
    for line in text.splitlines():
        f = line.split()
        if f and line.strip() != "No devices found":
            out.append((f[0], f[1] if len(f) > 1 else None))
    return out


def _refers_to(spec: str, uuid: str) -> bool:
    s = spec.strip().strip('"')
    for prefix in ("UUID=", "/dev/disk/by-uuid/"):
        if s.startswith(prefix):
            return _same(s[len(prefix):].strip('"'), uuid)
    return False


def enrich_luks(info: LuksInfo, crypttab: str | list[CrypttabEntry], dmsetup_text: str) -> LuksInfo:
    """Add the open mapping (from ``"<name> <dm-uuid>"`` lines) and the crypttab key file."""
    entries = parse_crypttab(crypttab) if isinstance(crypttab, str) else list(crypttab)
    hexid = info.luks_uuid.replace("-", "").lower()
    mapper = info.mapper_name
    for name, dmuuid in _dm_table(dmsetup_text):
        m = re.fullmatch(r"CRYPT-LUKS[12]-([0-9a-fA-F]+)-(.+)", dmuuid or "")
        if m and m.group(1).lower() == hexid:
            mapper = name
            break
    entry = next((e for e in entries if mapper and e.name == mapper), None) or next(
        (e for e in entries if _refers_to(e.device, info.luks_uuid)), None)
    return replace(info, mapper_name=mapper, keyfile=entry.keyfile if entry else info.keyfile)


def _installed(dpkg_status: str) -> set[str]:
    out = set()
    for para in re.split(r"\n\s*\n", dpkg_status):
        pkg = re.search(r"^Package:\s*(\S+)", para, re.M)
        st = re.search(r"^Status:\s*(.+?)\s*$", para, re.M)
        if pkg and st and st.group(1).split()[-1] == "installed":
            out.add(pkg.group(1))
    return out


def _subvol_name(path: str) -> str:
    path = path.strip()
    if path.startswith("<FS_TREE>/"):
        path = path[len("<FS_TREE>/"):]
    return path.strip("/")


def is_syslinuxos(dpkg_status: str, subvol_paths: Iterable[str]) -> bool:
    """SysLinuxOS: ``syslinuxos-snapshots`` installed and subvolumes ``@`` and ``@home``."""
    paths = {_subvol_name(p) for p in subvol_paths}
    return "syslinuxos-snapshots" in _installed(dpkg_status) and {"@", "@home"} <= paths


def parse_efibootmgr(text: str) -> tuple[str | None, dict[str, str]]:
    """``BootCurrent`` and the entry lines of ``efibootmgr -v`` (without ``dp:``/``data:``)."""
    current, entries = None, {}
    for line in text.splitlines():
        m = re.match(r"BootCurrent:\s*([0-9A-Fa-f]{4})\s*$", line)
        if m:
            current = m.group(1).upper()
            continue
        m = re.match(r"Boot([0-9A-Fa-f]{4})\*?\s", line)
        if m:
            entries[m.group(1).upper()] = line.strip()
    return current, entries


_HD = re.compile(r"HD\(\d+,GPT,(?P<uuid>[0-9A-Fa-f-]{36}),[^)]*\)/"
                 r"(?:File\((?P<file>[^)]*)\)|(?P<path>\\[^\s)]+))")


def _loader_of(line: str | None) -> tuple[str, str] | None:
    m = _HD.search(line or "")
    return (m.group("uuid"), m.group("file") or m.group("path")) if m else None


def _parse_swapon(text: str) -> list[tuple[str, str, int, str | None]]:
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 3:
            name = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), f[0])
            out.append((name, f[1], int(f[2]), f[3] if len(f) > 3 else None))
    return out


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
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return {}
    for n in names:
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
    try:
        names = os.listdir(base)
    except OSError:
        names = []
    for k in names:
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
    parts = {k: _partition(row, rows.get(row.get("pkname")) or {}, by_id)
             for k, row in rows.items() if row.get("type") == "part"}
    return _Live(rows=rows, parents=parents, by_path=by_path, parts=parts,
                 mounts=json.loads(_out(r, FINDMNT)).get("filesystems") or [],
                 crypttab=parse_crypttab(_read(root, "etc/crypttab") or ""),
                 dm_text=_dm_text(root), swaps=_parse_swapon(_out(r, SWAPON)))


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
    """Partition kernel name -> (role, mountpoint) of every volume to migrate."""
    found: dict[str, tuple[str, str]] = {}
    for m in live.mounts:
        target, source = m.get("target") or "", m.get("source") or ""
        role = SYSTEM_MOUNTPOINTS.get(target) or ("extra" if target in extra else None)
        if role is None:
            continue
        if not source.startswith("/dev/"):
            if strict and (role == "extra" or target == "/"):
                raise Unsupported(f"{target} is not on a disk partition")
            continue
        if m.get("fstype") != "btrfs" and (m.get("fsroot") or "/") != "/":
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
    missing = sorted(extra - {m.get("target") for m in live.mounts})
    if strict and missing:
        raise Unsupported(f"{missing[0]} is not mounted")
    return found


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


# --------------------------------------------------------------------------- btrfs

def _subvol_of(m: dict) -> str:
    opt = re.search(r"(?:^|,)subvol=([^,]*)", m.get("options") or "")
    return _subvol_name(opt.group(1) if opt else (m.get("fsroot") or "/"))


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
    listed = [(int(m.group(1)), _subvol_name(m.group(2))) for m in re.finditer(
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
            try:
                only = os.listdir(root / where.lstrip("/")) == [os.path.basename(swap)]
            except OSError:
                only = False
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
        return _same(val.strip('"'), part.uuid if key == "UUID" else part.partuuid)
    for prefix, value in (("/dev/disk/by-uuid/", part.uuid),
                          ("/dev/disk/by-partuuid/", part.partuuid)):
        if s.startswith(prefix):
            return _same(s[len(prefix):], value)
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
    pkgs = _installed(dpkg)
    if pkgs & {"dracut", "dracut-core"}:
        raise Unsupported("dracut is not supported; initramfs-tools is needed")
    if "initramfs-tools" not in pkgs:
        raise Unsupported("initramfs-tools is not installed")
    return dpkg


def _os_id(root: Path) -> str:
    text = _read(root, "etc/os-release") or _read(root, "usr/lib/os-release") or ""
    m = re.search(r'^ID=("?)([^"\n]*)\1\s*$', text, re.M)
    return m.group(2) if m else "linux"


def _unique(items: list, used: set[str]) -> list:
    out = []
    for it in items:
        vid, n = it.volume_id, 2
        while vid in used:
            vid, n = f"{it.volume_id}-{n}", n + 1
        used.add(vid)
        out.append(replace(it, volume_id=vid) if vid != it.volume_id else it)
    return out


def discover_source(r: Runner, root: Path = Path("/"), *,
                    extra_mounts: Iterable[str] = ()) -> Source:
    """The running system to migrate; ``extra_mounts`` are mountpoints the user includes."""
    root = Path(root)
    dpkg = _check_platform(r, root)
    check_tools(r)
    live = _gather(r, root)
    groups = _volume_groups(live, set(extra_mounts), strict=True)
    if not any(mp == "/" for _, mp in groups.values()):
        raise Unsupported("the root filesystem was not found")
    swaps = _swap_refs(r, live, groups, strict=True)
    files = [s.path for s in swaps if s.kind == "file"]
    volumes = sorted((_volume(r, live, root, k, role, mp, files)
                      for k, (role, mp) in groups.items()),
                     key=lambda v: (_ROLE_ORDER.index(v.role), v.mountpoint))
    root_vol = next(v for v in volumes if v.role == "root")
    holder = next((v for v in volumes if v.role == "boot"), root_vol)
    volumes = [replace(v, boot_inside_luks=True) if v is holder and v.luks else v for v in volumes]
    used: set[str] = set()
    volumes, swaps = _unique(volumes, used), _unique(swaps, used)

    esp_part, esp_mp = _choose_esp(live, parse_fstab(_read(root, "etc/fstab") or ""))
    current, entries = parse_efibootmgr(_out(r, ["efibootmgr", "-v"]))
    booted = _loader_of(entries.get(current or ""))
    own, loader = None, None
    if booted and _same(booted[0], esp_part.partuuid):
        pieces = booted[1].split("\\")
        loader = pieces[-1].lower()
        if len(pieces) >= 4 and pieces[1].upper() == "EFI":
            own = pieces[-2]
    if loader and loader not in _GRUB_LOADERS:
        raise Unsupported(f"the system was not started by GRUB ({booted[1]}); "
                          "only GRUB is supported")
    secure_boot = _secure_boot(r, root)
    if secure_boot:
        efi = _ci_child(root / esp_mp.lstrip("/"), "EFI")
        folder = _ci_child(efi, own) if efi and own else None
        signed = folder is not None and all(_ci_child(folder, f)
                                            for f in ("shimx64.efi", "grubx64.efi"))
        if not (loader == "shimx64.efi" and signed
                and {"shim-signed", "grub-efi-amd64-signed"} <= _installed(dpkg)):
            raise Unsupported("Secure Boot is on and the signed boot chain (shim and signed GRUB) "
                              "cannot be preserved")
    dirs = _efi_dirs(root, esp_mp)
    foreign = [d for d in dirs if d.upper() != "BOOT" and not _same(d, own)]
    esp = Esp(esp_part, esp_mp, dirs, foreign)

    unmigrated = []
    for m in live.mounts:
        source = m.get("source") or ""
        if not (source.startswith("/dev/") or m.get("fstype") in _NETWORK_FS):
            continue
        part = _partition_of(live, source) if source.startswith("/dev/") else None
        if part is None or (part.name not in groups and part.name != esp_part.name):
            unmigrated.append(_mountinfo(m))

    paths = [s.path for v in volumes if v.btrfs for s in v.btrfs.subvolumes]
    kind = ("ext4" if root_vol.fs == "ext4"
            else "syslinuxos" if is_syslinuxos(dpkg, paths) else "btrfs")
    return Source(kind, _os_id(root), volumes, unmigrated, esp, swaps, root_vol.fs_uuid,
                  secure_boot)


# --------------------------------------------------------------------------- snapshot

def collect_snapshot(r: Runner, root: Path = Path("/")) -> SystemSnapshot:
    """One coherent picture of the live system (see ``SystemSnapshot``)."""
    root = Path(root)
    live = _gather(r, root)
    groups = _volume_groups(live, set(), strict=False)
    swaps = _swap_refs(r, live, groups, strict=False)
    current, entries = parse_efibootmgr(_out(r, ["efibootmgr", "-v"]))
    swap_parts = {s.path for s in swaps if s.kind == "partition"}
    esp_contents: dict[str, list[str]] = {}
    identities = []
    for p in live.parts.values():
        is_esp = (p.parttype or "").lower() == ESP_TYPE
        targets = [m["target"] for m in live.mounts if _mounted_on(live, m, p.name)]
        if is_esp and targets:
            esp_contents[p.partuuid] = _efi_dirs(root, targets[0])
        role = (groups[p.name][0] if p.name in groups else "esp" if is_esp
                else "swap" if p.path in swap_parts else "extra")
        child = next((live.rows[k] for k, ps in live.parents.items()
                      if p.name in ps and live.rows[k].get("type") == "crypt"), None)
        luks_uuid = p.uuid if p.fstype == "crypto_LUKS" else None
        fs_uuid = (child.get("uuid") if child else None) if luks_uuid else p.uuid
        identities.append(VolumeIdentity(
            _volume_id(role, p) if role != "extra" else "", role, p.disk_wwn, p.disk_serial,
            p.disk_by_id, p.partuuid, p.start_sectors, p.size_sectors, luks_uuid, fs_uuid))
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
    """volume_id -> where each key file is needed: in the initramfs (to unlock and mount the
    root, which includes a separate /usr) or only after the root is mounted."""
    out: dict[str, Literal["initramfs", "after-root"]] = {}
    for v in source.volumes:
        if v.luks is not None and v.luks.keyfile:
            out[v.volume_id] = "initramfs" if v.role in ("root", "usr") else "after-root"
    for s in source.swaps:
        if s.luks is not None and s.luks.keyfile:
            out[s.volume_id] = "after-root"
    return out


def _sqlite_writers(root: Path) -> list[tuple[str, str]]:
    """(database path, process name) for SQLite files some process holds open for writing."""
    proc, found = root / "proc", {}
    try:
        pids = sorted((p for p in os.listdir(proc) if p.isdigit()), key=int)
    except OSError:
        return []
    for pid in pids:
        try:
            fds = os.listdir(proc / pid / "fd")
        except OSError:
            continue
        for fd in fds:
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
