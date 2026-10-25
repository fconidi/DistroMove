"""Parsers for what the probe reads: command output and configuration files. No side effects."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from typing import Iterable

from .model import Keyslot, LuksInfo, MountInfo, Partition


@dataclass(frozen=True)
class CrypttabEntry:
    name: str
    device: str
    keyfile: str | None            # None when the volume is unlocked with a passphrase
    options: str


def same(a: str | None, b: str | None) -> bool:
    """Two identifiers (UUIDs, names) are equal, ignoring case; empty values never match."""
    return bool(a) and bool(b) and a.strip().lower() == b.strip().lower()


# --------------------------------------------------------------------------- lsblk

def _part_number(name: str, parent: str | None) -> int:
    rest = name[len(parent):] if parent and name.startswith(parent) else name
    m = re.search(r"(\d+)$", rest)  # sda10 -> 10, nvme0n1p2 -> p2 -> 2, mmcblk0p1 -> 1
    if not m:
        raise ValueError(f"cannot tell the partition number of {name}")
    return int(m.group(1))


def partition_from_row(row: dict, disk: dict, by_id: dict[str, str]) -> Partition:
    """A partition from its lsblk row and the row of its disk."""
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
    """Partitions in the output of ``probe.LSBLK``; ``by_id`` maps a disk to its by-id link."""
    rows = json.loads(text).get("blockdevices") or []
    others = {r["kname"]: r for r in rows if r.get("type") != "part"}
    return [partition_from_row(r, others.get(r.get("pkname")) or {}, by_id or {})
            for r in rows if r.get("type") == "part"]


# --------------------------------------------------------------------------- fstab, crypttab

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


# --------------------------------------------------------------------------- LUKS

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


def parse_dm_table(text: str) -> list[tuple[str, str | None]]:
    """``"<name> <dm-uuid>"`` lines -> (name, dm UUID or None)."""
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
            return same(s[len(prefix):].strip('"'), uuid)
    return False


def enrich_luks(info: LuksInfo, crypttab: str | list[CrypttabEntry], dmsetup_text: str) -> LuksInfo:
    """Add the open mapping (from ``"<name> <dm-uuid>"`` lines), the crypttab key file and
    the crypttab options of the container."""
    entries = parse_crypttab(crypttab) if isinstance(crypttab, str) else list(crypttab)
    hexid = info.luks_uuid.replace("-", "").lower()
    mapper = info.mapper_name
    for name, dmuuid in parse_dm_table(dmsetup_text):
        m = re.fullmatch(r"CRYPT-LUKS[12]-([0-9a-fA-F]+)-(.+)", dmuuid or "")
        if m and m.group(1).lower() == hexid:
            mapper = name
            break
    entry = next((e for e in entries if mapper and e.name == mapper), None) or next(
        (e for e in entries if _refers_to(e.device, info.luks_uuid)), None)
    if entry is None:
        return replace(info, mapper_name=mapper)
    options = tuple(o.strip() for o in entry.options.split(",") if o.strip())
    return replace(info, mapper_name=mapper, keyfile=entry.keyfile, crypttab_options=options)


# --------------------------------------------------------------------------- packages, btrfs

def installed_packages(dpkg_status: str) -> set[str]:
    """Names of the packages the dpkg status file lists as installed."""
    out = set()
    for para in re.split(r"\n\s*\n", dpkg_status):
        pkg = re.search(r"^Package:\s*(\S+)", para, re.M)
        st = re.search(r"^Status:\s*(.+?)\s*$", para, re.M)
        if pkg and st and st.group(1).split()[-1] == "installed":
            out.add(pkg.group(1))
    return out


def subvol_name(path: str) -> str:
    """Subvolume path from the top level: ``<FS_TREE>/@home`` and ``/@home`` -> ``@home``."""
    path = path.strip()
    if path.startswith("<FS_TREE>/"):
        path = path[len("<FS_TREE>/"):]
    return path.strip("/")


def is_syslinuxos(dpkg_status: str, subvol_paths: Iterable[str]) -> bool:
    """SysLinuxOS: ``syslinuxos-snapshots`` installed and subvolumes ``@`` and ``@home``."""
    paths = {subvol_name(p) for p in subvol_paths}
    return "syslinuxos-snapshots" in installed_packages(dpkg_status) and {"@", "@home"} <= paths


# --------------------------------------------------------------------------- UEFI, swap, resume

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


def loader_of(line: str | None) -> tuple[str, str] | None:
    """(ESP PARTUUID, loader path) of a boot entry line, when it names a file on a GPT disk."""
    m = _HD.search(line or "")
    return (m.group("uuid"), m.group("file") or m.group("path")) if m else None


def parse_swapon(text: str) -> list[tuple[str, str, int, str | None]]:
    """(name, type, size in bytes, swap UUID) from ``probe.SWAPON``."""
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 3:
            name = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), f[0])
            out.append((name, f[1], int(f[2]), f[3] if len(f) > 3 else None))
    return out


def parse_resume(conf: str, cmdline: str) -> tuple[str | None, str | None]:
    """(``resume=`` of the kernel command line, ``RESUME`` of initramfs-tools).

    The initramfs-tools value is ``None`` when unset; ``auto`` and ``none`` are returned as is.
    """
    m = re.search(r"(?:^|\s)resume=(\S+)", cmdline)
    values = re.findall(r"""^\s*RESUME=["']?([^"'\s]*)""", conf, re.M)
    return (m.group(1) if m else None), (values[-1] if values and values[-1] else None)
