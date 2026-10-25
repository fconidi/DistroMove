"""Where the migrated volumes go: free space on the destination disks, size estimate,
the partition plan, and the check that the plan is still valid when it is applied.

Everything is computed in SECTORS of each disk's logical sector size (a 4096-byte disk
gets 4096-byte sectors); byte sizes are converted with that size. Partitions start and end
on 1 MiB boundaries. Destination disks are read with read-only commands through the
Runner; this module never writes to a disk.

The identities of everything that will be created (partition UUID, LUKS UUID, filesystem
UUID) are chosen here, before any write, so the journal can name them in advance.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Callable, Iterable, Literal

from .model import PlannedIdentity, Source, SwapRef, Volume
from .runner import Runner

__all__ = [
    "ALIGN_BYTES", "ESP_DEFAULT_BYTES", "LUKS2_HEADER_BYTES", "BYTES_PER_INODE",
    "BTRFS_META_MIN_BYTES", "BOOT_MARGIN_MIN_BYTES", "FreeRegion", "DiskInfo", "NoTable",
    "UnsupportedDisk", "InsufficientSpace", "TargetTooSmall", "TablesChanged", "SourceSpaceLow",
    "VolumeTarget", "EspChoice", "Partplan", "InitGpt", "MigrationPlan", "SpaceWatch",
    "parse_parted_free", "parse_wipefs", "scan_disk", "disk_info", "estimate_min_bytes",
    "source_snapshot_space_ok", "plan_init_gpt", "plan_layout", "fingerprint_tables",
    "assert_tables_unchanged",
]

MIB = 1024 ** 2
GIB = 1024 ** 3

ALIGN_BYTES = MIB                       # start and size of every partition
ESP_DEFAULT_BYTES = 512 * MIB           # size of a new EFI system partition
LUKS2_HEADER_BYTES = 16 * MIB           # room kept for the LUKS2 header of an encrypted volume

# Estimate constants (see estimate_min_bytes)
MARGIN_MIN_BYTES = GIB                  # smallest safety margin of a volume
BOOT_MARGIN_MIN_BYTES = 256 * MIB       # smallest margin of a separate /boot volume
MARGIN_FRACTION = 0.05                  # margin as a fraction of the filesystem content
BTRFS_META_MIN_BYTES = 256 * MIB        # btrfs metadata allowance, at least
BTRFS_META_FRACTION = 0.03              # ... or this fraction of the data
BTRFS_SUBVOL_BYTES = 16 * MIB           # extra metadata per subvolume carried over as a snapshot
EXT4_OVERHEAD_FRACTION = 0.04           # inode tables, bitmaps and reserved metadata
EXT4_JOURNAL_BYTES = 128 * MIB
BYTES_PER_INODE = 16384                 # mke2fs default ratio: one inode per 16 KiB of space
INODE_SLACK = 1.10                      # headroom on the inode count of the source
SOURCE_SNAPSHOT_MIN_FREE_BYTES = 512 * MIB   # free space the source needs to take a snapshot

SPACE_WATCH_MIN_BYTES = 2 * GIB         # SpaceWatch threshold: at least 2 GiB ...
SPACE_WATCH_FRACTION = 0.05             # ... or 5 % of the filesystem, whichever is larger


# --------------------------------------------------------------------------- exceptions

class UnsupportedDisk(Exception):
    """The partition table cannot be handled (only GPT is supported)."""

    def __init__(self, message: str, disk: str = "", table: str = ""):
        super().__init__(message)
        self.disk, self.table = disk, table


class NoTable(Exception):
    """The disk has no partition table. ``can_init`` is true only when ``wipefs`` also
    reports no recognised signature at all."""

    def __init__(self, disk: str, can_init: bool):
        super().__init__(f"{disk} has no partition table")
        self.disk, self.can_init = disk, can_init


class InsufficientSpace(Exception):
    def __init__(self, disk: str, needed_bytes: int, available_bytes: int, role: str = ""):
        what = f" for the {role} partition" if role else ""
        super().__init__(
            f"Not enough free space on {disk}{what}: {needed_bytes / GIB:.1f} GiB needed, "
            f"the largest free area is {available_bytes / GIB:.1f} GiB")
        self.disk, self.needed_bytes, self.available_bytes, self.role = (
            disk, needed_bytes, available_bytes, role)


class TargetTooSmall(Exception):
    def __init__(self, volume_id: str, size_bytes: int, min_bytes: int):
        super().__init__(f"{volume_id}: {size_bytes / GIB:.1f} GiB is below the estimated minimum "
                         f"of {min_bytes / GIB:.1f} GiB")
        self.volume_id, self.size_bytes, self.min_bytes = volume_id, size_bytes, min_bytes


class TablesChanged(Exception):
    """A destination disk changed after the plan was approved."""

    def __init__(self, disks: list[str]):
        super().__init__("the partition table changed after approval: " + ", ".join(disks))
        self.disks = list(disks)


class SourceSpaceLow(Exception):
    def __init__(self, mountpoint: str, free_bytes: int, threshold_bytes: int):
        super().__init__(f"only {free_bytes / GIB:.1f} GiB free on {mountpoint} "
                         f"(threshold {threshold_bytes / GIB:.1f} GiB)")
        self.mountpoint, self.free_bytes, self.threshold_bytes = mountpoint, free_bytes, threshold_bytes


# --------------------------------------------------------------------------- data

@dataclass(frozen=True)
class FreeRegion:
    disk: str
    start_sectors: int
    size_sectors: int
    logical_sector: int


@dataclass(frozen=True)
class DiskInfo:
    """What is known about a disk when deciding whether it may be initialised."""
    path: str
    size_bytes: int
    logical_sector: int
    signatures: tuple[str, ...] | None     # wipefs signature types; None = not read
    serial: str | None = None
    wwn: str | None = None
    by_id: str | None = None
    model: str | None = None


@dataclass(frozen=True)
class VolumeTarget:
    volume: Volume
    disk: str
    size_bytes: int


@dataclass(frozen=True)
class EspChoice:
    mode: Literal["reuse", "new"]
    disk: str
    size_bytes: int


@dataclass(frozen=True)
class Partplan:
    disk: str
    start_sectors: int
    size_sectors: int
    role: str                      # esp, swap or the volume role
    planned: PlannedIdentity
    volume_id: str = ""
    logical_sector: int = 512


@dataclass(frozen=True)
class InitGpt:
    """A new GPT to write on a disk that has no partition table and no recognised signature.

    That is not proof that the disk holds no data (raw data, an unknown format, an
    encrypted disk without header all look the same), so the user confirms by typing
    ``confirmation``.
    """
    disk: str
    disk_identity: str
    confirmation: str
    size_bytes: int
    logical_sector: int
    no_recognised_signatures: bool = True
    basis: str = "no recognised signatures"


@dataclass(frozen=True)
class MigrationPlan:
    targets: list[VolumeTarget]
    esp: EspChoice
    partitions: list[Partplan]
    swaps: list[Partplan]
    approved_tables: dict[str, str] = field(default_factory=dict)
    init_gpt: list[InitGpt] = field(default_factory=list)


# --------------------------------------------------------------------------- reading disks

PARTED = ["parted", "-m", "-s"]


def _parted_cmd(disk: str) -> list[str]:
    return PARTED + [disk, "unit", "s", "print", "free"]


def _wipefs_cmd(disk: str) -> list[str]:
    return ["wipefs", "-J", disk]


def _sfdisk_cmd(disk: str) -> list[str]:
    return ["sfdisk", "--dump", disk]


def parse_wipefs(text: str) -> list[str]:
    """Signature types reported by ``wipefs -J`` (no output at all means none)."""
    if not text.strip():
        return []
    data = json.loads(text)
    return [str(s.get("type")) for s in data.get("signatures") or []]


def _value(token: str, logical: int) -> int:
    """A parted value in sectors; ``unit s`` and ``unit B`` outputs are both accepted."""
    token = token.strip()
    if token.endswith("s"):
        return int(token[:-1])
    if token.endswith("B"):
        return int(token[:-1]) // logical
    return int(token)


def _parted_rows(text: str) -> tuple[list[str], list[list[str]]]:
    lines = [ln.strip().rstrip(";") for ln in text.splitlines() if ln.strip()]
    if lines and lines[0].startswith("BYT"):
        lines = lines[1:]
    if not lines:
        raise UnsupportedDisk("cannot read the partition table of this disk")
    return lines[0].split(":"), [ln.split(":") for ln in lines[1:]]


def parse_parted_free(text: str, disk: str, *, signatures: Iterable[str] | None = None
                      ) -> list[FreeRegion]:
    """Free regions of a GPT disk from ``parted -m unit s|B print free``.

    ``msdos`` and every other table type raise ``UnsupportedDisk``. A disk without a
    table raises ``NoTable``; its ``can_init`` is true only when ``signatures`` (the
    ``wipefs`` types) were read and are empty.
    """
    header, rows = _parted_rows(text)
    table = header[5] if len(header) > 5 else ""
    if table == "unknown":
        raise NoTable(disk, can_init=signatures is not None and not list(signatures))
    if table != "gpt":
        raise UnsupportedDisk(f"{disk} uses a {table or 'unknown'} partition table; only GPT is supported",
                              disk, table)
    logical = int(header[3])
    return [FreeRegion(disk, _value(row[1], logical), _value(row[3], logical), logical)
            for row in rows if len(row) > 4 and row[4] == "free"]


def scan_disk(r: Runner, disk: str) -> list[FreeRegion]:
    """Free regions of ``disk``, read with read-only commands."""
    out = r.run(_parted_cmd(disk), check=False, readonly=True).stdout
    header, _ = _parted_rows(out)
    signatures = None
    if len(header) > 5 and header[5] == "unknown":
        signatures = parse_wipefs(r.run(_wipefs_cmd(disk), check=False, readonly=True).stdout)
    return parse_parted_free(out, disk, signatures=signatures)


def disk_info(r: Runner, disk: str) -> DiskInfo:
    """Size, sector size, model and wipefs signatures of a disk (serial/WWN come from lsblk)."""
    out = r.run(_parted_cmd(disk), check=False, readonly=True).stdout
    header, _ = _parted_rows(out)
    logical = int(header[3])
    size = _value(header[1], logical) * logical
    sigs = tuple(parse_wipefs(r.run(_wipefs_cmd(disk), check=False, readonly=True).stdout))
    return DiskInfo(disk, size, logical, sigs, model=header[6] if len(header) > 6 and header[6] else None)


# --------------------------------------------------------------------------- estimate

def _align_up(value: int, step: int) -> int:
    return -(-value // step) * step


def estimate_min_bytes(volume: Volume, source_snapshots: bool) -> int:
    """Smallest size worth offering for the partition of ``volume``, in bytes.

    The content is the APPARENT size of the files (``volume.apparent_bytes``), not the
    blocks in use, so sparse files and compression on the source do not distort it.

        btrfs : apparent + max(256 MiB, 3 % of apparent) metadata
                (+ 16 MiB per subvolume when ``source_snapshots``: every subvolume is
                carried over as its own tree)
        other : apparent + 4 % metadata + 128 MiB journal, but never less than
                ``used_inodes`` x 16 KiB x 1.10 (the inode table of a new ext4 is sized
                by that ratio, so a volume with millions of small files needs room for
                them even when the data is small)
        total : that + margin (max(1 GiB, 5 %); max(256 MiB, 5 %) for a separate /boot)
                + 16 MiB LUKS2 header when the volume is encrypted,
                rounded up to 1 MiB.

    The ESP is not part of any volume; it is sized separately (``ESP_DEFAULT_BYTES``).
    """
    data = volume.apparent_bytes
    if volume.fs == "btrfs":
        content = data + max(BTRFS_META_MIN_BYTES, int(data * BTRFS_META_FRACTION))
        if source_snapshots and volume.btrfs is not None:
            content += len(volume.btrfs.subvolumes) * BTRFS_SUBVOL_BYTES
    else:
        content = data + int(data * EXT4_OVERHEAD_FRACTION) + EXT4_JOURNAL_BYTES
        content = max(content, int(volume.used_inodes * BYTES_PER_INODE * INODE_SLACK))
    margin_min = BOOT_MARGIN_MIN_BYTES if volume.role == "boot" else MARGIN_MIN_BYTES
    total = content + max(margin_min, int(content * MARGIN_FRACTION))
    if volume.luks is not None:
        total += LUKS2_HEADER_BYTES
    return _align_up(total, ALIGN_BYTES)


def source_snapshot_space_ok(volume: Volume) -> bool:
    """A btrfs source needs some free space to take its read-only snapshot; other
    filesystems are copied frozen and need none."""
    if volume.fs != "btrfs":
        return True
    capacity = volume.partition.size_bytes - (LUKS2_HEADER_BYTES if volume.luks else 0)
    return capacity - volume.used_bytes >= SOURCE_SNAPSHOT_MIN_FREE_BYTES


# --------------------------------------------------------------------------- identities

class _Identities:
    """Draws UUIDs from ``factory`` and never hands out the same value twice."""

    def __init__(self, factory: Callable[[], uuid.UUID]):
        self._factory = factory
        self._seen: set[str] = set()

    def _fresh(self, fmt: Callable[[uuid.UUID], str]) -> str:
        for _ in range(1000):
            value = fmt(self._factory())
            if value not in self._seen:
                self._seen.add(value)
                return value
        raise RuntimeError("cannot generate a unique identifier")

    def uuid(self) -> str:
        return self._fresh(lambda u: str(u).lower())

    def fat_id(self) -> str:
        return self._fresh(lambda u: f"{u.hex[:4]}-{u.hex[4:8]}".upper())

    def planned(self, *, encrypted: bool, fat: bool = False) -> PlannedIdentity:
        partuuid = self.uuid()
        luks_uuid = self.uuid() if encrypted else None
        return PlannedIdentity(partuuid, luks_uuid, self.fat_id() if fat else self.uuid())


# --------------------------------------------------------------------------- planning

def plan_init_gpt(info: DiskInfo) -> InitGpt | None:
    """An ``InitGpt`` only when ``wipefs`` read the disk and found no recognised signature."""
    if info.signatures is None or list(info.signatures):
        return None
    gib = info.size_bytes / GIB
    parts = [p for p in (info.model, info.serial or info.wwn or info.by_id, info.path) if p]
    identity = " ".join(parts) + f" ({gib:.1f} GiB)"
    confirmation = info.serial or info.wwn or (info.by_id or info.path).rsplit("/", 1)[-1]
    return InitGpt(info.path, identity, confirmation, info.size_bytes, info.logical_sector)


def _gpt_region(init: InitGpt) -> FreeRegion:
    """The whole usable area of a disk that will get a new GPT."""
    log = init.logical_sector
    total = init.size_bytes // log
    backup = -(-(16384 + log) // log)               # backup entries + backup header
    start = ALIGN_BYTES // log
    return FreeRegion(init.disk, start, total - backup - start, log)


class _Space:
    """First-fit allocator over the free regions, 1 MiB aligned."""

    def __init__(self, regions: Iterable[FreeRegion]):
        self.free: dict[str, list[list[int]]] = {}
        self.sector: dict[str, int] = {}
        for reg in sorted(regions, key=lambda x: (x.disk, x.start_sectors)):
            self.free.setdefault(reg.disk, []).append([reg.start_sectors,
                                                       reg.start_sectors + reg.size_sectors])
            self.sector[reg.disk] = reg.logical_sector

    def take(self, disk: str, size_bytes: int, role: str) -> tuple[int, int, int]:
        log = self.sector.get(disk, 512)
        align = ALIGN_BYTES // log
        size = _align_up(-(-size_bytes // log), align)
        largest = 0
        for reg in self.free.get(disk, []):
            start = _align_up(reg[0], align)
            largest = max(largest, (reg[1] - start) * log if reg[1] > start else 0)
            if start + size <= reg[1]:
                reg[0] = start + size
                return start, size, log
        raise InsufficientSpace(disk, size_bytes, largest, role)


def _swap_bytes(swap: SwapRef) -> int:
    return swap.size_bytes + (LUKS2_HEADER_BYTES if swap.luks is not None else 0)


def plan_layout(source: Source, targets: list[VolumeTarget], esp: EspChoice,
                regions: list[FreeRegion], *, init_gpt: Iterable[InitGpt] = (),
                approved_tables: dict[str, str] | None = None,
                uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4) -> MigrationPlan:
    """Place the ESP (when new), every volume and every swap partition, first-fit.

    ``regions`` are the free areas of the destination disks; disks listed in ``init_gpt``
    contribute their whole usable area. Order: ESP, volumes in the order of ``targets``,
    swap partitions (on the disk of the root volume). Raises ``TargetTooSmall`` when a
    chosen size is below the estimate, ``InsufficientSpace`` when something does not fit.
    ``approved_tables`` (see ``fingerprint_tables``) is stored in the plan.
    """
    init = list(init_gpt)
    space = _Space(list(regions) + [_gpt_region(i) for i in init])
    ids = _Identities(uuid_factory)
    partitions: list[Partplan] = []
    swaps: list[Partplan] = []

    if esp.mode == "new":
        start, size, log = space.take(esp.disk, esp.size_bytes, "esp")
        partitions.append(Partplan(esp.disk, start, size, "esp", ids.planned(encrypted=False, fat=True),
                                   "esp", log))
    for t in targets:
        minimum = estimate_min_bytes(t.volume, t.volume.btrfs is not None)
        if t.size_bytes < minimum:
            raise TargetTooSmall(t.volume.volume_id, t.size_bytes, minimum)
        start, size, log = space.take(t.disk, t.size_bytes, t.volume.role)
        partitions.append(Partplan(t.disk, start, size, t.volume.role,
                                   ids.planned(encrypted=t.volume.luks is not None),
                                   t.volume.volume_id, log))
    if targets:
        swap_disk = next((t.disk for t in targets if t.volume.role == "root"), targets[0].disk)
        for sw in source.swaps:
            if sw.kind != "partition":
                continue
            start, size, log = space.take(swap_disk, _swap_bytes(sw), "swap")
            swaps.append(Partplan(swap_disk, start, size, "swap",
                                  ids.planned(encrypted=sw.luks is not None), sw.volume_id, log))
    return MigrationPlan(list(targets), esp, partitions, swaps, dict(approved_tables or {}), init)


# --------------------------------------------------------------------------- stale plan

def _fingerprint(r: Runner, disk: str) -> str:
    table = r.run(_sfdisk_cmd(disk), check=False, readonly=True).stdout
    sigs = r.run(_wipefs_cmd(disk), check=False, readonly=True).stdout
    blob = f"table\n{table}\nsignatures\n{sigs}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def fingerprint_tables(r: Runner, disks: Iterable[str]) -> dict[str, str]:
    """A stable hash of the partition table dump and signatures of each disk."""
    return {d: _fingerprint(r, d) for d in disks}


def assert_tables_unchanged(r: Runner, plan: MigrationPlan) -> None:
    """Read every approved destination disk again; ``TablesChanged`` if any differs."""
    changed = [d for d, fp in plan.approved_tables.items() if _fingerprint(r, d) != fp]
    if changed:
        raise TablesChanged(changed)


# --------------------------------------------------------------------------- free space

class SpaceWatch:
    """Keeps an eye on the free space of the source while a copy runs."""

    def __init__(self, r: Runner, mountpoint: str, threshold_bytes: int | None = None):
        self.r, self.mountpoint, self.threshold_bytes = r, mountpoint, threshold_bytes

    def _read(self) -> tuple[int, int]:
        out = self.r.run(["stat", "-f", "-c", "%S %b %a", self.mountpoint], readonly=True).stdout
        block, total, avail = (int(x) for x in out.split())
        return total * block, avail * block

    def check(self) -> None:
        """Raise ``SourceSpaceLow`` when the free space is below the threshold
        (default: the larger of 2 GiB and 5 % of the filesystem)."""
        total, free = self._read()
        threshold = self.threshold_bytes
        if threshold is None:
            threshold = max(SPACE_WATCH_MIN_BYTES, int(total * SPACE_WATCH_FRACTION))
        if free < threshold:
            raise SourceSpaceLow(self.mountpoint, free, threshold)
