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
from pathlib import Path
from typing import Callable, Iterable, Literal

from .model import PlannedIdentity, Source, SwapRef, Volume
from .probe import _disk_links
from .runner import Runner

__all__ = [
    "ALIGN_BYTES", "ESP_DEFAULT_BYTES", "LUKS2_HEADER_BYTES", "BYTES_PER_INODE",
    "BTRFS_META_MIN_BYTES", "BOOT_MARGIN_MIN_BYTES", "FreeRegion", "DiskInfo", "NoTable",
    "UnsupportedDisk", "InsufficientSpace", "TargetTooSmall", "TablesChanged", "SourceSpaceLow",
    "DiskReadError", "TablesNotApproved", "space_threshold_bytes", "init_gpt_blocker",
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
BTRFS_META_PER_INODE = 2048             # metadata per file on btrfs (inode, reference, directory
                                        # entries, extent item, leaf slack), deliberately generous
BTRFS_DUP_FACTOR = 2                    # single-device mkfs keeps metadata twice (DUP profile)
BTRFS_SUBVOL_BYTES = 16 * MIB           # extra metadata per subvolume carried over as a snapshot
EXT4_OVERHEAD_FRACTION = 0.04           # inode tables, bitmaps and reserved metadata
EXT4_JOURNAL_BYTES = 128 * MIB
BYTES_PER_INODE = 16384                 # mke2fs default ratio: one inode per 16 KiB of space
INODE_SLACK = 1.10                      # headroom on the inode count of the source

SPACE_WATCH_MIN_BYTES = 2 * GIB         # free-space floor of the source: at least 2 GiB ...
SPACE_WATCH_FRACTION = 0.05             # ... or 5 % of the filesystem, whichever is larger

# Why a disk may not be initialised (see init_gpt_blocker)
BLOCK_SIGNATURES = "signatures_found"
BLOCK_UNKNOWN = "signatures_unknown"
BLOCK_NO_IDENTITY = "no_hardware_identity"


# --------------------------------------------------------------------------- exceptions

class UnsupportedDisk(Exception):
    """The partition table cannot be handled (only GPT is supported)."""

    def __init__(self, message: str, disk: str = "", table: str = ""):
        super().__init__(message)
        self.disk, self.table = disk, table


class NoTable(Exception):
    """The disk has no partition table. ``can_init`` is true only when ``wipefs`` also
    reports no recognised signature at all."""

    def __init__(self, disk: str, can_init: bool, reason: str | None = None):
        super().__init__(f"{disk} has no partition table")
        self.disk, self.can_init = disk, can_init
        self.reason = reason            # why not initialisable: BLOCK_SIGNATURES or BLOCK_UNKNOWN


class DiskReadError(Exception):
    """A read-only command on a disk failed; what it would have said is not known."""

    def __init__(self, disk: str, command: str, detail: str = ""):
        super().__init__(f"cannot read {disk} ({command})" + (f": {detail}" if detail else ""))
        self.disk, self.command, self.detail = disk, command, detail


class TablesNotApproved(ValueError):
    """A destination disk has no approved table fingerprint, so a change could not be seen."""

    def __init__(self, disks: list[str]):
        super().__init__("no approved table fingerprint for: " + ", ".join(disks))
        self.disks = list(disks)


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
        if signatures is None:
            raise NoTable(disk, False, BLOCK_UNKNOWN)
        found = list(signatures)
        raise NoTable(disk, not found, BLOCK_SIGNATURES if found else None)
    if table != "gpt":
        raise UnsupportedDisk(f"{disk} uses a {table or 'unknown'} partition table; only GPT is supported",
                              disk, table)
    logical = int(header[3])
    return [FreeRegion(disk, _value(row[1], logical), _value(row[3], logical), logical)
            for row in rows if len(row) > 4 and row[4] == "free"]


def _read_signatures(r: Runner, disk: str) -> list[str] | None:
    """wipefs signature types of ``disk``; ``None`` when wipefs failed or printed nonsense
    (unknown is never the same as clean)."""
    proc = r.run(_wipefs_cmd(disk), check=False, readonly=True)
    if proc.returncode != 0:
        return None
    try:
        return parse_wipefs(proc.stdout)
    except (ValueError, AttributeError):
        return None


def scan_disk(r: Runner, disk: str) -> list[FreeRegion]:
    """Free regions of ``disk``, read with read-only commands.

    ``DiskReadError`` when parted fails on a disk that has a table or prints nothing.
    """
    proc = r.run(_parted_cmd(disk), check=False, readonly=True)
    try:
        header, _ = _parted_rows(proc.stdout)
    except UnsupportedDisk:
        raise DiskReadError(disk, "parted", proc.stderr.strip()) from None
    table = header[5] if len(header) > 5 else ""
    signatures = None
    if table == "unknown":
        signatures = _read_signatures(r, disk)
    elif proc.returncode != 0:
        raise DiskReadError(disk, "parted", proc.stderr.strip())
    return parse_parted_free(proc.stdout, disk, signatures=signatures)


LSBLK_DISK = ["lsblk", "--json", "--bytes", "--nodeps", "--output",
              "NAME,KNAME,PATH,SIZE,LOG-SEC,SERIAL,WWN,MODEL"]


def disk_info(r: Runner, disk: str, root: Path = Path("/")) -> DiskInfo:
    """Size, sector size, model, serial, WWN, by-id link and wipefs signatures of a disk.

    ``signatures`` is ``None`` when wipefs failed. ``DiskReadError`` when lsblk fails.
    """
    proc = r.run(LSBLK_DISK + [disk], check=False, readonly=True)
    try:
        row = json.loads(proc.stdout)["blockdevices"][0]
        if proc.returncode != 0:
            raise ValueError
        size, log = int(row["size"]), int(row.get("log-sec") or 512)
    except (ValueError, KeyError, IndexError, TypeError):
        raise DiskReadError(disk, "lsblk", proc.stderr.strip()) from None
    clean = lambda v: (str(v).strip() or None) if v is not None else None   # noqa: E731
    sigs = _read_signatures(r, disk)
    return DiskInfo(disk, size, log, None if sigs is None else tuple(sigs),
                    serial=clean(row.get("serial")), wwn=clean(row.get("wwn")),
                    by_id=_disk_links(root).get(row.get("kname") or ""), model=clean(row.get("model")))


# --------------------------------------------------------------------------- estimate

def _align_up(value: int, step: int) -> int:
    return -(-value // step) * step


def estimate_min_bytes(volume: Volume, source_snapshots: bool) -> int:
    """Smallest size worth offering for the partition of ``volume``, in bytes.

    The content is the APPARENT size of the files (``volume.apparent_bytes``), not the
    blocks in use, so sparse files and compression on the source do not distort it.

        btrfs : apparent + metadata, the largest of 256 MiB, 3 % of apparent and
                ``used_inodes`` x 2 KiB x 2 (DUP metadata) x 1.10
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
        inode_meta = int(volume.used_inodes * BTRFS_META_PER_INODE * BTRFS_DUP_FACTOR * INODE_SLACK)
        content = data + max(BTRFS_META_MIN_BYTES, int(data * BTRFS_META_FRACTION), inode_meta)
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


def space_threshold_bytes(filesystem_bytes: int) -> int:
    """Free space the source must keep: the larger of 2 GiB and 5 % of the filesystem.

    One rule for the snapshot pre-check and for ``SpaceWatch``, so a source that passes the
    first is not stopped by the second at once.
    """
    return max(SPACE_WATCH_MIN_BYTES, int(filesystem_bytes * SPACE_WATCH_FRACTION))


def source_snapshot_space_ok(volume: Volume) -> bool:
    """A btrfs source needs at least ``space_threshold_bytes`` free to take its read-only
    snapshot and survive the copy; other filesystems are copied frozen and need none."""
    if volume.fs != "btrfs":
        return True
    capacity = volume.partition.size_bytes - (LUKS2_HEADER_BYTES if volume.luks else 0)
    return capacity - volume.used_bytes >= space_threshold_bytes(capacity)


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

def init_gpt_blocker(info: DiskInfo) -> str | None:
    """Why ``info`` may not be initialised (a stable code the GUI can show), or ``None``.

    BLOCK_UNKNOWN: wipefs could not be read; BLOCK_SIGNATURES: a recognised signature is
    present; BLOCK_NO_IDENTITY: no serial, WWN or by-id name to tie the typed confirmation to.
    """
    if info.signatures is None:
        return BLOCK_UNKNOWN
    if list(info.signatures):
        return BLOCK_SIGNATURES
    if not _confirmation(info):
        return BLOCK_NO_IDENTITY
    return None


def _confirmation(info: DiskInfo) -> str | None:
    """Hardware identity to type: serial, WWN or by-id name; never the kernel name."""
    if info.serial:
        return info.serial
    if info.wwn:
        return info.wwn
    if info.by_id:
        return info.by_id.rsplit("/", 1)[-1]
    return None


def plan_init_gpt(info: DiskInfo) -> InitGpt | None:
    """An ``InitGpt`` only when ``wipefs`` read the disk, found no recognised signature and
    the disk has a hardware identity; otherwise ``None`` (see ``init_gpt_blocker``)."""
    if init_gpt_blocker(info) is not None:
        return None
    gib = info.size_bytes / GIB
    parts = [p for p in (info.model, info.serial or info.wwn or info.by_id, info.path) if p]
    identity = " ".join(parts) + f" ({gib:.1f} GiB)"
    return InitGpt(info.path, identity, _confirmation(info) or "", info.size_bytes, info.logical_sector)


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
    ``approved_tables`` (see ``fingerprint_tables``) is stored in the plan and must hold a
    fingerprint for every disk something is created on (``TablesNotApproved`` otherwise).
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
    plan = MigrationPlan(list(targets), esp, partitions, swaps, dict(approved_tables or {}), init)
    missing = _unapproved(plan)
    if missing:
        raise TablesNotApproved(missing)
    return plan


# --------------------------------------------------------------------------- stale plan

_TABLE_SIGNATURES = {"gpt", "PMBR", "dos"}


def _fingerprint(r: Runner, disk: str) -> str:
    """Hash of the sfdisk dump and the wipefs signatures. A failed read raises
    ``DiskReadError``; only a disk wipefs reports as having no table may have a failing
    sfdisk (it has nothing to dump)."""
    wipe = r.run(_wipefs_cmd(disk), check=False, readonly=True)
    if wipe.returncode != 0:
        raise DiskReadError(disk, "wipefs", wipe.stderr.strip())
    try:
        types = set(parse_wipefs(wipe.stdout))
    except ValueError:
        raise DiskReadError(disk, "wipefs", "unreadable output") from None
    dump = r.run(_sfdisk_cmd(disk), check=False, readonly=True)
    if dump.returncode != 0 and types & _TABLE_SIGNATURES:
        raise DiskReadError(disk, "sfdisk", dump.stderr.strip())
    table = dump.stdout if dump.returncode == 0 else ""
    blob = f"table\n{table}\nsignatures\n{wipe.stdout}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def fingerprint_tables(r: Runner, disks: Iterable[str]) -> dict[str, str]:
    """A stable hash of the partition table dump and signatures of each disk
    (``DiskReadError`` if a disk cannot be read)."""
    return {d: _fingerprint(r, d) for d in disks}


def plan_disks(plan: MigrationPlan) -> list[str]:
    """Every disk the plan creates something on."""
    disks = [p.disk for p in plan.partitions] + [p.disk for p in plan.swaps]
    disks += [i.disk for i in plan.init_gpt]
    return sorted(set(disks))


def _unapproved(plan: MigrationPlan) -> list[str]:
    return [d for d in plan_disks(plan) if not plan.approved_tables.get(d)]


def assert_tables_unchanged(r: Runner, plan: MigrationPlan) -> None:
    """Read every destination disk again; ``TablesChanged`` if any differs.

    Fails closed: ``TablesNotApproved`` when a destination disk of the plan has no approved
    fingerprint, ``DiskReadError`` when a disk cannot be read.
    """
    missing = _unapproved(plan)
    if missing:
        raise TablesNotApproved(missing)
    disks = sorted(set(plan.approved_tables) | set(plan_disks(plan)))
    changed = [d for d in disks if _fingerprint(r, d) != plan.approved_tables[d]]
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
            threshold = space_threshold_bytes(total)
        if free < threshold:
            raise SourceSpaceLow(self.mountpoint, free, threshold)
