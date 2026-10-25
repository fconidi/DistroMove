"""Preflight and creation of destination storage.

All mutating commands in this module must follow a durable journal intent.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Literal

from .journal import Journal
from .layout import MigrationPlan, Partplan, assert_tables_unchanged
from .model import CreatedPartition, Keyslot, LuksInfo, Source
from .probe import classify_keys
from .runner import Runner


class UnsupportedKdf(ValueError):
    """A source keyslot or boot-time decryption mode cannot be recreated."""


class UnsafeKeyfile(ValueError):
    """A key needed in an unencrypted initramfs would leak its secret."""


class KernelTableStale(RuntimeError):
    """The partition table or the kernel view differs from the approved result."""


@dataclass(frozen=True)
class GrubCaps:
    luks_versions: frozenset[int]
    kdfs: frozenset[str]
    ciphers: frozenset[str]


@dataclass(frozen=True)
class CryptoPlan:
    per_volume: dict[str, list[Keyslot]]
    keyfiles: dict[str, str]
    boot_in_luks: dict[str, bool]
    key_class: dict[str, Literal["initramfs", "after-root"]]
    luks_by_volume: dict[str, LuksInfo]


def validate_crypto_plan(source: Source, grub_caps: GrubCaps) -> CryptoPlan:
    """Select a KDF for each new container before any destination write.

    GRUB can open LUKS2 only through PBKDF2. Its installed capabilities are
    supplied by the caller rather than assumed from a version string.
    """
    boot = next((v for v in source.volumes if v.role == "boot"), None)
    root = next((v for v in source.volumes if v.role == "root"), None)
    boot_encrypted = ((boot.luks is not None) if boot is not None else
                      (root is not None and root.luks is not None))
    classes = classify_keys(source)
    if not boot_encrypted and any(value == "initramfs" for value in classes.values()):
        raise UnsafeKeyfile("an initramfs keyfile would be exposed on unencrypted /boot")

    per_volume: dict[str, list[Keyslot]] = {}
    keyfiles: dict[str, str] = {}
    boot_flags: dict[str, bool] = {}
    luks_by_volume: dict[str, LuksInfo] = {}
    for item in [*source.volumes, *source.swaps]:
        luks = item.luks
        if luks is None:
            continue
        volume_id = item.volume_id
        if volume_id in per_volume:
            raise ValueError(f"duplicate encrypted volume id: {volume_id}")
        if luks.version not in (1, 2):
            raise UnsupportedKdf(f"{volume_id}: unsupported LUKS version")
        candidates = [slot for slot in luks.keyslots
                      if slot.kdf in {"pbkdf2", "argon2i", "argon2id"}]
        if not candidates:
            raise UnsupportedKdf(f"{volume_id}: no supported source keyslot")
        role = getattr(item, "role", "swap")
        needs_grub = ((role == "boot" or (role == "root" and boot is None))
                      and boot_encrypted)
        if needs_grub:
            if luks.version not in grub_caps.luks_versions or luks.cipher not in grub_caps.ciphers:
                raise UnsupportedKdf(f"{volume_id}: GRUB cannot read this LUKS container")
            selected = next((slot for slot in candidates
                             if slot.kdf == "pbkdf2" and slot.kdf in grub_caps.kdfs), None)
            if selected is None:
                raise UnsupportedKdf(f"{volume_id}: GRUB requires a PBKDF2 keyslot")
        else:
            selected = candidates[0]
        if luks.version == 1 and selected.kdf != "pbkdf2":
            raise UnsupportedKdf(f"{volume_id}: LUKS1 requires PBKDF2")
        per_volume[volume_id] = [selected]
        luks_by_volume[volume_id] = luks
        boot_flags[volume_id] = bool(needs_grub)
        if luks.keyfile:
            keyfiles[volume_id] = luks.keyfile
    return CryptoPlan(per_volume, keyfiles, boot_flags, classes, luks_by_volume)


_LINUX = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
_LUKS = "CA7D7CCB-63ED-4C53-861C-1742536059CC"
_ESP = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
_SWAP = "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F"
_LSBLK = ["lsblk", "--json", "--bytes", "--list", "--output",
          "PATH,TYPE,PARTUUID,START,SIZE"]


def _part_type(part: Partplan) -> str:
    if part.role == "esp":
        return _ESP
    if part.planned.luks_uuid:
        return _LUKS
    if part.role == "swap":
        return _SWAP
    return _LINUX


def _table(r: Runner, disk: str) -> tuple[int, list[dict]]:
    proc = r.run(["sfdisk", "--json", disk], readonly=True)
    try:
        table = json.loads(proc.stdout)["partitiontable"]
        if table["label"].lower() != "gpt" or table["device"] != disk:
            raise ValueError
        sector = int(table["sectorsize"])
        rows = table["partitions"]
        if sector not in (512, 1024, 2048, 4096) or not isinstance(rows, list):
            raise ValueError
        if any(not isinstance(row, dict) or not row.get("node") or not row.get("uuid")
               or int(row["start"]) < 0 or int(row["size"]) <= 0 for row in rows):
            raise ValueError
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        raise KernelTableStale(f"cannot read a valid GPT table on {disk}") from exc
    return sector, rows


def _kernel(r: Runner, disk: str) -> dict[str, tuple[str, int, int]]:
    proc = r.run(_LSBLK + [disk], readonly=True)
    try:
        rows = json.loads(proc.stdout)["blockdevices"]
        parts = [row for row in rows if row.get("type") == "part"]
        found = {row["path"]: (str(row["partuuid"]).casefold(),
                               int(row["start"]), int(row["size"])) for row in parts}
        if len(found) != len(parts):
            raise ValueError
    except (ValueError, TypeError, KeyError) as exc:
        raise KernelTableStale(f"cannot read kernel partitions of {disk}") from exc
    return found


def _expected_kernel(rows: list[dict], sector: int) -> dict[str, tuple[str, int, int]]:
    expected = {}
    for row in rows:
        start_bytes = int(row["start"]) * sector
        if start_bytes % 512:
            raise KernelTableStale("partition start is not representable in kernel sectors")
        expected[row["node"]] = (str(row["uuid"]).casefold(), start_bytes // 512,
                                 int(row["size"]) * sector)
    if len(expected) != len(rows):
        raise KernelTableStale("duplicate partition node in table")
    return expected


def _check_plan(parts: list[Partplan], previous: list[dict], sector: int) -> None:
    occupied = [(int(row["start"]), int(row["start"]) + int(row["size"]))
                for row in previous]
    uuids = {str(row["uuid"]).casefold() for row in previous}
    volume_ids: set[str] = set()
    for part in parts:
        if part.logical_sector != sector or part.start_sectors < 0 or part.size_sectors <= 0:
            raise ValueError("planned partition has invalid sector geometry")
        if not part.volume_id or part.volume_id in volume_ids:
            raise ValueError("planned partitions need unique volume IDs")
        if not part.planned.partuuid or part.planned.partuuid.casefold() in uuids:
            raise ValueError("planned PARTUUID is empty or already present")
        if not part.planned.fs_uuid:
            raise ValueError("planned filesystem UUID is empty")
        a, b = part.start_sectors, part.start_sectors + part.size_sectors
        if any(a < stop and start < b for start, stop in occupied):
            raise ValueError("planned partition overlaps an existing or planned partition")
        occupied.append((a, b))
        uuids.add(part.planned.partuuid.casefold())
        volume_ids.add(part.volume_id)


def _script(parts: list[Partplan]) -> bytes:
    lines = ["unit: sectors"]
    for part in parts:
        lines.append(f"start={part.start_sectors},size={part.size_sectors},"
                     f"type={_part_type(part)},uuid={part.planned.partuuid}")
    return ("\n".join(lines) + "\n").encode("ascii")


def _verify_result(before: list[dict], after: list[dict], parts: list[Partplan],
                   disk: str) -> dict[str, dict]:
    old = {str(row["uuid"]).casefold(): row for row in before}
    new = {str(row["uuid"]).casefold(): row for row in after}
    if len(old) != len(before) or len(new) != len(after):
        raise KernelTableStale(f"duplicate PARTUUID on {disk}")
    if any(new.get(key) != row for key, row in old.items()):
        raise KernelTableStale(f"pre-existing partition changed on {disk}")
    planned = {part.planned.partuuid.casefold(): part for part in parts}
    if set(new) != set(old) | set(planned):
        raise KernelTableStale(f"unexpected partition set on {disk}")
    for key, part in planned.items():
        row = new[key]
        if (int(row["start"]) != part.start_sectors or
                int(row["size"]) != part.size_sectors or
                str(row.get("type", "")).casefold() != _part_type(part).casefold()):
            raise KernelTableStale(f"planned partition differs on {disk}")
    return {part.volume_id: new[part.planned.partuuid.casefold()] for part in parts}


def create_partitions(r: Runner, plan: MigrationPlan,
                      journal: Journal) -> dict[str, CreatedPartition]:
    """Append only approved GPT partitions, then prove disk and kernel state.

    sfdisk's named start/size values are native logical sectors, while lsblk's
    START column is always 512-byte sectors. Both are compared in bytes.
    """
    if plan.init_gpt:
        raise ValueError("initialise GPT separately, then rebuild and approve the layout")
    assert_tables_unchanged(r, plan)
    created: dict[str, CreatedPartition] = {}
    for disk in sorted({part.disk for part in [*plan.partitions, *plan.swaps]}):
        parts = [part for part in [*plan.partitions, *plan.swaps] if part.disk == disk]
        sector, before = _table(r, disk)
        _check_plan(parts, before, sector)
        if _kernel(r, disk) != _expected_kernel(before, sector):
            raise KernelTableStale(f"kernel partition view was stale before writing {disk}")
        intents = []
        for part in parts:
            identity = {"partuuid": part.planned.partuuid,
                        "start_sectors": part.start_sectors,
                        "size_sectors": part.size_sectors,
                        "luks_uuid": part.planned.luks_uuid,
                        "fs_uuid": part.planned.fs_uuid}
            intents.append(journal.intend("create_partition", identity,
                                          creates="partition", disk=disk,
                                          volume_id=part.volume_id))
        r.run(["sfdisk", "--append", "--lock", disk], input=_script(parts))
        r.run(["partprobe", disk])
        r.run(["udevadm", "settle"])
        after_sector, after = _table(r, disk)
        if after_sector != sector:
            raise KernelTableStale(f"logical sector size changed on {disk}")
        rows = _verify_result(before, after, parts, disk)
        if _kernel(r, disk) != _expected_kernel(after, sector):
            raise KernelTableStale(f"kernel partition view did not match disk on {disk}")
        for part, op_id in zip(parts, intents):
            row = rows[part.volume_id]
            created[part.volume_id] = CreatedPartition(
                part.volume_id, row["node"], part.planned.partuuid,
                part.start_sectors, part.size_sectors,
                part.planned.luks_uuid, part.planned.fs_uuid)
            journal.done(op_id, "created", path=row["node"])
    return created
