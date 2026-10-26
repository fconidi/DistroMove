"""Fail-closed guards for removing volumes of a previously booted system."""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
from typing import Callable

from .config_rewrite import find_old_uuids
from .model import SystemSnapshot, VolumeIdentity
from .probe_parse import loader_of
from .state import MigrationState


@dataclass(frozen=True)
class DeleteDecision:
    ok: bool
    reasons: list[str]


def partuuid_key(volume: VolumeIdentity) -> str:
    """Case-folded PARTUUID of a live partition; an unreadable one is an error, never absence."""
    value = volume.partuuid
    if not isinstance(value, str) or not value.strip():
        where = volume.disk_by_id or volume.disk_wwn or volume.disk_serial or "unknown disk"
        raise ValueError(f"partition identity unreadable (start sector {volume.start_sectors} "
                         f"on {where})")
    return value.casefold()


def _same(expected: VolumeIdentity, actual: VolumeIdentity,
          *, erased_luks: bool = False) -> bool:
    for key in ("partuuid", "disk_wwn", "disk_serial", "disk_by_id",
                "start_sectors", "size_sectors"):
        a, b = getattr(expected, key), getattr(actual, key)
        if isinstance(a, str) and isinstance(b, str):
            if a.casefold() != b.casefold():
                return False
        elif a != b:
            return False
    for key in ("luks_uuid", "fs_uuid"):
        a, b = getattr(expected, key), getattr(actual, key)
        if erased_luks and expected.luks_uuid and b is None:
            continue
        if (a or "").casefold() != (b or "").casefold():
            return False
    return True


def _identity_key(value: VolumeIdentity) -> tuple[str | None, str | None, str | None]:
    return value.disk_wwn, value.disk_serial, value.disk_by_id


def _references_old(live: SystemSnapshot, old: list[VolumeIdentity],
                    new: list[VolumeIdentity],
                    resolve: Callable[[str], str]) -> list[str]:
    aliases = set()
    luks_ids = set()
    for volume in old:
        for value in (volume.partuuid, volume.fs_uuid, volume.luks_uuid):
            if value:
                aliases.add(value)
        path = f"/dev/disk/by-partuuid/{volume.partuuid}"
        aliases.add(path)
        aliases.add(resolve(path))
        if volume.fs_uuid:
            aliases.add(f"/dev/disk/by-uuid/{volume.fs_uuid}")
        if volume.luks_uuid:
            luks_ids.add(volume.luks_uuid.replace("-", "").casefold())
    reasons = []
    for name, text in (("fstab", live.fstab), ("crypttab", live.crypttab)):
        if find_old_uuids({name: text}, aliases, {}):
            reasons.append(f"{name} references an old volume")
    for mount in live.mounts:
        source = mount.source
        if any(value and (value.casefold() in source.casefold()
                          or resolve(source).casefold() == value.casefold()) for value in aliases):
            reasons.append(f"mounted old volume at {mount.target}")
    for mapper in live.mappers:
        parts = mapper.split(maxsplit=1)
        if len(parts) != 2 and luks_ids:
            reasons.append("device-mapper identity is unknown")
        elif len(parts) == 2 and any(value in parts[1].casefold() for value in luks_ids):
            reasons.append("old LUKS mapper is active")
    if luks_ids:
        new_luks = {item.luks_uuid.replace("-", "").casefold() for item in new
                    if item.luks_uuid}
        observed = {parts[0]: parts[1].casefold() for item in live.mappers
                    if len(parts := item.split(maxsplit=1)) == 2}
        references = "\n".join([live.fstab, live.crypttab,
                                *(mount.source for mount in live.mounts),
                                *(swap.path for swap in live.swaps)])
        for name in set(re.findall(r"/dev/mapper/([A-Za-z0-9_.+-]+)", references)):
            identity = observed.get(name, "")
            if not any(value in identity for value in new_luks):
                reasons.append(f"mapper {name} is not proven to belong to a new volume")
    for swap in live.swaps:
        text = " ".join(value for value in (swap.path, swap.uuid,
                                              swap.luks.luks_uuid if swap.luks else None)
                        if value)
        if any(value and value.casefold() in text.casefold() for value in aliases):
            reasons.append(f"old swap is active: {swap.path}")
    return reasons


def _esp_reasons(state: MigrationState, live: SystemSnapshot) -> list[str]:
    old = state.old_esp.partuuid.casefold()
    if old == state.new_esp.partuuid.casefold():
        return ["old ESP is the active new ESP"]
    if f"old_esp:{old}" in {item.casefold() for item in state.deletion_done}:
        return []
    reasons = []
    matches = [names for partuuid, names in live.esp_contents.items()
               if partuuid.casefold() == old]
    if len(matches) != 1:
        reasons.append("old ESP contents are unavailable or ambiguous")
    elif any(name.casefold() != state.bootloader_id_old.casefold() for name in matches[0]):
        reasons.append("old ESP contains foreign EFI directories")
    for mount in live.mounts:
        if old in mount.source.casefold() or (state.old_esp.fs_uuid and
                                              state.old_esp.fs_uuid.casefold() in
                                              mount.source.casefold()):
            reasons.append("old ESP is mounted by the new system")
    for number, line in live.boot_entries.items():
        match = re.search(r"HD\(\d+,GPT,([0-9A-Fa-f-]{36}),", line, re.I)
        if match is None or match[1].casefold() != old:
            continue
        target = loader_of(line)
        path = target[1].replace("/", "\\").casefold() if target else ""
        own = path.startswith(f"\\efi\\{state.bootloader_id_old.casefold()}\\")
        if number.upper() == (live.boot_current or "").upper() or not own:
            reasons.append("firmware uses old ESP for another entry")
    return reasons


def can_delete_old(state: MigrationState, live: SystemSnapshot, *,
                   delete_old_esp: bool = False,
                   resolve: Callable[[str], str] = os.path.realpath) -> DeleteDecision:
    reasons = []
    if not state.verified or state.phase not in {"ACTIVATED", "DELETING"}:
        reasons.append("migration is not verified and activated")
    if state.new_root_uuid.casefold() != live.running_root_uuid.casefold():
        reasons.append("running root is not the migrated root")
    if state.uefi_entry and (live.boot_current or "").upper() != state.uefi_entry.upper():
        reasons.append("firmware did not boot the new entry")
    if state.phase == "ACTIVATED" and state.deletion_done:
        reasons.append("deletion progress exists outside DELETING phase")
    expected = [*state.old_volumes, *state.new_volumes, state.old_esp, state.new_esp]
    for old in state.old_volumes:
        for new in [*state.new_volumes, state.new_esp]:
            same_disk = any(a and b and a.casefold() == b.casefold()
                            for a, b in zip(_identity_key(old), _identity_key(new)))
            if same_disk and max(old.start_sectors, new.start_sectors) < min(
                    old.start_sectors + old.size_sectors,
                    new.start_sectors + new.size_sectors):
                reasons.append(f"{old.volume_id}: old and new partitions overlap")
    seen = {}
    for volume in live.identities:
        try:
            seen.setdefault(partuuid_key(volume), []).append(volume)
        except ValueError as exc:
            reasons.append(str(exc))
    for volume in expected:
        if not any(_identity_key(volume)):
            reasons.append(f"{volume.volume_id}: disk has no stable identity")
        matches = seen.get(volume.partuuid.casefold(), [])
        done_partition = f"partition:{volume.partuuid.casefold()}" in {
            item.casefold() for item in state.deletion_done}
        done_esp = f"old_esp:{volume.partuuid.casefold()}" in {
            item.casefold() for item in state.deletion_done}
        if volume in state.old_volumes and done_partition and state.phase == "DELETING":
            if matches:
                reasons.append(f"{volume.volume_id}: partition marked removed still exists")
            continue
        if volume == state.old_esp and done_esp and state.phase == "DELETING":
            if matches:
                reasons.append("old ESP marked removed still exists")
            continue
        erased = (state.phase == "DELETING" and volume in state.old_volumes and
                  f"luks:{volume.partuuid.casefold()}" in {
                      item.casefold() for item in state.deletion_done})
        if len(matches) != 1 or not _same(volume, matches[0], erased_luks=erased):
            reasons.append(f"{volume.volume_id}: partition identity changed or disappeared")
    remaining = [volume for volume in state.old_volumes
                 if f"partition:{volume.partuuid.casefold()}" not in {
                     item.casefold() for item in state.deletion_done}]
    reasons.extend(_references_old(live, remaining, state.new_volumes, resolve))
    if delete_old_esp:
        reasons.extend(_esp_reasons(state, live))
    return DeleteDecision(not reasons, reasons)


def confirmation_text(state: MigrationState, *, delete_old_esp: bool = False,
                      erase_luks_header: bool = False) -> str:
    """List every old partition and its stable identity for typed approval."""
    lines = [f"Delete old system for migration {state.migration_id}:"]
    volumes = [*state.old_volumes, *([state.old_esp] if delete_old_esp else [])]
    for volume in volumes:
        lines.append(f"{volume.role} {volume.partuuid} "
                     f"disk={volume.disk_wwn or volume.disk_serial or volume.disk_by_id or 'unknown'} "
                     f"start={volume.start_sectors} size={volume.size_sectors}")
    if erase_luks_header:
        lines.append("Erase all keyslots on old LUKS volumes")
    return "\n".join(lines)
