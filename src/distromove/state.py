"""Durable migration state bound to the filesystem UUID of the running root."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import stat

from .journal import link_atomic, make_dirs, write_atomic
from .model import VolumeIdentity


STATE_VERSION = 1
STATE_LINK = "state-current"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_BOOTNUM = re.compile(r"[0-9A-Fa-f]{4}\Z")


@dataclass(frozen=True)
class MigrationState:
    version: int
    migration_id: str
    phase: str
    new_root_uuid: str
    old_volumes: list[VolumeIdentity]
    new_volumes: list[VolumeIdentity]
    old_esp: VolumeIdentity
    new_esp: VolumeIdentity
    bootloader_id_new: str
    bootloader_id_old: str
    uefi_entry: str | None
    verified: bool
    deletion_done: list[str]


def _validate(state: MigrationState) -> None:
    if (state.version != STATE_VERSION or not _ID.fullmatch(state.migration_id)
            or state.phase not in {"PREPARED", "PENDING_ACTIVATION", "ACTIVATED",
                                   "DELETING", "DELETED"}
            or not state.new_root_uuid or not state.old_volumes or not state.new_volumes
            or not isinstance(state.old_esp, VolumeIdentity)
            or not isinstance(state.new_esp, VolumeIdentity)
            or state.old_esp.role != "esp" or state.new_esp.role != "esp"
            or not state.bootloader_id_new or not state.bootloader_id_old
            or state.bootloader_id_new.casefold() == state.bootloader_id_old.casefold()
            or (state.uefi_entry is not None and not _BOOTNUM.fullmatch(state.uefi_entry))
            or (state.phase in {"ACTIVATED", "DELETING", "DELETED"}
                and state.uefi_entry is None)
            or len(set(state.deletion_done)) != len(state.deletion_done)):
        raise ValueError("invalid migration state")
    old_roots = [item for item in state.old_volumes if item.role == "root"]
    roots = [item for item in state.new_volumes if item.role == "root"]
    volume_ids = [item.partuuid.casefold() for item in [*state.old_volumes,
                   *state.new_volumes, state.old_esp, state.new_esp]]
    shared_esp = state.old_esp.partuuid.casefold() == state.new_esp.partuuid.casefold()
    if (len(old_roots) != 1 or len(roots) != 1
            or (roots[0].fs_uuid or "").casefold() != state.new_root_uuid.casefold()
            or (old_roots[0].fs_uuid or "").casefold() == state.new_root_uuid.casefold()
            or any(item.role == "esp" for item in [*state.old_volumes, *state.new_volumes])
            or len(set(volume_ids)) != len(volume_ids) - int(shared_esp)):
        raise ValueError("state root identity is inconsistent")


def _directory(root: Path | str) -> Path:
    root = Path(root)
    if (not root.is_absolute() or not root.is_dir() or root.is_symlink()
            or root.resolve() != root):
        raise ValueError("unsafe state root")
    path = root / "var/lib/distromove"
    for parent in (root / "var", root / "var/lib"):
        if parent.is_symlink() or (parent.exists() and
                                  not parent.resolve().is_relative_to(root)):
            raise ValueError("unsafe state parent directory")
    if path.exists() and (path.is_symlink() or not path.is_dir()
                          or not path.resolve().is_relative_to(root)):
        raise ValueError("unsafe state directory")
    return path


def _filename(migration_id: str) -> str:
    if not _ID.fullmatch(migration_id):
        raise ValueError("invalid migration ID")
    return f"state-{migration_id}.json"


def save_state(state: MigrationState, root: Path | str) -> Path:
    """Atomically replace one state and its relative current link, both durable."""
    _validate(state)
    directory = _directory(root)
    make_dirs(directory, 0o700)
    path = directory / _filename(state.migration_id)
    if path.is_symlink():
        raise ValueError("state file is a symlink")
    current = directory / STATE_LINK
    if current.is_symlink() and current.readlink() != Path(path.name):
        raise ValueError("another migration state is current")
    if current.exists() and not current.is_symlink():
        raise ValueError("current state link is occupied")
    data = json.dumps(asdict(state), sort_keys=True, separators=(",", ":")).encode() + b"\n"
    write_atomic(path, data, 0o600)
    link_atomic(path.name, current)
    return path


def state_from_record(raw: dict) -> MigrationState:
    """Validate a state copied into a durable journal record."""
    if not isinstance(raw, dict):
        raise ValueError("invalid state record")
    try:
        values = dict(raw)
        for key in ("old_volumes", "new_volumes"):
            values[key] = [VolumeIdentity(**item) for item in values[key]]
        for key in ("old_esp", "new_esp"):
            values[key] = VolumeIdentity(**values[key])
        state = MigrationState(**values)
        _validate(state)
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise ValueError("invalid state record") from exc
    return state


def _decode(path: Path) -> MigrationState:
    if (path.is_symlink() or not path.is_file()
            or stat.S_IMODE(path.stat().st_mode) != 0o600):
        raise ValueError("unsafe state file")
    state = state_from_record(json.loads(path.read_text()))
    if path.name != _filename(state.migration_id):
        raise ValueError("state filename and identity differ")
    return state


def load_state(root: Path | str, running_root_uuid: str) -> MigrationState | None:
    """Only a current state for the actual running root may authorize actions."""
    directory = _directory(root)
    current = directory / STATE_LINK
    if not current.is_symlink():
        if current.exists():
            raise ValueError("current state is not a symlink")
        return None
    target = current.readlink()
    if target.name != str(target) or not target.name.startswith("state-"):
        raise ValueError("unsafe current state link")
    state = _decode(directory / target)
    return state if state.new_root_uuid.casefold() == running_root_uuid.casefold() else None


def archived_states(root: Path | str,
                    running_root_uuid: str | None = None) -> list[MigrationState]:
    directory = _directory(root)
    if not directory.exists():
        return []
    current = ((directory / STATE_LINK).readlink().name
               if (directory / STATE_LINK).is_symlink() else None)
    current_id = current.removeprefix("state-").removesuffix(".json") if current else None
    states = [_decode(path) for path in sorted(directory.glob("state-*.json"))]
    return [item for item in states if item.migration_id != current_id or
            (running_root_uuid is not None and
             item.new_root_uuid.casefold() != running_root_uuid.casefold())]
