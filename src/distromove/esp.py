"""Conservative ESP and UEFI boot-entry handling."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re

from .disk import _assert_created, _journal_allows_fs, _require_no_signature
from .journal import Journal, read_journal
from .model import CreatedPartition, LoaderInfo, PlannedIdentity
from .probe_parse import loader_of
from .runner import Runner


class SecureBootUnsupported(RuntimeError):
    """The observed loader chain cannot be trusted for Secure Boot."""


class PartialRegistration(RuntimeError):
    """A firmware entry was created but the requested order was not proven."""

    def __init__(self, bootnum: str, ordered: bool = False):
        super().__init__(f"UEFI entry Boot{bootnum} exists; order was not verified")
        self.bootnum = bootnum
        self.ordered = ordered


@dataclass(frozen=True)
class BootState:
    order: tuple[str, ...]
    entries: dict[str, str]
    current: str | None


_BOOT = re.compile(r"^Boot([0-9A-Fa-f]{4})\*?\s")
_ORDER = re.compile(r"^BootOrder:\s*([0-9A-Fa-f]{4}(?:,[0-9A-Fa-f]{4})*)\s*$")
_CURRENT = re.compile(r"^BootCurrent:\s*([0-9A-Fa-f]{4})\s*$")
_LOADER = re.compile(r"^\\EFI\\([^\\]+)\\(shimx64|grubx64)\.efi$", re.I)


def parse_efibootmgr(text: str) -> BootState:
    """Parse only the summary lines of ``efibootmgr -v``; reject ambiguous order."""
    current = None
    order = None
    entries: dict[str, str] = {}
    for line in text.splitlines():
        match = _CURRENT.fullmatch(line.strip())
        if match:
            if current is not None:
                raise ValueError("duplicate BootCurrent")
            current = match[1].upper()
            continue
        match = _ORDER.fullmatch(line.strip())
        if match:
            if order is not None:
                raise ValueError("duplicate BootOrder")
            order = tuple(item.upper() for item in match[1].split(","))
            if len(order) != len(set(order)):
                raise ValueError("duplicate BootOrder item")
            continue
        match = _BOOT.match(line)
        if match:
            number = match[1].upper()
            if number in entries:
                raise ValueError("duplicate boot entry")
            entries[number] = line.strip()
    if order is None or any(number not in entries for number in order):
        raise ValueError("missing or invalid BootOrder")
    return BootState(order, entries, current)


def _esp_dirs(esp_dirs: dict, partuuid: str) -> tuple[str, dict[str, set[str]]] | None:
    for identity, value in esp_dirs.items():
        if str(identity).casefold() != partuuid.casefold():
            continue
        if isinstance(value, tuple):
            fs_uuid, dirs = value
        else:
            fs_uuid, dirs = partuuid, value
        if not isinstance(dirs, dict):
            raise ValueError("ESP contents must map directories to filenames")
        return str(fs_uuid), {str(k).casefold(): {str(f).casefold() for f in files}
                              for k, files in dirs.items()}
    return None


def detect_loader(state: BootState, esp_dirs: dict, *, secure_boot: bool = False) -> LoaderInfo:
    """Identify the actually booted GRUB/shim chain from its ESP partition."""
    if state.current not in state.entries:
        raise ValueError("BootCurrent has no entry")
    target = loader_of(state.entries[state.current])
    if target is None or not (match := _LOADER.fullmatch(target[1])):
        raise ValueError("current boot entry is not a GRUB or shim loader")
    contents = _esp_dirs(esp_dirs, target[0])
    if contents is None:
        raise ValueError("current boot ESP is unavailable")
    fs_uuid, dirs = contents
    boot_id, kind = match[1], match[2].casefold()
    files = dirs.get(boot_id.casefold(), set())
    if f"{kind}.efi" not in files:
        raise ValueError("current loader is absent from ESP")
    if secure_boot:
        # Names and PE signature presence do not prove trust by firmware/MOK.
        # A later installer must verify the trust chain before enabling this path.
        raise SecureBootUnsupported("the signed shim and GRUB trust chain is not verified")
    return LoaderInfo(boot_id, target[1], kind == "shimx64", fs_uuid)


def secure_boot_enabled(r: Runner) -> bool:
    result = r.run(["mokutil", "--sb-state"], readonly=True)
    if (result.returncode or
            not any(value in result.stdout for value in ("SecureBoot enabled", "SecureBoot disabled"))):
        raise ValueError("cannot determine Secure Boot state")
    return "SecureBoot enabled" in result.stdout


def choose_bootloader_id(existing_dirs: set[str] | list[str], os_id: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", os_id):
        raise ValueError("unsafe OS identifier")
    taken = {name.casefold() for name in existing_dirs}
    base = f"{os_id}-moved"
    for index in range(1, 10000):
        candidate = base if index == 1 else f"{base}-{index}"
        if candidate.casefold() not in taken:
            return candidate
    raise ValueError("no free bootloader identifier")


def foreign_entries(state: BootState, esp_dirs: dict) -> list[str]:
    """Entries whose loader directory is not the current system's directory."""
    own = detect_loader(state, esp_dirs)
    own_target = loader_of(state.entries[state.current])
    result = []
    for number, line in state.entries.items():
        target = loader_of(line)
        if target is None:
            continue
        directory = target[1].replace("/", "\\").split("\\")
        if (len(directory) < 4 or directory[1].casefold() != "efi"
                or directory[2].casefold() != own.bootloader_id.casefold()
                or target[0].casefold() != own_target[0].casefold()):
            result.append(number)
    for partuuid, value in esp_dirs.items():
        dirs = value[1] if isinstance(value, tuple) else value
        for directory in dirs:
            if (str(partuuid).casefold() != own_target[0].casefold()
                    or directory.casefold() != own.bootloader_id.casefold()):
                name = f"EFI/{directory}"
                if name not in result:
                    result.append(name)
    return result


def firmware_uses_esp(state: BootState, esp_uuid: str) -> bool:
    """Compare firmware GPT partition identity, including entries outside BootOrder."""
    pattern = re.compile(r"HD\(\d+,GPT,([0-9A-Fa-f-]{36}),", re.I)
    return any((match := pattern.search(line)) is not None and
               match[1].casefold() == esp_uuid.casefold() for line in state.entries.values())


def _state(r: Runner) -> BootState:
    return parse_efibootmgr(r.run(["efibootmgr", "-v"], readonly=True).stdout)


def _partuuid(r: Runner, disk: str, part_no: int) -> str:
    result = r.run(["lsblk", "--json", "--list", "--output", "PATH,PARTN,PARTUUID", disk],
                   readonly=True)
    try:
        rows = json.loads(result.stdout)["blockdevices"]
        matches = [str(row["partuuid"]) for row in rows if row.get("partn") is not None
                   and int(row["partn"]) == part_no and row.get("partuuid")]
    except (ValueError, TypeError, KeyError) as exc:
        raise ValueError("cannot read ESP partition identity") from exc
    if len(matches) != 1:
        raise ValueError("ESP partition number is absent or ambiguous")
    return matches[0]


def _new_bootnum(before: BootState, after: BootState, esp_partuuid: str,
                 loader_path: str, label: str) -> str:
    added = set(after.entries) - set(before.entries)
    if len(added) != 1 or any(after.entries.get(k) != v for k, v in before.entries.items()):
        raise RuntimeError("cannot identify a unique new firmware entry")
    number = added.pop()
    target = loader_of(after.entries[number])
    if (target is None or target[0].casefold() != esp_partuuid.casefold()
            or target[1].casefold() != loader_path.casefold()
            or label not in after.entries[number]):
        raise RuntimeError("new firmware entry points at an unexpected loader")
    return number


def register_new_entry(r: Runner, disk: str, part_no: int, loader_path: str,
                       label: str, journal: Journal) -> str:
    """Create a distinct entry on the host, then prepend it without reordering others."""
    if not disk.startswith("/dev/") or part_no < 1 or part_no > 128:
        raise ValueError("invalid disk or partition number")
    match = _LOADER.fullmatch(loader_path)
    if (not match or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", match[1])
            or match[1] in {".", ".."} or not label or len(label) > 80
            or any(ord(char) < 32 for char in label)):
        raise ValueError("invalid EFI loader or label")
    esp_partuuid = _partuuid(r, disk, part_no)
    before = _state(r)
    if _partuuid(r, disk, part_no).casefold() != esp_partuuid.casefold():
        raise RuntimeError("ESP partition identity changed before firmware update")
    op = journal.intend("uefi_entry", {"esp_partuuid": esp_partuuid,
                                       "loader": loader_path, "label": label},
                        creates="nvram_entry", disk=disk, part_no=part_no)
    try:
        r.run(["efibootmgr", "--create-only", "--disk", disk, "--part", str(part_no),
               "--loader", loader_path, "--label", label])
    except Exception:
        # Firmware may have accepted the entry despite a command failure.
        after = _state(r)
        try:
            number = _new_bootnum(before, after, esp_partuuid, loader_path, label)
        except RuntimeError:
            raise
        journal.done(op, "created", bootnum=number)
        raise PartialRegistration(number) from None
    after = _state(r)
    number = _new_bootnum(before, after, esp_partuuid, loader_path, label)
    journal.done(op, "created", bootnum=number)
    if after.order != before.order:
        raise PartialRegistration(number)
    wanted = (number, *before.order)
    order_op = journal.intend("uefi_order", {"esp_partuuid": esp_partuuid,
                                             "bootnum": number},
                              old_order=before.order, new_order=wanted)
    try:
        r.run(["efibootmgr", "-o", ",".join(wanted)])
        final = _state(r)
        if final.order != wanted or any(final.entries.get(k) != v for k, v in before.entries.items()):
            raise RuntimeError("firmware changed another entry or order")
    except Exception as exc:
        raise PartialRegistration(number) from exc
    journal.done(order_op, "ordered")
    return number


def create_esp(r: Runner, created: CreatedPartition, planned: PlannedIdentity,
               journal: Journal) -> str:
    """Format only the approved, newly created ESP and verify its FAT identity."""
    if (created.volume_id != "esp" or created.partuuid.casefold() != planned.partuuid.casefold()
            or created.fs_uuid.casefold() != planned.fs_uuid.casefold() or planned.luks_uuid):
        raise ValueError("ESP partition differs from approved layout")
    if not re.fullmatch(r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}", planned.fs_uuid):
        raise ValueError("invalid planned FAT volume ID")
    if not _journal_allows_fs(journal, created.path, created.fs_uuid):
        raise ValueError("journal does not authorize formatting this ESP")
    _assert_created(r, created)
    _require_no_signature(r, created.path)
    op = journal.intend("create_esp", {"esp_partuuid": created.partuuid,
                                       "fs_uuid": created.fs_uuid},
                        creates="filesystem", device=created.path)
    r.run(["mkfs.vfat", "-F", "32", "-i", planned.fs_uuid.replace("-", ""), created.path])
    actual = r.run(["blkid", "-p", "-o", "value", "-s", "UUID", created.path],
                   readonly=True).stdout.strip()
    kind = r.run(["blkid", "-p", "-o", "value", "-s", "TYPE", created.path],
                 readonly=True).stdout.strip()
    if actual.casefold() != planned.fs_uuid.casefold() or kind != "vfat":
        raise RuntimeError("created ESP filesystem identity differs from the plan")
    journal.done(op, "created", device=created.path)
    return actual


def _mounted_esp(r: Runner, path: Path) -> tuple[str, str]:
    result = r.run(["findmnt", "--json", "--mountpoint", str(path),
                    "--output", "TARGET,FSTYPE,SOURCE,UUID"], readonly=True)
    try:
        mounts = json.loads(result.stdout)["filesystems"]
        if len(mounts) != 1 or mounts[0]["target"] != str(path) or mounts[0]["fstype"] != "vfat":
            raise ValueError
        source, fs_uuid = str(mounts[0]["source"]), str(mounts[0]["uuid"])
        if not source or not fs_uuid:
            raise ValueError
        return source, fs_uuid
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        raise ValueError(f"not a verified mounted ESP: {path}") from exc


def _owned_esp(journal: Journal, device: str, fs_uuid: str) -> bool:
    if not journal.is_current():
        return False
    entries = read_journal(journal.path)
    intents = {entry["op_id"]: entry for entry in entries if entry["type"] == "intent"}
    for entry in entries:
        if entry["type"] != "outcome" or entry["outcome"] != "created":
            continue
        intent = intents.get(entry["op_id"])
        if (intent and intent["op"] == "create_esp" and
                intent["identity"].get("fs_uuid", "").casefold() == fs_uuid.casefold() and
                entry["fields"].get("device") == device):
            return True
    return False


def copy_esp(r: Runner, old: Path | str, new: Path | str, journal: Journal) -> None:
    """Copy the old ESP into a different mounted ESP without deleting either tree."""
    source, dest = Path(old), Path(new)
    if (not source.is_dir() or not dest.is_dir() or source.is_symlink() or dest.is_symlink()
            or source.resolve() == dest.resolve()):
        raise ValueError("ESP source and destination must be distinct mounted directories")
    old_identity, new_identity = _mounted_esp(r, source), _mounted_esp(r, dest)
    if old_identity[1].casefold() == new_identity[1].casefold():
        raise ValueError("both ESP paths refer to the same device")
    if not _owned_esp(journal, *new_identity):
        raise ValueError("destination ESP is not owned by this migration")
    op = journal.intend("copy_esp", {"source_uuid": old_identity[1],
                                    "destination_uuid": new_identity[1]},
                        source_mount=source, destination_mount=dest)
    # FAT cannot preserve POSIX owners, modes or symlinks; copy regular files and times.
    r.run(["rsync", "-r", "-t", "-x", "--checksum", "--",
           str(source) + "/", str(dest) + "/"])
    if _mounted_esp(r, source) != old_identity or _mounted_esp(r, dest) != new_identity:
        raise RuntimeError("ESP mount changed during copy")
    journal.done(op, "copied")


def remove_entry(r: Runner, bootnum: str, journal: Journal) -> None:
    """Remove one non-current firmware entry and preserve every other entry."""
    if not re.fullmatch(r"[0-9A-Fa-f]{4}", bootnum):
        raise ValueError("invalid boot number")
    number = bootnum.upper()
    before = _state(r)
    if number == before.current or number not in before.entries:
        raise ValueError("cannot remove current or missing firmware entry")
    op = journal.intend("remove_uefi_entry", {"bootnum": number})
    r.run(["efibootmgr", "-b", number, "-B"])
    after = _state(r)
    expected = tuple(item for item in before.order if item != number)
    if (number in after.entries or after.order != expected or
            any(after.entries.get(key) != value for key, value in before.entries.items()
                if key != number)):
        raise RuntimeError("firmware changed unrelated entries during removal")
    journal.done(op, "removed")
