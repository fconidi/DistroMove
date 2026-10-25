"""Operation journal, instance lock and conservative recovery.

Every change is preceded by an *intent* line, made durable before the change starts, and
followed by an *outcome* line linked to it by ``op_id``. Journal file
``<root>/journal-<migration_id>.jsonl`` holds one JSON object per line:

- ``header`` (first line): ``version``, ``migration_id``, ``host_root_uuid`` (filesystem
  UUID of the root of the system running the migration) and ``created_at``;
- ``intent``: ``op_id``, ``op``, ``identity`` (the identity chosen *before* the operation:
  PARTUUID, LUKS UUID, filesystem UUID, snapshot name...), ``fields`` and ``at``;
- ``outcome``: ``op_id`` of its intent, ``outcome``, ``fields`` and ``at``;
- ``end`` (last line, written by ``Journal.finish``): ``outcome`` and ``at``.

``<root>/current`` is a relative symbolic link to the journal of the migration in progress
on this system. It is set before the first intent can be written and removed by
``finish``; a journal with an ``end`` line is never current, even if the link survived.
Every durable write (journal file and lines, the ``current`` link, files installed
elsewhere) fsyncs the file and its directory.

An intent whose operation creates a resource names the kind of resource in the field
``creates``. ``recover`` understands these kinds, identified by the identity keys shown:

- ``"partition"``: ``partuuid`` (plus ``disk_wwn``, ``disk_serial``, ``disk_by_id``,
  ``start_sectors``, ``size_sectors`` when known);
- ``"luks"``: ``luks_uuid`` (plus ``partuuid`` and the keys above when known);
- ``"filesystem"`` (also a swap area): ``fs_uuid`` (plus the keys above when known);
- ``"efi_dir"``: ``esp_partuuid`` and ``efi_dir`` (name of the directory under ``EFI/``);
- ``"nvram_entry"``: ``esp_partuuid`` and ``loader`` (loader path on the ESP), plus
  ``label`` when known; the ``bootnum`` (four hex digits) is recorded in the fields of the
  intent or of an outcome once ``efibootmgr`` has assigned it.

Any other kind (btrfs snapshots among them) is never reported, because a
``SystemSnapshot`` cannot prove it exists. Values recorded on any line about the same
resource (linked by a shared UUID: ``partuuid``, ``luks_uuid``, ``fs_uuid``,
``esp_partuuid``) only ever add reasons to consider it in use: device paths and mapper
names (``path``, ``device``, ``mapper``, ``mapper_name``) and the partition ``number``.

Secrets never enter the journal: bytes values and keys naming a passphrase or a password
are refused with ``ValueError``.
"""
from __future__ import annotations

import dataclasses
import fcntl
import json
import math
import os
import re
import stat
import string
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePath
from typing import Any, Callable

from .model import SystemSnapshot, VolumeIdentity

DEFAULT_ROOT = Path("/var/lib/distromove")
DEFAULT_LOCK = Path("/run/distromove.lock")
FORMAT_VERSION = 1
CURRENT_LINK = "current"
WINDOW_OP = "freeze_window"

_PREFIX, _SUFFIX = "journal-", ".jsonl"
_MIGRATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SECRET_WORDS = ("passphrase", "password")
_VOLUME_KINDS = {"partition": "partuuid", "luks": "luks_uuid", "filesystem": "fs_uuid"}
_VOLUME_KEYS = ("partuuid", "luks_uuid", "fs_uuid", "disk_wwn", "disk_serial", "disk_by_id",
                "start_sectors", "size_sectors")
_UUID_KEYS = ("partuuid", "luks_uuid", "fs_uuid", "esp_partuuid")
_NAME_KEYS = ("path", "device", "mapper", "mapper_name")
RECOVERABLE_KINDS = (*_VOLUME_KINDS, "efi_dir", "nvram_entry")


# --------------------------------------------------------------------------- durability

def fsync_dir(path: Path | str) -> None:
    """fsync a directory, making the entries created, renamed or removed in it durable."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def make_dirs(path: Path | str, mode: int = 0o700) -> None:
    """Create ``path`` and its missing parents durably (parents get mode 0755)."""
    path = Path(os.path.abspath(path))
    missing = []
    p = path
    while not os.path.lexists(p):
        missing.append(p)
        p = p.parent
    for d in reversed(missing):
        try:
            os.mkdir(d, mode if d == path else 0o755)
        except FileExistsError:
            pass
        fsync_dir(d.parent)
    if not path.is_dir():
        raise NotADirectoryError(str(path))


def write_atomic(path: Path | str, data: bytes, mode: int = 0o600) -> None:
    """Replace ``path`` with ``data`` atomically: temporary file, fsync, rename, fsync dir."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    fsync_dir(path.parent)


def link_atomic(target: str, link: Path | str) -> None:
    """Point the symbolic link ``link`` at ``target`` atomically and durably."""
    link = Path(link)
    tmp = link.with_name(f".{link.name}.{uuid.uuid4().hex}.tmp")
    os.symlink(target, tmp)
    try:
        os.replace(tmp, link)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    fsync_dir(link.parent)


def append_durable(path: Path | str, data: bytes) -> None:
    """Append ``data`` to ``path`` and fsync the file and its directory."""
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600)
    try:
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(Path(path).parent)


# --------------------------------------------------------------------------- encoding

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean(value: Any, where: str) -> Any:
    """Plain JSON value; refuses secrets. Error messages never contain values."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError(f"{where}: binary values are not allowed in the journal")
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{where}: not a finite number")
        return value
    if isinstance(value, PurePath):
        return str(value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        value = {f.name: getattr(value, f.name) for f in dataclasses.fields(value)}
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, int) and not isinstance(k, bool):
                k = str(k)
            if not isinstance(k, str):
                raise TypeError(f"{where}: keys must be strings")
            if any(w in k.lower() for w in _SECRET_WORDS):
                raise ValueError(f"{where}: key {k!r} names a secret")
            out[k] = _clean(v, f"{where}.{k}")
        return out
    if isinstance(value, (list, tuple)):
        return [_clean(v, f"{where}[{i}]") for i, v in enumerate(value)]
    raise TypeError(f"{where}: {type(value).__name__} cannot be written to the journal")


def _encode(entry: dict) -> bytes:
    return (json.dumps(entry, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
            + "\n").encode("ascii")


def _valid(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    t = obj.get("type")
    if t == "header":
        return isinstance(obj.get("migration_id"), str)
    if t == "intent":
        return (isinstance(obj.get("op_id"), str) and isinstance(obj.get("op"), str)
                and isinstance(obj.get("identity"), dict) and isinstance(obj.get("fields"), dict))
    if t == "outcome":
        return (isinstance(obj.get("op_id"), str) and isinstance(obj.get("outcome"), str)
                and isinstance(obj.get("fields"), dict))
    if t == "end":
        return isinstance(obj.get("outcome"), str)
    return False


def read_journal(path: Path | str) -> list[dict]:
    """All well-formed lines of a journal, in order. A torn or damaged line is skipped."""
    with open(path, "rb") as f:
        data = f.read()
    entries = []
    for raw in data.split(b"\n"):
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            continue
        if _valid(obj):
            entries.append(obj)
    return entries


def _norm(value: Any) -> str | None:
    return None if value is None else str(value).strip().lower()


def _same(a: Any, b: Any) -> bool:
    na, nb = _norm(a), _norm(b)
    return bool(na) and na == nb


# --------------------------------------------------------------------------- journal

class Journal:
    """Journal of one migration, stored in ``root``.

    A new journal becomes the ``current`` one of ``root`` before the constructor returns,
    so before any intent; an existing, unfinished journal of the same ``migration_id`` is
    reopened and appended to (and becomes ``current`` again). ``host_root_uuid`` ties the
    journal to the system that runs it: ``recover`` only acts on the current journal of the
    running root. ``finish`` ends the migration: the journal is then read-only and archived.
    """

    def __init__(self, root: Path | str = DEFAULT_ROOT, migration_id: str | None = None, *,
                 host_root_uuid: str | None = None):
        self.root = Path(os.path.abspath(root))
        self.migration_id = migration_id if migration_id is not None else uuid.uuid4().hex
        if not _MIGRATION_ID.fullmatch(self.migration_id):
            raise ValueError(f"invalid migration id: {self.migration_id!r}")
        self.path = self.root / f"{_PREFIX}{self.migration_id}{_SUFFIX}"
        self._ops: dict[str, str] = {}
        self._open_windows: set[str] = set()
        self._finished = False
        make_dirs(self.root)
        if os.path.lexists(self.path):
            self._reopen(host_root_uuid)
        else:
            self.host_root_uuid = host_root_uuid
            write_atomic(self.path, _encode({
                "type": "header", "version": FORMAT_VERSION, "migration_id": self.migration_id,
                "host_root_uuid": host_root_uuid, "created_at": _now()}))
        link_atomic(self.path.name, self.root / CURRENT_LINK)

    def _reopen(self, host_root_uuid: str | None) -> None:
        if not stat.S_ISREG(os.lstat(self.path).st_mode):
            raise ValueError(f"not a regular file: {self.path}")
        entries = read_journal(self.path)
        header = entries[0] if entries and entries[0]["type"] == "header" else None
        if header is None or header["migration_id"] != self.migration_id:
            raise ValueError(f"{self.path} is not the journal of migration {self.migration_id}")
        recorded = header.get("host_root_uuid")
        if host_root_uuid is not None and not _same(recorded, host_root_uuid):
            raise ValueError(f"{self.path} belongs to another system")
        if any(e["type"] == "end" for e in entries):
            raise ValueError(f"{self.path} is finished")
        self.host_root_uuid = recorded
        self._ops = {e["op_id"]: e["op"] for e in entries if e["type"] == "intent"}
        closed = {e["op_id"] for e in entries if e["type"] == "outcome"}
        self._open_windows = {i for i, op in self._ops.items() if op == WINDOW_OP and i not in closed}
        with open(self.path, "rb") as f:
            f.seek(0, os.SEEK_END)
            if f.tell():
                f.seek(-1, os.SEEK_END)
                torn = f.read(1) != b"\n"
            else:
                torn = False
        if torn:  # terminate a line cut by a crash, so the next line stays readable
            append_durable(self.path, b"\n")

    def _append(self, entry: dict) -> None:
        if self._finished:
            raise RuntimeError(f"{self.path} is finished")
        append_durable(self.path, _encode(entry))

    def is_current(self) -> bool:
        """Whether ``current`` points at this journal."""
        try:
            return os.readlink(self.root / CURRENT_LINK) == self.path.name
        except OSError:
            return False

    def intend(self, op: str, identity: dict, **fields: Any) -> str:
        """Record, durably, that ``op`` is about to run; returns its ``op_id``."""
        if not isinstance(op, str) or not op:
            raise ValueError("operation name must be a non-empty string")
        if not isinstance(identity, dict):
            raise TypeError("identity must be a dict")
        identity = _clean(identity, "identity")
        fields = _clean(fields, "fields")
        if "creates" in fields and not isinstance(fields["creates"], str):
            raise ValueError("fields.creates must name a kind of resource")
        if self._finished:
            raise RuntimeError(f"{self.path} is finished")
        if not self.is_current():
            # an operation journaled here could never be recovered
            raise RuntimeError(f"{self.path} is no longer the current journal")
        op_id = f"{len(self._ops) + 1:04d}-{uuid.uuid4().hex[:12]}"
        self._append({"type": "intent", "op_id": op_id, "op": op, "identity": identity,
                      "fields": fields, "at": _now()})
        self._ops[op_id] = op
        return op_id

    def done(self, op_id: str, outcome: str, **fields: Any) -> None:
        """Record, durably, the outcome of the operation ``op_id`` of this journal."""
        if op_id not in self._ops:
            raise ValueError(f"unknown operation: {op_id!r}")
        if not isinstance(outcome, str) or not outcome:
            raise ValueError("outcome must be a non-empty string")
        fields = _clean(fields, "fields")
        self._append({"type": "outcome", "op_id": op_id, "outcome": outcome, "fields": fields,
                      "at": _now()})

    def window_open(self, name: str) -> str:
        """Record that a freeze window is about to open (before anything is frozen)."""
        op_id = self.intend(WINDOW_OP, {"window": name})
        self._open_windows.add(op_id)
        return op_id

    def window_close(self, op_id: str) -> None:
        """Record that the window ``op_id`` is closed (after the thaw is proven)."""
        if self._ops.get(op_id) != WINDOW_OP:
            raise ValueError(f"not a freeze window: {op_id!r}")
        self.done(op_id, "closed")
        self._open_windows.discard(op_id)

    def finish(self, outcome: str = "completed") -> None:
        """End the migration: nothing it created will be offered for recovery any more.

        Call it only when nothing of this migration may need recovery (activated, or
        rolled back completely). The ``end`` line is made durable first, then ``current``
        is removed (if it still points here) and the directory is fsynced.
        """
        if not isinstance(outcome, str) or not outcome:
            raise ValueError("outcome must be a non-empty string")
        if self._open_windows:
            raise RuntimeError("a freeze window is still open")
        self._append({"type": "end", "outcome": outcome, "at": _now()})
        self._finished = True
        if self.is_current():
            os.unlink(self.root / CURRENT_LINK)
            fsync_dir(self.root)

    def install_into(self, new_root: Path | str) -> None:
        """Copy the journal to the same directory inside ``new_root``, durably."""
        new_root = Path(os.path.abspath(new_root))
        dest_dir = new_root / self.root.relative_to(self.root.anchor)
        if os.path.realpath(dest_dir) == os.path.realpath(self.root):
            raise ValueError("the destination is the journal itself")
        make_dirs(dest_dir)
        write_atomic(dest_dir / self.path.name, self.path.read_bytes())
        d = dest_dir
        while True:  # the directories leading to it may be fresh copies never synced
            fsync_dir(d)
            if d == new_root or d == d.parent:
                break
            d = d.parent


# --------------------------------------------------------------------------- lock

class AlreadyRunning(Exception):
    """Another instance holds the lock."""


class Lock:
    """Exclusive instance lock (``flock``); released by the kernel if the holder dies."""

    def __init__(self, path: Path | str = DEFAULT_LOCK):
        self.path = Path(path)
        self._fd: int | None = None

    def __enter__(self) -> "Lock":
        if self._fd is not None:
            raise RuntimeError("lock already held")
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            holder = os.pread(fd, 32, 0).decode("ascii", "replace").strip()
            os.close(fd)
            detail = f" (pid {holder})" if holder.isdigit() else ""
            raise AlreadyRunning(f"another instance is already running{detail}") from None
        except BaseException:
            os.close(fd)
            raise
        try:
            os.ftruncate(fd, 0)
            os.pwrite(fd, f"{os.getpid()}\n".encode("ascii"), 0)
        except OSError:
            pass  # the pid is only informative
        self._fd = fd
        return self

    def __exit__(self, *exc: Any) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            os.ftruncate(fd, 0)
        except OSError:
            pass
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# --------------------------------------------------------------------------- recovery

@dataclass(frozen=True)
class Residue:
    """A resource created by the current migration that still exists and is not in use."""
    kind: str
    identity: dict[str, Any]
    proof: dict[str, Any]


@dataclass(frozen=True)
class OpenWindow:
    op_id: str
    name: str
    opened_at: str


def _journal_files(jdir: Path) -> list[Path]:
    try:
        names = os.listdir(jdir)
    except FileNotFoundError:
        return []
    out = []
    for name in sorted(names):
        if name.startswith(_PREFIX) and name.endswith(_SUFFIX):
            p = jdir / name
            if stat.S_ISREG(os.lstat(p).st_mode):
                out.append(p)
    return out


def current_journal(journal_dir: Path | str, running_root_uuid: str) -> Path | None:
    """The journal of the migration in progress on the running system, if any.

    It is the target of the ``current`` link (a file of ``journal_dir``) whose header names
    this migration and the running root, and that has no ``end`` line. Any other journal is
    archived.
    """
    jdir = Path(os.path.abspath(journal_dir))
    try:
        target = os.readlink(jdir / CURRENT_LINK)
    except OSError:
        return None
    if "/" in target or not (target.startswith(_PREFIX) and target.endswith(_SUFFIX)):
        return None
    path = jdir / target
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None
        entries = read_journal(path)
    except OSError:
        return None
    if not entries or entries[0]["type"] != "header":
        return None
    header = entries[0]
    if header["migration_id"] != target[len(_PREFIX):-len(_SUFFIX)]:
        return None
    if not _same(header.get("host_root_uuid"), running_root_uuid):
        return None
    if any(e["type"] == "end" for e in entries):
        return None
    return path


def archived_journals(journal_dir: Path | str, running_root_uuid: str) -> list[Path]:
    """Journals that are not the current one: earlier migrations, or copied from elsewhere."""
    jdir = Path(os.path.abspath(journal_dir))
    current = current_journal(jdir, running_root_uuid)
    return [p for p in _journal_files(jdir) if p != current]


def open_windows(journal_dir: Path | str, running_root_uuid: str) -> list[OpenWindow]:
    """Freeze windows of the current journal that were opened and never closed."""
    path = current_journal(journal_dir, running_root_uuid)
    if path is None:
        return []
    entries = read_journal(path)
    closed = {e["op_id"] for e in entries if e["type"] == "outcome"}
    return [OpenWindow(e["op_id"], str(e["identity"].get("window", "")), str(e.get("at", "")))
            for e in entries
            if e["type"] == "intent" and e["op"] == WINDOW_OP and e["op_id"] not in closed]


def _match_volume(identity: dict, key: str, live: list[VolumeIdentity]) -> VolumeIdentity | None:
    """The one live volume carrying the pre-assigned identity, or None (absent, changed,
    ambiguous)."""
    want = identity.get(key)
    if not isinstance(want, str) or not want.strip():
        return None
    hits = [v for v in live if _same(getattr(v, key), want)]
    if len(hits) != 1:
        return None
    v = hits[0]
    for k in _VOLUME_KEYS:
        if identity.get(k) is not None and _norm(getattr(v, k)) != _norm(identity[k]):
            return None
    return v


def _values(dicts: list[dict], keys: tuple[str, ...]) -> list[str]:
    return [d[k].strip() for d in dicts for k in keys
            if isinstance(d.get(k), str) and d[k].strip()]


def _groups(entries: list[dict]) -> list[dict]:
    """One group per intent: the intent with the fields of all its outcome lines."""
    outcomes: dict[str, list[dict]] = {}
    for e in entries:
        if e["type"] == "outcome":
            outcomes.setdefault(e["op_id"], []).append(e)
    groups = []
    for e in entries:
        if e["type"] != "intent":
            continue
        outs = outcomes.get(e["op_id"], [])
        dicts = [e["identity"], e["fields"]] + [o["fields"] for o in outs]
        groups.append({"intent": e, "outcomes": outs, "dicts": dicts,
                       "uuids": {_norm(v) for v in _values(dicts, _UUID_KEYS)}})
    return groups


def _related(groups: list[dict], seed: set[str]) -> tuple[set[str], list[dict]]:
    """Every UUID linked to ``seed`` through the journal, and the groups that carry them."""
    uuids = set(seed)
    changed = True
    while changed:
        changed = False
        for g in groups:
            if g["uuids"] & uuids and not g["uuids"] <= uuids:
                uuids |= g["uuids"]
                changed = True
    return uuids, [g for g in groups if g["uuids"] & uuids]


def _device_paths(raw_uuids: set[str], by_ids: set[str], numbers: set[str],
                  resolve: Callable[[str], str]) -> set[str]:
    """Current kernel device paths behind the stable /dev/disk links of a resource."""
    links = []
    for u in raw_uuids:
        for variant in {u, u.lower(), u.upper()}:
            links += [f"/dev/disk/by-partuuid/{variant}", f"/dev/disk/by-uuid/{variant}"]
    links += [f"{d}-part{n}" for d in by_ids for n in numbers]
    paths = set()
    for link in links:
        try:
            target = resolve(link)
        except OSError:
            continue
        if isinstance(target, str) and target != link and target.startswith("/dev/"):
            paths.add(target.lower())
    return paths


def _boot_texts(live: SystemSnapshot) -> list[str]:
    current = _bootnum(live.boot_current) if live.boot_current else None
    return [line for k, line in live.boot_entries.items() if current and _bootnum(k) == current]


def _volume_in_use(identity: dict, v: VolumeIdentity, live: SystemSnapshot,
                   groups: list[dict], roots: set[str],
                   resolve: Callable[[str], str]) -> bool:
    seed_raw = set(_values([identity], _UUID_KEYS))
    seed_raw |= {x.strip() for x in (v.partuuid, v.luks_uuid, v.fs_uuid) if x and x.strip()}
    uuids, related = _related(groups, {_norm(x) for x in seed_raw})
    if uuids & roots:
        return True
    dicts = [identity] + [d for g in related for d in g["dicts"]]
    raw = seed_raw | set(_values(dicts, _UUID_KEYS))
    names = {x.lower() for x in _values(dicts, _NAME_KEYS)}
    numbers = {str(d["number"]).strip() for d in dicts
               if isinstance(d.get("number"), (int, str)) and not isinstance(d.get("number"), bool)
               and str(d["number"]).strip().isdigit()}
    by_ids = {x for x in (identity.get("disk_by_id"), v.disk_by_id) if isinstance(x, str) and x}
    tokens = (uuids | {u.replace("-", "") for u in uuids} | names
              | _device_paths(raw, by_ids, numbers, resolve))
    encrypted = bool(v.luks_uuid) or bool(identity.get("luks_uuid"))
    if encrypted and any(len(m.split()) < 2 for m in live.mappers):
        return True  # a mapping of unknown origin could be this container, opened
    texts = [live.fstab, live.crypttab]
    texts += [f"{m.source} {m.target} {m.options}" for m in live.mounts]
    texts += list(live.mappers)
    for s in live.swaps:
        texts.append(f"{s.path} {s.uuid or ''}")
        if s.luks is not None:
            texts.append(f"{s.luks.luks_uuid} {s.luks.mapper_name or ''}")
    texts += _boot_texts(live)
    texts = [t.lower() for t in texts if t]
    return any(tok in text for tok in tokens for text in texts)


def _bootnum(value: Any) -> str | None:
    s = str(value).strip()
    if s[:4].lower() == "boot":
        s = s[4:]
    s = s.rstrip("*").strip()
    if not s or len(s) > 4 or any(c not in string.hexdigits for c in s):
        return None
    return s.upper().zfill(4)


def _loader_text(text: str) -> str:
    return text.lower().replace("/", "\\")


def _entry_is(line: str, identity: dict) -> bool:
    """Whether a boot entry line points at the ESP and loader of ``identity``."""
    esp, loader = identity.get("esp_partuuid"), identity.get("loader")
    if not (isinstance(esp, str) and esp.strip() and isinstance(loader, str) and loader.strip()):
        return False
    text = _loader_text(line)
    if esp.strip().lower() not in text or _loader_text(loader.strip()) not in text:
        return False
    label = identity.get("label")
    return not (isinstance(label, str) and label.strip()) or label.strip().lower() in line.lower()


def _match_nvram(identity: dict, dicts: list[dict], live: SystemSnapshot) -> tuple[str, str] | None:
    entries = {}
    for k, line in live.boot_entries.items():
        b = _bootnum(k)
        if b is not None:
            entries[b] = line
    recorded = {b for b in (_bootnum(x) for x in _values(dicts, ("bootnum",))) if b}
    pool = recorded if recorded else set(entries)  # a recorded number must still be ours
    hits = sorted(b for b in pool if b in entries and _entry_is(entries[b], identity))
    return (hits[0], entries[hits[0]]) if len(hits) == 1 else None


def _match_efi_dir(identity: dict, live: SystemSnapshot) -> tuple[str, str] | None:
    esp, name = identity.get("esp_partuuid"), identity.get("efi_dir")
    if not (isinstance(esp, str) and esp.strip() and isinstance(name, str) and name.strip()):
        return None
    if "/" in name or "\\" in name:
        return None
    keys = [k for k in live.esp_contents if _same(k, esp)]
    if len(keys) != 1:
        return None
    names = [n for n in live.esp_contents[keys[0]] if _same(n, name)]
    return (keys[0], names[0]) if len(names) == 1 else None


def _efi_dir_in_use(esp: str, name: str, live: SystemSnapshot, ours: set[str]) -> bool:
    """Booted from, or used by a boot entry this migration did not create."""
    current = _bootnum(live.boot_current) if live.boot_current else None
    folder = f"\\efi\\{name.lower()}\\"
    for k, line in live.boot_entries.items():
        b = _bootnum(k)
        text = _loader_text(line)
        if esp.lower() in text and folder in text and (b is None or b == current or b not in ours):
            return True
    return False


def recover(journal_dir: Path | str, live: SystemSnapshot, running_root_uuid: str, *,
            resolve: Callable[[str], str] = os.path.realpath) -> list[Residue]:
    """Resources created by the current migration that still exist and are not in use.

    Only the current journal of the running root is read (see ``current_journal``). A
    resource is a candidate when its intent says it creates one, with or without an outcome
    line. It is reported only if it still exists with its pre-assigned identity unchanged
    (exactly one match) and is not in use:

    - partitions, LUKS containers, filesystems: one live volume carries the identity, and
      none of the UUIDs, device paths or mapper names the journal links to it (on any of
      its lines) appears in fstab, crypttab, the mounts, the device-mapper table, the active
      swaps or the entry the firmware booted from; it is not the running root. The stable
      links ``/dev/disk/by-partuuid``, ``/dev/disk/by-uuid`` and ``/dev/disk/by-id`` are
      resolved with ``resolve`` so that a renamed kernel device is still recognised;
    - EFI directories: present on that ESP and used by no boot entry except those this
      migration created, and not by the entry the firmware booted from;
    - NVRAM entries: pointing at that ESP and loader (and label), and not the entry the
      firmware booted from.

    Nothing is ever matched by label or by name alone.
    """
    path = current_journal(journal_dir, running_root_uuid)
    if path is None:
        return []
    entries = read_journal(path)
    migration_id = entries[0]["migration_id"]
    groups = _groups(entries)
    roots = {r for r in (_norm(running_root_uuid), _norm(live.running_root_uuid)) if r}
    current_boot = _bootnum(live.boot_current) if live.boot_current else None

    nvram = {}
    for g in groups:
        if g["intent"]["fields"].get("creates") == "nvram_entry":
            nvram[g["intent"]["op_id"]] = _match_nvram(g["intent"]["identity"], g["dicts"], live)
    ours = {m[0] for m in nvram.values() if m is not None}

    residues: list[Residue] = []
    seen: set[tuple[str, str]] = set()
    for g in groups:
        e = g["intent"]
        kind = e["fields"].get("creates")
        identity = e["identity"]
        if kind in _VOLUME_KINDS:
            match = _match_volume(identity, _VOLUME_KINDS[kind], live.identities)
            if match is None or _volume_in_use(identity, match, live, groups, roots, resolve):
                continue
            found: dict[str, Any] = dataclasses.asdict(match)
        elif kind == "efi_dir":
            hit = _match_efi_dir(identity, live)
            if hit is None or _efi_dir_in_use(hit[0], hit[1], live, ours):
                continue
            found = {"esp_partuuid": hit[0], "efi_dir": hit[1]}
        elif kind == "nvram_entry":
            hit = nvram.get(e["op_id"])
            if hit is None or hit[0] == current_boot:
                continue
            found = {"bootnum": hit[0], "entry": hit[1]}
        else:
            continue
        marker = (kind, json.dumps(identity, sort_keys=True))
        if marker in seen:
            continue
        seen.add(marker)
        outcome = g["outcomes"][-1]["outcome"] if g["outcomes"] else None
        residues.append(Residue(kind=kind, identity=dict(identity), proof={
            "journal": str(path), "migration_id": migration_id, "op_id": e["op_id"],
            "op": e["op"], "intended_at": e.get("at"), "outcome": outcome, "live": found}))
    return residues
