"""Operation journal, instance lock and conservative recovery.

Every change is preceded by an *intent* line, made durable before the change starts, and
followed by an *outcome* line linked to it by ``op_id``. Journal file
``<root>/journal-<migration_id>.jsonl`` holds one JSON object per line:

- ``header`` (first line): ``version``, ``migration_id``, ``host_root_uuid`` (filesystem
  UUID of the root of the system running the migration) and ``created_at``;
- ``intent``: ``op_id``, ``op``, ``identity`` (the identity chosen *before* the operation:
  PARTUUID, LUKS UUID, filesystem UUID, snapshot name...), ``fields`` and ``at``;
- ``outcome``: ``op_id`` of its intent, ``outcome``, ``fields`` and ``at``.

``<root>/current`` is a relative symbolic link to the journal of the migration in progress
on this system. Every durable write (journal file and lines, the ``current`` link, files
installed elsewhere) fsyncs the file and its directory.

An intent whose operation creates a resource names the kind of resource in the field
``creates``. ``recover`` understands these kinds, identified by the identity keys shown:

- ``"partition"``: ``partuuid`` (plus ``disk_wwn``, ``disk_serial``, ``disk_by_id``,
  ``start_sectors``, ``size_sectors`` when known);
- ``"luks"``: ``luks_uuid`` (plus ``partuuid`` and the keys above when known);
- ``"filesystem"`` (also a swap area): ``fs_uuid`` (plus the keys above when known).

Any other kind is never reported, because a ``SystemSnapshot`` cannot prove it exists.
Device paths and mapper names, given as ``path``, ``device``, ``mapper`` or
``mapper_name``, only ever add reasons to consider a resource in use.

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
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePath
from typing import Any

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
_NAME_KEYS = ("path", "device", "mapper", "mapper_name")


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
        return isinstance(obj.get("op_id"), str) and isinstance(obj.get("outcome"), str)
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

    A new journal becomes the ``current`` one of ``root``; an existing journal of the same
    ``migration_id`` is reopened and appended to (and becomes ``current`` again).
    ``host_root_uuid`` ties the journal to the system that runs it: ``recover`` only acts on
    the current journal of the running root.
    """

    def __init__(self, root: Path | str = DEFAULT_ROOT, migration_id: str | None = None, *,
                 host_root_uuid: str | None = None):
        self.root = Path(os.path.abspath(root))
        self.migration_id = migration_id if migration_id is not None else uuid.uuid4().hex
        if not _MIGRATION_ID.fullmatch(self.migration_id):
            raise ValueError(f"invalid migration id: {self.migration_id!r}")
        self.path = self.root / f"{_PREFIX}{self.migration_id}{_SUFFIX}"
        self._ops: dict[str, str] = {}
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
        self.host_root_uuid = recorded
        self._ops = {e["op_id"]: e["op"] for e in entries if e["type"] == "intent"}
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
        append_durable(self.path, _encode(entry))

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
        return self.intend(WINDOW_OP, {"window": name})

    def window_close(self, op_id: str) -> None:
        """Record that the window ``op_id`` is closed (after the thaw is proven)."""
        if self._ops.get(op_id) != WINDOW_OP:
            raise ValueError(f"not a freeze window: {op_id!r}")
        self.done(op_id, "closed")

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
    this migration and the running root. Any other journal is archived.
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


def _in_use(identity: dict, fields: dict, v: VolumeIdentity, live: SystemSnapshot,
            roots: set[str]) -> bool:
    uuids = {_norm(x) for x in (identity.get("partuuid"), identity.get("luks_uuid"),
                                identity.get("fs_uuid"), v.partuuid, v.luks_uuid, v.fs_uuid)
             if _norm(x)}
    if uuids & roots:
        return True
    tokens = uuids | {u.replace("-", "") for u in uuids}
    for source in (identity, fields):
        for k in _NAME_KEYS:
            if isinstance(source.get(k), str) and source[k].strip():
                tokens.add(source[k].strip().lower())
    texts = [live.fstab, live.crypttab]
    texts += [f"{m.source} {m.target} {m.options}" for m in live.mounts]
    texts += list(live.mappers)
    for s in live.swaps:
        texts.append(f"{s.path} {s.uuid or ''}")
        if s.luks is not None:
            texts.append(f"{s.luks.luks_uuid} {s.luks.mapper_name or ''}")
    if live.boot_current is not None:
        texts.append(live.boot_entries.get(live.boot_current, ""))
    texts = [t.lower() for t in texts if t]
    return any(tok in text for tok in tokens for text in texts)


def recover(journal_dir: Path | str, live: SystemSnapshot,
            running_root_uuid: str) -> list[Residue]:
    """Resources created by the current migration that still exist and are not in use.

    Only the current journal of the running root is read (see ``current_journal``); a
    resource is reported when its intent says it creates one (with or without an outcome
    line), exactly one live volume carries its pre-assigned identity unchanged, and that
    volume is not mounted, not in fstab, crypttab, the device-mapper table or the active
    swaps, not booted from, and not the running root. Nothing is ever matched by label or
    by name alone.
    """
    path = current_journal(journal_dir, running_root_uuid)
    if path is None:
        return []
    entries = read_journal(path)
    migration_id = entries[0]["migration_id"]
    outcomes: dict[str, str] = {}
    for e in entries:
        if e["type"] == "outcome":
            outcomes[e["op_id"]] = e["outcome"]
    roots = {r for r in (_norm(running_root_uuid), _norm(live.running_root_uuid)) if r}
    residues: list[Residue] = []
    seen: set[tuple[str, str]] = set()
    for e in entries:
        if e["type"] != "intent":
            continue
        kind = e["fields"].get("creates")
        key = _VOLUME_KINDS.get(kind) if isinstance(kind, str) else None
        if key is None:
            continue
        identity = e["identity"]
        match = _match_volume(identity, key, live.identities)
        if match is None or _in_use(identity, e["fields"], match, live, roots):
            continue
        marker = (kind, json.dumps(identity, sort_keys=True))
        if marker in seen:
            continue
        seen.add(marker)
        residues.append(Residue(kind=kind, identity=dict(identity), proof={
            "journal": str(path), "migration_id": migration_id, "op_id": e["op_id"],
            "op": e["op"], "intended_at": e.get("at"), "outcome": outcomes.get(e["op_id"]),
            "live": dataclasses.asdict(match)}))
    return residues
