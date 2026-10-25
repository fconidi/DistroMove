"""Copy live ext4 volumes, then reconcile them under a bounded coordinated freeze."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import time
from typing import Callable

from .journal import Journal, read_journal
from .manifest import build_manifest
from .model import Manifest, MountInfo
from .runner import Runner


RSYNC_ARGS = ["-aAXHS", "--numeric-ids", "--one-file-system"]


class FreezeFailed(RuntimeError):
    """The source could not be frozen or safely thawed."""


class FreezeTooLong(FreezeFailed):
    """Convergence or the final frozen pass exceeded its deadline."""


@dataclass(frozen=True)
class CopyPair:
    source: Path
    destination: Path
    mountpoint: Path
    destination_fs_uuid: str
    filters: tuple[str, ...] = ()


@dataclass(frozen=True)
class PassStats:
    seconds: float
    files: int
    started_at: float


@dataclass(frozen=True)
class FreezeStats:
    seconds: float
    changed_files: int
    manifest: Manifest
    manifests: dict[str, Manifest]


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _relative(path: Path, root: Path) -> str:
    if not _inside(path, root) or path == root:
        raise ValueError(f"path is not a child of {root}: {path}")
    return path.relative_to(root).as_posix()


def _escape_filter(path: str) -> str:
    # An anchored rsync filter uses globs. Quote metacharacters in real names.
    return "".join("\\" + ch if ch in "*?[]\\" else ch for ch in path)


def _manifest_excludes(filters: tuple[str, ...]) -> tuple[str, ...]:
    paths = []
    for flag in filters:
        if not flag.startswith("--exclude=/"):
            raise ValueError("only anchored exclusion filters are supported")
        value = flag[len("--exclude=/"):]
        if value.endswith("/***"):
            value = value[:-4]
        value = re.sub(r"\\([*?\[\]\\])", r"\1", value)
        if not value or value.startswith("/") or ".." in Path(value).parts:
            raise ValueError("unsafe exclusion filter")
        paths.append(value)
    return tuple(paths)


def volume_filters(volume_root: Path | str, mounts: list[MountInfo | str | Path],
                   old_swapfiles: list[str | Path]) -> list[str]:
    """Protect child mounts and old swapfiles from both copying and deletion."""
    root = Path(volume_root).resolve(strict=True)
    protected = set()
    for mount in mounts:
        target = mount.target if isinstance(mount, MountInfo) else mount
        child = Path(target)
        if child.is_absolute() and _inside(child, root) and child != root:
            protected.add("/" + _escape_filter(_relative(child, root)) + "/***")
    for item in old_swapfiles:
        path = Path(item)
        if path.is_absolute() and _inside(path, root) and path != root:
            protected.add("/" + _escape_filter(_relative(path, root)))
    return ["--exclude=" + rule for rule in sorted(protected)]


def _verify_destination_mount(r: Runner, pair: CopyPair) -> None:
    target = str(Path(pair.destination).resolve(strict=True))
    proc = r.run(["findmnt", "--json", "--nofsroot", "--mountpoint", target,
                  "--output", "TARGET,SOURCE,FSTYPE"], readonly=True)
    try:
        rows = json.loads(proc.stdout)["filesystems"]
        if len(rows) != 1 or rows[0]["target"] != target or rows[0]["fstype"] != "ext4":
            raise ValueError
        source = rows[0]["source"]
        if source.startswith("UUID="):
            actual = source[5:]
        elif source.startswith("/dev/"):
            actual = r.run(["blkid", "-p", "-o", "value", "-s", "UUID", source],
                           readonly=True).stdout.strip()
        else:
            raise ValueError
        if actual.casefold() != pair.destination_fs_uuid.casefold():
            raise ValueError
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        raise ValueError(f"destination mount identity changed: {target}") from exc


def _check_pairs(pairs: list[CopyPair], journal: Journal | None = None,
                 r: Runner | None = None) -> None:
    if not pairs:
        raise ValueError("no ext4 volumes to copy")
    if journal is not None and not journal.is_current():
        raise ValueError("migration journal is no longer current")
    destinations = set()
    entries = read_journal(journal.path) if journal is not None else []
    intents = {e["op_id"]: e for e in entries if e["type"] == "intent"}
    mounted = {(intents[e["op_id"]]["fields"].get("path"),
                intents[e["op_id"]]["identity"].get("fs_uuid"))
               for e in entries if e["type"] == "outcome" and e["outcome"] == "mounted"
               and e["op_id"] in intents and intents[e["op_id"]]["op"] == "mount_destination"}
    for pair in pairs:
        src = Path(pair.source).resolve(strict=True)
        dst = Path(pair.destination).resolve(strict=True)
        mount = Path(pair.mountpoint).resolve(strict=True)
        if (not src.is_dir() or not dst.is_dir() or not mount.is_dir() or src != mount
                or _inside(dst, src) or _inside(src, dst) or dst in destinations
                or not pair.destination_fs_uuid):
            raise ValueError("invalid source or destination root")
        _manifest_excludes(pair.filters)
        if journal is not None and (str(dst), pair.destination_fs_uuid) not in mounted:
            raise ValueError("destination is not a verified mount of this migration")
        if r is not None:
            _verify_destination_mount(r, pair)
        destinations.add(dst)
    for parent in pairs:
        parent_src = Path(parent.source).resolve(strict=True)
        for child in pairs:
            child_src = Path(child.source).resolve(strict=True)
            if child_src != parent_src and _inside(child_src, parent_src):
                exclusion = "--exclude=/" + _escape_filter(_relative(child_src, parent_src)) + "/***"
                if exclusion not in parent.filters:
                    raise ValueError(f"child volume is not protected from deletion: {child_src}")


def _rsync(r: Runner, pair: CopyPair, extra: list[str], *, input: bytes | None = None) -> str:
    src = Path(pair.source).resolve(strict=True)
    dst = Path(pair.destination).resolve(strict=True)
    command = ["rsync", *RSYNC_ARGS, *pair.filters, *extra,
               str(src).rstrip("/") + "/", str(dst).rstrip("/") + "/"]
    return r.run(command, input=input).stdout


def hot_pass(r: Runner, src: Path | str, dst: Path | str, filters: list[str],
             on_progress: Callable[[PassStats], None] | None = None) -> PassStats:
    pair = CopyPair(Path(src), Path(dst), Path(src), "unverified", tuple(filters))
    _check_pairs([pair])
    started_at = time.time()
    began = time.monotonic()
    out = _rsync(r, pair, ["--stats"])
    match = re.search(r"^Number of regular files transferred:\s*([\d,]+)", out, re.M)
    if not match:
        raise ValueError("rsync did not report the transfer count")
    stats = PassStats(time.monotonic() - began, int(match.group(1).replace(",", "")), started_at)
    if on_progress is not None:
        on_progress(stats)
    return stats


def changed_since(r: Runner, root: Path | str, started_at: float) -> list[str]:
    """Return relative paths whose ctime changed since the first hot pass."""
    base = Path(root).resolve(strict=True)
    if not base.is_dir() or started_at <= 0:
        raise ValueError("invalid source or start time")
    out = r.run(["find", str(base), "-xdev", "-newerct", f"@{started_at:.9f}",
                 "-printf", "%P\\0"], readonly=True,
                encoding_errors="surrogateescape").stdout
    paths = out.split("\0")
    if paths[-1] != "":
        raise ValueError("incomplete find output")
    return sorted({p for p in paths[:-1] if p and not p.startswith("/")
                   and ".." not in Path(p).parts})


def _probe_thawed(mountpoint: Path, timeout: float = 1.0,
                  close_fd: int | None = None) -> bool:
    """Write an anonymous ext4 probe file in a child that may be blocked by freeze."""
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        if close_fd is not None:
            os.close(close_fd)
        try:
            fd = os.open(mountpoint, os.O_TMPFILE | os.O_WRONLY, 0o600)
            try:
                os.write(fd, b"ok")
            finally:
                os.close(fd)
            os.write(write_fd, b"1")
        except OSError:
            pass
        finally:
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    try:
        ready, _, _ = select.select([read_fd], [], [], timeout)
        ok = bool(ready and os.read(read_fd, 1) == b"1")
        if not ok:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        os.waitpid(pid, os.WNOHANG if not ok else 0)
        return ok
    finally:
        os.close(read_fd)


def _unfreeze_real(mountpoint: Path) -> None:
    try:
        subprocess.run(["fsfreeze", "-u", str(mountpoint)], check=False,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _watchdog_loop(control_fd: int, mountpoints: tuple[Path, ...], max_seconds: float,
                   *, thaw: Callable[[Path], None] = _unfreeze_real,
                   probe: Callable[[Path], bool] = _probe_thawed,
                   clock: Callable[[], float] = time.monotonic) -> None:
    """After deadline/EOF, keep retrying thaw, including a late completed freeze."""
    deadline = None
    lost_at = None
    closed = False
    while True:
        now = clock()
        if not closed:
            wait = 1.0 if deadline is None else min(0.25, max(0.0, deadline - now))
            ready, _, _ = select.select([control_fd], [], [], wait)
            if ready:
                data = os.read(control_fd, 1)
                if data == b"D":
                    return
                if data == b"S":
                    deadline = clock() + max_seconds
                    continue
                if not data:
                    closed = True
                    lost_at = clock()
        if not closed and (deadline is None or clock() < deadline):
            continue
        for mountpoint in reversed(mountpoints):
            thaw(mountpoint)
        all_open = all(probe(mountpoint) for mountpoint in mountpoints)
        if closed and all_open and clock() - lost_at >= max(0.5, max_seconds):
            return
        time.sleep(0.25)


class FreezeGroup:
    """Freeze all ext4 sources together with an independent thaw watchdog."""

    def __init__(self, r: Runner, mountpoints: list[Path | str], journal: Journal,
                 max_seconds: float):
        mounts = tuple(Path(p).resolve(strict=True) for p in mountpoints)
        if not mounts or len(set(mounts)) != len(mounts) or max_seconds <= 0:
            raise ValueError("invalid freeze group")
        self.r, self.mountpoints, self.journal = r, mounts, journal
        self.max_seconds = max_seconds
        self.started_at: float | None = None
        self.window_id: str | None = None
        self._watchdog_pid: int | None = None
        self._control_fd: int | None = None
        self._frozen: list[Path] = []

    def _start_watchdog(self) -> None:
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(write_fd)
            try:
                os.setsid()
                _watchdog_loop(read_fd, self.mountpoints, self.max_seconds)
            finally:
                os.close(read_fd)
                os._exit(0)
        os.close(read_fd)
        self._watchdog_pid, self._control_fd = pid, write_fd

    def _stop_watchdog(self, proven: bool) -> None:
        if self._control_fd is not None:
            if proven:
                try:
                    os.write(self._control_fd, b"D")
                except BrokenPipeError:
                    pass
            os.close(self._control_fd)
            self._control_fd = None
        if proven and self._watchdog_pid is not None:
            os.waitpid(self._watchdog_pid, 0)
            self._watchdog_pid = None

    def __enter__(self) -> FreezeGroup:
        self.window_id = self.journal.window_open("ext4-final-copy")
        try:
            self._start_watchdog()
        except BaseException:
            self.journal.window_close(self.window_id)
            raise
        try:
            for mountpoint in self.mountpoints:
                self.r.run(["fsfreeze", "-f", str(mountpoint)])
                self._frozen.append(mountpoint)
                if self.started_at is None:
                    self.started_at = time.monotonic()
                    os.write(self._control_fd, b"S")
            self.ensure_active()
            return self
        except BaseException:
            self._thaw()
            raise

    def ensure_active(self) -> None:
        if self.started_at is None:
            raise FreezeFailed("no filesystem has been frozen")
        if time.monotonic() - self.started_at > self.max_seconds:
            raise FreezeTooLong("ext4 freeze deadline exceeded")

    def _thaw(self) -> None:
        for mountpoint in reversed(self.mountpoints):
            self.r.run(["fsfreeze", "-u", str(mountpoint)], check=False)
        proven = all(_probe_thawed(p, close_fd=self._control_fd) for p in self.mountpoints)
        self._stop_watchdog(proven)
        if not proven:
            raise FreezeFailed("could not prove every filesystem thawed; watchdog remains active")
        self.journal.window_close(self.window_id)

    def __exit__(self, _type, _value, _traceback) -> None:
        self._thaw()


def reconcile_pass(r: Runner, pairs: list[CopyPair], group: FreezeGroup) -> None:
    group.ensure_active()
    _check_pairs(pairs, group.journal, r)
    for pair in pairs:
        group.ensure_active()
        _rsync(r, pair, ["--delete"])


def checksum_candidates_pass(r: Runner, pairs: list[CopyPair], group: FreezeGroup,
                             started_at: float) -> int:
    group.ensure_active()
    _check_pairs(pairs, group.journal, r)
    changed = 0
    for pair in pairs:
        group.ensure_active()
        paths = changed_since(r, pair.source, started_at)
        if not paths:
            continue
        payload = b"\0".join(os.fsencode(p) for p in paths) + b"\0"
        _rsync(r, pair, ["--checksum", "--from0", "--files-from=-"], input=payload)
        changed += len(paths)
    return changed


def final_pass(r: Runner, pairs: list[CopyPair], group: FreezeGroup,
               started_at: float) -> FreezeStats:
    reconcile_pass(r, pairs, group)
    changed = checksum_candidates_pass(r, pairs, group, started_at)
    manifests = {}
    for pair in pairs:
        group.ensure_active()
        manifests[str(pair.source)] = build_manifest(pair.source, kind="ext4-frozen",
                                                    exclude_paths=_manifest_excludes(pair.filters))
    group.ensure_active()
    root = next((pair for pair in pairs if str(pair.mountpoint) == "/"), pairs[0])
    return FreezeStats(time.monotonic() - group.started_at, changed,
                       manifests[str(root.source)], manifests)


def copy_ext4(r: Runner, pairs: list[CopyPair], journal: Journal,
              on_progress: Callable[[PassStats], None] | None = None,
              threshold_s: float = 20.0, max_rounds: int = 4) -> FreezeStats:
    _check_pairs(pairs, journal, r)
    if threshold_s <= 0 or max_rounds < 1:
        raise ValueError("invalid convergence limit")
    began = None
    for _ in range(max_rounds):
        results = [hot_pass(r, p.source, p.destination, list(p.filters), on_progress) for p in pairs]
        began = results[0].started_at if began is None else began
        if sum(item.seconds for item in results) <= threshold_s:
            break
    else:
        raise FreezeTooLong("ext4 copy did not converge before freeze")
    group = FreezeGroup(r, [p.mountpoint for p in pairs], journal, threshold_s)
    with group:
        result = final_pass(r, pairs, group, began)
    return result
