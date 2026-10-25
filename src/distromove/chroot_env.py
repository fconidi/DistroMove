"""Run commands in a fresh private mount namespace around a destination chroot."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

from .journal import Journal
from .runner import Runner


# One namespace per command avoids a persistent helper process and guarantees that
# even SIGKILL of the caller cannot leave bind mounts in the host namespace.
_SCRIPT = r'''
root=$1
shift
dev_mounted=0
proc_mounted=0
sys_mounted=0
run_mounted=0
cleanup() {
    status=$?
    trap - EXIT
    if [ "$run_mounted" = 1 ]; then umount -R "$root/run" || status=1; fi
    if [ "$sys_mounted" = 1 ]; then umount -R "$root/sys" || status=1; fi
    if [ "$proc_mounted" = 1 ]; then umount -R "$root/proc" || status=1; fi
    if [ "$dev_mounted" = 1 ]; then umount -R "$root/dev" || status=1; fi
    exit "$status"
}
trap cleanup EXIT
mount --rbind /dev "$root/dev"
dev_mounted=1
mount --make-rprivate "$root/dev"
mount --rbind /proc "$root/proc"
proc_mounted=1
mount --make-rprivate "$root/proc"
mount --rbind /sys "$root/sys"
sys_mounted=1
mount --make-rprivate "$root/sys"
if mountpoint -q "$root/sys/firmware/efi/efivars"; then
    umount "$root/sys/firmware/efi/efivars"
fi
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs "$root/run"
run_mounted=1
chroot "$root" "$@"
'''


def _mount_source(r: Runner, path: Path, allowed: set[str]) -> str:
    result = r.run(["findmnt", "--json", "--mountpoint", str(path),
                    "--output", "TARGET,SOURCE,FSTYPE"], readonly=True)
    try:
        rows = json.loads(result.stdout)["filesystems"]
        if len(rows) != 1 or rows[0]["target"] != str(path) or rows[0]["fstype"] not in allowed:
            raise ValueError
        source = str(rows[0]["source"])
        if not source.startswith(("/dev/", "UUID=")):
            raise ValueError
        return source
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        raise ValueError(f"destination mount is not verified: {path}") from exc


class Chroot:
    """A command interface for the copied system; every call gets its own namespace."""

    def __init__(self, r: Runner, root: Path | str, esp: Path | None, journal: Journal):
        self.r = r
        self.root = Path(root)
        self.esp = Path(esp) if esp is not None else None
        self.journal = journal
        self._active = False
        self._root_source = ""
        self._esp_source = ""

    def __enter__(self) -> "Chroot":
        root = self.root
        if (not root.is_absolute() or not root.is_dir() or root.is_symlink()
                or root.resolve() != root):
            raise ValueError("chroot root must be an existing real absolute directory")
        for name in ("dev", "proc", "sys", "run", "boot"):
            path = root / name
            if not path.is_dir() or path.is_symlink() or path.resolve() != path:
                raise ValueError(f"unsafe chroot mountpoint: {path}")
        if self.esp is not None:
            if self.esp != root / "boot/efi" or not self.esp.is_dir() or self.esp.is_symlink():
                raise ValueError("ESP must be mounted at the copied system's /boot/efi")
        self._root_source = _mount_source(self.r, root, {"ext4", "btrfs"})
        if self.esp is not None:
            self._esp_source = _mount_source(self.r, self.esp, {"vfat"})
        if not self.journal.is_current():
            raise ValueError("migration journal is not current")
        self._active = True
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self._active = False

    def run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        if not self._active or not argv or any(not isinstance(a, str) or not a or "\x00" in a
                                                for a in argv):
            raise ValueError("chroot command requires an active context and nonempty arguments")
        if _mount_source(self.r, self.root, {"ext4", "btrfs"}) != self._root_source:
            raise ValueError("chroot root mount changed")
        if self.esp is not None and _mount_source(self.r, self.esp, {"vfat"}) != self._esp_source:
            raise ValueError("chroot ESP mount changed")
        op = self.journal.intend("chroot_run", {"root_source": self._root_source,
                                                "esp_source": self._esp_source},
                                 root=self.root, esp=self.esp)
        result = self.r.run(["unshare", "--mount", "--propagation", "private", "--fork",
                             "/bin/sh", "-eu", "-c", _SCRIPT, "distromove", str(self.root),
                             *argv])
        self.journal.done(op, "completed")
        return result
