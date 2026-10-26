"""Configure the copied Debian system before installing its bootloader."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import os
import re
import shlex
import stat

from .config_rewrite import (find_old_uuids, rewrite_crypttab, rewrite_fstab,
                             rewrite_resume, rewrite_rootflags)
from .disk import CryptoPlan
from .journal import write_atomic
from .model import UuidMap
from .swap import SwapResult, resume_target


class OldUuidLeft(ValueError):
    """A destination configuration still uses an old volume identity."""

    def __init__(self, findings: list[tuple[str, str]]):
        super().__init__("old volume identifiers remain in the copied configuration")
        self.findings = findings


def _path(chroot, relative: str) -> Path:
    root = Path(chroot.root)
    path = root / relative
    if (not root.is_absolute() or root.is_symlink() or root.resolve() != root
            or not path.parent.is_dir() or path.parent.resolve() != path.parent
            or path.is_symlink()):
        raise ValueError(f"unsafe copied configuration path: {relative}")
    return path


def _read(chroot, relative: str, *, required: bool = True) -> str:
    path = _path(chroot, relative)
    if not path.exists():
        if required:
            raise FileNotFoundError(path)
        return ""
    if not path.is_file():
        raise ValueError(f"copied configuration is not a regular file: {relative}")
    return path.read_text(encoding="utf-8")


def _save(chroot, relative: str, content: str, *, mode: int | None = None) -> None:
    path = _path(chroot, relative)
    if (path.exists() and path.read_text(encoding="utf-8") == content and
            (mode is None or stat.S_IMODE(path.stat().st_mode) == mode)):
        return
    if mode is None:
        mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    op = chroot.journal.intend("write_system_config", {"path": "/" + relative},
                               destination=path)
    write_atomic(path, content.encode("utf-8"), mode=mode)
    chroot.journal.done(op, "written")


def _grub_cryptodisk(text: str, required: bool) -> str:
    lines = []
    seen = False
    for line in text.splitlines(keepends=True):
        if re.match(r"^\s*GRUB_ENABLE_CRYPTODISK=", line) and not line.lstrip().startswith("#"):
            if seen:
                raise ValueError("duplicate GRUB_ENABLE_CRYPTODISK")
            lines.append("GRUB_ENABLE_CRYPTODISK=" + ("y" if required else "n") + "\n")
            seen = True
        else:
            lines.append(line)
    if required and not seen:
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        lines.append("GRUB_ENABLE_CRYPTODISK=y\n")
    return "".join(lines)


def _resume_from_file(text: str) -> str | None:
    values = [match[1].strip() for line in text.splitlines()
              if (match := re.match(r"^\s*RESUME\s*=\s*(.*)$", line))]
    if len(values) > 1:
        raise ValueError("duplicate RESUME configuration")
    return values[0] if values else None


def _root_old_uuid(fstab: str, m: UuidMap) -> str | None:
    found = []
    for line in fstab.splitlines():
        parts = line.split()
        if parts and not line.lstrip().startswith("#") and len(parts) >= 2 and parts[1] == "/":
            found.append(parts[0][5:] if parts[0].startswith("UUID=") else None)
    if len(found) != 1:
        raise ValueError("copied fstab needs exactly one root entry")
    actual = found[0]
    for old, new in m.fs.items():
        if actual is not None and actual.casefold() == new.casefold():
            return old
    return actual


def _active_crypttab(text: str) -> list[list[str]]:
    return [parts for line in text.splitlines()
            if not line.lstrip().startswith("#") and (parts := line.split())]


def apply_configs(chroot, m: UuidMap, swaps: list[SwapResult], *,
                  root_fs_uuid: str | None = None,
                  filesystem_by_mount: dict[str, str] | None = None,
                  boot_in_luks: bool | None = None) -> None:
    """Rewrite all boot-critical files in memory, validate, then write atomically."""
    fstab = _read(chroot, "etc/fstab")
    crypttab = _read(chroot, "etc/crypttab", required=False)
    if boot_in_luks is None and _active_crypttab(crypttab):
        raise ValueError("boot encryption classification is required")
    boot_in_luks = bool(boot_in_luks)
    grub = _read(chroot, "etc/default/grub")
    resume_conf = _read(chroot, "etc/initramfs-tools/conf.d/resume", required=False)
    source_root_uuid = root_fs_uuid or _root_old_uuid(fstab, m)
    swap_ids = dict(m.swap_uuid)
    for swap in swaps:
        if swap.random_key and swap.source_uuid and (
                any(old.casefold() == swap.source_uuid.casefold() for old in swap_ids)
                or swap.source_uuid.casefold() in fstab.casefold()):
            raise ValueError("random-key swap cannot keep a persistent UUID reference")
        if swap.source_uuid and swap.uuid:
            prior = swap_ids.get(swap.source_uuid)
            if prior is not None and prior.casefold() != swap.uuid.casefold():
                raise ValueError("swap UUID map conflicts with created swap")
            swap_ids[swap.source_uuid] = swap.uuid
        if swap.kind == "file":
            if not swap.source_path.startswith("/") or ".." in Path(swap.source_path).parts:
                raise ValueError("unsafe original swapfile path")
            staged = Path(chroot.root) / swap.source_path.lstrip("/")
            if swap.path != str(staged):
                raise ValueError("swapfile path differs from the copied fstab layout")
    effective = replace(m, swap_uuid=swap_ids)
    new_fstab = rewrite_fstab(fstab, effective, filesystem_by_mount)
    new_crypttab = rewrite_crypttab(crypttab, effective)
    new_resume, new_grub = rewrite_resume(resume_conf, grub,
                                           resume_target(swaps, _resume_from_file(resume_conf)))
    new_grub = rewrite_rootflags(new_grub, effective, source_root_uuid)
    new_grub = _grub_cryptodisk(new_grub, boot_in_luks)
    files = {"etc/fstab": new_fstab, "etc/crypttab": new_crypttab,
             "etc/default/grub": new_grub,
             "etc/initramfs-tools/conf.d/resume": new_resume}
    old = [*m.fs, *m.luks, *m.partuuid, *effective.swap_uuid]
    findings = find_old_uuids(files, old, {})
    if findings:
        raise OldUuidLeft(findings)
    for name, content in files.items():
        _save(chroot, name, content)


def install_crypt_hooks(chroot, crypto: CryptoPlan | None = None,
                        *, boot_in_luks: bool = False) -> None:
    """Include crypttab and only approved early keyfiles in every new initramfs."""
    crypto = crypto or CryptoPlan({}, {}, {}, {}, {})
    crypttab = _read(chroot, "etc/crypttab", required=True)
    specified_keys = {parts[2] for parts in _active_crypttab(crypttab)
                      if len(parts) >= 3 and parts[2] not in {"none", "-", "/dev/urandom"}}
    if specified_keys - set(crypto.keyfiles.values()):
        raise ValueError("crypttab keyfile lacks an approved classification")
    early = []
    for volume_id, keyfile in crypto.keyfiles.items():
        kind = crypto.key_class.get(volume_id)
        if kind not in {"initramfs", "after-root"}:
            raise ValueError("keyfile has no approved boot-time classification")
        if kind == "after-root":
            continue
        if not boot_in_luks:
            raise ValueError("initramfs keyfile would be exposed on unencrypted /boot")
        relative = keyfile.lstrip("/")
        if not keyfile.startswith("/") or ".." in Path(keyfile).parts:
            raise ValueError("unsafe initramfs keyfile path")
        path = _path(chroot, relative)
        if (not path.is_file() or path.stat().st_uid != 0 or
                stat.S_IMODE(path.stat().st_mode) & 0o077):
            raise ValueError("initramfs keyfile is missing or accessible by other users")
        early.append(keyfile)
    lines = ["#!/bin/sh", "set -eu", 'PREREQ=""',
             'prereqs() { echo "$PREREQ"; }',
             'case "${1:-}" in prereqs) prereqs; exit 0;; esac',
             '. /usr/share/initramfs-tools/hook-functions',
             'copy_file config /etc/crypttab /etc/crypttab || [ "$?" -eq 1 ]']
    for keyfile in sorted(set(early)):
        quoted = shlex.quote(keyfile)
        lines.append(f'copy_file config {quoted} {quoted} || [ "$?" -eq 1 ]')
    hook_dir = Path(chroot.root) / "etc/initramfs-tools/hooks"
    if (not hook_dir.parent.is_dir() or hook_dir.parent.resolve() != hook_dir.parent
            or hook_dir.is_symlink()):
        raise ValueError("unsafe initramfs hooks directory")
    if not hook_dir.exists():
        op = chroot.journal.intend("mkdir_initramfs_hooks", {"path": "/etc/initramfs-tools/hooks"})
        hook_dir.mkdir(mode=0o755)
        chroot.journal.done(op, "created")
    _save(chroot, "etc/initramfs-tools/hooks/distromove-crypt", "\n".join(lines) + "\n",
          mode=0o700)


def rebuild_initramfs(chroot) -> list[Path]:
    """Create or update an initramfs for every installed bootable kernel."""
    root = Path(chroot.root)
    boot = root / "boot"
    modules = root / "lib/modules"
    if (not boot.is_dir() or not modules.is_dir() or
            not boot.resolve().is_relative_to(root) or
            not modules.resolve().is_relative_to(root)):
        raise ValueError("copied system lacks boot or kernel modules")
    versions = sorted(path.name[len("vmlinuz-"):] for path in boot.glob("vmlinuz-*")
                      if path.is_file() and not path.is_symlink())
    if not versions:
        raise ValueError("no installed bootable kernels")
    images = []
    for version in versions:
        if (not re.fullmatch(r"[A-Za-z0-9._+-]+", version) or
                not (modules / version).is_dir() or
                not (modules / version).resolve().is_relative_to(root)):
            raise ValueError(f"kernel has no matching modules: {version}")
        image = boot / f"initrd.img-{version}"
        if image.is_symlink():
            raise ValueError(f"unsafe initramfs image path: {version}")
        mode = "-u" if image.exists() else "-c"
        op = chroot.journal.intend("rebuild_initramfs", {"kernel": version}, image=image)
        chroot.run(["update-initramfs", mode, "-k", version])
        if not image.is_file() or image.is_symlink():
            raise RuntimeError(f"initramfs image was not produced: {version}")
        chroot.journal.done(op, "rebuilt")
        images.append(image)
    return images


def _os_release(chroot) -> str:
    """Read /etc/os-release, which is normally a relative link into the copy itself."""
    root = Path(chroot.root)
    link = root / "etc/os-release"
    if not link.is_symlink():
        return _read(chroot, "etc/os-release", required=False)
    target = (link.parent / os.readlink(link)).resolve()
    if not target.is_relative_to(root.resolve()) or not target.is_file():
        return ""
    return target.read_text(encoding="utf-8", errors="replace")


def reset_snapper(chroot) -> bool:
    """Prepare an empty snapshot tree and point SysLinuxOS snapper at the new root."""
    os_release = _os_release(chroot)
    if not re.search(r"^ID=['\"]?syslinuxos['\"]?$", os_release, re.M):
        return False
    snapshots = Path(chroot.root) / ".snapshots"
    if snapshots.is_symlink() or (snapshots.exists() and not snapshots.is_dir()):
        raise ValueError("unsafe snapshots directory")
    if snapshots.exists() and any(snapshots.iterdir()):
        raise ValueError("old snapshots must not be carried into the new system")
    if not snapshots.exists():
        op = chroot.journal.intend("mkdir_snapshots", {"path": "/.snapshots"})
        chroot.run(["btrfs", "subvolume", "create", "/.snapshots"])
        if not snapshots.is_dir():
            raise RuntimeError("new snapshots subvolume was not created")
        chroot.journal.done(op, "created")
    config = _read(chroot, "etc/snapper/configs/root")
    lines = []
    found = False
    for line in config.splitlines(keepends=True):
        if line.startswith("SUBVOLUME="):
            lines.append('SUBVOLUME="/"\n')
            found = True
        else:
            lines.append(line)
    if not found:
        lines.append('SUBVOLUME="/"\n')
    _save(chroot, "etc/snapper/configs/root", "".join(lines))
    return True


def assert_identities(chroot, expected: dict[str, str]) -> None:
    """Prove mounted target paths still point at the expected new filesystem UUIDs."""
    if not expected or "/" not in expected:
        raise ValueError("expected mount identities need a root UUID")
    for mountpoint, expected_uuid in expected.items():
        logical = Path(mountpoint)
        if not logical.is_absolute() or ".." in logical.parts or not expected_uuid:
            raise ValueError("invalid expected mount identity")
        target = Path(chroot.root) / mountpoint.lstrip("/")
        if target.is_symlink() or not target.resolve().is_relative_to(chroot.root):
            raise ValueError("unsafe expected mount path")
        proc = chroot.r.run(["findmnt", "--json", "--nofsroot", "--mountpoint", str(target),
                             "--output", "TARGET,SOURCE,FSTYPE"], readonly=True)
        try:
            rows = json.loads(proc.stdout)["filesystems"]
            if len(rows) != 1 or rows[0]["target"] != str(target):
                raise ValueError
            source = str(rows[0]["source"])
            if source.startswith("UUID="):
                actual = source[5:]
            elif source.startswith("/dev/"):
                actual = chroot.r.run(["blkid", "-p", "-o", "value", "-s", "UUID", source],
                                      readonly=True).stdout.strip()
            else:
                raise ValueError
            if actual.casefold() != expected_uuid.casefold():
                raise ValueError
        except (ValueError, TypeError, KeyError, IndexError) as exc:
            raise ValueError(f"mounted identity differs at {mountpoint}") from exc
