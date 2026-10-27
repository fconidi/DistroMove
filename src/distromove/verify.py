"""Read-only checks of a copied system before its firmware entry is activated."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
from typing import Mapping

from .config_rewrite import find_old_uuids
from .manifest import build_manifest
from .model import Manifest


@dataclass(frozen=True)
class Finding:
    severity: str
    check: str
    detail: str


@dataclass(frozen=True)
class VerifyReport:
    findings: list[Finding]

    @property
    def ok(self) -> bool:
        return not any(item.severity == "error" for item in self.findings)


def _error(check: str, detail: str) -> Finding:
    return Finding("error", check, detail)


def _relative(value: str) -> str:
    path = PurePosixPath(value)
    if (not value or value.startswith("/") or str(path) != value
            or value == "." or ".." in path.parts):
        raise ValueError(f"unsafe relative path: {value!r}")
    return value


def verify_copy(reference: Manifest, dst: Path,
                expected_diffs: set[str], *, exclude_paths: tuple[str, ...] = (),
                exclude_names: tuple[str, ...] = (),
                expected_trees: tuple[str, ...] = (),
                expected_mtime_paths: tuple[str, ...] = ()) -> list[Finding]:
    """Compare the destination only with a stable, already captured reference."""
    ignored = {_relative(value) for value in expected_diffs}
    trees = tuple(_relative(value) for value in expected_trees)
    expected_mtimes = {_relative(value) for value in expected_mtime_paths}
    ignored.update(trees)
    excluded = tuple(_relative(value) for value in exclude_paths)
    if any("/" in name or name in {"", ".", ".."} for name in exclude_names):
        raise ValueError("invalid excluded entry name")
    if not reference.entries and not exclude_paths:
        # emptiness is only legitimate when every child was excluded (a top-level of subvolumes)
        return [_error("copy", "reference manifest is empty")]
    for path in reference.entries:
        _relative(path)
    if not Path(dst).is_dir() or Path(dst).is_symlink():
        return [_error("copy", "destination tree is unavailable")]
    hashed = tuple(path for path, entry in reference.entries.items()
                   if entry.sha256 is not None and path not in ignored
                   and not any(path.startswith(tree + "/") for tree in trees))
    actual = build_manifest(dst, hash_paths=hashed, sample=0, kind=reference.kind,
                            exclude_paths=excluded, exclude_names=exclude_names)
    findings = []
    for path in sorted(set(reference.entries) | set(actual.entries)):
        if path in ignored or any(path.startswith(tree + "/") for tree in trees):
            continue
        old, new = reference.entries.get(path), actual.entries.get(path)
        if old is None or new is None:
            findings.append(_error("copy", f"{path}: unexpected extra or missing path"))
            continue
        fields = ("mode", "uid", "gid", "size", "mtime", "sha256")
        for field in fields:
            if field == "mtime" and path in expected_mtimes:
                continue
            if field == "mtime" and stat.S_ISDIR(old.mode) and any(
                    changed.startswith(path + "/") for changed in ignored):
                continue
            if getattr(old, field) != getattr(new, field):
                findings.append(_error("copy", f"{path}: {field} differs"))
    return findings


def _read(root: Path, relative: str) -> str | None:
    path = root / relative
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        return None
    if not path.exists():
        return None
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def verify_transformations(root: Path, new_uuids: set[str], old_uuids: set[str],
                           allowed_roles: Mapping[str, set[str]], *,
                           root_sources: set[str] | None = None) -> list[Finding]:
    """Check new boot configuration; old IDs are allowed only in the old entry."""
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        return [_error("config", "copied root is unavailable")]
    if set(allowed_roles) - {"old_entry"}:
        raise ValueError("only the old entry can allow an old UUID")
    allowed_old = {value.casefold() for value in allowed_roles.get("old_entry", set())}
    if allowed_old - {value.casefold() for value in old_uuids}:
        raise ValueError("allowed old-entry UUID is not an old identity")
    files = ("etc/fstab", "etc/crypttab", "etc/default/grub",
             "etc/initramfs-tools/conf.d/resume", "boot/grub/grub.cfg")
    findings = []
    old_grub_entry = ""
    for relative in files:
        content = _read(root, relative)
        if content is None:
            if relative in {"etc/fstab", "etc/default/grub", "boot/grub/grub.cfg"}:
                findings.append(_error("config", f"{relative}: missing or unsafe"))
            continue
        if relative == "boot/grub/grub.cfg":
            content, old_grub_entry = _split_old_grub_entry(content)
            for name, value in find_old_uuids({relative: old_grub_entry}, old_uuids, {}):
                if value.casefold() not in allowed_old:
                    findings.append(_error("config", f"{name}: unapproved old UUID {value}"))
        for name, value in find_old_uuids({relative: content}, old_uuids, {}):
            findings.append(_error("config", f"{name}: old UUID {value}"))
    old_script = _read(root, "etc/grub.d/40_distromove_old")
    if (root / "etc/grub.d/40_distromove_old").is_symlink():
        findings.append(_error("config", "old-system entry is a symlink"))
    if old_script is not None:
        if not old_script.startswith("#!/bin/sh\n# DistroMove old-system entry\n"):
            findings.append(_error("config", "old-system entry has an unexpected owner"))
        for name, value in find_old_uuids({"etc/grub.d/40_distromove_old": old_script},
                                          old_uuids, {}):
            if value.casefold() not in allowed_old:
                findings.append(_error("config", f"{name}: unapproved old UUID {value}"))
    if allowed_old and not any(value in (old_script or "").casefold() +
                               old_grub_entry.casefold() for value in allowed_old):
        findings.append(_error("config", "old-system menu entry is absent"))
    fstab = _read(root, "etc/fstab")
    if fstab is not None and new_uuids:
        roots = [line.split()[0] for line in fstab.splitlines()
                 if not line.lstrip().startswith("#") and len(line.split()) >= 2
                 and line.split()[1] == "/"]
        expected = root_sources if root_sources is not None else {
            "UUID=" + value for value in new_uuids}
        valid = len(roots) == 1 and any(
            roots[0] == value if value.startswith("/dev/mapper/")
            else roots[0].casefold() == value.casefold() for value in expected)
        if not valid:
            findings.append(_error("config", "fstab root does not identify the new filesystem"))
    return findings


def _split_old_grub_entry(content: str) -> tuple[str, str]:
    normal, old = [], []
    block = []
    depth = 0
    for line in content.splitlines(keepends=True):
        if not block and re.search(
                r"^\s*menuentry\b.*--id(?:=|\s+)['\"]?"
                r"(?:distromove-old|osprober-[A-Za-z0-9_-]+)\b", line):
            block = [line]
            depth = line.count("{") - line.count("}")
            if depth <= 0 and "{" in line:
                old.extend(block)
                block = []
            continue
        if block:
            block.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0 and any("{" in item for item in block):
                old.extend(block)
                block = []
        else:
            normal.append(line)
    normal.extend(block)  # incomplete blocks are never granted the exception
    return "".join(normal), "".join(old)


def check_initramfs(r, root: Path, luks: bool,
                    required_keyfiles: set[str] | None = None) -> list[Finding]:
    root = Path(root)
    boot = root / "boot"
    kernels = sorted(boot.glob("vmlinuz-*") if boot.is_dir() else [])
    if not kernels:
        return [_error("initramfs", "no bootable kernel found")]
    hook = _read(root, "etc/initramfs-tools/hooks/distromove-crypt") or ""
    keyfiles = set()
    for line in hook.splitlines():
        try:
            words = shlex.split(line, comments=True)
        except ValueError:
            return [_error("initramfs", "invalid crypt hook")]
        if len(words) >= 4 and words[:2] == ["copy_file", "config"]:
            if words[2] != "/etc/crypttab":
                keyfiles.add(words[2].lstrip("/"))
    if required_keyfiles is not None:
        for path in required_keyfiles:
            if not path.startswith("/") or ".." in Path(path).parts:
                raise ValueError("invalid required initramfs keyfile path")
        keyfiles.update(path.lstrip("/") for path in required_keyfiles)
    findings = []
    if luks and _read(root, "etc/crypttab") is None:
        findings.append(_error("initramfs", "copied crypttab is missing"))
    for kernel in kernels:
        version = kernel.name[len("vmlinuz-"):]
        image = boot / f"initrd.img-{version}"
        if (kernel.is_symlink() or not kernel.is_file() or image.is_symlink()
                or not image.is_file()):
            findings.append(_error("initramfs", f"kernel {version}: image missing or unsafe"))
            continue
        try:
            result = r.run(["lsinitramfs", str(image)], readonly=True)
            entries = {line.lstrip("./") for line in result.stdout.splitlines()}
        except Exception:
            findings.append(_error("initramfs", f"kernel {version}: image cannot be listed"))
            continue
        if not any(entry.startswith((f"lib/modules/{version}/", f"usr/lib/modules/{version}/"))
                   for entry in entries):
            findings.append(_error("initramfs", f"kernel {version}: modules missing"))
        if luks and "etc/crypttab" not in entries:
            findings.append(_error("initramfs", f"kernel {version}: crypttab missing"))
        for keyfile in keyfiles if luks else ():
            if keyfile not in entries:
                findings.append(_error("initramfs", f"kernel {version}: keyfile {keyfile} missing"))
    return findings


def check_unlock(r, devices: list[str],
                 credentials: Mapping[str, bytes | list[bytes]]) -> list[Finding]:
    """Try every planned credential without opening a device-mapper mapping."""
    if not devices:
        return [_error("unlock", "no encrypted devices supplied for verification")]
    findings = []
    for device in devices:
        keys = credentials.get(device)
        if isinstance(keys, bytes):
            keys = [keys]
        if (not device.startswith("/dev/") or ".." in Path(device).parts
                or not isinstance(keys, list) or not keys
                or any(not isinstance(key, bytes) or not key for key in keys)):
            findings.append(_error("unlock", f"{device}: credential or device is invalid"))
            continue
        for index, key in enumerate(keys, start=1):
            try:
                result = r.run(["cryptsetup", "open", "--test-passphrase", "--key-file", "-",
                                device], input=key, secret_input=True,
                               readonly=True, check=False)
                if result.returncode:
                    findings.append(_error("unlock", f"{device}: credential {index} did not unlock"))
            except Exception:
                findings.append(_error("unlock", f"{device}: credential {index} test failed"))
    return findings


def check_esp(esp: Path, bootloader_id: str) -> list[Finding]:
    if not re.fullmatch(r"[a-z0-9_-]{1,40}", bootloader_id):
        raise ValueError("invalid bootloader ID")
    esp = Path(esp)
    directory = esp / "EFI" / bootloader_id
    if (esp.is_symlink() or (esp / "EFI").is_symlink()
            or directory.is_symlink() or not directory.is_dir()):
        return [_error("esp", f"EFI/{bootloader_id}: loader directory missing or unsafe")]
    findings = []
    shim = directory / "shimx64.efi"
    has_shim = shim.exists() or shim.is_symlink()
    required = ("grubx64.efi", "grub.cfg") if has_shim else ("grubx64.efi",)
    for name in required:
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            findings.append(_error("esp", f"EFI/{bootloader_id}/{name}: missing or empty"))
    if has_shim and (shim.is_symlink() or not shim.is_file() or shim.stat().st_size == 0):
        findings.append(_error("esp", f"EFI/{bootloader_id}/shimx64.efi: invalid"))
    return findings


def check_identities(mounts: Mapping[str, str],
                     expected: Mapping[str, str]) -> list[Finding]:
    """Compare freshly probed mountpoint→filesystem-UUID mappings."""
    findings = []
    if "/" not in expected:
        raise ValueError("expected mount identities need a root UUID")
    for mountpoint, uuid in expected.items():
        if not mountpoint.startswith("/") or not uuid:
            raise ValueError("invalid expected mount identity")
        actual = mounts.get(mountpoint)
        if actual is None or actual.casefold() != uuid.casefold():
            findings.append(_error("identity", f"{mountpoint}: mounted filesystem UUID differs"))
    return findings
