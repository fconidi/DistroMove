"""Install an isolated EFI GRUB and preserve access to the previous system."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re

from .esp import SecureBootUnsupported, secure_boot_enabled
from .journal import fsync_dir, make_dirs, write_atomic
from .model import LoaderInfo


OLD_ENTRY = Path("etc/grub.d/40_distromove_old")
ID_CONFIG = Path("etc/default/grub.d/40_distromove.cfg")
_MARKER = "#!/bin/sh\n# DistroMove old-system entry\n"
_ID = re.compile(r"[a-z0-9_-]{1,40}\Z")
_ESP_UUID = re.compile(r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}\Z")
_LOADER = re.compile(r"\\EFI\\([A-Za-z0-9_-]{1,40})\\(shimx64|grubx64)\.efi\Z", re.I)


@dataclass(frozen=True)
class SignedChain:
    """Hashes of the binaries already accepted on the currently booted ESP."""

    shim_sha256: str
    grub_sha256: str
    esp_uuid: str


def _safe_file(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise SecureBootUnsupported(f"signed EFI binary unavailable: {path}")
    return path.read_bytes()


def _hash(data: bytes) -> str:
    return sha256(data).hexdigest()


def preflight_signed_chain(r, old_esp: Path, copied_root: Path,
                           loader: LoaderInfo) -> SignedChain:
    """Prove the destination packages match the running shim/GRUB binaries.

    ``loader`` must be the current BootCurrent entry. Run this before
    making any migration write. A mere PE signature is not evidence of trust.
    """
    if not secure_boot_enabled(r):
        raise SecureBootUnsupported("Secure Boot is not enabled")
    match = _LOADER.fullmatch(loader.path)
    if not loader.via_shim or not match or match[2].casefold() != "shimx64":
        raise SecureBootUnsupported("current Secure Boot loader is not shim")
    if match[1].casefold() != loader.bootloader_id.casefold() or not _ESP_UUID.fullmatch(loader.esp_uuid):
        raise SecureBootUnsupported("current loader identity is inconsistent")
    old_esp = Path(old_esp)
    if not old_esp.is_dir() or old_esp.is_symlink():
        raise SecureBootUnsupported("old ESP is not an existing mountpoint")
    try:
        rows = json.loads(r.run(["findmnt", "--json", "--mountpoint", str(old_esp),
                                 "--output", "TARGET,SOURCE,FSTYPE"], readonly=True).stdout)["filesystems"]
        if (len(rows) != 1 or rows[0]["target"] != str(old_esp)
                or rows[0]["fstype"] != "vfat" or not rows[0]["source"].startswith("/dev/")):
            raise ValueError
        actual_uuid = r.run(["blkid", "-p", "-o", "value", "-s", "UUID",
                             rows[0]["source"]], readonly=True).stdout.strip()
    except (ValueError, KeyError, TypeError, IndexError) as exc:
        raise SecureBootUnsupported("old ESP mount identity cannot be verified") from exc
    if actual_uuid.casefold() != loader.esp_uuid.casefold():
        raise SecureBootUnsupported("old ESP UUID differs from BootCurrent")
    old_dir = Path(old_esp) / "EFI" / loader.bootloader_id
    if old_dir.is_symlink():
        raise SecureBootUnsupported("old EFI directory is a symlink")
    old_shim = _hash(_safe_file(old_dir / "shimx64.efi"))
    old_grub = _hash(_safe_file(old_dir / "grubx64.efi"))
    root = Path(copied_root)
    package_shim = _hash(_safe_file(root / "usr/lib/shim/shimx64.efi.signed"))
    package_grub = _hash(_safe_file(root / "usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed"))
    if (old_shim, old_grub) != (package_shim, package_grub):
        raise SecureBootUnsupported("signed packages differ from the currently booted EFI chain")
    return SignedChain(old_shim, old_grub, loader.esp_uuid)


def old_system_entry(loader: LoaderInfo, esp_uuid: str, encrypted: bool,
                     osprober_sees_it: bool) -> str | None:
    if not encrypted and osprober_sees_it:
        return None
    match = _LOADER.fullmatch(loader.path)
    if (not match or match[1].casefold() != loader.bootloader_id.casefold()
            or esp_uuid.casefold() != loader.esp_uuid.casefold()
            or not _ESP_UUID.fullmatch(esp_uuid)):
        raise ValueError("invalid old loader or ESP identity")
    return (_MARKER + 'exec tail -n +4 "$0"\n'
            "menuentry 'Previous system' --id=distromove-old {\n"
            "    insmod part_gpt\n"
            "    insmod fat\n"
            f"    search --no-floppy --fs-uuid --set=root {esp_uuid}\n"
            f"    chainloader {loader.path.replace(chr(92), '/')}\n"
            "}\n")


def _file(chroot, relative: Path) -> Path:
    root = Path(chroot.root)
    if not root.is_absolute() or root.is_symlink() or root.resolve() != root:
        raise ValueError("unsafe copied root")
    path = root / relative
    if (path.is_symlink() or path.parent.is_symlink()
            or not path.parent.resolve().is_relative_to(root)):
        raise ValueError("configuration path is a symlink")
    make_dirs(path.parent, 0o755)
    return path


def install_old_entry(chroot, script: str | None) -> None:
    if script is None:
        return
    if not script.startswith(_MARKER) or "\x00" in script:
        raise ValueError("invalid old-system GRUB script")
    path = _file(chroot, OLD_ENTRY)
    if path.exists() and not path.read_text().startswith(_MARKER):
        raise ValueError("old-system GRUB script path is occupied")
    op = chroot.journal.intend("old_grub_entry", {"path": str(OLD_ENTRY)})
    write_atomic(path, script.encode(), 0o755)
    chroot.journal.done(op, "installed")


def persist_bootloader_id(chroot, bootloader_id: str) -> None:
    if not _ID.fullmatch(bootloader_id):
        raise ValueError("invalid EFI bootloader identifier")
    path = _file(chroot, ID_CONFIG)
    if path.exists() and not path.read_text().startswith("# DistroMove EFI identifier\n"):
        raise ValueError("EFI identifier config path is occupied")
    op = chroot.journal.intend("persist_bootloader_id", {"bootloader_id": bootloader_id})
    write_atomic(path, ("# DistroMove EFI identifier\n"
                        f'GRUB_DISTRIBUTOR="{bootloader_id}"\n').encode(), 0o644)
    chroot.journal.done(op, "installed")


def install_grub(chroot, bootloader_id: str, *, secure_boot: bool = False,
                 signed_chain: SignedChain | None = None) -> None:
    if not _ID.fullmatch(bootloader_id):
        raise ValueError("invalid EFI bootloader identifier")
    if chroot.esp != chroot.root / "boot/efi":
        raise ValueError("verified destination ESP is required")
    efi = Path(chroot.esp) / "EFI"
    if efi.is_symlink() or (efi.exists() and any(
            child.name.casefold() == bootloader_id.casefold() for child in efi.iterdir())):
        raise ValueError("EFI bootloader directory is already occupied")
    if secure_boot and signed_chain is None:
        raise SecureBootUnsupported("Secure Boot requires a verified running chain")
    if secure_boot:
        root = Path(chroot.root)
        if (_hash(_safe_file(root / "usr/lib/shim/shimx64.efi.signed")) != signed_chain.shim_sha256
                or _hash(_safe_file(root / "usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed"))
                != signed_chain.grub_sha256):
            raise SecureBootUnsupported("signed packages changed since preflight")
    argv = ["grub-install", "--target=x86_64-efi", "--efi-directory=/boot/efi",
            f"--bootloader-id={bootloader_id}", "--no-nvram"]
    if secure_boot:
        argv.append("--uefi-secure-boot")
    chroot.run(argv)
    if secure_boot:
        dest = Path(chroot.esp) / "EFI" / bootloader_id
        if (_hash(_safe_file(dest / "shimx64.efi")) != signed_chain.shim_sha256
                or _hash(_safe_file(dest / "grubx64.efi")) != signed_chain.grub_sha256):
            raise SecureBootUnsupported("installed EFI chain differs from verified binaries")


def update_grub(chroot) -> None:
    chroot.run(["update-grub"])


def remove_old_entry(chroot) -> None:
    path = _file(chroot, OLD_ENTRY)
    if path.exists():
        if not path.read_text().startswith(_MARKER):
            raise ValueError("old-system GRUB script was replaced")
        op = chroot.journal.intend("remove_old_grub_entry", {"path": str(OLD_ENTRY)})
        path.unlink()
        fsync_dir(path.parent)
        chroot.journal.done(op, "removed")
    update_grub(chroot)
