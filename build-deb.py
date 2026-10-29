#!/usr/bin/python3
"""Build the Debian package from an explicit runtime-file allowlist."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent
MODULES = ROOT / "src/distromove"
RUNTIME_MODULES = (
    "__init__.py", "__main__.py", "boot_install.py", "chroot_env.py", "cleanup.py",
    "config_rewrite.py", "copy_btrfs.py", "copy_ext4.py", "disk.py", "engine.py",
    "esp.py", "gui.py", "helper.py", "i18n.py", "journal.py", "layout.py",
    "manifest.py", "model.py", "probe.py", "probe_parse.py", "runner.py",
    "safety.py", "state.py", "swap.py", "system_config.py", "verify.py",
)
DEPENDS = (
    "python3 (>= 3.11)", "python3-gi", "gir1.2-gtk-3.0", "cryptsetup", "rsync",
    "btrfs-progs (>= 6.1)", "e2fsprogs", "dosfstools", "parted", "util-linux",
    "efibootmgr", "grub-efi-amd64-bin", "grub-efi-amd64-signed", "shim-signed",
    "mokutil", "pkexec", "polkitd", "gdisk", "udev", "initramfs-tools",
    "dmsetup", "procps", "findutils",
)


def copy(source: Path, destination: Path, *, executable: bool = False) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o755 if executable else 0o644)


def version() -> str:
    content = (MODULES / "__init__.py").read_text()
    match = re.search(r'^__version__ = "([0-9]+\.[0-9]+\.[0-9]+)"$', content, re.M)
    if match is None:
        raise ValueError("missing package version")
    return match[1]


def build(output: Path) -> Path:
    output = output.expanduser().resolve()
    source = ROOT.resolve()
    if output == source or source in output.parents:
        raise ValueError("package output must be outside the source tree")
    output.mkdir(parents=True, exist_ok=True)
    release = version()
    artifact = output / f"distromove_{release}_all.deb"
    with tempfile.TemporaryDirectory(prefix="distromove-package-", dir=output) as temp:
        root = Path(temp)
        root.chmod(0o755)
        for name in RUNTIME_MODULES:
            copy(MODULES / name, root / "usr/share/distromove/distromove" / name)
        copy(ROOT / "packaging/distromove", root / "usr/bin/distromove", executable=True)
        copy(ROOT / "packaging/helper", root / "usr/lib/distromove/helper", executable=True)
        copy(ROOT / "packaging/org.syslinuxos.DistroMove.desktop",
             root / "usr/share/applications/org.syslinuxos.DistroMove.desktop")
        copy(ROOT / "assets/org.syslinuxos.DistroMove.svg",
             root / "usr/share/icons/hicolor/scalable/apps/org.syslinuxos.DistroMove.svg")
        copy(ROOT / "assets/org.syslinuxos.DistroMoveTools.svg",
             root / "usr/share/icons/hicolor/scalable/categories/org.syslinuxos.DistroMoveTools.svg")
        copy(ROOT / "packaging/distromove-tools.directory",
             root / "usr/share/desktop-directories/distromove-tools.directory")
        copy(ROOT / "packaging/org.syslinuxos.distromove.policy",
             root / "usr/share/polkit-1/actions/org.syslinuxos.distromove.policy")
        copy(ROOT / "packaging/distromove.menu",
             root / "etc/xdg/menus/applications-merged/distromove.menu")
        copy(ROOT / "README.md", root / "usr/share/doc/distromove/README.md")
        copy(ROOT / "CHANGELOG.md", root / "usr/share/doc/distromove/changelog")
        copy(ROOT / "LICENSE", root / "usr/share/doc/distromove/copyright")
        control = root / "DEBIAN"
        control.mkdir()
        (control / "conffiles").write_text(
            "/etc/xdg/menus/applications-merged/distromove.menu\n")
        (control / "control").write_text(
            f"Package: distromove\nVersion: {release}\nArchitecture: all\n"
            "Section: utils\nPriority: optional\n"
            "Maintainer: Franco Conidi <fconidi@gmail.com>\n"
            f"Depends: {', '.join(DEPENDS)}\n"
            "Homepage: https://github.com/fconidi/DistroMove\n"
            "Description: Migrate a running Debian-based system to new partitions\n"
            " Native GTK wizard with privileged storage and boot setup.\n")
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(root), str(artifact)],
                       check=True)
    return artifact


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a DistroMove Debian package")
    parser.add_argument("--output-dir", type=Path,
                        default=Path.home() / ".cache/distromove/packages")
    args = parser.parse_args()
    print(build(args.output_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
