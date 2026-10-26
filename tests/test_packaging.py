"""The distributable contains only runtime files and user documentation."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from distromove import __version__


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def package(tmp_path_factory):
    output = tmp_path_factory.mktemp("packages")
    subprocess.run(["python3", "-B", str(ROOT / "build-deb.py"),
                    "--output-dir", str(output)], check=True, capture_output=True, text=True)
    artifact = output / f"distromove_{__version__}_all.deb"
    assert artifact.is_file()
    return artifact


def contents(package):
    output = subprocess.run(["dpkg-deb", "--contents", str(package)],
                            check=True, capture_output=True, text=True).stdout
    return {line.split()[-1].removeprefix("./") for line in output.splitlines()
            if not line.split()[-1].endswith("/")}


def test_deb_contains_only_program_files(package):
    modules = {f"usr/share/distromove/distromove/{item.name}"
               for item in (ROOT / "src/distromove").glob("*.py")
               if item.name != "events.py"}
    expected = modules | {
        "usr/bin/distromove", "usr/lib/distromove/helper",
        "usr/share/applications/org.syslinuxos.DistroMove.desktop",
        "usr/share/polkit-1/actions/org.syslinuxos.distromove.policy",
        "etc/xdg/menus/applications-merged/distromove.menu",
        "usr/share/doc/distromove/README.md",
        "usr/share/doc/distromove/changelog",
        "usr/share/doc/distromove/copyright",
    }
    assert contents(package) == expected


def test_deb_directory_and_launcher_permissions(package):
    listing = subprocess.run(["dpkg-deb", "--contents", str(package)],
                             check=True, capture_output=True, text=True).stdout.splitlines()
    root_line = next(line for line in listing if line.split()[-1] == "./")
    assert root_line.split()[0] == "drwxr-xr-x"
    scripts = {line.split()[-1]: line.split()[0] for line in listing
               if line.split()[-1] in {"./usr/bin/distromove", "./usr/lib/distromove/helper"}}
    assert scripts == {"./usr/bin/distromove": "-rwxr-xr-x",
                       "./usr/lib/distromove/helper": "-rwxr-xr-x"}


def test_no_internal_words_in_package_or_readme(package, tmp_path):
    subprocess.run(["dpkg-deb", "--extract", str(package), str(tmp_path)], check=True)
    words = re.compile(r"(?i)\b(?:Claude|Codex|Nextcloud|NUC)\b|~/work|"
                       r"\b(?:AGENTS|CLAUDE|HANDOFF|MEMORY|SPEC)\.md\b")
    internal_names = re.compile(r"(?i)(?:^|/)(?:\.agents|\.codex|\.claude|\.remember)(?:/|$)")
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert not words.search(path.read_text(errors="replace")), path
            assert not internal_names.search(str(path.relative_to(tmp_path))), path
    for path in (ROOT / "README.md", ROOT / "CHANGELOG.md"):
        assert not words.search(path.read_text()), path
        assert not re.search(r"(?i)\bagent\b", path.read_text()), path


def test_version_matches_init(package):
    control = subprocess.run(["dpkg-deb", "--field", str(package), "Version"],
                             check=True, capture_output=True, text=True).stdout.strip()
    assert control == __version__


def test_polkit_policy_names_helper_path(package, tmp_path):
    subprocess.run(["dpkg-deb", "--extract", str(package), str(tmp_path)], check=True)
    policy = tmp_path / "usr/share/polkit-1/actions/org.syslinuxos.distromove.policy"
    root = ET.parse(policy).getroot()
    action = root.find("action")
    assert action.attrib["id"] == "org.syslinuxos.distromove.run"
    annotation = action.find("annotate")
    assert annotation.attrib["key"] == "org.freedesktop.policykit.exec.path"
    assert annotation.text == "/usr/lib/distromove/helper"
    assert action.findtext("defaults/allow_active") == "auth_admin"
    assert action.findtext("defaults/allow_any") == "no"


def test_depends_include_btrfs_progs_min_version(package):
    depends = subprocess.run(["dpkg-deb", "--field", str(package), "Depends"],
                             check=True, capture_output=True, text=True).stdout
    for name in ("python3-gi", "gir1.2-gtk-3.0", "cryptsetup", "rsync", "gdisk",
                 "efibootmgr", "grub-efi-amd64-bin", "grub-efi-amd64-signed",
                 "shim-signed", "mokutil", "pkexec"):
        assert name in depends
    assert "btrfs-progs (>= 6.1)" in depends
    assert "policykit-1" not in depends


def test_tests_vm_not_in_git_index():
    output = subprocess.run(["git", "ls-files", "tests/vm"], cwd=ROOT,
                            check=True, capture_output=True, text=True).stdout
    assert not output.strip()
