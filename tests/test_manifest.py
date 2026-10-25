import hashlib
import os
import stat
import time
from datetime import datetime

import pytest

from distromove.manifest import build_manifest
from distromove.model import Manifest, ManifestEntry

FILES = {
    "etc/fstab": b"UUID=abc / ext4 defaults 0 1\n",
    "etc/ssh/sshd_config": b"Port 22\n",
    "boot/grub/grub.cfg": b"menuentry 'Debian' {}\n",
    "boot/config-6.1.0": b"CONFIG_EXT4_FS=y\n",
    "usr/bin/tool": b"\x7fELF\x02\x01",
    "home/user/notes.txt": b"notes",
    "var/log/syslog": b"log line\n",
}
for i in range(12):
    FILES[f"usr/share/doc/pkg{i}/copyright"] = f"copyright {i}\n".encode()


def make_tree(root):
    for rel, data in FILES.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    os.symlink("../usr/share/zoneinfo/UTC", root / "etc/localtime")  # dangling on purpose
    os.symlink("/usr", root / "etc/usr-link")  # symlink to a directory: never followed
    return root


def sha(data):
    return hashlib.sha256(data).hexdigest()


def all_paths():
    paths = set(FILES) | {"etc/localtime", "etc/usr-link"}
    for rel in list(paths):
        parts = rel.split("/")
        for n in range(1, len(parts)):
            paths.add("/".join(parts[:n]))
    return paths


def test_build_manifest_hashes_etc_boot_and_sample_and_respects_files_from(tmp_path):
    root = make_tree(tmp_path / "root")

    m = build_manifest(root, sample=3, kind="ext4-frozen")
    assert isinstance(m, Manifest) and m.kind == "ext4-frozen"
    datetime.fromisoformat(m.taken_at)
    assert set(m.entries) == all_paths()
    assert all(isinstance(e, ManifestEntry) for e in m.entries.values())

    # every regular file under etc/ and boot/ is hashed with its real content
    for rel in ("etc/fstab", "etc/ssh/sshd_config", "boot/grub/grub.cfg", "boot/config-6.1.0"):
        assert m.entries[rel].sha256 == sha(FILES[rel])
    # symlinks are recorded, never followed; under etc/ the link target is hashed
    assert m.entries["etc/localtime"].sha256 == sha(b"../usr/share/zoneinfo/UTC")
    assert stat.S_ISLNK(m.entries["etc/usr-link"].mode)
    assert not any(p.startswith("etc/usr-link/") for p in m.entries)
    # directories carry metadata but no size or hash
    assert m.entries["etc/ssh"].sha256 is None and m.entries["etc/ssh"].size == 0
    assert stat.S_ISDIR(m.entries["etc/ssh"].mode)

    # metadata comes from lstat, mtime in nanoseconds
    st = os.lstat(root / "etc/fstab")
    e = m.entries["etc/fstab"]
    assert (e.size, e.mtime, e.mode, e.uid, e.gid) == (
        st.st_size, st.st_mtime_ns, st.st_mode, st.st_uid, st.st_gid)

    # a sample of exactly `sample` other regular files is hashed, correctly
    others = [p for p in FILES if not p.startswith(("etc/", "boot/"))]
    sampled = sorted(p for p in others if m.entries[p].sha256 is not None)
    assert len(sampled) == 3
    assert all(m.entries[p].sha256 == sha(FILES[p]) for p in sampled)
    # the sample is deterministic, so a second run picks the same files
    again = build_manifest(root, sample=3, kind="ext4-frozen")
    assert sorted(p for p in others if again.entries[p].sha256 is not None) == sampled
    # sample=0: only etc/ and boot/ are hashed
    none = build_manifest(root, sample=0, kind="ext4-frozen")
    assert all(none.entries[p].sha256 is None for p in others)

    # files_from restricts the manifest to the listed (relative) paths
    m2 = build_manifest(root, sample=0, kind="btrfs-live",
                        files_from=["/etc/fstab", "usr/bin/tool", "./home/user/notes.txt",
                                    "missing/file"])
    assert m2.kind == "btrfs-live"
    assert set(m2.entries) == {"etc/fstab", "usr/bin/tool", "home/user/notes.txt"}
    assert m2.entries["etc/fstab"].sha256 == sha(FILES["etc/fstab"])
    assert m2.entries["usr/bin/tool"].sha256 is None
    with pytest.raises(ValueError):
        build_manifest(root, files_from=["../outside"], kind="btrfs-live")

    # other hash roots, and "." for a whole volume (e.g. a separate /boot)
    m3 = build_manifest(root, hash_paths=("home",), sample=0, kind="btrfs-snapshot")
    assert m3.entries["home/user/notes.txt"].sha256 == sha(FILES["home/user/notes.txt"])
    assert m3.entries["etc/fstab"].sha256 is None
    m4 = build_manifest(root / "boot", hash_paths=(".",), sample=0, kind="ext4-frozen")
    assert m4.entries["grub/grub.cfg"].sha256 == sha(FILES["boot/grub/grub.cfg"])


def test_build_manifest_does_not_change_the_source(tmp_path):
    root = make_tree(tmp_path / "root")
    before = {p: os.lstat(root / p) for p in all_paths()}
    build_manifest(root, sample=50, kind="ext4-frozen")
    for p, st in before.items():
        now = os.lstat(root / p)
        assert (now.st_mtime_ns, now.st_ctime_ns, now.st_size) == (
            st.st_mtime_ns, st.st_ctime_ns, st.st_size)


def test_live_reference_omits_stable_file_beneath_changed_directory(tmp_path):
    root = tmp_path / "root"
    child = root / "directory"
    child.mkdir(parents=True)
    (child / "old").write_text("unchanged")
    cutoff = time.time()
    time.sleep(0.01)
    (child / "new").write_text("changed directory")
    manifest = build_manifest(root, kind="btrfs-live", ctime_before=cutoff)
    assert "directory" not in manifest.entries
    assert "directory/old" not in manifest.entries
