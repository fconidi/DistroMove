"""The chroot command is recorded; tests do not create host mounts."""
import json
from pathlib import Path
import subprocess

import pytest

from distromove.chroot_env import Chroot
from distromove.journal import Journal, read_journal


class Recorder:
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.fail = False

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[0] == "findmnt":
            target = argv[argv.index("--mountpoint") + 1]
            output = {"filesystems": [{"target": target, "source": "/dev/vdb2",
                                       "fstype": "vfat" if target.endswith("/boot/efi") else "ext4"}]}
            return subprocess.CompletedProcess(argv, 0, json.dumps(output), "")
        if argv[0] == "unshare":
            if self.fail:
                raise RuntimeError("chroot command failed")
            return subprocess.CompletedProcess(argv, 0, "ok", "")
        raise AssertionError(argv)


def root_tree(tmp_path):
    root = tmp_path / "root"
    for name in ("dev", "proc", "sys", "run", "boot/efi"):
        (root / name).mkdir(parents=True, exist_ok=True)
    (root / "etc").mkdir()
    (root / "etc/fstab").write_text("UUID=new-root / ext4 defaults 0 1\n")
    return root


def test_separate_boot_must_be_mounted(tmp_path):
    root = root_tree(tmp_path)
    (root / "etc/fstab").write_text("UUID=new-root / ext4 defaults 0 1\n"
                                      "UUID=new-boot /boot ext4 defaults 0 2\n")

    class MissingBoot(Recorder):
        def run(self, argv, **kwargs):
            if argv[0] == "findmnt" and argv[argv.index("--mountpoint") + 1] == str(root / "boot"):
                return subprocess.CompletedProcess(argv, 0, '{"filesystems":[]}', "")
            return super().run(argv, **kwargs)

    j = Journal(tmp_path / "journal", host_root_uuid="host")
    with pytest.raises(ValueError, match="mount"):
        with Chroot(MissingBoot(root), root, None, j):
            pass


def test_commands_run_in_separate_mount_namespace(tmp_path):
    root = root_tree(tmp_path)
    r = Recorder(root)
    j = Journal(tmp_path / "journal", host_root_uuid="host")
    with Chroot(r, root, root / "boot/efi", j) as chroot:
        assert chroot.run(["update-initramfs", "-u", "-k", "all"]).stdout == "ok"
    command = r.calls[-1]
    assert command[:5] == ["unshare", "--mount", "--propagation", "private", "--fork"]
    assert "chroot \"$root\" \"$@\"" in command[8]
    assert command[-4:] == ["update-initramfs", "-u", "-k", "all"]


def test_binds_recursive_private_run_tmpfs_no_efivarfs(tmp_path):
    root = root_tree(tmp_path)
    r = Recorder(root)
    j = Journal(tmp_path / "journal", host_root_uuid="host")
    with Chroot(r, root, root / "boot/efi", j) as chroot:
        chroot.run(["true"])
    script = r.calls[-1][8]
    for name in ("dev", "proc", "sys"):
        assert f'mount --rbind /{name} "$root/{name}"' in script
        assert f'mount --make-rprivate "$root/{name}"' in script
    assert 'mount -t tmpfs' in script and '"$root/run"' in script
    assert '"$root/sys/firmware/efi/efivars"' in script
    assert script.index('umount "$root/sys/firmware/efi/efivars"') < script.index('chroot "$root"')


def test_unmount_reverse_on_error(tmp_path):
    root = root_tree(tmp_path)
    r = Recorder(root)
    r.fail = True
    j = Journal(tmp_path / "journal", host_root_uuid="host")
    with Chroot(r, root, None, j) as chroot:
        with pytest.raises(RuntimeError, match="failed"):
            chroot.run(["false"])
    script = r.calls[-1][8]
    assert script.index('umount -R "$root/run"') < script.index('umount -R "$root/sys"')
    assert script.index('umount -R "$root/sys"') < script.index('umount -R "$root/proc"')
    assert script.index('umount -R "$root/proc"') < script.index('umount -R "$root/dev"')
    assert "trap cleanup EXIT" in script
    assert any(e["type"] == "intent" and e["op"] == "chroot_run"
               for e in read_journal(j.path))
