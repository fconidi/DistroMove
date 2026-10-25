"""Swap commands are recorded; all paths are local pytest fixtures."""
from pathlib import Path
import json
import subprocess

import pytest

from distromove.config_rewrite import ResumeTarget
from distromove.journal import Journal
from distromove.disk import CryptoPlan
from distromove.model import CreatedPartition, Keyslot, LuksInfo, SwapRef
from distromove.swap import SwapMount, SwapPlan, SwapResult, make_swaps, resume_target


def source(kind="file", *, volume_id="swap-a", path="/swapfile", uuid="old-swap",
           random_key=False, resume=False):
    return SwapRef(volume_id, kind, path, "root" if kind == "file" else None,
                   uuid, 16 * 1024 * 1024, None, random_key, resume)


def result(source, *, uuid="new-swap", containing="new-root", offset=None):
    return SwapResult(source.volume_id, source.kind, source.path, source.uuid,
                      "/new/swapfile", uuid, containing, offset, None,
                      source.random_key, source.resume, "old-root")


def test_resume_uses_containing_device_for_file():
    old = source(resume=True)
    assert resume_target([result(old, offset=1234)], "UUID=old-swap") == ResumeTarget("new-root", 1234)
    assert resume_target([result(old, offset=1234)], "UUID=old-root") == ResumeTarget("new-root", 1234)


def test_random_key_swap_never_resume_target():
    old = source(random_key=True, resume=True)
    with pytest.raises(ValueError, match="random"):
        resume_target([result(old, uuid=None, offset=None)], "UUID=old-swap")


def test_several_swaps_each_has_own_volume_id():
    first = result(source(volume_id="swap-a", uuid="old-a"))
    second = result(source(volume_id="swap-b", uuid="old-b"), uuid="new-b", offset=2)
    assert resume_target([first, second], "UUID=old-b") == ResumeTarget("new-root", 2)
    with pytest.raises(ValueError, match="duplicate"):
        resume_target([first, first], None)


class FileRunner:
    def __init__(self, fs):
        self.fs = fs
        self.calls = []

    def run(self, argv, **kwargs):
        argv = [str(a) for a in argv]
        self.calls.append(argv)
        if argv[0] == "findmnt":
            return subprocess.CompletedProcess(argv, 0,
                '{"filesystems":[{"target":"' + argv[argv.index("--mountpoint") + 1] +
                '","source":"/dev/vdb2","fstype":"' + self.fs + '"}]}', "")
        if argv[0] == "blkid":
            is_mount = argv[-1] == "/dev/vdb2"
            value = (("new-root" if is_mount else "new-swap") if "UUID" in argv
                     else (self.fs if is_mount else "swap"))
            return subprocess.CompletedProcess(argv, 0, value + "\n", "")
        if argv[0] == "mkswap":
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:3] == ["btrfs", "filesystem", "mkswapfile"]:
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:3] == ["btrfs", "inspect-internal", "map-swapfile"]:
            return subprocess.CompletedProcess(argv, 0, "4096\n", "")
        if argv[0] == "filefrag":
            return subprocess.CompletedProcess(argv, 0,
                " ext: logical_offset: physical_offset: length: expected: flags:\n"
                "   0: 0..4095: 1234..5329: 4096: last,eof\n", "")
        raise AssertionError(argv)


def test_ext4_swapfile_offset_from_filefrag(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    r = FileRunner("ext4")
    j = Journal(tmp_path / "journal", host_root_uuid="host")
    plan = SwapPlan(source(), swap_uuid="new-swap", containing_volume_id="root",
                    relative_path="swapfile")
    results = make_swaps(r, [plan], {"root": SwapMount(root, "ext4", "new-root")},
                         None, b"", j)
    assert results[0].offset == 1234
    assert ["mkswap", "--file", "--size", str(source().size_bytes), "-U", "new-swap",
            str(root / "swapfile")] in r.calls
    assert ["filefrag", "-b4096", "-v", str(root / "swapfile")] in r.calls


def test_btrfs_swapfile_mkswapfile_and_map_swapfile(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    r = FileRunner("btrfs")
    j = Journal(tmp_path / "journal", host_root_uuid="host")
    plan = SwapPlan(source(), swap_uuid="new-swap", containing_volume_id="root",
                    relative_path="swapfile")
    results = make_swaps(r, [plan], {"root": SwapMount(root, "btrfs", "new-root")},
                         None, b"", j)
    assert results[0].offset == 4096
    assert ["btrfs", "filesystem", "mkswapfile", "-s", str(source().size_bytes),
            "-U", "new-swap", str(root / "swapfile")] in r.calls
    assert ["btrfs", "inspect-internal", "map-swapfile", "-r",
            str(root / "swapfile")] in r.calls


def test_swap_created_after_copy_not_before(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "swapfile").write_bytes(b"old copied data")
    r = FileRunner("ext4")
    j = Journal(tmp_path / "journal", host_root_uuid="host")
    plan = SwapPlan(source(), swap_uuid="new-swap", containing_volume_id="root",
                    relative_path="swapfile")
    with pytest.raises(ValueError, match="already exists"):
        make_swaps(r, [plan], {"root": SwapMount(root, "ext4", "new-root")},
                   None, b"", j)
    assert not any(call[0] == "mkswap" for call in r.calls)


def test_swap_partition_luks_with_common_passphrase(tmp_path):
    luks = LuksInfo(2, "aes-xts-plain64", 512, 512,
                    [Keyslot(0, "pbkdf2", "aes-xts-plain64")], "old-luks", None)
    old = SwapRef("swap-one", "partition", "/dev/vda3", None, "old-swap",
                  16 * 1024 * 1024, luks, False)
    created = CreatedPartition("swap-one", "/dev/vdb3", "new-part", 2048, 1000000,
                               "new-luks", "new-swap")
    crypto = CryptoPlan({"swap-one": [Keyslot(0, "pbkdf2", "aes-xts-plain64")]},
                        {}, {}, {}, {"swap-one": luks})

    class Runner:
        def __init__(self):
            self.calls = []

        def run(self, argv, **kwargs):
            self.calls.append((argv, kwargs))
            if argv[:2] == ["lsblk", "--json"]:
                out = json.dumps({"blockdevices": [{"path": "/dev/vdb3", "type": "part",
                    "partuuid": "new-part", "start": 2048, "size": 512000000,
                    "log-sec": 512}]})
            elif argv[:2] == ["wipefs", "-J"]:
                out = '{"signatures": []}'
            elif argv[:2] == ["cryptsetup", "luksUUID"]:
                out = "new-luks\n"
            elif argv[0] == "blkid":
                out = "new-swap\n" if "UUID" in argv else "swap\n"
            elif argv[0] in {"cryptsetup", "mkswap"}:
                out = ""
            else:
                raise AssertionError(argv)
            return subprocess.CompletedProcess(argv, 0, out, "")

    r = Runner()
    j = Journal(tmp_path / "journal", migration_id="m1", host_root_uuid="host")
    op = j.intend("create_partition", {"partuuid": "new-part", "fs_uuid": "new-swap"},
                  creates="partition")
    j.done(op, "created", path="/dev/vdb3")
    swaps = make_swaps(r, [SwapPlan(old, created=created)], {}, crypto, b"same-secret", j)
    assert swaps[0].path == "/dev/mapper/distromove-m1-swap-one"
    assert swaps[0].luks_uuid == "new-luks"
    assert ["mkswap", "-U", "new-swap", swaps[0].path] in [call for call, _ in r.calls]
    assert all(kwargs.get("secret_input") for call, kwargs in r.calls
               if call[:2] in (["cryptsetup", "luksFormat"], ["cryptsetup", "open"]))
