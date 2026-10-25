"""Btrfs copy commands use recorders; rsync fixtures stay in the local test cache."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from distromove.copy_btrfs import (BtrfsDestination, LiveCopy, branch, managed_snapshots,
                                   copy_from_snapshots, copy_live_swap_subvolume,
                                   reference_manifests, release_snapshots, take_snapshots)
from distromove.journal import Journal, read_journal
from distromove.layout import SourceSpaceLow
from distromove.model import BtrfsInfo, Partition, Subvol, Volume
from distromove.runner import Runner


def subvol(sid, path, *, swap=False, only=False, mountpoint=None):
    return Subvol(sid, path, mountpoint, None, {}, swap, only)


def volume(top, subvols):
    part = Partition("/dev/vdb2", "vdb2", "/dev/vdb", 2, 1024**3, "btrfs", "source-fs",
                     "source-part", None, str(top), "wwn", "serial", None, 2048, 100000, 512)
    return Volume("root", "root", str(top), part, None, "btrfs", "source-fs", 1, 1, 1,
                  BtrfsInfo("source-fs", 5, subvols), False)


def test_branch_classification_three_cases():
    assert branch(subvol(256, "@")) == "snapshot"
    assert branch(subvol(257, "@swap", swap=True, only=True)) == "swap-only"
    assert branch(subvol(258, "@var", swap=True)) == "live"


class Watch:
    def __init__(self, fail_after=None):
        self.count = 0
        self.fail_after = fail_after

    def check(self):
        self.count += 1
        if self.fail_after is not None and self.count >= self.fail_after:
            raise SourceSpaceLow("/source", 1, 2)


class BtrfsRunner:
    def __init__(self, top):
        self.top = Path(top)
        self.calls = []
        self.next_id = 500
        self.snapshots = {}
        self.destinations = {}
        self.active_swapfile = None

    def run(self, argv, **kwargs):
        argv = [str(a) for a in argv]
        self.calls.append((argv, kwargs))
        if argv[:2] == ["findmnt", "--json"]:
            target = Path(argv[argv.index("--target") + 1]) if "--target" in argv else self.top
            destination = next((p for p in self.destinations if target == p or p in target.parents), None)
            out = json.dumps({"filesystems": [{"target": str(destination or self.top),
                         "source": "UUID=new-fs" if destination else "UUID=source-fs",
                         "fstype": "btrfs"}]})
        elif argv[:2] == ["swapon", "--show=NAME,TYPE"]:
            out = f"{self.active_swapfile} file\n" if self.active_swapfile else ""
        elif argv[:2] == ["btrfs", "inspect-internal"]:
            if Path(argv[-1]) in self.destinations:
                out = str(self.destinations[Path(argv[-1])]) + "\n"
            else:
                relative = Path(argv[-1]).relative_to(self.top).as_posix()
                out = str({".": 5, "@": 256, "@/var": 300, "@home": 257,
                           "@swap": 257, "swapfile": 5}.get(relative, 256)) + "\n"
        elif argv[:3] == ["btrfs", "subvolume", "snapshot"]:
            self.next_id += 1
            path = Path(argv[-1])
            path.mkdir()
            if Path(argv[-2]) != self.top:
                shutil.copytree(argv[-2], path, dirs_exist_ok=True)
            self.snapshots[str(path)] = (f"uuid-{self.next_id}", self.next_id)
            out = ""
        elif argv[:3] == ["btrfs", "subvolume", "show"]:
            uid, sid = self.snapshots[argv[-1]]
            out = f"UUID: {uid}\nSubvolume ID: {sid}\nFlags: readonly\n"
        elif argv[:3] == ["btrfs", "property", "get"]:
            out = "ro=true\n"
        elif argv[:3] == ["btrfs", "subvolume", "delete"]:
            self.snapshots.pop(argv[-1])
            shutil.rmtree(argv[-1])
            out = ""
        elif argv[0] == "rsync":
            return Runner().run(argv)
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, out, "")


def test_snapshots_readonly_prefixed_with_migration_id(tmp_path):
    (tmp_path / "@").mkdir()
    r = BtrfsRunner(tmp_path)
    j = Journal(tmp_path / "j", migration_id="m1", host_root_uuid="host-root")
    refs = take_snapshots(r, volume(tmp_path, [subvol(256, "@")]), j, Watch(), top_level=tmp_path)
    assert {ref.subvol_path for ref in refs} == {".", "@"}
    assert all(Path(ref.snapshot_path).name.startswith("distromove-m1-") for ref in refs)
    commands = [argv for argv, _ in r.calls if argv[:3] == ["btrfs", "subvolume", "snapshot"]]
    assert len(commands) == 2 and all(command[3] == "-r" for command in commands)
    assert all(ref.owner_op for ref in refs)
    assert any(argv == ["swapon", "--show=NAME,TYPE", "--noheadings", "--raw"]
               for argv, _ in r.calls)


def test_nested_subvolumes_included(tmp_path):
    (tmp_path / "@").mkdir()
    (tmp_path / "@/var").mkdir()
    r = BtrfsRunner(tmp_path)
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    refs = take_snapshots(r, volume(tmp_path, [subvol(256, "@"), subvol(300, "@/var")]),
                          j, Watch(), top_level=tmp_path)
    assert {ref.subvol_path for ref in refs} == {".", "@", "@/var"}
    assert "var" in next(ref for ref in refs if ref.subvol_path == "@").exclude_paths
    assert "@" in next(ref for ref in refs if ref.subvol_path == ".").exclude_paths


def test_only_swapfile_subvolume_skipped(tmp_path):
    (tmp_path / "@swap").mkdir()
    r = BtrfsRunner(tmp_path)
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    refs = take_snapshots(r, volume(tmp_path, [subvol(257, "@swap", swap=True, only=True)]),
                          j, Watch(), top_level=tmp_path)
    assert {ref.subvol_path for ref in refs} == {"."}
    assert "@swap" in refs[0].exclude_paths


def test_newly_active_swapfile_blocks_snapshot_before_write(tmp_path):
    (tmp_path / "@").mkdir()
    active = tmp_path / "@/swap file"
    active.write_text("swap")
    r = BtrfsRunner(tmp_path)
    r.active_swapfile = active
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    with pytest.raises(ValueError, match="active swapfile"):
        take_snapshots(r, volume(tmp_path, [subvol(256, "@")]), j, Watch(), top_level=tmp_path)
    assert not any(argv[:3] == ["btrfs", "subvolume", "snapshot"] for argv, _ in r.calls)


def test_top_level_swapfile_requires_live_branch(tmp_path):
    active = tmp_path / "swapfile"
    active.write_text("swap")
    r = BtrfsRunner(tmp_path)
    r.active_swapfile = active
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    with pytest.raises(ValueError, match="active swapfile"):
        take_snapshots(r, volume(tmp_path, []), j, Watch(), top_level=tmp_path)
    assert not r.snapshots


def test_burst_has_no_other_commands_between_snapshots(tmp_path):
    (tmp_path / "@").mkdir()
    (tmp_path / "@home").mkdir()
    r = BtrfsRunner(tmp_path)
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    take_snapshots(r, volume(tmp_path, [subvol(256, "@"), subvol(257, "@home")]),
                   j, Watch(), top_level=tmp_path)
    indexes = [i for i, (argv, _) in enumerate(r.calls)
               if argv[:3] == ["btrfs", "subvolume", "snapshot"]]
    assert indexes == list(range(indexes[0], indexes[-1] + 1))


def mounted(j, path, fs_uuid="new-fs"):
    op = j.intend("mount_destination", {"fs_uuid": fs_uuid}, path=str(path))
    j.done(op, "mounted")


def test_prefix_match_alone_not_enough_requires_journal_ownership(tmp_path):
    (tmp_path / "@").mkdir()
    r = BtrfsRunner(tmp_path)
    j = Journal(tmp_path / "j", migration_id="m1", host_root_uuid="host-root")
    refs = take_snapshots(r, volume(tmp_path, [subvol(256, "@")]), j, Watch(), top_level=tmp_path)
    forged = replace(refs[1], owner_op="not-an-operation")
    with pytest.raises(ValueError, match="not owned"):
        release_snapshots(r, [forged], j)
    assert Path(refs[1].snapshot_path).exists()
    release_snapshots(r, refs, j)
    assert not r.snapshots
    release_snapshots(r, refs, j)  # release is safe in an outer finally, too


def test_snapshot_uuid_change_blocks_release(tmp_path):
    (tmp_path / "@").mkdir()
    r = BtrfsRunner(tmp_path)
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    refs = take_snapshots(r, volume(tmp_path, [subvol(256, "@")]), j, Watch(), top_level=tmp_path)
    ref = refs[1]
    r.snapshots[ref.snapshot_path] = ("someone-else", 900)
    with pytest.raises(RuntimeError, match="changed"):
        release_snapshots(r, [ref], j)
    assert Path(ref.snapshot_path).exists()


def test_snapshots_kept_until_release_and_released_in_finally(tmp_path):
    (tmp_path / "@").mkdir()
    r = BtrfsRunner(tmp_path)
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    with pytest.raises(RuntimeError, match="later verification"):
        with managed_snapshots(r, volume(tmp_path, [subvol(256, "@")]), j, Watch(),
                               top_level=tmp_path) as refs:
            assert all(Path(ref.snapshot_path).exists() for ref in refs)
            raise RuntimeError("later verification failed")
    assert not r.snapshots


def test_space_watch_low_aborts_and_releases_owned_snapshots(tmp_path):
    (tmp_path / "@").mkdir()
    r = BtrfsRunner(tmp_path)
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    with pytest.raises(SourceSpaceLow):
        take_snapshots(r, volume(tmp_path, [subvol(256, "@")]), j,
                       Watch(fail_after=2), top_level=tmp_path)
    assert not r.snapshots
    assert any(e["op"] == "delete_btrfs_snapshot" for e in read_journal(j.path)
               if e["type"] == "intent")


def test_failed_snapshot_burst_releases_earlier_snapshot(tmp_path):
    (tmp_path / "@").mkdir()

    class FailingRunner(BtrfsRunner):
        def run(self, argv, **kwargs):
            if argv[:3] == ["btrfs", "subvolume", "snapshot"] and self.snapshots:
                raise RuntimeError("second snapshot failed")
            return super().run(argv, **kwargs)

    r = FailingRunner(tmp_path)
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    with pytest.raises(RuntimeError, match="second snapshot"):
        take_snapshots(r, volume(tmp_path, [subvol(256, "@")]), j, Watch(), top_level=tmp_path)
    assert not r.snapshots


def test_snapshots_dir_not_copied(tmp_path):
    top, dest = tmp_path / "source", tmp_path / "destination"
    top.mkdir()
    dest.mkdir()
    (top / "@").mkdir()
    (top / "@/file").write_text("data")
    (top / "@/.snapshots").mkdir()
    (top / "@/.snapshots/old").write_text("history")
    dest_sub = dest / "@"
    dest_sub.mkdir()
    r = BtrfsRunner(top)
    r.destinations = {dest: 5, dest_sub: 600}
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    mounted(j, dest)
    refs = take_snapshots(r, volume(top, [subvol(256, "@")]), j, Watch(), top_level=top)
    destinations = {("source-fs", "."): BtrfsDestination(dest, "new-fs", 5),
                    ("source-fs", "@"): BtrfsDestination(dest_sub, "new-fs", 600)}
    copy_from_snapshots(r, refs, destinations, journal=j, watch=Watch())
    assert (dest_sub / "file").read_text() == "data"
    assert not (dest_sub / ".snapshots").exists()
    manifests = reference_manifests(refs, [])
    assert "file" in manifests["source-fs:@"].entries
    assert not any(".snapshots" in path for path in manifests["source-fs:@"].entries)
    assert all(Path(ref.snapshot_path).exists() for ref in refs)
    release_snapshots(r, refs, j)


def test_copy_preflight_failure_releases_owned_snapshots(tmp_path):
    top, dest = tmp_path / "source", tmp_path / "destination"
    top.mkdir()
    dest.mkdir()
    (top / "@").mkdir()
    r = BtrfsRunner(top)
    r.destinations = {dest: 5}
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    mounted(j, dest)
    refs = take_snapshots(r, volume(top, [subvol(256, "@")]), j, Watch(), top_level=top)
    wrong = {("source-fs", "."): BtrfsDestination(dest, "wrong-fs", 5)}
    with pytest.raises(RuntimeError, match="destination"):
        copy_from_snapshots(r, refs, wrong, journal=j)
    assert not r.snapshots


def test_low_space_during_copy_releases_snapshots(tmp_path):
    top, dest = tmp_path / "source", tmp_path / "destination"
    top.mkdir()
    dest.mkdir()
    r = BtrfsRunner(top)
    r.destinations = {dest: 5}
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    mounted(j, dest)
    refs = take_snapshots(r, volume(top, []), j, Watch(), top_level=top)
    mapping = {("source-fs", "."): BtrfsDestination(dest, "new-fs", 5)}
    with pytest.raises(SourceSpaceLow):
        copy_from_snapshots(r, refs, mapping, journal=j, watch=Watch(fail_after=1))
    assert not r.snapshots


def test_mixed_swap_subvolume_copied_live_without_swapfile_and_data_preserved(tmp_path):
    top, dest = tmp_path / "source", tmp_path / "destination"
    top.mkdir()
    dest.mkdir()
    source = top / "@"
    source.mkdir()
    (source / "swapfile").write_text("old swap")
    (source / "data").write_text("keep")
    r = BtrfsRunner(top)
    r.destinations = {dest: 600}
    r.active_swapfile = source / "swapfile"
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    mounted(j, dest)
    live = copy_live_swap_subvolume(r, subvol(256, "@", swap=True),
                                    BtrfsDestination(dest, "new-fs", 600),
                                    [source / "swapfile"], journal=j,
                                    source_fs_uuid="source-fs",
                                    source_top_level=top, watch=Watch())
    assert (dest / "data").read_text() == "keep"
    assert not (dest / "swapfile").exists()
    assert live.manifest.kind == "btrfs-live"
    assert "swapfile" not in live.manifest.entries
    assert not any(argv[:3] == ["btrfs", "subvolume", "snapshot"] for argv, _ in r.calls)


def test_live_copy_refuses_unexcluded_active_swapfile(tmp_path):
    top, dest = tmp_path / "source", tmp_path / "destination"
    top.mkdir()
    dest.mkdir()
    source = top / "@"
    source.mkdir()
    (source / "swapfile").write_text("old swap")
    r = BtrfsRunner(top)
    r.destinations = {dest: 600}
    r.active_swapfile = source / "swapfile"
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    mounted(j, dest)
    with pytest.raises(ValueError, match="not excluded"):
        copy_live_swap_subvolume(r, subvol(256, "@", swap=True),
                                  BtrfsDestination(dest, "new-fs", 600), [],
                                  journal=j, source_fs_uuid="source-fs", source_top_level=top)
    assert not any(argv[0] == "rsync" for argv, _ in r.calls)


def test_live_branch_data_of_root_subvolume_preserved_and_verified(tmp_path):
    top, dest = tmp_path / "source", tmp_path / "destination"
    top.mkdir()
    dest.mkdir()
    source = top / "@"
    source.mkdir()
    (source / "swapfile").write_text("old swap")
    (source / "config").write_text("persistent")
    r = BtrfsRunner(top)
    r.destinations = {dest: 600}
    r.active_swapfile = source / "swapfile"
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    mounted(j, dest)
    live = copy_live_swap_subvolume(r, subvol(256, "@", swap=True),
                                    BtrfsDestination(dest, "new-fs", 600),
                                    [source / "swapfile"], journal=j,
                                    source_fs_uuid="source-fs", source_top_level=top)
    refs = reference_manifests([], [live])
    assert refs["source-fs:@"].entries["config"].size == len("persistent")
    assert (dest / "config").read_text() == "persistent"
