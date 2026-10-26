"""Ext4 copy exercises real rsync only on temporary local directories."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import threading
import time

import pytest

from distromove.copy_ext4 import (RSYNC_ARGS, CopyPair, FreezeFailed, FreezeGroup,
                                  FreezeTooLong, PassStats, _probe_thawed, _watchdog_loop,
                                  _verify_destination_mount,
                                  changed_since, checksum_candidates_pass, copy_ext4,
                                  hot_pass, reconcile_pass, volume_filters)
from distromove.journal import Journal, read_journal
from distromove.manifest import build_manifest
from distromove.model import MountInfo
from distromove.runner import Runner


@pytest.fixture(autouse=True)
def local_directory_mounts(monkeypatch):
    # Real rsync runs in the cache; these fixtures are directories, not mounted devices.
    from distromove import copy_ext4 as module
    monkeypatch.setattr(module, "_verify_destination_mount", lambda _r, _pair: None)


def mount_journal(journal, pair):
    op = journal.intend("mount_destination", {"fs_uuid": pair.destination_fs_uuid},
                        path=str(pair.destination))
    journal.done(op, "mounted")


def pair_in(tmp_path, *, filters=()):
    src, dst = tmp_path / "source", tmp_path / "destination"
    src.mkdir()
    dst.mkdir()
    return CopyPair(src, dst, src, "new-fs", tuple(filters))


class ActiveGroup:
    def __init__(self, journal):
        self.journal = journal

    def ensure_active(self):
        pass


def test_rsync_args_exact():
    assert RSYNC_ARGS == ["-aAXHS", "--numeric-ids", "--one-file-system"]


def test_filters_per_volume_docker_data_kept_old_swapfile_excluded(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    filters = volume_filters(root, [MountInfo("/dev/child", str(root / "home"), "ext4", "rw")],
                             [root / "swapfile"])
    assert filters == ["--exclude=/home/***", "--exclude=/swapfile"]
    assert not any("docker" in item for item in filters)


def test_same_size_same_mtime_content_change_is_recopied(tmp_path):
    pair = pair_in(tmp_path)
    src_file = pair.source / "same"
    src_file.write_bytes(b"old")
    r = Runner()
    j = Journal(tmp_path / "journal", host_root_uuid="host-root")
    mount_journal(j, pair)
    first = hot_pass(r, pair.source, pair.destination, [])
    assert first.files == 1
    old_stat = src_file.stat()
    time.sleep(0.01)
    src_file.write_bytes(b"new")
    os.utime(src_file, ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns))
    group = ActiveGroup(j)
    reconcile_pass(r, [pair], group)
    assert (pair.destination / "same").read_bytes() == b"old"
    assert "same" in changed_since(r, pair.source, first.started_at)
    assert checksum_candidates_pass(r, [pair], group, first.started_at) >= 1
    assert (pair.destination / "same").read_bytes() == b"new"
    assert any("--checksum" in call and "--delete" not in call for call in r.calls)


def test_deleted_file_removed_in_destination_by_reconcile(tmp_path):
    pair = pair_in(tmp_path)
    (pair.source / "gone").write_text("old")
    r = Runner()
    j = Journal(tmp_path / "journal", host_root_uuid="host-root")
    mount_journal(j, pair)
    hot_pass(r, pair.source, pair.destination, [])
    (pair.source / "gone").unlink()
    reconcile_pass(r, [pair], ActiveGroup(j))
    assert not (pair.destination / "gone").exists()


def test_renamed_file_and_removed_directory_reconciled(tmp_path):
    pair = pair_in(tmp_path)
    (pair.source / "old-dir").mkdir()
    (pair.source / "old-dir/file").write_text("data")
    r = Runner()
    j = Journal(tmp_path / "journal", host_root_uuid="host-root")
    mount_journal(j, pair)
    hot_pass(r, pair.source, pair.destination, [])
    (pair.source / "old-dir/file").rename(pair.source / "new-file")
    (pair.source / "old-dir").rmdir()
    reconcile_pass(r, [pair], ActiveGroup(j))
    assert not (pair.destination / "old-dir").exists()
    assert (pair.destination / "new-file").read_text() == "data"


def test_child_volume_untouched_by_delete(tmp_path):
    pair = pair_in(tmp_path)
    (pair.source / "home").mkdir()
    (pair.destination / "home").mkdir()
    (pair.destination / "home/keep").write_text("child")
    filters = volume_filters(pair.source, [pair.source / "home"], [])
    pair = CopyPair(pair.source, pair.destination, pair.mountpoint,
                    pair.destination_fs_uuid, tuple(filters))
    j = Journal(tmp_path / "journal", host_root_uuid="host-root")
    mount_journal(j, pair)
    reconcile_pass(Runner(), [pair], ActiveGroup(j))
    assert (pair.destination / "home/keep").read_text() == "child"


def test_child_volume_requires_parent_filter(tmp_path):
    parent = pair_in(tmp_path)
    home_src, home_dst = parent.source / "home", parent.destination / "home"
    home_src.mkdir()
    home_dst.mkdir()
    child = CopyPair(home_src, home_dst, home_src, "home-fs")
    j = Journal(tmp_path / "journal", host_root_uuid="host-root")
    mount_journal(j, parent)
    mount_journal(j, child)
    with pytest.raises(ValueError, match="child volume"):
        reconcile_pass(Runner(), [parent, child], ActiveGroup(j))


def test_manifest_omits_protected_mount_and_swapfile(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "home").mkdir()
    (root / "home/unrelated").write_text("child")
    (root / "swapfile").write_text("old swap")
    (root / "docker").mkdir()
    (root / "docker/data").write_text("keep")
    manifest = build_manifest(root, kind="ext4-frozen", exclude_paths=("home", "swapfile"))
    assert "home" not in manifest.entries
    assert "swapfile" not in manifest.entries
    assert "docker/data" in manifest.entries


def test_files_from_candidates_recopied_without_deleting_siblings(tmp_path):
    pair = pair_in(tmp_path)
    (pair.source / "one").write_text("one")
    (pair.destination / "unlisted").write_text("keep")
    j = Journal(tmp_path / "journal", host_root_uuid="host-root")
    mount_journal(j, pair)
    r = Runner()
    count = checksum_candidates_pass(r, [pair], ActiveGroup(j), time.time() - 60)
    assert count >= 1
    assert (pair.destination / "one").read_text() == "one"
    assert (pair.destination / "unlisted").read_text() == "keep"


def test_changed_since_preserves_non_utf8_filename(tmp_path):
    src = tmp_path / "source"
    src.mkdir()
    name = os.fsdecode(b"byte-\xff")
    (src / name).write_text("content")
    assert name in changed_since(Runner(), src, time.time() - 60)


def test_final_pass_delete_only_in_validated_destination(tmp_path):
    pair = pair_in(tmp_path)
    j = Journal(tmp_path / "journal", host_root_uuid="host-root")
    group = ActiveGroup(j)
    with pytest.raises(ValueError, match="verified mount"):
        reconcile_pass(Runner(), [pair], group)
    mount_journal(j, pair)
    other = tmp_path / "unrelated"
    other.mkdir()
    bad = CopyPair(pair.source, other, pair.mountpoint, "new-fs")
    with pytest.raises(ValueError, match="verified mount"):
        reconcile_pass(Runner(), [bad], group)


def test_mount_identity_rechecked_before_delete(tmp_path):
    pair = pair_in(tmp_path)

    class WrongMount:
        def run(self, argv, **_kwargs):
            return subprocess.CompletedProcess(argv, 0,
                '{"filesystems":[{"target":"' + str(pair.destination) + '",'
                '"source":"UUID=someone-else","fstype":"ext4"}]}', "")

    with pytest.raises(ValueError, match="identity changed"):
        _verify_destination_mount(WrongMount(), pair)


class FreezeRunner:
    def __init__(self, journal):
        self.calls = []
        self.journal = journal

    def run(self, argv, **_kwargs):
        self.calls.append(argv)
        if argv[:2] == ["fsfreeze", "-f"]:
            entries = read_journal(self.journal.path)
            assert any(e["type"] == "intent" and e["op"] == "freeze_window" for e in entries)
            assert not any(e["type"] == "outcome" and e["outcome"] == "closed" for e in entries)
        return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()


def test_all_volumes_frozen_together_then_thawed(tmp_path, monkeypatch):
    from distromove import copy_ext4 as module
    monkeypatch.setattr(module, "_probe_thawed", lambda *_args, **_kwargs: True)
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    j = Journal(tmp_path / "journal", host_root_uuid="host-root")
    r = FreezeRunner(j)
    with FreezeGroup(r, [a, b], j, 5):
        assert r.calls == [["fsfreeze", "-f", str(a)], ["fsfreeze", "-f", str(b)]]
        assert not any(e["type"] == "outcome" and e["outcome"] == "closed"
                       for e in read_journal(j.path))
    assert r.calls[2:] == [["fsfreeze", "-u", str(b)], ["fsfreeze", "-u", str(a)]]
    assert any(e["type"] == "outcome" and e["outcome"] == "closed"
               for e in read_journal(j.path))


def test_freeze_failure_thaws_every_mount_and_closes_window(tmp_path, monkeypatch):
    from distromove import copy_ext4 as module
    monkeypatch.setattr(module, "_probe_thawed", lambda *_args, **_kwargs: True)
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    j = Journal(tmp_path / "journal", host_root_uuid="host-root")

    class FailingRunner(FreezeRunner):
        def run(self, argv, **kwargs):
            if argv == ["fsfreeze", "-f", str(b)]:
                raise FreezeFailed("second volume cannot be frozen")
            return super().run(argv, **kwargs)

    r = FailingRunner(j)
    with pytest.raises(FreezeFailed, match="second"):
        with FreezeGroup(r, [a, b], j, 5):
            pass
    assert ["fsfreeze", "-u", str(a)] in r.calls
    assert any(e["type"] == "outcome" and e["outcome"] == "closed"
               for e in read_journal(j.path))


def test_watchdog_thaws_when_helper_dies_and_retries_late_freeze(tmp_path):
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    calls = []
    probes = iter((False, False, True, True, True, True))
    try:
        _watchdog_loop(read_fd, (tmp_path,), 0.1,
                       thaw=lambda p: calls.append(p), probe=lambda p: next(probes, True))
    finally:
        os.close(read_fd)
    assert len(calls) >= 3


def test_watchdog_retries_after_deadline_for_late_freeze(tmp_path):
    read_fd, write_fd = os.pipe()
    calls = []
    os.write(write_fd, b"S")
    timer = threading.Timer(0.65, lambda: os.write(write_fd, b"D"))
    timer.start()
    try:
        _watchdog_loop(read_fd, (tmp_path,), 0.05,
                       thaw=lambda p: calls.append(p), probe=lambda p: True)
    finally:
        timer.join()
        os.close(read_fd)
        os.close(write_fd)
    assert len(calls) >= 2


def test_thaw_proven_by_probe_file(tmp_path):
    assert _probe_thawed(tmp_path)
    assert not list(tmp_path.glob(".distromove-thaw-*"))


def test_nothing_persistent_written_inside_window(tmp_path, monkeypatch):
    from distromove import copy_ext4 as module
    pair = pair_in(tmp_path)
    j = Journal(tmp_path / "journal", host_root_uuid="host-root")
    mount_journal(j, pair)
    monkeypatch.setattr(module, "_probe_thawed", lambda *_args, **_kwargs: True)

    class Recorder:
        def run(self, argv, **_kwargs):
            if argv[0] == "rsync" and "--delete" in argv:
                entries = read_journal(j.path)
                assert [e["op"] for e in entries if e["type"] == "intent"] == [
                    "mount_destination", "freeze_window"]
                assert not any(e["type"] == "outcome" and e["outcome"] == "closed" for e in entries)
            return subprocess.CompletedProcess(argv, 0, "\0" if argv[0] == "find" else "", "")

    r = Recorder()
    with FreezeGroup(r, [pair.mountpoint], j, 5) as group:
        module.final_pass(r, [pair], group, time.time() - 1)
    assert [e["outcome"] for e in read_journal(j.path) if e["type"] == "outcome"] == [
        "mounted", "closed"]


def test_convergence_until_under_threshold(tmp_path, monkeypatch):
    from distromove import copy_ext4 as module
    pair = pair_in(tmp_path)
    j = Journal(tmp_path / "journal", host_root_uuid="host-root")
    mount_journal(j, pair)
    durations = iter((25.0, 1.0))
    called = []
    monkeypatch.setattr(module, "hot_pass", lambda *args: (
        called.append(1) or PassStats(next(durations), 0, time.time())))
    monkeypatch.setattr(module, "_probe_thawed", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(module, "final_pass", lambda *args: "finished")
    r = FreezeRunner(j)
    assert copy_ext4(r, [pair], j, threshold_s=20.0) == "finished"
    assert len(called) == 2


def test_FreezeTooLong_after_max_rounds(tmp_path, monkeypatch):
    from distromove import copy_ext4 as module
    pair = pair_in(tmp_path)
    j = Journal(tmp_path / "journal", host_root_uuid="host-root")
    mount_journal(j, pair)
    monkeypatch.setattr(module, "hot_pass", lambda *args: PassStats(21.0, 0, time.time()))
    with pytest.raises(FreezeTooLong, match="converge"):
        copy_ext4(Runner(), [pair], j, threshold_s=20.0, max_rounds=2)
    assert not any(e["op"] == "freeze_window" for e in read_journal(j.path) if e["type"] == "intent")


def test_never_writes_to_source(tmp_path):
    pair = pair_in(tmp_path)
    (pair.source / "content").write_text("unchanged")
    r = Runner()
    before = {p.relative_to(pair.source): p.read_bytes() for p in pair.source.rglob("*") if p.is_file()}
    hot_pass(r, pair.source, pair.destination, [])
    after = {p.relative_to(pair.source): p.read_bytes() for p in pair.source.rglob("*") if p.is_file()}
    assert after == before
    assert all(not str(pair.source).startswith(call[-1]) for call in r.calls if call[0] == "rsync")


def test_checksum_pass_leaves_directory_mtimes_equal_to_the_source(tmp_path):
    src, dst = tmp_path / "s", tmp_path / "d"
    (src / "load").mkdir(parents=True)
    dst.mkdir()
    target = src / "load" / "f1"
    target.write_bytes(b"A" * 4096)
    r = Runner()
    started = hot_pass(r, src, dst, []).started_at
    before = target.stat()
    time.sleep(0.05)
    target.write_bytes(b"B" * 4096)                      # same size, same mtime: rsync skips it
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    group = type("Group", (), {"ensure_active": lambda self: None, "journal": None})()
    pair = CopyPair(src, dst, src, "x", ())
    import distromove.copy_ext4 as module
    original, module._check_pairs = module._check_pairs, lambda *a, **k: None
    try:
        assert checksum_candidates_pass(r, [pair], group, started) >= 1
    finally:
        module._check_pairs = original
    assert (dst / "load" / "f1").read_bytes() == b"B" * 4096
    assert (dst / "load").stat().st_mtime_ns == (src / "load").stat().st_mtime_ns
