import json
import os
import shutil
import signal
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from distromove.journal import (AlreadyRunning, Journal, Lock, Residue, archived_journals,
                                current_journal, open_windows, read_journal, recover,
                                write_atomic)
from distromove.model import LuksInfo, MountInfo, SwapRef, SystemSnapshot, VolumeIdentity

SRC = str(Path(__file__).resolve().parent.parent / "src")

ROOT_UUID = "0f1e2d3c-4b5a-4968-8776-655443322110"
OTHER_ROOT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
WWN = "0x5000c500a1b2c3d4"
PU = {c: f"{c * 8}-1111-4222-8333-444455556666" for c in "abcdefgh"}
FU = {c: f"{c * 8}-9999-4888-8777-666655554444" for c in "abcdefgh"}
LU = {c: f"{c * 8}-5555-4555-8555-555555555555" for c in "abcdefgh"}
PU_IDLE = "99999999-1111-4222-8333-444455556666"


def child_env():
    return {"PYTHONPATH": SRC, "PYTHONDONTWRITEBYTECODE": "1", "PATH": os.environ.get("PATH", "")}


def part_identity(partuuid, start=2048, size=4096, wwn=WWN):
    return {"partuuid": partuuid, "disk_wwn": wwn, "disk_serial": "SER123",
            "disk_by_id": "/dev/disk/by-id/ata-NEWDISK_SER123",
            "start_sectors": start, "size_sectors": size}


def live_volume(partuuid, start=2048, size=4096, wwn=WWN, fs_uuid=None, luks_uuid=None):
    return VolumeIdentity(volume_id="", role="extra", disk_wwn=wwn, disk_serial="SER123",
                          disk_by_id="/dev/disk/by-id/ata-NEWDISK_SER123", partuuid=partuuid,
                          start_sectors=start, size_sectors=size, luks_uuid=luks_uuid,
                          fs_uuid=fs_uuid)


def snapshot(identities=(), *, fstab="", crypttab="", mounts=(), mappers=(), swaps=(),
             esp_contents=None, boot_current=None, boot_entries=None,
             running_root_uuid=ROOT_UUID):
    return SystemSnapshot(fstab=fstab, crypttab=crypttab, mounts=list(mounts),
                          mappers=list(mappers), swaps=list(swaps),
                          esp_contents=dict(esp_contents or {}), boot_current=boot_current,
                          boot_entries=dict(boot_entries or {}), identities=list(identities),
                          running_root_uuid=running_root_uuid)


def NO_LINKS(path):
    """Resolver for a system where no /dev/disk link exists."""
    return path


def links(mapping):
    return lambda path: mapping.get(path, path)


def new_journal(jdir, migration_id="m1", host=ROOT_UUID):
    return Journal(jdir, migration_id=migration_id, host_root_uuid=host)


@pytest.fixture
def fsyncs(monkeypatch):
    """Record every os.fsync: (path of the descriptor, file content at that moment)."""
    real = os.fsync
    calls = []

    def recording_fsync(fd):
        path = os.readlink(f"/proc/self/fd/{fd}")
        content = Path(path).read_bytes() if os.path.isfile(path) else None
        real(fd)
        calls.append((path, content))

    monkeypatch.setattr(os, "fsync", recording_fsync)
    return calls


def test_intent_fsynced_before_return_and_returns_op_id(tmp_path, fsyncs):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    real_dir = str(jdir.resolve())
    # creation of the journal file and of the `current` link is durable
    assert (real_dir, None) in fsyncs
    assert os.readlink(jdir / "current") == j.path.name
    fsyncs.clear()

    op_id = j.intend("create_partition", part_identity(PU["a"]), creates="partition",
                     path="/dev/vdb2")
    assert isinstance(op_id, str) and op_id
    # at return the line is on disk: the journal file was fsynced while holding it
    synced = [c for p, c in fsyncs if p == str(j.path.resolve())]
    assert synced, "journal file was not fsynced"
    last = json.loads(synced[-1].decode().splitlines()[-1])
    assert last["type"] == "intent" and last["op_id"] == op_id
    assert last["op"] == "create_partition"
    assert last["identity"]["partuuid"] == PU["a"]
    assert last["fields"] == {"creates": "partition", "path": "/dev/vdb2"}
    # ...and so was its directory
    assert (real_dir, None) in fsyncs

    other = j.intend("create_partition", part_identity(PU["b"], start=8192), creates="partition")
    assert other != op_id
    # files are private
    assert stat.S_IMODE(j.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(jdir.stat().st_mode) == 0o700


@pytest.mark.parametrize("identity, fields", [
    ({"luks_uuid": LU["a"]}, {"key": b"secret-bytes"}),
    ({"luks_uuid": LU["a"]}, {"key": bytearray(b"secret-bytes")}),
    ({"luks_uuid": LU["a"]}, {"passphrase": "secret-text"}),
    ({"luks_uuid": LU["a"], "New_PassPhrase": "secret-text"}, {}),
    ({"luks_uuid": LU["a"]}, {"extra": {"nested": [b"secret-bytes"]}}),
    ({"luks_uuid": LU["a"]}, {"extra": {"old_passphrase": "secret-text"}}),
    ({"luks_uuid": b"secret-bytes"}, {}),
])
def test_secret_rejected(tmp_path, identity, fields):
    j = new_journal(tmp_path / "journal")
    with pytest.raises(ValueError):
        j.intend("luks_format", identity, **fields)
    op = j.intend("luks_format", {"luks_uuid": LU["a"]}, keyfile="/etc/keys/root.key")
    with pytest.raises(ValueError):
        j.done(op, "ok", **fields) if fields else j.done(op, "ok", passphrase="secret-text")
    text = j.path.read_text()
    assert "secret" not in text
    assert [e["type"] for e in read_journal(j.path)] == ["header", "intent"]


def test_done_links_to_intent(tmp_path):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    a = j.intend("create_partition", part_identity(PU["a"]), creates="partition")
    b = j.intend("create_partition", part_identity(PU["b"], start=8192), creates="partition")
    j.done(b, "created", path="/dev/vdb3")
    j.done(a, "failed", error="sgdisk exited 4")

    entries = read_journal(j.path)
    header = entries[0]
    assert header["type"] == "header" and header["migration_id"] == "m1"
    assert header["host_root_uuid"] == ROOT_UUID
    intents = {e["op_id"]: e for e in entries if e["type"] == "intent"}
    outcomes = [e for e in entries if e["type"] == "outcome"]
    assert set(intents) == {a, b}
    assert [(o["op_id"], o["outcome"]) for o in outcomes] == [(b, "created"), (a, "failed")]
    assert outcomes[0]["fields"] == {"path": "/dev/vdb3"}
    assert all(o["op_id"] in intents for o in outcomes)

    with pytest.raises(ValueError):
        j.done("no-such-op", "created")

    # reopening the same migration journal keeps linking to the earlier intents
    j2 = new_journal(jdir)
    assert j2.path == j.path
    j2.done(a, "removed")
    assert read_journal(j.path)[-1]["op_id"] == a
    # a journal of another system is never reopened as if it were ours
    with pytest.raises(ValueError):
        new_journal(jdir, host=OTHER_ROOT)


def test_torn_last_line_is_ignored(tmp_path):
    j = new_journal(tmp_path / "journal")
    a = j.intend("create_partition", part_identity(PU["a"]), creates="partition")
    with open(j.path, "a") as f:
        f.write('{"type": "intent", "op_id": "x", "op"')  # power lost mid-write
    assert [e.get("op_id") for e in read_journal(j.path)] == [None, a]
    live = snapshot([live_volume(PU["a"])])
    assert [r.identity["partuuid"] for r in recover(tmp_path / "journal", live, ROOT_UUID)] == [PU["a"]]
    # after a restart the next line is not glued to the torn one
    j2 = new_journal(tmp_path / "journal")
    b = j2.intend("create_partition", part_identity(PU["b"], start=8192), creates="partition")
    assert [e.get("op_id") for e in read_journal(j.path)] == [None, a, b]


def test_write_atomic_fsyncs_file_then_directory(tmp_path, fsyncs):
    target = tmp_path / "state.json"
    write_atomic(target, b'{"phase": "PREPARED"}')
    assert target.read_bytes() == b'{"phase": "PREPARED"}'
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    real_dir = str(tmp_path.resolve())
    assert fsyncs[0][1] == b'{"phase": "PREPARED"}' and str(Path(fsyncs[0][0]).parent) == real_dir
    assert fsyncs[-1] == (real_dir, None)
    assert os.listdir(tmp_path) == ["state.json"]


LOCK_HOLDER = """
import sys, time
from pathlib import Path
from distromove.journal import Lock
with Lock(Path(sys.argv[1])):
    print("locked", flush=True)
    time.sleep(120)
"""

LOCK_TRY = """
import sys
from pathlib import Path
from distromove.journal import AlreadyRunning, Lock
try:
    with Lock(Path(sys.argv[1])):
        sys.exit(0)
except AlreadyRunning:
    sys.exit(3)
"""


def test_lock_blocks_second_instance(tmp_path):
    lock_path = tmp_path / "distromove.lock"
    with Lock(lock_path):
        with pytest.raises(AlreadyRunning) as ei:
            with Lock(lock_path):
                pass
        assert str(os.getpid()) in str(ei.value)
        res = subprocess.run([sys.executable, "-c", LOCK_TRY, str(lock_path)],
                             env=child_env(), timeout=30)
        assert res.returncode == 3
    # released when the block ends
    res = subprocess.run([sys.executable, "-c", LOCK_TRY, str(lock_path)],
                         env=child_env(), timeout=30)
    assert res.returncode == 0


def test_lock_released_after_kill(tmp_path):
    lock_path = tmp_path / "distromove.lock"
    child = subprocess.Popen([sys.executable, "-c", LOCK_HOLDER, str(lock_path)],
                             stdout=subprocess.PIPE, text=True, env=child_env())
    try:
        assert child.stdout.readline().strip() == "locked"
        with pytest.raises(AlreadyRunning) as ei:
            with Lock(lock_path):
                pass
        assert str(child.pid) in str(ei.value)
        child.send_signal(signal.SIGKILL)
        assert child.wait(timeout=30) == -signal.SIGKILL
        with Lock(lock_path):
            pass
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        child.stdout.close()


DIE_AFTER_INTENT = """
import json, os, signal, sys
from pathlib import Path
from distromove.journal import Journal
j = Journal(Path(sys.argv[1]), migration_id="m1", host_root_uuid=sys.argv[2])
j.intend("create_partition", json.loads(sys.argv[3]), creates="partition", path="/dev/vdb2")
# the partition gets created here, then the process dies before the outcome line
os.kill(os.getpid(), signal.SIGKILL)
"""


def test_recover_finds_resource_with_intent_but_no_outcome(tmp_path):
    jdir = tmp_path / "journal"
    identity = part_identity(PU["a"])
    res = subprocess.run([sys.executable, "-c", DIE_AFTER_INTENT, str(jdir), ROOT_UUID,
                          json.dumps(identity)], env=child_env(), timeout=30)
    assert res.returncode == -signal.SIGKILL
    assert [e["type"] for e in read_journal(jdir / "journal-m1.jsonl")] == ["header", "intent"]

    # the partition with the pre-assigned identity exists and nothing uses it
    live = snapshot([live_volume(PU["a"]), live_volume(PU["h"], start=10_000)])
    residues = recover(jdir, live, ROOT_UUID)
    assert len(residues) == 1
    r = residues[0]
    assert isinstance(r, Residue)
    assert r.kind == "partition"
    assert r.identity == identity
    assert r.proof["outcome"] is None
    assert r.proof["migration_id"] == "m1"
    assert r.proof["live"]["partuuid"] == PU["a"]

    # not created at all (died before creating): nothing to recover
    assert recover(jdir, snapshot([live_volume(PU["h"], start=10_000)]), ROOT_UUID) == []


def test_recover_ignores_lookalike_label_without_matching_identity(tmp_path):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    op = j.intend("create_partition", part_identity(PU["a"]), creates="partition",
                  label="distromove-root", path="/dev/vdb2")
    j.done(op, "created")
    j.intend("mkfs", {"fs_uuid": FU["a"], "partuuid": PU["a"]}, creates="filesystem",
             label="distromove-root")
    # same disk, same place, same label: but another PARTUUID and another filesystem UUID
    live = snapshot([live_volume(PU["b"], fs_uuid=FU["b"])])
    assert recover(jdir, live, ROOT_UUID) == []


@pytest.mark.parametrize("live_ids", [
    [live_volume(PU["a"], start=4096)],                       # moved
    [live_volume(PU["a"], size=8192)],                        # resized
    [live_volume(PU["a"], wwn="0x5000c500ffffffff")],         # on another disk
    [live_volume(PU["a"], wwn=None)],                         # disk identity lost
    [live_volume(PU["a"]), live_volume(PU["a"], start=9000)],  # ambiguous duplicate
], ids=["moved", "resized", "other-disk", "no-disk-id", "duplicate"])
def test_recover_skips_when_identity_changed(tmp_path, live_ids):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    j.done(j.intend("create_partition", part_identity(PU["a"]), creates="partition"), "created")
    assert recover(jdir, snapshot(live_ids), ROOT_UUID) == []


def test_recover_skips_luks_container_found_on_another_partition(tmp_path):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    j.intend("luks_format", {"luks_uuid": LU["a"], "partuuid": PU["a"]}, creates="luks")
    assert recover(jdir, snapshot([live_volume(PU["b"], luks_uuid=LU["a"])]), ROOT_UUID) == []
    found = recover(jdir, snapshot([live_volume(PU["a"], luks_uuid=LU["a"])]), ROOT_UUID)
    assert [(r.kind, r.identity["luks_uuid"]) for r in found] == [("luks", LU["a"])]


def test_recover_ignores_operations_that_create_nothing(tmp_path):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    # a removal journaled with the identity of an existing partition is not a residue
    j.done(j.intend("remove_partition", part_identity(PU["a"])), "ok")
    assert recover(jdir, snapshot([live_volume(PU["a"])]), ROOT_UUID) == []


def test_window_open_without_close_reported(tmp_path):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    w1 = j.window_open("freeze:/,/home")
    j.window_close(w1)
    w2 = j.window_open("freeze:/")
    wins = open_windows(jdir, ROOT_UUID)
    assert [(w.op_id, w.name) for w in wins] == [(w2, "freeze:/")]
    assert wins[0].opened_at
    # only the journal of the current migration on this system counts
    assert open_windows(jdir, OTHER_ROOT) == []
    # window_close only closes windows
    op = j.intend("mount", {"target": "/mnt/new"})
    with pytest.raises(ValueError):
        j.window_close(op)
    j.window_close(w2)
    assert open_windows(jdir, ROOT_UUID) == []


def test_install_into_new_root_fsyncs_file_and_directory(tmp_path, fsyncs):
    jdir = tmp_path / "src" / "var" / "lib" / "distromove"
    j = new_journal(jdir)
    j.done(j.intend("create_partition", part_identity(PU["a"]), creates="partition"), "created")
    new_root = tmp_path / "newroot"
    (new_root / "var" / "lib").mkdir(parents=True)
    fsyncs.clear()

    j.install_into(new_root)

    dest_dir = new_root / jdir.relative_to("/")
    dest = dest_dir / j.path.name
    content = j.path.read_bytes()
    assert dest.read_bytes() == content
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600
    real_dest_dir = str(dest_dir.resolve())
    file_syncs = [i for i, (p, c) in enumerate(fsyncs)
                  if c == content and str(Path(p).parent) == real_dest_dir]
    dir_syncs = [i for i, (p, c) in enumerate(fsyncs) if p == real_dest_dir]
    assert file_syncs, "installed journal file was not fsynced"
    assert dir_syncs and max(dir_syncs) > min(file_syncs), "directory not fsynced after the file"
    assert not [p for p in os.listdir(dest_dir) if p != j.path.name], "temporary files left"
    # the source journal is untouched and still the current one
    assert current_journal(jdir, ROOT_UUID) == j.path


def test_recover_ignores_inherited_journal_of_other_migration(tmp_path):
    jdir = tmp_path / "journal"
    live = snapshot([live_volume(PU["a"]), live_volume(PU["b"], start=10_000),
                     live_volume(PU["c"], start=20_000)])

    earlier = new_journal(jdir, migration_id="earlier")
    earlier.done(earlier.intend("create_partition", part_identity(PU["a"]), creates="partition"),
                 "created")
    current = new_journal(jdir, migration_id="current")
    current.intend("create_partition", part_identity(PU["b"], start=10_000), creates="partition")
    found = recover(jdir, live, ROOT_UUID)
    assert [r.identity["partuuid"] for r in found] == [PU["b"]]
    assert archived_journals(jdir, ROOT_UUID) == [earlier.path]

    # a journal written by another system (copied in with the data) became `current`:
    # it is archived and never acted upon, nor does it revive the earlier ones
    inherited = new_journal(jdir, migration_id="inherited", host=OTHER_ROOT)
    inherited.intend("create_partition", part_identity(PU["c"], start=20_000), creates="partition")
    assert current_journal(jdir, ROOT_UUID) is None
    assert recover(jdir, live, ROOT_UUID) == []
    assert sorted(archived_journals(jdir, ROOT_UUID)) == sorted(
        [earlier.path, current.path, inherited.path])

    # no `current` link at all: nothing is the current migration
    os.unlink(jdir / "current")
    assert recover(jdir, live, ROOT_UUID) == []
    # a `current` link pointing outside the journal directory is not followed
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    shutil.copy(current.path, outside / current.path.name)
    os.symlink(outside / current.path.name, jdir / "current")
    assert recover(jdir, live, ROOT_UUID) == []


def test_recover_never_returns_an_active_resource(tmp_path):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    layout = {  # how each created partition is in use: (letter, start sector, journal fields)
        "mounted_by_path": ("a", 1_000, {"path": "/dev/vdb1"}),
        "mounted_by_uuid": ("b", 2_000, {}),
        "in_fstab": ("c", 3_000, {}),
        "in_crypttab": ("d", 4_000, {}),
        "mapper_by_name": ("e", 5_000, {"mapper_name": "distromove-m1-home"}),
        "mapper_by_dm_uuid": ("f", 6_000, {}),
        "swap": ("g", 7_000, {}),
    }
    for c, start, fields in layout.values():
        op = j.intend("create_partition", part_identity(PU[c], start=start), creates="partition",
                      **fields)
        j.done(op, "created")
    j.done(j.intend("create_partition", part_identity(PU["h"], start=8_000), creates="partition"),
           "created")
    j.done(j.intend("create_partition", part_identity(PU_IDLE, start=9_000), creates="partition"),
           "created")

    encrypted = ("in_crypttab", "mapper_by_name", "mapper_by_dm_uuid")
    ids = [live_volume(PU[c], start=start, fs_uuid=FU[c],
                       luks_uuid=LU[c] if name in encrypted else None)
           for name, (c, start, _) in layout.items()]
    ids.append(live_volume(PU["h"], start=8_000, fs_uuid=ROOT_UUID))  # the running root
    ids.append(live_volume(PU_IDLE, start=9_000))
    live = snapshot(
        ids,
        fstab=f"UUID={ROOT_UUID} / ext4 defaults 0 1\nUUID={FU['c'].upper()} /data ext4 defaults 0 2\n",
        crypttab=f"data_crypt UUID={LU['d']} none luks\n",
        mounts=[MountInfo("/dev/vdb1", "/media/user/disk", "ext4", "rw,nosuid"),
                MountInfo(f"/dev/disk/by-partuuid/{PU['b']}", "/mnt/b", "ext4", "rw")],
        mappers=["distromove-m1-home CRYPT-PLAIN-distromove-m1-home",
                 f"other CRYPT-LUKS2-{LU['f'].replace('-', '')}-other"],
        swaps=[SwapRef("swap0", "partition", "/dev/vdb7", None, FU["g"], 1 << 30, None, False)],
    )
    found = recover(jdir, live, ROOT_UUID, resolve=NO_LINKS)
    assert [r.identity["partuuid"] for r in found] == [PU_IDLE]
    # the running root is excluded whether the argument or the snapshot names it
    as_root = [live_volume(PU["h"], start=8_000, fs_uuid=ROOT_UUID)]
    assert recover(jdir, snapshot(as_root, running_root_uuid=""), ROOT_UUID) == []
    as_root = [live_volume(PU["h"], start=8_000, fs_uuid=FU["h"])]
    assert recover(jdir, snapshot(as_root, running_root_uuid=FU["h"]), ROOT_UUID) == []
    assert len(recover(jdir, snapshot(as_root), ROOT_UUID)) == 1


def test_recover_excludes_encrypted_swap_and_mapper_of_open_container(tmp_path):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    j.intend("luks_format", {"luks_uuid": LU["a"], "partuuid": PU["a"]}, creates="luks")
    luks = LuksInfo(2, "aes-xts-plain64", 512, 4096, [], LU["a"], "swap_crypt")
    live = snapshot([live_volume(PU["a"], luks_uuid=LU["a"])],
                    swaps=[SwapRef("swap0", "partition", "/dev/mapper/swap_crypt", None, None,
                                   1 << 30, luks, False)])
    assert recover(jdir, live, ROOT_UUID) == []


# ------------------------------------------------------------------ in-use detection

def test_recover_sees_device_path_recorded_only_on_the_outcome(tmp_path):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    op = j.intend("create_partition", part_identity(PU["a"]), creates="partition")
    j.done(op, "created", path="/dev/vdb2")  # the kernel path is known only once created
    j.done(j.intend("mkfs", {"fs_uuid": FU["a"], "partuuid": PU["a"]}, creates="filesystem"),
           "ok")
    live_ids = [live_volume(PU["a"], fs_uuid=FU["a"])]
    mounted = snapshot(live_ids, mounts=[
        MountInfo("/dev/vdb2", "/mnt/distromove-m1/root", "ext4", "rw,relatime")])
    assert recover(jdir, mounted, ROOT_UUID, resolve=NO_LINKS) == []
    idle = recover(jdir, snapshot(live_ids), ROOT_UUID, resolve=NO_LINKS)
    assert [r.kind for r in idle] == ["partition", "filesystem"]


def test_recover_sees_mapper_named_only_by_a_later_luks_open(tmp_path):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    j.done(j.intend("create_partition", part_identity(PU["a"]), creates="partition"), "created")
    j.done(j.intend("luks_format", {"luks_uuid": LU["a"], "partuuid": PU["a"]}, creates="luks"),
           "ok")
    j.done(j.intend("luks_open", {"luks_uuid": LU["a"]}, mapper_name="distromove-m1-root"), "ok")
    in_mount = [MountInfo("/dev/mapper/distromove-m1-root", "/mnt/distromove-m1/root", "ext4",
                          "rw")]
    in_table = ["distromove-m1-root CRYPT-PLAIN-distromove-m1-root"]
    for live_ids in ([live_volume(PU["a"], luks_uuid=LU["a"])],
                     # the container's UUID not visible: still linked through luks_format
                     [live_volume(PU["a"])]):
        assert recover(jdir, snapshot(live_ids, mounts=in_mount), ROOT_UUID,
                       resolve=NO_LINKS) == []
        assert recover(jdir, snapshot(live_ids, mappers=in_table), ROOT_UUID,
                       resolve=NO_LINKS) == []
    idle = recover(jdir, snapshot([live_volume(PU["a"], luks_uuid=LU["a"])]), ROOT_UUID,
                   resolve=NO_LINKS)
    assert [r.kind for r in idle] == ["partition", "luks"]


def test_recover_treats_mapper_without_dm_uuid_as_possibly_an_open_container(tmp_path):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    j.done(j.intend("luks_format", {"luks_uuid": LU["a"], "partuuid": PU["a"]}, creates="luks"),
           "ok")
    j.done(j.intend("create_partition", part_identity(PU["b"], start=10_000),
                    creates="partition"), "created")
    live_ids = [live_volume(PU["a"], luks_uuid=LU["a"]), live_volume(PU["b"], start=10_000)]
    unknown = recover(jdir, snapshot(live_ids, mappers=["cryptdata"]), ROOT_UUID,
                      resolve=NO_LINKS)
    assert [r.identity.get("partuuid") for r in unknown] == [PU["b"]]  # plain one only
    known = recover(jdir, snapshot(live_ids, mappers=["vg0-swap LVM-Q2x9abcdef"]), ROOT_UUID,
                    resolve=NO_LINKS)
    assert [r.kind for r in known] == ["luks", "partition"]


def test_recover_resolves_renamed_kernel_device(tmp_path):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    op = j.intend("create_partition", part_identity(PU["a"]), creates="partition",
                  path="/dev/vdb2")
    j.done(op, "created", path="/dev/vdb2")
    live_ids = [live_volume(PU["a"], fs_uuid=FU["a"])]
    # after a reboot the disk is vdc and the desktop mounted the partition by kernel path
    automounted = snapshot(live_ids, mounts=[
        MountInfo("/dev/vdc2", "/media/user/root", "ext4", "rw,nosuid,nodev")])
    by_partuuid = links({f"/dev/disk/by-partuuid/{PU['a']}": "/dev/vdc2"})
    by_uuid = links({f"/dev/disk/by-uuid/{FU['a']}": "/dev/vdc2"})
    assert recover(jdir, automounted, ROOT_UUID, resolve=by_partuuid) == []
    assert recover(jdir, automounted, ROOT_UUID, resolve=by_uuid) == []
    # active swap on the renamed device is seen the same way
    swapping = snapshot(live_ids, swaps=[
        SwapRef("s", "partition", "/dev/vdc2", None, None, 1 << 30, None, False)])
    assert recover(jdir, swapping, ROOT_UUID, resolve=by_partuuid) == []
    # it is the stable link that ties the mount to the partition: the stale path does not
    assert len(recover(jdir, automounted, ROOT_UUID, resolve=NO_LINKS)) == 1


def test_recover_resolves_by_id_and_case_of_uuid_links(tmp_path):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    j.done(j.intend("create_partition", part_identity(PU["b"]), creates="partition", number=1),
           "created")
    j.done(j.intend("mkfs", {"fs_uuid": "abcd-1234", "partuuid": PU["b"]}, creates="filesystem"),
           "ok")
    live_ids = [live_volume(PU["b"], fs_uuid="abcd-1234")]
    mounted = snapshot(live_ids, mounts=[MountInfo("/dev/sdc1", "/media/user/ESP", "vfat", "rw")])
    by_id = links({"/dev/disk/by-id/ata-NEWDISK_SER123-part1": "/dev/sdc1"})
    upper = links({"/dev/disk/by-uuid/ABCD-1234": "/dev/sdc1"})  # vfat links are upper case
    assert recover(jdir, mounted, ROOT_UUID, resolve=by_id) == []
    assert recover(jdir, mounted, ROOT_UUID, resolve=upper) == []
    assert len(recover(jdir, mounted, ROOT_UUID, resolve=NO_LINKS)) == 2


# ------------------------------------------------------------------ end of a migration

def test_finish_retires_current_and_ends_recovery(tmp_path, fsyncs):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    op = j.intend("create_partition", part_identity(PU["a"]), creates="partition")
    j.done(op, "created")
    live = snapshot([live_volume(PU["a"])])
    assert len(recover(jdir, live, ROOT_UUID)) == 1
    fsyncs.clear()

    j.finish("activated")

    end = read_journal(j.path)[-1]
    assert end["type"] == "end" and end["outcome"] == "activated"
    assert not os.path.lexists(jdir / "current")
    real_dir = str(jdir.resolve())
    file_syncs = [i for i, (p, c) in enumerate(fsyncs)
                  if p == str(j.path.resolve()) and b'"type":"end"' in c]
    dir_syncs = [i for i, (p, c) in enumerate(fsyncs) if p == real_dir]
    assert file_syncs and dir_syncs and max(dir_syncs) > min(file_syncs)
    # booted back into the source: the migrated system's volumes are not residues
    assert recover(jdir, live, ROOT_UUID) == []
    assert current_journal(jdir, ROOT_UUID) is None
    assert open_windows(jdir, ROOT_UUID) == []
    assert archived_journals(jdir, ROOT_UUID) == [j.path]
    with pytest.raises(RuntimeError):
        j.intend("create_partition", part_identity(PU["b"]), creates="partition")
    with pytest.raises(RuntimeError):
        j.done(op, "removed")
    with pytest.raises(ValueError):
        new_journal(jdir)  # a finished journal is never reopened


def test_finished_journal_is_ignored_even_if_current_link_survived(tmp_path):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    j.done(j.intend("create_partition", part_identity(PU["a"]), creates="partition"), "created")
    j.finish("activated")
    os.symlink(j.path.name, jdir / "current")  # power lost between the end line and unlink
    assert current_journal(jdir, ROOT_UUID) is None
    assert recover(jdir, snapshot([live_volume(PU["a"])]), ROOT_UUID) == []


DIE_BEFORE_LINK = """
import os, signal, sys
from pathlib import Path
import distromove.journal as jm

def die(*args, **kwargs):
    os.kill(os.getpid(), signal.SIGKILL)

jm.link_atomic = die
jm.Journal(Path(sys.argv[1]), migration_id=sys.argv[3], host_root_uuid=sys.argv[2])
"""


def test_new_journal_killed_before_linking_current(tmp_path):
    jdir = tmp_path / "journal"
    live = snapshot([live_volume(PU["a"]), live_volume(PU["b"], start=10_000)])

    done = new_journal(jdir, migration_id="m1")
    done.done(done.intend("create_partition", part_identity(PU["a"]), creates="partition"),
              "created")
    done.finish("activated")
    os.symlink(done.path.name, jdir / "current")  # stale link left over
    res = subprocess.run([sys.executable, "-c", DIE_BEFORE_LINK, str(jdir), ROOT_UUID, "m2"],
                         env=child_env(), timeout=30)
    assert res.returncode == -signal.SIGKILL
    assert [e["type"] for e in read_journal(jdir / "journal-m2.jsonl")] == ["header"]
    # the completed migration is not revived, and the new one never wrote an intent
    assert recover(jdir, live, ROOT_UUID) == []

    # an unfinished earlier migration stays current: its leftovers are real
    os.unlink(jdir / "current")
    crashed = new_journal(jdir, migration_id="m3")
    crashed.intend("create_partition", part_identity(PU["b"], start=10_000), creates="partition")
    res = subprocess.run([sys.executable, "-c", DIE_BEFORE_LINK, str(jdir), ROOT_UUID, "m4"],
                         env=child_env(), timeout=30)
    assert res.returncode == -signal.SIGKILL
    assert [r.identity["partuuid"] for r in recover(jdir, live, ROOT_UUID)] == [PU["b"]]


def test_intend_refused_when_journal_is_no_longer_current(tmp_path):
    jdir = tmp_path / "journal"
    j1 = new_journal(jdir, migration_id="m1")
    a = j1.intend("create_partition", part_identity(PU["a"]), creates="partition")
    new_journal(jdir, migration_id="m2")
    with pytest.raises(RuntimeError):
        j1.intend("create_partition", part_identity(PU["b"]), creates="partition")
    with pytest.raises(RuntimeError):
        j1.window_open("freeze:/")
    j1.done(a, "created")  # outcomes of operations already journaled are still recorded
    assert [e["type"] for e in read_journal(j1.path)] == ["header", "intent", "outcome"]


def test_finish_refused_while_a_freeze_window_is_open(tmp_path):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    w = j.window_open("freeze:/")
    with pytest.raises(RuntimeError):
        j.finish()
    with pytest.raises(RuntimeError):
        new_journal(jdir).finish()  # also when reopened after a restart
    j.window_close(w)
    j.finish()
    assert read_journal(j.path)[-1]["type"] == "end"


# ------------------------------------------------------------------ EFI and NVRAM

ESP = "c0ffee00-1111-4222-8333-444455556666"
ESP_OLD = "0e5f0e5f-1111-4222-8333-444455556666"
OLD_ENTRY = f"Boot0000* debian\tHD(1,GPT,{ESP_OLD},0x800,0x100000)/File(\\EFI\\debian\\shimx64.efi)"
NEW_ENTRY = (f"Boot0007* DistroMove (new)\tHD(1,GPT,{ESP},0x800,0x100000)"
             "/File(\\EFI\\distromove\\shimx64.efi)")
EFI_ID = {"esp_partuuid": ESP, "efi_dir": "distromove"}
NVRAM_ID = {"esp_partuuid": ESP, "loader": "/EFI/distromove/shimx64.efi",
            "label": "DistroMove (new)"}


def efi_journal(jdir, bootnum="0007"):
    j = new_journal(jdir)
    j.done(j.intend("copy_esp", EFI_ID, creates="efi_dir"), "created")
    op = j.intend("register_entry", NVRAM_ID, creates="nvram_entry")
    if bootnum is not None:
        j.done(op, "created", bootnum=bootnum)
    return j


def boot_snapshot(entries, current="0000", contents=None, identities=()):
    return snapshot(identities, esp_contents=contents or {ESP.upper(): ["BOOT", "DistroMove"],
                                                          ESP_OLD: ["BOOT", "debian"]},
                    boot_current=current, boot_entries=entries)


def test_recover_reports_efi_dir_and_nvram_entry(tmp_path):
    live = boot_snapshot({"0000": OLD_ENTRY, "0007": NEW_ENTRY})
    efi_journal(tmp_path / "a")
    found = recover(tmp_path / "a", live, ROOT_UUID)
    assert [(r.kind, r.proof["live"]) for r in found] == [
        ("efi_dir", {"esp_partuuid": ESP.upper(), "efi_dir": "DistroMove"}),
        ("nvram_entry", {"bootnum": "0007", "entry": NEW_ENTRY})]
    assert found[0].identity == EFI_ID and found[1].identity == NVRAM_ID
    # the process died after efibootmgr and before the outcome: found by ESP and loader
    efi_journal(tmp_path / "b", bootnum=None)
    found = recover(tmp_path / "b", live, ROOT_UUID)
    assert [(r.kind, r.proof["outcome"]) for r in found] == [("efi_dir", "created"),
                                                             ("nvram_entry", None)]
    assert found[1].proof["live"]["bootnum"] == "0007"


def test_recover_never_returns_booted_nvram_entry_or_its_efi_dir(tmp_path):
    j = efi_journal(tmp_path / "journal")
    j.done(j.intend("create_partition", part_identity(ESP), creates="partition"), "created")
    entries = {"0000": OLD_ENTRY, "0007": NEW_ENTRY}
    esp = [live_volume(ESP)]
    booted = boot_snapshot(entries, current="0007", identities=esp)
    assert recover(tmp_path / "journal", booted, ROOT_UUID, resolve=NO_LINKS) == []
    # booted from the old system: entry, directory and new ESP are all leftovers
    other = boot_snapshot(entries, current="0000", identities=esp)
    assert {r.kind for r in recover(tmp_path / "journal", other, ROOT_UUID, resolve=NO_LINKS)} == {
        "efi_dir", "nvram_entry", "partition"}


@pytest.mark.parametrize("case", [
    "dir-on-other-esp", "dir-used-by-foreign-entry", "entry-other-esp", "entry-other-loader",
    "entry-other-label",
    "recorded-number-reused", "ambiguous-entries"])
def test_recover_ignores_efi_and_nvram_lookalikes(tmp_path, case):
    entries = {"0000": OLD_ENTRY, "0007": NEW_ENTRY}
    contents = None
    bootnum = "0007"
    expected = {"efi_dir", "nvram_entry"}
    if case == "dir-on-other-esp":
        contents = {ESP_OLD: ["BOOT", "debian", "distromove"], ESP: ["BOOT"]}
        expected = {"nvram_entry"}
    elif case == "dir-used-by-foreign-entry":
        entries["0003"] = (f"Boot0003* Other\tHD(1,GPT,{ESP},0x800,0x100000)"
                           "/File(\\EFI\\distromove\\grubx64.efi)")
        expected = {"nvram_entry"}
    elif case == "entry-other-esp":
        entries["0007"] = NEW_ENTRY.replace(ESP, ESP_OLD)  # same label and loader path
        expected = {"efi_dir"}
    elif case == "entry-other-loader":
        entries["0007"] = NEW_ENTRY.replace("\\distromove\\", "\\debian\\")
        expected = {"efi_dir"}
    elif case == "entry-other-label":
        entries["0007"] = NEW_ENTRY.replace("DistroMove (new)", "Other system")
        expected = set()  # not ours, and it points into our EFI dir: the dir is in use
    elif case == "recorded-number-reused":
        entries["0007"] = OLD_ENTRY.replace("Boot0000", "Boot0007")
        entries["0008"] = NEW_ENTRY.replace("Boot0007", "Boot0008")
        expected = set()  # 0008 is not ours; and it keeps our EFI dir in use
    elif case == "ambiguous-entries":
        bootnum = None
        entries["0008"] = NEW_ENTRY.replace("Boot0007", "Boot0008")
        expected = set()
    efi_journal(tmp_path / "journal", bootnum=bootnum)
    found = recover(tmp_path / "journal", boot_snapshot(entries, contents=contents), ROOT_UUID)
    assert {r.kind for r in found} == expected


def test_recover_never_reports_btrfs_snapshots(tmp_path):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    j.done(j.intend("snapshot", {"fs_uuid": FU["a"], "snapshot_path": "@distromove-m1"},
                    creates="snapshot"), "created")
    assert recover(jdir, snapshot([live_volume(PU["a"], fs_uuid=FU["a"])]), ROOT_UUID) == []


@pytest.mark.xfail(strict=False, reason="recover() never matches a created partition whose "
                   "planned fs_uuid cannot be read (closed LUKS container, no filesystem yet), "
                   "so rollback of an encrypted destination ends in manual review")
def test_recover_matches_created_partition_whose_planned_fs_uuid_is_unreadable(tmp_path):
    jdir = tmp_path / "journal"
    j = new_journal(jdir)
    identity = dict(part_identity(PU["a"]), luks_uuid=LU["a"], fs_uuid=FU["a"])
    j.done(j.intend("create_partition", identity, creates="partition", path="/dev/vdb2"),
           "created")
    # the container is closed again: only the LUKS UUID is readable, the inner fs is not
    live = snapshot([live_volume(PU["a"], luks_uuid=LU["a"], fs_uuid=None)])
    found = recover(jdir, live, ROOT_UUID)
    assert [r.kind for r in found] == ["partition"]
