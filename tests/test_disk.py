"""Destination creation is tested with command recorders, never real disks."""

from dataclasses import replace
import json
import subprocess

import pytest

from distromove.disk import (GrubCaps, KernelTableStale, UnsafeKeyfile, UnsupportedKdf,
                             add_keyfile, create_partitions, luks_format, luks_open, make_fs,
                             prove_unlock, validate_crypto_plan)
from distromove.journal import Journal, read_journal
from distromove.layout import (EspChoice, MigrationPlan, Partplan, TablesChanged,
                                fingerprint_tables)
from distromove.model import (CreatedPartition, Esp, Keyslot, LuksInfo, Partition,
                              PlannedIdentity, Source, SwapRef, Volume)


def partition():
    return Partition("/dev/vda2", "vda2", "/dev/vda", 2, 8 * 1024**3, "crypto_LUKS",
                     "old-luks", "old-part", None, "/", "wwn-1", "serial-1", None,
                     2048, 16 * 1024**3, 512)


def luks(*kdfs, keyfile=None, version=2):
    return LuksInfo(version, "aes-xts-plain64", 512, 512,
                    [Keyslot(i, kdf, "aes-xts-plain64") for i, kdf in enumerate(kdfs)],
                    "old-luks", "old-root", keyfile)


def source(*, root_luks=None, boot=None, swaps=(), boot_inside_luks=False):
    root = Volume("root", "root", "/", partition(), root_luks, "btrfs", "old-fs",
                  1024, 1024, 1, None, boot_inside_luks)
    vols = [root] + ([boot] if boot else [])
    return Source("btrfs", "debian", vols, [], Esp(partition(), "/boot/efi", [], []),
                  list(swaps), "old-fs", False)


CAPS = GrubCaps(frozenset({1, 2}), frozenset({"pbkdf2"}),
                frozenset({"aes-xts-plain64"}))


def test_preflight_refuses_argon2_only_with_boot_in_luks_before_any_call():
    with pytest.raises(UnsupportedKdf, match="PBKDF2"):
        validate_crypto_plan(source(root_luks=luks("argon2id"), boot_inside_luks=True), CAPS)


def test_crypto_plan_has_pbkdf2_slot_when_boot_in_luks():
    plan = validate_crypto_plan(source(root_luks=luks("argon2id", "pbkdf2"),
                                       boot_inside_luks=True), CAPS)
    assert [slot.kdf for slot in plan.per_volume["root"]] == ["pbkdf2"]
    assert plan.boot_in_luks == {"root": True}
    assert plan.luks_by_volume["root"].sector_size == 512


def test_preflight_rejects_grub_without_luks2_support():
    limited = replace(CAPS, luks_versions=frozenset({1}))
    with pytest.raises(UnsupportedKdf, match="GRUB"):
        validate_crypto_plan(source(root_luks=luks("pbkdf2"), boot_inside_luks=True), limited)


def test_initramfs_key_on_unencrypted_boot_refused_in_preflight():
    boot = Volume("boot", "boot", "/boot", partition(), None, "ext4", "boot-fs",
                  1024, 1024, 1, None, False)
    with pytest.raises(UnsafeKeyfile, match="unencrypted"):
        validate_crypto_plan(source(root_luks=luks("pbkdf2", keyfile="/etc/root.key"),
                                    boot=boot), CAPS)


def test_key_class_and_encrypted_swap_are_keyed_by_volume_id():
    swap = SwapRef("swap-1", "partition", "/dev/vda3", None, "old-swap", 1024**3,
                   luks("argon2id", keyfile="/etc/swap.key"), False)
    plan = validate_crypto_plan(source(root_luks=luks("pbkdf2"), swaps=[swap]), CAPS)
    assert set(plan.per_volume) == {"root", "swap-1"}
    assert plan.keyfiles == {"swap-1": "/etc/swap.key"}
    assert plan.key_class == {"swap-1": "after-root"}


DISK = "/dev/vdb"
OLD = {"node": "/dev/vdb1", "start": 2048, "size": 4096,
       "type": "0FC63DAF-8483-4772-8E79-3D69D8477DE4", "uuid": "old-part"}
NEW = {"node": "/dev/vdb2", "start": 8192, "size": 8192,
       "type": "CA7D7CCB-63ED-4C53-861C-1742536059CC", "uuid": "new-part"}


class PartitionRunner:
    """Model only read-only results and the scripted write; no command is executed."""

    def __init__(self, *, kernel_stale=False, old_changed=False, sector=512):
        self.calls = []
        self.written = False
        self.kernel_stale = kernel_stale
        self.old_changed = old_changed
        self.sector = sector

    def run(self, argv, *, input=None, readonly=False, **_kwargs):
        argv = [str(arg) for arg in argv]
        self.calls.append((argv, input, readonly))
        if argv[:2] == ["wipefs", "-J"]:
            out = '{"signatures":[{"type":"gpt"},{"type":"PMBR"}]}'
        elif argv[:2] == ["sfdisk", "--dump"]:
            out = "label: gpt\n/dev/vdb1 : start=2048, size=4096\n"
        elif argv[:2] == ["sfdisk", "--json"]:
            old = dict(OLD)
            if self.written and self.old_changed:
                old["size"] += 1
            rows = [old] + ([NEW] if self.written else [])
            out = json.dumps({"partitiontable": {"label": "gpt", "device": DISK,
                                                  "sectorsize": self.sector,
                                                  "partitions": rows}})
        elif argv[:2] == ["lsblk", "--json"]:
            rows = [{"path": DISK, "type": "disk", "partuuid": None,
                     "start": None, "size": 1000000},
                    {"path": OLD["node"], "type": "part", "partuuid": OLD["uuid"],
                     "start": OLD["start"] * self.sector // 512,
                     "size": OLD["size"] * self.sector}]
            if self.written and not self.kernel_stale:
                rows.append({"path": NEW["node"], "type": "part", "partuuid": NEW["uuid"],
                             "start": NEW["start"] * self.sector // 512,
                             "size": NEW["size"] * self.sector})
            out = json.dumps({"blockdevices": rows})
        elif argv[:2] == ["sfdisk", "--append"]:
            assert input is not None
            self.written = True
            out = ""
        elif argv[0] in {"partprobe", "udevadm"}:
            out = ""
        else:
            raise AssertionError(f"unexpected command: {argv}")
        return subprocess.CompletedProcess(argv, 0, out, "")


def partition_plan(r, *, sector=512):
    fingerprints = fingerprint_tables(r, [DISK])
    part = Partplan(DISK, NEW["start"], NEW["size"], "root",
                    PlannedIdentity("new-part", "new-luks", "new-fs"), "root", sector)
    return MigrationPlan([], EspChoice("reuse", DISK, 0), [part], [], fingerprints)


def test_stale_table_checked_before_sfdisk(tmp_path):
    r = PartitionRunner()
    plan = partition_plan(r)
    r.calls.clear()
    plan = replace(plan, approved_tables={DISK: "wrong"})
    with pytest.raises(TablesChanged):
        create_partitions(r, plan, Journal(tmp_path / "j", host_root_uuid="host-root"))
    assert all(argv[:2] != ["sfdisk", "--append"] for argv, _, _ in r.calls)


def test_sfdisk_sector_units_and_planned_partuuid(tmp_path):
    r = PartitionRunner(sector=4096)
    result = create_partitions(r, partition_plan(r, sector=4096),
                               Journal(tmp_path / "j", host_root_uuid="host-root"))
    writes = [(argv, data) for argv, data, _ in r.calls if argv[:2] == ["sfdisk", "--append"]]
    assert len(writes) == 1
    argv, data = writes[0]
    assert argv == ["sfdisk", "--append", "--lock", DISK]
    assert b"unit: sectors\n" in data
    assert b"start=8192,size=8192" in data
    assert b"uuid=new-part" in data
    assert b"--force" not in data and "--no-reread" not in argv
    assert result["root"].path == "/dev/vdb2"
    assert result["root"].luks_uuid == "new-luks"


def test_preexisting_partitions_unchanged_after(tmp_path):
    r = PartitionRunner()
    plan = partition_plan(r)
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    created = create_partitions(r, plan, j)
    assert list(created) == ["root"]
    assert created["root"].partuuid == "new-part"
    entries = read_journal(j.path)
    intent = next(e for e in entries if e["type"] == "intent")
    assert intent["identity"]["partuuid"] == "new-part"
    assert intent["identity"]["luks_uuid"] == "new-luks"
    assert next(e for e in entries if e["type"] == "outcome")["op_id"] == intent["op_id"]


def test_kernel_table_stale_stops(tmp_path):
    r = PartitionRunner(kernel_stale=True)
    with pytest.raises(KernelTableStale):
        create_partitions(r, partition_plan(r),
                          Journal(tmp_path / "j", host_root_uuid="host-root"))
    assert r.written


def test_preexisting_partition_change_stops(tmp_path):
    r = PartitionRunner(old_changed=True)
    with pytest.raises(KernelTableStale, match="pre-existing"):
        create_partitions(r, partition_plan(r),
                          Journal(tmp_path / "j", host_root_uuid="host-root"))


class CryptoRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv, *, input=None, secret_input=False, readonly=False, **_kwargs):
        argv = [str(arg) for arg in argv]
        self.calls.append((argv, input, secret_input, readonly))
        if argv[:2] == ["lsblk", "--json"]:
            out = json.dumps({"blockdevices": [{"path": "/dev/vdb2", "type": "part",
                                                 "partuuid": "new-part", "start": 8192,
                                                 "size": 8192 * 512, "log-sec": 512}]})
        elif argv[:2] == ["cryptsetup", "luksUUID"]:
            out = "new-luks\n"
        elif argv[:2] == ["blkid", "-p"]:
            out = "new-fs\n" if "UUID" in argv else "ext4\n"
        elif argv[0] in {"cryptsetup", "mkfs.ext4", "mkfs.btrfs"}:
            out = ""
        else:
            raise AssertionError(f"unexpected command: {argv}")
        return subprocess.CompletedProcess(argv, 0, out, "")


def created_partition():
    return CreatedPartition("root", "/dev/vdb2", "new-part", 8192, 8192,
                            "new-luks", "new-fs")


def crypto_plan():
    return validate_crypto_plan(source(root_luks=luks("pbkdf2"),
                                       boot_inside_luks=True), CAPS)


def test_luks_params_copied_and_uuid_preassigned(tmp_path):
    r = CryptoRunner()
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    result = luks_format(r, {"root": created_partition()}, crypto_plan(), "root", b"secret", j)
    assert result == "new-luks"
    command = next(argv for argv, _, _, _ in r.calls if argv[:2] == ["cryptsetup", "luksFormat"])
    assert ["--type", "luks2"] == command[2:4]
    assert ["--cipher", "aes-xts-plain64"] == command[4:6]
    assert ["--key-size", "512"] == command[6:8]
    assert ["--sector-size", "512"] == command[8:10]
    assert ["--uuid", "new-luks"] == command[10:12]
    assert ["--pbkdf", "pbkdf2"] == command[12:14]
    assert command[-1] == "/dev/vdb2"
    assert command.index("--key-file") >= 0 and command[command.index("--key-file") + 1] == "-"


def test_passphrase_only_on_stdin(tmp_path):
    r = CryptoRunner()
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    secret = b"this is private"
    luks_format(r, {"root": created_partition()}, crypto_plan(), "root", secret, j)
    argv, data, scrub, _ = next(call for call in r.calls if call[0][:2] == ["cryptsetup", "luksFormat"])
    assert data == secret and scrub is True
    assert secret.decode() not in " ".join(argv)
    assert secret.decode() not in j.path.read_text()


def test_empty_passphrase_rejected(tmp_path):
    r = CryptoRunner()
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    with pytest.raises(ValueError, match="passphrase"):
        luks_format(r, {"root": created_partition()}, crypto_plan(), "root", b"", j)
    assert not r.calls
    assert not any(e["type"] == "intent" for e in read_journal(j.path))


def test_unicode_and_newline_passphrase_verbatim(tmp_path):
    r = CryptoRunner()
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    secret = "é\npass\n".encode()
    luks_format(r, {"root": created_partition()}, crypto_plan(), "root", secret, j)
    assert next(data for argv, data, _, _ in r.calls
                if argv[:2] == ["cryptsetup", "luksFormat"]) == secret


def test_keyfile_in_keyslot_and_unlock_proven(tmp_path):
    keyfile = tmp_path / "keyfile"
    keyfile.write_bytes(b"keyfile bytes")
    r = CryptoRunner()
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    add_keyfile(r, "/dev/vdb2", keyfile, b"secret", j, luks_uuid="new-luks")
    calls = [argv for argv, _, _, _ in r.calls if argv[:2] == ["cryptsetup", "luksAddKey"]]
    assert len(calls) == 1 and str(keyfile) in calls[0]
    tests = [argv for argv, _, _, _ in r.calls if argv[:2] == ["cryptsetup", "open"]
             and "--test-passphrase" in argv]
    assert any(str(keyfile) in argv for argv in tests)


def test_luks_open_uses_new_mapper_name_and_journals(tmp_path):
    r = CryptoRunner()
    j = Journal(tmp_path / "j", migration_id="m1", host_root_uuid="host-root")
    path = luks_open(r, created_partition(), b"secret", j)
    assert path == "/dev/mapper/distromove-m1-root"
    argv, data, secret, _ = next(call for call in r.calls if call[0][:2] == ["cryptsetup", "open"])
    assert data == b"secret" and secret is True
    assert "distromove-m1-root" in argv


def test_mkfs_uses_preassigned_uuid_and_journal_authority(tmp_path):
    r = CryptoRunner()
    j = Journal(tmp_path / "j", host_root_uuid="host-root")
    op = j.intend("create_partition", {"partuuid": "new-part", "fs_uuid": "new-fs"},
                  creates="partition")
    j.done(op, "created", path="/dev/vdb2")
    assert make_fs(r, "/dev/vdb2", "ext4", "new-fs", j) == "new-fs"
    assert any(argv == ["mkfs.ext4", "-U", "new-fs", "/dev/vdb2"]
               for argv, _, _, _ in r.calls)
    with pytest.raises(ValueError, match="journal"):
        make_fs(r, "/dev/vda2", "ext4", "new-fs", j)
