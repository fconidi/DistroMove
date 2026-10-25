import dataclasses
from pathlib import Path

import pytest

from distromove import layout
from distromove.layout import (ALIGN_BYTES, ESP_DEFAULT_BYTES, DiskInfo, EspChoice, FreeRegion,
                               InitGpt, InsufficientSpace, MigrationPlan, NoTable, SourceSpaceLow,
                               SpaceWatch, TablesChanged, TargetTooSmall, UnsupportedDisk,
                               VolumeTarget, assert_tables_unchanged, estimate_min_bytes,
                               fingerprint_tables, parse_parted_free, parse_wipefs, plan_init_gpt,
                               plan_layout, scan_disk, source_snapshot_space_ok)
from distromove.model import (BtrfsInfo, Esp, LuksInfo, Partition, Source, Subvol, SwapRef, Volume)
from distromove.runner import Runner

FIX = Path(__file__).parent / "fixtures"
GIB = 1024 ** 3
MIB = 1024 ** 2


def fx(name):
    return (FIX / name).read_text()


def partition(path="/dev/sda2", size=150 * GIB, number=2, log=512):
    return Partition(path=path, name=path.rsplit("/", 1)[-1], parent_disk="/dev/sda", number=number,
                     size_bytes=size, fstype="ext4", uuid="0f8e7d6c-5b4a-4938-a271-605f4e3d2c1b",
                     partuuid="aaaaaaaa-0000-4000-8000-000000000001", parttype=None, mountpoint="/",
                     disk_wwn=None, disk_serial="INV0001", disk_by_id=None,
                     start_sectors=2048, size_sectors=size // log, logical_sector=log)


def luks():
    return LuksInfo(version=2, cipher="aes-xts-plain64", key_bits=512, sector_size=512, keyslots=[],
                    luks_uuid="5f3e2d1c-0b9a-4876-a543-210fedcba987", mapper_name="cryptroot")


def volume(role="root", apparent=60 * GIB, used=None, inodes=400_000, fs="ext4", encrypted=False,
           size=150 * GIB, btrfs=None, vid=None):
    return Volume(volume_id=vid or role, role=role, mountpoint="/" if role == "root" else f"/{role}",
                  partition=partition(size=size), luks=luks() if encrypted else None, fs=fs,
                  fs_uuid="0f8e7d6c-5b4a-4938-a271-605f4e3d2c1b",
                  used_bytes=apparent if used is None else used, apparent_bytes=apparent,
                  used_inodes=inodes, btrfs=btrfs, boot_inside_luks=False)


def swap(vid, kind="partition", size=8 * GIB, encrypted=False):
    return SwapRef(volume_id=vid, kind=kind, path="/dev/sda3" if kind == "partition" else "/swapfile",
                   containing_volume_role=None if kind == "partition" else "root", uuid=None,
                   size_bytes=size, luks=luks() if encrypted else None, random_key=False)


def source(volumes=None, swaps=()):
    esp = Esp(partition=partition("/dev/sda1", 512 * MIB, 1), mountpoint="/boot/efi",
              loader_dirs=["debian"], foreign_entries=[])
    return Source(kind="ext4", os_id="debian", volumes=volumes or [volume()], unmigrated_mounts=[],
                  esp=esp, swaps=list(swaps), running_root_uuid="0f8e7d6c-5b4a-4938-a271-605f4e3d2c1b",
                  secure_boot=False)


def region(start=2048, size_gib=250, disk="/dev/sdb", log=512):
    return FreeRegion(disk, start, size_gib * GIB // log, log)


NEW_ESP = EspChoice("new", "/dev/sdb", ESP_DEFAULT_BYTES)


def seq_factory(values):
    it = iter(values)
    return lambda: next(it)


# ---------------------------------------------------------------- parsing

def test_parse_parted_free_gpt_sectors():
    regions = parse_parted_free(fx("parted_free_gpt512.txt"), "/dev/sdb")
    assert [(r.start_sectors, r.size_sectors) for r in regions] == [
        (34, 2014), (419430400, 2048), (629145600, 209715200), (860000001, 116773134)]
    assert all(r.disk == "/dev/sdb" and r.logical_sector == 512 for r in regions)


def test_parse_parted_free_bytes_matches_sectors():
    by_sectors = parse_parted_free(fx("parted_free_gpt512.txt"), "/dev/sdb")
    by_bytes = parse_parted_free(fx("parted_free_gpt512_bytes.txt"), "/dev/sdb")
    assert by_bytes == by_sectors


def test_sector_units_4096():
    regions = parse_parted_free(fx("parted_free_gpt4096.txt"), "/dev/nvme1n1")
    assert all(r.logical_sector == 4096 for r in regions)
    tail = regions[-1]
    assert (tail.start_sectors, tail.size_sectors) == (104857600, 139333041)
    plan = plan_layout(source(), [VolumeTarget(volume(), "/dev/nvme1n1", 100 * GIB)],
                       EspChoice("new", "/dev/nvme1n1", ESP_DEFAULT_BYTES), regions)
    for p in plan.partitions:
        assert p.logical_sector == 4096
        assert p.start_sectors % (ALIGN_BYTES // 4096) == 0
        assert p.size_sectors % (ALIGN_BYTES // 4096) == 0
    root = [p for p in plan.partitions if p.role == "root"][0]
    assert root.size_sectors * 4096 >= 100 * GIB


def test_msdos_UnsupportedDisk():
    with pytest.raises(UnsupportedDisk) as exc:
        parse_parted_free(fx("parted_free_msdos.txt"), "/dev/sdc")
    assert "msdos" in str(exc.value)


def test_empty_disk_NoTable_can_init_only_if_wipefs_clean():
    text = fx("parted_free_notable.txt")
    with pytest.raises(NoTable) as exc:
        parse_parted_free(text, "/dev/sdd", signatures=parse_wipefs(fx("wipefs_clean.json")))
    assert exc.value.can_init is True
    with pytest.raises(NoTable) as exc:
        parse_parted_free(text, "/dev/sdd", signatures=parse_wipefs(fx("wipefs_signatures.json")))
    assert exc.value.can_init is False
    with pytest.raises(NoTable) as exc:          # wipefs data unavailable: never assume clean
        parse_parted_free(text, "/dev/sdd")
    assert exc.value.can_init is False


def test_parse_wipefs_forms():
    assert parse_wipefs(fx("wipefs_none.txt")) == []
    assert parse_wipefs(fx("wipefs_clean.json")) == []
    assert parse_wipefs(fx("wipefs_signatures.json")) == ["ext4"]
    assert parse_wipefs(fx("wipefs_gpt.json")) == ["gpt", "PMBR"]


def test_scan_disk_reads_through_runner_readonly():
    r = Runner(dry_run=True, fixtures={
        ("parted", "-m", "-s", "/dev/sdb", "unit", "s", "print", "free"): fx("parted_free_gpt512.txt")})
    regions = scan_disk(r, "/dev/sdb")
    assert len(regions) == 4
    assert r.calls == [["parted", "-m", "-s", "/dev/sdb", "unit", "s", "print", "free"]]


# ---------------------------------------------------------------- estimate

def test_estimate_uses_apparent_size_not_blocks():
    sparse = volume(apparent=20 * GIB, used=400 * GIB)
    dense = volume(apparent=20 * GIB, used=20 * GIB)
    assert estimate_min_bytes(sparse, False) == estimate_min_bytes(dense, False)
    assert estimate_min_bytes(sparse, False) < 30 * GIB
    bigger = volume(apparent=80 * GIB, used=10 * GIB)
    assert estimate_min_bytes(bigger, False) > 80 * GIB


def test_estimate_has_margin_header_and_alignment():
    plain = estimate_min_bytes(volume(apparent=10 * GIB), False)
    enc = estimate_min_bytes(volume(apparent=10 * GIB, encrypted=True), False)
    assert plain >= 10 * GIB + GIB
    assert enc - plain >= layout.LUKS2_HEADER_BYTES
    assert plain % ALIGN_BYTES == 0 and enc % ALIGN_BYTES == 0


def test_inode_exhaustion_counted():
    few = estimate_min_bytes(volume(apparent=10 * GIB, inodes=100_000), False)
    many = estimate_min_bytes(volume(apparent=10 * GIB, inodes=5_000_000), False)
    assert many >= 5_000_000 * layout.BYTES_PER_INODE
    assert many > few + 40 * GIB


def test_btrfs_snapshots_and_metadata_counted():
    subs = [Subvol(i, f"@{n}", None, None, {}, False, False) for i, n in enumerate(["", "home", "var"], 256)]
    info = BtrfsInfo("e1f2a3b4-c5d6-4e7f-8091-a2b3c4d5e6f7", 5, subs)
    v = volume(fs="btrfs", apparent=30 * GIB, btrfs=info)
    plain = estimate_min_bytes(v, False)
    snap = estimate_min_bytes(v, True)
    assert plain >= 30 * GIB + layout.BTRFS_META_MIN_BYTES + GIB
    assert snap > plain


def test_boot_margin_smaller_than_root_margin():
    boot = estimate_min_bytes(volume(role="boot", apparent=300 * MIB, size=GIB, inodes=500), False)
    assert boot < 2 * GIB
    assert boot >= 300 * MIB + layout.BOOT_MARGIN_MIN_BYTES


def test_source_snapshot_space_ok():
    tight = volume(fs="btrfs", apparent=99 * GIB, size=100 * GIB)
    tight = dataclasses.replace(tight, used_bytes=100 * GIB - 100 * MIB)
    roomy = dataclasses.replace(tight, used_bytes=60 * GIB)
    assert source_snapshot_space_ok(roomy) is True
    assert source_snapshot_space_ok(tight) is False
    assert source_snapshot_space_ok(volume(fs="ext4")) is True      # ext4 is frozen, no snapshot


# ---------------------------------------------------------------- planning

def test_150g_to_200g_example():
    src = source([volume(apparent=90 * GIB, size=150 * GIB)])
    plan = plan_layout(src, [VolumeTarget(src.volumes[0], "/dev/sdb", 200 * GIB)], NEW_ESP,
                       [region(size_gib=300)])
    roles = [p.role for p in plan.partitions]
    assert roles == ["esp", "root"]
    esp, root = plan.partitions
    assert esp.size_sectors * 512 == ESP_DEFAULT_BYTES
    assert root.size_sectors * 512 == 200 * GIB
    assert root.start_sectors == esp.start_sectors + esp.size_sectors
    assert root.volume_id == "root"
    assert plan.esp == NEW_ESP and plan.swaps == [] and plan.init_gpt == []


def test_smaller_target_allowed_if_estimate_fits():
    v = volume(apparent=40 * GIB, size=150 * GIB)
    src = source([v])
    assert estimate_min_bytes(v, False) < 50 * GIB
    plan = plan_layout(src, [VolumeTarget(v, "/dev/sdb", 50 * GIB)], EspChoice("reuse", "/dev/sdb", 0),
                       [region(size_gib=60)])
    assert [p.role for p in plan.partitions] == ["root"]
    assert plan.partitions[0].size_sectors * 512 == 50 * GIB


def test_target_below_estimate_TargetTooSmall():
    v = volume(apparent=40 * GIB, size=150 * GIB)
    with pytest.raises(TargetTooSmall) as exc:
        plan_layout(source([v]), [VolumeTarget(v, "/dev/sdb", 30 * GIB)], NEW_ESP, [region()])
    assert exc.value.min_bytes == estimate_min_bytes(v, False)
    assert exc.value.size_bytes == 30 * GIB
    assert exc.value.volume_id == "root"


def test_no_free_space_InsufficientSpace_message():
    regions = parse_parted_free(fx("parted_free_full.txt"), "/dev/sde")
    v = volume(apparent=10 * GIB)
    with pytest.raises(InsufficientSpace) as exc:
        plan_layout(source([v]), [VolumeTarget(v, "/dev/sde", 20 * GIB)],
                    EspChoice("reuse", "/dev/sde", 0), regions)
    msg = str(exc.value)
    assert "/dev/sde" in msg and "20.0 GiB" in msg and "free" in msg
    assert exc.value.disk == "/dev/sde" and exc.value.needed_bytes == 20 * GIB
    assert exc.value.available_bytes == 0


def test_alignment_1MiB():
    regions = parse_parted_free(fx("parted_free_gpt512.txt"), "/dev/sdb")
    tail = [r for r in regions if r.start_sectors == 860000001][0]
    v = volume(apparent=10 * GIB)
    plan = plan_layout(source([v]), [VolumeTarget(v, "/dev/sdb", 20 * GIB + 12345)],
                       EspChoice("reuse", "/dev/sdb", 0), [tail])
    p = plan.partitions[0]
    assert p.start_sectors == 860000256               # 860000001 rounded up to the next MiB
    assert p.start_sectors * 512 % ALIGN_BYTES == 0
    assert p.size_sectors * 512 % ALIGN_BYTES == 0
    assert p.size_sectors * 512 >= 20 * GIB + 12345


def test_regions_not_overlapping():
    vols = [volume("root", apparent=20 * GIB), volume("home", apparent=30 * GIB)]
    src = source(vols, swaps=[swap("s1"), swap("s2", size=4 * GIB)])
    regions = [FreeRegion("/dev/sdb", 2048, 40 * GIB // 512, 512),
               FreeRegion("/dev/sdb", 100 * GIB // 512, 120 * GIB // 512, 512)]
    targets = [VolumeTarget(vols[0], "/dev/sdb", 40 * GIB), VolumeTarget(vols[1], "/dev/sdb", 50 * GIB)]
    plan = plan_layout(src, targets, NEW_ESP, regions)
    parts = sorted(plan.partitions + plan.swaps, key=lambda p: p.start_sectors)
    assert len(parts) == 5
    for a, b in zip(parts, parts[1:]):
        assert a.start_sectors + a.size_sectors <= b.start_sectors
    for p in parts:
        assert any(r.start_sectors <= p.start_sectors and
                   p.start_sectors + p.size_sectors <= r.start_sectors + r.size_sectors
                   for r in regions)


def test_several_swaps_planned():
    src = source(swaps=[swap("swap0", size=8 * GIB), swap("swap1", size=2 * GIB, encrypted=True),
                        swap("swapfile", kind="file")])
    plan = plan_layout(src, [VolumeTarget(src.volumes[0], "/dev/sdb", 100 * GIB)], NEW_ESP,
                       [region(size_gib=200)])
    assert [p.volume_id for p in plan.swaps] == ["swap0", "swap1"]
    assert all(p.role == "swap" for p in plan.swaps)
    assert plan.swaps[0].planned.luks_uuid is None
    assert plan.swaps[1].planned.luks_uuid is not None
    assert plan.swaps[1].size_sectors * 512 >= 2 * GIB + layout.LUKS2_HEADER_BYTES


def test_planned_identities_unique():
    vols = [volume("root", apparent=5 * GIB, encrypted=True), volume("home", apparent=5 * GIB)]
    src = source(vols, swaps=[swap("swap0", encrypted=True)])
    plan = plan_layout(src, [VolumeTarget(v, "/dev/sdb", 20 * GIB) for v in vols], NEW_ESP,
                       [region(size_gib=300)])
    ids = []
    for p in plan.partitions + plan.swaps:
        ids += [p.planned.partuuid, p.planned.luks_uuid, p.planned.fs_uuid]
    ids = [i for i in ids if i]
    assert len(ids) == len(set(ids))
    assert all(p.planned.partuuid == p.planned.partuuid.lower() for p in plan.partitions)
    root = [p for p in plan.partitions if p.role == "root"][0]
    assert root.planned.luks_uuid is not None
    esp = plan.partitions[0]
    assert len(esp.planned.fs_uuid) == 9 and esp.planned.fs_uuid[4] == "-"   # FAT volume id


def test_uuid_factory_injectable_and_duplicates_skipped():
    import uuid
    seq = [uuid.UUID(int=n) for n in (1, 1, 2, 2, 3, 4, 5, 6, 7, 8)]
    v = volume(apparent=5 * GIB)
    plan = plan_layout(source([v]), [VolumeTarget(v, "/dev/sdb", 20 * GIB)], NEW_ESP,
                       [region(size_gib=100)], uuid_factory=seq_factory(seq))
    assert plan.partitions[0].planned.partuuid == str(uuid.UUID(int=1))
    values = [p.planned.partuuid for p in plan.partitions] + [p.planned.fs_uuid for p in plan.partitions]
    assert len(values) == len(set(values))


def test_init_gpt_disk_gets_whole_disk_region():
    info = DiskInfo(path="/dev/sdd", size_bytes=250 * GIB, logical_sector=512, signatures=(),
                    serial="INV0042")
    init = plan_init_gpt(info)
    v = volume(apparent=5 * GIB)
    plan = plan_layout(source([v]), [VolumeTarget(v, "/dev/sdd", 100 * GIB)],
                       EspChoice("new", "/dev/sdd", ESP_DEFAULT_BYTES), [], init_gpt=[init])
    assert plan.init_gpt == [init]
    assert plan.partitions[0].start_sectors == ALIGN_BYTES // 512


# ---------------------------------------------------------------- init gpt

def test_init_gpt_only_when_no_recognised_signature_wording_not_proof_of_no_data():
    clean = DiskInfo(path="/dev/sdd", size_bytes=250 * GIB, logical_sector=512, signatures=(),
                     serial="INV0042", model="Invented Disk")
    init = plan_init_gpt(clean)
    assert isinstance(init, InitGpt)
    assert init.no_recognised_signatures is True
    assert init.basis == "no recognised signatures"
    assert "INV0042" in init.disk_identity and init.confirmation
    assert not hasattr(init, "empty") and not hasattr(init, "is_empty")
    assert plan_init_gpt(dataclasses.replace(clean, signatures=("ext4",))) is None
    assert plan_init_gpt(dataclasses.replace(clean, signatures=("gpt", "PMBR"))) is None
    assert plan_init_gpt(dataclasses.replace(clean, signatures=None)) is None   # unknown is not clean


# ---------------------------------------------------------------- stale plan

SFDISK = ("sfdisk", "--dump", "/dev/sdb")
WIPEFS = ("wipefs", "-J", "/dev/sdb")
TABLE = ("label: gpt\nlabel-id: 5A1B2C3D-0000-4000-8000-00000000AAAA\ndevice: /dev/sdb\nunit: sectors\n\n"
         "/dev/sdb1 : start=2048, size=1048576, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B\n")


def plan_with(approved):
    v = volume(apparent=5 * GIB)
    return plan_layout(source([v]), [VolumeTarget(v, "/dev/sdb", 20 * GIB)], NEW_ESP,
                       [region(size_gib=100)], approved_tables=approved)


def test_tables_changed_after_approval_raises():
    fixtures = {SFDISK: TABLE, WIPEFS: fx("wipefs_gpt.json")}
    approved = fingerprint_tables(Runner(dry_run=True, fixtures=fixtures), ["/dev/sdb"])
    plan = plan_with(approved)
    assert plan.approved_tables == approved
    assert_tables_unchanged(Runner(dry_run=True, fixtures=fixtures), plan)       # same: fine

    changed = dict(fixtures)
    changed[SFDISK] = TABLE + "/dev/sdb2 : start=1050624, size=2048, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4\n"
    r = Runner(dry_run=True, fixtures=changed)
    with pytest.raises(TablesChanged) as exc:
        assert_tables_unchanged(r, plan)
    assert exc.value.disks == ["/dev/sdb"]
    assert all(c[0] in ("sfdisk", "wipefs") for c in r.calls)                    # read-only commands only


def test_new_signature_on_disk_counts_as_change():
    fixtures = {SFDISK: "", WIPEFS: fx("wipefs_clean.json")}
    approved = fingerprint_tables(Runner(dry_run=True, fixtures=fixtures), ["/dev/sdb"])
    plan = plan_with(approved)
    fixtures[WIPEFS] = fx("wipefs_signatures.json")
    with pytest.raises(TablesChanged):
        assert_tables_unchanged(Runner(dry_run=True, fixtures=fixtures), plan)


def test_fingerprint_is_stable_hex_and_differs_per_content():
    a = fingerprint_tables(Runner(dry_run=True, fixtures={SFDISK: TABLE, WIPEFS: ""}), ["/dev/sdb"])
    b = fingerprint_tables(Runner(dry_run=True, fixtures={SFDISK: TABLE + " ", WIPEFS: ""}), ["/dev/sdb"])
    assert len(a["/dev/sdb"]) == 64 and a != b


# ---------------------------------------------------------------- space watch

def stat_fixture(mp, block, total, avail):
    return {("stat", "-f", "-c", "%S %b %a", mp): f"{block} {total} {avail}\n"}


def test_space_watch_raises_below_threshold():
    # 10 GiB filesystem: threshold is the 2 GiB floor
    low = Runner(dry_run=True, fixtures=stat_fixture("/", 4096, 10 * GIB // 4096, GIB // 4096))
    with pytest.raises(SourceSpaceLow) as exc:
        SpaceWatch(low, "/").check()
    assert exc.value.free_bytes == GIB and exc.value.threshold_bytes == 2 * GIB
    ok = Runner(dry_run=True, fixtures=stat_fixture("/", 4096, 10 * GIB // 4096, 3 * GIB // 4096))
    assert SpaceWatch(ok, "/").check() is None
    # 100 GiB filesystem: 5 % = 5 GiB beats the floor
    big = Runner(dry_run=True, fixtures=stat_fixture("/", 4096, 100 * GIB // 4096, 4 * GIB // 4096))
    with pytest.raises(SourceSpaceLow) as exc:
        SpaceWatch(big, "/").check()
    assert exc.value.threshold_bytes == 5 * GIB
    # explicit threshold wins
    assert SpaceWatch(big, "/", threshold_bytes=GIB).check() is None
