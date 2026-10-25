import json
import os
import shlex
from dataclasses import replace
from pathlib import Path

import pytest

from distromove import probe
from distromove.model import Keyslot, LuksInfo, MountInfo
from distromove.probe import (Unsupported, check_tools, classify_keys, collect_snapshot,
                              database_activity, discover_source, enrich_luks, is_syslinuxos,
                              parse_crypttab, parse_fstab, parse_luks_dump, parse_lsblk)
from distromove.runner import Runner, RunnerError

FIX = Path(__file__).parent / "fixtures"


def fx(*parts):
    return FIX.joinpath(*parts).read_text()


LSBLK = ("lsblk", "--json", "--list", "--bytes", "--output",
         "NAME,KNAME,PATH,PKNAME,TYPE,SIZE,FSTYPE,UUID,PARTUUID,PARTTYPE,START,LOG-SEC,WWN,SERIAL,"
         "MOUNTPOINT")
FINDMNT = ("findmnt", "--json", "--list", "--nofsroot", "--output",
           "SOURCE,TARGET,FSTYPE,OPTIONS,FSROOT")
SWAPON = ("swapon", "--show=NAME,TYPE,SIZE,UUID", "--raw", "--bytes", "--noheadings")
TOOLS = {
    ("btrfs", "--version"): fx("versions", "btrfs.txt"),
    ("cryptsetup", "--version"): fx("versions", "cryptsetup.txt"),
    ("rsync", "--version"): fx("versions", "rsync.txt"),
    ("sfdisk", "--version"): fx("versions", "sfdisk.txt"),
    ("mke2fs", "-V"): fx("versions", "mke2fs.txt"),
    ("grub-install", "--version"): fx("versions", "grub-install.txt"),
    ("efibootmgr", "--version"): fx("versions", "efibootmgr.txt"),
}

EXT4_ROOT = "0f8e7d6c-5b4a-4938-a271-605f4e3d2c1b"
BTRFS_FS = "e1f2a3b4-c5d6-4e7f-8091-a2b3c4d5e6f7"
R = "5f3e2d1c-0b9a-4876-a543-210fedcba987"      # LUKS2, root
H = "6b5a4f3e-2d1c-4b0a-9f8e-7d6c5b4a3f2e"      # LUKS2, home
S = "7c6b5a4f-3e2d-4c1b-a0f9-8e7d6c5b4a3f"      # LUKS1, swap
SLX_ROOT_FS = "8a7b6c5d-4e3f-4a1b-9c0d-e1f2a3b4c5d6"
SLX_HOME_FS = "9b8c7d6e-5f4a-4b2c-8d1e-f2a3b4c5d6e7"
SLX_ESP = "0a9b8c7d-6e5f-4a3b-9c2d-1e0f9a8b7c6d"
BTRFS_OPTS = "rw,noatime,compress=zstd:3,ssd,discard=async,space_cache=v2,subvolid={},subvol=/{}"


def dm_uuid(luks_uuid, version):
    return f"CRYPT-LUKS{version}-{luks_uuid.replace('-', '')}-luks-{luks_uuid}"


DM = [("dm-0", f"luks-{R}", dm_uuid(R, 2)), ("dm-1", f"luks-{H}", dm_uuid(H, 2)),
      ("dm-2", f"luks-{S}", dm_uuid(S, 1)), ("dm-3", "cswap2", "CRYPT-PLAIN-cswap2")]


class FixtureRunner(Runner):
    """Answers only the commands it knows; any other command behaves like a missing program."""

    def __init__(self, fixtures):
        super().__init__(dry_run=True, fixtures=fixtures)

    def run(self, argv, **kw):
        assert kw.get("readonly") is True, f"not run as read-only: {argv}"
        if tuple(str(a) for a in argv) not in self.fixtures:
            raise RunnerError(f"cannot run {shlex.join(argv)}: No such file or directory", argv)
        return super().run(argv, **kw)


def df(path, used, iused):
    return {("df", "-B1", "--output=used,iused", path):
            f"{'Used':>11} {'IUsed':>6}\n{used:>11} {iused:>6}\n"}


def du(path, size):
    return {("du", "-sxb", path): f"{size}\t{path}\n"}


def props(path, inode=""):
    return {("btrfs", "property", "get", "-t", "subvol", path): "ro=false\n",
            ("btrfs", "property", "get", "-t", "inode", path): inode}


def btrfs_fs(mp, show, listing, default):
    return {("btrfs", "filesystem", "show", mp): show, ("btrfs", "subvolume", "list", mp): listing,
            ("btrfs", "subvolume", "get-default", mp): default}


def commands(name):
    cmds = {("uname", "-m"): "x86_64\n", LSBLK: fx(name, "lsblk.json"),
            FINDMNT: fx(name, "findmnt.json"), SWAPON: fx(name, "swapon.txt"),
            ("efibootmgr", "-v"): fx(name, "efibootmgr.txt"),
            ("mokutil", "--sb-state"): fx(name, "mokutil.txt"), **TOOLS}
    if name == "ext4":
        cmds |= df("/", 23622320128, 412345) | du("/", 22890123456)
    elif name == "btrfs":
        cmds |= btrfs_fs("/", fx("btrfs", "btrfs-show.txt"), fx("btrfs", "btrfs-list.txt"),
                         fx("btrfs", "btrfs-default.txt"))
        for p in ("/", "/var/log", "/swap", "/var/lib/portables", "/var/lib/machines"):
            cmds |= props(p)
        cmds |= props("/home", inode="compression=zstd\n")
        cmds |= df("/", 40931622912, 0) | du("/", 18234567890) | du("/home", 21474836480)
        cmds |= du("/var/log", 734003200) | du("/var/lib/portables", 0) | du("/var/lib/machines", 0)
    else:
        for part, dump in (("nvme0n1p2", "root"), ("nvme0n1p3", "home"), ("nvme0n1p4", "swap")):
            cmds[("cryptsetup", "luksDump", f"/dev/{part}")] = fx(name, f"luksdump-{dump}.txt")
        cmds |= btrfs_fs("/", fx(name, "btrfs-show-root.txt"), fx(name, "btrfs-list-root.txt"),
                         fx(name, "btrfs-default.txt"))
        cmds |= btrfs_fs("/home", fx(name, "btrfs-show-home.txt"), fx(name, "btrfs-list-home.txt"),
                         fx(name, "btrfs-default.txt"))
        cmds |= props("/") | props("/var/lib/portables") | props("/home")
        cmds |= df("/", 22945431552, 0) | df("/home", 121114382336, 0)
        cmds |= du("/", 20401094656) | du("/var/lib/portables", 0) | du("/home", 118111600640)
    return cmds


def put(root, rel, text=""):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def make_root(tmp_path, name, *, dpkg="dpkg-status", efi=True, swapfile="swap/swapfile"):
    root = tmp_path / "root"
    put(root, "etc/fstab", fx(name, "fstab"))
    put(root, "etc/os-release", fx(name, "os-release"))
    put(root, "var/lib/dpkg/status", fx(name, dpkg))
    if (FIX / name / "crypttab").exists():
        put(root, "etc/crypttab", fx(name, "crypttab"))
    if efi:
        (root / "sys/firmware/efi/efivars").mkdir(parents=True)
    for line in fx(name, "by-id.txt").splitlines():
        link, _, target = line.partition(" -> ")
        (root / "dev/disk/by-id").mkdir(parents=True, exist_ok=True)
        os.symlink(target, root / "dev/disk/by-id" / link)
    for rel in fx(name, "esp-tree.txt").splitlines():
        put(root, f"boot/efi/{rel}")
    if name == "syslinuxos":
        for kname, mapper, uuid in DM:
            put(root, f"sys/block/{kname}/dm/name", mapper + "\n")
            put(root, f"sys/block/{kname}/dm/uuid", uuid + "\n")
    if name == "btrfs":
        (root / "swap").mkdir()
        put(root, swapfile)
    return root


def probe_of(name, tmp_path, overrides=None, **root_kw):
    return FixtureRunner(commands(name) | (overrides or {})), make_root(tmp_path, name, **root_kw)


# --------------------------------------------------------------------------- parsers

def test_nvme_mmc_numbers():
    text = fx("ext4", "lsblk.json")
    parts = {p.name: p for p in parse_lsblk(text)}
    assert {n: p.number for n, p in parts.items()} == {
        "sda1": 1, "sda2": 2, "sda3": 3, "sda4": 4, "mmcblk0p1": 1,
        "nvme0n1p1": 1, "nvme0n1p2": 2, "nvme0n1p3": 3}
    p = parts["nvme0n1p2"]
    assert (p.path, p.parent_disk, p.fstype, p.uuid, p.partuuid) == (
        "/dev/nvme0n1p2", "/dev/nvme0n1", "ext4", EXT4_ROOT, "1b2c3d4e-5f60-4a71-b82c-93d4e5f60718")
    assert (p.start_sectors, p.size_sectors, p.logical_sector, p.size_bytes) == (
        1050624, 419430400, 512, 200 * 2 ** 30)
    assert (p.disk_wwn, p.disk_serial, p.disk_by_id) == ("eui.002538b411a2c3d4", "S5GXNF0R123456A", None)
    sd = parts["mmcblk0p1"]
    assert (sd.parent_disk, sd.disk_serial, sd.disk_wwn, sd.partuuid) == (
        "/dev/mmcblk0", "0xa1b2c3d4", None, "0e5d7a1c-01")
    assert parts["sda1"].mountpoint == "/mnt/winesp"

    # lsblk START counts 512-byte units; the model counts logical sectors of the disk
    data = json.loads(text)
    for row in data["blockdevices"]:
        if row["kname"].startswith("nvme0n1"):
            row["log-sec"] = 4096
    big = {p.name: p for p in parse_lsblk(json.dumps(data))}["nvme0n1p2"]
    assert (big.start_sectors, big.size_sectors, big.logical_sector) == (131328, 52428800, 4096)

    linked = {p.name: p for p in parse_lsblk(text, by_id={"nvme0n1": "/dev/disk/by-id/nvme-x"})}
    assert linked["nvme0n1p3"].disk_by_id == "/dev/disk/by-id/nvme-x"
    assert linked["sda4"].disk_by_id is None


def test_luks2_two_keyslots_kdfs():
    info = parse_luks_dump(fx("syslinuxos", "luksdump-root.txt"))
    assert info == LuksInfo(
        version=2, cipher="aes-xts-plain64", key_bits=512, sector_size=512,
        keyslots=[Keyslot(0, "argon2id", "aes-xts-plain64 512 bits"),
                  Keyslot(1, "pbkdf2", "aes-xts-plain64 512 bits")],
        luks_uuid=R, mapper_name=None, keyfile=None)
    home = parse_luks_dump(fx("syslinuxos", "luksdump-home.txt"))
    assert (home.sector_size, [k.kdf for k in home.keyslots], home.luks_uuid) == (4096, ["argon2id"], H)


def test_luks1_dump():
    info = parse_luks_dump(fx("syslinuxos", "luksdump-swap.txt"))
    assert info == LuksInfo(
        version=1, cipher="aes-xts-plain64", key_bits=512, sector_size=512,
        keyslots=[Keyslot(0, "pbkdf2", "aes-xts-plain64 512 bits"),
                  Keyslot(1, "pbkdf2", "aes-xts-plain64 512 bits")],
        luks_uuid=S, mapper_name=None, keyfile=None)


def test_enrich_luks_mapper_and_keyfile():
    crypttab = fx("syslinuxos", "crypttab")
    table = "".join(f"{name} {uuid}\n" for _, name, uuid in DM)
    root = enrich_luks(parse_luks_dump(fx("syslinuxos", "luksdump-root.txt")), crypttab, table)
    assert (root.mapper_name, root.keyfile) == (f"luks-{R}", "/crypto_keyfile.bin")
    home_info = parse_luks_dump(fx("syslinuxos", "luksdump-home.txt"))
    home = enrich_luks(home_info, parse_crypttab(crypttab), table)
    assert (home.mapper_name, home.keyfile) == (f"luks-{H}", "/etc/cryptsetup-keys.d/home.key")
    assert home.keyslots == home_info.keyslots and home.luks_uuid == H

    # not open: no mapping, but the key file is still found through UUID= in crypttab
    closed = enrich_luks(home_info, crypttab, f"luks-{R} {dm_uuid(R, 2)}\n")
    assert (closed.mapper_name, closed.keyfile) == (None, "/etc/cryptsetup-keys.d/home.key")

    # Debian installer naming, unlocked with a passphrase
    deb = enrich_luks(home_info, f"nvme0n1p3_crypt UUID={H} none luks,discard\n",
                      f"nvme0n1p3_crypt CRYPT-LUKS2-{H.replace('-', '')}-nvme0n1p3_crypt\n")
    assert (deb.mapper_name, deb.keyfile) == ("nvme0n1p3_crypt", None)

    entries = {e.name: e for e in parse_crypttab(crypttab)}
    assert entries["cswap2"].keyfile == "/dev/urandom"
    assert entries["cswap2"].options == "swap,cipher=aes-xts-plain64,size=512"
    assert entries[f"luks-{R}"].device == f"UUID={R}"


def test_parse_fstab_entries():
    entries = parse_fstab(fx("ext4", "fstab") + "/dev/sdb1 /mnt/my\\040disk ext4\n")
    assert entries[0] == MountInfo(f"UUID={EXT4_ROOT}", "/", "ext4", "errors=remount-ro")
    assert [e.target for e in entries] == ["/", "/boot/efi", "none", "/media/cdrom0", "/srv/data",
                                          "/mnt/my disk"]
    assert entries[-1].options == "defaults"


def test_is_syslinuxos_requires_package_and_subvols():
    slx, deb = fx("syslinuxos", "dpkg-status"), fx("btrfs", "dpkg-status")
    paths = ["@", "@/.snapshots", "@/.snapshots/1/snapshot", "@home"]
    assert is_syslinuxos(slx, paths)
    assert is_syslinuxos(slx, ["<FS_TREE>/@", "<FS_TREE>/@home"])
    assert not is_syslinuxos(deb, paths)
    assert not is_syslinuxos(slx, ["@", "@/.snapshots"])
    assert not is_syslinuxos(slx, ["@rootfs", "@home"])
    removed = slx.replace("Package: syslinuxos-snapshots\nStatus: install ok installed",
                          "Package: syslinuxos-snapshots\nStatus: deinstall ok config-files")
    assert removed != slx and not is_syslinuxos(removed, paths)


# --------------------------------------------------------------------------- discovery

def test_discover_ext4(tmp_path):
    r, root = probe_of("ext4", tmp_path)
    src = discover_source(r, root)
    assert (src.kind, src.os_id, src.secure_boot, src.running_root_uuid) == (
        "ext4", "debian", True, EXT4_ROOT)
    assert [(v.role, v.mountpoint, v.partition.name, v.fs) for v in src.volumes] == [
        ("root", "/", "nvme0n1p2", "ext4")]
    v = src.volumes[0]
    assert (v.fs_uuid, v.used_bytes, v.apparent_bytes, v.used_inodes) == (
        EXT4_ROOT, 23622320128, 22890123456, 412345)
    assert v.luks is None and v.btrfs is None and v.boot_inside_luks is False
    assert v.partition.disk_by_id == "/dev/disk/by-id/nvme-eui.002538b411a2c3d4"
    esp = src.esp
    assert (esp.partition.name, esp.mountpoint, esp.loader_dirs, esp.foreign_entries) == (
        "nvme0n1p1", "/boot/efi", ["BOOT", "debian"], [])
    assert [(s.kind, s.path, s.uuid, s.size_bytes, s.luks, s.random_key, s.containing_volume_role)
            for s in src.swaps] == [
        ("partition", "/dev/nvme0n1p3", "3c2b1a09-f8e7-4d6c-b5a4-938271605f4e", 8589930496, None,
         False, None)]
    assert r.calls and all(tuple(c) in r.fixtures for c in r.calls)


def test_discover_btrfs_standard(tmp_path):
    r, root = probe_of("btrfs", tmp_path)
    src = discover_source(r, root)
    assert (src.kind, src.os_id, src.secure_boot, src.running_root_uuid) == (
        "btrfs", "debian", False, BTRFS_FS)
    [v] = src.volumes
    assert (v.role, v.mountpoint, v.partition.name, v.fs, v.fs_uuid) == (
        "root", "/", "nvme0n1p2", "btrfs", BTRFS_FS)
    b = v.btrfs
    assert (b.fs_uuid, b.default_subvol_id) == (BTRFS_FS, 256)
    assert [(s.id, s.path, s.mountpoint) for s in b.subvolumes] == [
        (256, "@", "/"), (257, "@home", "/home"), (258, "@log", "/var/log"), (259, "@swap", "/swap"),
        (260, "@/var/lib/portables", None), (261, "@/var/lib/machines", None)]
    home = b.subvolumes[1]
    assert home.options == BTRFS_OPTS.format(257, "@home")
    assert home.properties == {"ro": "false", "compression": "zstd"}
    assert b.subvolumes[4].properties == {"ro": "false"} and b.subvolumes[4].options is None
    # @swap holds nothing but the active swap file: not counted, it is made new
    assert v.apparent_bytes == 18234567890 + 21474836480 + 734003200
    assert (v.used_bytes, v.used_inodes) == (40931622912, 0)
    assert (src.esp.loader_dirs, src.esp.foreign_entries) == (["BOOT", "Microsoft", "debian"],
                                                               ["Microsoft"])
    assert [(s.volume_id, s.kind, s.path, s.containing_volume_role, s.uuid) for s in src.swaps] == [
        ("swapfile-swap-swapfile", "file", "/swap/swapfile", "root",
         "5e4d3c2b-1a09-4f8e-9d7c-6b5a49382716")]
    assert src.unmigrated_mounts == []


def test_discover_syslinuxos_root_home_partitions(tmp_path):
    r, root = probe_of("syslinuxos", tmp_path)
    src = discover_source(r, root)
    assert (src.kind, src.os_id, src.running_root_uuid) == ("syslinuxos", "SysLinuxOS", SLX_ROOT_FS)
    assert [(v.role, v.mountpoint, v.partition.name, v.fs, v.fs_uuid) for v in src.volumes] == [
        ("root", "/", "nvme0n1p2", "btrfs", SLX_ROOT_FS),
        ("home", "/home", "nvme0n1p3", "btrfs", SLX_HOME_FS)]
    root_v, home_v = src.volumes
    assert (root_v.luks.version, root_v.luks.luks_uuid, root_v.luks.mapper_name) == (2, R, f"luks-{R}")
    assert (home_v.luks.luks_uuid, home_v.luks.mapper_name, home_v.luks.sector_size) == (
        H, f"luks-{H}", 4096)
    assert [s.path for s in root_v.btrfs.subvolumes] == [
        "@", "@/.snapshots", "@/.snapshots/1/snapshot", "@/.snapshots/2/snapshot",
        "@/var/lib/portables"]
    assert [s.mountpoint for s in root_v.btrfs.subvolumes] == ["/", None, None, None, None]
    assert root_v.btrfs.subvolumes[2].properties == {}  # snapper snapshots are not migrated
    assert [(s.id, s.path, s.mountpoint) for s in home_v.btrfs.subvolumes] == [(256, "@home", "/home")]
    assert root_v.btrfs.default_subvol_id == 5 and home_v.btrfs.fs_uuid == SLX_HOME_FS
    assert (root_v.apparent_bytes, home_v.apparent_bytes) == (20401094656, 118111600640)
    assert [m.target for m in src.unmigrated_mounts] == ["/mnt/backup"]
    assert (src.esp.partition.partuuid, src.esp.loader_dirs, src.esp.foreign_entries) == (
        SLX_ESP, ["BOOT", "SysLinuxOS"], [])


def test_only_exact_mountpoints_are_volumes_others_unmigrated(tmp_path):
    src = discover_source(*probe_of("ext4", tmp_path))
    assert [v.mountpoint for v in src.volumes] == ["/"]
    assert [m.target for m in src.unmigrated_mounts] == [
        "/srv/data", "/mnt/winesp", "/media/alice/SDCARD"]
    assert src.unmigrated_mounts[0] == MountInfo("/dev/sda4", "/srv/data", "ext4", "rw,relatime")


def test_two_esps_picks_the_one_in_fstab(tmp_path):
    esps = [p.name for p in parse_lsblk(fx("ext4", "lsblk.json")) if p.parttype == probe.ESP_TYPE]
    assert esps == ["sda1", "nvme0n1p1"]  # the first ESP listed is not the one the system uses
    src = discover_source(*probe_of("ext4", tmp_path / "a"))
    assert (src.esp.partition.name, src.esp.partition.uuid) == ("nvme0n1p1", "4C1E-9A2B")
    assert "/mnt/winesp" in [m.target for m in src.unmigrated_mounts]

    # the other ESP mounted on /efi by hand: fstab still decides
    mounts = fx("ext4", "findmnt.json").replace('"/mnt/winesp"', '"/efi"')
    r, root = probe_of("ext4", tmp_path / "b", {FINDMNT: mounts})
    assert discover_source(r, root).esp.partition.name == "nvme0n1p1"

    # fstab naming the ESP by PARTUUID
    r, root = probe_of("ext4", tmp_path / "c")
    fstab = fx("ext4", "fstab").replace("UUID=4C1E-9A2B",
                                        "PARTUUID=6a4b0f1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b")
    put(root, "etc/fstab", fstab)
    assert discover_source(r, root).esp.partition.name == "nvme0n1p1"


def test_btrfs_without_subvolumes_counts_the_top_level(tmp_path):
    mounts = json.loads(fx("btrfs", "findmnt.json"))
    mounts["filesystems"] = [m for m in mounts["filesystems"]
                             if m["source"] != "/dev/nvme0n1p2" or m["target"] == "/"]
    top = next(m for m in mounts["filesystems"] if m["target"] == "/")
    top.update(options="rw,relatime,ssd,discard=async,space_cache=v2,subvolid=5,subvol=/",
               fsroot="/")
    over = {FINDMNT: json.dumps(mounts), SWAPON: "", ("btrfs", "subvolume", "list", "/"): "",
            ("btrfs", "subvolume", "get-default", "/"): "ID 5 (FS_TREE)\n"}
    src = discover_source(*probe_of("btrfs", tmp_path, over))
    [v] = src.volumes
    assert (v.btrfs.subvolumes, v.btrfs.default_subvol_id, v.apparent_bytes) == ([], 5, 18234567890)
    assert src.kind == "btrfs" and src.swaps == []


def test_btrfs_multi_device_Unsupported(tmp_path):
    r, root = probe_of("btrfs", tmp_path, {("btrfs", "filesystem", "show", "/"):
                                           fx("btrfs", "btrfs-show-multi.txt")})
    with pytest.raises(Unsupported) as exc:
        discover_source(r, root)
    assert "2 devices" in exc.value.reason


def test_dracut_Unsupported(tmp_path):
    r, root = probe_of("ext4", tmp_path, dpkg="dpkg-status-dracut")
    with pytest.raises(Unsupported) as exc:
        discover_source(r, root)
    assert "dracut" in exc.value.reason


def test_btrfs_progs_too_old_Unsupported(tmp_path):
    check_tools(FixtureRunner(TOOLS))
    old = {("btrfs", "--version"): fx("versions", "btrfs-old.txt")}
    with pytest.raises(Unsupported) as exc:
        check_tools(FixtureRunner(TOOLS | old))
    assert "btrfs-progs" in exc.value.reason and "5.10.1" in exc.value.reason
    assert "6.1" in exc.value.reason
    missing = {k: v for k, v in TOOLS.items() if k[0] != "btrfs"}
    with pytest.raises(Unsupported) as exc:
        check_tools(FixtureRunner(missing))
    assert "btrfs-progs" in exc.value.reason and "not installed" in exc.value.reason
    with pytest.raises(Unsupported):
        discover_source(*probe_of("ext4", tmp_path, old))


def test_swapfile_subvolume_only_swapfile_vs_mixed(tmp_path):
    src = discover_source(*probe_of("btrfs", tmp_path / "a"))
    sv = {s.path: s for s in src.volumes[0].btrfs.subvolumes}
    assert (sv["@swap"].has_active_swapfile, sv["@swap"].only_swapfile) == (True, True)
    assert (sv["@"].has_active_swapfile, sv["@"].only_swapfile) == (False, False)

    r, root = probe_of("btrfs", tmp_path / "b", {SWAPON: fx("btrfs", "swapon-mixed.txt")}
                       | du("/swap", 0), swapfile="swapfile")
    mixed = discover_source(r, root)
    sv = {s.path: s for s in mixed.volumes[0].btrfs.subvolumes}
    assert (sv["@"].has_active_swapfile, sv["@"].only_swapfile) == (True, False)
    assert (sv["@swap"].has_active_swapfile, sv["@swap"].only_swapfile) == (False, False)
    assert [(s.path, s.containing_volume_role, s.size_bytes) for s in mixed.swaps] == [
        ("/swapfile", "root", 4294963200)]
    assert mixed.volumes[0].apparent_bytes == 18234567890 + 21474836480 + 734003200 + 0

    # a swap file on the /home filesystem belongs to @home, not to the root's @
    r, root = probe_of("syslinuxos", tmp_path / "c", {
        SWAPON: "/home/swapfile file 2147479552 1a2b3c4d-5e6f-4789-8abc-def012345678\n"})
    put(root, "home/swapfile")
    put(root, "home/alice/.profile", "umask 022\n")
    src = discover_source(r, root)
    root_sv, home_sv = (v.btrfs.subvolumes for v in src.volumes)
    assert [s.has_active_swapfile for s in root_sv] == [False] * 5
    assert (home_sv[0].has_active_swapfile, home_sv[0].only_swapfile) == (True, False)
    assert [(s.path, s.containing_volume_role) for s in src.swaps] == [("/home/swapfile", "home")]


def test_encrypted_swap_modeled(tmp_path):
    src = discover_source(*probe_of("syslinuxos", tmp_path))
    luks_swap, random_swap = src.swaps
    assert (luks_swap.kind, luks_swap.path, luks_swap.uuid, luks_swap.size_bytes,
            luks_swap.random_key, luks_swap.containing_volume_role) == (
        "partition", "/dev/nvme0n1p4", "0d1e2f3a-4b5c-4d6e-8f7a-9b0c1d2e3f4a", 17177767936, False, None)
    assert (luks_swap.luks.version, luks_swap.luks.luks_uuid, luks_swap.luks.mapper_name,
            luks_swap.luks.keyfile) == (1, S, f"luks-{S}", "/crypto_keyfile.bin")
    assert (random_swap.kind, random_swap.path, random_swap.luks, random_swap.random_key,
            random_swap.uuid, random_swap.size_bytes) == (
        "partition", "/dev/sda1", None, True, None, 4294963200)


def test_boot_inside_luks_detected(tmp_path):
    src = discover_source(*probe_of("syslinuxos", tmp_path / "a"))
    assert [(v.role, v.boot_inside_luks) for v in src.volumes] == [("root", True), ("home", False)]
    plain = discover_source(*probe_of("ext4", tmp_path / "b"))
    assert plain.volumes[0].boot_inside_luks is False

    # a separate, unencrypted /boot: GRUB never opens LUKS
    lsblk = json.loads(fx("syslinuxos", "lsblk.json"))
    lsblk["blockdevices"].append({
        "name": "nvme0n1p5", "kname": "nvme0n1p5", "path": "/dev/nvme0n1p5", "pkname": "nvme0n1",
        "type": "part", "size": 1073741824, "fstype": "ext4",
        "uuid": "1f2e3d4c-5b6a-4798-8a9b-0c1d2e3f4a5b",
        "partuuid": "6f7a8b9c-0d1e-4f2a-8b3c-4d5e6f7a8b9c",
        "parttype": "0fc63daf-8483-4772-8e79-3d69d8477de4", "start": 1712326656, "log-sec": 512,
        "wwn": "eui.0026b7682d5f1e45", "serial": None, "mountpoint": "/boot"})
    mounts = json.loads(fx("syslinuxos", "findmnt.json"))
    mounts["filesystems"].append({"source": "/dev/nvme0n1p5", "target": "/boot", "fstype": "ext4",
                                  "options": "rw,relatime", "fsroot": "/"})
    over = {LSBLK: json.dumps(lsblk), FINDMNT: json.dumps(mounts)} | df("/boot", 98566144, 342)
    src = discover_source(*probe_of("syslinuxos", tmp_path / "c", over | du("/boot", 97910784)))
    assert [(v.role, v.boot_inside_luks) for v in src.volumes] == [
        ("root", False), ("boot", False), ("home", False)]


def test_keyfile_classified_initramfs_vs_after_root(tmp_path):
    src = discover_source(*probe_of("syslinuxos", tmp_path))
    ids = {v.role: v.volume_id for v in src.volumes}
    assert classify_keys(src) == {ids["root"]: "initramfs", ids["home"]: "after-root",
                                  src.swaps[0].volume_id: "after-root"}
    no_keys = replace(src, swaps=[], volumes=[replace(v, luks=replace(v.luks, keyfile=None))
                                              for v in src.volumes])
    assert classify_keys(no_keys) == {}


def test_every_volume_and_swap_has_unique_volume_id(tmp_path):
    roles = {"root", "boot", "home", "var", "usr", "opt", "srv", "swap", "extra"}
    for name in ("ext4", "btrfs", "syslinuxos"):
        src = discover_source(*probe_of(name, tmp_path / name))
        ids = [v.volume_id for v in src.volumes] + [s.volume_id for s in src.swaps]
        assert all(ids) and len(set(ids)) == len(ids) and not set(ids) & roles, name
        again = discover_source(*probe_of(name, tmp_path / f"{name}-again"))
        assert ids == [v.volume_id for v in again.volumes] + [s.volume_id for s in again.swaps]
    assert len(src.swaps) == 2


def test_manual_extra_mount_gets_role_extra(tmp_path):
    over = df("/srv/data", 189234561024, 20811) | du("/srv/data", 187654321098)
    r, root = probe_of("ext4", tmp_path, over)
    src = discover_source(r, root, extra_mounts=["/srv/data"])
    assert [(v.role, v.mountpoint, v.partition.name) for v in src.volumes] == [
        ("root", "/", "nvme0n1p2"), ("extra", "/srv/data", "sda4")]
    extra = src.volumes[1]
    assert (extra.fs_uuid, extra.used_bytes, extra.apparent_bytes) == (
        "d4c3b2a1-0f9e-4d8c-b7a6-958473625140", 189234561024, 187654321098)
    assert "/srv/data" not in [m.target for m in src.unmigrated_mounts]
    with pytest.raises(Unsupported):
        discover_source(r, root, extra_mounts=["/tmp"])


@pytest.mark.parametrize("case, word", [
    ("bios", "UEFI"), ("arm", "x86-64"), ("lvm", "LVM"), ("raid", "RAID"),
    ("secure-boot", "Secure Boot"), ("systemd-boot", "GRUB")])
def test_unsupported_systems(tmp_path, case, word):
    over, kw = {}, {}
    lsblk = json.loads(fx("ext4", "lsblk.json"))
    mounts = fx("ext4", "findmnt.json")
    if case == "bios":
        kw["efi"] = False
    elif case == "arm":
        over[("uname", "-m")] = "aarch64\n"
    elif case in ("lvm", "raid"):
        part = next(d for d in lsblk["blockdevices"] if d["kname"] == "nvme0n1p2")
        if case == "lvm":
            part["fstype"] = "LVM2_member"
            dev = {"name": "vg0-root", "kname": "dm-0", "path": "/dev/mapper/vg0-root", "type": "lvm"}
        else:
            part["fstype"] = "linux_raid_member"
            dev = {"name": "md0", "kname": "md0", "path": "/dev/md0", "type": "raid1"}
        lsblk["blockdevices"].append(dict(dict.fromkeys(part), **dev, pkname="nvme0n1p2",
                                          size=part["size"], fstype="ext4", uuid=EXT4_ROOT,
                                          mountpoint="/"))
        mounts = mounts.replace('"source": "/dev/nvme0n1p2"', f'"source": "{dev["path"]}"')
    elif case == "systemd-boot":
        over[("efibootmgr", "-v")] = fx("ext4", "efibootmgr.txt").replace(
            r"File(\EFI\debian\shimx64.efi)", r"File(\EFI\systemd\systemd-bootx64.efi)")
    over |= {LSBLK: json.dumps(lsblk), FINDMNT: mounts}
    r, root = probe_of("ext4", tmp_path, over, **kw)
    if case == "secure-boot":  # Secure Boot on, but the signed GRUB is not installed
        put(root, "var/lib/dpkg/status", fx("ext4", "dpkg-status").replace(
            "Package: grub-efi-amd64-signed\n", "Package: grub-efi-amd64-signed-template\n"))
    with pytest.raises(Unsupported) as exc:
        discover_source(r, root)
    assert word in exc.value.reason


# --------------------------------------------------------------------------- snapshot and keys

def test_snapshot_contains_fstab_crypttab_mounts_mappers_esp_bootcurrent(tmp_path):
    r, root = probe_of("syslinuxos", tmp_path)
    snap = collect_snapshot(r, root)
    assert snap.fstab == fx("syslinuxos", "fstab") and snap.crypttab == fx("syslinuxos", "crypttab")
    assert len(snap.mounts) == len(json.loads(fx("syslinuxos", "findmnt.json"))["filesystems"])
    assert MountInfo(f"/dev/mapper/luks-{R}", "/", "btrfs", BTRFS_OPTS.format(256, "@")) in snap.mounts
    assert snap.mappers == ["cswap2 CRYPT-PLAIN-cswap2", f"luks-{R} {dm_uuid(R, 2)}",
                            f"luks-{H} {dm_uuid(H, 2)}", f"luks-{S} {dm_uuid(S, 1)}"]
    assert snap.esp_contents == {SLX_ESP: ["BOOT", "SysLinuxOS"]}
    assert (snap.boot_current, sorted(snap.boot_entries)) == ("0000", ["0000", "0001"])
    entry = snap.boot_entries["0000"]
    assert entry.startswith(f"Boot0000* SysLinuxOS\tHD(1,GPT,{SLX_ESP},0x800,0x100000)")
    assert entry.endswith(r"/File(\EFI\SysLinuxOS\shimx64.efi)") and "dp:" not in entry
    assert [(s.path, s.random_key) for s in snap.swaps] == [("/dev/nvme0n1p4", False),
                                                             ("/dev/sda1", True)]
    assert snap.running_root_uuid == SLX_ROOT_FS
    ids = {i.partuuid: i for i in snap.identities}
    assert len(snap.identities) == 6
    rid = ids["1a2b3c4d-5e6f-4a0b-8c1d-2e3f4a5b6c7d"]
    assert (rid.role, rid.luks_uuid, rid.fs_uuid, rid.disk_wwn, rid.disk_serial, rid.disk_by_id,
            rid.start_sectors, rid.size_sectors) == (
        "root", R, SLX_ROOT_FS, "eui.0026b7682d5f1e45", "50026B7682D5F1E4",
        "/dev/disk/by-id/nvme-eui.0026b7682d5f1e45", 1050624, 629145600)
    discovered = discover_source(*probe_of("syslinuxos", tmp_path / "d"))
    assert rid.volume_id == discovered.volumes[0].volume_id
    assert (ids[SLX_ESP].role, ids[SLX_ESP].fs_uuid) == ("esp", "71A4-C2E9")
    assert ids["4d5e6f7a-8b9c-4d3e-9f4a-5b6c7d8e9fa0"].role == "swap"
    backup = ids["5e6f7a8b-9cad-4e4f-8a5b-6c7d8e9fa0b1"]
    assert (backup.role, backup.volume_id, backup.disk_by_id, backup.luks_uuid) == (
        "extra", "", "/dev/disk/by-id/wwn-0x5000c500d1e2f3a4", None)
    assert all(tuple(c) in r.fixtures for c in r.calls)

    # a device-mapper device without a UUID is kept, by name only
    put(root, "sys/block/dm-9/dm/name", "leftover\n")
    put(root, "sys/block/dm-9/dm/uuid", "\n")
    assert "leftover" in collect_snapshot(r, root).mappers

    ext4 = collect_snapshot(*probe_of("ext4", tmp_path / "e"))
    assert (ext4.mappers, ext4.crypttab, ext4.boot_current) == ([], "", "0001")
    assert set(ext4.esp_contents) == {"6a4b0f1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b",
                                      "5d0b6f1a-3c2e-4b8d-9f7a-1e2d3c4b5a69"}


def fake_fd(proc, pid, comm, fd, target, flags):
    put(proc, f"{pid}/comm", comm + "\n")
    (proc / str(pid) / "fd").mkdir(parents=True, exist_ok=True)
    os.symlink(target, proc / str(pid) / "fd" / str(fd))
    put(proc, f"{pid}/fdinfo/{fd}", f"pos:\t0\nflags:\t{flags}\nmnt_id:\t29\nino:\t1835012\n")


def test_database_activity_detects_postgres_and_docker(tmp_path):
    ps = ("systemd\nkthreadd\npostgres\npostgres\nmariadbd\ndockerd\ncontainerd\n"
          "Web Content\nsqlitebrowser\nbash\n")
    r = FixtureRunner({("ps", "-e", "-o", "comm="): ps})
    root = tmp_path / "root"
    header = b"SQLite format 3\x00" + bytes(84)
    for rel in ("var/lib/app/state.db", "srv/archive.sqlite"):
        (root / rel).parent.mkdir(parents=True)
        (root / rel).write_bytes(header)
    put(root, "var/log/app.log", "started\n")
    proc = root / "proc"
    fake_fd(proc, 4242, "sqlitebrowser", 5, "/var/lib/app/state.db", "0100002")      # O_RDWR
    fake_fd(proc, 4242, "sqlitebrowser", 6, "/var/lib/app/state.db-wal", "0100002")
    fake_fd(proc, 4300, "reader", 3, "/srv/archive.sqlite", "0100000")              # read only
    fake_fd(proc, 4301, "logger", 3, "/var/log/app.log", "0102001")                 # not SQLite
    fake_fd(proc, 4302, "cat", 1, "pipe:[48213]", "01")
    assert database_activity(r, root) == [
        "PostgreSQL", "MySQL/MariaDB", "SQLite: /var/lib/app/state.db (sqlitebrowser)", "Docker"]
    quiet = FixtureRunner({("ps", "-e", "-o", "comm="): "systemd\nbash\n"})
    assert database_activity(quiet, tmp_path / "empty") == []
