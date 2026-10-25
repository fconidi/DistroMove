import dataclasses
import typing

import pytest

from distromove import model

INTERFACE = {
    "Partition": ("path", "name", "parent_disk", "number", "size_bytes", "fstype", "uuid",
                  "partuuid", "parttype", "mountpoint", "disk_wwn", "disk_serial", "disk_by_id",
                  "start_sectors", "size_sectors", "logical_sector"),
    "Keyslot": ("index", "kdf", "cipher_info"),
    "LuksInfo": ("version", "cipher", "key_bits", "sector_size", "keyslots", "luks_uuid",
                 "mapper_name", "keyfile", "crypttab_options"),
    "Subvol": ("id", "path", "mountpoint", "options", "properties", "has_active_swapfile",
               "only_swapfile"),
    "BtrfsInfo": ("fs_uuid", "default_subvol_id", "subvolumes"),
    "MountInfo": ("source", "target", "fstype", "options"),
    "SnapshotRef": ("fs_uuid", "subvol_path", "snapshot_path", "owner_op", "exclude_paths"),
    "Volume": ("volume_id", "role", "mountpoint", "partition", "luks", "fs", "fs_uuid",
               "used_bytes", "apparent_bytes", "used_inodes", "btrfs", "boot_inside_luks"),
    "SwapRef": ("volume_id", "kind", "path", "containing_volume_role", "uuid", "size_bytes",
                "luks", "random_key", "resume"),
    "LoaderInfo": ("bootloader_id", "path", "via_shim", "esp_uuid"),
    "Esp": ("partition", "mountpoint", "loader_dirs", "foreign_entries"),
    "Source": ("kind", "os_id", "volumes", "unmigrated_mounts", "esp", "swaps",
               "running_root_uuid", "secure_boot"),
    "VolumeIdentity": ("volume_id", "role", "disk_wwn", "disk_serial", "disk_by_id", "partuuid",
                       "start_sectors", "size_sectors", "luks_uuid", "fs_uuid"),
    "UuidMap": ("fs", "luks", "partuuid", "mapper", "subvolid", "swap_uuid"),
    "PlannedIdentity": ("partuuid", "luks_uuid", "fs_uuid"),
    "CreatedPartition": ("volume_id", "path", "partuuid", "start_sectors", "size_sectors",
                         "luks_uuid", "fs_uuid"),
    "SystemSnapshot": ("fstab", "crypttab", "mounts", "mappers", "swaps", "esp_contents",
                       "boot_current", "boot_entries", "identities", "running_root_uuid"),
    "ManifestEntry": ("size", "mtime", "mode", "uid", "gid", "sha256"),
    "Manifest": ("entries", "taken_at", "kind"),
}

# The only fields with a default: trailing optional fields (``| None``, empty, false).
DEFAULTS = {("LuksInfo", "keyfile"): None, ("LuksInfo", "crypttab_options"): (),
            ("SwapRef", "resume"): False, ("ManifestEntry", "sha256"): None,
            ("SnapshotRef", "exclude_paths"): ()}


@pytest.mark.parametrize("name", sorted(INTERFACE))
def test_dataclass_fields_match_interface(name):
    cls = getattr(model, name)
    assert dataclasses.is_dataclass(cls)
    assert tuple(f.name for f in dataclasses.fields(cls)) == INTERFACE[name]
    assert cls.__dataclass_params__.frozen


@pytest.mark.parametrize("name", sorted(INTERFACE))
def test_only_trailing_optional_fields_have_defaults(name):
    cls = getattr(model, name)
    for f in dataclasses.fields(cls):
        has_default = f.default is not dataclasses.MISSING or f.default_factory is not dataclasses.MISSING
        if (name, f.name) in DEFAULTS:
            assert f.default == DEFAULTS[(name, f.name)]
        else:
            assert not has_default, f"{name}.{f.name} must not have a default"


def test_instances_are_immutable():
    m = model.MountInfo("/dev/vda2", "/", "ext4", "rw,relatime")
    with pytest.raises(dataclasses.FrozenInstanceError):
        m.target = "/mnt"  # type: ignore[misc]
    e = model.ManifestEntry(1, 2, 0o100644, 0, 0)
    assert e.sha256 is None
    with pytest.raises(dataclasses.FrozenInstanceError):
        e.size = 5  # type: ignore[misc]


def test_literal_values():
    assert typing.get_args(model.VolumeRole) == (
        "root", "boot", "home", "var", "usr", "opt", "srv", "swap", "extra")
    assert typing.get_args(model.SourceKind) == ("ext4", "btrfs", "syslinuxos")
    assert typing.get_args(model.SwapKind) == ("partition", "file")
    assert typing.get_args(model.ManifestKind) == ("btrfs-snapshot", "btrfs-live", "ext4-frozen")


def test_nested_construction_and_equality():
    slot = model.Keyslot(0, "argon2id", "aes-xts-plain64")
    luks = model.LuksInfo(2, "aes-xts-plain64", 512, 4096, [slot], "luks-uuid", "root_crypt")
    assert luks.keyfile is None
    assert luks == model.LuksInfo(2, "aes-xts-plain64", 512, 4096, [slot], "luks-uuid", "root_crypt", None)
    planned = model.PlannedIdentity("pu", None, "fu")
    assert dataclasses.replace(planned, luks_uuid="lu").luks_uuid == "lu"
    assert planned.luks_uuid is None


def test_created_partition_carries_preassigned_identifiers():
    created = model.CreatedPartition("root", "/dev/vdb2", "part-new", 2048, 4096,
                                     "luks-new", "fs-new")
    assert (created.luks_uuid, created.fs_uuid) == ("luks-new", "fs-new")
