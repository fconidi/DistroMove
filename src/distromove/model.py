"""Shared data model. Every type used by more than one module is defined here, once.

All types are frozen dataclasses: values describe what was observed or planned and are
never changed in place (use ``dataclasses.replace`` to derive a new value).
UUIDs are kept as the tools print them; comparisons elsewhere are case-insensitive.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

VolumeRole = Literal["root", "boot", "home", "var", "usr", "opt", "srv", "swap", "extra"]
SourceKind = Literal["ext4", "btrfs", "syslinuxos"]
SwapKind = Literal["partition", "file"]
ManifestKind = Literal["btrfs-snapshot", "btrfs-live", "ext4-frozen"]


@dataclass(frozen=True)
class Partition:
    """A partition as seen on the system (lsblk/blkid), with the identity of its disk."""
    path: str                      # kernel device path, e.g. /dev/nvme0n1p2 (may change between boots)
    name: str                      # kernel name, e.g. nvme0n1p2
    parent_disk: str               # device path of the disk, e.g. /dev/nvme0n1
    number: int                    # partition number in the table
    size_bytes: int
    fstype: str | None             # filesystem or container type (ext4, btrfs, crypto_LUKS, swap, vfat)
    uuid: str | None               # filesystem / container UUID
    partuuid: str
    parttype: str | None           # GPT partition type GUID
    mountpoint: str | None
    disk_wwn: str | None
    disk_serial: str | None
    disk_by_id: str | None         # stable /dev/disk/by-id path of the disk
    start_sectors: int             # in logical sectors of the disk
    size_sectors: int
    logical_sector: int            # logical sector size of the disk in bytes


@dataclass(frozen=True)
class Keyslot:
    index: int
    kdf: str                       # argon2id, argon2i, pbkdf2
    cipher_info: str               # as reported for the slot (cipher, key size)


@dataclass(frozen=True)
class LuksInfo:
    version: int                   # 1 or 2
    cipher: str                    # e.g. aes-xts-plain64
    key_bits: int
    sector_size: int               # encryption sector size in bytes
    keyslots: list[Keyslot]
    luks_uuid: str
    mapper_name: str | None        # name of the open mapping, when known
    keyfile: str | None = None     # path of the key file used in crypttab, if any
    crypttab_options: tuple[str, ...] = ()  # its crypttab options (initramfs, keyscript=...)


@dataclass(frozen=True)
class Subvol:
    id: int
    path: str                      # path inside the btrfs filesystem, e.g. @home
    mountpoint: str | None
    options: str | None            # mount options used for this subvolume
    properties: dict[str, str]
    has_active_swapfile: bool
    only_swapfile: bool            # the subvolume holds nothing but the swap file


@dataclass(frozen=True)
class BtrfsInfo:
    fs_uuid: str
    default_subvol_id: int
    subvolumes: list[Subvol]


@dataclass(frozen=True)
class MountInfo:
    source: str
    target: str
    fstype: str
    options: str


@dataclass(frozen=True)
class SnapshotRef:
    """A read-only btrfs snapshot taken for the copy, owned by the journal operation owner_op."""
    fs_uuid: str
    subvol_path: str
    snapshot_path: str
    owner_op: str
    exclude_paths: tuple[str, ...] = ()  # other subvolumes nested beneath this snapshot


@dataclass(frozen=True)
class Volume:
    """One volume of the system to migrate (a mounted filesystem with a role)."""
    volume_id: str                 # stable identifier inside a migration
    role: VolumeRole
    mountpoint: str
    partition: Partition
    luks: LuksInfo | None
    fs: str
    fs_uuid: str
    used_bytes: int
    apparent_bytes: int
    used_inodes: int
    btrfs: BtrfsInfo | None
    boot_inside_luks: bool


@dataclass(frozen=True)
class SwapRef:
    volume_id: str
    kind: SwapKind
    path: str                      # device path or swap file path
    containing_volume_role: str | None  # for a swap file: role of the volume holding it
    uuid: str | None               # swap area UUID
    size_bytes: int
    luks: LuksInfo | None
    random_key: bool               # encrypted with a random key at each boot (no resume)
    resume: bool = False           # the initramfs resumes from it (hibernation target)


@dataclass(frozen=True)
class LoaderInfo:
    bootloader_id: str             # directory name under EFI/
    path: str                      # loader path on the ESP, e.g. \EFI\debian\shimx64.efi
    via_shim: bool
    esp_uuid: str


@dataclass(frozen=True)
class Esp:
    partition: Partition
    mountpoint: str
    loader_dirs: list[str]         # directories under EFI/
    foreign_entries: list[str]     # loader directories that belong to other systems


@dataclass(frozen=True)
class Source:
    """The running system to migrate."""
    kind: SourceKind
    os_id: str
    volumes: list[Volume]
    unmigrated_mounts: list[MountInfo]
    esp: Esp
    swaps: list[SwapRef]
    running_root_uuid: str
    secure_boot: bool


@dataclass(frozen=True)
class VolumeIdentity:
    """What makes a volume the same volume: disk identity, place on disk and UUIDs.

    Never a kernel device name, which can change between boots.
    """
    volume_id: str
    role: str                      # root, boot, home, var, usr, opt, srv, swap, esp, extra, foreign
    disk_wwn: str | None
    disk_serial: str | None
    disk_by_id: str | None
    partuuid: str
    start_sectors: int
    size_sectors: int
    luks_uuid: str | None
    fs_uuid: str | None


@dataclass(frozen=True)
class UuidMap:
    """Old identifier -> new identifier, used to rewrite the configuration of the copy."""
    fs: dict[str, str]
    luks: dict[str, str]
    partuuid: dict[str, str]
    mapper: dict[str, str]
    subvolid: dict[str, dict[int, int]]   # btrfs fs UUID -> old subvolume id -> new id
    swap_uuid: dict[str, str]


@dataclass(frozen=True)
class PlannedIdentity:
    """Identity chosen before anything is written, so the journal can name it in advance."""
    partuuid: str
    luks_uuid: str | None          # None for an unencrypted volume
    fs_uuid: str


@dataclass(frozen=True)
class CreatedPartition:
    volume_id: str
    path: str
    partuuid: str
    start_sectors: int
    size_sectors: int
    luks_uuid: str | None
    fs_uuid: str


@dataclass(frozen=True)
class SystemSnapshot:
    """One coherent picture of the live system, read again before every destructive step.

    - ``mounts``: every mount of the running system (sources as the kernel reports them).
    - ``mappers``: one entry per device-mapper device, ``"<name> <dm-uuid>"``, as
      ``dmsetup info -c --noheadings -o name,uuid --separator ' '`` prints them; the
      device-mapper UUID is mandatory (``CRYPT-LUKS2-<LUKS UUID without dashes>-<name>``
      for LUKS). An entry without it is treated as possibly any encrypted volume.
    - ``esp_contents``: ESP PARTUUID -> names of the directories under ``EFI/``.
    - ``boot_current``: the four hex digits of the entry the firmware booted (``BootCurrent``).
    - ``boot_entries``: four hex digits -> the entry line printed by ``efibootmgr -v``
      (label, GPT PARTUUID of the ESP and loader path).
    - ``identities``: every partition visible on the system.
    """
    fstab: str
    crypttab: str
    mounts: list[MountInfo]
    mappers: list[str]
    swaps: list[SwapRef]
    esp_contents: dict[str, list[str]]
    boot_current: str | None
    boot_entries: dict[str, str]
    identities: list[VolumeIdentity]
    running_root_uuid: str


@dataclass(frozen=True)
class ManifestEntry:
    size: int                      # 0 for directories and special files
    mtime: int                     # nanoseconds since the epoch
    mode: int                      # st_mode (file type and permissions)
    uid: int
    gid: int
    sha256: str | None = None      # content hash (target text for symbolic links), when hashed


@dataclass(frozen=True)
class Manifest:
    """Reference description of a stable tree; keys are paths relative to the tree root."""
    entries: dict[str, ManifestEntry]
    taken_at: str                  # ISO 8601, UTC
    kind: ManifestKind
