"""Ordered migration transaction and its durable activation boundary.

The engine owns the sequence.  Storage and copy details are implemented by an
explicit backend so tests can exercise failures without touching a disk.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import json
from pathlib import Path
from typing import Callable, Protocol
import os
import re

from .cleanup import _locate
from .boot_install import (install_grub, install_old_entry, old_system_entry,
                           persist_bootloader_id, preflight_signed_chain, update_grub)
from .chroot_env import Chroot
from .copy_btrfs import (BtrfsDestination, branch, copy_from_snapshots,
                         copy_live_swap_subvolume, reference_manifests,
                         release_snapshots, take_snapshots)
from .copy_ext4 import CopyPair, _manifest_excludes, volume_filters, copy_ext4
from .disk import (DestinationMount, GrubCaps, add_keyfile, create_partitions, init_gpt,
                   luks_format, luks_open, make_fs, mount_destination,
                   replicate_subvolumes, validate_crypto_plan)
from .esp import _partuuid, _state, create_esp, copy_esp, register_new_entry
from .copy_ext4 import FreezeStats
from .journal import AlreadyRunning, Journal, Lock, open_windows, read_journal, recover
from .safety import partuuid_key
from .layout import (MigrationPlan, SpaceWatch, assert_tables_unchanged,
                     estimate_min_bytes, fingerprint_tables, scan_disk)
from .model import CreatedPartition, LoaderInfo, SnapshotRef, Source, UuidMap
from .probe import check_tools, collect_snapshot, discover_source
from .probe_parse import loader_of
from .state import MigrationState, load_state, save_state
from .swap import SwapMount, SwapPlan, make_swaps
from .system_config import (apply_configs, install_crypt_hooks,
                            rebuild_initramfs, reset_snapper, _read as config_read,
                            _save as config_save)
from .verify import (VerifyReport, check_esp, check_identities, check_initramfs,
                     check_unlock, verify_copy, verify_transformations)


@dataclass(frozen=True)
class Secrets:
    new_passphrase: bytes | None = None


@dataclass(frozen=True)
class MigrationResult:
    ok: bool
    verify: VerifyReport | None
    new_bootnum: str | None
    freeze: FreezeStats | None
    warnings: list[str]
    phase: str


@dataclass(frozen=True)
class Action:
    kind: str
    detail: str


@dataclass(frozen=True)
class MigrationContext:
    """Locally verified inputs not derivable from the partition layout.

    ``staging_root`` and ``scratch_root`` must be real, distinct directories.
    Btrfs source top levels are separately mounted subvolid=5 trees, supplied
    by the privileged caller after checking their filesystem UUID.
    """

    staging_root: Path
    scratch_root: Path
    grub_caps: GrubCaps
    loader: LoaderInfo
    bootloader_id: str
    btrfs_source_tops: dict[str, Path] = field(default_factory=dict)
    swapfile_uuids: dict[str, str] = field(default_factory=dict)
    osprober_sees_old: bool = False
    expected_diffs: set[str] = field(default_factory=set)


class SystemBackend:
    """Concrete adapter for the storage, copy, boot and verification modules."""

    def __init__(self, context: MigrationContext):
        self.context = context
        self._created: dict[str, CreatedPartition] = {}
        self._devices: dict[str, str] = {}
        self._tops: dict[str, Path] = {}
        self._subvol_maps: dict[str, dict[int, int]] = {}
        self._snapshots: list[SnapshotRef] = []
        self._references: dict[str, tuple[object, Path, tuple[str, ...], tuple[str, ...]]] = {}
        self._freeze: FreezeStats | None = None
        self._swaps = []
        self._crypto = None
        self._signed = None
        self._plan: MigrationPlan | None = None
        self._runner = None
        self._journal = None
        self._passphrase: bytes | None = None
        self._new_esp_uuid = ""
        self._esp_device = ""
        self._esp_disk = ""
        self._esp_number = 0

    @property
    def new_root(self) -> Path:
        return self.context.staging_root

    def preflight(self, plan: MigrationPlan, source: Source, r, journal: Journal) -> None:
        self._runner, self._journal = r, journal
        ctx = self.context
        for path in (ctx.staging_root, ctx.scratch_root):
            if not path.is_absolute() or not path.is_dir() or path.is_symlink() or path.resolve() != path:
                raise ValueError("unsafe staging or scratch directory")
        if ctx.staging_root == ctx.scratch_root or ctx.staging_root in ctx.scratch_root.parents:
            raise ValueError("staging and scratch directories overlap")
        if (journal.host_root_uuid or "").casefold() != source.running_root_uuid.casefold():
            raise ValueError("journal belongs to another root")
        check_tools(r)
        fresh = discover_source(r)
        expected = {(v.volume_id, v.mountpoint, v.partition.partuuid.casefold(),
                     v.fs_uuid.casefold()) for v in source.volumes}
        actual = {(v.volume_id, v.mountpoint, v.partition.partuuid.casefold(),
                   v.fs_uuid.casefold()) for v in fresh.volumes}
        if (source.running_root_uuid.casefold() != fresh.running_root_uuid.casefold()
                or expected != actual or source.esp.partition.partuuid.casefold()
                != fresh.esp.partition.partuuid.casefold()):
            raise ValueError("running source changed since planning")
        if {(t.volume.volume_id) for t in plan.targets} != {v.volume_id for v in source.volumes}:
            raise ValueError("layout does not cover every source volume")
        if len(plan.targets) != len(source.volumes) or any(
                target.volume != next(v for v in source.volumes
                                      if v.volume_id == target.volume.volume_id)
                for target in plan.targets):
            raise ValueError("layout was built for a different source")
        if ctx.bootloader_id.casefold() == ctx.loader.bootloader_id.casefold():
            raise ValueError("new EFI identifier must differ from the old one")
        if source.esp.mountpoint not in {"/boot/efi", "/efi"}:
            raise ValueError("unsupported source ESP mountpoint")
        for target in plan.targets:
            if target.size_bytes < estimate_min_bytes(target.volume, target.volume.btrfs is not None):
                raise ValueError("destination volume is too small")
        self._crypto = validate_crypto_plan(source, ctx.grub_caps)
        if source.secure_boot:
            self._signed = preflight_signed_chain(r, Path(source.esp.mountpoint), Path("/"), ctx.loader)
        assert_tables_unchanged(r, plan)
        for volume in source.volumes:
            SpaceWatch(r, volume.mountpoint).check()
        self._plan = plan

    def initialise_tables(self, plan: MigrationPlan, r, journal: Journal) -> MigrationPlan:
        for action in plan.init_gpt:
            init_gpt(r, action, journal)
        # Re-read the actual free areas.  Existing approved geometry and UUIDs
        # survive only if every planned extent is still wholly free.
        for disk in {action.disk for action in plan.init_gpt}:
            free = scan_disk(r, disk)
            for part in [*plan.partitions, *plan.swaps]:
                if part.disk != disk:
                    continue
                if not any(reg.logical_sector == part.logical_sector
                           and reg.start_sectors <= part.start_sectors
                           and reg.start_sectors + reg.size_sectors >= part.start_sectors + part.size_sectors
                           for reg in free):
                    raise ValueError("new GPT layout no longer fits approved geometry")
        updated = replace(plan, init_gpt=[],
                          approved_tables=fingerprint_tables(r, plan.approved_tables))
        assert_tables_unchanged(r, updated)
        self._plan = updated
        return updated

    def _watch(self, source: Source, r) -> None:
        for volume in source.volumes:
            SpaceWatch(r, volume.mountpoint).check()

    def create_storage(self, plan: MigrationPlan, source: Source, secrets: Secrets,
                       r, journal: Journal) -> None:
        self._passphrase = secrets.new_passphrase
        self._watch(source, r)
        if any(item.luks for item in [*source.volumes, *source.swaps]) and not secrets.new_passphrase:
            raise ValueError("new passphrase is required")
        self._created = create_partitions(r, plan, journal)
        for volume in source.volumes:
            part = self._created[volume.volume_id]
            device = part.path
            if volume.luks:
                luks_format(r, self._created, self._crypto, volume.volume_id,
                            secrets.new_passphrase, journal)
                device = luks_open(r, part, secrets.new_passphrase, journal)
            make_fs(r, device, volume.fs, part.fs_uuid, journal)
            self._devices[volume.volume_id] = device
            self._watch(source, r)
        if plan.esp.mode == "new":
            part = self._created["esp"]
            planned = next(p.planned for p in plan.partitions if p.volume_id == "esp")
            create_esp(r, part, planned, journal)
            self._esp_device, self._new_esp_uuid, self._esp_disk = part.path, part.fs_uuid, plan.esp.disk
        else:
            old = source.esp.partition
            if not old.uuid:
                raise ValueError("source ESP lacks filesystem UUID")
            self._esp_device, self._new_esp_uuid, self._esp_disk = old.path, old.uuid, old.parent_disk
        # The top-level btrfs mounts are journalled and verified before they
        # become a copy destination.  They stay outside the copied root.
        for volume in source.volumes:
            if volume.btrfs is None:
                continue
            part = self._created[volume.volume_id]
            top = self.context.scratch_root / f"top-{volume.volume_id}"
            if top.exists():
                if top.is_symlink() or any(top.iterdir()):
                    raise ValueError("btrfs top-level staging directory is occupied")
            else:
                top.mkdir(mode=0o700)
            actual = r.run(["blkid", "-p", "-o", "value", "-s", "UUID",
                            self._devices[volume.volume_id]], readonly=True).stdout.strip()
            if actual.casefold() != part.fs_uuid.casefold():
                raise ValueError("btrfs destination UUID changed")
            op = journal.intend("mount_destination", {"fs_uuid": part.fs_uuid},
                                device=self._devices[volume.volume_id], path=str(top))
            r.run(["mount", "-t", "btrfs", "-o", "subvolid=5",
                   self._devices[volume.volume_id], str(top)])
            journal.done(op, "mounted")
            self._tops[volume.volume_id] = top
            raw = replicate_subvolumes(r, top, volume.btrfs, journal)
            self._subvol_maps[part.fs_uuid] = raw
            self._watch(source, r)
        specs = []
        for volume in source.volumes:
            part = self._created[volume.volume_id]
            if volume.btrfs:
                mounted = [s for s in volume.btrfs.subvolumes if s.mountpoint]
                for subvol in mounted:
                    specs.append(DestinationMount(self._devices[volume.volume_id], volume.fs,
                                                  subvol.mountpoint, part.fs_uuid,
                                                  old_subvolid=subvol.id))
                if volume.mountpoint not in {s.mountpoint for s in mounted}:
                    specs.append(DestinationMount(self._devices[volume.volume_id], volume.fs,
                                                  volume.mountpoint, part.fs_uuid,
                                                  old_subvolid=volume.btrfs.default_subvol_id))
            else:
                specs.append(DestinationMount(self._devices[volume.volume_id], volume.fs,
                                              volume.mountpoint, part.fs_uuid))
        specs.append(DestinationMount(self._esp_device, "vfat", "/boot/efi", self._new_esp_uuid))
        mount_destination(r, specs, self._subvol_maps, self.context.staging_root, journal)
        if plan.esp.mode == "new":
            copy_esp(r, source.esp.mountpoint, self.context.staging_root / "boot/efi", journal)
        # Resolve the number from the live PARTUUID, not a guessed device suffix.
        live = collect_snapshot(r)
        matching = [v for v in live.identities if partuuid_key(v) ==
                    (self._created["esp"].partuuid if plan.esp.mode == "new"
                     else source.esp.partition.partuuid).casefold()]
        if len(matching) != 1:
            raise ValueError("ESP identity is ambiguous after creation")
        self._esp_number = next((p.number for p in [source.esp.partition]
                                 if plan.esp.mode == "reuse"), 0)
        if plan.esp.mode == "new":
            number = r.run(["lsblk", "-n", "-o", "PARTN", self._esp_device],
                           readonly=True).stdout.strip()
            if not number.isdecimal() or not 1 <= int(number) <= 128:
                raise ValueError("cannot identify new ESP partition number")
            self._esp_number = int(number)

    def copy(self, source: Source, r, journal: Journal) -> FreezeStats | None:
        self._watch(source, r)
        old_files = [swap.path for swap in source.swaps if swap.kind == "file"]
        ext4 = []
        for volume in source.volumes:
            if volume.fs != "ext4":
                continue
            destination = self.new_root / volume.mountpoint.lstrip("/")
            children = [v.mountpoint for v in source.volumes
                        if v.mountpoint != volume.mountpoint and
                        v.mountpoint.startswith(volume.mountpoint.rstrip("/") + "/")]
            if source.esp.mountpoint.startswith(volume.mountpoint.rstrip("/") + "/"):
                children.append(source.esp.mountpoint)
            filters = tuple(volume_filters(volume.mountpoint, children, old_files))
            ext4.append(CopyPair(Path(volume.mountpoint), destination,
                                 Path(volume.mountpoint),
                                 self._created[volume.volume_id].fs_uuid, filters))
        if ext4:
            self._freeze = copy_ext4(r, ext4, journal)
            for pair in ext4:
                self._references[str(pair.source)] = (
                    self._freeze.manifests[str(pair.source)], pair.destination,
                    _manifest_excludes(pair.filters), ())
            self._watch(source, r)
        for volume in source.volumes:
            info = volume.btrfs
            if info is None:
                continue
            top = self.context.btrfs_source_tops.get(volume.volume_id)
            if top is None:
                raise ValueError("btrfs source top-level mount is required")
            watch = SpaceWatch(r, volume.mountpoint)
            refs = take_snapshots(r, volume, journal, watch, top_level=top)
            self._snapshots.extend(refs)
            destination_top = self._tops[volume.volume_id]
            new_uuid = self._created[volume.volume_id].fs_uuid
            id_map = self._subvol_maps[new_uuid]
            destinations = {}
            for ref in refs:
                path = destination_top if ref.subvol_path == "." else destination_top / ref.subvol_path
                old_id = 5 if ref.subvol_path == "." else next(
                    s.id for s in info.subvolumes if s.path == ref.subvol_path)
                destinations[(ref.fs_uuid, ref.subvol_path)] = BtrfsDestination(
                    path, new_uuid, id_map[old_id])
            copy_from_snapshots(r, refs, destinations, journal=journal, watch=watch)
            live = []
            live_excludes = {}
            for subvol in info.subvolumes:
                kind = branch(subvol)
                if kind == "swap-only":
                    continue
                if kind != "live":
                    continue
                children = tuple(s.path[len(subvol.path) + 1:] for s in info.subvolumes
                                 if s.path.startswith(subvol.path + "/"))
                item = copy_live_swap_subvolume(
                    r, subvol,
                    BtrfsDestination(destination_top / subvol.path, new_uuid, id_map[subvol.id]),
                    old_files, journal=journal, source_fs_uuid=volume.fs_uuid,
                    source_top_level=top, watch=watch, excluded_subvols=children)
                live.append(item)
                live_excludes[subvol.path] = tuple(children) + tuple(
                    str(Path(path).relative_to(item.source)) for path in old_files
                    if Path(path).is_relative_to(item.source))
            refs_by_key = reference_manifests(refs, live)
            for ref in refs:
                key = f"{ref.fs_uuid}:{ref.subvol_path}"
                self._references[key] = (refs_by_key[key],
                                         destinations[(ref.fs_uuid, ref.subvol_path)].path,
                                         ref.exclude_paths, (".snapshots",))
            for item in live:
                key = f"{item.fs_uuid}:{item.subvol_path}"
                self._references[key] = (item.manifest, item.destination,
                                         live_excludes[item.subvol_path], (".snapshots",))
            self._watch(source, r)
        return self._freeze

    def make_swaps(self, source: Source, secrets: Secrets, r, journal: Journal) -> None:
        plans = []
        mounts = {}
        for volume in source.volumes:
            part = self._created[volume.volume_id]
            mounts[volume.volume_id] = SwapMount(
                self.new_root / volume.mountpoint.lstrip("/"), volume.fs, part.fs_uuid)
        for swap in source.swaps:
            if swap.kind == "partition":
                plans.append(SwapPlan(swap, created=self._created[swap.volume_id]))
                continue
            holders = [v for v in source.volumes if swap.path.startswith(
                v.mountpoint.rstrip("/") + "/")]
            if not holders or swap.volume_id not in self.context.swapfile_uuids:
                raise ValueError("swapfile has no unambiguous holder or planned UUID")
            holder = max(holders, key=lambda v: len(v.mountpoint))
            relative = swap.path[len(holder.mountpoint.rstrip("/")) + 1:]
            plans.append(SwapPlan(swap, swap_uuid=self.context.swapfile_uuids[swap.volume_id],
                                  containing_volume_id=holder.volume_id,
                                  relative_path=relative,
                                  source_containing_uuid=holder.fs_uuid))
        self._swaps = make_swaps(r, plans, mounts, self._crypto,
                                 secrets.new_passphrase or b"", journal)
        self._watch(source, r)

    def _uuid_map(self, source: Source, journal: Journal) -> UuidMap:
        fs, luks, partuuid, mapper, subvolid, swap_uuid = {}, {}, {}, {}, {}, {}
        live = collect_snapshot(self._runner)
        for volume in source.volumes:
            part = self._created[volume.volume_id]
            fs[volume.fs_uuid] = part.fs_uuid
            partuuid[volume.partition.partuuid] = part.partuuid
            if volume.luks:
                luks[volume.luks.luks_uuid] = part.luks_uuid
                if volume.luks.mapper_name:
                    mapper[volume.luks.mapper_name] = (
                        f"distromove-{journal.migration_id}-{volume.volume_id}")
            if volume.btrfs:
                subvolid[volume.fs_uuid] = self._subvol_maps[part.fs_uuid]
        for swap in source.swaps:
            if swap.kind == "partition":
                part = self._created[swap.volume_id]
                old = [v for v in live.identities if v.volume_id == swap.volume_id
                       and v.role == "swap"]
                if len(old) != 1:
                    raise ValueError("old swap partition changed")
                partuuid[old[0].partuuid] = part.partuuid
                if swap.luks:
                    luks[swap.luks.luks_uuid] = part.luks_uuid
                if swap.uuid:
                    swap_uuid[swap.uuid] = part.fs_uuid
            elif swap.uuid:
                swap_uuid[swap.uuid] = self.context.swapfile_uuids[swap.volume_id]
        if self._plan and self._plan.esp.mode == "new":
            partuuid[source.esp.partition.partuuid] = self._created["esp"].partuuid
            if source.esp.partition.uuid:
                fs[source.esp.partition.uuid] = self._new_esp_uuid
        return UuidMap(fs, luks, partuuid, mapper, subvolid, swap_uuid)

    def configure(self, source: Source, r, journal: Journal) -> None:
        mapping = self._uuid_map(source, journal)
        root = next(v for v in source.volumes if v.role == "root")
        filesystems = {v.mountpoint: v.fs_uuid for v in source.volumes}
        filesystems["/boot/efi"] = source.esp.partition.uuid or ""
        boot_encrypted = any(self._crypto.boot_in_luks.values())
        for volume_id, keyfile in self._crypto.keyfiles.items():
            if not keyfile.startswith("/") or ".." in Path(keyfile).parts:
                raise ValueError("unsafe keyfile path")
            planned = self._created[volume_id]
            add_keyfile(r, planned.path, self.new_root / keyfile.lstrip("/"),
                        self._passphrase, journal, luks_uuid=planned.luks_uuid)
        with Chroot(r, self.new_root, self.new_root / "boot/efi", journal) as chroot:
            if source.esp.mountpoint == "/efi":
                lines, changed = [], 0
                for line in config_read(chroot, "etc/fstab").splitlines(keepends=True):
                    if not line.lstrip().startswith("#") and re.match(r"^\s*\S+\s+/efi\s+", line):
                        line = re.sub(r"^(\s*\S+\s+)/efi(\s+)",
                                      r"\1/boot/efi\2", line, count=1)
                        changed += 1
                    lines.append(line)
                if changed != 1:
                    raise ValueError("copied fstab does not have exactly one /efi entry")
                config_save(chroot, "etc/fstab", "".join(lines))
            apply_configs(chroot, mapping, self._swaps, root_fs_uuid=root.fs_uuid,
                          filesystem_by_mount=filesystems, boot_in_luks=boot_encrypted)
            install_crypt_hooks(chroot, self._crypto, boot_in_luks=boot_encrypted)
            if root.fs == "btrfs":
                reset_snapper(chroot)
            rebuild_initramfs(chroot)
        self._watch(source, r)

    def install_boot(self, source: Source, r, journal: Journal) -> None:
        script = old_system_entry(self.context.loader,
                                  source.esp.partition.uuid or "",
                                  any(v.luks for v in source.volumes),
                                  self.context.osprober_sees_old)
        with Chroot(r, self.new_root, self.new_root / "boot/efi", journal) as chroot:
            install_old_entry(chroot, script)
            esp_partuuid = (self._created["esp"].partuuid if self._plan.esp.mode == "new"
                            else source.esp.partition.partuuid)
            op = journal.intend("install_efi_dir",
                                {"esp_partuuid": esp_partuuid,
                                 "efi_dir": self.context.bootloader_id},
                                creates="efi_dir")
            install_grub(chroot, self.context.bootloader_id,
                         secure_boot=source.secure_boot, signed_chain=self._signed)
            journal.done(op, "installed")
            persist_bootloader_id(chroot, self.context.bootloader_id)
            update_grub(chroot)
        self._watch(source, r)

    def verify(self, source: Source, secrets: Secrets, r) -> VerifyReport:
        findings = []
        transformed = {"etc/fstab", "etc/crypttab", "etc/default/grub",
                       "etc/default/grub.d", "etc/initramfs-tools/hooks",
                       "etc/default/grub.d/40_distromove.cfg",
                       "etc/grub.d/40_distromove_old",
                       "etc/initramfs-tools/conf.d/resume",
                       "etc/initramfs-tools/hooks/distromove-crypt",
                       "boot/grub/grub.cfg", "etc/snapper/configs/root"}
        for reference, destination, excludes, excluded_names in self._references.values():
            dynamic = {path for path in reference.entries
                       if path.startswith("boot/initrd.img-") or
                       path.startswith("var/lib/distromove/")}
            dynamic.update(str(path.relative_to(destination)) for path in
                           destination.glob("boot/initrd.img-*") if path.is_file())
            findings.extend(verify_copy(reference, destination,
                                        transformed | dynamic | self.context.expected_diffs,
                                        exclude_paths=excludes,
                                        exclude_names=excluded_names,
                                        expected_trees=("boot/grub",
                                                        "var/lib/initramfs-tools")))
        mapping = self._uuid_map(source, self._journal)
        new_ids = set(mapping.fs.values()) | set(mapping.luks.values()) | set(mapping.swap_uuid.values())
        old_ids = set(mapping.fs) | set(mapping.luks) | set(mapping.swap_uuid)
        findings.extend(verify_transformations(
            self.new_root, new_ids, old_ids,
            {"old_entry": {self.context.loader.esp_uuid} & old_ids}))
        early = {key for volume_id, key in self._crypto.keyfiles.items()
                 if self._crypto.key_class.get(volume_id) == "initramfs"}
        findings.extend(check_initramfs(r, self.new_root,
                                        bool(self._crypto.per_volume), early))
        encrypted = [self._created[v.volume_id].path for v in source.volumes if v.luks]
        encrypted += [self._created[s.volume_id].path for s in source.swaps if s.luks]
        if encrypted:
            credentials = {path: [secrets.new_passphrase] for path in encrypted}
            for volume_id, keyfile in self._crypto.keyfiles.items():
                credentials[self._created[volume_id].path].append(
                    (self.new_root / keyfile.lstrip("/")).read_bytes())
            findings.extend(check_unlock(r, encrypted, credentials))
        findings.extend(check_esp(self.new_root / "boot/efi", self.context.bootloader_id))
        expected = {v.mountpoint: self._created[v.volume_id].fs_uuid for v in source.volumes}
        expected["/boot/efi"] = self._new_esp_uuid
        observed = {}
        for mountpoint in expected:
            path = self.new_root / mountpoint.lstrip("/")
            raw = r.run(["findmnt", "--json", "--mountpoint", str(path),
                         "--output", "TARGET,SOURCE,FSTYPE"], readonly=True).stdout
            rows = json.loads(raw)["filesystems"]
            if len(rows) == 1 and rows[0]["target"] == str(path):
                device = rows[0]["source"]
                observed[mountpoint] = (device[5:] if device.startswith("UUID=") else
                    r.run(["blkid", "-p", "-o", "value", "-s", "UUID", device],
                          readonly=True).stdout.strip())
        findings.extend(check_identities(observed, expected))
        return VerifyReport(findings)

    def release_snapshots(self, r, journal: Journal) -> None:
        if self._snapshots:
            release_snapshots(r, self._snapshots, journal)
            self._snapshots.clear()

    def pending_state(self, source: Source, journal: Journal) -> MigrationState:
        live = collect_snapshot(self._runner)
        def find(partuuid: str):
            found = [v for v in live.identities if partuuid_key(v) == partuuid.casefold()]
            if len(found) != 1:
                raise ValueError("planned partition is absent or ambiguous")
            return found[0]
        old = [replace(find(v.partition.partuuid), volume_id=v.volume_id, role=v.role)
               for v in source.volumes]
        new = [replace(find(self._created[v.volume_id].partuuid), volume_id=v.volume_id,
                       role=v.role) for v in source.volumes]
        for swap in source.swaps:
            if swap.kind != "partition":
                continue
            prior = [v for v in live.identities if v.volume_id == swap.volume_id
                     and v.role == "swap"]
            if len(prior) != 1:
                raise ValueError("old swap partition is absent or ambiguous")
            old.append(prior[0])
            new.append(replace(find(self._created[swap.volume_id].partuuid),
                               volume_id=swap.volume_id, role="swap"))
        old_esp = replace(find(source.esp.partition.partuuid), role="esp")
        new_esp = (replace(find(self._created["esp"].partuuid), role="esp")
                   if self._plan.esp.mode == "new" else old_esp)
        root = next(v for v in new if v.role == "root")
        return MigrationState(1, journal.migration_id, "PENDING_ACTIVATION",
                              root.fs_uuid or "", old, new, old_esp, new_esp,
                              self.context.bootloader_id, self.context.loader.bootloader_id,
                              None, True, [])

    def register(self, r, journal: Journal) -> str:
        disk, number, path, label = self.registration_details()
        return register_new_entry(r, disk, number, path, label, journal)

    def registration_details(self) -> tuple[str, int, str, str]:
        loader = "shimx64.efi" if self._signed else "grubx64.efi"
        path = f"\\EFI\\{self.context.bootloader_id}\\{loader}"
        return self._esp_disk, self._esp_number, path, self.context.bootloader_id

    def unwind(self, r, journal: Journal) -> None:
        rollback_destination(r, journal)

    def close(self, r, journal: Journal) -> None:
        _release_journal_resources(r, journal, collect_snapshot(r),
                                   read_journal(journal.path))

class MigrationBackend(Protocol):
    """The privileged operations required by one migration.

    Implementations must journal each write before issuing it.  The engine
    calls ``preflight`` before any destination mutation and ``verify`` before
    the durable pending state.
    """

    def preflight(self, plan: MigrationPlan, source: Source, r, journal: Journal) -> None: ...
    def initialise_tables(self, plan: MigrationPlan, r, journal: Journal) -> MigrationPlan: ...
    def create_storage(self, plan: MigrationPlan, source: Source, secrets: Secrets,
                       r, journal: Journal) -> None: ...
    def copy(self, source: Source, r, journal: Journal) -> FreezeStats | None: ...
    def make_swaps(self, source: Source, secrets: Secrets, r, journal: Journal) -> None: ...
    def configure(self, source: Source, r, journal: Journal) -> None: ...
    def install_boot(self, source: Source, r, journal: Journal) -> None: ...
    def verify(self, source: Source, secrets: Secrets, r) -> VerifyReport: ...
    def release_snapshots(self, r, journal: Journal) -> None: ...
    def pending_state(self, source: Source, journal: Journal) -> MigrationState: ...
    @property
    def new_root(self) -> Path: ...
    def register(self, r, journal: Journal) -> str: ...
    def registration_details(self) -> tuple[str, int, str, str]: ...
    def close(self, r, journal: Journal) -> None: ...
    def unwind(self, r, journal: Journal) -> None: ...


def _event(emit: Callable[[dict], None], phase: str, **fields) -> None:
    # Only public phase names and measured values go to the event stream.
    try:
        emit({"phase": phase, **fields})
    except Exception:
        # A disconnected GUI cannot change the transaction outcome or prevent
        # the recovery path from running.
        pass


def run_migration(plan: MigrationPlan, source: Source, secrets: Secrets, r,
                  emit: Callable[[dict], None], journal: Journal, lock: Lock,
                  *, context: MigrationContext | None = None,
                  backend: MigrationBackend | None = None) -> MigrationResult:
    """Run one migration.  Firmware registration is the last mutating step.

    Once PENDING_ACTIVATION is durable, a failure is a reconciliation problem;
    it must never trigger deletion of the new installation.
    """
    if backend is None:
        if context is None:
            raise ValueError("migration execution context is required")
        backend = SystemBackend(context)
    phase = "preflight"
    pending = False
    acquired = False
    freeze = None
    report = None
    bootnum = None
    warnings: list[str] = []
    owns_lock = lock._fd is None
    try:
        if owns_lock:
            lock.__enter__()
    except AlreadyRunning:
        _event(emit, "error", failed_phase="lock", error="AlreadyRunning")
        return MigrationResult(False, None, None, None, ["AlreadyRunning"], "lock")
    acquired = True
    try:
        if not journal.is_current():
            raise ValueError("migration journal is not current")
        _event(emit, phase)
        backend.preflight(plan, source, r, journal)
        phase = "init_gpt"
        if plan.init_gpt:
            _event(emit, phase)
            plan = backend.initialise_tables(plan, r, journal)
        phase = "create_storage"
        _event(emit, phase)
        backend.create_storage(plan, source, secrets, r, journal)
        phase = "copy"
        _event(emit, phase)
        freeze = backend.copy(source, r, journal)
        phase = "make_swaps"
        _event(emit, phase)
        backend.make_swaps(source, secrets, r, journal)
        phase = "configure"
        _event(emit, phase)
        backend.configure(source, r, journal)
        phase = "install_boot"
        _event(emit, phase)
        backend.install_boot(source, r, journal)
        phase = "verify"
        _event(emit, phase)
        report = backend.verify(source, secrets, r)
        if not report.ok:
            raise RuntimeError("final verification failed")
        phase = "release_snapshots"
        _event(emit, phase)
        backend.release_snapshots(r, journal)
        phase = "install_journal"
        _event(emit, phase)
        journal.install_into(backend.new_root)
        phase = "pending_activation"
        state = backend.pending_state(source, journal)
        if state.phase != "PENDING_ACTIVATION" or not state.verified:
            raise ValueError("backend supplied an unverified pending state")
        # The intent lets a restarted helper locate the copied state even
        # if it is killed between the state write and its journal outcome.
        op = journal.intend("pending_activation", {"new_root_uuid": state.new_root_uuid},
                            state_root=str(backend.new_root),
                            registration=list(backend.registration_details()))
        save_state(state, backend.new_root)
        journal.done(op, "saved")
        pending = True
        _event(emit, phase)
        phase = "register_entry"
        _event(emit, phase)
        bootnum = backend.register(r, journal)
        save_state(replace(state, phase="ACTIVATED", uefi_entry=bootnum), backend.new_root)
        backend.close(r, journal)
        journal.finish("activated")
        phase = "activated"
        _event(emit, phase, bootnum=bootnum,
               freeze_seconds=freeze.seconds if freeze else None)
        return MigrationResult(True, report, bootnum, freeze, warnings, phase)
    except Exception as exc:
        # An exception never serialises secret data to the event stream.
        warnings.append(type(exc).__name__)
        _event(emit, "error", failed_phase=phase, error=type(exc).__name__)
        if pending:
            return MigrationResult(False, report, bootnum, freeze, warnings,
                                   "pending_reconciliation")
        if acquired:
            try:
                backend.release_snapshots(r, journal)
            except Exception as cleanup_exc:
                warnings.append(type(cleanup_exc).__name__)
            try:
                backend.unwind(r, journal)
            except Exception as cleanup_exc:
                warnings.append(type(cleanup_exc).__name__)
        return MigrationResult(False, report, None, freeze, warnings, phase)
    finally:
        if owns_lock:
            lock.__exit__(None, None, None)


def reconcile_on_start(r, journal: Journal, *, state_root: Path | None = None) -> list[Action]:
    """Resolve a killed migration using the source-bound current journal.

    Ambiguous firmware entries or changed destination identities remain for
    manual review; neither is guessed from a device name or EFI label alone.
    """
    if not journal.is_current():
        if state_root is None:
            return []
        live = collect_snapshot(r)
        state = load_state(state_root, live.running_root_uuid)
        if state is None or state.phase != "PENDING_ACTIVATION" or not state.verified:
            return []
        firmware = _state(r)
        bootnum = firmware.current
        line = firmware.entries.get(bootnum or "", "")
        target = loader_of(line)
        if (not target or target[0].casefold() != state.new_esp.partuuid.casefold()
                or not re.fullmatch(
                    r"\\EFI\\" + re.escape(state.bootloader_id_new) +
                    r"\\(?:shimx64|grubx64)\.efi", target[1], re.I)):
            return [Action("manual_review", "BootCurrent is not the verified new loader")]
        save_state(replace(state, phase="ACTIVATED", uefi_entry=bootnum), state_root)
        return [Action("activated", bootnum)]
    actions = []
    live = collect_snapshot(r)
    if (journal.host_root_uuid or "").casefold() != live.running_root_uuid.casefold():
        raise ValueError("reconciliation is running on another root")
    for window in open_windows(journal.root, live.running_root_uuid):
        if window.name != "ext4-final-copy":
            actions.append(Action("manual_review", "unknown open freeze window"))
            continue
        from .copy_ext4 import _probe_thawed
        source = discover_source(r)
        for volume in source.volumes:
            if volume.fs == "ext4":
                r.run(["fsfreeze", "-u", volume.mountpoint], check=False)
                if not _probe_thawed(Path(volume.mountpoint)):
                    raise RuntimeError("source filesystem is still frozen")
        journal.window_close(window.op_id)
        actions.append(Action("thawed", window.name))
    entries = read_journal(journal.path)
    pending = [e for e in entries if e["type"] == "intent" and e["op"] == "pending_activation"]
    if pending:
        entry = pending[-1]
        root = Path(entry["fields"]["state_root"])
        root_uuid = entry["identity"]["new_root_uuid"]
        state = load_state(root, root_uuid)
        if state is None:
            actions.append(Action("manual_review", "pending destination state is not mounted"))
            return actions
        if state.migration_id != journal.migration_id or not state.verified:
            raise ValueError("pending state differs from journal")
        disk, number, path, label = entry["fields"]["registration"]
        if (_partuuid(r, disk, int(number)).casefold() != state.new_esp.partuuid.casefold()
                or not path.startswith(f"\\EFI\\{state.bootloader_id_new}\\")):
            raise ValueError("ESP registration target changed")
        firmware = _state(r)
        matching = []
        for bootnum, line in firmware.entries.items():
            target = loader_of(line)
            if (target and target[0].casefold() == state.new_esp.partuuid.casefold()
                    and target[1].casefold() == path.casefold()
                    and re.match(r"^Boot[0-9A-Fa-f]{4}\*?\s+" + re.escape(label) +
                                 r"\s+HD\(", line)):
                matching.append(bootnum)
        if len(matching) > 1:
            actions.append(Action("manual_review", "ambiguous firmware entries"))
            return actions
        if matching:
            bootnum = matching[0]
            if not firmware.order or firmware.order[0] != bootnum:
                wanted = (bootnum, *(item for item in firmware.order if item != bootnum))
                op = journal.intend("reconcile_uefi_order",
                                    {"bootnum": bootnum, "esp_partuuid": state.new_esp.partuuid},
                                    new_order=wanted)
                r.run(["efibootmgr", "-o", ",".join(wanted)])
                after = _state(r)
                if after.order != wanted or any(after.entries.get(k) != v
                                                for k, v in firmware.entries.items()):
                    raise RuntimeError("firmware order was not applied")
                journal.done(op, "ordered")
        elif state.phase == "ACTIVATED":
            actions.append(Action("manual_review", "activated firmware entry is missing"))
            return actions
        else:
            bootnum = register_new_entry(r, disk, int(number), path, label, journal)
            actions.append(Action("entry_retried", bootnum))
        if state.phase == "PENDING_ACTIVATION":
            save_state(replace(state, phase="ACTIVATED", uefi_entry=bootnum), root)
        elif state.uefi_entry != bootnum:
            raise ValueError("saved firmware number changed")
        _release_journal_resources(r, journal, live, entries)
        journal.finish("activated")
        actions.append(Action("activated", bootnum))
    else:
        try:
            rollback_destination(r, journal)
        except RuntimeError as exc:
            actions.append(Action("manual_review", str(exc)))
        else:
            actions.append(Action("rolled_back", journal.migration_id))
    return actions



def _release_journal_resources(r, journal: Journal, live, entries):
    """Unmount and close only still-present resources proven by journal identity."""
    intents = {e["op_id"]: e for e in entries if e["type"] == "intent"}
    # A killed helper can leave a mount between the durable intent and its
    # outcome. Identify it by the recorded path, device and filesystem UUID.
    mounted = [e for e in entries if e["type"] == "intent"
               and e["op"] == "mount_destination"]
    opened = [intents[e["op_id"]] for e in entries if e["type"] == "outcome"
              and e["outcome"] == "opened" and e["op_id"] in intents
              and intents[e["op_id"]]["op"] == "luks_open"]
    if not mounted and not opened:
        return live
    source = discover_source(r)
    protected = {v.mountpoint for v in source.volumes} | {source.esp.mountpoint}
    for item in reversed(mounted):
        path = str(item["fields"].get("path", ""))
        expected = str(item["identity"].get("fs_uuid", ""))
        if not path.startswith("/") or path in protected or not expected:
            raise RuntimeError("unsafe destination mount in journal")
        live_mounts = [m for m in live.mounts if m.target == path]
        if not live_mounts:
            continue
        if len(live_mounts) != 1:
            raise RuntimeError("destination mount is ambiguous")
        device = live_mounts[0].source.split("[")[0]
        planned_device = str(item["fields"].get("device", ""))
        if (not planned_device.startswith("/dev/") or
                (device.startswith("/dev/") and
                 os.path.realpath(device) != os.path.realpath(planned_device))):
            raise RuntimeError("destination mount device changed")
        actual = (device[5:] if device.startswith("UUID=") else
                  r.run(["blkid", "-p", "-o", "value", "-s", "UUID", device],
                        readonly=True).stdout.strip())
        if actual.casefold() != expected.casefold():
            raise RuntimeError("destination mount changed")
        op = journal.intend("rollback_mount", {"fs_uuid": expected}, path=path)
        r.run(["umount", path])
        journal.done(op, "unmounted")
        live = collect_snapshot(r)
    for item in reversed(opened):
        name = str(item["fields"].get("mapper_name", ""))
        luks_uuid = str(item["identity"].get("luks_uuid", ""))
        if not name.startswith(f"distromove-{journal.migration_id}-") or not luks_uuid:
            raise RuntimeError("unsafe mapper in journal")
        matching = [entry for entry in live.mappers if entry.split()[0] == name]
        if not matching:
            continue
        if len(matching) != 1 or luks_uuid.replace("-", "").casefold() not in matching[0].casefold():
            raise RuntimeError("destination mapper identity changed")
        op = journal.intend("rollback_mapper", {"luks_uuid": luks_uuid}, mapper_name=name)
        r.run(["cryptsetup", "close", name])
        journal.done(op, "closed")
        live = collect_snapshot(r)
    return live

def rollback_destination(r, journal: Journal) -> None:
    """Remove only detached destination partitions proven by the journal guard."""
    if not journal.is_current():
        raise ValueError("migration journal is not current")
    live = collect_snapshot(r)
    if (journal.host_root_uuid or "").casefold() != live.running_root_uuid.casefold():
        raise ValueError("rollback is running on another root")
    if open_windows(journal.root, live.running_root_uuid):
        raise RuntimeError("a source freeze window remains open")
    entries = read_journal(journal.path)
    live = _release_journal_resources(r, journal, live, entries)
    snapshots = []
    for item in entries:
        if item["type"] == "intent" and item["op"] == "btrfs_snapshot":
            ident = item["identity"]
            created = any(e["type"] == "outcome" and e["op_id"] == item["op_id"]
                          and e["outcome"] == "created" for e in entries)
            if not created and not Path(ident["snapshot_path"]).exists():
                continue
            if not created:
                raise RuntimeError("unconfirmed source snapshot needs manual review")
            snapshots.append(SnapshotRef(ident["fs_uuid"], ident["subvol_path"],
                                         ident["snapshot_path"], item["op_id"]))
    if snapshots:
        release_snapshots(r, snapshots, journal)
    residues = recover(journal.root, live, live.running_root_uuid)
    if any(item.kind == "nvram_entry" for item in residues):
        raise RuntimeError("firmware entry exists; reconcile activation first")
    parts = [item for item in residues if item.kind == "partition"]
    for item in reversed(parts):
        identity = item.identity
        found = [v for v in live.identities if partuuid_key(v) ==
                 str(identity["partuuid"]).casefold()]
        if len(found) != 1:
            raise RuntimeError("destination partition identity changed")
        disk, number, _ = _locate(r, found[0], os.path.realpath)
        op = journal.intend("rollback_partition", identity, disk=disk, part_no=number)
        r.run(["sgdisk", f"--delete={number}", disk])
        r.run(["partprobe", disk])
        journal.done(op, "removed")
        live = collect_snapshot(r)
        if any(partuuid_key(v) == str(identity["partuuid"]).casefold()
               for v in live.identities):
            raise RuntimeError("destination partition remained after rollback")
    remaining = recover(journal.root, live, live.running_root_uuid)
    planned = {str(item["identity"]["partuuid"]).casefold() for item in entries
               if item["type"] == "intent" and item["op"] == "create_partition"}
    if any(partuuid_key(v) in planned for v in live.identities):
        raise RuntimeError("created destination remains in use or changed")
    if remaining:
        raise RuntimeError("owned destination residues require manual review")
    if any(e["type"] == "intent" and e["op"] == "init_gpt" for e in entries):
        raise RuntimeError("new GPT needs manual review before journal can be closed")
    journal.finish("rolled_back")
