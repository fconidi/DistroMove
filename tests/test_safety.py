"""Deletion guards are exercised on coherent synthetic live snapshots."""
from dataclasses import replace

from distromove.model import MountInfo, SwapRef, SystemSnapshot, VolumeIdentity
from distromove.safety import can_delete_old, confirmation_text
from distromove.state import MigrationState


OLD_PART = "11111111-1111-4111-8111-111111111111"
NEW_PART = "22222222-2222-4222-8222-222222222222"
OLD_ESP = "33333333-3333-4333-8333-333333333333"
NEW_ESP = "44444444-4444-4444-8444-444444444444"


def v(name, role, part, fs, luks=None, *, wwn="wwn-disk"):
    start = {"old-root": 2048, "old-esp": 8192,
             "new-root": 16384, "new-esp": 24576}.get(name, 32768)
    return VolumeIdentity(name, role, wwn, "serial-disk", "/dev/disk/by-id/disk",
                          part, start, 4096, luks, fs)


def state():
    return MigrationState(1, "m1", "ACTIVATED", "new-root",
                          [v("old-root", "root", OLD_PART, "old-root", "old-luks")],
                          [v("new-root", "root", NEW_PART, "new-root")],
                          v("old-esp", "esp", OLD_ESP, "OLD-1111"),
                          v("new-esp", "esp", NEW_ESP, "NEW-2222"),
                          "debian-moved", "debian", "0003", True, [])


def live(s=None):
    s = s or state()
    old_entry = (f"Boot0001* Debian HD(1,GPT,{OLD_ESP},0x800,0x1000)"
                 "/File(\\EFI\\debian\\shimx64.efi)")
    new_entry = (f"Boot0003* Moved HD(1,GPT,{NEW_ESP},0x800,0x1000)"
                 "/File(\\EFI\\debian-moved\\shimx64.efi)")
    return SystemSnapshot("UUID=new-root / ext4 defaults 0 1\n", "",
                          [MountInfo("UUID=new-root", "/", "ext4", "rw")], [], [],
                          {OLD_ESP: ["debian"], NEW_ESP: ["debian-moved"]},
                          "0003", {"0001": old_entry, "0003": new_entry},
                          [*s.old_volumes, *s.new_volumes, s.old_esp, s.new_esp],
                          "new-root")


def reasons(s=None, snap=None, **kwargs):
    return can_delete_old(s or state(), snap or live(s), **kwargs).reasons


def test_guard_accepts_clean_new_boot():
    assert can_delete_old(state(), live()).ok


def test_refuse_running_from_old_system():
    assert any("running root" in x for x in reasons(snap=replace(live(), running_root_uuid="old-root")))


def test_refuse_not_verified_or_wrong_phase():
    assert reasons(replace(state(), verified=False))
    assert reasons(replace(state(), phase="PENDING_ACTIVATION"))


def test_refuse_renamed_device_changed_disk():
    snap = live()
    snap = replace(snap, identities=[replace(snap.identities[0], disk_wwn="different"),
                                     *snap.identities[1:]])
    assert any("old-root" in x for x in reasons(snap=snap))


def test_refuse_partition_recreated_same_name_other_partuuid():
    snap = live()
    snap = replace(snap, identities=[replace(snap.identities[0], partuuid="other-part"),
                                     *snap.identities[1:]])
    assert any("old-root" in x for x in reasons(snap=snap))


def test_refuse_old_new_partition_overlap():
    s = state()
    s = replace(s, new_volumes=[replace(s.new_volumes[0], start_sectors=2048)])
    assert any("overlap" in x for x in reasons(s, live(s)))


def test_refuse_disk_without_unique_identity():
    s = state()
    missing = replace(s.old_volumes[0], disk_wwn=None, disk_serial=None, disk_by_id=None)
    s = replace(s, old_volumes=[missing])
    snap = live(s)
    assert any("stable identity" in x for x in reasons(s, snap))


def test_refuse_when_new_system_references_old_uuid_in_fstab_crypttab_mapper_or_swap():
    snap = live()
    assert reasons(snap=replace(snap, fstab="UUID=old-root / ext4 defaults 0 1\n"))
    assert reasons(snap=replace(snap, crypttab="root UUID=old-luks none luks\n"))
    assert reasons(snap=replace(snap, mappers=["old CRYPT-LUKS2-oldluks-old"]))
    assert reasons(snap=replace(snap, mounts=[MountInfo("UUID=old-root", "/mnt", "ext4", "rw")]))
    assert reasons(snap=replace(snap, fstab="/dev/mapper/old / ext4 defaults 0 1\n"))
    old_swap = SwapRef("old-swap", "partition", f"/dev/disk/by-partuuid/{OLD_PART}",
                       None, "old-swap", 4096, None, False)
    assert reasons(snap=replace(snap, swaps=[old_swap]))


def test_refuse_active_esp():
    s = replace(state(), new_esp=state().old_esp)
    snap = live(s)
    assert any("active new ESP" in x for x in reasons(s, snap, delete_old_esp=True))


def test_refuse_old_esp_with_windows_entry():
    snap = live()
    contents = dict(snap.esp_contents)
    contents[OLD_ESP] = ["debian", "Microsoft"]
    assert any("foreign" in x for x in reasons(snap=replace(snap, esp_contents=contents),
                                                 delete_old_esp=True))


def test_refuse_old_esp_used_by_firmware():
    snap = live()
    entries = dict(snap.boot_entries)
    entries["0002"] = (f"Boot0002* Windows HD(1,GPT,{OLD_ESP},0x800,0x1000)"
                       "/File(\\EFI\\Microsoft\\bootmgfw.efi)")
    assert any("firmware" in x for x in reasons(snap=replace(snap, boot_entries=entries),
                                                  delete_old_esp=True))


def test_confirmation_lists_all_partitions():
    text = confirmation_text(state(), delete_old_esp=True)
    assert OLD_PART in text and OLD_ESP in text and "start=" in text


def test_resume_in_deleting_checks_only_residual_resources():
    s = replace(state(), phase="DELETING", deletion_done=[f"partition:{OLD_PART}"])
    snap = live(s)
    snap = replace(snap, identities=[item for item in snap.identities if item.partuuid != OLD_PART])
    assert can_delete_old(s, snap).ok
    assert reasons(s, replace(snap, identities=[*snap.identities, s.old_volumes[0]]))


def test_luks_erase_does_not_make_resume_fail():
    s = replace(state(), phase="DELETING", deletion_done=[f"luks:{OLD_PART}"])
    snap = live(s)
    snap = replace(snap, identities=[replace(snap.identities[0], luks_uuid=None, fs_uuid=None),
                                     *snap.identities[1:]])
    assert can_delete_old(s, snap).ok


def test_closed_old_luks_container_keeps_its_partition_identity():
    snap = live()
    closed = replace(snap.identities[0], fs_uuid=None)
    snap = replace(snap, identities=[closed, *snap.identities[1:]])
    assert can_delete_old(state(), snap).ok


def test_closed_old_luks_container_rejects_changed_luks_identity():
    snap = live()
    changed = replace(snap.identities[0], luks_uuid="other-luks", fs_uuid=None)
    snap = replace(snap, identities=[changed, *snap.identities[1:]])
    assert any("old-root" in reason for reason in reasons(snap=snap))


def test_open_old_luks_container_rejects_changed_filesystem_identity():
    snap = live()
    changed = replace(snap.identities[0], fs_uuid="other-fs")
    snap = replace(snap, identities=[changed, *snap.identities[1:]])
    assert any("old-root" in reason for reason in reasons(snap=snap))


def test_refuse_when_a_live_partition_identity_is_unreadable():
    snap = live()
    unreadable = replace(snap.identities[0], partuuid=None)
    snap = replace(snap, identities=[unreadable, *snap.identities[1:]])
    found = reasons(snap=snap)
    assert any("partition identity unreadable" in x for x in found)
