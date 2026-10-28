"""Two-level verification against stable references and copied-system state."""
from pathlib import Path
import os
import shutil
import subprocess

from distromove.manifest import build_manifest
from distromove.config_rewrite import rewrite_fstab
from distromove.model import UuidMap
from distromove.verify import (Finding, VerifyReport, check_esp, check_identities,
                              check_initramfs, check_unlock, verify_copy,
                              verify_transformations)


def tree(tmp_path):
    src, dst = tmp_path / "source", tmp_path / "destination"
    (src / "etc").mkdir(parents=True)
    (src / "boot").mkdir()
    (src / "etc/fstab").write_text("UUID=new-root / ext4 defaults 0 1\n")
    (src / "boot/vmlinuz-1").write_bytes(b"kernel")
    shutil.copytree(src, dst, copy_function=shutil.copy2)
    return src, dst


def errors(findings):
    return [f for f in findings if f.severity == "error"]


def test_identical_ok(tmp_path):
    src, dst = tree(tmp_path)
    reference = build_manifest(src, sample=0)
    assert verify_copy(reference, dst, set()) == []


def test_missing_file_error(tmp_path):
    src, dst = tree(tmp_path)
    reference = build_manifest(src, sample=0)
    (dst / "boot/vmlinuz-1").unlink()
    assert any("boot/vmlinuz-1" in f.detail for f in errors(verify_copy(reference, dst, set())))


def test_content_change_in_etc_same_size_mtime_detected(tmp_path):
    src, dst = tree(tmp_path)
    reference = build_manifest(src, sample=0)
    path = dst / "etc/fstab"
    before = path.stat()
    path.write_bytes(path.read_bytes().replace(b"new-root", b"bad-root"))
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert any("sha256" in f.detail for f in errors(verify_copy(reference, dst, set())))


def test_expected_diffs_not_copy_errors(tmp_path):
    src, dst = tree(tmp_path)
    reference = build_manifest(src, sample=0)
    (dst / "etc/fstab").write_text("UUID=moved / ext4 defaults 0 1\n")
    assert verify_copy(reference, dst, {"etc/fstab"}) == []


def test_top_level_holding_only_excluded_subvolumes_is_a_valid_empty_reference(tmp_path):
    src, dst = tmp_path / "top", tmp_path / "copy"
    (src / "@rootfs").mkdir(parents=True)
    dst.mkdir()
    reference = build_manifest(src, sample=0, exclude_paths=("@rootfs",))
    assert not reference.entries
    assert verify_copy(reference, dst, set(), exclude_paths=("@rootfs",)) == []
    # anything the copy placed there is still reported
    (dst / "stray").write_text("x")
    assert errors(verify_copy(reference, dst, set(), exclude_paths=("@rootfs",)))
    # without exclusions an empty reference is still refused
    assert errors(verify_copy(reference, dst, set()))


def test_empty_btrfs_subvolume_is_valid_only_when_destination_is_empty(tmp_path):
    src, dst = tmp_path / "empty-subvolume", tmp_path / "copy"
    src.mkdir()
    dst.mkdir()
    reference = build_manifest(src, kind="btrfs-snapshot", sample=0)
    assert not reference.entries
    assert verify_copy(reference, dst, set()) == []
    (dst / "stray").write_text("unexpected")
    assert any("stray" in finding.detail for finding in errors(verify_copy(reference, dst, set())))


def test_child_mount_excluded_on_both_sides(tmp_path):
    src, dst = tree(tmp_path)
    (src / "boot/efi").mkdir()
    (dst / "boot/efi").mkdir()
    reference = build_manifest(src, sample=0, exclude_paths=("boot/efi",))
    (dst / "boot/efi/loader.efi").write_bytes(b"EFI")
    assert verify_copy(reference, dst, set(), exclude_paths=("boot/efi",)) == []
    assert errors(verify_copy(reference, dst, set()))


def test_declared_generated_tree_does_not_hide_other_copy_errors(tmp_path):
    src, dst = tree(tmp_path)
    reference = build_manifest(src, sample=0)
    (dst / "boot/grub").mkdir()
    (dst / "boot/grub/grub.cfg").write_text("generated")
    assert verify_copy(reference, dst, set(), expected_trees=("boot/grub",)) == []
    (dst / "etc/fstab").write_text("corrupt")
    assert errors(verify_copy(reference, dst, set(), expected_trees=("boot/grub",)))


def test_expected_added_file_allows_parent_mtime_change(tmp_path):
    src, dst = tree(tmp_path)
    reference = build_manifest(src, sample=0)
    (dst / "etc/new.conf").write_text("new")
    assert verify_copy(reference, dst, {"etc/new.conf"}) == []


def test_known_runtime_directory_mtime_does_not_hide_mode_change(tmp_path):
    src, dst = tree(tmp_path)
    (src / "tmp").mkdir(mode=0o1777)
    (dst / "tmp").mkdir(mode=0o1777)
    reference = build_manifest(src, sample=0)
    before = (dst / "tmp").stat()
    os.utime(dst / "tmp", ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
    assert errors(verify_copy(reference, dst, set()))
    assert verify_copy(reference, dst, set(), expected_mtime_paths=("tmp",)) == []
    (dst / "tmp").chmod(0o755)
    assert errors(verify_copy(reference, dst, set(), expected_mtime_paths=("tmp",)))


def test_generated_osprober_label_and_run_mtime_keep_other_copy_checks(tmp_path):
    src, dst = tree(tmp_path)
    for root in (src, dst):
        (root / "run").mkdir()
        (root / "var/lib/os-prober").mkdir(parents=True)
    reference = build_manifest(src, sample=0)
    (dst / "var/lib/os-prober/labels").write_text("generated")
    before = (dst / "run").stat()
    os.utime(dst / "run", ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
    expected = {"var/lib/os-prober/labels"}
    assert verify_copy(reference, dst, expected, expected_mtime_paths=("run",)) == []
    (dst / "var/lib/os-prober/other").write_text("unexpected")
    assert errors(verify_copy(reference, dst, expected, expected_mtime_paths=("run",)))
    (dst / "var/lib/os-prober/other").unlink()
    (dst / "run").chmod(0o700)
    assert errors(verify_copy(reference, dst, expected, expected_mtime_paths=("run",)))


def test_encrypted_root_fstab_accepts_only_its_planned_mapper(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc/fstab").write_text("/dev/mapper/distromove-new-root / btrfs defaults 0 0\n")
    expected = {"UUID=new-root", "/dev/mapper/distromove-new-root"}
    assert not any("fstab root" in f.detail for f in errors(
        verify_transformations(root, {"new-root"}, set(), {}, root_sources=expected)))
    (root / "etc/fstab").write_text("/dev/mapper/other / btrfs defaults 0 0\n")
    assert any("fstab root" in f.detail for f in errors(
        verify_transformations(root, {"new-root"}, set(), {}, root_sources=expected)))
    (root / "etc/fstab").write_text("/dev/mapper/DISTROMOVE-new-root / btrfs defaults 0 0\n")
    assert any("fstab root" in f.detail for f in errors(
        verify_transformations(root, {"new-root"}, set(), {}, root_sources=expected)))


def test_rewritten_encrypted_root_fstab_passes_root_identity_check(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    source = "/dev/mapper/luks-old / btrfs subvol=/@,defaults 0 0\n"
    mapping = UuidMap(fs={"old-fs": "new-fs"}, luks={}, partuuid={},
                      mapper={"luks-old": "distromove-new-root"},
                      subvolid={}, swap_uuid={})
    rewritten = rewrite_fstab(source, mapping, filesystem_by_mount={"/": "old-fs"})
    (root / "etc/fstab").write_text(rewritten)
    assert not any("fstab root" in f.detail for f in errors(
        verify_transformations(root, {"new-fs"}, set(), {},
                               root_sources={"UUID=new-fs", "/dev/mapper/distromove-new-root"})))


def test_unexpected_extra_file_and_bad_expected_path(tmp_path):
    src, dst = tree(tmp_path)
    reference = build_manifest(src, sample=0)
    (dst / "etc/extra").write_text("surprise")
    assert any("etc/extra" in f.detail for f in errors(verify_copy(reference, dst, set())))
    try:
        verify_copy(reference, dst, {"../outside"})
    except ValueError:
        pass
    else:
        raise AssertionError("unsafe exception path accepted")


def test_old_uuid_allowed_only_in_old_entry_role(tmp_path):
    root = tmp_path / "root"
    (root / "etc/grub.d").mkdir(parents=True)
    (root / "etc/default").mkdir()
    (root / "etc/initramfs-tools/conf.d").mkdir(parents=True)
    (root / "etc/fstab").write_text("UUID=new-root / ext4 defaults 0 1\n")
    (root / "etc/crypttab").write_text("")
    (root / "etc/default/grub").write_text("GRUB_CMDLINE_LINUX=''\n")
    (root / "etc/initramfs-tools/conf.d/resume").write_text("RESUME=none\n")
    (root / "boot/grub").mkdir(parents=True)
    (root / "boot/grub/grub.cfg").write_text(
        "menuentry 'Previous system' --id=distromove-old {\n"
        " search --fs-uuid --set=root OLD-1111\n}\n")
    old = root / "etc/grub.d/40_distromove_old"
    old.write_text("#!/bin/sh\n# DistroMove old-system entry\n"
                   "search --fs-uuid --set=root OLD-1111\n")
    assert not errors(verify_transformations(root, {"new-root"}, {"OLD-1111"},
                                             {"old_entry": {"OLD-1111"}}))
    (root / "etc/fstab").write_text("UUID=OLD-1111 / ext4 defaults 0 1\n")
    assert errors(verify_transformations(root, {"new-root"}, {"OLD-1111"},
                                         {"old_entry": {"OLD-1111"}}))


def test_osprober_old_entry_is_allowed_but_grub_root_reference_is_not(tmp_path):
    root = tmp_path / "root"
    (root / "etc/default").mkdir(parents=True)
    (root / "boot/grub").mkdir(parents=True)
    (root / "etc/fstab").write_text("UUID=new-root / ext4 defaults 0 1\n")
    (root / "etc/default/grub").write_text("GRUB_CMDLINE_LINUX=''\n")
    grub = root / "boot/grub/grub.cfg"
    grub.write_text("menuentry 'Previous system' --id=osprober-efi-OLD-1111 {\n"
                    " search --fs-uuid --set=root OLD-1111\n}\n")
    assert not errors(verify_transformations(root, {"new-root"}, {"OLD-1111"},
                                             {"osprober_entry": {"OLD-1111"}}))
    grub.write_text(grub.read_text() + "linux /vmlinuz root=UUID=OLD-1111\n")
    assert errors(verify_transformations(root, {"new-root"}, {"OLD-1111"},
                                         {"osprober_entry": {"OLD-1111"}}))


def test_debian_osprober_old_root_entry_is_not_a_new_root_reference(tmp_path):
    root = tmp_path / "root"
    (root / "etc/default").mkdir(parents=True)
    (root / "boot/grub").mkdir(parents=True)
    (root / "etc/fstab").write_text("UUID=new-root / ext4 defaults 0 1\n")
    (root / "etc/default/grub").write_text("GRUB_CMDLINE_LINUX=''\n")
    grub = root / "boot/grub/grub.cfg"
    grub.write_text(
        "menuentry 'Debian GNU/Linux' $menuentry_id_option 'gnulinux-simple-new-root' {\n"
        " linux /vmlinuz root=UUID=new-root\n}\n"
        "menuentry 'Previous system (on /dev/sda2)' $menuentry_id_option "
        "'osprober-gnulinux-simple-OLD-1111' {\n"
        " search --fs-uuid --set=root OLD-1111\n"
        " linux /vmlinuz root=UUID=OLD-1111\n}\n"
        "submenu 'Advanced options for previous system' $menuentry_id_option "
        "'osprober-gnulinux-advanced-OLD-1111' {\n"
        " menuentry 'Recovery' $menuentry_id_option 'osprober-gnulinux-recovery-OLD-1111' {\n"
        "  linux /vmlinuz root=UUID=OLD-1111 single\n"
        " }\n}\n")
    allowed = {"osprober_entry": {"OLD-1111"}}
    assert not errors(verify_transformations(root, {"new-root"}, {"OLD-1111"}, allowed))
    approved = grub.read_text()
    grub.write_text(approved + "linux /vmlinuz root=UUID=OLD-1111\n")
    assert errors(verify_transformations(root, {"new-root"}, {"OLD-1111"}, allowed))
    grub.write_text(approved.replace("osprober-gnulinux-simple-OLD-1111",
                                     "osprober-gnulinux-simple-OTHER"))
    assert errors(verify_transformations(root, {"new-root"}, {"OLD-1111"}, allowed))


def test_expected_old_menu_entry_must_exist(tmp_path):
    root = tmp_path / "root"
    (root / "etc/default").mkdir(parents=True)
    (root / "boot/grub").mkdir(parents=True)
    (root / "etc/fstab").write_text("UUID=new-root / ext4 defaults 0 1\n")
    (root / "etc/default/grub").write_text("GRUB_CMDLINE_LINUX=''\n")
    (root / "boot/grub/grub.cfg").write_text("menuentry 'New system' {}\n")
    assert any("old-system menu entry" in f.detail for f in errors(
        verify_transformations(root, {"new-root"}, {"OLD-1111"},
                               {"old_entry": {"OLD-1111"}})))


def test_reused_esp_old_menu_uses_esp_uuid_not_old_root_uuid(tmp_path):
    root = tmp_path / "root"
    (root / "etc/grub.d").mkdir(parents=True)
    (root / "etc/default").mkdir(parents=True)
    (root / "boot/grub").mkdir(parents=True)
    (root / "etc/fstab").write_text("UUID=NEW-ROOT / ext4 defaults 0 1\n")
    (root / "etc/default/grub").write_text("GRUB_CMDLINE_LINUX=''\n")
    menu = ("menuentry 'Previous system' --id=distromove-old {\n"
            "    search --no-floppy --fs-uuid --set=root DE73-523D\n"
            "    chainloader /EFI/SysLinuxOS/shimx64.efi\n"
            "}\n")
    script = "#!/bin/sh\n# DistroMove old-system entry\nexec tail -n +4 \"$0\"\n" + menu
    (root / "etc/grub.d/40_distromove_old").write_text(script)
    grub = root / "boot/grub/grub.cfg"
    grub.write_text("menuentry 'New system' --id=new-root {\n}\n" + menu)
    roles = {"old_entry": set(), "osprober_entry": {"OLD-ROOT"}}

    assert not errors(verify_transformations(
        root, {"NEW-ROOT"}, {"OLD-ROOT", "OLD-LUKS"}, roles,
        expected_old_script=script))

    grub.write_text("menuentry 'New system' --id=new-root {\n}\n")
    assert any("old-system menu entry is absent" in f.detail for f in errors(
        verify_transformations(root, {"NEW-ROOT"}, {"OLD-ROOT", "OLD-LUKS"}, roles,
                               expected_old_script=script)))

    grub.write_text("menuentry 'New system' --id=new-root {\n}\n" + menu)
    (root / "etc/grub.d/40_distromove_old").write_text(script.replace(
        "SysLinuxOS/shimx64.efi", "other/grubx64.efi"))
    assert any("old-system entry differs" in f.detail for f in errors(
        verify_transformations(root, {"NEW-ROOT"}, {"OLD-ROOT", "OLD-LUKS"}, roles,
                               expected_old_script=script)))


class ArchiveRunner:
    def __init__(self, listings):
        self.listings = listings
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, self.listings.get(Path(argv[-1]).name, ""), "")


def kernel_tree(root):
    (root / "boot").mkdir(parents=True)
    (root / "etc/initramfs-tools/hooks").mkdir(parents=True)
    (root / "etc/crypttab").write_text("root UUID=new-luks none luks\n")
    for version in ("1", "2"):
        (root / "boot" / f"vmlinuz-{version}").write_bytes(b"kernel")
        (root / "boot" / f"initrd.img-{version}").write_bytes(b"initrd")


def test_initramfs_without_keyfile_error(tmp_path):
    root = tmp_path / "root"
    kernel_tree(root)
    (root / "etc/initramfs-tools/hooks/distromove-crypt").write_text(
        "copy_file config /etc/root.key /etc/root.key\n")
    listing = "lib/modules/1/kernel/ext4.ko\netc/crypttab\n"
    r = ArchiveRunner({"initrd.img-1": listing,
                       "initrd.img-2": listing.replace("/1/", "/2/")})
    assert any("keyfile" in f.detail for f in errors(check_initramfs(r, root, True)))


def test_explicit_keyfile_requirement_catches_missing_hook(tmp_path):
    root = tmp_path / "root"
    kernel_tree(root)
    r = ArchiveRunner({"initrd.img-1": "lib/modules/1/kernel/ext4.ko\netc/crypttab\n",
                       "initrd.img-2": "lib/modules/2/kernel/ext4.ko\netc/crypttab\n"})
    assert any("keyfile" in f.detail for f in errors(
        check_initramfs(r, root, True, {"/etc/root.key"})))


def test_second_kernel_without_modules_error(tmp_path):
    root = tmp_path / "root"
    kernel_tree(root)
    r = ArchiveRunner({"initrd.img-1": "lib/modules/1/kernel/ext4.ko\netc/crypttab\n",
                       "initrd.img-2": "etc/crypttab\n"})
    assert any("2" in f.detail and "modules" in f.detail
               for f in errors(check_initramfs(r, root, True)))


def test_unlock_failure_error():
    class CryptRunner:
        def run(self, argv, **kwargs):
            assert kwargs["secret_input"] and kwargs["input"] == b"passphrase"
            return subprocess.CompletedProcess(argv, 2, "", "failed")
    assert errors(check_unlock(CryptRunner(), ["/dev/vdb2"],
                               {"/dev/vdb2": b"passphrase"}))
    assert errors(check_unlock(CryptRunner(), [], {}))


def test_every_unlock_credential_is_checked():
    class CryptRunner:
        def __init__(self):
            self.keys = []

        def run(self, argv, **kwargs):
            self.keys.append(kwargs["input"])
            return subprocess.CompletedProcess(argv, 0 if kwargs["input"] == b"first"
                                               else 2, "", "")
    runner = CryptRunner()
    findings = check_unlock(runner, ["/dev/vdb2"],
                            {"/dev/vdb2": [b"first", b"second"]})
    assert runner.keys == [b"first", b"second"]
    assert any("credential 2" in f.detail for f in errors(findings))


def test_identity_mismatch_error():
    assert errors(check_identities({"/": "old-root"}, {"/": "new-root"}))


def test_esp_missing_loader_error(tmp_path):
    (tmp_path / "EFI/debian-moved").mkdir(parents=True)
    assert errors(check_esp(tmp_path, "debian-moved"))


def test_esp_unsigned_loader_does_not_need_shim_config(tmp_path):
    folder = tmp_path / "EFI/debian-moved"
    folder.mkdir(parents=True)
    (folder / "grubx64.efi").write_bytes(b"GRUB")
    assert check_esp(tmp_path, "debian-moved") == []


def test_report_not_ok_on_error():
    report = VerifyReport([Finding("error", "copy", "missing")])
    assert not report.ok
    assert VerifyReport([Finding("warning", "copy", "sampled")]).ok


def test_ext4_manifest_built_from_frozen_state_not_live_source(tmp_path):
    src, dst = tree(tmp_path)
    frozen = build_manifest(src, kind="ext4-frozen", sample=0)
    (src / "etc/fstab").write_text("UUID=live-now / ext4 defaults 0 1\n")
    assert verify_copy(frozen, dst, set()) == []
    assert errors(verify_copy(frozen, src, set()))
