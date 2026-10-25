"""Two-level verification against stable references and copied-system state."""
from pathlib import Path
import os
import shutil
import subprocess

from distromove.manifest import build_manifest
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
    grub.write_text("menuentry 'Previous system' --id=osprober-efi-123 {\n"
                    " search --fs-uuid --set=root OLD-1111\n}\n")
    assert not errors(verify_transformations(root, {"new-root"}, {"OLD-1111"},
                                             {"old_entry": {"OLD-1111"}}))
    grub.write_text(grub.read_text() + "linux /vmlinuz root=UUID=OLD-1111\n")
    assert errors(verify_transformations(root, {"new-root"}, {"OLD-1111"},
                                         {"old_entry": {"OLD-1111"}}))


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
