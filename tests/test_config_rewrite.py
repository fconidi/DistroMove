"""Configuration changes applied to the copied system."""

from pathlib import Path

import pytest

from distromove.model import UuidMap
from distromove.config_rewrite import (
    ResumeTarget,
    find_old_uuids,
    rewrite_crypttab,
    rewrite_fstab,
    rewrite_resume,
    rewrite_rootflags,
)


def mapping(**changes):
    values = dict(fs={}, luks={}, partuuid={}, mapper={}, subvolid={}, swap_uuid={})
    values.update(changes)
    return UuidMap(**values)


def test_fstab_uuid_replaced_comments_kept():
    original = "# UUID=old-root remains a comment\nUUID=old-root  /  ext4  defaults  0  1 # root\n"
    assert rewrite_fstab(original, mapping(fs={"old-root": "new-root"})) == (
        "# UUID=old-root remains a comment\nUUID=new-root  /  ext4  defaults  0  1 # root\n"
    )


def test_subvolid_mapped_per_filesystem_same_id_two_fs():
    original = ("UUID=old-root / btrfs subvolid=256,compress=zstd 0 0\n"
                "UUID=old-home /home btrfs compress=zstd,subvolid=256 0 0\n")
    result = rewrite_fstab(original, mapping(
        fs={"old-root": "new-root", "old-home": "new-home"},
        subvolid={"old-root": {256: 300}, "old-home": {256: 400}},
    ))
    assert result == ("UUID=new-root / btrfs subvolid=300,compress=zstd 0 0\n"
                      "UUID=new-home /home btrfs compress=zstd,subvolid=400 0 0\n")


def test_encrypted_btrfs_subvolid_ambiguity_is_rejected():
    with pytest.raises(ValueError, match="filesystem"):
        rewrite_fstab(
            "/dev/mapper/old-root / btrfs subvolid=256 0 0\n",
            mapping(mapper={"old-root": "new-root"},
                    subvolid={"old-root-fs": {256: 300}, "old-home-fs": {256: 400}}),
        )


def test_encrypted_btrfs_subvolid_uses_mount_to_filesystem_map():
    original = ("/dev/mapper/old-root / btrfs subvolid=256 0 0\n"
                "/dev/mapper/old-home /home btrfs subvolid=256 0 0\n")
    result = rewrite_fstab(
        original,
        mapping(mapper={"old-root": "new-root", "old-home": "new-home"},
                subvolid={"old-root-fs": {256: 300}, "old-home-fs": {256: 400}}),
        filesystem_by_mount={"/": "old-root-fs", "/home": "old-home-fs"},
    )
    assert result == ("/dev/mapper/new-root / btrfs subvolid=300 0 0\n"
                      "/dev/mapper/new-home /home btrfs subvolid=400 0 0\n")


def test_fstab_mount_uuid_map_mismatch_rejected():
    with pytest.raises(ValueError, match="disagrees"):
        rewrite_fstab(
            "UUID=old-root / btrfs subvolid=256 0 0\n",
            mapping(fs={"old-root": "new-root"}, subvolid={"old-root": {256: 300}}),
            filesystem_by_mount={"/": "different-root"},
        )


def test_old_swap_replaced():
    original = "UUID=old-swap none swap sw 0 0\nPARTUUID=old-part none swap defaults 0 0\n"
    result = rewrite_fstab(original, mapping(
        swap_uuid={"old-swap": "new-swap"}, partuuid={"old-part": "new-part"},
    ))
    assert result == "UUID=new-swap none swap sw 0 0\nPARTUUID=new-part none swap defaults 0 0\n"


def test_mapper_path_and_unmapped_data_mount():
    original = ("/dev/mapper/old-root / btrfs defaults 0 0\n"
                "UUID=data /srv/data ext4 nofail 0 2\n")
    assert rewrite_fstab(original, mapping(mapper={"old-root": "new-root"})) == (
        "/dev/mapper/new-root / btrfs defaults 0 0\n"
        "UUID=data /srv/data ext4 nofail 0 2\n"
    )


def test_crypttab_new_uuid_keyfile_swap_lines():
    original = ("root_crypt UUID=old-luks /etc/keyfile luks,discard\n"
                "cswap PARTUUID=old-part /dev/urandom swap,cipher=aes-xts-plain64\n")
    result = rewrite_crypttab(original, mapping(
        luks={"old-luks": "new-luks"}, partuuid={"old-part": "new-part"},
        mapper={"root_crypt": "new_root_crypt", "cswap": "new_cswap"},
    ))
    assert result == ("new_root_crypt UUID=new-luks /etc/keyfile luks,discard\n"
                      "new_cswap PARTUUID=new-part /dev/urandom swap,cipher=aes-xts-plain64\n")


def test_resume_file_uses_containing_device_and_offset():
    conf, grub = rewrite_resume(
        "RESUME=UUID=old\nRESUME_OFFSET=10\n",
        'GRUB_CMDLINE_LINUX_DEFAULT="quiet resume=UUID=old resume_offset=10"\n',
        ResumeTarget("new-container", 8192),
    )
    assert conf == "RESUME=UUID=new-container\nRESUME_OFFSET=8192\n"
    assert grub == 'GRUB_CMDLINE_LINUX_DEFAULT="quiet resume=UUID=new-container resume_offset=8192"\n'


def test_resume_partition_uses_swap_uuid():
    conf, grub = rewrite_resume(
        "RESUME=UUID=old\nRESUME_OFFSET=10\n",
        'GRUB_CMDLINE_LINUX_DEFAULT="quiet resume=UUID=old resume_offset=10"\n',
        ResumeTarget("new-swap", None),
    )
    assert conf == "RESUME=UUID=new-swap\n"
    assert grub == 'GRUB_CMDLINE_LINUX_DEFAULT="quiet resume=UUID=new-swap"\n'


def test_resume_preserves_unrelated_grub_spacing_and_comments():
    grub = ('# GRUB_CMDLINE_LINUX_DEFAULT="resume=UUID=old"\n'
            'GRUB_CMDLINE_LINUX="quiet  splash"\n'
            'GRUB_CMDLINE_LINUX_DEFAULT="quiet  resume=UUID=old  splash"\n')
    conf, new_grub = rewrite_resume("# RESUME=UUID=old\n", grub, ResumeTarget("new", None))
    assert conf == "# RESUME=UUID=old\nRESUME=UUID=new\n"
    assert new_grub == ('# GRUB_CMDLINE_LINUX_DEFAULT="resume=UUID=old"\n'
                        'GRUB_CMDLINE_LINUX="quiet  splash"\n'
                        'GRUB_CMDLINE_LINUX_DEFAULT="quiet  resume=UUID=new  splash"\n')


def test_resume_none_disables_old_target():
    conf, grub = rewrite_resume(
        "RESUME=UUID=old\nRESUME_OFFSET=24\n",
        'GRUB_CMDLINE_LINUX_DEFAULT="quiet resume=UUID=old resume_offset=24"\n',
        None,
    )
    assert conf == "RESUME=none\n"
    assert grub == 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"\n'


def test_resume_added_when_default_grub_line_absent():
    conf, grub = rewrite_resume("", "GRUB_TIMEOUT=5\n", ResumeTarget("new-swap", None))
    assert conf == "RESUME=UUID=new-swap\n"
    assert grub == 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX_DEFAULT="resume=UUID=new-swap"\n'


def test_rootflags_mapped():
    grub = 'GRUB_CMDLINE_LINUX="root=UUID=old-root rootflags=subvolid=256,compress=zstd"\n'
    assert rewrite_rootflags(grub, mapping(
        fs={"old-root": "new-root"}, subvolid={"old-root": {256: 300}},
    )) == 'GRUB_CMDLINE_LINUX="root=UUID=new-root rootflags=subvolid=300,compress=zstd"\n'


def test_rootflags_explicit_root_uuid_disambiguates_two_filesystems():
    grub = 'GRUB_CMDLINE_LINUX="quiet rootflags=subvolid=256"\n'
    assert rewrite_rootflags(grub, mapping(
        subvolid={"old-root": {256: 300}, "old-home": {256: 400}},
    ), root_fs_uuid="old-root") == 'GRUB_CMDLINE_LINUX="quiet rootflags=subvolid=300"\n'


def test_find_old_uuids_ignores_allowed_role():
    texts = {"fstab": "UUID=old", "grub-old-entry": "search --fs-uuid old"}
    assert find_old_uuids(texts, ["old"], {"grub-old-entry": {"old"}}) == [("fstab", "old")]


def test_find_old_uuids_reports_leftover():
    assert find_old_uuids({"fstab": "UUID=old-root\n"}, ["old-root"], {}) == [
        ("fstab", "old-root")
    ]


def test_find_old_uuids_skips_comments_and_substrings():
    assert find_old_uuids({"fstab": "# UUID=old\nUUID=old-extra /srv ext4 defaults 0 2\n"},
                          ["old"], {}) == []


def test_find_old_uuids_detects_mapper_and_generator_in_every_file():
    old = (value for value in ["1234-abcd"])
    assert find_old_uuids({
        "fstab": "UUID=1234-abcd / ext4 defaults 0 1\n",
        "crypttab": "luks-1234-abcd UUID=1234-abcd none luks\n",
    }, old, {}) == [("fstab", "1234-abcd"), ("crypttab", "1234-abcd")]


def test_unknown_line_untouched():
    original = "# crypttab note\nother /dev/sdb3 none noauto\n"
    assert rewrite_crypttab(original, mapping()) == original
    assert rewrite_fstab("# note\n/dev/sr0 /media/cdrom udf noauto 0 0\n", mapping()) == (
        "# note\n/dev/sr0 /media/cdrom udf noauto 0 0\n"
    )


def test_syslinuxos_fixture_preserves_foreign_mount_and_crypttab_keys():
    fixture = Path(__file__).parent / "fixtures" / "syslinuxos"
    fstab = (fixture / "fstab").read_text()
    crypttab = (fixture / "crypttab").read_text()
    luks_root = "5f3e2d1c-0b9a-4876-a543-210fedcba987"
    luks_home = "6b5a4f3e-2d1c-4b0a-9f8e-7d6c5b4a3f2e"
    luks_swap = "7c6b5a4f-3e2d-4c1b-a0f9-8e7d6c5b4a3f"
    m = mapping(
        luks={luks_root: "new-luks-root", luks_home: "new-luks-home",
              luks_swap: "new-luks-swap"},
        mapper={"luks-" + luks_root: "new-root", "luks-" + luks_home: "new-home",
                "luks-" + luks_swap: "new-swap", "cswap2": "new-cswap"},
        partuuid={"4d5e6f7a-8b9c-4d3e-9f4a-5b6c7d8e9fa0": "new-random-swap"},
    )
    new_fstab = rewrite_fstab(fstab, m)
    new_crypttab = rewrite_crypttab(crypttab, m)
    assert "/dev/mapper/new-root /" in new_fstab
    assert "/dev/mapper/new-home " in new_fstab
    assert "UUID=c9d8e7f6-a5b4-4c3d-9e2f-1a0b9c8d7e6f /mnt/backup" in new_fstab
    assert "new-cswap UUID=" not in new_crypttab
    assert "new-cswap PARTUUID=new-random-swap /dev/urandom swap,cipher=" in new_crypttab
    assert "new-root UUID=new-luks-root /crypto_keyfile.bin luks,discard" in new_crypttab


def test_ambiguous_rootflags_rejected():
    with pytest.raises(ValueError, match="root filesystem"):
        rewrite_rootflags(
            'GRUB_CMDLINE_LINUX="rootflags=subvolid=256"\n',
            mapping(subvolid={"old-root": {256: 300}, "old-home": {256: 400}}),
        )
