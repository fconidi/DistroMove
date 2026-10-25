"""Migration state tests use filesystem trees in the host-local pytest cache."""
from dataclasses import replace
import os
import stat

from distromove.model import VolumeIdentity
from distromove.journal import Journal
from distromove.state import MigrationState, STATE_LINK, archived_states, load_state, save_state


def volume(volume_id, role, partuuid, fs_uuid):
    return VolumeIdentity(volume_id, role, "wwn-disk", "serial-disk", "/dev/disk/by-id/disk",
                          partuuid, 2048, 4096, None, fs_uuid)


def state():
    return MigrationState(1, "migration-1", "ACTIVATED", "new-root",
                          [volume("old-root", "root", "old-part", "old-root")],
                          [volume("new-root", "root", "new-part", "new-root")],
                          volume("old-esp", "esp", "old-esp-part", "OLD-1111"),
                          volume("new-esp", "esp", "new-esp-part", "NEW-2222"),
                          "debian-moved", "debian", "0003", True, [])


def test_state_atomic_mode_600(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    path = save_state(state(), root)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert os.readlink(path.parent / STATE_LINK) == path.name
    assert load_state(root, "new-root") == state()


def test_state_from_other_root_is_archived_not_used(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    save_state(state(), root)
    assert load_state(root, "different-root") is None
    assert archived_states(root, "different-root") == [state()]
    other = replace(state(), migration_id="migration-2")
    current = root / "var/lib/distromove" / STATE_LINK
    current.unlink()
    save_state(other, root)
    assert archived_states(root) == [state()]
    (root / "var/lib/distromove" / STATE_LINK).unlink()
    assert archived_states(root) == [state(), other]


def test_state_link_does_not_replace_current_journal(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    journal = Journal(root / "var/lib/distromove", migration_id="migration-1",
                      host_root_uuid="new-root")
    save_state(state(), root)
    assert journal.is_current()
    assert load_state(root, "new-root") == state()


def test_state_rejects_old_partition_that_is_the_new_root(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    invalid = replace(state(), old_volumes=[replace(state().old_volumes[0],
                                                    partuuid=state().new_volumes[0].partuuid)])
    try:
        save_state(invalid, root)
    except ValueError:
        pass
    else:
        raise AssertionError("overlapping old and new identities accepted")
