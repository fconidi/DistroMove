from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from distromove.engine import (MigrationContext, Secrets, SystemBackend,
                               reconcile_on_start, rollback_destination, run_migration)
from distromove.esp import BootState
from distromove.journal import Journal, Lock
from distromove.layout import EspChoice, MigrationPlan
from distromove.model import VolumeIdentity
from distromove.model import SnapshotRef, Subvol
from distromove.state import MigrationState, load_state
from distromove.verify import Finding, VerifyReport


def identity(role, suffix, fs_uuid):
    return VolumeIdentity(role, role, "wwn-test", None, None,
                          f"part-{suffix}", 2048, 4096, None, fs_uuid)


class Backend:
    def __init__(self, root, fail=None, verified=True):
        self.root = root
        self.root.mkdir()
        self.calls = []
        self.fail = fail
        self.verified = verified

    @property
    def new_root(self):
        return self.root

    def step(self, name):
        self.calls.append(name)
        if self.fail == name:
            raise RuntimeError("injected failure")

    def preflight(self, *args): self.step("preflight")
    def initialise_tables(self, plan, *args):
        self.step("init_gpt")
        return replace(plan, init_gpt=[])
    def create_storage(self, *args): self.step("create_storage")
    def copy(self, *args): self.step("copy")
    def make_swaps(self, *args): self.step("make_swaps")
    def configure(self, *args): self.step("configure")
    def install_boot(self, *args): self.step("install_boot")
    def verify(self, *args):
        self.step("verify")
        return VerifyReport([] if self.verified else [Finding("error", "copy", "bad")])
    def release_snapshots(self, *args): self.step("release_snapshots")
    def pending_state(self, source, journal):
        self.step("pending_activation")
        installed = self.root / journal.root.relative_to("/") / journal.path.name
        assert installed.is_file()
        return MigrationState(1, journal.migration_id, "PENDING_ACTIVATION", "new-root",
                              [identity("root", "old", "old-root")],
                              [identity("root", "new", "new-root")],
                              identity("esp", "old-esp", "AAAA-1111"),
                              identity("esp", "new-esp", "BBBB-2222"),
                              "distromove", "old-loader", None, True, [])
    def register(self, *args):
        self.step("register_entry")
        return "0007"
    def registration_details(self): return "/dev/mock", 1, "\\EFI\\distromove\\grubx64.efi", "distromove"
    def close(self, *args): self.step("close")
    def unwind(self, *args): self.step("unwind")


def execute(tmp_path, backend, plan=None):
    journal = Journal(tmp_path / "journal", "test-engine", host_root_uuid="old-root")
    events = []
    plan = plan or MigrationPlan([], EspChoice("reuse", "/dev/mock", 0), [], [])
    result = run_migration(plan, object(), Secrets(b"secret"), object(),
                           events.append, journal, Lock(tmp_path / "lock"), backend=backend)
    return result, events, journal


def test_order_and_durable_activation(tmp_path):
    backend = Backend(tmp_path / "new")
    result, events, journal = execute(tmp_path, backend)
    assert result.ok and result.new_bootnum == "0007"
    assert backend.calls == ["preflight", "create_storage", "copy", "make_swaps",
                             "configure", "install_boot", "verify", "release_snapshots",
                             "pending_activation", "register_entry", "close"]
    assert [e["phase"] for e in events] == ["preflight", "create_storage", "copy",
        "make_swaps", "configure", "install_boot", "verify", "release_snapshots",
        "install_journal", "pending_activation", "register_entry", "activated"]
    state = load_state(backend.new_root, "new-root")
    assert state.phase == "ACTIVATED" and state.uefi_entry == "0007"
    assert not journal.is_current()


def test_vanished_hot_pass_emits_event_after_copy_completes(tmp_path):
    class VanishedBackend(Backend):
        def copy(self, *args):
            super().copy(*args)
            return SimpleNamespace(seconds=0.5, vanished_hot_passes=1)

    result, events, _ = execute(tmp_path, VanishedBackend(tmp_path / "new"))
    assert result.ok
    assert {"phase": "copy_hot_vanished", "passes": 1} in events


@pytest.mark.parametrize("step", ["preflight", "create_storage", "copy", "make_swaps",
    "configure", "install_boot", "verify", "release_snapshots", "pending_activation"])
def test_pre_pending_failure_unwinds_without_firmware(tmp_path, step):
    backend = Backend(tmp_path / "new", fail=step)
    result, events, journal = execute(tmp_path, backend)
    assert not result.ok and "register_entry" not in backend.calls
    assert "unwind" in backend.calls
    assert events[-1]["phase"] == "error"
    assert "secret" not in str(events)


def test_verify_failure_stops_before_pending(tmp_path):
    backend = Backend(tmp_path / "new", verified=False)
    result, events, journal = execute(tmp_path, backend)
    assert not result.ok and result.verify and not result.verify.ok
    assert "pending_activation" not in backend.calls
    assert "register_entry" not in backend.calls
    assert {"phase": "verify_findings", "findings": [
        {"severity": "error", "check": "copy", "detail": "bad"}]} in events


def test_registration_failure_keeps_pending_state(tmp_path):
    backend = Backend(tmp_path / "new", fail="register_entry")
    result, events, journal = execute(tmp_path, backend)
    assert result.phase == "pending_reconciliation"
    assert "unwind" not in backend.calls
    assert load_state(backend.new_root, "new-root").phase == "PENDING_ACTIVATION"
    assert journal.is_current()


def test_second_instance_is_refused_without_unwind(tmp_path):
    backend = Backend(tmp_path / "new")
    lock = Lock(tmp_path / "lock")
    journal = Journal(tmp_path / "journal", "test-engine", host_root_uuid="old-root")
    with lock:
        result = run_migration(object(), object(), Secrets(), object(), lambda event: None,
                               journal, Lock(tmp_path / "lock"), backend=backend)
    assert not result.ok and backend.calls == []


def test_preheld_lock_stays_held_through_migration(tmp_path):
    backend = Backend(tmp_path / "new")
    lock = Lock(tmp_path / "lock")
    journal = Journal(tmp_path / "journal", "test-preheld", host_root_uuid="old-root")
    with lock:
        result = run_migration(MigrationPlan([], EspChoice("reuse", "/dev/mock", 0), [], []),
                               object(), Secrets(), object(), lambda event: None,
                               journal, lock, backend=backend)
        assert result.ok
        assert lock._fd is not None
    assert lock._fd is None


def test_gpt_initialisation_only_when_planned(tmp_path):
    backend = Backend(tmp_path / "new")
    plan = MigrationPlan([], EspChoice("reuse", "/dev/mock", 0), [], [],
                         init_gpt=[object()])
    result, events, _ = execute(tmp_path, backend, plan)
    assert result.ok
    assert backend.calls[:3] == ["preflight", "init_gpt", "create_storage"]
    assert [e["phase"] for e in events].count("init_gpt") == 1


def test_partial_firmware_entry_is_reconciled(tmp_path, monkeypatch):
    import distromove.engine as engine
    backend = Backend(tmp_path / "new", fail="register_entry")
    result, events, journal = execute(tmp_path, backend)
    assert result.phase == "pending_reconciliation"
    monkeypatch.setattr(engine, "collect_snapshot", lambda r: type("Live", (),
                        {"running_root_uuid": "old-root"})())
    monkeypatch.setattr(engine, "_partuuid", lambda r, disk, number: "part-new-esp")
    monkeypatch.setattr(engine, "loader_of", lambda line:
                        ("part-new-esp", "\\EFI\\distromove\\grubx64.efi"))
    monkeypatch.setattr(engine, "_state", lambda r: BootState(("0007",),
                        {"0007": "Boot0007* distromove HD(1,GPT,part-new-esp,0x800,0x1000)"},
                        "0001"))
    actions = reconcile_on_start(object(), journal)
    assert actions[-1].kind == "activated"
    assert load_state(backend.new_root, "new-root").uefi_entry == "0007"
    assert not journal.is_current()


def test_missing_entry_is_retried(tmp_path, monkeypatch):
    import distromove.engine as engine
    backend = Backend(tmp_path / "new", fail="register_entry")
    _, _, journal = execute(tmp_path, backend)
    monkeypatch.setattr(engine, "collect_snapshot", lambda r: type("Live", (),
                        {"running_root_uuid": "old-root"})())
    monkeypatch.setattr(engine, "_partuuid", lambda r, disk, number: "part-new-esp")
    monkeypatch.setattr(engine, "_state", lambda r: BootState((), {}, None))
    called = []
    monkeypatch.setattr(engine, "register_new_entry", lambda *args:
                        called.append(args) or "0008")
    actions = reconcile_on_start(object(), journal)
    assert actions[-1].detail == "0008"
    assert len(called) == 1
    assert load_state(backend.new_root, "new-root").phase == "ACTIVATED"


def test_pending_state_activates_after_booting_new_root(tmp_path, monkeypatch):
    import distromove.engine as engine
    backend = Backend(tmp_path / "new", fail="register_entry")
    _, _, journal = execute(tmp_path, backend)
    # The copied journal belongs to the old root and is not current here.
    (journal.root / "current").unlink()
    monkeypatch.setattr(engine, "collect_snapshot", lambda r: type("Live", (),
                        {"running_root_uuid": "new-root"})())
    monkeypatch.setattr(engine, "_state", lambda r: BootState(("0009",),
                        {"0009": "Boot0009* distromove HD(...)"}, "0009"))
    monkeypatch.setattr(engine, "loader_of", lambda line:
                        ("part-new-esp", "\\EFI\\distromove\\grubx64.efi"))
    actions = reconcile_on_start(object(), journal, state_root=backend.new_root)
    assert actions == [engine.Action("activated", "0009")]
    assert load_state(backend.new_root, "new-root").phase == "ACTIVATED"


def test_pending_unmounted_state_is_never_rolled_back(tmp_path, monkeypatch):
    import distromove.engine as engine
    backend = Backend(tmp_path / "new", fail="register_entry")
    _, _, journal = execute(tmp_path, backend)
    monkeypatch.setattr(engine, "collect_snapshot", lambda r: type("Live", (),
                        {"running_root_uuid": "old-root"})())
    monkeypatch.setattr(engine, "load_state", lambda root, uuid: None)
    monkeypatch.setattr(engine, "rollback_destination", lambda *args:
                        pytest.fail("pending installation must be preserved"))
    actions = reconcile_on_start(object(), journal)
    assert actions[-1].kind == "manual_review"


def test_saved_pending_state_recovers_after_destination_was_unmounted(tmp_path, monkeypatch):
    import distromove.engine as engine
    backend = Backend(tmp_path / "new", fail="register_entry")
    _, _, journal = execute(tmp_path, backend)
    state = load_state(backend.new_root, "new-root")
    live = SimpleNamespace(running_root_uuid="old-root", identities=state.new_volumes,
                           mounts=[], mappers=[])
    monkeypatch.setattr(engine, "collect_snapshot", lambda r: live)
    monkeypatch.setattr(engine, "load_state", lambda root, uuid: None)
    monkeypatch.setattr(engine, "_partuuid", lambda r, disk, number: state.new_esp.partuuid)
    monkeypatch.setattr(engine, "loader_of", lambda line:
                        (state.new_esp.partuuid, "\\EFI\\distromove\\grubx64.efi"))
    monkeypatch.setattr(engine, "_state", lambda r: BootState(("0007",),
                        {"0007": "Boot0007* distromove HD(1,GPT,part-new-esp,0x800,0x1000)"},
                        "0001"))
    monkeypatch.setattr(engine, "_release_journal_resources", lambda *args: live)
    monkeypatch.setattr(engine, "save_state", lambda *args:
                        pytest.fail("an unmounted state root must not be written"))
    actions = reconcile_on_start(object(), journal)
    assert actions[-1] == engine.Action("activated", "0007")
    assert not journal.is_current()


@pytest.mark.parametrize("unsafe", ["changed_identity", "missing_saved_outcome"])
def test_unmounted_pending_state_refuses_unproven_recovery(tmp_path, monkeypatch, unsafe):
    import distromove.engine as engine
    backend = Backend(tmp_path / "new", fail="register_entry")
    _, _, journal = execute(tmp_path, backend)
    state = load_state(backend.new_root, "new-root")
    identities = list(state.new_volumes)
    if unsafe == "changed_identity":
        identities[0] = replace(identities[0], partuuid="replacement")
    else:
        original = engine.read_journal
        monkeypatch.setattr(engine, "read_journal", lambda path: [
            item for item in original(path)
            if not (item["type"] == "outcome" and item["outcome"] == "saved")])
    live = SimpleNamespace(running_root_uuid="old-root", identities=identities,
                           mounts=[], mappers=[])
    monkeypatch.setattr(engine, "collect_snapshot", lambda r: live)
    monkeypatch.setattr(engine, "load_state", lambda root, uuid: None)
    monkeypatch.setattr(engine, "_partuuid", lambda *args:
                        pytest.fail("unproven state must not reach firmware registration"))
    actions = reconcile_on_start(object(), journal)
    assert actions == [engine.Action("manual_review", "pending destination state is not mounted")]
    assert journal.is_current()


def test_table_change_aborts_before_storage_write(tmp_path, monkeypatch):
    import distromove.engine as engine
    staging, scratch = tmp_path / "staging", tmp_path / "scratch"
    staging.mkdir(); scratch.mkdir()
    loader = SimpleNamespace(bootloader_id="old", esp_uuid="AAAA-1111")
    context = MigrationContext(staging, scratch, object(), loader, "new")
    backend = SystemBackend(context)
    source = SimpleNamespace(volumes=[], swaps=[], running_root_uuid="old-root",
                             esp=SimpleNamespace(partition=SimpleNamespace(partuuid="old-esp"),
                                                 mountpoint="/boot/efi"), secure_boot=False)
    plan = MigrationPlan([], EspChoice("reuse", "/dev/mock", 0), [], [])
    monkeypatch.setattr(engine, "check_tools", lambda r: None)
    monkeypatch.setattr(engine, "discover_source", lambda r: source)
    monkeypatch.setattr(engine, "validate_crypto_plan", lambda source, caps: object())
    monkeypatch.setattr(engine, "assert_tables_unchanged", lambda r, p:
                        (_ for _ in ()).throw(ValueError("table changed")))
    journal = Journal(tmp_path / "journal", "table-test", host_root_uuid="old-root")
    with pytest.raises(ValueError, match="table changed"):
        backend.preflight(plan, source, object(), journal)
    assert backend._created == {}


def test_btrfs_snapshot_skip_and_live_branches(tmp_path, monkeypatch):
    import distromove.engine as engine
    staging, scratch = tmp_path / "staging", tmp_path / "scratch"
    staging.mkdir(); scratch.mkdir()
    context = MigrationContext(staging, scratch, object(), object(), "new",
                               btrfs_source_tops={"root": tmp_path / "source-top"})
    backend = SystemBackend(context)
    subvols = [Subvol(256, "@", "/", None, {}, False, False),
               Subvol(257, "@swap", None, None, {}, True, True),
               Subvol(258, "@mixed", None, None, {}, True, False)]
    volume = SimpleNamespace(volume_id="root", fs="btrfs", fs_uuid="old-fs",
                             mountpoint="/", btrfs=SimpleNamespace(subvolumes=subvols))
    source = SimpleNamespace(volumes=[volume], swaps=[SimpleNamespace(kind="file",
                              path="/swapfile")])
    backend._created = {"root": SimpleNamespace(fs_uuid="new-fs")}
    backend._tops = {"root": scratch / "top-root"}
    backend._subvol_maps = {"new-fs": {5: 5, 256: 300, 257: 301, 258: 302}}
    backend._watch = lambda *args: None
    monkeypatch.setattr(engine, "SpaceWatch", lambda *args: object())
    refs = [SnapshotRef("old-fs", ".", "/snapshot/top", "op1"),
            SnapshotRef("old-fs", "@", "/snapshot/root", "op2")]
    calls = []
    monkeypatch.setattr(engine, "take_snapshots", lambda *args, **kwargs:
                        calls.append("snapshot") or refs)
    monkeypatch.setattr(engine, "copy_from_snapshots", lambda *args, **kwargs:
                        calls.append("copy_snapshots"))
    live = SimpleNamespace(fs_uuid="old-fs", subvol_path="@mixed",
                           source=Path("/@mixed"),
                           destination=scratch / "top-root/@mixed", manifest=object())
    monkeypatch.setattr(engine, "copy_live_swap_subvolume", lambda *args, **kwargs:
                        calls.append("copy_live") or live)
    monkeypatch.setattr(engine, "reference_manifests", lambda snaps, lives:
                        {"old-fs:.": object(), "old-fs:@": object(),
                         "old-fs:@mixed": live.manifest})
    backend.copy(source, object(), object())
    assert calls == ["snapshot", "copy_snapshots", "copy_live"]
    assert len(backend._references) == 3


def test_rollback_refuses_partition_still_in_use(tmp_path, monkeypatch):
    import distromove.engine as engine
    journal = Journal(tmp_path / "journal", "rollback-test", host_root_uuid="old-root")
    journal.intend("create_partition", {"partuuid": "planned-part"}, creates="partition")
    live = SimpleNamespace(running_root_uuid="old-root", identities=[
        identity("root", "still-in-use", "old-root")], mounts=[], mappers=[])
    live.identities[0] = replace(live.identities[0], partuuid="planned-part")
    monkeypatch.setattr(engine, "collect_snapshot", lambda r: live)
    monkeypatch.setattr(engine, "discover_source", lambda r: SimpleNamespace(
        volumes=[], esp=SimpleNamespace(mountpoint="/boot/efi")))
    monkeypatch.setattr(engine, "recover", lambda *args: [])
    with pytest.raises(RuntimeError, match="remains in use"):
        rollback_destination(object(), journal)
    assert journal.is_current()


@pytest.mark.parametrize("unreadable", ["", None])
def test_rollback_reports_unreadable_partition_identity_without_mutating(
        tmp_path, monkeypatch, unreadable):
    import distromove.engine as engine
    journal = Journal(tmp_path / "journal", "rollback-test", host_root_uuid="old-root")
    journal.intend("create_partition", {"partuuid": "planned-part"}, creates="partition")
    live = SimpleNamespace(running_root_uuid="old-root", mounts=[], mappers=[], identities=[
        replace(identity("root", "x", "old-root"), partuuid=unreadable)])
    ran = []
    runner = SimpleNamespace(run=lambda argv, **kw: ran.append(argv))
    monkeypatch.setattr(engine, "collect_snapshot", lambda r: live)
    monkeypatch.setattr(engine, "discover_source", lambda r: SimpleNamespace(
        volumes=[], esp=SimpleNamespace(mountpoint="/boot/efi")))
    monkeypatch.setattr(engine, "recover", lambda *args: [SimpleNamespace(
        kind="partition", identity={"partuuid": "planned-part"})])
    actions = reconcile_on_start(runner, journal)
    assert [a.kind for a in actions] == ["manual_review"]
    assert "partition identity unreadable" in actions[0].detail
    assert ran == []
    assert journal.is_current()


def test_rollback_reports_identity_unreadable_after_deleting_the_partition(
        tmp_path, monkeypatch):
    import distromove.engine as engine
    journal = Journal(tmp_path / "journal", "rollback-test", host_root_uuid="old-root")
    journal.intend("create_partition", {"partuuid": "planned-part"}, creates="partition")
    before = SimpleNamespace(running_root_uuid="old-root", mounts=[], mappers=[], identities=[
        replace(identity("root", "x", "old-root"), partuuid="planned-part")])
    after = SimpleNamespace(**{**vars(before), "identities": [
        replace(before.identities[0], partuuid="")]})
    snapshots = iter([before, after, after])
    monkeypatch.setattr(engine, "collect_snapshot", lambda r: next(snapshots))
    monkeypatch.setattr(engine, "discover_source", lambda r: SimpleNamespace(
        volumes=[], esp=SimpleNamespace(mountpoint="/boot/efi")))
    monkeypatch.setattr(engine, "recover", lambda *args: [SimpleNamespace(
        kind="partition", identity={"partuuid": "planned-part"})])
    monkeypatch.setattr(engine, "_locate", lambda *args: ("/dev/loop9", 1, None))
    ran = []
    runner = SimpleNamespace(run=lambda argv, **kw: ran.append(argv))
    with pytest.raises(RuntimeError, match="partition identity unreadable"):
        rollback_destination(runner, journal)
    assert ["udevadm", "settle"] in ran
    assert ran.index(["udevadm", "settle"]) > ran.index(["partprobe", "/dev/loop9"])


def test_efi_mount_is_rewritten_for_copied_chroot(tmp_path, monkeypatch):
    import distromove.engine as engine
    staging, scratch = tmp_path / "staging", tmp_path / "scratch"
    staging.mkdir(); scratch.mkdir()
    backend = SystemBackend(MigrationContext(staging, scratch, object(), object(), "new"))
    backend._created = {"root": SimpleNamespace(fs_uuid="new-root")}
    backend._crypto = SimpleNamespace(keyfiles={}, boot_in_luks={})
    backend._uuid_map = lambda *args: object()
    backend._watch = lambda *args: None
    root = SimpleNamespace(role="root", fs="ext4", volume_id="root",
                           fs_uuid="old-root", mountpoint="/")
    source = SimpleNamespace(volumes=[root], esp=SimpleNamespace(
        mountpoint="/efi", partition=SimpleNamespace(uuid="AAAA-1111")))
    saved = []
    class Chroot:
        def __init__(self, *args): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
    monkeypatch.setattr(engine, "Chroot", Chroot)
    monkeypatch.setattr(engine, "config_read", lambda chroot, path:
                        "UUID=AAAA-1111 /efi vfat defaults 0 1\n")
    monkeypatch.setattr(engine, "config_save", lambda chroot, path, value:
                        saved.append(value))
    monkeypatch.setattr(engine, "apply_configs", lambda *args, **kwargs: None)
    monkeypatch.setattr(engine, "install_crypt_hooks", lambda *args, **kwargs: None)
    monkeypatch.setattr(engine, "rebuild_initramfs", lambda *args, **kwargs: None)
    backend.configure(source, object(), object())
    assert saved == ["UUID=AAAA-1111 /boot/efi vfat defaults 0 1\n"]


def test_firmware_registration_happens_after_durable_pending_state(tmp_path):
    seen = []
    class Observing(Backend):
        def register(self, *args):
            seen.append(load_state(self.root, "new-root").phase)
            return super().register(*args)
    result, _, _ = execute(tmp_path, Observing(tmp_path / "new"))
    assert result.ok and seen == ["PENDING_ACTIVATION"]


def test_secret_is_not_in_events_or_journal(tmp_path):
    backend = Backend(tmp_path / "new", fail="copy")
    result, events, journal = execute(tmp_path, backend)
    assert not result.ok
    assert "secret" not in str(events) + str(result)
    for path in (tmp_path / "journal").rglob("*"):
        if path.is_file():
            assert b"secret" not in path.read_bytes()


def test_low_source_space_releases_snapshots_then_unwinds(tmp_path):
    class LowSpace(Backend):
        def copy(self, *args):
            self.step("copy")
            raise RuntimeError("source space low")
    backend = LowSpace(tmp_path / "new")
    result, events, _ = execute(tmp_path, backend)
    assert not result.ok and result.phase == "copy"
    assert backend.calls[-2:] == ["release_snapshots", "unwind"]
    assert "register_entry" not in backend.calls


@pytest.mark.parametrize("step", ["create_storage", "copy", "configure", "install_boot",
                                  "verify", "pending_activation"])
def test_kill_leaves_journal_for_recovery(tmp_path, monkeypatch, step):
    import distromove.engine as engine
    class Killed(Backend):
        def step(self, name):
            self.calls.append(name)
            if name == step:
                raise KeyboardInterrupt
    backend = Killed(tmp_path / "new")
    with pytest.raises(KeyboardInterrupt):
        execute(tmp_path, backend)
    assert "register_entry" not in backend.calls and "unwind" not in backend.calls
    # The lock is released and the journal stays current for the next start.
    with Lock(tmp_path / "lock"):
        pass
    journal = Journal(tmp_path / "journal", "test-engine", host_root_uuid="old-root")
    assert journal.is_current()
    rolled = []
    monkeypatch.setattr(engine, "collect_snapshot", lambda r: SimpleNamespace(
        running_root_uuid="old-root"))
    monkeypatch.setattr(engine, "open_windows", lambda *args: [])
    monkeypatch.setattr(engine, "rollback_destination", lambda *args: rolled.append(1))
    actions = reconcile_on_start(object(), journal)
    if step == "pending_activation":
        assert rolled == [] or actions
    else:
        assert rolled == [1] and actions[-1].kind == "rolled_back"


class StatRunner:
    """Answers ``stat -f`` for mount points: total and available blocks of 4096 bytes."""

    def __init__(self, filesystems):
        self.filesystems = filesystems

    def run(self, argv, *, readonly=False, **_kwargs):
        import subprocess
        total, avail = self.filesystems[argv[-1]]
        return subprocess.CompletedProcess(argv, 0, f"4096 {total // 4096} {avail // 4096}\n", "")


def test_source_space_is_watched_only_where_snapshots_are_taken():
    import distromove.engine as engine
    from distromove.layout import SourceSpaceLow
    gib = 1024**3
    small_boot = SimpleNamespace(volume_id="boot", mountpoint="/boot", btrfs=None)
    btrfs_root = SimpleNamespace(volume_id="root", mountpoint="/", btrfs=object())
    runner = StatRunner({"/boot": (1 * gib, gib // 2), "/": (20 * gib, 10 * gib)})
    # a 1 GiB /boot has less than the 2 GiB floor free; nothing is snapshotted there
    engine.watch_source_space(runner, SimpleNamespace(volumes=[small_boot, btrfs_root]))
    runner.filesystems["/"] = (20 * gib, gib)
    with pytest.raises(SourceSpaceLow):
        engine.watch_source_space(runner, SimpleNamespace(volumes=[small_boot, btrfs_root]))


def test_volume_prefix_places_a_separate_boot_volume_inside_the_new_root(tmp_path):
    from distromove.engine import _volume_prefix
    assert _volume_prefix(tmp_path, tmp_path) == ""
    assert _volume_prefix(tmp_path, tmp_path / "boot") == "boot"
    assert _volume_prefix(tmp_path, tmp_path / "var/lib.d") == "var/lib.d"
    assert _volume_prefix(tmp_path, Path("/elsewhere/top/@")) == ""


def test_mounted_device_drops_the_btrfs_subvolume_suffix():
    from distromove.engine import _mounted_device
    assert _mounted_device("/dev/vdb1[/@rootfs]") == "/dev/vdb1"
    assert _mounted_device("/dev/mapper/cryptroot[/@rootfs/sub]") == "/dev/mapper/cryptroot"
    assert _mounted_device("/dev/vdb1") == "/dev/vdb1"
    assert _mounted_device("UUID=abcd-1234") == "UUID=abcd-1234"


def test_failed_command_and_exit_code_reach_the_error_event(tmp_path):
    from distromove.engine import error_fields
    from distromove.runner import RunnerError

    failure = RunnerError("command failed (1): sfdisk --append --lock /dev/nvme0n1",
                          ["sfdisk", "--append", "--lock", "/dev/nvme0n1"], 1)
    assert error_fields(failure) == {"error": "RunnerError", "command": "sfdisk",
                                     "exit_code": 1}
    assert error_fields(ValueError("plain")) == {"error": "ValueError"}
