"""Child process of the integration tests: runs the real engine, or the real deletion, on
loop devices, and can be killed by SIGKILL at a chosen point.

Usage: engine_child.py migrate|delete SPEC.json

Kill points (``spec["kill"]``):
  {"after_records": N}  right after the N-th durable journal record
  {"step": "copy"}      on entering that engine step
  {"freeze": true}      inside the freeze window, after the source is frozen
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import sys
import time
from types import SimpleNamespace

from distromove import copy_ext4 as copy_mod
from distromove import journal as journal_mod
from distromove.cleanup import delete_old_system
from distromove.copy_ext4 import CopyPair, copy_ext4
from distromove.disk import (CryptoPlan, DestinationMount, create_partitions, luks_format,
                             luks_open, make_fs, mount_destination)
from distromove.engine import Secrets, run_migration
from distromove.esp import register_new_entry
from distromove.journal import AlreadyRunning, Journal, Lock
from distromove.layout import (EspChoice, MigrationPlan, Partplan, assert_tables_unchanged)
from distromove.model import Keyslot, LuksInfo, PlannedIdentity, VolumeIdentity
from distromove.runner import Runner
from distromove.safety import confirmation_text
from distromove.state import MigrationState, load_state
from distromove.verify import VerifyReport, verify_copy

from loopkit import identity_from_node, loop_snapshot

STEPS = ("preflight", "create_storage", "copy", "make_swaps", "configure", "install_boot",
         "verify", "release_snapshots", "pending_state", "register", "close")


def die() -> None:
    os.kill(os.getpid(), signal.SIGKILL)


def install_record_counter(spec: dict) -> dict:
    counter = {"records": 0}
    original = journal_mod.append_durable
    limit = (spec.get("kill") or {}).get("after_records")

    def counting(path, data):
        original(path, data)
        counter["records"] += 1
        if limit is not None and counter["records"] >= limit:
            die()

    journal_mod.append_durable = counting
    return counter


class LoopBackend:
    """Real storage, copy, journal and firmware operations; boot-image steps are no-ops
    because a loop device holds no installed system."""

    def __init__(self, spec: dict):
        self.s = spec
        self.staging = Path(spec["staging"])
        self.freeze = None
        self.device = None
        self.created = None
        self.entry_loader = f"\\EFI\\{spec['new_loader_id']}\\grubx64.efi"
        kill = spec.get("kill") or {}
        self.kill_step = kill.get("step")
        if kill.get("freeze"):
            def killed_in_window(*args, **kwargs):
                die()
            copy_mod.final_pass = killed_in_window

    # --- engine protocol
    @property
    def new_root(self) -> Path:
        return self.staging

    def _enter(self, name: str) -> None:
        if self.kill_step == name:
            die()

    def preflight(self, plan, source, r, journal):
        self._enter("preflight")
        assert_tables_unchanged(r, plan)

    def initialise_tables(self, plan, r, journal):
        return plan

    def create_storage(self, plan, source, secrets, r, journal):
        self._enter("create_storage")
        self.created = create_partitions(r, plan, journal)
        part = self.created["root"]
        device = part.path
        if self.s["luks"]:
            luks = LuksInfo(2, "aes-xts-plain64", 512, 512, [Keyslot(0, "pbkdf2", "")],
                            part.luks_uuid, None)
            crypto = CryptoPlan({"root": [Keyslot(0, "pbkdf2", "")]}, {}, {"root": False}, {},
                                {"root": luks})
            luks_format(r, self.created, crypto, "root", secrets.new_passphrase, journal)
            device = luks_open(r, part, secrets.new_passphrase, journal)
        make_fs(r, device, "ext4", part.fs_uuid, journal)
        mount_destination(r, [DestinationMount(device, "ext4", "/", part.fs_uuid)], {},
                          self.staging, journal)
        self.device = device

    def copy(self, source, r, journal):
        self._enter("copy")
        if self.s.get("sleep_before_copy"):
            time.sleep(self.s["sleep_before_copy"])
        src = Path(self.s["src_mount"])
        pair = CopyPair(src, self.staging, src, self.created["root"].fs_uuid, ())
        self.freeze = copy_ext4(r, [pair], journal, threshold_s=self.s.get("threshold", 20.0))
        return self.freeze

    def make_swaps(self, source, secrets, r, journal):
        self._enter("make_swaps")

    def configure(self, source, r, journal):
        self._enter("configure")

    def install_boot(self, source, r, journal):
        self._enter("install_boot")

    def verify(self, source, secrets, r):
        self._enter("verify")
        return VerifyReport(verify_copy(self.freeze.manifest, self.staging, set()))

    def release_snapshots(self, r, journal):
        self._enter("release_snapshots")

    def pending_state(self, source, journal):
        self._enter("pending_state")
        s = self.s
        old_root = VolumeIdentity(**s["old_root"])
        old_esp = VolumeIdentity(**s["old_esp"])
        part = self.created["root"]
        new_root = identity_from_node(part.path, "root", "root", by_id=s.get("dst_by_id"),
                                      luks_uuid=part.luks_uuid, fs_uuid=part.fs_uuid)
        return MigrationState(1, journal.migration_id, "PENDING_ACTIVATION", part.fs_uuid,
                              [old_root], [new_root], old_esp, old_esp,
                              s["new_loader_id"], s["old_loader_id"], None, True, [])

    def register(self, r, journal):
        self._enter("register")
        esp = self.s["esp"]
        return register_new_entry(r, esp["disk"], esp["part_no"], self.entry_loader,
                                  self.s["new_loader_id"], journal)

    def registration_details(self):
        esp = self.s["esp"]
        return esp["disk"], esp["part_no"], self.entry_loader, self.s["new_loader_id"]

    def _release(self, r, journal):
        part = self.created["root"]
        if os.path.ismount(self.staging):
            op = journal.intend("unmount_destination", {"fs_uuid": part.fs_uuid},
                                path=str(self.staging))
            r.run(["umount", str(self.staging)])
            journal.done(op, "unmounted")
        if self.s["luks"]:
            name = f"distromove-{journal.migration_id}-root"
            if os.path.exists(f"/dev/mapper/{name}"):
                op = journal.intend("close_mapper", {"luks_uuid": part.luks_uuid},
                                    mapper_name=name)
                r.run(["cryptsetup", "close", name])
                journal.done(op, "closed")

    def close(self, r, journal):
        self._enter("close")
        self._release(r, journal)

    def unwind(self, r, journal):
        if self.created is not None:
            self._release(r, journal)


def load_plan(spec: dict) -> MigrationPlan:
    parts = [Partplan(p["disk"], p["start"], p["size"], p["role"],
                      PlannedIdentity(p["partuuid"], p["luks_uuid"], p["fs_uuid"]),
                      p["volume_id"], 512) for p in spec["partitions"]]
    return MigrationPlan([], EspChoice("reuse", spec["esp"]["disk"], 0), parts, [],
                         dict(spec["approved_tables"]), [])


def migrate(spec: dict) -> dict:
    counter = install_record_counter(spec)
    r = Runner()
    # Like the privileged helper: the instance lock first, the journal only after it.
    lock = Lock(spec["lock"])
    try:
        lock.__enter__()
    except AlreadyRunning:
        return {"ok": False, "phase": "lock", "warnings": ["AlreadyRunning"], "records": 0}
    try:
        journal = Journal(spec["journal_dir"], spec["migration_id"],
                          host_root_uuid=spec["host_root_uuid"])
        events = open(spec["events"], "a", buffering=1) if spec.get("events") else None

        def emit(event: dict) -> None:
            if events:
                events.write(json.dumps(event) + "\n")

        result = run_migration(load_plan(spec), SimpleNamespace(),
                               Secrets(spec["passphrase"].encode()), r, emit, journal, lock,
                               backend=LoopBackend(spec))
    finally:
        lock.__exit__(None, None, None)
    return {"ok": result.ok, "phase": result.phase, "bootnum": result.new_bootnum,
            "warnings": result.warnings, "records": counter["records"],
            "freeze_seconds": result.freeze.seconds if result.freeze else None}


def delete(spec: dict) -> dict:
    counter = install_record_counter(spec)
    r = Runner()
    live = spec["live"]
    state_root = Path(spec["state_root"])
    state = load_state(state_root, live["running_root_uuid"])
    journal = Journal(spec["journal_dir"], spec["migration_id"],
                      host_root_uuid=live["running_root_uuid"])
    done = delete_old_system(
        r, state, erase_luks_header=False, delete_old_esp=False, journal=journal,
        recheck=lambda: loop_snapshot(live), state_root=state_root,
        confirmation=confirmation_text(state), lock_path=Path(spec["lock"]))
    return {"ok": True, "phase": done.phase, "records": counter["records"]}


def main() -> int:
    mode, path = sys.argv[1], sys.argv[2]
    spec = json.loads(Path(path).read_text())
    outcome = {"migrate": migrate, "delete": delete}[mode](spec)
    print(json.dumps(outcome))
    return 0


if __name__ == "__main__":
    sys.exit(main())
