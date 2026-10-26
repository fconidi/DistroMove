"""Fixtures for the loop-device integration tests (root only, opt-in)."""
import os
from pathlib import Path
import shutil
import sys
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

ENABLED = os.environ.get("DISTROMOVE_IT") == "1" and os.geteuid() == 0
BASE_TOOLS = ("losetup", "sfdisk", "sgdisk", "partprobe", "udevadm", "lsblk", "findmnt",
              "blkid", "wipefs", "mkfs.ext4", "mkfs.vfat", "rsync", "cryptsetup", "dmsetup",
              "fsfreeze")


def pytest_collection_modifyitems(config, items):
    if ENABLED:
        return
    skip = pytest.mark.skip(reason="loop-device tests need DISTROMOVE_IT=1 and root")
    for item in items:
        if "integration" in Path(str(item.fspath)).parts:
            item.add_marker(skip)


@pytest.fixture
def env(tmp_path):
    """One isolated LoopEnv; everything it created is released afterwards."""
    from loopkit import LoopEnv

    base = Path(os.environ.get("DISTROMOVE_IT_DIR") or tmp_path).resolve()
    base = base / f"it-{uuid.uuid4().hex[:8]}"
    if str(base).startswith(("/tmp/", "/var/tmp/")):
        pytest.skip("use --basetemp or DISTROMOVE_IT_DIR on a disk-backed directory")
    missing = [tool for tool in BASE_TOOLS if shutil.which(tool) is None]
    if missing:
        pytest.skip("missing tools: " + ", ".join(missing))
    environment = LoopEnv(base)
    yield environment
    errors = environment.close()
    assert not errors, errors


@pytest.fixture
def fw(env):
    from loopkit import Firmware

    return Firmware(env)


@pytest.fixture
def host(monkeypatch):
    """Recovery code reads the host (the 'running system'); the loop volumes are never part
    of it, so source discovery is replaced by a stub that protects nothing."""
    from types import SimpleNamespace

    from distromove import engine

    stub = SimpleNamespace(volumes=[], esp=SimpleNamespace(mountpoint="/boot/efi"))
    monkeypatch.setattr(engine, "discover_source", lambda r, *a, **k: stub)
