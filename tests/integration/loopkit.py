"""Loop-device harness for the integration tests.

Everything here needs root and only ever touches ``/dev/loop*`` devices attached by this
module from image files under a caller-supplied directory.  Resources are released through
an explicit LIFO list of what the harness itself created; nothing is ever unmounted,
closed or deleted unless this module made it.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import random
import re
import stat
import subprocess
import sys
import textwrap
import uuid

from distromove.model import MountInfo, SystemSnapshot, VolumeIdentity
from distromove.runner import Runner

LINUX = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
ESP = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
MIB = 1024 * 1024
SECTOR = 512
PASSPHRASE = b"integration-passphrase"


def run(*argv, input: bytes | None = None, check: bool = True, env: dict | None = None,
        timeout: float = 600) -> str:
    """Run one setup command (not through the product Runner) and return stdout."""
    proc = subprocess.run([str(a) for a in argv], input=input, capture_output=True,
                          env=env, timeout=timeout, stdin=subprocess.DEVNULL if input is None else None)
    if check and proc.returncode:
        raise RuntimeError(f"{' '.join(map(str, argv))} failed ({proc.returncode}): "
                           f"{proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout.decode(errors="replace")


def loop_only(device: str) -> str:
    """Refuse anything that is not a loop device."""
    if not re.fullmatch(r"/dev/loop\d+(p\d+)?", str(device)):
        raise AssertionError(f"not a loop device: {device}")
    return device


# --------------------------------------------------------------------------- environment

class LoopEnv:
    """Disks, mounts and mappers of one test, all released by ``close``."""

    def __init__(self, base: Path):
        self.base = Path(base)
        self.base.mkdir(parents=True, exist_ok=True)
        self.tag = uuid.uuid4().hex[:8]
        self.r = Runner()
        self._undo: list[tuple[str, callable]] = []
        self.mappers: list[str] = []
        self.own_mounts: set[str] = set()

    # ---- bookkeeping
    def on_close(self, label: str, fn) -> None:
        self._undo.append((label, fn))

    def close(self) -> list[str]:
        """Release everything this environment created, newest first; return errors.

        Whatever the code under test left mounted below this environment's directory, or
        open as a mapper carrying this environment's tag, is released last (it can only be
        something the test run itself created); the attempt is reported only when it fails.
        """
        errors = []
        while self._undo:
            label, fn = self._undo.pop()
            try:
                fn()
            except Exception as exc:  # keep releasing the rest
                errors.append(f"{label}: {exc}")
        for leftover in self.leftovers():
            kind, _, name = leftover.partition(" ")
            try:
                if kind == "mount":
                    self.umount(Path(name))
                else:
                    run("cryptsetup", "close", name)
            except Exception as exc:
                errors.append(f"cannot release {leftover}: {exc}")
        for leftover in self.leftovers():
            errors.append(f"left behind: {leftover}")
        return errors

    def stray(self) -> list[str]:
        """Resources below this environment that no harness call created."""
        return [x for x in self.leftovers()
                if not (x.startswith("mount ") and x[6:] in self.own_mounts)]

    def leftovers(self) -> list[str]:
        """Mounts under, and mappers owned by, this environment that are still present."""
        found = []
        base = str(self.base.resolve())
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            target = line.split()[4].replace("\\040", " ")
            if target == base or target.startswith(base + "/"):
                found.append(f"mount {target}")
        found.sort(key=lambda x: -len(x))
        mappers = run("dmsetup", "ls", "--target", "crypt", check=False)
        for name in re.findall(r"^(\S+)\s", mappers, re.M):
            if name.startswith((f"it{self.tag}-", f"distromove-it{self.tag}")):
                found.append(f"mapper {name}")
        return found

    # ---- disks
    def disk(self, name: str, size_mib: int, parts: list[dict] | None = None,
             by_id: bool = False) -> "LoopDisk":
        return LoopDisk(self, name, size_mib, parts or [], by_id)

    # ---- mounts
    def mount(self, device: str, target: Path, *, fstype: str | None = None,
              options: str | None = None) -> Path:
        target = Path(target)
        target.mkdir(parents=True, exist_ok=True)
        argv = ["mount"]
        if fstype:
            argv += ["-t", fstype]
        if options:
            argv += ["-o", options]
        run(*argv, device, target)
        self.own_mounts.add(str(target.resolve()))
        self.on_close(f"umount {target}", lambda t=target: self.umount(t))
        return target

    def umount(self, target: Path) -> None:
        target = Path(target)
        if not os.path.ismount(target):
            return
        proc = subprocess.run(["umount", str(target)], capture_output=True)
        if proc.returncode:
            run("umount", "-l", target)

    # ---- LUKS owned by the test (source side)
    def luks_source(self, device: str, name: str, passphrase: bytes = PASSPHRASE,
                    luks_uuid: str | None = None) -> tuple[str, str]:
        """Format and open a container for a *source* volume; returns (mapper path, luks uuid)."""
        loop_only(device)
        luks_uuid = luks_uuid or str(uuid.uuid4())
        run("cryptsetup", "luksFormat", "--type", "luks2", "--pbkdf", "pbkdf2",
            "--pbkdf-force-iterations", "1000", "--uuid", luks_uuid, "--key-file", "-",
            "--batch-mode", device, input=passphrase)
        mapper = f"it{self.tag}-{name}"
        run("cryptsetup", "open", "--key-file", "-", device, mapper, input=passphrase)
        self.mappers.append(mapper)
        self.on_close(f"close {mapper}", lambda m=mapper: self.close_mapper(m))
        return f"/dev/mapper/{mapper}", luks_uuid

    def close_mapper(self, name: str) -> None:
        if name not in self.mappers and not name.startswith(f"distromove-it{self.tag}"):
            raise AssertionError(f"refusing to close a mapper this test did not create: {name}")
        if Path(f"/dev/mapper/{name}").exists():
            run("cryptsetup", "close", name)

    def swapoff_later(self, path: Path) -> None:
        self.on_close(f"swapoff {path}", lambda p=path: run("swapoff", p, check=False))


class LoopDisk:
    def __init__(self, env: LoopEnv, name: str, size_mib: int, parts: list[dict], by_id: bool):
        self.env, self.name = env, name
        self.image = env.base / f"{name}.img"
        with open(self.image, "wb") as handle:
            handle.truncate(size_mib * MIB)
        out = run("losetup", "--find", "--show", "--partscan", self.image).strip()
        self.dev = loop_only(out)
        env.on_close(f"detach {self.dev}", self._detach)
        self.by_id_link: Path | None = None
        if by_id:
            link = Path("/dev/disk/by-id") / f"distromove-it-{env.tag}-{name}"
            link.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(self.dev, link)
            self.by_id_link = link
            env.on_close(f"unlink {link}", lambda l=link: l.unlink() if l.is_symlink() else None)
        self.parts: list[PartInfo] = []
        if parts:
            self.partition(parts)

    def _detach(self) -> None:
        run("udevadm", "settle", check=False)
        proc = subprocess.run(["losetup", "-d", self.dev], capture_output=True)
        if proc.returncode:
            raise RuntimeError(f"losetup -d {self.dev}: {proc.stderr.decode().strip()}")

    def partition(self, specs: list[dict]) -> list["PartInfo"]:
        """specs: name, start_mib, size_mib, kind ('linux' or 'esp')."""
        lines = ["label: gpt"]
        infos = []
        for number, spec in enumerate(specs, start=1):
            part_uuid = str(uuid.uuid4())
            kind = ESP if spec.get("kind") == "esp" else LINUX
            start, size = spec["start_mib"] * MIB // SECTOR, spec["size_mib"] * MIB // SECTOR
            lines.append(f"start={start},size={size},type={kind},uuid={part_uuid}")
            infos.append(PartInfo(spec["name"], number, f"{self.dev}p{number}", part_uuid,
                                  start, size))
        run("sfdisk", "--lock", self.dev, input=("\n".join(lines) + "\n").encode())
        run("partprobe", self.dev)
        run("udevadm", "settle")
        for info in infos:
            if not Path(info.node).exists():
                raise RuntimeError(f"partition node did not appear: {info.node}")
        self.parts = infos
        return infos

    def part(self, name: str) -> "PartInfo":
        return next(p for p in self.parts if p.name == name)


class PartInfo:
    def __init__(self, name, number, node, partuuid, start_sectors, size_sectors):
        self.name, self.number, self.node, self.partuuid = name, number, node, partuuid
        self.start_sectors, self.size_sectors = start_sectors, size_sectors


# --------------------------------------------------------------------------- identities

def lsblk_rows(*devices: str) -> list[dict]:
    out = run("lsblk", "--json", "--list", "--bytes", "--output",
              "PATH,TYPE,PKNAME,PARTN,PARTUUID,START,SIZE,LOG-SEC,FSTYPE,UUID", *devices)
    return json.loads(out)["blockdevices"]


def identity_from_node(node: str, role: str, volume_id: str, *, by_id: str | None = None,
                       luks_uuid: str | None = None, fs_uuid: str | None = None) -> VolumeIdentity:
    row = next(r for r in lsblk_rows(node) if r["path"] == node)
    sector = int(row["log-sec"])
    start = int(row["start"]) * 512 // sector
    return VolumeIdentity(volume_id, role, None, None, by_id, row["partuuid"], start,
                          int(row["size"]) // sector, luks_uuid, fs_uuid)


def loop_snapshot(live: dict) -> SystemSnapshot:
    """A SystemSnapshot of the loop world, read fresh from the kernel.

    ``live``: disks (loop devices), links (disk -> by-id path), running_root_uuid, mounts
    (list of [source, target, fstype]), firmware (path of the shim state) and esp_contents.
    """
    rows = []
    for disk in live["disks"]:
        rows += lsblk_rows(loop_only(disk))
    by_kname = {Path(r["path"]).name: r for r in rows}
    identities = []
    for row in rows:
        if row["type"] != "part":
            continue
        crypt = next((c for c in rows if c["type"] == "crypt"
                      and c.get("pkname") == Path(row["path"]).name), None)
        sector = int(row["log-sec"])
        is_luks = row["fstype"] == "crypto_LUKS"
        disk_path = "/dev/" + row["pkname"]
        identities.append(VolumeIdentity(
            "", "foreign", None, None, live["links"].get(disk_path), row["partuuid"],
            int(row["start"]) * 512 // sector, int(row["size"]) // sector,
            row["uuid"] if is_luks else None,
            ((crypt or {}).get("uuid") if is_luks else row["uuid"])))
    fw = json.loads(Path(live["firmware"]).read_text())
    dm = run("dmsetup", "info", "-c", "--noheadings", "-o", "name,uuid", "--separator", " ",
             check=False)
    mappers = [line.strip() for line in dm.splitlines()
               if line.strip() and len(line.split()) == 2]
    return SystemSnapshot(
        fstab="", crypttab="",
        mounts=[MountInfo(s, t, f, "rw") for s, t, f in live["mounts"]],
        mappers=mappers, swaps=[], esp_contents=live.get("esp_contents", {}),
        boot_current=fw["current"], boot_entries=dict(fw["entries"]),
        identities=identities, running_root_uuid=live["running_root_uuid"])


def mkfs(device: str, fs: str, fs_uuid: str) -> None:
    if device.startswith("/dev/loop"):
        loop_only(device)
    if fs == "ext4":
        run("mkfs.ext4", "-q", "-U", fs_uuid, device)
    elif fs == "btrfs":
        run("mkfs.btrfs", "-q", "-f", "-U", fs_uuid, device)
    elif fs == "vfat":
        run("mkfs.vfat", "-F", "32", "-i", fs_uuid.replace("-", ""), device)
    else:
        raise ValueError(fs)


def blkid(device: str, tag: str) -> str:
    return run("blkid", "-p", "-o", "value", "-s", tag, device).strip()


# --------------------------------------------------------------------------- trees

def populate(root: Path, seed: int = 1, *, scale: int = 1) -> None:
    """Deterministic mixed content: nested dirs, empty/large/sparse files, links, a FIFO."""
    rng = random.Random(seed)
    root = Path(root)
    for sub in ("etc/default", "usr/share/doc/pkg", "var/log", "home/user/.config", "srv/data"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    (root / "etc/hostname").write_text(f"host-{seed}\n")
    (root / "etc/fstab").write_text("# placeholder\n")
    (root / "etc/default/grub").write_text("GRUB_TIMEOUT=5\n")
    for i in range(40 * scale):
        path = root / "usr/share/doc/pkg" / f"file{i:03d}.txt"
        path.write_bytes(rng.randbytes(rng.randint(0, 6000)))
        os.utime(path, ns=(1_700_000_000_000_000_000 + i, 1_700_000_000_000_000_000 + i * 7919))
    (root / "var/log/big.bin").write_bytes(rng.randbytes(3 * MIB))
    (root / "empty").write_bytes(b"")
    with open(root / "srv/data/sparse.img", "wb") as handle:
        handle.truncate(8 * MIB)
        handle.seek(4 * MIB)
        handle.write(b"tail")
    os.link(root / "etc/hostname", root / "etc/hostname.hard")
    os.symlink("hostname", root / "etc/hostname.link")
    os.symlink("/nonexistent/target", root / "etc/dangling")
    os.mkfifo(root / "srv/data/fifo")
    os.chmod(root / "home/user", 0o750)
    os.chown(root / "home/user", 1000, 1000)
    private = root / "home/user/.config/token"
    private.write_text("private\n")
    os.chmod(private, 0o600)
    os.chown(private, 1000, 1000)


def _digest(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def tree_state(root: Path, *, skip: tuple[str, ...] = ("lost+found",),
               exclude: tuple[str, ...] = (), fat: bool = False) -> dict[str, tuple]:
    """Logical description of a tree: type, owner, mode, size, content hash, file mtime.

    Entries on another device (nested btrfs subvolumes, mounts) are left out.  Directory
    mtimes and atimes are not compared.  ``fat`` keeps only names, sizes and content.
    """
    root = Path(root)
    root_dev = os.lstat(root).st_dev
    out: dict[str, tuple] = {}

    def walk(directory: str, rel: str) -> None:
        with os.scandir(directory) as it:
            entries = sorted(it, key=lambda e: e.name)
        for entry in entries:
            if entry.name in skip:
                continue
            sub = f"{rel}/{entry.name}" if rel else entry.name
            if any(sub == e or sub.startswith(e + "/") for e in exclude):
                continue
            st = entry.stat(follow_symlinks=False)
            if st.st_dev != root_dev:
                continue
            mode = st.st_mode
            if stat.S_ISDIR(mode):
                out[sub] = ("d",) if fat else ("d", stat.S_IMODE(mode), st.st_uid, st.st_gid)
                walk(entry.path, sub)
            elif stat.S_ISLNK(mode):
                out[sub] = ("l", os.readlink(entry.path))
            elif stat.S_ISREG(mode):
                out[sub] = (("f", st.st_size, _digest(entry.path)) if fat else
                            ("f", stat.S_IMODE(mode), st.st_uid, st.st_gid, st.st_size,
                             _digest(entry.path), st.st_mtime_ns, st.st_nlink))
            else:
                out[sub] = ("s", stat.S_IFMT(mode)) if fat else (
                    "s", stat.S_IFMT(mode), stat.S_IMODE(mode), st.st_uid, st.st_gid)

    walk(str(root), "")
    return out


def diff_trees(a: dict, b: dict) -> list[str]:
    problems = []
    for key in sorted(set(a) | set(b)):
        if a.get(key) != b.get(key):
            problems.append(f"{key}: {a.get(key)} != {b.get(key)}")
    return problems


def no_migration_snapshots(top: Path) -> list[str]:
    """Names of leftover ``distromove-*`` entries or subvolumes under a btrfs top level."""
    found = [e.name for e in os.scandir(top) if e.name.startswith("distromove-")]
    listing = run("btrfs", "subvolume", "list", top)
    found += re.findall(r"path (\S*distromove-\S+)", listing)
    return sorted(set(found))


# --------------------------------------------------------------------------- firmware shim

_EFIBOOTMGR = textwrap.dedent('''\
    #!/usr/bin/env python3
    """Stand-in for efibootmgr: keeps a private firmware table in a JSON file."""
    import json, os, signal, subprocess, sys
    STATE = os.environ["FAKE_EFI_STATE"]
    def load():
        with open(STATE) as handle:
            return json.load(handle)
    def save(state):
        with open(STATE + ".tmp", "w") as handle:
            json.dump(state, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(STATE + ".tmp", STATE)
    def fail(text):
        sys.stderr.write(text + "\\n")
        sys.exit(2)
    def die():
        os.kill(os.getppid(), signal.SIGKILL)
        os._exit(9)
    args = sys.argv[1:]
    if "--version" in args:
        print("efibootmgr version 18")
        sys.exit(0)
    state = load()
    if args in ([], ["-v"]):
        print("BootCurrent: " + state["current"])
        print("Timeout: 0 seconds")
        print("BootOrder: " + ",".join(state["order"]))
        for number in sorted(state["entries"]):
            print(state["entries"][number])
        sys.exit(0)
    if args and args[0] == "--create-only":
        opts = dict(zip(args[1::2], args[2::2]))
        disk, part = opts["--disk"], opts["--part"]
        rows = json.loads(subprocess.run(
            ["lsblk", "--json", "--list", "--output", "PATH,PARTN,PARTUUID", disk],
            capture_output=True, text=True, check=True).stdout)["blockdevices"]
        found = [r["partuuid"] for r in rows if r.get("partn") is not None
                 and str(r["partn"]) == part and r.get("partuuid")]
        if len(found) != 1:
            fail("no such partition")
        number = "%04X" % (max([int(k, 16) for k in state["entries"]] + [0]) + 1)
        line = "Boot%s* %s\\tHD(%s,GPT,%s,0x800,0x100000)/File(%s)" % (
            number, opts["--label"], part, found[0], opts["--loader"])
        if os.environ.get("FAKE_EFI_DIE") == "before":
            die()
        state["entries"][number] = line
        save(state)
        if os.environ.get("FAKE_EFI_DIE") == "after":
            die()
        sys.exit(0)
    if args and args[0] == "-o":
        order = args[1].split(",")
        if any(item not in state["entries"] for item in order) or len(set(order)) != len(order):
            fail("invalid order")
        if os.environ.get("FAKE_EFI_DIE") == "order":
            die()
        state["order"] = order
        save(state)
        sys.exit(0)
    if args and args[0] == "-b" and args[2:] == ["-B"]:
        number = args[1].upper()
        if number not in state["entries"]:
            fail("no such entry")
        del state["entries"][number]
        state["order"] = [x for x in state["order"] if x != number]
        save(state)
        sys.exit(0)
    fail("unsupported arguments: %r" % (args,))
    ''')


class Firmware:
    """A private fake NVRAM; the real firmware is never reachable while its directory leads PATH."""

    def __init__(self, env: LoopEnv):
        self.env = env
        self.bin = env.base / "shims"
        self.bin.mkdir(parents=True, exist_ok=True)
        (self.bin / "efibootmgr").write_text(_EFIBOOTMGR)
        (self.bin / "update-grub").write_text("#!/bin/sh\nexit 0\n")
        for name in ("efibootmgr", "update-grub"):
            (self.bin / name).chmod(0o755)
        self.state_file = env.base / "firmware.json"

    def init(self, esp_partuuid: str, *, windows: bool = True, old_id: str = "debian") -> None:
        entries = {"0001": (f"Boot0001* {old_id}\tHD(1,GPT,{esp_partuuid},0x800,0x100000)"
                            f"/File(\\EFI\\{old_id}\\shimx64.efi)")}
        order = ["0001"]
        if windows:
            entries["0003"] = (f"Boot0003* Windows Boot Manager\tHD(1,GPT,{esp_partuuid},0x800,"
                               "0x100000)/File(\\EFI\\Microsoft\\Boot\\bootmgfw.efi)")
            order.append("0003")
        self.write({"current": "0001", "order": order, "entries": entries})

    def write(self, state: dict) -> None:
        self.state_file.write_text(json.dumps(state))

    def read(self) -> dict:
        return json.loads(self.state_file.read_text())

    def environ(self, **extra: str) -> dict:
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:{env['PATH']}"
        env["FAKE_EFI_STATE"] = str(self.state_file)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env.update(extra)
        return env

    def activate(self, monkeypatch) -> None:
        """Point this process (and its children) at the shim; prove the real tool is shadowed."""
        for key, value in self.environ().items():
            if key in ("PATH", "FAKE_EFI_STATE"):
                monkeypatch.setenv(key, value)
        found = subprocess.run(["sh", "-c", "command -v efibootmgr"], capture_output=True,
                               text=True).stdout.strip()
        assert found == str(self.bin / "efibootmgr"), found


def efi_loader_dirs(esp_root: Path) -> list[str]:
    return sorted(e.name for e in os.scandir(Path(esp_root) / "EFI") if e.is_dir())


def populate_esp(root: Path, *, windows: bool = True, loader_id: str = "debian") -> None:
    root = Path(root)
    for rel, payload in ((f"EFI/{loader_id}/shimx64.efi", b"shim" * 100),
                         (f"EFI/{loader_id}/grubx64.efi", b"grub" * 200),
                         (f"EFI/{loader_id}/grub.cfg", b"configfile ...\n"),
                         ("EFI/BOOT/BOOTX64.EFI", b"fallback" * 50)):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    if windows:
        path = root / "EFI/Microsoft/Boot/bootmgfw.efi"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"windows" * 300)


def python_env_for_child(firmware: Firmware | None, **extra: str) -> dict:
    env = firmware.environ(**extra) if firmware else dict(os.environ, **extra)
    src = str(Path(__file__).resolve().parents[2] / "src")
    here = str(Path(__file__).resolve().parent)
    env["PYTHONPATH"] = os.pathsep.join([src, here] + ([env["PYTHONPATH"]]
                                                       if env.get("PYTHONPATH") else []))
    return env


def child_command(script: str, *args: str) -> list[str]:
    return [sys.executable, str(Path(__file__).resolve().parent / script), *args]
