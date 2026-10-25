"""Rewrite references in the copied system's boot configuration.

Only active configuration fields are changed; comments and unrelated entries
retain their original spelling and whitespace. Ambiguous btrfs IDs fail closed.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from collections.abc import Iterable

from .model import UuidMap


@dataclass(frozen=True)
class ResumeTarget:
    """New resume device UUID and, for a swap file, its physical page offset."""

    device_uuid: str
    offset: int | None


_FSTAB = re.compile(r"^(\s*)(\S+)(\s+)(\S+)(\s+)(\S+)(\s+)(\S+)(.*)$")
_CRYPTTAB = re.compile(r"^(\s*)(\S+)(\s+)(\S+)(\s+)(\S+)(.*)$")
_SUBVOLID = re.compile(r"(?<!\w)subvolid=(\d+)(?!\d)")
_GRUB_VALUE = re.compile(r'^(\s*(?:GRUB_CMDLINE_LINUX|GRUB_CMDLINE_LINUX_DEFAULT)=)(["\'])(.*)\2(\s*)$')


def _lookup(mapping: dict[str, str], old: str) -> str | None:
    """UUIDs are case-insensitive; mapper names remain case-sensitive."""
    for key, value in mapping.items():
        if key.casefold() == old.casefold():
            return value
    return None


def _device(source: str, m: UuidMap, *, crypttab: bool = False,
            swap: bool = False) -> str:
    if source.startswith("UUID="):
        old = source[5:]
        table = m.luks if crypttab else (m.swap_uuid if swap else m.fs)
        new = _lookup(table, old)
        return "UUID=" + new if new is not None else source
    if source.startswith("PARTUUID="):
        new = _lookup(m.partuuid, source[9:])
        return "PARTUUID=" + new if new is not None else source
    prefix = "/dev/mapper/"
    if source.startswith(prefix):
        return prefix + m.mapper.get(source[len(prefix):], source[len(prefix):])
    return source


def _subvol_id(old_id: int, m: UuidMap, fs_uuid: str | None) -> int:
    if fs_uuid is not None:
        for old_fs, ids in m.subvolid.items():
            if old_fs.casefold() == fs_uuid.casefold():
                if old_id not in ids:
                    raise ValueError(f"subvolume {old_id} missing for root filesystem {fs_uuid}")
                return ids[old_id]
        raise ValueError(f"root filesystem {fs_uuid} has no subvolume map")
    candidates = {ids[old_id] for ids in m.subvolid.values() if old_id in ids}
    if len(candidates) != 1:
        raise ValueError(f"cannot identify root filesystem for subvolume {old_id}")
    return candidates.pop()


def _rewrite_options(options: str, m: UuidMap, fs_uuid: str | None) -> str:
    if "subvolid=" not in options:
        return options
    return _SUBVOLID.sub(lambda match: "subvolid=" + str(
        _subvol_id(int(match.group(1)), m, fs_uuid)), options)


def rewrite_fstab(text: str, m: UuidMap,
                  filesystem_by_mount: dict[str, str] | None = None) -> str:
    """Replace migrated references; identify encrypted btrfs by source mount UUID."""
    lines = []
    for line in text.splitlines(keepends=True):
        body, ending = _split_ending(line)
        if not body.strip() or body.lstrip().startswith("#"):
            lines.append(line)
            continue
        match = _FSTAB.match(body)
        if match is None:
            lines.append(line)
            continue
        lead, source, ws1, mount, ws2, fstype, ws3, options, tail = match.groups()
        is_swap = fstype == "swap"
        fs_uuid = source[5:] if source.startswith("UUID=") and _lookup(m.fs, source[5:]) else None
        explicit_uuid = (filesystem_by_mount or {}).get(mount)
        if explicit_uuid is not None:
            if fs_uuid is not None and fs_uuid.casefold() != explicit_uuid.casefold():
                raise ValueError(f"filesystem UUID disagrees for mount {mount}")
            fs_uuid = explicit_uuid
        new_source = _device(source, m, swap=is_swap)
        if is_swap and source.startswith(("UUID=", "PARTUUID=", "/dev/mapper/")) and new_source == source:
            raise ValueError(f"swap has no destination identity: {source}")
        if fstype == "btrfs" and "subvolid=" in options and (
            fs_uuid is not None or new_source != source
        ):
            options = _rewrite_options(options, m, fs_uuid)
        lines.append(lead + new_source + ws1 + mount + ws2 + fstype + ws3 + options + tail + ending)
    return "".join(lines)


def rewrite_crypttab(text: str, m: UuidMap) -> str:
    """Keep keyfiles and options while replacing LUKS and swap identities."""
    lines = []
    for line in text.splitlines(keepends=True):
        body, ending = _split_ending(line)
        if not body.strip() or body.lstrip().startswith("#"):
            lines.append(line)
            continue
        match = _CRYPTTAB.match(body)
        if match is None:
            lines.append(line)
            continue
        lead, name, ws1, source, ws2, keyfile, tail = match.groups()
        new_name = m.mapper.get(name, name)
        new_source = _device(source, m, crypttab=True)
        if re.search(r"(?:^|,)swap(?:,|\s|$)", tail) and new_source == source:
            raise ValueError(f"encrypted swap has no destination identity: {source}")
        lines.append(lead + new_name + ws1 + new_source + ws2 + keyfile + tail + ending)
    return "".join(lines)


def _split_ending(line: str) -> tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n"):
        return line[:-1], "\n"
    return line, ""


def _rewrite_grub_values(text: str, transform) -> str:
    result = []
    for line in text.splitlines(keepends=True):
        body, ending = _split_ending(line)
        match = _GRUB_VALUE.match(body)
        if match is None:
            result.append(line)
            continue
        prefix, quote, value, suffix = match.groups()
        result.append(prefix + quote + transform(value, prefix) + quote + suffix + ending)
    return "".join(result)


def rewrite_resume(resume_conf: str, grub_default: str,
                   resume: ResumeTarget | None) -> tuple[str, str]:
    """Point initramfs and GRUB at the new swap, or disable resume."""
    if resume is not None and (not resume.device_uuid or
                               (resume.offset is not None and resume.offset < 0)):
        raise ValueError("invalid resume target")
    lines = []
    saw_resume = saw_offset = False
    for line in resume_conf.splitlines(keepends=True):
        body, ending = _split_ending(line)
        if re.match(r"^\s*RESUME\s*=", body) and not body.lstrip().startswith("#"):
            lines.append(f"RESUME={'UUID=' + resume.device_uuid if resume else 'none'}{ending}")
            saw_resume = True
        elif re.match(r"^\s*RESUME_OFFSET\s*=", body) and not body.lstrip().startswith("#"):
            saw_offset = True
            if resume is not None and resume.offset is not None:
                lines.append(f"RESUME_OFFSET={resume.offset}{ending}")
        else:
            lines.append(line)
    if not saw_resume:
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        lines.append(f"RESUME={'UUID=' + resume.device_uuid if resume else 'none'}\n")
    if resume is not None and resume.offset is not None and not saw_offset:
        lines.append(f"RESUME_OFFSET={resume.offset}\n")

    grub_lines = [match for line in grub_default.splitlines()
                  if (match := _GRUB_VALUE.match(line)) is not None]
    has_resume_any = any(re.search(r"(?<!\S)resume=\S+", match.group(3))
                         for match in grub_lines)
    has_default_line = any(match.group(1).strip().startswith("GRUB_CMDLINE_LINUX_DEFAULT")
                           for match in grub_lines)

    def update_value(value: str, prefix: str) -> str:
        had_resume = bool(re.search(r"(?<!\S)resume=\S+", value))
        had_offset = bool(re.search(r"(?<!\S)resume_offset=\S+", value))
        if resume is None:
            value = re.sub(r"(?:^|\s+)resume(?:_offset)?=\S+", "", value)
            return value.strip()
        if had_resume:
            value = re.sub(r"(?<!\S)resume=\S+", "resume=UUID=" + resume.device_uuid, value)
        elif had_offset or (not has_resume_any and prefix.strip().startswith("GRUB_CMDLINE_LINUX_DEFAULT")):
            value += (" " if value and not value.endswith(" ") else "") + "resume=UUID=" + resume.device_uuid
        if resume.offset is None:
            value = re.sub(r"(?:^|\s+)resume_offset=\S+", "", value)
        elif had_offset:
            value = re.sub(r"(?<!\S)resume_offset=\S+", "resume_offset=" + str(resume.offset), value)
        elif had_resume or (not has_resume_any and prefix.strip().startswith("GRUB_CMDLINE_LINUX_DEFAULT")):
            value += (" " if value and not value.endswith(" ") else "") + "resume_offset=" + str(resume.offset)
        return value

    new_grub = _rewrite_grub_values(grub_default, update_value)
    if resume is not None and not has_resume_any and not has_default_line:
        if new_grub and not new_grub.endswith("\n"):
            new_grub += "\n"
        options = "resume=UUID=" + resume.device_uuid
        if resume.offset is not None:
            options += " resume_offset=" + str(resume.offset)
        new_grub += f'GRUB_CMDLINE_LINUX_DEFAULT="{options}"\n'
    return "".join(lines), new_grub


def rewrite_rootflags(grub_default: str, m: UuidMap,
                      root_fs_uuid: str | None = None) -> str:
    """Rewrite root subvolume ID; explicit root UUID resolves multi-fs layouts."""
    def update_value(value: str, _prefix: str) -> str:
        root_uuid = root_fs_uuid
        root_match = re.search(r"(?<!\S)root=UUID=([^\s]+)", value)
        if root_match is not None and root_uuid is None:
            root_uuid = root_match.group(1)

        def replace_root(match: re.Match[str]) -> str:
            return "root=UUID=" + (_lookup(m.fs, match.group(1)) or match.group(1))

        value = re.sub(r"(?<!\S)root=UUID=([^\s]+)", replace_root, value)

        def replace_flags(match: re.Match[str]) -> str:
            return "rootflags=" + _rewrite_options(match.group(1), m, root_uuid)

        return re.sub(r"(?<!\S)rootflags=([^\s]+)", replace_flags, value)
    return _rewrite_grub_values(grub_default, update_value)


def find_old_uuids(texts: dict[str, str], old: Iterable[str],
                   allowed: dict[str, set[str]]) -> list[tuple[str, str]]:
    """Report old IDs in active text, except explicitly allowed file roles."""
    findings = []
    old_ids = tuple(old)
    for name, text in texts.items():
        active = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
        permitted = {value.casefold() for value in allowed.get(name, set())}
        for value in old_ids:
            if value.casefold() in permitted:
                continue
            if re.search(r"(?<![A-Za-z0-9])" + re.escape(value) +
                         r"(?![A-Za-z0-9-])", active, re.IGNORECASE):
                findings.append((name, value))
    return findings
