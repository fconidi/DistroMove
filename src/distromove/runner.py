"""Single entry point for every external command (and so every side effect)."""
from __future__ import annotations

import os
import shlex
import signal
import subprocess
from typing import Callable, Optional

CompletedProcess = subprocess.CompletedProcess


class RunnerError(Exception):
    """A command failed. The message never contains secret input."""

    def __init__(self, message: str, argv: Optional[list[str]] = None,
                 returncode: Optional[int] = None, stdout: str = "", stderr: str = ""):
        super().__init__(message)
        self.argv = list(argv) if argv is not None else []
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _scrub(text: str, secret: Optional[str]) -> str:
    if not secret:
        return text
    for variant in {secret, secret.strip("\r\n")}:
        if variant:
            text = text.replace(variant, "<secret>")
    return text


class Runner:
    def __init__(self, dry_run: bool = False,
                 log: Optional[Callable[[str], None]] = None,
                 fixtures: Optional[dict[tuple[str, ...], str]] = None):
        self.dry_run = dry_run
        self.log = log
        self.fixtures = dict(fixtures or {})
        self.calls: list[list[str]] = []

    def _emit(self, text: str) -> None:
        if self.log is not None:
            self.log(text)

    def run(self, argv: list[str], *, check: bool = True, input: Optional[bytes] = None,
            secret_input: bool = False, cwd: Optional[str] = None,
            readonly: bool = False,
            encoding_errors: str = "replace",
            periodic_check: Optional[Callable[[], None]] = None,
            check_interval: float = 1.0) -> "subprocess.CompletedProcess[str]":
        argv = [str(a) for a in argv]
        self.calls.append(list(argv))
        line = shlex.join(argv)
        if input is not None:
            line += " <stdin:secret>" if secret_input else " <stdin>"
        self._emit(("[dry-run] " if self.dry_run and not readonly else "") + line)

        if self.dry_run:
            key = tuple(argv)
            if key in self.fixtures:
                return subprocess.CompletedProcess(argv, 0, self.fixtures[key], "")
            if not readonly:
                return subprocess.CompletedProcess(argv, 0, "", "")

        secret = None
        if secret_input and input:
            secret = input.decode("utf-8", errors="replace")
        try:
            if periodic_check is None:
                proc = subprocess.run(
                    argv, input=input, cwd=cwd, capture_output=True, check=False,
                    stdin=subprocess.DEVNULL if input is None else None)
            else:
                if input is not None or check_interval <= 0:
                    raise ValueError("periodic command checks need no stdin and a positive interval")
                child = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         start_new_session=True)
                try:
                    while True:
                        try:
                            out_bytes, err_bytes = child.communicate(timeout=check_interval)
                            break
                        except subprocess.TimeoutExpired:
                            periodic_check()
                    periodic_check()
                except BaseException:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.communicate()
                    raise
                proc = subprocess.CompletedProcess(argv, child.returncode, out_bytes, err_bytes)
        except OSError as exc:
            raise RunnerError(_scrub(f"cannot run {shlex.join(argv)}: {exc.strerror or exc}", secret),
                              argv) from None
        out = proc.stdout.decode("utf-8", errors=encoding_errors)
        err = proc.stderr.decode("utf-8", errors="replace")
        if secret is not None:
            out, err = _scrub(out, secret), _scrub(err, secret)
        result = subprocess.CompletedProcess(argv, proc.returncode, out, err)
        if check and proc.returncode != 0:
            detail = err.strip() or out.strip()
            msg = f"command failed ({proc.returncode}): {shlex.join(argv)}"
            if detail:
                msg += f": {detail}"
            raise RunnerError(_scrub(msg, secret), argv, proc.returncode, out, err)
        return result
