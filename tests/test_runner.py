import sys

import pytest

from distromove.runner import Runner, RunnerError


def test_dry_run_does_not_execute(tmp_path):
    marker = tmp_path / "marker"
    r = Runner(dry_run=True)
    res = r.run(["touch", str(marker)])
    assert not marker.exists()
    assert res.returncode == 0 and res.stdout == "" and res.stderr == ""
    assert r.calls == [["touch", str(marker)]]


def test_readonly_runs_in_dry_run():
    r = Runner(dry_run=True)
    res = r.run(["echo", "hello"], readonly=True)
    assert res.stdout == "hello\n"
    assert isinstance(res.stdout, str)
    assert r.calls == [["echo", "hello"]]


def test_fixture_returned_in_dry_run():
    r = Runner(dry_run=True, fixtures={("lsblk", "-J"): '{"blockdevices": []}'})
    res = r.run(["lsblk", "-J"])
    assert res.stdout == '{"blockdevices": []}'
    assert res.returncode == 0
    res2 = r.run(["lsblk", "-J"], readonly=True)
    assert res2.stdout == '{"blockdevices": []}'


def test_secret_input_never_logged_or_in_error():
    secret = "s3crét-passphrase"
    logs = []
    r = Runner(log=logs.append)
    with pytest.raises(RunnerError) as ei:
        r.run([sys.executable, "-c", "import sys; d=sys.stdin.buffer.read(); sys.stderr.buffer.write(d); sys.exit(3)"],
              input=secret.encode(), secret_input=True)
    assert secret not in str(ei.value)
    assert "<secret>" in str(ei.value)
    assert all(secret not in line for line in logs)
    assert logs, "the command should still be logged"
    # also in dry-run
    logs2 = []
    Runner(dry_run=True, log=logs2.append).run(["cryptsetup", "open", "x"], input=secret.encode(), secret_input=True)
    assert all(secret not in line for line in logs2)


def test_input_is_passed_on_stdin_as_bytes():
    res = Runner().run(["cat"], input=b"\x00\xffabc\n")
    assert res.stdout == "\x00�abc\n"


def test_check_raises_on_nonzero():
    r = Runner()
    with pytest.raises(RunnerError) as ei:
        r.run(["false"])
    assert ei.value.returncode == 1
    assert "false" in str(ei.value)
    res = r.run(["false"], check=False)
    assert res.returncode == 1


def test_cwd_is_honoured(tmp_path):
    res = Runner().run(["pwd"], cwd=str(tmp_path))
    assert res.stdout.strip() == str(tmp_path)


def test_no_input_means_stdin_is_devnull_not_inherited():
    import subprocess

    code = (
        "from distromove.runner import Runner\n"
        "r = Runner().run(['cat'])\n"
        "assert r.returncode == 0 and r.stdout == ''\n"
    )
    src = str(__import__("pathlib").Path(__file__).resolve().parent.parent / "src")
    # The child's stdin is an open pipe that never closes: it must not be inherited.
    child = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE,
                             env={"PYTHONPATH": src, "PYTHONDONTWRITEBYTECODE": "1"})
    try:
        assert child.wait(timeout=10) == 0
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        child.stdin.close()
