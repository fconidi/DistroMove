import io
import json
import subprocess
from types import SimpleNamespace

import pytest

from distromove import helper


def request(data, secret=None):
    stream = io.BytesIO()
    helper.write_frame(stream, json.dumps(data).encode())
    if secret is not None:
        helper.write_frame(stream, secret)
    stream.seek(0)
    return stream


def events(stream):
    stream.seek(0)
    result = []
    while stream.tell() < len(stream.getvalue()):
        result.append(json.loads(helper.read_frame(stream, helper.CONTROL_MAX)))
    return result


def test_frame_roundtrip_unicode_and_newlines():
    stream = io.BytesIO()
    payload = 'pàss\nsecond line 🔒'.encode()
    helper.write_frame(stream, payload)
    stream.seek(0)
    assert helper.read_frame(stream, helper.SECRET_MAX) == payload


def test_secret_frame_over_1024_rejected():
    stream = io.BytesIO((1025).to_bytes(4, 'big') + b'x' * 1025)
    with pytest.raises(ValueError):
        helper.read_frame(stream, helper.SECRET_MAX)


def test_plan_larger_than_1024_bytes_accepted_as_control_frame():
    stream = io.BytesIO()
    payload = json.dumps({'op': 'migrate', 'plan': 'x' * 2000}).encode()
    helper.write_frame(stream, payload)
    stream.seek(0)
    assert helper.read_frame(stream, helper.CONTROL_MAX) == payload


def test_events_use_control_frames():
    output = io.BytesIO()
    helper.emit_event(output, {'phase': 'probe', 'message': 'pronto'})
    assert events(output) == [{'phase': 'probe', 'message': 'pronto'}]


def test_non_root_refused(monkeypatch):
    monkeypatch.setattr(helper.os, 'geteuid', lambda: 1000)
    output = io.BytesIO()
    assert helper.main(request({'op': 'probe'}), output) != 0
    assert events(output)[0]['error'] == 'RootRequired'


def test_secret_never_written_to_stdout_or_event():
    secret = 'pàss\n🔒'.encode()
    output = io.BytesIO()
    seen = []

    def operation(data, received, emit):
        seen.append(received)
        emit({'phase': 'running'})
        return {'ok': True}

    assert helper.serve(request({'op': 'migrate', 'has_secret': True}, secret),
                        output, operation) == 0
    assert seen == [secret]
    assert secret not in output.getvalue()
    assert events(output)[-1] == {'ok': True}


def test_gui_to_helper_to_cryptsetup_passphrase_roundtrip(monkeypatch):
    secret = 'prìma riga\nseconda 🔒\n'.encode()
    calls = []
    logs = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs['input']))
        return subprocess.CompletedProcess(argv, 0, b'', b'')

    monkeypatch.setattr(subprocess, 'run', fake_run)

    def operation(data, received, emit):
        helper.Runner(log=logs.append).run(
            ['cryptsetup', 'open', '--key-file', '-', '/dev/verified', 'root'],
            input=received, secret_input=True)
        return {'ok': True}

    output = io.BytesIO()
    assert helper.serve(request({'op': 'migrate', 'has_secret': True}, secret),
                        output, operation) == 0
    assert calls[0][1] == secret
    assert secret not in output.getvalue()
    assert secret.decode() not in ''.join(logs)


def test_reconcile_runs_before_migrate():
    calls = []

    def operation(data, secret, emit):
        calls.append(data['op'])
        return {'ok': True}

    helper.serve(request({'op': 'migrate'}), io.BytesIO(), operation,
                 before=lambda: calls.append('reconcile'))
    assert calls == ['reconcile', 'migrate']


def test_failed_operation_sets_failure_exit_code():
    output = io.BytesIO()
    status = helper.serve(request({'op': 'migrate'}), output,
                          lambda data, secret, emit: {'ok': False, 'phase': 'preflight'})
    assert status == 1
    assert events(output) == [{'ok': False, 'phase': 'preflight'}]


def test_paths_from_gui_ignored_identities_used(monkeypatch):
    monkeypatch.setattr(helper.os.path, 'realpath', lambda path: '/dev/null')
    monkeypatch.setattr(helper, 'disk_info', lambda r, path: SimpleNamespace(
        by_id='/dev/disk/by-id/stable', wwn='wwn-1', serial='serial-1'))
    source = SimpleNamespace(volumes=[SimpleNamespace(volume_id='root')])
    raw = {
        'disks': {'/dev/gui-name': {'by_id': '/dev/disk/by-id/stable',
                                   'wwn': 'wwn-1', 'serial': 'serial-1'}},
        'targets': [{'volume_id': 'root', 'disk': '/dev/gui-name', 'size_bytes': 4096}],
        'esp': {'mode': 'new', 'disk': '/dev/gui-name', 'size_bytes': 4096},
        'partitions': [{'disk': '/dev/gui-name', 'start_sectors': 2048,
                        'size_sectors': 4096, 'role': 'root',
                        'planned': {'partuuid': 'part-new', 'luks_uuid': None,
                                    'fs_uuid': 'fs-new'}}],
        'swaps': [], 'approved_tables': {'/dev/gui-name': 'fingerprint'},
    }
    plan = helper._plan(raw, source, object())
    assert plan.targets[0].disk == '/dev/null'
    assert plan.partitions[0].disk == '/dev/null'
    assert plan.approved_tables == {'/dev/null': 'fingerprint'}


def test_unverified_disk_identity_refused(monkeypatch):
    monkeypatch.setattr(helper.os.path, 'realpath', lambda path: '/dev/null')
    monkeypatch.setattr(helper, 'disk_info', lambda r, path: SimpleNamespace(
        by_id='/dev/disk/by-id/other', wwn='wwn-2', serial='serial-2'))
    with pytest.raises(ValueError):
        helper._plan({'disks': {'/dev/gui-name': {
            'by_id': '/dev/disk/by-id/stable', 'wwn': 'wwn-1', 'serial': 'serial-1'}}},
            SimpleNamespace(volumes=[]), object())


def test_bad_delete_confirmation_creates_no_journal(monkeypatch):
    class FakeLock:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(helper, 'Lock', FakeLock)
    monkeypatch.setattr(helper, 'collect_snapshot', lambda r: SimpleNamespace(
        running_root_uuid='new-root'))
    monkeypatch.setattr(helper, 'load_state', lambda root, uuid: SimpleNamespace(
        migration_id='migration', new_root_uuid='new-root'))
    monkeypatch.setattr(helper, 'confirmation_text', lambda *args, **kwargs: 'exact')
    monkeypatch.setattr(helper, 'Journal', lambda *args, **kwargs:
                        pytest.fail('journal created before confirmation'))
    with pytest.raises(ValueError, match='confirmation'):
        helper.system_operation({'op': 'delete_old', 'confirmation': 'wrong'},
                                None, lambda event: None)


def test_btrfs_top_mount_is_journalled_before_mount(tmp_path, monkeypatch):
    actions = []
    original_path = helper.Path

    # The source UUID symlink is the local identity, never a path from JSON.
    monkeypatch.setattr(original_path, 'is_symlink', lambda self:
                        str(self).startswith('/dev/disk/by-uuid/'))
    monkeypatch.setattr(helper.os.path, 'realpath', lambda path: '/dev/null')

    class Journal:
        def intend(self, name, identity, **fields):
            actions.append(('intent', name, identity, fields))
            return 'token'

        def done(self, token, outcome):
            actions.append(('done', outcome))

    class Runner:
        def run(self, argv, **kwargs):
            actions.append(('run', argv[0]))
            if argv[0] == 'findmnt':
                return SimpleNamespace(stdout='rw,subvolid=5\n')
            if argv[0] == 'blkid':
                return SimpleNamespace(stdout='source-uuid\n')
            return SimpleNamespace(stdout='')

    volume = SimpleNamespace(volume_id='root', btrfs=object(), fs_uuid='source-uuid')
    tops = helper._source_tops(SimpleNamespace(volumes=[volume]), tmp_path,
                               Runner(), Journal())
    assert tops['root'] == tmp_path / 'source-root'
    assert actions[0] == ('run', 'blkid')
    assert actions[1][0:2] == ('intent', 'mount_destination')
    assert actions[2] == ('run', 'mount')
    assert actions[-1] == ('done', 'mounted')


def test_plan_requests_gpt_word_only_for_signature_free_disk(monkeypatch):
    from distromove.layout import InitGpt, NoTable

    source = SimpleNamespace(
        volumes=[SimpleNamespace(volume_id='root')], unmigrated_mounts=[],
        esp=SimpleNamespace(partition=SimpleNamespace(parent_disk='/dev/old')))
    info = SimpleNamespace(path='/dev/new', by_id='/dev/disk/by-id/stable',
                           wwn='wwn-1', serial='SERIAL', signatures=(),
                           size_bytes=20 * 1024**3, logical_sector=512)
    monkeypatch.setattr(helper, 'discover_source', lambda r, **kwargs: source)
    monkeypatch.setattr(helper, '_disk_inventory', lambda r: [
        {'path': '/dev/new', 'by_id': info.by_id, 'wwn': info.wwn,
         'serial': info.serial}])
    monkeypatch.setattr(helper, 'disk_info', lambda r, path: info)
    monkeypatch.setattr(helper, 'scan_disk', lambda r, path:
                        (_ for _ in ()).throw(NoTable(path, True)))
    monkeypatch.setattr(helper, 'plan_init_gpt', lambda value: InitGpt(
        '/dev/new', 'stable disk', 'SERIAL', info.size_bytes, 512))
    request = {'targets': [{'volume_id': 'root', 'disk': '/dev/new',
                            'size_bytes': 10 * 1024**3}],
               'esp': {'mode': 'reuse'}}
    result = helper._planned(request, object())
    assert result['needs_gpt_confirmation'][0]['confirmation'] == 'SERIAL'
    assert result['needs_gpt_confirmation'][0]['signatures'] == []


def test_plan_refuses_unrecognized_disk_signatures(monkeypatch):
    from distromove.layout import NoTable

    source = SimpleNamespace(
        volumes=[SimpleNamespace(volume_id='root')], unmigrated_mounts=[],
        esp=SimpleNamespace(partition=SimpleNamespace(parent_disk='/dev/old')))
    monkeypatch.setattr(helper, 'discover_source', lambda r, **kwargs: source)
    monkeypatch.setattr(helper, '_disk_inventory', lambda r: [
        {'path': '/dev/new', 'by_id': '/dev/disk/by-id/stable',
         'wwn': 'wwn-1', 'serial': None}])
    monkeypatch.setattr(helper, 'disk_info', lambda r, path: SimpleNamespace(
        path=path, by_id='/dev/disk/by-id/stable', wwn='wwn-1', serial=None))
    monkeypatch.setattr(helper, 'scan_disk', lambda r, path:
                        (_ for _ in ()).throw(NoTable(path, False)))
    monkeypatch.setattr(helper, 'plan_init_gpt', lambda info:
                        pytest.fail('GPT offered on a disk with signatures'))
    with pytest.raises(ValueError, match='no usable GPT'):
        helper._planned({'targets': [{'volume_id': 'root', 'disk': '/dev/new',
                                      'size_bytes': 10 * 1024**3}],
                          'esp': {'mode': 'reuse'}}, object())


def test_planned_source_ignores_usage_counters_but_not_identity():
    from distromove.helper import _stable_source
    planned = {"volumes": [{"volume_id": "root", "fs_uuid": "u1", "used_bytes": 10,
                            "apparent_bytes": 9, "used_inodes": 5}], "secure_boot": False}
    busy = {"volumes": [{"volume_id": "root", "fs_uuid": "u1", "used_bytes": 99,
                         "apparent_bytes": 98, "used_inodes": 50}], "secure_boot": False}
    assert _stable_source(planned) == _stable_source(busy)
    other = {"volumes": [{"volume_id": "root", "fs_uuid": "u2", "used_bytes": 10,
                          "apparent_bytes": 9, "used_inodes": 5}], "secure_boot": False}
    assert _stable_source(planned) != _stable_source(other)
