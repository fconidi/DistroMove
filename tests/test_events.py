import json

import pytest

from distromove.events import Event, decode, encode


def test_events_roundtrip():
    e = Event("progress", "copy", "Copying files – café", 0.25, {"bytes": 10, "nested": {"a": [1, 2]}})
    line = encode(e)
    assert "\n" not in line
    assert decode(line) == e
    e2 = Event("step", "probe", "start", None, {})
    assert decode(encode(e2)) == e2


def test_encode_single_line_even_with_newlines_in_message():
    e = Event("log", "x", "a\nb\r\nc", None, {})
    line = encode(e)
    assert "\n" not in line and "\r" not in line
    assert decode(line).message == "a\nb\r\nc"


@pytest.mark.parametrize("line", [
    "",
    "not json",
    "[1, 2, 3]",
    "42",
    json.dumps({"kind": "step"}),
    json.dumps({"kind": 1, "step": "s", "message": "m", "progress": None, "data": {}}),
    json.dumps({"kind": "k", "step": "s", "message": "m", "progress": "x", "data": {}}),
    json.dumps({"kind": "k", "step": "s", "message": "m", "progress": None, "data": []}),
])
def test_decode_rejects_garbage(line):
    with pytest.raises(ValueError):
        decode(line)
