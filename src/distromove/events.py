"""Line-based event protocol: one JSON object per line."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Event:
    kind: str
    step: str
    message: str
    progress: float | None = None
    data: dict[str, Any] = field(default_factory=dict)


def encode(e: Event) -> str:
    """Encode an event as a single line (no newline characters inside)."""
    return json.dumps(
        {"kind": e.kind, "step": e.step, "message": e.message,
         "progress": e.progress, "data": e.data},
        ensure_ascii=True, separators=(",", ":"),
    )


def decode(line: str) -> Event:
    """Decode one line; raises ValueError for anything that is not a valid event."""
    try:
        obj = json.loads(line)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid event line: {exc}") from None
    if not isinstance(obj, dict):
        raise ValueError("invalid event: not an object")
    try:
        kind, step, message = obj["kind"], obj["step"], obj["message"]
        progress, data = obj["progress"], obj["data"]
    except KeyError as exc:
        raise ValueError(f"invalid event: missing {exc.args[0]}") from None
    if not all(isinstance(v, str) for v in (kind, step, message)):
        raise ValueError("invalid event: kind, step and message must be strings")
    if progress is not None and (isinstance(progress, bool) or not isinstance(progress, (int, float))):
        raise ValueError("invalid event: progress must be a number or null")
    if not isinstance(data, dict):
        raise ValueError("invalid event: data must be an object")
    return Event(kind, step, message, None if progress is None else float(progress), data)
