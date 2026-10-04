"""JSON-RPC 2.0 framing for the helper socket.

Transport-agnostic encode/decode. No I/O here, so the framing rules can be
tested without a socket and the daemon and its client cannot drift apart.

**Newline-delimited JSON, one frame per line.** A length prefix would be
marginally faster and would let a malformed length stall a reader forever; a
newline cannot, because a frame that never terminates simply never parses. The
encoders therefore reject any payload that would embed a raw newline, which
``json.dumps`` guarantees by escaping them.

**One request, many frames.** A request is answered by zero or more *progress*
and *heartbeat* frames and then exactly one terminal frame - a result or an
error. Every frame carries the request id it belongs to. This is the whole of
the difference from plain JSON-RPC, and it exists because the operations behind
this socket are hours long: batching a wipe's progress into its final reply
means the progress arrives after the wipe, which is not progress.

The three non-terminal frame kinds and what each one asserts:

* ``progress`` - the engine moved. Carries one
  :class:`~core.models.Progress` as JSON.
* ``heartbeat`` - the helper process is alive and its socket is writable. It
  carries ``since_progress_seconds`` and asserts **nothing** about the engine:
  a phase with no yield points (a sampled verify of a 4 TB disk) is quiet for
  minutes and is not stalled. Read §"liveness" in :mod:`helper.daemon`.
* ``cancel`` - sent by the *client*, on the connection the operation is running
  on, to ask for cooperative cancellation. It is the only frame that travels
  upstream during an operation.

Two rules the daemon depends on:

* **A request names a method, never a command.** ``method`` is a lookup key in
  a static allowlist. No shell string, no path to an executable, no argv ever
  crosses this boundary.
* **An error response carries a message, never a traceback.** A traceback from
  a root process tells an unprivileged caller about the filesystem layout and
  the code path it took to fail.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = [
    "encode_request",
    "decode_request",
    "encode_response",
    "decode_response",
    "encode_progress",
    "encode_heartbeat",
    "encode_cancel",
    "decode_frame",
    "is_cancel_frame",
    "MAX_FRAME_BYTES",
    "RpcError",
]

#: Longest frame the daemon will read. A caller that sends more is dropped
#: rather than allowed to exhaust memory in a root process.
MAX_FRAME_BYTES = 1 * 1024 * 1024

JSONRPC_VERSION = "2.0"


class RpcError(Exception):
    """A JSON-RPC error returned by the peer, raised on the client side."""

    def __init__(self, message: str, *, remediation: str = "", kind: str = "") -> None:
        super().__init__(message)
        self.message = message
        #: Carried through verbatim from the core exception, so the operator
        #: reads the same sentence the library author wrote.
        self.remediation = remediation
        #: The exception class name, so a caller can branch without parsing prose.
        self.kind = kind


def encode_request(method: str, params: dict[str, Any], *, req_id: int) -> bytes:
    """Serialize a JSON-RPC request frame."""
    if not isinstance(method, str) or not method:
        raise ValueError("an RPC method name must be a non-empty string")
    frame = json.dumps(
        {"jsonrpc": JSONRPC_VERSION, "id": req_id, "method": method, "params": params},
        separators=(",", ":"),
        sort_keys=True,
    )
    return frame.encode("utf-8") + b"\n"


def decode_request(frame: bytes) -> tuple[int, str, dict[str, Any]]:
    """Parse a request frame into ``(req_id, method, params)``.

    Raises:
        ValueError: the frame is not a well-formed JSON-RPC request.
    """
    if len(frame) > MAX_FRAME_BYTES:
        raise ValueError(f"request frame exceeds {MAX_FRAME_BYTES} bytes")
    try:
        payload = json.loads(frame)
    except json.JSONDecodeError as exc:
        raise ValueError(f"request frame is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("a JSON-RPC request must be an object")
    if payload.get("jsonrpc") != JSONRPC_VERSION:
        raise ValueError(f"unsupported jsonrpc version: {payload.get('jsonrpc')!r}")

    method = payload.get("method")
    if not isinstance(method, str) or not method:
        raise ValueError("a JSON-RPC request must name a method")
    params = payload.get("params", {})
    if not isinstance(params, dict):
        raise ValueError("params must be an object, never a positional array")
    req_id = payload.get("id")
    if not isinstance(req_id, int):
        raise ValueError("a JSON-RPC request must carry an integer id")
    return req_id, method, params


def encode_response(
    req_id: int,
    *,
    result: dict[str, Any] | None = None,
    error: str | None = None,
    remediation: str = "",
    kind: str = "",
) -> bytes:
    """Serialize a JSON-RPC response frame (exactly one of result/error)."""
    if (result is None) == (error is None):
        raise ValueError("a response carries exactly one of result or error")
    if error is not None:
        body: dict[str, Any] = {
            "jsonrpc": JSONRPC_VERSION,
            "id": req_id,
            "error": {
                "code": -32000,
                "message": error,
                "data": {"remediation": remediation, "kind": kind},
            },
        }
    else:
        body = {"jsonrpc": JSONRPC_VERSION, "id": req_id, "result": result}
    text = json.dumps(body, separators=(",", ":"), sort_keys=True)
    return text.encode("utf-8") + b"\n"


def encode_progress(req_id: int, record: dict[str, Any]) -> bytes:
    """Serialize one non-terminal progress frame for ``req_id``."""
    text = json.dumps(
        {"jsonrpc": JSONRPC_VERSION, "id": req_id, "progress": record},
        separators=(",", ":"),
        sort_keys=True,
    )
    return text.encode("utf-8") + b"\n"


def encode_heartbeat(req_id: int, info: dict[str, Any]) -> bytes:
    """Serialize one liveness frame for ``req_id``.

    See the module docstring for what a heartbeat does and does not assert.
    """
    text = json.dumps(
        {"jsonrpc": JSONRPC_VERSION, "id": req_id, "heartbeat": info},
        separators=(",", ":"),
        sort_keys=True,
    )
    return text.encode("utf-8") + b"\n"


def encode_cancel(req_id: int) -> bytes:
    """Serialize the client's cancellation request for a running ``req_id``.

    It names no method and carries no parameters, so it cannot widen what the
    daemon will do: the only thing it can ask for is that an operation the
    caller already started stop early.
    """
    text = json.dumps(
        {"jsonrpc": JSONRPC_VERSION, "id": req_id, "cancel": True},
        separators=(",", ":"),
        sort_keys=True,
    )
    return text.encode("utf-8") + b"\n"


def is_cancel_frame(frame: bytes) -> bool:
    """True when ``frame`` is a client cancellation for a running operation.

    Deliberately total: a frame this cannot parse is not a cancellation, and
    the caller - a root daemon in the middle of a wipe - must not be handed an
    exception for a stray byte on a socket it is about to abandon anyway.
    """
    try:
        payload = json.loads(frame)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return False
    return isinstance(payload, dict) and payload.get("cancel") is True


def decode_frame(frame: bytes) -> tuple[str, dict[str, Any]]:
    """Parse any downstream frame into ``(kind, payload)``.

    ``kind`` is one of ``"progress"``, ``"heartbeat"`` or ``"result"``. A
    ``"result"`` is terminal; the other two are not.

    Raises:
        RpcError: the peer returned an error, with its remediation attached.
        ValueError: the frame is not a well-formed JSON-RPC frame.
    """
    if len(frame) > MAX_FRAME_BYTES:
        raise ValueError(f"response frame exceeds {MAX_FRAME_BYTES} bytes")
    try:
        payload = json.loads(frame)
    except json.JSONDecodeError as exc:
        raise ValueError(f"response frame is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("a JSON-RPC response must be an object")
    if payload.get("jsonrpc") != JSONRPC_VERSION:
        raise ValueError(f"unsupported jsonrpc version: {payload.get('jsonrpc')!r}")

    if "error" in payload:
        error = payload["error"] or {}
        data = error.get("data") or {}
        raise RpcError(
            str(error.get("message") or "the helper returned an unspecified error"),
            remediation=str(data.get("remediation") or ""),
            kind=str(data.get("kind") or ""),
        )
    for kind in ("progress", "heartbeat"):
        if kind in payload:
            body = payload[kind]
            if not isinstance(body, dict):
                raise ValueError(f"a JSON-RPC {kind} body must be an object")
            return kind, body
    result = payload.get("result")
    if not isinstance(result, dict):
        raise ValueError("a JSON-RPC result must be an object")
    return "result", result


def decode_response(frame: bytes) -> dict[str, Any]:
    """Parse a *terminal* response frame, raising on a JSON-RPC error object.

    Raises:
        RpcError: the peer returned an error, with its remediation attached.
        ValueError: the frame is not a well-formed terminal response - which
            includes a progress or heartbeat frame, because a caller using this
            entry point asked for one answer and must not silently treat an
            intermediate frame as the result.
    """
    kind, payload = decode_frame(frame)
    if kind != "result":
        raise ValueError(
            f"expected a terminal result frame, got a {kind} frame; use "
            "decode_frame() to read a streamed operation"
        )
    return payload
