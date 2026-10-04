"""JSON-RPC framing: the rules the daemon and its client both depend on."""

from __future__ import annotations

import json

import pytest

from helper import rpc


def test_a_request_round_trips() -> None:
    frame = rpc.encode_request("enumerate_devices", {"include_virtual": True}, req_id=7)
    req_id, method, params = rpc.decode_request(frame)

    assert req_id == 7
    assert method == "enumerate_devices"
    assert params == {"include_virtual": True}


def test_every_frame_ends_in_exactly_one_newline() -> None:
    """Newline-delimited framing: a frame that never terminates never parses.

    A length prefix would let a malformed length stall a reader in a root
    process forever; a newline cannot.
    """
    frame = rpc.encode_request("m", {"text": "line one\nline two"}, req_id=1)

    assert frame.endswith(b"\n")
    assert frame.count(b"\n") == 1, (
        "json.dumps escapes newlines, so a payload can never split a frame"
    )


def test_a_result_round_trips() -> None:
    frame = rpc.encode_response(3, result={"devices": []})
    assert rpc.decode_response(frame) == {"devices": []}


def test_an_error_response_raises_with_its_remediation_intact() -> None:
    """The remediation crosses the boundary verbatim.

    The operator reads the sentence the library author wrote, not one the
    transport invented.
    """
    frame = rpc.encode_response(
        4,
        error="The typed serial does not match.",
        remediation="Re-read the device serial and type it exactly.",
        kind="ConfirmationMismatch",
    )

    with pytest.raises(rpc.RpcError) as caught:
        rpc.decode_response(frame)

    assert caught.value.message == "The typed serial does not match."
    assert caught.value.remediation == "Re-read the device serial and type it exactly."
    assert caught.value.kind == "ConfirmationMismatch"


def test_a_response_carries_exactly_one_of_result_or_error() -> None:
    with pytest.raises(ValueError):
        rpc.encode_response(1)
    with pytest.raises(ValueError):
        rpc.encode_response(1, result={}, error="both")


@pytest.mark.parametrize(
    "frame",
    [
        b"not json",
        b"[]",
        json.dumps({"jsonrpc": "1.0", "id": 1, "method": "m"}).encode(),
        json.dumps({"jsonrpc": "2.0", "id": 1}).encode(),
        json.dumps({"jsonrpc": "2.0", "method": "m"}).encode(),
        json.dumps({"jsonrpc": "2.0", "id": "x", "method": "m"}).encode(),
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "m", "params": []}).encode(),
    ],
)
def test_a_malformed_request_is_refused(frame: bytes) -> None:
    """Positional params are refused too: handlers take structured input only."""
    with pytest.raises(ValueError):
        rpc.decode_request(frame)


def test_an_oversized_frame_is_refused_before_it_is_parsed() -> None:
    """A root process must not be made to allocate whatever a caller sends."""
    with pytest.raises(ValueError, match="exceeds"):
        rpc.decode_request(b"x" * (rpc.MAX_FRAME_BYTES + 1))
