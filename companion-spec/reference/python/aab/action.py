# SPDX-License-Identifier: Apache-2.0
"""Action request record, digest, record checks and forwarding (Section 6)."""

from __future__ import annotations

from typing import Dict, Optional, Tuple

from . import encoding, jsonstrict
from .encoding import i64, u64
from .errors import (
    AabError,
    E_AUDIENCE,
    E_DIGEST_MISMATCH,
    E_EXPIRED,
    E_FP_CHANGED,
    E_HEADER_MISMATCH,
    E_JSON,
    E_REPLAY,
    E_SESSION,
)
from .identity import ServerIdentity
from .jcs import jcs
from .records import (
    DEFAULT_CONFIG,
    Config,
    DigestRef,
    Field,
    decode_record,
    encode_record,
    f_i64,
    f_id16,
    f_json,
    f_ref,
    f_server_identity,
    f_u64,
    f_utf8,
    ref_of,
)

OBJECT_TYPE = "action"
MAX_WINDOW_MS = 300_000
SKEW_MS = 30_000

SCHEMA = {
    0x01: Field("audience", True, f_utf8),
    0x02: Field("session", True, f_id16),
    0x03: Field("sequence", True, f_u64),
    0x04: Field("server", True, f_server_identity),
    0x05: Field("name", True, f_utf8),
    0x06: Field("fingerprint", True, f_ref("tool-fp")),
    0x07: Field("arguments", True, f_json(require_object=True)),
    0x08: Field("not_before", True, f_i64),
    0x09: Field("not_after", True, f_i64),
    0x0A: Field("approver", False, f_utf8),
    # SPEC-AMBIGUITY: 6.1: field 0x0B is a digest reference whose object type
    # is undefined [OI-8], so its expected algorithm is undefined. We require
    # the algorithm configured for "action".
    0x0B: Field("presentation", False, f_ref("action")),
}


def canonical_arguments(arguments) -> bytes:
    """Field 0x07: ``jcs(arguments)``; absent/None -> ``jcs({})``; non-object -> E_JSON."""
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise AabError(E_JSON, "arguments is not an object")
    return jcs(arguments)


def build(audience: str, session: bytes, sequence: int, server: ServerIdentity, name: str,
          fingerprint: DigestRef, arguments, not_before: int, not_after: int,
          approver: Optional[str] = None, presentation: Optional[DigestRef] = None,
          arguments_bytes: Optional[bytes] = None) -> bytes:
    """Encode an action record (Section 6.1)."""
    if len(session) != 16:
        raise ValueError("session id must be 16 bytes")
    args = arguments_bytes if arguments_bytes is not None else canonical_arguments(arguments)
    fields = [
        (0x01, encoding.utf8(audience)),
        (0x02, bytes(session)),
        (0x03, u64(sequence)),
        (0x04, server.encode()),
        (0x05, encoding.utf8(name)),
        (0x06, fingerprint.encode()),
        (0x07, args),
        (0x08, i64(not_before)),
        (0x09, i64(not_after)),
    ]
    if approver is not None:
        fields.append((0x0A, encoding.utf8(approver)))
    if presentation is not None:
        fields.append((0x0B, presentation.encode()))
    return encode_record(fields)


def decode(data: bytes, cfg: Config = DEFAULT_CONFIG) -> dict:
    return decode_record(data, SCHEMA, cfg)


def digest_ref(record_bytes: bytes, alg: str = "sha-256") -> DigestRef:
    return ref_of(OBJECT_TYPE, record_bytes, alg)


class VerifierState:
    """What a verifier knows when it runs the checks of Section 6.4.

    ``pending`` maps ``(session id, sequence)`` to the encoded action digest
    reference of an unconsumed pending entry (Section 6.2).
    ``current_fps`` maps ``(server identity bytes, tool name)`` to the tool's
    current fingerprint at the comparison point (Section 5.4).
    """

    def __init__(self, proxy_id: str, now: int, open_sessions=(), request_session: Optional[bytes] = None,
                 pending: Optional[Dict[Tuple[bytes, int], bytes]] = None,
                 current_fps: Optional[Dict[Tuple[bytes, str], DigestRef]] = None,
                 cfg: Config = DEFAULT_CONFIG):
        self.proxy_id = proxy_id
        self.now = now
        self.open_sessions = set(open_sessions)
        self.request_session = request_session
        self.pending = dict(pending or {})
        self.current_fps = dict(current_fps or {})
        self.cfg = cfg

    def consume(self, session: bytes, sequence: int, ref_bytes: bytes) -> None:
        """Atomic compare-and-delete of a pending entry (Section 6.4, last paragraph)."""
        if self.pending.get((session, sequence)) != ref_bytes:
            raise AabError(E_REPLAY, "pending entry already consumed")
        del self.pending[(session, sequence)]


def window_ok(not_before: int, not_after: int, max_ms: int) -> bool:
    # SPEC-AMBIGUITY: 6.4/8.4: with i64 arithmetic `not_after - not_before`
    # and `not_after + 30 000` can overflow; the spec does not say how to
    # compute them. Python integers do not overflow, so we compute exactly.
    return not_after >= not_before and not_after - not_before <= max_ms


def check_record(rec: dict, state: VerifierState, evidence_ref_bytes: bytes) -> None:
    """The record checks of Section 6.4, in order."""
    if rec["session"] not in state.open_sessions or rec["session"] != state.request_session:
        raise AabError(E_SESSION, "session not open or not the request's session")
    if rec["audience"] != state.proxy_id:
        raise AabError(E_AUDIENCE, "audience %r" % rec["audience"])
    if not window_ok(rec["not_before"], rec["not_after"], MAX_WINDOW_MS):
        raise AabError(E_EXPIRED, "validity window invalid or longer than 300 000 ms")
    if state.now < rec["not_before"] - SKEW_MS or state.now > rec["not_after"] + SKEW_MS:
        raise AabError(E_EXPIRED, "current time outside the validity window")
    if state.pending.get((rec["session"], rec["sequence"])) != evidence_ref_bytes:
        raise AabError(E_REPLAY, "no unconsumed pending entry")
    key = (rec["server"].encode(), rec["name"])
    current = state.current_fps.get(key)
    # SPEC-AMBIGUITY: 6.4 #6: a tool with no current fingerprint at the
    # comparison point (removed from tools/list) is not addressed. We treat
    # it as changed (E_FP_CHANGED).
    if current is None or current != rec["fingerprint"]:
        raise AabError(E_FP_CHANGED, "tool fingerprint changed")


# --- proxy side: incoming request, forwarding (Section 6.3) -----------------


def parse_request(body: bytes, headers: Optional[Dict[str, str]] = None) -> dict:
    """Parse an agent's ``tools/call`` request under Section 6.3 rules 1-2.

    Returns ``{"id", "name", "arguments", "arguments_bytes"}``.
    """
    msg = jsonstrict.parse(body)
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or msg.get("method") != "tools/call":
        raise AabError(E_JSON, "not a JSON-RPC 2.0 tools/call request")
    # SPEC-AMBIGUITY: 6.3: a tools/call without `id` (a notification) or with
    # a non-scalar id is not addressed. We reject both with E_JSON.
    if "id" not in msg or not (msg["id"] is None or isinstance(msg["id"], (str, float))):
        raise AabError(E_JSON, "missing or invalid JSON-RPC id")
    params = msg.get("params")
    if not isinstance(params, dict) or not isinstance(params.get("name"), str):
        raise AabError(E_JSON, "params.name missing or not a string")
    if headers is not None:
        # SPEC-AMBIGUITY: 6.3 rule 2: the encoding of non-ASCII tool names in
        # the Mcp-Name header (SEP-2243) is not fixed here. We compare the
        # header, decoded as a Python str, for exact equality.
        h = {k.lower(): v for k, v in headers.items()}
        if "mcp-method" in h and h["mcp-method"] != msg["method"]:
            raise AabError(E_HEADER_MISMATCH, "Mcp-Method differs from body")
        if "mcp-name" in h and h["mcp-name"] != params["name"]:
            raise AabError(E_HEADER_MISMATCH, "Mcp-Name differs from params.name")
    args = params.get("arguments")
    return {
        "id": msg["id"],
        "name": params["name"],
        "arguments": {} if args is None else args,
        "arguments_bytes": canonical_arguments(args),
    }


def forward_body(record: dict, request_id) -> bytes:
    """The forwarded request of Section 6.3 rule 3, built from the record."""
    # SPEC-AMBIGUITY: 6.3 rules 3 and 5: `<id>` is serialized with jcs, so a
    # numeric id such as 1.0 is forwarded as 1 and the response id no longer
    # matches the agent's bytes; the spec does not say whether the proxy
    # restores the original id on the response. We forward jcs(id).
    args_bytes = record["_raw"][0x07]
    body = (b'{"id":' + jcs(request_id) + b',"jsonrpc":"2.0","method":"tools/call","params":{"arguments":'
            + args_bytes + b',"name":' + jcs(record["name"]) + b"}}")
    # Cross-check against a full JCS serialization (Section 6.3 rule 3).
    expect = jcs({"id": request_id, "jsonrpc": "2.0", "method": "tools/call",
                  "params": {"arguments": jsonstrict.parse(args_bytes), "name": record["name"]}})
    assert body == expect, "forwarding construction disagrees with jcs()"
    return body


def forward_headers(record: dict) -> Dict[str, str]:
    return {"Mcp-Method": "tools/call", "Mcp-Name": record["name"]}


def tool_server_check(received_body: bytes, record: dict) -> None:
    """Section 6.3 rule 6: a tool server acting as verifier."""
    # SPEC-AMBIGUITY: 6.3 rule 6: "the bytes of params.arguments" could mean
    # the raw span received or jcs() of the parsed value, and the position of
    # this check among the steps of Section 7.2 is not given. We compare the
    # raw received span, after parsing the whole body with Section 4.3 rules.
    msg, spans = jsonstrict.parse(received_body, spans=True)
    params = msg.get("params") if isinstance(msg, dict) else None
    if not isinstance(params, dict) or "arguments" not in params or "name" not in params:
        raise AabError(E_DIGEST_MISMATCH, "received request lacks params.name/arguments")
    if params["name"] != record["name"]:
        raise AabError(E_DIGEST_MISMATCH, "params.name differs from field 0x05")
    if jsonstrict.raw_span(spans, ("params", "arguments")) != record["_raw"][0x07]:
        raise AabError(E_DIGEST_MISMATCH, "params.arguments bytes differ from field 0x07")


def forwarding_harness(record: dict, bytes_at_tool: bytes) -> str:
    """Conformance harness for Section 6.3 (vector ACT-011).

    Returns ``"conformant"`` when the bytes that reached the test tool are
    exactly the body built from the record, else ``"non-conformant"``.
    """
    try:
        msg = jsonstrict.parse(bytes_at_tool)
        rid = msg["id"]
    except (AabError, KeyError, TypeError):
        return "non-conformant"
    return "conformant" if bytes(bytes_at_tool) == forward_body(record, rid) else "non-conformant"
