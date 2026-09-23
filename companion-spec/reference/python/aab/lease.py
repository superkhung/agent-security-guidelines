# SPDX-License-Identifier: Apache-2.0
"""Capability lease (Section 8): record, constraints, grant and enforcement."""

from __future__ import annotations

from typing import Dict, Iterable, List, NamedTuple, Optional, Set, Tuple

from . import encoding, evidence
from .action import SKEW_MS, window_ok
from .encoding import i64, lp, read_lp, u32, u64
from .errors import (
    AabError,
    E_AUDIENCE,
    E_EXPIRED,
    E_FP_CHANGED,
    E_LEASE_BUDGET,
    E_LEASE_CONSTRAINT,
    E_LEASE_REVOKED,
    E_LEASE_SCOPE,
    E_LENGTH,
    E_REPLAY,
    E_SESSION,
    E_TAG_ORDER,
    E_VALUE,
)
from .identity import ServerIdentity
from .identity import decode as decode_identity
from .jcs import jcs
from .records import (
    DEFAULT_CONFIG,
    Config,
    DigestRef,
    Field,
    decode_digest_ref,
    decode_record,
    encode_record,
    f_i64,
    f_id16,
    f_json,
    f_u64,
    f_utf8,
    ref_of,
)

OBJECT_TYPE = "lease"
MAX_WINDOW_MS = 28_800_000

OPS = ("eq", "prefix", "beneath", "in", "max", "absent")


class ToolEntry(NamedTuple):
    server: ServerIdentity
    name: str
    fingerprint: DigestRef

    def encode(self) -> bytes:
        return lp(self.server.encode()) + lp(encoding.utf8(self.name)) + lp(self.fingerprint.encode())


def encode_tools(entries: Iterable[ToolEntry], sort: bool = True) -> bytes:
    enc = [e.encode() for e in entries]
    if sort:
        enc.sort()
    return u32(len(enc)) + b"".join(enc)


def decode_tools(value: bytes, cfg: Config) -> List[ToolEntry]:
    """Field 0x06 (Section 8.1)."""
    if len(value) < 4:
        raise AabError(E_LENGTH, "tools field shorter than u32(n)")
    n = int.from_bytes(value[:4], "big")
    pos = 4
    raw_entries = []
    for _ in range(n):
        start = pos
        if pos >= len(value):
            raise AabError(E_LENGTH, "count n larger than the entries present")
        sid_b, pos = read_lp(value, pos)
        name_b, pos = read_lp(value, pos)
        fp_b, pos = read_lp(value, pos)
        raw_entries.append((value[start:pos], sid_b, name_b, fp_b))
    if pos != len(value):
        raise AabError(E_LENGTH, "count n smaller than the entries present")
    # SPEC-AMBIGUITY: 8.1: order between sort/duplicate checks (E_TAG_ORDER)
    # and decoding each entry's contents is not given. We decode first.
    entries = []
    for whole, sid_b, name_b, fp_b in raw_entries:
        entries.append((whole, ToolEntry(decode_identity(sid_b), encoding.check_string(name_b),
                                         decode_digest_ref(fp_b, cfg.alg("tool-fp")))))
    seen = set()
    for i, (whole, e) in enumerate(entries):
        if i and not entries[i - 1][0] < whole:
            raise AabError(E_TAG_ORDER, "tool entries not in ascending byte order")
        key = (e.server.encode(), e.name)
        if key in seen:
            raise AabError(E_TAG_ORDER, "duplicate tool entry")
        seen.add(key)
    return [e for _, e in entries]


SCHEMA = {
    0x01: Field("audience", True, f_utf8),
    0x02: Field("lease_id", True, f_id16),
    0x03: Field("session", True, f_id16),
    0x04: Field("grantor", True, f_utf8),
    0x05: Field("grantee", True, f_utf8),
    0x06: Field("tools", True, decode_tools),
    0x07: Field("constraints", True, f_json()),
    0x08: Field("max_calls", True, f_u64),
    0x09: Field("max_arg_bytes", False, f_u64),
    0x0A: Field("not_before", True, f_i64),
    0x0B: Field("not_after", True, f_i64),
}


def build(audience: str, lease_id: bytes, session: bytes, grantor: str, grantee: str,
          tools: Iterable[ToolEntry], constraints, max_calls: int, not_before: int, not_after: int,
          max_arg_bytes: Optional[int] = None, tools_bytes: Optional[bytes] = None,
          constraints_bytes: Optional[bytes] = None) -> bytes:
    fields = [
        (0x01, encoding.utf8(audience)),
        (0x02, bytes(lease_id)),
        (0x03, bytes(session)),
        (0x04, encoding.utf8(grantor)),
        (0x05, encoding.utf8(grantee)),
        (0x06, tools_bytes if tools_bytes is not None else encode_tools(tools)),
        (0x07, constraints_bytes if constraints_bytes is not None else jcs(constraints)),
        (0x08, u64(max_calls)),
    ]
    if max_arg_bytes is not None:
        fields.append((0x09, u64(max_arg_bytes)))
    fields += [(0x0A, i64(not_before)), (0x0B, i64(not_after))]
    return encode_record(fields)


def decode(data: bytes, cfg: Config = DEFAULT_CONFIG) -> dict:
    return decode_record(data, SCHEMA, cfg)


def digest_ref(record_bytes: bytes, alg: str = "sha-256") -> DigestRef:
    return ref_of(OBJECT_TYPE, record_bytes, alg)


# --- constraints (Section 8.3) ---------------------------------------------


def is_plain_relative_path(s) -> bool:
    if not isinstance(s, str) or s == "" or s.startswith("/") or "\\" in s or "\x00" in s:
        return False
    return all(seg not in ("", ".", "..") for seg in s.split("/"))


def _valid_pointer(p) -> bool:
    if not isinstance(p, str):
        return False
    if p == "":
        return True
    if not p.startswith("/"):
        return False
    i = 0
    while True:
        i = p.find("~", i)
        if i == -1:
            return True
        if p[i + 1:i + 2] not in ("0", "1"):
            return False
        i += 2


def validate_constraints(constraints, tool_names: Set[str]) -> None:
    """Grant-time validation (Section 8.3, 8.4 check 8). Failures are E_VALUE."""
    # SPEC-AMBIGUITY: 8.1/8.3: `constraints` that is valid JSON but not an
    # array has no stated error. We treat it as malformed (E_VALUE at check 8).
    if not isinstance(constraints, list):
        raise AabError(E_VALUE, "constraints is not an array")
    for c in constraints:
        if not isinstance(c, dict):
            raise AabError(E_VALUE, "constraint is not an object")
        op = c.get("op")
        if op not in OPS:
            raise AabError(E_VALUE, "unknown op %r" % (op,))
        # SPEC-AMBIGUITY: 8.3: which members are required per op is implicit.
        # We require pointer+op, value for every op except `absent`, and
        # reject `value` on `absent` as an unknown member.
        allowed = {"tool", "pointer", "op"} | ({"value"} if op != "absent" else set())
        extra = set(c) - allowed
        if extra:
            raise AabError(E_VALUE, "unknown member(s) %s" % sorted(extra))
        if "pointer" not in c or (op != "absent" and "value" not in c):
            raise AabError(E_VALUE, "missing required member")
        # SPEC-AMBIGUITY: 8.3: the pointer syntax is not validated by the
        # text; we require a valid RFC 6901 pointer.
        if not _valid_pointer(c["pointer"]):
            raise AabError(E_VALUE, "pointer is not an RFC 6901 JSON Pointer")
        if "tool" in c:
            if not isinstance(c["tool"], str):
                raise AabError(E_VALUE, "tool is not a string")
            # SPEC-AMBIGUITY: 8.3: a `tool` naming no tool in the lease makes the
            # constraint silently inert (fail-open on a typo). We reject it.
            if c["tool"] not in tool_names:
                raise AabError(E_VALUE, "constraint names a tool not in the lease")
        v = c.get("value")
        if op in ("prefix",) and not isinstance(v, str):
            raise AabError(E_VALUE, "prefix value is not a string")
        if op == "beneath" and not is_plain_relative_path(v):
            raise AabError(E_VALUE, "beneath value is not a plain relative path")
        if op == "in" and not isinstance(v, list):
            raise AabError(E_VALUE, "in value is not an array")
        if op == "max" and (isinstance(v, bool) or not isinstance(v, float)):
            raise AabError(E_VALUE, "max value is not a number")


_MISSING = object()


def resolve_pointer(doc, pointer: str):
    """RFC 6901 evaluation; returns ``_MISSING`` when it does not resolve."""
    if pointer == "":
        return doc
    cur = doc
    for tok in pointer[1:].split("/"):
        tok = tok.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict):
            if tok not in cur:
                return _MISSING
            cur = cur[tok]
        elif isinstance(cur, list):
            if tok == "-" or not tok.isdigit() or not tok.isascii() or (len(tok) > 1 and tok[0] == "0"):
                return _MISSING
            i = int(tok)
            if i >= len(cur):
                return _MISSING
            cur = cur[i]
        else:
            return _MISSING
    return cur


def beneath(value, root: str) -> bool:
    """The lexical ``beneath`` check of Section 8.3."""
    # SPEC-AMBIGUITY: 8.3: by the letter of the rule a path equal to the root
    # ("src" beneath "src") holds, because its first segments equal the
    # root's. Whether the root itself is "beneath" is not stated; we follow
    # the letter (holds).
    if not is_plain_relative_path(value):
        return False
    segs, rsegs = value.split("/"), root.split("/")
    return len(segs) >= len(rsegs) and segs[:len(rsegs)] == rsegs


def constraint_holds(c: dict, arguments) -> bool:
    got = resolve_pointer(arguments, c["pointer"])
    op = c["op"]
    if op == "absent":
        return got is _MISSING
    if got is _MISSING:
        return False
    v = c["value"]
    if op == "eq":
        return jcs(got) == jcs(v)
    if op == "prefix":
        return isinstance(got, str) and got.startswith(v)
    if op == "beneath":
        return beneath(got, v)
    if op == "in":
        return any(jcs(got) == jcs(x) for x in v)
    if op == "max":
        return isinstance(got, float) and not isinstance(got, bool) and got <= v
    raise AssertionError(op)


def check_constraints(constraints, tool_name: str, arguments) -> None:
    for c in constraints:
        if "tool" in c and c["tool"] != tool_name:
            continue
        if not constraint_holds(c, arguments):
            raise AabError(E_LEASE_CONSTRAINT, "constraint %s on %s violated" % (c["op"], c["pointer"]))


# --- grant verification (Section 8.4) ---------------------------------------


class GrantState:
    """Lease ids ever granted, and tool policy classification (8.4 checks 5, 7)."""

    def __init__(self, granted: Iterable[bytes] = (), forbidden_tools: Optional[Dict[Tuple[bytes, str], str]] = None):
        self.granted: Set[bytes] = set(granted)
        # (server identity bytes, name) -> "irreversible" | "privileged" | "shell"
        self.forbidden_tools = dict(forbidden_tools or {})


def check_lease_record(rec: dict, ctx: evidence.ApprovalContext, grants: GrantState) -> None:
    """Lease record checks 1-8 of Section 8.4 step 3."""
    st = ctx.state
    if rec["session"] not in st.open_sessions or rec["session"] != st.request_session:
        raise AabError(E_SESSION, "lease session not open or not the grant's session")
    if rec["audience"] != st.proxy_id:
        raise AabError(E_AUDIENCE, "audience %r" % rec["audience"])
    if not window_ok(rec["not_before"], rec["not_after"], MAX_WINDOW_MS):
        raise AabError(E_EXPIRED, "lease window invalid or longer than 8 hours")
    # SPEC-AMBIGUITY: 8.4 check 4: only expiry is checked at grant; a lease
    # whose not_before lies far in the future (a pre-signed lease) is
    # accepted. We apply the check as written.
    if st.now > rec["not_after"] + SKEW_MS:
        raise AabError(E_EXPIRED, "lease already expired")
    if rec["lease_id"] in grants.granted:
        raise AabError(E_REPLAY, "lease id granted before")
    for e in rec["tools"]:
        cur = st.current_fps.get((e.server.encode(), e.name))
        if cur is None or cur != e.fingerprint:
            raise AabError(E_FP_CHANGED, "entry fingerprint differs for %s" % e.name)
    for e in rec["tools"]:
        if (e.server.encode(), e.name) in grants.forbidden_tools:
            raise AabError(E_LEASE_SCOPE, "%s is %s" % (e.name, grants.forbidden_tools[(e.server.encode(), e.name)]))
    validate_constraints(rec["constraints"], {e.name for e in rec["tools"]})


def verify_grant(data: bytes, ctx: evidence.ApprovalContext, grants: GrantState) -> dict:
    """Section 8.4. On success the lease id is recorded permanently."""
    m = evidence.decode_container(data)                                   # step 1
    ref, rec = evidence.bind_record(m, OBJECT_TYPE, decode, ctx.state.cfg)  # step 2
    check_lease_record(rec, ctx, grants)                                  # step 3
    # SPEC-AMBIGUITY: 8.4 step 4 / 7.2 step 4: which action class a lease
    # grant needs is not defined. We require the grantor to be authorized
    # for the class of every tool in the lease.
    classes = [ctx.tool_classes.get(e.name) for e in rec["tools"]]
    # SPEC-AMBIGUITY: 8.4 steps 1 and 4 say "Step 1 of Section 7.3" and "the
    # remaining steps of Section 7.3", but 7.3 step 1 *is* 7.2 steps 1-4, so a
    # literal reading skips the credential check for device-key grants. We
    # run 7.2 step 4 for both profiles, then the profile's remaining steps.
    cred = evidence.lookup_credential(ctx, m[4], classes, rec["grantor"])  # step 4 (7.2 step 4)
    count = None
    if m[2] == evidence.WEBAUTHN:
        count = evidence.webauthn_tail(ctx, m, ref, cred)                 # 7.2 steps 5-8
    else:
        evidence.device_key_tail(ctx, m, cred)                            # 7.3 steps 2-8
    if rec["lease_id"] in grants.granted:
        raise AabError(E_REPLAY, "lease id granted concurrently")
    grants.granted.add(rec["lease_id"])
    if count is not None:
        cred.counter = count
    return {"record": rec, "digest": ref}


# --- enforcement (Section 8.2) ---------------------------------------------


class LeaseUsage:
    """Proxy-held budget counters and revocations (Section 8.2 rules 1 and 3)."""

    def __init__(self, calls: int = 0, arg_bytes: int = 0, revoked: bool = False):
        self.calls = calls
        self.arg_bytes = arg_bytes
        self.revoked = revoked


def enforce_call(rec: dict, usage: LeaseUsage, now: int, session: bytes, server: ServerIdentity,
                 name: str, current_fp: Optional[DigestRef], arguments, budget_mode: str = "reject",
                 agent_id: Optional[str] = None) -> str:
    """The checks of Section 8.2 rule 4. Returns ``"accept"`` or ``"escalate"``."""
    if usage.revoked:
        raise AabError(E_LEASE_REVOKED, "lease revoked")
    if session != rec["session"]:
        raise AabError(E_SESSION, "call session is not the lease session")
    # SPEC-AMBIGUITY: 8.2: the grantee (field 0x05) is never checked at
    # enforcement. We check it when the caller supplies the agent id, with
    # E_LEASE_SCOPE, right after the session check.
    if agent_id is not None and agent_id != rec["grantee"]:
        raise AabError(E_LEASE_SCOPE, "agent is not the grantee")
    if now < rec["not_before"] - SKEW_MS or now > rec["not_after"] + SKEW_MS:
        raise AabError(E_EXPIRED, "outside the lease window")
    entry = next((e for e in rec["tools"] if e.server == server and e.name == name), None)
    if entry is None:
        raise AabError(E_LEASE_SCOPE, "tool not in the lease tool set")
    if current_fp is None or current_fp != entry.fingerprint:
        raise AabError(E_FP_CHANGED, "tool fingerprint differs from the lease entry")
    check_constraints(rec["constraints"], name, arguments)
    n_bytes = len(jcs(arguments))
    over = usage.calls + 1 > rec["max_calls"] or (
        rec.get("max_arg_bytes") is not None and usage.arg_bytes + n_bytes > rec["max_arg_bytes"])
    if over:
        if budget_mode == "escalate":
            return "escalate"
        raise AabError(E_LEASE_BUDGET, "budget exceeded")
    usage.calls += 1
    usage.arg_bytes += n_bytes
    return "accept"
