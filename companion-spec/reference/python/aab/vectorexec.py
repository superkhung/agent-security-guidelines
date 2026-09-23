# SPDX-License-Identifier: Apache-2.0
"""Execute one test vector file (Section 12.2) against this implementation.

``execute(vector)`` returns an *outcome* dict. The runner compares it with
``vector["expected"]``: every key of ``expected`` (except ``status``,
``source`` and cross-vector keys) must be present in the outcome with an
equal value. The format extensions are described in
companion-spec/reference/README.md.
"""

# SPEC-AMBIGUITY: 12.2: the file format fixes `id`, `group`, `input`,
# `expected.result` and `expected.error` only. Outcomes such as "digests
# differ", "verified up to index k", "harness reports non-conformance" or
# "escalation" have no representation; exact-byte fields have no naming rule
# when an input has several of them; verifier state (time, sessions, pending
# entries, credentials) has no schema; and there is no status for a value
# produced by one implementation only. The keys used here are a proposal.

from __future__ import annotations

from typing import Optional

from . import action, evidence, fingerprint, identity, jsonstrict, lease, log, records, sigs
from .errors import AabError, CryptoUnavailable, Unsupported
from .jcs import jcs


_BACKEND = [sigs.NullBackend()]


def _hex(s: Optional[str]) -> Optional[bytes]:
    return None if s is None else bytes.fromhex(s)


def _text_or_hex(d: dict, base: str):
    """Return the exact bytes of ``<base>_hex`` or ``<base>_json_text``."""
    if base + "_hex" in d:
        return bytes.fromhex(d[base + "_hex"])
    if base + "_json_text" in d:
        return d[base + "_json_text"].encode("utf-8", errors="surrogatepass")
    return None


def _server(d: dict) -> identity.ServerIdentity:
    return identity.make(d["kind"], d["id"])


def _cfg(ctx: dict) -> records.Config:
    return records.Config(ctx.get("algs"))


def _cose_key(d: dict) -> dict:
    out = {}
    for k, v in d.items():
        if k.endswith("_hex"):
            out[k[:-4]] = bytes.fromhex(v)
        else:
            out[k] = v
    return out


def build_state(ctx: dict) -> action.VerifierState:
    pending = {(bytes.fromhex(p["session"]), p["sequence"]): bytes.fromhex(p["digest_ref_hex"])
               for p in ctx.get("pending", [])}
    fps = {}
    for f in ctx.get("current_fingerprints", []):
        fps[(_server(f["server"]).encode(), f["name"])] = records.parse_ref_text(f["fingerprint"])
    return action.VerifierState(
        proxy_id=ctx.get("proxy_id", ""), now=ctx.get("now", 0),
        open_sessions=[bytes.fromhex(s) for s in ctx.get("open_sessions", [])],
        request_session=_hex(ctx.get("request_session")), pending=pending, current_fps=fps,
        cfg=_cfg(ctx))


def build_approval_context(ctx: dict) -> evidence.ApprovalContext:
    creds = []
    for c in ctx.get("credentials", []):
        creds.append(evidence.Credential(
            bytes.fromhex(c["id_hex"]), c["approver"], _cose_key(c["cose_key"]),
            user_handle=_hex(c.get("user_handle_hex")), be=c.get("be", False),
            counter=c.get("counter", 0), classes=c.get("classes", []), revoked=c.get("revoked", False)))
    return evidence.ApprovalContext(
        build_state(ctx), creds, tool_classes=ctx.get("tool_classes"), rp_id=ctx.get("rp_id", ""),
        allowed_origins=ctx.get("allowed_origins", []), forbid_synced=ctx.get("forbid_synced", False),
        accept_rs256=ctx.get("accept_rs256", False), backend=_BACKEND[0])


def _accept(**kw) -> dict:
    kw["result"] = "accept"
    return kw


# --- handlers ---------------------------------------------------------------


def h_string(v, inp, ctx):
    from .encoding import check_string
    check_string(_text_or_hex(v, "input"))
    return _accept()


def h_json(v, inp, ctx):
    data = _text_or_hex(v, "input")
    out = jcs(jsonstrict.parse(data))
    return _accept(canonical_hex=out.hex(), canonical_text=out.decode("utf-8"))


_DECODERS = {
    "tool-fp": fingerprint.decode, "action": action.decode, "lease": lease.decode,
    "log": log.decode, "checkpoint": log.decode_checkpoint,
}


def h_record(v, inp, ctx):
    rtype = inp["record_type"]
    data = bytes.fromhex(inp["record_hex"])
    _DECODERS[rtype](data, _cfg(ctx))
    out = _accept()
    if rtype != "log":
        out["digest"] = records.ref_of(rtype, data, v.get("alg", "sha-256")).text()
    return out


def h_digest_ref(v, inp, ctx):
    ref = records.decode_digest_ref(bytes.fromhex(inp["ref_hex"]), inp["expected_alg"])
    return _accept(digest=ref.text())


def h_server_identity(v, inp, ctx):
    if "identity_hex" in inp:
        sid = identity.decode(bytes.fromhex(inp["identity_hex"]))
    else:
        sid = _server(inp)
    return _accept(identity_hex=sid.encode().hex(), id=sid.id)


def _tool_value(inp):
    b = _text_or_hex(inp, "tool")
    return jsonstrict.parse(b) if b is not None else inp["tool"]


def h_tool_fp(v, inp, ctx):
    sid = _server(inp["server"])
    rec = fingerprint.record(sid, _tool_value(inp))
    return _accept(digest=records.ref_of("tool-fp", rec, v.get("alg", "sha-256")).text(),
                   record_hex=rec.hex())


def h_fp_comparator(v, inp, ctx):
    sid = _server(inp["server"])
    comp = fingerprint.Comparator(v.get("alg", "sha-256"))
    comp.approve(sid, inp["approved_tool"])
    cache = inp["cached_tool"]
    steps = []
    for st in inp["steps"]:
        if st["op"] == "server_changes":
            live = st["tool"]
            steps.append({"result": "ok"})
        elif st["op"] == "refresh":
            cache = live
            steps.append({"result": "ok"})
        elif st["op"] == "deliver":
            steps.append(_run(lambda: {"result": comp.deliver(sid, cache)}))
    return {"result": "accept", "steps": steps}


def _action_from_input(inp, cfg):
    if "request_json_text" in inp or "request_hex" in inp:
        req = action.parse_request(_text_or_hex(inp, "request"))
        name, args_bytes = req["name"], req["arguments_bytes"]
    else:
        name = inp["name"]
        args_bytes = action.canonical_arguments(jsonstrict.parse(_text_or_hex(inp, "arguments")))
    return action.build(
        inp["audience"], bytes.fromhex(inp["session_hex"]), inp["sequence"], _server(inp["server"]),
        name, records.parse_ref_text(inp["fingerprint"]), None, inp["not_before"], inp["not_after"],
        approver=inp.get("approver"), arguments_bytes=args_bytes)


def h_action(v, inp, ctx):
    rec = _action_from_input(inp, _cfg(ctx))
    return _accept(digest=action.digest_ref(rec, v.get("alg", "sha-256")).text(), record_hex=rec.hex())


def h_request(v, inp, ctx):
    req = action.parse_request(_text_or_hex(inp, "body"), inp.get("headers"))
    return _accept(arguments_hex=req["arguments_bytes"].hex())


def h_forwarding(v, inp, ctx):
    rec = action.decode(bytes.fromhex(inp["record_hex"]), _cfg(ctx))
    req = action.parse_request(_text_or_hex(inp, "request"), inp.get("headers"))
    body = action.forward_body(rec, req["id"])
    return _accept(forwarded_hex=body.hex(), forwarded_text=body.decode("utf-8"),
                   forwarded_headers=action.forward_headers(rec),
                   arguments_equal_field_07=(req["arguments_bytes"] == rec["_raw"][0x07]))


def h_tool_server(v, inp, ctx):
    rec = action.decode(bytes.fromhex(inp["record_hex"]), _cfg(ctx))
    action.tool_server_check(_text_or_hex(inp, "received"), rec)
    return _accept()


def h_harness(v, inp, ctx):
    rec = action.decode(bytes.fromhex(inp["record_hex"]), _cfg(ctx))
    verdict = action.forwarding_harness(rec, _text_or_hex(inp, "bytes_at_tool"))
    return {"result": "accept" if verdict == "conformant" else "reject", "harness": verdict}


def h_evidence(v, inp, ctx):
    actx = build_approval_context(ctx)
    presentations = inp.get("presentations") or [inp["evidence_hex"]]
    outs = [_run(lambda e=e: (evidence.verify_action(bytes.fromhex(e), actx), _accept())[1])
            for e in presentations]
    if "presentations" in inp:
        return {"result": outs[-1]["result"], "presentations": outs}
    return outs[0]


def _grant_state(ctx):
    forb = {(_server(f["server"]).encode(), f["name"]): f["class"] for f in ctx.get("forbidden_tools", [])}
    return lease.GrantState([bytes.fromhex(x) for x in ctx.get("granted_leases", [])], forb)


def h_lease_grant(v, inp, ctx):
    actx = build_approval_context(ctx)
    lease.verify_grant(bytes.fromhex(inp["evidence_hex"]), actx, _grant_state(ctx))
    return _accept()


def h_lease_call(v, inp, ctx):
    rec = lease.decode(bytes.fromhex(inp["lease_hex"]), _cfg(ctx))
    u = inp.get("usage", {})
    usage = lease.LeaseUsage(u.get("calls", 0), u.get("arg_bytes", 0), u.get("revoked", False))
    outs = []
    for call in inp["calls"]:
        def one(call=call):
            fp = call.get("current_fingerprint")
            res = lease.enforce_call(
                rec, usage, call["now"], bytes.fromhex(call["session_hex"]), _server(call["server"]),
                call["name"], records.parse_ref_text(fp) if fp else None,
                jsonstrict.parse(call["arguments_json_text"].encode("utf-8")),
                budget_mode=call.get("budget_mode", "reject"), agent_id=call.get("agent_id"))
            return {"result": res}
        outs.append(_run(one))
    last = outs[-1]
    out = dict(last)
    out["calls"] = outs
    return out


def h_log_audit(v, inp, ctx):
    anchored = [log.AnchoredCheckpoint(bytes.fromhex(a["record_hex"]), bytes.fromhex(a["cose_sign1_hex"]),
                                       _hex(a.get("timestamp_token_hex"))) for a in inp.get("anchored", [])]
    store = None
    if "payload_store" in inp:
        store = {records.parse_ref_text(p).digest: b"" for p in inp["payload_store"]}
    res = log.audit([bytes.fromhex(r) for r in inp["records_hex"]], anchored, bytes.fromhex(inp["log_id_hex"]),
                    _cose_key(inp.get("log_key", {})), backend=_BACKEND[0], cfg=_cfg(ctx),
                    payload_store=store)
    if res["error"]:
        return {"result": "reject", "error": res["error"]}
    out = _accept(verified_up_to=res["verified_up_to"], unanchored=res["unanchored"])
    if store is not None:
        out["payload_missing"] = res["payload_missing"]
    return out


HANDLERS = {
    "string": h_string, "json": h_json, "record": h_record, "digest-ref": h_digest_ref,
    "server-identity": h_server_identity, "tool-fp": h_tool_fp, "fp-comparator": h_fp_comparator,
    "action": h_action, "request": h_request, "forwarding": h_forwarding, "tool-server": h_tool_server,
    "harness": h_harness, "evidence": h_evidence, "lease-grant": h_lease_grant,
    "lease-call": h_lease_call, "log-audit": h_log_audit,
}


def _run(fn) -> dict:
    try:
        return fn()
    except AabError as exc:
        return {"result": "reject", "error": exc.code, "detail": exc.detail}
    except CryptoUnavailable as exc:
        return {"result": "needs-crypto", "detail": str(exc)}
    except Unsupported as exc:
        return {"result": "unsupported", "detail": str(exc)}


def execute(vector: dict, backend: Optional[sigs.SignatureBackend] = None) -> dict:
    """Run one vector (or each of its ``cases``) and return the outcome.

    ``backend`` is the signature backend; the default raises
    ``CryptoUnavailable`` at every signature step.
    """
    prev = _BACKEND[0]
    _BACKEND[0] = backend or sigs.NullBackend()
    try:
        return _execute(vector)
    finally:
        _BACKEND[0] = prev


def _execute(vector: dict) -> dict:
    handler = HANDLERS[vector["object"]]
    inp = vector.get("input", {})
    ctx = vector.get("context", {})
    if "cases" in inp:
        outs = []
        for case in inp["cases"]:
            sub = dict(vector)
            sub["input"] = case
            sub.update({k: case[k] for k in ("input_hex", "input_json_text") if k in case})
            outs.append(_execute(sub))
        keys = [o.get("digest") or o.get("canonical_hex") or o.get("identity_hex") for o in outs]
        res = {"result": "accept" if all(o["result"] == "accept" for o in outs) else "reject",
               "cases": outs}
        if all(k is not None for k in keys):
            res["all_equal"] = len(set(keys)) == 1
            res["all_distinct"] = len(set(keys)) == len(keys)
        return res
    return _run(lambda: handler(vector, inp, ctx))
