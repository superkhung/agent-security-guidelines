# SPDX-License-Identifier: Apache-2.0
"""A minimal proxy that ties Sections 5, 6, 7 and 9 together (E2E vectors).

It is not a production proxy: one tool server per tool name, no transport,
no policy language. Every action is sent for per-action WebAuthn/device-key
approval. It exists so that the end-to-end vectors (Appendix B.8) exercise
fingerprint approval, action digest, approval evidence, forwarding and the
log in one run.
"""

from __future__ import annotations

from typing import Dict, Tuple

from . import action, cbor, evidence, fingerprint, jsonstrict, log, records
from .errors import AabError, E_FP_CHANGED, E_JSON
from .identity import ServerIdentity
from .records import DigestRef

DECISION_APPROVED, DECISION_REJECTED = 3, 6


class Proxy:
    def __init__(self, ctx: evidence.ApprovalContext, log_id: bytes, window_ms: int = 120_000):
        self.ctx = ctx
        self.state = ctx.state
        self.window_ms = window_ms
        self.comparator = fingerprint.Comparator()
        self.defs: Dict[str, Tuple[ServerIdentity, dict]] = {}   # name -> (server, current definition)
        self.next_seq: Dict[bytes, int] = {}
        self.actions: Dict[Tuple[bytes, int], dict] = {}          # (session, seq) -> decoded record
        self.writer = log.LogWriter(log_id)

    # --- log ---------------------------------------------------------------

    def _log(self, now: int, session: bytes, seq: int, rtype: int, **kw) -> None:
        rec = log.build(self.writer.log_id, len(self.writer.records), now, session, seq, rtype, **kw)
        self.writer.append(rec)

    # --- sessions ----------------------------------------------------------

    def open_session(self, session: bytes, now: int) -> None:
        self.state.open_sessions.add(session)
        self.next_seq[session] = 1
        self._log(now, session, 0, 0)

    def close_session(self, session: bytes, now: int) -> None:
        self.state.open_sessions.discard(session)
        self._log(now, session, 0, 6)

    # --- tools (Section 5.4) ------------------------------------------------

    def tools_list(self, server: ServerIdentity, body: bytes) -> Dict[str, str]:
        """Compare every delivered definition with its approved fingerprint."""
        msg = jsonstrict.parse(body)
        tools = msg.get("result", {}).get("tools") if isinstance(msg, dict) else None
        if not isinstance(tools, list):
            raise AabError(E_JSON, "not a tools/list result")
        out = {}
        for tool in tools:
            self.defs[tool["name"]] = (server, tool)
            self.state.current_fps[(server.encode(), tool["name"])] = fingerprint.fingerprint(server, tool)
            try:
                out[tool["name"]] = self.comparator.deliver(server, tool)
            except AabError as exc:
                out[tool["name"]] = exc.code
        return out

    def approve_tool(self, name: str) -> DigestRef:
        server, tool = self.defs[name]
        return self.comparator.approve(server, tool)

    # --- actions (Sections 6 and 7) ------------------------------------------

    def call(self, session: bytes, body: bytes, now: int) -> dict:
        """Evaluate a tools/call. Returns the challenge, or raises AabError."""
        req = action.parse_request(body)
        seq = self.next_seq[session]
        self.next_seq[session] = seq + 1
        server, _ = self.defs[req["name"]]
        key = (server.encode(), req["name"])
        approved = self.comparator.approved.get(key)
        if approved is None:
            raise ValueError("tool %r has no approved fingerprint (Section 5.4: new tool)" % req["name"])
        rec_bytes = action.build(self.state.proxy_id, session, seq, server, req["name"], approved,
                                 None, now, now + self.window_ms, arguments_bytes=req["arguments_bytes"])
        ref = action.digest_ref(rec_bytes)
        self.actions[(session, seq)] = {"record": rec_bytes, "digest": ref, "id": req["id"]}
        self._log(now, session, seq, 1, action=ref)
        # SPEC-AMBIGUITY: 6.2/6.4 check 6 (F-42): the spec checks the fingerprint only
        # when evidence is verified. We also check it before issuing a
        # challenge, so no person is asked to approve a call to a changed tool.
        if self.state.current_fps.get(key) != approved:
            self._log(now, session, seq, 2, decision=DECISION_REJECTED, action=ref)
            raise AabError(E_FP_CHANGED, "tool fingerprint changed since approval")
        self.state.pending[(session, seq)] = ref.encode()
        return {"sequence": seq, "record": rec_bytes, "digest": ref}

    def present(self, session: bytes, seq: int, evidence_bytes: bytes, now: int) -> bytes:
        """Verify evidence for the request (session, seq); return the forwarded body.

        The decision is logged under the sequence of the request being
        evaluated, whatever sequence the presented record carries.
        """
        # SPEC-AMBIGUITY: 6.2 rule 1 / 9.1 (F-43): when evidence for an earlier
        # action is presented again for a retry, the spec does not say which
        # sequence and action digest the decision record carries. We log it
        # under the retry's own sequence and record digest.
        self.state.now = now
        self.state.request_session = session
        entry = self.actions[(session, seq)]
        try:
            out = evidence.verify_action(evidence_bytes, self.ctx)
        except AabError:
            self._log(now, session, seq, 2, decision=DECISION_REJECTED, action=entry["digest"])
            raise
        cred_id = cbor.decode(evidence_bytes)[4]
        self._log(now, session, seq, 2, decision=DECISION_APPROVED, action=out["digest"],
                  credential=log.credential_ref(cred_id))
        # Section 6.3 rule 3: forward what the record says, not the agent's bytes.
        return action.forward_body(out["record"], entry["id"])

    def result(self, session: bytes, seq: int, payload: bytes, now: int) -> None:
        """Log the tool's result; only its digest enters the chain (Section 14)."""
        self._log(now, session, seq, 3, action=self.actions[(session, seq)]["digest"],
                  payload=log.payload_ref(payload))

    # --- checkpoints (Section 9.3) --------------------------------------------

    def checkpoint(self, now: int) -> bytes:
        """The checkpoint record over the log so far (to be signed by the KMS)."""
        head = records.DigestRef("sha-256", self.writer.head)
        return log.build_checkpoint(self.writer.log_id, len(self.writer.records), head, now)
