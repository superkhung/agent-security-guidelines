# SPDX-License-Identifier: Apache-2.0
"""Action log records, hash chain, checkpoints and the auditor (Section 9)."""

from __future__ import annotations

from typing import Dict, Iterable, List, NamedTuple, Optional

from . import evidence, sigs
from .encoding import i64, lp, u8, u64
from .errors import (
    AabError,
    E_LOG_CHAIN,
    E_LOG_CHECKPOINT,
    E_LOG_ID,
    E_LOG_INDEX,
    E_LOG_ROLLBACK,
    E_LOG_SESSION,
    E_MISSING_FIELD,
    E_VALUE,
    Unsupported,
)
from .records import (
    DEFAULT_CONFIG,
    Config,
    DigestRef,
    Field,
    decode_record,
    encode_record,
    f_enum8,
    f_i64,
    f_id16,
    f_ref,
    f_u64,
    ref_of,
    domain_prefix,
    HASHES,
)

RECORD_TYPES = {0: "session open", 1: "action request", 2: "action decision", 3: "action result",
                4: "lease grant", 5: "lease revoke", 6: "session close", 7: "kill switch"}
DECISIONS = {1: "allow by policy", 2: "deny by policy", 3: "approved by person", 4: "denied by person",
             5: "allowed under lease", 6: "rejected by verification"}

SCHEMA = {
    0x01: Field("log_id", True, f_id16),
    0x02: Field("index", True, f_u64),
    0x03: Field("time", True, f_i64),
    0x04: Field("session", True, f_id16),
    0x05: Field("sequence", True, f_u64),
    0x06: Field("type", True, f_enum8(RECORD_TYPES)),
    0x07: Field("decision", False, f_enum8(DECISIONS)),
    0x08: Field("action", False, f_ref("action")),
    0x09: Field("credential", False, f_ref("credential")),
    0x0A: Field("lease_id", False, f_id16),
    0x0B: Field("payload", False, f_ref("payload")),
    0x0C: Field("trace_id", False, f_id16),
}

CHECKPOINT_SCHEMA = {
    0x01: Field("log_id", True, f_id16),
    0x02: Field("size", True, f_u64),
    # SPEC-AMBIGUITY: 9.3: the head is a digest reference whose object type
    # is "log-link" or "log-genesis" (for size 0); the expected algorithm is
    # the one configured for "log-link".
    0x03: Field("head", True, f_ref("log-link")),
    0x04: Field("time", True, f_i64),
}


def build(log_id: bytes, index: int, time: int, session: bytes, sequence: int, rtype: int,
          decision: Optional[int] = None, action: Optional[DigestRef] = None,
          credential: Optional[DigestRef] = None, lease_id: Optional[bytes] = None,
          payload: Optional[DigestRef] = None, trace_id: Optional[bytes] = None) -> bytes:
    fields = [(0x01, log_id), (0x02, u64(index)), (0x03, i64(time)), (0x04, session),
              (0x05, u64(sequence)), (0x06, u8(rtype))]
    if decision is not None:
        fields.append((0x07, u8(decision)))
    if action is not None:
        fields.append((0x08, action.encode()))
    if credential is not None:
        fields.append((0x09, credential.encode()))
    if lease_id is not None:
        fields.append((0x0A, lease_id))
    if payload is not None:
        fields.append((0x0B, payload.encode()))
    if trace_id is not None:
        fields.append((0x0C, trace_id))
    return encode_record(fields)


def decode(data: bytes, cfg: Config = DEFAULT_CONFIG) -> dict:
    rec = decode_record(data, SCHEMA, cfg)
    t = rec["type"]
    if t == 2 and "decision" not in rec:
        raise AabError(E_MISSING_FIELD, "type-2 record without decision")
    if t != 2 and "decision" in rec:
        # SPEC-AMBIGUITY: 9.1: "absent for other types" has no error code. We
        # use E_VALUE.
        raise AabError(E_VALUE, "decision present in a type-%d record" % t)
    # SPEC-AMBIGUITY: 9.1: the session sequence rule ("0 for types 0, 4-7";
    # sequences start at 1, Section 6.2) has no error code. We use E_VALUE.
    if t in (1, 2, 3) and rec["sequence"] == 0:
        raise AabError(E_VALUE, "type-%d record with sequence 0" % t)
    if t not in (1, 2, 3) and rec["sequence"] != 0:
        raise AabError(E_VALUE, "type-%d record with non-zero sequence" % t)
    # SPEC-AMBIGUITY: 9.1 vs 8.2 rule 2: calls under a lease "MUST be logged
    # with the lease id", and lease grant/revoke records are meaningless
    # without one, yet field 0x0A is OPTIONAL for every type. We require it
    # for types 4 and 5 and for decision 5 (E_MISSING_FIELD).
    if (t in (4, 5) or rec.get("decision") == 5) and "lease_id" not in rec:
        raise AabError(E_MISSING_FIELD, "lease id required for this record")
    return rec


def credential_ref(credential_id: bytes, alg: str = "sha-256") -> DigestRef:
    return ref_of("credential", lp(credential_id), alg)


def payload_ref(payload: bytes, alg: str = "sha-256") -> DigestRef:
    return ref_of("payload", lp(payload), alg)


# --- chain (Section 9.2) ----------------------------------------------------


def head0(log_id: bytes, alg: str = "sha-256") -> bytes:
    return HASHES[alg][0](domain_prefix("log-genesis", alg) + lp(log_id)).digest()


def next_head(head: bytes, record: bytes, alg: str = "sha-256") -> bytes:
    return HASHES[alg][0](domain_prefix("log-link", alg) + lp(head) + lp(record)).digest()


def heads(log_id: bytes, records: Iterable[bytes], alg: str = "sha-256") -> List[bytes]:
    """``[head_0, head_1, ..., head_n]``."""
    out = [head0(log_id, alg)]
    for r in records:
        out.append(next_head(out[-1], r, alg))
    return out


class LogWriter:
    """Appends records (Section 9.2, last paragraph)."""

    def __init__(self, log_id: bytes, alg: str = "sha-256"):
        self.log_id = log_id
        self.alg = alg
        self.records: List[bytes] = []
        self.head = head0(log_id, alg)

    def append(self, record: bytes, cfg: Config = DEFAULT_CONFIG) -> bytes:
        rec = decode(record, cfg)
        # SPEC-AMBIGUITY: 9.2: the append rejections have no error codes; we
        # use E_LOG_ID and E_LOG_INDEX as the auditor does.
        if rec["log_id"] != self.log_id:
            raise AabError(E_LOG_ID, "record of another log")
        if rec["index"] != len(self.records):
            raise AabError(E_LOG_INDEX, "index %d, next is %d" % (rec["index"], len(self.records)))
        self.records.append(bytes(record))
        self.head = next_head(self.head, record, self.alg)
        return self.head


# --- checkpoints (Section 9.3) ---------------------------------------------


def build_checkpoint(log_id: bytes, size: int, head: DigestRef, time: int) -> bytes:
    return encode_record([(0x01, log_id), (0x02, u64(size)), (0x03, head.encode()), (0x04, i64(time))])


def decode_checkpoint(data: bytes, cfg: Config = DEFAULT_CONFIG) -> dict:
    return decode_record(data, CHECKPOINT_SCHEMA, cfg)


def checkpoint_ref(data: bytes, alg: str = "sha-256") -> DigestRef:
    return ref_of("checkpoint", data, alg)


class AnchoredCheckpoint(NamedTuple):
    """A checkpoint the auditor holds from an independent party (Section 9.4)."""

    # SPEC-AMBIGUITY: 9.3/9.4: there is no wire format for a signed checkpoint
    # (record + COSE_Sign1 + optional RFC 3161 token), no COSE header profile
    # (alg set, kid), no signature algorithm list for the log key, and no rule
    # for how the auditor obtains the log key. We use this tuple; the
    # COSE_Sign1 payload must be the checkpoint digest reference, `alg` must be
    # in the protected header, and the algorithms of Section 7.5 except RS256
    # apply (as for device-key).
    record: bytes
    cose_sign1: bytes
    timestamp_token: Optional[bytes] = None


def verify_checkpoint_signature(cp: AnchoredCheckpoint, log_key: dict, backend: sigs.SignatureBackend,
                                cfg: Config) -> None:
    prot_b, prot, unprot, payload, sig = evidence.decode_cose_sign1(cp.cose_sign1, E_LOG_CHECKPOINT)
    alg = prot.get(1)
    if (alg not in sigs.EQUIVALENT or 1 in unprot or log_key.get("alg") not in sigs.EQUIVALENT
            or sigs.EQUIVALENT[alg] != sigs.EQUIVALENT[log_key["alg"]]):
        raise AabError(E_LOG_CHECKPOINT, "checkpoint alg missing or not the log key's")
    if payload != checkpoint_ref(cp.record, cfg.alg("checkpoint")).encode():
        raise AabError(E_LOG_CHECKPOINT, "COSE payload is not the checkpoint digest reference")
    try:
        sigs.verify(log_key, evidence.sig_structure(prot_b, payload), sig, "checkpoint", backend)
    except sigs.SignatureFailure as exc:
        raise AabError(E_LOG_CHECKPOINT, str(exc))
    if cp.timestamp_token is not None:
        raise Unsupported("RFC 3161 time-stamp token validation is not implemented")


# --- auditor (Section 9.5) -------------------------------------------------


def audit(records: List[bytes], anchored: List[AnchoredCheckpoint], log_id: bytes, log_key: dict,
          backend: Optional[sigs.SignatureBackend] = None, cfg: Config = DEFAULT_CONFIG,
          payload_store: Optional[Dict[bytes, bytes]] = None) -> dict:
    """Section 9.5. Stops at the first error (Section 10).

    Returns ``{"error": code|None, "verified_up_to": k|None,
    "unanchored": [indices], "payload_missing": [indices]}``.
    ``anchored`` is in the order the checkpoints were anchored.
    """
    # SPEC-AMBIGUITY: 9.5: the reference log id when there is no anchored
    # checkpoint is not defined ("the log id of the anchored checkpoints").
    # The caller supplies the expected log id.
    # SPEC-AMBIGUITY: 9.5/10: the auditor must report "any errors", while
    # Section 10 says to report the first. We stop at the first error and then
    # report no verified range.
    # SPEC-AMBIGUITY: 9.5 step 4: "the order the checkpoints were anchored" is
    # external metadata (not the checkpoint `time` field); we take list order.
    # Since step 3 already checks every head against the same records, the
    # "extends" condition can never fail here, and a later but smaller
    # checkpoint that is consistent with the records is still E_LOG_ROLLBACK.
    backend = backend or sigs.NullBackend()
    alg = cfg.alg("log-link")
    decoded = []
    for pos, r in enumerate(records):          # step 1, record by record
        # SPEC-AMBIGUITY: 9.5 step 1: "every record decodes ... and then its
        # index" can be read per record or as two passes. We go per record:
        # decode, log id, index.
        try:
            rec = decode(r, cfg)
        except AabError as exc:
            return _fail(exc.code)
        if rec["log_id"] != log_id:
            return _fail(E_LOG_ID)
        if rec["index"] != pos:
            return _fail(E_LOG_INDEX)
        decoded.append(rec)
    hs = heads(log_id, records, alg)           # step 2
    cps = []
    for cp in anchored:                        # step 3
        try:
            c = decode_checkpoint(cp.record, cfg)
        except AabError:
            # SPEC-AMBIGUITY: 9.5: a checkpoint that does not decode has no
            # stated code; we use E_LOG_CHECKPOINT.
            return _fail(E_LOG_CHECKPOINT)
        if c["log_id"] != log_id:
            # SPEC-AMBIGUITY: 9.5: an anchored checkpoint of another log id.
            return _fail(E_LOG_ID)
        verify_checkpoint_signature(cp, log_key, backend, cfg)
        if c["size"] > len(records) or c["head"].digest != hs[c["size"]]:
            return _fail(E_LOG_CHAIN)
        cps.append(c)
    for a, b in zip(cps, cps[1:]):             # step 4
        if b["size"] < a["size"]:
            return _fail(E_LOG_ROLLBACK)
    requests = set()                           # step 5
    for rec in decoded:
        key = (rec["session"], rec["sequence"])
        if rec["type"] == 1:
            if key in requests:
                return _fail(E_LOG_SESSION)
            requests.add(key)
        elif rec["type"] in (2, 3) and key not in requests:
            return _fail(E_LOG_SESSION)
    latest = cps[-1]["size"] if cps else 0     # step 6
    missing = []
    if payload_store is not None:
        for i, rec in enumerate(decoded):
            if "payload" in rec and rec["payload"].digest not in payload_store:
                missing.append(i)
    return {"error": None, "verified_up_to": latest - 1 if latest else None,
            "unanchored": list(range(latest, len(records))), "payload_missing": missing}


def _fail(code: str) -> dict:
    return {"error": code, "verified_up_to": None, "unanchored": None, "payload_missing": None}
