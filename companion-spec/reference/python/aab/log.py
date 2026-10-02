# SPDX-License-Identifier: Apache-2.0
"""Action log records, hash chain, checkpoints and the auditor (Section 9)."""

from __future__ import annotations

from typing import Dict, Iterable, List, NamedTuple, Optional

from . import cbor, evidence, sigs
from .encoding import i64, lp, u8, u64
from .errors import (
    AabError,
    E_ALG_MISMATCH,
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
    WIRE_VERSION,
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
    # The head uses the log's hash algorithm (Section 9.6).
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


class LogKey(NamedTuple):
    """One log key in the auditor's configuration (Section 9.6)."""

    cose_key: dict
    not_before: int
    not_after: int


class LogTrust(NamedTuple):
    """The auditor's configuration for one log id (Section 9.6)."""

    alg: str                    # the log's hash algorithm, fixed at genesis
    keys: Dict[bytes, LogKey]   # kid -> key


class Bundle(NamedTuple):
    """A signed checkpoint bundle (Section 9.3)."""

    checkpoint: bytes
    cose_sign1: bytes
    timestamp: Optional[bytes] = None


_BUNDLE_KEYS = {1: str, 2: bytes, 3: bytes, 4: bytes}


def encode_bundle(checkpoint: bytes, cose_sign1: bytes, timestamp: Optional[bytes] = None) -> bytes:
    m = {1: WIRE_VERSION, 2: checkpoint, 3: cose_sign1}
    if timestamp is not None:
        m[4] = timestamp
    return cbor.encode(m)


def decode_bundle(data: bytes) -> Bundle:
    """Section 9.3: deterministic CBOR map; every failure is E_LOG_CHECKPOINT."""
    try:
        m = cbor.decode(data, deterministic=True)
    except cbor.CborError as exc:
        raise AabError(E_LOG_CHECKPOINT, "bundle: %s" % exc)
    if not isinstance(m, dict):
        raise AabError(E_LOG_CHECKPOINT, "bundle is not a map")
    for k, v in m.items():
        if k not in _BUNDLE_KEYS or not isinstance(v, _BUNDLE_KEYS[k]):
            raise AabError(E_LOG_CHECKPOINT, "bundle key %r unknown or of the wrong type" % (k,))
    if not {1, 2, 3} <= set(m):
        raise AabError(E_LOG_CHECKPOINT, "bundle misses keys %s" % sorted({1, 2, 3} - set(m)))
    if m[1] != WIRE_VERSION:
        raise AabError(E_LOG_CHECKPOINT, "bundle version is not %r" % WIRE_VERSION)
    return Bundle(m[2], m[3], m.get(4))


def verify_checkpoint_signature(bundle: Bundle, cp: dict, trust: LogTrust, backend: sigs.SignatureBackend) -> None:
    """Section 9.5 step 3, the COSE and signature part. Every failure is E_LOG_CHECKPOINT."""
    prot_b, prot, unprot, payload, sig = evidence.decode_cose_sign1(bundle.cose_sign1, E_LOG_CHECKPOINT)
    if unprot:
        raise AabError(E_LOG_CHECKPOINT, "unprotected header is not empty")
    if 1 not in prot or 4 not in prot or not isinstance(prot[4], bytes):
        raise AabError(E_LOG_CHECKPOINT, "alg and kid must be in the protected header")
    entry = trust.keys.get(prot[4])
    if entry is None:
        raise AabError(E_LOG_CHECKPOINT, "kid is not a key of this log")
    alg, reg = prot[1], entry.cose_key.get("alg")
    if not isinstance(alg, int) or isinstance(alg, bool):
        raise AabError(E_LOG_CHECKPOINT, "checkpoint alg is not an integer")
    if (alg not in sigs.EQUIVALENT or reg not in sigs.EQUIVALENT or sigs.EQUIVALENT[alg] != sigs.EQUIVALENT[reg]
            or sigs.EQUIVALENT[reg] == sigs.RS256):
        raise AabError(E_LOG_CHECKPOINT, "checkpoint alg %r not allowed or not the key's" % (alg,))
    if payload != checkpoint_ref(bundle.checkpoint, trust.alg).encode():
        raise AabError(E_LOG_CHECKPOINT, "COSE payload is not the checkpoint digest reference")
    if not entry.not_before <= cp["time"] <= entry.not_after:
        raise AabError(E_LOG_CHECKPOINT, "checkpoint time outside the key's validity")
    try:
        sigs.verify(entry.cose_key, evidence.sig_structure(prot_b, payload), sig, "checkpoint", backend)
    except sigs.SignatureFailure as exc:
        raise AabError(E_LOG_CHECKPOINT, str(exc))
    if bundle.timestamp is not None:
        # SPEC-AMBIGUITY: 9.4 rule 2 / 9.5 step 3.7 (F-41): no RFC 3161
        # validation profile (trusted TSAs, required checks, genTime vs the
        # checkpoint time), so no conforming check can be written.
        raise Unsupported("RFC 3161 time-stamp token validation is not implemented")


# --- auditor (Section 9.5) -------------------------------------------------


def audit(records: List[bytes], bundles: List[bytes], log_id: bytes, trust: LogTrust,
          backend: Optional[sigs.SignatureBackend] = None, cfg: Config = DEFAULT_CONFIG,
          payload_store: Optional[Dict[bytes, bytes]] = None) -> dict:
    """Section 9.5. Stops at the first error (Section 10).

    Returns ``{"error": code|None, "verified_up_to": k|None,
    "unanchored": [indices], "payload_missing": [indices]}``.
    ``bundles`` are the anchored checkpoint bundles, in the order they were
    anchored. ``trust`` gives the log's hash algorithm and keys; ``cfg``
    governs only the digest references inside the records.
    """
    # The log id and the trust configuration come from the auditor (Section 9.6).
    # SPEC-AMBIGUITY: 9.5/10: the auditor must report "any errors", while
    # Section 10 says to report the first. We stop at the first error and then
    # report no verified range.
    # SPEC-AMBIGUITY: 9.5 step 4: "the order the checkpoints were anchored" is
    # external metadata (not the checkpoint `time` field); we take list order.
    # Since step 3 already checks every head against the same records, the
    # "extends" condition can never fail here, and a later but smaller
    # checkpoint that is consistent with the records is still E_LOG_ROLLBACK.
    backend = backend or sigs.NullBackend()
    alg = trust.alg
    cp_cfg = Config({"log-link": alg, "checkpoint": alg}, default=alg)
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
    for data in bundles:                       # step 3
        try:
            b = decode_bundle(data)
            try:
                c = decode_checkpoint(b.checkpoint, cp_cfg)
            except AabError as exc:
                if exc.code == E_ALG_MISMATCH:
                    raise
                raise AabError(E_LOG_CHECKPOINT, "checkpoint record: %s" % exc)
            if c["log_id"] != log_id:
                raise AabError(E_LOG_ID, "checkpoint of another log")
            verify_checkpoint_signature(b, c, trust, backend)
        except AabError as exc:
            return _fail(exc.code)
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
