# SPDX-License-Identifier: Apache-2.0
"""Approval evidence container and verification (Section 7).

:func:`verify_action` runs Section 7.2 (``webauthn``) or 7.3
(``device-key``) for an action approval. The lease grant variant
(Section 8.4) lives in :mod:`aab.lease` and reuses the step functions here.
"""

from __future__ import annotations

import hashlib
from typing import Dict, Iterable, Optional

from . import action as action_mod
from . import cbor, jsonstrict, sigs
from .encoding import b64u
from .errors import (
    AabError,
    E_CBOR,
    E_COSE,
    E_CREDENTIAL,
    E_DIGEST_MISMATCH,
    E_JSON,
    E_WA_AUTHDATA,
    E_WA_CHALLENGE,
    E_WA_COUNTER,
    E_WA_FLAGS,
    E_WA_ORIGIN,
    E_WA_RPID,
    E_WA_SIGNATURE,
    E_WA_TYPE,
)
from .records import DigestRef, decode_digest_ref, ref_of

WEBAUTHN, DEVICE_KEY = "webauthn", "device-key"

# key -> (name, CBOR type)
_KEYS = {1: int, 2: str, 3: bytes, 4: bytes, 5: bytes, 6: bytes, 7: bytes, 8: bytes, 9: bytes, 10: bytes}
_COMMON = {1, 2, 3, 4, 10}
_REQUIRED = {WEBAUTHN: _COMMON | {5, 6, 7}, DEVICE_KEY: _COMMON | {9}}
_ALLOWED = {WEBAUTHN: _REQUIRED[WEBAUTHN] | {8}, DEVICE_KEY: _REQUIRED[DEVICE_KEY]}

UP, UV, BE, BS, AT, ED = 0x01, 0x04, 0x08, 0x10, 0x40, 0x80


class Credential:
    """One entry of the verifier's credential registry (Section 7.2)."""

    def __init__(self, cred_id: bytes, approver: str, key: dict, user_handle: Optional[bytes] = None,
                 be: bool = False, counter: int = 0, classes: Iterable[str] = (), revoked: bool = False):
        self.id = cred_id
        self.approver = approver
        self.key = key
        self.user_handle = user_handle
        self.be = be
        self.counter = counter
        self.classes = set(classes)
        self.revoked = revoked


class ApprovalContext:
    """Verifier configuration and state for Sections 7 and 8.4."""

    def __init__(self, state: action_mod.VerifierState, credentials: Iterable[Credential] = (),
                 tool_classes: Optional[Dict[str, str]] = None, rp_id: str = "",
                 allowed_origins: Iterable[str] = (), forbid_synced: bool = False,
                 accept_rs256: bool = False, backend: Optional[sigs.SignatureBackend] = None):
        self.state = state
        self.credentials = {c.id: c for c in credentials}
        self.tool_classes = dict(tool_classes or {})
        self.rp_id = rp_id
        self.allowed_origins = set(allowed_origins)
        self.forbid_synced = forbid_synced
        self.accept_rs256 = accept_rs256
        self.backend = backend or sigs.NullBackend()


# --- step 1: container -------------------------------------------------------


def decode_container(data: bytes, expected_profile: Optional[str] = None) -> dict:
    """Section 7.1 and step 1 of Section 7.2/7.3. All failures are E_CBOR."""
    try:
        m = cbor.decode(data, deterministic=True)
    except cbor.CborError as exc:
        raise AabError(E_CBOR, str(exc))
    if not isinstance(m, dict):
        raise AabError(E_CBOR, "container is not a map")
    for k, v in m.items():
        if k not in _KEYS:
            raise AabError(E_CBOR, "unknown container key %r" % (k,))
        t = _KEYS[k]
        if not isinstance(v, t) or isinstance(v, bool):
            raise AabError(E_CBOR, "container key %d has the wrong type" % k)
    if m.get(1) != 0:
        raise AabError(E_CBOR, "version is not 0")
    profile = m.get(2)
    if profile not in _REQUIRED:
        raise AabError(E_CBOR, "unknown profile %r" % (profile,))
    if expected_profile is not None and profile != expected_profile:
        raise AabError(E_CBOR, "profile %r not accepted here" % profile)
    keys = set(m)
    if not _REQUIRED[profile] <= keys:
        raise AabError(E_CBOR, "missing keys %s" % sorted(_REQUIRED[profile] - keys))
    if not keys <= _ALLOWED[profile]:
        raise AabError(E_CBOR, "keys %s not allowed for %s" % (sorted(keys - _ALLOWED[profile]), profile))
    return m


# --- step 2: record ---------------------------------------------------------


def bind_record(m: dict, object_type: str, decoder, cfg):
    """Step 2 of Section 7.2: key 3 as digest ref, key 10 decoded, digests equal."""
    # SPEC-AMBIGUITY: 7.1/8.4: the container does not say whether key 10 is an
    # action or a lease record; the verifier must know from context which one
    # it expects. We take `object_type` from the caller (the endpoint).
    ref =decode_digest_ref(m[3], cfg.alg(object_type))
    rec = decoder(m[10], cfg)
    if ref_of(object_type, m[10], ref.alg).encode() != m[3]:
        raise AabError(E_DIGEST_MISMATCH, "record digest differs from key 3")
    return ref, rec


# --- step 4: credential -----------------------------------------------------


def lookup_credential(ctx: ApprovalContext, cred_id: bytes, classes_needed: Iterable[str],
                      required_approver: Optional[str]) -> Credential:
    cred = ctx.credentials.get(cred_id)
    if cred is None or cred.revoked:
        raise AabError(E_CREDENTIAL, "unknown or revoked credential")
    for cls in classes_needed:
        if cls is None or cls not in cred.classes:
            raise AabError(E_CREDENTIAL, "approver not authorized for class %r" % cls)
    if required_approver is not None and cred.approver != required_approver:
        raise AabError(E_CREDENTIAL, "credential belongs to %r, not %r" % (cred.approver, required_approver))
    return cred


# --- steps 5-8: WebAuthn ------------------------------------------------------


def check_client_data(ctx: ApprovalContext, cdj: bytes, ref: DigestRef) -> None:
    """Step 5 of Section 7.2."""
    cd = jsonstrict.parse(cdj)
    if not isinstance(cd, dict):
        # SPEC-AMBIGUITY: 7.2 step 5: clientDataJSON that is valid JSON but
        # not an object has no listed error. We use E_JSON.
        raise AabError(E_JSON, "clientDataJSON is not an object")
    if cd.get("type") != "webauthn.get":
        raise AabError(E_WA_TYPE, "type %r" % (cd.get("type"),))
    if cd.get("challenge") != b64u(ref.digest):
        raise AabError(E_WA_CHALLENGE, "challenge mismatch")
    if not isinstance(cd.get("origin"), str) or cd["origin"] not in ctx.allowed_origins:
        raise AabError(E_WA_ORIGIN, "origin %r not allowed" % (cd.get("origin"),))
    if "crossOrigin" in cd and cd["crossOrigin"] is not False:
        raise AabError(E_WA_ORIGIN, "crossOrigin is not false")
    if "topOrigin" in cd:
        raise AabError(E_WA_ORIGIN, "topOrigin present")


def parse_auth_data(ad: bytes) -> dict:
    """Step 6.1 of Section 7.2."""
    if len(ad) < 37:
        raise AabError(E_WA_AUTHDATA, "authenticatorData shorter than 37 bytes")
    flags = ad[32]
    if flags & AT:
        # SPEC-AMBIGUITY: 7.2 step 6.1: "consistent with the AT and ED flags"
        # does not say whether AT may be set in an assertion. WebAuthn only
        # includes attested credential data at registration; we reject AT.
        raise AabError(E_WA_AUTHDATA, "AT flag set in an assertion")
    if flags & ED:
        try:
            ext, end = cbor.decode_prefix(ad, 37)
        except cbor.CborError as exc:
            raise AabError(E_WA_AUTHDATA, "bad extensions: %s" % exc)
        if not isinstance(ext, dict) or end != len(ad):
            raise AabError(E_WA_AUTHDATA, "extensions do not fill authenticatorData")
    elif len(ad) != 37:
        raise AabError(E_WA_AUTHDATA, "trailing bytes without ED flag")
    return {"rp_id_hash": ad[:32], "flags": flags, "sign_count": int.from_bytes(ad[33:37], "big")}


def check_auth_data(ctx: ApprovalContext, cred: Credential, ad: bytes, user_handle: Optional[bytes]) -> dict:
    """Step 6 of Section 7.2, in order."""
    info = parse_auth_data(ad)
    if info["rp_id_hash"] != hashlib.sha256(ctx.rp_id.encode("utf-8")).digest():
        raise AabError(E_WA_RPID, "rpIdHash mismatch")
    f = info["flags"]
    if not f & UP:
        raise AabError(E_WA_FLAGS, "UP not set")
    if not f & UV:
        raise AabError(E_WA_FLAGS, "UV not set")
    if f & BS and not f & BE:
        raise AabError(E_WA_FLAGS, "BS set without BE")
    if bool(f & BE) != cred.be:
        raise AabError(E_WA_FLAGS, "BE differs from registration")
    if ctx.forbid_synced and f & BE:
        raise AabError(E_WA_FLAGS, "synced credential forbidden")
    if user_handle is not None and user_handle != cred.user_handle:
        raise AabError(E_CREDENTIAL, "userHandle mismatch")
    return info


def webauthn_tail(ctx: ApprovalContext, m: dict, ref: DigestRef, cred: Credential) -> int:
    """Steps 5-8 of Section 7.2. Returns the new signature counter."""
    check_client_data(ctx, m[6], ref)
    info = check_auth_data(ctx, cred, m[5], m.get(8))
    message = m[5] + hashlib.sha256(m[6]).digest()
    try:
        sigs.verify(cred.key, message, m[7], WEBAUTHN, ctx.backend, ctx.accept_rs256)
    except sigs.SignatureFailure as exc:
        raise AabError(E_WA_SIGNATURE, str(exc))
    count = info["sign_count"]
    # SPEC-AMBIGUITY: 7.2 step 8 vs 6.2 rule 1: approvals may complete in any
    # order, but with a counter-using authenticator two assertions signed as
    # (n, n+1) and presented as (n+1, n) make the second fail E_WA_COUNTER.
    # The spec also does not say how the counter update and the pending-entry
    # compare-and-delete are made atomic together. We apply step 8 as written.
    if (cred.counter != 0 or count != 0) and not count > cred.counter:
        raise AabError(E_WA_COUNTER, "signCount %d not greater than %d" % (count, cred.counter))
    return count


# --- steps 2-8 of Section 7.3: device key -----------------------------------


def decode_cose_sign1(data: bytes, err: str):
    """Decode a tagged COSE_Sign1; return (protected_bytes, protected, unprotected, payload, sig)."""
    try:
        t = cbor.decode(data, deterministic=False)
    except cbor.CborError as exc:
        raise AabError(err, "COSE_Sign1: %s" % exc)
    if not isinstance(t, cbor.Tag) or t.tag != 18:
        raise AabError(err, "not a tagged COSE_Sign1 (tag 18)")
    v = t.value
    if not (isinstance(v, list) and len(v) == 4 and isinstance(v[0], bytes) and isinstance(v[1], dict)
            and (v[2] is None or isinstance(v[2], bytes)) and isinstance(v[3], bytes)):
        raise AabError(err, "COSE_Sign1 structure malformed")
    prot_b = v[0]
    if prot_b == b"":
        prot = {}
    else:
        try:
            prot = cbor.decode(prot_b, deterministic=False)
        except cbor.CborError as exc:
            raise AabError(err, "protected header: %s" % exc)
        if not isinstance(prot, dict):
            raise AabError(err, "protected header is not a map")
    return prot_b, prot, v[1], v[2], v[3]


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    """RFC 9052 section 4.4 Sig_structure for COSE_Sign1 with empty external_aad."""
    return cbor.encode(["Signature1", protected, b"", payload])


def device_key_tail(ctx: ApprovalContext, m: dict, cred: Credential) -> None:
    """Steps 2-8 of Section 7.3."""
    prot_b, prot, unprot, payload, sig = decode_cose_sign1(m[9], E_COSE)
    if 1 not in prot or 4 not in prot or 1 in unprot or 4 in unprot:
        raise AabError(E_COSE, "alg and kid must be in the protected header only")
    if prot[4] != m[4]:
        raise AabError(E_COSE, "kid differs from key 4")
    alg = prot[1]
    reg = cred.key.get("alg")
    # SPEC-AMBIGUITY: 7.3 step 5 / 7.5: RS256 is "not allowed" for device-key
    # but no step says where it is rejected. We reject it here with E_COSE.
    if (not isinstance(alg, int) or isinstance(alg, bool) or alg not in sigs.EQUIVALENT
            or reg not in sigs.EQUIVALENT or sigs.EQUIVALENT[alg] != sigs.EQUIVALENT[reg]
            or sigs.EQUIVALENT[reg] == sigs.RS256):
        raise AabError(E_COSE, "alg %r does not match registered %r" % (alg, reg))
    if payload is None:
        raise AabError(E_COSE, "detached payload")
    if payload != m[3]:
        raise AabError(E_DIGEST_MISMATCH, "COSE payload differs from key 3")
    try:
        sigs.verify(cred.key, sig_structure(prot_b, payload), sig, DEVICE_KEY, ctx.backend)
    except sigs.SignatureFailure as exc:
        raise AabError(E_COSE, str(exc))


# --- Section 7.2 / 7.3 for actions ----------------------------------------


def verify_action(data: bytes, ctx: ApprovalContext) -> dict:
    """Verify approval evidence for one action; consume its pending entry on success."""
    m = decode_container(data)                                   # step 1
    state = ctx.state
    ref, rec = bind_record(m, "action", action_mod.decode, state.cfg)  # step 2
    action_mod.check_record(rec, state, m[3])                    # step 3
    cred = lookup_credential(ctx, m[4], [ctx.tool_classes.get(rec["name"])],
                             rec.get("approver"))                # step 4
    count = None
    if m[2] == WEBAUTHN:
        count = webauthn_tail(ctx, m, ref, cred)                 # steps 5-8
    else:
        device_key_tail(ctx, m, cred)                            # 7.3 steps 2-8
    state.consume(rec["session"], rec["sequence"], m[3])
    if count is not None:
        cred.counter = count
    return {"record": rec, "digest": ref}
