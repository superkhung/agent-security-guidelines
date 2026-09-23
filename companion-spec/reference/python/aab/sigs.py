# SPDX-License-Identifier: Apache-2.0
"""Signature algorithms (Section 7.5) and the pluggable crypto backend.

Everything that can be decided without cryptography is decided here:
the algorithm comes from the registered key, never from the evidence; the
key type and curve must match the algorithm; the signature must have the
format required by the profile (strict DER for WebAuthn ECDSA, raw
``r || s`` for COSE). Only the final mathematical check is delegated to a
:class:`SignatureBackend`. The default :class:`NullBackend` raises
:class:`~aab.errors.CryptoUnavailable`.

Registered keys are dicts with COSE_Key semantics::

    {"kty": 2, "crv": 1, "alg": -7, "x": b"...", "y": b"..."}   # EC2 P-256
    {"kty": 1, "crv": 6, "alg": -8, "x": b"..."}                 # OKP Ed25519
    {"kty": 3, "alg": -257, "n": b"...", "e": b"..."}            # RSA
"""

from __future__ import annotations

from .errors import CryptoUnavailable

ES256, ESP256, EDDSA, ED25519, RS256 = -7, -9, -8, -19, -257
KTY_OKP, KTY_EC2, KTY_RSA = 1, 2, 3
CRV_P256, CRV_ED25519, CRV_ED448 = 1, 6, 7

P256_N = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

#: Section 7.5 "MUST, equivalent to": the fully specified and polymorphic ids.
# SPEC-AMBIGUITY: 7.3 step 5 / 7.5: "or its equivalent" is not said to be
# symmetric (registered -19, header -8?). We treat equivalence as symmetric.
EQUIVALENT = {ES256: ES256, ESP256: ES256, EDDSA: EDDSA, ED25519: EDDSA, RS256: RS256}


class SignatureFailure(Exception):
    """The signature step failed; the caller maps it to its profile's code."""


class SignatureBackend:
    """Interface for the mathematical signature check.

    ``verify`` receives the registered key, the effective algorithm
    (``ES256``, ``EDDSA`` or ``RS256`` after equivalence), the signed
    message, and the signature in the profile's format: for ES256 the
    ``(r, s)`` integers are also passed so a backend need not reparse DER.
    It returns ``True`` or ``False``.
    """

    def verify(self, key: dict, alg: int, message: bytes, signature: bytes, rs=None) -> bool:
        raise NotImplementedError


class NullBackend(SignatureBackend):
    def verify(self, key, alg, message, signature, rs=None):
        raise CryptoUnavailable("no crypto backend installed (stdlib-only milestone)")


def parse_der_ecdsa(sig: bytes):
    """Strict DER ``Ecdsa-Sig-Value`` (SEQUENCE of two INTEGERs); return (r, s)."""
    def read_int(b, pos):
        if pos + 2 > len(b) or b[pos] != 0x02:
            raise SignatureFailure("expected INTEGER")
        n = b[pos + 1]
        if n & 0x80 or n == 0:
            raise SignatureFailure("bad INTEGER length")
        v = b[pos + 2:pos + 2 + n]
        if len(v) != n:
            raise SignatureFailure("truncated INTEGER")
        if v[0] & 0x80:
            raise SignatureFailure("negative INTEGER")
        if n > 1 and v[0] == 0 and not (v[1] & 0x80):
            raise SignatureFailure("non-minimal INTEGER")
        return int.from_bytes(v, "big"), pos + 2 + n

    sig = bytes(sig)
    if len(sig) < 8 or sig[0] != 0x30 or sig[1] & 0x80 or sig[1] != len(sig) - 2:
        raise SignatureFailure("not a DER SEQUENCE")
    r, pos = read_int(sig, 2)
    s, pos = read_int(sig, pos)
    if pos != len(sig):
        raise SignatureFailure("trailing bytes in DER signature")
    if not (1 <= r < P256_N and 1 <= s < P256_N):
        raise SignatureFailure("r or s out of range")
    return r, s


def check_key(key: dict, profile: str, accept_rs256: bool) -> int:
    """Validate the registered key against Section 7.5; return the effective alg."""
    alg = key.get("alg")
    if alg not in EQUIVALENT:
        raise SignatureFailure("algorithm %r not supported" % alg)
    eff = EQUIVALENT[alg]
    if eff == ES256:
        if key.get("kty") != KTY_EC2 or key.get("crv") != CRV_P256:
            raise SignatureFailure("ES256 needs an EC2 P-256 key")
        if len(key.get("x", b"")) != 32 or len(key.get("y", b"")) != 32:
            raise SignatureFailure("bad P-256 coordinates")
    elif eff == EDDSA:
        if key.get("kty") != KTY_OKP or key.get("crv") != CRV_ED25519:
            raise SignatureFailure("EdDSA restricted to Ed25519 (Section 7.5)")
        if len(key.get("x", b"")) != 32:
            raise SignatureFailure("bad Ed25519 public key")
    else:
        if profile != "webauthn":
            raise SignatureFailure("RS256 not allowed for %s" % profile)
        if not accept_rs256:
            raise SignatureFailure("verifier does not accept RS256")
        if key.get("kty") != KTY_RSA or len(key.get("n", b"").lstrip(b"\x00")) * 8 < 2048:
            raise SignatureFailure("RS256 needs an RSA key of at least 2048 bits")
    return eff


def verify(key: dict, message: bytes, signature: bytes, profile: str, backend: SignatureBackend,
           accept_rs256: bool = False) -> None:
    """Run the signature step for ``profile`` ('webauthn', 'device-key', 'checkpoint')."""
    eff = check_key(key, profile, accept_rs256)
    rs = None
    if eff == ES256:
        if profile == "webauthn":
            rs = parse_der_ecdsa(signature)
        else:
            if len(signature) != 64:
                raise SignatureFailure("COSE ES256 signature must be raw r||s, 64 bytes")
            rs = (int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    elif eff == EDDSA:
        if len(signature) != 64:
            raise SignatureFailure("Ed25519 signature must be 64 bytes")
    else:
        if len(signature) != len(key["n"].lstrip(b"\x00")):
            raise SignatureFailure("RSA signature length differs from modulus length")
    if not backend.verify(key, eff, message, signature, rs):
        raise SignatureFailure("signature does not verify")
