# SPDX-License-Identifier: Apache-2.0
"""Optional signature backend built on the ``cryptography`` package.

Importing this module fails with ``ImportError`` when ``cryptography`` is
not installed; :func:`aab.sigs.default_backend` then falls back to the
stdlib-only :class:`~aab.sigs.NullBackend`. Nothing else in the package
imports ``cryptography``.

Verification (Section 7.5): the caller (:func:`aab.sigs.verify`) has
already fixed the algorithm from the registered key, checked the key type
and curve, and checked the signature *format* (strict DER for WebAuthn
ECDSA, raw ``r || s`` for COSE). This backend only does the arithmetic.

The ``sign_*`` helpers exist for generating test vectors and unit tests.
ECDSA signing uses RFC 6979 deterministic nonces, so regenerating a vector
from the same inputs yields the same bytes.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from . import sigs

NAME = "cryptography"


def _version() -> str:
    import cryptography

    return cryptography.__version__


VERSION = _version()


def _p256_public(key: dict) -> ec.EllipticCurvePublicKey:
    nums = ec.EllipticCurvePublicNumbers(int.from_bytes(key["x"], "big"), int.from_bytes(key["y"], "big"),
                                         ec.SECP256R1())
    return nums.public_key()  # raises ValueError for a point not on the curve


class CryptographyBackend(sigs.SignatureBackend):
    """ES256/ESP256, EdDSA/Ed25519 and RS256 verification."""

    name = "%s %s" % (NAME, VERSION)

    def verify(self, key, alg, message, signature, rs=None):
        try:
            if alg == sigs.ES256:
                r, s = rs
                _p256_public(key).verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
            elif alg == sigs.EDDSA:
                # SPEC-AMBIGUITY: 7.5 (F-44): Ed25519 verification rules
                # (cofactored or not, non-canonical encodings, small-order
                # points) are not pinned; this is OpenSSL's behaviour.
                ed25519.Ed25519PublicKey.from_public_bytes(key["x"]).verify(signature, message)
            elif alg == sigs.RS256:
                pub = rsa.RSAPublicNumbers(int.from_bytes(key["e"], "big"), int.from_bytes(key["n"], "big"))
                pub.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            else:
                return False
        except (InvalidSignature, ValueError):
            return False
        return True


# --- signing helpers (vector generation and tests only) ---------------------


def p256_private_from_label(label: str) -> ec.EllipticCurvePrivateKey:
    """A fixed P-256 key: d = SHA-256(label) mod (n - 1) + 1. Test only."""
    d = int.from_bytes(hashlib.sha256(label.encode()).digest(), "big") % (sigs.P256_N - 1) + 1
    return ec.derive_private_key(d, ec.SECP256R1())


def p256_cose_key(priv: ec.EllipticCurvePrivateKey, alg: int = sigs.ES256) -> dict:
    n = priv.public_key().public_numbers()
    return {"kty": sigs.KTY_EC2, "crv": sigs.CRV_P256, "alg": alg,
            "x": n.x.to_bytes(32, "big"), "y": n.y.to_bytes(32, "big")}


def ed25519_private(seed: bytes) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def ed25519_public_bytes(priv: ed25519.Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def ed448_public_bytes(seed: bytes) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return ed448.Ed448PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def sign_es256(priv: ec.EllipticCurvePrivateKey, message: bytes, fmt: str) -> bytes:
    """Deterministic (RFC 6979) ES256; ``fmt`` is ``"der"`` or ``"raw"``."""
    der = priv.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    if fmt == "der":
        return der
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def der_to_raw(der: bytes) -> bytes:
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def raw_to_der(raw: bytes) -> bytes:
    return encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))


def sign_ed25519(priv: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    return priv.sign(message)
