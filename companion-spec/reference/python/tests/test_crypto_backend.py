# SPDX-License-Identifier: Apache-2.0
"""The optional ``cryptography`` backend (skipped when it is not installed)."""

import hashlib
import os
import subprocess
import sys
import unittest

import context
from aab import cbor, evidence, sigs
from aab.vectorexec import execute

try:
    from aab import crypto_cryptography as cc
except ImportError:  # stdlib-only mode
    cc = None

needs_crypto = unittest.skipIf(cc is None, "cryptography not installed (stdlib-only mode)")


def evidence_map(vid):
    return cbor.decode(bytes.fromhex(context.load_vector(vid)["input"]["evidence_hex"]))


def webauthn_message(m):
    return m[5] + hashlib.sha256(m[6]).digest()


class BackendSelection(unittest.TestCase):
    def test_env_forces_stdlib(self):
        old = os.environ.get("AAB_BACKEND")
        os.environ["AAB_BACKEND"] = "none"
        try:
            self.assertIsInstance(sigs.default_backend(), sigs.NullBackend)
        finally:
            if old is None:
                del os.environ["AAB_BACKEND"]
            else:
                os.environ["AAB_BACKEND"] = old

    def test_core_imports_without_cryptography(self):
        code = ("import sys; sys.modules['cryptography'] = None; sys.path.insert(0, %r); "
                "import warnings; warnings.simplefilter('ignore'); "
                "from aab import sigs, vectorexec, evidence, log, lease, proxy; "
                "b = sigs.default_backend(); assert isinstance(b, sigs.NullBackend), b; print(b.name)"
                % context.ROOT)
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("stdlib", out.stdout)

    @needs_crypto
    def test_default_is_cryptography(self):
        if os.environ.get("AAB_BACKEND", "").lower() in ("none", "null", "stdlib"):
            self.skipTest("AAB_BACKEND forces stdlib")
        self.assertIsInstance(sigs.default_backend(), cc.CryptographyBackend)


@needs_crypto
class RealSignatures(unittest.TestCase):
    def setUp(self):
        self.b = cc.CryptographyBackend()
        self.es_key = cc.p256_cose_key(cc.p256_private_from_label("aab-00 test key: approver es256"))

    def test_webauthn_es256_vector_signature(self):
        m = evidence_map("WA-001")
        msg = webauthn_message(m)
        sigs.verify(self.es_key, msg, m[7], "webauthn", self.b)
        with self.assertRaises(sigs.SignatureFailure):
            sigs.verify(self.es_key, msg + b"x", m[7], "webauthn", self.b)

    def test_wa028_catches_lenient_verifier(self):
        """The raw r||s in WA-028 is a real signature: its DER form verifies."""
        m = evidence_map("WA-028")
        self.assertEqual(len(m[7]), 64)
        with self.assertRaises(sigs.SignatureFailure):
            sigs.parse_der_ecdsa(m[7])
        sigs.verify(self.es_key, webauthn_message(m), cc.raw_to_der(m[7]), "webauthn", self.b)

    def test_dk006_catches_lenient_verifier(self):
        """The DER signature in DK-006 is real: its raw r||s form verifies."""
        m = evidence_map("DK-006")
        prot_b, _, _, payload, sig = evidence.decode_cose_sign1(m[9], "E_COSE")
        key = cc.p256_cose_key(cc.p256_private_from_label("aab-00 test key: device-key es256"))
        sigs.parse_der_ecdsa(sig)  # it is DER
        sigs.verify(key, evidence.sig_structure(prot_b, payload), cc.der_to_raw(sig), "device-key", self.b)

    def test_esp256_equivalent_to_es256(self):
        v = context.load_vector("WA-001")
        v["context"]["credentials"][0]["cose_key"]["alg"] = -9
        self.assertEqual(execute(v, backend=self.b)["result"], "accept")

    def test_device_key_header_esp256(self):
        v = context.load_vector("DK-001")
        m = cbor.decode(bytes.fromhex(v["input"]["evidence_hex"]))
        prot_b = cbor.encode({1: -9, 4: m[4]})
        priv = cc.p256_private_from_label("aab-00 test key: device-key es256")
        sig = cc.sign_es256(priv, evidence.sig_structure(prot_b, m[3]), "raw")
        m[9] = cbor.encode(cbor.Tag(18, [prot_b, {}, m[3], sig]))
        v["input"]["evidence_hex"] = cbor.encode(m).hex()
        self.assertEqual(execute(v, backend=self.b)["result"], "accept")

    def test_rs256_policy(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        n = priv.public_key().public_numbers()
        key = {"kty": 3, "alg": -257, "n": n.n.to_bytes(256, "big"), "e": n.e.to_bytes(3, "big")}
        sig = priv.sign(b"msg", padding.PKCS1v15(), hashes.SHA256())
        sigs.verify(key, b"msg", sig, "webauthn", self.b, accept_rs256=True)
        with self.assertRaises(sigs.SignatureFailure):
            sigs.verify(key, b"msg", sig, "webauthn", self.b, accept_rs256=False)
        with self.assertRaises(sigs.SignatureFailure):
            sigs.verify(key, b"msg", sig, "device-key", self.b, accept_rs256=True)
        with self.assertRaises(sigs.SignatureFailure):
            sigs.verify(key, b"other", sig, "webauthn", self.b, accept_rs256=True)

    def test_non_minimal_der_rejected(self):
        m = evidence_map("WA-001")
        der = m[7]
        r_len = der[3]
        # Re-encode r with one superfluous leading zero byte (BER, not DER).
        r = der[4:4 + r_len]
        rest = der[4 + r_len:]
        bad = bytes([0x30, der[1] + 1, 0x02, r_len + 1, 0x00]) + r + rest
        # A lax (BER) parser would read the same (r, s); strict DER must reject it.
        with self.assertRaises(sigs.SignatureFailure):
            sigs.verify(self.es_key, webauthn_message(m), bad, "webauthn", self.b)

    def test_high_s_is_accepted(self):
        """ECDSA malleability: (r, n - s) also verifies (finding F-39)."""
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

        m = evidence_map("WA-001")
        r, s = decode_dss_signature(m[7])
        other = encode_dss_signature(r, sigs.P256_N - s)
        self.assertNotEqual(other, m[7])
        sigs.verify(self.es_key, webauthn_message(m), other, "webauthn", self.b)

    def test_point_not_on_curve(self):
        m = evidence_map("WA-001")
        bad = dict(self.es_key, y=(int.from_bytes(self.es_key["y"], "big") ^ 1).to_bytes(32, "big"))
        with self.assertRaises(sigs.SignatureFailure):
            sigs.verify(bad, webauthn_message(m), m[7], "webauthn", self.b)

    def test_ed25519_rfc8032_test1(self):
        # RFC 8032 section 7.1 TEST 1: empty message.
        priv = cc.ed25519_private(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
        sig = cc.sign_ed25519(priv, b"")
        self.assertEqual(sig.hex(), "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                                    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        key = {"kty": 1, "crv": 6, "alg": -19, "x": cc.ed25519_public_bytes(priv)}
        sigs.verify(key, b"", sig, "device-key", self.b)

    def test_replayed_vector_rejected(self):
        out = execute(context.load_vector("ACT-006"), backend=self.b)
        self.assertEqual([p["result"] for p in out["presentations"]], ["accept", "reject"])
        self.assertEqual(out["presentations"][1]["error"], "E_REPLAY")


if __name__ == "__main__":
    unittest.main()
