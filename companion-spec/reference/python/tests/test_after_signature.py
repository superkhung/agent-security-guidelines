# SPDX-License-Identifier: Apache-2.0
"""Logic after the signature step, exercised with FAKE backends.

These tests run the inputs of the signature-dependent vectors with a
backend that pretends every signature verifies (or fails). They check the
steps *after* the signature (counter, pending-entry consumption, checkpoint
heads, rollback, unanchored records) independently of any crypto library,
so they also run with the standard library only. The real signatures are
checked by test_crypto_backend.py and the vector runner.
"""

import hashlib
import unittest

import context
from aab import cbor, evidence, log, records
from aab.errors import AabError
from aab.vectorexec import execute

ACCEPT_ALL = context.AcceptAll
REJECT_ALL = context.RejectAll


def run(vid, backend):
    return execute(context.load_vector(vid), backend=backend)


class WebAuthnAfterSignature(unittest.TestCase):
    def test_valid_assertions(self):
        for vid in ("WA-001", "WA-002", "WA-026", "WA-015", "DK-001"):
            self.assertEqual(run(vid, ACCEPT_ALL())["result"], "accept", vid)

    def test_signed_message(self):
        b = ACCEPT_ALL()
        v = context.load_vector("WA-001")
        execute(v, backend=b)
        (alg, message, _), = b.calls
        from aab import cbor
        m = cbor.decode(bytes.fromhex(v["input"]["evidence_hex"]))
        self.assertEqual(alg, -7)
        self.assertEqual(message, m[5] + hashlib.sha256(m[6]).digest())

    def test_cose_sig_structure(self):
        b = ACCEPT_ALL()
        v = context.load_vector("DK-001")
        execute(v, backend=b)
        (_, message, _), = b.calls
        from aab import cbor
        m = cbor.decode(bytes.fromhex(v["input"]["evidence_hex"]))
        prot = cbor.decode(m[9], deterministic=False).value[0]
        self.assertEqual(message, evidence.sig_structure(prot, m[3]))
        self.assertEqual(cbor.decode(message), ["Signature1", prot, b"", m[3]])

    def test_counter(self):
        out = run("WA-014", ACCEPT_ALL())
        self.assertEqual((out["result"], out.get("error")), ("reject", "E_WA_COUNTER"))

    def test_bad_signature(self):
        out = run("WA-013", REJECT_ALL())
        self.assertEqual(out.get("error"), "E_WA_SIGNATURE")

    def test_format_checks_precede_backend(self):
        self.assertEqual(run("WA-028", ACCEPT_ALL()).get("error"), "E_WA_SIGNATURE")
        self.assertEqual(run("DK-006", ACCEPT_ALL()).get("error"), "E_COSE")

    def test_replay_and_concurrency(self):
        out = run("ACT-006", ACCEPT_ALL())
        self.assertEqual([p["result"] for p in out["presentations"]], ["accept", "reject"])
        self.assertEqual(out["presentations"][1]["error"], "E_REPLAY")
        out = run("ACT-018", ACCEPT_ALL())
        self.assertEqual([p["result"] for p in out["presentations"]], ["accept", "accept"])


NOW, NB = 1790000060000, 1790000000000


def credential(base=5, history=()):
    return evidence.Credential(b"c", "alice", {}, counter=base, history=history)


class Counter(unittest.TestCase):
    """F-1: counter compared with the snapshot at not_before (Section 7.2 step 8)."""

    def ok(self, cred, received, not_before=NB):
        return evidence.counter_ok(cred, received, not_before, NOW)

    def test_out_of_order_presentation(self):
        self.assertTrue(self.ok(credential(history=[(NOW, 12)]), 11))

    def test_value_reused_after_snapshot(self):
        self.assertFalse(self.ok(credential(history=[(NOW - 1000, 9)]), 9))

    def test_below_snapshot(self):
        self.assertFalse(self.ok(credential(history=[(NB - 1000, 9)]), 8))
        self.assertFalse(self.ok(credential(history=[(NB - 1000, 9)]), 9))
        self.assertTrue(self.ok(credential(history=[(NB - 1000, 9)]), 10))

    def test_zero_counters(self):
        self.assertTrue(self.ok(credential(base=0), 0))
        self.assertFalse(self.ok(credential(base=10), 0))

    def test_snapshot_clamped_to_retention(self):
        cred = credential(history=[(NOW - 100_000, 9)])
        self.assertFalse(self.ok(cred, 9, not_before=NOW - 7_200_000))
        self.assertTrue(self.ok(cred, 10, not_before=NOW - 7_200_000))

    def test_commit_folds_old_entries(self):
        cred = credential(history=[(NOW - 400_000, 8), (NOW - 1000, 9)])
        evidence.commit_counter(cred, 11, NOW)
        self.assertEqual(cred.counter, 8)
        self.assertEqual(cred.history, [(NOW - 1000, 9), (NOW, 11)])

    def context_for(self, vid):
        from aab import vectorexec
        v = context.load_vector(vid)
        ctx = vectorexec.build_approval_context(v["context"])
        ctx.backend = ACCEPT_ALL()
        return v, ctx

    def test_counter_failure_keeps_pending(self):
        v, ctx = self.context_for("WA-001")
        cred = ctx.credentials[bytes.fromhex(v["context"]["credentials"][0]["id_hex"])]
        cred.counter = 100
        pending = dict(ctx.state.pending)
        with self.assertRaises(AabError) as cm:
            evidence.verify_action(bytes.fromhex(v["input"]["evidence_hex"]), ctx)
        self.assertEqual(cm.exception.code, "E_WA_COUNTER")
        self.assertEqual(ctx.state.pending, pending)
        self.assertEqual(cred.history, [])

    def test_replay_does_not_commit_counter(self):
        v, ctx = self.context_for("WA-001")
        data = bytes.fromhex(v["input"]["evidence_hex"])
        evidence.verify_action(data, ctx)
        cred = ctx.credentials[bytes.fromhex(v["context"]["credentials"][0]["id_hex"])]
        history = list(cred.history)
        with self.assertRaises(AabError) as cm:
            evidence.verify_action(data, ctx)
        self.assertEqual(cm.exception.code, "E_REPLAY")
        self.assertEqual(cred.history, history)


class CheckpointBundle(unittest.TestCase):
    """F-5: signed checkpoint bundle, COSE profile and auditor trust (Section 9.3, 9.6)."""

    LOG_ID = bytes.fromhex("1f" * 16)
    KID = bytes.fromhex("10c0" * 8)
    EC_KEY = {"kty": 2, "crv": 1, "alg": -7, "x": b"\x01" * 32, "y": b"\x02" * 32}
    LOW_SIG = b"\x01" * 64

    def trust(self, key=None, nb=0, na=10 ** 13):
        return log.LogTrust("sha-256", {self.KID: log.LogKey(key or self.EC_KEY, nb, na)})

    def records(self, n=3):
        return [log.build(self.LOG_ID, i, 1000 + i, bytes(16), 0, 0) for i in range(n)]

    def bundle(self, size=3, prot=None, unprot=None, head_alg="sha-256", sig=None, extra=None, prot_b=None):
        hs = log.heads(self.LOG_ID, self.records()[:size], head_alg)
        cp = log.build_checkpoint(self.LOG_ID, size, records.DigestRef(head_alg, hs[size]), 2000)
        payload = log.checkpoint_ref(cp, "sha-256").encode()
        prot = {1: -7, 4: self.KID} if prot is None else prot
        prot_b = cbor.encode(prot) if prot_b is None else prot_b
        cose = cbor.encode(cbor.Tag(18, [prot_b, unprot or {}, payload, sig or self.LOW_SIG]))
        if extra is None:
            return log.encode_bundle(cp, cose)
        m = {1: "01", 2: cp, 3: cose}
        m.update(extra)
        return cbor.encode(m)

    def error(self, bundle, trust=None):
        return log.audit(self.records(), [bundle], self.LOG_ID, trust or self.trust(), backend=ACCEPT_ALL())["error"]

    def test_bundle_roundtrip(self):
        b = self.bundle()
        d = log.decode_bundle(b)
        self.assertIsNone(d.timestamp)
        self.assertEqual(log.encode_bundle(d.checkpoint, d.cose_sign1), b)
        out = log.audit(self.records(), [b], self.LOG_ID, self.trust(), backend=ACCEPT_ALL())
        self.assertEqual((out["error"], out["verified_up_to"]), (None, 2))

    def test_alg_wrong_type(self):
        self.assertEqual(self.error(self.bundle(prot={1: [1], 4: self.KID})), "E_LOG_CHECKPOINT")
        import struct
        float_alg = b"\xa2\x01\xfb" + struct.pack(">d", -7.0) + b"\x04\x50" + self.KID
        self.assertEqual(self.error(self.bundle(prot_b=float_alg)), "E_LOG_CHECKPOINT")
        self.assertEqual(self.error(self.bundle(prot={1: True, 4: self.KID})), "E_LOG_CHECKPOINT")

    def test_bundle_unknown_key(self):
        self.assertEqual(self.error(self.bundle(extra={5: b""})), "E_LOG_CHECKPOINT")

    def test_bundle_version(self):
        self.assertEqual(self.error(self.bundle(extra={1: "00"})), "E_LOG_CHECKPOINT")

    def test_unprotected_header_must_be_empty(self):
        self.assertEqual(self.error(self.bundle(unprot={4: self.KID})), "E_LOG_CHECKPOINT")

    def test_kid_not_configured(self):
        self.assertEqual(self.error(self.bundle(prot={1: -7, 4: b"\xff" * 16})), "E_LOG_CHECKPOINT")

    def test_key_validity(self):
        self.assertEqual(self.error(self.bundle(), self.trust(na=1999)), "E_LOG_CHECKPOINT")
        self.assertIsNone(self.error(self.bundle(), self.trust(nb=2000, na=2000)))

    def test_head_alg_mismatch(self):
        self.assertEqual(self.error(self.bundle(head_alg="sha-384")), "E_ALG_MISMATCH")

    def test_rs256_log_key(self):
        rsa = {"kty": 3, "alg": -257, "n": b"\xc0" * 256, "e": b"\x01\x00\x01"}
        self.assertEqual(self.error(self.bundle(prot={1: -257, 4: self.KID}, sig=b"\x01" * 256), self.trust(rsa)),
                         "E_LOG_CHECKPOINT")

    def test_high_s_checkpoint(self):
        from aab import sigs
        high = b"\x01" * 32 + (sigs.P256_N - 1).to_bytes(32, "big")
        self.assertEqual(self.error(self.bundle(sig=high)), "E_LOG_CHECKPOINT")

    def test_low_s(self):
        from aab import sigs
        self.assertTrue(sigs.low_s(b"\x01" * 32 + (1).to_bytes(32, "big")))
        self.assertTrue(sigs.low_s(b"\x01" * 32 + (sigs.P256_N // 2).to_bytes(32, "big")))
        self.assertFalse(sigs.low_s(b"\x01" * 32 + (sigs.P256_N // 2 + 1).to_bytes(32, "big")))


class AuditorAfterSignature(unittest.TestCase):
    def expect(self, vid, backend, **want):
        out = run(vid, backend)
        for k, v in want.items():
            self.assertEqual(out.get(k), v, (vid, k, out))

    def test_verified_ranges(self):
        self.expect("LOG-001", ACCEPT_ALL(), result="accept", verified_up_to=4, unanchored=[])
        self.expect("LOG-004", ACCEPT_ALL(), result="accept", verified_up_to=4, unanchored=[5, 6, 7])
        self.expect("LOG-005", ACCEPT_ALL(), result="accept", verified_up_to=4, unanchored=[])
        self.expect("LOG-016", ACCEPT_ALL(), result="accept", verified_up_to=4)

    def test_chain_errors(self):
        for vid in ("LOG-003", "LOG-008", "LOG-012", "LOG-018"):
            self.expect(vid, ACCEPT_ALL(), result="reject", error="E_LOG_CHAIN")
        self.expect("LOG-011", ACCEPT_ALL(), result="reject", error="E_LOG_ROLLBACK")
        self.expect("LOG-009", REJECT_ALL(), result="reject", error="E_LOG_CHECKPOINT")

    def test_payload_missing(self):
        self.expect("LOG-014", ACCEPT_ALL(), result="accept", verified_up_to=4, payload_missing=[3])

    def test_timestamp_token_unsupported(self):
        self.expect("LOG-017", ACCEPT_ALL(), result="unsupported")


if __name__ == "__main__":
    unittest.main()
