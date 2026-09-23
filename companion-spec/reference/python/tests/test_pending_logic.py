# SPDX-License-Identifier: Apache-2.0
"""Logic after the signature step, exercised with FAKE backends.

These tests run the inputs of the pending vectors with a backend that
pretends every signature verifies (or fails). They check that the steps
*after* the signature (counter, pending-entry consumption, checkpoint heads,
rollback, unanchored records) produce the outcome the catalogue states.
They are not evidence about real signatures, which is why the vector files
stay pending.
"""

import hashlib
import unittest

import context
from aab import evidence
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
