# SPDX-License-Identifier: Apache-2.0
"""Appendix D of the spec: the illustrative values must be reproduced exactly."""

import unittest

import context  # noqa: F401
from aab import action, fingerprint, identity, records
from aab.encoding import b64u

# SPEC-AMBIGUITY: D.1: the identity is given as "abab...ab (64 hex digits)";
# we read it as "ab" repeated 32 times, which reproduces every D value.
SERVER = identity.make("oci", "registry.example.internal/mcp/files@sha256:" + "ab" * 32)
TOOL = {
    "name": "read_file",
    "title": "Read file",
    "description": "Read a UTF-8 text file inside the workspace.",
    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    "annotations": {"readOnlyHint": True, "destructiveHint": False},
}


class AppendixD1(unittest.TestCase):
    def test_canonical_json(self):
        from aab.jcs import jcs
        self.assertEqual(jcs(TOOL["inputSchema"]),
                         b'{"properties":{"path":{"type":"string"}},"required":["path"],"type":"object"}')
        self.assertEqual(jcs(TOOL["annotations"]), b'{"destructiveHint":false,"readOnlyHint":true}')

    def test_domain_prefix(self):
        self.assertEqual(records.domain_prefix("tool-fp", "sha-256").hex(),
                         "00000016" "6161622f30302f746f6f6c2d66702f7368612d323536")

    def test_record_start_and_length(self):
        rec = fingerprint.record(SERVER, TOOL)
        self.assertEqual(len(rec), 338)
        self.assertTrue(rec.hex().startswith(
            "0001" "00000076" "00000003" "6f6369" "0000006b" "72656769737472792e6578616d706c652e"))

    def test_fingerprints(self):
        self.assertEqual(fingerprint.fingerprint(SERVER, TOOL).text(),
                         "sha-256:U2Q4CNaBoz71PtbKXEotxCxzb_PkZ0_gm4DMcKRWUa0")
        self.assertEqual(fingerprint.fingerprint(SERVER, dict(TOOL, name="read_secret")).text(),
                         "sha-256:oAKxl7KFWAN2ffZpEH2B-TMZZY6WAetlqckp3T6Qj08")
        ann = {"readOnlyHint": True, "destructiveHint": True}
        self.assertEqual(fingerprint.fingerprint(SERVER, dict(TOOL, annotations=ann)).text(),
                         "sha-256:zPeISc33LtI6rfSV-U2mfHa4mO2_3RqU0iVDiJRowwI")


class AppendixD2(unittest.TestCase):
    def test_action_digest_and_challenge(self):
        fp = fingerprint.fingerprint(SERVER, TOOL)
        rec = action.build("https://proxy.example.internal", bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
                           7, SERVER, "read_file", fp, {"path": "src/main.py"}, 1790000000000, 1790000120000)
        ref = action.digest_ref(rec)
        self.assertEqual(ref.text(), "sha-256:TNrzsHt4kGTrvz_NDchY22aNsZmz9zdfmvbLPGPUGx0")
        self.assertEqual(b64u(ref.digest), "TNrzsHt4kGTrvz_NDchY22aNsZmz9zdfmvbLPGPUGx0")
        # The record decodes back to the same fields.
        d = action.decode(rec)
        self.assertEqual(d["sequence"], 7)
        self.assertEqual(d["fingerprint"], fp)


if __name__ == "__main__":
    unittest.main()
