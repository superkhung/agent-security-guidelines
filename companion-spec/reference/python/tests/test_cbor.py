# SPDX-License-Identifier: Apache-2.0
"""Strict CBOR decoding (RFC 8949) as used by Section 7.1."""

import unittest

import context  # noqa: F401
from aab import cbor, evidence
from aab.errors import AabError


class Decode(unittest.TestCase):
    def test_rfc8949_appendix_a(self):
        cases = {"00": 0, "17": 23, "1818": 24, "1903e8": 1000, "20": -1, "3863": -100, "40": b"",
                 "4401020304": b"\x01\x02\x03\x04", "6161": "a", "83010203": [1, 2, 3],
                 "a201020304": {1: 2, 3: 4}, "f4": False, "f5": True, "f6": None}
        for h, want in cases.items():
            self.assertEqual(cbor.decode(bytes.fromhex(h)), want, h)
            self.assertEqual(cbor.encode(want), bytes.fromhex(h), h)

    def test_deterministic_rules(self):
        for h in ("1817", "190017", "1a00000017", "1b0000000000000017",   # non-preferred ints
                  "5f42010243030405ff",                                    # indefinite bstr
                  "9f0102ff",                                              # indefinite array
                  "a203040102",                                            # keys out of order
                  "fa3f800000"):                                           # float not shortest
            with self.assertRaises(cbor.CborError, msg=h):
                cbor.decode(bytes.fromhex(h), deterministic=True)
        # Accepted without the deterministic requirement.
        self.assertEqual(cbor.decode(bytes.fromhex("5f42010243030405ff"), deterministic=False), b"\x01\x02\x03\x04\x05")

    def test_always_rejected(self):
        for h in ("a201020103",    # duplicate key
                  "0000",          # trailing byte
                  "62c0af",        # ill-formed UTF-8
                  "1c",            # reserved additional information
                  "18"):           # truncated
            with self.assertRaises(cbor.CborError, msg=h):
                cbor.decode(bytes.fromhex(h), deterministic=False)

    def test_tag(self):
        v = cbor.decode(bytes.fromhex("d28440a0f640"), deterministic=False)
        self.assertEqual(v, cbor.Tag(18, [b"", {}, None, b""]))


class Container(unittest.TestCase):
    def container(self, version="01", **over):
        m = {1: version, 2: "device-key", 3: b"x", 4: b"c", 9: b"s", 10: b"r", 11: "action"}
        m.update(over)
        return cbor.encode({k: v for k, v in m.items() if v is not None})

    def code(self, data, expected_object="action"):
        try:
            evidence.decode_container(data, expected_object)
        except AabError as exc:
            return exc.code
        return None

    def test_container_version(self):
        self.assertEqual(self.code(self.container(0)), "E_CBOR")
        self.assertEqual(self.code(self.container("00")), "E_CBOR")
        self.assertIsNone(self.code(self.container("01")))

    def test_object_key_required(self):
        self.assertEqual(self.code(cbor.encode({1: "01", 2: "device-key", 3: b"x", 4: b"c", 9: b"s", 10: b"r"})),
                         "E_CBOR")

    def test_object_key_mismatch(self):
        self.assertEqual(self.code(self.container(), expected_object="lease"), "E_CBOR")
        self.assertIsNone(self.code(self.container(), "action"))

    def test_object_key_wrong_type(self):
        data = cbor.encode({1: "01", 2: "device-key", 3: b"x", 4: b"c", 9: b"s", 10: b"r", 11: 1})
        self.assertEqual(self.code(data), "E_CBOR")

    def test_object_key_unknown_value(self):
        data = cbor.encode({1: "01", 2: "device-key", 3: b"x", 4: b"c", 9: b"s", 10: b"r", 11: "checkpoint"})
        self.assertEqual(self.code(data, expected_object="checkpoint"), "E_CBOR")


if __name__ == "__main__":
    unittest.main()
