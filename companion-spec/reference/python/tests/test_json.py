# SPDX-License-Identifier: Apache-2.0
"""Strict JSON (Section 4.3) and RFC 8785 serialization."""

import struct
import unittest

import context  # noqa: F401
from aab import jsonstrict
from aab.errors import AabError
from aab.jcs import jcs, number_to_string

# RFC 8785 Appendix B sample values (IEEE 754 bits -> expected string).
RFC8785_NUMBERS = {
    "0000000000000000": "0", "8000000000000000": "0", "0000000000000001": "5e-324",
    "8000000000000001": "-5e-324", "7fefffffffffffff": "1.7976931348623157e+308",
    "ffefffffffffffff": "-1.7976931348623157e+308", "4340000000000000": "9007199254740992",
    "c340000000000000": "-9007199254740992", "4430000000000000": "295147905179352830000",
    "44b52d02c7e14af5": "9.999999999999997e+22", "44b52d02c7e14af6": "1e+23",
    "44b52d02c7e14af7": "1.0000000000000001e+23", "444b1ae4d6e2ef4e": "999999999999999700000",
    "444b1ae4d6e2ef4f": "999999999999999900000", "444b1ae4d6e2ef50": "1e+21",
    "3eb0c6f7a0b5ed8c": "9.999999999999997e-7", "3eb0c6f7a0b5ed8d": "0.000001",
    "41b3de4355555553": "333333333.3333332", "41b3de4355555554": "333333333.33333325",
    "41b3de4355555555": "333333333.3333333", "41b3de4355555556": "333333333.3333334",
    "41b3de4355555557": "333333333.33333343", "becbf647612f3696": "-0.0000033333333333333333",
    "43143ff3c1cb0959": "1424953923781206.2",
}


def code(data):
    try:
        jsonstrict.parse(data)
    except AabError as exc:
        return exc.code
    return None


class Numbers(unittest.TestCase):
    def test_rfc8785_samples(self):
        for bits, want in RFC8785_NUMBERS.items():
            x = struct.unpack(">d", bytes.fromhex(bits))[0]
            self.assertEqual(number_to_string(x), want, bits)

    def test_boundaries(self):
        self.assertEqual(number_to_string(1e21), "1e+21")
        self.assertEqual(number_to_string(1e20), "100000000000000000000")
        self.assertEqual(number_to_string(1e-6), "0.000001")
        self.assertEqual(number_to_string(1e-7), "1e-7")
        self.assertEqual(number_to_string(123.0), "123")
        self.assertEqual(number_to_string(1.5e300), "1.5e+300")

    def test_e_number(self):
        self.assertEqual(code(b"9007199254740993"), "E_NUMBER")
        self.assertEqual(code(b"1e400"), "E_NUMBER")
        self.assertEqual(code(b"-1e400"), "E_NUMBER")
        self.assertEqual(code(b"1e-400"), "E_NUMBER")        # underflows to 0
        self.assertEqual(code(b"0.30000000000000001"), "E_NUMBER")
        for ok in (b"0.1", b"1.0", b"-0", b"1E2", b"1e-7", b"9007199254740992", b"0e99999"):
            self.assertIsNone(code(ok), ok)
        self.assertEqual(jcs(jsonstrict.parse(b"[-0,1.0,1E2]")), b"[0,1,100]")


class Strings(unittest.TestCase):
    def test_escaping(self):
        self.assertEqual(jcs("\u001f\b\t\n\f\r\"\\/\u2028\u00e9"),
                         b'"\\u001f\\b\\t\\n\\f\\r\\"\\\\/\xe2\x80\xa8\xc3\xa9"')

    def test_rfc8785_sort_example(self):
        # RFC 8785 section 3.2.3 example keys.
        obj = {"\u20ac": "Euro Sign", "\r": "Carriage Return", "\ufb01": "Latin Small Ligature Fi (U+FB33 of the RFC example is not NFC)",
               "1": "One", "\U0001F600": "Emoji: Grinning Face", "\u0080": "Control", "\u00f6": "Latin Small Letter O With Diaeresis"}
        out = jcs(obj).decode("utf-8")
        keys = [k for k in ("\r", "1", "\u0080", "\u00f6", "\u20ac", "\U0001F600", "\ufb01")]
        positions = [out.index(jcs(k).decode()) for k in keys]
        self.assertEqual(positions, sorted(positions))

    def test_rejections(self):
        self.assertEqual(code(b'{"a":1,"a":2}'), "E_DUP_KEY")
        self.assertEqual(code(b'{"a":1,"\\u0061":2}'), "E_DUP_KEY")
        self.assertEqual(code(b'[{"x":{"a":1,"a":2}}]'), "E_DUP_KEY")
        self.assertEqual(code('"cafe\u0301"'.encode()), "E_NOT_NFC")
        self.assertEqual(code('"\u0378"'.encode()), "E_NOT_NFC")
        self.assertEqual(code(b'"\\uD800"'), "E_BAD_UTF8")
        self.assertEqual(code(b'"\\uDC00\\uD800"'), "E_BAD_UTF8")
        self.assertEqual(code(b'"\\u0000"'), "E_BAD_UTF8")
        self.assertEqual(code(b'"\x00"'), "E_BAD_UTF8")
        self.assertEqual(code(b'"\xc0\xaf"'), "E_BAD_UTF8")
        self.assertEqual(code(b'"\xed\xa0\x80"'), "E_BAD_UTF8")  # encoded surrogate
        for bad in (b"NaN", b'{"a":NaN}', b"Infinity", b"[1,]", b"01", b"1.", b".5", b"+1", b"\xef\xbb\xbf{}",
                    b"", b'"\t"', b"{'a':1}", b"[1] 2"):
            self.assertEqual(code(bad), "E_JSON", bad)

    def test_surrogate_pair_escape_ok(self):
        self.assertEqual(jsonstrict.parse(b'"\\ud83d\\ude00"'), "\U0001F600")

    def test_precedence(self):
        # Grammar anywhere beats semantic errors; semantic errors in document order.
        self.assertEqual(code(b'{"a":1,"a":2'), "E_JSON")
        self.assertEqual(code(b'[{"a":1,"a":2},"\\u0000"]'), "E_DUP_KEY")
        self.assertEqual(code(b'["\\u0000",{"a":1,"a":2}]'), "E_BAD_UTF8")

    def test_spans(self):
        text = b'{"params":{"arguments":{"b":1, "a":2},"name":"x"}}'
        v, spans = jsonstrict.parse(text, spans=True)
        self.assertEqual(jsonstrict.raw_span(spans, ("params", "arguments")), b'{"b":1, "a":2}')


if __name__ == "__main__":
    unittest.main()
