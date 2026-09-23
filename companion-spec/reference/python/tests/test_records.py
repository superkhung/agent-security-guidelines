# SPDX-License-Identifier: Apache-2.0
"""Tagged records, digest references and server identities (Sections 4.2, 4.5, 5.2)."""

import unittest

import context  # noqa: F401
from aab import identity, log, records
from aab.encoding import i64, lp, u64
from aab.errors import AabError, Unsupported
from aab.records import encode_field


def code(fn, *a):
    try:
        fn(*a)
    except AabError as exc:
        return exc.code
    return None


LOG_ID = bytes(16)
HEAD = records.DigestRef("sha-256", log.head0(LOG_ID))
CP = [(1, LOG_ID), (2, u64(0)), (3, HEAD.encode()), (4, i64(0))]


def raw(fields):
    return b"".join(encode_field(t, v) for t, v in fields)


class TaggedRecords(unittest.TestCase):
    def test_valid_checkpoint(self):
        d = log.decode_checkpoint(raw(CP))
        self.assertEqual(d["size"], 0)
        self.assertEqual(d["head"], HEAD)

    def test_rules(self):
        dec = log.decode_checkpoint
        self.assertEqual(code(dec, raw([CP[1], CP[0], CP[2], CP[3]])), "E_TAG_ORDER")
        self.assertEqual(code(dec, raw([CP[0]] + CP)), "E_TAG_ORDER")
        self.assertEqual(code(dec, raw(CP) + b"\x00"), "E_LENGTH")
        self.assertEqual(code(dec, raw(CP)[:-1]), "E_LENGTH")
        self.assertEqual(code(dec, raw(CP + [(0x7F, b"")])), "E_UNKNOWN_TAG")
        self.assertEqual(code(dec, raw(CP[:3])), "E_MISSING_FIELD")
        self.assertEqual(code(dec, raw([CP[0], (2, u64(0)[1:]), CP[2], CP[3]])), "E_LENGTH")
        self.assertEqual(code(dec, raw([(1, bytes(15))] + CP[1:])), "E_LENGTH")

    def test_empty_vs_absent(self):
        # An empty value is a present field (4.2 rule 2).
        a = raw([(1, b"x")])
        b = raw([(1, b"x"), (2, b"")])
        self.assertNotEqual(a, b)
        self.assertEqual(records.split_record(b, {1, 2}), {1: b"x", 2: b""})

    def test_log_record_rules(self):
        base = log.build(LOG_ID, 0, 0, bytes(16), 0, 0)
        self.assertEqual(log.decode(base)["type"], 0)
        bad = base.replace(encode_field(6, b"\x00"), encode_field(6, b"\x09"))
        self.assertEqual(code(log.decode, bad), "E_VALUE")
        self.assertEqual(code(log.decode, log.build(LOG_ID, 0, 0, bytes(16), 1, 2)), "E_MISSING_FIELD")
        self.assertEqual(code(log.decode, log.build(LOG_ID, 0, 0, bytes(16), 1, 1, decision=3)), "E_VALUE")
        self.assertEqual(code(log.decode, log.build(LOG_ID, 0, 0, bytes(16), 1, 2, decision=7)), "E_VALUE")


class DigestRefs(unittest.TestCase):
    def test_decode(self):
        d = bytes(32)
        ok = lp(b"sha-256") + lp(d)
        self.assertEqual(records.decode_digest_ref(ok, "sha-256"), records.DigestRef("sha-256", d))
        self.assertEqual(code(records.decode_digest_ref, lp(b"sha-256") + lp(bytes(31)), "sha-256"), "E_LENGTH")
        self.assertEqual(code(records.decode_digest_ref, lp(b"sha-1") + lp(bytes(20)), "sha-256"), "E_ALG_MISMATCH")
        self.assertEqual(code(records.decode_digest_ref, lp(b"sha-384") + lp(bytes(48)), "sha-256"),
                         "E_ALG_MISMATCH")
        self.assertEqual(code(records.decode_digest_ref, ok + b"\x00", "sha-256"), "E_LENGTH")

    def test_text_form(self):
        ref = records.DigestRef("sha-256", bytes(32))
        self.assertEqual(records.parse_ref_text(ref.text()), ref)

    def test_domain_separation(self):
        self.assertNotEqual(records.digest("action", b""), records.digest("lease", b""))
        self.assertNotEqual(records.digest("action", b"", "sha-256"), records.digest("action", b"", "sha-512")[:32])


class ServerIdentities(unittest.TestCase):
    def test_url_normalization(self):
        n = identity.normalize_url
        self.assertEqual(n("HTTPS://MCP.Example:443/mcp"), "https://mcp.example/mcp")
        self.assertEqual(n("https://mcp.example"), "https://mcp.example/")
        self.assertEqual(n("https://mcp.example:8443/a%2fb#frag"), "https://mcp.example:8443/a%2Fb")
        self.assertEqual(n("https://[2001:db8::1]/"), "https://[2001:db8::1]/")
        self.assertEqual(n("https://127.0.0.1/"), "https://127.0.0.1/")
        self.assertEqual(n("https://mcp.example/MCP"), "https://mcp.example/MCP")

    def test_url_rejections(self):
        n = identity.normalize_url
        for bad in ("http://mcp.example/", "https://user:pass@mcp.example/", "https://mcp.example/?b=2&a=1",
                    "https://mcp.example/?", "https://mcp.example:/", "https://mcp.example:0443/",
                    "https://mcp.example:70000/", "https://mcp.example./", "https://mcp.example/a/../b",
                    "https://mcp.example/%2e%2E/x", "https://mcp.example\\@evil/", "https://m cp.example/",
                    "https://[2001:DB8:0:0::1]/", "https://0x7f.1/", "https://127.1/", "https://mcp.example/%zz",
                    "https://-a.example/", "https://ab--c.example/", "https://mcp.example/a b"):
            self.assertEqual(code(n, bad), "E_VALUE", bad)

    def test_non_ascii_host_unsupported(self):
        with self.assertRaises(Unsupported):
            identity.normalize_url("https://stra\u00dfe.example/")
        with self.assertRaises(Unsupported):
            identity.normalize_url("https://xn--strae-oqa.example/")

    def test_decode_requires_normalized_url(self):
        good = identity.make("url", "https://mcp.example/mcp").encode()
        self.assertEqual(identity.decode(good).id, "https://mcp.example/mcp")
        bad = lp(b"url") + lp(b"https://MCP.example/mcp")
        self.assertEqual(code(identity.decode, bad), "E_VALUE")
        self.assertEqual(code(identity.decode, good + b"\x00\x00"), "E_LENGTH")

    def test_other_kinds(self):
        h = "0" * 64
        identity.make("oci", "docker.io/library/nginx@sha256:" + h)
        identity.make("oci", "localhost:5000/a/b@sha256:" + h)
        identity.make("pkg", "npm:@scope/server@1.2.3#sha512-abc+/=")
        identity.make("local", "/usr/local/bin/mcp-files#sha256:" + h)
        for kind, id_ in (("oci", "nginx@sha256:" + h), ("oci", "docker.io/library/nginx:latest"),
                          ("oci", "docker.io/Library/nginx@sha256:" + h), ("oci", "docker.io/x@sha256:" + "A" * 64),
                          ("pkg", "npm:server"), ("local", "bin/mcp#sha256:" + h), ("git", "x")):
            self.assertEqual(code(identity.make, kind, id_), "E_VALUE", (kind, id_))


if __name__ == "__main__":
    unittest.main()
