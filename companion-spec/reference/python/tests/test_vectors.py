# SPDX-License-Identifier: Apache-2.0
"""Every vector file must match the reference implementation (as run.py checks)."""

import importlib.util
import os
import unittest

import context


def _load_runner():
    spec = importlib.util.spec_from_file_location("aab_run", os.path.join(context.VECTORS, "run.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Vectors(unittest.TestCase):
    def test_all_catalogue_ids_have_files(self):
        run = _load_runner()
        for vid in run.catalogue_ids():
            path = os.path.join(context.VECTORS, vid.split("-")[0], vid + ".json")
            self.assertTrue(os.path.exists(path), vid)

    def test_all_vectors(self):
        import glob
        import json

        run = _load_runner()
        vectors = []
        for path in sorted(glob.glob(os.path.join(context.VECTORS, "*", "*.json"))):
            with open(path, encoding="utf-8") as fh:
                vectors.append(json.load(fh))
        by_id = {v["id"]: v for v in vectors}
        from aab import sigs

        active = sigs.default_backend()
        for backend in {type(active): active, sigs.NullBackend: sigs.NullBackend()}.values():
            for v in vectors:
                status, msg = run.check(v, by_id, backend)
                allowed = ("pass", "pending") if sigs.has_crypto(backend) else ("pass", "pending", "no-crypto")
                self.assertIn(status, allowed, "%s [%s]: %s" % (v["id"], backend.name, msg))
                if v["expected"].get("status") != "pending":
                    self.assertEqual(v["expected"]["source"], "reference-python-1")

    def test_only_uts46_and_rfc3161_pending(self):
        run = _load_runner()
        pending = sorted(v["id"] for v in run.load_vectors() if v["expected"].get("status") == "pending")
        self.assertEqual(pending, ["FP-016", "LOG-017"])


    def test_runner_detects_mismatch(self):
        run = _load_runner()
        v = context.load_vector("ACT-001")
        v["expected"]["digest"] = "sha-256:" + "A" * 43
        self.assertEqual(run.check(v, {})[0], "fail")
        v = context.load_vector("ENC-002")
        v["expected"]["error"] = "E_BAD_UTF8"
        self.assertEqual(run.check(v, {})[0], "fail")
        from aab import sigs

        v = context.load_vector("WA-001")
        v["precheck"] = {"stdlib": {"result": "accept"}}
        self.assertEqual(run.check(v, {}, sigs.NullBackend())[0], "fail")
        v = context.load_vector("WA-001")
        self.assertEqual(run.check(v, {}, sigs.NullBackend())[0], "no-crypto")
        if sigs.has_crypto(sigs.default_backend()):
            v["expected"]["result"] = "reject"
            self.assertEqual(run.check(v, {})[0], "fail")


class LogWriter(unittest.TestCase):
    def test_append_rules(self):
        from aab import log
        from aab.errors import AabError

        w = log.LogWriter(bytes(16))
        w.append(log.build(bytes(16), 0, 0, bytes(16), 0, 0))
        for bad, code in ((log.build(bytes(16), 2, 0, bytes(16), 0, 0), "E_LOG_INDEX"),
                          (log.build(b"\x01" * 16, 1, 0, bytes(16), 0, 0), "E_LOG_ID")):
            with self.assertRaises(AabError) as cm:
                w.append(bad)
            self.assertEqual(cm.exception.code, code)
        self.assertEqual(w.head, log.heads(bytes(16), w.records)[-1])


if __name__ == "__main__":
    unittest.main()
