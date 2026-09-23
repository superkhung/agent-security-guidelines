# SPDX-License-Identifier: Apache-2.0
"""Lease constraints (Section 8.3) and tool entries (Section 8.1)."""

import unittest

import context  # noqa: F401
from aab import lease
from aab.errors import AabError


def code(fn, *a):
    try:
        fn(*a)
    except AabError as exc:
        return exc.code
    return None


class Beneath(unittest.TestCase):
    def test_examples_from_spec(self):
        self.assertTrue(lease.beneath("src/a/b.py", "src"))
        for bad in ("srcfoo/a", "src/../.env", "./src/a", "src//a", "/etc/passwd", "src\\..\\x", "", "docs/a.md",
                    "src/", 1, None):
            self.assertFalse(lease.beneath(bad, "src"), bad)

    def test_multi_segment_root(self):
        self.assertTrue(lease.beneath("src/app/x.py", "src/app"))
        self.assertFalse(lease.beneath("src/application/x.py", "src/app"))

    def test_root_itself(self):
        # Follows the letter of 8.3 (see the ambiguity marker in lease.beneath).
        self.assertTrue(lease.beneath("src", "src"))


class Constraints(unittest.TestCase):
    def v(self, cs, tools=("write_file",)):
        return code(lease.validate_constraints, cs, set(tools))

    def test_validation(self):
        ok = [{"tool": "write_file", "pointer": "/path", "op": "beneath", "value": "src"},
              {"pointer": "/mode", "op": "absent"}, {"pointer": "/n", "op": "max", "value": 10.0},
              {"pointer": "/e", "op": "in", "value": ["a", "b"]}, {"pointer": "", "op": "eq", "value": {}}]
        self.assertIsNone(self.v(ok))
        for bad in ([{"pointer": "/p", "op": "glob", "value": "x"}], [{"pointer": "/p", "op": "eq"}],
                    [{"op": "eq", "value": 1}], [{"pointer": "/p", "op": "eq", "value": 1, "x": 1}],
                    [{"pointer": "/p", "op": "absent", "value": 1}], [{"pointer": "p", "op": "eq", "value": 1}],
                    [{"pointer": "/~2", "op": "eq", "value": 1}], [{"pointer": "/p", "op": "beneath", "value": "../src"}],
                    [{"pointer": "/p", "op": "beneath", "value": "src/"}], [{"pointer": "/p", "op": "in", "value": 1}],
                    [{"pointer": "/p", "op": "max", "value": "1"}], [{"pointer": "/p", "op": "prefix", "value": 1}],
                    [{"tool": "write_fil", "pointer": "/p", "op": "eq", "value": 1}], {"not": "an array"}, [1]):
            self.assertEqual(self.v(bad), "E_VALUE", bad)

    def test_evaluation(self):
        args = {"path": "src/a.py", "n": 3.0, "list": [1.0, {"a~b": "x", "c/d": "y"}]}
        holds = lease.constraint_holds
        self.assertTrue(holds({"pointer": "/path", "op": "prefix", "value": "src/"}, args))
        self.assertTrue(holds({"pointer": "/n", "op": "max", "value": 3.0}, args))
        self.assertFalse(holds({"pointer": "/n", "op": "max", "value": 2.0}, args))
        self.assertTrue(holds({"pointer": "/list/1/a~0b", "op": "eq", "value": "x"}, args))
        self.assertTrue(holds({"pointer": "/list/1/c~1d", "op": "in", "value": ["y"]}, args))
        self.assertFalse(holds({"pointer": "/list/01", "op": "absent"}, args) is False and False)
        self.assertTrue(holds({"pointer": "/list/01", "op": "absent"}, args))
        self.assertTrue(holds({"pointer": "/missing", "op": "absent"}, args))
        self.assertFalse(holds({"pointer": "/missing", "op": "eq", "value": None}, args))
        self.assertFalse(holds({"pointer": "/path", "op": "absent"}, args))
        # A tool-scoped constraint does not apply to other tools.
        cs = [{"tool": "write_file", "pointer": "/path", "op": "beneath", "value": "src"}]
        self.assertIsNone(code(lease.check_constraints, cs, "read_file", {"path": "/etc/passwd"}))
        self.assertEqual(code(lease.check_constraints, cs, "write_file", {"path": "/etc/passwd"}), "E_LEASE_CONSTRAINT")


if __name__ == "__main__":
    unittest.main()
