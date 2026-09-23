# SPDX-License-Identifier: Apache-2.0
"""Test helpers: import path and fake signature backends.

The fake backends are NOT cryptography. They let the unit tests exercise
the verification logic that follows the signature step (counters, pending
entry consumption, checkpoint heads) without a crypto library. Vector files
never use them: vectors that depend on a real signature stay pending.
"""

import os
import sys
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VECTORS = os.path.normpath(os.path.join(ROOT, "..", "..", "vectors"))
SPEC = os.path.normpath(os.path.join(ROOT, "..", "..", "agent-action-binding-draft-00.md"))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
warnings.simplefilter("ignore", RuntimeWarning)

from aab import sigs  # noqa: E402


class AcceptAll(sigs.SignatureBackend):
    """Pretends every signature verifies. Test-only."""

    def __init__(self):
        self.calls = []

    def verify(self, key, alg, message, signature, rs=None):
        self.calls.append((alg, message, signature))
        return True


class RejectAll(sigs.SignatureBackend):
    """Pretends every signature fails. Test-only."""

    def verify(self, key, alg, message, signature, rs=None):
        return False


def load_vector(vid):
    import json

    group = vid.split("-")[0]
    with open(os.path.join(VECTORS, group, vid + ".json"), encoding="utf-8") as fh:
        return json.load(fh)
