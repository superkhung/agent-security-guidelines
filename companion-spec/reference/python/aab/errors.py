# SPDX-License-Identifier: Apache-2.0
"""Error codes of aab-00 (Section 10) and implementation-level exceptions.

``AabError`` carries exactly one code from Section 10. Two further
exceptions are *not* spec outcomes and must never be mapped to an ``E_*``
code by a caller:

* ``CryptoUnavailable``: verification reached a signature step and no
  crypto backend is installed (this milestone is stdlib-only).
* ``Unsupported``: the input needs a feature this implementation does not
  have (UTS #46 for non-ASCII hosts, RFC 3161 token validation).
"""

from __future__ import annotations

E_NOT_NFC = "E_NOT_NFC"
E_BAD_UTF8 = "E_BAD_UTF8"
E_TAG_ORDER = "E_TAG_ORDER"
E_MISSING_FIELD = "E_MISSING_FIELD"
E_UNKNOWN_TAG = "E_UNKNOWN_TAG"
E_LENGTH = "E_LENGTH"
E_VALUE = "E_VALUE"
E_DUP_KEY = "E_DUP_KEY"
E_NUMBER = "E_NUMBER"
E_JSON = "E_JSON"
E_ALG_MISMATCH = "E_ALG_MISMATCH"
E_FP_CHANGED = "E_FP_CHANGED"
E_REPLAY = "E_REPLAY"
E_EXPIRED = "E_EXPIRED"
E_AUDIENCE = "E_AUDIENCE"
E_SESSION = "E_SESSION"
E_DIGEST_MISMATCH = "E_DIGEST_MISMATCH"
E_HEADER_MISMATCH = "E_HEADER_MISMATCH"
E_CBOR = "E_CBOR"
E_CREDENTIAL = "E_CREDENTIAL"
E_WA_TYPE = "E_WA_TYPE"
E_WA_CHALLENGE = "E_WA_CHALLENGE"
E_WA_ORIGIN = "E_WA_ORIGIN"
E_WA_AUTHDATA = "E_WA_AUTHDATA"
E_WA_RPID = "E_WA_RPID"
E_WA_FLAGS = "E_WA_FLAGS"
E_WA_SIGNATURE = "E_WA_SIGNATURE"
E_WA_COUNTER = "E_WA_COUNTER"
E_COSE = "E_COSE"
E_LEASE_BUDGET = "E_LEASE_BUDGET"
E_LEASE_REVOKED = "E_LEASE_REVOKED"
E_LEASE_SCOPE = "E_LEASE_SCOPE"
E_LEASE_CONSTRAINT = "E_LEASE_CONSTRAINT"
E_LOG_ID = "E_LOG_ID"
E_LOG_INDEX = "E_LOG_INDEX"
E_LOG_CHAIN = "E_LOG_CHAIN"
E_LOG_CHECKPOINT = "E_LOG_CHECKPOINT"
E_LOG_ROLLBACK = "E_LOG_ROLLBACK"
E_LOG_SESSION = "E_LOG_SESSION"

ALL_CODES = frozenset(v for k, v in dict(globals()).items() if k.startswith("E_"))


class AabError(Exception):
    """A rejection with one error code of Section 10."""

    def __init__(self, code: str, detail: str = ""):
        if code not in ALL_CODES:
            raise ValueError("not an aab-00 error code: %r" % code)
        super().__init__("%s: %s" % (code, detail) if detail else code)
        self.code = code
        self.detail = detail


class CryptoUnavailable(Exception):
    """Verification reached a signature check and no backend is installed."""


class Unsupported(Exception):
    """The input needs a feature this implementation does not provide."""
