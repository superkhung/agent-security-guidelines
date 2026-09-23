# SPDX-License-Identifier: Apache-2.0
"""Tagged records (Section 4.2), digests and digest references (Section 4.5).

Decoding order used for every tagged record (the spec lists the rules of
Section 4.2 but not their order):

1. framing, left to right: header truncated or length beyond input
   (``E_LENGTH``), value over 2^24 (``E_LENGTH``), tag not greater than the
   previous one (``E_TAG_ORDER``), tag not in the schema (``E_UNKNOWN_TAG``);
2. required tags present (``E_MISSING_FIELD``);
3. each field value, in tag order (fixed widths ``E_LENGTH``, enumerations
   ``E_VALUE``, strings, JSON, sub-structures and digest references with
   their own errors);
4. record-specific cross-field checks.
"""

from __future__ import annotations

import hashlib
from typing import Callable, Dict, NamedTuple, Optional

from . import encoding, identity, jcs, jsonstrict
from .encoding import MAX_VALUE_LEN, b64u, lp, split_lp, u16, u32
from .errors import (
    AabError,
    E_ALG_MISMATCH,
    E_JSON,
    E_LENGTH,
    E_MISSING_FIELD,
    E_TAG_ORDER,
    E_UNKNOWN_TAG,
    E_VALUE,
)

# SPEC-AMBIGUITY: 4.2: the order in which the rules of Section 4.2 are applied
# is not specified (e.g. a record with an out-of-order tag *and* a missing
# field). We use framing -> missing -> values -> cross-field (module docstring).

WIRE_VERSION = "00"

HASHES = {
    "sha-256": (hashlib.sha256, 32),
    "sha-384": (hashlib.sha384, 48),
    "sha-512": (hashlib.sha512, 64),
}

OBJECT_TYPES = (
    "tool-fp", "action", "lease", "log-genesis", "log-link",
    "checkpoint", "credential", "payload",
)


class Config:
    """Per-deployment algorithm choice per object type (Section 4.5)."""

    def __init__(self, algs: Optional[Dict[str, str]] = None, default: str = "sha-256"):
        self.algs = dict(algs or {})
        self.default = default

    def alg(self, object_type: str) -> str:
        return self.algs.get(object_type, self.default)


DEFAULT_CONFIG = Config()


def domain_prefix(object_type: str, alg: str) -> bytes:
    return lp(encoding.utf8("aab/%s/%s/%s" % (WIRE_VERSION, object_type, alg)))


def digest(object_type: str, body: bytes, alg: str = "sha-256") -> bytes:
    """``H_alg(lp(utf8("aab/00/" + object_type + "/" + alg)) || body)``."""
    if object_type not in OBJECT_TYPES:
        raise ValueError("unknown object type %r" % object_type)
    if alg not in HASHES:
        raise AabError(E_ALG_MISMATCH, "unknown algorithm %r" % alg)
    return HASHES[alg][0](domain_prefix(object_type, alg) + body).digest()


class DigestRef(NamedTuple):
    alg: str
    digest: bytes

    def encode(self) -> bytes:
        """``lp(utf8(alg)) || lp(digest)``."""
        return lp(encoding.utf8(self.alg)) + lp(self.digest)

    def text(self) -> str:
        return "%s:%s" % (self.alg, b64u(self.digest))


def ref_of(object_type: str, body: bytes, alg: str = "sha-256") -> DigestRef:
    return DigestRef(alg, digest(object_type, body, alg))


def parse_ref_text(s: str) -> DigestRef:
    alg, _, b = s.partition(":")
    return DigestRef(alg, encoding.b64u_decode(b))


def decode_digest_ref(value: bytes, expected_alg: str) -> DigestRef:
    """Decode a digest reference (Section 4.5).

    ``E_LENGTH`` if the lp() values do not fill the value, ``E_ALG_MISMATCH``
    if ``alg`` is unknown or not ``expected_alg``, ``E_LENGTH`` if the digest
    length differs from the output length of ``alg``.
    """
    alg_b, dig = split_lp(value, 2)
    alg = encoding.check_string(alg_b)
    if alg not in HASHES:
        raise AabError(E_ALG_MISMATCH, "unknown digest algorithm %r" % alg)
    if alg != expected_alg:
        raise AabError(E_ALG_MISMATCH, "digest algorithm %r, expected %r" % (alg, expected_alg))
    if len(dig) != HASHES[alg][1]:
        raise AabError(E_LENGTH, "%s digest of %d bytes" % (alg, len(dig)))
    return DigestRef(alg, dig)


# --- tagged records ---------------------------------------------------------


def encode_record(fields) -> bytes:
    """Encode ``[(tag, value_bytes), ...]`` (must already be in tag order)."""
    out = []
    prev = -1
    for tag, value in fields:
        if tag <= prev:
            raise ValueError("tags must be strictly increasing")
        if len(value) > MAX_VALUE_LEN:
            raise AabError(E_LENGTH, "value longer than 2^24")
        prev = tag
        out.append(u16(tag) + u32(len(value)) + value)
    return b"".join(out)


def encode_field(tag: int, value: bytes) -> bytes:
    """One raw field, with no ordering checks (for building bad vectors)."""
    return u16(tag) + u32(len(value)) + value


def split_record(data: bytes, known_tags) -> Dict[int, bytes]:
    """Framing pass of Section 4.2 (rules 1, 3 unknown-tag, 4, 5)."""
    data = bytes(data)
    pos = 0
    prev = -1
    out = {}
    while pos < len(data):
        if len(data) - pos < 6:
            raise AabError(E_LENGTH, "%d trailing bytes after last field" % (len(data) - pos))
        tag = int.from_bytes(data[pos:pos + 2], "big")
        n = int.from_bytes(data[pos + 2:pos + 6], "big")
        pos += 6
        if n > len(data) - pos:
            raise AabError(E_LENGTH, "field 0x%02X length %d exceeds remaining input" % (tag, n))
        if n > MAX_VALUE_LEN:
            raise AabError(E_LENGTH, "field 0x%02X longer than 2^24" % tag)
        if tag <= prev:
            raise AabError(E_TAG_ORDER, "tag 0x%02X after 0x%02X" % (tag, prev))
        if tag not in known_tags:
            raise AabError(E_UNKNOWN_TAG, "unknown tag 0x%02X" % tag)
        prev = tag
        out[tag] = data[pos:pos + n]
        pos += n
    return out


class Field(NamedTuple):
    name: str
    required: bool
    decode: Callable  # (value_bytes, cfg) -> python value


def decode_record(data: bytes, schema: Dict[int, Field], cfg: Config = DEFAULT_CONFIG) -> dict:
    """Decode a tagged record against ``schema``; return ``{name: value}``.

    The raw field bytes are kept under ``"_raw"`` (tag -> bytes).
    """
    raw = split_record(data, schema.keys())
    for tag in sorted(schema):
        if schema[tag].required and tag not in raw:
            raise AabError(E_MISSING_FIELD, "missing tag 0x%02X (%s)" % (tag, schema[tag].name))
    out = {"_raw": raw}
    for tag in sorted(raw):
        f = schema[tag]
        out[f.name] = f.decode(raw[tag], cfg)
    return out


# --- field decoders ---------------------------------------------------------


def f_utf8(v, cfg):
    return encoding.check_string(v)


def f_u8(v, cfg):
    return encoding.read_fixed_uint(v, 1)


def f_u64(v, cfg):
    return encoding.read_fixed_uint(v, 8)


def f_i64(v, cfg):
    return encoding.read_i64(v)


def f_id16(v, cfg):
    return encoding.read_id16(v)


def f_enum8(allowed):
    def dec(v, cfg):
        n = encoding.read_fixed_uint(v, 1)
        if n not in allowed:
            raise AabError(E_VALUE, "value %d outside its table" % n)
        return n
    return dec


def f_server_identity(v, cfg):
    return identity.decode(v)


def f_ref(object_type):
    def dec(v, cfg):
        return decode_digest_ref(v, cfg.alg(object_type))
    return dec


def f_json(require_object: bool = False):
    """A ``jcs(v)`` field: strict parse, then require canonical bytes."""
    def dec(v, cfg):
        val = jsonstrict.parse(v)
        # SPEC-AMBIGUITY: 4.2/4.3: nothing says a consumer must check that a
        # jcs() field is canonical, nor which error applies. The forwarding
        # rule (6.3) depends on it, so we require it and use E_JSON.
        if jcs.jcs(val) != bytes(v):
            raise AabError(E_JSON, "JSON field is not in RFC 8785 canonical form")
        if require_object and not isinstance(val, dict):
            raise AabError(E_JSON, "JSON field is not an object")
        return val
    return dec
