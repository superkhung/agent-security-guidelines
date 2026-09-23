# SPDX-License-Identifier: Apache-2.0
"""RFC 8785 JSON Canonicalization Scheme, ``jcs(v)`` of Section 2.2 / 4.3.

* Numbers: ECMAScript ``Number::toString`` (RFC 8785 section 3.2.2.3). The digit
  string comes from CPython's ``repr(float)``, which returns the shortest
  digit string that round-trips and, among those, the one closest to the
  value (David Gay's algorithm, mode 0). The ECMAScript formatting rules
  are applied to those digits here.
* Strings: RFC 8785 section 3.2.2.2 (ECMAScript ``JSON.stringify`` escaping).
* Object members sorted by UTF-16 code units (RFC 8785 section 3.2.3).
"""

from __future__ import annotations

import math

from . import encoding
from .errors import AabError, E_NUMBER

_ESC = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def number_to_string(x: float) -> str:
    """ECMAScript Number::toString for a finite binary64 value."""
    x = float(x)
    if math.isnan(x) or math.isinf(x):
        raise AabError(E_NUMBER, "NaN/Infinity have no JSON form")
    if x == 0:
        return "0"  # covers -0 (RFC 8785 section 3.2.2.3)
    if x < 0:
        return "-" + number_to_string(-x)
    r = repr(x)
    mant, _, exp = r.partition("e")
    e10 = int(exp) if exp else 0
    ip, _, fp = mant.partition(".")
    digits = ip + fp
    e10 -= len(fp)
    digits = digits.lstrip("0")
    while digits.endswith("0"):
        digits = digits[:-1]
        e10 += 1
    k = len(digits)
    n = k + e10  # value = digits * 10^(n-k)
    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    e = n - 1
    sign = "+" if e >= 0 else "-"
    if k == 1:
        return digits + "e" + sign + str(abs(e))
    return digits[0] + "." + digits[1:] + "e" + sign + str(abs(e))


def _string(s: str) -> str:
    encoding.check_text(s)
    out = ['"']
    for ch in s:
        o = ord(ch)
        if o in _ESC:
            out.append(_ESC[o])
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(s: str) -> bytes:
    return s.encode("utf-16-be", errors="strict")


def _ser(v, out: list) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, (int, float)):
        f = float(v)
        if isinstance(v, int) and int(f) != v:
            raise AabError(E_NUMBER, "integer %d not exactly representable" % v)
        out.append(number_to_string(f))
    elif isinstance(v, str):
        out.append(_string(v))
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, item in enumerate(v):
            if i:
                out.append(",")
            _ser(item, out)
        out.append("]")
    elif isinstance(v, dict):
        out.append("{")
        for i, key in enumerate(sorted(v, key=_utf16_key)):
            if i:
                out.append(",")
            out.append(_string(key))
            out.append(":")
            _ser(v[key], out)
        out.append("}")
    else:
        raise TypeError("not a JSON value: %r" % type(v))


def serialize_text(v) -> str:
    out = []
    _ser(v, out)
    return "".join(out)


def jcs(v) -> bytes:
    """RFC 8785 serialization of ``v`` as UTF-8 bytes."""
    return serialize_text(v).encode("utf-8")


def canonicalize_text(data) -> bytes:
    """Parse JSON text strictly (Section 4.3) and return its JCS bytes."""
    from .jsonstrict import parse

    return jcs(parse(data))
