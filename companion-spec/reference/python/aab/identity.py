# SPDX-License-Identifier: Apache-2.0
"""Server identity (Section 5.2): ``lp(utf8(kind)) || lp(utf8(id))``.

URL identities are normalized by :func:`normalize_url`. Non-ASCII hosts
need UTS #46 non-transitional processing, which needs the IDNA mapping
table (not shipped with the Python standard library). This milestone
therefore raises :class:`~aab.errors.Unsupported` for non-ASCII hosts and
for ``xn--`` labels (whose validation also needs UTS #46 data).
"""

from __future__ import annotations

import ipaddress
import re

from . import encoding
from .encoding import lp, split_lp
from .errors import AabError, E_VALUE, Unsupported

KINDS = ("oci", "pkg", "url", "local")

_OCI_COMPONENT = r"[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*"
_OCI_RE = re.compile(
    r"^(?P<registry>[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]+)?)"
    r"/(?P<repo>" + _OCI_COMPONENT + r"(?:/" + _OCI_COMPONENT + r")*)"
    r"@sha256:[0-9a-f]{64}$"
)
_PKG_RE = re.compile(r"^(?P<eco>[a-z0-9][a-z0-9._-]*):(?P<name>[^#]+)@(?P<ver>[^@#]+)#(?P<integ>[^#\s]+)$")
_LOCAL_RE = re.compile(r"^(?P<path>(?:/|[A-Za-z]:\\).*)#sha256:[0-9a-f]{64}$", re.S)
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_PATH_OK = re.compile(r"^[A-Za-z0-9\-._~!$&'()*+,;=:@/%]*$")


class ServerIdentity:
    __slots__ = ("kind", "id")

    def __init__(self, kind: str, id_: str):
        self.kind = kind
        self.id = id_

    def encode(self) -> bytes:
        return lp(encoding.utf8(self.kind)) + lp(encoding.utf8(self.id))

    def __eq__(self, other):
        return isinstance(other, ServerIdentity) and self.encode() == other.encode()

    def __hash__(self):
        return hash(self.encode())

    def __repr__(self):
        return "ServerIdentity(%r, %r)" % (self.kind, self.id)


def _normalize_host(host: str) -> str:
    if host.startswith("["):
        if not host.endswith("]"):
            raise AabError(E_VALUE, "bad IPv6 literal")
        inner = host[1:-1].lower()
        try:
            addr = ipaddress.IPv6Address(inner)
        except ValueError:
            raise AabError(E_VALUE, "bad IPv6 literal")
        # SPEC-AMBIGUITY: 5.2: IPv6 literal normalization is not specified
        # (WHATWG serializes RFC 5952 form). We reject non-canonical forms.
        if addr.compressed != inner:
            raise AabError(E_VALUE, "IPv6 literal not in RFC 5952 form")
        return "[" + inner + "]"
    if any(ord(c) > 0x7F for c in host):
        # SPEC-AMBIGUITY: 5.2: UTS #46 flags (CheckHyphens, CheckBidi,
        # CheckJoiners, UseSTD3ASCIIRules, VerifyDnsLength) are not named.
        # UTS #46 mapping also case-folds and NFKC-maps input (e.g. fullwidth
        # letters), a "repair" that D4/Section 4 otherwise forbid; the spec
        # does not say whether the Section 4.1 NFC check applies before
        # mapping (we apply it first, to the whole URL).
        raise Unsupported("non-ASCII host needs UTS #46 (not in stdlib)")
    h = host.lower()
    if not h or "%" in h:
        raise AabError(E_VALUE, "empty or percent-encoded host")
    # SPEC-AMBIGUITY: 5.2: a trailing dot ("mcp.example.") names the same
    # host with different bytes; not addressed. We reject it.
    if h.endswith("."):
        raise AabError(E_VALUE, "trailing dot in host")
    if len(h) > 253:
        raise AabError(E_VALUE, "host longer than 253 octets")
    labels = h.split(".")
    for label in labels:
        if label.startswith("xn--"):
            raise Unsupported("A-label validation needs UTS #46 (not in stdlib)")
        if not _LABEL_RE.match(label):
            raise AabError(E_VALUE, "host label %r is not LDH" % label)
        if label[2:4] == "--":
            raise AabError(E_VALUE, "label with '--' in positions 3-4 (CheckHyphens)")
    last = labels[-1]
    # SPEC-AMBIGUITY: 5.2: hosts that WHATWG parses as IPv4 numbers
    # ("0x7f.1", "127.1") are not addressed. We accept only canonical
    # dotted-quad IPv4 when the last label is numeric.
    if last.isdigit() or last.startswith("0x"):
        try:
            v4 = ipaddress.IPv4Address(h)
        except ValueError:
            raise AabError(E_VALUE, "numeric host that is not a canonical IPv4 address")
        if str(v4) != h:
            raise AabError(E_VALUE, "non-canonical IPv4 address")
    return h


def normalize_url(url: str) -> str:
    """Normalize a URL server identity (Section 5.2, rules 1 and 2)."""
    encoding.check_text(url)
    # SPEC-AMBIGUITY: 5.2: backslash handling differs between WHATWG (treated
    # as '/') and RFC 3986 (invalid). We reject any backslash.
    if "\\" in url:
        raise AabError(E_VALUE, "backslash in URL")
    if any(c <= " " or c == "\x7f" for c in url):
        raise AabError(E_VALUE, "whitespace or control character in URL")
    scheme, sep, rest = url.partition(":")
    if not sep or scheme.lower() != "https":
        raise AabError(E_VALUE, "scheme must be https")
    if not rest.startswith("//"):
        raise AabError(E_VALUE, "missing authority")
    rest = rest[2:]
    cut = len(rest)
    for ch in "/?#":
        j = rest.find(ch)
        if j != -1:
            cut = min(cut, j)
    authority, tail = rest[:cut], rest[cut:]
    if "@" in authority:
        raise AabError(E_VALUE, "userinfo not allowed")
    path, _, _fragment = tail.partition("#")  # fragment removed
    if "?" in path:
        # SPEC-AMBIGUITY: 5.2: an empty query ("https://h/?") is not
        # mentioned; we treat any '?' as a query and reject.
        raise AabError(E_VALUE, "query not allowed")
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            raise AabError(E_VALUE, "bad IPv6 literal")
        host, port_part = authority[:end + 1], authority[end + 1:]
        if port_part and not port_part.startswith(":"):
            raise AabError(E_VALUE, "garbage after IPv6 literal")
        port = port_part[1:] if port_part else None
    else:
        host, sep, port = authority.partition(":")
        port = port if sep else None
    host = _normalize_host(host)
    if port is not None:
        # SPEC-AMBIGUITY: 5.2: empty port, leading zeros and out-of-range
        # ports are not addressed. We reject all three.
        if not port.isdigit() or not port.isascii() or (len(port) > 1 and port[0] == "0"):
            raise AabError(E_VALUE, "bad port")
        if not 1 <= int(port) <= 65535:
            raise AabError(E_VALUE, "port out of range")
        if port == "443":
            port = None
    if path == "":
        path = "/"
    # SPEC-AMBIGUITY: 5.2: characters outside RFC 3986 pchar are not
    # addressed (WHATWG percent-encodes them). We reject them.
    if not _PATH_OK.match(path):
        raise AabError(E_VALUE, "character not allowed in path")
    out = []
    i = 0
    while i < len(path):
        c = path[i]
        if c == "%":
            h = path[i + 1:i + 3]
            if len(h) != 2 or any(x not in "0123456789abcdefABCDEF" for x in h):
                raise AabError(E_VALUE, "bad percent-encoding")
            out.append("%" + h.upper())
            i += 3
        else:
            out.append(c)
            i += 1
    path = "".join(out)
    # SPEC-AMBIGUITY: 5.2: dot segments are not addressed (WHATWG and
    # RFC 3986 remove them, a raw-string implementation keeps them). We reject
    # them, including percent-encoded dots.
    for seg in path.split("/"):
        if seg.upper().replace("%2E", ".") in (".", ".."):
            raise AabError(E_VALUE, "dot segment in path")
    return "https://" + host + (":" + port if port else "") + path


def validate_id(kind: str, id_: str) -> None:
    """Consumer-side check of an identity ``id`` (Section 5.2)."""
    # SPEC-AMBIGUITY: 5.2: the spec gives formats for oci/pkg/local ids but no
    # grammar, and says only that URL-rule violations are E_VALUE. We apply
    # each format strictly and reject violations with E_VALUE.
    # SPEC-AMBIGUITY: 5.2: it is not said whether a *decoded* url identity
    # must already be normalized. We require it (a consumer does not repair)
    # and reject a non-normalized one with E_VALUE.
    if kind not in KINDS:
        # SPEC-AMBIGUITY: 5.2/4.2: an unknown kind is not listed as an
        # enumerated value; we reject it with E_VALUE.
        raise AabError(E_VALUE, "unknown server identity kind %r" % kind)
    if kind == "url":
        if normalize_url(id_) != id_:
            raise AabError(E_VALUE, "url identity not normalized")
    elif kind == "oci":
        m = _OCI_RE.match(id_)
        if not m:
            raise AabError(E_VALUE, "oci identity not <registry>/<repo>@sha256:<hex>")
        reg = m.group("registry")
        # SPEC-AMBIGUITY: 5.2: "fully qualified" is not defined. We use the
        # Docker rule: the first component is a registry only if it contains
        # '.' or ':' or is 'localhost'.
        if "." not in reg and ":" not in reg and reg != "localhost":
            raise AabError(E_VALUE, "oci identity not fully qualified")
    elif kind == "pkg":
        # SPEC-AMBIGUITY: 5.2: no grammar for ecosystem, name, version or
        # integrity; '@' appears in scoped npm names. We split on the last
        # '@' before the single '#'.
        if not _PKG_RE.match(id_):
            raise AabError(E_VALUE, "pkg identity not <eco>:<name>@<version>#<integrity>")
    elif kind == "local":
        # SPEC-AMBIGUITY: 5.2: "absolute path" is not defined across OSes and
        # the hex case is not stated. We accept POSIX '/...' and Windows
        # 'X:\...' paths and require lowercase hex.
        if not _LOCAL_RE.match(id_):
            raise AabError(E_VALUE, "local identity not <absolute path>#sha256:<hex>")


def make(kind: str, id_: str) -> ServerIdentity:
    """Producer side: build an identity, normalizing a URL (Section 5.2)."""
    if kind == "url":
        id_ = normalize_url(id_)
    encoding.check_text(kind)
    encoding.check_text(id_)
    validate_id(kind, id_)
    return ServerIdentity(kind, id_)


def decode(value: bytes) -> ServerIdentity:
    """Consumer side: decode and validate identity bytes (Section 4.2, 5.2)."""
    kind_b, id_b = split_lp(value, 2)
    kind = encoding.check_string(kind_b)
    id_ = encoding.check_string(id_b)
    validate_id(kind, id_)
    return ServerIdentity(kind, id_)
