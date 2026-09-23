# SPDX-License-Identifier: Apache-2.0
"""Tool fingerprint (Section 5): record, digest and comparison point (5.4)."""

from __future__ import annotations

from typing import Dict, Optional, Tuple

from . import encoding, jsonstrict
from .errors import AabError, E_FP_CHANGED, E_JSON, E_MISSING_FIELD
from .identity import ServerIdentity
from .jcs import jcs
from .records import (
    DEFAULT_CONFIG,
    Config,
    DigestRef,
    Field,
    decode_record,
    encode_record,
    f_json,
    f_server_identity,
    f_utf8,
    ref_of,
)

OBJECT_TYPE = "tool-fp"

SCHEMA = {
    0x01: Field("server", True, f_server_identity),
    0x02: Field("name", True, f_utf8),
    0x03: Field("title", False, f_utf8),
    0x04: Field("description", False, f_utf8),
    0x05: Field("inputSchema", True, f_json()),
    0x06: Field("outputSchema", False, f_json()),
    0x07: Field("annotations", False, f_json()),
}


def _string_member(tool: dict, key: str, required: bool) -> Optional[str]:
    if key not in tool:
        if required:
            # SPEC-AMBIGUITY: 5.1: the error for a tool definition that lacks
            # `name` or `inputSchema` is not given. We use E_MISSING_FIELD.
            raise AabError(E_MISSING_FIELD, "tool definition lacks %r" % key)
        return None
    v = tool[key]
    if not isinstance(v, str):
        # SPEC-AMBIGUITY: 5.1: a member of the wrong JSON type (for example
        # "title": null) is not addressed. We reject with E_JSON.
        raise AabError(E_JSON, "tool member %r is not a string" % key)
    return v


def _object_member(tool: dict, key: str, required: bool):
    if key not in tool:
        if required:
            raise AabError(E_MISSING_FIELD, "tool definition lacks %r" % key)
        return None
    v = tool[key]
    # SPEC-AMBIGUITY: 5.1: the spec says jcs(inputSchema) etc. without
    # requiring an object; MCP requires objects. We reject non-objects with
    # E_JSON.
    if not isinstance(v, dict):
        raise AabError(E_JSON, "tool member %r is not an object" % key)
    return v


def record(server: ServerIdentity, tool) -> bytes:
    """Build the tool-fp tagged record (Section 5.1) from a parsed definition.

    ``tool`` is a parsed JSON object (from :func:`aab.jsonstrict.parse`) or
    JSON text, which is then parsed with the rules of Section 4.3.
    """
    if isinstance(tool, (bytes, bytearray, str)):
        tool = jsonstrict.parse(tool)
    if not isinstance(tool, dict):
        raise AabError(E_JSON, "tool definition is not an object")
    fields = [(0x01, server.encode())]
    fields.append((0x02, encoding.utf8(_string_member(tool, "name", True))))
    title = _string_member(tool, "title", False)
    if title is not None:
        fields.append((0x03, encoding.utf8(title)))
    desc = _string_member(tool, "description", False)
    if desc is not None:
        fields.append((0x04, encoding.utf8(desc)))
    fields.append((0x05, jcs(_object_member(tool, "inputSchema", True))))
    out_schema = _object_member(tool, "outputSchema", False)
    if out_schema is not None:
        fields.append((0x06, jcs(out_schema)))
    ann = _object_member(tool, "annotations", False)
    if ann is not None:
        fields.append((0x07, jcs(ann)))
    return encode_record(fields)


def fingerprint(server: ServerIdentity, tool, alg: str = "sha-256") -> DigestRef:
    return ref_of(OBJECT_TYPE, record(server, tool), alg)


def decode(data: bytes, cfg: Config = DEFAULT_CONFIG) -> dict:
    return decode_record(data, SCHEMA, cfg)


class Comparator:
    """The comparison point of Section 5.4.

    Holds approved fingerprints keyed by ``(server identity bytes, name)``.
    :meth:`deliver` must be called on every definition *before* it reaches
    the model, including definitions served from a ``tools/list`` cache.
    """

    def __init__(self, alg: str = "sha-256"):
        self.alg = alg
        self.approved: Dict[Tuple[bytes, str], DigestRef] = {}

    def approve(self, server: ServerIdentity, tool) -> DigestRef:
        tool = jsonstrict.parse(tool) if isinstance(tool, (bytes, str)) else tool
        fp = fingerprint(server, tool, self.alg)
        self.approved[(server.encode(), tool["name"])] = fp
        return fp

    def deliver(self, server: ServerIdentity, tool) -> str:
        """Return ``"accept"`` or ``"new"``; raise ``E_FP_CHANGED``."""
        tool = jsonstrict.parse(tool) if isinstance(tool, (bytes, str)) else tool
        fp = fingerprint(server, tool, self.alg)
        key = (server.encode(), tool["name"])
        if key not in self.approved:
            # SPEC-AMBIGUITY: 5.4 rule 3: "treated as new" has no defined
            # outcome (block? deliver and request approval?). We return "new"
            # and leave the decision to policy.
            return "new"
        if self.approved[key] != fp:
            raise AabError(E_FP_CHANGED, "fingerprint %s, approved %s" % (fp.text(), self.approved[key].text()))
        return "accept"
