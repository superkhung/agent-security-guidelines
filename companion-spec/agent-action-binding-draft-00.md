# Agent Action Binding: Wire Format and Test Vectors

| | |
| :--- | :--- |
| Draft | `aab-00` (first working draft) |
| Status | Working draft. **Not for implementation.** Tag numbers, encodings and error codes will change. |
| Companion to | *Hướng dẫn kỹ thuật an ninh cho AI Agent* (Agent Security Technical Guidelines) 0.1.0, Phụ lục E |
| Author | superkhung · VNSecurity |
| Date | 2026-09-23 |
| Tracks | Model Context Protocol specification 2026-07-28; WebAuthn Level 3; RFC 8785, RFC 8949, RFC 9052, RFC 9864, RFC 3161; Unicode 16.0.0 |

---

## Status of this draft

This draft fixes the *structure* of the specification and the *catalogue* of test vectors. It proposes concrete byte layouts so that reviewers have something precise to attack, but none of them is stable.

Per the guideline (Phụ lục E), this specification will be frozen only after:

1. the semantics of SC-05, ACT-04, ACT-06 and OBS-02 in the guideline are stable after the public comment round;
2. every test vector in Appendix B has expected values produced by at least two independent implementations that agree byte for byte;
3. the vectors run with one command in CI.

Until then, the only normative-looking text that reviewers should treat as settled is the list of design decisions in Section 1.3, because those come directly from the guideline. Everything else is a proposal. Open questions are collected in Appendix C and referenced inline as `[OI-n]`.

---

## Contents

1. Introduction
2. Conventions and terminology
3. Threat model and required properties
4. Encoding primitives
5. Tool fingerprint (SC-05)
6. Action request digest (ACT-06)
7. Approval evidence and verification (ACT-06)
8. Capability lease (ACT-04)
9. Action log records and chain (OBS-02)
10. Error codes
11. Versioning and compatibility
12. Conformance
13. Security considerations
14. Privacy considerations
15. References

- Appendix A. Changes from the unpublished pre-draft
- Appendix B. Test vector catalogue
- Appendix C. Open issues
- Appendix D. Worked example (illustrative)

---

## 1. Introduction

### 1.1. Purpose

The guideline describes four controls whose security depends on two parties computing *exactly the same bytes*:

| Control | What must be byte-exact |
| :--- | :--- |
| SC-05 Rug pull detection | The fingerprint of a tool definition, computed at approval time and again at every `tools/list` |
| ACT-06 Cryptographically bound approval | The digest of the request the approver signs, and the bytes the proxy forwards |
| ACT-04 Capability lease | The lease object the grantor signs and the proxy enforces |
| OBS-02 Tamper-evident log | The log records, the hash chain over them, and the signed checkpoints |

Without a shared format, every scanner, gateway and log pipeline computes these differently. Results cannot be compared across tools, cannot be checked by an independent verifier, and do not survive a change of vendor. This specification defines one format for all four.

### 1.2. Scope

In scope:

- Byte-level encoding of tool fingerprints, action request digests, capability leases, log records and log checkpoints.
- The structure of approval evidence (WebAuthn assertion, device-bound key signature) and the steps to verify it.
- A catalogue of test vectors and the file format they are distributed in.

Out of scope:

- The trusted display (ACT-05). This specification binds a signature to bytes; it cannot prove what the approver saw. See Section 13.2.
- Transport between client, proxy and approver device, including push channels and device pairing.
- Policy languages (ACT-02), except the minimal argument constraints needed by a lease (Section 8.3).
- Key management, key ceremony and authenticator enrolment.
- The MCP protocol itself. This specification sits on top of MCP 2026-07-28 and does not change it.

### 1.3. Design decisions carried over from the guideline

These decisions are not open for this draft, because the guideline already made them:

- **D1.** A tool fingerprint covers server identity, tool name, `title`, `description`, `inputSchema`, `outputSchema` and `annotations`, not only schema and description. (Guideline SC-05, Phụ lục E.)
- **D2.** Variable-length fields use a length prefix, not a `0x00` separator.
- **D3.** The hash algorithm identifier is part of the domain prefix, so a digest is never ambiguous about its algorithm.
- **D4.** The proxy forwards exactly the canonical bytes it hashed. Strings not in NFC are **rejected**, never silently normalized.
- **D5.** The byte structure of the WebAuthn assertion (CBOR) and the list of verification steps are defined explicitly.
- **D6.** There is a format for capability leases.
- **D7.** Log records carry a session identifier, a sequence number, a time and a decision. The chain has signed checkpoints anchored outside the log writer's control.
- **D8.** "Session" is defined at the proxy/agent layer and issued by the proxy, because MCP 2026-07-28 removed protocol-level sessions (SEP-2567, SEP-2575). A W3C Trace Context trace-id MAY be logged for correlation but MUST NOT be used as the session identifier in any signed structure.

---

## 2. Conventions and terminology

### 2.1. Requirements language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, NOT RECOMMENDED, MAY and OPTIONAL are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

### 2.2. Notation

| Notation | Meaning |
| :--- | :--- |
| `a ‖ b` | Concatenation of byte strings |
| `s + t` | Concatenation of text strings |
| `u8(n)`, `u16(n)`, `u32(n)`, `u64(n)` | Unsigned integer, big-endian, 1/2/4/8 bytes |
| `i64(n)` | Signed integer, two's complement, big-endian, 8 bytes |
| `lp(x)` | `u32(len(x)) ‖ x`, where `len` counts bytes |
| `utf8(s)` | UTF-8 encoding of string `s`, after the checks in Section 4.1 |
| `jcs(v)` | RFC 8785 serialization of JSON value `v`, after the checks in Section 4.3 |
| `H_alg(x)` | Hash function identified by `alg` (Section 4.5) |
| `raw(ref)` | The digest bytes inside a digest reference (Section 4.5) |
| `b64u(x)` | base64url without padding (RFC 4648 §5) |

### 2.3. Roles

| Role | Description |
| :--- | :--- |
| **Proxy** | The component between the agent and the tool that enforces policy, computes digests, verifies approvals and forwards requests. May be an MCP gateway or part of the client. Issues session identifiers. |
| **Approver** | The human who approves an action or grants a lease. |
| **Authenticator** | The device holding the approver's signing key (FIDO2 authenticator, or a platform key in Secure Enclave/TPM). |
| **Verifier** | Any party that checks approval evidence. Usually the proxy; MAY be the tool server (Section 6.3). |
| **Log writer** | The component that appends log records. MUST run under an identity different from the agent's (guideline OBS-02). |
| **Log auditor** | An independent party that verifies the log chain and checkpoints. |

### 2.4. Terms

- **Tool definition.** One element of the `tools` array in a `tools/list` result, as delivered to the model.
- **Server identity.** A stable identifier of the tool server that does not depend on the name the server gives itself (Section 5.2).
- **Session.** A proxy-issued context tied to one user and one start time, identified by a 16-byte random **session id**. It is not an MCP protocol session.
- **Action.** One `tools/call` request that the proxy evaluates.
- **Pending entry.** The proxy's record that it has issued a challenge for one action and not yet accepted evidence for it (Section 6.2).
- **Anchored checkpoint.** A signed checkpoint that has been delivered to a party independent of the log writer (Section 9.4).

---

## 3. Threat model and required properties

The attacker classes are those of the guideline, Mục 1.2. This specification addresses:

| Attacker | Relevant capability | Property this specification must provide |
| :--- | :--- | :--- |
| K1 (content the agent reads) | Makes the model issue any tool call, including ones crafted to exploit parser differences | **P1** Unambiguous encoding: two different requests never produce the same digest |
| K2 (malicious or compromised tool server) | Changes tool definitions after approval; returns crafted `tools/list` | **P2** Any change to any covered field changes the fingerprint |
| K3 (malware as the same user), partially | Tampers with what is sent after approval | **P3** The forwarded request is built from exactly the signed record; altered records are rejected |
| Log writer compromise or operator tampering | Deletes, reorders, truncates, splices log records | **P4** Deletion, reordering, splicing and truncation of records covered by an anchored checkpoint are detected |
| Any | Replays an old approval or lease | **P5** Replay, reuse across sessions and use after expiry are rejected |

K4 (another compromised agent sending requests into this agent) is not addressed separately: its requests reach the proxy as ordinary actions.

Not provided: proof of what the approver saw (needs ACT-05); protection against an approver who approves a malicious action; protection when the proxy itself is compromised; protection for log records not covered by an anchored checkpoint.

---

## 4. Encoding primitives

### 4.1. Strings

All strings are Unicode text encoded as UTF-8. Normalization and code point properties are those of Unicode 16.0.0. `[OI-16]`

1. A producer MUST emit strings in Normalization Form C (NFC).
2. A consumer MUST reject a string that is not in NFC with `E_NOT_NFC`. It MUST NOT normalize the string and continue.
3. A consumer MUST reject a string containing a code point whose General_Category is `Cn` (unassigned, including noncharacters) in Unicode 16.0.0 with `E_NOT_NFC`. An implementation with newer Unicode data MUST still apply the 16.0.0 assignments.
4. A consumer MUST reject ill-formed UTF-8, including encoded surrogate code points and overlong forms, with `E_BAD_UTF8`.
5. A consumer MUST reject the code point U+0000 in any string, including JSON strings after unescaping, with `E_BAD_UTF8`. `[OI-1]`

Rationale: normalizing before hashing and forwarding the original allows two byte-distinct strings (for example `café` in NFC and NFD, which name two different files on ext4) to share a digest. Rejecting is the only rule under which the forwarded bytes and the hashed bytes cannot diverge. Rule 3 exists because newly assigned combining marks change NFC results, so two implementations on different Unicode versions could otherwise disagree.

### 4.2. Tagged records

Every top-level object in this specification (tool fingerprint, action, lease, log record, checkpoint) is a **tagged record**: a sequence of fields, each

```
field = u16(tag) ‖ u32(len(value)) ‖ value
```

1. Tags MUST appear in strictly increasing order. A consumer MUST reject a repeated tag or a tag out of order with `E_TAG_ORDER`.
2. A field that is absent is omitted entirely. An empty value (`len = 0`) is a present field. Absent and empty are distinct and produce different digests.
3. A consumer MUST reject a required tag that is missing with `E_MISSING_FIELD`, and an unknown tag with `E_UNKNOWN_TAG`. There is no "ignore unknown fields" rule in `aab-00`. `[OI-2]`
4. A consumer MUST reject a length that exceeds the remaining input, and trailing bytes after the last field, with `E_LENGTH`.
5. The maximum length of a single value, including an `lp()` value inside a sub-structure, is 2^24 bytes. Larger values MUST be rejected with `E_LENGTH`. `[OI-3]`
6. A field whose type has a fixed width (`u8`, `u64`, `i64`, 16-byte id) MUST have exactly that length. Else `E_LENGTH`.
7. An enumerated value outside its table (record type, decision) MUST be rejected with `E_VALUE`.

**Sub-structures.** The server identity (Section 5.2), the digest reference (Section 4.5) and the lease tool entry (Section 8.1) are concatenations of `lp()` values, **not** tagged records. They are placed directly as the value of a field (a lease tool entry, inside field `0x06` of the lease), with no further length prefix and no domain prefix. A consumer MUST reject a sub-structure whose `lp()` values do not exactly fill the enclosing value with `E_LENGTH`.

### 4.3. JSON values

Tool schemas, annotations and tool arguments are JSON. They are included in digests as `jcs(v)`, the RFC 8785 (JCS) serialization. Before serializing, the consumer MUST parse the JSON text it received and MUST reject it if:

| Condition | Error |
| :--- | :--- |
| An object has two members whose names are equal after unescaping (for example `"a"` and `"\u0061"`) | `E_DUP_KEY` |
| A string (member name or value), after unescaping, is not in NFC or contains an unassigned code point (Section 4.1) | `E_NOT_NFC` |
| A string contains an unpaired surrogate escape (`"\uD800"`) or U+0000 (`"\u0000"`) | `E_BAD_UTF8` |
| The decimal value of a number differs from the decimal value of its RFC 8785 serialization (for example 2^53 + 1, which serializes as `9007199254740992`), or the number overflows binary64 (for example `1e400`) | `E_NUMBER` |
| The text is not valid JSON (this includes `NaN` and `Infinity`) | `E_JSON` |

`0.1` and `1.0` are accepted: their serializations `0.1` and `1` denote the same decimal values. Negative zero serializes as `0` under RFC 8785. This is accepted: because the proxy forwards the canonical bytes (Section 6.3), the tool never sees a form other than the one that was hashed.

JCS sorts member names by their UTF-16 code units (RFC 8785 §3.2.3), not by code points or UTF-8 bytes. The orders differ for names containing characters above U+FFFF (vector ENC-012).

Parsers MUST detect duplicate keys themselves. Many JSON libraries silently keep the first or last value, which is the parser differential that NET-05 in the guideline warns about.

### 4.4. Integers and times

- Counters and sizes are `u64`.
- Times are `i64` milliseconds since the Unix epoch, UTC.
- Session ids, lease ids and log ids are 16 bytes from a cryptographically secure random source.

### 4.5. Algorithms and domain separation

Every digest in this specification is computed as

```
digest = H_alg( lp( utf8("aab/00/" + object_type + "/" + alg) ) ‖ body )
```

| `object_type` | `body` |
| :--- | :--- |
| `tool-fp` | Tagged record, Section 5.1 |
| `action` | Tagged record, Section 6.1 |
| `lease` | Tagged record, Section 8.1 |
| `log-genesis` | `lp(log id)`, Section 9.2 |
| `log-link` | `lp(headᵢ) ‖ lp(recordᵢ)`, Section 9.2 |
| `checkpoint` | Tagged record, Section 9.3 |
| `credential` | `lp(credential id)`, Section 9.1 |
| `payload` | `lp(payload bytes)`, Sections 9.1 and 14 |

| `alg` | Function | Output | Requirement |
| :--- | :--- | :--- | :--- |
| `sha-256` | SHA-256 | 32 bytes | MUST implement |
| `sha-384` | SHA-384 | 48 bytes | MAY implement |
| `sha-512` | SHA-512 | 64 bytes | MAY implement |

Inside a tagged record, a **digest reference** is

```
ref = lp(utf8(alg)) ‖ lp(digest)
```

and `raw(ref)` denotes `digest`, the bytes inside it. In text contexts (logs, UI, configuration), a digest reference is written `alg ":" b64u(raw(ref))`, for example `sha-256:U2Q4CNaBoz71PtbKXEotxCxzb_PkZ0_gm4DMcKRWUa0`.

A consumer MUST reject a digest reference:

- whose `alg` is not in the table above, or is not the algorithm the deployment has configured for that object, with `E_ALG_MISMATCH`, even if it could compute the other algorithm;
- whose digest length differs from the output length of `alg`, with `E_LENGTH`.

Two digests computed with different algorithms are never compared.

Because the wire version `00` is part of the prefix, every digest changes when the wire version changes. Stored fingerprints must be recomputed on upgrade (Section 11).

---

## 5. Tool fingerprint (SC-05)

### 5.1. Record

`object_type = "tool-fp"`

| Tag | Field | Presence | Value |
| :--- | :--- | :--- | :--- |
| `0x01` | server identity | REQUIRED | Server identity (Section 5.2) |
| `0x02` | name | REQUIRED | `utf8(name)` |
| `0x03` | title | if present in the definition | `utf8(title)` |
| `0x04` | description | if present | `utf8(description)` |
| `0x05` | inputSchema | REQUIRED | `jcs(inputSchema)` |
| `0x06` | outputSchema | if present | `jcs(outputSchema)` |
| `0x07` | annotations | if present | `jcs(annotations)` |

Fields not listed (`icons`, `_meta`, and any field added by later MCP versions) are not covered by `aab-00`. `[OI-4]`

### 5.2. Server identity

`value = lp(utf8(kind)) ‖ lp(utf8(id))`

This is a sub-structure (Section 4.2), not a tagged record.

| `kind` | `id` | Use |
| :--- | :--- | :--- |
| `oci` | `<registry>/<repository>@sha256:<hex>`: fully qualified (registry host included, for example `docker.io/library/nginx`, not `nginx`), lowercase, no tag, digest in lowercase hex | Server run from a container image pinned by digest (guideline SC-03) |
| `pkg` | `<ecosystem>:<name>@<version>#<integrity>`, for example `npm:@scope/server@1.2.3#sha512-...` | Server installed from a lockfile with integrity hash |
| `url` | Normalized URL (below) | Remote server over Streamable HTTP |
| `local` | Absolute path of the executable, followed by `#sha256:<hex>` of its content | Server built and run locally |

URL rules for `kind = url`:

1. The scheme MUST be `https`. The URL MUST NOT contain userinfo (`https://user:pass@host/`) or a query. A URL that violates this MUST be rejected with `E_VALUE`. Userinfo would put a credential into every fingerprint, log record and approval that carries the identity, and parsers disagree on where the host starts when userinfo is present. A query is rejected rather than sorted, because reordering parameters is a repair (Section 4) and servers may treat order as significant. `[OI-5]`
2. Normalization: scheme and host lowercased; host converted to IDNA A-labels using UTS #46 non-transitional processing; default port removed; empty path becomes `/`; percent-encoding hex digits uppercased, no other decoding; fragment removed.

The name a server reports about itself, or the key under which it appears in client configuration, is **not** a server identity. Several servers can share a name (guideline SC-02).

### 5.3. Annotations are hashed as received

The `annotations` field is hashed exactly as received, with no MCP defaults applied. A definition that omits `destructiveHint` and one that sets `"destructiveHint": true` have the same meaning under MCP, but different fingerprints under this specification. This is intentional: the fingerprint detects *any* change in what the server declares, and interpretation belongs to policy (guideline ACT-01). `[OI-6]`

### 5.4. Where the fingerprint is computed

The fingerprint protects the definition the model actually sees.

1. The comparison point MUST be the component that delivers tool definitions to the model. If both the client and a gateway hold a copy, the deployment MUST choose one as the comparison point and document it.
2. When the client serves a cached `tools/list` result (SEP-2549 `ttlMs`, `cacheScope`), the comparison MUST be run against the cached definition before it is delivered, not only when the cache is refreshed.
3. A tool whose fingerprint differs from the approved one MUST be blocked with `E_FP_CHANGED`, and a re-approval requested. A tool with no approved fingerprint MUST be treated as new.

---

## 6. Action request digest (ACT-06)

### 6.1. Record

`object_type = "action"`

| Tag | Field | Presence | Value |
| :--- | :--- | :--- | :--- |
| `0x01` | audience | REQUIRED | `utf8(proxy_id)`: the identifier of the verifier that will accept this approval, for example the proxy's origin |
| `0x02` | session id | REQUIRED | 16 bytes, issued by the proxy |
| `0x03` | sequence | REQUIRED | `u64`, assigned by the proxy (Section 6.2) |
| `0x04` | server identity | REQUIRED | Server identity (Section 5.2) |
| `0x05` | tool name | REQUIRED | `utf8(name)` |
| `0x06` | tool fingerprint | REQUIRED | Digest reference to the approved fingerprint (Section 5) |
| `0x07` | arguments | REQUIRED | `jcs(arguments)`; an absent or `null` `arguments` member is encoded as `jcs({})`; a value that is not an object is rejected with `E_JSON` |
| `0x08` | not before | REQUIRED | `i64` |
| `0x09` | not after | REQUIRED | `i64`; `not_after − not_before` MUST NOT exceed 300 000 ms (Section 6.4) `[OI-7]` |
| `0x0A` | approver id | OPTIONAL | `utf8(approver_id)`: when present, only this approver's credential may sign |
| `0x0B` | presentation digest | OPTIONAL | Digest reference to what the trusted display rendered; object type undefined `[OI-8]` |

### 6.2. Sequence numbers, pending entries and the challenge

1. The proxy assigns a sequence to every action it evaluates, whether the action is allowed by policy, allowed under a lease, or sent for approval. Sequences are unique within the session, start at 1, and increase in the order they are assigned. There is no requirement on execution order: several approvals MAY be pending at the same time and MAY complete in any order.
2. For an action that needs approval, the proxy builds the action record, computes its digest reference, and stores a **pending entry** `(session id, sequence, action digest reference)` before issuing the challenge. It MUST NOT create two pending entries with the same `(session id, sequence)`.
3. The challenge is `raw(action digest reference)`. For WebAuthn, the proxy passes these bytes as `challenge` in `PublicKeyCredentialRequestOptions`, so `clientDataJSON.challenge` is `b64u(raw(action digest reference))`. The proxy sends the action record bytes together with the challenge; they come back as evidence key `10` (Section 7.1).
4. One challenge covers exactly one action. `[OI-14]`
5. A pending entry is consumed atomically when verification succeeds, before forwarding (Section 6.4). A consumed entry is never reinstated, even if forwarding fails. An entry MAY be discarded once the current time is past `not_after` plus the skew allowance.

A verifier other than the proxy needs access to the proxy's pending entries. How it gets them is out of scope.

### 6.3. Forwarding rule

1. The proxy MUST parse the whole body of every incoming request (JSON-RPC envelope, `params` and `arguments`) with the rules of Section 4.3, and reject a violation with the error listed there. This includes duplicate keys anywhere in the body (guideline NET-05).
2. If the proxy decides based on the `Mcp-Method` and `Mcp-Name` headers (SEP-2243), it MUST also check they match `method` and `params.name` in the body, and reject a mismatch with `E_HEADER_MISMATCH` (guideline NET-05).
3. After a successful verification (Section 7), the proxy MUST build the forwarded request from the action record, not from the request received from the agent:

   ```
   {"id":<id>,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":<field 0x07>,"name":<field 0x05>}}
   ```

   `<id>` is the JSON-RPC `id` of the agent's request. Every other member of the envelope and of `params`, including `params._meta`, is dropped. `[OI-17]` The body is serialized with `jcs`, so member names come out in UTF-16 code unit order: `id`, `jsonrpc`, `method`, `params` in the envelope, and `arguments` before `name` inside `params`, as shown above. Implementers using a JCS library should expect this order rather than the order in which the members were built. Because JCS is idempotent and field `0x07` is already `jcs(arguments)`, the bytes of `params.arguments` in the forwarded body are exactly the bytes of field `0x07`. The proxy sets the `Mcp-Method` and `Mcp-Name` headers of the forwarded request from the same values.
4. Actions allowed by policy or under a lease are forwarded with the same construction, from their canonical name and arguments.
5. The `id` is not covered by the signature; it only correlates the response.
6. A tool server acting as verifier MUST compare `params.name` and the bytes of `params.arguments` in the request it received with fields `0x05` and `0x07` of the record in evidence key `10`, and reject a mismatch with `E_DIGEST_MISMATCH`.

A conformance harness for proxies (Section 12) checks this rule by comparing the bytes that reach a test tool with the bytes in the signed record.

### 6.4. Record checks

The verifier runs these checks on the decoded action record, in this order, as step 3 of Section 7.2, and rejects on the first failure. The current time is taken once, when verification starts.

| # | Condition | Error |
| :--- | :--- | :--- |
| 1 | The session id is not an open session issued by this proxy, or is not the session of the request being verified | `E_SESSION` |
| 2 | The audience is not this verifier | `E_AUDIENCE` |
| 3 | `not_after < not_before`, or `not_after − not_before` exceeds 300 000 ms | `E_EXPIRED` |
| 4 | The current time is earlier than `not_before − 30 000 ms` or later than `not_after + 30 000 ms` | `E_EXPIRED` |
| 5 | There is no unconsumed pending entry for `(session id, sequence)` whose digest reference equals evidence key `3` | `E_REPLAY` |
| 6 | The current fingerprint of the tool at the comparison point (Section 5.4) differs from field `0x06` | `E_FP_CHANGED` |

The verifier MUST accept a clock skew of up to 30 000 ms and no more.

After every step of Section 7.2 or 7.3 has succeeded, the verifier consumes the pending entry with an atomic compare-and-delete. If another verification consumed it first, this verification fails with `E_REPLAY`.

---

## 7. Approval evidence and verification (ACT-06)

### 7.1. Evidence container

Approval evidence is a CBOR map, encoded with the deterministic encoding rules of RFC 8949 §4.2.1 (shortest integer forms, definite lengths, map keys sorted by bytewise order of their encodings). A consumer MUST reject evidence that is not deterministically encoded with `E_CBOR`. The check applies to the container map, not to the contents of its byte strings.

| Key | Name | Type | Presence |
| :--- | :--- | :--- | :--- |
| `1` | version | uint, `0` for `aab-00` | REQUIRED |
| `2` | profile | tstr, `"webauthn"` or `"device-key"` | REQUIRED |
| `3` | action digest | bstr: the digest reference (Section 4.5) of the record in key `10` | REQUIRED |
| `4` | credential id | bstr | REQUIRED |
| `5` | authenticatorData | bstr | REQUIRED for `webauthn` |
| `6` | clientDataJSON | bstr, exactly as returned by the client | REQUIRED for `webauthn` |
| `7` | signature | bstr | REQUIRED for `webauthn` |
| `8` | userHandle | bstr | OPTIONAL, `webauthn` only |
| `9` | COSE_Sign1 | bstr, a tagged COSE_Sign1 (RFC 9052) | REQUIRED for `device-key` |
| `10` | record | bstr: the action record (Section 6.1) as tagged-record bytes | REQUIRED |

Unknown keys, a missing required key, and a key that belongs to the other profile MUST be rejected with `E_CBOR` in `aab-00`.

The same container carries a lease grant (Section 8.4), with key `10` holding the lease record (Section 8.1) and key `3` its digest reference.

### 7.2. Profile `webauthn`: verification steps

The verifier holds a registry of approver credentials: credential id, public key (COSE_Key, including its `alg`), the approver it belongs to, the user handle, the BE flag value seen at registration, the last seen signature counter, and the action classes the approver may approve (from the organization's policy, guideline ACT-01).

The verifier MUST perform all of the following, in this order, and reject on the first failure:

1. **Container.** Decode the container (Section 7.1). Check `version = 0`, `profile = "webauthn"` and the key set. Else `E_CBOR`.
2. **Record.** Decode key `3` as a digest reference (Section 4.5; `E_ALG_MISMATCH`, `E_LENGTH`). Decode key `10` as an action record (Sections 4.2, 6.1; errors of Section 4). Compute the record's digest reference with the algorithm of key `3`. It MUST equal key `3` byte for byte. Else `E_DIGEST_MISMATCH`.
3. **Record checks.** Run the checks of Section 6.4, in order.
4. **Credential.** Look up key `4`. Unknown, revoked, or belonging to an approver not authorized for this action's class: `E_CREDENTIAL`. If the record has an approver id (`0x0A`), the credential MUST belong to that approver. Else `E_CREDENTIAL`.
5. **clientDataJSON.** Parse key `6` as JSON with the rules of Section 4.3. Check:
   1. `type` is exactly `"webauthn.get"`. Else `E_WA_TYPE`.
   2. `challenge` is exactly `b64u(raw(key 3))`, compared as strings. Padded base64 or the standard alphabet is a mismatch. Else `E_WA_CHALLENGE`.
   3. `origin` is in the verifier's configured set of allowed origins. Else `E_WA_ORIGIN`.
   4. `crossOrigin`, if present, is `false`, and `topOrigin` is absent. Else `E_WA_ORIGIN`. `[OI-9]`
6. **authenticatorData.** Parse key `5`. Check:
   1. It is at least 37 bytes, and its length is consistent with the AT and ED flags. Else `E_WA_AUTHDATA`.
   2. `rpIdHash` equals SHA-256 of the configured RP ID. Else `E_WA_RPID`.
   3. Flag UP (bit 0) is set. Else `E_WA_FLAGS`.
   4. Flag UV (bit 2) is set. Else `E_WA_FLAGS`.
   5. If flag BS (bit 4) is set, flag BE (bit 3) is set. Else `E_WA_FLAGS`.
   6. Flag BE equals the value stored at registration. Else `E_WA_FLAGS`.
   7. If the deployment forbids synced credentials, flag BE is not set. Else `E_WA_FLAGS`.
   8. If key `8` (userHandle) is present, it equals the user handle stored for the credential. Else `E_CREDENTIAL`.
7. **Signature.** Verify key `7` over `authenticatorData ‖ SHA-256(clientDataJSON)` with the registered public key, using the algorithm and signature format of Section 7.5. Else `E_WA_SIGNATURE`.
8. **Counter.** If either the stored counter or the received `signCount` is non-zero, the received value MUST be greater than the stored one. Else `E_WA_COUNTER`.

On success, the verifier stores the new counter value, consumes the pending entry (Section 6.4), and the proxy forwards the request built from the record (Section 6.3).

Step 2 binds the record to the signed digest; steps 5 and 7 bind the digest to the signature; the forwarding rule binds the forwarded request to the record. A proxy that forwards the agent's original request, rather than the request built from the record, does not conform.

### 7.3. Profile `device-key`

For a key held in Secure Enclave or a TPM, gated by biometric or PIN, the verifier MUST perform, in this order, and reject on the first failure:

1. Steps 1–4 of Section 7.2, with `profile = "device-key"`.
2. Decode key `9` as a tagged COSE_Sign1 (CBOR tag 18). Else `E_COSE`.
3. The protected header contains `alg` and `kid`, and neither appears in the unprotected header. Else `E_COSE`.
4. `kid` equals key `4`. Else `E_COSE`.
5. `alg` equals the registered key's algorithm, or its equivalent in Section 7.5. Else `E_COSE`.
6. The payload is present (not detached). Else `E_COSE`.
7. The payload equals key `3` byte for byte. Else `E_DIGEST_MISMATCH`.
8. The signature verifies over the `Sig_structure` of RFC 9052 §4.4 with empty `external_aad`, in the format of Section 7.5. Else `E_COSE`.

On success, the verifier consumes the pending entry (Section 6.4). There is no signature counter.

The result of a local authentication API that returns only a boolean (for example `LAContext.evaluatePolicy`, `UserConsentVerifier`) is not evidence under any profile.

### 7.4. What verification does not prove

A valid `webauthn` assertion proves that the holder of the key was present (UP), was verified (UV, as reported by the authenticator), and agreed to sign this digest. A valid `device-key` signature proves only that the key was used. That its use was gated by biometric or PIN is a property of how the key was created at enrolment, which the verifier cannot check for each signature.

Neither profile proves the holder saw the arguments. That property comes only from the trusted display (guideline ACT-05), and is outside this specification.

### 7.5. Signature algorithms

The algorithm is taken from the registered COSE_Key (`alg` parameter), never from the evidence.

| COSE `alg` | Key | Signature format, `webauthn` | Signature format, `device-key` | Requirement |
| :--- | :--- | :--- | :--- | :--- |
| `−7` ES256 | EC2, P-256 | ASN.1 DER `Ecdsa-Sig-Value` (WebAuthn Level 3) | Raw `r ‖ s`, 64 bytes (RFC 9052) | MUST |
| `−9` ESP256 (RFC 9864) | EC2, P-256 | As `−7` | As `−7` | MUST, equivalent to `−7` |
| `−8` EdDSA | OKP, Ed25519 only | 64 bytes (RFC 8032) | 64 bytes | MUST |
| `−19` Ed25519 (RFC 9864) | OKP, Ed25519 | As `−8` | As `−8` | MUST, equivalent to `−8` |
| `−257` RS256 | RSA, at least 2048 bits | RSASSA-PKCS1-v1_5 | Not allowed | MAY |

A `−8` key whose curve is not Ed25519 MUST be rejected (`E_WA_SIGNATURE` or `E_COSE`). A verifier that does not accept RS256 rejects an RS256 credential with `E_WA_SIGNATURE`. `[OI-18]` Post-quantum algorithms are out of scope. `[OI-15]`

---

## 8. Capability lease (ACT-04)

### 8.1. Record

`object_type = "lease"`

| Tag | Field | Presence | Value |
| :--- | :--- | :--- | :--- |
| `0x01` | audience | REQUIRED | `utf8(proxy_id)` |
| `0x02` | lease id | REQUIRED | 16 bytes |
| `0x03` | session id | REQUIRED | 16 bytes |
| `0x04` | grantor | REQUIRED | `utf8(approver_id)` |
| `0x05` | grantee | REQUIRED | `utf8(agent_id)` |
| `0x06` | tools | REQUIRED | `u32(n)` followed by `n` tool entries (below) |
| `0x07` | constraints | REQUIRED | `jcs(constraints)`, Section 8.3; `jcs([])` for none |
| `0x08` | max calls | REQUIRED | `u64` |
| `0x09` | max argument bytes | OPTIONAL | `u64`: total of `len(jcs(arguments))` over all calls |
| `0x0A` | not before | REQUIRED | `i64` |
| `0x0B` | not after | REQUIRED | `i64`; `not_after − not_before` MUST NOT exceed 28 800 000 ms (8 hours) `[OI-19]` |

A **tool entry** is the sub-structure (Section 4.2) `lp(server identity) ‖ lp(utf8(name)) ‖ lp(fingerprint reference)`.

- Entries MUST be sorted in ascending lexicographic order of the unsigned bytes of the complete entry; an entry that is a proper prefix of another sorts first.
- Two entries with the same server identity and name are duplicates, even if their fingerprints differ.
- An unsorted or duplicated entry MUST be rejected with `E_TAG_ORDER`. A count `n` that does not match the entries present MUST be rejected with `E_LENGTH`.

A lease is granted by approval evidence (Section 7) over the lease digest, verified as in Section 8.4.

### 8.2. Enforcement

1. The budget counters MUST be held by the proxy, outside the agent's reach. They are not part of the wire object.
2. Each call made under a lease receives a sequence (Section 6.2), MUST be logged with the lease id (Section 9), and MUST decrement the counters atomically before forwarding.
3. A lease MUST be revocable immediately. Revocation is recorded by lease id and is permanent.
4. For each call under a lease, the proxy runs these checks in order and stops at the first failure:

| # | Condition | Error |
| :--- | :--- | :--- |
| 1 | The lease has been revoked | `E_LEASE_REVOKED` |
| 2 | The call's session is not the lease's session | `E_SESSION` |
| 3 | The current time is outside `[not_before, not_after]`, with the skew allowance of Section 6.4 | `E_EXPIRED` |
| 4 | The (server identity, name) of the tool is not in the lease tool set | `E_LEASE_SCOPE` |
| 5 | The tool's current fingerprint differs from the entry's | `E_FP_CHANGED` |
| 6 | A constraint (Section 8.3) is violated | `E_LEASE_CONSTRAINT` |
| 7 | The call would exceed `max calls` or `max argument bytes` | `E_LEASE_BUDGET`, or escalation to per-action approval, according to policy |

A call that fails check 4 or 5 is not covered by the lease. The error is logged, and the proxy MAY then evaluate the call under per-action policy as a new action.

### 8.3. Argument constraints

`constraints` is a JSON array. Each element is an object:

```json
{ "tool": "write_file", "pointer": "/path", "op": "beneath", "value": "src" }
```

`tool` is OPTIONAL. When present, it is a tool name, and the constraint applies only to calls to tools with that name in the lease tool set. When absent, the constraint applies to calls to every tool in the lease.

| `op` | Meaning |
| :--- | :--- |
| `eq` | The value at `pointer` (RFC 6901) equals `value` under JCS comparison (`jcs(a) = jcs(b)`) |
| `prefix` | The value is a string whose code points begin with those of `value` |
| `beneath` | Path check, below |
| `in` | The value equals one element of the array `value`, under JCS comparison |
| `max` | The value is a number less than or equal to `value` |
| `absent` | No value exists at `pointer` |

All applicable constraints must hold (logical AND). A pointer that does not resolve fails every `op` except `absent`. A call that violates a constraint is rejected with `E_LEASE_CONSTRAINT`. A constraint element with an unknown `op`, an unknown member, or a missing required member MUST be rejected at grant time with `E_VALUE`.

`prefix` MUST NOT be used for file paths: `"src/../.env"` has the prefix `"src/"`. Use `beneath`.

`beneath` is a lexical check that rejects rather than resolves. A string is a **plain relative path** if it is non-empty, does not start with `/`, contains no `\` and no U+0000, and, split on `/`, has no segment that is empty, `.` or `..`. The constraint holds when the value at `pointer` is a plain relative path and its first segments equal, one by one and byte for byte, the segments of `value`. So `src/a/b.py` is beneath `src`, while `srcfoo/a`, `src/../.env`, `./src/a`, `src//a` and `/etc/passwd` are not, and fail with `E_LEASE_CONSTRAINT`. A `value` that is not itself a plain relative path is rejected at grant time with `E_VALUE`.

`beneath` does not see symbolic links. A link inside `src/` that points outside it passes the check. The tool must still resolve paths beneath its root (for example `openat2` with `RESOLVE_BENEATH`), or run in a sandbox that bounds the filesystem (guideline ISO-03). Paths are compared byte for byte, so on a case-insensitive filesystem the check can only fail closed. `[OI-10]`

### 8.4. Grant verification

The grant evidence is the container of Section 7.1, with key `10` holding the lease record and key `3` its digest reference. The verifier MUST perform, in this order, and reject on the first failure:

1. Step 1 of Section 7.2 (or of Section 7.3 for `device-key`).
2. Step 2 of Section 7.2, decoding key `10` as a lease record (Section 8.1). Else the errors of Section 4, or `E_DIGEST_MISMATCH`.
3. Lease record checks, in order:

   | # | Condition | Error |
   | :--- | :--- | :--- |
   | 1 | The session id is not an open session issued by this proxy, or is not the session in which the grant is made | `E_SESSION` |
   | 2 | The audience is not this verifier | `E_AUDIENCE` |
   | 3 | `not_after < not_before`, or `not_after − not_before` exceeds 28 800 000 ms | `E_EXPIRED` |
   | 4 | The current time is later than `not_after + 30 000 ms` | `E_EXPIRED` |
   | 5 | The lease id has been granted before (including leases since revoked or exhausted) | `E_REPLAY` |
   | 6 | An entry's fingerprint differs from the tool's current fingerprint | `E_FP_CHANGED` |
   | 7 | An entry is a tool classified as irreversible or privileged, or a shell tool (guideline ACT-01, ACT-04). The classification comes from the organization's policy, not from annotations | `E_LEASE_SCOPE` |
   | 8 | A constraint element is malformed (Section 8.3) | `E_VALUE` |

4. Steps 4–8 of Section 7.2 (or the remaining steps of Section 7.3). In step 4, the credential MUST belong to the grantor in field `0x04`. Else `E_CREDENTIAL`.

On success, the verifier records the lease id permanently, atomically and before the lease becomes active, and logs a lease grant record (Section 9.1).

---

## 9. Action log records and chain (OBS-02)

### 9.1. Record

A log is an ordered sequence of records with a 16-byte **log id**. Each record is a tagged record:

| Tag | Field | Presence | Value |
| :--- | :--- | :--- | :--- |
| `0x01` | log id | REQUIRED | 16 bytes |
| `0x02` | index | REQUIRED | `u64`, position in the log, starting at 0, no gaps |
| `0x03` | time | REQUIRED | `i64` |
| `0x04` | session id | REQUIRED | 16 bytes; all zero for an event not tied to a session (for example a global kill switch) |
| `0x05` | session sequence | REQUIRED | `u64`: the action's sequence (Section 6.2) for types 1–3; `0` for types 0, 4, 5, 6 and 7 |
| `0x06` | record type | REQUIRED | `u8`, table below |
| `0x07` | decision | REQUIRED for type 2, absent for other types | `u8`, table below |
| `0x08` | action digest | OPTIONAL | Digest reference, object type `action` |
| `0x09` | approver credential | OPTIONAL | Digest reference, object type `credential` (Section 4.5) |
| `0x0A` | lease id | OPTIONAL | 16 bytes |
| `0x0B` | payload digest | OPTIONAL | Digest reference, object type `payload`, to the full or redacted payload stored outside the chain |
| `0x0C` | trace id | OPTIONAL | 16 bytes, W3C Trace Context; informational only |

| Record type | Value |
| :--- | :--- |
| session open | 0 |
| action request | 1 |
| action decision | 2 |
| action result | 3 |
| lease grant | 4 |
| lease revoke | 5 |
| session close | 6 |
| kill switch (guideline OBS-04) | 7 |

| Decision | Value |
| :--- | :--- |
| allow by policy | 1 |
| deny by policy | 2 |
| approved by person | 3 |
| denied by person | 4 |
| allowed under lease | 5 |
| rejected by verification (any `E_*`) | 6 |

Values outside these tables are rejected with `E_VALUE` (Section 4.2).

### 9.2. Chain

```
head₀     = H_alg( lp(utf8("aab/00/log-genesis/" + alg)) ‖ lp(log id) )
headᵢ₊₁   = H_alg( lp(utf8("aab/00/log-link/"    + alg)) ‖ lp(headᵢ) ‖ lp(recordᵢ) )
```

The bodies here are not tagged records (Section 4.5). `head_n` commits to the first `n` records.

The log writer MUST reject appending a record whose log id differs from the log's, or whose index is not the next index.

### 9.3. Checkpoint

A checkpoint commits to the log state after `size` records:

`object_type = "checkpoint"`

| Tag | Field | Presence | Value |
| :--- | :--- | :--- | :--- |
| `0x01` | log id | REQUIRED | 16 bytes |
| `0x02` | size | REQUIRED | `u64` |
| `0x03` | head | REQUIRED | Digest reference to `head_size` |
| `0x04` | time | REQUIRED | `i64` |

The log writer signs the checkpoint digest with a key held in a KMS or HSM, as a COSE_Sign1 with the checkpoint digest reference as payload. The log key MUST NOT be accessible to the agent or to the user running the agent (guideline OBS-02, "Sai lầm hay gặp"). `[OI-12]`

A checkpoint SHOULD be produced at least every `N` records or every `T` seconds, whichever comes first. `N` and `T` are deployment choices. `[OI-11]`

### 9.4. Anchoring

A signed checkpoint alone does not stop the log writer from producing a second, shorter history. A time-stamp does not stop it either: it shows *when* a checkpoint existed, not that it is the only one. A log writer can time-stamp a forked checkpoint and withhold the original.

1. Each signed checkpoint MUST, when it is created, be delivered to at least one party independent of the log writer, which keeps it: a witness, the log auditor's own store, or a transparency log (for example one built with Trillian Tessera) operated by a different party. A checkpoint so delivered is **anchored**.
2. An RFC 3161 time-stamp token over the checkpoint MAY be added, from a TSA the log writer does not operate. Its `messageImprint.hashAlgorithm` is the hash function `alg` of the checkpoint digest, and `messageImprint.hashedMessage` is `raw(checkpoint digest reference)`.

### 9.5. Verification by the log auditor

The auditor takes a sequence of records, supplied by the log writer, and the anchored checkpoints, which it holds itself or obtains from the independent parties of Section 9.4. Checkpoints supplied only by the log writer are not anchored. The auditor ignores them: they are not an error, and they do not make any record verified.

The auditor MUST:

1. Check that every record decodes (errors of Section 4) and carries the log id of the anchored checkpoints (else `E_LOG_ID`), and then that its index equals its position (else `E_LOG_INDEX`).
2. Recompute the chain.
3. For every anchored checkpoint, check:
   1. its signature, and its time-stamp token if present. Else `E_LOG_CHECKPOINT`.
   2. that `size` does not exceed the number of records, and that the recomputed `head_size` equals the checkpoint head. Else `E_LOG_CHAIN`. This check against the latest checkpoint the auditor holds is what detects truncation.
4. Check that checkpoint sizes are non-decreasing in the order the checkpoints were anchored, and that a later checkpoint's history extends an earlier one's. Else `E_LOG_ROLLBACK`.
5. Check, within each session, that each sequence appears in at most one type-1 record, and that every type-2 or type-3 record has a lower-indexed type-1 record with the same session id and sequence. Else `E_LOG_SESSION`. Records of different actions MAY interleave in any order.
6. Report the records after the latest anchored checkpoint as **unanchored**. The auditor MUST NOT report them as verified.

Result: the auditor reports `verified up to index k`, plus the list of unanchored records, plus any errors. A plain "valid/invalid" result is not sufficient.

---

## 10. Error codes

| Code | Meaning | Section |
| :--- | :--- | :--- |
| `E_NOT_NFC` | String not in NFC under Unicode 16.0.0, or containing an unassigned code point | 4.1, 4.3 |
| `E_BAD_UTF8` | Ill-formed UTF-8, unpaired surrogate, or U+0000 | 4.1, 4.3 |
| `E_TAG_ORDER` | Tag repeated or out of order; lease tool entries unsorted or duplicated | 4.2, 8.1 |
| `E_MISSING_FIELD` | Required tag missing | 4.2 |
| `E_UNKNOWN_TAG` | Unknown tag | 4.2 |
| `E_LENGTH` | Length exceeds input or limit, trailing bytes, fixed-width field of wrong length, sub-structure not filling its value, digest length wrong for `alg`, or count mismatch | 4.2, 4.5, 8.1 |
| `E_VALUE` | Enumerated value out of range, URL server identity with userinfo or query, or malformed lease constraint | 4.2, 5.2, 8.3, 8.4, 9.1 |
| `E_DUP_KEY` | Duplicate JSON member name | 4.3, 6.3, 7.2 |
| `E_NUMBER` | JSON number whose value changes under RFC 8785 serialization, or that overflows binary64 | 4.3 |
| `E_JSON` | Invalid JSON, or `arguments` not an object | 4.3, 6.1 |
| `E_ALG_MISMATCH` | Digest algorithm unknown, or not the expected one | 4.5, 7.2 |
| `E_FP_CHANGED` | Tool fingerprint differs from approved | 5.4, 6.4, 8.2, 8.4 |
| `E_REPLAY` | No unconsumed pending entry for the action, or lease id already granted | 6.2, 6.4, 8.4 |
| `E_EXPIRED` | Validity window too long, or current time outside it | 6.4, 8.2, 8.4 |
| `E_AUDIENCE` | Wrong audience | 6.4, 8.4 |
| `E_SESSION` | Unknown or closed session, or not the session of the request | 6.4, 8.2, 8.4 |
| `E_DIGEST_MISMATCH` | Record does not match key `3`, COSE payload differs from key `3`, or received request differs from the record | 6.3, 7.2, 7.3, 8.4 |
| `E_HEADER_MISMATCH` | `Mcp-Method` or `Mcp-Name` header differs from the body | 6.3 |
| `E_CBOR` | Evidence container malformed, not deterministic, or with a wrong key set | 7.1, 7.2 |
| `E_CREDENTIAL` | Unknown, revoked or unauthorized credential; wrong approver or grantor; userHandle mismatch | 7.2, 8.4 |
| `E_WA_TYPE`, `E_WA_CHALLENGE`, `E_WA_ORIGIN`, `E_WA_AUTHDATA`, `E_WA_RPID`, `E_WA_FLAGS`, `E_WA_SIGNATURE`, `E_WA_COUNTER` | WebAuthn verification step failed (`E_WA_AUTHDATA`: malformed authenticatorData) | 7.2, 7.5 |
| `E_COSE` | Device-key COSE_Sign1 malformed, header or algorithm wrong, or signature failed | 7.3, 7.5 |
| `E_LEASE_BUDGET`, `E_LEASE_REVOKED`, `E_LEASE_SCOPE`, `E_LEASE_CONSTRAINT` | Lease enforcement failed | 8.2, 8.3, 8.4 |
| `E_LOG_ID`, `E_LOG_INDEX`, `E_LOG_CHAIN`, `E_LOG_CHECKPOINT`, `E_LOG_ROLLBACK`, `E_LOG_SESSION` | Log verification failed | 9.5 |

When several errors apply, an implementation reports the first one in the order of the verification steps. Test vectors specify that expected code.

---

## 11. Versioning and compatibility

- The wire version appears in every domain prefix (`aab/00/...`) and in the evidence container (`version`). A consumer MUST reject a version it does not implement.
- Changing the wire version changes every digest. Deployments must re-fingerprint approved tools on upgrade, and log chains start a new log id.
- Drafts `aab-00` to `aab-nn` are not compatible with each other. The first frozen version will be `aab-1`, with domain prefix `aab/1/` and container `version = 1`.

| Wire format | Guideline | Status |
| :--- | :--- | :--- |
| `aab-00` | 0.1.0 | Working draft |

---

## 12. Conformance

### 12.1. Conformance classes

| Class | Must pass vector groups (Appendix B) |
| :--- | :--- |
| Fingerprinter (scanner, gateway, client) | ENC, FP |
| Approval verifier | ENC, FP, ACT (except vectors marked P), WA, DK |
| Proxy | Verifier groups, plus ACT vectors marked P (including the forwarding harness ACT-011), LS and E2E |
| Log writer | ENC, LOG (producer side) |
| Log auditor | ENC, LOG |

### 12.2. Test vector files

Vectors are distributed as JSON files, one per vector, under `vectors/<group>/<id>.json`:

```json
{
  "id": "FP-003",
  "group": "FP",
  "required_minimum": true,
  "description": "Flipping destructiveHint changes the fingerprint",
  "object": "tool-fp",
  "alg": "sha-256",
  "input": { "server": { "kind": "oci", "id": "..." }, "tool": { } },
  "expected": { "result": "accept", "digest": "sha-256:...", "differs_from": "FP-001" }
}
```

- `input` fields that must carry exact bytes (non-NFC strings, duplicate keys, malformed CBOR) are given as `"input_hex"` or `"input_json_text"`, never as a parsed JSON value, because parsing would destroy the property under test.
- `expected.result` is `accept` or `reject`. For `reject`, `expected.error` is the code of Section 10.
- A runner executes all vectors of a group with one command and exits non-zero on the first mismatch.

### 12.3. Independent implementations

A vector's expected values are filled only when two implementations written independently (different authors, and preferably different languages and JSON/CBOR libraries) produce the same result. Until then the vector carries `"expected": { "status": "pending" }`.

---

## 13. Security considerations

### 13.1. Parser differentials

The main risk this specification addresses is two components interpreting the same input differently: the proxy hashes one meaning, the tool executes another. Duplicate JSON keys, Unicode normalization, number precision, and header-body mismatch (SEP-2243) are the known classes. The rule "reject, don't repair" (Section 4) and the forwarding rule (Section 6.3) are the defences. An implementation that repairs input for convenience breaks both.

### 13.2. Authenticators have no display

A FIDO2 security key signs whatever challenge it is given. Malware on the approver's machine can display benign arguments and request a signature over a malicious digest. Binding does not help against this; ACT-05 does. The optional presentation digest (field `0x0B`, `[OI-8]`) is a hook for a trusted display to commit to what it rendered, not a solution.

### 13.3. Synced passkeys

Passkeys synced across devices (BE flag set) are only as strong as the sync account. Deployments at ASAL-3a SHOULD require device-bound credentials for approvers.

### 13.4. Clock skew

Validity windows depend on the verifier's clock. The skew allowance (Section 6.4) is deliberately small: a verifier MUST accept up to 30 000 ms and no more. Verifiers SHOULD synchronize time from an authenticated source.

### 13.5. Signature counters

Many authenticators always report zero. The counter check detects cloned authenticators only when counters are used, and is not a replay defence. Replay is prevented by pending entries (Section 6.2), which are consumed once.

### 13.6. Log writer compromise

A compromised log writer can write false records from that point on. The chain and anchored checkpoints prove only that records were not changed *after* they were anchored. Records not covered by an anchored checkpoint are not protected: they can be changed or deleted without detection.

### 13.7. Cached tool lists

A client serving a cached `tools/list` can deliver a definition that no longer matches the server, in either direction. Section 5.4 places the comparison at the point of delivery to the model for this reason.

### 13.8. Algorithm agility

Agility is limited to the hash functions of Section 4.5 and the signature algorithms of Section 7.5. Adding an algorithm requires a new draft. There is no negotiation on the wire.

---

## 14. Privacy considerations

Tool arguments in logs can contain personal data and secrets. The log record carries only a payload digest (`0x0B`, object type `payload`); the payload itself is stored separately under the organization's access and retention rules and can be redacted or deleted without breaking the chain. Deleting a payload leaves its digest in the chain, which proves a payload existed but reveals nothing about it, provided the payload has enough entropy. For low-entropy payloads, the digest can be confirmed by guessing. `[OI-13]`

Credential ids are logged as a digest (`0x09`, object type `credential`) to keep raw credential ids out of log pipelines and exports. The digest is unkeyed: anyone who holds the credential registry can link it to the credential.

---

## 15. References

### 15.1. Normative

- RFC 2119, RFC 8174: Key words for use in RFCs to indicate requirement levels
- RFC 3629: UTF-8
- RFC 4648: Base16, Base32 and Base64 data encodings
- RFC 6901: JSON Pointer
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 8259: The JavaScript Object Notation (JSON) data interchange format
- RFC 8785: JSON Canonicalization Scheme (JCS)
- RFC 8949: Concise Binary Object Representation (CBOR)
- RFC 9052: CBOR Object Signing and Encryption (COSE): Structures and Process
- RFC 9864: Fully-Specified Algorithms for JOSE and COSE
- RFC 3161: Internet X.509 PKI Time-Stamp Protocol
- W3C, *Web Authentication: An API for accessing Public Key Credentials, Level 3*
- The Unicode Standard, Version 16.0.0
- Unicode Standard Annex #15: Unicode Normalization Forms
- Unicode Technical Standard #46: Unicode IDNA Compatibility Processing
- Model Context Protocol, Specification 2026-07-28

### 15.2. Informative

- Agent Security Technical Guidelines 0.1.0, controls SC-03, SC-05, ACT-01, ACT-04, ACT-05, ACT-06, NET-05, OBS-02, OBS-04
- MCP SEP-2243 (`Mcp-Method`, `Mcp-Name` headers), SEP-2549 (list cache hints), SEP-2567 (remove sessions), SEP-2575 (remove handshake)
- RFC 8693: OAuth 2.0 Token Exchange
- W3C, *Trace Context*
- Trillian Tessera: https://github.com/transparency-dev/tessera

---

## Appendix A. Changes from the unpublished pre-draft

| Change (guideline, Phụ lục E) | Where |
| :--- | :--- |
| Fingerprint covers server identity, tool name, `title`, `outputSchema`, `annotations` | 5.1, 5.2 |
| Length prefix instead of `0x00` separators | 4.2 |
| Hash algorithm identifier in the domain prefix | 4.5 |
| Proxy forwards exactly the canonical bytes; non-NFC strings rejected | 4.1, 4.3, 6.3 |
| WebAuthn assertion structure (CBOR) and verification steps | 7.1, 7.2 |
| Capability lease format | 8 |
| Log records with session id, sequence, time, decision; signed and anchored checkpoints | 9 |
| Session defined and issued by the proxy | 2.4, 6.1, 6.2 |

Additions not listed in Phụ lục E, proposed by this draft: tagged records with strictly ascending tags (instead of fixed field order), so that optional fields are unambiguous; the `device-key` profile using COSE_Sign1; audience binding in action and lease records; evidence container key `10`, which carries the signed record so that the verifier checks the record's fields before the signature and the proxy builds the forwarded request from it; pending entries (Section 6.2) as the replay defence, allowing concurrent approvals; single-use lease ids (Section 8.4); delivery of every checkpoint to a party independent of the log writer (Section 9.4); the auditor's "verified up to index k" result.

---

## Appendix B. Test vector catalogue

`★` marks the minimum set required by the guideline, Phụ lục E. Expected digests are `pending` until produced by two independent implementations (Section 12.3); Appendix D gives illustrative values for three of them.

### B.1. ENC · Encoding primitives

| ID | Case | Expected |
| :--- | :--- | :--- |
| ENC-001 | NFC string `café` (U+00E9) | accept |
| ENC-002 ★ | NFD string `café` (U+0065 U+0301) | reject `E_NOT_NFC` |
| ENC-003 | Overlong UTF-8 encoding of `/` (`0xC0 0xAF`) | reject `E_BAD_UTF8` |
| ENC-004 | String containing U+0000 | reject `E_BAD_UTF8` |
| ENC-005 ★ | JSON object with duplicate key at top level `{"a":1,"a":2}` | reject `E_DUP_KEY` |
| ENC-006 ★ | Duplicate key in a nested object | reject `E_DUP_KEY` |
| ENC-007 | Keys equal after unescaping: `{"a":1,"\u0061":2}` | reject `E_DUP_KEY` |
| ENC-008 | Member name in NFD | reject `E_NOT_NFC` |
| ENC-009 | Unpaired surrogate escape `"\uD800"` | reject `E_BAD_UTF8` |
| ENC-010 | Integer 9007199254740993 (2^53 + 1) | reject `E_NUMBER` |
| ENC-011 | `-0` | accept; canonical bytes `0` |
| ENC-012 | Key ordering with non-BMP characters (JCS sorts by UTF-16 code units) | accept; canonical bytes given |
| ENC-013 | Same object, different key order and whitespace | accept; identical canonical bytes |
| ENC-014 | Tagged record with tags `0x02, 0x01` | reject `E_TAG_ORDER` |
| ENC-015 | Tagged record with tag `0x01` twice | reject `E_TAG_ORDER` |
| ENC-016 | Length field larger than remaining input | reject `E_LENGTH` |
| ENC-017 | One trailing byte after last field | reject `E_LENGTH` |
| ENC-018 | Unknown tag `0x7F` | reject `E_UNKNOWN_TAG` |
| ENC-019 | Field present with empty value vs field absent | both accept; digests differ |
| ENC-020 | Log record with record type `9` | reject `E_VALUE` |
| ENC-021 | `u64` field with a 7-byte value | reject `E_LENGTH` |
| ENC-022 | Digest reference with `sha-256` and a 31-byte digest | reject `E_LENGTH` |
| ENC-023 | Digest reference with `alg = "sha-1"` | reject `E_ALG_MISMATCH` |
| ENC-024 | String containing a code point unassigned in Unicode 16.0.0 | reject `E_NOT_NFC` |
| ENC-025 | Number `0.1` | accept; canonical bytes `0.1` |
| ENC-026 | Number `1e400` | reject `E_NUMBER` |
| ENC-027 | JSON string `"\u0000"` | reject `E_BAD_UTF8` |
| ENC-028 | Action record without tag `0x03` | reject `E_MISSING_FIELD` |
| ENC-029 | JSON text `{"a":NaN}` | reject `E_JSON` |
| ENC-030 | Server identity whose `lp()` values leave 2 bytes of the field value unused | reject `E_LENGTH` |

### B.2. FP · Tool fingerprint

| ID | Case | Expected |
| :--- | :--- | :--- |
| FP-001 | Baseline tool with all fields | accept; digest |
| FP-002 ★ | Two tools with different names, identical schema and description | digests differ |
| FP-003 ★ | `destructiveHint` flipped from `false` to `true` | digest differs from FP-001 |
| FP-004 | `destructiveHint` omitted vs explicitly `true` (same MCP meaning) | digests differ (Section 5.3) |
| FP-005 | One character changed in `description` | digest differs |
| FP-006 | Same tool definition on two different server identities | digests differ |
| FP-007 | `title` added | digest differs |
| FP-008 | `outputSchema` changed | digest differs |
| FP-009 | `inputSchema` with members in different order | same digest as FP-001 |
| FP-010 | `description` not in NFC | reject `E_NOT_NFC` |
| FP-011 ★ | Client serves cached `tools/list` (`ttlMs` not expired) while server has changed the definition: comparator given approved fingerprint, cached definition, and live definition | cached definition compared before delivery: accept while it equals the approved fingerprint; after refresh to the changed definition: reject `E_FP_CHANGED`, no stale approval reused |
| FP-012 | `url` identities differing only in host case and default port | same identity bytes |
| FP-013 | `url` identities differing in path case | different identity bytes |
| FP-014 | Fingerprint reference with `sha-384` where `sha-256` is expected | reject `E_ALG_MISMATCH` |
| FP-015 | Description containing invisible characters (U+200B, tag characters) | accept; digest (detection is the scanner's job, not the fingerprint's) |
| FP-016 | `url` identity with a non-ASCII host whose UTS #46 transitional and non-transitional A-labels differ (for example containing `ß`) | identity bytes use the non-transitional A-label |
| FP-017 | `url` identity `https://user:pass@mcp.example/` | reject `E_VALUE` |
| FP-018 | `url` identity with a query, `https://mcp.example/?b=2&a=1` | reject `E_VALUE` |
| FP-019 | `url` identity with scheme `http` | reject `E_VALUE` |

### B.3. ACT · Action request digest

Vectors marked P test proxy behaviour and are required only for the Proxy class (Section 12.1).

| ID | Case | Expected |
| :--- | :--- | :--- |
| ACT-001 | Baseline action | accept; digest |
| ACT-002 ★ | One byte of the arguments in the record (key `10`) altered after signing, key `3` unchanged | reject `E_DIGEST_MISMATCH` |
| ACT-003 P | Agent sends arguments with different key order than signed | accept; forwarded bytes equal canonical bytes |
| ACT-004 ★ | Argument path `café` in NFD | reject `E_NOT_NFC` (not normalized) |
| ACT-005 ★ | Duplicate key in arguments `{"path":"a","path":"b"}` | reject `E_DUP_KEY` |
| ACT-006 | Same evidence presented twice | second: reject `E_REPLAY` |
| ACT-007 | Valid evidence for a `(session id, sequence)` the proxy never issued as pending | reject `E_REPLAY` |
| ACT-008 | Presented after `not_after` + skew | reject `E_EXPIRED` |
| ACT-009 | Approval computed for a different session id | reject `E_SESSION` |
| ACT-010 | Tool fingerprint changed between approval and execution | reject `E_FP_CHANGED` |
| ACT-011 P | Forwarding harness: proxy forwards original bytes instead of canonical bytes | harness reports non-conformance |
| ACT-012 | Audience of another proxy | reject `E_AUDIENCE` |
| ACT-013 | Validity window longer than 300 000 ms | reject `E_EXPIRED` |
| ACT-014 P | `Mcp-Name` header differs from `params.name` | reject `E_HEADER_MISMATCH` |
| ACT-015 | Absent `arguments`, `"arguments": null`, and `{}` | same digest |
| ACT-016 | Approver id set; signed by another approver's valid credential | reject `E_CREDENTIAL` |
| ACT-017 | Tool server as verifier receives `params.arguments` differing by one byte from field `0x07` of key `10` | reject `E_DIGEST_MISMATCH` |
| ACT-018 P | Two approvals pending at once; the later sequence is approved and executed first | both accept |
| ACT-019 P | Agent request with `params._meta` and an extra `params` member | accept; forwarded request contains only the members of Section 6.3 |
| ACT-020 | Duplicate `name` member in `params` of the agent's request | reject `E_DUP_KEY` |

### B.4. WA · WebAuthn evidence

Vectors in this group include a test authenticator key pair so that runners can verify signatures without hardware. Unless stated, key `10` and key `3` are consistent and the record passes Section 6.4.

| ID | Case | Expected |
| :--- | :--- | :--- |
| WA-001 | Valid assertion, ES256 | accept |
| WA-002 | Valid assertion, EdDSA | accept |
| WA-003 | Challenge is digest of another action | reject `E_WA_CHALLENGE` |
| WA-004 | Challenge encoded with padding | reject `E_WA_CHALLENGE` |
| WA-005 | Challenge encoded with standard base64 alphabet | reject `E_WA_CHALLENGE` |
| WA-006 | `type` is `webauthn.create` | reject `E_WA_TYPE` |
| WA-007 | Origin not in allowed set | reject `E_WA_ORIGIN` |
| WA-008 | `crossOrigin: true` | reject `E_WA_ORIGIN` |
| WA-009 | `rpIdHash` of a different RP ID | reject `E_WA_RPID` |
| WA-010 | UP flag clear | reject `E_WA_FLAGS` |
| WA-011 | UV flag clear | reject `E_WA_FLAGS` |
| WA-012 | BE flag set, deployment forbids synced credentials | reject `E_WA_FLAGS` |
| WA-013 | Signature over a different `clientDataJSON` | reject `E_WA_SIGNATURE` |
| WA-014 | Stored counter 10, received 10 | reject `E_WA_COUNTER` |
| WA-015 | Stored counter 0, received 0 | accept |
| WA-016 | Unknown credential id | reject `E_CREDENTIAL` |
| WA-017 | Container with map keys out of canonical order | reject `E_CBOR` |
| WA-018 | Container with indefinite-length byte string | reject `E_CBOR` |
| WA-019 | Container with unknown key `11` | reject `E_CBOR` |
| WA-020 | `clientDataJSON` with duplicate `challenge` member | reject `E_DUP_KEY` |
| WA-021 | RS256 credential, verifier configured without RS256 | reject `E_WA_SIGNATURE` |
| WA-022 | BS flag set, BE flag clear | reject `E_WA_FLAGS` |
| WA-023 | BE flag differs from the value stored at registration | reject `E_WA_FLAGS` |
| WA-024 | `authenticatorData` of 36 bytes | reject `E_WA_AUTHDATA` |
| WA-025 | `userHandle` of another user | reject `E_CREDENTIAL` |
| WA-026 | Valid assertion, credential registered with `alg = −19` | accept |
| WA-027 | Credential registered with `alg = −8` on an Ed448 key | reject `E_WA_SIGNATURE` |
| WA-028 | ES256 signature as raw `r ‖ s` instead of DER | reject `E_WA_SIGNATURE` |
| WA-029 | Container without key `10` | reject `E_CBOR` |

### B.5. DK · Device-key evidence

| ID | Case | Expected |
| :--- | :--- | :--- |
| DK-001 | Valid COSE_Sign1, ES256 | accept |
| DK-002 | Payload is another action's digest | reject `E_DIGEST_MISMATCH` |
| DK-003 | `alg` in protected header differs from registered key | reject `E_COSE` |
| DK-004 | `alg` only in unprotected header | reject `E_COSE` |
| DK-005 | `kid` of another credential | reject `E_COSE` |
| DK-006 | ES256 signature DER-encoded instead of raw `r ‖ s` | reject `E_COSE` |
| DK-007 | Detached payload (`nil`) | reject `E_COSE` |

### B.6. LS · Capability lease

| ID | Case | Expected |
| :--- | :--- | :--- |
| LS-001 | Valid lease, call within all limits | accept |
| LS-002 | `max calls = 10`, eleventh call (guideline ACT-04 "Kiểm chứng") | reject `E_LEASE_BUDGET`, or escalation to per-action approval, as set by the vector's policy mode |
| LS-003 | `beneath` constraint `src`, argument `docs/a.md` | reject `E_LEASE_CONSTRAINT` |
| LS-004 | `beneath` constraint `src`, argument `src/../.env` | reject `E_LEASE_CONSTRAINT` |
| LS-005 | Call after `not_after` | reject `E_EXPIRED` |
| LS-006 | Tool not in the lease tool set | reject `E_LEASE_SCOPE` |
| LS-007 | Tool in set but fingerprint changed | reject `E_FP_CHANGED` |
| LS-008 | Lease granting a tool classified privileged | reject at grant `E_LEASE_SCOPE` |
| LS-009 | Lease granting a shell tool | reject at grant `E_LEASE_SCOPE` |
| LS-010 | Call after revocation | reject `E_LEASE_REVOKED` |
| LS-011 | `max argument bytes` exceeded by the last call | reject `E_LEASE_BUDGET` |
| LS-012 | Lease tool entries not sorted | reject at grant `E_TAG_ORDER` |
| LS-013 | Pointer does not resolve, op `absent` | accept |
| LS-014 | Two entries with the same server identity and name, different fingerprints | reject at grant `E_TAG_ORDER` |
| LS-015 | Grant evidence presented again after the lease was exhausted or revoked | reject at grant `E_REPLAY` |
| LS-016 | Lease window longer than 8 hours | reject at grant `E_EXPIRED` |
| LS-017 | Constraint with `"tool": "write_file"`; call to another tool in the lease that violates it | accept |
| LS-018 | Tool count `n` larger than the entries present | reject at grant `E_LENGTH` |
| LS-019 | Constraint with unknown `op` | reject at grant `E_VALUE` |
| LS-020 | `beneath` constraint `src`, argument `src/a/b.py` | accept |
| LS-021 | `beneath` constraint `src`, argument `srcfoo/a` | reject `E_LEASE_CONSTRAINT` |
| LS-022 | `beneath` constraint `src`, arguments `./src/a`, `src//a`, `/etc/passwd`, `src\..\x` | each rejected `E_LEASE_CONSTRAINT` |
| LS-023 | `beneath` constraint with `value` `../src` | reject at grant `E_VALUE` |

### B.7. LOG · Log chain

| ID | Case | Expected |
| :--- | :--- | :--- |
| LOG-001 | Five records, one anchored checkpoint at size 5 | verified up to index 4 |
| LOG-002 | Record at index 2 deleted (guideline OBS-02 "Kiểm chứng") | `E_LOG_INDEX` |
| LOG-003 | Last record deleted; the auditor holds an anchored checkpoint whose size includes it | `E_LOG_CHAIN` (truncation detected) |
| LOG-004 | Eight records, latest anchored checkpoint at size 5 | verified up to index 4; indices 5–7 reported unanchored |
| LOG-005 | Records 5–7 deleted; latest anchored checkpoint at size 5, so none of them was covered | verified up to index 4; the deletion is not detectable (Section 13.6) |
| LOG-006 | Record from log B inserted into log A | `E_LOG_ID` |
| LOG-007 | Two records swapped | `E_LOG_INDEX` |
| LOG-008 | Records renumbered after deletion, chain recomputed, old anchored checkpoint kept | `E_LOG_CHAIN` |
| LOG-009 | Anchored checkpoint with invalid signature | `E_LOG_CHECKPOINT` |
| LOG-010 | Checkpoint supplied only by the log writer, never delivered to an independent party | ignored; records it covers reported unanchored |
| LOG-011 | Later anchored checkpoint with smaller size | `E_LOG_ROLLBACK` |
| LOG-012 | One byte of a record's decision changed from `3` to `4` | `E_LOG_CHAIN` |
| LOG-013 | Type-2 record for sequence 3 with no earlier type-1 record for sequence 3 in that session | `E_LOG_SESSION` |
| LOG-014 | Payload deleted from external store, digest remains | verified; payload reported missing |
| LOG-015 | Two type-1 records with the same session id and sequence | `E_LOG_SESSION` |
| LOG-016 | Concurrent actions: type-1 record for sequence 3 before the type-1 record for sequence 2 | verified |
| LOG-017 | Anchored checkpoint with an RFC 3161 token that does not verify | `E_LOG_CHECKPOINT` |
| LOG-018 | Log writer supplies a forked history whose own checkpoint is time-stamped; the auditor holds an anchored checkpoint of the original history | `E_LOG_CHAIN` |

### B.8. E2E · End to end

| ID | Case | Expected |
| :--- | :--- | :--- |
| E2E-001 | `tools/list` → approve fingerprint → `tools/call` → action digest → WebAuthn approval → forward → log records → checkpoint | all steps accept; log auditor verifies |
| E2E-002 | As E2E-001, server changes description between approval and call | call rejected `E_FP_CHANGED`; decision logged as 6 |
| E2E-003 | As E2E-001, the same approval evidence is presented again for a retry | second presentation rejected `E_REPLAY`; both logged |

---

## Appendix C. Open issues

| ID | Issue | Current proposal |
| :--- | :--- | :--- |
| OI-1 | Should U+0000 and other control characters be rejected in all strings? | Reject U+0000 only |
| OI-2 | Unknown tags: reject, or allow a range of ignorable extension tags? | Reject everything in `aab-00`; revisit before freezing |
| OI-3 | Maximum value length | 2^24 bytes; may be too small for large schemas |
| OI-4 | Should `icons`, `_meta`, and future tool fields be fingerprinted? `_meta` may carry vendor data shown to the model | Not covered; needs input from MCP client implementers on what reaches the model |
| OI-5 | URL identity: are there remote MCP servers whose endpoint genuinely needs a query? Should `http` be allowed for loopback addresses during development? Should trailing slashes be normalized? | Userinfo and query rejected (`E_VALUE`); no trailing-slash normalization |
| OI-6 | Hash annotations as received, or with MCP defaults applied? | As received; policy interprets |
| OI-7 | Maximum validity window of an action approval | 300 000 ms |
| OI-8 | Presentation digest: what exactly does a trusted display commit to? | Field reserved; format and object type undefined until ACT-05 has an implementation |
| OI-9 | Should `topOrigin` ever be allowed, for approval UIs embedded in another origin? | Reject |
| OI-10 | Path constraints in leases: is a lexical `beneath` that rejects `.`, `..` and empty segments too strict for real tools (for example tools that expect `./` prefixes or absolute paths inside a declared root)? Should absolute roots be supported? | `beneath` with plain relative paths only; symbolic links left to the tool and the sandbox |
| OI-11 | Recommended checkpoint frequency | Deployment choice; guideline suggests "mỗi N bản ghi hoặc mỗi vài phút" |
| OI-12 | Align the checkpoint format with the C2SP `tlog-checkpoint` / signed-note formats used by existing transparency logs, instead of a new tagged record | Open; alignment would let existing witnesses co-sign |
| OI-13 | Salt payload digests to prevent confirmation of low-entropy payloads? | Open |
| OI-14 | Batch approval: one signature over several actions | Not supported; leases cover the use case |
| OI-15 | Post-quantum signature algorithms for approvers | Out of scope until supported by FIDO2 authenticators |
| OI-16 | Unicode version pin: how to move to a newer Unicode version, given that it changes which code points are accepted? | Pin 16.0.0; a newer version requires a new wire version |
| OI-17 | Dropping `params._meta` and other `params` members from the forwarded request may break progress tokens and other MCP features | Drop everything except `name` and `arguments`; decide later which members can be bound in the record instead |
| OI-18 | Accept only the fully-specified COSE identifiers (`−9`, `−19`), or also the polymorphic ones (`−7`, `−8`)? | Accept both, with `−8` restricted to Ed25519 |
| OI-19 | Maximum lease duration | 8 hours (28 800 000 ms) |

---

## Appendix D. Worked example (illustrative)

These values were computed by a single throwaway script while drafting. They are **illustrative, not test vectors**: they have not been cross-checked by an independent implementation.

### D.1. Tool fingerprint (illustrative, based on FP-001 without `outputSchema`)

Server identity: `kind = "oci"`, `id = "registry.example.internal/mcp/files@sha256:abab…ab"` (64 hex digits).

Tool definition:

```json
{
  "name": "read_file",
  "title": "Read file",
  "description": "Read a UTF-8 text file inside the workspace.",
  "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } }, "required": ["path"] },
  "annotations": { "readOnlyHint": true, "destructiveHint": false }
}
```

Canonical JSON:

```
inputSchema : {"properties":{"path":{"type":"string"}},"required":["path"],"type":"object"}
annotations : {"destructiveHint":false,"readOnlyHint":true}
```

Domain prefix `lp(utf8("aab/00/tool-fp/sha-256"))`:

```
00000016 6161622f30302f746f6f6c2d66702f7368612d323536
```

Record starts (tag `0x0001`, length `0x00000076`, then the server identity record):

```
0001 00000076 00000003 6f6369 0000006b 72656769737472792e6578616d706c652e ...
```

Record length: 338 bytes. Result:

| Variant | Fingerprint |
| :--- | :--- |
| As above | `sha-256:U2Q4CNaBoz71PtbKXEotxCxzb_PkZ0_gm4DMcKRWUa0` |
| `name` changed to `read_secret` (FP-002-like) | `sha-256:oAKxl7KFWAN2ffZpEH2B-TMZZY6WAetlqckp3T6Qj08` |
| `destructiveHint` set to `true` (FP-003-like) | `sha-256:zPeISc33LtI6rfSV-U2mfHa4mO2_3RqU0iVDiJRowwI` |

### D.2. Action request digest (ACT-001-like)

| Field | Value |
| :--- | :--- |
| audience | `https://proxy.example.internal` |
| session id | `000102030405060708090a0b0c0d0e0f` |
| sequence | 7 |
| server identity, tool name | as D.1 |
| tool fingerprint | the D.1 baseline |
| arguments | `{"path":"src/main.py"}` |
| not before / not after | 1790000000000 / 1790000120000 |

Action digest: `sha-256:TNrzsHt4kGTrvz_NDchY22aNsZmz9zdfmvbLPGPUGx0`

`clientDataJSON.challenge`: `TNrzsHt4kGTrvz_NDchY22aNsZmz9zdfmvbLPGPUGx0`
