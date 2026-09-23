# aab-00 reference implementation (Python, first milestone)

This directory holds **one** implementation of the draft
[Agent Action Binding: Wire Format and Test Vectors](../agent-action-binding-draft-00.md)
(`aab-00`), and the generator of the test vector files in [`../vectors/`](../vectors/).

> **This is one implementation, by one author.** Section 12.3 of the spec requires a second,
> independent implementation (different author, preferably a different language and different
> JSON/CBOR libraries) before any expected value is final. Every value generated here is marked
> `"status": "provisional", "source": "reference-python-1"`. Treat it as a claim to be checked,
> not as a reference answer. Where this code and the spec disagree, the spec wins, and where the
> spec is unclear the code says so with a `# SPEC-AMBIGUITY:` comment.

The ambiguities and contradictions found while writing this code are collected, with proposed fixes, in [SPEC-FINDINGS.md](SPEC-FINDINGS.md). They are input for `aab-01`; the spec itself is frozen for the comment round.

## Run

Python 3.10 or newer, standard library only. No network access, no packages.

```sh
python3 -m unittest discover -s companion-spec/reference/python/tests   # unit tests
python3 companion-spec/vectors/run.py                                    # all vectors
python3 companion-spec/vectors/run.py --group WA -v --fail-fast          # one group
python3 companion-spec/reference/python/gen_vectors.py                  # regenerate vector files
```

The runner prints pass / fail / pending counts per group, checks that every vector ID in
Appendix B has a file, and exits non-zero on any mismatch. `--fail-fast` stops at the first
mismatch, as Section 12.2 describes.

On macOS, `/usr/bin/python3` may be 3.9 with Unicode 13.0.0. The code runs there, but prints a
warning because the Unicode pin cannot be honoured (see below). Use a Python whose
`unicodedata.unidata_version` is `16.0.0` (CPython 3.14) to produce or check values.

## What is implemented

| Area | Spec | Module |
| :--- | :--- | :--- |
| Integers, `lp()`, base64url, string checks (UTF-8, U+0000, NFC, unassigned) | 2.2, 4.1, 4.4 | `aab/encoding.py` |
| Strict JSON: duplicate keys, NFC, surrogates, `E_NUMBER`, byte spans | 4.3 | `aab/jsonstrict.py` |
| RFC 8785 JCS: ECMAScript number formatting, UTF-16 key order | 4.3 | `aab/jcs.py` |
| Tagged records, domain-separated digests, digest references | 4.2, 4.5 | `aab/records.py` |
| Server identity, URL normalization (ASCII hosts only) | 5.2 | `aab/identity.py` |
| Tool fingerprint and comparison point | 5 | `aab/fingerprint.py` |
| Action record and digest, record checks, request parsing, header check, forwarding, tool-server check, forwarding harness | 6 | `aab/action.py` |
| Strict CBOR decoder with the deterministic rules, deterministic encoder | 7.1 | `aab/cbor.py` |
| Evidence container, WebAuthn steps 1-8, device-key steps, COSE_Sign1 | 7 | `aab/evidence.py` |
| Algorithm and key checks, strict DER, pluggable signature backend | 7.5 | `aab/sigs.py` |
| Lease record, tool entries, constraints (`beneath` included), grant checks, enforcement | 8 | `aab/lease.py` |
| Log records, chain, log writer, checkpoints, auditor | 9 | `aab/log.py` |
| Execution of one vector file | 12.2 | `aab/vectorexec.py` |

Appendix D is reproduced exactly (both D.1 fingerprint variants, the baseline, the 338-byte
record, the domain prefix and the D.2 action digest); see `tests/test_appendix_d.py`.

## What is pending, and why

| Group | Provisional | Pending | Reason for pending |
| :--- | ---: | ---: | :--- |
| ENC | 30 | 0 | |
| FP | 18 | 1 | FP-016 needs UTS #46 (see below) |
| ACT | 18 | 2 | ACT-006, ACT-018 need a first presentation that verifies |
| WA | 22 | 7 | WA-001, 002, 013, 014, 015, 026, 028 need real signatures |
| DK | 5 | 2 | DK-001, 006 need real signatures |
| LS | 23 | 0 | |
| LOG | 6 | 12 | Every vector with an anchored checkpoint needs its signature verified first; LOG-017 also needs RFC 3161 |
| E2E | 0 | 3 | Need a real WebAuthn assertion and a signed checkpoint |

**Signatures.** The standard library has no ECDSA, EdDSA or RSA. Every check that does not need
the signature arithmetic is implemented: container, record binding, record checks, credential
lookup, clientDataJSON, authenticatorData and flags, counter, algorithm and key-type policy,
strict DER / raw `r || s` format, COSE headers and `Sig_structure`. The arithmetic goes through
`aab.sigs.SignatureBackend`; the default `NullBackend` raises `CryptoUnavailable`, which the
runner reports, and never maps to an `E_*` code.

A vector whose expected error occurs *before* the signature step in the order of Sections 7.2,
7.3, 8.4 or 9.5 is generated with placeholder signature bytes (for example WA-003 to WA-012,
WA-016 to WA-025, WA-027, WA-029, DK-002 to DK-005, DK-007, ACT-002, ACT-007 to ACT-010,
ACT-012, ACT-013, ACT-016,
LS-008/009/012/014-016/018/019/023, LOG-002, LOG-006, LOG-007). WA-021 and WA-027 are rejected
by the algorithm and key policy of step 7 before any arithmetic. WA-028 and DK-006 stay pending
although a placeholder is rejected: only a real signature catches a verifier that leniently
accepts the wrong signature format. LOG-010, LOG-013 and LOG-015 have no anchored checkpoint, so
they need no signature.

Pending vectors still carry their full inputs, the test key pairs (`test_keys`: P-256 private
key 1, and the RFC 8032 section 7.1 TEST 1 Ed25519 key), and a `precheck`: the outcome this
implementation reaches with the placeholder, usually `needs-crypto`, which proves that every
earlier step passes. The unit tests also run these inputs with a fake backend that pretends
signatures verify, to test the logic after the signature step (counter, pending-entry
consumption, auditor ranges, rollback). The fake backend is never used for vector files.

**UTS #46.** Correct non-transitional UTS #46 needs the IDNA mapping table, which the standard
library does not ship (`encodings.idna` is IDNA 2003). URL hosts are therefore restricted to
ASCII; a non-ASCII host or an `xn--` label raises `Unsupported`. FP-016 is pending; its note gives
the value a UTS #46 implementation should produce.

**Unicode 16.0.0.** Section 4.1 pins Unicode 16.0.0. This code uses the interpreter's
`unicodedata`: CPython 3.14 carries 16.0.0; 3.9-3.13 carry 13.0.0-15.1.0, and a future CPython
will carry a newer version. With another version, NFC and "unassigned" results can differ from
a conforming implementation for code points whose properties changed. The code warns at import
and the runner prints the version. Vectors were generated with CPython 3.14.7, unicodedata
16.0.0.

## Vector file format

Files follow Section 12.2. Section 12.2 leaves much open, so these extensions are proposals:

- `object` selects the operation: `string`, `json`, `record`, `digest-ref`, `server-identity`,
  `tool-fp`, `fp-comparator`, `action`, `request`, `forwarding`, `tool-server`, `harness`,
  `evidence`, `lease-grant`, `lease-call`, `log-audit`.
- Exact bytes: top-level `input_hex` / `input_json_text` for single-input vectors, and
  `<name>_hex` / `<name>_json_text` inside `input` otherwise (`evidence_hex`, `record_hex`,
  `tool_hex`, `body_json_text`, ...).
- `input.cases`: several inputs; the outcome adds `all_equal` / `all_distinct` over their digests
  or bytes.
- `context`: verifier state for evidence, lease and log vectors: `now`, `proxy_id`,
  `open_sessions`, `request_session`, `pending` entries, `current_fingerprints`, `tool_classes`,
  `credentials` (with a COSE key as `kty`, `crv`, `alg`, `x_hex`, `y_hex`, ...), `rp_id`,
  `allowed_origins`, `forbid_synced`, `accept_rs256`, `granted_leases`, `forbidden_tools`.
- `expected.status`: `provisional` (one implementation) or `pending` (none yet). Provisional
  values carry `source`. `expected.differs_from` / `expected.same_as` name another vector.
- Outcomes beyond accept/reject: `harness` (`conformant` / `non-conformant`), `escalate`,
  `verified_up_to`, `unanchored`, `payload_missing`, `steps`, `calls`, `presentations`.
- `precheck`, `test_keys`, `intermediate` (chain heads), `proxy_only` (vectors marked P) and
  `note` are informative.

## Ambiguities found

Every place where the spec was ambiguous, contradictory or not implementable as written is
marked in the code:

```sh
grep -rn "SPEC-AMBIGUITY" companion-spec/reference/python
```

Each marker names the section, states the problem and says which reading the code takes (the
most conservative one, usually "reject"). They are input for the public comment round.
