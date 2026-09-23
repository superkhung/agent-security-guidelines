# aab-00 reference implementation (Python)

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

Python 3.10 or newer. The core is standard library only. An optional signature backend uses the
[`cryptography`](https://cryptography.io/) package; it is used only when `cryptography`
imports, and nothing else depends on it.

```sh
# Standard library only: 122 vectors decided, 25 need the backend (not decided), 2 pending.
python3 -m unittest discover -s companion-spec/reference/python/tests
python3 companion-spec/vectors/run.py

# With the signature backend: 147 decided, 2 pending.
python3 -m venv .venv && .venv/bin/pip install cryptography==50.0.1
.venv/bin/python -m unittest discover -s companion-spec/reference/python/tests
.venv/bin/python companion-spec/vectors/run.py

# Options
python3 companion-spec/vectors/run.py --group WA -v --fail-fast   # one group, stop at first mismatch
python3 companion-spec/vectors/run.py --no-crypto                 # force stdlib mode (or AAB_BACKEND=none)
.venv/bin/python companion-spec/reference/python/gen_vectors.py   # regenerate vector files (needs cryptography)
```

The runner and the unit tests print the Python version, the `unicodedata` version and the active
signature backend (`cryptography 50.0.1` or `none (stdlib only)`). The runner prints per group:
`pass`, `fail`, `pending` (nothing can decide the vector yet) and `no-crypto` (the vector needs
the signature backend, which is absent). `no-crypto` is never a failure; for those vectors the
runner still checks `precheck.stdlib`, the outcome the stdlib-only mode must reach (normally
`needs-crypto` at the signature step, which shows that every earlier step passed). It checks
that every vector ID in Appendix B has a file and exits non-zero on any mismatch.

CI: `.github/workflows/aab.yml` runs the unit tests and the vectors with Python 3.14, once with
`cryptography==50.0.1` and once with the standard library only.

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
| Algorithm and key checks, strict DER, pluggable signature backend, backend selection | 7.5 | `aab/sigs.py` |
| Optional backend: ES256/ESP256 (DER and raw `r || s`), EdDSA/Ed25519 (-8, -19), RS256 where allowed | 7.5 | `aab/crypto_cryptography.py` |
| Lease record, tool entries, constraints (`beneath` included), grant checks, enforcement | 8 | `aab/lease.py` |
| Log records, chain, log writer, checkpoints and their COSE_Sign1 signatures, auditor | 9 | `aab/log.py` |
| Minimal proxy tying Sections 5-7 and 9 together (end-to-end vectors) | B.8 | `aab/proxy.py` |
| Execution of one vector file | 12.2 | `aab/vectorexec.py` |

Appendix D is reproduced exactly (both D.1 fingerprint variants, the baseline, the 338-byte
record, the domain prefix and the D.2 action digest); see `tests/test_appendix_d.py`.

## Vector counts

| Group | Files | Decided without backend | Need the backend | Decided with backend | Pending |
| :--- | ---: | ---: | ---: | ---: | ---: |
| ENC | 30 | 30 | 0 | 30 | 0 |
| FP | 19 | 18 | 0 | 18 | 1 (FP-016) |
| ACT | 20 | 18 | 2 | 20 | 0 |
| WA | 29 | 22 | 7 | 29 | 0 |
| DK | 7 | 5 | 2 | 7 | 0 |
| LS | 23 | 23 | 0 | 23 | 0 |
| LOG | 18 | 6 | 11 | 17 | 1 (LOG-017) |
| E2E | 3 | 0 | 3 | 3 | 0 |
| **Total** | **149** | **122** | **25** | **147** | **2** |

"Decided" means the file carries a provisional expected value and this implementation matches it.

**Still pending.**

- **FP-016 (UTS #46).** Correct non-transitional UTS #46 needs the IDNA mapping table, which the
  standard library does not ship (`encodings.idna` is IDNA 2003), and no other package may be
  installed for this milestone. URL hosts are therefore restricted to ASCII; a non-ASCII host or
  an `xn--` label raises `Unsupported`. The vector's note gives the value a UTS #46
  implementation should produce.
- **LOG-017 (RFC 3161).** The spec has no validation profile for time-stamp tokens (trusted TSAs,
  required checks; finding F-41), and `cryptography` cannot verify CMS SignedData, so a
  home-made token fixture could not be checked independently. The checkpoint signature in the
  vector is real; the token is a placeholder, and the implementation reports `unsupported` when it
  reaches it.

## Signatures and test keys

The signature arithmetic goes through `aab.sigs.SignatureBackend`. Everything that can be decided
without it is decided in the core: container, record binding, record checks, credential lookup,
clientDataJSON, authenticatorData and flags, counter, algorithm and key-type policy (the algorithm
comes from the registered key, never from the evidence), strict DER for WebAuthn ECDSA, raw
`r || s` for COSE, COSE headers and `Sig_structure`. Without a backend, `NullBackend` raises
`CryptoUnavailable`, which the runner reports and never maps to an `E_*` code.

Every signature in the vector files is real and made with fixed test keys, which each file lists
under `test_keys` with the private key:

| Key | Use | Derivation |
| :--- | :--- | :--- |
| `es256` | approver credential `c7ed0001...` (WebAuthn, DER) | P-256, `d = SHA-256("aab-00 test key: approver es256") mod (n - 1) + 1` |
| `device` | device-key credential `d4e10001...` (COSE, raw `r || s`) | same, label `aab-00 test key: device-key es256` |
| `log` | log writer checkpoint key (COSE, raw `r || s`) | same, label `aab-00 test key: log checkpoint es256` |
| `ed25519` | approver credential `c7ed0002...` (-8, and -19 in WA-026) | RFC 8032 section 7.1 TEST 1 |
| `ed448` | WA-027 only, which must be rejected | `SHA-512("aab-00 test key: ed448 (WA-027)")[:57]` |

ECDSA signatures use RFC 6979 deterministic nonces (`ec.ECDSA(..., deterministic_signing=True)`)
and Ed25519 is deterministic, so `gen_vectors.py` rewrites byte-identical files when the inputs
do not change.

Vectors whose error occurs before the signature step also carry valid signatures, so each one
tests exactly one defect. WA-028 carries the raw `r || s` form and DK-006 the DER form of a valid
signature; a verifier that accepts the wrong format therefore accepts these vectors and fails them
(`tests/test_crypto_backend.py` checks that the other format verifies). WA-021 (RS256 not
configured) and WA-027 (Ed448 under -8) are rejected by the key policy before any arithmetic.

The unit tests in `tests/test_after_signature.py` also run the signature-dependent inputs with a
fake backend that pretends signatures verify or fail, so the logic after the signature step is
tested in the stdlib-only mode too. The fake backend is never used to write vector files.

**Unicode 16.0.0.** Section 4.1 pins Unicode 16.0.0. This code uses the interpreter's
`unicodedata`: CPython 3.14 carries 16.0.0; 3.9-3.13 carry 13.0.0-15.1.0, and a future CPython
will carry a newer version. With another version, NFC and "unassigned" results can differ from
a conforming implementation for code points whose properties changed. The code warns at import
and the runner prints the version. Vectors were generated with CPython 3.14.7, unicodedata
16.0.0, cryptography 50.0.1.

## Vector file format

Files follow Section 12.2. Section 12.2 leaves much open, so these extensions are proposals:

- `object` selects the operation: `string`, `json`, `record`, `digest-ref`, `server-identity`,
  `tool-fp`, `fp-comparator`, `action`, `request`, `forwarding`, `tool-server`, `harness`,
  `evidence`, `lease-grant`, `lease-call`, `log-audit`, `e2e`.
- Exact bytes: top-level `input_hex` / `input_json_text` for single-input vectors, and
  `<name>_hex` / `<name>_json_text` inside `input` otherwise (`evidence_hex`, `record_hex`,
  `tool_hex`, `body_json_text`, ...).
- `input.cases`: several inputs; the outcome adds `all_equal` / `all_distinct` over their digests
  or bytes. `input.steps` (`fp-comparator`, `e2e`) and `input.presentations` run in order on
  shared state.
- `context`: verifier state for evidence, lease, log and e2e vectors: `now`, `proxy_id`,
  `open_sessions`, `request_session`, `pending` entries, `current_fingerprints`, `tool_classes`,
  `credentials` (with a COSE key as `kty`, `crv`, `alg`, `x_hex`, `y_hex`, ...), `rp_id`,
  `allowed_origins`, `forbid_synced`, `accept_rs256`, `granted_leases`, `forbidden_tools`.
- `expected.status`: `provisional` (one implementation) or `pending` (none yet). Provisional
  values carry `source`. `expected.differs_from` / `expected.same_as` name another vector.
- `requires: ["crypto"]`: the outcome depends on a real signature. `precheck` holds the outcome
  this implementation reaches per mode (`stdlib`, and for pending vectors also `crypto`).
- Outcomes beyond accept/reject: `harness` (`conformant` / `non-conformant`), `escalate`,
  `verified_up_to`, `unanchored`, `payload_missing`, `steps`, `calls`, `presentations`,
  `log_hex` (the records the reference proxy wrote in an e2e run).
- `test_keys`, `intermediate` (chain heads), `proxy_only` (vectors marked P) and `note` are
  informative.

## Ambiguities found

Every place where the spec was ambiguous, contradictory or not implementable as written is
marked in the code and collected in [SPEC-FINDINGS.md](SPEC-FINDINGS.md) (F-1 to F-45):

```sh
grep -rn "SPEC-AMBIGUITY" companion-spec/reference/python
```

Each marker names the section, states the problem and says which reading the code takes (the
most conservative one, usually "reject"). They are input for the public comment round.
