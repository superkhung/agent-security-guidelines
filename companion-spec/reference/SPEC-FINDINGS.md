# Findings from the first implementation of aab-00

Writing `reference-python-1` turned up the places below where `aab-00` is ambiguous, contradictory, or silent. The spec is frozen for the comment round, so none of these has been applied to it. They are input for `aab-01`. Each item lists what the code does today; the code marks the spot with `# SPEC-AMBIGUITY:` (`grep -rn SPEC-AMBIGUITY companion-spec/reference/python`).

Where the spec is silent, the code sometimes rejects more than the spec requires. No generated vector depends on those extra rejections.

Comments on any item: open an Issue with the "Companion spec (aab)" template and the item number, for example `[aab-00] F-3`.

## Design problems (fix before anything else)

| # | Section | Problem | Code today | Proposed fix |
| :--- | :--- | :--- | :--- | :--- |
| F-1 | 7.2 step 8 vs 6.2 rule 1 | Approvals may complete in any order, but with an authenticator that increments its signature counter, two approvals presented in the opposite order to signing make the second one fail `E_WA_COUNTER`. The spec also does not say how the counter update and the pending-entry consumption are made atomic together. | ACT-018 is written so signing order equals presentation order | Drop the "must increase" rule for concurrent approvals, or only require the counter to differ from values already seen; define one atomic update for counter and pending entry |
| F-2 | 8.4 steps 1 and 4 | "Step 1 of 7.3" plus "the remaining steps of 7.3" skips the credential check for device-key lease grants when read literally, because 7.3 step 1 is 7.2 steps 1–4. | Runs the credential check for both profiles | Spell out the order: 7.2 step 1, 7.2 step 4, then 7.2 steps 5–8 or 7.3 steps 2–8 |
| F-3 | 8.2 | The lease grantee (field `0x05`) is never checked when a lease is used, so any agent in the session can use it. | Checks it when the agent id is known (`E_LEASE_SCOPE`) | Add an explicit grantee check with an error code |
| F-4 | 8.3 | A constraint whose `tool` names a tool that is not in the lease silently applies to nothing, so a typo fails open. | Rejects at grant (`E_VALUE`) | Require `tool` to name a tool in the lease |
| F-5 | 9.3, 9.4 | There is no format for a signed checkpoint: how record, COSE_Sign1 and time-stamp token are bundled, the COSE headers, the allowed algorithms for the log key, how the auditor gets the key, which algorithm governs the chain head. | 7.5 algorithms minus RS256, `alg` in the protected header, digest reference as payload | Define all of these, or adopt C2SP signed notes (OI-12) |
| F-6 | 7.1, 8.4 | The evidence container does not say whether key `10` holds an action or a lease record; the verifier must know from context. | Endpoint decides | Add a container key for the object type, or state that the endpoint decides |
| F-7 | 4.2, 4.3, 6.3 | Nothing requires a consumer to check that JSON fields inside a record are already in canonical form, although the forwarding rule depends on it. | Requires canonical form, rejects with `E_JSON` | Make it a MUST with an error code |

## Encoding (Section 4)

| # | Section | Problem | Code today |
| :--- | :--- | :--- | :--- |
| F-8 | 4.1 rule 3, OI-16 | The Unicode 16.0.0 pin cannot be honoured without shipping tables; the spec does not say what an implementation with older data must do. RFC 8785's own sort example uses U+FB33, which is not NFC, so off-the-shelf JCS test suites fail under aab-00. | Warns when `unicodedata.unidata_version` is not 16.0.0 |
| F-9 | 4.2 | Order of decode checks not given. | Framing, then missing fields, then values, then cross-field checks |
| F-10 | 4.3 | No precedence when one text breaks several JSON rules. | UTF-8, then grammar anywhere, then first problem in document order |
| F-11 | 4.3 | A raw U+0000 is both invalid JSON (`E_JSON`) and a banned character (`E_BAD_UTF8`). | `E_BAD_UTF8` |
| F-12 | 4.3 | No nesting-depth or size limit. | Rejects beyond depth 256 with `E_JSON` |

## Server identity and fingerprint (Section 5)

| # | Section | Problem | Code today |
| :--- | :--- | :--- | :--- |
| F-13 | 5.2 | UTS #46 options (CheckHyphens, CheckBidi, CheckJoiners, UseSTD3ASCIIRules, VerifyDnsLength) are not named; its mapping step case-folds and NFKC-maps, which is a repair that D4 otherwise forbids; order relative to the NFC check and validation of decoded `xn--` labels are unstated. | ASCII hosts only; FP-016 pending |
| F-14 | 5.2 | URL rules do not cover dot segments (including `%2e`), backslashes, an empty `?`, empty, leading-zero or out-of-range ports, a trailing dot on the host, IPv4 number forms (`0x7f.1`, `127.1`), IPv6 literal form, characters outside the path set, `%` in the host, `--` in label positions 3–4. No URL parser (WHATWG or RFC 3986) is named. | Rejects all with `E_VALUE` |
| F-15 | 5.2 | Whether a decoded URL identity must already be normalized is not stated. | Requires it (`E_VALUE`) |
| F-16 | 5.2 | `oci`, `pkg` and `local` have no grammar: "fully qualified" is undefined, `@` in scoped npm names makes `pkg` ambiguous, "absolute path" has no OS rule, hex case for `local` is unstated; an unknown kind has no error. | Docker's qualification rule; `E_VALUE` |
| F-17 | 5.1 | No error for a tool definition missing `name` or `inputSchema`, a member of the wrong type (`"title": null`), or a non-object schema. | `E_MISSING_FIELD`, `E_JSON` |
| F-18 | 5.4 rule 3, 6.4 check 6 | "Treated as new" has no defined result; a tool with no current fingerprint (removed from the list) is not covered. | Removed tool gives `E_FP_CHANGED` |

## Action and forwarding (Section 6)

| # | Section | Problem | Code today |
| :--- | :--- | :--- | :--- |
| F-19 | 6.1 | Field `0x0B` has no object type (OI-8), so its algorithm is undefined. | Uses the action's algorithm |
| F-20 | 6.3 rule 6 | "The bytes of `params.arguments`" could mean the raw received span or the canonical form; the check's place among the steps is not given. | Compares the raw span |
| F-21 | 6.3 | No rule for a request without `id` or with a non-scalar `id`; no header encoding for non-ASCII tool names in `Mcp-Name`; `jcs(id)` turns `1.0` into `1`, so the response id no longer matches. | Rejects missing or non-scalar `id` with `E_JSON` |
| F-22 | 6.4, 8.4 | `not_after − not_before` and `not_after + 30000` can overflow 64-bit arithmetic. | Checks order first, uses exact arithmetic |

## Evidence (Section 7)

| # | Section | Problem | Code today |
| :--- | :--- | :--- | :--- |
| F-23 | 7.2 step 5 | clientDataJSON that is valid JSON but not an object has no error. | `E_JSON` |
| F-24 | 7.2 step 6.1 | "Consistent with the AT and ED flags" does not say whether AT may be set in an assertion. | Rejects AT (`E_WA_AUTHDATA`) |
| F-25 | 7.3, 7.5 | RS256 is not allowed for device-key, but no step rejects it; whether the −9/−7 and −19/−8 equivalence is symmetric is not stated. | Rejects at step 5 (`E_COSE`); symmetric |

## Lease (Section 8)

| # | Section | Problem | Code today |
| :--- | :--- | :--- | :--- |
| F-26 | 8.4 step 4 | Which approver authorization a lease grant needs is not defined. | Grantor must be authorized for every tool in the lease |
| F-27 | 8.3 | Required members per `op` are implicit; pointer and value types are unchecked; a non-array `constraints` has no error. | `value` required except for `absent`; valid RFC 6901 pointer; `E_VALUE` |
| F-28 | 8.3 `beneath` | Whether the root itself holds (`src` beneath `src`) is not stated. | Holds, per the letter of the rule |
| F-29 | 8.1 | Order of entry decoding vs the sort and duplicate check is not given; the "proper prefix" sentence is vacuous because entries are self-delimiting. | Decodes first |
| F-30 | 8.4 check 4 | A lease whose start is far in the future is accepted at grant. | Accepted |

## Log (Section 9)

| # | Section | Problem | Code today |
| :--- | :--- | :--- | :--- |
| F-31 | 9.1 | No error for a decision on a non-type-2 record, or for breaking the sequence rule; field `0x0A` is optional although 8.2 says lease calls MUST be logged with it; decision 6 does not record which `E_*` occurred. | `E_VALUE`; `0x0A` required for types 4, 5 and decision 5 |
| F-32 | 9.2 | Log writer append rejections have no codes. | `E_LOG_ID`, `E_LOG_INDEX` |
| F-33 | 9.5 | No reference log id when there is no anchored checkpoint; step 1 per record or two passes; "report any errors" conflicts with Section 10's "report the first"; no codes for a checkpoint that does not decode or has another log's id; anchoring order is outside information; the "extends" condition cannot fail after step 3, and a later, smaller checkpoint consistent with the records is still a rollback (LOG-011). | Caller supplies the log id; per record; stops at the first error |

## Crypto path (found with the signature backend)

| # | Section | Problem | Code today | Proposed fix |
| :--- | :--- | :--- | :--- | :--- |
| F-39 | 7.5 | ECDSA signatures are malleable: if `(r, s)` verifies, so does `(r, n - s)`. Low-S is not required, so one approval has two valid evidence byte strings. Replay is still stopped by pending entries, but anything that keys on the evidence bytes (deduplication, a log of evidence digests) sees two approvals. | Accepts high-S (unit test `test_high_s_is_accepted`) | State that evidence bytes are not unique identifiers; optionally require low-S for `device-key` and checkpoints, where the signer software is under the deployment's control (WebAuthn authenticators cannot be forced) |
| F-40 | 7.5 | "ASN.1 DER `Ecdsa-Sig-Value`" does not say that a BER encoding (non-minimal integer, long-form length) MUST be rejected; WebAuthn libraries differ, so two verifiers can disagree on the same evidence. | Strict DER; BER rejected with `E_WA_SIGNATURE` | Say MUST reject non-DER; add a vector with a valid signature re-encoded in BER |
| F-41 | 9.4 rule 2, 9.5 step 3.1 | There is no RFC 3161 validation profile: which TSA certificates are trusted and how the auditor learns them, which checks are required (ESSCertIDv2, `id-kp-timeStamping`, policy OID, nonce, `genTime` against the checkpoint `time`, accuracy), and what to do when the TSA certificate has expired. Without it LOG-017 cannot be given a fixture that two implementations would judge the same way (and `cryptography` cannot verify CMS SignedData, so a home-made token could not be cross-checked). | LOG-017 pending; any time-stamp token raises `Unsupported` after the checkpoint signature is verified | Define the profile and the trust configuration, or drop time-stamp tokens from `aab-00` and keep only anchoring (9.4 rule 1) |
| F-42 | 6.2, 6.4 check 6 | The fingerprint is compared only when evidence is verified, so a proxy may ask a person to approve a call to a tool whose definition has already changed (E2E-002), and the person's approval is then wasted or, worse, taken as consent to the old definition. | The reference proxy also checks before issuing the challenge: `E_FP_CHANGED`, logged as decision 6 | Require the check before a pending entry is created, in addition to 6.4 check 6 |
| F-43 | 9.1, 9.5 step 5, 6.2 rule 1 | Logging is under-specified for real flows: which sequence and action digest a re-presented (replayed) evidence is logged under (E2E-003); whether every rejected presentation writes its own type-2 record; what the type-3 payload is (tool response, forwarded body?); whether the credential digest is logged on decision 6. Section 6.4 ties the evidence to the session of the request being verified but not to its sequence, so evidence for one pending action can be presented while another request is being evaluated. The auditor also does not check that a type-3 (result) record follows a type-2 record that allowed the action, so "result of a rejected action" is not detected. | Retry is a new action (sequence 2); decision 6 logged under it; type-3 payload is the tool response; credential logged only on decision 3 | Specify the record sequence per decision path; add an auditor check that a type-3 record follows an allowing type-2 record (decision 1, 3 or 5) |
| F-44 | 7.5 | Ed25519 verification rules are not pinned: RFC 8032 allows cofactored or cofactorless verification, and libraries differ on non-canonical `S` or point encodings and small-order keys (see ZIP-215). Edge-case signatures can verify in one implementation and fail in another. | Whatever OpenSSL does (cofactorless, rejects non-canonical `S`) | Pin the rules (for example RFC 8032 section 5.1.7 with canonical `S`, reject small-order `A` and `R`) and add edge-case vectors |
| F-45 | 7.2, 7.5 | Validation of the *registered* key is not specified: EC point on the curve and not the identity, Ed25519 small-order keys, RSA public exponent (only "at least 2048 bits" is given), and which error applies at verification time when a registered key is invalid. | An invalid EC point fails the signature step (`E_WA_SIGNATURE` / `E_COSE`); RSA exponent not checked | Require key validation at registration; if a stored key is invalid at verification, reject with `E_CREDENTIAL` |

## Conformance and catalogue

| # | Section | Problem |
| :--- | :--- | :--- |
| F-34 | 12.2, 12.3 | The vector format cannot express "digests differ", "verified up to index k", "harness non-conformant" or "escalate"; no naming rule for several exact-byte inputs; no schema for verifier state; no status for "one implementation so far". The format used here is documented in [README.md](README.md). |
| F-35 | 12.1 | "LOG (producer side)" does not say which LOG vectors those are. |
| F-36 | B.4 | WA-005 tests nothing unless the challenge contains `-` or `_` (the D.2 digest does); WA-028 and DK-006 need real signatures to be meaningful (both now carry the other format of a valid signature, so a lenient verifier accepts them and fails the vector). |
| F-37 | B.1 | ENC-007 was printed as `{"a":1,"a":2}`, identical to ENC-005. Fixed in the spec as a typo (the escape `\u0061` had been lost). |
| F-38 | Appendix D | "abab…ab" is ambiguous (it is `ab` × 32); the text calls the server identity a "record" although it is a sub-structure. |
