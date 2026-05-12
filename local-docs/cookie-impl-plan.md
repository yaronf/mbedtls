# DTLS 1.3 cookie API — implementation plan

**Status:** open. Depends on the design decision recorded in
`local-docs/cookie-api-decision.md` (option (a) recommended). This doc
plans the implementation work that resolves Area 12 finding #4 of the
code-review plan.

The work is split into two halves, sequenced as the design doc
recommends ("API first, architectural change second"):

- **Phase 1 (API):** introduce `mbedtls_ssl_conf_dtls_cookie_secret`
  and the new transcript-bearing DTLS 1.3 cookie format. Library still
  keeps `handshake_params` alive across HRR; the transcript-from-cookie
  path is wired in but unused for state recovery (the in-memory
  transcript is still authoritative). Wire format is locked in.

- **Phase 2 (Stateless server):** stop keeping `handshake_params`
  alive across HRR. On second-CH receipt, rebuild the transcript from
  the cookie's payload via `mbedtls_ssl_reset_transcript_for_hrr` (or
  equivalent). The DoS-resistance claim materialises here.

Each phase has its own commit topology and tests. They can be reviewed
and shipped independently if needed.

---

## Phase 1 — API addition

### 1.1 Public-API surface

New header additions in `include/mbedtls/ssl.h`:

```c
#define MBEDTLS_SSL_COOKIE_SECRET_APPLY_TO_DTLS12    (1u << 0)

/**
 * \brief    Configure a server-side secret for the DTLS 1.3 HRR cookie
 *           (and optionally the DTLS 1.2 HVR cookie).
 *
 *           When set, the stack uses this secret to construct cookies
 *           internally — the application does not write HMAC code.
 *           The DTLS 1.3 cookie includes a hash of the first
 *           ClientHello so a stateless server (see RFC 9147 §5.1) can
 *           rebuild the transcript on the second ClientHello.
 *
 * \param conf      SSL config to extend.
 * \param key       Secret key bytes (cluster-wide if applicable).
 *                  Must outlive \p conf; the implementation does not
 *                  copy.
 * \param key_len   Length of \p key in bytes.  Validated against an
 *                  internal range (16–64 bytes).
 * \param flags     Bitmask of MBEDTLS_SSL_COOKIE_SECRET_* flags.
 *
 * \return          0 on success, MBEDTLS_ERR_SSL_BAD_INPUT_DATA on
 *                  parameter validation failure.
 *
 * \note            Precedence with legacy `f_cookie_*` callbacks: see
 *                  the DTLS 1.3 cookie API design doc.  Summary:
 *                  legacy callbacks always win for DTLS 1.2; the
 *                  secret feeds DTLS 1.3 unconditionally and DTLS 1.2
 *                  only with `APPLY_TO_DTLS12`.
 */
int mbedtls_ssl_conf_dtls_cookie_secret(
    mbedtls_ssl_config *conf,
    const unsigned char *key, size_t key_len,
    unsigned int flags);
```

**Design point — does the implementation copy the key?** I lean
"no": the key is cluster-wide and long-lived; making the application
manage its lifetime is normal. But if we copy, we need a corresponding
free in `mbedtls_ssl_config_free` and zeroize-on-free semantics. **To
decide before coding:** check what other config setters do for similar
material (`mbedtls_ssl_conf_psk_opaque`, ticket key APIs).

### 1.2 New cookie format (DTLS 1.3)

Wire format on the HRR cookie extension:

```
struct {
    uint16 ciphersuite_id;           /* picked at HRR time, recorded for stateless replay */
    uint32 timestamp;                /* big-endian seconds */
    opaque ch1_hash[hash_len];       /* H(ClientHello1), length per the ciphersuite's hash */
    opaque hmac_tag[28];             /* HMAC-SHA-256 truncated, as today */
} dtls13_hrr_cookie;
```

HMAC input is `timestamp || cli_id || ciphersuite_id || ch1_hash`.

The `ciphersuite_id` is what the server picked when it sent HRR; it
is fixed for the rest of the handshake by RFC 8446 §4.1.4 (HRR
carries the negotiated cipher_suite). Recording it in the cookie
gives the verify path:

- the transcript hash type (which we need for
  `mbedtls_ssl_reset_transcript_for_hrr`), and
- the final ciphersuite choice itself, so the server does not need
  to re-derive it from CH2's `cipher_suites` list.

We record the full ciphersuite_id (2 bytes) rather than just the
hash type (1 byte) because it's the simpler design: the verify path
loads it directly into `handshake_params->ciphersuite_info` and
proceeds, instead of having to re-run ciphersuite selection against
CH2 with a hash-family constraint.

**No "CS in CH2's list" check.** The server just *uses* the cookie's
`ciphersuite_id` directly — no re-negotiation against CH2's
`cipher_suites` list. RFC 8446 §4.1.2 already requires the client
to offer the same suites in CH2 as in CH1 for the HRR case, so the
question is moot. The HMAC over `ciphersuite_id` prevents an
attacker from forging a different value; if the cookie validates,
the ciphersuite recorded in it is what the server picked at HRR
time, and that's what the rest of the handshake uses.

The field is in the wire format from Phase 1 even though Phase 1
doesn't strictly need it (the in-memory `handshake_params` still
holds the ciphersuite). Phase 2 then becomes a pure server-side
refactor with no on-wire change.

**Open design point — HRR content.** RFC §5.1 says "the complete
HelloRetryRequest contents are needed" for the synthetic-message-hash
replay. mbedtls's existing `mbedtls_ssl_reset_transcript_for_hrr`
takes only the post-CH1 transcript hash and replaces it with a
synthetic `message_hash` record — i.e. **it does not need the HRR's
bytes**, only the *running hash state after CH1*. So the cookie can
get away with carrying just `H(CH1)`, not HRR content. **To verify
before coding:** read `reset_transcript_for_hrr` end-to-end and
confirm no HRR bytes are needed downstream.

**Format-version byte?** None. The wire format stays minimal
(2 + 4 + hash_len + 28 = 66 bytes for SHA-256). If a future change
needs new fields, in-flight cookies issued by older servers get
rejected and clients retry — replay window is bounded by
`MBEDTLS_SSL_COOKIE_TIMEOUT` (60s default), so the rejection cost is
low. YAGNI.

### 1.3 Hook points in the library

**Where the secret + flag get stored:**

The existing `mbedtls_ssl_cookie_ctx` (in `include/mbedtls/ssl_cookie.h`)
holds the cookie state for the reference implementation; it's the `*ctx`
passed to the callbacks. The library-managed cookie context is a
parallel structure. Decision: extend `mbedtls_ssl_config` directly
with the secret + flag fields, not the cookie_ctx — the cookie_ctx is
caller-supplied, and we want the stack-owned path to work regardless of
whether the application also configured a callback-style context.

```c
/* in mbedtls_ssl_config */
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)
    const unsigned char *MBEDTLS_PRIVATE(dtls_cookie_secret);
    size_t MBEDTLS_PRIVATE(dtls_cookie_secret_len);
    unsigned int MBEDTLS_PRIVATE(dtls_cookie_secret_flags);
#endif
```

**Where the cookie is constructed (write path):**

- DTLS 1.3 HRR: `library/ssl_tls13_server.c:2495` — currently calls
  `conf->f_cookie_write`. Wrap with: "if secret is configured, take
  the stack-managed path; else if callback configured, take legacy
  path; else send no cookie." Plumb `H(ClientHello1)` from the
  parse-ClientHello site to here.

- DTLS 1.2 HVR: `library/ssl_msg.c:4526` — same wrap-with-precedence
  pattern, but only takes the secret-stack path if both no callback
  *and* `APPLY_TO_DTLS12` is set.

**Where the cookie is verified (check path):**

- DTLS 1.3: `library/ssl_tls13_server.c:1723` — same precedence wrap.
  Phase 1 only verifies the HMAC + timestamp; the recovered `H(CH1)`
  is checked against the *current* transcript-hash state (which is
  still in memory because `handshake_params` is still alive). Phase 2
  replaces "check against in-memory state" with "feed into
  `mbedtls_ssl_reset_transcript_for_hrr`."

- DTLS 1.2: `library/ssl_msg.c:4487` — same precedence wrap.

**Plumbing for `H(ClientHello1)`:**

On the write side: capture the transcript hash state *after* CH1 has
been hashed in but *before* HRR processing starts. mbedtls's
`mbedtls_ssl_get_handshake_transcript` (used by
`reset_transcript_for_hrr` at `ssl_tls13_generic.c:1454`) is the right
API — it gives a snapshot of the current running hash without
modifying the state. Call it at HRR-write time, embed in cookie.

On the check side: the cookie carries `H(CH1)`. We need to compare
it against the value `mbedtls_ssl_get_handshake_transcript` would
return for the just-parsed second-CH-time transcript state. **But in
phase 1 we keep state across HRR, so the running transcript already
includes the synthetic-message-hash replacement after the original
HRR send.** That means at second-CH parse time the running transcript
hash has already moved beyond `H(CH1)`. We'd need to either (a) save
`H(CH1)` separately on the server side at HRR-write time so we can
compare it against the cookie's claim, or (b) accept the cookie's
`H(CH1)` as authoritative (no comparison) and only verify the HMAC.

Phase 1 picks (b) — HMAC + timestamp validity is enough, because the
recovered transcript hash matches what the cookie's HMAC was computed
over (anything else would have failed HMAC verification). Saving for
the future: phase 2 will need the cookie's `H(CH1)` for actual
transcript recovery, so it'll be read off the cookie regardless;
phase 1 just doesn't *use* it for anything beyond the implicit binding
via HMAC.

### 1.4 Internal helpers

New static helpers in `library/ssl_cookie.c` (or a new
`library/ssl_tls13_cookie.c` if the file gets unwieldy):

- `ssl_dtls13_cookie_write_from_secret(...)` — writes the
  `timestamp || ch1_hash || hmac` payload given the secret and CH1
  hash.
- `ssl_dtls13_cookie_check_from_secret(...)` — verifies the cookie,
  extracts the timestamp and `ch1_hash`. Returns the extracted hash
  by out-param for phase 2's use.
- `ssl_dtls12_hvr_cookie_write_from_secret(...)` — same as today's
  cookie format but keyed off the new secret instead of the
  cookie_ctx's psa key.
- `ssl_dtls12_hvr_cookie_check_from_secret(...)` — matching check.

These do their own PSA HMAC operations rather than going through the
existing `mbedtls_ssl_cookie_write`/`_check` (those expect a
`cookie_ctx` and we want to avoid coupling the new secret path to that
structure).

### 1.5 Tests for Phase 1

The existing `tests/dtls13/cases/hrr-cookie.yaml` has two cases. We
extend it to cover the new API matrix.

**Test program changes (`ssl_server2.c`):**

Add CLI options:
- `dtls_cookie_secret=HEX` — bytes of the new secret. Empty = not
  configured.
- `dtls_cookie_secret_apply_to_dtls12=0|1` — sets the flag.

If `dtls_cookie_secret` is configured, the program calls the new API
in addition to (or instead of) the existing `mbedtls_ssl_conf_dtls_cookies`
call, mirroring real applications' choices.

**New YAML test cases** (added to `hrr-cookie.yaml`):

Phase 1 acceptance tests:

0. **neither configured, DTLS 1.3 sends no HRR cookie.** Server: no
   secret, no `f_cookie_*` callbacks. DTLS 1.3 client. Asserts: HRR
   is sent without a cookie extension; handshake completes (the
   client doesn't require a cookie). Anchors row 4 of the precedence
   table — "do nothing" is a real, supported config.

1. **secret only, DTLS 1.3 succeeds.** Server: `dtls_cookie_secret=…`,
   no `f_cookie_*` callbacks. Client: DTLS 1.3. Asserts: HRR carries a
   cookie of the new format (= 64+ bytes); second CH echoes it; cookie
   verifies; handshake completes. The new wire format is exercised.

2. **secret only, DTLS 1.2 has no cookie.** Same server config, but
   force_version=dtls12. Asserts: server sends ServerHello directly,
   no HelloVerifyRequest (the `APPLY_TO_DTLS12` flag is off → secret
   doesn't apply to 1.2 → no callbacks → no cookie).

3. **secret + `APPLY_TO_DTLS12`, DTLS 1.2 uses the secret.**
   force_version=dtls12. Server: secret + flag, no callbacks. Asserts:
   HVR is sent and verifies; handshake completes via the second CH
   path.

4. **secret + callbacks both configured, DTLS 1.2 uses callbacks.**
   `dtls_cookie_secret=…`, also `mbedtls_ssl_conf_dtls_cookies(…)`.
   force_version=dtls12. Asserts: callback path was used (probe via
   a custom callback that records invocation; the test program would
   set this up under a debug-only flag, or inline-implements its own
   callback that prints a tag).

5. **secret + `APPLY_TO_DTLS12` + callbacks, DTLS 1.2 uses callbacks.**
   Same as (4) plus the flag, to confirm the flag has no effect when
   callbacks are also set. Asserts: same as (4).

6. **secret + callbacks both, DTLS 1.3 uses secret.** Same server
   config. force_version=dtls13. Asserts: HRR cookie is the new
   format (length-based check), not what the callback would have
   produced.

Phase 1 regression tests (must not break):

7. **Existing "HRR+cookie exchange (cookie enabled)"** — runs against
   the legacy-callback-only config. Should pass unchanged. This is the
   back-compat anchor.

8. **Existing "bad cookie on retry causes server handshake_failure"**
   — same. Should pass unchanged.

Phase 1 negative tests:

9. **Bad secret-cookie HMAC.** Client crafts a second CH whose cookie
   has a flipped HMAC byte. Server rejects with handshake_failure.
   (Implementation: add a `ssl_client2.c` test-only flag that mutates
   the echoed cookie before sending the second CH. Mirrors the
   existing `bad_keyupdate` / `bad_cookie_on_retry` test-injection
   pattern.)

10. **Expired secret-cookie timestamp.** Server rejects an echoed
    cookie whose timestamp is older than
    `MBEDTLS_SSL_COOKIE_TIMEOUT`. Implementation: add a
    `ssl_client2.c` test-only flag (e.g. `cookie_age_override=N`)
    that decrements the timestamp inside the echoed cookie by N
    seconds before recomputing the HMAC and sending the second CH.
    Set N to `COOKIE_TIMEOUT + 60` to put it firmly outside the
    window. No sleep-based timing; flag-driven, deterministic.

    Requires the test program to know the cookie format and the
    secret well enough to recompute the HMAC after mutating the
    timestamp — fine for a test-only injection hook, follows the
    existing `mbedtls_ssl_dtls13_test_send_bad_*` pattern.

11. **Key-length validation at config time.** Unit test in
    `tests/suites/test_suite_ssl.dtls13.function`: call
    `mbedtls_ssl_conf_dtls_cookie_secret` with `key_len = 0`, 15, 65,
    SIZE_MAX. Assert `MBEDTLS_ERR_SSL_BAD_INPUT_DATA`.

Phase 1 unit tests in `test_suite_ssl.dtls13`:

12. **Cookie roundtrip.** Construct a cookie via the new helper, then
    verify it via the new check helper with the same secret. Assert
    success. Vary timestamp, cli_id, ch1_hash. Run with both
    SHA-256-available and SHA-384-fallback configs.

13. **Cookie wrong-secret rejection.** Construct a cookie with key A,
    verify with key B. Assert rejection.

14. **Cookie tampered fields rejection.** For each byte of the
    cookie's HMAC region, flip one bit and verify; assert rejection.
    (Targeted, e.g. random sample of 8 byte positions, not full
    enumeration.)

### 1.6 Commit topology for Phase 1

Per the design doc's "API first, sub-sequencing" lean, phase 1 lands
as a single PR (multiple commits) so the on-wire format and the
back-compat behaviour are reviewable together. Suggested commits:

1. **Public API + config struct field.** `ssl.h` additions, no
   behaviour change. Build clean.
2. **Internal helpers** in `ssl_cookie.c` / `ssl_tls13_cookie.c`.
   No call sites yet; unit tests in (1.5/12–14) anchor the helpers.
3. **DTLS 1.2 HVR integration.** Wrap the existing
   `f_cookie_write`/`_check` invocations in `ssl_msg.c` with the
   precedence rule. Test cases (1.5/3, 4, 5) added.
4. **DTLS 1.3 HRR integration.** Wrap `ssl_tls13_server.c:2495`
   and `:1723`. Test cases (1.5/1, 2, 6, 9, 10) added.
5. **Test-program plumbing.** `ssl_server2.c` and `ssl_client2.c`
   CLI options for the new secret + flag. Wire-format-mutation
   test-injection hooks for cases 9, 10.

After commit 4 the new behaviour is end-to-end functional. Commit 5
is "tests against it" — committing test infrastructure last is the
opposite of the TDD-with-failing-tests pattern we used for the KU
work, but it fits here because the new behaviour is *additive* and
all-or-nothing (no partial-progress signal from running tests early).

---

## Phase 2 — Stateless server

The architectural change. Smaller in test surface but bigger in code
risk because it touches the server handshake state machine.

### 2.1 What changes

Today: `ssl_tls13_server.c` keeps `handshake_params` alive between
HRR send and second-CH receipt. The transcript hash is in
`handshake_params`'s running hash state. Memory cost: one
`handshake_params` per pending HRR exchange per client IP — the DoS
gap.

Goal: discard `handshake_params` after HRR send. On second-CH parse,
allocate a fresh `handshake_params`, hash the cookie's `H(CH1)` into
the transcript via `mbedtls_ssl_reset_transcript_for_hrr`, then parse
the second CH normally.

### 2.2 Touchpoints

- **HRR write path.** After sending HRR, the existing code transitions
  to a state that waits for the second CH while keeping
  `handshake_params`. Change: after HRR send, call something
  equivalent to `mbedtls_ssl_handshake_free(ssl)` to release
  `handshake_params`. Server returns to `accept()`-equivalent state.

- **Second-CH parse path.** Today the parser assumes
  `handshake_params` is already populated (in particular, the
  ciphersuite is recorded). Change: when the cookie validates,
  allocate a fresh `handshake_params`, load the cookie's
  `ciphersuite_id` (already in Phase 1's wire format — see §1.2)
  into `handshake_params->ciphersuite_info`, then call
  `reset_transcript_for_hrr` with the cookie's `H(CH1)` using the
  hash type implied by that ciphersuite.

- **Cleanup of post-HRR state retention paths.** Search for sites
  that today assume `handshake_params != NULL` between HRR and
  second-CH (the equivalent of `ssl_msg.c:7202` in the post-handshake
  retransmit work, but for the HRR window). Audit + likely small
  fixes to NULL-guard or to skip cleanup that's no longer needed.

### 2.3 Tests for Phase 2

The functional behaviour does not change vs phase 1 (HRR+cookie still
completes successfully, bad cookies still rejected). What *does*
change is the DoS resistance, which is hard to test in a unit / YAML
test in any direct way. So phase 2 tests are largely:

- **Regression coverage** (must not break): all phase 1 tests
  (1.5/1–14) and the legacy HRR+cookie tests still pass.

- **State-clear assertion** (new, white-box): a unit test in
  `test_suite_ssl.dtls13` that drives a server through HRR send,
  inspects `ssl->handshake` via the `MBEDTLS_PRIVATE` accessor
  (test-only), and asserts it is `NULL` after HRR send completes.
  This is the direct expression of the architectural change.

- **Fresh-server cookie validation (new, integration):** the
  property that actually justifies "stateless" is "any server with
  the right secret can verify and complete the handshake, not just
  the server that issued the HRR." Test pattern: two `ssl_server2`
  instances configured with the same `dtls_cookie_secret`, listening
  on different ports.

  1. Client sends CH1 to **server A**.
  2. Server A responds with HRR (carrying the cookie).
  3. Client sends CH2 (echoing the cookie) to **server B**.
  4. Server B verifies the cookie and completes the handshake.

  This is the cluster property — directly user-visible. If the
  server is stateful (Phase 1 behaviour), server B doesn't have
  server A's `handshake_params` and the handshake fails. If
  stateless (Phase 2 behaviour), it succeeds.

  Implementation: extend the YAML runner to support directing CH1
  and CH2 to different server instances, or have udp_proxy fork the
  client traffic across two upstream sockets after the first
  exchange. Larger plumbing than a normal YAML test; worth the
  expense because this is the only test that actually proves the
  architectural goal.

- **Cookie's ch1_hash actually used (new):** a test that maliciously
  flips one bit of `ch1_hash` *inside the cookie* (HMAC still valid
  because the test re-computes HMAC over the flipped data using the
  server's known secret — requires the secret to be readable from
  the test program). The server should reject the handshake when
  it tries to derive keys from the wrong transcript. Distinguishes
  phase 2's transcript-recovery use from phase 1's HMAC-only check.

### 2.4 Commit topology for Phase 2

A single core commit:

1. **Discard `handshake_params` after HRR send + restore transcript
   from cookie on second CH.** The architectural refactor. The
   `ciphersuite_id` field is already in the wire format from Phase 1,
   so no wire-format change is needed. Tests 2.3 added.

Possibly a follow-up cleanup commit if NULL-guard / state-retention
audit (§2.2 third bullet) turns up sites worth tidying.

---

## Cross-phase concerns

### Test-only hooks

Several tests above (cookie format-fuzz on the client side, test-only
"force discard" entry points, secret-readable-from-tests for the
ch1_hash flip test) require `MBEDTLS_TEST_HOOKS`-style instrumentation.
Audit which hooks already exist (`mbedtls_ssl_dtls13_test_send_bad_*`
is the existing pattern) and add the new ones to
`library/ssl_misc.h` under the "TEST ONLY, DO NOT USE IN PRODUCTION"
header so they don't leak into the public API.

### YAML schema changes

The runner profile (`tests/dtls13/runners/mbedtls.yaml`) needs new
parameters declared so `generate.py` doesn't reject the new test
cases. Specifically: `dtls_cookie_secret` (server), `bad_cookie_hmac`
and `bad_cookie_ch1_hash` (client, test injection),
`cookie_timeout_test_mode` (whether to use sleep or the test-only
force-discard hook).

### Documentation

- `include/mbedtls/ssl.h` near the new API: short doxygen explaining
  the secret API, the back-compat precedence with the legacy
  callbacks, and the `APPLY_TO_DTLS12` flag's purpose.
- `ChangeLog.d/`: a fresh entry for the new feature, version-tagged
  per the project convention.
- Either update or supersede `local-docs/cookie-api-decision.md` to
  mark the design as accepted once Phase 1 lands.

### What's *not* in this plan

- **Anti-DoS rate-limiting of cookie issuance.** Orthogonal; if the
  application wants per-IP rate limiting it sits in front of the
  library. Out of scope.
- **Key rotation across cluster nodes.** The API takes one key; if
  the application wants overlapping-key rotation (RFC §5.1 mentions
  "It is RECOMMENDED that servers implement a key rotation scheme"),
  it would call the conf setter repeatedly as keys rotate. That's
  application logic, not library logic. Could revisit if pain
  emerges.
- **Cluster-wide replay protection (cookie issued by node A, replayed
  to node B).** Same key on both nodes → both verify the same
  cookie. Replay window is the cookie timeout. Tightening this is
  out of scope.
