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

### 2.5 Implementation addendum: audit findings, refined design

§2.1–§2.4 described the *what*. This section is the *how*, written
after auditing the codebase: it lists the actual sites that read
`ssl->handshake` in the HRR window, sketches the rewritten CH2 entry
path, and pins down the cluster-test plumbing.

#### 2.5.1 The DTLS 1.2 precedent: how mbedtls already handles this

Before designing anything new, look at what DTLS 1.2 already does for
HVR — because mbedtls *is* already stateless in DTLS 1.2 and we should
copy that shape, not reinvent it.

When DTLS 1.2 needs an HVR (`ssl_tls12_server.c:1882` →
`ssl_write_hello_verify_request`), the state machine sets state to
`MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT`, sends HVR, and on the
next `mbedtls_ssl_handshake_step` returns
`MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED` *to the application*
(`ssl_tls12_server.c:3486–3487`). The application
(`programs/ssl/ssl_server2.c:3803–3806`) then:

1. Sees the signaling error, prints "hello verification requested"
2. Goes to its `reset:` label
3. Calls `mbedtls_net_free(&client_fd)` and `mbedtls_ssl_session_reset(&ssl)`
4. Goes back to `net_accept` and waits for the next datagram

Between HVR-send and CH2-receive the server holds zero handshake
state. The cookie carries everything. **That is the model.**

The reconnect path (`ssl_msg.c:4604` `ssl_handle_possible_reconnect`)
is the same shape from the opposite direction: when an unexpected
ClientHello shows up on a fresh epoch-0 record, the cookie is
validated *before* any `handshake_params` allocation
(`mbedtls_ssl_check_dtls_clihlo_cookie` operates on the raw record
buffer). Only when the cookie verifies does the code call
`mbedtls_ssl_session_reset_int(ssl, 1)` and return
`MBEDTLS_ERR_SSL_CLIENT_RECONNECT` for the app to handle.

What Phase 1 of *DTLS 1.3* did differently — and shouldn't have:
after HRR-send the state machine moves to `MBEDTLS_SSL_CLIENT_HELLO`
and **stays inside `mbedtls_ssl_handshake()`'s loop**, keeping
`handshake_params` allocated, calling `mbedtls_ssl_send_flight_completed`
to arm a retransmit timer (`ssl_tls13_server.c:2797–2803`). That is
the DoS gap — and it's *new behaviour* introduced by the DTLS 1.3
work, not an architectural property of the codebase.

The fix is therefore "make DTLS 1.3 match DTLS 1.2", not "invent a
new statelessness mechanism."

#### 2.5.2 Audit: `ssl->handshake` reads after HRR-send

If we naïvely free `ssl->handshake` after `ssl_tls13_write_hello_retry_request`
returns *without* also taking the DTLS-1.2-style escape route, every
site below NULL-derefs. They are all in `library/ssl_msg.c` and they
all belong to the DTLS retransmit machinery:

| site | function | field |
| ---- | -------- | ----- |
| ssl_msg.c:405–439 | `ssl_double_retransmit_timeout`, `ssl_reset_retransmit_timeout` | `retransmit_timeout`, `mtu` |
| ssl_msg.c:2129    | `mbedtls_ssl_fetch_input` (timer scheduling) | `retransmit_timeout` |
| ssl_msg.c:2528–2572 | epoch-0 counter save/restore on flight resend | `dtls13_epoch0_out_ctr` |
| ssl_msg.c:2592–2880 | `mbedtls_ssl_resend_hello_request` (retransmit sender) | `retransmit_state`, `flight`, `cur_msg`, `cur_msg_p`, `dtls13_frag_off` |
| ssl_msg.c:2922–2933 | `mbedtls_ssl_send_flight_completed` | `retransmit_timeout`, `retransmit_state` |
| ssl_msg.c:7008    | `ssl_dtls13_process_ack` (entry) | direct `hs = ssl->handshake` |
| ssl_msg.c:7299–7300 | `mbedtls_ssl_handle_message_type` (ACK path) | `retransmit_state` |
| ssl_tls13_generic.c:85 | `fetch_handshake_msg` (DTLS msg_seq advance) | `in_msg_seq` (already guarded) |
| ssl_tls13_server.c:1253, 1501 | `parse_client_hello` (CH2 entry) | `handshake = ssl->handshake`, `hello_retry_request_flag` |

These fall into three groups:

1. **Retransmit machinery** (everything in `ssl_msg.c` above). Only
   matters if the server keeps a flight to retransmit. The DTLS 1.2
   model doesn't (HVR is fire-and-forget; client retransmits CH1 if
   it doesn't see the HVR); DTLS 1.3 should match. So once we adopt
   the DTLS 1.2 escape pattern, these sites never run between
   HRR-send and CH2-receive.

2. **`fetch_handshake_msg` `in_msg_seq` advance** (ssl_tls13_generic.c:85).
   Already NULL-guarded. CH2 arrives as a fresh handshake from the
   server's POV after `session_reset`, so `in_msg_seq` is freshly 0
   and the guard is irrelevant.

3. **`parse_client_hello` entry** (ssl_tls13_server.c:1253). Assumes
   `ssl->handshake != NULL`. After `session_reset`, the next
   `handshake_step` calls `ssl_handshake_init` (via the same path
   `mbedtls_ssl_setup` uses), so `ssl->handshake` is allocated again
   before CH2 parsing. No change required here.

#### 2.5.3 Rewritten HRR-send: copy the DTLS 1.2 escape pattern

After HRR-send completes, the server should signal "I'm done with this
attempt, reset me and wait for the retry" — exactly what the DTLS 1.2
HVR path does. Concretely:

```c
/* ssl_tls13_server.c — ssl_tls13_write_hello_retry_request */
static int ssl_tls13_write_hello_retry_request(mbedtls_ssl_context *ssl)
{
    /* ... existing write code (unchanged) ... */
    ssl->handshake->hello_retry_request_flag = 1;

    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->conf->dtls_cookie_secret != NULL) {
        /* Stateless DTLS 1.3 (RFC 9147 §5.1): we keep no state across
         * HRR.  The cookie carries H(CH1) and the ciphersuite_id.
         * Signal the application to reset and wait for the retried
         * ClientHello — mirrors the DTLS 1.2 HVR path. */
        mbedtls_ssl_handshake_set_state(
            ssl, MBEDTLS_SSL_SERVER_HELLO_RETRY_REQUEST_SENT);
        return 0;
    }

    /* Legacy/stateful path (no secret cookie, or TLS-over-TCP) —
     * unchanged from Phase 1. */
    mbedtls_ssl_handshake_set_state(ssl, MBEDTLS_SSL_CLIENT_HELLO);
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        mbedtls_ssl_send_flight_completed(ssl);
    }
#endif
    return 0;
}
```

The new state `MBEDTLS_SSL_SERVER_HELLO_RETRY_REQUEST_SENT` is the
DTLS 1.3 analogue of DTLS 1.2's `SERVER_HELLO_VERIFY_REQUEST_SENT`.
The state-machine handler for it returns the signaling error:

```c
/* ssl_tls13_server.c — state machine in mbedtls_ssl_handshake_server_step */
case MBEDTLS_SSL_SERVER_HELLO_RETRY_REQUEST_SENT:
    return MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED;
```

(Reuse the existing error code — semantically it means exactly what we
need: "no failure, but please reset and wait for retry". A new code
like `MBEDTLS_ERR_SSL_HELLO_RETRY_REQUIRED` is cleaner but introduces
a public-API surface change that's hard to justify when the existing
code communicates the same thing.)

The application loop in `ssl_server2.c:3803` already handles this:
prints "hello verification requested", goes to `reset:`, calls
`mbedtls_net_free` + `mbedtls_ssl_session_reset`, returns to
`net_accept`. **No application change required.** That is the whole
point of copying the DTLS 1.2 pattern.

#### 2.5.4 CH2 entry: transcript recovery from cookie

After session_reset, the freshly-allocated `handshake_params` has:
- `transcript == empty` (no CH1 hashed in)
- `hello_retry_request_flag == 0` (we have no record of having sent
  an HRR)
- `ciphersuite_info == NULL` (no CS selected yet)

CH2 contains the cookie ext, so the existing Phase 1 cookie-verify
site in `parse_client_hello` (ssl_tls13_server.c:~1723) already pulls
out `cookie_cs_id` and `ch1_hash_in_cookie`. Phase 2 uses them:

```c
/* Inside the COOKIE extension parse block, after
 * mbedtls_ssl_dtls13_hrr_cookie_check_from_secret returns success. */

/* The cookie says CH1 negotiated this ciphersuite.  Re-select it now
 * so the transcript hash uses the right algorithm. */
const mbedtls_ssl_ciphersuite_t *cs =
    mbedtls_ssl_ciphersuite_from_id(cookie_cs_id);
if (cs == NULL || !mbedtls_ssl_tls13_cipher_suite_is_offered(ssl, cookie_cs_id)) {
    /* Cookie names a ciphersuite we no longer support — bail. */
    return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
}
ssl->handshake->ciphersuite_info = cs;
ssl->handshake->hello_retry_request_flag = 1;

/* Replay H(CH1) into the transcript so subsequent transcript-hash
 * computations match what they would have been in the stateful flow.
 * mbedtls_ssl_reset_transcript_for_hrr already understands the
 * RFC 8446 §4.4.1 message_hash substitution; we just need to feed
 * it the recovered H(CH1) instead of the in-memory transcript. */
ret = mbedtls_ssl_dtls13_replay_ch1_hash_into_transcript(
    ssl, ch1_hash_in_cookie, hash_len);
if (ret != 0) return ret;
```

The helper `replay_ch1_hash_into_transcript` is the only new library
function we need on this path — and it's a thin wrapper around the
existing transcript-reset code.

Ordering note: the cookie is a TLS extension (RFC 8446 §4.2.2), parsed
inside the existing extension-walk loop. The per-extension parsers in
`parse_client_hello` don't read the running transcript hash — they
read CH bytes, set flags, and stash state. The transcript hash is
only *read* after the loop terminates (PSK binder check at
ssl_tls13_server.c:~706, and HRR/SH write paths). So whether the
cookie extension arrives first, last, or in the middle of CH2 doesn't
matter: by the time anyone reads the transcript, we've already
recovered H(CH1) into it. No two-pass parse needed.

#### 2.5.5 Cluster-test plumbing decision

**Use udp_proxy as the redirector.** Two ssl_server2 instances bind
different ports with the same `dtls_cookie_secret`. The client speaks
only to udp_proxy. udp_proxy gets a new CLI flag pair:

```
upstream_b=ADDR:PORT
redirect_after_server_pkts=N
```

After udp_proxy has forwarded N packets *from* the original upstream
(server A) *to* the client, it tears down `server_fd`, calls
`mbedtls_net_connect` with `upstream_b`, and continues. The client
side never sees the swap.

Why not the alternative (teach ssl_client2 to switch destinations)?
- ssl_client2 would have to know about the cookie protocol to time the
  switch correctly. Bleeding the test scaffolding into the client is
  worse than putting it in the proxy.
- The proxy approach is closer to the deployment model the cluster
  property claims to cover (NAT/L4 LB redirecting flows between
  servers behind the same VIP).

Why not skip the test entirely?
- Statelessness is the *only* user-visible benefit of Phase 2. A test
  that doesn't exercise the cluster behaviour leaves the architectural
  goal unverified.

Estimated effort: ~80 lines in udp_proxy.c plus a new YAML runner
hook to spin up two server binaries. Within the budget for a Phase 2
landing.

#### 2.5.6 Failing tests first (TDD)

Land these tests *before* any production code change. Each test
captures a property the implementation must satisfy. They should all
fail on the current tree; once Phase 2 is complete they all pass.
Following the project's habit (we did this for the post-handshake
retransmit work), the failing tests are the spec.

The tests are split between YAML integration tests
(`tests/dtls13/cases/`) and white-box unit tests
(`tests/suites/test_suite_ssl.dtls13`). Where a test needs a new
internal accessor (e.g. peeking at `ssl->handshake == NULL`), the
accessor is added under the existing `MBEDTLS_PRIVATE` /
test-only-hooks pattern in `library/ssl_misc.h`.

**T1 — white-box: handshake state is freed after HRR send.**
Drive a server through a CH1+HRR exchange (use the helper
`mbedtls_test_ssl_perform_handshake` already in the test suite, or
inline a minimal harness). After the HRR-write step returns, assert
`ssl->handshake == NULL`. Today (Phase 1) this is non-NULL.

**T2 — white-box: HRR-send returns HELLO_VERIFY_REQUIRED to caller.**
Same harness as T1. Assert that the *next* `mbedtls_ssl_handshake_step`
returns `MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED`. Today it returns 0
and stays inside the handshake loop.

**T3 — white-box: HRR-send does NOT arm a DTLS retransmit timer.**
After HRR-send, inspect the (newly added test accessor for)
`retransmit_timeout` / `retransmit_state` fields. They must reflect
"no pending flight." Today `send_flight_completed` is called and the
timer is armed.

**T4 — integration: stateless HRR exchange completes end-to-end.**
Plain DTLS 1.3 client + server, server configured with
`dtls_cookie_secret`, no `f_cookie_*` callbacks. Assert: handshake
completes, server log shows the DTLS-1.2-style "hello verification
requested" line *and* the "HRR cookie (secret) verified" line. Today
the first log line is absent because the state machine never returns
HELLO_VERIFY_REQUIRED for DTLS 1.3. (This is the Phase 1 regression
anchor: must pass after Phase 2 to prove no functional regression.)

**T5 — integration: client retransmits CH1, server stays consistent.**
Use udp_proxy to drop the first server→client packet (the HRR), so
the client retransmits CH1. The server, being stateless, mints a
fresh HRR with the same H(CH1). Assert: handshake eventually
completes. Today the server is in `MBEDTLS_SSL_CLIENT_HELLO` after
HRR send, holding state; a retransmitted CH1 is treated as a
duplicate / out-of-sequence message rather than a fresh start.

**T6 — integration: the cluster property (the headline test).**
Two `ssl_server2` instances, same `dtls_cookie_secret`, different
ports. udp_proxy forwards CH1→serverA, returns HRR to client,
forwards CH2→serverB. Assert: handshake completes against server B.
Today serverB has no `handshake_params` matching this client's HRR
and the handshake fails. This is the only test that directly
verifies the architectural goal of Phase 2.

**T7 — integration: transcript binding actually matters
(`ch1_hash` consumed, not just verified).** Server-side fault hook:
inject a one-bit flip into `ch1_hash` *inside the cookie* before
HMAC, then re-HMAC over the flipped data using the configured
secret (the server has both, so the cookie passes HMAC but encodes
the wrong CH1 hash). When the client echoes the cookie back, the
server reconstructs a transcript from a wrong H(CH1) and key
derivation later in the handshake fails because the Finished MAC
will mismatch. Assert: handshake fails with the right error
(`MBEDTLS_ERR_SSL_BAD_HS_FINISHED` or similar). Reuse the existing
`mbedtls_ssl_dtls13_test_set_hrr_cookie_fault` setter from Phase 1
step 5; add a new mode 3 ("flip a ch1_hash byte and re-HMAC").
Today the cookie's `ch1_hash` is verified but unused — the in-memory
transcript is authoritative — so the test would pass today
*falsely* (handshake succeeds despite the flip). Phase 2 step 2
makes it fail correctly. This is the test that distinguishes "Phase
1 with HMAC binding" from "Phase 2 with transcript recovery."

**T8 — negative: secret cookie configured but DTLS 1.2 client connects.**
Phase 2 only changes DTLS 1.3 behaviour; DTLS 1.2 must remain
on its existing stateless HVR pattern. Re-run an existing Phase 1
DTLS-1.2-with-secret test post-Phase-2; assert it still passes.
Regression anchor.

**T9 — white-box: legacy callback path is unchanged.**
Server configured with only `f_cookie_write`/`f_cookie_check` (no
secret). Drive HRR. Assert: `ssl->handshake != NULL` after HRR
send (legacy stays stateful for back-compat) and HRR retransmits
fire on a timer (legacy keeps the flight). This is the back-compat
anchor — Phase 2 must NOT change behaviour for applications that
haven't migrated to the secret API.

#### Commit ordering for the TDD lands

These tests land as the FIRST commit of Phase 2, before any
implementation. Run state:

| Test | Phase 1 (today) | After P2 step 1 | After P2 step 2 | After P2 step 3 |
| ---- | --------------- | --------------- | --------------- | --------------- |
| T1   | FAIL            | PASS            | PASS            | PASS            |
| T2   | FAIL            | PASS            | PASS            | PASS            |
| T3   | FAIL            | PASS            | PASS            | PASS            |
| T4   | FAIL            | FAIL (no xscript)| PASS           | PASS            |
| T5   | FAIL            | FAIL            | PASS            | PASS            |
| T6   | N/A (no plumbing)| N/A            | N/A             | PASS            |
| T7   | FAIL (false PASS today, see note) | FAIL  | PASS  | PASS    |
| T8   | PASS            | PASS            | PASS            | PASS            |
| T9   | PASS            | PASS            | PASS            | PASS            |

Tests that are expected to fail mid-series (T4, T5, T7 after step 1)
must be marked with `requires_dtls13_phase2_complete` or similar so
CI's "all failing tests must fail with the expected pattern" gate
doesn't mistake them for real regressions. The simpler option: don't
commit T4–T7 until the implementation commit they pair with. That
gives up the pure-TDD ordering for review hygiene, which is the right
tradeoff in a multi-step landing.

**Pragmatic recommendation**: land T1–T3, T8, T9 as the first commit
(all PASS-or-FAIL deterministic against the current tree). Land T4–T7
each in the same commit as the production change that makes them
pass. Net result: every commit has green CI, no temporary
expected-failure infrastructure needed.

#### 2.5.7 Refined commit topology

Replaces §2.4. Phase 2 lands as **four** small commits, not three:

0. **Failing-tests-first scaffold.** T1, T2, T3, T8, T9 from §2.5.6.
   T1–T3 fail; T8–T9 pass. Adds any new test-only accessors needed
   (`mbedtls_test_ssl_handshake_is_null`, `mbedtls_test_ssl_retransmit_state`).

1. **Adopt the DTLS 1.2 escape pattern for DTLS 1.3 HRR.** Add the
   `MBEDTLS_SSL_SERVER_HELLO_RETRY_REQUEST_SENT` state. After HRR-send
   (when the secret cookie is configured), move to that state instead
   of `MBEDTLS_SSL_CLIENT_HELLO`, skip the `send_flight_completed`
   call, and return `MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED` from the
   state machine on the next step. Application loop in ssl_server2
   is already wired (`reset:` label handles it). T1–T3 pass; T4–T5
   land in this commit but FAIL (we leave them in so the next commit
   has a green target); T7's "flip-and-re-HMAC" test mode is added
   and FAILS today.

2. **Restore transcript from cookie on CH2.** Wire the ciphersuite
   recovery + `replay_ch1_hash_into_transcript` helper described in
   §2.5.4. T4, T5, T7 pass.

3. **Cluster test (udp_proxy redirect + two-server YAML).** Plumbing
   commit. Adds the udp_proxy flags, the YAML schema entry for a
   second server instance, T6. No library changes. T6 passes.

Note: alternatively, fold commit 0 into commit 1 (TDD-with-failing-
intermediate-commits doesn't survive `git bisect` well). The split
above keeps every commit green except step 1, which is acceptable
for review hygiene but means `git bisect` on a future bug would
need to know to skip step 1. Decision can be deferred to landing
time.

#### 2.5.8 Risks not yet mitigated

- **`set_client_transport_id` on the retried CH.** Today the server
  application calls this once per `net_accept`, before
  `mbedtls_ssl_handshake`. The DTLS 1.2 HVR pattern already requires
  the application to call it again after `session_reset` (because
  `session_reset` clears `cli_id`); Phase 2's DTLS 1.3 path will hit
  the same code path. ssl_server2 already handles this — line 3656
  is inside the same loop as the `reset:` label.
- **Concurrent CH1+HRR exchanges from the same client.** If client
  retransmits CH1 before our HRR reaches it, the server will mint a
  *second* HRR with a fresh timestamp. Both HRRs are valid (same
  H(CH1), same secret) but only one CH2 will follow. The second
  HRR's cookie won't be echoed back; the cookie expires harmlessly.
  No state to leak. **Verify with a YAML test:** drive a CH1
  retransmit via udp_proxy duplication and assert the server still
  handshakes successfully.

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
