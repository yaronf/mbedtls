# DTLS 1.3 cookie API — design decision

**Status:** open. The recommendation below is option (a); (b), (c), (d)
are kept in the doc as rejected alternatives with the reasoning, so the
choice is reviewable. Resolves Area 12 finding #4 of the code-review
plan.

**Context:** code-review plan finding §"Area 12 #4". RFC 9147 **§5.1**
(Denial-of-Service Countermeasures, not §5.6 — that one is about
EndOfEarlyData) describes the DTLS 1.3 HRR cookie:

> The handshake transcript is not reset with the second ClientHello, and a
> stateless server-cookie implementation requires the content or hash of the
> initial ClientHello (and HelloRetryRequest) to be stored in the cookie. The
> initial ClientHello is included in the handshake transcript as a synthetic
> "message_hash" message, so only the hash value is needed for the handshake
> to complete, though the complete HelloRetryRequest contents are needed.

Version asymmetry — important context:

- **DTLS 1.2 server *is* stateless across HelloVerifyRequest** in
  mbedtls today. The canonical pattern (visible in
  `programs/ssl/ssl_server2.c:3721`) is: receive datagram, call
  `mbedtls_ssl_handshake()`, library detects no/bad cookie, library
  sends HVR with a fresh cookie, library returns
  `MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED`, application calls
  `mbedtls_ssl_session_reset()` (which tears down
  `handshake_params`), server returns to `accept()` for the next
  datagram. The client's second ClientHello arrives as a fresh
  connection; the first ClientHello is not part of the DTLS 1.2
  transcript (HVR is explicitly outside the transcript), so the cookie
  needs to carry only reachability. The current `cli_id`-only cookie
  is RFC-compliant for DTLS 1.2.

- **DTLS 1.3 is different** because §5.1 says "the handshake transcript
  is not reset with the second ClientHello." The first CH *is* part of
  the transcript. So when the second CH arrives, the server has to
  reconstruct the first CH (or its hash) to compute consistent keys.
  That has to come from somewhere — either server-side memory (=
  stateful across HRR) or the cookie itself (= what §5.1 assumes).

Today, mbedtls's DTLS 1.3 server keeps `handshake_params` alive across
HRR. That's how HRR+cookie tests pass in the dtls13 branch despite the
cookie carrying no transcript content. The functional handshake works;
the DoS resistance the cookie is meant to provide does not — an attacker
can force `handshake_params` allocation with a single ClientHello.

**This is a regression vs DTLS 1.2.** DTLS 1.2's HVR path is stateless;
shipping a stateful DTLS 1.3 cookie path is strictly worse on the
exact dimension the cookie exists for. The endpoint state has to be
stateless across HRR, just like 1.2. That's the design constraint, not
a design choice.

The constraint forces the architecture: the cookie has to carry
`H(ClientHello1)` (and enough HRR content to rebuild the synthetic
message_hash + HRR record), per §5.1. The library's job is to expose
an API that makes this feasible. The current callback signature has no
transcript parameter, so the API must grow.

The remaining question is **how** the API grows — that's what options
(a)–(d) below address.

---

## The existing API

`f_cookie_write` and `f_cookie_check` are both DTLS 1.2-era callbacks
(introduced for HelloVerifyRequest / RFC 6347):

```c
typedef int mbedtls_ssl_cookie_write_t(
    void *ctx,
    unsigned char **p, unsigned char *end,
    const unsigned char *cli_id, size_t cli_id_len);

typedef int mbedtls_ssl_cookie_check_t(
    void *ctx,
    const unsigned char *cookie, size_t cookie_len,
    const unsigned char *cli_id, size_t cli_id_len);
```

`cli_id` is what `mbedtls_ssl_set_client_transport_id` set — typically
the peer's IP+port. The reference implementation
(`library/ssl_cookie.c`, `mbedtls_ssl_cookie_write`) computes
`cookie = timestamp(4) || HMAC(K, timestamp || cli_id)`. Both DTLS 1.2
(HelloVerifyRequest, `library/ssl_msg.c:4487` and 4526) and DTLS 1.3
(HRR cookie extension, `library/ssl_tls13_server.c:2495`) currently go
through this same callback.

Two problems for DTLS 1.3:

1. **No transcript content in the cookie.** Per §5.1, a stateless server
   needs `H(ClientHello1)` (and HRR content) to recover the transcript
   on the second ClientHello. The current callback signature has no
   transcript parameter, so no callback implementation can supply it.

2. **Application carries HMAC responsibility.** If an application wants
   to extend the cookie format itself (not currently possible — see
   problem 1), it has to write its own HMAC routine. That puts crypto
   construction in app code, and makes cluster-wide deployments
   awkward: the natural injection point (callback) couples the secret
   key to the HMAC construction.

The design choice is: how does the library grow an API that enables the
stateless-server-with-transcript-in-cookie pattern §5.1 requires?

---

## Option (a) — Stack-owned cookie construction with application-supplied secret

**Recommended.** API-additive.

Add a new config knob:

```c
/* flags */
#define MBEDTLS_SSL_COOKIE_SECRET_APPLY_TO_DTLS12    (1u << 0)

int mbedtls_ssl_conf_dtls_cookie_secret(
    mbedtls_ssl_config *conf,
    const unsigned char *key, size_t key_len,
    unsigned int flags);
```

The secret applies to DTLS 1.3 unconditionally. It applies to DTLS 1.2
**only** if the application passes
`MBEDTLS_SSL_COOKIE_SECRET_APPLY_TO_DTLS12`. This keeps the 1.2 cookie
behaviour of every existing application identical on upgrade — silently
turning on a 1.2 cookie exchange just because the application
configured a 1.3 secret would be a behaviour change those applications
didn't ask for.

When set:
- The stack owns the DTLS 1.3 HRR cookie construction, including the
  transcript payload (§5.1's "content or hash of the initial
  ClientHello").
- The secret feeds DTLS 1.2 HVR cookies **only** if the application
  passes the `APPLY_TO_DTLS12` flag — an explicit opt-in, never a
  side effect of configuring the 1.3 path.
- The application's only job is supplying the cluster-wide secret
  (and choosing whether to apply it to 1.2).
- The legacy `f_cookie_write`/`f_cookie_check` callbacks remain in
  the API and are unchanged. When configured, they keep handling
  DTLS 1.2 HVR cookies. They are *not* invoked from the DTLS 1.3
  path under any configuration (cannot satisfy §5.1). See the
  precedence rule below.

Internally, the stack:
- DTLS 1.2 (HelloVerifyRequest): cookie = `timestamp(4) || HMAC(K,
  timestamp || cli_id)` — same wire format as today (HMAC truncated
  to 28 bytes).
- DTLS 1.3 (HRR): cookie = `timestamp(4) || H(ClientHello1) || HMAC(K,
  timestamp || cli_id || H(ClientHello1))`. The transcript hash is
  carried in the cookie so the stateless server can rebuild the
  transcript on the second ClientHello; the HMAC binds the whole thing
  to the server's secret and the client's IP. Same HMAC algorithm /
  truncation as DTLS 1.2.

The `H(ClientHello1)` is already computed by the handshake transcript-hash
machinery; we'd plumb a snapshot of it from the parse-ClientHello path
(`ssl_tls13_server.c:1234–1760`) through to the HRR-write path
(`ssl_tls13_server.c:2495`), and from the second-CH parse path back to
the cookie-check site (`ssl_tls13_server.c:1723`) for verification +
transcript replay.

**Pros:**
- Fixes the §5.1 transcript-in-cookie gap in the default code path.
- Application never writes HMAC code.
- Clean cluster deployment: one config call per server with the shared key.
- Makes the security responsibility split explicit: stack does crypto, app
  supplies key material.
- Does not break any existing callers; the old callbacks remain functional
  for DTLS 1.2.
- Matches established patterns: wolfSSL's `wolfSSL_CTX_set_cookie_secret`,
  s2n's `s2n_config_set_cookie_secret`.

**Cons:**
- Adds a second cookie-config mechanism alongside the callbacks. Two ways
  to configure cookies on one `ssl_config` is a surface-area cost.
- Stack must own a small bit of HMAC plumbing it didn't own before
  (currently routed through the callback indirection).

### Precedence rule

Back-compat principle: an application that upgrades the mbedtls
version without changing its cookie configuration must see identical
DTLS 1.2 cookie behaviour. Configuring the new 1.3 secret is not
allowed to silently turn on (or change) a DTLS 1.2 cookie exchange.

DTLS 1.3 HRR cookie:

| Secret configured? | DTLS 1.3 cookie |
|--------------------|-----------------|
| yes                | stack-issued from secret (with transcript) |
| no                 | none (legacy callbacks cannot satisfy §5.1, never invoked from 1.3 path) |

DTLS 1.2 HVR cookie:

| Legacy callbacks configured? | Secret configured with `APPLY_TO_DTLS12`? | DTLS 1.2 cookie |
|------------------------------|-------------------------------------------|-----------------|
| yes                          | (either)                                  | legacy callback path (unchanged from today) |
| no                           | yes                                       | stack-issued from secret |
| no                           | no                                        | none |

In words:

- **DTLS 1.3:** the new secret is the only way to get an HRR cookie.
  Always used when configured. The legacy callbacks are never invoked
  from the DTLS 1.3 path (cannot satisfy §5.1).
- **DTLS 1.2:** legacy callbacks always win when configured. The
  secret is used for DTLS 1.2 only if the application explicitly opts
  in via `APPLY_TO_DTLS12` *and* no callbacks are set.
- A legacy app that configures only the callbacks keeps the exact 1.2
  behaviour it had before, and gets no 1.3 cookie. To enable 1.3, the
  app adds a secret-config call; the 1.2 path stays on the callbacks.
- A new app that wants cookies in both versions configures the secret
  with `APPLY_TO_DTLS12` and skips the callbacks.

The "secret + callbacks both configured" combination is allowed but
unusual: 1.2 uses the callbacks (legacy behaviour preserved); 1.3 uses
the secret. If the app also sets `APPLY_TO_DTLS12` in that
combination, the flag has no effect (callbacks already cover 1.2) —
no error, but documented as a no-op so it doesn't surprise anyone.

### Decisions on the sub-questions

- **Scope of the new secret API:** the API exists primarily for
  DTLS 1.3 HRR cookies, which it always handles when set. It can
  optionally feed DTLS 1.2 HVR cookies, but only when the application
  passes `MBEDTLS_SSL_COOKIE_SECRET_APPLY_TO_DTLS12`. Without that
  flag, the 1.2 path is untouched: legacy callbacks remain
  authoritative if set, no cookie if not. The flag is the explicit
  back-compat boundary: legacy apps never see a 1.2 behaviour change
  unless they ask for it. Proposed name
  `mbedtls_ssl_conf_dtls_cookie_secret` (no version suffix in the
  function name; the flag dimension carries the version detail).
- **Key length and algorithm:** match the reference implementation —
  HMAC-SHA-256 truncated to 28 bytes (`mbedtls_ssl_cookie.c:41-43`),
  with SHA-384 fallback if SHA-256 is not available. The application
  supplies the raw key bytes; the config call validates `key_len` is
  within a sane range (e.g. 16–64 bytes) and rejects out-of-bounds
  at config time. No library-side default key.
- **Timeout:** reuse the existing `MBEDTLS_SSL_COOKIE_TIMEOUT`
  semantics. No new knob.
- **Migration:** every legacy configuration sees zero DTLS 1.2
  behaviour change:
  - App with callbacks only: 1.2 keeps its callback path; 1.3 has
    no cookie (same as today).
  - App with callbacks + new secret (no flag): 1.2 keeps its
    callback path; 1.3 gets a cookie via the secret. The secret
    addition adds 1.3 coverage without touching 1.2.
  - App with new secret only (no callbacks, no flag): 1.2 has no
    cookie (same as today for a no-callbacks app); 1.3 gets a
    cookie. Strict additive.
  - App with new secret + `APPLY_TO_DTLS12` flag (no callbacks): 1.2
    and 1.3 both use the secret. This is the only configuration
    where 1.2 behaviour can change vs. an upgrade — and it requires
    the app to ask for it explicitly.

  Documentation note in `ssl.h` near the new conf API recommends the
  secret API for any new DTLS 1.3 deployment, and recommends the
  `APPLY_TO_DTLS12` flag for new applications without legacy
  callbacks. No deprecation of the callbacks in this release;
  revisit when upstream's TLS 1.3 cookie work lands.

---

## Option (b) — New DTLS 1.3-specific callback type with transcript hash

```c
typedef int mbedtls_ssl_dtls13_cookie_write_t(
    void *ctx,
    unsigned char **p, unsigned char *end,
    const unsigned char *cli_id, size_t cli_id_len,
    const unsigned char *transcript_hash, size_t transcript_hash_len);

typedef int mbedtls_ssl_dtls13_cookie_check_t(
    void *ctx,
    const unsigned char *cookie, size_t cookie_len,
    const unsigned char *cli_id, size_t cli_id_len,
    const unsigned char *transcript_hash, size_t transcript_hash_len);
```

Plus a matching `mbedtls_ssl_conf_dtls13_cookies` setter. Existing
callbacks and `mbedtls_ssl_conf_dtls_cookies` unchanged for DTLS 1.2.

**Pros:**
- API-clean: callback signature explicitly carries the data needed.
- Same architectural pattern as today (callback-based), just versioned.

**Cons:**
- Application still writes HMAC code, just with one more input. Doesn't
  fix the "crypto in app code" problem — only its lack-of-input subset.
- Two callback types to maintain (1.2 and 1.3) and corresponding reference
  implementations.
- Cluster deployments still have to share the secret out-of-band and write
  matching code on every server.
- Two cookie-config setters on the same `ssl_config`; ergonomic
  regression vs. (a)'s single secret call.

---

## Option (c) — Concatenate transcript hash into `cli_id` before calling

The library would re-write `cli_id` to be `cli_id || transcript_hash`
before invoking the existing callbacks. No API change.

**Pros:**
- Zero API surface change. Existing callers compile.

**Cons:**
- **Silently breaks the reference `mbedtls_ssl_cookie_check`.** It would
  HMAC over the new `cli_id` (which now includes the transcript) without
  knowing the format changed; the resulting cookie wouldn't match what
  any existing peer or replay would generate. Anyone using the reference
  implementation in production sees their service break on upgrade with
  no compile error.
- Footgun for any custom cookie callback that does its own format
  parsing of `cli_id`.
- Conflates "client transport identifier" and "transcript hash" in one
  parameter — misleading semantics for future readers of the callback
  signature.

I'd not ship this; listed for completeness.

---

## Option (d) — Accept the limitation; document and move on

Don't change the API. Document in `include/mbedtls/ssl.h` near
`mbedtls_ssl_conf_dtls_cookies` that DTLS 1.3 cookies as currently
implemented provide reachability verification only, not transcript
binding, and that applications requiring transcript-bound cookies must
write a custom callback that obtains the transcript hash from
`mbedtls_ssl_get_transcript_hash` (or similar — would need exposing).

**Pros:**
- Zero code change. The HRR+cookie path works today because mbedtls
  keeps `handshake_params` alive across HRR.
- Defers the API decision until upstream mbedtls TLS 1.3 cookie work
  lands and we can converge.

**Cons:**
- **Regresses vs DTLS 1.2.** DTLS 1.2's HVR mechanism is stateless;
  shipping a stateful DTLS 1.3 cookie path is strictly worse on the
  exact dimension the cookie exists for. Single-ClientHello DoS attack
  still works.
- "Document the footgun" doesn't help: there is no callback an
  application can write that fixes it. The §5.1 transcript requirement
  cannot be satisfied through the current API at all.
- Lower security floor than wolfSSL/s2n peers in the same DTLS 1.3
  space — their APIs leave the door open for stateless deployments.

(d) is included for completeness but is effectively "ship the
regression and document it." Not a real candidate given the constraint.

---

## Trade-off summary

| Option | Carries transcript in cookie (§5.1) | App writes crypto | API surface change | Cluster story | Stateless server feasible |
|--------|------------------|-------------------|--------------------|---------------|---------------------------|
| (a)    | yes, by default  | no                | additive (new conf API) | clean (one secret call) | yes |
| (b)    | only if app implements it | yes | additive (new callback type) | app-managed | yes (if app implements it) |
| (c)    | yes, but silently breaks reference check | no | zero | clean | yes |
| (d)    | no               | n/a (no callback can satisfy §5.1) | zero | app-managed | no |

---

## Recommendation

(a) is the answer. The DoS-resistance constraint forces stateless-
across-HRR, which forces transcript-in-cookie, which the existing
callback API can't carry. (a) is the shape that lets the library
provide this without making the application write HMAC code.

The work has two halves:

1. **API addition** (`mbedtls_ssl_conf_dtls_cookie_secret` + cookie
   format with `H(ClientHello1)` payload). Smaller half.

2. **Architectural change** — stop keeping `handshake_params` alive
   across HRR; mirror the DTLS 1.2 HVR pattern but with §5.1's
   transcript-recovery from the cookie. Bigger half: touches the
   server-side handshake state machine, the parse-second-CH path, and
   the transcript replay logic.

Within the (a) work itself the sub-sequencing options are:

- **API first, architectural change second.** Cookie format ships
  with transcript content; library still keeps state across HRR
  temporarily; subsequent commit removes the state-keeping. On-wire
  format stable from the first release; correctness still flips on
  the second commit.

- **Architectural change first, API second.** Server goes stateless,
  but with the existing reachability-only cookie. *This briefly
  breaks the HRR+cookie tests* because the transcript won't match.
  Not viable as an intermediate landing point; would have to be
  squashed.

- **Both together.** Single PR, larger review surface but no
  intermediate broken states.

I'd go API-first within (a): the on-wire format is the most
externally-visible artifact, and locking it in before the larger
internal refactor reduces the risk of revisiting the format if the
refactor surfaces something unexpected.

(b) is strictly worse than (a) on every axis except "fits the existing
callback pattern."

(c) should not be shipped — silent breakage of the reference
`mbedtls_ssl_cookie_check`.

(d) is included for completeness but is effectively "ship a known
regression vs DTLS 1.2." Not a real candidate.

---

## What's *not* covered here (intentionally)

This doc settles **the API shape**. The implementation details below
are decided when (a) is built, not here:

- **Detailed design of the stateless-across-HRR refactor.** Within (a),
  the architectural half (discard `handshake_params` after sending
  HRR; rebuild the transcript from cookie payload on second CH)
  touches the server-side handshake state machine, the parse-second-CH
  path, and the transcript replay logic. The work is *required* for
  (a) to deliver its security claim (see Recommendation), but the
  step-by-step plan for it belongs in a separate implementation doc.
- **DTLS 1.2 HelloVerifyRequest cookie format**: unchanged. (a)'s
  secret API supplies the key for both 1.2 and 1.3 cookies; the 1.2
  wire format stays as today.
- **Cookie timeout policy**: the existing `MBEDTLS_SSL_COOKIE_TIMEOUT`
  semantics are unchanged.
- **Cookie length / HMAC algorithm choice**: match the reference
  implementation (HMAC-SHA-256 truncated to 28 bytes, with SHA-384
  fallback). Key length validated at config time (e.g. 16–64 bytes).
  Locked-in here only because (a)'s text relies on them.
- **Anti-DoS calibration of the cookie issuance rate**: orthogonal
  concern, not addressed by any of these options.
