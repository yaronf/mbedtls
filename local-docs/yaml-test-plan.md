# Plan: Declarative DTLS Test Suite (YAML + Generated Runner)

**Status:** Implemented (2026-03). `tests/dtls13/` with YAML cases,
`generate.py`, mbedtls + wolfSSL runners. Generated scripts
(`dtls13-tests.sh`, `dtls13-wolfssl-tests.sh`, etc.) are committed
alongside sources.

---

## Motivation

The current test suite (`tests/ssl-opt.sh`) encodes every test as a bash `run_test`
call with server args, client args, proxy args, guards, and assertion patterns all
as free-form strings in a 15k-line script. Adding a wolfSSL runner today means
either forking the script or threading conditionals throughout it. Neither scales.

Goal: express each test case as structured data (YAML), generate the bash runner
from that data, and derive interop tests against wolfSSL (or any other stack) by
running the same YAML through a different runner profile.

---

## Decisions

- **Generated files**: runtime-generated only, not checked in. mbedtls CI already
  runs Python; no drift risk.
- **Scope**: DTLS 1.3 only. No migration of existing TLS or DTLS 1.2 tests.
- **Location**: `tests/dtls13/` (self-contained, revisit when upstreaming).
- **Assertions**: all assertion types are first-class YAML fields — no escape hatches,
  no inline shell. Schema grows to accommodate new types as needed.
- **Unmapped parameters**: runner profile must explicitly map or explicitly skip every
  case parameter. Silently dropping an unmapped parameter is an error. A runner that
  doesn't support a parameter must either declare it as `skip: true` (meaning that
  test dimension is not exercised) or the case is excluded from that runner's run.
- **Assertion strings**: runner-specific. Each runner profile declares what its binary
  prints (e.g. wolfSSL prints something other than "Protocol is DTLSv1.3"). Test cases
  reference logical assertion names; runners map them to concrete strings.
- **Runner profile format**: can be Python (not required to be pure declarative YAML).
  The boundary between `runners/mbedtls.yaml` and `generate.py` is flexible.
- **Schema documentation**: every field must be documented with type, allowed values,
  and semantics (e.g. `drop: 5` means "drop every 5th datagram, 1-indexed").

---

## Proposed Directory Layout

```
tests/dtls13/
  cases/
    handshake-basic.yaml       # full 1-RTT, bidir data, ACK, version negotiation
    hrr-cookie.yaml            # HRR+cookie, DTLS 1.2 fallback
    proxy-basic.yaml           # duplicate, pack, bad_ad
    proxy-3d.yaml              # drop+delay+duplicate variants
    fragmentation.yaml         # MTU fragmentation
  runners/
    mbedtls.py                 # mbedtls ssl_client2 / ssl_server2 runner
    wolfssl.py                 # wolfSSL client/server runner
  schema.yaml                  # field definitions, types, and validation rules
  generate.py                  # YAML + runner → shell test block
```

---

## Schema Documentation (excerpt)

The `schema.yaml` file defines every allowed field with type, constraints, and
semantics. Fields not listed in the schema are rejected at validation time.

Example entries:

```yaml
fields:
  family:
    type: string
    required: true
    description: >
      Prefix used for all test names in this file. Test names are
      "{family}, {case.name}".

  timeout:
    type: integer
    unit: seconds
    description: >
      Per-test wall-clock timeout. Applies to the entire run_test invocation.
      Defaults to the ssl-opt.sh global default if omitted.

  client_time_factor:
    type: integer
    min: 1
    description: >
      Multiplier passed to client_needs_more_time. Scales the client-side
      handshake timeout budget. Use when proxy loss/delay makes the default
      budget too tight.

proxy_fields:
  drop:
    type: integer
    min: 1
    description: >
      Drop every Nth datagram (1-indexed). drop=5 means datagrams 5, 10, 15, …
      are dropped. Does not apply to the first (N-1) datagrams in each window.
  delay:
    type: integer
    min: 1
    description: >
      Delay every Nth datagram by one round-trip (hold, deliver after the next
      packet). delay=5 means datagrams 5, 10, 15, … are delayed.
  duplicate:
    type: integer
    min: 1
    description: >
      Duplicate every Nth datagram (deliver it twice). duplicate=5 means
      datagrams 5, 10, 15, … are duplicated.
  bad_ad:
    type: boolean
    description: >
      Inject a record with a corrupted authentication tag (bad AEAD). Used to
      test badmac_limit handling.

server_fields:
  dgram_packing:
    type: boolean
    description: >
      Enable or disable datagram packing (coalescing multiple records into one
      UDP datagram). false = one record per datagram.
  hs_timeout:
    type: [integer, integer]
    description: >
      Handshake retransmit timeout range [min_ms, max_ms]. min_ms is the initial
      timeout; max_ms is the cap after doubling. Example: [500, 20000].
  auth_mode:
    type: enum
    values: [none, optional, required]
    description: >
      Client certificate verification mode. required = server rejects clients
      without a certificate.
  nbio:
    type: integer
    values: [0, 2]
    description: >
      Non-blocking I/O mode. 0 = blocking. 2 = simulated non-blocking
      (delayed_send: first send returns WANT_WRITE, second succeeds).
  debug_level:
    type: integer
    min: 0
    max: 4
    description: >
      Verbosity level for ssl_client2/ssl_server2 debug output.

assertions:
  dtls13_negotiated:
    description: >
      Both sides completed a DTLS 1.3 handshake. Runner maps this to whatever
      string the binary prints on success (e.g. "Protocol is DTLSv1.3" for
      mbedtls, "DTLSv1.3" for wolfSSL).
  server_dtls13_negotiated:
    description: Server side confirmed DTLS 1.3 negotiated.
  client_dtls13_negotiated:
    description: Client side confirmed DTLS 1.3 negotiated.
```

---

## YAML Case Format

One file per test family. Fields use the types defined in `schema.yaml`.
`hs_timeout` is a two-element list `[min_ms, max_ms]`. `dgram_packing` is boolean.
Assertions reference logical names; runners resolve them to concrete strings.

```yaml
family: "DTLS 1.3: proxy — 3d"
requires:
  - config: MBEDTLS_SSL_PROTO_DTLS

cases:
  - name: "basic handshake"
    client_time_factor: 4
    proxy:
      drop: 5
      delay: 5
      duplicate: 5
    server:
      dgram_packing: false
      hs_timeout: [500, 20000]
    client:
      dgram_packing: false
      hs_timeout: [500, 20000]
    expect:
      exit: 0
      assert:
        - server_dtls13_negotiated
        - client_dtls13_negotiated

  - name: "client auth"
    client_time_factor: 4
    proxy:
      drop: 5
      delay: 5
      duplicate: 5
    server:
      dgram_packing: false
      hs_timeout: [500, 20000]
      auth_mode: required
    client:
      dgram_packing: false
      hs_timeout: [500, 20000]
    expect:
      exit: 0
      assert:
        - server_dtls13_negotiated
        - client_dtls13_negotiated

  - name: "nbio"
    client_time_factor: 4
    proxy:
      drop: 5
      delay: 5
      duplicate: 5
    server:
      dgram_packing: false
      hs_timeout: [500, 20000]
      nbio: 2
      debug_level: 1
    client:
      dgram_packing: false
      hs_timeout: [500, 20000]
      nbio: 2
      debug_level: 1
    expect:
      exit: 0
      assert:
        - server_dtls13_negotiated
        - client_dtls13_negotiated
```

---

## Runner Profile Format

Runner profiles map abstract YAML fields to concrete binary invocations and flag
syntax. The profile format can be YAML (for simple 1:1 mappings) or Python (for
conditional logic). Every parameter used in any case file must be either mapped or
explicitly marked `skip: true`. An unmapped parameter that appears in a case is a
validation error — it will not be silently dropped.

```yaml
# runners/mbedtls.yaml
server_cmd: "$P_SRV dtls=1 force_version=dtls13"
client_cmd: "$P_CLI dtls=1 force_version=dtls13"
proxy_cmd:  "$P_PXY"

param_map:
  dgram_packing: "dgram_packing={0 if not value else 1}"
  hs_timeout:    "hs_timeout={value[0]}-{value[1]}"
  nbio:          "nbio={value}"
  auth_mode:     "auth_mode={value}"
  mtu:           "mtu={value}"
  debug_level:   "debug_level={value}"

proxy_param_map:
  drop:      "drop={value}"
  delay:     "delay={value}"
  duplicate: "duplicate={value}"
  mtu:       "mtu={value}"
  bad_ad:    "bad_ad={1 if value else 0}"

assertion_map:
  server_dtls13_negotiated:
    flag: "-s"
    string: "Protocol is DTLSv1.3"
  client_dtls13_negotiated:
    flag: "-c"
    string: "Protocol is DTLSv1.3"
  server_not_contains:
    flag: "-S"
  client_not_contains:
    flag: "-C"
```

```yaml
# runners/wolfssl.yaml
server_cmd: "$WOLFSSL_SERVER -v 4 -u"
client_cmd: "$WOLFSSL_CLIENT -v 4 -u"
proxy_cmd:  "$P_PXY"

param_map:
  hs_timeout:  "--dtls-timeout={value[0]}"   # wolfSSL takes a single value
  auth_mode:   "{'-d' if value == 'required' else ''}"
  mtu:         "--mtu={value}"
  debug_level: "-d"
  dgram_packing:
    skip: true   # no wolfSSL equivalent; cases using this param are excluded
  nbio:
    skip: true   # no wolfSSL equivalent; cases using this param are excluded

proxy_param_map:
  drop:      "drop={value}"
  delay:     "delay={value}"
  duplicate: "duplicate={value}"
  mtu:       "mtu={value}"

assertion_map:
  server_dtls13_negotiated:
    flag: "-s"
    string: "DTLSv1.3"          # wolfSSL's actual output (TBD — verify empirically)
  client_dtls13_negotiated:
    flag: "-c"
    string: "DTLSv1.3"
```

---

## Generator Output (mbedtls runner, proxy-3d.yaml)

`generate.py --cases cases/proxy-3d.yaml --runner runners/mbedtls.yaml` emits:

```bash
# AUTO-GENERATED — do not edit. Source: cases/proxy-3d.yaml + runners/mbedtls.yaml
# Regenerate: python3 tests/dtls13/generate.py

client_needs_more_time 4
requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
run_test "DTLS 1.3: proxy — 3d, basic handshake" \
    -p "$P_PXY drop=5 delay=5 duplicate=5" \
    "$P_SRV dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000" \
    "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000" \
    0 \
    -s "Protocol is DTLSv1.3" \
    -c "Protocol is DTLSv1.3"

client_needs_more_time 4
requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
run_test "DTLS 1.3: proxy — 3d, client auth" \
    -p "$P_PXY drop=5 delay=5 duplicate=5" \
    "$P_SRV dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 auth_mode=required" \
    "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000" \
    0 \
    -s "Protocol is DTLSv1.3" \
    -c "Protocol is DTLSv1.3"

client_needs_more_time 4
requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
run_test "DTLS 1.3: proxy — 3d, nbio" \
    -p "$P_PXY drop=5 delay=5 duplicate=5" \
    "$P_SRV dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 nbio=2 debug_level=1" \
    "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 nbio=2 debug_level=1" \
    0 \
    -s "Protocol is DTLSv1.3" \
    -c "Protocol is DTLSv1.3"
```

Cases that use a `skip: true` parameter are omitted from the wolfSSL run.
The nbio case, for example, would not appear in wolfSSL output.

---

## Pros

**Single source of truth.**
Adding a case or changing a guard is one YAML edit. No bash context to understand.

**Structured parameters, not free-form strings.**
Typos in flag names are caught by schema validation before the test runs silently wrong.
`hs_timeout: [500, 20000]` cannot be mistyped as `"500_20000"`.

**Interop tests are free.**
Interop tests are not a separate suite — they are the same YAML cases run through
the wolfSSL runner profile. Coverage gap is explicit: any `skip: true` parameter
shows exactly what behaviors can't yet be tested against wolfSSL.

**Assertion strings are per-runner.**
wolfSSL may print "DTLSv1.3" instead of "Protocol is DTLSv1.3".
Declare the mapping once in the runner profile, not in every test case.

**No drift.**
Runtime generation means the bash is always in sync with the YAML. No CI check needed.

**Formal schema.**
Every field is documented: type, unit, semantics. New contributors don't need to
reverse-engineer what `drop: 5` means from the proxy source.

---

## Cons

**Indirection cost.**
A developer debugging a failing test must trace YAML case → runner profile →
generated bash. Three files where there used to be one call. This is mitigated by
keeping generated output short and by the generator printing a header with the source.

**Expressiveness cost of first-class-only assertions.**
Every new assertion type requires a schema change and a runner mapping update before
it can be used in a case. No quick one-off inline assertions. This is intentional
(consistency over convenience) but has a friction cost for novel test patterns.

**wolfSSL param mapping is not clean 1:1.**
`dgram_packing` and `nbio` have no wolfSSL equivalent. Cases using them are excluded
from the wolfSSL run. Some behavioral dimensions simply can't be tested interop-style.

**Migration cost.**
All 17 existing DTLS 1.3 tests must be rewritten into YAML and validated for
equivalence. Future tests written before the infrastructure exists will need migration.

---

## Proposed Stages

**Stage 1** — Schema + generator for DTLS 1.3 families only (17 tests).
Write YAML cases and `generate.py`. Validate that generated output is equivalent
to the existing bash. Commit only the YAML and generator (not the generated bash).
Wire `generate.py` into the CI test invocation for the DTLS 1.3 suite.

**Stage 2** — wolfSSL runner profile. Run whatever subset of cases maps cleanly
(i.e. no `skip: true` parameters). This gives the interop baseline with no new
test authoring.

**Stage 3** — New phases (PSK, CID, KeyUpdate) are YAML-first from day one.
No migration of existing TLS or DTLS 1.2 tests.
