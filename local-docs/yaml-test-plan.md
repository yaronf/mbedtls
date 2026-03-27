# Plan: Declarative DTLS Test Suite (YAML + Generated Runner)

**Status:** Proposal — awaiting review and comments before implementation.

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
    mbedtls.yaml               # mbedtls ssl_client2 / ssl_server2 profile
    wolfssl.yaml               # wolfSSL client/server profile
  schema.yaml                  # field definitions and validation rules
  generate.py                  # YAML + runner profile → shell test block
```

---

## YAML Case Format

One file per test family (tests that share structure, differ in parameters).

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
      dgram_packing: 0
      hs_timeout: "500-20000"
    client:
      dgram_packing: 0
      hs_timeout: "500-20000"
    expect:
      exit: 0
      server_contains:
        - "Protocol is DTLSv1.3"
      client_contains:
        - "Protocol is DTLSv1.3"

  - name: "client auth"
    client_time_factor: 4
    proxy:
      drop: 5
      delay: 5
      duplicate: 5
    server:
      dgram_packing: 0
      hs_timeout: "500-20000"
      auth_mode: required
    client:
      dgram_packing: 0
      hs_timeout: "500-20000"
    expect:
      exit: 0
      server_contains:
        - "Protocol is DTLSv1.3"
      client_contains:
        - "Protocol is DTLSv1.3"

  - name: "nbio"
    client_time_factor: 4
    proxy:
      drop: 5
      delay: 5
      duplicate: 5
    server:
      dgram_packing: 0
      hs_timeout: "500-20000"
      nbio: 2
      debug_level: 1
    client:
      dgram_packing: 0
      hs_timeout: "500-20000"
      nbio: 2
      debug_level: 1
    expect:
      exit: 0
      server_contains:
        - "Protocol is DTLSv1.3"
      client_contains:
        - "Protocol is DTLSv1.3"
```

---

## Runner Profile Format

Maps abstract YAML fields to concrete binary invocations and flag syntax.
Unmapped parameters are silently dropped (or flagged if marked `required:`).

```yaml
# runners/mbedtls.yaml
server_cmd: "$P_SRV dtls=1 force_version=dtls13"
client_cmd: "$P_CLI dtls=1 force_version=dtls13"
proxy_cmd:  "$P_PXY"

param_map:
  dgram_packing: "dgram_packing={value}"
  hs_timeout:    "hs_timeout={value}"
  nbio:          "nbio={value}"
  auth_mode:     "auth_mode={value}"
  mtu:           "mtu={value}"
  debug_level:   "debug_level={value}"

proxy_param_map:
  drop:      "drop={value}"
  delay:     "delay={value}"
  duplicate: "duplicate={value}"
  mtu:       "mtu={value}"
  bad_ad:    "bad_ad={value}"

assertion_map:
  server_contains:     "-s"
  client_contains:     "-c"
  server_not_contains: "-S"
  client_not_contains: "-C"
```

```yaml
# runners/wolfssl.yaml
server_cmd: "$WOLFSSL_SERVER -v 4 -u"
client_cmd: "$WOLFSSL_CLIENT -v 4 -u"
proxy_cmd:  "$P_PXY"

param_map:
  hs_timeout:  "--dtls-timeout={value}"
  auth_mode:   "{value == 'required' ? '-d' : ''}"
  mtu:         "--mtu={value}"
  debug_level: "-d"
  # dgram_packing: not mapped — silently dropped
  # nbio: not mapped — silently dropped

proxy_param_map:
  drop:      "drop={value}"
  delay:     "delay={value}"
  duplicate: "duplicate={value}"
  mtu:       "mtu={value}"

assertion_map:
  server_contains:     "-s"
  client_contains:     "-c"
  server_not_contains: "-S"
  client_not_contains: "-C"
```

---

## Generator Output (mbedtls runner, proxy-3d.yaml)

`generate.py --cases cases/proxy-3d.yaml --runner runners/mbedtls.yaml` emits:

```bash
# AUTO-GENERATED from cases/proxy-3d.yaml + runners/mbedtls.yaml
# Edit the source files, not this output.

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

---

## Pros

**Single source of truth.**
Adding a case or changing a guard is one YAML edit. No bash context to understand.

**Structured parameters, not free-form strings.**
Typos in flag names are caught by schema validation before the test runs silently wrong.

**Interop tests are free.**
Interop tests are not a separate suite — they are the same YAML cases run through
the wolfSSL runner profile. Coverage gap is explicit: any unmapped YAML parameter
shows exactly what behaviors can't yet be tested against wolfSSL.

**Assertion patterns are per-runner.**
wolfSSL may print "DTLSv1.3 established" instead of "Protocol is DTLSv1.3".
Declare both in the runner profile, not in every test case.

**Generated bash is auditable.**
Checking in the generated file means CI has no Python dependency at test-run time,
and the output is inspectable/diffable.

---

## Cons

**Indirection cost.**
A developer debugging a failing test must trace YAML case → runner profile →
generated bash, not just read one file. Three files where there used to be one call.

**Drift risk (if generated file is checked in).**
Generated file can go out of sync with YAML. Requires a CI check:
`generate.py && git diff --exit-code generated/`.

**Expressiveness ceiling.**
Some current tests have logic that doesn't fit a flat data model:
- `not_with_valgrind` (conditional skip based on runtime environment)
- `requires_max_content_len 2048` (depends on compile-time buffer size)
- Per-test cert file paths (server7_int-ca.crt, server8_int-ca2.crt)
- Negative/uniqueness assertions (`-S`, `-C`, `-u`, `-U`)
- Shell function assertions (`-f`, `-F`)

These either become first-class YAML fields (schema grows over time) or escape
hatches (inline shell in YAML). Both are compromises.

**wolfSSL param mapping is not clean 1:1.**
`dgram_packing` and `nbio=2` have no wolfSSL equivalent — those test dimensions
simply don't exist for that runner. Some behavioral differences may require a
structurally different test, not just a different flag.

**Migration cost.**
All 17 existing DTLS 1.3 tests must be rewritten into YAML and validated for
equivalence against the existing bash output. Future tests written before the
infrastructure exists will either wait for it or need later migration.

---

## Open Questions

1. **Generated file: checked in or runtime-generated?**
   - Checked in: no Python dependency in CI, auditable diff, risk of drift.
   - Runtime: always in sync, adds Python to CI, no drift.
   - mbedtls CI already runs Python for config scripts → runtime generation is
     probably fine, but worth confirming.

2. **Scope: DTLS 1.3 only, or all DTLS tests?**
   - DTLS 1.3 only has clear ROI (interop angle, bounded scope, known structure).
   - Migrating all DTLS tests is large churn with unclear benefit — most DTLS 1.2
     tests have no wolfSSL interop angle.

3. **Where does the runner live in the repo?**
   - Inside `tests/dtls13/` (self-contained): clean but diverges from mbedtls
     conventions.
   - Alongside existing `ssl-opt.sh` infrastructure: reuses `run_test` and friends,
     but couples the YAML system to the bash test harness.

4. **wolfSSL log assertion strings.**
   What does wolfSSL actually print on successful DTLS 1.3 handshake?
   This determines whether `-s`/`-c` assertions can be meaningfully shared or
   must always be runner-specific.

---

## Proposed Stages

**Stage 1** — Schema + generator for DTLS 1.3 families only (17 tests).
Validate that generated output is equivalent to existing bash. Check both in.

**Stage 2** — wolfSSL runner profile. Run whatever subset of cases maps cleanly.
This gives the interop baseline with no new test authoring.

**Stage 3** — New phases (PSK, CID, KeyUpdate) are YAML-first from day one.
No migration of existing TLS or DTLS 1.2 tests.
