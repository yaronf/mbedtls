#!/usr/bin/env python3
"""
Generate DTLS 1.3 test infrastructure from YAML case files + a runner profile.

Usage (from repo root or tests/dtls13/):
    # Print test blocks to stdout:
    python3 tests/dtls13/generate.py --runner runners/mbedtls.yaml --all

    # Write tests/dtls13/dtls13-tests.sh (standalone script):
    python3 tests/dtls13/generate.py --runner runners/mbedtls.yaml --emit

    # Process specific case files:
    python3 tests/dtls13/generate.py --runner runners/mbedtls.yaml cases/proxy-3d.yaml

Requires: Python 3.6+, pyyaml.

Validation:
  - Every parameter in a case must be mapped (or skip: true) in the runner.
    Unmapped parameters are a hard error — never silently dropped.
  - Every assertion must be mapped in the runner's assertion_map.
"""

import argparse
import re
import sys
from pathlib import Path

import yaml


SCRIPT_DIR = Path(__file__).parent
SCHEMA_PATH = SCRIPT_DIR / "schema.yaml"
CASES_DIR = SCRIPT_DIR / "cases"
RUNNERS_DIR = SCRIPT_DIR / "runners"


def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def render_requires(guards, runner):
    lines = []
    rmap = runner.get("requires_map", {})
    for g in guards:
        if not isinstance(g, dict):
            raise ValueError(f"Guard must be a dict, got: {g!r}")
        if "protocol" in g:
            proto = g["protocol"]
            proto_map = rmap.get("protocol", {})
            if not isinstance(proto_map, dict) or proto not in proto_map:
                raise ValueError(f"Unknown protocol guard: {proto}")
            lines.append(proto_map[proto])
        elif "config" in g:
            tmpl = rmap.get("config", "requires_config_enabled {value}")
            lines.append(tmpl.format(value=g["config"]))
        elif "max_content_len" in g:
            tmpl = rmap.get("max_content_len", "requires_max_content_len {value}")
            lines.append(tmpl.format(value=g["max_content_len"]))
        elif "not_valgrind" in g:
            lines.append(rmap.get("not_valgrind", "not_with_valgrind"))
        else:
            # Generic lookup: the first key in the guard dict is looked up in
            # requires_map.  If the value is a plain string it is emitted as-is;
            # if it is a dict, the guard value selects the sub-key.
            key = next(iter(g))
            if key not in rmap:
                raise ValueError(f"Unknown guard type: {g}")
            entry = rmap[key]
            if isinstance(entry, dict):
                val = g[key]
                if val not in entry:
                    raise ValueError(f"Unknown value '{val}' for guard '{key}'")
                lines.append(entry[val])
            else:
                lines.append(entry)
    return lines


def render_params(params, param_map, side):
    parts = []
    if not params:
        return parts
    for key, value in params.items():
        if key.startswith("_"):
            continue  # internal keys
        if key not in param_map:
            raise ValueError(
                f"Parameter '{key}' on {side} is not mapped in runner profile. "
                "Add a mapping or mark skip: true."
            )
        mapping = param_map[key]
        if isinstance(mapping, dict) and mapping.get("skip"):
            continue
        # Evaluate template
        result = eval(f'f"{mapping}"', {"value": value})
        if result:
            parts.append(result)
    return parts


def render_assertions(assertions, assertion_map):
    parts = []
    for name in assertions:
        if name not in assertion_map:
            raise ValueError(f"Assertion '{name}' not in runner assertion_map")
        entry = assertion_map[name]
        flag = entry["flag"]
        string = entry["string"]
        parts.append(f'{flag} "{string}"')
    return parts


def render_case(family, case, runner, runner_stem=""):
    lines = []
    name = case["name"]
    full_name = f"{family}: {name}"

    # Guards: runner_requires are prepended to every case in this runner.
    all_guards = list(runner.get("runner_requires") or [])
    all_guards += list(case.get("_file_requires") or [])
    all_guards += list(case.get("requires") or [])

    client_time_factor = case.get("client_time_factor")
    if client_time_factor:
        lines.append(f"client_needs_more_time {client_time_factor}")

    # Render and deduplicate guard lines (multiple guards can emit the same string).
    seen_guards = set()
    for gl in render_requires(all_guards, runner):
        if gl not in seen_guards:
            seen_guards.add(gl)
            lines.append(gl)

    # no_proxy: true suppresses ssl-opt.sh's automatic DTLS proxy insertion.
    # Can be set per-case or as a runner-level default (default_no_proxy: true).
    no_proxy = case.get("no_proxy", runner.get("default_no_proxy", False))

    raw_proxy = case.get("proxy")
    # proxy: false is equivalent to no_proxy: true
    if raw_proxy is False:
        no_proxy = True
        raw_proxy = None
    proxy_block = dict(raw_proxy or {})
    server_block = dict(case.get("server") or {})
    client_block = dict(case.get("client") or {})

    # runner_overrides: per-runner substitutions for server/client/proxy blocks.
    # Keys in the override dict are merged (shallow) over the base block.
    overrides = (case.get("runner_overrides") or {}).get(runner_stem, {})
    if overrides:
        server_block.update(overrides.get("server") or {})
        client_block.update(overrides.get("client") or {})
        proxy_block.update(overrides.get("proxy") or {})
    param_map = runner.get("param_map") or {}
    proxy_param_map = runner.get("proxy_param_map") or {}
    assertion_map = runner.get("assertion_map") or {}

    # Server command: handle force_version override
    srv_base = runner["server_cmd"]
    if "force_version" in server_block and runner.get("force_version_override"):
        fv = server_block.pop("force_version")
        srv_base = re.sub(r"force_version=\S+", f"force_version={fv}", srv_base)
    # Handle min/max_version (removes force_version from base)
    if "min_version" in server_block or "max_version" in server_block:
        srv_base = re.sub(r"\s*force_version=\S+", "", runner["server_cmd"]).strip()

    # Use client_param_map if provided, falling back to param_map.
    client_param_map = runner.get("client_param_map") or param_map

    srv_params = render_params(server_block, param_map, "server")
    srv_full = (srv_base + " " + " ".join(srv_params)).strip() if srv_params else srv_base

    # Client command
    cli_base = runner["client_cmd"]
    if "force_version" in client_block and runner.get("force_version_override"):
        fv = client_block.pop("force_version")
        cli_base = re.sub(r"force_version=\S+", f"force_version={fv}", cli_base)
    if "min_version" in client_block or "max_version" in client_block:
        cli_base = re.sub(r"\s*force_version=\S+", "", runner["client_cmd"]).strip()

    cli_params = render_params(client_block, client_param_map, "client")
    cli_full = (cli_base + " " + " ".join(cli_params)).strip() if cli_params else cli_base

    # Proxy
    pxy_params = render_params(proxy_block, proxy_param_map, "proxy")

    # Assertions
    expect = case.get("expect") or {}
    exit_code = expect.get("exit", 0)
    assertions = render_assertions(expect.get("assert") or [], assertion_map)

    # Emit run_test (optionally preceded by set_cli_delay_factor for slow tests)
    slow_factor = case.get("slow")
    if slow_factor:
        lines.append(f'client_needs_more_time {slow_factor}')
    lines.append(f'run_test    "{full_name}" \\')
    if pxy_params:
        pxy_full = runner["proxy_cmd"] + " " + " ".join(pxy_params)
        lines.append(f'            -p "{pxy_full}" \\')
    elif no_proxy:
        lines.append(f'            -p "" \\')
    lines.append(f'            "{srv_full}" \\')
    lines.append(f'            "{cli_full}" \\')
    if assertions:
        lines.append(f'            {exit_code} \\')
        for i, a in enumerate(assertions):
            suffix = " \\" if i < len(assertions) - 1 else ""
            lines.append(f'            {a}{suffix}')
    else:
        lines.append(f'            {exit_code}')
    lines.append("")
    return lines


def emit_header(runner_name, emit_path_name):
    return f"""\
#!/bin/sh
# AUTO-GENERATED — do not edit.
# Regenerate: python3 tests/dtls13/generate.py --runner runners/{runner_name} --emit
#
# Standalone DTLS 1.3 integration test script.
# Designed to run from the same directory as ssl-opt.sh (typically
# build-dbg/tests/ or any cmake build's tests/ directory).
#
# Sources ssl-opt.sh for infrastructure (run_test, requires_*, etc.) without
# executing its main body, then runs all DTLS 1.3 tests and exits with $FAILS.
#
# Usage (from build tests directory):
#   ./{emit_path_name} [-f FILTER] [-e EXCLUDE] [other ssl-opt.sh flags]

set -u

ORIGINAL_PWD=$PWD
if ! cd "$(dirname "$0")"; then
    exit 125
fi

# When the dtls13/ directory is a symlink into a build tree (e.g.
# build-dbg/tests/dtls13 -> <repo>/tests/dtls13), the shell resolves ".."
# against the *real* path, so ssl-opt.sh's defaults for DATA_FILES_PATH and
# P_SRV/P_CLI/P_PXY/P_QUERY all point into the source tree rather than the
# build tree.  Detect this once and patch up any unset variables.
# Use the logical (symlink-preserving) path so that ".." stays in the build
# tree rather than escaping through the symlink into the source tree.
_script_logical=$(cd "$(dirname "$0")" && pwd)    # logical path of dtls13/
_build_tests=$(dirname "$_script_logical")         # …/tests
_build_root=$(dirname "$_build_tests")             # …  (the cmake build root)
_build_programs="$_build_root/programs"

if [ -z "${{DATA_FILES_PATH:-}}" ] && [ -d "$_build_root/framework/data_files" ]; then
    DATA_FILES_PATH="$_build_root/framework/data_files"
    export DATA_FILES_PATH
fi
if [ -z "${{P_SRV:-}}" ] && [ -f "$_build_programs/ssl/ssl_server2" ]; then
    P_SRV="$_build_programs/ssl/ssl_server2"
    export P_SRV
fi
if [ -z "${{P_CLI:-}}" ] && [ -f "$_build_programs/ssl/ssl_client2" ]; then
    P_CLI="$_build_programs/ssl/ssl_client2"
    export P_CLI
fi
if [ -z "${{P_PXY:-}}" ] && [ -f "$_build_programs/test/udp_proxy" ]; then
    P_PXY="$_build_programs/test/udp_proxy"
    export P_PXY
fi
if [ -z "${{P_QUERY:-}}" ] && [ -f "$_build_programs/test/query_compile_time_config" ]; then
    P_QUERY="$_build_programs/test/query_compile_time_config"
    export P_QUERY
fi
unset _script_logical _build_tests _build_root _build_programs

SSL_OPT_SOURCE_ONLY=1
export SSL_OPT_SOURCE_ONLY

# shellcheck source=ssl-opt.sh
. ./ssl-opt.sh "$@"

# ssl-opt.sh sets DOG_DELAY inside its main() body which we skip.
# Set it here so that client_needs_more_time() works correctly.
: "${{DOG_DELAY:=20}}"
CLI_DELAY_FACTOR=1
SRV_DELAY_SECONDS=0
"""

EMIT_FOOTER = """\

# DTLS 1.3 stateless-cookie cluster test (T6 of Phase 2 — see
# local-docs/cookie-impl-plan.md §2.5.6).  This is a multi-process
# scenario (two ssl_server2 instances + udp_proxy with mid-stream
# redirect) that doesn't fit the single-server `run_test` shape, so
# it lives in a standalone script and is invoked here as a synthetic
# test entry that integrates with ssl-opt.sh's TESTS/PASSES/FAILS
# counters.  print_name handles TESTS++; we just emit PASS/FAIL.
if [ -x "$(dirname "$0")/cluster-test.sh" ]; then
    print_name "DTLS 1.3: stateless cluster (CH1 → server A, CH2 → server B)"
    cluster_log="$(mktemp -t cluster-test.XXXXXX)"
    if "$(dirname "$0")/cluster-test.sh" >"$cluster_log" 2>&1; then
        record_outcome "PASS"
        rm -f "$cluster_log"
    else
        record_outcome "FAIL" "cluster test failed"
        echo "  ! cluster test failed; output:"
        cat "$cluster_log" | sed 's/^/  ! /'
        rm -f "$cluster_log"
        FAILS=$(( FAILS + 1 ))
    fi
fi

if [ $FAILS -gt 255 ]; then
    FAILS=255
fi
exit $FAILS
"""


def generate(case_files, runner_path, emit=False, emit_path=None):
    runner = load_yaml(runner_path)

    runner_name = Path(runner_path).name
    if emit:
        ep_name = Path(emit_path).name if emit_path else DEFAULT_EMIT_PATH.name
        header_lines = emit_header(runner_name, ep_name).splitlines()
    else:
        header_lines = [
            "# AUTO-GENERATED — do not edit.",
            f"# Runner: {runner_path}",
            f"# Regenerate: python3 tests/dtls13/generate.py --runner {runner_name} --all",
        ]
    output = header_lines + [""]

    for case_file in case_files:
        doc = load_yaml(case_file)
        family = doc["family"]
        file_requires = doc.get("requires") or []

        output.append(f"# {'=' * 70}")
        output.append(f"# Cases from: {case_file.name}")
        output.append(f"# {'=' * 70}")
        output.append("")

        runner_stem = Path(runner_path).stem  # e.g. "mbedtls", "wolfssl", "wolfssl-srv"
        for case in (doc.get("cases") or []):
            skip_runners = case.get("skip_runners") or []
            if runner_stem in skip_runners:
                continue
            case["_file_requires"] = file_requires
            try:
                lines = render_case(family, case, runner, runner_stem)
                output.extend(lines)
            except ValueError as e:
                print(f"ERROR in {case_file.name} case '{case.get('name')}': {e}",
                      file=sys.stderr)
                sys.exit(1)

    result = "\n".join(output)
    if emit:
        result += EMIT_FOOTER
    return result


DEFAULT_EMIT_PATH = SCRIPT_DIR / "dtls13-tests.sh"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", required=True, help="Runner profile YAML file")
    parser.add_argument("--all", action="store_true",
                        help="Process all cases matching the runner's case_glob")
    parser.add_argument("--emit", action="store_true",
                        help="Write standalone shell script instead of stdout")
    parser.add_argument("cases", nargs="*", help="Case YAML files")
    args = parser.parse_args()

    runner_path = Path(args.runner)
    if not runner_path.is_absolute():
        runner_path = SCRIPT_DIR / runner_path

    runner = load_yaml(runner_path)

    # Determine emit path: runner can specify its own via emit_path key.
    emit_path_str = runner.get("emit_path")
    emit_path = (SCRIPT_DIR / emit_path_str) if emit_path_str else DEFAULT_EMIT_PATH

    # Determine which case files to use.
    if args.emit or args.all:
        # Runners can restrict which cases they handle via case_glob.
        # Accepts a single glob string or a list of glob strings.
        case_glob = runner.get("case_glob", "*.yaml")
        if isinstance(case_glob, list):
            seen_paths = set()
            case_files = []
            for g in case_glob:
                for p in sorted(CASES_DIR.glob(g)):
                    if p not in seen_paths:
                        seen_paths.add(p)
                        case_files.append(p)
            case_files.sort()
        else:
            case_files = sorted(CASES_DIR.glob(case_glob))
    else:
        case_files = [Path(f) for f in args.cases]

    if not case_files:
        print("ERROR: no case files. Use --all, --emit, or list files.", file=sys.stderr)
        sys.exit(1)

    result = generate(case_files, runner_path, emit=args.emit, emit_path=emit_path)

    if args.emit:
        emit_path.write_text(result)
        emit_path.chmod(0o755)
        print(f"Written: {emit_path}", file=sys.stderr)
    else:
        print(result)


if __name__ == "__main__":
    main()
