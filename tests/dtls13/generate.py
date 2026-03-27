#!/usr/bin/env python3
"""
Generate ssl-opt.sh test blocks from YAML case files + a runner profile.

Usage (from repo root or tests/dtls13/):
    python3 tests/dtls13/generate.py --runner runners/mbedtls.yaml --all
    python3 tests/dtls13/generate.py --runner runners/mbedtls.yaml cases/proxy-3d.yaml

Output goes to stdout. The DTLS 1.3 section of ssl-opt.sh is generated from
this output; do not edit the generated section by hand.

Requires: Python 3.6+, no external dependencies.

Validation:
  - Every parameter in a case must be mapped (or skip: true) in the runner.
    Unmapped parameters are a hard error — never silently dropped.
  - Every assertion must be mapped in the runner's assertion_map.
"""

import argparse
import re
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).parent
SCHEMA_PATH = SCRIPT_DIR / "schema.yaml"
CASES_DIR = SCRIPT_DIR / "cases"
RUNNERS_DIR = SCRIPT_DIR / "runners"


# ---------------------------------------------------------------------------
# Minimal iterative YAML parser.
#
# Supports the subset used in our case/runner files:
#   - Top-level dicts
#   - Nested dicts (indentation-based)
#   - Lists of scalars or dicts
#   - Inline lists: [500, 20000]
#   - Block scalars (> and |)
#   - Scalars: quoted strings, unquoted strings, int, float, bool, null
#
# Does NOT support: anchors, aliases, multi-document, complex keys.
#
# Implementation: two-pass iterative.
#   Pass 1: tokenise lines into structured token tuples.
#   Pass 2: build the Python data structure from tokens using an explicit stack.
# ---------------------------------------------------------------------------

def _parse_scalar(s):
    """Parse a scalar string to a Python value."""
    s = s.strip()
    if s in ("true", "True", "yes"):
        return True
    if s in ("false", "False", "no"):
        return False
    if s in ("null", "None", "~", ""):
        return None
    if (s.startswith('"') and s.endswith('"')) or \
       (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(x.strip()) for x in inner.split(",")]
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _tokenise(lines):
    """
    Convert raw YAML lines into a flat list of tokens.

    Token types:
      ('KEY',        indent, key, value)  -- dict key; value is scalar or PENDING
      ('DASH',       indent)              -- list item start (no inline content)
      ('DASH_KV',    indent, key, value)  -- list item that starts with "key: val"
      ('SCALAR',     indent, value)       -- scalar list item (after "- ")
      ('BS_LINE',    text)                -- block scalar content line
      ('BS_END',)                         -- block scalar ended (synthesised)
    """
    tokens = []
    PENDING = object()  # sentinel for "value comes from next indented block"

    in_bs = False     # inside a block scalar
    bs_mode = None    # '>' or '|'
    bs_indent = None  # indent of first content line
    bs_end_at = None  # indent where bs was defined (to detect end)

    for raw in lines:
        stripped = raw.rstrip()

        if in_bs:
            if not stripped.strip():
                tokens.append(('BS_LINE', ''))
                continue
            cur_indent = len(stripped) - len(stripped.lstrip())
            if bs_indent is None:
                bs_indent = cur_indent
            if cur_indent >= bs_indent:
                tokens.append(('BS_LINE', stripped[bs_indent:]))
                continue
            else:
                # End of block scalar
                tokens.append(('BS_END',))
                in_bs = False
                bs_mode = bs_indent = bs_end_at = None
                # Fall through to parse this line normally

        if not stripped or stripped.lstrip().startswith('#'):
            continue

        content = stripped.lstrip()
        indent = len(stripped) - len(content)

        # List item
        if content.startswith('- ') or content == '-':
            after = content[2:].strip() if len(content) > 1 else ''
            if not after:
                tokens.append(('DASH', indent))
                continue
            # Check for inline dict item: "- key: val"
            m = re.match(r'^([^:\s][^:]*):\s*(.*)', after)
            if m and not after.startswith('"') and not after.startswith("'"):
                key = m.group(1).strip()
                val_str = m.group(2).strip()
                if val_str in ('>', '|'):
                    tokens.append(('DASH_KV', indent, key, PENDING))
                    in_bs = True
                    bs_mode = val_str
                    bs_indent = None
                elif val_str == '':
                    tokens.append(('DASH_KV', indent, key, PENDING))
                else:
                    tokens.append(('DASH_KV', indent, key, _parse_scalar(val_str)))
                continue
            # Plain scalar after dash
            tokens.append(('SCALAR', indent, _parse_scalar(after)))
            continue

        # Dict key
        m = re.match(r'^([^:\s#][^:]*):\s*(.*)', content)
        if m:
            key = m.group(1).strip()
            val_str = m.group(2).strip()
            if val_str in ('>', '|'):
                tokens.append(('KEY', indent, key, PENDING))
                in_bs = True
                bs_mode = val_str
                bs_indent = None
            elif val_str == '':
                tokens.append(('KEY', indent, key, PENDING))
            else:
                tokens.append(('KEY', indent, key, _parse_scalar(val_str)))

    if in_bs:
        tokens.append(('BS_END',))

    return tokens, PENDING


def load_yaml(path):
    """
    Parse a YAML file using a two-pass iterative approach.
    Returns a dict representing the top-level YAML document.
    """
    with open(path) as f:
        raw_lines = f.readlines()
    lines = [l.rstrip('\n') for l in raw_lines]

    tokens, PENDING = _tokenise(lines)

    # Pass 2: build data structure.
    #
    # Stack frames:
    #   {
    #     'type':        'dict' | 'list',
    #     'container':   the dict or list,
    #     'own_indent':  the indent of the key/dash that introduced this frame;
    #                    child tokens must have indent > own_indent,
    #     'pending_key': for dict frames — key whose value is PENDING
    #                    (i.e., child tokens at deeper indent fill it),
    #   }
    #
    # Pop rule:
    #   - dict frame: pop when new token's indent <= own_indent
    #   - list frame: pop when new token's indent < own_indent
    #     (a list dash at own_indent is still part of this list)

    root = {}
    stack = [{'type': 'dict', 'container': root,
              'own_indent': -1, 'pending_key': None}]

    def pop_to(indent):
        while len(stack) > 1:
            top = stack[-1]
            if top['type'] == 'dict' and indent <= top['own_indent']:
                stack.pop()
            elif top['type'] == 'list' and indent < top['own_indent']:
                stack.pop()
            else:
                break

    def resolve_pending_as_dict(frame, own_indent):
        """
        The pending key in `frame` is about to receive dict content.
        Create a new dict, store it in frame['container'][pending_key],
        push a dict frame, and return it.
        """
        pk = frame['pending_key']
        frame['pending_key'] = None
        new_dict = {}
        frame['container'][pk] = new_dict
        new_frame = {'type': 'dict', 'container': new_dict,
                     'own_indent': own_indent, 'pending_key': None}
        stack.append(new_frame)
        return new_frame

    def resolve_pending_as_list(frame, own_indent):
        """
        The pending key in `frame` is about to receive list content.
        Create a new list, store it, push a list frame, return it.
        """
        pk = frame['pending_key']
        frame['pending_key'] = None
        new_list = []
        frame['container'][pk] = new_list
        new_frame = {'type': 'list', 'container': new_list,
                     'own_indent': own_indent, 'pending_key': None}
        stack.append(new_frame)
        return new_frame

    # Block scalar collector
    bs_collecting = False
    bs_target = None   # callable(value) to assign result
    bs_mode_cur = None
    bs_accum = []

    j = 0
    while j < len(tokens):
        tok = tokens[j]

        # Handle block scalar lines
        if bs_collecting:
            if tok[0] == 'BS_LINE':
                bs_accum.append(tok[1])
                j += 1
                continue
            elif tok[0] == 'BS_END':
                # Finalise
                if bs_mode_cur == '>':
                    val = ' '.join(l for l in bs_accum if l).strip()
                else:
                    val = '\n'.join(bs_accum).strip()
                bs_target(val)
                bs_collecting = False
                bs_target = bs_mode_cur = None
                bs_accum = []
                j += 1
                continue
            else:
                # No BS_END was emitted but we got a real token — shouldn't
                # happen since _tokenise always emits BS_END, but handle:
                if bs_mode_cur == '>':
                    val = ' '.join(l for l in bs_accum if l).strip()
                else:
                    val = '\n'.join(bs_accum).strip()
                bs_target(val)
                bs_collecting = False
                bs_target = bs_mode_cur = None
                bs_accum = []
                # Don't advance j — reprocess this token
                continue

        if tok[0] in ('BS_LINE', 'BS_END'):
            j += 1
            continue

        indent = tok[1]
        pop_to(indent)
        frame = stack[-1]

        # ---- KEY token: dict entry ----
        if tok[0] == 'KEY':
            _, ind, key, value = tok

            # If frame is a dict with a pending key, and this KEY is at a
            # deeper indent, it belongs to the sub-dict for that pending key.
            if frame['type'] == 'dict' and frame['pending_key'] is not None:
                if ind > frame['own_indent']:
                    # child of pending key — create sub-dict
                    frame = resolve_pending_as_dict(frame, ind - 1)
                    # Now process key in the new sub-dict frame... but
                    # resolve_pending_as_dict sets own_indent = ind-1,
                    # which is wrong for proper pop behaviour.
                    # We want: the new dict's own_indent = the indent of the
                    # key that introduced it (the pending key's indent).
                    # We don't have that easily, so use ind - 1 as an
                    # approximation that ensures pop_to works correctly
                    # for siblings.
                else:
                    # sibling — pending key had no child content, stays None
                    frame['pending_key'] = None

            if frame['type'] != 'dict':
                raise ValueError(f"KEY token in non-dict context: {tok}")

            if value is PENDING:
                frame['container'][key] = None
                frame['pending_key'] = key
            else:
                frame['container'][key] = value
                frame['pending_key'] = None

            j += 1
            continue

        # ---- DASH token: empty list item ----
        if tok[0] == 'DASH':
            _, ind = tok
            if frame['type'] == 'dict' and frame['pending_key'] is not None:
                frame = resolve_pending_as_list(frame, ind)
            elif frame['type'] == 'dict':
                raise ValueError(f"DASH in dict frame with no pending key: {tok}")

            # Start a new dict item
            new_dict = {}
            frame['container'].append(new_dict)
            new_frame = {'type': 'dict', 'container': new_dict,
                         'own_indent': ind, 'pending_key': None}
            stack.append(new_frame)
            j += 1
            continue

        # ---- DASH_KV token: list item with inline key:val ----
        if tok[0] == 'DASH_KV':
            _, ind, key, value = tok
            if frame['type'] == 'dict' and frame['pending_key'] is not None:
                frame = resolve_pending_as_list(frame, ind)
            elif frame['type'] == 'dict':
                raise ValueError(f"DASH_KV in dict frame with no pending key: {tok}")

            # New dict item
            new_dict = {}
            frame['container'].append(new_dict)
            new_frame = {'type': 'dict', 'container': new_dict,
                         'own_indent': ind, 'pending_key': None}
            stack.append(new_frame)

            if value is PENDING:
                new_dict[key] = None
                new_frame['pending_key'] = key
                # block scalar case — wait for BS_LINE/BS_END
                # (already handled by bs_collecting logic above)
                # Actually value=PENDING for both block scalar and empty val.
                # For block scalar, the next token will be BS_LINE; for empty
                # val (DASH_KV with "- key:"), next token will be a KEY or DASH
                # at deeper indent.  Both work with pending_key.
            else:
                new_dict[key] = value
            j += 1
            continue

        # ---- SCALAR token: scalar list item ----
        if tok[0] == 'SCALAR':
            _, ind, value = tok
            if frame['type'] == 'dict' and frame['pending_key'] is not None:
                frame = resolve_pending_as_list(frame, ind)
            elif frame['type'] == 'dict':
                raise ValueError(f"SCALAR in dict frame with no pending key: {tok}")

            frame['container'].append(value)
            j += 1
            continue

        j += 1

    # Flush any trailing block scalar
    if bs_collecting and bs_accum:
        if bs_mode_cur == '>':
            val = ' '.join(l for l in bs_accum if l).strip()
        else:
            val = '\n'.join(bs_accum).strip()
        bs_target(val)

    return root


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

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
            raise ValueError(f"Unknown guard type: {g}")
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


def render_case(family, case, runner):
    lines = []
    name = case["name"]
    full_name = f"{family}: {name}"

    # Guards
    all_guards = list(case.get("_file_requires") or [])
    all_guards += list(case.get("requires") or [])
    # Deduplicate
    seen, deduped = set(), []
    for g in all_guards:
        key = str(sorted(g.items()))
        if key not in seen:
            seen.add(key)
            deduped.append(g)

    client_time_factor = case.get("client_time_factor")
    if client_time_factor:
        lines.append(f"client_needs_more_time {client_time_factor}")

    for gl in render_requires(deduped, runner):
        lines.append(gl)

    proxy_block = dict(case.get("proxy") or {})
    server_block = dict(case.get("server") or {})
    client_block = dict(case.get("client") or {})
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

    srv_params = render_params(server_block, param_map, "server")
    srv_full = (srv_base + " " + " ".join(srv_params)).strip() if srv_params else srv_base

    # Client command
    cli_base = runner["client_cmd"]
    if "force_version" in client_block and runner.get("force_version_override"):
        fv = client_block.pop("force_version")
        cli_base = re.sub(r"force_version=\S+", f"force_version={fv}", cli_base)
    if "min_version" in client_block or "max_version" in client_block:
        cli_base = re.sub(r"\s*force_version=\S+", "", runner["client_cmd"]).strip()

    cli_params = render_params(client_block, param_map, "client")
    cli_full = (cli_base + " " + " ".join(cli_params)).strip() if cli_params else cli_base

    # Proxy
    pxy_params = render_params(proxy_block, proxy_param_map, "proxy")

    # Assertions
    expect = case.get("expect") or {}
    exit_code = expect.get("exit", 0)
    assertions = render_assertions(expect.get("assert") or [], assertion_map)

    # Emit run_test
    lines.append(f'run_test    "{full_name}" \\')
    if pxy_params:
        pxy_full = runner["proxy_cmd"] + " " + " ".join(pxy_params)
        lines.append(f'            -p "{pxy_full}" \\')
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


def generate(case_files, runner_path):
    runner = load_yaml(runner_path)

    output = [
        "# AUTO-GENERATED — do not edit.",
        f"# Runner: {runner_path}",
        "# Regenerate: python3 tests/dtls13/generate.py --runner "
        "runners/mbedtls.yaml --all",
        "",
    ]

    for case_file in case_files:
        doc = load_yaml(case_file)
        family = doc["family"]
        file_requires = doc.get("requires") or []

        output.append(f"# {'=' * 70}")
        output.append(f"# Cases from: {case_file.name}")
        output.append(f"# {'=' * 70}")
        output.append("")

        for case in (doc.get("cases") or []):
            case["_file_requires"] = file_requires
            try:
                lines = render_case(family, case, runner)
                output.extend(lines)
            except ValueError as e:
                print(f"ERROR in {case_file.name} case '{case.get('name')}': {e}",
                      file=sys.stderr)
                sys.exit(1)

    return "\n".join(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", required=True, help="Runner profile YAML file")
    parser.add_argument("--all", action="store_true",
                        help="Process all cases/*.yaml files")
    parser.add_argument("cases", nargs="*", help="Case YAML files")
    args = parser.parse_args()

    runner_path = Path(args.runner)
    if not runner_path.is_absolute():
        runner_path = SCRIPT_DIR / runner_path

    if args.all:
        case_files = sorted(CASES_DIR.glob("*.yaml"))
    else:
        case_files = [Path(f) for f in args.cases]

    if not case_files:
        print("ERROR: no case files. Use --all or list files.", file=sys.stderr)
        sys.exit(1)

    print(generate(case_files, runner_path))


if __name__ == "__main__":
    main()
