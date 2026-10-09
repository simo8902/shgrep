"""Wall-clock benchmark: shgrep CLI against rg and ug (and optionally tgrep --no-index) on one root.

Usage: python tests/bench.py ROOT [--shgrep dist/shgrep.exe] [--rg rg] [--ug ug] [--tgrep PATH] [--runs 5]

Each workload runs once to warm the file cache, then --runs times; the median wall time is reported.
CONTRACT: flags are chosen so every tool selects the same files: recursive, hidden files skipped, binary
files skipped, .gitignore and .ignore honored, symlinks not followed.
"""
import argparse
import itertools
import json
import os
import re
import statistics
import subprocess
import tempfile
import time
import uuid

WORDS = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet"]


def literals(count):
    return [f"zqlit{i:04d}_{WORDS[i % len(WORDS)]}" for i in range(count)]


def regexes(count):
    return [f"zq{i:04d}[a-z]+_[0-9]{{2,}}x" for i in range(count)]


# name, patterns, literal, files-with-matches output
WORKLOADS = [
    ("1 literal, no match", ["zzqqxx_nomatch"], True, False),
    ("1 regex, no match", [r"zzq[0-9]+_(alpha|beta)[a-z]*baz\s*\("], False, False),
    ("100 literals, no match", literals(100), True, False),
    ("1000 literals, no match", literals(1000), True, False),
    ("100 regexes, no match", regexes(100), False, False),
    ("common literal -l", ["return"], True, True),
    ("common regex -l", [r"[A-Z][a-z]+[A-Z][A-Za-z]*\("], False, True),
]


def shgrep_cmd(exe, root, patterns, literal, files, pattern_file):
    cmd = [exe, "search", "--root", root, "--max-results", "10000", "--max-matches-per-file", "10000",
           "--max-output-bytes", "1048576", "--timeout-ms", "300000"]
    if literal:
        cmd.append("-F")
    if files:
        cmd.append("-l")
    for p in patterns:
        cmd += ["-e", p]
    return cmd


def ug_cmd(exe, root, patterns, literal, files, pattern_file):
    cmd = [exe, "-r", "-I", "-s", "--ignore-files", "--ignore-files=.ignore"]
    if literal:
        cmd.append("-F")
    if files:
        cmd.append("-l")
    return cmd + ["-f", pattern_file, root]


def rg_cmd(exe, root, patterns, literal, files, pattern_file):
    # --no-require-git: shgrep honors .gitignore without a Git repository, rg only inside one by default.
    cmd = [exe, "--no-require-git", "--no-messages", "--no-config"]
    if literal:
        cmd.append("-F")
    if files:
        cmd.append("-l")
    return cmd + ["-f", pattern_file, root]


def tgrep_cmd(exe, root, patterns, literal, files, pattern_file):
    cmd = [exe, "--no-index", "--no-messages"]
    if literal:
        cmd.append("-F")
    if files:
        cmd.append("-l")
    return cmd + ["-f", pattern_file, root]


def shgrep_index_cmd(exe, root, patterns, literal, files, pattern_file):
    return shgrep_cmd(exe, root, patterns, literal, files, pattern_file) + ["--index"]


def tgrep_index_cmd(exe, root, patterns, literal, files, pattern_file):
    # No --no-index: tgrep uses its local index (or a server for this root, if one runs).
    cmd = [exe, "--no-messages"]
    if literal:
        cmd.append("-F")
    if files:
        cmd.append("-l")
    return cmd + ["-f", pattern_file, root]


def timed(cmd, env=None):
    start = time.perf_counter()
    done = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    return time.perf_counter() - start, done


def variant_env(spec):
    """'base' or 'NAME=VALUE[,NAME=VALUE]'; SHGREP_* variables from the caller's shell never leak in."""
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("SHGREP_")}
    if spec != "base":
        for pair in spec.split(","):
            name, _, value = pair.partition("=")
            env[name.strip()] = value.strip()
    return env


def ab(args):
    """Interleaved A/B: every round runs each variant once, rotating the order so no variant always goes first.
    Paired per-round differences cancel drift (cache, clocks, background load) that separate batches pick up."""
    cmd = shgrep_cmd(args.shgrep, args.root, [args.pattern], True, args.files, None)
    variants = [(spec, variant_env(spec)) for spec in args.ab]
    outputs = {}
    for spec, env in variants:
        # The no-match summary reports elapsed ms; everything else must be byte-identical across variants.
        outputs[spec] = re.sub(rb" in \d+ ms", b"", timed(cmd, env)[1].stdout)
    if len(set(outputs.values())) > 1:
        print("WARNING: variants produced different output")
    samples = {spec: [] for spec, _ in variants}
    for index in range(args.runs):
        start = index % len(variants)
        for spec, env in variants[start:] + variants[:start]:
            samples[spec].append(timed(cmd, env)[0] * 1000)
    base = args.ab[0]
    print(f"root: {args.root}  pattern: {args.pattern}  rounds: {args.runs}, interleaved (ms)")
    for spec, _ in variants:
        q1, _, q3 = statistics.quantiles(samples[spec], n=4)
        line = f"{spec:<30} median {statistics.median(samples[spec]):6.1f}  p25 {q1:6.1f}  p75 {q3:6.1f}"
        if spec != base:
            diffs = [b - a for a, b in zip(samples[base], samples[spec])]
            faster = sum(d < 0 for d in diffs)
            line += f"   vs {base}: median diff {statistics.median(diffs):+5.1f}, faster in {faster}/{len(diffs)} rounds"
        print(line)


def live(args):
    """MCP server with --live-index: times searches over stdio, then checks that a new file is found by the very next
    search and that a deleted one is gone. Writes and removes one temporary file in ROOT."""
    server = subprocess.Popen([args.shgrep, "--root", args.root, "--live-index"], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    ids = itertools.count(1)

    def send(message):
        server.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
        server.stdin.flush()

    def call(method, params):
        request_id = next(ids)
        send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            line = server.stdout.readline()
            if not line:
                raise RuntimeError("the server exited")
            message = json.loads(line)
            if message.get("id") == request_id:
                return message

    def search(pattern, **extra):
        arguments = {"pattern": pattern, "mode": "literal", "output": "files", "max_results": 10000,
                     "max_output_bytes": 1048576, **extra}
        message = call("tools/call", {"name": "search", "arguments": arguments})
        return "".join(part.get("text", "") for part in message["result"]["content"])

    try:
        call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                            "clientInfo": {"name": "bench", "version": "1"}})
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        started = time.perf_counter()
        while "[index: live" not in search("zzqqxx_nomatch"):
            if time.perf_counter() - started > args.live_wait:
                raise RuntimeError("the live index was not ready in time")
            time.sleep(0.5)
        print(f"live index ready after {time.perf_counter() - started:.1f} s")
        for pattern in ("zzqqxx_nomatch", args.pattern, "return"):
            for indexed in (False, True):
                samples = []
                for _ in range(args.runs):
                    begin = time.perf_counter()
                    search(pattern, index=indexed)
                    samples.append((time.perf_counter() - begin) * 1000)
                print(f"{pattern:<16} index={str(indexed):<5} median {statistics.median(samples):6.1f} ms (MCP round trip)")
        token = "shgrepfresh" + uuid.uuid4().hex
        name = f"shgrep-live-test-{token}.txt"
        path = os.path.join(args.root, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(f"freshness probe {token}\n")
        try:
            found = name in search(token)
        finally:
            os.remove(path)
        gone = name not in search(token)
        print(f"new file found by the next search: {'yes' if found else 'NO'}")
        print(f"deleted file gone from the next search: {'yes' if gone else 'NO'}")
    finally:
        server.kill()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root")
    parser.add_argument("--shgrep", default=os.path.join("dist", "shgrep.exe"))
    parser.add_argument("--rg", default="rg")
    parser.add_argument("--ug", default="ug")
    parser.add_argument("--tgrep")
    parser.add_argument("--index", action="store_true", help="add a shgrep --index column (builds the index first)")
    parser.add_argument("--tgrep-index", action="store_true", help="add an indexed tgrep column (runs tgrep index first)")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--ab", nargs="+", metavar="VARIANT",
                        help="interleaved shgrep-only A/B: 'base' or NAME=VALUE[,NAME=VALUE] per variant; the "
                             "first is the baseline")
    parser.add_argument("--pattern", default="zzqqxx_nomatch", help="literal searched in --ab mode")
    parser.add_argument("--files", action="store_true", help="-l output in --ab mode")
    parser.add_argument("--live", action="store_true",
                        help="time an MCP server with --live-index and check freshness (writes one temp file in ROOT)")
    parser.add_argument("--live-wait", type=float, default=600, help="seconds to wait for the live index to be ready")
    args = parser.parse_args()
    if args.live:
        live(args)
        return
    if args.ab:
        ab(args)
        return
    tools = [("shgrep", args.shgrep, shgrep_cmd), ("rg", args.rg, rg_cmd), ("ug", args.ug, ug_cmd)]
    if args.tgrep:
        tools.append(("tgrep", args.tgrep, tgrep_cmd))
    # Indexed columns are snapshots; each index is built once here, before any timing.
    if args.index:
        subprocess.run([args.shgrep, "index", "--root", args.root], check=True, stdout=subprocess.DEVNULL)
        tools.insert(1, ("shgrep idx", args.shgrep, shgrep_index_cmd))
    if args.tgrep_index:
        if not args.tgrep:
            parser.error("--tgrep-index needs --tgrep PATH")
        subprocess.run([args.tgrep, "index", args.root], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        tools.append(("tgrep idx", args.tgrep, tgrep_index_cmd))

    print(f"root: {args.root}  runs: {args.runs} (median, ms)")
    print(f"{'workload':<26}" + "".join(f"{name:>12}" for name, _, _ in tools) + "   lines out")
    for name, patterns, literal, files in WORKLOADS:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as handle:
            handle.write("\n".join(patterns) + "\n")
            pattern_file = handle.name
        try:
            cells, outputs = [], []
            for _, exe, build in tools:
                cmd = build(exe, args.root, patterns, literal, files, pattern_file)
                timed(cmd)
                samples = []
                for _ in range(args.runs):
                    elapsed, done = timed(cmd)
                    samples.append(elapsed)
                cells.append(statistics.median(samples) * 1000)
                outputs.append(len(done.stdout.splitlines()))
            print(f"{name:<26}" + "".join(f"{ms:>12.0f}" for ms in cells) + "   " + "/".join(map(str, outputs)))
        finally:
            os.unlink(pattern_file)


if __name__ == "__main__":
    main()
