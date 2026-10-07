"""Wall-clock benchmark: shgrep CLI against rg, ug and tgrep on one root.

Usage: python tests/bench.py ROOT [--shgrep dist/shgrep.exe] [--rg rg] [--ug ug] [--tgrep PATH]
                               [--tgrep-index DIR] [--runs 5] [--tools shgrep,rg,ug,tgrep,tgrep-idx]
                               [--server] [--breakdown]

Each workload runs once to warm the file cache, then --runs times; the median wall time is reported.
--server adds a column timed through one persistent shgrep MCP process (no process start-up, warm
compiled-pattern cache), which is how Claude Code and Codex use shgrep.
--breakdown (implies --server) splits shgrep's no-match cost into process start-up, MCP round trip,
traversal, and scan, using the server's own summary counters.
CONTRACT: flags are chosen so every tool selects the same files: recursive, hidden files skipped, binary
files skipped, .gitignore and .ignore honored, symlinks not followed.
"""
import argparse
import json
import os
import statistics
import subprocess
import tempfile
import time

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

# Footer lines shgrep appends to text output; not results.
FOOTER_PREFIXES = ("No matches.", "Selection:", "Skipped oversized", "[status ")


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
    # --no-require-git: honor .gitignore outside git repos, as shgrep does.
    cmd = [exe, "--no-messages", "--no-require-git"]
    if literal:
        cmd.append("-F")
    if files:
        cmd.append("-l")
    return cmd + ["-f", pattern_file, root]


def tgrep_cmd(exe, root, patterns, literal, files, pattern_file):
    cmd = [exe, "--no-index", "--no-messages", "--no-require-git"]
    if literal:
        cmd.append("-F")
    if files:
        cmd.append("-l")
    return cmd + ["-f", pattern_file, root]


def tgrep_index_cmd(index_dir):
    def build(exe, root, patterns, literal, files, pattern_file):
        cmd = [exe, "--index-path", index_dir, "--no-messages", "--no-require-git"]
        if literal:
            cmd.append("-F")
        if files:
            cmd.append("-l")
        return cmd + ["-f", pattern_file, root]
    return build


class Server:
    """One persistent shgrep MCP process over STDIO; requests are sent one at a time."""

    def __init__(self, exe, root):
        self.process = subprocess.Popen([exe, "--root", root], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL)
        self.next_id = 0
        self.call("initialize", {"protocolVersion": "2025-06-18"})

    def call(self, method, params=None):
        self.next_id += 1
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            message["params"] = params
        self.process.stdin.write(json.dumps(message).encode() + b"\n")
        self.process.stdin.flush()
        response = json.loads(self.process.stdout.readline())
        if "error" in response:
            raise RuntimeError(f"{method}: {response['error']}")
        return response["result"]

    def tool(self, name, arguments):
        result = self.call("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            raise RuntimeError(f"{name}: {result['content'][0]['text']}")
        return result["content"][0]["text"]

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=30)


def server_args(patterns, literal, output):
    return {"patterns": patterns, "mode": "literal" if literal else "regex", "output": output,
            "max_results": 10000, "max_matches_per_file": 10000, "max_output_bytes": 1048576,
            "timeout_ms": 300000}


def result_lines(text):
    return sum(1 for line in text.splitlines() if not line.startswith(FOOTER_PREFIXES))


def run_cli(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def measure(run, runs):
    """Returns (median ms, first-call ms, last result). The first call warms caches and is not in the median."""
    start = time.perf_counter()
    result = run()
    first = (time.perf_counter() - start) * 1000
    samples = []
    for _ in range(runs):
        start = time.perf_counter()
        result = run()
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples), first, result


def breakdown(args, server, first_calls):
    print("\nshgrep breakdown (median ms over --runs; internal = server's own elapsed_ms)")
    with tempfile.TemporaryDirectory(prefix="shgrep-empty-") as empty:
        cmd = [args.shgrep, "search", "--root", empty, "-F", "-e", "zzqqxx_nomatch"]
        ms, _, _ = measure(lambda: run_cli(cmd), args.runs)
    print(f"  {'CLI process on empty root':<36}{ms:8.1f}")
    ms, _, _ = measure(lambda: server.call("ping"), args.runs)
    print(f"  {'MCP round trip (ping)':<36}{ms:8.1f}")
    walk = {"exact_name": "zz_no_such_file_zz", "output": "json"}
    ms, _, reply = measure(lambda: json.loads(server.tool("find_files", walk)), args.runs)
    seen = reply.get("selection", {}).get("regular_files_seen", "?")
    print(f"  {'traversal only (find_files)':<36}{ms:8.1f}   internal {reply['summary']['elapsed_ms']} ms, "
          f"{seen} files seen")
    print(f"\n  {'no-match search via server':<26}{'first':>8}{'median':>8}{'internal':>10}{'scanned':>9}"
          f"{'binary':>8}{'MiB':>8}{'GB/s':>7}")
    for name, patterns, literal, files in WORKLOADS:
        if files:
            continue
        arguments = server_args(patterns, literal, "json")
        ms, _, reply = measure(lambda: json.loads(server.tool("search", arguments)), args.runs)
        s = reply["summary"]
        internal = s["elapsed_ms"]
        rate = s["bytes_scanned"] / (internal / 1000) / 1e9 if internal else float("nan")
        print(f"  {name:<26}{first_calls.get(name, float('nan')):>8.0f}{ms:>8.1f}{internal:>10}"
              f"{s['files_scanned']:>9}{s['files_skipped_binary']:>8}{s['bytes_scanned'] / 2**20:>8.0f}{rate:>7.2f}")
    print("  first = first server call for that pattern set (compiled-pattern load/compile + scan).")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root")
    parser.add_argument("--shgrep", default=os.path.join("dist", "shgrep.exe"))
    parser.add_argument("--ug", default="ug")
    parser.add_argument("--rg", default="rg")
    parser.add_argument("--tgrep")
    parser.add_argument("--tgrep-index", help="index directory; builds a tgrep index there and adds an indexed column")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--tools", default="shgrep,rg,ug,tgrep,tgrep-idx",
                        help="comma-separated subset of shgrep,rg,ug,tgrep,tgrep-idx")
    parser.add_argument("--server", action="store_true", help="add a persistent shgrep MCP server column")
    parser.add_argument("--breakdown", action="store_true", help="print shgrep's cost breakdown (implies --server)")
    args = parser.parse_args()
    selected = set(args.tools.split(","))
    tools = [(name, exe, build) for name, exe, build in
             [("shgrep", args.shgrep, shgrep_cmd), ("rg", args.rg, rg_cmd), ("ug", args.ug, ug_cmd)]
             if name in selected]
    if args.tgrep and "tgrep" in selected:
        tools.append(("tgrep", args.tgrep, tgrep_cmd))
    if args.tgrep and args.tgrep_index and "tgrep-idx" in selected:
        start = time.perf_counter()
        built = subprocess.run([args.tgrep, "index", "--force", "--index-path", args.tgrep_index, "--no-require-git",
                                args.root], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"tgrep index build: {(time.perf_counter() - start) * 1000:.0f} ms (exit {built.returncode})")
        tools.append(("tgrep idx", args.tgrep, tgrep_index_cmd(args.tgrep_index)))
    server = Server(args.shgrep, args.root) if args.server or args.breakdown else None
    columns = [name for name, _, _ in tools] + (["shgrep srv"] if server else [])
    first_calls = {}

    try:
        print(f"root: {args.root}  runs: {args.runs} (median, ms)")
        print(f"{'workload':<26}" + "".join(f"{name:>11}" for name in columns) + "   lines out")
        for name, patterns, literal, files in WORKLOADS:
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as handle:
                handle.write("\n".join(patterns) + "\n")
                pattern_file = handle.name
            try:
                cells, outputs = [], []
                for _, exe, build in tools:
                    cmd = build(exe, args.root, patterns, literal, files, pattern_file)
                    ms, _, done = measure(lambda: run_cli(cmd), args.runs)
                    cells.append(ms)
                    outputs.append(len(done.stdout.splitlines()))
                if server:
                    arguments = server_args(patterns, literal, "files" if files else "lines")
                    ms, first_calls[name], text = measure(lambda: server.tool("search", arguments), args.runs)
                    cells.append(ms)
                    outputs.append(result_lines(text))
                print(f"{name:<26}" + "".join(f"{ms:>11.0f}" for ms in cells) + "   " + "/".join(map(str, outputs)))
            finally:
                os.unlink(pattern_file)
        if args.breakdown:
            breakdown(args, server, first_calls)
    finally:
        if server:
            server.close()


if __name__ == "__main__":
    main()
