"""Wall-clock benchmark: shgrep CLI against ug (and optionally tgrep --no-index) on one root.

Usage: python tests/bench.py ROOT [--shgrep dist/shgrep.exe] [--rg rg] [--ug ug] [--tgrep PATH]
                               [--tgrep-index DIR] [--runs 5]

Each workload runs once to warm the file cache, then --runs times; the median wall time is reported.
CONTRACT: flags are chosen so every tool selects the same files: recursive, hidden files skipped, binary
files skipped, .gitignore and .ignore honored, symlinks not followed.
"""
import argparse
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


def timed(cmd):
    start = time.perf_counter()
    done = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return time.perf_counter() - start, done


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root")
    parser.add_argument("--shgrep", default=os.path.join("dist", "shgrep.exe"))
    parser.add_argument("--ug", default="ug")
    parser.add_argument("--rg", default="rg")
    parser.add_argument("--tgrep")
    parser.add_argument("--tgrep-index", help="index directory; builds a tgrep index there and adds an indexed column")
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()
    tools = [("shgrep", args.shgrep, shgrep_cmd), ("rg", args.rg, rg_cmd), ("ug", args.ug, ug_cmd)]
    if args.tgrep:
        tools.append(("tgrep", args.tgrep, tgrep_cmd))
    if args.tgrep and args.tgrep_index:
        start = time.perf_counter()
        built = subprocess.run([args.tgrep, "index", "--force", "--index-path", args.tgrep_index, "--no-require-git",
                                args.root], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"tgrep index build: {(time.perf_counter() - start) * 1000:.0f} ms (exit {built.returncode})")
        tools.append(("tgrep idx", args.tgrep, tgrep_index_cmd(args.tgrep_index)))

    print(f"root: {args.root}  runs: {args.runs} (median, ms)")
    print(f"{'workload':<26}" + "".join(f"{name:>10}" for name, _, _ in tools) + "   lines out")
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
            print(f"{name:<26}" + "".join(f"{ms:>10.0f}" for ms in cells) + "   " + "/".join(map(str, outputs)))
        finally:
            os.unlink(pattern_file)


if __name__ == "__main__":
    main()
