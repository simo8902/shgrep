"""Measures intent -> function retrieval on a real repository: shgrep's keyword ranking against unranked results.
Usage: python tests/retrieval_eval.py dist/shgrep.exe <repo> [--count 30] [--seed 1] [--hard]
  Questions come from the repo's own doc comments (Rust ///, Python docstrings), with the function's own name
  removed; the answer is that function. With --hard, question words that also appear in the answer's code are
  dropped too (questions left with fewer than 3 words are skipped). For each question it measures:
    baseline  grep the intent's words (lines output) + read the answer's whole file: tokens an agent pays
    unranked  the same search without an intent: findings in scan order, candidates sorted by hit count
    ranked    the same search with the intent: BM25-ranked hunks (top 10, at most 3 per file), in returned order
  Candidates are enclosing functions (LSP) or text hunks; a hunk overlapping the answer's lines counts as the answer.
  Top-three tokens are a comparison metric only. Tokens are estimated as characters / 4. Nothing in the repo is written.
"""
import argparse
from bisect import bisect_left, bisect_right
from collections import Counter
import json
import math
import os
from pathlib import Path
import random
import re
import sys
import subprocess
import time

from lsp_smoke import Client

SLOW = {"timeout_ms": 300000}
SKIP = {"target", "node_modules", "libs", "third_party", "vendor", "build", "dist", "__pycache__"}
STOP = set("""a an and are as at be by can for from has have if in into is it its of on or that the this to was
when where which while with without not no will would should must may might each every one all any per than then
also only its their there these those used use uses using returns return given gets get sets set""".split())


def tokens(text):
    return math.ceil(len(text) / 4)


def function_span(lines, start, python):
    """1-based first/last line of the function defined at lines[start]: indentation (Python) or braces (Rust)."""
    end = start
    if python:
        indent = len(lines[start]) - len(lines[start].lstrip())
        for i in range(start + 1, len(lines)):
            if lines[i].strip() and len(lines[i]) - len(lines[i].lstrip()) <= indent:
                break
            end = i
    else:
        depth, opened = 0, False
        for i in range(start, len(lines)):
            depth += lines[i].count("{") - lines[i].count("}")
            opened = opened or "{" in lines[i]
            end = i
            if (opened and depth <= 0) or (not opened and lines[i].rstrip().endswith(";")):
                break
    return start + 1, end + 1


def code_terms(lines, start, end, python):
    """Lowercase words (identifiers split at _ and camelCase, plus a plural-stripped form) in lines[start:end], with
    comments and docstrings left out."""
    terms, in_doc = set(), False
    for line in lines[start:end]:
        stripped = line.strip()
        if python:
            quotes = stripped.count('"""') + stripped.count("'''")
            if in_doc or quotes:
                if quotes % 2 == 1:
                    in_doc = not in_doc
                continue
            if stripped.startswith("#"):
                continue
        elif stripped.startswith("//"):
            continue
        for token in re.findall(r"[A-Za-z0-9_]+", stripped):
            for part in [token] + token.split("_"):
                for piece in [part] + re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", part):
                    piece = piece.lower()
                    if piece:
                        terms.add(piece)
                        terms.add(piece.rstrip("s"))
    return terms


def harden(text, terms):
    """The question without the words its answer's code contains: it can no longer be matched by identifier."""
    kept = [w for w in re.findall(r"\S+", text)
            if not (re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", w.strip(".,;:()'\"`")) and
                    (w.strip(".,;:()'\"`").lower() in terms or w.strip(".,;:()'\"`").lower().rstrip("s") in terms))]
    return " ".join(kept)


def questions(repo, count, seed, hard=False):
    found = []
    for folder, subfolders, files in os.walk(repo):
        subfolders[:] = [d for d in subfolders if not d.startswith(".") and d.lower() not in SKIP]
        for name in files:
            path = Path(folder) / name
            if path.suffix not in (".rs", ".py") or path.stat().st_size > 2_000_000:
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (UnicodeDecodeError, OSError):
                continue
            for i, line in enumerate(lines):
                if path.suffix == ".rs":
                    match = re.match(r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)", line)
                    doc, j = [], i - 1
                    while j >= 0 and (lines[j].strip().startswith("///") or lines[j].strip().startswith("#[")):
                        if lines[j].strip().startswith("///"):
                            doc.insert(0, lines[j].strip()[3:].strip())
                        j -= 1
                    doc_first = j + 2  # 1-based first doc/attribute line: the doc the intent comes from is above fn
                else:
                    match = re.match(r"\s*(?:async\s+)?def\s+(\w+)", line)
                    doc = []
                    doc_first = i + 1  # the docstring is inside the function
                    if match and i + 1 < len(lines) and lines[i + 1].strip().startswith(('"""', "'''")):
                        body = lines[i + 1].strip()[3:]
                        doc = [body.split('"""')[0].split("'''")[0]]
                if not match or not doc:
                    continue
                text = " ".join(doc)
                text = re.split(r"(?<=[.!?])\s", text, maxsplit=1)[0]
                fn = match[1]
                # The question must not hand over the answer's name.
                for part in set(re.split(r"_+", fn)) | {fn}:
                    if len(part) > 2:
                        text = re.sub(rf"\b{re.escape(part)}\b", "", text, flags=re.IGNORECASE)
                span = function_span(lines, i, path.suffix == ".py")
                if hard:
                    text = harden(text, code_terms(lines, i, span[1], path.suffix == ".py"))
                words = [w for w in re.findall(r"[A-Za-z][A-Za-z0-9]+", text) if w.lower() not in STOP]
                if len(words) >= 3:
                    found.append({"intent": " ".join(text.split()), "path": path.relative_to(repo).as_posix(),
                                  "function": fn, "line": i + 1, "span": (doc_first, span[1])})
    random.Random(seed).shuffle(found)
    return found[:count]


def keywords(intent):
    words = [w.lower() for w in re.findall(r"[A-Za-z][A-Za-z0-9]+", intent) if w.lower() not in STOP and len(w) > 2]
    # Identifier guesses from adjacent words: "retry timeout" -> retry_timeout, retryTimeout.
    joined = [a + "_" + b for a, b in zip(words, words[1:])] + [a + b.capitalize() for a, b in zip(words, words[1:])]
    return list(dict.fromkeys(words + joined))


def lexical(client, keys, extensions, intent=None):
    """Candidates (functions via LSP, else text hunks) from one search. With an intent shgrep ranks the hunks and
    they come best first; without one the findings arrive in scan order and candidates sort by hit count."""
    arguments = {"operation": "text", "patterns": keys, "case_insensitive": True, "mode": "literal",
                 "output": "json", "extensions": extensions, "index": False, **SLOW}
    if intent:
        arguments["intent"] = intent
    reply = client.tool("search", arguments)
    summary = reply["summary"]
    if summary["status"] != "complete" or summary.get("truncated"):
        raise RuntimeError(f"Incomplete search; refusing to report full-retrieval metrics: {summary}")
    by_file = {}
    best = {}  # (path, line) -> rank of the hunk that returned it; ranked results arrive best first
    for item in reply["results"]:
        path = item["path"].replace("\\", "/")
        by_file.setdefault(path, []).append(item["line"])
        if intent:
            best.setdefault((path, item["line"]), item["ranking"]["rank"])
    candidates = []
    for path in sorted(by_file, key=lambda p: (-len(by_file[p]), p)):
        hit_lines = sorted(by_file[path])
        covered = set()
        try:
            outline = client.tool("read_file", {"path": path, "operation": "overview", "depth": -1, "format": "json", **SLOW})["results"]
        except (AssertionError, KeyError, json.JSONDecodeError) as error:
            # Keep every hit as text if LSP cannot provide an outline for this file.
            print(f"Outline unavailable for {path}; retaining text candidates: {error}", file=sys.stderr)
            outline = []
        for symbol in outline:
            if symbol.get("kind") not in (6, 12):
                continue
            first, last = symbol["range"]["start_line"], symbol["range"]["end_line"]
            left, right = bisect_left(hit_lines, first), bisect_right(hit_lines, last)
            hits = right - left
            if hits:
                covered.update(hit_lines[left:right])
                candidates.append({"path": path, "name": symbol["name"], "name_path": symbol["name_path"],
                                   "first": first, "last": last, "hits": hits, "kind": "function"})
        # Comments, module-level code and files without LSP are findings too.
        pending = None
        for line, hits in sorted(Counter(hit_lines).items()):
            if line in covered:
                continue
            if pending is not None and line == pending["last"] + 1:
                pending["last"] = line
                pending["hits"] += hits
            else:
                pending = {"path": path, "name": "", "name_path": None,
                           "first": line, "last": line, "hits": hits, "kind": "text"}
                candidates.append(pending)
    if intent:
        for c in candidates:
            c["rank"] = min(r for (p, line), r in best.items() if p == c["path"] and c["first"] <= line <= c["last"])
        candidates.sort(key=lambda c: (c["rank"], -c["hits"]))
    else:
        candidates.sort(key=lambda c: (-c["hits"], c["last"] - c["first"]))
    return candidates, reply


def rank_of(candidates, question):
    """1-based rank of the first candidate that is the answer function, or a text hunk inside its lines."""
    first, last = question["span"]
    for index, c in enumerate(candidates):
        if c["path"] != question["path"]:
            continue
        # Without a language server every candidate is a text hunk; overlap with the function's lines counts.
        if c["name"].split("::")[-1] == question["function"] or (c["first"] <= last and c["last"] >= first):
            return index + 1
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("executable", type=Path)
    parser.add_argument("repo", type=Path)
    parser.add_argument("--count", type=int, default=30)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--hard", action="store_true",
                        help="drop the question words that also appear in the answer's code; keep questions with 3+ words left")
    args = parser.parse_args()
    repo = args.repo.resolve()
    asked = questions(repo, args.count, args.seed, args.hard)
    print(f"{len(asked)} questions from doc comments in {repo}")
    if not asked:
        return
    client = Client(args.executable.resolve(), repo, timeout=330)
    rows = []
    try:
        for q in asked:
            extensions = ["rs"] if q["path"].endswith(".rs") else ["py"]
            keys = keywords(q["intent"])
            started = time.monotonic()
            candidates, findings = lexical(client, keys, extensions, q["intent"])
            lexical_s = time.monotonic() - started
            unranked_candidates, _ = lexical(client, keys, extensions)
            # The comparison baseline uses the native CLI, never an MCP bypass.
            command = [str(args.executable.resolve()), "search", "--root", str(repo), "-F", "-i",
                       "--color", "never", "--timeout-ms", "300000"]
            for extension in extensions:
                command += ["--extension", extension]
            for key in keys:
                command += ["--pattern", key]
            grep = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  encoding="utf-8", errors="replace", timeout=330).stdout
            baseline = tokens(grep) + tokens((repo / q["path"]).read_text(encoding="utf-8"))
            source = {}
            def lines_of(c):
                if c["path"] not in source:
                    source[c["path"]] = (repo / c["path"]).read_text(encoding="utf-8").splitlines()
                return source[c["path"]][c["first"] - 1:c["last"]]
            answer_tokens = sum(tokens("\n".join(lines_of(c))) for c in candidates[:3])
            row = {"intent": q["intent"], "answer": f"{q['path']}::{q['function']}",
                   "answer_lines": f"{q['span'][0]}-{q['span'][1]}",
                   "top3": [f"{c['path']}:{c['first']}-{c['last']}" for c in candidates[:3]],
                   "candidates": len(candidates),
                   "matched_files": len({item["path"] for item in findings["results"]}),
                   "search_hits": len(findings["results"]),
                   "unmapped_text_candidates": sum(c["kind"] == "text" for c in candidates),
                   "ranked_rank": rank_of(candidates, q), "unranked_rank": rank_of(unranked_candidates, q),
                   "ranking": findings.get("ranking"),
                   "baseline_tokens": baseline, "mcp_tokens": tokens(json.dumps(findings, ensure_ascii=False)), "top3_tokens": answer_tokens, "lexical_s": round(lexical_s, 1)}
            rows.append(row)
            print(json.dumps(row), flush=True)
    finally:
        client.close()
    n = len(rows)
    def share(key, k):
        return sum(1 for r in rows if r[key] and r[key] <= k) / n if n else 0
    print("\nsummary")
    print(f"  ranked   recall, top-1 / top-3     {share('ranked_rank', 10**9):.0%}, {share('ranked_rank', 1):.0%} / {share('ranked_rank', 3):.0%}")
    print(f"  unranked recall, top-1 / top-3     {share('unranked_rank', 10**9):.0%}, {share('unranked_rank', 1):.0%} / {share('unranked_rank', 3):.0%}")
    print(f"  ranked search time per question    {sum(r['lexical_s'] for r in rows) / n:.1f} s")
    print(f"  tokens: MCP selected evidence    {sum(r['mcp_tokens'] for r in rows) // n} per question")
    print(f"  tokens: baseline grep+read        {sum(r['baseline_tokens'] for r in rows) // n} per question")
    print(f"  tokens: top-3 bodies (metric only) {sum(r['top3_tokens'] for r in rows) // n} per question")


if __name__ == "__main__":
    main()
