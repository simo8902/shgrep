"""Tests a standard reranker (llama-server --reranking) on the same questions and candidates as retrieval_eval.py.
Usage: python tests/rerank_eval.py dist/shgrep.exe <repo> [--count 30] [--seed 1] [--rerank-port 8081]
  Needs two llama-servers: Laya on SHGREP_LAYA_PORT (default 8080, shgrep requires it to start) and the reranker:
    llama-server -m <reranker.gguf> --reranking --pooling rank --embedding -ngl 99 --port 8081
  Candidates are shgrep's keyword pool (budget 0, whole pool returned). Per question the reranker scores every
  candidate (path + code) against the intent through POST /v1/rerank; arms compare keyword order, reranker order,
  and RRF fusion of both at weights 100/50/25 (percent of the reranker's rank), the same fusion shgrep uses for Laya.
  Nothing in the repo is written.
"""
import argparse
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.request

import retrieval_eval as ev
from laya_fixture import require_server
from lsp_smoke import Client

RRF_K = 60.0
WEIGHTS = (100, 50, 25)


def rerank(port, query, documents):
    """Scores for documents in input order, via llama-server's rerank endpoint."""
    body = json.dumps({"model": "reranker", "query": query, "documents": documents}).encode("utf-8")
    last = None
    for path in ("/v1/rerank", "/rerank"):
        request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", body, {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                results = json.load(response)["results"]
        except urllib.error.HTTPError as error:
            last = f"{path}: HTTP {error.code} {error.read()[:200]!r}"
            continue
        scores = [None] * len(documents)
        for item in results:
            scores[item["index"]] = item["relevance_score"]
        if None in scores:
            raise RuntimeError("reranker did not score every document")
        return scores
    raise RuntimeError(f"reranker failed: {last}")


def fused(candidates, scores, weight):
    """Candidates reordered by RRF of keyword rank and weighted reranker rank."""
    by_score = sorted(range(len(candidates)), key=lambda i: -scores[i])
    position = {i: rank for rank, i in enumerate(by_score)}
    order = sorted(range(len(candidates)), key=lambda i: -(1 / (RRF_K + i) + weight / 100 / (RRF_K + position[i])))
    return [candidates[i] for i in order]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("executable", type=Path)
    parser.add_argument("repo", type=Path)
    parser.add_argument("--count", type=int, default=30)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--rerank-port", type=int, default=8081)
    parser.add_argument("--max-chars", type=int, default=2000, help="code characters sent per candidate")
    parser.add_argument("--query-prefix", default="", help="text before the intent, e.g. a reranker instruction")
    args = parser.parse_args()
    require_server()
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{args.rerank_port}/health", timeout=10).close()
    except OSError as error:
        raise SystemExit(f"reranker not answering on 127.0.0.1:{args.rerank_port}: {error}") from None
    repo = args.repo.resolve()
    asked = ev.questions(repo, args.count, args.seed)
    print(f"{len(asked)} questions from doc comments in {repo}")
    # Budget 0 and no limits: the whole BM25 pool comes back in keyword order for the reranker to reorder.
    client = Client(args.executable.resolve(), repo, timeout=330, regression_laya=False,
                    environment={**os.environ, "SHGREP_LAYA_BUDGET_MS": "0", "SHGREP_LAYA_RETURN": "0"})
    rows = []
    try:
        for q in asked:
            extensions = ["rs"] if q["path"].endswith(".rs") else ["py"]
            candidates, _ = ev.lexical(client, ev.keywords(q["intent"]), extensions, q["intent"])
            source = {}

            def code_of(c):
                if c["path"] not in source:
                    source[c["path"]] = (repo / c["path"]).read_text(encoding="utf-8").splitlines()
                body = "\n".join(source[c["path"]][c["first"] - 1:c["last"]])
                return f"file: {c['path']} (lines {c['first']}-{c['last']})\n{body[:args.max_chars]}"

            documents = [code_of(c) for c in candidates]
            started = time.monotonic()
            scores = rerank(args.rerank_port, args.query_prefix + q["intent"], documents) if documents else []
            seconds = time.monotonic() - started
            reranked = [candidates[i] for i in sorted(range(len(candidates)), key=lambda i: -scores[i])]
            row = {"intent": q["intent"], "answer": f"{q['path']}::{q['function']}", "pool": len(candidates),
                   "keyword_rank": ev.rank_of(candidates, q), "rerank_rank": ev.rank_of(reranked, q),
                   **{f"w{w}_rank": ev.rank_of(fused(candidates, scores, w), q) for w in WEIGHTS},
                   "rerank_s": round(seconds, 2)}
            rows.append(row)
            print(json.dumps(row), flush=True)
    finally:
        client.close()
    n = len(rows)

    def share(key, k):
        return sum(1 for r in rows if r[key] and r[key] <= k) / n if n else 0

    print("\nsummary (pool = shgrep's keyword pool, same questions as retrieval_eval.py)")
    arms = [("keywords only", "keyword_rank"), ("reranker only", "rerank_rank")] + \
           [(f"keywords + reranker weight {w}%", f"w{w}_rank") for w in WEIGHTS]
    for label, key in arms:
        print(f"  {label:<34} recall {share(key, 10**9):.0%}, top-1 / top-3 {share(key, 1):.0%} / {share(key, 3):.0%}")
    print(f"  rerank time per question          {sum(r['rerank_s'] for r in rows) / n:.2f} s")


if __name__ == "__main__":
    main()
