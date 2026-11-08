"""User-run check of the bundled C/C++ language server on a real repository. Edits nothing in the sources.
Usage: python tests/lsp_repo.py dist/shgrep.exe <repo> [--file <relative path> --symbol <name>] [--exclude <folder>]
  Project files are the ones in the compile database clangd uses (file_info reports it), minus library folders
  (libs and every --exclude). Without --file/--symbol it picks a function from them that other project files use.
  clangd still indexes the libraries, so navigation into library APIs works; they only stay out of the comparison.
shgrep writes below <repo>/.shgrep/lsp-state; with the repo's own compile_commands.json, clangd's index goes to
<repo>/.cache/clangd. The first run indexes the whole repo.
"""
import argparse
import json
import os
from pathlib import Path
import time

from lsp_smoke import Client

SLOW = {"timeout_ms": 300000}
SOURCES = (".cpp", ".cc", ".cxx", ".c")


def timed(label, call):
    start = time.monotonic()
    result = call()
    print(f"{label}: {time.monotonic() - start:.1f} s")
    return result


def in_library(relative, libraries):
    return Path(relative).parts[0].lower() in libraries if Path(relative).parts else False


def database_sources(database, repo, libraries):
    """Project sources the compile database lists: inside the repo, outside library folders, still on disk."""
    sources = {}
    for entry in json.loads(Path(database).read_text(encoding="utf-8-sig")):
        path = Path(entry["file"])
        if not path.is_absolute():
            path = Path(entry.get("directory", repo)) / path
        try:
            relative = path.resolve().relative_to(repo).as_posix()
        except ValueError:
            continue
        if relative.lower().endswith(SOURCES) and not in_library(relative, libraries) and path.is_file():
            sources[relative] = path.stat().st_size
    return sources


def wait_indexed(client, path, limit_s):
    start = time.monotonic()
    last = None
    while True:
        status = client.tool("file_info", {"path": path, "operation": "lsp", **SLOW})
        state = status.get("indexing", "complete")
        if state != last:
            print(f"[{time.monotonic() - start:7.0f} s] indexing: {state}")
            last = state
        if state == "complete":
            return status, time.monotonic() - start
        assert time.monotonic() - start < limit_s, f"index not complete after {limit_s} s: {status}"
        time.sleep(15)


def text_files(client, symbol):
    """Files where the name appears as a whole word: an upper bound for the references' files."""
    raw = client.tool("search", {"operation": "text", "pattern": symbol, "word": True, "output": "files",
                                 "types": ["c", "cpp", "h"], **SLOW}, raw=True)
    return {line.strip().replace("\\", "/") for line in raw.splitlines() if line.strip() and not line.startswith("[")}


def pick(client, sources, project, libraries):
    """A function from a mid-sized project file whose name at least 3 other project files mention."""
    for relative in sorted(sources, key=lambda path: abs(sources[path] - 20000))[:15]:
        overview = client.tool("read_file", {"path": relative, "operation": "overview", "depth": -1, **SLOW})["results"]
        for symbol in overview:
            name = symbol["name"].split("::")[-1]
            if symbol.get("kind") not in (6, 12) or len(name) < 6 or not name.isidentifier():
                continue
            users = {path for path in text_files(client, name) if project(path)} - {relative}
            if len(users) >= 3:
                print(f"picked {relative} :: {name} (mentioned in {len(users)} other project files)")
                return relative, name
    raise AssertionError("no function used across files found; pass --file and --symbol")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("executable", type=Path)
    parser.add_argument("repo", type=Path)
    parser.add_argument("--file")
    parser.add_argument("--symbol")
    parser.add_argument("--exclude", action="append", default=[], help="Another library folder (top level) to leave out")
    parser.add_argument("--index-limit-hours", type=float, default=6)
    parser.add_argument("--clangd-log", type=Path, help="Write shgrep's and clangd's verbose stderr log to this file")
    args = parser.parse_args()
    executable, repo = args.executable.resolve(), args.repo.resolve()
    libraries = {"libs"} | {name.lower().strip("/\\") for name in args.exclude}
    assert bool(args.file) == bool(args.symbol), "give both --file and --symbol, or neither"
    # The repo's own database seeds the first request; file_info then names the database clangd really uses.
    seed = repo / "compile_commands.json"
    probe = args.file or (next(iter(database_sources(seed, repo, libraries))) if seed.is_file() else None)
    assert probe, "pass --file: the repo has no compile_commands.json to pick a first file from"
    log = None
    if args.clangd_log:
        os.environ["SHGREP_CLANGD_LOG"] = "verbose"
        log = args.clangd_log.open("w", encoding="utf-8")
    client = Client(executable, repo, stderr=log)
    try:
        status = timed("server start", lambda: client.tool("file_info", {"path": probe, "operation": "lsp", **SLOW}))
        assert status["language_id"] == "cpp", status
        print(f"compile database: {status['compile_database']}")
        status, indexed = wait_indexed(client, probe, args.index_limit_hours * 3600)
        print(f"index complete after {indexed / 60:.1f} min")
        database = status["compile_database"].get("path")
        sources = database_sources(database, repo, libraries) if database else {}
        folders = {Path(path).parts[0].lower() for path in sources if len(Path(path).parts) > 1}
        print(f"{len(sources)} project sources in the database, top folders {sorted(folders)}; excluded {sorted(libraries)}")

        def project(path):
            parts = Path(path).parts
            return bool(parts) and not in_library(path, libraries) and (len(parts) == 1 or parts[0].lower() in folders)

        if not args.file:
            assert sources, "the compile database lists no project sources; pass --file and --symbol"
            args.file, args.symbol = pick(client, sources, project, libraries)

        symbols = timed("symbols in file", lambda: client.tool("search", {"path": args.file, "pattern": args.symbol,
                                                                           "substring_matching": True, **SLOW})["results"])
        assert symbols, f"{args.symbol} not found in {args.file}"
        name_path = symbols[0]["name_path"]
        print(f"symbol: {name_path} (line {symbols[0].get('line')})")

        definition = timed("definition", lambda: client.tool("search", {"operation": "definition", "path": args.file,
                                                                          "name_path": name_path, **SLOW}))
        print(f"  -> {[(item['path'], item['line']) for item in definition['results']][:5]}")

        references = timed("references", lambda: client.tool("search", {"operation": "references", "path": args.file,
                                                                          "name_path": name_path, **SLOW}))
        found = {item["path"].replace("\\", "/") for item in references["results"]}
        print(f"  {len(references['results'])} references in {len(found)} files; stale {references['stale_locations']}, "
              f"ignored {references['ignored_locations']}, outside {references['outside_roots']}, "
              f"enclosing symbol omitted {references.get('symbols_omitted', 0)}")
        # An empty answer right after "complete" can mean clangd was still loading index shards without reporting it.
        for delay in (30, 30, 60) if not references["results"] else ():
            time.sleep(delay)
            references = client.tool("search", {"operation": "references", "path": args.file, "name_path": name_path, **SLOW})
            found = {item["path"].replace("\\", "/") for item in references["results"]}
            print(f"  retry: {len(references['results'])} references in {len(found)} files")
            if references["results"]:
                break

        # Text hits include comments, strings and unrelated same-named symbols, so they bound coverage from above.
        words = timed("text search", lambda: {path for path in text_files(client, args.symbol) if project(path)})
        missing = sorted(words - found - {args.file})
        print(f"  name appears in {len(words)} project files; {len(missing)} have no reference (check a few by hand):")
        for path in missing[:10]:
            print(f"    {path}")

        timed("workspace symbol search", lambda: client.tool("find_files", {"operation": "symbols",
                                                                             "pattern": args.symbol, **SLOW}))
        diff = timed("rename (dry run)", lambda: client.tool("edit_file", {"operation": "rename", "path": args.file,
                                                                             "name_path": name_path, "new_name": args.symbol + "_renamed",
                                                                             "dry_run": True, **SLOW}, raw=True))
        print(f"  rename would touch {diff.count('+++ ')} files")
        timed("references again (warm)", lambda: client.tool("search", {"operation": "references", "path": args.file,
                                                                          "name_path": name_path, **SLOW}))
        print(client.tool("file_info", {"path": args.file, "operation": "lsp", **SLOW}).get("open_documents"), "documents open")
    finally:
        client.close()
        if log:
            log.close()
            print(f"log: {args.clangd_log}")


if __name__ == "__main__":
    main()
