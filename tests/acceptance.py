"""User-run acceptance check on a real repository: roadmap Phase 1 lookups and symbol edits, per language.
Usage: python tests/acceptance.py dist/shgrep.exe <repo> [--exclude <folder>] [--languages cpp,python,lua,rust,xml]
         [--target LANG=PATH::NAME] [--at PATH:LINE:COLUMN] [--outline PATH]
  --target uses that function instead of picking one; --at adds definition and hover at a usage position;
  --outline adds an outline check for a file. Each may repeat.
For each language present (outside libs, dot folders and build output) it picks a function other files use, then
runs outline, symbol search, references, definition and hover, and replace / insert_before / insert_after / rename /
safe_delete as dry runs. Nothing in the repository changes; the script checks every touched file is unchanged.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import time

from lsp_smoke import Client

SLOW = {"timeout_ms": 300000}
LANGUAGES = {
    "cpp": ((".cpp", ".cc", ".cxx"), "//"),
    "python": ((".py",), "#"),
    "lua": ((".lua",), "--"),
    "rust": ((".rs",), "//"),
    "xml": ((".xml",), None),  # outline and symbol search only: XML has no functions to refactor
}
SKIP = {"libs", "build", "out", "dist", "node_modules", "target", "third_party", "external", "vendor"}
FUNCTION_KINDS = (6, 9, 12)


class Report:
    def __init__(self):
        self.rows = []

    def check(self, language, name, call):
        start = time.monotonic()
        try:
            ok, detail = call()
        except Exception as error:  # a failed tool call is a failed check, not a crashed run
            ok, detail = False, str(error)[:300]
        self.rows.append((language, name, ok, time.monotonic() - start, detail))
        print(f"{'PASS' if ok else 'FAIL'}  {language:<7} {name:<22} {time.monotonic() - start:6.1f} s  {detail}", flush=True)
        return ok

    def summary(self):
        failed = [row for row in self.rows if not row[2]]
        print(f"\n{len(self.rows) - len(failed)}/{len(self.rows)} checks passed")
        for language, name, _, _, detail in failed:
            print(f"  failed: {language} {name}: {detail}")
        return not failed


def files_for(repo, extensions, excluded):
    found = []
    for folder, subfolders, files in os.walk(repo):
        subfolders[:] = [d for d in subfolders if not d.startswith(".") and d.lower() not in excluded and not d.lower().startswith("build")]
        for name in files:
            if name.lower().endswith(extensions):
                path = Path(folder) / name
                found.append((path.relative_to(repo).as_posix(), path.stat().st_size))
    return sorted(found, key=lambda item: abs(item[1] - 20000))


def project_file(relative, excluded):
    parts = Path(relative).parts[:-1]
    return not any(part.startswith(".") or part.lower() in excluded or part.lower().startswith("build") for part in parts)


def mentions(client, name, extensions, excluded):
    raw = client.tool("search", {"operation": "text", "pattern": name, "word": True, "output": "files",
                                 "extensions": [e.lstrip(".") for e in extensions], **SLOW}, raw=True)
    found = {line.strip().replace("\\", "/") for line in raw.splitlines() if line.strip() and not line.startswith("[")}
    return {path for path in found if project_file(path, excluded)}


def defines(client, relative, name):
    """True when the file declares or defines its own symbol of that name (a same-named copy, a header)."""
    try:
        return bool(client.tool("search", {"path": relative, "pattern": name, **SLOW})["results"])
    except AssertionError:
        return False


def pick(client, candidates, extensions, excluded):
    """A function with a body that some other file uses without defining its own copy."""
    for relative, _ in candidates[:12]:
        try:
            overview = client.tool("read_file", {"path": relative, "operation": "overview", "depth": -1, **SLOW})["results"]
        except AssertionError:
            continue
        for symbol in overview:
            name = symbol["name"].split("::")[-1]
            if symbol.get("kind") not in FUNCTION_KINDS or not symbol.get("body_available") or len(name) < 5 or not name.isidentifier():
                continue
            users = sorted(mentions(client, name, extensions, excluded) - {relative})[:6]
            # Text mentions are not uses: standalone scripts often define their own function of the same name.
            if any(not defines(client, user, name) for user in users):
                return relative, symbol, name
    return None


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_language(client, report, repo, language, extensions, comment, excluded, target=None):
    candidates = files_for(repo, extensions, excluded)
    if not candidates:
        print(f"skip  {language:<7} no files")
        return
    if language == "rust" and not (repo / "Cargo.toml").is_file() and not any(repo.glob("*/Cargo.toml")):
        print(f"skip  {language:<7} no Cargo.toml, so rust-analyzer cannot load a project")
        return
    first = candidates[0][0]
    report.check(language, "outline", lambda: (lambda r: (bool(r), f"{first}: {len(r)} symbols"))(
        client.tool("read_file", {"path": first, "operation": "overview", **SLOW})["results"]))
    if comment is None:
        name = client.tool("read_file", {"path": first, "operation": "overview", **SLOW})["results"][0]["name"]
        report.check(language, "symbol search", lambda: (lambda r: (bool(r), f"{name}: {len(r)} hits"))(
            client.tool("search", {"path": first, "pattern": name, "substring_matching": True, **SLOW})["results"]))
        return
    if target:
        target_path, target_name = target.split("::", 1)
        found = client.tool("search", {"path": target_path, "pattern": target_name, **SLOW})["results"]
        chosen = (target_path, found[0], target_name) if found else None
        if not chosen:
            report.check(language, "target symbol", lambda: (False, f"{target_name} not found in {target_path}"))
            return
    else:
        chosen = pick(client, candidates, extensions, excluded)
    if not chosen:
        # A repo whose scripts never use each other's functions cannot exercise cross-file references.
        print(f"skip  {language:<7} no function is used by another project file; cross-file checks need one")
        return
    path, symbol, name = chosen
    name_path = symbol["name_path"]
    print(f"      {language:<7} using {path} :: {name_path}")
    before = {path: digest(repo / path)}
    report.check(language, "symbol search", lambda: (lambda r: (bool(r), f"{len(r)} hits"))(
        client.tool("search", {"path": path, "pattern": name, "substring_matching": True, **SLOW})["results"]))
    references = []
    def refs():
        references.extend(client.tool("search", {"operation": "references", "path": path, "name_path": name_path, **SLOW})["results"])
        others = {item["path"].replace("\\", "/") for item in references} - {path}
        if not others:
            # Show what the other files actually say, so a static-analysis limit (dynamic calls) is told apart
            # from a missed reference.
            lines = client.tool("search", {"operation": "text", "pattern": name, "word": True, "max_results": 6,
                                           "extensions": [e.lstrip(".") for e in extensions], **SLOW}, raw=True)
            sample = [line.strip() for line in lines.splitlines() if line.strip() and not line.startswith("[") and
                      not line.replace("\\", "/").startswith(path + ":")]
            print("      mentions elsewhere:\n        " + "\n        ".join(line[:160] for line in sample[:5]))
        return bool(others), f"{len(references)} references in {len(others)} other files"
    report.check(language, "references", refs)
    usage = next((item for item in references if item["path"].replace("\\", "/") != path), references[0] if references else None)
    if usage:
        where = {"path": usage["path"], "line": usage["line"], "column": usage["column"]}
        before.setdefault(usage["path"].replace("\\", "/"), digest(repo / usage["path"]))
        report.check(language, "definition", lambda: (lambda r: (bool(r), f"-> {[(i['path'], i['line']) for i in r][:3]}"))(
            client.tool("search", {"operation": "definition", **where, **SLOW})["results"]))
        report.check(language, "hover", lambda: (lambda h: (bool(h), json.dumps(h)[:80]))(
            client.tool("search", {"operation": "hover", **where, **SLOW}).get("hover")))
    else:
        report.check(language, "definition", lambda: (False, "no reference to start from"))
    body = client.tool("read_file", {"path": path, "name_path": name_path, **SLOW})["results"][0]["body"]
    edits = [
        ("replace", {"name_path": name_path, "new_text": body}),
        ("insert_before", {"operation": "insert_before", "name_path": name_path, "new_text": f"{comment} acceptance\n"}),
        ("insert_after", {"operation": "insert_after", "name_path": name_path, "new_text": f"{comment} acceptance\n"}),
        ("rename", {"operation": "rename", "name_path": name_path, "new_name": name + "_acceptance"}),
    ]
    for label, arguments in edits:
        report.check(language, f"{label} (dry run)", lambda a=arguments: (lambda t: ("Dry run" in t, t.splitlines()[0][:100]))(
            client.tool("edit_file", {"path": path, "dry_run": True, **a, **SLOW}, raw=True)))
    def delete():
        reply = client.call("tools/call", {"name": "edit_file", "arguments": {"path": path, "operation": "safe_delete",
                                                                              "name_path": name_path, "dry_run": True, **SLOW}})
        text = reply["content"][0]["text"]
        # A used function must be refused; an unused one gets a dry-run diff. Both are correct answers.
        return ("Dry run" in text) or ("references outside" in text), text.splitlines()[0][:100]
    report.check(language, "safe_delete (dry run)", delete)
    report.check(language, "files unchanged", lambda: (all(digest(repo / p) == h for p, h in before.items()),
                                                       f"{len(before)} files checked"))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("executable", type=Path)
    parser.add_argument("repo", type=Path)
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--languages", default=",".join(LANGUAGES))
    parser.add_argument("--target", action="append", default=[], help="LANG=PATH::NAME")
    parser.add_argument("--at", action="append", default=[], help="PATH:LINE:COLUMN")
    parser.add_argument("--outline", action="append", default=[], help="PATH")
    args = parser.parse_args()
    targets = dict(item.split("=", 1) for item in args.target)
    repo = args.repo.resolve()
    excluded = SKIP | {name.lower() for name in args.exclude}
    # The tool calls carry timeout_ms 300000; wait a little longer than that for each reply.
    client = Client(args.executable.resolve(), repo, timeout=330)
    report = Report()
    try:
        for path in args.outline:
            report.check("given", f"outline {Path(path).name}", lambda p=path: (lambda r: (bool(r), f"{len(r)} symbols"))(
                client.tool("read_file", {"path": p, "operation": "overview", **SLOW})["results"]))
        for position in args.at:
            path, line, column = position.rsplit(":", 2)
            where = {"path": path, "line": int(line), "column": int(column), **SLOW}
            report.check("given", f"definition {line}:{column}", lambda w=where: (lambda r: (bool(r), f"-> {[(i['path'], i['line']) for i in r][:3]}"))(
                client.tool("search", {"operation": "definition", **w})["results"]))
            report.check("given", f"hover {line}:{column}", lambda w=where: (lambda h: (bool(h), json.dumps(h)[:80]))(
                client.tool("search", {"operation": "hover", **w}).get("hover")))
        for language in args.languages.split(","):
            extensions, comment = LANGUAGES[language]
            run_language(client, report, repo, language, extensions, comment, excluded, targets.get(language))
    finally:
        client.close()
    raise SystemExit(0 if report.summary() else 1)


if __name__ == "__main__":
    main()
