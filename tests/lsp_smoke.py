"""User-run protocol checks; no installed language server needed.
Usage: python tests/lsp_smoke.py dist/shgrep.exe
The mock checks transport/synchronization/ranges, not any real language server's semantics.
"""
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from laya_fixture import REGRESSION_INTENT, RegressionLaya, strip_selection


def units(text):
    return len(text.encode("utf-16-le")) // 2


def pos(line, column):
    return {"line": line, "character": column}


def mock():
    documents = {}
    events = []
    # --index: answer like a server with its own index. Unopened files come from a deliberately stale view (one
    # line shifted), so edits planned from it are wrong until the client opens the file and asks again.
    indexed = "--index" in sys.argv
    root_dir = None

    def selected_name(params):
        document = documents[params["textDocument"]["uri"]]
        line = document["text"].splitlines()[params["position"]["line"]]
        column = params["position"]["character"]
        for match in re.finditer(r"\w+", line):
            if units(line[:match.start()]) <= column < units(line[:match.end()]):
                return match[0]
        raise AssertionError((line, column))

    def diagnostics(uri):
        document = documents[uri]
        items = [{"range": {"start": pos(0, 0), "end": pos(0, 1)}, "severity": 1, "message": "mock syntax error"}] if "--ERROR" in document["text"] else []
        send({"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics",
              "params": {"uri": uri, "version": document["version"], "diagnostics": items}})
        return items

    def send(message):
        payload = json.dumps(message, ensure_ascii=False).encode("utf-8")
        frame = b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
        # Fragment framing and multibyte text to exercise the client's exact reads.
        for offset in range(0, len(frame), 97):
            sys.stdout.buffer.write(frame[offset:offset + 97])
            sys.stdout.buffer.flush()

    def tree(uri):
        text = documents[uri]["text"]
        lines = text.splitlines()
        children = []
        for index, line in enumerate(lines):
            match = re.search(r"function (\w+)\(", line)
            if not match:
                continue
            end = next(i for i in range(index + 1, len(lines)) if lines[i] == "end")
            children.append({
                "name": match[1], "kind": 12,
                "range": {"start": pos(index, units(line[:match.start()])), "end": pos(end, 3)},
                "selectionRange": {"start": pos(index, units(line[:match.start(1)])),
                                   "end": pos(index, units(line[:match.end(1)]))},
            })
        end = pos(text.count("\n"), 0) if text.endswith("\n") else pos(len(lines) - 1, units(lines[-1]))
        return [{"name": "root", "kind": 3, "range": {"start": pos(0, 0), "end": end},
                 "selectionRange": {"start": pos(0, 0), "end": pos(0, 0)}, "children": children}]

    content_modified_sent = False
    while True:
        headers = {}
        while True:
            line = sys.stdin.buffer.readline()
            if not line:
                return
            if line == b"\r\n":
                break
            name, value = line.decode("ascii").split(":", 1)
            headers[name.lower()] = value.strip()
        length = int(headers["content-length"])
        data = bytearray()
        while len(data) < length:
            chunk = sys.stdin.buffer.read(length - len(data))
            if not chunk:
                return
            data.extend(chunk)
        request = json.loads(data)
        method, params = request.get("method"), request.get("params", {})
        request_id = request.get("id")
        if method is None:  # Client response to workspace/configuration.
            if request_id == "register":
                assert request["result"] is None
                continue
            assert request_id == "config"
            assert request["result"] == [{"live": True}]
            send({"jsonrpc": "2.0", "id": initialize_id, "result": {"capabilities": {
                "textDocumentSync": {"openClose": True, "change": 2, "save": {"includeText": True}},
                "documentSymbolProvider": True, "definitionProvider": True, "referencesProvider": True,
                "implementationProvider": True, "typeDefinitionProvider": True, "hoverProvider": True,
                "renameProvider": {"prepareProvider": True},
                "diagnosticProvider": False if "--push-only" in sys.argv else {"interFileDependencies": False, "workspaceDiagnostics": False},
                "workspace": {"fileOperations": {"willRename": {"filters": [{"pattern": {"glob": "**/*.lua"}}]},
                                                 "didRename": {"filters": [{"pattern": {"glob": "**/*.lua"}}]},
                                                 "didCreate": {"filters": [{"pattern": {"glob": "**/*.lua"}}]}}},
                "positionEncoding": "utf-16",
            }}})
            continue
        if method == "initialize":
            initialize_id = request_id
            root_uri = params.get("rootUri") or ""
            root_dir = urllib.parse.unquote(root_uri[8:]) if root_uri.startswith("file:///") else None
            send({"jsonrpc": "2.0", "id": "config", "method": "workspace/configuration",
                  "params": {"items": [{"section": "mock"}]}})
            continue
        if method == "initialized":
            send({"jsonrpc": "2.0", "id": "register", "method": "client/registerCapability", "params": {
                "registrations": [{"id": "declaration", "method": "textDocument/declaration", "registerOptions": {}}]}})
        elif method in {"textDocument/didSave", "workspace/didCreateFiles", "workspace/didRenameFiles"}:
            events.append(method)
            if method == "textDocument/didSave":
                assert documents[params["textDocument"]["uri"]]["text"] == params["text"]
        elif method == "textDocument/didOpen":
            document = params["textDocument"]
            documents[document["uri"]] = {"text": document["text"], "version": document["version"]}
            diagnostics(document["uri"])
        elif method == "textDocument/didChange":
            document = documents[params["textDocument"]["uri"]]
            assert params["textDocument"]["version"] > document["version"]
            change = params["contentChanges"][0]
            assert change["range"]["start"] == pos(0, 0)
            old = document["text"]
            end = pos(old.count("\n"), 0) if old.endswith("\n") else pos(len(old.splitlines()) - 1, units(old.splitlines()[-1]))
            assert change["range"]["end"] == end
            document.update(text=change["text"], version=params["textDocument"]["version"])
            diagnostics(params["textDocument"]["uri"])
        elif method == "textDocument/didClose":
            documents.pop(params["textDocument"]["uri"])
        elif method == "textDocument/documentSymbol":
            uri = params["textDocument"]["uri"]
            if not content_modified_sent:
                content_modified_sent = True
                send({"jsonrpc": "2.0", "id": request_id,
                      "error": {"code": -32801, "message": "Content modified."}})
                continue
            hang = re.search(r"--HANG(\d*)", documents[uri]["text"])
            if hang:
                time.sleep(int(hang[1] or 10))
            result = tree(uri)
        elif method in {"textDocument/definition", "textDocument/declaration", "textDocument/typeDefinition", "textDocument/implementation"}:
            uri = params["textDocument"]["uri"]
            target = next(x for x in tree(uri)[0]["children"] if x["name"] == "alpha")
            result = [{"targetUri": uri.lower(), "targetRange": target["range"], "targetSelectionRange": target["selectionRange"]}]
        elif method == "textDocument/references":
            result = []
            name = selected_name(params)
            for uri, document in documents.items():
                for index, line in enumerate(document["text"].splitlines()):
                    for match in re.finditer(r"\b" + re.escape(name) + r"\(", line):
                        if "function " + name + "(" in line and not params["context"]["includeDeclaration"]:
                            continue
                        result.append({"uri": uri.lower(), "range": {
                            "start": pos(index, units(line[:match.start()])),
                            "end": pos(index, units(line[:match.start()]) + units(name))}})
            if name == "alpha":
                result.append({"uri": "file:///Z:/outside-shgrep-test.lua",
                               "range": {"start": pos(0, 0), "end": pos(0, 1)}})
                result.append({"uri": next(iter(documents)).rsplit("/", 1)[0] + "/missing.lua",
                               "range": {"start": pos(0, 0), "end": pos(0, 1)}})
                result.append({"uri": next(iter(documents)).rsplit("/", 1)[0] + "/ignored/use.lua",
                               "range": {"start": pos(0, 0), "end": pos(0, 1)}})
        elif method == "textDocument/hover":
            result = {"contents": {"kind": "plaintext", "value": selected_name(params) + " " + ",".join(events)}}
        elif method == "textDocument/diagnostic":
            result = {"kind": "full", "items": diagnostics(params["textDocument"]["uri"])}
        elif method == "textDocument/prepareRename":
            result = {"defaultBehavior": True}
        elif method == "textDocument/rename":
            if "--SLOWRENAME" in documents[params["textDocument"]["uri"]]["text"]:
                time.sleep(2)
            name = selected_name(params)
            result = {"documentChanges": []}
            for uri, document in documents.items():
                edits = []
                for line_index, line in enumerate(document["text"].splitlines()):
                    for match in re.finditer(r"\b" + re.escape(name) + r"\b", line):
                        edits.append({"range": {"start": pos(line_index, units(line[:match.start()])),
                                                "end": pos(line_index, units(line[:match.end()]))},
                                      "newText": params["newName"]})
                if edits:
                    if params["newName"] == "OVERLAP":
                        edits.append(edits[0].copy())
                    result["documentChanges"].append({"textDocument": {"uri": uri.lower(),
                        "version": document["version"] - (1 if params["newName"] == "STALE" else 0)}, "edits": edits})
            if params["newName"] == "OUTSIDE":
                result["documentChanges"].append({"textDocument": {"uri": "file:///Z:/outside.lua", "version": None}, "edits": []})
            if params["newName"] == "RESOURCE":
                result["documentChanges"].append({"kind": "rename", "oldUri": params["textDocument"]["uri"], "newUri": "file:///Z:/other.lua"})
            if params["newName"] == "IGNORED":
                ignored_uri = next(iter(documents)).rsplit("/", 1)[0] + "/ignored/use.lua"
                result["documentChanges"].append({"textDocument": {"uri": ignored_uri, "version": None},
                                                  "edits": [{"range": {"start": pos(0, 0), "end": pos(0, 1)},
                                                             "newText": "blocked"}]})
        elif method == "workspace/willRenameFiles":
            before = params["files"][0]["oldUri"].rsplit("/", 1)[-1].removesuffix(".lua")
            after = params["files"][0]["newUri"].rsplit("/", 1)[-1].removesuffix(".lua")
            result = {"changes": {}}
            views = dict(documents)
            if indexed and root_dir:
                opened = {urllib.parse.unquote(uri[8:]).lower() for uri in documents}
                for path in Path(root_dir).rglob("*.lua"):
                    if ".shgrep" in path.parts or path.as_posix().lower() in opened:
                        continue
                    views["file:///" + urllib.parse.quote(path.as_posix())] = {"text": "\n" + path.read_text(encoding="utf-8-sig")}
            for uri, document in views.items():
                edits = []
                for index, line in enumerate(document["text"].splitlines()):
                    for match in re.finditer(re.escape('require("' + before + '")'), line):
                        edits.append({"range": {"start": pos(index, units(line[:match.start()])),
                                                "end": pos(index, units(line[:match.end()]))},
                                      "newText": 'require("' + after + '")'})
                if edits:
                    result["changes"][uri.lower()] = edits
        elif request_id is not None:
            send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": method}})
            continue
        if request_id is not None:
            send({"jsonrpc": "2.0", "id": request_id, "result": result})


class Client:
    def __init__(self, executable, root, stderr=None, arguments=(), cwd=None, timeout=20, regression_laya=True, environment=None):
        self.laya = RegressionLaya() if regression_laya else None
        environment = self.laya.environment() if self.laya else environment
        self.process = subprocess.Popen([str(executable), "--root", str(root), *arguments], cwd=cwd,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, env=environment)
        self.timeout = timeout  # seconds to wait for one reply; real servers on cold repos need minutes
        self.messages = queue.Queue()
        self.next_id = 0
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.call("initialize", {"protocolVersion": "2025-06-18"})

    def _read(self):
        for line in self.process.stdout:
            try:
                self.messages.put(json.loads(line))
            except Exception as error:
                self.messages.put(error)

    def call(self, method, params):
        if self.laya and method == "tools/call" and params.get("name") == "search" and params.get("arguments", {}).get("operation") == "text":
            params = {**params, "arguments": {"intent": REGRESSION_INTENT, **params["arguments"]}}
        self.next_id += 1
        request = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
        self.process.stdin.write(json.dumps(request).encode() + b"\n")
        self.process.stdin.flush()
        while True:
            response = self.messages.get(timeout=self.timeout)
            assert isinstance(response, dict), response
            # A reply to a request that already timed out here is stale; skip it instead of misreading it.
            if isinstance(response.get("id"), int) and response["id"] < self.next_id:
                continue
            assert response["id"] == self.next_id and "error" not in response, response
            return response["result"]

    def tool(self, name, arguments, error=False, raw=False):
        if name == "search" and arguments.get("operation") == "text":
            arguments = {"intent": REGRESSION_INTENT, **arguments}
        # Overviews default to compact text; parsed checks ask for the json form.
        overview = name in ("read_file", "list_dir") and not any(k in arguments for k in ("name_path", "offset", "limit")) and \
            arguments.get("operation", "overview" if name == "list_dir" else "auto") in ("auto", "overview")
        if overview and not raw and not error and "format" not in arguments and \
                (name == "read_file" or arguments.get("operation") == "overview"):
            arguments = {**arguments, "format": "json"}
        result = self.call("tools/call", {"name": name, "arguments": arguments})
        assert bool(result.get("isError")) == error, result
        text = result["content"][0]["text"]
        if self.laya and not error:
            text = strip_selection(text)
        return text if raw or error else json.loads(text)

    def close(self):
        self.process.stdin.close()
        try:
            assert self.process.wait(timeout=10) == 0
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise
        finally:
            if self.laya:
                self.laya.close()


def exercise_extended(client, root):
    # All ten existing tools share lifecycle state, without adding tool names.
    status = client.tool("file_info", {"path": "code.lua", "operation": "lsp"})
    assert status["language_id"] == "lua" and status["open_documents"] >= 1
    assert "size:" in client.tool("file_info", {"path": "code.lua"}, raw=True)
    for operation in ("declaration", "type_definition", "implementation"):
        assert client.tool("search", {"operation": operation, "path": "code.lua", "name_path": "alpha"})["results"]
    info = client.tool("search", {"path": "code.lua", "pattern": "alpha", "include_info": True})
    assert "alpha" in info["results"][0]["info"]["contents"]["value"]
    assert not client.tool("search", {"path": "code.lua", "pattern": "/alpha"})["results"]
    assert client.tool("search", {"path": "code.lua", "pattern": "root/pha", "substring_matching": True})["results"]
    assert not client.tool("search", {"path": "code.lua", "pattern": "roo/alpha", "substring_matching": True})["results"]
    children = client.tool("search", {"path": "code.lua", "pattern": "/root", "depth": 1})
    assert {item["name_path"] for item in children["results"]} >= {"root", "root/alpha", "root/caller"}
    complete_outline = client.tool("read_file", {"path": "code.lua", "operation": "overview"})
    assert {item["name_path"] for item in complete_outline["results"]} >= {"root", "root/alpha", "root/caller"}
    shallow_outline = client.tool("read_file", {"path": "code.lua", "operation": "overview", "depth": 0})
    assert [item["name_path"] for item in shallow_outline["results"]] == ["root"]
    assert not client.tool("search", {"path": "code.lua", "pattern": "alpha", "exclude_kinds": [12]})["results"]

    client.tool("create_directory", {"path": "subdir"}, raw=True)
    client.tool("write_file", {"path": "subdir/refactor.lua", "content": "function target()\n    return 1\nend\n"}, raw=True)
    client.tool("write_file", {"path": "subdir/use.lua", "content": "function usage()\n    return target()\nend\n"}, raw=True)
    overview = client.tool("list_dir", {"path": "subdir", "operation": "overview", "depth": 1})
    assert {item["path"] for item in overview["results"]} == {"subdir/refactor.lua", "subdir/use.lua"}
    configured = client.tool("find_files", {"operation": "lsp", "path": "subdir"})
    assert {item["path"] for item in configured["results"]} == {"subdir/refactor.lua", "subdir/use.lua"}
    matching = client.tool("find_files", {"operation": "symbols", "path": "subdir", "pattern": "target"})
    assert [item["path"] for item in matching["files"]] == ["subdir/refactor.lua"]
    target = root / "subdir/refactor.lua"
    usage = root / "subdir/use.lua"
    before, use_before = target.read_bytes(), usage.read_bytes()
    for new_name in ("OUTSIDE", "OVERLAP", "STALE", "RESOURCE", "IGNORED"):
        client.tool("edit_file", {"operation": "rename", "path": "subdir/refactor.lua",
                                 "name_path": "target", "new_name": new_name}, error=True)
        assert target.read_bytes() == before and usage.read_bytes() == use_before
    client.tool("edit_file", {"operation": "safe_delete", "path": "subdir/refactor.lua", "name_path": "target"}, error=True)
    client.tool("edit_file", {"operation": "rename", "path": "subdir/refactor.lua", "name_path": "target",
                             "new_name": "renamed", "dry_run": True}, raw=True)
    assert target.read_bytes() == before and usage.read_bytes() == use_before

    # A later read-only target must fail the entire preflight before earlier files are committed.
    import stat
    os.chmod(usage, stat.S_IREAD)
    try:
        client.tool("edit_file", {"operation": "rename", "path": "subdir/refactor.lua",
                                 "name_path": "target", "new_name": "renamed"}, error=True)
        assert target.read_bytes() == before and usage.read_bytes() == use_before
    finally:
        os.chmod(usage, stat.S_IREAD | stat.S_IWRITE)
    client.tool("edit_file", {"operation": "rename", "path": "subdir/refactor.lua",
                             "name_path": "target", "new_name": "renamed"}, raw=True)
    assert b"renamed()" in target.read_bytes() and b"renamed()" in usage.read_bytes()
    client.tool("edit_file", {"path": "subdir/refactor.lua", "name_path": "renamed", "operation": "insert_before",
                             "new_text": "function before()\n    return 2\nend\n"}, raw=True)
    client.tool("edit_file", {"path": "subdir/refactor.lua", "name_path": "renamed", "operation": "insert_after",
                             "new_text": "function after()\n    return 3\nend\n"}, raw=True)
    assert target.read_text().index("before()") < target.read_text().index("renamed()") < target.read_text().index("after()")
    client.tool("edit_file", {"path": "subdir/refactor.lua", "name_path": "before", "operation": "safe_delete"}, raw=True)
    assert b"function before()" not in target.read_bytes()

    # Layout matches Serena: inserted symbols keep a blank line from their neighbour; a deleted one takes its lines
    # and the blank lines after it, so the gap before it remains.
    layout = root / "subdir" / "layout.lua"
    one, two = "function one()\n    return 1\nend\n", "function two()\n    return 2\nend\n"
    layout.write_text(one + "\n" + two, encoding="utf-8")
    client.tool("edit_file", {"path": "subdir/layout.lua", "name_path": "two", "operation": "insert_before",
                             "new_text": "function mid()\n    return 0\nend\n"}, raw=True)
    mid = "function mid()\n    return 0\nend\n"
    assert layout.read_text(encoding="utf-8") == one + "\n" + mid + "\n" + two, layout.read_text(encoding="utf-8")
    client.tool("edit_file", {"path": "subdir/layout.lua", "name_path": "two", "operation": "insert_after",
                             "new_text": "function last()\n    return 3\nend\n"}, raw=True)
    last = "function last()\n    return 3\nend\n"
    assert layout.read_text(encoding="utf-8") == one + "\n" + mid + "\n" + two + "\n" + last, layout.read_text(encoding="utf-8")
    client.tool("edit_file", {"path": "subdir/layout.lua", "name_path": "mid", "operation": "safe_delete"}, raw=True)
    assert layout.read_text(encoding="utf-8") == one + "\n" + two + "\n" + last, layout.read_text(encoding="utf-8")

    # Duplicate sibling symbols are individually readable and editable.
    client.tool("write_file", {"path": "overload.lua", "content": "function repeated()\n    return 1\nend\nfunction repeated()\n    return 2\nend\n"}, raw=True)
    overloaded = client.tool("search", {"path": "overload.lua", "pattern": "repeated"})
    assert [item["name_path"] for item in overloaded["results"]] == ["root/repeated[0]", "root/repeated[1]"]
    client.tool("edit_file", {"path": "overload.lua", "name_path": "root/repeated[1]",
                             "new_text": "function repeated()\n    return 9\nend"}, raw=True)
    assert (root / "overload.lua").read_text().count("return 1") == 1
    assert "return 9" in client.tool("read_file", {"path": "overload.lua", "name_path": "repeated[1]"})["results"][0]["body"]

    # Pull diagnostics, symbol scoping, and normalized coordinates.
    client.tool("write_file", {"path": "problem.lua", "content": "function broken()\n    return 1\nend\n--ERROR\n"}, raw=True)
    problems = client.tool("file_info", {"path": "problem.lua", "operation": "diagnostics", "name_path": "broken"})
    assert problems["version_verified"] and problems["items"][0]["range"]["start_line"] == 1
    client.tool("edit_file", {"path": "problem.lua", "operation": "text",
                             "edits": [{"old_text": "--ERROR", "new_text": "--fixed"}]}, raw=True)
    assert not client.tool("file_info", {"path": "problem.lua", "operation": "diagnostics"})["items"]
    assert "textDocument/didSave" in client.tool("search", {"operation": "hover", "path": "problem.lua", "name_path": "broken"})["hover"]["contents"]["value"]

    # willRenameFiles edits imports and rolls those edits back when the final OS move fails.
    client.tool("write_file", {"path": "module.lua", "content": "function module()\n    return 1\nend\n"}, raw=True)
    client.tool("write_file", {"path": "import.lua", "content": 'function load()\n    return require("module")\nend\n'}, raw=True)
    import_file = root / "import.lua"
    imports_before = import_file.read_bytes()
    client.tool("move_file", {"source": "module.lua", "destination": "moved.lua", "operation": "refactor", "dry_run": True}, raw=True)
    assert (root / "module.lua").exists() and import_file.read_bytes() == imports_before
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                      wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.CreateFileW(str(root / "module.lua"), 0x80000000, 3, None, 3, 0x80, None)
        assert handle != wintypes.HANDLE(-1).value
        try:
            client.tool("move_file", {"source": "module.lua", "destination": "moved.lua", "operation": "refactor"}, error=True)
            assert import_file.read_bytes() == imports_before and (root / "module.lua").exists()
        finally:
            kernel.CloseHandle(handle)
    client.tool("move_file", {"source": "module.lua", "destination": "moved.lua", "operation": "refactor"}, raw=True)
    assert not (root / "module.lua").exists() and (root / "moved.lua").exists()
    assert 'require("moved")' in import_file.read_text()
    assert "workspace/didRenameFiles" in client.tool("search", {"operation": "hover", "path": "import.lua", "name_path": "load"})["hover"]["contents"]["value"]
    client.tool("move_file", {"source": "moved.lua", "destination": "nested/new/module.lua", "operation": "filesystem"}, raw=True)
    assert (root / "nested/new/module.lua").exists()

    # Raw byte searches and discovery are uncapped by default.
    (root / "bytes.bin").write_bytes(b"\x7f" * 1200)
    binary = client.tool("search_bytes", {"pattern": "7f", "include": ["bytes.bin"], "context_bytes": 0})
    assert len(binary["results"]) == 1200
    many = root / "many"
    many.mkdir()
    for index in range(625):
        (many / f"{index:04}.txt").write_text("hit\n", encoding="utf-8")
    assert "0624.txt" in client.tool("list_dir", {"path": "many"}, raw=True)
    assert len(client.tool("find_files", {"include": ["many/*"], "output": "json"})["results"]) == 625
    assert len(client.tool("search", {"operation": "text", "pattern": "hit", "include": ["many/*"], "output": "json"})["results"]) == 625

    # Push-only diagnostics remain usable, with a version check.
    config_path = root / ".shgrep/lsp.json"
    config = json.loads(config_path.read_text())
    config["servers"][0]["command"].append("--push-only")
    config_path.write_text(json.dumps(config), encoding="utf-8")
    client.tool("file_info", {"path": "problem.lua", "operation": "restart"})
    pushed = client.tool("file_info", {"path": "problem.lua", "operation": "diagnostics"})
    assert pushed["version_verified"] and pushed["transport"] == "publish" and not pushed["items"]


def main():
    executable = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="shgrep-lsp-") as directory:
        root = Path(directory)
        (root / ".shgrep").mkdir()
        # Servers shipped beside the executable would claim plain.xml; this run checks only the mock.
        (root / ".shgrep" / "lsp.json").write_text(json.dumps({"bundled": False, "servers": [{
            "language_id": "lua", "extensions": [".lua"],
            "ignored_paths": ["ignored/**"],
            "command": [sys.executable, str(Path(__file__).resolve()), "--mock"],
            "settings": {"mock": {"live": True}},
        }]}), encoding="utf-8")
        original = 'local face = "😀"; function alpha()\r\n    return 1\r\nend\r\nfunction caller()\r\n    return alpha()\r\nend\r\n'
        source = root / "code.lua"
        source.write_bytes(b"\xef\xbb\xbf" + original.encode())
        (root / "plain.xml").write_text("\n".join(f"<n>{i}</n>" for i in range(300)), encoding="utf-8")
        (root / "ignored").mkdir()
        (root / "ignored" / "use.lua").write_text("function ignored()\n    return alpha()\nend\n", encoding="utf-8")
        client = Client(executable, root)
        try:
            names = [x["name"] for x in client.call("tools/list", {})["tools"]]
            assert names == ["search", "search_bytes", "find_files", "read_file", "list_dir",
                             "file_info", "edit_file", "write_file", "move_file", "create_directory"]
            status = client.tool("file_info", {"path": "code.lua", "operation": "lsp"})
            assert status["open_documents"] == 1
            overview = client.tool("read_file", {"path": "code.lua"})
            assert [x["name_path"] for x in overview["results"]] == ["root", "root/alpha", "root/caller"]
            # The default overview is one line per symbol: line, kind, name_path.
            compact = client.tool("read_file", {"path": "code.lua"}, raw=True)
            assert compact.startswith("[outline code.lua | 3 symbols | mtime ") and "\n     1 namespace root\n" in compact, compact
            assert "body" not in overview["results"][0]
            functions = client.tool("search", {"path": "code.lua", "patterns": ["alpha", "caller"]})
            assert {x["name_path"] for x in functions["results"]} == {"root/alpha", "root/caller"}
            selected = client.tool("read_file", {"path": "code.lua", "name_path": "alpha"})
            assert selected["results"][0]["body"] == "function alpha()\r\n    return 1\r\nend"
            selected_hash = selected["sha256"]
            assert selected_hash == hashlib.sha256(source.read_bytes()).hexdigest()
            definitions = client.tool("search", {"operation": "definition", "path": "code.lua", "line": 5, "column": 12})
            assert definitions["results"][0]["line"] == 1
            assert definitions["results"][0]["column"] == units('local face = "😀"; function ') + 1
            references = client.tool("search", {"operation": "references", "path": "code.lua", "name_path": "alpha"})
            assert [x["symbol"] for x in references["results"]] == ["root/caller"]
            assert [x["reference_name"] for x in references["results"]] == ["alpha"]
            assert references["outside_roots"] == 1
            assert references["stale_locations"] == 1
            assert references["ignored_locations"] == 1
            assert all(item["path"] != "ignored/use.lua" for item in references["results"])
            listed = client.tool("find_files", {"operation": "lsp"})
            assert {item["path"] for item in listed["results"]} == {"code.lua"}

            # Changes with a preserved mtime must be synchronized from bytes.
            stamp = source.stat()
            modified = original.replace("return 1", 'return "' + "x" * 90000 + '"')
            source.write_bytes(b"\xef\xbb\xbf" + modified.encode())
            os.utime(source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            large_body = client.tool("read_file", {"path": "code.lua", "name_path": "alpha"})
            assert len(large_body["results"][0]["body"]) > 90000
            client.tool("edit_file", {"path": "code.lua", "name_path": "alpha",
                                     "new_text": "function alpha()\n    return 2\nend",
                                     "expected_sha256": selected_hash}, error=True)

            # Newly created/deleted files change reference results on the next request.
            extra = root / "new.lua"
            extra.write_text("function late()\n    return alpha()\nend\n", encoding="utf-8")
            references = client.tool("search", {"operation": "references", "path": "code.lua", "name_path": "alpha"})
            assert {x["symbol"] for x in references["results"]} == {"root/caller", "root/late"}
            extra.unlink()
            references = client.tool("search", {"operation": "references", "path": "code.lua", "name_path": "alpha"})
            assert [x["symbol"] for x in references["results"]] == ["root/caller"]

            before = source.read_bytes()
            replacement = "function alpha()\n    return 2\nend"
            client.tool("edit_file", {"path": "code.lua", "name_path": "root/alpha",
                                     "new_text": replacement, "dry_run": True}, raw=True)
            assert source.read_bytes() == before
            client.tool("edit_file", {"path": "code.lua", "name_path": "root/alpha",
                                     "new_text": replacement}, raw=True)
            expected = original.replace("return 1", "return 2")
            assert source.read_bytes() == b"\xef\xbb\xbf" + expected.encode()

            # Text fallback returns a default window; explicit larger reads have no byte cap.
            plain = client.tool("read_file", {"path": "plain.xml"}, raw=True)
            assert "<n>299</n>" in plain and "[status limit" not in plain
            assert "<n>299</n>" in client.tool("read_file", {"path": "plain.xml", "limit": 300}, raw=True)
            client.tool("read_file", {"path": "../escape.lua"}, error=True)

            exercise_extended(client, root)

            # A timed-out server is reported with the relay banner, the read falls back to the file's text, and the
            # server is terminated and restarted for the following request.
            source.write_bytes(source.read_bytes() + b"--HANG\r\n")
            start = time.monotonic()
            timed_out = client.tool("read_file", {"path": "code.lua", "timeout_ms": 1000}, raw=True)
            assert timed_out.startswith("[LSP FAILURE - tell the user") and "timeout_ms" in timed_out, timed_out
            assert "     7\u2192--HANG" in timed_out, timed_out
            assert time.monotonic() - start < 5
            source.write_bytes(b"\xef\xbb\xbf" + expected.encode())
            assert client.tool("read_file", {"path": "code.lua"})["backend"] == "lsp"
            print("LSP protocol, freshness, Unicode, symbol edit, output, and recovery checks passed.")
        finally:
            client.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--mock":
        mock()
    else:
        main()
