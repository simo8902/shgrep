"""User-run checks for the six production review fixes. Native Windows required.
Usage: python tests/review_regressions.py dist/shgrep.exe --cpp
--cpp also checks the clangd bundle beside the executable, in normal and read-only mode.
"""
import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from lsp_smoke import Client


class ReviewClient(Client):
    def __init__(self, *args, **kwargs):
        self.pending = {}
        super().__init__(*args, **kwargs)

    def send(self, method, params, request_id=None):
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        if request_id is not None:
            message["id"] = request_id
        self.process.stdin.write(json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n")
        self.process.stdin.flush()

    def begin(self, method, params):
        self.next_id += 1
        self.send(method, params, self.next_id)
        return self.next_id

    def receive(self, request_id):
        deadline = time.monotonic() + 300
        while request_id not in self.pending:
            response = self.messages.get(timeout=max(0.01, deadline - time.monotonic()))
            assert isinstance(response, dict), response
            if "id" in response:
                self.pending[response["id"]] = response
        response = self.pending.pop(request_id)
        assert "error" not in response, response
        return response["result"]

    def call(self, method, params):
        return self.receive(self.begin(method, params))


def write(root, name, text):
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def no_lsp(root):
    write(root, ".shgrep/lsp.json", json.dumps({"servers": [], "bundled": False}))


def found(client, **arguments):
    result = client.tool("find_files", {"operation": "filesystem", "output": "json", **arguments})
    return {Path(item["path"]).name for item in result["results"]}


def listed(text):
    return {line.split(" ", 2)[1] for line in text.splitlines() if line.startswith(("f ", "d ", "l "))}


def check_filters(executable):
    with tempfile.TemporaryDirectory(prefix="shgrep-filters-", ignore_cleanup_errors=True) as folder:
        root = Path(folder)
        no_lsp(root)
        for name in ("é.txt", "Ä.txt", "😀.txt", "plain.txt", "a.cpp", "b.cpp", "c.cpp"):
            write(root, name, "needle\n")
        client = ReviewClient(executable, root)
        try:
            assert found(client, glob="?.txt") == {"é.txt", "Ä.txt", "😀.txt"}
            assert found(client, glob="ä.TXT") == {"Ä.txt"}
            assert found(client, exact_name="ä.txt") == {"Ä.txt"}
            assert found(client, substring="ä") == {"Ä.txt"}
            assert found(client, path_filter="ä.txt") == {"Ä.txt"}
            assert found(client, include=["ä.txt"]) == {"Ä.txt"}
            assert "Ä.txt" not in found(client, exclude=["ä.txt"])
            result = client.tool("search", {"operation": "text", "output": "json", "pattern": "needle", "include": ["?.txt"]})
            assert {Path(item["path"]).name for item in result["results"]} == {"é.txt", "Ä.txt", "😀.txt"}

            cases = [
                ("*.cpp\n![ab].cpp\n", {"a.cpp", "b.cpp"}),
                ("*.cpp\n![a-b].cpp\n", {"a.cpp", "b.cpp"}),
                ("*.cpp\n![!ab].cpp\n", {"c.cpp"}),
                ("*.cpp\n![[:lower:]].cpp\n", {"a.cpp", "b.cpp", "c.cpp"}),
            ]
            for rules, expected in cases:
                write(root, ".gitignore", rules)
                assert found(client, glob="*.cpp") == expected, rules
                result = client.tool("search", {"operation": "text", "output": "json", "pattern": "needle", "include": ["*.cpp"]})
                assert {Path(item["path"]).name for item in result["results"]} == expected, rules
                assert {name for name in listed(client.tool("list_dir", {}, raw=True)) if name.endswith(".cpp")} == expected
            write(root, ".gitignore", "")
            write(root, ".ignore", "*.cpp\n![ab].cpp\n")
            assert found(client, glob="*.cpp") == {"a.cpp", "b.cpp"}

            write(root, ".ignore", "")
            write(root, ".gitignore", "*.log\n/sub/anchored.txt\n")
            write(root, ".ignore", "*.tmp\n")
            write(root, "sub/.gitignore", "!keep.log\n*.cpp\n")
            write(root, "sub/.ignore", "!keep.tmp\n")
            write(root, "sub/deep/.gitignore", "!a.cpp\n")
            for name in ("drop.log", "keep.log", "drop.tmp", "keep.tmp", "anchored.txt", "a.cpp", "b.cpp", "plain.txt"):
                write(root, "sub/" + name, "needle\n")
                write(root, "sub/deep/" + name, "needle\n")
            sub = listed(client.tool("list_dir", {"path": "sub"}, raw=True))
            assert sub == {"deep/", "keep.log", "keep.tmp", "plain.txt"}, sub
            deep = listed(client.tool("list_dir", {"path": "sub/deep"}, raw=True))
            assert deep == {"keep.log", "keep.tmp", "a.cpp", "anchored.txt", "plain.txt"}, deep
            recursive = listed(client.tool("list_dir", {"path": "sub", "depth": 2}, raw=True))
            assert {name.removeprefix("deep/") for name in recursive if name.startswith("deep/") and name != "deep/"} == deep
            all_items = listed(client.tool("list_dir", {"path": "sub/deep", "no_ignore": True}, raw=True))
            assert {"drop.log", "drop.tmp", "a.cpp", "b.cpp", "anchored.txt"} <= all_items
        finally:
            client.close()


def check_long_root(executable):
    with tempfile.TemporaryDirectory(prefix="shgrep-long-", ignore_cleanup_errors=True) as folder:
        plain = Path(folder)
        while len(str(plain.relative_to(Path(folder)))) < 310:
            plain /= "directory_with_a_long_name"
        # Create through the extended path, then pass the ordinary >MAX_PATH form to --root.
        extended = Path("\\\\?\\" + str(plain))
        extended.mkdir(parents=True)
        no_lsp(extended)
        write(extended, "needle.txt", "fresh needle\n")
        for configured in (plain, plain.relative_to(Path(folder))):
            client = ReviewClient(executable, configured, cwd=folder)
            try:
                assert found(client, exact_name="needle.txt") == {"needle.txt"}
                result = client.tool("search", {"operation": "text", "output": "json", "pattern": "needle"})
                assert len(result["results"]) == 1, result
                assert "fresh needle" in client.tool("read_file", {"path": "needle.txt", "operation": "text"}, raw=True)
                client.tool("write_file", {"path": "fresh.txt", "content": "new bytes\n", "overwrite": True}, raw=True)
                result = client.tool("search", {"operation": "text", "output": "json", "pattern": "new bytes"})
                assert {Path(item["path"]).name for item in result["results"]} == {"fresh.txt"}, result
            finally:
                client.close()


class Oplock:
    """Hold an exclusive oplock so a dispatched file open waits until cancellation has been processed."""
    def __init__(self, path):
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        k = self.kernel
        class Overlapped(ctypes.Structure):
            _fields_ = [("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t),
                        ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD), ("hEvent", wintypes.HANDLE)]
        k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        k.CreateFileW.restype = wintypes.HANDLE
        k.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        k.CreateEventW.restype = wintypes.HANDLE
        k.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                      wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(Overlapped)]
        k.DeviceIoControl.restype = wintypes.BOOL
        k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        k.WaitForSingleObject.restype = wintypes.DWORD
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(Overlapped)]
        k.GetOverlappedResult.argtypes = [wintypes.HANDLE, ctypes.POINTER(Overlapped), ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
        self.file = k.CreateFileW(str(path), 0x80000000, 7, None, 3, 0x40000000, None)
        assert self.file != wintypes.HANDLE(-1).value, ctypes.WinError(ctypes.get_last_error())
        self.event = k.CreateEventW(None, True, False, None)
        assert self.event, ctypes.WinError(ctypes.get_last_error())
        self.overlap = Overlapped()
        self.overlap.hEvent = self.event
        returned = wintypes.DWORD()
        granted = k.DeviceIoControl(self.file, 0x00090000, None, 0, None, 0, ctypes.byref(returned), ctypes.byref(self.overlap))
        error = ctypes.get_last_error()
        if granted or error != 997:  # ERROR_IO_PENDING means the oplock is held until another opener breaks it.
            self.close()
            raise AssertionError(f"Exclusive oplocks are required for this check (use a local NTFS fixture): {error}")

    def wait(self):
        assert self.kernel.WaitForSingleObject(self.event, 20000) == 0, "dispatched tool never opened the target"

    def close(self):
        if self.file is not None:
            self.kernel.CancelIoEx(self.file, ctypes.byref(self.overlap))
            returned = wintypes.DWORD()
            self.kernel.GetOverlappedResult(self.file, ctypes.byref(self.overlap), ctypes.byref(returned), True)
            self.kernel.CloseHandle(self.file)
            self.kernel.CloseHandle(self.event)
            self.file = None


def check_cancellation(executable):
    with tempfile.TemporaryDirectory(prefix="shgrep-cancel-", ignore_cleanup_errors=True) as folder:
        root = Path(folder)
        no_lsp(root)
        target = write(root, "target.txt", "original bytes\n")
        client = ReviewClient(executable, root)
        try:
            for name, arguments in [
                ("edit_file", {"operation": "text", "edits": [{"old_text": "original", "new_text": "changed"}]}),
                ("write_file", {"overwrite": True, "content": "changed bytes\n"}),
            ]:
                lease = Oplock(target)
                try:
                    request = client.begin("tools/call", {"name": name, "arguments": {"path": "target.txt", **arguments}})
                    lease.wait()
                    client.send("notifications/cancelled", {"requestId": request})
                    client.call("ping", {})  # barrier: the cancellation notification has been handled
                finally:
                    lease.close()
                response = client.receive(request)
                assert response.get("isError"), response
                assert "cancel" in response["content"][0]["text"].lower(), response
                assert target.read_bytes() == b"original bytes\n"
                assert not list(root.glob(".shgrep-*.tmp"))
        finally:
            client.close()


def check_cpp(executable, read_only):
    clangd = executable.parent / "lsp/clangd/bin/clangd.exe"
    assert clangd.is_file(), f"--cpp requires the clangd bundle beside {executable}"
    with tempfile.TemporaryDirectory(prefix="shgrep-cdb-", ignore_cleanup_errors=True) as folder:
        root = Path(folder)
        for project, filename, value in [("alpha", "a.cpp", 11), ("beta", "b file.cpp", 22)]:
            write(root, f"{project}/include dir/local.hpp", "inline int local_value() { return 1; }\n")
            write(root, f"{project}/{filename}", f'#if PROJECT != {value}\n#error wrong project flags\n#endif\n'
                  '#include "local.hpp"\nstatic_assert(sizeof(MESSAGE) == 10);\nint value() { return local_value(); }\n')
        arguments = ["clang++", "-DPROJECT=11", '-DMESSAGE="two words"', "-Iinclude dir", "-c", "a.cpp"]
        # Root commands take precedence even when older; commands for beta must still be present.
        root_db = [{"directory": str(root / "alpha"), "file": "a.cpp", "arguments": arguments}]
        write(root, "compile_commands.json", json.dumps(root_db))
        older = time.time() - 1000
        os.utime(root / "compile_commands.json", (older, older))
        bad_arguments = [arg.replace("PROJECT=11", "PROJECT=99") for arg in arguments]
        write(root, "alpha/build/compile_commands.json", json.dumps([
            {"directory": "..", "file": "a.cpp", "arguments": bad_arguments}]))
        beta_arguments = ["clang++", "-DPROJECT=22", '-DMESSAGE="two words"', "-Iinclude dir", "-c", "b file.cpp"]
        write(root, "beta/build/compile_commands.json", json.dumps([
            {"directory": "..", "file": "b file.cpp", "command": subprocess.list2cmdline(beta_arguments)}]))
        client = ReviewClient(executable, root, arguments=("--read-only",) if read_only else ())
        try:
            status = client.tool("file_info", {"path": "alpha/a.cpp", "operation": "lsp", "timeout_ms": 300000})
            database = status["compile_database"]
            assert database["source"] == "existing (combined)" and database["files"] == 2, database
            assert len(database["paths"]) == 3 and database["duplicate_commands"] == 1, database
            if read_only:
                assert "path" not in database, database
                assert not (root / ".shgrep/lsp-state/cpp/combined").exists()
            else:
                entries = json.loads(Path(database["path"]).read_text(encoding="utf-8"))
                assert {Path(entry["file"]).name for entry in entries} == {"a.cpp", "b file.cpp"}
                assert all(Path(entry["directory"]).is_absolute() for entry in entries)
                a = next(entry for entry in entries if Path(entry["file"]).name == "a.cpp")
                assert "-DPROJECT=11" in a["arguments"] and "-DPROJECT=99" not in a["arguments"]
            for path in ("alpha/a.cpp", "beta/b file.cpp"):
                diagnostics = client.tool("file_info", {"path": path, "operation": "diagnostics", "severity": 1,
                                                         "timeout_ms": 300000})
                assert not diagnostics["items"], (path, diagnostics)
        finally:
            client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--cpp", action="store_true")
    args = parser.parse_args()
    assert os.name == "nt", "These checks target native Windows behavior"
    executable = args.executable.resolve()
    check_filters(executable)
    check_long_root(executable)
    check_cancellation(executable)
    if args.cpp:
        check_cpp(executable, False)
        check_cpp(executable, True)
    print("Review regression checks passed" + (" (including clangd)" if args.cpp else " (clangd not requested)"))


if __name__ == "__main__":
    main()
