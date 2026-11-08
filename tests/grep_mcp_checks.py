"""Checks the benchmark MCP servers against the Nebula source tree."""
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import threading
import time

ROOT = Path("C:/Users/Simeon/Documents/nebula device 4")
HERE = Path(__file__).resolve().parents[1]
RG = "C:/sysinternals/rg.exe"
GIT = "C:/Program Files/Git/cmd/git.exe"
AST = ["uvx", "--from", "git+https://github.com/ast-grep/ast-grep-mcp", "ast-grep-server"]

class Client:
    def __init__(self, command, env=None):
        self.proc = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env=env)
        self.lines = queue.Queue()
        threading.Thread(target=self.read, daemon=True).start()
        self.seq = 0
        self.call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "check", "version": "1"}})
        self.notify("notifications/initialized", {})

    def read(self):
        for line in self.proc.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def notify(self, method, params):
        self.proc.stdin.write((json.dumps({"jsonrpc":"2.0","method":method,"params":params})+"\n").encode())
        self.proc.stdin.flush()

    def call(self, method, params):
        self.seq += 1
        self.proc.stdin.write((json.dumps({"jsonrpc":"2.0","id":self.seq,"method":method,"params":params})+"\n").encode())
        self.proc.stdin.flush()
        deadline = time.monotonic() + 120
        while True:
            line = self.lines.get(timeout=max(0.01, deadline-time.monotonic()))
            if line is None:
                raise RuntimeError("server stopped: " + self.proc.stderr.read().decode(errors="replace"))
            reply = json.loads(line)
            if reply.get("id") == self.seq:
                if "error" in reply:
                    raise AssertionError(reply)
                return reply["result"]

    def tool(self, name, arguments):
        return self.call("tools/call", {"name":name, "arguments":arguments})

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()

def payload(reply):
    assert not reply.get("isError"), reply
    return json.loads(reply["content"][0]["text"])

def pairs(output):
    found = set()
    for line in output.splitlines():
        match = re.match(r"^(.*?):(\d+):", line.replace("\\", "/"))
        assert match, line
        found.add((match[1].removeprefix("./"), int(match[2])))
    return found

def main():
    clients = []
    failures = []
    def check(number, fn):
        try:
            fn()
            print(f"PASS {number}", flush=True)
        except Exception as exc:
            failures.append(number)
            print(f"FAIL {number}: {type(exc).__name__}: {exc}", flush=True)

    try:
        for tool, executable in [("rg",RG),("gitgrep",GIT)]:
            clients.append(Client(["node",str(HERE/"grep-mcp.js"),"--tool",tool,"--root",str(ROOT),"--executable",executable]))
        rg, git = clients

        def listing():
            for client, tool in [(rg,"rg"),(git,"gitgrep")]:
                tools = client.call("tools/list", {})["tools"]
                assert [x["name"] for x in tools] == [tool+"_search",tool+"_files"], tools
                assert all(x["inputSchema"].get("additionalProperties") is False for x in tools)
        check(1, listing)

        actual = {}
        def rg_direct():
            actual["rg"] = payload(rg.tool("rg_search", {"pattern":"PumpPendingLoads","path":"src","flags":["-n"]}))
            direct = subprocess.run([RG,"-n","--","PumpPendingLoads","src"], cwd=ROOT, capture_output=True)
            assert direct.returncode == 0, direct.stderr
            assert actual["rg"]["stdout"].encode("utf-8") == direct.stdout, (actual["rg"]["stdout"][:200],direct.stdout[:200])
        check(2, rg_direct)

        def compare():
            left = pairs(actual["rg"]["stdout"])
            right = pairs(payload(git.tool("gitgrep_search", {"pattern":"PumpPendingLoads","path":"src","flags":["-n"]}))["stdout"])
            assert left and left == right, (left-right, right-left)
        check(3, compare)

        def no_match():
            for client, name in [(rg,"rg_search"),(git,"gitgrep_search")]:
                response = client.tool(name, {"pattern":"ZZZ_NEBULA_NO_SUCH_MATCH_872349","path":"src"})
                assert not response.get("isError") and payload(response)["exitCode"] == 1, response
        check(4, no_match)

        def refused():
            for client, name in [(rg,"rg_search"),(git,"gitgrep_search")]:
                for args in [{"path":".."},{"path":"C:/"},{"path":"src","flags":["--definitely-unknown"]}]:
                    response = client.tool(name, {"pattern":"x",**args})
                    assert response.get("isError") and not response["content"][0]["text"].startswith("{"), response
        check(5, refused)

        def regex():
            pattern = r"vkQueueSubmit2?\s*\("
            got = payload(rg.tool("rg_search", {"pattern":pattern,"path":"src","flags":["-n"]}))
            direct = subprocess.run([RG,"-n","--",pattern,"src"],cwd=ROOT,capture_output=True)
            assert got["exitCode"] == direct.returncode and sorted(got["stdout"].splitlines()) == sorted(direct.stdout.decode("utf-8").splitlines()), got
            spaced = "PumpPendingLoads *\\("
            got = payload(rg.tool("rg_search", {"pattern":spaced,"path":"src"}))
            direct = subprocess.run([RG,"--",spaced,"src"],cwd=ROOT,capture_output=True)
            assert got["exitCode"] == direct.returncode and sorted(got["stdout"].splitlines()) == sorted(direct.stdout.decode("utf-8").splitlines()), got
        check(6, regex)

        def timeout():
            import tempfile
            with tempfile.NamedTemporaryFile(prefix="grep-mcp-heavy-", suffix=".txt", dir=ROOT/"src", delete=False) as fixture:
                fixture_path = Path(fixture.name)
                for _ in range(256):
                    fixture.write((b"a" * 1023 + b"\\n") * 256)
            try:
              for client, name in [(rg,"rg_search"),(git,"gitgrep_search")]:
                response = client.tool(name, {"pattern":"a{100}z","path":str(fixture_path),"timeoutMs":100})
                data = json.loads(response["content"][0]["text"])
                assert response.get("isError") and "timed out" in data["stderr"], response
                # Parent-child identity avoids treating unrelated agent processes as leaks.
                query = subprocess.run(["powershell","-NoProfile","-Command",
                    f"Get-CimInstance Win32_Process -Filter \"ParentProcessId={client.proc.pid}\" | Select-Object -ExpandProperty Name"],
                    capture_output=True, text=True)
                assert query.returncode == 0 and not re.search(r"^(rg|git)\.exe$",query.stdout,re.I|re.M), query.stdout+query.stderr
            finally:
                fixture_path.unlink()
        check(7, timeout)

        def ast_check():
            env = os.environ.copy()
            env["PATH"] = "C:/sysinternals;" + env["PATH"]
            env["AST_GREP_PATH"] = "C:/sysinternals/sg.exe"
            ast = Client(AST, env)
            clients.append(ast)
            tools = ast.call("tools/list", {})["tools"]
            assert any(x["name"] == "find_code" for x in tools), tools
            print("AST find_code schema:",json.dumps(next(x for x in tools if x["name"]=="find_code")["inputSchema"]),flush=True)
            result = ast.tool("find_code", {"project_folder":str(ROOT), "pattern":"$OBJ.PumpPendingLoads($$$)", "language":"cpp"})
            assert not result.get("isError"), result
            text = json.dumps(result).replace("\\\\","/")
            assert "DeferredRenderer.cpp" in text and "3168" in text, result
        check(8, ast_check)
    finally:
        for client in clients:
            client.close()
    if failures:
        raise SystemExit("Failed checks: " + ", ".join(map(str,failures)))

if __name__ == "__main__":
    main()
