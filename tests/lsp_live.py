"""User-run checks against the LuaLS and XML servers prepared by setup_lsp.py.
Usage from workspace: python shgrep/tests/lsp_live.py shgrep/build-lsp/shgrep.exe --config .shgrep/lsp.json
Uses an isolated fixture under .shgrep/checks; never edits the game resources.
"""
import argparse
import copy
import json
from pathlib import Path
import tempfile
import xml.etree.ElementTree as ET

from lsp_smoke import Client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    executable = args.executable.resolve()
    config_path = args.config.resolve()
    workspace = Path(__file__).resolve().parents[2]
    config_path.relative_to(workspace)
    configuration = json.loads(config_path.read_text(encoding="utf-8-sig"))
    servers = [copy.deepcopy(server) for server in configuration["servers"] if server["language_id"] in {"lua", "xml"}]
    assert {server["language_id"] for server in servers} == {"lua", "xml"}, "Run setup_lsp.py first"
    checks = workspace / ".shgrep" / "checks"
    checks.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="live-", dir=checks) as directory:
        root = Path(directory)
        (root / ".shgrep").mkdir()
        for server in servers:
            if server["language_id"] == "lua":
                server["command"] = [arg for arg in server["command"] if not arg.startswith(("--logpath=", "--metapath="))]
                server["command"].extend([f"--logpath={root / '.shgrep/lua-logs'}", f"--metapath={root / '.shgrep/lua-meta'}"])
            else:
                xml_settings = server.setdefault("settings", {}).setdefault("xml", {})
                xml_settings.setdefault("server", {})["workDir"] = str(root / ".shgrep/xml-cache")
                xml_settings.setdefault("logs", {})["file"] = str(root / ".shgrep/xml-cache/lemminx.log")
                server.setdefault("initialization_options", {})["settings"] = copy.deepcopy(server["settings"])
                (root / ".shgrep/xml-cache").mkdir()
        (root / ".shgrep/lsp.json").write_text(json.dumps({"servers": servers}), encoding="utf-8")
        (root / "code.lua").write_text("function alpha()\n    return 1\nend\nfunction caller()\n    return alpha()\nend\n", encoding="utf-8")
        (root / "use.lua").write_text("function usage()\n    return alpha()\nend\n", encoding="utf-8")
        (root / "legacy-invalid.lua").write_bytes(b"-- legacy comment: \xff\r\n")
        xml = root / "data.xml"
        xml.write_text('<root>\n  <item id="a">value</item>\n</root>\n', encoding="utf-8")
        client = Client(executable, root)
        try:
            assert len(client.call("tools/list", {})["tools"]) == 10
            assert client.tool("read_file", {"path": "code.lua"})["backend"] == "lsp"
            alpha = client.tool("search", {"path": "code.lua", "pattern": "alpha"})
            assert len(alpha["results"]) == 1
            alpha_name = alpha["results"][0]["name_path"]
            references = client.tool("search", {"operation": "references", "path": "code.lua", "name_path": alpha_name})
            assert {item["path"] for item in references["results"]} >= {"code.lua", "use.lua"}, references
            assert client.tool("search", {"operation": "definition", "path": "use.lua", "line": 2, "column": 12})["results"]
            client.tool("edit_file", {"operation": "rename", "path": "code.lua", "name_path": alpha_name, "new_name": "beta"}, raw=True)
            assert "function beta()" in (root / "code.lua").read_text()
            assert "return beta()" in (root / "use.lua").read_text()
            caller = client.tool("search", {"path": "code.lua", "pattern": "caller"})["results"][0]["name_path"]
            client.tool("edit_file", {"operation": "insert_before", "path": "code.lua", "name_path": caller,
                                     "new_text": "function inserted()\n    return 2\nend\n"}, raw=True)
            assert client.tool("read_file", {"path": "code.lua", "name_path": "inserted"})["results"]
            client.tool("create_directory", {"path": "sub"}, raw=True)
            client.tool("write_file", {"path": "sub/extra.lua", "content": "function extra()\n    return beta()\nend\n"}, raw=True)
            client.tool("move_file", {"source": "use.lua", "destination": "sub/moved.lua", "operation": "filesystem"}, raw=True)
            references = client.tool("search", {"operation": "references", "path": "code.lua", "name_path": "beta"})
            assert {item["path"] for item in references["results"]} >= {"code.lua", "sub/extra.lua", "sub/moved.lua"}, references
            assert "use.lua" not in {item["path"] for item in references["results"]}
            assert client.tool("find_files", {"operation": "symbols", "pattern": "extra"})["files"]
            assert client.tool("find_files", {"operation": "lsp"})["results"]
            assert client.tool("list_dir", {"operation": "overview", "path": ".", "depth": 1})["results"]
            assert "sha256:" in client.tool("file_info", {"path": "code.lua"}, raw=True)
            assert client.tool("search_bytes", {"pattern": "62657461", "include": ["*.lua"]})["results"]

            # LemMinX supplies XML element ranges; game-specific ID relationships are outside its grammar.
            items = client.tool("search", {"path": "data.xml", "pattern": "item", "substring_matching": True})["results"]
            assert len(items) == 1, items
            item_name = items[0]["name_path"]
            selected = client.tool("read_file", {"path": "data.xml", "name_path": item_name})
            assert "<item" in selected["results"][0]["body"]
            before = xml.read_bytes()
            client.tool("edit_file", {"path": "data.xml", "name_path": item_name, "new_text": '<item id="b">changed</item>',
                                     "dry_run": True}, raw=True)
            assert xml.read_bytes() == before
            client.tool("edit_file", {"path": "data.xml", "name_path": item_name, "new_text": '<item id="b">changed</item>'}, raw=True)
            assert ET.fromstring(xml.read_text()).find("item").get("id") == "b"
            valid = xml.read_text()
            client.tool("write_file", {"path": "data.xml", "content": "<root><broken></root>", "overwrite": True}, raw=True)
            problems = client.tool("file_info", {"path": "data.xml", "operation": "diagnostics", "severity": 1})
            assert problems["items"], problems
            client.tool("write_file", {"path": "data.xml", "content": valid, "overwrite": True}, raw=True)
            assert not client.tool("file_info", {"path": "data.xml", "operation": "diagnostics", "severity": 1})["items"]
            print("Real LuaLS/XML navigation, refactoring, all-ten-tool lifecycle, and diagnostics checks passed.")
        finally:
            client.close()


if __name__ == "__main__":
    main()
