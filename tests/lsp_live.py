"""User-run checks against the language servers bundled by tools/fetch_lsp.py, with no .shgrep/lsp.json.
Usage: python tests/lsp_live.py dist/shgrep.exe   (after: python tools/fetch_lsp.py dist)
Rust checks are skipped when cargo is not on PATH, because rust-analyzer loads projects through it.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import xml.etree.ElementTree as ET

from lsp_smoke import Client

# Cold servers index the fixture before answering; give them the maximum deadline.
SLOW = {"timeout_ms": 300000}


def names(results):
    return {item["path"] for item in results}


def check_lua_xml(client, root):
    assert client.tool("read_file", {"path": "code.lua"})["backend"] == "lsp"
    alpha = client.tool("search", {"path": "code.lua", "pattern": "alpha"})
    assert len(alpha["results"]) == 1
    alpha_name = alpha["results"][0]["name_path"]
    references = client.tool("search", {"operation": "references", "path": "code.lua", "name_path": alpha_name})
    assert names(references["results"]) >= {"code.lua", "use.lua"}, references
    assert client.tool("search", {"operation": "definition", "path": "use.lua", "line": 2, "column": 12})["results"]
    # A rename lists whole-word mentions it does not change (here a note no language server reads).
    (root / "notes.md").write_text("alpha is called from use.lua\n", encoding="utf-8")
    renamed = client.tool("edit_file", {"operation": "rename", "path": "code.lua", "name_path": alpha_name, "new_name": "beta"}, raw=True)
    # The fixture's C++ and Python files have their own alpha, so they are listed too.
    assert "whole-word mentions of alpha in" in renamed and "the rename does not change" in renamed, renamed
    assert "notes.md:1: alpha is called from use.lua" in renamed.replace("\\", "/"), renamed
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
    assert names(references["results"]) >= {"code.lua", "sub/extra.lua", "sub/moved.lua"}, references
    assert "use.lua" not in names(references["results"])
    assert client.tool("find_files", {"operation": "symbols", "pattern": "extra"})["files"]
    assert client.tool("list_dir", {"operation": "overview", "path": ".", "depth": 1})["results"]

    # LemMinX supplies XML element ranges; game-specific ID relationships are outside its grammar.
    xml = root / "data.xml"
    items = client.tool("search", {"path": "data.xml", "pattern": "item", "substring_matching": True})["results"]
    assert len(items) == 1, items
    item_name = items[0]["name_path"]
    assert "<item" in client.tool("read_file", {"path": "data.xml", "name_path": item_name})["results"][0]["body"]
    before = xml.read_bytes()
    client.tool("edit_file", {"path": "data.xml", "name_path": item_name, "new_text": '<item id="b">changed</item>',
                             "dry_run": True}, raw=True)
    assert xml.read_bytes() == before
    client.tool("edit_file", {"path": "data.xml", "name_path": item_name, "new_text": '<item id="b">changed</item>'}, raw=True)
    assert ET.fromstring(xml.read_text()).find("item").get("id") == "b"
    valid = xml.read_text()
    client.tool("write_file", {"path": "data.xml", "content": "<root><broken></root>", "overwrite": True}, raw=True)
    assert client.tool("file_info", {"path": "data.xml", "operation": "diagnostics", "severity": 1})["items"]
    client.tool("write_file", {"path": "data.xml", "content": valid, "overwrite": True}, raw=True)
    assert not client.tool("file_info", {"path": "data.xml", "operation": "diagnostics", "severity": 1})["items"]


def check_cpp(client, root):
    status = client.tool("file_info", {"path": "a.cpp", "operation": "lsp", **SLOW})
    assert status["language_id"] == "cpp" and status["compile_database"]["source"] == "fallback", status
    symbols = client.tool("search", {"path": "a.cpp", "pattern": "alpha", **SLOW})["results"]
    assert symbols, symbols
    alpha = symbols[0]["name_path"]
    # "int caller() { return alpha(); }": alpha starts in column 23.
    assert client.tool("search", {"operation": "definition", "path": "b.cpp", "line": 2, "column": 23, **SLOW})["results"]
    references = client.tool("search", {"operation": "references", "path": "a.cpp", "name_path": alpha, **SLOW})
    assert "b.cpp" in names(references["results"]), references
    client.tool("edit_file", {"operation": "rename", "path": "a.cpp", "name_path": alpha, "new_name": "beta", **SLOW}, raw=True)
    assert "int beta()" in (root / "a.hpp").read_text() and "return beta();" in (root / "b.cpp").read_text()
    client.tool("write_file", {"path": "b.cpp", "content": "int broken( {\n", "overwrite": True}, raw=True)
    assert client.tool("file_info", {"path": "b.cpp", "operation": "diagnostics", "severity": 1, **SLOW})["items"]


def check_python(client, root):
    assert client.tool("file_info", {"path": "mod_a.py", "operation": "lsp", **SLOW})["language_id"] == "python"
    symbols = client.tool("search", {"path": "mod_a.py", "pattern": "alpha", **SLOW})["results"]
    assert symbols, symbols
    alpha = symbols[0]["name_path"]
    # "    return alpha()": alpha starts in column 12.
    assert client.tool("search", {"operation": "definition", "path": "mod_b.py", "line": 4, "column": 12, **SLOW})["results"]
    references = client.tool("search", {"operation": "references", "path": "mod_a.py", "name_path": alpha, **SLOW})
    assert "mod_b.py" in names(references["results"]), references
    client.tool("edit_file", {"operation": "rename", "path": "mod_a.py", "name_path": alpha, "new_name": "beta", **SLOW}, raw=True)
    assert "def beta()" in (root / "mod_a.py").read_text() and "return beta()" in (root / "mod_b.py").read_text()


def check_csharp(client, root):
    # OmniSharp loads app.csproj (C# 9: records, with-expressions, relational patterns) before it answers initialize.
    assert client.tool("file_info", {"path": "Person.cs", "operation": "lsp", **SLOW})["language_id"] == "csharp"
    symbols = client.tool("search", {"path": "Person.cs", "pattern": "Person", **SLOW})["results"]
    assert symbols, symbols
    use = (root / "Use.cs").read_text(encoding="utf-8").splitlines()
    line = next(number for number, text in enumerate(use, 1) if "new Person(" in text)
    column = use[line - 1].index("Person(") + 1
    definition = client.tool("search", {"operation": "definition", "path": "Use.cs", "line": line, "column": column, **SLOW})
    assert "Person.cs" in names(definition["results"]), definition
    references = client.tool("search", {"operation": "references", "path": "Person.cs", "name_path": symbols[0]["name_path"], **SLOW})
    assert "Use.cs" in names(references["results"]), references


def check_rust(client, root):
    assert client.tool("file_info", {"path": "src/main.rs", "operation": "lsp", **SLOW})["language_id"] == "rust"
    symbols = client.tool("search", {"path": "src/util.rs", "pattern": "alpha", **SLOW})["results"]
    overview = client.tool("read_file", {"path": "src/util.rs", "operation": "overview", **SLOW})
    assert symbols, (overview, client.tool("file_info", {"path": "src/util.rs", "operation": "lsp", **SLOW}))
    alpha = symbols[0]["name_path"]
    # "    util::alpha()": alpha starts in column 11.
    assert client.tool("search", {"operation": "definition", "path": "src/main.rs", "line": 4, "column": 11, **SLOW})["results"]
    references = client.tool("search", {"operation": "references", "path": "src/util.rs", "name_path": alpha, **SLOW})
    assert "src/main.rs" in names(references["results"]), references


# Each file compiles only when its build system's define reaches clangd.
GUARDED = "#ifndef {0}\n#error {0} missing\n#endif\n#include \"x.hpp\"\nint main() {{ return value(); }}\n"
HEADER = "#pragma once\ninline int value() { return 1; }\n"
VCXPROJ = """<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
    <ClCompile>
      <AdditionalIncludeDirectories>$(ProjectDir)inc;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <PreprocessorDefinitions>FROM_PROJECT;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <LanguageStandard>stdcpp20</LanguageStandard>
    </ClCompile>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClCompile Include="src\\main.cpp" />
  </ItemGroup>
</Project>
"""
CMAKE = "cmake_minimum_required(VERSION 3.20)\nproject(fixture CXX)\nadd_executable(fixture src/main.cpp)\n" \
        "target_include_directories(fixture PRIVATE inc)\ntarget_compile_definitions(fixture PRIVATE FROM_CMAKE)\n"


def check_build_system(executable, files, source, wait=False):
    """A .vcxproj or CMake workspace must compile cleanly in clangd with nothing added by the user."""
    with tempfile.TemporaryDirectory(prefix="shgrep-live-") as directory:
        root = Path(directory)
        write(root, files)
        client = Client(executable, root)
        try:
            deadline = time.monotonic() + 600
            while True:
                status = client.tool("file_info", {"path": "src/main.cpp", "operation": "lsp", **SLOW})
                if status["compile_database"]["source"] == source:
                    break
                assert wait and time.monotonic() < deadline, status
                time.sleep(5)
            errors = client.tool("file_info", {"path": "src/main.cpp", "operation": "diagnostics", "severity": 1, **SLOW})
            assert not errors["items"], errors
        finally:
            client.close()


def write(root, files):
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("executable", type=Path)
    args = parser.parse_args()
    executable = args.executable.resolve()
    manifest = executable.parent / "lsp" / "manifest.json"
    assert manifest.is_file(), f"No bundled servers beside {executable}; run: python tools/fetch_lsp.py {executable.parent}"
    installed = set(json.loads(manifest.read_text(encoding="utf-8")))
    assert installed == {"lua", "xml", "clangd", "rust", "python", "csharp"}, f"Incomplete bundle: {sorted(installed)}"
    rust = shutil.which("cargo") is not None
    # OmniSharp needs a .NET 10+ SDK; without one shgrep reports it missing instead of starting the server.
    csharp = shutil.which("dotnet") is not None or (Path(os.environ.get("ProgramFiles", "")) / "dotnet" / "dotnet.exe").is_file()
    with tempfile.TemporaryDirectory(prefix="shgrep-live-") as directory:
        root = Path(directory)
        write(root, {
            "code.lua": "function alpha()\n    return 1\nend\nfunction caller()\n    return alpha()\nend\n",
            "use.lua": "function usage()\n    return alpha()\nend\n",
            "data.xml": '<root>\n  <item id="a">value</item>\n</root>\n',
            "a.hpp": "#pragma once\nint alpha();\n",
            "a.cpp": "#include \"a.hpp\"\nint alpha() { return 1; }\n",
            "b.cpp": "#include \"a.hpp\"\nint caller() { return alpha(); }\n",
            "mod_a.py": "def alpha():\n    return 1\n",
            "mod_b.py": "from mod_a import alpha\n\ndef usage():\n    return alpha()\n",
        })
        (root / "legacy-invalid.lua").write_bytes(b"-- legacy comment: \xff\r\n")
        if csharp:
            write(root, {
                "app.csproj": '<Project Sdk="Microsoft.NET.Sdk">\n  <PropertyGroup>\n    <TargetFramework>net10.0</TargetFramework>\n'
                              '    <LangVersion>9.0</LangVersion>\n  </PropertyGroup>\n</Project>\n',
                "Person.cs": "namespace Demo\n{\n    public record Person(string Name, int Age);\n    public static class Classifier\n    {\n"
                             "        public static string Classify(Person p) => p switch\n        {\n"
                             "            { Age: < 18 } => \"minor\",\n            _ => \"adult\",\n        };\n    }\n}\n",
                "Use.cs": "namespace Demo\n{\n    public static class Use\n    {\n        public static string Run()\n        {\n"
                          "            var p = new Person(\"Ann\", 30);\n            return Classifier.Classify(p with { Age = 70 });\n"
                          "        }\n    }\n}\n",
            })
        if rust:
            write(root, {
                "Cargo.toml": '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2021"\n',
                "src/main.rs": "mod util;\n\nfn main() {\n    util::alpha();\n}\n",
                "src/util.rs": "pub fn alpha() -> i32 {\n    1\n}\n",
            })
        client = Client(executable, root)
        try:
            assert len(client.call("tools/list", {})["tools"]) == 10
            check_lua_xml(client, root)
            check_cpp(client, root)
            check_python(client, root)
            if rust:
                check_rust(client, root)
            if csharp:
                check_csharp(client, root)
            listed = {item["language_id"] for item in client.tool("find_files", {"operation": "lsp"})["results"]}
            expected = {"lua", "xml", "cpp", "python"} | ({"rust"} if rust else set()) | ({"csharp"} if csharp else set())
            assert listed == expected, listed
            status = client.tool("file_info", {"operation": "lsp", **SLOW})
            print(json.dumps([item.get("language_id") for item in status.get("results", [])]))
            print("Bundled Lua, XML, C++, Python" + (", Rust" if rust else " (Rust skipped: no cargo)") +
                  (", C#" if csharp else " (C# skipped: no .NET SDK)") +
                  " navigation, refactoring and diagnostics checks passed with no lsp.json.")
        finally:
            client.close()
    check_build_system(executable, {"app.vcxproj": VCXPROJ, "src/main.cpp": GUARDED.format("FROM_PROJECT"),
                                    "inc/x.hpp": HEADER}, "vcxproj")
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if vswhere.is_file():
        # The configure runs in the background; clangd restarts on the exact database once it lands.
        check_build_system(executable, {"CMakeLists.txt": CMAKE, "src/main.cpp": GUARDED.format("FROM_CMAKE"),
                                        "inc/x.hpp": HEADER}, "cmake", wait=True)
        print("C++ compile flags from .vcxproj and a background CMake configure checks passed.")
    else:
        print("C++ compile flags from .vcxproj passed (CMake skipped: no Visual Studio).")


if __name__ == "__main__":
    main()
