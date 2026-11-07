# shgrep

i started shgrep because i wanted agents to grab useful code without eating their context
then it turned into something handy for normal searches too
so yeah you can navigate a codebase or find that mp3 buried somewhere on your drive

it uses LSP servers for code navigation and supports multiple repos and solutions at once
there’s keyword ranking plus optional embedded models for finding code by meaning
the idea is fast searches and accurate results without throwing a wall of text at you

under the hood it’s C++26 with Intel Hyperscan PCRE2 and Boost

## the calls are kinda adorable

models can call tools with this little syntax
```
s::<3::fs~>find_files()
```

## What you get

- Symbols, definitions, references, implementations, and code edits through language servers.
- Filename searches, regular expressions, plain text, and binary searches.
- Matching lines, nearby context, whole code blocks, or JSON.
- Result limits and ranking to keep large searches manageable.
- A persistent C++ REPL for agent workflows.

Ranked searches use BM25, which scores matches against your search intent.
The optional GPU build adds embedded models for searching by meaning.
You can also connect a local reranker through SHGREP_RERANK_PORT.

## Getting started

You’ll need Windows x64 and a package that supports your CPU.
Keep these three files together, from the same build:

shgrep.exe
shgrep-compiler.dll
shgrep.dat

Keep the licenses folder too.
Add the package folder to PATH to use shgrep from any terminal.

Code navigation needs the right language server and your project’s dependencies.
There’s a download helper in the package:

python C:\tools\shgrep\tools\fetch_lsp.py C:\tools\shgrep

C# support needs the Roslyn server and .NET 10 SDK.
The C++ REPL needs MSVC tools, Windows SDK, and Visual C++ Redistributable.

Warning: C++ REPL cells run with your Windows account’s permissions.

## Using it from a terminal

Find TODOs in text files, with two lines of context:

shgrep search "TODO|FIXME" --root C:\work\repo -t txt -C 2

Find MP3s anywhere on your current drive:

shgrep find_files --glob "*.mp3" --whole

Look for solutions across a couple of folders:

shgrep find_files --glob "*.sln" --root C:\work --root D:\projects

Search executable files for a byte pattern:

shgrep search_bytes --pattern 4d5a --root C:\work --include "*.exe"

A few useful flags:

- -F searches plain text instead of regular expressions.
- -i ignores letter case.
- --json gives you structured output.
- --max-results limits how many results come back.
- --max-output-bytes caps the output size.

Programming files use LSP.
Raw text fallback needs --allow-text-fallback when LSP fails or isn’t available.

For the full command list or dependency licenses:

shgrep --help
shgrep --license

## Connecting an agent

Add shgrep as a STDIO server in your MCP client.
Replace the example paths with your own:

{
  "mcpServers": {
    "shgrep": {
      "command": "C:\\tools\\shgrep\\shgrep.exe",
      "args": [
        "--root", "C:\\work\\repo-a",
        "--root", "C:\\work\\repo-b"
      ]
    }
  }
}

The first root is your default workspace and gets the live search index.
Name the other roots explicitly when you want to search them.

Put your exclusions in .shignore.
It uses .gitignore syntax and takes priority over .gitignore and .ignore.
Check .shgrep/index.log for index and language-server startup progress.

Your agent can request the full manual through the lsp tool:

{"method":"help","arguments":{"topic":"manual"}}

## Building it yourself

You’ll need:

- Visual Studio C++ Build Tools, Windows SDK, and a current MSVC standard library.
- CMake 3.25 or newer, plus Ninja.
- LLVM 23.1 development SDK, including Clang, LLD, and clangInterpreter.

The current setup uses LLVM 23.1.4 and MSVC 14.51.
The LLVM SDK needs its headers, libraries, and CMake packages—not just compiler executables.

The dependency sources belong here:

libs/hyperscan-5.4.2/
libs/boost-1.92.0/
libs/pcre2-10.49/

Open an x64 Developer PowerShell in the source folder.
Change the LLVM path below if yours is different:

$llvmRoot = 'C:/llvm23.1.4'

cmake -S . -B build -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  "-DCMAKE_C_COMPILER=$llvmRoot/bin/clang-cl.exe" `
  "-DCMAKE_CXX_COMPILER=$llvmRoot/bin/clang-cl.exe" `
  "-DCMAKE_LINKER=$llvmRoot/bin/lld-link.exe" `
  "-DSHGREP_LLVM_ROOT=$llvmRoot" `
  -DSHGREP_HS_ARCH=AVX2

cmake --build build --target shgrep

Warning: This configuration needs an AVX2-capable CPU.
Use -DSHGREP_HS_ARCH=SSE for the baseline build.

To make the portable ZIP:

cmake --build build --target portable_zip

### Optional GPU build

For embedded meaning search, use a separate build folder: -B build-rocm.
Reuse the configure command above and add these options:

-DSHGREP_EMBED=ON
-DSHGREP_LLAMA_ROOT=C:/llama.cpp-0.9.0
-DSHGREP_LLAMA_BIN=C:/llama.cpp-0.9.0/build-hip/bin
-DSHGREP_EMBED_MODEL_FILE=C:/models/embedding.gguf

This needs a HIP-enabled llama.cpp build and a compatible embedding model.
Then build it:

cmake --build build-rocm --target shgrep

Keep the copied GPU runtime DLLs and embedding.gguf beside that build’s executable.

## benchmarks

tested on one C++ repo with 249 files and 112 questions about the code
MRR@5 rewards getting the correct file closer to the top of five results

| setup | MRR@5 ↑ |
|---|---:|
| BM25 with shgrep settings | 0.680 |
| sweet-search | 0.711 |
| EmbeddingGemma 2 | 0.734 |
| experimental 80% Gemma + 20% BM25 mix | 0.780 |

these are ranking experiments from November 4 2026
the mix was tuned on these same questions so it still needs checking elsewhere
current-build search speed needs separate measurements
