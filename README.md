# shgrep

grep but stupid fast. windows only. made for AI agents but you can use it too i guess.

runs on Intel Hyperscan 5.4.2 (the regex engine firewalls use). one exe, works as a CLI and as an MCP server. no index, no cache, every search reads whats actually on disk right now. you edit a file, search again, its there. wild right

if you used rg, ug or tgrep you already know how this works. regex by default, `path:line:text` output, `-l -c -w -t -C` etc.

## benchmarks

my machine: Ryzen 5 5600, 12 threads, windows 11, warm cache. big folder = 80 MB, 6,920 files, median of 5 runs. small repo = this repo, 865 files. all tools set to skip the same stuff (gitignore, hidden, binary). run it yourself with `tests/bench.py`, dont trust me

| test | **shgrep** | rg 15.1 | ug | tgrep |
| --- | --- | --- | --- | --- |
| big folder, 1 literal | 85 ms | **82 ms** | 246 ms | 1187 ms |
| big folder, 1 regex | 86 ms | **73 ms** | 283 ms | 1196 ms |
| big folder, 100 literals | **85 ms** | 87 ms | 251 ms | 1179 ms |
| big folder, 1000 literals | 97 ms | **73 ms** | 283 ms | 1231 ms |
| big folder, 100 regexes | 163 ms | **69 ms** | 283 ms | 1182 ms |
| big folder, common word, files only | **66 ms** | 81 ms | 224 ms | 1239 ms |
| big folder, common regex, files only | **77 ms** | 81 ms | 250 ms | 1403 ms |
| big folder, just walking dirs | **8 ms** | 22 ms | 55 ms (older run) | 32 ms |
| big folder, backreference | 606 ms | **106 ms** (-P) | 896 ms (-P, older run) | 108 ms (-P) |
| big folder, files found with "return" | 3712 | 3712 | 3649 (skips Latin-1) | 3712 |
| small repo, 1 literal | 56 ms | not tested | not tested | **50 ms** |
| small repo, 1 regex | 56 ms | not tested | not tested | **52 ms** |
| small repo, 40 regexes | 52 ms | not tested | not tested | **51.5 ms** |
| find 1 mp3 on all of C: | **6.2 s** | not tested | 24.4 s | not tested |

honest take: rg is the real boss. we beat it on listing files and walking dirs, tie on plain literals, and it beats us on regex-heavy stuff and backreferences. part of that is the CLI recompiling patterns every run (the MCP server caches them, the CLI doesnt), part is Chimera being slow when the pattern has no literal to grab onto. ug and tgrep (`--no-index`) are just slower here. tgrep with its index wasnt tested.

## build

you need VS 2026 Build Tools dev powershell, CMake, Ninja, Ragel 6.9, Python, Boost headers, OpenSSL. CMake 3.31 doesnt know VS 2026 so its Ninja.

```powershell
& 'C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\Launch-VsDevShell.ps1' -Arch amd64 -HostArch amd64
cmake -S . -B build-ninja -G Ninja -DCMAKE_BUILD_TYPE=Release '-DBOOST_ROOT=C:/Users/Simeon/Documents/boost-1.92.0'
cmake --build build-ninja --target shgrep
cmake --install build-ninja --prefix "$PWD\dist" --component shgrep
```

- builds hyperscan for AVX2 (`-DSHGREP_HS_ARCH=AVX2`). `AVX512` if you have it, `SSE` if your pc is ancient. hyperscan's cmake gives MSVC no cpu flags at all so normally you get the slow path and nobody tells you. fixed. old cpu gets an error, not a crash
- backreferences and lookaround use Chimera (hyperscan + PCRE). needs PCRE 8.41+ in `libs/pcre-8.45/` or `-DSHGREP_PCRE_SOURCE=DIR`. no PCRE = still builds, those patterns just fail
- `libs/` has only the parts of Hyperscan 5.4.2 and PCRE 8.45 the build needs, plus small cmake fixes marked `COMPAT`
- ship `dist/shgrep.exe` alone, everything is static. `shgrep.exe --license` for the hyperscan license

## MCP

run `shgrep.exe --root C:\work`. requests can narrow roots, never widen them. stdout is JSON-RPC only, logs on stderr.

| tool | for | rg version |
| --- | --- | --- |
| `search` | text in code | `rg PATTERN` |
| `search_bytes` | raw bytes in any file | they cant |
| `find_files` | files by name, never opens them | `rg --files` |

| `search` arg | rg | default |
| --- | --- | --- |
| `pattern` / `patterns` | `PATTERN` / `-e` | required, many patterns still one pass |
| `mode: "literal"` | `-F` | `"regex"`, PCRE syntax, ^ and $ per line, backrefs and lookaround ok |
| `case_insensitive` | `-i` | false |
| `word` | `-w` | false |
| `output: "files"` / `"count"` | `-l` / `-c` | `"lines"` |
| `context_lines` / `before_lines` / `after_lines` | `-C` / `-B` / `-A` | 0 |
| `line_numbers: false` | `-N` | true |
| `types` | `-t` | all |
| `include` / `exclude` | `-g` / `-g !` | none |
| `max_matches_per_file` | `-m` | 20 lines |
| `hidden`, `no_ignore` | `--hidden`, `--no-ignore` | false |

all tools also take `roots`, `extensions`, `path_filter`, `max_results` (100, counts lines, or files for files/count/find_files), `max_output_bytes` (65536), `timeout_ms` (30000, find_files 300000). `find_files` wants `exact_name`, `substring` or `glob`. `search_bytes` takes hex like `"4d5a"` or byte regex and returns JSON.

globs match the WHOLE path or WHOLE filename, case-insensitive. `"*parser*"` works, `"parser.cpp"` only matches exactly `parser.cpp`. this already broke one of our tests. file types: `asm bat c cmake cpp cs css go h html java js json lua make md msbuild proto ps py rust sh sql toml ts txt xml yaml`, plus `python`, `rs`, `csharp`, `powershell`.

### output

```
C:\work\src\net.cpp-41-    // reconnect
C:\work\src\net.cpp:42:    retry_connect(socket);
--
C:\work\src\net.cpp:97:    retry_connect(other);
```

`:` match, `-` context, `--` gap (only with context). lines over 400 bytes get cut around the match with `...`.

finished clean? nothing extra printed. if results might be incomplete it says so, so your agent doesnt confidently lie about "no other usages":

```
No matches. Scanned 1,204 files in 85 ms. Roots: C:\work
[status limit: stopped at max_results=100; more matches may exist. Narrow the search or raise max_results.]
```

| status | means |
| --- | --- |
| `limit` | hit `max_results` |
| `per_file_limit` | a file had too many hits |
| `output_limit` | hit `max_output_bytes` |
| `partial_files` | some files unreadable or over `max_file_bytes` |
| `timeout` / `cancelled` | stopped early, partial |

`output: "json"` gives full objects (path, line, byte offsets, `pattern_id`, context) plus a `summary`.

## CLI

```powershell
shgrep search "TODO|FIXME" -t cpp -C 2
shgrep search -F "operator<<" --root C:\work -l
shgrep search -e open -e close -w -c
shgrep search_bytes --root .\dist --pattern 4d5a --include shgrep.exe
shgrep find_files AISHITERU.mp3 --whole
```

flags: `-F -E -i -w -e -l -c -A -B -C -N -m -t -g`, plus `--root DIR` (repeatable), `--whole` (entire drive), `--exclude`, `--extension`, `--path-filter`, `--hidden`, `--no-ignore`, `--max-results`, `--max-output-bytes`, `--timeout-ms`, `--max-file-bytes`, `--output MODE`, `--json`. no `--root` means current folder. exit codes: `0` ran, `2` bad args or broke, `3` timeout/cancel.

## how it works

- one thread per logical cpu. every directory listed through one handle, no per-file metadata calls
- respects `.gitignore` and `.ignore` (`*`, `?`, `**`, `/`, `!`). no `[...]` or backslash escapes yet
- skips hidden stuff unless `hidden`
- never follows junctions or symlinks. access denied folders get skipped quietly
- files open relative to their parent folder handle, so you cant escape the root even by swapping in a junction mid-search. also way faster than the old path check
- binary files get detected from the first 64 KiB and skipped without reading the rest. text: UTF-8, UTF-8 BOM, UTF-16 BOM. files over 64 MiB get reported as skipped (max 256 MiB)
- all patterns compile into one hyperscan database, each file scanned once. block mode for text, 1 MiB streaming for `search_bytes`. literal compiler for literals. start-of-match tracking only when actually needed. patterns hyperscan refuses fall back to Chimera automatically. compiled databases are cached in the server, file contents and results never are

## does it work tho

no one knows

## flex on ug yourself

```powershell
python tests/bench.py "C:\path\to\big\folder" --runs 5
```
