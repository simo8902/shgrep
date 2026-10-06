# shgrep

ok so. it's grep. but it goes stupid fast. on windows. for AI agents. that's it. that's the readme. (no it's not keep scrolling)

it runs on **Intel Hyperscan 5.4.2**, the regex engine they built so firewalls could scan your whole internet connection without crying. we pointed it at your source code. it's a CLI AND an MCP server, one exe, zero index, zero cache. every search reads the actual bytes on disk RIGHT NOW. you edit a file, you search again, the new stuff is there. revolutionary concept apparently.

it acts like ripgrep / ugrep / tgrep: regex by default, `path:line:text` output, `-l -c -w -t -C` all there. you already know how to use it. you were born knowing.

## numbers bro

80 MB of source, 6,920 files, one Ryzen 5 5600, median of 5 runs:

| search | **shgrep** | ug |
| --- | --- | --- |
| 1 literal | **94 ms** | 412 ms |
| 1,000 literals at once | **119 ms** | 320 ms |
| 100 regexes at once | **191 ms** | 416 ms |
| common regex, files only | **95 ms** | 303 ms |

2–4x faster than ug. 1000 patterns cost basically the same as 1. that's what hyperscan is FOR. one machine, warm cache, your mileage may vary, don't email me.

## build it (yes you have to build it, it's C++, welcome)

grab the Visual Studio 2026 Build Tools Developer PowerShell, plus CMake, Ninja, Ragel 6.9, Python, Boost headers, and OpenSSL. CMake 3.31 doesn't know VS 2026 exists yet so we use Ninja inside the MSVC environment. don't ask. it works.

```powershell
& 'C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\Launch-VsDevShell.ps1' -Arch amd64 -HostArch amd64
cmake -S . -B build-ninja -G Ninja -DCMAKE_BUILD_TYPE=Release '-DBOOST_ROOT=C:/Users/Simeon/Documents/boost-1.92.0'
cmake --build build-ninja --target shgrep
cmake --install build-ninja --prefix "$PWD\dist" --component shgrep
```

**AVX2 by default** (`-DSHGREP_HS_ARCH=AVX2`). got AVX-512BW? `AVX512`. computer from 2012? `SSE`, grandpa. fun fact: hyperscan's own CMake gives MSVC zero CPU flags, so a normal build quietly ships the slow SSSE3 paths and nobody tells you. we fixed it. if your CPU can't do AVX2 you get a polite error instead of a crash. we're not monsters.

**backreferences and lookaround** go through **Chimera**, hyperscan's secret hyperscan+PCRE hybrid that nobody uses. it builds when PCRE 8.41+ source sits at `libs/pcre-8.45/` (or `-DSHGREP_PCRE_SOURCE=DIR`). PCRE gets built static with UTF-8, unicode properties and JIT. no PCRE? shgrep still builds, those patterns just get yelled at by hyperscan.

`libs/` = the parts of Hyperscan 5.4.2 and PCRE 8.45 that actually build stuff, plus a few CMake fixes marked `COMPAT` so they behave on MSVC and as a subproject. docs and tests were left at home.

ship `dist/shgrep.exe`. just the exe. hyperscan and the MSVC runtime are linked static, only windows system DLLs remain. `shgrep.exe --license` prints the hyperscan license because lawyers.

## MCP (the reason this exists)

start it like `shgrep.exe --root C:\work`. requests can narrow the roots, never widen them. no escaping the sandbox lil bro. stdout is JSON-RPC only, logs go to stderr.

| tool | use it for | rg/tgrep version |
| --- | --- | --- |
| `search` | text in code | `rg PATTERN` |
| `search_bytes` | raw bytes in literally anything | — (they can't) |
| `find_files` | files by name, never opens them | `rg --files` + filter |

`search` args, rg translation included:

| arg | rg | default |
| --- | --- | --- |
| `pattern` / `patterns` | `PATTERN` / `-e` | required. many patterns = still one pass. flex. |
| `mode: "literal"` | `-F` | `"regex"`: PCRE syntax, line anchors (^, $) work per line, backreferences and lookaround work too |
| `case_insensitive` | `-i` | false |
| `word` | `-w` | false |
| `output: "files"` / `"count"` | `-l` / `-c` | `"lines"` |
| `context_lines` / `before_lines` / `after_lines` | `-C` / `-B` / `-A` | 0 |
| `line_numbers: false` | `-N` | true |
| `types` | `-t` | everything |
| `include` / `exclude` | `-g` / `-g !` | — |
| `max_matches_per_file` | `-m` | 20 matching lines |
| `hidden`, `no_ignore` | `--hidden`, `--no-ignore` | false |

every tool also takes `roots`, `extensions`, `path_filter`, `max_results` (default 100; counts matching lines for lines output, files for files/count/find_files), `max_output_bytes` (default 65536), `timeout_ms` (default 30000, `find_files` gets 300000). `find_files` wants `exact_name`, `substring`, or `glob`. `search_bytes` eats hex literals (`"4d5a"`) or byte regexes and spits JSON.

globs are case-insensitive and match the WHOLE path or WHOLE filename. `"*parser*"` works. `"parser.cpp"` matches exactly `parser.cpp` and nothing else. this has already burned one test. don't be the second. file types: `asm bat c cmake cpp cs css go h html java js json lua make md msbuild proto ps py rust sh sql toml ts txt xml yaml`, plus aliases like `python`, `rs`, `csharp`, `powershell`.

### what comes out

default `lines` output, same shape rg uses, you'll feel at home:

```
C:\work\src\net.cpp-41-    // reconnect
C:\work\src\net.cpp:42:    retry_connect(socket);
--
C:\work\src\net.cpp:97:    retry_connect(other);
```

`:` = match, `-` = context, `--` = gap (only when you asked for context). lines over 400 bytes get chopped around the match with `...` because nobody needs your minified JS.

search finished clean with results? it prints NOTHING extra. like a real grep. if the list might be incomplete it TELLS you, so your agent doesn't hallucinate "there are no other usages" lmao:

```
No matches. Scanned 1,204 files in 85 ms. Roots: C:\work
[status limit: stopped at max_results=100; more matches may exist. Narrow the search or raise max_results.]
```

| status | translation |
| --- | --- |
| `limit` | hit `max_results`, there's more |
| `per_file_limit` | one file had too many hits |
| `output_limit` | hit `max_output_bytes` |
| `partial_files` | some files were unreadable or too fat (`max_file_bytes`) |
| `timeout` / `cancelled` | ran out of time, results are partial |

`output: "json"` = full objects with `results` (path, line, byte offsets, `pattern_id`, byte context), `skipped_files`, and a `summary` with the same statuses. for nerds.

## command line (for humans, allegedly)

same flags as rg/ug. muscle memory works:

```powershell
shgrep search "TODO|FIXME" -t cpp -C 2
shgrep search -F "operator<<" --root C:\work -l
shgrep search -e open -e close -w -c
shgrep search_bytes --root .\dist --pattern 4d5a --include shgrep.exe
shgrep find_files AISHITERU.mp3 --whole
```

flags: `-F` `-E` `-i` `-w` `-e` `-l` `-c` `-A` `-B` `-C` `-N` `-m` `-t` `-g`, plus `--root DIR` (stack em), `--whole` (your entire drive, go wild), `--exclude`, `--extension`, `--path-filter`, `--hidden`, `--no-ignore`, `--max-results`, `--max-output-bytes`, `--timeout-ms`, `--max-file-bytes`, `--output MODE`, `--json`. no `--root` = current folder. exit codes: `0` it ran, `2` you typed something wrong (or something broke), `3` timeout/cancel.

## how it actually works (the lore)

- **threads:** one worker per logical CPU. all of them. every tool. each directory gets listed through one handle, names and attributes straight from the listing, zero per-file metadata calls.
- **ignore files:** `.gitignore` and `.ignore` respected unless `no_ignore`. supports `*`, `?`, `**`, leading `/`, trailing `/`, `!`. no `[...]` classes or backslash escapes yet. it's on the list. the list is long.
- **hidden stuff** (leading `.` or the windows hidden attribute) is skipped unless `hidden`.
- **reparse points** (junctions, symlinks, the cursed ones) are never followed. folders that deny access get skipped quietly, other failures count as file errors.
- **sandbox:** under each root, files and folders open by name RELATIVE to the parent's handle without following reparse points. you can't sneak out even if you swap a junction in mid-search. we tried. also it's faster: the old per-file path check cost ~30 µs a pop and choked on threads.
- **binary files:** `search` sniffs the first 64 KiB for NUL bytes and bails without reading the rest. text gets decoded: UTF-8, UTF-8 BOM, UTF-16 BOM. broken UTF-8 gets patched up. text files over `max_file_bytes` (64 MiB default, max 256 MiB) get reported as skipped.
- **hyperscan, done right:** all patterns go into one database, each file gets scanned once. text uses block mode, `search_bytes` streams 1 MiB chunks (matches across chunk edges still found). literals use hyperscan's literal compiler. start-of-match tracking only turns on when needed (json output, or `word` + regex) because it's expensive. regexes hyperscan refuses (backreferences, lookaround, `\b` in unicode mode) quietly fall over to Chimera, which prefilters with hyperscan and confirms with JIT PCRE. slower, but it works. compiled databases get cached in the server process. never file contents. never results. freshness or death.

## does it work tho 

no one knows

## want to flex on ug yourself:

```powershell
python tests/bench.py "C:\path\to\big\folder" --runs 5
```

that's it. go search something.
