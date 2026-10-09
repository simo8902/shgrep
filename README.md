# shgrep

grep but it goes absolutely feral. windows only. built for AI agents first, humans second (sorry humans). runs on Intel Hyperscan 5.4.2. ONE exe that's a CLI and an MCP server at the same time

by default every search reads whatever is on disk RIGHT NOW. no index, no cache, no "results from 3 business days ago". want it even faster? there's an optional trigram index, and a live one that watches your files like an overprotective parent. your call.

talks like rg: regex by default, `path:line:text`, `-l -c -w -t -C`. your muscle memory is safe here.

## benchmarks (the part you actually came for)

Ryzen 5 5600 (12 threads), windows 11, warm cache, median of 7 runs. repo: 80 MB, 6,920 files (a C++ game engine). same skip rules for every tool, no cheating. CLI times include process start (~4 ms for shgrep). `idx` columns are snapshot indexes built before the run, so they CAN be stale. plain shgrep never is. rerun it yourself: `python src/tests/bench.py ROOT --runs 7 --index --tgrep PATH --tgrep-index --rg PATH`.

| test | shgrep | shgrep idx | rg | ug | tgrep | tgrep idx |
| --- | --- | --- | --- | --- | --- | --- |
| 1 literal, no match | 39 ms | **6 ms** | 87 ms | 226 ms | 1220 ms | 10 ms |
| 1 regex, no match | 40 ms | **8 ms** | 67 ms | 192 ms | 1211 ms | **8 ms** |
| 100 literals, no match | 36 ms | **10 ms** | 71 ms | 181 ms | 1200 ms | 11 ms |
| 1000 literals, no match | 35 ms | **17 ms** | 68 ms | 185 ms | 1312 ms | 28 ms |
| 100 regexes, no match | 39 ms | **6 ms** | 77 ms | 265 ms | 1251 ms | 10 ms |
| common literal, files only | 39 ms | **38 ms** | 76 ms | 198 ms | 1303 ms | 293 ms |
| common regex, files only | **38 ms** | 42 ms | 79 ms | 227 ms | 1403 ms | 551 ms |

shgrep, shgrep idx, rg, tgrep and tgrep idx all find the exact same files. ug finds 63 fewer on the common-word tests (probably its binary detection, didn't dig). shgrep's output also has its `[index ...]` note lines, that's why its line counts are +1 or +2.

live index through MCP (`--live-index`, one round trip per search, median of 21, no process start, same repo). every edit gets applied before each search, and a file created right before a search gets found by that search:

| test | walk | live index |
| --- | --- | --- |
| no match | 27.4 ms | **0.3 ms** |
| rare word | 26.3 ms | **3.0 ms** |
| common word | 29.4 ms | 28.5 ms |

tl;dr: no index, shgrep is ~2x rg and ~30x unindexed tgrep. with the index it beats indexed tgrep on every row, and on common words it's 7-13x faster because tgrep has to decode postings for half the repo. common words don't get faster with ANY index tho, the cost there is literally opening the files. backreferences/lookaround run on PCRE2 and aren't in these tables because they'd ruin the vibe.

## build

you need: VS 2026 Build Tools dev powershell, CMake, Ninja, Ragel 6.9, Python, Boost headers, OpenSSL.

```powershell
& 'C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\Launch-VsDevShell.ps1' -Arch amd64 -HostArch amd64
cmake -S . -B build-ninja -G Ninja -DCMAKE_BUILD_TYPE=Release '-DBOOST_ROOT=C:/Users/Simeon/Documents/boost-1.92.0'
cmake --build build-ninja --target shgrep
cmake --install build-ninja --prefix "$PWD\dist" --component shgrep
```

- hyperscan gets built for AVX2 (`-DSHGREP_HS_ARCH=AVX2|AVX512|SSE`). potato cpu = clean error, not a crash
- backreferences/lookaround go through PCRE2 JIT (same engine as `rg -P`), source in `libs/pcre2-10.49/`
- `libs/` holds only the bits of Hyperscan 5.4.2 and PCRE2 10.49 the build needs. don't touch it, it bites
- ship `dist/shgrep.exe` alone. fully static, no DLL scavenger hunt

## CLI

```powershell
shgrep "TODO|FIXME" -t cpp -C 2                  # "search" is optional now, like rg
shgrep -F "operator<<" --root C:\work -l
shgrep prepare_index --root src --block          # show the WHOLE function around each match
shgrep search_bytes --root .\dist --pattern 4d5a --include shgrep.exe
shgrep find_files AISHITERU.mp3 --whole --hidden
shgrep index --root C:\work                      # build the snapshot index
shgrep needle --root C:\work --index             # then search through it
```

- with no command it's a search, and options can go before the pattern. `find_files`, `search_bytes`, `index` still want the command first
- it searches the CURRENT folder unless you pass `--root` or `--whole`. hidden folders (yes, `AppData` counts) and `.gitignore`'d stuff are skipped unless `--hidden` / `--no-ignore`. if shgrep "can't find" something windows search finds, it's one of these. promise
- `--block`: every match comes with its whole enclosing function (or class if there's no function). brace languages (C/C++/C#/Java/JS/TS/Rust/Go/...) + Python. it's a heuristic, not a real parser, so cursed macros can fool it. blocks over `--max-block-lines` (200) fall back to normal context
- colors, rg style but lighter: light magenta paths, light green line numbers, **bold red-pink** matches, light yellow notes. `shgrep --color always|never|auto` ALONE saves it for every command, `--color` next to a command overrides it for that one run. `--json` and MCP output are never colored
- `--profile` dumps per-worker timing (list, open, read, scan, close) as JSON, for when you want to know where the milliseconds went
- flags: `-F -E -i -w -v -U -e -l -c -A -B -C -N -m -t -g --root --whole --hidden --no-ignore --sniff-all --block --index --json --color --profile`. exit codes: `0` ran, `2` error, `3` timeout

## MCP

`shgrep.exe --root C:\work [--read-only] [--live-index]`. MCP clients start it with stdin as a pipe; if YOU run it in a terminal you get the CLI instead.

tools: `search` (text), `search_bytes` (hex / raw bytes), `find_files` (names only, never opens files), plus file tools:

- `read_file`: whole file by default, `     42→text` line numbers, `offset`/`limit`, several files via `paths`. header gives encoding (utf-8, utf-8-bom, utf-16le/be), line endings, final newline, mtime, sha256. lines are never chopped. binary and >64 MiB files are refused (use `search_bytes` / `search`). hidden and gitignored files ARE readable if you name them
- `list_dir`: files AND folders (`d sub/`, `f name SIZE`, `l link`), `depth`. skips hidden and gitignored entries unless you pass `hidden: true` / `no_ignore: true`
- `file_info`: size, mtime, type, binary or not, lines, encoding, line endings, sha256
- `edit_file`: exact-text replace, `edits: [{old_text, new_text, replace_all}]`. must match once unless `replace_all`. all edits or none, atomic (temp file + rename), LF `old_text` works on CRLF files, keeps encoding/BOM, gives back a unified diff. `dry_run`, `expected_sha256` / `expected_mtime` guards
- `write_file`: create, or replace with `overwrite: true`. makes parent folders, atomic, `line_endings`/`encoding` default to the old file's
- `move_file`, `create_directory`

paths are relative to the first `--root` or absolute inside a root. `..` can't escape, and a symlink/junction anywhere below the root gets refused, never followed. `--read-only` hides the write tools.

`search` args worth knowing: `pattern`/`patterns` (up to 1000, one pass), `mode` (`regex` default, `literal`), `case_insensitive`, `word`, `output` (`lines`, `files`, `files_without_match`, `count`, `json`), `context_lines`/`before_lines`/`after_lines`, `block`, `invert`, `multiline`, `types`, `include`/`exclude` (globs match the WHOLE name or path, so `*parser*`, not `parser`), `max_results` (100), `max_matches_per_file` (20), `max_output_bytes` (64 KiB, keeps agent context from exploding), `hidden`, `no_ignore`, `index`.

the tool schemas are kept short on purpose (~13 KB for all 10 tools, it used to be 30), because every word in them costs tokens in every session. if results might be incomplete you get a `[status ...]` line at the end, so the agent can't confidently lie about "there are no other usages".

## the index (optional, but it slaps)

off unless you ask. two flavors:

**snapshot** (CLI + MCP): `shgrep index --root C:\work` writes a trigram index to `.shgrep\index` (one file per root). then `--index` (MCP: `index: true`) skips the tree walk and opens only files that could possibly match. it's a snapshot: files added after the build aren't searched and edited ones can be missed. the output tells you when it was built so nobody gets gaslit.

**live** (MCP server only, basically `tgrep serve` but ours): `shgrep.exe --root C:\monorepo --live-index`. builds or loads the index in the background, watches the tree with `ReadDirectoryChangesW`, and before EVERY search it applies every change windows has reported. edits show up instantly. with this flag searches use the index by default (`index: false` opts out), and while it's building or reconciling, searches just walk like normal. a file still open for writing might not get reported until it's closed, that's a windows thing.

how it's fast, stolen with love from tgrep:

- postings carry position + next-byte masks, so trigrams of a literal have to actually line up next to each other. it's basically 4-grams for the price of 3
- regexes become AND/OR trigram plans, so alternations and groups still use the index. stuff it can't analyze just isn't constrained, so the plan can only ever find MORE candidates than the regex, never fewer
- trigrams that show up in more than half the files get dropped, they don't narrow anything. that's why common words stay fast instead of dying like tgrep's
- the build is an external merge sort with a 256 MiB budget: sorted runs spill to disk and get merged. monorepo size is not a problem
- the live overlay merges into a new index file in the background. old files get renamed aside instead of overwritten, so a running search never has the floor pulled out from under it

not used with `invert`, `files_without_match`, `hidden`, `no_ignore` or `sniff_all`, or for patterns with no 3+ byte literal (it tells you and walks instead). the index never stores file contents. candidates are always read fresh from disk.

## how it works

- one worker per cpu thread, every folder listed with ONE call, files opened relative to their parent folder handle (fast, and physically can't escape the root)
- respects `.gitignore`/`.ignore` (no git needed), skips hidden, never follows symlinks/junctions
- obvious binaries (`.exe .dll .png .zip ...`) get skipped without even being opened. everything else gets a NUL check (whole small files, first 64 KiB of big ones)
- ASCII and valid UTF-8 get scanned straight out of the read buffer, no copy, no decode. only UTF-16 and broken UTF-8 get decoded
- files get closed right on the worker that read them. a single background closer used to do it and it was the bottleneck: 56 ms -> 36 ms when we killed it
- all patterns go into ONE hyperscan database, every file is scanned once. other engines (teddy, dfa) only take a query when they report exactly what hyperscan would, and whatever hyperscan can't do falls back to PCRE2 JIT
- compiled patterns are cached in the server and on disk (`.shgrep\db-cache` in the first root, `SHGREP_DB_CACHE=0` to turn it off), so the second CLI run with 100 regexes skips the compile. file contents and results are never cached

benchmark knobs, if you're that kind of person: `SHGREP_WORKERS=N`, `SHGREP_BACKEND=auto|hyperscan|teddy|dfa`, `SHGREP_DEFER_CLOSE=1` (the old slow closer, for A/B), `SHGREP_DB_CACHE=0`, `SHGREP_TEDDY=0`. `python src/tests/bench.py ROOT --ab base SHGREP_WORKERS=6` interleaves variants so you can trust a 1 ms difference.

## does it work tho

on the 6,920-file repo above: the index finds the exact same files as a plain search (literals, alternations, classes, case-insensitive), and the live index finds a brand new file on the very next search and forgets a deleted one. `python src/tests/bench.py ROOT --live` checks that for you. monorepo scale? untested for now. vibes are good though.

## flex on rg yourself

```powershell
python src/tests/bench.py "C:\path\to\big\folder" --runs 7 --rg C:\path\to\rg.exe
```
