# shgrep

grep but fast, windows only, built for AI agents. runs on Intel Hyperscan 5.4.2. one exe: CLI + MCP server. no index, every search reads whats on disk right now.

works like rg: regex by default, `path:line:text`, `-l -c -w -t -C`.

## benchmarks

Ryzen 5 5600 (12 threads), windows 11, warm cache, median of 7 runs. repo: 80 MB, 6,920 files (a C++ game engine). same skip rules for every tool. CLI times include process start (~4 ms for shgrep). `idx` columns are snapshot indexes built before the run: they can be stale, plain shgrep never is. rerun with `python src/tests/bench.py ROOT --runs 7 --index --tgrep PATH --tgrep-index --rg PATH`.

| test | shgrep | shgrep idx | rg | ug | tgrep | tgrep idx |
| --- | --- | --- | --- | --- | --- | --- |
| 1 literal, no match | 39 ms | **6 ms** | 87 ms | 226 ms | 1220 ms | 10 ms |
| 1 regex, no match | 40 ms | **8 ms** | 67 ms | 192 ms | 1211 ms | **8 ms** |
| 100 literals, no match | 36 ms | **10 ms** | 71 ms | 181 ms | 1200 ms | 11 ms |
| 1000 literals, no match | 35 ms | **17 ms** | 68 ms | 185 ms | 1312 ms | 28 ms |
| 100 regexes, no match | 39 ms | **6 ms** | 77 ms | 265 ms | 1251 ms | 10 ms |
| common literal, files only | 39 ms | **38 ms** | 76 ms | 198 ms | 1303 ms | 293 ms |
| common regex, files only | **38 ms** | 42 ms | 79 ms | 227 ms | 1403 ms | 551 ms |

shgrep, shgrep idx, rg, tgrep and tgrep idx list the same files. ug lists 63 fewer on the common-word tests (probably its binary detection; not investigated). shgrep's output lines also include its `[index ...]` notes.

live index through MCP (`--live-index`, round trip per search, median of 21, no process start), same repo. edits are applied before each search, and a file created right before a search is found by it:

| test | walk | live index |
| --- | --- | --- |
| no match | 27.4 ms | **0.3 ms** |
| rare word | 26.3 ms | **3.0 ms** |
| common word | 29.4 ms | 28.5 ms |

short version: no index, shgrep is ~2x rg and ~30x unindexed tgrep. with the index it beats indexed tgrep everywhere, by 7-13x on common words, where tgrep has to decode postings for most files. common words gain nothing from any index; the cost there is opening the files. backreferences/lookaround go to PCRE2 and are not in this table.

## build

VS 2026 Build Tools dev powershell, CMake, Ninja, Ragel 6.9, Python, Boost headers, OpenSSL.

```powershell
& 'C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\Launch-VsDevShell.ps1' -Arch amd64 -HostArch amd64
cmake -S . -B build-ninja -G Ninja -DCMAKE_BUILD_TYPE=Release '-DBOOST_ROOT=C:/Users/Simeon/Documents/boost-1.92.0'
cmake --build build-ninja --target shgrep
cmake --install build-ninja --prefix "$PWD\dist" --component shgrep
```

- hyperscan built for AVX2 (`-DSHGREP_HS_ARCH=AVX2|AVX512|SSE`). old cpu = error, not crash
- backreferences/lookaround via PCRE2 JIT (same engine as `rg -P`), source in `libs/pcre2-10.49/`
- `libs/` = only the parts of Hyperscan 5.4.2 and PCRE2 10.49 the build needs
- ship `dist/shgrep.exe` alone, its all static

## MCP

`shgrep.exe --root C:\work`. tools: `search` (text), `search_bytes` (hex/raw bytes), `find_files` (names only, never opens files), plus file tools:

- `read_file`: whole file by default, exact contents with `     42→text` line numbers, optional `offset`/`limit`, several files via `paths`. header says encoding (utf-8, utf-8-bom, utf-16le/be), line endings (lf/crlf/mixed), final newline, mtime, sha256. no line cutting. binary files refused (use `search_bytes`). hidden and gitignored files are readable when you name them
- `list_dir`: files AND folders (`d sub/`, `f name SIZE`, `l link`), `depth`. lists everything, hidden and gitignored included; `hidden: false` / `no_ignore: false` filter like search
- `file_info`: size, mtime, type, binary or not, lines, encoding, line endings, sha256
- `edit_file`: exact-string replace, `edits: [{old_text, new_text, replace_all}]`. must match once unless `replace_all`. all edits or none, atomic (temp file + rename), LF old_text works on CRLF files, keeps encoding/BOM, returns a unified diff. `dry_run`, `expected_sha256`/`expected_mtime` guards
- `write_file`: create or (with `overwrite: true`) replace, makes parent folders, atomic, `line_endings`/`encoding` default to the replaced file's
- `move_file`, `create_directory`

file tool paths are relative to the first `--root` or absolute inside a root. `..` cant leave the root, and a symlink/junction anywhere below the root is refused, not followed. `--read-only` hides the write tools (`edit_file`, `write_file`, `move_file`, `create_directory`).

main `search` args: `pattern`/`patterns`, `mode` (`regex` default, `literal` = `-F`), `case_insensitive`, `word`, `output` (`lines`, `files`, `count`, `json`), `context_lines`/`before_lines`/`after_lines`, `types`, `include`/`exclude` (globs must match the WHOLE name or path, so use `*parser*` not `parser`), `max_results` (100), `max_matches_per_file` (20), `max_line_bytes` (400, `0` = never window long lines), `hidden`, `no_ignore`, `sniff_all`.

output is rg-style. if results might be incomplete you get one `[status ...]` line at the end so the agent doesnt lie about "no other usages".

## CLI

```powershell
shgrep search "TODO|FIXME" -t cpp -C 2
shgrep search -F "operator<<" --root C:\work -l
shgrep search_bytes --root .\dist --pattern 4d5a --include shgrep.exe
shgrep find_files AISHITERU.mp3 --whole
```

flags: `-F -E -i -w -e -l -c -A -B -C -N -m -t -g --root --whole --hidden --no-ignore --json`. exit codes: `0` ran, `2` error, `3` timeout.

## optional index

off unless you ask. `shgrep index --root C:\work` builds a trigram snapshot into `.shgrep\index` (one file per root). then `shgrep search --index ...` (MCP: `index: true`) skips the tree walk and opens only files that held the pattern's literal text at build time. like tgrep: postings carry position/next-byte masks so adjacent trigrams must line up, and regexes become AND/OR trigram plans (alternations and groups work). it's a snapshot: files added since the build aren't searched and edited files can be missed; the output says when it was built. not used with `--invert`, `--files-without-match`, `--hidden`, `--no-ignore` or `--sniff-all`, or for patterns without 3+ bytes of literal text. searches without `--index` don't change at all.

live mode (MCP server only, like `tgrep serve`): `shgrep.exe --root C:\monorepo --live-index`. builds or loads the index in the background, watches the tree with `ReadDirectoryChangesW`, and before every search applies every change windows has reported, so edits are visible right away. searches use the index by default (`index: false` opts out) and walk normally while it builds or reconciles. the build spills sorted postings to disk (256 MiB budget), so monorepo size isn't capped.

## how it works

- one thread per cpu, each folder listed with one call, files opened relative to the parent folder (fast, and cant escape the root)
- respects `.gitignore`/`.ignore`, skips hidden, never follows symlinks/junctions
- skips empty files and obvious binaries (`.exe .dll .png .zip ...`) without opening them, everything else gets a NUL check on the first 64 KiB
- ASCII and valid UTF-8 files get scanned straight out of the read buffer, no copy, no decode. only UTF-16 and broken UTF-8 get decoded
- all patterns go into one hyperscan database, every file scanned once. patterns hyperscan cant do fall back to PCRE2 JIT
- compiled patterns are cached in the server and on disk (`%LOCALAPPDATA%\shgrep\db-cache`, `SHGREP_DB_CACHE=0` to turn off), so the second CLI run with 100 regexes skips the compile. file contents and results are never cached

## does it work tho

no one knows

## flex on ug yourself

```powershell
python src/tests/bench.py "C:\path\to\big\folder" --runs 5
```
