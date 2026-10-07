# shgrep

grep but fast, windows only, built for AI agents. runs on Intel Hyperscan 5.4.2. one exe: CLI + MCP server. no index, every search reads whats on disk right now.

works like rg: regex by default, `path:line:text`, `-l -c -w -t -C`.

## benchmarks

Ryzen 5 5600, windows 11, warm cache, median of 5. big = 80 MB, 6,920 files. small = this repo. same skip rules for everyone. tgrep idx = tgrep with its trigram index (built in 0.9 s big / 0.15 s small, can go stale). rerun with `src/tests/bench.py`.

| test | **shgrep** | rg 15.1 | ug | tgrep | tgrep idx |
| --- | --- | --- | --- | --- | --- |
| big, 1 literal | 71 ms | 97 ms | 301 ms | 1197 ms | **9 ms** |
| big, 1 regex | 66 ms | 70 ms | 323 ms | 1227 ms | **8 ms** |
| big, 100 literals | 64 ms | 71 ms | 317 ms | 1174 ms | **10 ms** |
| big, 1000 literals | 62 ms | 71 ms | 252 ms | 1239 ms | **26 ms** |
| big, 100 regexes | 63 ms | 71 ms | 311 ms | 1166 ms | **9 ms** |
| big, common word, files only | **56 ms** | 77 ms | 211 ms | 1210 ms | 262 ms |
| big, common regex, files only | **67 ms** | 82 ms | 310 ms | 1317 ms | 573 ms |
| big, backreference | 623 ms | **125 ms** | 252 ms | 179 ms | n/a |
| big, walk dirs only | **9 ms** | 23 ms | 47 ms | 35 ms | n/a |
| small, 1 literal | 18 ms | 20 ms | 46 ms | 54 ms | **6 ms** |
| small, 1 regex | 22 ms | 19 ms | 53 ms | 59 ms | **7 ms** |
| small, 100 literals | 23 ms | 26 ms | 61 ms | 60 ms | **8 ms** |
| small, 1000 literals | 22 ms | 26 ms | 54 ms | 74 ms | **19 ms** |
| small, 100 regexes | 19 ms | 21 ms | 91 ms | 62 ms | **8 ms** |
| small, common word, files only | **19 ms** | 21 ms | 62 ms | 69 ms | 51 ms |
| small, common regex, files only | **21 ms** | 24 ms | 42 ms | 85 ms | 86 ms |
| small, backreference | 416 ms | **25 ms** | 63 ms | 1134 ms | n/a |
| small, walk dirs only | **5 ms** | 14 ms | 14 ms | 21 ms | n/a |
| find 1 mp3 on all of C: | **1.28 s** | 2.89 s | 10.41 s | 5.06 s | n/a |

short version: without an index we now beat rg on basically everything except backreferences (Chimera is slow there) and 1 regex on the small repo. indexed tgrep still wins rare matches but chokes on common ones and can be stale. 100-regex numbers use the on-disk pattern cache (first run pays ~85 ms compile).

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
