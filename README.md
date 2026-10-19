# shgrep

## mcp__shgrep__create_directory

Create a folder and its parents (mkdir -p). Links are never followed.

exec tool declaration:
```ts
declare const tools: { mcp__shgrep__create_directory(args: {
  // Relative to the first root, or absolute inside a root.
  path: string;
}): Promise<CallToolResult>; };
```

## mcp__shgrep__edit_file

Live LSP symbol replace, insert_before/insert_after, rename across files (listing same-name mentions it leaves, e.g. other languages), or reference-checked safe_delete. Text edits remain available. Snapshot guards, encoding preservation, dry-run diffs and rollback on commit failure; atomic per file. Links are never followed.

exec tool declaration:
```ts
declare const tools: { mcp__shgrep__edit_file(args: {
  // rename: 1-based UTF-16 column with line.
  column?: number;
  // Return diagnostics for the primary file after a successful write; default false.
  diagnostics?: boolean;
  // Diff only, write nothing.
  dry_run?: boolean;
  // 1-256 edits.
  edits?: Array<{
  // Replacement.
  new_text: string;
  // Exact text; must match once unless replace_all.
  old_text: string;
  // Replace every match.
  replace_all?: boolean;
}>;
  // Fail if the file's mtime (from read_file) changed.
  expected_mtime?: string;
  // Fail if the file's sha256 (from read_file) changed.
  expected_sha256?: string;
  // rename: 1-based line instead of name_path.
  line?: number;
  // Optional diff byte cap; no cap by default.
  max_output_bytes?: number;
  // Unique slash-separated symbol path; overload [i] supported.
  name_path?: string;
  // rename: new identifier; language server computes all affected files.
  new_name?: string;
  // Complete replacement symbol, including declaration; used with name_path.
  new_text?: string;
  // Default auto: name_path selects symbol replacement; edits selects text.
  operation?: "auto" | "symbol" | "insert_before" | "insert_after" | "rename" | "safe_delete" | "text";
  // Relative to the first root, or absolute inside a root.
  path: string;
  // LSP deadline, 1-300000; default 30000.
  timeout_ms?: number;
}): Promise<CallToolResult>; };
```

## mcp__shgrep__file_info

Disk metadata, or operation=lsp for server capabilities and whether the reranker works, diagnostics for current file/symbol problems, restart for LSP recovery. Links are never followed.

exec tool declaration:
```ts
declare const tools: { mcp__shgrep__file_info(args: {
  // Optional byte cap, 512-1048576. Default unlimited.
  max_output_bytes?: number;
  // diagnostics: restrict to this symbol.
  name_path?: string;
  // Default metadata. lsp/restart may omit path to address all configured servers.
  operation?: "metadata" | "lsp" | "diagnostics" | "restart";
  // Relative to the first root, or absolute inside a root.
  path?: string;
  // Up to 32 paths instead of path.
  paths?: Array<string>;
  // diagnostics: highest numeric severity to include, 1-4; default 4.
  severity?: number;
  // LSP deadline, 1-300000; default 30000.
  timeout_ms?: number;
}): Promise<CallToolResult>; };
```

## mcp__shgrep__find_files

Find live files by name/path, configured LSP source files, or files containing symbol hits. Use list_dir for folder or symbol overviews.

exec tool declaration:
```ts
declare const tools: { mcp__shgrep__find_files(args: {
  // Whole filename, case-insensitive.
  exact_name?: string;
  // Globs of files or dirs to skip; a matching dir is not entered: "third_party".
  exclude?: Array<string>;
  exclude_kinds?: Array<number>;
  // Extensions to keep: ["cpp", "h"].
  extensions?: Array<string>;
  // Glob on the name or relative path.
  glob?: string;
  // Include hidden files.
  hidden?: boolean;
  // File globs (* ?, case-insensitive). Without '/' a glob matches the whole filename, with '/' the whole relative path: "*.cpp", "*parser*", "src/*".
  include?: Array<string>;
  include_kinds?: Array<number>;
  // Optional byte cap, 512-1048576; default unlimited.
  max_output_bytes?: number;
  // Optional result limit, 1-10000; default unlimited.
  max_results?: number;
  // symbols: alternative to pattern.
  name_path?: string;
  // Include .gitignore/.ignore'd files.
  no_ignore?: boolean;
  // Default filesystem. symbols finds files containing symbol hits; lsp lists configured source files without starting servers.
  operation?: "filesystem" | "symbols" | "lsp";
  // Default lines.
  output?: "lines" | "json";
  // LSP file/directory scope; omit for all configured roots.
  path?: string;
  // Substring of the relative path.
  path_filter?: string;
  // Default relative (to a single root).
  paths?: "absolute" | "relative";
  // symbols: symbol name-path pattern.
  pattern?: string;
  // Absolute dirs inside the configured roots. Default: all.
  roots?: Array<string>;
  // Text in the name or relative path.
  substring?: string;
  // symbols: substring match on final component.
  substring_matching?: boolean;
  // Default 30000 (find_files 300000).
  timeout_ms?: number;
  // File types: asm bat c cmake cpp cs css go h html java js json lua make md msbuild proto ps py rust sh sql toml ts txt xml yaml.
  types?: Array<string>;
}): Promise<CallToolResult>; };
```

## mcp__shgrep__list_dir

List files and folders: "d sub/", "f name SIZE", "l link". Links are never followed.

exec tool declaration:
```ts
declare const tools: { mcp__shgrep__list_dir(args: {
  // Filesystem: 1-32, default 1. Overview: child depth, default -1 (all).
  depth?: number;
  // Include hidden entries.
  hidden?: boolean;
  // Optional byte cap, 512-1048576. Default unlimited.
  max_output_bytes?: number;
  // Optional entry limit, 1-10000; default unlimited.
  max_results?: number;
  // Include .gitignore/.ignore'd entries.
  no_ignore?: boolean;
  // Default filesystem; overview returns live LSP symbols by file.
  operation?: "filesystem" | "overview";
  // Folder; default the first root.
  path?: string;
  // Default 30000.
  timeout_ms?: number;
}): Promise<CallToolResult>; };
```

## mcp__shgrep__move_file

Move a file/folder; auto asks configured LSP servers for import edits when supported. Refactor requires that support; filesystem moves paths. Active servers refresh after success. Links are never followed.

exec tool declaration:
```ts
declare const tools: { mcp__shgrep__move_file(args: {
  // Relative to the first root, or absolute inside a root.
  destination: string;
  // Preview import edits and move without writing.
  dry_run?: boolean;
  // Default auto. refactor requires willRenameFiles; filesystem bypasses semantic import edits.
  operation?: "auto" | "refactor" | "filesystem";
  // Replace an existing file; requires operation=filesystem.
  overwrite?: boolean;
  // Relative to the first root, or absolute inside a root.
  source: string;
  // LSP deadline, 1-300000; default 30000.
  timeout_ms?: number;
}): Promise<CallToolResult>; };
```

## mcp__shgrep__read_file

Read live code through LSP: complete symbol overview by default (one "LINE kind name_path" line each; format=json for ranges), or name_path for a symbol body. Explicit offset/limit or operation=text reads lines (all remaining lines unless limit is set). Unconfigured formats use text; a code file whose bundled server is missing reads as text under an [LSP FAILURE ...] line to relay to the user. No output byte cap. Text header includes encoding, mtime and sha256; binary and >256 MiB refused (UTF-16 >64 MiB). Links are never followed.

exec tool declaration:
```ts
declare const tools: { mcp__shgrep__read_file(args: {
  // Overview child depth; default -1 (all).
  depth?: number;
  // LSP kinds to exclude.
  exclude_kinds?: Array<number>;
  // LSP kinds 1-26 to include.
  include_kinds?: Array<number>;
  // Optional text line limit per file; default all remaining lines.
  limit?: number;
  // Text line numbers; default true.
  line_numbers?: boolean;
  // Read this symbol's complete body; slash-separated parent/name with optional overload [i].
  name_path?: string;
  // First line, from 1.
  offset?: number;
  // Default auto: LSP if configured, otherwise text.
  operation?: "auto" | "overview" | "symbol" | "text";
  // Relative to the first root, or absolute inside a root.
  path?: string;
  // Up to 32 paths instead of path.
  paths?: Array<string>;
  // LSP deadline, 1-300000; default 30000.
  timeout_ms?: number;
}): Promise<CallToolResult>; };
```

## mcp__shgrep__search

Navigate live code through LSP: symbols, definition/declaration/type_definition, implementation, references, or hover. Bodies are opt-in; no LSP output cap. Lua, XML, C/C++, Rust, Python and C# (with the .NET 10+ SDK) work out of the box; .shgrep/lsp.json adds or overrides servers. A missing or failing server is reported in a leading [LSP FAILURE ...] line, to relay to the user, followed by whole-word text matches. operation=text requires intent (the task in words): only the best 10 hunks return, ranked by BM25 keywords (at most 3 per file) and then a local reranker, and a note states how many were left out. A reranker that is down fails the search with a leading [RERANK FAILURE ...] line, to relay to the user; for every reference to a symbol use operation=references. Grep filters apply, including XML and files without a language server.

exec tool declaration:
```ts
declare const tools: { mcp__shgrep__search(args: { after_lines?: number; before_lines?: number; block?: boolean; case_insensitive?: boolean; column?: number; context_after_bytes?: number; context_before_bytes?: number; context_bytes?: number; context_lines?: number; intent?: string; depth?: number; exclude?: Array<string>; exclude_kinds?: Array<number>; extensions?: Array<string>; hidden?: boolean; include?: Array<string>; include_body?: boolean; include_declaration?: boolean; include_info?: boolean; include_kinds?: Array<number>; index?: boolean; invert?: boolean; line?: number; line_numbers?: boolean; max_block_lines?: number; max_file_bytes?: number; max_line_bytes?: number; max_matches_per_file?: number; max_output_bytes?: number; max_results?: number; mode?: "regex" | "literal"; multiline?: boolean; name_path?: string; no_ignore?: boolean; operation?: "symbols" | "definition" | "declaration" | "type_definition" | "implementation" | "references" | "hover" | "text"; output?: "lines" | "files" | "files_without_match" | "count" | "json"; path?: string; path_filter?: string; paths?: "absolute" | "relative"; pattern?: string; patterns?: Array<string>; roots?: Array<string>; sniff_all?: boolean; substring_matching?: boolean; timeout_ms?: number; types?: Array<string>; word?: boolean; }): Promise<CallToolResult>; };
```

## mcp__shgrep__search_bytes

Search raw bytes of any file (no decoding or binary skipping) by hex or byte regex; exact offsets.

exec tool declaration:
```ts
declare const tools: { mcp__shgrep__search_bytes(args: {
  // ASCII only.
  case_insensitive?: boolean;
  // json: context bytes after.
  context_after_bytes?: number;
  // json: context bytes before.
  context_before_bytes?: number;
  // json: context bytes per side, default 80.
  context_bytes?: number;
  // Globs of files or dirs to skip; a matching dir is not entered: "third_party".
  exclude?: Array<string>;
  // Extensions to keep: ["cpp", "h"].
  extensions?: Array<string>;
  // Include hidden files.
  hidden?: boolean;
  // File globs (* ?, case-insensitive). Without '/' a glob matches the whole filename, with '/' the whole relative path: "*.cpp", "*parser*", "src/*".
  include?: Array<string>;
  // Add lines to json.
  line_numbers?: boolean;
  // Optional per-file match limit; default unlimited.
  max_matches_per_file?: number;
  // Optional byte cap, 512-1048576; default unlimited.
  max_output_bytes?: number;
  // Optional result limit, 1-10000; default unlimited.
  max_results?: number;
  // literal (default): hex such as "4d5a". regex: byte regex such as "\\x4d\\x5a" or plain ASCII.
  mode?: "literal" | "regex";
  // Include .gitignore/.ignore'd files.
  no_ignore?: boolean;
  // Default json (offsets, hex context).
  output?: "json" | "files" | "count";
  // Substring of the relative path.
  path_filter?: string;
  // Default relative (to a single root).
  paths?: "absolute" | "relative";
  // One pattern; search LSP mode uses a symbol name path.
  pattern?: string;
  // Text: up to 1000 in one pass. LSP: symbol name paths, matched together.
  patterns?: Array<string>;
  // Absolute dirs inside the configured roots. Default: all.
  roots?: Array<string>;
  // Default 30000 (find_files 300000).
  timeout_ms?: number;
  // File types: asm bat c cmake cpp cs css go h html java js json lua make md msbuild proto ps py rust sh sql toml ts txt xml yaml.
  types?: Array<string>;
}): Promise<CallToolResult>; };
```

## mcp__shgrep__write_file

Create or replace a file atomically; creates parent folders. Links are never followed.

exec tool declaration:
```ts
declare const tools: { mcp__shgrep__write_file(args: {
  // Full contents.
  content: string;
  // Include diagnostics after writing; default false.
  diagnostics?: boolean;
  // Default: the replaced file's, else utf-8.
  encoding?: "utf-8" | "utf-8-bom" | "utf-16le" | "utf-16be";
  // Fail if the file's mtime (from read_file) changed.
  expected_mtime?: string;
  // Fail if the file's sha256 (from read_file) changed.
  expected_sha256?: string;
  // Default: the replaced file's, else as given.
  line_endings?: "lf" | "crlf";
  // Replace an existing file.
  overwrite?: boolean;
  // Relative to the first root, or absolute inside a root.
  path: string;
  // Diagnostic deadline, 1-300000; default 30000.
  timeout_ms?: number;
}): Promise<CallToolResult>; };
```
