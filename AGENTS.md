# Workspace instructions

This folder may be a git repo, a workspace containing repos, or a plain folder. Find out first (see "Layout"). Hooks in `.claude/hooks` and `.codex/hooks` enforce the tool routing below and reject calls that break it.

Response format, length and tone are controlled by the ADHD mode hooks. Do not restate or override them here or in your replies.

## Tool routing

This repo is shgrep's own source. Do not read, search or edit it with shgrep tools (`mcp__shgrep__*`).

- shgrep is the tool under change. A half-finished shgrep editing its own source can corrupt it.
- Its MCP server runs `build-rocm/shgrep.exe` (see `.mcp.json`). While it runs, that exe and its DLLs are locked, so the user cannot rebuild.

| Task | Tool |
|---|---|
| Find a symbol, trace callers, see architecture | codebase-memory: `search_graph`, `trace_path`, `get_code_snippet`, `get_architecture`, `query_graph` |
| Read or edit code at symbol level | Serena `mcp__serena__serena_repl`: `s.lsp.get_symbols_overview`, `s.lsp.find_symbol`, `s.lsp.find_referencing_symbols`, `s.edit.replace_symbol_body`, `s.edit.insert_before_symbol`, `s.edit.insert_after_symbol`, `s.lsp.rename_symbol`, `s.lsp.safe_delete_symbol` |
| Small edits inside a code symbol, includes and imports | Serena `s.edit.replace_content` |
| Read any file, list folders, find files | Serena `s.fs.read_file`, `s.fs.list_dir`, `s.fs.find_file` |
| Search text in any file | tgrep `tgrep_search`, `tgrep_files`; Serena `s.fs.search_for_pattern` |
| Edit existing non-programming files (text, json, yaml, toml, xml, md, config, docs) | tgrep `tgrep_edit`; Serena `s.edit.replace_content` |
| Create a new file | Serena `s.fs.create_text_file` |
| Check a code file for errors | Serena `s.lsp.get_diagnostics_for_file` |

Call `mcp__serena__initial_instructions` once per session to get the Serena session id. Line numbers from Serena are 0-based.

Serena edits rewrite the whole file with CRLF line endings. `src` is CRLF, but `AGENTS.md`, `internal-issues-list.md` and `.claude/hooks/*` are LF only (`tools/check_issues.py` fails otherwise). Edit LF files with `tgrep_edit`, or restore LF right after a Serena edit.

Built-in Read, Grep, Glob, Edit and Write are blocked. Shell file reads (`cat`, `head`, `tail`, `sed`, `awk`, `find`, `Get-Content`, `Select-String` and similar) are blocked. If a hook blocks a call, follow its message and switch tools. Do not retry the same call.

## shgrep test sessions

- From time to time the user adds the shgrep MCP server so you can test a new build. Its tools then appear as `mcp__shgrep__*`.
- Only then use shgrep tools, and only for the test the user names. By default test in `warehouse-demo-main` with real edits and real tool calls.
- Even during a test session, edit shgrep's own source (`src`, `tools`, `CMakeLists.txt`, docs) with Serena, never with shgrep.
- Report every shgrep defect you hit: the exact call, the output, and what you expected. Add it to `internal-issues-list.md` when the user asks.
- Before a rebuild the user removes or disables the shgrep server. If a build fails because `shgrep.exe` is in use, say so. Do not kill the process yourself.

## Code work order

1. Call a codebase-memory tool first in every turn that touches code. Symbol edits are blocked until you have.
2. Then use Serena `s.lsp` to read the symbol you found, and Serena `s.edit` to change it.
3. Never use `tgrep_edit` on programming files (`.cpp`, `.hpp`, `.h`, `.cs`, `.ts`, `.tsx`, `.js`, `.jsx`, `.py`, `.html`, `.css` and similar). Edit those with Serena symbol edits, or `s.edit.replace_content` for a few lines inside one symbol.

## Layout (do this first, once per session)

Before the first codebase-memory call, look at what is in the workspace folder with Serena `s.fs.list_dir` or tgrep `tgrep_files`. Do not guess from the folder name.

1. Does the workspace folder itself contain `.git`? Then it is **one repo**. The workspace folder is the repo.
2. Otherwise list its direct subfolders that contain `.git`. Each one is a separate repo, so this is a **multi-repo workspace**.
3. If neither finds a `.git`, treat the workspace as a plain folder and work in it. Do not ask for another folder solely because Git is absent.

Use the result for everything below. Do not call a single repo a "workspace with several repos", and do not look for repo subfolders in a single repo.

## codebase-memory projects

- Always pass `project`. Do not call `list_projects` to search all projects. If a call says the project was not found, call `list_projects` once to read the exact name, then use it.
- The base name is the workspace path with `:` removed and `/` and spaces turned into `-`.
  Example: `C:/Users/you/Documents/my-repo` gives `C-Users-you-Documents-my-repo`.
- **Single repo or plain folder:** the project is the base name alone.
- **Multi-repo workspace:** the project is the base name, then `-` and the repo folder name.
  Example: `C:/Users/you/Documents/my-workspace` + `BackendApi` gives `C-Users-you-Documents-my-workspace-BackendApi`.
- The first call for a repo indexes it. Later calls reindex only if the repo changed. Wait for the hook; do not index by hand.
- In a multi-repo workspace each repo is searched on its own. Cross-repo links are added automatically after indexing.

## Task completion

- Treat requests to implement, fix, or integrate as instructions to complete the work, not just investigate or propose a plan.
- Continue through all authorized implementation steps and affected callers until the requested behavior is complete. Research and progress updates are not stopping points.
- If a tool fails or information is missing, use available alternatives and keep working on independent parts. Ask only when a decision, permission, or external change is genuinely required.
- Do not stop because the task is large, time-consuming, uncertain, or needs further investigation. Respect the verification restrictions below.
- If blocked, state the exact blocker, what remains, and the action needed; do not claim completion. If the user asks to continue, resume the work instead of only acknowledging the earlier stop.

## Engineering principles

- **Understand first.** Read the code that owns the behavior before changing it. Trace the full caller chain and every implementation with the graph, up to entry points, not by guessing from names.
- **Fix the cause.** Reproduce the problem, find the root cause, then fix it there. Do not patch symptoms or add a workaround next to the real defect.
- **Change what the task needs.** The change can be as large as the task requires. Cover every affected caller, implementation and consumer in one pass. Do not leave half-updated call sites. Keep unrelated cleanup out of it.
- **Follow the repo.** Match its structure, naming, error handling, logging, formatting and test style. If the repo has a linter or formatter config, obey it.
- **Reuse before adding.** Look for an existing helper, service or component before writing a new one. Add a dependency only when the platform and current dependencies cannot do the job.
- **Design for change.** Keep modules small with one responsibility. Depend on interfaces at boundaries. Avoid hidden global state, and make side effects explicit.
- **Handle failure.** Validate input at system boundaries. Do not swallow exceptions. Return or log errors with enough context to debug. Keep async, cancellation and disposal correct.
- **Secure by default.** Never hardcode secrets, tokens or connection strings. Do not log sensitive data. Parameterize queries, encode output, and check authorization on the server side.
- **Mind performance where it counts.** Avoid N+1 queries, unbounded loops and unneeded allocations on hot paths. Measure before optimizing anything else.

## Changes that cross repos (multi-repo workspaces only)

- Skip this section in a single repo.
- Before you change a public contract (API route, DTO, event, shared type, package version), find every consumer in the other repos with the graph.
- Change the producer and its consumers together, or keep the old shape working until consumers move.
- Database and storage changes need a migration that is safe to run twice and does not lose data.

## Verification

- Do not build, and do not run tests or lint. The user runs them.
- When the user says the build or restart is done, run the requested test at once. Do not re-check exe times, processes, or whether it is the new build.
- `warehouse-demo-main` is the C# test repo for shgrep. Test there with real edits and real tool calls, not dry runs, during a shgrep test session (see above).
- Do not write tests until the user says the foundation is ready and asks for them.
- Verify the logic yourself by reading the code. Check control flow, edge cases, null and empty handling, error paths, async and ordering, data shape across callers, and that every traced caller still works with the change. Syntax and formatting are not your job.
- When the user needs to check something, give them the exact commands to run: build, test, lint, run, and any setup or data they need. Name the folder to run them in (the repo subfolder in a multi-repo workspace, the workspace folder in a single repo).
- Say which parts you checked by reading and which you could not check. Never claim you built, tested or ran anything.
