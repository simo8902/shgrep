"""Adapters for user-run checks against the current MCP/REPL interface. No checks run on import."""
import json
import re
from pathlib import Path

_SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp",
    ".rs", ".py", ".pyi", ".lua", ".cs", ".xml", ".xsd", ".xsl", ".xslt", ".svg",
    ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".swift", ".kt",
}


def unpack_json(value):
    """Decode one self-contained shgrep-rowpack v1 response, preserving raw JSON cells."""
    if not isinstance(value, dict) or not isinstance(value.get("$format"), dict):
        return value
    fmt = value["$format"]
    if fmt.get("name") != "shgrep-rowpack":
        return value
    if fmt.get("version") != 1:
        raise ValueError("Unsupported rowpack version")

    def at(table, index):
        if type(index) is not int or not 0 <= index < len(table):
            raise ValueError("Invalid rowpack index")
        return table[index]

    def node(row):
        tag = row[0]
        if tag == "J":
            return row[1]
        if tag == "A":
            return [node(item) for item in row[1:]]
        if tag == "O":
            return {key: node(item) for key, item in row[1].items()}
        if tag != "S":
            raise ValueError("Unknown rowpack node")
        schema = at(fmt["schemas"], row[1])
        if len(row) != len(schema) + 2:
            raise ValueError("Invalid rowpack row width")
        result = {}
        for (names, kind), cell in zip(schema, row[2:]):
            if kind == "F":
                values = at(fmt["files"], cell)
                if len(names) != len(values):
                    raise ValueError("Invalid rowpack file tuple")
                result.update(zip(names, values))
                continue
            if kind == "N":
                cell = node(cell)
            elif kind == "Q":
                cell = at(fmt["prefixes"], cell[0]) + cell[1]
            elif kind == "P":
                cell = dict(zip(("line", "column"), cell))
            elif kind == "R":
                cell = {"start": {"line": cell[0], "column": cell[1]},
                        "end": {"line": cell[2], "column": cell[3]}}
            elif kind == "r":
                cell = dict(zip(("start_line", "start_column", "end_line", "end_column"), cell))
            elif kind != "J":
                raise ValueError("Unknown rowpack field type")
            result[names] = cell
        return result

    return node(value["data"])


def normalize_tool_result(result):
    """Decode row packing and REPL string values for the legacy assertion helpers."""
    if not isinstance(result, dict) or result.get("isError") or not result.get("content"):
        return result
    first = result["content"][0]
    if first.get("type") != "text":
        return result
    try:
        encoded = json.loads(first["text"])
    except (ValueError, TypeError):
        return result
    decoded = unpack_json(encoded)
    if decoded is encoded and not isinstance(decoded, str):
        return result
    blocks = list(result["content"])
    blocks[0] = {**first, "text": decoded if isinstance(decoded, str) else json.dumps(decoded, ensure_ascii=False)}
    return {**result, "content": blocks}


_TEXT_READ_EXTENSIONS = {".xml", ".xsd", ".xsl", ".xslt", ".svg"}

# Query methods return structured results when format=json; edits, renames, deletes and moves answer in text.
_QUERY_METHODS = {
    "lsp.find_symbol", "lsp.find_definition", "lsp.find_declaration", "lsp.find_type_definition",
    "lsp.find_implementations", "lsp.find_referencing_symbols", "lsp.hover", "lsp.read_symbol",
    "lsp.get_symbols_overview", "lsp.list_symbols", "lsp.status", "lsp.find_files",
    "lsp.get_diagnostics_for_file", "lsp.restart_language_server",
}


def lsp_call(method, arguments, timeout_ms=None):
    """The params of one direct lsp tool call (no C++ worker): {"name": "lsp", "arguments": {method, arguments}}."""
    call = {"method": method, "arguments": dict(arguments)}
    if timeout_ms is not None:
        call["arguments"]["timeout_ms"] = timeout_ms
    return {"name": "lsp", "arguments": call}


def repl_call(method, arguments, session_id="checks", timeout_ms=30000):
    """The params of one REPL cell calling a facade (s.edit.insert_before_symbol, ...): the Serena-compatible surface,
    which the direct lsp tool does not replace for checks of facade behavior."""
    encoded = json.dumps(json.dumps(dict(arguments), ensure_ascii=True), ensure_ascii=True)
    return {"name": "repl", "arguments": {"code": f"s.{method}(shgrep::Json::parse({encoded}).object())",
                                         "session_id": session_id, "timeout_ms": timeout_ms}}


def adapt_tool_call(params, root, *, read_only=False, session_id="checks"):
    """Route the legacy semantic spellings (search operation=references, edit_file operation=rename, ...) to the
    direct lsp tool, which needs no C++ worker; plain and invalid RPC calls pass through unchanged.
    session_id is kept for older callers; the lsp tool has no REPL session."""
    del session_id
    if read_only or not isinstance(params, dict) or not isinstance(params.get("arguments", {}), dict):
        return params
    name = params.get("name")
    args = dict(params.get("arguments", {}))
    operation = args.get("operation")
    method = None

    def source_scope(path):
        if not isinstance(path, str):
            return False
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = Path(root) / candidate
        return candidate.is_dir() or candidate.suffix.lower() in _SOURCE_EXTENSIONS

    if name == "search" and operation != "text":
        method = {
            None: "lsp.find_symbol", "symbols": "lsp.find_symbol",
            "definition": "lsp.find_definition", "declaration": "lsp.find_declaration",
            "type_definition": "lsp.find_type_definition", "implementation": "lsp.find_implementations",
            "references": "lsp.find_referencing_symbols", "hover": "lsp.hover",
        }.get(operation)
    elif name == "read_file":
        if "paths" in args and not isinstance(args["paths"], list):
            return params
        ranges = "offset" in args or "limit" in args
        # read_file contract: XML and SVG stay text unless a symbol is named.
        def outlined(path):
            return source_scope(path) and Path(str(path)).suffix.lower() not in _TEXT_READ_EXTENSIONS
        if args.get("allow_text_fallback") and "name_path" not in args:
            return {**params, "arguments": args}  # read_file itself returns the outline or, permitted, the text
        semantic = operation in ("overview", "symbol") or (
            operation in (None, "auto") and not ranges and
            ("name_path" in args or any(outlined(p) for p in args.get("paths", [args.get("path")]))))
        if semantic:
            method = "lsp.read_symbol" if "name_path" in args or operation == "symbol" else "lsp.get_symbols_overview"
            if method.endswith("get_symbols_overview"):
                args.setdefault("format", "compact")
        elif operation == "auto":
            args["operation"] = "text"
    elif name == "list_dir" and operation == "overview":
        method = "lsp.list_symbols"
        args.setdefault("format", "compact")
    elif name == "file_info":
        method = {"lsp": "lsp.status", "restart": "lsp.restart_language_server",
                  "diagnostics": "lsp.get_diagnostics_for_file"}.get(operation)
    elif name == "find_files" and operation in ("lsp", "symbols"):
        method = "lsp.find_files" if operation == "lsp" else "lsp.find_symbol"
        args.pop("output", None)
    elif name == "edit_file":
        method = {"symbol": "edit.replace_symbol_body", "insert_before": "edit.insert_before_symbol",
                  "insert_after": "edit.insert_after_symbol", "rename": "lsp.rename_symbol",
                  "safe_delete": "lsp.safe_delete_symbol"}.get(operation)
        if operation in (None, "auto") and "name_path" in args:
            method = "edit.replace_symbol_body"
        elif operation == "auto":
            args["operation"] = "text"
    elif name == "move_file" and operation != "filesystem":
        if operation == "refactor" or source_scope(args.get("source")):
            method = "lsp.move_file"
        else:
            args["operation"] = "filesystem"
    if method is None:
        return {**params, "arguments": args}

    args.pop("operation", None)
    if method in _QUERY_METHODS:
        args.setdefault("format", "json")
    if method == "lsp.status":
        args.setdefault("detail", "full")  # compile_database, capabilities and progress are in the full rows only
    return lsp_call(method, args)


def adapt_tool_result(params, result):
    """Reshape a direct lsp answer where the legacy spelling promised another shape: find_files operation=symbols
    lists each matching file once ({"files": [{"root", "path"}], "backend": "lsp"}), in result order."""
    if not (isinstance(params, dict) and params.get("name") == "find_files" and
            isinstance(params.get("arguments"), dict) and params["arguments"].get("operation") == "symbols"):
        return result
    if not isinstance(result, dict) or result.get("isError") or not result.get("content"):
        return result
    hits = json.loads(result["content"][0]["text"])
    files, seen = [], set()
    for hit in hits.get("results", []):
        item = {"root": hit.get("root", ""), "path": hit["path"]}
        key = (item["root"], item["path"])
        if key not in seen:
            seen.add(key)
            files.append(item)
    blocks = list(result["content"])
    blocks[0] = {**blocks[0], "text": json.dumps({"files": files, "backend": "lsp"}, ensure_ascii=False)}
    return {**result, "content": blocks}


_ROW = re.compile(r"^(\d+)([:-])(.*)$")


def flat_lines(text, default_path=None):
    """Lines output as rg-style rows with forward slashes: "path:line:text" for a match, "path-line-text" for
    context. Search output groups rows under a heading line per file; a search of one named file prints no heading,
    so default_path names it. Status, notice and call lines (starting with "[" or "s::<3::") are dropped."""
    rows, current = [], default_path.replace("\\", "/") if default_path else None
    for line in text.splitlines():
        if not line or line.startswith(("[", "s::<3::")) or line.startswith("No matches."):
            continue
        row = _ROW.match(line)
        if row:
            number, separator, body = row.groups()
            rows.append(f"{current}{separator}{number}{separator}{body}")
        else:
            current = line.replace("\\", "/")
    return "\n".join(rows) + ("\n" if rows else "")


_CONTINUE = re.compile(r'continue: "([^"]+:\d+)"')


def continuation(text):
    """The "<id>:<offset>" a split response names for its next part, or None when it is the last part."""
    found = _CONTINUE.findall(text)
    return found[-1] if found else None
