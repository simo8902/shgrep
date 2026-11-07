#include "json.hpp"
#include "banner.hpp"
#include "cli.hpp"
#include "search.hpp"
#include "files.hpp"
#include "lsp.hpp"
#include "embed.hpp"
#include "meaning.hpp"
#include "repl.hpp"
#include "log_window.hpp"

#include <windows.h>
#include <fcntl.h>
#include <io.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <future>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <version>

// CONTRACT: shgrep builds as C++26 against an STL in C++26 mode; the build fails here if a toolchain or flag change
//   drops either. __cpp_lib_flat_map 202511 is the STL version probed through the REPL on 2026-11-03.
static_assert(_HAS_CXX26 == 1, "the MSVC STL is not in C++26 mode");
static_assert(__cpp_lib_flat_map >= 202511, "std::flat_map from the C++26-mode STL is missing");

namespace {
using shgrep::Json;
std::mutex output_mutex;
// CONTRACT: line is one serialized JSON-RPC message without its newline.
void send_line(std::string line) {
    line.push_back('\n');
    std::lock_guard lock(output_mutex);
    std::fwrite(line.data(), 1, line.size(), stdout);
    std::fflush(stdout);
}
void send(const Json& message) { send_line(message.dump()); }
Json error(const Json& id, int code, const std::string& message) {
    return Json::Object{{"jsonrpc", "2.0"}, {"id", id},
                        {"error", Json::Object{{"code", code}, {"message", message}}}};
}
Json success(const Json& id, Json result) {
    return Json::Object{{"jsonrpc", "2.0"}, {"id", id}, {"result", std::move(result)}};
}
// CONTRACT: the session health notice travels as a second text block after the result, so clients and tests that read
//   the first block see the result unchanged, while the model and the notify hook see both.
Json content(std::string text, const std::string& notice) {
    Json::Array blocks{Json::Object{{"type", "text"}, {"text", std::move(text)}}};
    if (!notice.empty()) blocks.push_back(Json::Object{{"type", "text"}, {"text", notice}});
    return blocks;
}
// A spilled text result as one JSON-RPC line: the response frame is built around a placeholder and the text is escaped
// piece by piece, so the whole text is never held twice. Cancellation and deadlines are checked before the first byte;
// after that the line is finished, because half a line would corrupt the transport.
void send_stream(const Json& id, shgrep::TextStream& stream, const std::string& notice,
                 const std::function<void()>& check) {
    const std::string placeholder = "SHGREP_STREAM_PLACEHOLDER_7c1f0e5a";
    const std::string frame = success(id, Json::Object{{"content", content(placeholder, notice)}}).dump(check);
    const size_t at = frame.find(placeholder);
    if (at == std::string::npos || frame.find(placeholder, at + 1) != std::string::npos)
        throw std::runtime_error("cannot frame the streamed response");
    check();
    std::lock_guard lock(output_mutex);
    std::fwrite(frame.data(), 1, at, stdout);
    try {
        std::string piece;
        while (stream.next(piece)) {
            const std::string escaped = Json(std::move(piece)).dump();
            std::fwrite(escaped.data() + 1, 1, escaped.size() - 2, stdout);
        }
    } catch (...) {
        // End the broken line, so the error response that follows starts on a line of its own.
        std::fputc('\n', stdout);
        std::fflush(stdout);
        throw;
    }
    std::fwrite(frame.data() + at + placeholder.size(), 1, frame.size() - at - placeholder.size(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}
// ---- Continuations ----
// CONTRACT: nothing is cut. A response larger than the caller's max_output_bytes keeps the whole tool output here, as
//   a pointer the model follows (arXiv 2511.22729), and returns its first part, which must stand on its own
//   (arXiv 2608.26130), with a status naming continue: "<id>:<offset>" for the rest or narrowing the request instead
//   (arXiv 2405.15793). Text pages end at a line break; JSON results page by whole items, so every page decodes alone.
//   Bounded: the last 16 split outputs and 64 MiB; an evicted one asks for the request to run again, and an output
//   larger than 64 MiB alone is refused with a request to narrow it. JSON output is kept as its frame plus one
//   serialized string per result item; a page parses only the items it probes, so `size` is what it really holds
//   and page cost follows page size, not result size.
struct Continuation {
    bool json = false;
    std::string text;                // text output
    Json::Object frame;              // JSON output: every result member except results
    std::vector<std::string> items;  // JSON output: each results item, serialized
    uint32_t max_bytes = 65536;
    uint64_t size = 0;
};
std::mutex continuation_mutex;
std::list<std::pair<std::string, std::shared_ptr<const Continuation>>> continuations;  // most recently used first
uint64_t continuation_bytes = 0, continuation_serial = 0;  // guarded by continuation_mutex
constexpr size_t max_continuations = 16;
constexpr uint64_t max_continuation_bytes = 64ull << 20;

std::string keep_continuation(std::shared_ptr<const Continuation> kept) {
    if (kept->size > max_continuation_bytes)
        throw std::runtime_error("the output is " + std::to_string(kept->size >> 20) + " MiB, more than the " +
                                 std::to_string(max_continuation_bytes >> 20) + " MiB the server keeps for continue; "
                                 "narrow the request (path, include, patterns or max_results)");
    std::lock_guard lock(continuation_mutex);
    const std::string key = "r" + std::to_string(++continuation_serial);
    continuation_bytes += kept->size;
    continuations.emplace_front(key, std::move(kept));
    // The newest fits alone, so eviction stops before it.
    while (continuations.size() > max_continuations || continuation_bytes > max_continuation_bytes) {
        continuation_bytes -= continuations.back().second->size;
        continuations.pop_back();
    }
    return key;
}

std::shared_ptr<const Continuation> find_continuation(const std::string& key) {
    std::lock_guard lock(continuation_mutex);
    for (auto it = continuations.begin(); it != continuations.end(); ++it) {
        if (it->first != key) continue;
        continuations.splice(continuations.begin(), continuations, it);
        return continuations.front().second;
    }
    return nullptr;
}

// Top-level tool arguments as clients send them. A property a tool's schema does not declare can arrive as a string
// ("1200", "true"), so whole numbers and booleans are also accepted in that form; anything else is a clear error.
int64_t integer_argument(const Json& value, const char* name) {
    if (const auto* number = std::get_if<int64_t>(&value.value)) return *number;
    if (const auto* real = std::get_if<double>(&value.value);
        real && *real == static_cast<double>(static_cast<int64_t>(*real))) return static_cast<int64_t>(*real);
    if (const auto* text = std::get_if<std::string>(&value.value); text && !text->empty() && text->size() <= 18 &&
        text->find_first_not_of("0123456789") == std::string::npos) return std::stoll(*text);
    throw std::runtime_error(std::string(name) + " must be an integer");
}
bool boolean_argument(const Json& value, const char* name) {
    if (const auto* flag = std::get_if<bool>(&value.value)) return *flag;
    if (const auto* text = std::get_if<std::string>(&value.value); text && (*text == "true" || *text == "false"))
        return *text == "true";
    throw std::runtime_error(std::string(name) + " must be true or false");
}

// The call in shgrep syntax, s::<3::group~>operation("target"), as the last text block of each result. Codex shows
// only "server.tool" for a call, ignores MCP titles and previews the tail of a result in its compact view, so the
// transcript shows the syntax this way. repl cells already
// show their code, so they get none.
std::string love_call_line(const std::string& tool, const Json& arguments) {
    if (tool == "repl") return {};
    std::string group = "fs", operation = tool;
    const Json* source = &arguments;
    if (tool == "lsp") {
        const Json* method = arguments.get("method");
        const std::string name = method && std::holds_alternative<std::string>(method->value) ? method->string() : "help";
        const size_t dot = name.find('.');
        group = dot == std::string::npos ? "lsp" : name.substr(0, dot);
        operation = dot == std::string::npos ? name : name.substr(dot + 1);
        source = arguments.get("arguments");
    }
    std::string shown;
    if (source && std::holds_alternative<Json::Object>(source->value)) {
        size_t count = 0;
        for (const char* key : {"relative_path", "path", "source", "name_path", "name_path_pattern", "pattern", "destination"}) {
            const Json* value = source->get(key);
            if (!value || !std::holds_alternative<std::string>(value->value) || count == 2) continue;
            std::string text = value->string();
            if (text.size() > 120) text = text.substr(0, 117) + "...";
            shown += (count++ ? ", " : "") + Json(text).dump();
        }
    }
    return "s::<3::" + group + "~>" + operation + "(" + shown + ")\n";
}

std::string continue_marker(const std::string& key, size_t next, size_t total) {
    return "[status output_limit: showed up to byte " + std::to_string(next) + " of " + std::to_string(total) +
           "; nothing was cut. Read the next part by calling this tool again with continue: \"" + key + ":" +
           std::to_string(next) + "\", or narrow the request.]\n";
}

size_t utf8_step(std::string_view text, size_t at) {
    const auto lead = static_cast<unsigned char>(text[at]);
    const size_t length = lead < 0x80 ? 1 : lead >= 0xF0 && lead < 0xF8 ? 4 : lead >= 0xE0 ? 3 : lead >= 0xC0 ? 2 : 1;
    return std::min(length, text.size() - at);
}

// The response for text[offset..]: all of it when it fits max_bytes; else the longest part that fits, ended at its last
// line break (else at a character), and the continue marker. make_key names the continuation, storing it if needed.
std::string text_page(const Json& id, const std::string& text, size_t offset, uint32_t max_bytes, bool uncapped,
                      const std::string& notice, const std::function<std::string()>& make_key,
                      const std::function<void()>& check) {
    const std::string_view rest = std::string_view(text).substr(offset);
    const auto respond = [&](std::string body) {
        return success(id, Json::Object{{"content", content(std::move(body), notice)}}).dump(check);
    };
    const size_t frame = respond(std::string()).size() - Json::escaped_size("");
    if (uncapped || frame + Json::escaped_size(rest, check) <= max_bytes) return respond(std::string(rest));
    const std::string key = make_key();
    // The longest marker (the most digits) bounds every page's; escaped_size counts its quotes once per string.
    const size_t marker = Json::escaped_size(continue_marker(key, text.size(), text.size())) - 2;
    if (frame + 2 + marker >= max_bytes) throw std::runtime_error("max_output_bytes is too small for any output; raise it");
    const size_t budget = max_bytes - frame - 2 - marker;
    size_t used = 0, length = 0, line_end = 0;
    while (length < rest.size()) {
        if ((length & 1023) < 4) check();
        const size_t step = utf8_step(rest, length);
        const size_t cost = Json::escaped_size(rest.substr(length, step)) - 2;
        if (used + cost > budget) break;
        used += cost;
        length += step;
        if (rest[length - 1] == '\n') line_end = length;
    }
    if (line_end) length = line_end;
    if (!length) throw std::runtime_error("max_output_bytes is too small for any output; raise it");
    return respond(std::string(rest.substr(0, length)) + continue_marker(key, offset + length, text.size()));
}

// The response for items [first..] of a result split into frame (every member but results) and items fetched by
// index: as many whole items as fit, in a complete result object whose summary names the page and
// continue: "<key>:<next item>". Items are fetched and copied only as far as the probes reach.
std::string json_items_page(const Json& id, const Json::Object& frame, size_t total,
                            const std::function<Json(size_t)>& item_at, size_t first, uint32_t max_bytes,
                            const std::string& notice, const std::string& key, const std::function<void()>& check) {
    std::vector<Json> loaded;  // items [first, first + loaded.size())
    const auto page = [&](size_t count) {
        while (loaded.size() < count) {
            check();
            loaded.push_back(item_at(first + loaded.size()));
        }
        Json::Object out = frame;
        out["results"] = Json::Array(loaded.begin(), loaded.begin() + static_cast<std::ptrdiff_t>(count));
        const size_t next = first + count;
        if (auto it = out.find("summary"); it != out.end() && std::holds_alternative<Json::Object>(it->second.value)) {
            auto& summary = std::get<Json::Object>(it->second.value);
            summary["page"] = Json::Object{{"first", static_cast<uint64_t>(first)}, {"count", static_cast<uint64_t>(count)},
                                           {"total", static_cast<uint64_t>(total)}};
            if (next < total) {
                summary["continue"] = key + ":" + std::to_string(next);
                summary["note"] = "nothing was cut: call this tool again with continue for the next items, or narrow the request";
            }
        }
        return success(id, Json::Object{{"content", content(shgrep::pack_json(Json(std::move(out)), check).dump(check), notice)}}).dump(check);
    };
    // Whole items only. Gallop 1, 2, 4, ... until a page overflows, then bisect inside the last step, so probes stay
    // proportional to the page that fits (each probe serializes one page).
    const size_t available = total - first;
    size_t low = 0, high = 0;
    for (size_t probe = 1;; probe *= 2) {
        probe = std::min(probe, available);
        if (page(probe).size() > max_bytes) { high = probe - 1; break; }
        low = high = probe;
        if (probe == available) break;
    }
    while (low < high) {
        check();
        const size_t mid = low + (high - low + 1) / 2;
        if (page(mid).size() <= max_bytes) low = mid;
        else high = mid - 1;
    }
    if (!low) throw std::runtime_error("max_output_bytes cannot hold one result item; raise it");
    return page(low);
}

// Returns the serialized response, so the size check and the send share one dump.
std::string tool_response(const Json& id, Json& result, uint32_t max_bytes, bool uncapped,
                          const std::string& notice, const std::function<void()>& check) {
    check();
    if (const Json* value = result.get("structured_result")) {
        Json::Array blocks = content(shgrep::pack_json(*value, check).dump(check), notice).array();
        if (const Json* output = result.get("text"); output && !output->string().empty())
            blocks.insert(blocks.begin() + 1, Json::Object{{"type", "text"}, {"text", output->string()}});
        std::string response = success(id, Json::Object{{"content", std::move(blocks)}}).dump(check);
        if (!uncapped && response.size() > max_bytes)
            throw std::runtime_error("max_output_bytes cannot hold structured MCP response");
        return response;
    }
    // CONTRACT: text output (lines/files/count) is sent as-is so agents read grep-style lines, not JSON.
    if (const Json* text = result.get("text")) {
        return text_page(id, text->string(), 0, max_bytes, uncapped, notice, [&] {
            auto kept = std::make_shared<Continuation>();
            kept->text = text->string();
            kept->max_bytes = max_bytes;
            kept->size = kept->text.size();
            return keep_continuation(std::move(kept));
        }, check);
    }
    {
        std::string whole = success(id, Json::Object{{"content", content(shgrep::pack_json(result, check).dump(check), notice)}}).dump(check);
        if (uncapped || whole.size() <= max_bytes) return whole;
    }
    const Json* listed = std::holds_alternative<Json::Object>(result.value) ? result.get("results") : nullptr;
    if (!listed || !std::holds_alternative<Json::Array>(listed->value))
        throw std::runtime_error("max_output_bytes cannot hold this response; raise it");
    const Json::Array& items = listed->array();
    // Kept as frame plus per-item strings: the frame copy skips results, and later pages parse only their items.
    auto kept = std::make_shared<Continuation>();
    kept->json = true;
    for (const auto& [name, value] : result.object())
        if (name != "results") kept->frame.emplace(name, value);
    kept->size = Json(kept->frame).dump(check).size();
    kept->items.reserve(items.size());
    for (const auto& item : items) {
        kept->items.push_back(item.dump(check));
        kept->size += kept->items.back().size() + 1;
    }
    kept->max_bytes = max_bytes;
    const Json::Object frame = kept->frame;
    const std::string key = keep_continuation(std::move(kept));
    return json_items_page(id, frame, items.size(), [&](size_t index) { return items[index]; }, 0, max_bytes, notice, key, check);
}

// The response to continue: "<id>:<offset>", from the stored output.
std::string continued_response(const Json& id, const std::string& resume, uint32_t max_bytes, bool capped,
                               const std::string& notice, const std::function<void()>& check) {
    check();
    const size_t colon = resume.rfind(':');
    const std::string key = colon == std::string::npos ? resume : resume.substr(0, colon);
    size_t offset = 0;
    try {
        if (colon == std::string::npos) throw std::invalid_argument("no offset");
        size_t used = 0;
        offset = static_cast<size_t>(std::stoull(resume.substr(colon + 1), &used));
        if (used != resume.size() - colon - 1) throw std::invalid_argument("trailing text");
    } catch (const std::exception&) {
        throw std::runtime_error("continue must be \"<id>:<offset>\" as a status line names it");
    }
    const std::shared_ptr<const Continuation> kept = find_continuation(key);
    if (!kept) throw std::runtime_error("continue \"" + resume + "\" is unknown or expired (the server keeps the last 16 "
                                        "split outputs); run the request again");
    const uint32_t bytes = capped ? max_bytes : kept->max_bytes;
    const auto same = [&] { return key; };
    if (kept->json) {
        if (offset >= kept->items.size()) throw std::runtime_error("continue offset is past the last item");
        return json_items_page(id, kept->frame, kept->items.size(),
                               [&](size_t index) { return Json::parse(kept->items[index]); }, offset, bytes, notice, key, check);
    }
    if (offset >= kept->text.size()) throw std::runtime_error("continue offset is past the end of the output");
    if ((static_cast<unsigned char>(kept->text[offset]) & 0xC0) == 0x80)
        throw std::runtime_error("continue offset is not at a character boundary; use the one a status line names");
    return text_page(id, kept->text, offset, bytes, false, notice, same, check);
}

// The tool in shgrep's call syntax: s::<3::fs~>read_file, s::<3::lsp~>call, s::<3::repl~>cell.
std::string love_tool_name(const std::string& tool) {
    return tool == "lsp" ? "s::<3::lsp~>call" : tool == "repl" ? "s::<3::repl~>cell" : "s::<3::fs~>" + tool;
}
// The internal tool for a name a client sends; plain names pass through, so both spellings work.
std::string tool_from_love_name(const std::string& name) {
    static constexpr std::string_view fs_prefix = "s::<3::fs~>";
    if (name == "s::<3::lsp~>call") return "lsp";
    if (name == "s::<3::repl~>cell") return "repl";
    if (name.starts_with(fs_prefix)) {
        std::string tool = name.substr(fs_prefix.size());
        if (tool != "lsp" && tool != "repl") return tool;
    }
    return name;
}
// Adds `continue` to every tool that takes max_output_bytes, and says that larger output continues rather than is cut.
// love_names (--love-tool-names) also sends the call syntax as the tool name. Codex shows the raw name in its
// "Called server.tool" line and gives the model a cleaned name (other characters become _), so this is opt-in:
// clients and hooks that match plain names such as mcp__shgrep__read_file keep the default.
Json with_continuations(Json tools, bool love_names) {
    if (!std::holds_alternative<Json::Array>(tools.value)) return tools;
    for (Json& tool : std::get<Json::Array>(tools.value)) {
        if (!std::holds_alternative<Json::Object>(tool.value)) continue;
        auto& definition = std::get<Json::Object>(tool.value);
        // Display titles in shgrep's call syntax for clients that show MCP tool titles.
        if (const auto name = definition.find("name");
            name != definition.end() && std::holds_alternative<std::string>(name->second.value)) {
            const std::string title = love_tool_name(name->second.string());
            definition["title"] = title;
            auto& annotations = definition["annotations"];
            if (!std::holds_alternative<Json::Object>(annotations.value)) annotations = Json::Object{};
            std::get<Json::Object>(annotations.value)["title"] = title;
        }
        const auto schema = definition.find("inputSchema");
        if (schema == definition.end() || !std::holds_alternative<Json::Object>(schema->second.value)) continue;
        auto& fields = std::get<Json::Object>(schema->second.value);
        const auto properties = fields.find("properties");
        if (properties == fields.end() || !std::holds_alternative<Json::Object>(properties->second.value)) continue;
        auto& props = std::get<Json::Object>(properties->second.value);
        props["offload_output"] = Json::Object{{"type", "boolean"},
            {"description", "Default true: save text over 8000 bytes as UTF-8 under the first root's .shgrep-output folder, returning a 500-character preview and path. Files persist until deleted. Structured values remain inline; read-only mode keeps all output inline. Set false to read a saved output inline."}};
        const auto limit = props.find("max_output_bytes");
        if (limit == props.end()) continue;
        if (std::holds_alternative<Json::Object>(limit->second.value)) {
            auto& description = std::get<Json::Object>(limit->second.value)["description"];
            const std::string before = std::holds_alternative<std::string>(description.value) ? description.string() : "";
            const bool semantic = tool.get("name") &&
                (tool.get("name")->string() == "lsp" || tool.get("name")->string() == "repl");
            description = before + (before.empty() ? "" : " ") + (semantic
                ? "Split text output ends with continue: \"<id>:<offset>\" for the rest; structured responses must fit the limit."
                : "Larger output is never cut: the response ends with continue: \"<id>:<offset>\" for the rest.");
        }
        props["continue"] = Json::Object{{"type", "string"},
            {"description", "Reads the next part of an earlier response that max_output_bytes split: pass the "
                            "\"<id>:<offset>\" its status line or summary names. The tool is not run again; other "
                            "arguments except max_output_bytes are ignored."}};
    }
    // Renamed last: the loop above still reads the plain names.
    if (love_names)
        for (Json& tool : std::get<Json::Array>(tools.value))
            if (std::holds_alternative<Json::Object>(tool.value))
                if (auto& definition = std::get<Json::Object>(tool.value); definition.contains("name") &&
                    std::holds_alternative<std::string>(definition["name"].value))
                    definition["name"] = love_tool_name(definition["name"].string());
    return tools;
}

// Invalid UTF-8 becomes U+FFFD instead of dropping the rest of the message.
std::string valid_utf8(const std::string& text) {
    if (text.empty() || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                                            nullptr, 0)) return text;
    const int wide_size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring wide(static_cast<size_t>(wide_size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), wide_size);
    const int size = WideCharToMultiByte(CP_UTF8, 0, wide.data(), wide_size, nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), wide_size, out.data(), size, nullptr, nullptr);
    return out;
}

Json tool_error_response(const Json& id, std::string message, uint32_t max_bytes, bool uncapped,
                          const std::string& notice, const Json* structured_content = nullptr) {
    if (message.find(" - tell the user about this in your next message, before continuing:") == std::string::npos)
        message = shgrep::failure_banner("SHGREP ERROR", "The request failed", "Details follow") + message;
    const auto build = [&](const std::string& text, const std::string& health, const Json* details) {
        Json::Object result{{"isError", true}, {"content", content(valid_utf8(text), health)}};
        if (details) result.emplace("structuredContent", *details);
        return success(id, std::move(result));
    };
    if (uncapped) return build(message, notice, structured_content);
    // CONTRACT: the whole serialized error envelope, structured details and health notice included, is measured
    //   against max_output_bytes. Structured details go first (the message already names the key facts), then the
    //   health notice, then the message is shortened. A response that cannot fit even with an empty message is
    //   returned in that minimal form.
    if (message.size() > 1024) message.resize(1024);
    if (structured_content) {
        Json response = build(message, notice, structured_content);
        if (response.dump().size() <= max_bytes) return response;
        message += "\n[structured error details omitted: they exceed max_output_bytes]";
    }
    std::string health = notice;
    for (;;) {
        Json response = build(message, health, nullptr);
        if (response.dump().size() <= max_bytes) return response;
        if (!health.empty()) { health.clear(); continue; }
        if (message.empty()) return response;
        message.resize(message.size() / 2);
    }
}
std::string request_key(const Json& id) { return id.dump(); }
bool read_line(std::string& line, const std::atomic_bool* exiting = nullptr) {
    line.clear();
    bool oversized = false;
    for (;;) {
        // Exit also stops a continuously supplied or oversized line without
        // waiting for a newline or for a pending Windows I/O operation.
        if (exiting && exiting->load()) return false;
        int c = std::getc(stdin);
        if (c == EOF) return !line.empty() || oversized;
        if (c == '\n') {
            if (oversized) line.clear();
            return true;
        }
        if (line.size() < 1048576) line.push_back(static_cast<char>(c));
        else oversized = true;
    }
}

// Only the MCP input reader can be interrupted by the tray. Holding this mutex
// around the state transitions keeps cancellation away from stdout and worker I/O.
struct McpInputWait {
    HANDLE thread = nullptr;
    std::mutex mutex;
    bool reading = false;
    bool cancel_error_reported = false;
    std::atomic_bool exiting{false};

    explicit McpInputWait(bool enabled) noexcept {
        if (enabled && !DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                                        &thread, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            std::fprintf(stderr, "shgrep: log window unavailable: cannot prepare tray Exit (Windows error %lu); MCP server continues\n",
                         static_cast<unsigned long>(GetLastError()));
        }
    }
    ~McpInputWait() {
        if (thread) CloseHandle(thread);
    }

    void request_exit() {
        std::lock_guard lock(mutex);
        exiting.store(true);
        if (reading && !CancelSynchronousIo(thread)) {
            const DWORD code = GetLastError();
            // A cancellation can beat the actual ReadFile call. The UI timer
            // retries until read() has observed the exit flag and unwound.
            if (code != ERROR_NOT_FOUND && !cancel_error_reported) {
                cancel_error_reported = true;
                std::fprintf(stderr, "shgrep: cannot interrupt MCP input for tray Exit (Windows error %lu)\n",
                             static_cast<unsigned long>(code));
            }
        }
    }

    bool read(std::string& line) {
        if (!thread) return read_line(line);
        {
            std::lock_guard lock(mutex);
            if (exiting.load()) return false;
            reading = true;
        }
        struct ReadGuard {
            McpInputWait& input;
            ~ReadGuard() {
                std::lock_guard lock(input.mutex);
                input.reading = false;
            }
        } guard{*this};
        const bool have_line = read_line(line, &exiting);
        // Do not parse a partial line returned by a cancelled stdio read.
        return have_line && !exiting.load();
    }
};
}

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"--repl-worker") return shgrep::run_repl_worker();
    if (argc > 1 && std::wstring_view(argv[1]) == L"--pack-data") return shgrep::pack_runtime_data(argc - 1, argv + 1);
    // MCP clients start the server with stdin as a pipe; a person at a console gets the CLI, even for
    // `shgrep --root DIR PATTERN`.
    DWORD console_mode = 0;
    const bool interactive = GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &console_mode) != 0;
    if (argc == 1 && interactive) return shgrep::run_cli(argc, argv);
    if (argc > 1 && (interactive || (std::wstring(argv[1]) != L"--root" && std::wstring(argv[1]) != L"--read-only" &&
                                     std::wstring(argv[1]) != L"--live-index" && std::wstring(argv[1]) != L"--no-live-index" &&
                                     std::wstring(argv[1]) != L"--love-tool-names" &&
                                     std::wstring(argv[1]) != L"--enable-gui-log-window")))
        return shgrep::run_cli(argc, argv);
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    shgrep::SearchContext context;
    // The MCP server builds and watches the workspace's index by default; --live-index stays accepted for old configs.
    context.live_index = true;
    bool gui_log_window = false;
    bool love_tool_names = false;
    for (int i = 1; i < argc; ++i) {
        if (std::wstring(argv[i]) == L"--root" && i + 1 < argc) context.allowed_roots.emplace_back(argv[++i]);
        else if (std::wstring(argv[i]) == L"--read-only") context.read_only = true;
        else if (std::wstring(argv[i]) == L"--live-index") context.live_index = true;
        else if (std::wstring(argv[i]) == L"--no-live-index") context.live_index = false;
        else if (std::wstring_view(argv[i]) == L"--love-tool-names") love_tool_names = true;
        else if (std::wstring_view(argv[i]) == L"--enable-gui-log-window" && i + 1 < argc &&
                 (std::wstring_view(argv[i + 1]) == L"true" || std::wstring_view(argv[i + 1]) == L"false"))
            gui_log_window = std::wstring_view(argv[++i]) == L"true";
        else {
            std::fprintf(stderr, "usage: shgrep [--root DIRECTORY]... [--read-only] [--no-live-index] "
                                 "[--love-tool-names] [--enable-gui-log-window true|false] for MCP; "
                                 "shgrep --help for CLI\n");
            return 2;
        }
    }
    if (context.allowed_roots.empty()) context.allowed_roots.push_back(std::filesystem::current_path());
    // SAFETY: the live index writes into the workspace (.shgrep\index files and sync cookies), so --read-only turns
    // it off whatever the order of the flags; searches then walk unless they pass index: true for an existing snapshot.
    if (context.read_only) context.live_index = false;
    // SHGREP_REQUIRE_INTENT=0 lifts the intent requirement for test suites; an MCP client cannot change it.
    wchar_t require_intent[4];
    const DWORD require_length = GetEnvironmentVariableW(L"SHGREP_REQUIRE_INTENT", require_intent, 4);
    context.require_intent = !(require_length == 1 && require_intent[0] == L'0');
    // Keep the cancellable input handle alive until the viewer's callback and UI thread stop.
    McpInputWait input_wait(gui_log_window);
    // Declare the viewer before all asynchronous producers so it outlives their futures.
    shgrep::LogWindow logs(gui_log_window && input_wait.thread != nullptr,
                           [&input_wait] { input_wait.request_exit(); });
    using shgrep::LogLevel;
    logs.write(LogLevel::info, context.read_only ? "Starting MCP server in read-only mode" : "Starting MCP server");
    const auto send_error = [&](const Json& id, int code, const std::string& message) {
        // Keep the existing response and log its full diagnostic separately.
        const char* category = code == -32700 ? "Invalid or oversized JSON message" :
            code == -32600 ? "Invalid JSON-RPC request" :
            code == -32602 ? "Invalid request arguments" :
            code == -32601 ? "Unknown JSON-RPC method" :
            code == -32000 ? "Request rejected: server busy" : "JSON-RPC request rejected";
        const Json response = error(id, code, message);
        send(response);
        logs.write(LogLevel::warning, category);
        logs.write_payload(LogLevel::error, "JSON-RPC error response", response);
    };
    // Index and warm-up events also show in the log window. Detached index threads may log until exit, so the guard,
    // declared after `logs`, removes the listener on every way out of wmain before the window goes away.
    shgrep::set_index_log_listener([&logs](bool warning, const std::string& message) {
        logs.write(warning ? LogLevel::warning : LogLevel::info, message, "index");
    });
    struct IndexLogListenerGuard {
        ~IndexLogListenerGuard() { shgrep::set_index_log_listener({}); }
    } index_log_listener_guard;
    // The build and the watchers run in the background; searches walk until the workspace's index is ready.
    if (context.live_index) shgrep::start_live_indexes(context);
    shgrep::start_language_servers(context);
    // GPU build: the DLLs and the embedding model load in the background; ranked searches wait for them (#87).
    shgrep::start_embedder();
    shgrep::start_meaning_index(context);
    // The health check runs while the client finishes its handshake; the first tool result of the session carries it.
    const std::shared_future<std::string> health = std::async(std::launch::async, [&context, &logs] {
        try {
            auto notice = shgrep::health_notice(context);
            logs.write(notice.empty() ? LogLevel::info : LogLevel::warning,
                       notice.empty() ? std::string_view("Health check completed") : std::string_view(notice));
            return notice;
        } catch (const std::exception& e) {
            logs.write(LogLevel::error, "Health check failed; diagnostic will accompany a tool response");
            logs.write(LogLevel::error, e.what());
            return shgrep::failure_banner("SHGREP HEALTH", std::string("the health check itself failed: ") + e.what(),
                                          "Requests still run and report their own failures");
        }
    }).share();
    std::atomic_bool health_sent{false};
    std::mutex active_mutex;
    std::map<std::string, std::shared_ptr<std::atomic_bool>> active;
    std::vector<std::future<void>> tasks;
    std::string line;
    while (input_wait.read(line)) {
        if (input_wait.exiting.load()) break;
        for (auto it = tasks.begin(); it != tasks.end();) {
            if (it->wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                try { it->get(); } catch (const std::exception& e) {
                    logs.write(LogLevel::error, "MCP worker failed");
                    logs.write(LogLevel::error, e.what());
                    std::fprintf(stderr, "worker: %s\n", e.what());
                }
                it = tasks.erase(it);
            } else ++it;
        }
        if (line.empty()) { send_error(nullptr, -32700, "invalid or oversized JSON message"); continue; }
        Json request;
        try { request = Json::parse(line); }
        catch (const std::exception& e) { send_error(nullptr, -32700, e.what()); continue; }
        const Json* id_ptr = request.get("id");
        Json id = id_ptr ? *id_ptr : Json(nullptr);
        bool has_id = id_ptr && !std::holds_alternative<std::nullptr_t>(id_ptr->value);
        try {
            const Json* version = request.get("jsonrpc");
            const Json* method = request.get("method");
            if (!version || !std::holds_alternative<std::string>(version->value) || version->string() != "2.0" ||
                !method || !std::holds_alternative<std::string>(method->value)) {
                send_error(id, -32600, "invalid JSON-RPC request"); continue;
            }
            if (id_ptr && !std::holds_alternative<std::string>(id_ptr->value) &&
                !std::holds_alternative<int64_t>(id_ptr->value) &&
                !std::holds_alternative<std::nullptr_t>(id_ptr->value)) {
                send_error(nullptr, -32600, "invalid JSON-RPC id"); continue;
            }
            if (id_ptr && id_ptr->dump().size() > 256) { send_error(nullptr, -32600, "JSON-RPC id is too long"); continue; }
            const std::string& name = method->string();
            if (name == "notifications/cancelled") {
                const Json* params = request.get("params");
                const Json* target = params ? params->get("requestId") : nullptr;
                if (target) {
                    std::lock_guard lock(active_mutex);
                    auto it = active.find(request_key(*target));
                    if (it != active.end()) {
                        it->second->store(true);
                        logs.write(LogLevel::warning, "Cancellation requested for an active tool call");
                    }
                }
                continue;
            }
            if (!has_id) continue;
            if (name == "initialize") {
                const Json* params = request.get("params");
                const Json* wanted = params ? params->get("protocolVersion") : nullptr;
                std::string protocol = "2025-06-18";
                if (wanted && std::holds_alternative<std::string>(wanted->value)) {
                    if (wanted->string() == "2024-11-05" || wanted->string() == "2025-03-26" || wanted->string() == "2025-06-18")
                        protocol = wanted->string();
                }
                const std::string love_names_note = love_tool_names
                    ? " Tool names use the shgrep call syntax: s::<3::fs~>read_file is the read_file tool, s::<3::lsp~>call is lsp "
                      "and s::<3::repl~>cell is repl; plain names are accepted too."
                    : "";
                const std::string instructions = shgrep::tool_manual(context, true) + love_names_note;
                send(success(id, Json::Object{{"protocolVersion", protocol},
                                              {"capabilities", Json::Object{{"tools", Json::Object{}}}},
                                              {"serverInfo", Json::Object{{"name", "shgrep"}, {"version", "0.3.0"}}},
                                              {"instructions", instructions}}));
                logs.write(LogLevel::info, "MCP client initialized");
            } else if (name == "ping") send(success(id, Json::Object{}));
            else if (name == "tools/list") send(success(id, Json::Object{{"tools", with_continuations(shgrep::tool_list(context), love_tool_names)}}));
            else if (name == "tools/call") {
                std::string key = request_key(id);
                // Includes the original arguments, even for rejected tool calls.
                logs.write_payload(LogLevel::info, "Tool call request", request, "tools/call", key);
                const Json* params = request.get("params");
                if (!params || !params->get("name")) { send_error(id, -32602, "tool name required"); continue; }
                // Both spellings route to the same tool; logs and results use the plain name.
                std::string tool_name = tool_from_love_name(params->get("name")->string());
                if (!shgrep::tool_available(tool_name, context)) {
                    send_error(id, -32602, "unknown tool"); continue;
                }
                Json arguments = params->get("arguments") ? *params->get("arguments") : Json::Object{};
                auto flag = std::make_shared<std::atomic_bool>(false);
                {
                    std::lock_guard lock(active_mutex);
                    if (active.size() >= 4) { send_error(id, -32000, "server busy"); continue; }
                    if (active.contains(key)) { send_error(id, -32600, "duplicate request id"); continue; }
                    active.emplace(key, flag);
                }
                try { tasks.push_back(std::async(std::launch::async, [&, id, tool_name, arguments, flag, key] {
                    const auto started = std::chrono::steady_clock::now();
                    const auto elapsed_ms = [&] {
                        return std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - started).count();
                    };
                    logs.write(LogLevel::info, "Tool call started", tool_name, key);
                    bool partial_timeout = false;
                    const std::string call_line = love_call_line(tool_name, arguments);
                    bool uncapped = !arguments.get("max_output_bytes");
                    std::string notice;
                    const uint32_t ceiling = 1048576;
                    uint32_t max_bytes = 65536;
                    bool completed_writes = false;
                    Json result;
                    bool has_result = false;
                    // A large uncapped text-search result arrives here instead of in result["text"].
                    std::shared_ptr<shgrep::TextStream> stream;
                    try {
                        int64_t timeout;
                        if (tool_name == "lsp") {
                            const shgrep::RequestDeadline resolving(started + std::chrono::milliseconds(300000));
                            timeout = shgrep::lsp_request_timeout_ms(arguments, context, flag);
                        } else {
                            timeout = arguments.get("timeout_ms") ? integer_argument(*arguments.get("timeout_ms"), "timeout_ms")
                                : shgrep::default_request_timeout_ms(tool_name, arguments);
                        }
                        if (timeout < 1 || timeout > 300000) throw std::runtime_error("timeout_ms must be 1-300000");
                        using ResponseClock = std::chrono::steady_clock;
                        const auto deadline = (tool_name == "lsp" ? started : ResponseClock::now()) + std::chrono::milliseconds(timeout);
                        const shgrep::RequestDeadline request_deadline(deadline);
                        auto encoding_deadline = deadline;
                        const std::function<void()> check = [&] {
                            if (flag->load()) throw std::runtime_error("request cancelled while encoding response");
                            if (ResponseClock::now() >= encoding_deadline)
                                throw std::runtime_error("request timed out while encoding response");
                        };
                        if (health.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready &&
                            !health_sent.exchange(true)) notice = health.get();
                        if (const Json* limit = arguments.get("max_output_bytes")) {
                            int64_t requested = integer_argument(*limit, "max_output_bytes");
                            if (requested < 512 || requested > ceiling)
                                throw std::runtime_error("max_output_bytes must be 512-1048576");
                            max_bytes = static_cast<uint32_t>(requested);
                        }
                        if (const Json* resume = arguments.get("continue")) {
                            if (!std::holds_alternative<std::string>(resume->value))
                                throw std::runtime_error("continue must be the \"<id>:<offset>\" string a status line names");
                            const std::string response = continued_response(id, resume->string(), max_bytes, !uncapped, notice, check);
                            send_line(response);
                            logs.write(LogLevel::info, "Continuation response", tool_name, key);
                            logs.write(LogLevel::info, response, tool_name, key);
                        } else {
                            // The tool returns its whole output; tool_response splits it at max_output_bytes into
                            // continued parts, so nothing is cut.
                            const Json* offload_argument = arguments.get("offload_output");
                            const bool offload_output = (!offload_argument || boolean_argument(*offload_argument, "offload_output")) &&
                                !context.read_only;
                            Json tool_arguments = arguments;
                            if (std::holds_alternative<Json::Object>(tool_arguments.value)) {
                                auto& object = std::get<Json::Object>(tool_arguments.value);
                                object.erase("max_output_bytes");
                                object.erase("offload_output");
                                if (tool_name == "lsp") object["timeout_ms"] = timeout;
                            }
                            result = shgrep::run_tool(tool_name, tool_arguments, context, flag,
                                                  (uncapped || offload_output) ? &stream : nullptr,
                                                  (uncapped || offload_output) ? 0 : max_continuation_bytes);
                            has_result = true;
                            completed_writes = shgrep::is_write_tool(tool_name) &&
                                (!arguments.get("dry_run") || !std::holds_alternative<bool>(arguments.get("dry_run")->value) ||
                                 !arguments.get("dry_run")->boolean());
                            if (const Json* writes = result.get("completed_writes"))
                                completed_writes = completed_writes || writes->integer() > 0;
                            if (const Json* limit = result.get("response_max_output_bytes"); limit && limit->integer() != 0) {
                                const int64_t requested = limit->integer();
                                if (requested < 512 || requested > ceiling)
                                    throw std::runtime_error("max_output_bytes must be 512-1048576");
                                max_bytes = uncapped ? static_cast<uint32_t>(requested)
                                                     : std::min(max_bytes, static_cast<uint32_t>(requested));
                                uncapped = false;
                            }
                            // Timed-out text searches retain their partial results. Bound the extra encoding work.
                            const Json* summary = result.get("summary");
                            const Json* status = summary ? summary->get("status") : nullptr;
                            if (status && status->string() == "timeout") {
                                partial_timeout = true;
                                encoding_deadline = std::max(deadline, ResponseClock::now() + std::chrono::seconds(1));
                            }
                            const Json* output = result.get("text");
                            if (offload_output && (stream || (output && output->string().size() > 8000))) {
                                try {
                                    if (stream) stream->retain_for_replay();
                                    size_t at = 0;
                                    const Json saved = shgrep::save_output_artifact(context, [&](std::string& piece) {
                                        if (stream) return stream->next(piece);
                                        const std::string& text = output->string();
                                        if (at == text.size()) return false;
                                        const size_t count = std::min<size_t>(text.size() - at, size_t{1} << 20);
                                        piece.assign(text, at, count);
                                        at += count;
                                        return true;
                                    }, check);
                                    const Json read_arguments = Json::Object{{"path", saved.get("path")->string()},
                                        {"offload_output", false}, {"operation", "text"}, {"offset", 1}, {"limit", 100}};
                                    std::string preview = saved.get("preview")->string() +
                                        "\n[Complete text output saved: " + saved.get("path")->string() +
                                        " | " + std::to_string(saved.get("bytes")->integer()) + " bytes]\n" +
                                        "Read with read_file " + read_arguments.dump() + "\n";
                                    std::get<Json::Object>(result.value)["text"] = std::move(preview);
                                    stream.reset();
                                } catch (const std::exception& e) {
                                    if (stream) stream->rewind();
                                    check();
                                    if (stream && !uncapped)
                                        throw std::runtime_error(std::string("output offloading failed: ") + e.what() +
                                            "; the complete output cannot fit this response limit; retry with offload_output=false and a narrower query");
                                    notice += std::string(notice.empty() ? "" : "\n") +
                                        "[warning: output offloading failed; returning complete output inline: " + e.what() + "]\n";
                                }
                            }
                            // Codex's compact view shows only the last lines of a result, so the call line ends the
                            // response as the final text block; the result itself keeps its exact shape.
                            if (!call_line.empty())
                                notice += std::string(notice.empty() || notice.ends_with('\n') ? "" : "\n") + call_line;
                            if (stream) send_stream(id, *stream, notice, check);
                            else send_line(tool_response(id, result, max_bytes, uncapped, notice, check));
                        }
                        logs.write(partial_timeout ? LogLevel::warning : LogLevel::info,
                                   partial_timeout ? "Response sent with partial results after timeout" : "Response sent",
                                   tool_name, key, elapsed_ms());
                    } catch (const std::exception& e) {
                        // Log the full diagnostic as well as the size-limited MCP error response.
                        const std::string_view reason(e.what());
                        const bool cancelled = flag->load();
                        const bool timed_out = reason.find("timed out") != std::string_view::npos;
                        logs.write(cancelled || timed_out ? LogLevel::warning : LogLevel::error,
                                   cancelled ? "Tool call cancelled" : timed_out ? "Tool call timed out" :
                                   "Tool call failed; diagnostic returned to client", tool_name, key, elapsed_ms());
                        std::string message = e.what();
                        if (completed_writes) message += "\nThe write operation completed; any applied changes remain in place.";
                        const shgrep::Json* structured_content = nullptr;
                        if (const auto* warming = dynamic_cast<const shgrep::IndexWarmingFailure*>(&e))
                            structured_content = &warming->details;
                        else if (const auto* lookup = dynamic_cast<const shgrep::SymbolLookupFailure*>(&e))
                            structured_content = &lookup->details;
                        // As on success, the call line is the final text block; a tight budget drops it before the message.
                        // Encoding can fail after the success path already appended it.
                        if (!call_line.empty() && !notice.ends_with(call_line))
                            notice += std::string(notice.empty() || notice.ends_with('\n') ? "" : "\n") + call_line;
                        send(tool_error_response(id, message, max_bytes, uncapped, notice, structured_content));
                        logs.write(cancelled || timed_out ? LogLevel::warning : LogLevel::error,
                                   message, tool_name, key);
                    }
                    // Preserve the complete backend value, before compression or response paging.
                    // Serialize after sending so detailed logging does not consume the encoding deadline.
                    if (has_result)
                        logs.write_payload(LogLevel::info, "Backend result (before response paging)", result, tool_name, key);
                    std::lock_guard lock(active_mutex);
                    active.erase(key);
                })); }
                catch (...) {
                    logs.write(LogLevel::error, "Could not schedule or retain the tool worker", tool_name, key);
                    std::lock_guard lock(active_mutex);
                    active.erase(key);
                    throw;
                }
            } else send_error(id, -32601, "method not found");
        } catch (const std::exception& e) {
            send_error(id, -32602, e.what());
        }
    }
    logs.write(LogLevel::info, input_wait.exiting.load()
        ? "Tray Exit requested; cancelling active tool calls"
        : "Client input closed; cancelling active tool calls");
    {
        std::lock_guard lock(active_mutex);
        for (auto& [_, flag] : active) flag->store(true);
    }
    for (auto& task : tasks) {
        try { task.get(); } catch (const std::exception& e) {
            logs.write(LogLevel::error, "MCP worker failed during shutdown");
            logs.write(LogLevel::error, e.what());
            std::fprintf(stderr, "worker: %s\n", e.what());
        }
    }
    shgrep::stop_language_server_warmup();
    health.wait();
    logs.write(LogLevel::info, "MCP server stopped");
    return 0;
}
