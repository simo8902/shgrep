#include "json.hpp"

#include <charconv>
#include <cmath>
#include <cstdio>
#include <limits>
#include <initializer_list>

namespace shgrep {
namespace {
const char* json_type_name(const Json& value) {
    static constexpr const char* names[] = {"null", "boolean", "integer", "number", "string", "array", "object"};
    return names[value.value.index()];
}
// A typed read of the wrong JSON type names both types instead of std::bad_variant_access's "bad variant access".
[[noreturn]] void wrong_type(const Json& value, const char* wanted) {
    throw std::runtime_error(std::string("JSON value is ") + json_type_name(value) + ", expected " + wanted);
}
}
const Json::Object& Json::object() const {
    if (const auto* found = std::get_if<Object>(&value)) return *found;
    wrong_type(*this, "object");
}
const Json::Array& Json::array() const {
    if (const auto* found = std::get_if<Array>(&value)) return *found;
    wrong_type(*this, "array");
}
const std::string& Json::string() const {
    if (const auto* found = std::get_if<std::string>(&value)) return *found;
    wrong_type(*this, "string");
}
int64_t Json::integer() const {
    if (const auto* found = std::get_if<int64_t>(&value)) return *found;
    // A whole-valued number (some servers send 3.0) is still an integer.
    if (const auto* real = std::get_if<double>(&value);
        real && std::isfinite(*real) && *real == std::trunc(*real) && std::fabs(*real) < 9.0e15)
        return static_cast<int64_t>(*real);
    wrong_type(*this, "integer");
}
bool Json::boolean() const {
    if (const auto* found = std::get_if<bool>(&value)) return *found;
    wrong_type(*this, "boolean");
}
const Json* Json::get(const std::string& key) const {
    auto* obj = std::get_if<Object>(&value);
    if (!obj) return nullptr;
    auto it = obj->find(key);
    return it == obj->end() ? nullptr : &it->second;
}

namespace {
bool valid_utf8(const std::string& s, const std::function<void()>& check = {}) {
    for (size_t i = 0; i < s.size();) {
        if (check && (i & 1023) < 4) check();
        unsigned char lead = static_cast<unsigned char>(s[i]);
        if (lead < 0x80) { ++i; continue; }
        size_t count = lead >= 0xf0 && lead <= 0xf4 ? 4 : lead >= 0xe0 && lead <= 0xef ? 3 :
                       lead >= 0xc2 && lead <= 0xdf ? 2 : 0;
        if (!count || i + count > s.size()) return false;
        uint32_t cp = lead & ((1u << (7 - count)) - 1);
        for (size_t j = 1; j < count; ++j) {
            unsigned char c = static_cast<unsigned char>(s[i + j]);
            if ((c & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (c & 0x3f);
        }
        if (cp < (count == 2 ? 0x80u : count == 3 ? 0x800u : 0x10000u) ||
            cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return false;
        i += count;
    }
    return true;
}
void append_utf8(std::string& out, uint32_t cp) {
    if (cp <= 0x7f) out.push_back(static_cast<char>(cp));
    else if (cp <= 0x7ff) {
        out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 63)));
    } else if (cp <= 0xffff) {
        out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 63)));
        out.push_back(static_cast<char>(0x80 | (cp & 63)));
    } else {
        out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 63)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 63)));
        out.push_back(static_cast<char>(0x80 | (cp & 63)));
    }
}
struct Parser {
    const std::string& s;
    size_t p = 0;
    void ws() { while (p < s.size() && (s[p] == ' ' || s[p] == '\n' || s[p] == '\r' || s[p] == '\t')) ++p; }
    char take() { if (p == s.size()) throw std::runtime_error("unexpected end of JSON"); return s[p++]; }
    void expect(char c) { if (take() != c) throw std::runtime_error("invalid JSON syntax"); }
    uint32_t hex4() {
        uint32_t n = 0;
        for (int i = 0; i < 4; ++i) {
            char c = take();
            n <<= 4;
            if (c >= '0' && c <= '9') n |= c - '0';
            else if (c >= 'a' && c <= 'f') n |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') n |= c - 'A' + 10;
            else throw std::runtime_error("invalid Unicode escape");
        }
        return n;
    }
    std::string str() {
        expect('"');
        std::string out;
        while (true) {
            char c = take();
            if (c == '"') {
                if (!valid_utf8(out)) throw std::runtime_error("invalid UTF-8 JSON string");
                return out;
            }
            if (static_cast<unsigned char>(c) < 32) throw std::runtime_error("control byte in JSON string");
            if (c != '\\') { out.push_back(c); continue; }
            switch (c = take()) {
            case '"': case '\\': case '/': out.push_back(c); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
                uint32_t cp = hex4();
                if (cp >= 0xd800 && cp <= 0xdbff) {
                    expect('\\'); expect('u');
                    uint32_t lo = hex4();
                    if (lo < 0xdc00 || lo > 0xdfff) throw std::runtime_error("invalid surrogate pair");
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                } else if (cp >= 0xdc00 && cp <= 0xdfff) throw std::runtime_error("invalid surrogate");
                append_utf8(out, cp);
                break;
            }
            default: throw std::runtime_error("invalid JSON escape");
            }
        }
    }
    Json parse(unsigned depth = 0) {
        if (depth > 64) throw std::runtime_error("JSON nesting limit exceeded");
        ws();
        if (p == s.size()) throw std::runtime_error("empty JSON value");
        if (s[p] == '"') return str();
        if (s[p] == '{') {
            ++p; Json::Object out; ws();
            if (p < s.size() && s[p] == '}') { ++p; return out; }
            do {
                ws(); std::string key = str(); ws(); expect(':');
                auto [it, inserted] = out.emplace(std::move(key), parse(depth + 1));
                if (!inserted) throw std::runtime_error("duplicate JSON key");
                ws(); char c = take();
                if (c == '}') return out;
                if (c != ',') throw std::runtime_error("invalid JSON object");
            } while (true);
        }
        if (s[p] == '[') {
            ++p; Json::Array out; ws();
            if (p < s.size() && s[p] == ']') { ++p; return out; }
            do {
                out.push_back(parse(depth + 1)); ws(); char c = take();
                if (c == ']') return out;
                if (c != ',') throw std::runtime_error("invalid JSON array");
            } while (true);
        }
        if (s.compare(p, 4, "true") == 0) { p += 4; return true; }
        if (s.compare(p, 5, "false") == 0) { p += 5; return false; }
        if (s.compare(p, 4, "null") == 0) { p += 4; return nullptr; }
        size_t start = p;
        if (s[p] == '-') ++p;
        if (p == s.size() || s[p] < '0' || s[p] > '9') throw std::runtime_error("invalid JSON number");
        if (s[p] == '0') ++p;
        else while (p < s.size() && s[p] >= '0' && s[p] <= '9') ++p;
        bool floating = false;
        if (p < s.size() && s[p] == '.') {
            floating = true; ++p;
            if (p == s.size() || s[p] < '0' || s[p] > '9') throw std::runtime_error("invalid JSON fraction");
            while (p < s.size() && s[p] >= '0' && s[p] <= '9') ++p;
        }
        if (p < s.size() && (s[p] == 'e' || s[p] == 'E')) {
            floating = true; ++p;
            if (p < s.size() && (s[p] == '+' || s[p] == '-')) ++p;
            if (p == s.size() || s[p] < '0' || s[p] > '9') throw std::runtime_error("invalid JSON exponent");
            while (p < s.size() && s[p] >= '0' && s[p] <= '9') ++p;
        }
        if (floating) {
            double n;
            auto [end, ec] = std::from_chars(s.data() + start, s.data() + p, n);
            if (ec != std::errc{} || end != s.data() + p || !std::isfinite(n)) throw std::runtime_error("JSON number out of range");
            return n;
        }
        int64_t n;
        auto [end, ec] = std::from_chars(s.data() + start, s.data() + p, n);
        if (ec != std::errc{} || end != s.data() + p) throw std::runtime_error("JSON integer out of range");
        return n;
    }
};
bool needs_escape(unsigned char c) { return c == '"' || c == '\\' || c < 32 || c >= 0x80; }
// Length of the valid UTF-8 sequence starting at p[0], or 0 when it is invalid or cut short.
size_t utf8_sequence(const unsigned char* p, size_t n) {
    const unsigned char c = p[0];
    size_t length = 0;
    unsigned char low = 0x80, high = 0xbf;
    if (c >= 0xc2 && c <= 0xdf) length = 2;
    else if (c >= 0xe0 && c <= 0xef) { length = 3; if (c == 0xe0) low = 0xa0; else if (c == 0xed) high = 0x9f; }
    else if (c >= 0xf0 && c <= 0xf4) { length = 4; if (c == 0xf0) low = 0x90; else if (c == 0xf4) high = 0x8f; }
    else return 0;
    if (n < length || p[1] < low || p[1] > high) return 0;
    for (size_t k = 2; k < length; ++k) if ((p[k] & 0xc0) != 0x80) return 0;
    return length;
}
// PERF: runs of bytes that need no escaping are appended at once; MCP text responses are hundreds of KB.
// SAFETY: the output is always valid UTF-8, as JSON requires: an invalid byte (a cut character, legacy text) is
//   written as U+FFFD, so no caller can produce an invalid MCP response.
void escape(const std::string& s, std::string& out, const std::function<void()>& check) {
    constexpr char hex[] = "0123456789abcdef";
    out.reserve(out.size() + s.size() + 2);
    out.push_back('"');
    size_t run = 0;
    const auto* bytes = reinterpret_cast<const unsigned char*>(s.data());
    for (size_t i = 0; i < s.size(); ++i) {
        if (check && (i & 1023) < 4) check();
        const auto c = static_cast<unsigned char>(s[i]);
        if (!needs_escape(c)) continue;
        if (c >= 0x80) {
            if (const size_t length = utf8_sequence(bytes + i, s.size() - i)) { i += length - 1; continue; }
            out.append(s, run, i - run);
            out += "\xEF\xBF\xBD";
            run = i + 1;
            continue;
        }
        out.append(s, run, i - run);
        run = i + 1;
        if (c == '"' || c == '\\') { out.push_back('\\'); out.push_back(static_cast<char>(c)); }
        else { out += "\\u00"; out.push_back(hex[c >> 4]); out.push_back(hex[c & 15]); }
    }
    out.append(s, run, s.size() - run);
    out.push_back('"');
}
void dump_value(const Json& j, std::string& out, const std::function<void()>& check) {
    if (check) check();
    if (std::holds_alternative<std::nullptr_t>(j.value)) out += "null";
    else if (auto flag = std::get_if<bool>(&j.value)) out += *flag ? "true" : "false";
    else if (auto integer = std::get_if<int64_t>(&j.value)) out += std::to_string(*integer);
    else if (auto number = std::get_if<double>(&j.value)) {
        char buffer[64];
        auto [end, ec] = std::to_chars(buffer, buffer + sizeof(buffer), *number);
        if (ec != std::errc{}) throw std::runtime_error("cannot serialize JSON number");
        out.append(buffer, end);
    }
    else if (auto text = std::get_if<std::string>(&j.value)) escape(*text, out, check);
    else if (auto array = std::get_if<Json::Array>(&j.value)) {
        out.push_back('[');
        for (const auto& v : *array) { if (&v != &array->front()) out.push_back(','); dump_value(v, out, check); }
        out.push_back(']');
    } else {
        out.push_back('{');
        const auto& obj = std::get<Json::Object>(j.value);
        for (auto it = obj.begin(); it != obj.end(); ++it) {
            if (it != obj.begin()) out.push_back(',');
            escape(it->first, out, check); out.push_back(':'); dump_value(it->second, out, check);
        }
        out.push_back('}');
    }
}
}
Json Json::parse(const std::string& input) {
    Parser parser{input}; Json result = parser.parse(); parser.ws();
    if (parser.p != input.size()) throw std::runtime_error("trailing JSON data");
    return result;
}
std::string Json::dump(const std::function<void()>& check) const { std::string out; dump_value(*this, out, check); return out; }
size_t Json::escaped_size(std::string_view s, const std::function<void()>& check) {
    if (check) check();
    size_t size = s.size() + 2;
    const auto* bytes = reinterpret_cast<const unsigned char*>(s.data());
    for (size_t i = 0; i < s.size(); ++i) {
        if (check && (i & 1023) < 4) check();
        const unsigned char c = bytes[i];
        if (c == '"' || c == '\\') size += 1;
        else if (c < 32) size += 5;
        else if (c >= 0x80) {
            if (const size_t length = utf8_sequence(bytes + i, s.size() - i)) i += length - 1;
            else size += 2;  // written as the 3-byte U+FFFD
        }
    }
    return size;
}

namespace {
using RowObject = Json::Object;
using RowArray = Json::Array;

[[noreturn]] void row_error(const char* message) {
    throw std::runtime_error(std::string("invalid shgrep-rowpack: ") + message);
}
const RowArray& row_array(const Json& value) {
    const auto* array = std::get_if<RowArray>(&value.value);
    if (!array) row_error("expected array");
    return *array;
}
const RowObject& row_object(const Json& value) {
    const auto* object = std::get_if<RowObject>(&value.value);
    if (!object) row_error("expected object");
    return *object;
}
const std::string& row_string(const Json& value) {
    const auto* text = std::get_if<std::string>(&value.value);
    if (!text) row_error("expected string");
    return *text;
}
size_t row_index(const Json& value, size_t size) {
    const auto* index = std::get_if<int64_t>(&value.value);
    if (!index || *index < 0 || static_cast<uint64_t>(*index) >= size) row_error("index out of bounds");
    return static_cast<size_t>(*index);
}
void row_validate(const Json& value, const std::function<void()>& check = {}) {
    if (check) check();
    if (const auto* text = std::get_if<std::string>(&value.value)) {
        if (!valid_utf8(*text, check)) row_error("invalid UTF-8");
    } else if (const auto* number = std::get_if<double>(&value.value)) {
        if (!std::isfinite(*number)) row_error("non-finite number");
    } else if (const auto* array = std::get_if<RowArray>(&value.value)) {
        for (const auto& item : *array) row_validate(item, check);
    } else if (const auto* object = std::get_if<RowObject>(&value.value)) {
        for (const auto& [key, item] : *object) {
            if (!valid_utf8(key, check)) row_error("invalid UTF-8 key");
            row_validate(item, check);
        }
    }
}
bool row_envelope(const Json& value) {
    const Json* format = value.get("$format");
    const Json* name = format ? format->get("name") : nullptr;
    const auto* text = name ? std::get_if<std::string>(&name->value) : nullptr;
    return text && *text == "shgrep-rowpack";
}
Json row_nodes() {
    return RowObject{{"J", "[J,raw JSON]"}, {"A", "[A,node,...]"},
                     {"O", "[O,{key:node,...}]"}, {"S", "[S,schema index,field values...]"}};
}
Json row_types() {
    return RowObject{{"J", "raw JSON"}, {"N", "node"}, {"P", RowArray{"line", "column"}},
        {"R", RowArray{"start.line", "start.column", "end.line", "end.column"}},
        {"r", RowArray{"start_line", "start_column", "end_line", "end_column"}},
        {"F", "files index; expand tuple into listed field names"},
        {"Q", "[prefix index,suffix]; concatenate exactly"}};
}
bool row_integers(const RowObject& object, std::initializer_list<const char*> keys) {
    if (object.size() != keys.size()) return false;
    for (const char* key : keys) {
        const auto it = object.find(key);
        if (it == object.end() || !std::holds_alternative<int64_t>(it->second.value)) return false;
    }
    return true;
}
std::string row_layout(const Json& value) {
    const auto* object = std::get_if<RowObject>(&value.value);
    if (!object) return {};
    if (row_integers(*object, {"line", "column"})) return "P";
    if (row_integers(*object, {"start_line", "start_column", "end_line", "end_column"})) return "r";
    if (object->size() == 2 && object->contains("start") && object->contains("end") &&
        row_layout(object->at("start")) == "P" && row_layout(object->at("end")) == "P") return "R";
    return {};
}
bool row_qname(const std::string& key) {
    return key == "name_path" || key == "qualifiedName" || key == "qualified_name";
}
RowArray row_file_keys(const RowObject& object) {
    RowArray keys;
    // Only exact tuples are shared; partial metadata never borrows another file's fields.
    for (const char* key : {"path", "filePath", "file_path", "sha256", "hash", "mtime", "timestamp"})
        if (const auto it = object.find(key); it != object.end() &&
            std::holds_alternative<std::string>(it->second.value)) keys.emplace_back(key);
    bool path = false;
    for (const auto& key : keys)
        path |= key.string() == "path" || key.string() == "filePath" || key.string() == "file_path";
    return path ? keys : RowArray{};
}
bool row_has_key(const RowArray& keys, const std::string& key) {
    for (const auto& item : keys) if (item.string() == key) return true;
    return false;
}
RowArray row_file_values(const RowObject& object, const RowArray& keys) {
    RowArray values;
    for (const auto& key : keys) values.push_back(object.at(key.string()));
    return values;
}
struct RowPack {
    const std::function<void()>& check;
    void checkpoint() const { if (check) check(); }
    struct Candidate { Json value; size_t count = 0; };
    std::map<std::string, Candidate> file_candidates, prefix_candidates, shape_candidates;
    std::vector<std::string> file_order, prefix_order, shape_order;
    std::map<std::string, size_t> file_ids, prefix_ids, shape_ids;
    RowArray files, prefixes, schemas;

    void remember(std::map<std::string, Candidate>& candidates, std::vector<std::string>& order,
                         const Json& value) {
        const std::string key = value.dump(check);
        auto [it, inserted] = candidates.try_emplace(key, Candidate{value, 0});
        if (inserted) order.push_back(key);
        ++it->second.count;
    }
    // Prefix candidates are optional (a name without a shared prefix stays inline), so discovery stops adding new
    // ones once their distinct keys reach kPrefixBudget bytes; memory stays proportional to the input.
    static constexpr size_t kMaxPrefixName = 1024, kMaxPrefixCuts = 32, kPrefixBudget = size_t{8} << 20;
    size_t prefix_bytes = 0;
    void remember_prefix(std::string text) {
        checkpoint();
        Json value(std::move(text));
        std::string key = value.dump(check);
        auto it = prefix_candidates.find(key);
        if (it == prefix_candidates.end()) {
            if (key.size() > kPrefixBudget - prefix_bytes) return;
            prefix_bytes += key.size();
            prefix_order.push_back(key);
            it = prefix_candidates.emplace(std::move(key), Candidate{std::move(value), 0}).first;
        }
        ++it->second.count;
    }
    void collect(const Json& value) {
        checkpoint();
        if (const auto* object = std::get_if<RowObject>(&value.value)) {
            const auto keys = row_file_keys(*object);
            if (!keys.empty()) remember(file_candidates, file_order, row_file_values(*object, keys));
            for (const auto& [key, item] : *object) {
                if (row_qname(key) && std::holds_alternative<std::string>(item.value)) {
                    const auto& name = item.string();
                    // Lexical boundaries only: no language-specific qualified-name rewriting.
                    // SAFETY (F2): every prefix is a copy of the name's start, so a long, delimiter-dense name would
                    // materialize quadratic bytes. Only names up to kMaxPrefixName bytes are cut, at their first
                    // kMaxPrefixCuts boundaries; real qualified names are far shorter.
                    if (name.size() <= kMaxPrefixName) {
                        size_t cuts = 0;
                        for (size_t i = 0; i < name.size() && cuts < kMaxPrefixCuts; ++i) {
                            if (name[i] == '/' || name[i] == '.' || (name[i] == ':' && i && name[i - 1] == ':')) {
                                remember_prefix(name.substr(0, i + 1));
                                ++cuts;
                            }
                        }
                    }
                    remember_prefix(name);
                }
                collect(item);
            }
        } else if (const auto* array = std::get_if<RowArray>(&value.value)) {
            for (const auto& item : *array) collect(item);
        }
    }
    void select(const std::map<std::string, Candidate>& candidates, const std::vector<std::string>& order,
                       std::map<std::string, size_t>& ids, RowArray& table, size_t reference_cost) {
        for (const auto& key : order) {
            checkpoint();
            const auto& candidate = candidates.at(key);
            const size_t bytes = key.size();
            if (candidate.count < 2 || bytes <= reference_cost ||
                candidate.count * (bytes - reference_cost) <= bytes + 2) continue;
            ids.emplace(key, table.size());
            table.push_back(candidate.value);
        }
    }
    size_t prefix(const std::string& name) const {
        size_t best = prefixes.size(), length = 0;
        for (size_t i = 0; i < prefixes.size(); ++i) {
            checkpoint();
            const auto& text = prefixes[i].string();
            if (text.size() > length && name.starts_with(text)) { best = i; length = text.size(); }
        }
        return best;
    }
    Json shape(const RowObject& object) const {
        checkpoint();
        RowArray fields;
        const auto keys = row_file_keys(object);
        const bool shared_file = !keys.empty() && file_ids.contains(Json(row_file_values(object, keys)).dump(check));
        bool file_added = false;
        for (const auto& [key, item] : object) {
            if (shared_file && row_has_key(keys, key)) {
                if (!file_added) fields.emplace_back(RowArray{keys, "F"});
                file_added = true;
                continue;
            }
            std::string type = row_layout(item);
            if (type.empty() && row_qname(key) && std::holds_alternative<std::string>(item.value) &&
                prefix(item.string()) != prefixes.size()) type = "Q";
            if (type.empty()) type = std::holds_alternative<RowObject>(item.value) ||
                                     std::holds_alternative<RowArray>(item.value) ? "N" : "J";
            fields.emplace_back(RowArray{key, type});
        }
        return fields;
    }
    void collect_shapes(const Json& value) {
        checkpoint();
        if (const auto* object = std::get_if<RowObject>(&value.value)) {
            remember(shape_candidates, shape_order, shape(*object));
            for (const auto& [key, item] : *object) { (void)key; collect_shapes(item); }
        } else if (const auto* array = std::get_if<RowArray>(&value.value)) {
            for (const auto& item : *array) collect_shapes(item);
        }
    }
    Json field(const RowObject& object, const RowArray& descriptor) const {
        checkpoint();
        const auto& type = descriptor[1].string();
        if (type == "F") return static_cast<uint64_t>(file_ids.at(Json(row_file_values(object, descriptor[0].array())).dump(check)));
        const auto& item = object.at(descriptor[0].string());
        if (type == "J") return item;
        if (type == "N") return node(item);
        if (type == "Q") {
            const size_t id = prefix(item.string());
            return RowArray{static_cast<uint64_t>(id), item.string().substr(prefixes[id].string().size())};
        }
        const auto& nested = item.object();
        if (type == "P") return RowArray{nested.at("line"), nested.at("column")};
        if (type == "r") return RowArray{nested.at("start_line"), nested.at("start_column"),
                                       nested.at("end_line"), nested.at("end_column")};
        return RowArray{nested.at("start").object().at("line"), nested.at("start").object().at("column"),
                        nested.at("end").object().at("line"), nested.at("end").object().at("column")};
    }
    Json node(const Json& value) const {
        checkpoint();
        Json raw = RowArray{"J", value};
        Json packed;
        if (const auto* object = std::get_if<RowObject>(&value.value)) {
            const Json layout = shape(*object);
            if (const auto it = shape_ids.find(layout.dump(check)); it != shape_ids.end()) {
                RowArray row{"S", static_cast<uint64_t>(it->second)};
                for (const auto& descriptor : layout.array()) row.push_back(field(*object, descriptor.array()));
                packed = std::move(row);
            } else {
                RowObject fields;
                for (const auto& [key, item] : *object) fields.emplace(key, node(item));
                packed = RowArray{"O", std::move(fields)};
            }
        } else if (const auto* array = std::get_if<RowArray>(&value.value)) {
            RowArray items{"A"};
            for (const auto& item : *array) items.push_back(node(item));
            packed = std::move(items);
        } else return raw;
        return packed.dump(check).size() < raw.dump(check).size() ? packed : raw;
    }
    struct Used {
        RowArray schemas, files, prefixes;
        std::map<size_t, size_t> schema_ids, file_ids, prefix_ids;
        static size_t intern(size_t old, const RowArray& source, std::map<size_t, size_t>& ids, RowArray& target) {
            auto [it, inserted] = ids.emplace(old, target.size());
            if (inserted) target.push_back(source[old]);
            return it->second;
        }
    };
    Json compact(const Json& encoded, Used& used) const {
        checkpoint();
        const auto& row = encoded.array();
        const auto& tag = row[0].string();
        if (tag == "J") return encoded;
        if (tag == "A") {
            RowArray items{"A"};
            for (size_t i = 1; i < row.size(); ++i) items.push_back(compact(row[i], used));
            return items;
        }
        if (tag == "O") {
            RowObject fields;
            for (const auto& [key, item] : row[1].object()) fields.emplace(key, compact(item, used));
            return RowArray{"O", std::move(fields)};
        }
        const size_t old = static_cast<size_t>(row[1].integer());
        RowArray result{"S", static_cast<uint64_t>(Used::intern(old, schemas, used.schema_ids, used.schemas))};
        const auto& schema = schemas[old].array();
        for (size_t i = 0; i < schema.size(); ++i) {
            const auto& type = schema[i].array()[1].string();
            const Json& cell = row[i + 2];
            if (type == "N") result.push_back(compact(cell, used));
            else if (type == "F")
                result.emplace_back(static_cast<uint64_t>(Used::intern(static_cast<size_t>(cell.integer()),
                    files, used.file_ids, used.files)));
            else if (type == "Q") {
                const auto& tuple = cell.array();
                result.emplace_back(RowArray{static_cast<uint64_t>(Used::intern(static_cast<size_t>(tuple[0].integer()),
                    prefixes, used.prefix_ids, used.prefixes)), tuple[1]});
            } else result.push_back(cell);
        }
        return result;
    }
    Json encode(const Json& value) {
        checkpoint();
        collect(value);
        select(file_candidates, file_order, file_ids, files, 4);
        select(prefix_candidates, prefix_order, prefix_ids, prefixes, 8);
        collect_shapes(value);
        for (const auto& key : shape_order) {
            checkpoint();
            const auto& candidate = shape_candidates.at(key);
            size_t key_bytes = 0;
            for (const auto& field : candidate.value.array()) {
                const auto& name = field.array()[0];
                if (std::holds_alternative<std::string>(name.value)) key_bytes += name.dump(check).size() + 1;
                else for (const auto& part : name.array()) key_bytes += part.dump(check).size() + 1;
            }
            if (candidate.count < 2 || key_bytes <= 8 || candidate.count * (key_bytes - 8) <= key.size() + 2) continue;
            shape_ids.emplace(key, schemas.size());
            schemas.push_back(candidate.value);
        }
        Used used;
        Json data = compact(node(value), used);
        return RowObject{{"$format", RowObject{{"name", "shgrep-rowpack"}, {"version", 1},
            {"nodes", row_nodes()}, {"types", row_types()}, {"schemas", std::move(used.schemas)},
            {"files", std::move(used.files)}, {"prefixes", std::move(used.prefixes)}}}, {"data", std::move(data)}};
    }
};

struct RowUnpack {
    const RowArray& schemas;
    const RowArray& files;
    const RowArray& prefixes;

    static void insert(RowObject& object, const std::string& key, Json value) {
        if (!object.emplace(key, std::move(value)).second) row_error("duplicate schema field");
    }
    static Json coordinates(const Json& value, const std::string& type) {
        const auto& tuple = row_array(value);
        const size_t width = type == "P" ? 2 : 4;
        if (tuple.size() != width) row_error("coordinate width");
        for (const auto& part : tuple)
            if (!std::holds_alternative<int64_t>(part.value)) row_error("coordinate must be integer");
        if (type == "P") return RowObject{{"line", tuple[0]}, {"column", tuple[1]}};
        if (type == "r") return RowObject{{"start_line", tuple[0]}, {"start_column", tuple[1]},
                                        {"end_line", tuple[2]}, {"end_column", tuple[3]}};
        return RowObject{{"start", RowObject{{"line", tuple[0]}, {"column", tuple[1]}}},
                         {"end", RowObject{{"line", tuple[2]}, {"column", tuple[3]}}}};
    }
    void validate() const {
        for (const auto& file : files)
            for (const auto& part : row_array(file)) (void)row_string(part);
        for (const auto& prefix : prefixes) (void)row_string(prefix);
        for (const auto& schema : schemas) {
            RowObject fields;
            for (const auto& item : row_array(schema)) {
                const auto& descriptor = row_array(item);
                if (descriptor.size() != 2) row_error("field descriptor width");
                const auto& type = row_string(descriptor[1]);
                if (type == "F") {
                    const auto& names = row_array(descriptor[0]);
                    if (names.empty()) row_error("empty file fields");
                    for (const auto& name : names) insert(fields, row_string(name), nullptr);
                } else {
                    if (type != "J" && type != "N" && type != "Q" && type != "P" && type != "R" && type != "r")
                        row_error("unknown field type");
                    insert(fields, row_string(descriptor[0]), nullptr);
                }
            }
        }
    }
    Json node(const Json& value) const {
        const auto& row = row_array(value);
        if (row.empty()) row_error("empty node");
        const auto& tag = row_string(row[0]);
        if (tag == "J") {
            if (row.size() != 2) row_error("raw node width");
            return row[1];
        }
        if (tag == "A") {
            RowArray array;
            for (size_t i = 1; i < row.size(); ++i) array.push_back(node(row[i]));
            return array;
        }
        if (tag == "O") {
            if (row.size() != 2) row_error("object node width");
            RowObject object;
            for (const auto& [key, item] : row_object(row[1])) object.emplace(key, node(item));
            return object;
        }
        if (tag != "S" || row.size() < 2) row_error("unknown node tag");
        const auto& schema = row_array(schemas[row_index(row[1], schemas.size())]);
        if (row.size() != schema.size() + 2) row_error("row width");
        RowObject object;
        for (size_t i = 0; i < schema.size(); ++i) {
            const auto& descriptor = schema[i].array();
            const auto& type = descriptor[1].string();
            const auto& cell = row[i + 2];
            if (type == "F") {
                const auto& names = descriptor[0].array();
                const auto& tuple = row_array(files[row_index(cell, files.size())]);
                if (tuple.size() != names.size()) row_error("file tuple width");
                for (size_t j = 0; j < names.size(); ++j) insert(object, names[j].string(), tuple[j]);
            } else {
                Json decoded = cell;
                if (type == "N") decoded = node(cell);
                else if (type == "Q") {
                    const auto& tuple = row_array(cell);
                    if (tuple.size() != 2) row_error("qualified name width");
                    decoded = prefixes[row_index(tuple[0], prefixes.size())].string() + row_string(tuple[1]);
                } else if (type != "J") decoded = coordinates(cell, type);
                insert(object, descriptor[0].string(), std::move(decoded));
            }
        }
        return object;
    }
};
} // namespace

Json pack_json(const Json& value, const std::function<void()>& check) {
    row_validate(value, check);
    const Json packed = RowPack{check}.encode(value);
    // Escape an original object that resembles our envelope, even when that costs bytes.
    // Otherwise decode(encode(x)) could interpret user data as codec instructions.
    return row_envelope(value) || Json::escaped_size(packed.dump(check), check) < Json::escaped_size(value.dump(check), check) ? packed : value;
}
Json unpack_json(const Json& value) {
    row_validate(value);
    if (!row_envelope(value)) return value;
    if (value.object().size() != 2 || !value.get("data")) row_error("envelope fields");
    const Json& format = *value.get("$format");
    const auto& fields = row_object(format);
    if (fields.size() != 7 || !format.get("version") || !format.get("nodes") || !format.get("types") ||
        !format.get("schemas") || !format.get("files") || !format.get("prefixes")) row_error("format fields");
    const auto* version = std::get_if<int64_t>(&format.get("version")->value);
    if (!version || *version != 1) row_error("unsupported version");
    if (format.get("nodes")->dump() != row_nodes().dump() || format.get("types")->dump() != row_types().dump())
        row_error("unsupported layouts");
    RowUnpack decoder{row_array(*format.get("schemas")), row_array(*format.get("files")),
                      row_array(*format.get("prefixes"))};
    decoder.validate();
    return decoder.node(*value.get("data"));
}

}
