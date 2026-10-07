#include "json.hpp"

#include <charconv>
#include <cmath>
#include <cstdio>
#include <limits>

namespace shgrep {
const Json::Object& Json::object() const { return std::get<Object>(value); }
const Json::Array& Json::array() const { return std::get<Array>(value); }
const std::string& Json::string() const { return std::get<std::string>(value); }
int64_t Json::integer() const { return std::get<int64_t>(value); }
bool Json::boolean() const { return std::get<bool>(value); }
const Json* Json::get(const std::string& key) const {
    auto* obj = std::get_if<Object>(&value);
    if (!obj) return nullptr;
    auto it = obj->find(key);
    return it == obj->end() ? nullptr : &it->second;
}

namespace {
bool valid_utf8(const std::string& s) {
    for (size_t i = 0; i < s.size();) {
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
bool needs_escape(unsigned char c) { return c == '"' || c == '\\' || c < 32; }
// PERF: runs of bytes that need no escaping are appended at once; MCP text responses are hundreds of KB.
void escape(const std::string& s, std::string& out) {
    constexpr char hex[] = "0123456789abcdef";
    out.reserve(out.size() + s.size() + 2);
    out.push_back('"');
    size_t run = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (!needs_escape(c)) continue;
        out.append(s, run, i - run);
        run = i + 1;
        if (c == '"' || c == '\\') { out.push_back('\\'); out.push_back(static_cast<char>(c)); }
        else { out += "\\u00"; out.push_back(hex[c >> 4]); out.push_back(hex[c & 15]); }
    }
    out.append(s, run, s.size() - run);
    out.push_back('"');
}
void dump_value(const Json& j, std::string& out) {
    if (std::holds_alternative<std::nullptr_t>(j.value)) out += "null";
    else if (auto flag = std::get_if<bool>(&j.value)) out += *flag ? "true" : "false";
    else if (auto integer = std::get_if<int64_t>(&j.value)) out += std::to_string(*integer);
    else if (auto number = std::get_if<double>(&j.value)) {
        char buffer[64];
        auto [end, ec] = std::to_chars(buffer, buffer + sizeof(buffer), *number);
        if (ec != std::errc{}) throw std::runtime_error("cannot serialize JSON number");
        out.append(buffer, end);
    }
    else if (auto text = std::get_if<std::string>(&j.value)) escape(*text, out);
    else if (auto array = std::get_if<Json::Array>(&j.value)) {
        out.push_back('[');
        for (const auto& v : *array) { if (&v != &array->front()) out.push_back(','); dump_value(v, out); }
        out.push_back(']');
    } else {
        out.push_back('{');
        const auto& obj = std::get<Json::Object>(j.value);
        for (auto it = obj.begin(); it != obj.end(); ++it) {
            if (it != obj.begin()) out.push_back(',');
            escape(it->first, out); out.push_back(':'); dump_value(it->second, out);
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
std::string Json::dump() const { std::string out; dump_value(*this, out); return out; }
size_t Json::escaped_size(std::string_view s) {
    size_t size = s.size() + 2;
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') size += 1;
        else if (c < 32) size += 5;
    }
    return size;
}
}
