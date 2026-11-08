#pragma once
#include "json.hpp"
#include <string_view>
#include <utility>

// The C ABI keeps allocations and exceptions inside their originating runtime.
extern "C" const char* shgrep_cpp_bridge(const char* method, const char* arguments);

namespace shgrep::cpp {
struct IndexWarmingError : std::runtime_error {
    Json details;
    IndexWarmingError(std::string message, Json value)
        : std::runtime_error(std::move(message)), details(std::move(value)) {}
};
struct SymbolLookupError : std::runtime_error {
    Json details;
    SymbolLookupError(std::string message, Json value)
        : std::runtime_error(std::move(message)), details(std::move(value)) {}
};

class Value {
public:
    Json data;
    Value() = default;
    Value(Json value) : data(std::move(value)) {}
    Value operator[](std::string_view key) const {
        const Json* found = data.get(std::string(key));
        if (!found) throw std::runtime_error("missing result field: " + std::string(key));
        return *found;
    }
    Value operator[](size_t index) const { return data.array().at(index); }
    Value get(const std::string& key, Value fallback = {}) const {
        const Json* found = data.get(key);
        return found ? Value(*found) : std::move(fallback);
    }
    std::vector<Value> array() const {
        std::vector<Value> values;
        values.reserve(data.array().size());
        for (const auto& value : data.array()) values.emplace_back(value);
        return values;
    }
    std::string string() const { return data.string(); }
    int64_t integer() const { return data.integer(); }
    bool boolean() const { return data.boolean(); }
    std::string dump() const { return data.dump(); }
    size_t size() const {
        if (const auto* a = std::get_if<Json::Array>(&data.value)) return a->size();
        if (const auto* o = std::get_if<Json::Object>(&data.value)) return o->size();
        return data.string().size();
    }
};
inline Value call(const std::string& method, const Json::Object& arguments = {}) {
    const std::string encoded = Json(arguments).dump();
    const char* reply = shgrep_cpp_bridge(method.c_str(), encoded.c_str());
    if (!reply) throw std::runtime_error("C++ facade bridge returned no response");
    const Json response = Json::parse(reply);
    if (!response.get("ok")->boolean()) {
        const std::string message = response.get("error") ? response.get("error")->string() : "C++ facade call failed";
        const Json* code = response.get("error_code");
        if (code && std::holds_alternative<std::string>(code->value) && code->string() == "index_warming") {
            const Json* details = response.get("error_data");
            throw IndexWarmingError(message, details ? *details : Json(Json::Object{}));
        }
        if (code && std::holds_alternative<std::string>(code->value) && code->string() == "symbol_lookup") {
            const Json* details = response.get("error_data");
            throw SymbolLookupError(message, details ? *details : Json(Json::Object{}));
        }
        throw std::runtime_error(message);
    }
    return *response.get("value");
}
#define SHGREP_CPP_METHOD(group, name) \
    Value name(const Json::Object& arguments = {}) const { return call(#group "." #name, arguments); }
struct Lsp {
    SHGREP_CPP_METHOD(lsp, get_symbols_overview)
    SHGREP_CPP_METHOD(lsp, find_symbol)
    SHGREP_CPP_METHOD(lsp, search_by_meaning)
    SHGREP_CPP_METHOD(lsp, find_referencing_symbols)
    SHGREP_CPP_METHOD(lsp, find_implementations)
    SHGREP_CPP_METHOD(lsp, find_declaration)
    SHGREP_CPP_METHOD(lsp, find_definition)
    SHGREP_CPP_METHOD(lsp, find_type_definition)
    SHGREP_CPP_METHOD(lsp, hover)
    SHGREP_CPP_METHOD(lsp, read_symbol)
    SHGREP_CPP_METHOD(lsp, list_symbols)
    SHGREP_CPP_METHOD(lsp, find_files)
    SHGREP_CPP_METHOD(lsp, get_diagnostics_for_file)
    SHGREP_CPP_METHOD(lsp, get_diagnostics_for_symbol)
    SHGREP_CPP_METHOD(lsp, restart_language_server)
    SHGREP_CPP_METHOD(lsp, status)
    SHGREP_CPP_METHOD(lsp, availability)
    SHGREP_CPP_METHOD(lsp, rename_symbol)
    SHGREP_CPP_METHOD(lsp, safe_delete_symbol)
    SHGREP_CPP_METHOD(lsp, move_file)
};
struct Edit {
    SHGREP_CPP_METHOD(edit, replace_symbol_body)
    SHGREP_CPP_METHOD(edit, replace_in_symbol)
    SHGREP_CPP_METHOD(edit, insert_in_symbol)
    SHGREP_CPP_METHOD(edit, replace_outside_symbols)
    SHGREP_CPP_METHOD(edit, insert_outside_symbols)
    SHGREP_CPP_METHOD(edit, insert_before_symbol)
    SHGREP_CPP_METHOD(edit, insert_after_symbol)
    SHGREP_CPP_METHOD(edit, replace_content)
    SHGREP_CPP_METHOD(edit, replace_in_files)
    SHGREP_CPP_METHOD(edit, delete_lines)
    SHGREP_CPP_METHOD(edit, replace_lines)
    SHGREP_CPP_METHOD(edit, insert_at_line)
    SHGREP_CPP_METHOD(edit, edit_file)
};
struct Fs {
    SHGREP_CPP_METHOD(fs, read_file)
    SHGREP_CPP_METHOD(fs, list_dir)
    SHGREP_CPP_METHOD(fs, find_file)
    SHGREP_CPP_METHOD(fs, find_files)
    SHGREP_CPP_METHOD(fs, search_for_pattern)
    SHGREP_CPP_METHOD(fs, search_bytes)
    SHGREP_CPP_METHOD(fs, file_info)
    SHGREP_CPP_METHOD(fs, create_text_file)
    SHGREP_CPP_METHOD(fs, write_file)
    SHGREP_CPP_METHOD(fs, delete_file)
    SHGREP_CPP_METHOD(fs, move_file)
    SHGREP_CPP_METHOD(fs, create_directory)
};
#undef SHGREP_CPP_METHOD
struct Root {
    Lsp lsp;
    Edit edit;
    Fs fs;
    std::string info(const std::string& topic = "") const { return call("s.info", {{"topic", topic}}).string(); }
    std::string vars() const { return call("s.vars").string(); }
    std::string clear() const { return call("s.clear").string(); }
};
} // namespace shgrep::cpp
inline const shgrep::cpp::Root s;
