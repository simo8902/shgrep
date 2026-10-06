#pragma once

#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace shgrep {
struct Json {
    using Object = std::map<std::string, Json>;
    using Array = std::vector<Json>;
    std::variant<std::nullptr_t, bool, int64_t, double, std::string, Array, Object> value;

    Json() : value(nullptr) {}
    Json(std::nullptr_t) : value(nullptr) {}
    Json(bool v) : value(v) {}
    Json(int v) : value(static_cast<int64_t>(v)) {}
    Json(int64_t v) : value(v) {}
    Json(double v) : value(v) {}
    Json(uint64_t v) : value(static_cast<int64_t>(v)) {
        if (v > INT64_MAX) throw std::runtime_error("JSON integer overflow");
    }
    Json(std::string v) : value(std::move(v)) {}
    Json(const char* v) : value(std::string(v)) {}
    Json(Array v) : value(std::move(v)) {}
    Json(Object v) : value(std::move(v)) {}

    const Object& object() const;
    const Array& array() const;
    const std::string& string() const;
    int64_t integer() const;
    bool boolean() const;
    const Json* get(const std::string& key) const;
    std::string dump() const;
    static Json parse(const std::string& input);
};
}
