#pragma once
#include "tool_contracts.hpp"
#include <algorithm>
#include <iterator>
#include <string_view>
#include <type_traits>

namespace shgrep::contracts {
template<class T> struct RecordTraits;
template<class E> struct EnumTraits;
template<class T> struct OptionalTraits { static constexpr bool value = false; };
template<class T> struct OptionalTraits<std::optional<T>> {
    static constexpr bool value = true;
    using type = T;
};
template<class T> struct VectorTraits { static constexpr bool value = false; };
template<class T, class A> struct VectorTraits<std::vector<T, A>> {
    static constexpr bool value = true;
    using type = T;
};
template<class T> struct EnumTextTraits { static constexpr bool value = false; };
template<class E> struct EnumTextTraits<EnumText<E>> {
    static constexpr bool value = true;
    using type = E;
};

template<class E> std::optional<E> enum_from_string(std::string_view text) {
    std::optional<E> result;
    EnumTraits<E>::visit([&](E value, std::string_view name) {
        if (text == name) result = value;
    });
    return result;
}
template<class E> std::string enum_to_string(E value) {
    std::optional<std::string> result;
    EnumTraits<E>::visit([&](E candidate, std::string_view name) {
        if (value == candidate) result = name;
    });
    if (!result) throw std::runtime_error("invalid reflected enum value");
    return *result;
}

// Unknown/backend-only keys remain available to the owning operation's validator.
// Missing values stay missing: operation-specific defaults and required fields belong to the backend.
template<class T> struct Parsed {
    T value;
    Json::Object extra;
};
template<class T> T decode_value(const Json& json, const std::string& path);
template<class T> Json encode_value(const T& value);

template<class T> Parsed<T> from_json(const Json& json) {
    const auto& source = json.object();
    Parsed<T> result{};
    RecordTraits<T>::visit(result.value, [&](const char* name, auto& field) {
        using Value = typename std::remove_cvref_t<decltype(field)>::value_type;
        if (const auto found = source.find(name); found != source.end())
            field = decode_value<Value>(found->second, name);
    });
    for (const auto& [name, value] : source)
        if (std::find(std::begin(RecordTraits<T>::names), std::end(RecordTraits<T>::names), name) == std::end(RecordTraits<T>::names))
            result.extra.emplace(name, value);
    return result;
}
template<class T> Json to_json(const Parsed<T>& parsed) {
    auto result = parsed.extra;
    RecordTraits<T>::visit(parsed.value, [&](const char* name, const auto& field) {
        if (field) result[name] = encode_value(*field);
    });
    return result;
}
template<class T> Json take_json(T&& value) {
    using Value = std::remove_cvref_t<T>;
    if constexpr (std::is_same_v<Value, Json> || std::is_same_v<Value, std::string> ||
                  std::is_same_v<Value, bool> || std::is_same_v<Value, int64_t> || std::is_same_v<Value, double>)
        return Json(std::move(value));
    else if constexpr (EnumTextTraits<Value>::value) return std::move(value.text);
    else if constexpr (VectorTraits<Value>::value) {
        Json::Array result;
        result.reserve(value.size());
        if constexpr (std::is_same_v<typename VectorTraits<Value>::type, bool>) {
            for (bool item : value) result.emplace_back(item);
        } else {
            for (auto& item : value) result.push_back(take_json(std::move(item)));
        }
        return result;
    } else {
        Json::Object result;
        RecordTraits<Value>::visit(value, [&](const char* name, auto& field) {
            if (field) result[name] = take_json(std::move(*field));
        });
        return result;
    }
}
template<class T> Json to_json(Parsed<T>&& parsed) {
    auto result = std::move(parsed.extra);
    RecordTraits<T>::visit(parsed.value, [&](const char* name, auto& field) {
        if (field) result[name] = take_json(std::move(*field));
    });
    return result;
}
template<class T> T decode_value(const Json& json, const std::string& path) {
    try {
        if constexpr (std::is_same_v<T, Json>) return json;
        else if constexpr (std::is_same_v<T, std::string>) return json.string();
        else if constexpr (std::is_same_v<T, bool>) return json.boolean();
        else if constexpr (std::is_same_v<T, int64_t>) return json.integer();
        else if constexpr (std::is_same_v<T, double>) {
            if (const auto* number = std::get_if<double>(&json.value)) return *number;
            return static_cast<double>(json.integer());
        } else if constexpr (EnumTextTraits<T>::value) return T{json.string()};
        else if constexpr (VectorTraits<T>::value) {
            T result;
            const auto& array = json.array();
            result.reserve(array.size());
            for (size_t i = 0; i < array.size(); ++i)
                result.push_back(decode_value<typename VectorTraits<T>::type>(array[i], path + "[" + std::to_string(i) + "]"));
            return result;
        } else {
            // Nested records reject unknown keys just like their advertised object schema.
            auto result = from_json<T>(json);
            if (!result.extra.empty()) throw std::runtime_error("unknown field " + result.extra.begin()->first);
            return std::move(result.value);
        }
    } catch (const std::exception& error) {
        throw std::runtime_error(path + ": " + error.what());
    }
}
template<class T> Json encode_value(const T& value) {
    if constexpr (std::is_same_v<T, Json> || std::is_same_v<T, std::string> ||
                  std::is_same_v<T, bool> || std::is_same_v<T, int64_t> || std::is_same_v<T, double>) return Json(value);
    else if constexpr (EnumTextTraits<T>::value) return value.text;
    else if constexpr (VectorTraits<T>::value) {
        Json::Array result;
        result.reserve(value.size());
        for (const auto& item : value) result.push_back(encode_value(item));
        return result;
    } else return to_json(Parsed<T>{value, {}});
}
template<class T> Json record_schema() {
    T value{};
    Json::Object properties;
    Json::Array required;
    RecordTraits<T>::fields(value, [&](const char* name, const auto& field, const char* extra, bool mandatory) {
        using Value = typename std::remove_cvref_t<decltype(field)>::value_type;
        properties.emplace(name, RecordTraits<T>::template field_schema<Value>(extra));
        if (mandatory) required.emplace_back(name);
    });
    Json::Object schema{{"type", "object"}, {"properties", std::move(properties)}, {"additionalProperties", false}};
    if (!required.empty()) schema.emplace("required", std::move(required));
    return schema;
}
template<class T> Json value_schema() {
    if constexpr (std::is_same_v<T, Json>) return Json::Object{};
    else if constexpr (std::is_same_v<T, std::string>) return Json::Object{{"type", "string"}};
    else if constexpr (std::is_same_v<T, bool>) return Json::Object{{"type", "boolean"}};
    else if constexpr (std::is_same_v<T, int64_t>) return Json::Object{{"type", "integer"}};
    else if constexpr (std::is_same_v<T, double>) return Json::Object{{"type", "number"}};
    else if constexpr (EnumTextTraits<T>::value) {
        Json::Array values;
        EnumTraits<typename EnumTextTraits<T>::type>::visit([&](auto, const char* name) { values.emplace_back(name); });
        return Json::Object{{"type", "string"}, {"enum", std::move(values)}};
    } else if constexpr (VectorTraits<T>::value)
        return Json::Object{{"type", "array"}, {"items", value_schema<typename VectorTraits<T>::type>()}};
    else return record_schema<T>();
}
template<class T> Json annotated_schema(const char* extra) {
    auto base = value_schema<T>().object();
    const Json annotations = Json::parse(extra);
    for (const auto& [key, value] : annotations.object()) base[key] = value;
    return base;
}
} // namespace shgrep::contracts
