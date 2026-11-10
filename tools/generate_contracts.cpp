// Built only by the separate GCC 16+ toolchain. Never linked into shgrep.
#include <meta>
#if !defined(__cpp_impl_reflection) || !defined(__cpp_lib_reflection)
#error GCC with C++26 language reflection and the matching <meta> library is required
#endif
#include "tool_contracts.hpp"
#include <fstream>
#include <iostream>

using shgrep::Json;
namespace meta = std::meta;
using namespace shgrep::contracts;

template<class T> struct OptionalMember { static constexpr bool value = false; };
template<class T> struct OptionalMember<std::optional<T>> { static constexpr bool value = true; };

// Filter before using reflections as template arguments. Function-overload
// reflections are irrelevant to contracts and can collide in compiler-generated symbols.
consteval std::vector<meta::info> reflected_contract_types() {
    std::vector<meta::info> result;
    for (auto entity : meta::members_of(^^shgrep::contracts, meta::access_context::unprivileged())) {
        if (!meta::is_type(entity)) continue;
        if (meta::is_enum_type(entity)) result.push_back(entity);
        else if (meta::is_class_type(entity) &&
                 (!meta::annotations_of_with_type(entity, ^^Record).empty() ||
                  !meta::annotations_of_with_type(entity, ^^Tool).empty()))
            result.push_back(entity);
    }
    return result;
}

template<class Annotation, meta::info Entity>
consteval Annotation annotation() {
    constexpr auto values = std::define_static_array(meta::annotations_of_with_type(Entity, ^^Annotation));
    static_assert(values.size() == 1, "each reflected declaration needs exactly one contract annotation");
    return meta::extract<Annotation>(values[0]);
}

template<meta::info Entity>
void emit_enum(std::ostream& out) {
    constexpr auto name = meta::identifier_of(Entity);
    out << "template<> struct EnumTraits<" << name << "> {\n"
           "    template<class F> static void visit(F&& f) {\n";
    template for (constexpr auto item : std::define_static_array(meta::enumerators_of(Entity))) {
        constexpr auto wire = annotation<WireName, item>();
        out << "        f(" << name << "::" << meta::identifier_of(item)
            << ", " << Json(wire.value).dump() << ");\n";
    }
    out << "    }\n};\n";
}

template<meta::info Entity>
void emit_record(std::ostream& out) {
    constexpr auto name = meta::identifier_of(Entity);
    out << "template<> struct RecordTraits<" << name << "> {\n"
           "    template<class V, class F> static void fields(V& value, F&& f) {\n";
    std::string names;
    template for (constexpr auto member : std::define_static_array(
                      meta::nonstatic_data_members_of(Entity, meta::access_context::unprivileged()))) {
        using Member = [:meta::type_of(member):];
        static_assert(OptionalMember<Member>::value, "contract fields must preserve absent arguments");
        constexpr auto field = annotation<Field, member>();
        constexpr auto member_name = meta::identifier_of(member);
        names += Json(std::string(member_name)).dump() + ",";
        // Parse metadata now so malformed annotations fail code generation before replacing the header.
        Json::parse(field.extra).object();
        out << "        f(" << Json(std::string(member_name)).dump() << ", value." << member_name
            << ", " << Json(field.extra).dump() << ", " << (field.required ? "true" : "false") << ");\n";
    }
    out << "    }\n"
           "    inline static constexpr std::string_view names[]{" << names << "};\n"
           "    template<class V, class F> static void visit(V& value, F&& f) {\n"
           "        fields(value, [&](const char* name, auto& field, const char*, bool) { f(name, field); });\n"
           "    }\n"
           "    template<class V> static Json field_schema(const char* extra) { return annotated_schema<V>(extra); }\n"
           "};\n";
}

// Keep filtering dependent on Entity. In the non-template emit() body,
// discarded branches can still require checking invalid reflection queries.
template<meta::info Entity>
void emit_enum_entry(std::ostream& out) {
    if constexpr (meta::is_type(Entity)) {
        if constexpr (meta::is_enum_type(Entity)) emit_enum<Entity>(out);
    }
}

template<meta::info Entity>
void emit_record_entry(std::ostream& out) {
    if constexpr (meta::is_type(Entity)) {
        if constexpr (meta::is_class_type(Entity)) {
            if constexpr (!meta::annotations_of_with_type(Entity, ^^Record).empty()) {
                if constexpr (meta::is_complete_type(Entity)) emit_record<Entity>(out);
                else static_assert(meta::is_complete_type(Entity), "reflected argument records must be complete");
            }
        }
    }
}

template<meta::info Entity>
void emit_tool_entry(std::ostream& out) {
    if constexpr (meta::is_type(Entity)) {
        if constexpr (meta::is_class_type(Entity)) {
            if constexpr (!meta::annotations_of_with_type(Entity, ^^Tool).empty()) {
                static_assert(meta::is_complete_type(Entity), "reflected tool arguments must be complete");
                static_assert(!meta::annotations_of_with_type(Entity, ^^Record).empty(),
                              "a tool must also have a Record annotation");
                constexpr auto tool = annotation<Tool, Entity>();
                constexpr auto name = meta::identifier_of(Entity);
                out << "        {" << Json(tool.name).dump() << ", " << tool.group << ", "
                    << (tool.writes ? "true" : "false") << ", " << tool.order << ",\n"
                       "         +[]() -> Json { static const Json value = Json::Object{{\"name\", "
                    << Json(tool.name).dump() << "}, {\"description\", " << Json(tool.description).dump()
                    << "}, {\"inputSchema\", record_schema<" << name << ">()}}; return value; },\n"
                       "         +[](const Json& value) -> Json { return to_json(from_json<" << name << ">(value)); }},\n";
            }
        }
    }
}

void emit(std::ostream& out) {
    out << "// Generated by tools/generate_contracts.cpp using C++26 reflection. Do not edit.\n"
           "#pragma once\n#include \"contract_codec.hpp\"\nnamespace shgrep::contracts {\n";
    template for (constexpr auto entity : std::define_static_array(reflected_contract_types())) {
        emit_enum_entry<entity>(out);
    }
    template for (constexpr auto entity : std::define_static_array(reflected_contract_types())) {
        emit_record_entry<entity>(out);
    }
    out << "struct ToolEntry {\n"
           "    std::string_view name;\n    int group;\n    bool writes;\n    int order;\n"
           "    Json (*definition)();\n    Json (*normalize)(const Json&);\n};\n"
           "inline const std::vector<ToolEntry>& tool_entries() {\n"
           "    static const std::vector<ToolEntry> entries = [] {\n"
           "    std::vector<ToolEntry> result{\n";
    template for (constexpr auto entity : std::define_static_array(reflected_contract_types())) {
        emit_tool_entry<entity>(out);
    }
    out << "    };\n"
           "    std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) { return a.order < b.order; });\n"
           "    for (size_t i = 1; i < result.size(); ++i)\n"
           "        if (result[i-1].order == result[i].order) throw std::runtime_error(\"duplicate reflected tool order\");\n"
           "    return result;\n    }();\n    return entries;\n}\n"
           "inline Json tool_definitions(int group, bool read_only = false) {\n"
           "    Json::Array result;\n"
           "    for (const auto& entry : tool_entries())\n"
           "        if (entry.group == group && !(read_only && entry.writes)) result.push_back(entry.definition());\n"
           "    return result;\n}\n"
           "inline Json tool_definition(std::string_view name) {\n"
           "    for (const auto& entry : tool_entries()) if (entry.name == name) return entry.definition();\n"
           "    throw std::runtime_error(\"unknown tool: \" + std::string(name));\n}\n"
           "inline Json normalize_arguments(std::string_view name, const Json& arguments) {\n"
           "    for (const auto& entry : tool_entries()) if (entry.name == name) return entry.normalize(arguments);\n"
           "    throw std::runtime_error(\"unknown tool: \" + std::string(name));\n}\n"
           "} // namespace shgrep::contracts\n";
}

int main(int argc, char** argv) {
    try {
        if (argc != 2) throw std::runtime_error("usage: generate_contracts OUTPUT_HEADER");
        std::ofstream output(argv[1], std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("cannot create generated header");
        emit(output);
        output.flush();
        if (!output) throw std::runtime_error("cannot write generated header");
        output.close();
        if (!output) throw std::runtime_error("cannot close generated header");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "reflection generation failed: " << error.what() << '\n';
        return 1;
    }
}
