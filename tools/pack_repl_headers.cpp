#include "../src/repl.hpp"
#include "../src/repl_header_pack.hpp"

#include <windows.h>
#include <compressapi.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace shgrep {
namespace {
namespace fs = std::filesystem;
using namespace repl_headers;

struct Input {
    fs::path source;
    std::string path;
    uint64_t size = 0;
    uint64_t offset = 0;
    uint32_t method = kMethodStored;
    uint64_t stored = 0;     // bytes in the pack: size when stored, the compressed length otherwise
    std::vector<char> data;  // exactly the bytes written to the pack
};

std::string path_utf8(const fs::path& path) {
    auto text = path.generic_u8string();
    return std::string(text.begin(), text.end());
}

std::string folded(std::string text) {
    for (char& ch : text) {
        if (ch == '\\') ch = '/';
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    }
    return text;
}

bool safe_name(const std::string& name) {
    if (name.empty() || name.size() > kMaximumPathBytes || name.front() == '/' ||
        name.front() == '\\' || name.find(':') != std::string::npos ||
        name.find('\0') != std::string::npos) return false;
    for (size_t start = 0; start <= name.size();) {
        const size_t end = name.find_first_of("/\\", start);
        const auto part = name.substr(start, end == std::string::npos ? end : end - start);
        if (part.empty() || part == "." || part == "..") return false;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return true;
}

void put_u32(std::ostream& out, uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8) out.put(static_cast<char>(value >> shift));
}
void put_u64(std::ostream& out, uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8) out.put(static_cast<char>(value >> shift));
}

void append_file(std::vector<Input>& entries, std::set<std::string>& names,
                 const fs::path& source, const std::string& name) {
    if (!safe_name(name)) throw std::runtime_error("invalid runtime resource path: " + name);
    if (!names.insert(folded(name)).second) throw std::runtime_error("duplicate runtime resource: " + name);
    const auto size = fs::file_size(source);
    if (size > kMaximumFileBytes) throw std::runtime_error("runtime resource is too large: " + name);
    if (entries.size() >= kMaximumEntries) throw std::runtime_error("too many runtime resources");
    entries.push_back({source, name, size, 0});
}

// Buffer-mode XPRESS Huffman from the Windows Compression API: the format repl_headers_vfs.cpp decodes.
class Compressor {
    COMPRESSOR_HANDLE handle_ = nullptr;
    static std::runtime_error failure(const char* what) {
        return std::runtime_error(std::string(what) + " (Windows error " + std::to_string(GetLastError()) + ")");
    }
public:
    Compressor() {
        if (!CreateCompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, nullptr, &handle_))
            throw failure("cannot create the XPRESS Huffman compressor");
    }
    ~Compressor() { CloseCompressor(handle_); }
    Compressor(const Compressor&) = delete;
    Compressor& operator=(const Compressor&) = delete;
    std::vector<char> compress(const std::vector<char>& input) {
        SIZE_T needed = 0;
        if (!Compress(handle_, input.data(), input.size(), nullptr, 0, &needed) &&
            GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            throw failure("cannot size compressed runtime resource");
        std::vector<char> output(needed);
        SIZE_T written = 0;
        if (!Compress(handle_, input.data(), input.size(), output.data(), output.size(), &written))
            throw failure("cannot compress runtime resource");
        output.resize(written);
        return output;
    }
};
}

int pack_runtime_data(int argc, wchar_t** argv) {
    fs::path temporary;
    bool owns_temporary = false;
    try {
        if (argc < 4 || (argc - 2) % 2 != 0)
            throw std::runtime_error("usage: --pack-data OUTPUT NAME SOURCE [NAME SOURCE ...]");
        const fs::path output = fs::absolute(argv[1]);
        std::vector<Input> entries;
        std::set<std::string> names;
        for (int i = 2; i < argc; i += 2) {
            const fs::path prefix(argv[i]), source(argv[i + 1]);
            const std::string name = path_utf8(prefix);
            if (!safe_name(name)) throw std::runtime_error("invalid runtime resource prefix: " + name);
            const auto source_status = fs::symlink_status(source);
            if (fs::is_symlink(source_status)) throw std::runtime_error("runtime source must not be a symbolic link");
            if (fs::is_regular_file(source_status)) {
                append_file(entries, names, source, name);
            } else if (fs::is_directory(source_status)) {
                for (const auto& item : fs::recursive_directory_iterator(source)) {
                    const auto status = item.symlink_status();
                    if (fs::is_symlink(status)) throw std::runtime_error("symbolic link in runtime source tree");
                    if (fs::is_directory(status)) continue;
                    if (!fs::is_regular_file(status)) throw std::runtime_error("unsupported runtime source entry");
                    append_file(entries, names, item.path(), name + "/" + path_utf8(item.path().lexically_relative(source)));
                }
            } else {
                throw std::runtime_error("runtime source does not exist or is not a regular file");
            }
        }
        std::sort(entries.begin(), entries.end(), [](const Input& a, const Input& b) {
            return folded(a.path) < folded(b.path);
        });
        // Each resource is read once, compressed in memory and written from there.
        uint64_t total = 0;
        for (const auto& entry : entries) {
            if (entry.size > kMaximumPackBytes - total) throw std::runtime_error("runtime pack is too large");
            total += entry.size;
        }
        Compressor compressor;
        for (auto& entry : entries) {
            std::vector<char> raw(static_cast<size_t>(entry.size));
            std::ifstream input(entry.source, std::ios::binary);
            if (!input) throw std::runtime_error("cannot read runtime resource: " + entry.path);
            if (!raw.empty() && !input.read(raw.data(), static_cast<std::streamsize>(raw.size())))
                throw std::runtime_error("runtime resource changed while packing: " + entry.path);
            if (input.peek() != std::char_traits<char>::eof())
                throw std::runtime_error("runtime resource changed while packing: " + entry.path);
            // A resource stays stored when compressing saves nothing; empty files are always stored, because the
            //   reader rejects empty compressed entries.
            std::vector<char> packed = raw.empty() ? std::vector<char>{} : compressor.compress(raw);
            if (!packed.empty() && packed.size() < raw.size()) {
                entry.method = kMethodXpressHuff;
                entry.data = std::move(packed);
            } else {
                entry.data = std::move(raw);
            }
            entry.stored = entry.data.size();
        }
        uint64_t offset = kPackHeaderBytes;
        for (const auto& entry : entries) {
            const uint64_t size = kPackEntryFixedBytes + entry.path.size();
            if (size > kMaximumPackBytes - offset) throw std::runtime_error("runtime table is too large");
            offset += size;
        }
        for (auto& entry : entries) {
            entry.offset = offset;
            if (entry.stored > kMaximumPackBytes - offset) throw std::runtime_error("runtime pack is too large");
            offset += entry.stored;
        }
        temporary = output;
        temporary += L"." + std::to_wstring(GetCurrentProcessId()) + L".tmp";
        if (fs::exists(temporary)) throw std::runtime_error("runtime pack temporary file already exists");
        std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("cannot create runtime pack");
        owns_temporary = true;
        out.write(kPackMagic, sizeof(kPackMagic));
        put_u32(out, kPackVersion);
        put_u32(out, static_cast<uint32_t>(entries.size()));
        for (const auto& entry : entries) {
            put_u32(out, static_cast<uint32_t>(entry.path.size()));
            put_u32(out, entry.method);
            put_u64(out, entry.size);
            put_u64(out, entry.stored);
            put_u64(out, entry.offset);
            out.write(entry.path.data(), static_cast<std::streamsize>(entry.path.size()));
        }
        for (const auto& entry : entries) {
            out.write(entry.data.data(), static_cast<std::streamsize>(entry.data.size()));
            if (!out) throw std::runtime_error("cannot write runtime pack");
        }
        out.flush();
        if (!out) throw std::runtime_error("cannot flush runtime pack");
        out.close();
        if (!out) throw std::runtime_error("cannot close runtime pack");
        if (!MoveFileExW(temporary.c_str(), output.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            throw std::runtime_error("cannot replace runtime pack");
        return 0;
    } catch (const std::exception& error) {
        if (owns_temporary) {
            std::error_code ignored;
            fs::remove(temporary, ignored);
        }
        std::cerr << "shgrep pack-data: " << error.what() << '\n';
        return 1;
    }
}
}
