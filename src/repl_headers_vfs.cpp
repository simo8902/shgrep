#include "repl_headers_vfs.hpp"
#include "repl_header_pack.hpp"

#include <Windows.h>
#include <compressapi.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <cstring>
#include <list>
#include <mutex>
#include <limits>
#include <memory>
#include <set>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include <llvm/ADT/SmallVector.h>
#include <llvm/Support/MemoryBuffer.h>

namespace shgrep::repl_headers {
namespace {

struct Entry {
    std::string relative_path;
    uint32_t method = 0;
    uint64_t original_size = 0;
    uint64_t stored_size = 0;
    uint64_t data_offset = 0;
};

struct PackMapping {
    struct Handle {
        HANDLE value = nullptr;
        ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
        Handle() = default;
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
    } file, section;
    const char* bytes = nullptr;
    uint64_t size = 0;

    explicit PackMapping(const std::filesystem::path& path) {
        file.value = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, nullptr);
        if (file.value == INVALID_HANDLE_VALUE)
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "cannot open shgrep.dat");
        LARGE_INTEGER length{};
        if (!GetFileSizeEx(file.value, &length))
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "cannot size shgrep.dat");
        if (length.QuadPart < static_cast<LONGLONG>(kPackHeaderBytes) ||
            static_cast<uint64_t>(length.QuadPart) > kMaximumPackBytes ||
            static_cast<uint64_t>(length.QuadPart) > std::numeric_limits<size_t>::max())
            throw std::runtime_error("invalid shgrep.dat size");
        size = static_cast<uint64_t>(length.QuadPart);
        section.value = CreateFileMappingW(file.value, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!section.value)
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "cannot map shgrep.dat");
        bytes = static_cast<const char*>(MapViewOfFile(section.value, FILE_MAP_READ, 0, 0, 0));
        if (!bytes)
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "cannot view shgrep.dat");
    }
    ~PackMapping() { if (bytes) UnmapViewOfFile(bytes); }
    PackMapping(const PackMapping&) = delete;
    PackMapping& operator=(const PackMapping&) = delete;
};

struct PackData {
    PackMapping mapping;
    std::unordered_map<std::string, Entry> entries;
    // These limits bound cache retention, not buffers still owned by LLVM.
    static constexpr size_t cache_limit = 64ull * 1024 * 1024;
    static constexpr size_t cache_entry_limit = 1ull * 1024 * 1024;
    struct Cached {
        std::shared_ptr<const llvm::MemoryBuffer> buffer;
        std::list<std::string>::iterator position;
    };
    std::mutex cache_mutex;
    std::list<std::string> recent;
    std::unordered_map<std::string, Cached> cache;
    size_t retained = 0;

    explicit PackData(const std::filesystem::path& path) : mapping(path) {}
    static bool cacheable(const Entry& entry) {
        return entry.original_size != 0 && entry.original_size <= cache_entry_limit &&
               !entry.relative_path.starts_with("lib/");
    }
    std::shared_ptr<const llvm::MemoryBuffer> lookup(const Entry& entry) {
        if (!cacheable(entry)) return {};
        std::lock_guard lock(cache_mutex);
        const auto found = cache.find(entry.relative_path);
        if (found == cache.end()) return {};
        recent.splice(recent.begin(), recent, found->second.position);
        return found->second.buffer;
    }
    std::shared_ptr<const llvm::MemoryBuffer> retain(
        const Entry& entry, std::shared_ptr<const llvm::MemoryBuffer> buffer) {
        if (!cacheable(entry)) return buffer;
        std::lock_guard lock(cache_mutex);
        if (const auto found = cache.find(entry.relative_path); found != cache.end()) {
            recent.splice(recent.begin(), recent, found->second.position);
            return found->second.buffer;
        }
        const size_t charge = buffer->getBufferSize() + 1;
        while (retained > cache_limit - charge && !recent.empty()) {
            const auto found = cache.find(recent.back());
            retained -= found->second.buffer->getBufferSize() + 1;
            cache.erase(found);
            recent.pop_back();
        }
        recent.push_front(entry.relative_path);
        try { cache.emplace(entry.relative_path, Cached{buffer, recent.begin()}); }
        catch (...) { recent.pop_front(); throw; }
        retained += charge;
        return buffer;
    }
};

// A returned view pins the mapping or decoded buffer, including after the VFS
// file closes or its cache entry is evicted. Caller-specific names stay separate.
class SharedBuffer final : public llvm::MemoryBuffer {
    std::shared_ptr<const void> owner_;
    std::string identifier_;
    BufferKind kind_;
public:
    SharedBuffer(std::shared_ptr<const void> owner, const char* bytes, size_t size,
                 std::string identifier, bool terminated, BufferKind kind)
        : owner_(std::move(owner)), identifier_(std::move(identifier)), kind_(kind) {
        init(bytes, bytes + size, terminated);
    }
    llvm::StringRef getBufferIdentifier() const override { return identifier_; }
    BufferKind getBufferKind() const override { return kind_; }
};

class ReusableDecompressor {
    DECOMPRESSOR_HANDLE handle_ = nullptr;
    void discard() { if (handle_) CloseDecompressor(handle_); handle_ = nullptr; }
public:
    ~ReusableDecompressor() { discard(); }
    std::error_code decode(const char* source, size_t stored, char* target, size_t expanded) {
        if (!handle_ && !CreateDecompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, nullptr, &handle_))
            return std::error_code(static_cast<int>(GetLastError()), std::system_category());
        if (!ResetDecompressor(handle_)) {
            const auto error = std::error_code(static_cast<int>(GetLastError()), std::system_category());
            discard();
            return error;
        }
        SIZE_T written = 0;
        if (!Decompress(handle_, source, stored, target, expanded, &written)) {
            const auto error = std::error_code(static_cast<int>(GetLastError()), std::system_category());
            discard();
            return error;
        }
        if (written != expanded) {
            discard();
            return std::make_error_code(std::errc::io_error);
        }
        return {};
    }
};

struct PackCursor {
    const char* bytes;
    uint64_t size;
    uint64_t position = 0;
    int take() {
        if (position == size) return -1;
        return static_cast<unsigned char>(bytes[position++]);
    }
    bool read(char* target, size_t length) {
        if (length > size - position) return false;
        if (length) std::memcpy(target, bytes + static_cast<size_t>(position), length);
        position += length;
        return true;
    }
};

std::error_code io_error() {
    return std::make_error_code(std::errc::io_error);
}

std::string to_utf8(const std::filesystem::path& path) {
    const auto text = path.generic_u8string();
    return std::string(reinterpret_cast<const char*>(text.data()), text.size());
}

std::string fold_path(std::string value) {
    for (char& ch : value) {
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
        if (ch == '\\') ch = '/';
    }
    return value;
}

std::string normalized_path(llvm::StringRef path) {
    return fold_path(to_utf8(std::filesystem::u8path(path.str()).lexically_normal()));
}

bool safe_relative_path(llvm::StringRef path) {
    if (path.empty() || path.front() == '/' || path.front() == '\\' ||
        path.find(':') != llvm::StringRef::npos || path.find('\0') != llvm::StringRef::npos)
        return false;

    size_t start = 0;
    while (start <= path.size()) {
        const size_t end = path.find_first_of("/\\", start);
        const llvm::StringRef part =
            end == llvm::StringRef::npos ? path.drop_front(start) : path.slice(start, end);
        if (part.empty() || part == "." || part == "..") return false;
        if (end == llvm::StringRef::npos) break;
        start = end + 1;
    }
    return true;
}

bool read_u32(PackCursor& input, uint32_t& value) {
    value = 0;
    for (unsigned shift = 0; shift != 32; shift += 8) {
        const int byte = input.take();
        if (byte < 0) return false;
        value |= static_cast<uint32_t>(static_cast<unsigned char>(byte)) << shift;
    }
    return true;
}

bool read_u64(PackCursor& input, uint64_t& value) {
    value = 0;
    for (unsigned shift = 0; shift != 64; shift += 8) {
        const int byte = input.take();
        if (byte < 0) return false;
        value |= static_cast<uint64_t>(static_cast<unsigned char>(byte)) << shift;
    }
    return true;
}

std::shared_ptr<PackData> read_pack(const std::filesystem::path& pack_path,
                                    const std::filesystem::path& runtime_root) {
    auto pack = std::make_shared<PackData>(pack_path);
    PackCursor input{pack->mapping.bytes, pack->mapping.size};
    char magic[sizeof(kPackMagic)]{};
    if (!input.read(magic, sizeof(magic)) ||
        !std::equal(std::begin(magic), std::end(magic), std::begin(kPackMagic)))
        throw std::runtime_error("invalid shgrep.dat signature");

    uint32_t version = 0, count = 0;
    if (!read_u32(input, version) || !read_u32(input, count) ||
        version != kPackVersion || count > kMaximumEntries)
        throw std::runtime_error("invalid shgrep.dat header");

    const std::string root = normalized_path(to_utf8(runtime_root));
    pack->entries.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t path_size = 0;
        Entry entry;
        if (!read_u32(input, path_size) || !read_u32(input, entry.method) ||
            !read_u64(input, entry.original_size) || !read_u64(input, entry.stored_size) ||
            !read_u64(input, entry.data_offset) ||
            path_size == 0 || path_size > kMaximumPathBytes ||
            entry.original_size > kMaximumFileBytes ||
            (entry.method != kMethodStored && entry.method != kMethodXpressHuff))
            throw std::runtime_error("invalid shgrep.dat entry");
        entry.relative_path.resize(path_size);
        if (!input.read(entry.relative_path.data(), path_size) || !safe_relative_path(entry.relative_path))
            throw std::runtime_error("unsafe path in shgrep.dat");
        if (entry.method == kMethodStored && entry.stored_size != entry.original_size)
            throw std::runtime_error("invalid stored runtime entry size in runtime pack");
        if (entry.method == kMethodXpressHuff && (entry.stored_size == 0 || entry.original_size == 0))
            throw std::runtime_error("invalid compressed runtime entry size in runtime pack");
        if (entry.data_offset > pack->mapping.size ||
            entry.stored_size > pack->mapping.size - entry.data_offset)
            throw std::runtime_error("runtime data extends past the runtime pack");
        const std::string full_path = root + "/" + fold_path(entry.relative_path);
        if (!pack->entries.emplace(full_path, std::move(entry)).second)
            throw std::runtime_error("duplicate path in shgrep.dat");
    }
    for (const auto& [path, entry] : pack->entries) {
        (void)path;
        if (entry.data_offset < input.position)
            throw std::runtime_error("runtime data overlaps the runtime pack table");
    }
    return pack;
}

class PackedHeaderFile final : public llvm::vfs::File {
public:
    PackedHeaderFile(std::shared_ptr<PackData> pack, Entry entry,
                     llvm::vfs::Status status)
        : pack_(std::move(pack)), entry_(std::move(entry)), status_(std::move(status)) {}

    llvm::ErrorOr<llvm::vfs::Status> status() override { return status_; }

    std::error_code close() override { return {}; }

    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>>
    getBuffer(const llvm::Twine& name, int64_t, bool requires_null, bool) override {
        if (entry_.original_size > std::numeric_limits<size_t>::max() ||
            entry_.stored_size > std::numeric_limits<size_t>::max())
            return io_error();
        const std::string identifier = name.str();
        const size_t size = static_cast<size_t>(entry_.original_size);
        const char* source = pack_->mapping.bytes + static_cast<size_t>(entry_.data_offset);
        if (entry_.method == kMethodStored && !requires_null) {
            std::unique_ptr<llvm::MemoryBuffer> result = std::make_unique<SharedBuffer>(
                pack_, source, size, identifier, false, llvm::MemoryBuffer::MemoryBuffer_MMap);
            return result;
        }
        auto decoded = pack_->lookup(entry_);
        if (!decoded) {
            // LLVM allocates the final content buffer and its trailing NUL.
            // Compressed input is a read-only slice of the mapped data file.
            auto output = llvm::WritableMemoryBuffer::getNewUninitMemBuffer(size, identifier);
            if (!output) return std::make_error_code(std::errc::not_enough_memory);
            if (entry_.method == kMethodStored) {
                if (size) std::memcpy(output->getBufferStart(), source, size);
            } else {
                // A handle is never shared between threads. Each independent
                // packed stream resets it, and failures discard the handle.
                thread_local ReusableDecompressor decompressor;
                if (const auto error = decompressor.decode(source, static_cast<size_t>(entry_.stored_size),
                                                           output->getBufferStart(), size))
                    return error;
            }
            decoded = pack_->retain(entry_, std::shared_ptr<const llvm::MemoryBuffer>(std::move(output)));
        }
        std::unique_ptr<llvm::MemoryBuffer> result = std::make_unique<SharedBuffer>(
            decoded, decoded->getBufferStart(), decoded->getBufferSize(), identifier,
            true, llvm::MemoryBuffer::MemoryBuffer_Malloc);
        return result;
    }

private:
    std::shared_ptr<PackData> pack_;
    Entry entry_;
    llvm::vfs::Status status_;
};

class PackedHeaderFileSystem final : public llvm::vfs::ProxyFileSystem {
public:
    PackedHeaderFileSystem(llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem> base,
                           const std::filesystem::path& pack_path,
                           const std::filesystem::path& runtime_root)
        : llvm::vfs::ProxyFileSystem(std::move(base)),
          pack_(read_pack(pack_path, runtime_root)),
          root_(normalized_path(to_utf8(runtime_root))),
          memory_(new llvm::vfs::InMemoryFileSystem(true)) {
        for (const auto& item : pack_->entries) {
            const std::string& path = item.first;
            const size_t relative_start = root_.size() + 1;
            const llvm::StringRef relative(path.data() + relative_start,
                                           path.size() - relative_start);
            size_t slash = 0;
            while ((slash = relative.find('/', slash)) != llvm::StringRef::npos) {
                add_directory(root_ + "/" + relative.take_front(slash).str());
                ++slash;
            }

            auto empty = llvm::MemoryBuffer::getMemBufferCopy("", path);
            if (!memory_->addFile(path, 0, std::move(empty), std::nullopt, std::nullopt,
                                  llvm::sys::fs::file_type::regular_file,
                                  llvm::sys::fs::perms::all_read))
                throw std::runtime_error("could not mount a shgrep.dat entry");
        }
    }

    llvm::ErrorOr<llvm::vfs::Status> status(const llvm::Twine& path) override {
        const std::string requested = path.str();
        const std::string key = normalized_path(requested);
        if (key == root_ || key.starts_with(root_ + "/")) {
            auto memory_status = memory_->status(key);
            if (memory_status) {
                auto named = llvm::vfs::Status::copyWithNewName(*memory_status, requested);
                const auto found = pack_->entries.find(key);
                if (found != pack_->entries.end())
                    return llvm::vfs::Status::copyWithNewSize(named,
                                                              found->second.original_size);
                return named;
            }
            return memory_status.getError();
        }
        return llvm::vfs::ProxyFileSystem::status(path);
    }

    llvm::ErrorOr<std::unique_ptr<llvm::vfs::File>>
    openFileForRead(const llvm::Twine& path) override {
        const std::string requested = path.str();
        const std::string key = normalized_path(requested);
        const auto found = pack_->entries.find(key);
        if (found == pack_->entries.end()) {
            if (key == root_ || key.starts_with(root_ + "/"))
                return std::make_error_code(std::errc::no_such_file_or_directory);
            return llvm::vfs::ProxyFileSystem::openFileForRead(path);
        }

        auto file_status = status(path);
        if (!file_status) return file_status.getError();
        std::unique_ptr<llvm::vfs::File> file =
            std::make_unique<PackedHeaderFile>(pack_, found->second, *file_status);
        return file;
    }

    llvm::vfs::directory_iterator dir_begin(const llvm::Twine& directory,
                                            std::error_code& ec) override {
        const std::string key = normalized_path(directory.str());
        if (key == root_ || key.starts_with(root_ + "/")) {
            return memory_->dir_begin(key, ec);
        }
        return llvm::vfs::ProxyFileSystem::dir_begin(directory, ec);
    }

    std::error_code getRealPath(const llvm::Twine& path,
                                llvm::SmallVectorImpl<char>& output) override {
        const std::string requested = path.str();
        const std::string key = normalized_path(requested);
        if (key == root_ || key.starts_with(root_ + "/")) {
            auto known = memory_->status(key);
            if (!known) return known.getError();
            output.append(requested.begin(), requested.end());
            return {};
        }
        return llvm::vfs::ProxyFileSystem::getRealPath(path, output);
    }

    std::error_code isLocal(const llvm::Twine& path, bool& result) override {
        const std::string key = normalized_path(path.str());
        if (key == root_ || key.starts_with(root_ + "/")) {
            auto known = memory_->status(key);
            if (!known) return known.getError();
            result = true;
            return {};
        }
        return llvm::vfs::ProxyFileSystem::isLocal(path, result);
    }

private:
    void add_directory(const std::string& path) {
        if (!directories_.insert(path).second) return;
        if (!memory_->addFile(path, 0, nullptr, std::nullopt, std::nullopt,
                              llvm::sys::fs::file_type::directory_file,
                              llvm::sys::fs::perms::all_read |
                                  llvm::sys::fs::perms::all_exe))
            throw std::runtime_error("could not mount a C++ runtime directory");
    }

    std::shared_ptr<PackData> pack_;
    std::string root_;
    llvm::IntrusiveRefCntPtr<llvm::vfs::InMemoryFileSystem> memory_;
    std::set<std::string> directories_;
};

} // namespace

llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem>
create_header_filesystem(const std::filesystem::path& pack_path,
                         const std::filesystem::path& runtime_root) {
    return llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem>(
        new PackedHeaderFileSystem(llvm::vfs::getRealFileSystem(), pack_path,
                                   runtime_root));
}

} // namespace shgrep::repl_headers
