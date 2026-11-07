#pragma once

#include <filesystem>

#include <llvm/ADT/IntrusiveRefCntPtr.h>
#include <llvm/Support/VirtualFileSystem.h>

namespace shgrep::repl_headers {

inline constexpr char kRuntimeSymbolIndexPath[] = "lib/runtime-symbols.idx";
inline constexpr char kRuntimeSymbolIndexMagic[8] = {'S', 'G', 'R', 'P', 'S', 'Y', 'M', '1'};

// Holds one read-only mapping and a 64 MiB decoded-entry cache per reader.
// Returned LLVM buffers retain their storage independently of VFS/cache lifetime.
llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem>
create_header_filesystem(const std::filesystem::path& pack_path,
                         const std::filesystem::path& runtime_root);

} // namespace shgrep::repl_headers
