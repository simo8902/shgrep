#pragma once

#include <cstdint>

namespace shgrep::repl_headers {

inline constexpr char kPackMagic[8] = {'S', 'G', 'R', 'P', 'D', 'A', 'T', '1'};
inline constexpr uint32_t kPackVersion = 1;
inline constexpr uint32_t kMethodStored = 0;
inline constexpr uint32_t kMethodXpressHuff = 1;
inline constexpr uint64_t kMaximumEntries = 200000;
inline constexpr uint64_t kMaximumPathBytes = 32768;
inline constexpr uint64_t kMaximumFileBytes = 512ull * 1024 * 1024;
inline constexpr uint64_t kMaximumPackBytes = 2ull * 1024 * 1024 * 1024;
inline constexpr uint64_t kPackHeaderBytes = 16;
inline constexpr uint64_t kPackEntryFixedBytes = 32;

} // namespace shgrep::repl_headers
