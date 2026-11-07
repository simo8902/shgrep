#pragma once
#include <cstddef>
#include <cstdint>

namespace shgrep::compiler_api {
// Bump when the entry contract or operation semantics change.
// 2: the licenses operation moved to shgrep.exe, which reads licenses\ beside it.
inline constexpr uint32_t version = 2;
inline constexpr uint32_t worker = 1;
inline constexpr char entry_name[] = "shgrep_compiler_entry_v1";
// Only scalar values and caller-owned bytes cross the separate /MT runtimes.
using Entry = int (__cdecl *)(uint32_t, uint32_t, char*, size_t) noexcept;
}

namespace shgrep {
// Internal implementation, linked only into shgrep-compiler.dll.
int run_compiler_worker();
}
