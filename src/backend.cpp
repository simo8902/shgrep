#include "backend.hpp"

#include <windows.h>
#include <intrin.h>

#include <stdexcept>
#include <string>

namespace shgrep {

std::optional<Backend> parse_backend(std::string_view name) {
    if (name == "auto") return Backend::automatic;
    if (name == "hyperscan") return Backend::hyperscan;
    if (name == "teddy") return Backend::teddy;
    if (name == "dfa") return Backend::dfa;
    if (name == "cuda") return Backend::cuda;
    if (name == "hip") return Backend::hip;
    return std::nullopt;
}

const char* backend_name(Backend backend) {
    switch (backend) {
        case Backend::automatic: return "auto";
        case Backend::hyperscan: return "hyperscan";
        case Backend::teddy: return "teddy";
        case Backend::dfa: return "dfa";
        case Backend::cuda: return "cuda";
        case Backend::hip: return "hip";
    }
    return "unknown";
}

Backend default_backend() {
    static const std::optional<Backend> configured = []() -> std::optional<Backend> {
        wchar_t value[16] = {};
        const DWORD length = GetEnvironmentVariableW(L"SHGREP_BACKEND", value, 16);
        if (length == 0) return Backend::automatic;
        std::string name;
        if (length < 16)
            for (DWORD i = 0; i < length; ++i) name.push_back(value[i] < 0x80 ? static_cast<char>(value[i]) : '?');
        return parse_backend(name);
    }();
    if (!configured)
        throw std::runtime_error("SHGREP_BACKEND must be auto, hyperscan, teddy, dfa, cuda, or hip");
    return *configured;
}

const CpuFeatures& cpu_features() {
    static const CpuFeatures features = [] {
        CpuFeatures f;
        int info[4] = {};
        __cpuid(info, 0);
        const int max_leaf = info[0];
        if (max_leaf < 1) return f;
        __cpuid(info, 1);
        f.ssse3 = (info[2] & (1 << 9)) != 0;
        f.sse42 = (info[2] & (1 << 20)) != 0;
        f.popcnt = (info[2] & (1 << 23)) != 0;
        const bool osxsave = (info[2] & (1 << 27)) != 0, avx = (info[2] & (1 << 28)) != 0;
        if (max_leaf < 7) return f;
        __cpuidex(info, 7, 0);
        f.bmi1 = (info[1] & (1 << 3)) != 0;
        f.bmi2 = (info[1] & (1 << 8)) != 0;
        const unsigned long long xcr0 = osxsave ? _xgetbv(0) : 0;
        const bool ymm = avx && (xcr0 & 0x6) == 0x6;  // the OS saves XMM and YMM state
        f.avx2 = ymm && (info[1] & (1 << 5)) != 0;
        // AVX-512 also needs opmask and ZMM state saved (XCR0 bits 5-7).
        f.avx512bw = ymm && (xcr0 & 0xe6) == 0xe6 && (info[1] & (1 << 16)) != 0 && (info[1] & (1 << 30)) != 0;
        return f;
    }();
    return features;
}

} // namespace shgrep
