#pragma once
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

namespace shgrep {

// Engines that scan text. Hyperscan is the reference: it is compiled for every query, and another engine runs a
// query only where it reports exactly what Hyperscan would. PCRE2 is not selectable; under auto and hyperscan it
// runs the text regexes Hyperscan rejects, and the other backends refuse those queries.
enum class Backend : uint8_t { automatic, hyperscan, teddy, dfa, cuda, hip };

// "auto", "hyperscan", "teddy", "dfa", "cuda", "hip"; nullopt for anything else.
std::optional<Backend> parse_backend(std::string_view name);
const char* backend_name(Backend backend);
// SHGREP_BACKEND, the default for requests without a backend argument; automatic when unset. Throws when set to
// an unknown name, so a benchmark never silently measures the wrong engine.
Backend default_backend();

// Instruction sets the CPU has and the OS enables (XCR0 state for AVX and AVX-512), read once.
struct CpuFeatures {
    bool ssse3 = false, sse42 = false, popcnt = false, bmi1 = false, bmi2 = false;
    bool avx2 = false, avx512bw = false;  // avx512bw implies AVX-512F
};
const CpuFeatures& cpu_features();

// The shape of Hyperscan's match_event_handler, so every engine feeds the same collector: pattern id, start
// (meaningful only when the query tracks starts), end (exclusive), flags (always 0). Non-zero stops the scan.
using MatchHandler = int (*)(unsigned id, unsigned long long from, unsigned long long to, unsigned flags,
                             void* context);

// Per-worker mutable engine state (a lazy DFA's cache, device buffers): one per worker per request, used by one
// thread at a time.
struct EngineScratch {
    virtual ~EngineScratch() = default;
};

enum class ScanStatus : uint8_t { complete, stopped, failed };

// A query compiled for one engine other than Hyperscan; immutable and shared by all workers.
// CONTRACT: scan() reports what hs_scan with the query's block-mode database reports: every (pattern, end)
// occurrence once, with exact starts when the query asks for them, in ascending end offset as Hyperscan does
// (Hyperscan leaves the order of same-end matches undefined). stopped means on_match returned non-zero. failed means the
// engine could not finish (device error, resource limit) and reported nothing; the caller rescans with Hyperscan.
class TextEngine {
public:
    virtual ~TextEngine() = default;
    virtual Backend backend() const = 0;
    // Null when the engine keeps no per-worker state.
    virtual std::unique_ptr<EngineScratch> make_scratch() const { return nullptr; }
    virtual ScanStatus scan(std::string_view text, EngineScratch* scratch, MatchHandler on_match,
                            void* context) const = 0;
    // Longest possible match in bytes; 0 when unbounded. A bounded engine can scan a stream as chunks that overlap
    // by max_match_bytes() - 1 bytes, with scan_chunk.
    virtual size_t max_match_bytes() const { return 0; }
    // One chunk of a stream: chunk[0, fresh_from) repeats the end of the previous chunk, only matches ending after
    // fresh_from are reported, and offsets are base + position. Called for bounded engines only.
    virtual ScanStatus scan_chunk(std::string_view, size_t, uint64_t, EngineScratch*, MatchHandler, void*) const {
        return ScanStatus::failed;
    }
};

} // namespace shgrep
