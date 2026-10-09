#include "teddy.hpp"

#include <immintrin.h>
#include <intrin.h>

#include <algorithm>
#include <bit>
#include <cstring>

#if defined(_MSC_VER) && !defined(__clang__)
// MSVC compiles SSSE3 and AVX2 intrinsics without /arch flags; build() checks the CPU first.
#define TEDDY_AVX2
#define TEDDY_SSSE3
#else
#define TEDDY_AVX2 __attribute__((target("avx2")))
#define TEDDY_SSSE3 __attribute__((target("ssse3")))
#endif

namespace shgrep {
namespace {

inline uint8_t lower(uint8_t c) { return c >= 'A' && c <= 'Z' ? static_cast<uint8_t>(c + 32) : c; }

// Verify one candidate: does literal `lit` occur at text[start]?
inline bool verify(const Teddy::Literal& lit, bool caseless, const uint8_t* text, size_t size, size_t start) {
    const size_t length = lit.bytes.size();
    if (length > size - start) return false;
    const auto* want = reinterpret_cast<const uint8_t*>(lit.bytes.data());
    if (!caseless) return std::memcmp(text + start, want, length) == 0;
    for (size_t i = 0; i < length; ++i)
        if (lower(text[start + i]) != want[i]) return false;
    return true;
}

// A match held until it can be reported in order; positions are chunk offsets.
struct Pending {
    size_t end, start;
    unsigned id;
};

struct TeddyScratch final : EngineScratch {
    std::vector<Pending> pending;  // reused across files, so a worker allocates it once
};

// Delivers matches in Hyperscan's order: ascending end, then pattern id (Hyperscan leaves the order of same-end
// matches undefined). The vector pass finds them in start order, which is already that order unless literals
// differ in length or two can end together; then they wait in `pending` until no later start can sort before them.
struct Emitter {
    MatchHandler on_match;
    void* context;
    uint64_t base;
    size_t fresh_from;              // matches ending at or before this were reported with the previous chunk
    std::vector<Pending>* pending;  // null when start order is report order
    bool emit(unsigned id, size_t start, size_t end) const {
        return end <= fresh_from || on_match(id, base + start, base + end, 0, context) == 0;
    }
    bool add(unsigned id, size_t start, size_t end) const {
        if (!pending) return emit(id, start, end);
        pending->push_back({end, start, id});
        return true;
    }
    // Reports the held matches that end before `limit`.
    bool flush(size_t limit) const {
        if (!pending || pending->empty()) return true;
        auto& held = *pending;
        std::sort(held.begin(), held.end(), [](const Pending& a, const Pending& b) {
            return a.end != b.end ? a.end < b.end : a.id < b.id;
        });
        size_t done = 0;
        for (; done < held.size() && held[done].end < limit; ++done)
            if (!emit(held[done].id, held[done].start, held[done].end)) return false;
        held.erase(held.begin(), held.begin() + static_cast<ptrdiff_t>(done));
        return true;
    }
};

// Report every literal of the buckets named by `bits` that occurs at `start`.
inline bool report(const Teddy& t, unsigned bits, const uint8_t* text, size_t size, size_t start, const Emitter& e) {
    while (bits) {
        const auto bucket = static_cast<unsigned>(std::countr_zero(bits));
        bits &= bits - 1;
        for (uint32_t k = t.bucket_begin[bucket]; k < t.bucket_begin[bucket + 1]; ++k) {
            const Teddy::Literal& lit = t.literals[t.bucket_items[k]];
            if (verify(lit, t.caseless, text, size, start) && !e.add(lit.id, start, start + lit.bytes.size()))
                return false;
        }
    }
    return true;
}

// Bucket bits for the 32 bytes at `p`: byte i holds the buckets whose fingerprint matches p[i .. i+N-1].
template <unsigned N>
TEDDY_AVX2 inline __m256i candidates32(const Teddy& t, const uint8_t* p) {
    const __m256i nibble = _mm256_set1_epi8(0x0F);
    __m256i all = _mm256_set1_epi8(static_cast<char>(0xFF));
    for (unsigned k = 0; k < N; ++k) {
        const __m256i x = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p + k));
        const __m256i lo = _mm256_shuffle_epi8(_mm256_load_si256(reinterpret_cast<const __m256i*>(t.low[k])),
                                               _mm256_and_si256(x, nibble));
        // The shift works on 16-bit lanes, so the mask also clears bits that crossed in from the neighbor byte;
        // PSHUFB would otherwise zero lanes whose index has bit 7 set.
        const __m256i hi = _mm256_shuffle_epi8(_mm256_load_si256(reinterpret_cast<const __m256i*>(t.high[k])),
                                               _mm256_and_si256(_mm256_srli_epi16(x, 4), nibble));
        all = _mm256_and_si256(all, _mm256_and_si256(lo, hi));
    }
    return all;
}

// The same for the 16 bytes at `p`, with SSSE3; the tables' first lane serves.
template <unsigned N>
TEDDY_SSSE3 inline __m128i candidates16(const Teddy& t, const uint8_t* p) {
    const __m128i nibble = _mm_set1_epi8(0x0F);
    __m128i all = _mm_set1_epi8(static_cast<char>(0xFF));
    for (unsigned k = 0; k < N; ++k) {
        const __m128i x = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + k));
        const __m128i lo = _mm_shuffle_epi8(_mm_load_si128(reinterpret_cast<const __m128i*>(t.low[k])),
                                            _mm_and_si128(x, nibble));
        const __m128i hi = _mm_shuffle_epi8(_mm_load_si128(reinterpret_cast<const __m128i*>(t.high[k])),
                                            _mm_and_si128(_mm_srli_epi16(x, 4), nibble));
        all = _mm_and_si128(all, _mm_and_si128(lo, hi));
    }
    return all;
}

// Verify every candidate of one block starting at text[pos]. Every match found from here on starts at pos or
// later and so ends at pos + shortest or later; held matches ending before that are final.
inline bool report_block(const Teddy& t, uint32_t mask, const uint8_t* bits, const uint8_t* text, size_t size,
                         size_t pos, const Emitter& e) {
    if (!e.flush(pos + t.shortest)) return false;
    while (mask) {
        const auto bit = static_cast<unsigned>(std::countr_zero(mask));
        mask &= mask - 1;
        if (!report(t, bits[bit], text, size, pos + bit, e)) return false;
    }
    return true;
}

template <unsigned N>
TEDDY_AVX2 bool run32(const Teddy& t, const uint8_t* text, size_t size, const Emitter& e) {
    const __m256i zero = _mm256_setzero_si256();
    alignas(32) uint8_t bits[32];
    size_t pos = 0;
    // Main loop: the load at pos + N - 1 reads 32 bytes, which must stay inside the text.
    for (; pos + 32 + (N - 1) <= size; pos += 32) {
        const __m256i c = candidates32<N>(t, text + pos);
        const uint32_t mask = ~static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(c, zero)));
        if (!mask) continue;
        _mm256_store_si256(reinterpret_cast<__m256i*>(bits), c);
        if (!report_block(t, mask, bits, text, size, pos, e)) return false;
    }
    // Tail (at most 31 + N - 1 bytes): copy each remaining block with its lookahead into a zero-padded buffer
    // and run the same pass. Candidates past the real end are masked off, and verify() bounds-checks every
    // literal against the real text, so the padding never produces a match.
    while (pos < size) {
        const size_t left = size - pos;
        alignas(32) uint8_t tail[64] = {};
        std::memcpy(tail, text + pos, std::min<size_t>(left, 32 + (N - 1)));
        const __m256i c = candidates32<N>(t, tail);
        uint32_t mask = ~static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(c, zero)));
        if (left < 32) mask &= (1u << left) - 1;
        _mm256_store_si256(reinterpret_cast<__m256i*>(bits), c);
        if (!report_block(t, mask, bits, text, size, pos, e)) return false;
        pos += 32;
    }
    return true;
}

// run32 with 16-byte SSSE3 blocks, for CPUs without AVX2.
template <unsigned N>
TEDDY_SSSE3 bool run16(const Teddy& t, const uint8_t* text, size_t size, const Emitter& e) {
    const __m128i zero = _mm_setzero_si128();
    alignas(16) uint8_t bits[16];
    size_t pos = 0;
    for (; pos + 16 + (N - 1) <= size; pos += 16) {
        const __m128i c = candidates16<N>(t, text + pos);
        const uint32_t mask = ~static_cast<uint32_t>(_mm_movemask_epi8(_mm_cmpeq_epi8(c, zero))) & 0xFFFFu;
        if (!mask) continue;
        _mm_store_si128(reinterpret_cast<__m128i*>(bits), c);
        if (!report_block(t, mask, bits, text, size, pos, e)) return false;
    }
    while (pos < size) {
        const size_t left = size - pos;
        alignas(16) uint8_t tail[32] = {};
        std::memcpy(tail, text + pos, std::min<size_t>(left, 16 + (N - 1)));
        const __m128i c = candidates16<N>(t, tail);
        uint32_t mask = ~static_cast<uint32_t>(_mm_movemask_epi8(_mm_cmpeq_epi8(c, zero))) & 0xFFFFu;
        if (left < 16) mask &= (1u << left) - 1;
        _mm_store_si128(reinterpret_cast<__m128i*>(bits), c);
        if (!report_block(t, mask, bits, text, size, pos, e)) return false;
        pos += 16;
    }
    return true;
}

} // namespace

std::unique_ptr<Teddy> Teddy::build(const std::vector<std::string>& patterns, bool caseless) {
    if (patterns.empty() || patterns.size() > max_patterns || !cpu_features().ssse3) return nullptr;
    size_t shortest = SIZE_MAX, longest = 0;
    for (const auto& p : patterns) {
        if (p.empty()) return nullptr;
        shortest = std::min(shortest, p.size());
        longest = std::max(longest, p.size());
    }
    auto t = std::make_unique<Teddy>();
    t->caseless = caseless;
    t->wide = cpu_features().avx2;
    t->shortest = shortest;
    t->longest = longest;
    t->fingerprint = static_cast<unsigned>(std::min<size_t>(shortest, 3));
    t->literals.reserve(patterns.size());
    for (size_t i = 0; i < patterns.size(); ++i) {
        Literal lit;
        lit.id = static_cast<unsigned>(i);
        lit.bytes = patterns[i];
        if (caseless)
            for (char& c : lit.bytes) c = static_cast<char>(lower(static_cast<uint8_t>(c)));
        t->literals.push_back(std::move(lit));
    }
    // Two ids can end at the same offset exactly when one (folded) literal ends another, duplicates included.
    for (const auto& a : t->literals)
        for (const auto& b : t->literals)
            if (&a != &b && a.bytes.size() <= b.bytes.size() &&
                b.bytes.compare(b.bytes.size() - a.bytes.size(), a.bytes.size(), a.bytes) == 0)
                t->ties = true;
    t->reorder = t->ties || shortest != longest;

    // Bucket assignment: sort by fingerprint and cut the order into contiguous groups, so literals that share
    // fingerprint bytes share a bucket and add few extra false candidates.
    std::vector<uint32_t> order(patterns.size());
    for (uint32_t i = 0; i < order.size(); ++i) order[i] = i;
    const unsigned n = t->fingerprint;
    std::sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) {
        return t->literals[a].bytes.compare(0, n, t->literals[b].bytes, 0, n) < 0;
    });
    const size_t per_bucket = (order.size() + bucket_count - 1) / bucket_count;
    t->bucket_begin.assign(bucket_count + 1, 0);
    for (size_t b = 0; b < bucket_count; ++b) {
        const size_t begin = std::min(order.size(), b * per_bucket);
        const size_t end = std::min(order.size(), begin + per_bucket);
        t->bucket_begin[b] = static_cast<uint32_t>(t->bucket_items.size());
        for (size_t k = begin; k < end; ++k) t->bucket_items.push_back(order[k]);
        t->bucket_begin[b + 1] = static_cast<uint32_t>(t->bucket_items.size());
        for (size_t k = begin; k < end; ++k) {
            const std::string& bytes = t->literals[order[k]].bytes;
            for (unsigned pos = 0; pos < n; ++pos) {
                const auto c = static_cast<uint8_t>(bytes[pos]);
                const bool both = caseless && c >= 'a' && c <= 'z';
                for (int variant = 0; variant < (both ? 2 : 1); ++variant) {
                    const auto v = static_cast<uint8_t>(variant ? c - 32 : c);
                    // Both 128-bit lanes carry the same 16-entry table, because PSHUFB indexes within a lane.
                    for (int lane = 0; lane < 2; ++lane) {
                        t->low[pos][lane * 16 + (v & 0x0F)] |= static_cast<uint8_t>(1u << b);
                        t->high[pos][lane * 16 + (v >> 4)] |= static_cast<uint8_t>(1u << b);
                    }
                }
            }
        }
    }
    return t;
}

std::unique_ptr<EngineScratch> Teddy::make_scratch() const {
    if (!reorder) return nullptr;
    return std::make_unique<TeddyScratch>();
}

ScanStatus Teddy::scan(std::string_view text, EngineScratch* scratch, MatchHandler on_match, void* context) const {
    return scan_chunk(text, 0, 0, scratch, on_match, context);
}

ScanStatus Teddy::scan_chunk(std::string_view chunk, size_t fresh_from, uint64_t base, EngineScratch* scratch,
                             MatchHandler on_match, void* context) const {
    std::vector<Pending> local;
    std::vector<Pending>* pending = nullptr;
    if (reorder) {
        // CONTRACT: scratch, when given, came from this engine's make_scratch().
        pending = scratch ? &static_cast<TeddyScratch*>(scratch)->pending : &local;
        pending->clear();
    }
    const Emitter e{on_match, context, base, fresh_from, pending};
    const auto* bytes = reinterpret_cast<const uint8_t*>(chunk.data());
    const size_t size = chunk.size();
    bool complete;
    if (wide) {
        switch (fingerprint) {
            case 1: complete = run32<1>(*this, bytes, size, e); break;
            case 2: complete = run32<2>(*this, bytes, size, e); break;
            default: complete = run32<3>(*this, bytes, size, e); break;
        }
    } else {
        switch (fingerprint) {
            case 1: complete = run16<1>(*this, bytes, size, e); break;
            case 2: complete = run16<2>(*this, bytes, size, e); break;
            default: complete = run16<3>(*this, bytes, size, e); break;
        }
    }
    complete = complete && e.flush(SIZE_MAX);
    return complete ? ScanStatus::complete : ScanStatus::stopped;
}

} // namespace shgrep
