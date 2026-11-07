#include "dfa.hpp"

#include <emmintrin.h>

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstring>
#include <map>
#include <new>
#include <string_view>
#include <utility>

namespace shgrep {
namespace {

// Thrown inside build() when a pattern or a limit rules the DFA out; build() turns it into `why`.
struct Declined {
    std::string why;
};

// ---- Patterns --------------------------------------------------------------------------------------------------

using Ranges = std::vector<std::pair<uint32_t, uint32_t>>;  // inclusive code point ranges
constexpr uint32_t max_code_point = 0x10FFFF;
constexpr uint32_t unbounded = UINT32_MAX;
constexpr uint32_t max_repeat = 1000;

void normalize(Ranges& r) {
    std::sort(r.begin(), r.end());
    Ranges out;
    for (const auto& x : r) {
        if (!out.empty() && x.first <= out.back().second + 1) out.back().second = std::max(out.back().second, x.second);
        else out.push_back(x);
    }
    r = std::move(out);
}

Ranges complement(const Ranges& r) {
    Ranges out;
    uint32_t next = 0;
    for (const auto& x : r) {
        if (x.first > next) out.push_back({next, x.first - 1});
        next = x.second + 1;
    }
    if (next <= max_code_point) out.push_back({next, max_code_point});
    return out;
}

// Hyperscan's caseless closure (make_caseless over ucp_caseless_def) restricted to ASCII input: each letter adds
// its other case, and k and s also add KELVIN SIGN and LATIN SMALL LETTER LONG S.
void add_caseless(Ranges& r) {
    Ranges extra;
    for (const auto& [lo, hi] : r) {
        for (uint32_t c = lo; c <= hi; ++c) {
            const bool letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
            if (!letter) continue;
            const uint32_t lower = c | 0x20;
            extra.push_back({lower, lower});
            extra.push_back({lower - 32, lower - 32});
            if (lower == 'k') extra.push_back({0x212A, 0x212A});
            if (lower == 's') extra.push_back({0x17F, 0x17F});
        }
    }
    r.insert(r.end(), extra.begin(), extra.end());
    normalize(r);
}

struct Node {
    enum Kind : uint8_t { empty, set, concat, alternate, repeat, line_start, line_end };
    Kind kind = empty;
    Ranges ranges;               // set
    std::vector<Node> children;  // concat, alternate; repeat has one
    uint32_t min = 0, max = 0;   // repeat; max may be unbounded
};

// Parses the accepted subset of Hyperscan's PCRE syntax. Anything outside it throws Declined.
class Parser {
public:
    Parser(std::string_view pattern, bool caseless) : p_(pattern), caseless_(caseless) {}

    Node parse() {
        Node n = alternation(0);
        if (pos_ != p_.size()) decline("unbalanced ')'");
        return n;
    }

private:
    [[noreturn]] static void decline(const std::string& why) { throw Declined{why}; }
    bool done() const { return pos_ >= p_.size(); }
    char peek() const { return p_[pos_]; }

    Node alternation(int depth) {
        if (depth > 200) decline("groups nested too deeply");
        Node alt;
        alt.kind = Node::alternate;
        alt.children.push_back(concatenation(depth));
        while (!done() && peek() == '|') {
            ++pos_;
            alt.children.push_back(concatenation(depth));
        }
        if (alt.children.size() == 1) return std::move(alt.children.front());
        return alt;
    }

    Node concatenation(int depth) {
        Node seq;
        seq.kind = Node::concat;
        while (!done() && peek() != '|' && peek() != ')') {
            Node item = atom(depth);
            quantify(item);
            seq.children.push_back(std::move(item));
        }
        if (seq.children.empty()) return Node{};
        if (seq.children.size() == 1) return std::move(seq.children.front());
        return seq;
    }

    Node atom(int depth) {
        const char c = peek();
        switch (c) {
            case '(': {
                ++pos_;
                if (!done() && peek() == '?') {
                    if (pos_ + 1 < p_.size() && p_[pos_ + 1] == ':') pos_ += 2;
                    else decline("only (...) and (?:...) groups");
                }
                Node inner = alternation(depth + 1);
                if (done() || peek() != ')') decline("unbalanced '('");
                ++pos_;
                return inner;
            }
            case '[': return set(bracket(), false);
            case '.':
                // CONTRACT: no HS_FLAG_DOTALL, so '.' is any code point but '\n'.
                ++pos_;
                return set(complement({{'\n', '\n'}}), false);
            case '^': ++pos_; return anchor(Node::line_start);
            case '$': ++pos_; return anchor(Node::line_end);
            case '*': case '+': case '?': decline("quantifier without an operand");
            case '{': decline("'{' that does not follow a quantifiable item");
            case '\\': return set({{escape(), 0}}, true);
            default: return set({{literal(), 0}}, true);
        }
    }

    static Node anchor(Node::Kind kind) {
        Node n;
        n.kind = kind;
        return n;
    }

    // `ranges` arrives as {{code point, 0}} for single characters, or as a finished set.
    Node set(Ranges ranges, bool single) {
        if (single) ranges.front().second = ranges.front().first;
        if (single && caseless_) {
            if (ranges.front().first >= 0x80) decline("caseless non-ASCII character (needs Unicode case tables)");
            add_caseless(ranges);
        }
        Node n;
        n.kind = Node::set;
        n.ranges = std::move(ranges);
        return n;
    }

    void quantify(Node& item) {
        if (done()) return;
        uint32_t min = 0, max = 0;
        const char c = peek();
        if (c == '*') { min = 0; max = unbounded; ++pos_; }
        else if (c == '+') { min = 1; max = unbounded; ++pos_; }
        else if (c == '?') { min = 0; max = 1; ++pos_; }
        else if (c == '{') counted(min, max);
        else return;
        if (item.kind == Node::line_start || item.kind == Node::line_end) decline("quantified anchor");
        // Lazy and greedy repeats end at the same offsets, and every end is reported.
        if (!done() && peek() == '?') ++pos_;
        else if (!done() && peek() == '+') decline("possessive quantifier");
        if (!done() && (peek() == '*' || peek() == '+' || peek() == '?' || peek() == '{')) decline("stacked quantifiers");
        if (max != unbounded && min > max) decline("repeat with min above max");
        if (min > max_repeat || (max != unbounded && max > max_repeat)) decline("counted repeat above 1000");
        Node r;
        r.kind = Node::repeat;
        r.min = min;
        r.max = max;
        r.children.push_back(std::move(item));
        item = std::move(r);
    }

    // {n}, {n,} or {n,m}. PCRE reads any other '{' as a literal; the DFA declines it instead.
    void counted(uint32_t& min, uint32_t& max) {
        ++pos_;
        auto number = [&](uint32_t& out) {
            size_t digits = 0;
            out = 0;
            while (!done() && peek() >= '0' && peek() <= '9') {
                if (++digits > 6) decline("counted repeat above 1000");
                out = out * 10 + static_cast<uint32_t>(peek() - '0');
                ++pos_;
            }
            return digits != 0;
        };
        if (!number(min)) decline("'{' that is not a {n}, {n,} or {n,m} quantifier");
        if (!done() && peek() == '}') {
            max = min;
        } else if (!done() && peek() == ',') {
            ++pos_;
            if (!done() && peek() == '}') max = unbounded;
            else if (!number(max)) decline("'{' that is not a {n}, {n,} or {n,m} quantifier");
        }
        if (done() || peek() != '}') decline("'{' that is not a {n}, {n,} or {n,m} quantifier");
        ++pos_;
    }

    // One UTF-8 encoded code point; text patterns are validated UTF-8.
    uint32_t literal() {
        const auto lead = static_cast<unsigned char>(p_[pos_]);
        const unsigned length = lead < 0x80 ? 1 : lead < 0xE0 ? 2 : lead < 0xF0 ? 3 : 4;
        if (pos_ + length > p_.size()) decline("truncated UTF-8");
        uint32_t cp = length == 1 ? lead : lead & (0x7Fu >> length);
        for (unsigned i = 1; i < length; ++i) cp = (cp << 6) | (static_cast<unsigned char>(p_[pos_ + i]) & 0x3F);
        pos_ += length;
        return cp;
    }

    uint32_t escape() {
        ++pos_;
        if (done()) decline("trailing backslash");
        const auto c = static_cast<unsigned char>(peek());
        if (c >= 0x80) decline("escaped non-ASCII character");
        ++pos_;
        const bool alnum = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        if (!alnum) return c;  // PCRE: a backslash before any other ASCII character quotes it
        switch (c) {
            case 't': return '\t';
            case 'n': return '\n';
            case 'r': return '\r';
            case 'f': return '\f';
            case 'e': return 0x1B;
            case 'a': return 0x07;
            case 'x': return hex();
            default: decline(std::string("escape \\") + static_cast<char>(c));
        }
    }

    // \xh, \xhh or \x{h...}.
    uint32_t hex() {
        auto digit = [](char d) -> int {
            if (d >= '0' && d <= '9') return d - '0';
            if (d >= 'a' && d <= 'f') return d - 'a' + 10;
            if (d >= 'A' && d <= 'F') return d - 'A' + 10;
            return -1;
        };
        uint32_t value = 0;
        size_t digits = 0;
        if (!done() && peek() == '{') {
            ++pos_;
            while (!done() && digit(peek()) >= 0) {
                if (++digits > 6) decline("\\x{...} out of range");
                value = value * 16 + static_cast<uint32_t>(digit(peek()));
                ++pos_;
            }
            if (done() || peek() != '}' || digits == 0) decline("malformed \\x{...}");
            ++pos_;
        } else {
            while (digits < 2 && !done() && digit(peek()) >= 0) {
                value = value * 16 + static_cast<uint32_t>(digit(peek()));
                ++digits;
                ++pos_;
            }
            if (digits == 0) decline("\\x without hex digits");
        }
        if (value > max_code_point || (value >= 0xD800 && value <= 0xDFFF)) decline("\\x value is not a Unicode scalar");
        return value;
    }

    // A bracket class. CONTRACT: like Hyperscan's UTF8ComponentClass, each item gets its caseless closure first and
    // the whole set is negated last.
    Ranges bracket() {
        ++pos_;
        bool negate = false;
        if (!done() && peek() == '^') {
            negate = true;
            ++pos_;
        }
        Ranges r;
        for (bool first = true;; first = false) {
            if (done()) decline("unterminated class");
            if (peek() == ']' && !first) {
                ++pos_;
                break;
            }
            const uint32_t lo = class_atom();
            uint32_t hi = lo;
            if (!done() && peek() == '-' && pos_ + 1 < p_.size() && p_[pos_ + 1] != ']') {
                ++pos_;
                hi = class_atom();
                if (hi < lo) decline("reversed class range");
            }
            Ranges item{{lo, hi}};
            if (caseless_) {
                if (hi >= 0x80) decline("caseless non-ASCII class (needs Unicode case tables)");
                add_caseless(item);
            }
            r.insert(r.end(), item.begin(), item.end());
        }
        normalize(r);
        return negate ? complement(r) : r;
    }

    uint32_t class_atom() {
        const char c = peek();
        if (c == '[' && pos_ + 1 < p_.size() && (p_[pos_ + 1] == ':' || p_[pos_ + 1] == '.' || p_[pos_ + 1] == '='))
            decline("POSIX class (Unicode-dependent under UCP)");
        if (c == '\\') return escape();
        return literal();
    }

    std::string_view p_;
    bool caseless_;
    size_t pos_ = 0;
};

// ---- NFA over bytes --------------------------------------------------------------------------------------------

struct NfaState {
    enum Kind : uint8_t { range, split, line_start, line_end, match };
    Kind kind = split;
    uint8_t lo = 0, hi = 0;          // range
    uint32_t next = 0;               // range, line_start, line_end
    std::vector<uint32_t> targets;   // split
    unsigned pattern = 0;            // match
};

using ByteRange = std::pair<uint8_t, uint8_t>;

unsigned utf8_encode(uint32_t cp, uint8_t* out) {
    if (cp < 0x80) { out[0] = static_cast<uint8_t>(cp); return 1; }
    if (cp < 0x800) {
        out[0] = static_cast<uint8_t>(0xC0 | (cp >> 6));
        out[1] = static_cast<uint8_t>(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = static_cast<uint8_t>(0xE0 | (cp >> 12));
        out[1] = static_cast<uint8_t>(0x80 | ((cp >> 6) & 0x3F));
        out[2] = static_cast<uint8_t>(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = static_cast<uint8_t>(0xF0 | (cp >> 18));
    out[1] = static_cast<uint8_t>(0x80 | ((cp >> 12) & 0x3F));
    out[2] = static_cast<uint8_t>(0x80 | ((cp >> 6) & 0x3F));
    out[3] = static_cast<uint8_t>(0x80 | (cp & 0x3F));
    return 4;
}

// Splits a code point range into sequences of byte ranges whose product is exactly its UTF-8 encodings, like
// regex-syntax's Utf8Sequences. Surrogates are left out; they never occur in valid UTF-8.
void utf8_sequences(uint32_t lo, uint32_t hi, std::vector<std::vector<ByteRange>>& out) {
    std::vector<std::pair<uint32_t, uint32_t>> stack{{lo, hi}};
    while (!stack.empty()) {
        const auto [a, b] = stack.back();
        stack.pop_back();
        if (a > b) continue;
        if (a <= 0xDFFF && b >= 0xD800) {
            if (a < 0xD800) stack.push_back({a, 0xD7FF});
            if (b > 0xDFFF) stack.push_back({0xE000, b});
            continue;
        }
        bool split = false;
        for (const uint32_t edge : {0x7Fu, 0x7FFu, 0xFFFFu}) {
            if (a <= edge && b > edge) {
                stack.push_back({edge + 1, b});
                stack.push_back({a, edge});
                split = true;
                break;
            }
        }
        if (split) continue;
        uint8_t ea[4], eb[4];
        const unsigned n = utf8_encode(a, ea);
        utf8_encode(b, eb);
        for (unsigned i = 1; i < n && !split; ++i) {
            const uint32_t m = (1u << (6 * i)) - 1;
            if ((a & ~m) == (b & ~m)) continue;
            if ((a & m) != 0) {
                stack.push_back({(a | m) + 1, b});
                stack.push_back({a, a | m});
                split = true;
            } else if ((b & m) != m) {
                stack.push_back({b & ~m, b});
                stack.push_back({a, (b & ~m) - 1});
                split = true;
            }
        }
        if (split) continue;
        std::vector<ByteRange> sequence;
        for (unsigned i = 0; i < n; ++i) sequence.push_back({ea[i], eb[i]});
        out.push_back(std::move(sequence));
    }
}

class NfaBuilder {
public:
    explicit NfaBuilder(size_t limit) : limit_(limit) {}
    std::vector<NfaState> states;

    uint32_t add(NfaState s) {
        if (states.size() >= limit_) throw Declined{"NFA above " + std::to_string(limit_) + " states"};
        states.push_back(std::move(s));
        return static_cast<uint32_t>(states.size() - 1);
    }

    // Compiles `n` so that after it control continues at `next`; returns its entry state.
    uint32_t compile(const Node& n, uint32_t next) {
        switch (n.kind) {
            case Node::empty: return next;
            case Node::set: return compile_set(n.ranges, next);
            case Node::concat:
                for (auto it = n.children.rbegin(); it != n.children.rend(); ++it) next = compile(*it, next);
                return next;
            case Node::alternate: {
                NfaState s;
                s.kind = NfaState::split;
                for (const auto& child : n.children) s.targets.push_back(compile(child, next));
                return add(std::move(s));
            }
            case Node::line_start:
            case Node::line_end: {
                NfaState s;
                s.kind = n.kind == Node::line_start ? NfaState::line_start : NfaState::line_end;
                s.next = next;
                return add(std::move(s));
            }
            case Node::repeat: return compile_repeat(n, next);
        }
        return next;
    }

private:
    uint32_t compile_set(const Ranges& ranges, uint32_t next) {
        std::vector<std::vector<ByteRange>> sequences;
        for (const auto& [lo, hi] : ranges) utf8_sequences(lo, hi, sequences);
        if (sequences.empty()) {
            // An empty set matches nothing: a range no byte satisfies.
            NfaState s;
            s.kind = NfaState::split;
            return add(std::move(s));
        }
        NfaState alt;
        alt.kind = NfaState::split;
        for (const auto& sequence : sequences) {
            uint32_t at = next;
            for (auto it = sequence.rbegin(); it != sequence.rend(); ++it) {
                NfaState s;
                s.kind = NfaState::range;
                s.lo = it->first;
                s.hi = it->second;
                s.next = at;
                at = add(std::move(s));
            }
            alt.targets.push_back(at);
        }
        if (alt.targets.size() == 1) return alt.targets.front();
        return add(std::move(alt));
    }

    uint32_t compile_repeat(const Node& n, uint32_t next) {
        const Node& body = n.children.front();
        uint32_t tail = next;
        if (n.max == unbounded) {
            NfaState loop;
            loop.kind = NfaState::split;
            const uint32_t id = add(std::move(loop));
            const uint32_t entry = compile(body, id);
            states[id].targets = {entry, next};
            tail = id;
        } else {
            // Optional copies, innermost first: each may stop and continue at `next`.
            for (uint32_t i = n.min; i < n.max; ++i) {
                NfaState optional;
                optional.kind = NfaState::split;
                optional.targets = {compile(body, tail), next};
                tail = add(std::move(optional));
            }
        }
        for (uint32_t i = 0; i < n.min; ++i) tail = compile(body, tail);
        return tail;
    }

    size_t limit_;
};

// ---- Determinization -------------------------------------------------------------------------------------------

// Subset construction. A DFA state is the set of NFA states live at a position (byte ranges to take, pattern
// matches, and $ assertions waiting for the next byte) plus whether the previous byte was '\n' (^ holds). The
// unanchored start is added at every position. Matches found at a position end there; those that need $ are
// reported only when the next byte is '\n' or the text ends, so each state keeps two match lists.
class Determinizer {
public:
    Determinizer(const std::vector<NfaState>& nfa, uint32_t start, const DfaLimits& limits)
        : nfa_(nfa), start_(start), limits_(limits), mark_(nfa.size(), 0) {
        for (const auto& s : nfa)
            if (s.kind == NfaState::line_start) uses_line_start_ = true;
        deadline_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(limits.max_build_ms);
    }

    void run(Dfa& dfa) {
        byte_classes(dfa);
        std::vector<uint32_t> seeds{start_};
        intern(closure(seeds, uses_line_start_, false), uses_line_start_);
        std::vector<uint32_t> moved;
        for (size_t i = 0; i < sets_.size(); ++i) {
            if (std::chrono::steady_clock::now() > deadline_)
                throw Declined{"DFA build over " + std::to_string(limits_.max_build_ms) + " ms"};
            const std::vector<uint32_t> set = sets_[i];  // copy: intern() may grow sets_
            const bool flag = flags_[i];
            const std::vector<uint32_t> before_newline = closure(set, flag, true);
            matches_.push_back(match_ids(set));
            matches_nl_.push_back(match_ids(before_newline));
            for (unsigned k = 0; k < classes_; ++k) {
                const uint8_t b = representative_[k];
                const std::vector<uint32_t>& live = b == '\n' ? before_newline : set;
                moved.clear();
                for (uint32_t s : live) {
                    const NfaState& st = nfa_[s];
                    if (st.kind == NfaState::range && b >= st.lo && b <= st.hi) moved.push_back(st.next);
                }
                moved.push_back(start_);
                const bool next_flag = uses_line_start_ && b == '\n';
                raw_.push_back(intern(closure(moved, next_flag, false), next_flag));
            }
        }
        finish(dfa);
    }

private:
    void byte_classes(Dfa& dfa) {
        bool boundary[257] = {};
        boundary[0] = true;
        boundary['\n'] = boundary['\n' + 1] = true;
        for (const auto& s : nfa_) {
            if (s.kind != NfaState::range) continue;
            boundary[s.lo] = true;
            boundary[s.hi + 1] = true;
        }
        unsigned k = 0;
        for (unsigned b = 0; b < 256; ++b) {
            if (b && boundary[b]) ++k;
            dfa.byte_class[b] = static_cast<uint8_t>(k);
            if (boundary[b]) representative_.push_back(static_cast<uint8_t>(b));
        }
        classes_ = k + 1;
    }

    // Follows splits, ^ when the previous byte was '\n' (or at the start), and $ when the next byte is known to be
    // '\n'; keeps byte ranges, matches, and $ assertions still waiting.
    std::vector<uint32_t> closure(const std::vector<uint32_t>& seeds, bool prev_nl, bool next_nl) {
        ++generation_;
        std::vector<uint32_t> out;
        stack_.assign(seeds.begin(), seeds.end());
        while (!stack_.empty()) {
            const uint32_t s = stack_.back();
            stack_.pop_back();
            if (mark_[s] == generation_) continue;
            mark_[s] = generation_;
            const NfaState& st = nfa_[s];
            switch (st.kind) {
                case NfaState::split:
                    stack_.insert(stack_.end(), st.targets.begin(), st.targets.end());
                    break;
                case NfaState::line_start:
                    if (prev_nl) stack_.push_back(st.next);
                    break;
                case NfaState::line_end:
                    if (next_nl) stack_.push_back(st.next);
                    else out.push_back(s);
                    break;
                case NfaState::range:
                case NfaState::match:
                    out.push_back(s);
                    break;
            }
        }
        std::sort(out.begin(), out.end());
        return out;
    }

    std::vector<unsigned> match_ids(const std::vector<uint32_t>& set) const {
        std::vector<unsigned> ids;
        for (uint32_t s : set)
            if (nfa_[s].kind == NfaState::match) ids.push_back(nfa_[s].pattern);
        std::sort(ids.begin(), ids.end());
        ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
        return ids;
    }

    uint32_t intern(std::vector<uint32_t> set, bool flag) {
        std::vector<uint32_t> key = set;
        key.push_back(flag ? 1u : 0u);
        const auto found = index_.find(key);
        if (found != index_.end()) return found->second;
        if (sets_.size() >= limits_.max_dfa_states)
            throw Declined{"DFA above " + std::to_string(limits_.max_dfa_states) + " states"};
        build_bytes_ += 2 * key.size() * sizeof(uint32_t) + 96;
        if (build_bytes_ > limits_.max_build_bytes) throw Declined{"DFA build above its memory limit"};
        const auto id = static_cast<uint32_t>(sets_.size());
        index_.emplace(std::move(key), id);
        sets_.push_back(std::move(set));
        flags_.push_back(flag);
        return id;
    }

    // Lays the table out for scanning: rows padded to a power of two, ids premultiplied to row offsets, and the
    // states that report or accelerate numbered last so one compare finds them.
    void finish(Dfa& dfa) {
        const size_t count = sets_.size();
        dfa.shift = static_cast<unsigned>(std::bit_width(classes_ - 1));
        const size_t stride = size_t{1} << dfa.shift;
        if (count * stride * sizeof(uint32_t) > limits_.max_table_bytes) throw Declined{"DFA table above its memory limit"};
        std::vector<Dfa::Special> info(count);
        std::vector<bool> special(count, false);
        for (size_t i = 0; i < count; ++i) {
            Dfa::Special& sp = info[i];
            sp.matches = std::move(matches_[i]);
            sp.matches_nl = std::move(matches_nl_[i]);
            // Escapes: bytes that leave the state, and '\n' when a $ match waits for it.
            bool leaves[256] = {};
            unsigned escapes = 0;
            for (unsigned b = 0; b < 256; ++b) {
                const bool out = raw_[i * classes_ + dfa.byte_class[b]] != i || (b == '\n' && !sp.matches_nl.empty());
                if (out) { leaves[b] = true; ++escapes; }
            }
            if (sp.matches.empty() && escapes <= 3) {
                sp.accelerate = true;
                for (unsigned b = 0; b < 256; ++b)
                    if (leaves[b]) sp.escape[sp.escapes++] = static_cast<uint8_t>(b);
                for (unsigned e = sp.escapes; e < 3; ++e) sp.escape[e] = sp.escapes ? sp.escape[0] : 0;
            }
            special[i] = sp.accelerate || !sp.matches.empty() || !sp.matches_nl.empty();
        }
        std::vector<uint32_t> order(count);
        uint32_t next = 0;
        for (size_t i = 0; i < count; ++i) if (!special[i]) order[i] = next++;
        const uint32_t first_special = next;
        for (size_t i = 0; i < count; ++i) if (special[i]) order[i] = next++;
        dfa.table.assign(count * stride, 0);
        for (size_t i = 0; i < count; ++i)
            for (unsigned k = 0; k < classes_; ++k)
                dfa.table[(size_t{order[i]} << dfa.shift) + k] = order[raw_[i * classes_ + k]] << dfa.shift;
        dfa.special.assign(count - first_special, {});
        for (size_t i = 0; i < count; ++i)
            if (special[i]) dfa.special[order[i] - first_special] = std::move(info[i]);
        dfa.start = order[0] << dfa.shift;
        dfa.special_min = first_special << dfa.shift;
        dfa.states = count;
    }

    const std::vector<NfaState>& nfa_;
    uint32_t start_;
    const DfaLimits& limits_;
    bool uses_line_start_ = false;
    std::chrono::steady_clock::time_point deadline_;
    std::vector<uint32_t> mark_, stack_;
    uint32_t generation_ = 0;
    unsigned classes_ = 0;
    std::vector<uint8_t> representative_;  // first byte of each class
    std::map<std::vector<uint32_t>, uint32_t> index_;
    std::vector<std::vector<uint32_t>> sets_;
    std::vector<bool> flags_;
    std::vector<std::vector<unsigned>> matches_, matches_nl_;
    std::vector<uint32_t> raw_;  // transitions by state index * classes_ + class
    size_t build_bytes_ = 0;
};

// First position at or after p holding one of the state's escape bytes, or n.
size_t find_escape(const uint8_t* t, size_t p, size_t n, const Dfa::Special& s) {
    if (s.escapes == 0) return n;
    const __m128i a = _mm_set1_epi8(static_cast<char>(s.escape[0]));
    const __m128i b = _mm_set1_epi8(static_cast<char>(s.escape[1]));
    const __m128i c = _mm_set1_epi8(static_cast<char>(s.escape[2]));
    for (; p + 16 <= n; p += 16) {
        const __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(t + p));
        const __m128i hit = _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(v, a), _mm_cmpeq_epi8(v, b)), _mm_cmpeq_epi8(v, c));
        const auto mask = static_cast<unsigned>(_mm_movemask_epi8(hit));
        if (mask) return p + static_cast<size_t>(std::countr_zero(mask));
    }
    for (; p < n; ++p)
        if (t[p] == s.escape[0] || t[p] == s.escape[1] || t[p] == s.escape[2]) return p;
    return n;
}

} // namespace

std::unique_ptr<Dfa> Dfa::build(const std::vector<std::string>& patterns, bool caseless, const DfaLimits& limits,
                                std::string& why) {
    try {
        NfaBuilder nfa(limits.max_nfa_states);
        NfaState start;
        start.kind = NfaState::split;
        for (size_t i = 0; i < patterns.size(); ++i) {
            Node ast;
            try {
                ast = Parser(patterns[i], caseless).parse();
            } catch (const Declined& d) {
                throw Declined{"pattern " + std::to_string(i) + ": " + d.why};
            }
            NfaState match;
            match.kind = NfaState::match;
            match.pattern = static_cast<unsigned>(i);
            start.targets.push_back(nfa.compile(ast, nfa.add(std::move(match))));
        }
        const uint32_t entry = nfa.add(std::move(start));
        auto dfa = std::make_unique<Dfa>();
        Determinizer(nfa.states, entry, limits).run(*dfa);
        return dfa;
    } catch (const Declined& d) {
        why = d.why;
        return nullptr;
    } catch (const std::bad_alloc&) {
        why = "DFA build ran out of memory";
        return nullptr;
    }
}

ScanStatus Dfa::scan(std::string_view text, EngineScratch*, MatchHandler on_match, void* context) const {
    const auto* t = reinterpret_cast<const uint8_t*>(text.data());
    const size_t n = text.size();
    const uint32_t* next = table.data();
    uint32_t s = start;
    size_t p = 0;
    for (;;) {
        // Hot loop: states that neither report nor accelerate.
        while (p < n && s < special_min) s = next[s + byte_class[t[p++]]];
        if (p == n) break;
        const Special& sp = special[(s - special_min) >> shift];
        if (sp.accelerate) {
            p = find_escape(t, p, n, sp);
            if (p == n) break;
        }
        for (unsigned id : t[p] == '\n' ? sp.matches_nl : sp.matches)
            if (on_match(id, 0, p, 0, context)) return ScanStatus::stopped;
        s = next[s + byte_class[t[p]]];
        ++p;
    }
    // The end of the text satisfies $.
    if (s >= special_min)
        for (unsigned id : special[(s - special_min) >> shift].matches_nl)
            if (on_match(id, 0, n, 0, context)) return ScanStatus::stopped;
    return ScanStatus::complete;
}

} // namespace shgrep
