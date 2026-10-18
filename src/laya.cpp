#include "laya.hpp"
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <algorithm>
#include <cmath>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace shgrep {
namespace {
using Clock = std::chrono::steady_clock;
constexpr size_t max_response = 2 * 1024 * 1024;
// CONTRACT: laya-code is served at 128 state tokens; code runs about 3 bytes per token on the Laya tokenizer
//   (measured on llama-server: 1000 bytes of Python = 333 tokens), so 400 bytes of code fit that window.
constexpr size_t state_code_bytes = 400;
constexpr size_t max_query_terms = 64;
constexpr unsigned max_parallel = 16;
// Laya question used by laya-codex's laya-code re-ranker, so a converted laya-code GGUF needs no change here.
constexpr const char* question_prefix = "Is this source code relevant to the software change: \"";
std::timed_mutex inference_gate;

// The time budget ended before this decision finished; the candidate stays unscored.
struct BudgetExpired {};

std::runtime_error failure(const std::string& message) {
    return std::runtime_error("LAYA_REQUIRED: " + message);
}
std::string ascii(const wchar_t* text) {
    std::string out;
    for (; *text; ++text) out.push_back(static_cast<char>(*text));
    return out;
}
std::wstring setting(const wchar_t* name) {
    const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (!size) return {};
    if (size > 4096) throw failure("environment setting is too long");
    std::wstring value(size, L'\0');
    const DWORD used = GetEnvironmentVariableW(name, value.data(), size);
    if (!used || used >= size) throw failure("environment setting changed; retry");
    value.resize(used);
    return value;
}
uint32_t setting_number(const wchar_t* name, uint32_t fallback, uint32_t low, uint32_t high) {
    const auto value = setting(name);
    if (value.empty()) return fallback;
    const auto range = [&] {
        return failure(ascii(name) + " must be " + std::to_string(low) + "-" + std::to_string(high));
    };
    uint64_t result = 0;
    for (wchar_t c : value) {
        if (c < L'0' || c > L'9') throw range();
        result = result * 10 + static_cast<unsigned>(c - L'0');
        if (result > high) throw range();
    }
    if (result < low) throw range();
    return static_cast<uint32_t>(result);
}
struct HttpHandle {
    HINTERNET value = nullptr;
    explicit HttpHandle(HINTERNET h) : value(h) {}
    ~HttpHandle() { if (value) WinHttpCloseHandle(value); }
    HttpHandle(const HttpHandle&) = delete;
    HttpHandle& operator=(const HttpHandle&) = delete;
};
struct AsyncRequest {
    HINTERNET handle = nullptr;
    std::mutex mutex;
    std::condition_variable wake;
    DWORD completed = 0, error = 0, transferred = 0;
    bool closing = false;
    static void CALLBACK callback(HINTERNET, DWORD_PTR context, DWORD status, void* info, DWORD length) noexcept {
        auto* self = reinterpret_cast<AsyncRequest*>(context);
        if (!self) return;
        std::lock_guard lock(self->mutex);
        if (status == WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) self->closing = true;
        else if (status == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR)
            self->error = static_cast<WINHTTP_ASYNC_RESULT*>(info)->dwError;
        else if (status == WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE ||
                 status == WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE ||
                 status == WINHTTP_CALLBACK_STATUS_READ_COMPLETE) {
            self->completed = status;
            self->transferred = length;
        }
        self->wake.notify_all();
    }
    explicit AsyncRequest(HINTERNET h) : handle(h) {
        if (!handle) throw failure("cannot create local HTTP request");
        DWORD_PTR context = reinterpret_cast<DWORD_PTR>(this);
        if (!WinHttpSetOption(handle, WINHTTP_OPTION_CONTEXT_VALUE, &context, sizeof(context))) {
            WinHttpCloseHandle(handle);
            throw failure("cannot bind local HTTP context");
        }
        const DWORD flags = WINHTTP_CALLBACK_FLAG_SENDREQUEST_COMPLETE | WINHTTP_CALLBACK_FLAG_HEADERS_AVAILABLE |
                            WINHTTP_CALLBACK_FLAG_READ_COMPLETE | WINHTTP_CALLBACK_FLAG_REQUEST_ERROR |
                            WINHTTP_CALLBACK_FLAG_HANDLES;
        if (WinHttpSetStatusCallback(handle, callback, flags, 0) == WINHTTP_INVALID_STATUS_CALLBACK) {
            WinHttpCloseHandle(handle);
            throw failure("cannot register local HTTP callback");
        }
    }
    ~AsyncRequest() {
        // SAFETY: callers close only after the asynchronous API returned. Context and buffers survive until the
        // final HANDLE_CLOSING callback; removing the callback alone would not synchronize outstanding callbacks.
        WinHttpCloseHandle(handle);
        std::unique_lock lock(mutex);
        wake.wait(lock, [&] { return closing; });
    }
    AsyncRequest(const AsyncRequest&) = delete;
    AsyncRequest& operator=(const AsyncRequest&) = delete;
    void reset() {
        std::lock_guard lock(mutex);
        completed = error = transferred = 0;
    }
    template<class Check>
    DWORD wait(DWORD expected, Check&& check) {
        std::unique_lock lock(mutex);
        for (;;) {
            check();
            if (error)
                throw failure("llama-server unreachable or HTTP I/O failed (WinHTTP error " + std::to_string(error) +
                              "); start llama-server with the Laya GGUF on 127.0.0.1:SHGREP_LAYA_PORT (default 8080)");
            if (completed == expected) return transferred;
            wake.wait_for(lock, std::chrono::milliseconds(20));
        }
    }
};
bool continuation(char c) { return (static_cast<unsigned char>(c) & 0xc0) == 0x80; }

// Bytes of code that go into the state: whole lines when a line break falls in the second half of the window.
size_t code_cut(std::string_view code) {
    if (code.size() <= state_code_bytes) return code.size();
    const size_t newline = code.rfind('\n', state_code_bytes);
    if (newline != std::string_view::npos && newline >= state_code_bytes / 2) return newline;
    size_t cut = state_code_bytes;
    while (cut > 0 && continuation(code[cut])) --cut;
    return cut;
}

// Lowercase terms; identifiers split at snake_case and camelCase boundaries ("HTTPServer" -> http, server).
template<class Emit>
void for_each_term(std::string_view text, Emit&& emit) {
    std::string word;
    const auto is_lower = [](unsigned char c) { return c >= 'a' && c <= 'z'; };
    const auto is_upper = [](unsigned char c) { return c >= 'A' && c <= 'Z'; };
    const auto is_digit = [](unsigned char c) { return c >= '0' && c <= '9'; };
    const auto flush_word = [&] {
        if (word.empty()) return;
        std::vector<std::string> parts;
        std::string part;
        for (size_t i = 0; i < word.size(); ++i) {
            const auto c = static_cast<unsigned char>(word[i]);
            if (c == '_') {
                if (!part.empty()) parts.push_back(std::move(part));
                part.clear();
                continue;
            }
            if (!part.empty()) {
                const auto previous = static_cast<unsigned char>(word[i - 1]);
                const bool next_lower = i + 1 < word.size() && is_lower(static_cast<unsigned char>(word[i + 1]));
                const bool boundary = (is_upper(c) && (is_lower(previous) || is_digit(previous) ||
                                      (is_upper(previous) && next_lower))) ||
                                      (is_digit(c) != is_digit(previous));
                if (boundary) {
                    parts.push_back(std::move(part));
                    part.clear();
                }
            }
            part.push_back(is_upper(c) ? static_cast<char>(c - 'A' + 'a') : static_cast<char>(c));
        }
        if (!part.empty()) parts.push_back(std::move(part));
        const bool compound = parts.size() > 1;
        for (const auto& token : parts) if (token.size() >= 2) emit(token);
        if (compound) {
            std::string joined;
            joined.reserve(word.size());
            for (unsigned char c : word)
                joined.push_back(is_upper(c) ? static_cast<char>(c - 'A' + 'a') : static_cast<char>(c));
            emit(joined);
        }
        word.clear();
    };
    for (unsigned char c : text) {
        if (is_lower(c) || is_upper(c) || is_digit(c) || c == '_') word.push_back(static_cast<char>(c));
        else flush_word();
    }
    flush_word();
}

// Instruction words that would otherwise outrank the task's own words, because BM25 favours rare terms.
bool stop_word(const std::string& term) {
    static const std::unordered_set<std::string> words{
        "a", "about", "all", "an", "and", "any", "are", "as", "at", "be", "by", "can", "code", "could", "do", "does",
        "each", "explain", "file", "files", "find", "for", "from", "get", "has", "have", "how", "if", "in", "into",
        "is", "it", "its", "locate", "look", "me", "my", "need", "not", "of", "on", "or", "our", "please", "see",
        "should", "show", "so", "some", "that", "the", "their", "them", "then", "there", "these", "this", "those",
        "to", "use", "used", "uses", "using", "want", "was", "we", "what", "when", "where", "which", "while", "who",
        "why", "will", "with", "would", "you", "your"};
    return words.contains(term);
}

// Request-local BM25 (k1 1.2, b 0.75) of the intent over path + code; ties keep scan order.
std::vector<size_t> lexical_order(const std::string& intent, const std::vector<LayaCandidate>& candidates) {
    std::vector<size_t> order(candidates.size());
    std::iota(order.begin(), order.end(), size_t{0});
    std::unordered_map<std::string, uint32_t> query;
    for_each_term(intent, [&](const std::string& term) {
        if (query.size() < max_query_terms && !stop_word(term)) query.emplace(term, static_cast<uint32_t>(query.size()));
    });
    if (query.empty() || candidates.empty()) return order;
    // PERF: term frequencies are kept sparse (query terms only), so memory is bounded by matches, not candidates x terms.
    std::vector<std::vector<std::pair<uint32_t, uint32_t>>> frequencies(candidates.size());
    std::vector<uint32_t> lengths(candidates.size(), 0), document_frequency(query.size(), 0);
    uint64_t total_length = 0;
    for (size_t i = 0; i < candidates.size(); ++i) {
        auto& counts = frequencies[i];
        const auto count = [&](const std::string& term) {
            ++lengths[i];
            const auto it = query.find(term);
            if (it == query.end()) return;
            for (auto& [slot, tf] : counts) if (slot == it->second) { ++tf; return; }
            counts.emplace_back(it->second, 1u);
        };
        for_each_term(candidates[i].path, count);
        for_each_term(candidates[i].code, count);
        total_length += lengths[i];
        for (const auto& [slot, tf] : counts) ++document_frequency[slot];
    }
    const double n = static_cast<double>(candidates.size());
    const double average = std::max(1.0, static_cast<double>(total_length) / n);
    std::vector<double> scores(candidates.size(), 0.0);
    for (size_t i = 0; i < candidates.size(); ++i) {
        for (const auto& [slot, tf] : frequencies[i]) {
            const double df = document_frequency[slot];
            const double idf = std::log(1.0 + (n - df + 0.5) / (df + 0.5));
            const double f = tf;
            scores[i] += idf * f * 2.2 / (f + 1.2 * (0.25 + 0.75 * lengths[i] / average));
        }
    }
    std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) { return scores[a] > scores[b]; });
    return order;
}

double milliseconds(Clock::duration d) { return std::chrono::duration<double, std::milli>(d).count(); }
}

struct LayaFingerprint::Impl {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    ~Impl() {
        if (hash) BCryptDestroyHash(hash);
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    }
};
LayaFingerprint::LayaFingerprint() : impl_(std::make_unique<Impl>()) {
    if (BCryptOpenAlgorithmProvider(&impl_->algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptCreateHash(impl_->algorithm, &impl_->hash, nullptr, 0, nullptr, 0, 0) < 0)
        throw failure("cannot create evidence digest");
}
LayaFingerprint::~LayaFingerprint() = default;
void LayaFingerprint::add(std::string_view text) {
    if (!impl_->hash) throw failure("evidence digest already finished");
    while (!text.empty()) {
        const ULONG size = static_cast<ULONG>(std::min<size_t>(text.size(), 1u << 20));
        if (BCryptHashData(impl_->hash, reinterpret_cast<PUCHAR>(const_cast<char*>(text.data())), size, 0) < 0)
            throw failure("cannot hash evidence");
        text.remove_prefix(size);
    }
}
std::string LayaFingerprint::finish() {
    unsigned char digest[32];
    if (!impl_->hash || BCryptFinishHash(impl_->hash, digest, sizeof(digest), 0) < 0)
        throw failure("cannot finish evidence digest");
    BCryptDestroyHash(impl_->hash);
    impl_->hash = nullptr;
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(64);
    for (unsigned char byte : digest) { output += digits[byte >> 4]; output += digits[byte & 15]; }
    return output;
}

struct LayaSelector::Impl {
    std::string intent, model;
    Json question;
    std::shared_ptr<std::atomic_bool> cancelled;
    Clock::time_point deadline;
    std::unique_lock<std::timed_mutex> gate{inference_gate, std::defer_lock};
    HttpHandle session{WinHttpOpen(L"shgrep-laya/2", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC)};
    HttpHandle connection{nullptr};
    std::wstring authorization;
    uint32_t port = 8080, budget_ms = 2000, pool_limit = 24, score_limit = 12, return_limit = 10, filter_percent = 0, weight_percent = 100;
    unsigned parallel = 1;
    // Report of the last rank() call.
    uint64_t candidates = 0, pool = 0, to_score = 0, scored = 0, returned = 0;
    double laya_ms = 0;

    void check() const {
        if (cancelled && cancelled->load()) throw failure("cancelled");
        if (Clock::now() >= deadline) throw failure("timeout; selection is incomplete");
    }
    // The request deadline and cancellation are errors; `until` alone ending is the time budget.
    void check(Clock::time_point until) const {
        check();
        if (Clock::now() >= until) throw BudgetExpired{};
    }
    int remaining(Clock::time_point until) const {
        check(until);
        return static_cast<int>(std::clamp<int64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::min(until, deadline) - Clock::now()).count(),
            1, std::numeric_limits<int>::max()));
    }
    Json request(const wchar_t* method, const wchar_t* path, const Json* body, Clock::time_point until) const {
        check(until);
        // Buffers are declared before request, so they outlive cancellation and HANDLE_CLOSING.
        const std::string payload = body ? body->dump() : std::string();
        std::string response;
        char buffer[16384];
        const std::wstring headers = std::wstring(body ? L"Content-Type: application/json\r\n" : L"") +
                                     L"Accept: application/json\r\nConnection: close\r\n" + authorization;
        if (payload.size() > std::numeric_limits<DWORD>::max()) throw failure("llama-server request is too large");
        AsyncRequest call(WinHttpOpenRequest(connection.value, method, path, nullptr,
                                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0));
        DWORD redirects = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        DWORD disabled = WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
        if (!WinHttpSetOption(call.handle, WINHTTP_OPTION_REDIRECT_POLICY, &redirects, sizeof(redirects)) ||
            !WinHttpSetOption(call.handle, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled)))
            throw failure("cannot configure local HTTP request");
        const int timeout = remaining(until);
        if (!WinHttpSetTimeouts(call.handle, timeout, std::min(timeout, 2000), timeout, timeout))
            throw failure("cannot configure local HTTP timeout");
        const auto start = [&](BOOL started) {
            if (!started && GetLastError() != ERROR_IO_PENDING) {
                check(until);
                throw failure("llama-server unreachable or HTTP I/O failed; start llama-server with the Laya GGUF");
            }
        };
        const auto check_call = [&] { check(until); };
        call.reset();
        start(WinHttpSendRequest(call.handle, headers.c_str(), static_cast<DWORD>(headers.size()),
                                 payload.empty() ? nullptr : static_cast<LPVOID>(const_cast<char*>(payload.data())),
                                 static_cast<DWORD>(payload.size()), static_cast<DWORD>(payload.size()),
                                 reinterpret_cast<DWORD_PTR>(&call)));
        call.wait(WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE, check_call);
        call.reset();
        start(WinHttpReceiveResponse(call.handle, nullptr));
        call.wait(WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE, check_call);
        DWORD status = 0, status_size = sizeof(status);
        if (!WinHttpQueryHeaders(call.handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                 WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX))
            throw failure("cannot read llama-server HTTP status");
        for (;;) {
            check(until);
            call.reset();
            start(WinHttpReadData(call.handle, buffer, sizeof(buffer), nullptr));
            const DWORD got = call.wait(WINHTTP_CALLBACK_STATUS_READ_COMPLETE, check_call);
            if (!got) break;
            if (response.size() + got > max_response) throw failure("llama-server response exceeds 2 MiB");
            response.append(buffer, got);
        }
        check(until);
        const std::string where = "llama-server " + ascii(path);
        Json result;
        try { result = Json::parse(response); }
        catch (const std::exception&) {
            throw failure(where + (status == 200 ? " returned invalid JSON" : " returned HTTP " + std::to_string(status)));
        }
        if (status != 200) {
            // llama-server errors are {"error":{"code":..,"message":".."}}.
            std::string message;
            if (const Json* error = result.get("error")) {
                if (std::holds_alternative<std::string>(error->value)) message = error->string();
                else if (const Json* text = std::holds_alternative<Json::Object>(error->value) ? error->get("message") : nullptr;
                         text && std::holds_alternative<std::string>(text->value))
                    message = text->string();
            }
            if (message.size() > 300) message.resize(300);
            throw failure(where + " returned HTTP " + std::to_string(status) + (message.empty() ? "" : ": " + message));
        }
        if (!std::holds_alternative<Json::Object>(result.value)) throw failure(where + " returned a non-object");
        return result;
    }
    double decide(const LayaCandidate& candidate, Clock::time_point until) const {
        std::string state = "file: ";
        state.append(candidate.path);
        if (candidate.first_line)
            state += " (lines " + std::to_string(candidate.first_line) + "-" +
                     std::to_string(std::max(candidate.first_line, candidate.last_line)) + ")";
        state += '\n';
        state.append(candidate.code.substr(0, code_cut(candidate.code)));
        const Json body = Json::Object{{"state", std::move(state)}, {"questions", question}};
        const Json response = request(L"POST", L"/v1/systemone", &body, until);
        const Json* answers = response.get("answers");
        const Json* answer = answers && std::holds_alternative<Json::Object>(answers->value) ? answers->get("relevant") : nullptr;
        const Json* value = answer && std::holds_alternative<Json::Object>(answer->value) ? answer->get("noul") : nullptr;
        double p = -1;
        if (value) {
            if (const auto* number = std::get_if<double>(&value->value)) p = *number;
            else if (const auto* integer = std::get_if<int64_t>(&value->value)) p = static_cast<double>(*integer);
        }
        if (!std::isfinite(p) || p < 0 || p > 1) throw failure("llama-server returned no valid Laya noul probability");
        return p;
    }
    Impl(std::string task, std::shared_ptr<std::atomic_bool> flag, Clock::time_point until)
        : intent(std::move(task)), cancelled(std::move(flag)), deadline(until) {
        if (intent.empty() || intent.size() > 4096 || intent.find_first_not_of(" \t\r\n") == std::string::npos)
            throw failure("search operation=text requires a nonempty intent (at most 4096 UTF-8 bytes)");
        question = Json::Object{{"relevant", Json::Object{{"type", "noul"},
                                                          {"instructions", question_prefix + intent + "\"?"}}}};
        port = setting_number(L"SHGREP_LAYA_PORT", 8080, 1, 65535);
        budget_ms = setting_number(L"SHGREP_LAYA_BUDGET_MS", 2000, 0, 300000);
        // 0 means no limit for the pool, the scored share of it, and the returned share of it.
        pool_limit = setting_number(L"SHGREP_LAYA_POOL", 24, 0, 100000);
        score_limit = setting_number(L"SHGREP_LAYA_SCORE", 16, 0, 100000);
        return_limit = setting_number(L"SHGREP_LAYA_RETURN", 10, 0, 100000);
        // Percent of P a scored candidate needs to be kept; 0 keeps every candidate in ranked order.
        filter_percent = setting_number(L"SHGREP_LAYA_FILTER", 0, 0, 100);
        // Weight of Laya's rank against the keyword rank in the fusion; 100 is equal, 0 keeps keyword order.
        weight_percent = setting_number(L"SHGREP_LAYA_WEIGHT", 100, 0, 1000);
        while (!gate.try_lock_for(std::chrono::milliseconds(20))) check();
        check();
        if (!session.value) throw failure("cannot initialize WinHTTP");
        DWORD connections = max_parallel;
        WinHttpSetOption(session.value, WINHTTP_OPTION_MAX_CONNS_PER_SERVER, &connections, sizeof(connections));
        connection.value = WinHttpConnect(session.value, L"127.0.0.1", static_cast<INTERNET_PORT>(port), 0);
        if (!connection.value) throw failure("cannot connect to llama-server");
        const auto token = setting(L"SHGREP_LAYA_TOKEN");
        if (token.find_first_of(L"\r\n") != std::wstring::npos) throw failure("invalid SHGREP_LAYA_TOKEN");
        if (!token.empty()) authorization = L"Authorization: Bearer " + token + L"\r\n";
        const Json props = request(L"GET", L"/props", nullptr, deadline);
        if (const Json* slots = props.get("total_slots"); slots && std::holds_alternative<int64_t>(slots->value))
            parallel = static_cast<unsigned>(std::clamp<int64_t>(slots->integer(), 1, max_parallel));
        for (const char* key : {"model_alias", "model_path"})
            if (const Json* name = props.get(key); name && std::holds_alternative<std::string>(name->value) && model.empty())
                model = name->string();
    }
};

LayaSelector::LayaSelector(std::string intent, std::shared_ptr<std::atomic_bool> cancelled,
                           Clock::time_point deadline)
    : impl_(std::make_unique<Impl>(std::move(intent), std::move(cancelled), deadline)) {}
LayaSelector::~LayaSelector() = default;

std::vector<LayaRanked> LayaSelector::rank(const std::vector<LayaCandidate>& candidates) {
    auto& s = *impl_;
    s.check();
    const auto order = lexical_order(s.intent, candidates);
    std::vector<size_t> pool_order;
    pool_order.reserve(order.size());
    std::unordered_map<std::string_view, size_t> per_file;
    for (size_t index : order) {
        size_t& count = per_file[candidates[index].path];
        // CONTRACT: SHGREP_LAYA_POOL=0 keeps every candidate, so there is no per-file cap either.
        if (s.pool_limit && count >= 3) continue;
        ++count;
        pool_order.push_back(index);
        if (s.pool_limit && pool_order.size() == s.pool_limit) break;
    }
    const size_t pool = pool_order.size();
    const size_t to_score = s.score_limit ? std::min<size_t>(pool, s.score_limit) : pool;
    const auto started = Clock::now();
    // CONTRACT: Laya gets at most half of the request's remaining time, so the freshness scan after it still runs.
    const auto budget_end = std::min(started + std::chrono::milliseconds(s.budget_ms),
                                     started + (s.deadline - started) / 2);
    std::vector<std::optional<double>> probability(to_score);
    std::mutex mutex;
    std::exception_ptr error;
    size_t next = 0, done = 0;
    double busy_ms = 0;
    const auto work = [&] {
        for (;;) {
            size_t k = 0;
            {
                std::lock_guard lock(mutex);
                if (error || next >= to_score) return;
                const auto now = Clock::now();
                // PERF: start a decision only if the mean decision so far would still end inside the budget.
                if (now >= budget_end || (done && now + std::chrono::duration_cast<Clock::duration>(
                                                         std::chrono::duration<double, std::milli>(busy_ms / done)) > budget_end))
                    return;
                k = next++;
            }
            const auto begun = Clock::now();
            try {
                const double p = s.decide(candidates[pool_order[k]], budget_end);
                std::lock_guard lock(mutex);
                probability[k] = p;
                busy_ms += milliseconds(Clock::now() - begun);
                ++done;
            } catch (const BudgetExpired&) {
                return;
            } catch (...) {
                std::lock_guard lock(mutex);
                if (!error) error = std::current_exception();
                return;
            }
        }
    };
    {
        std::vector<std::thread> helpers;
        struct Join {
            std::vector<std::thread>& threads;
            ~Join() { for (auto& t : threads) if (t.joinable()) t.join(); }
        } join{helpers};
        const size_t threads = std::min<size_t>(s.parallel, to_score);
        for (size_t i = 1; i < threads; ++i) helpers.emplace_back(work);
        work();
    }
    if (error) std::rethrow_exception(error);
    s.check();

    std::vector<LayaRanked> ranked(pool);
    std::vector<size_t> reached;
    reached.reserve(to_score);
    for (size_t k = 0; k < pool; ++k) {
        auto& item = ranked[k];
        item.index = pool_order[k];
        item.lexical_rank = k;
        item.scored = k < probability.size() && probability[k].has_value();
        item.probability = item.scored ? *probability[k] : 0.0;
        if (item.scored) reached.push_back(k);
    }

    std::vector<size_t> laya_order = reached;
    std::stable_sort(laya_order.begin(), laya_order.end(), [&](size_t a, size_t b) {
        return ranked[a].probability > ranked[b].probability;
    });
    std::vector<size_t> laya_rank(pool, 0);
    for (size_t rank = 0; rank < laya_order.size(); ++rank) laya_rank[laya_order[rank]] = rank;
    constexpr double rrf_k = 60.0;
    for (size_t lexical_rank = 0; lexical_rank < reached.size(); ++lexical_rank) {
        auto& item = ranked[reached[lexical_rank]];
        item.lexical_rank = lexical_rank;
        item.score = 1.0 / (rrf_k + lexical_rank) +
                     (s.weight_percent / 100.0) / (rrf_k + laya_rank[reached[lexical_rank]]);
    }

    std::vector<LayaRanked> ordered;
    ordered.reserve(pool);
    for (size_t index : reached) ordered.push_back(std::move(ranked[index]));
    std::stable_sort(ordered.begin(), ordered.end(),
                     [](const LayaRanked& a, const LayaRanked& b) { return a.score > b.score; });
    for (size_t k = 0; k < pool; ++k) {
        if (!ranked[k].scored) {
            ranked[k].score = 0.0;
            ordered.push_back(std::move(ranked[k]));
        }
    }
    const double p_threshold = s.filter_percent / 100.0;
    constexpr size_t min_keep = 3;
    // CONTRACT: SHGREP_LAYA_RETURN=0 returns the whole pool in ranked order, without the P filter;
    //   SHGREP_LAYA_FILTER=0 drops only the P filter and keeps the return limit.
    if (s.return_limit && s.filter_percent) {
        const size_t passing = static_cast<size_t>(std::count_if(ordered.begin(), ordered.end(), [=](const LayaRanked& item) {
            return item.scored && item.probability >= p_threshold;
        }));
        if (passing < min_keep) {
            ordered.resize(std::min(min_keep, ordered.size()));
        } else {
            ordered.erase(std::remove_if(ordered.begin(), ordered.end(), [=](const LayaRanked& item) {
                return !item.scored || item.probability < p_threshold;
            }), ordered.end());
        }
    }
    if (s.return_limit && ordered.size() > s.return_limit) ordered.resize(s.return_limit);
    const size_t scored = reached.size();
    ranked = std::move(ordered);
    s.candidates = candidates.size();
    s.pool = pool;
    s.to_score = to_score;
    s.scored = scored;
    s.returned = ranked.size();
    s.laya_ms = milliseconds(Clock::now() - started);
    return ranked;
}

Json LayaSelector::report() const {
    const auto& s = *impl_;
    const char* mode = s.scored == s.to_score ? "laya" : s.scored ? "laya-partial" : "lexical";
    return Json::Object{{"required", true}, {"model", s.model}, {"mode", mode},
        {"candidates", s.candidates}, {"pool", s.pool}, {"scored", s.scored}, {"unscored", s.to_score - s.scored},
        {"returned", s.returned}, {"budget_ms", static_cast<int64_t>(s.budget_ms)},
        {"laya_ms", static_cast<int64_t>(std::llround(s.laya_ms))}, {"parallel", static_cast<int64_t>(s.parallel)},
        {"per_file_cap", s.pool_limit ? 3 : 0}, {"p_threshold", s.return_limit ? s.filter_percent / 100.0 : 0.0},
        {"min_keep", s.return_limit && s.filter_percent ? 3 : 0}, {"laya_weight", s.weight_percent / 100.0},
        {"question", "noul"}, {"state_code_bytes", static_cast<int64_t>(state_code_bytes)},
        {"fusion", "rrf(k=60, lexical_rank, weight*laya_rank)"}, {"scores_calibrated_for_code", false}};
}
}
