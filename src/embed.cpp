#include "embed.hpp"

#include <algorithm>
#include <cmath>
#include <condition_variable>
#include <cstdlib>
#include <string>
#include <deque>
#include <filesystem>
#include <initializer_list>
#include <mutex>
#include <thread>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#if SHGREP_EMBED
#include "llama.h"
#endif

namespace shgrep {
#if !SHGREP_EMBED
bool embed_built() { return false; }
void start_embedder() {}
std::string embedder_state() { return "off (portable build: no embedding model)"; }
size_t embed_dimensions() { return 0; }
std::string embed_model_identity() { return {}; }
std::vector<float> embed_query(std::string_view, EmbedClock::time_point, const std::shared_ptr<std::atomic_bool>&) {
    throw EmbedFailure("this shgrep build has no meaning search (portable build); use the GPU build for it");
}
std::vector<std::vector<float>> embed_documents(const std::vector<EmbedDocument>&, EmbedClock::time_point,
                                                const std::shared_ptr<std::atomic_bool>&) {
    throw EmbedFailure("this shgrep build has no meaning search (portable build); use the GPU build for it");
}
#else
namespace {
namespace fs = std::filesystem;

std::string narrow(const std::wstring& text) {
    if (text.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(std::max(size, 0)), '\0');
    if (size > 0)
        WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size, nullptr, nullptr);
    return out;
}

std::wstring widen(const std::string& text) {
    if (text.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(std::max(size, 0)), L'\0');
    if (size > 0) MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size);
    return out;
}

std::string win32_message(DWORD code) {
    wchar_t* buffer = nullptr;
    const DWORD size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                      nullptr, code, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    std::wstring text = size && buffer ? std::wstring(buffer, size) : std::wstring();
    if (buffer) LocalFree(buffer);
    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ' || text.back() == L'.'))
        text.pop_back();
    return "Win32 error " + std::to_string(code) + (text.empty() ? "" : ": " + narrow(text));
}

fs::path exe_folder() {
    std::wstring path(32768, L'\0');
    const DWORD size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!size || size >= path.size()) throw EmbedFailure("cannot find shgrep.exe's own folder (" + win32_message(GetLastError()) + ")");
    path.resize(size);
    return fs::path(path).parent_path();
}

// An environment variable as UTF-8; empty when unset.
std::string env_text(const wchar_t* name) {
    const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (!size) return {};
    std::wstring value(size, L'\0');
    const DWORD written = GetEnvironmentVariableW(name, value.data(), size);
    value.resize(written < size ? written : 0);
    return narrow(value);
}

uint32_t env_number(const wchar_t* name, uint32_t fallback, uint32_t low, uint32_t high) {
    const std::string value = env_text(name);
    if (value.empty()) return fallback;
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(value.c_str(), &end, 10);
    if (*end || parsed < low || parsed > high)
        throw EmbedFailure(narrow(name) + " must be a number from " + std::to_string(low) + " to " + std::to_string(high));
    return static_cast<uint32_t>(parsed);
}

// The GGUF: SHGREP_EMBED_MODEL, else embedding.gguf beside shgrep.exe.
fs::path model_file(const fs::path& folder) {
    const std::string configured = env_text(L"SHGREP_EMBED_MODEL");
    return configured.empty() ? folder / L"embedding.gguf" : fs::path(widen(configured));
}

// The llama.cpp C API, resolved from the DLLs at runtime so the rest of shgrep starts without them. Types come from
// the llama.h shgrep was built with; a DLL from another version that lacks a function fails the load by name.
struct Api {
    decltype(&::llama_backend_init) backend_init = nullptr;
    decltype(&::llama_log_set) log_set = nullptr;
    decltype(&::llama_model_default_params) model_default_params = nullptr;
    decltype(&::llama_context_default_params) context_default_params = nullptr;
    decltype(&::llama_model_load_from_file) model_load_from_file = nullptr;
    decltype(&::llama_init_from_model) init_from_model = nullptr;
    decltype(&::llama_model_get_vocab) model_get_vocab = nullptr;
    decltype(&::llama_model_n_embd) model_n_embd = nullptr;
    decltype(&::llama_model_n_embd_out) model_n_embd_out = nullptr;
    decltype(&::llama_model_desc) model_desc = nullptr;
    decltype(&::llama_tokenize) tokenize = nullptr;
    decltype(&::llama_batch_init) batch_init = nullptr;
    decltype(&::llama_batch_free) batch_free = nullptr;
    decltype(&::llama_decode) decode = nullptr;
    decltype(&::llama_get_embeddings_seq) get_embeddings_seq = nullptr;
    decltype(&::llama_get_memory) get_memory = nullptr;
    decltype(&::llama_memory_clear) memory_clear = nullptr;
    decltype(&::llama_pooling_type) pooling_type = nullptr;
    decltype(&::llama_max_parallel_sequences) max_parallel_sequences = nullptr;
    decltype(&::ggml_backend_load) backend_load = nullptr;
    decltype(&::ggml_backend_dev_count) dev_count = nullptr;
    decltype(&::ggml_backend_dev_get) dev_get = nullptr;
    decltype(&::ggml_backend_dev_type) dev_type = nullptr;
    decltype(&::ggml_backend_dev_name) dev_name = nullptr;
    decltype(&::ggml_backend_dev_description) dev_description = nullptr;
    decltype(&::ggml_backend_dev_memory) dev_memory = nullptr;
};

enum class State { idle, loading, ready, failed };

// One process-wide engine. Loading runs once on its own thread; embedding calls are serialized on one context.
struct Engine {
    std::mutex mutex;  // guards state, step, failure, ready_text and log_lines
    std::condition_variable changed;
    State state = State::idle;
    std::string step, failure, ready_text, identity;
    std::deque<std::string> log_lines;  // last warnings and errors from llama.cpp, for failure messages
    std::mutex run;  // one embedding run at a time on the context
    // Written only by the loader before the state becomes ready; read-only afterwards.
    Api api;
    llama_model* model = nullptr;
    llama_context* context = nullptr;
    const llama_vocab* vocab = nullptr;
    size_t dimensions = 0;
    uint32_t batch_tokens = 8192, sequences = 32, max_tokens = 1024;
    // Set once the DLLs, backends and GPU are loaded; a retry after the model file appears reuses them.
    bool runtime_loaded = false;
    ggml_backend_dev_t gpu = nullptr;
    std::string device_text;
    bool model_missing = false;  // guarded by mutex: the last failure was a missing GGUF
};
Engine& engine() {
    static Engine instance;
    return instance;
}

void on_log(ggml_log_level level, const char* text, void*) {
    if (!text || (level != GGML_LOG_LEVEL_ERROR && level != GGML_LOG_LEVEL_WARN)) return;
    std::string line(text);
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
    if (line.empty()) return;
    auto& e = engine();
    std::lock_guard lock(e.mutex);
    e.log_lines.push_back(std::move(line));
    while (e.log_lines.size() > 8) e.log_lines.pop_front();
}

// The last llama.cpp warnings and errors, for a failure message ("" when there are none).
std::string recent_log() {
    auto& e = engine();
    std::lock_guard lock(e.mutex);
    std::string out;
    for (const auto& line : e.log_lines) out += (out.empty() ? "" : " | ") + line;
    return out.empty() ? out : " [llama.cpp: " + out + "]";
}

void set_step(const std::string& step) {
    auto& e = engine();
    {
        std::lock_guard lock(e.mutex);
        e.step = step;
    }
    e.changed.notify_all();
}

template<class F>
void resolve(F& slot, const char* name, std::initializer_list<HMODULE> modules) {
    for (HMODULE module : modules)
        if (FARPROC address = module ? GetProcAddress(module, name) : nullptr) {
            slot = reinterpret_cast<F>(reinterpret_cast<void*>(address));
            return;
        }
    throw EmbedFailure(std::string("the llama.cpp DLLs beside shgrep.exe lack ") + name +
                       "; they come from another llama.cpp version than the headers shgrep was built with. "
                       "Fix: rebuild llama.cpp and shgrep from the same llama.cpp source tree");
}

HMODULE load_dll(const fs::path& folder, const wchar_t* name) {
    const fs::path path = folder / name;
    std::error_code error;
    if (!fs::exists(path, error))
        throw EmbedFailure(narrow(name) + " is missing at " + narrow(path.wstring()) +
                           ". Fix: rebuild shgrep with SHGREP_EMBED=ON so the build copies the llama.cpp DLLs beside shgrep.exe");
    const UINT old_mode = SetErrorMode(SEM_FAILCRITICALERRORS);
    // Dependencies (ggml.dll, ggml-base.dll) resolve from the DLL's own folder.
    HMODULE module = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    const DWORD code = module ? 0 : GetLastError();
    SetErrorMode(old_mode);
    if (!module)
        throw EmbedFailure("cannot load " + narrow(path.wstring()) + " (" + win32_message(code) + ")" +
                           (code == ERROR_MOD_NOT_FOUND ? ". A DLL it needs is missing beside it" : ""));
    return module;
}

// Everything that can fail before the first vector: DLLs, GPU, model file, video memory, model and context.
void load(Engine& e) {
    const fs::path folder = exe_folder();
    e.max_tokens = env_number(L"SHGREP_EMBED_MAX_TOKENS", 1024, 16, 8192);

    Api& a = e.api;
    // The DLLs, backends and GPU load once per process; a retry after a missing model skips them.
    if (!e.runtime_loaded) {
        set_step("loading llama.dll");
        HMODULE llama = load_dll(folder, L"llama.dll");
        HMODULE ggml = GetModuleHandleW(L"ggml.dll");
        HMODULE ggml_base = GetModuleHandleW(L"ggml-base.dll");
        resolve(a.backend_init, "llama_backend_init", {llama});
        resolve(a.log_set, "llama_log_set", {llama});
        resolve(a.model_default_params, "llama_model_default_params", {llama});
        resolve(a.context_default_params, "llama_context_default_params", {llama});
        resolve(a.model_load_from_file, "llama_model_load_from_file", {llama});
        resolve(a.init_from_model, "llama_init_from_model", {llama});
        resolve(a.model_get_vocab, "llama_model_get_vocab", {llama});
        resolve(a.model_n_embd, "llama_model_n_embd", {llama});
        resolve(a.model_n_embd_out, "llama_model_n_embd_out", {llama});
        resolve(a.model_desc, "llama_model_desc", {llama});
        resolve(a.tokenize, "llama_tokenize", {llama});
        resolve(a.batch_init, "llama_batch_init", {llama});
        resolve(a.batch_free, "llama_batch_free", {llama});
        resolve(a.decode, "llama_decode", {llama});
        resolve(a.get_embeddings_seq, "llama_get_embeddings_seq", {llama});
        resolve(a.get_memory, "llama_get_memory", {llama});
        resolve(a.memory_clear, "llama_memory_clear", {llama});
        resolve(a.pooling_type, "llama_pooling_type", {llama});
        resolve(a.max_parallel_sequences, "llama_max_parallel_sequences", {llama});
        resolve(a.backend_load, "ggml_backend_load", {ggml, ggml_base});
        resolve(a.dev_count, "ggml_backend_dev_count", {ggml, ggml_base});
        resolve(a.dev_get, "ggml_backend_dev_get", {ggml, ggml_base});
        resolve(a.dev_type, "ggml_backend_dev_type", {ggml_base, ggml});
        resolve(a.dev_name, "ggml_backend_dev_name", {ggml_base, ggml});
        resolve(a.dev_description, "ggml_backend_dev_description", {ggml_base, ggml});
        resolve(a.dev_memory, "ggml_backend_dev_memory", {ggml_base, ggml});
        a.log_set(on_log, nullptr);  // also sets ggml's logger, so nothing goes to stderr
        a.backend_init();

        // Backends load by exact path, not ggml_backend_load_all (silent about failures in release builds): the CPU
        // backend for the input layer, the HIP backend for everything else.
        for (const wchar_t* name : {L"ggml-cpu.dll", L"ggml-hip.dll"}) {
            set_step("loading " + narrow(name));
            const fs::path path = folder / name;
            std::error_code error;
            if (!fs::exists(path, error))
                throw EmbedFailure(narrow(name) + " is missing at " + narrow(path.wstring()) +
                                   ". Fix: build llama.cpp with GGML_BACKEND_DL=ON (and GGML_HIP=ON for ggml-hip.dll), then "
                                   "rebuild shgrep with SHGREP_EMBED=ON");
            if (!a.backend_load(narrow(path.wstring()).c_str()))
                throw EmbedFailure("cannot load the backend " + narrow(path.wstring()) + recent_log() +
                                   (std::wstring_view(name) == L"ggml-hip.dll"
                                        ? ". Fix: install the AMD HIP runtime (amdhip64_*.dll), or put its DLLs beside shgrep.exe"
                                        : ""));
        }

        set_step("finding the GPU");
        ggml_backend_dev_t gpu = nullptr;
        for (size_t i = 0; i < a.dev_count() && !gpu; ++i) {
            ggml_backend_dev_t device = a.dev_get(i);
            if (device && a.dev_type(device) == GGML_BACKEND_DEVICE_TYPE_GPU) gpu = device;
        }
        if (!gpu)
            throw EmbedFailure("HIP device not found: ggml-hip.dll loaded but reports no AMD GPU" + recent_log() +
                               ". Fix: check the AMD driver, and that HIP_VISIBLE_DEVICES does not hide the GPU");
        const std::string device_text = std::string(a.dev_name(gpu)) + " (" + a.dev_description(gpu) + ")";
        e.gpu = gpu;
        e.device_text = device_text;
        e.runtime_loaded = true;
    }
    ggml_backend_dev_t gpu = e.gpu;
    const std::string& device_text = e.device_text;

    const fs::path model_path = model_file(folder);
    std::error_code error;
    const auto model_bytes = static_cast<uint64_t>(fs::file_size(model_path, error));
    if (error) {
        {
            std::lock_guard lock(e.mutex);
            e.model_missing = true;
        }
        throw EmbedFailure("GGUF missing at " + narrow(model_path.wstring()) +
                           ". Fix: put the EmbeddingGemma 2 Q8_0 GGUF there as embedding.gguf (or rebuild with "
                           "SHGREP_EMBED_MODEL_FILE=<path> to copy it), or set SHGREP_EMBED_MODEL to its full path");
    }
    size_t free_memory = 0, total_memory = 0;
    a.dev_memory(gpu, &free_memory, &total_memory);
    // Weights plus about 30% and 256 MB for the compute buffers of an 8192-token batch.
    const uint64_t needed = model_bytes + model_bytes * 3 / 10 + (256ull << 20);
    if (free_memory && free_memory < needed)
        throw EmbedFailure("out of video memory while loading the model on " + device_text + ": needed about " +
                           std::to_string(needed >> 20) + " MB, free " + std::to_string(free_memory >> 20) + " MB of " +
                           std::to_string(total_memory >> 20) + " MB. Fix: close programs that use the GPU, then restart shgrep");

    set_step("loading " + narrow(model_path.filename().wstring()) + " on " + device_text);
    static ggml_backend_dev_t devices[2];  // must outlive the model
    devices[0] = gpu;
    devices[1] = nullptr;
    llama_model_params model_params = a.model_default_params();
    model_params.devices = devices;
    model_params.n_gpu_layers = -1;  // every layer on the GPU; no CPU fallback
    e.model = a.model_load_from_file(narrow(model_path.wstring()).c_str(), model_params);
    if (!e.model) throw EmbedFailure("model load error for " + narrow(model_path.wstring()) + recent_log());

    set_step("creating the embedding context");
    const auto parallel = static_cast<uint32_t>(std::max<size_t>(a.max_parallel_sequences(), 1));
    e.sequences = std::min<uint32_t>(32, parallel);
    llama_context_params context_params = a.context_default_params();
    context_params.n_ctx = e.batch_tokens;
    context_params.n_batch = e.batch_tokens;
    context_params.n_ubatch = e.batch_tokens;  // non-causal models need a whole batch in one ubatch
    context_params.n_seq_max = e.sequences;
    context_params.kv_unified = true;
    context_params.embeddings = true;
    context_params.pooling_type = LLAMA_POOLING_TYPE_UNSPECIFIED;  // the model's own pooling
    context_params.n_threads = context_params.n_threads_batch = 4;
    e.context = a.init_from_model(e.model, context_params);
    if (!e.context) throw EmbedFailure("cannot create the embedding context on " + device_text + recent_log());
    const enum llama_pooling_type pooling = a.pooling_type(e.context);
    if (pooling == LLAMA_POOLING_TYPE_NONE || pooling == LLAMA_POOLING_TYPE_RANK)
        throw EmbedFailure(narrow(model_path.wstring()) + " is not a sentence-embedding model (pooling none or rank). "
                           "Fix: use the EmbeddingGemma 2 GGUF converted with --sentence-transformers-dense-modules");
    e.vocab = a.model_get_vocab(e.model);
    const int32_t out = a.model_n_embd_out(e.model);
    e.dimensions = static_cast<size_t>(out > 0 ? out : a.model_n_embd(e.model));
    char description[256] = {};
    a.model_desc(e.model, description, sizeof(description));
    std::lock_guard lock(e.mutex);
    e.ready_text = device_text + ", " + description + ", " + std::to_string(e.dimensions) + " dimensions";
    e.identity = std::string(description) + "|" + std::to_string(model_bytes) + "|" + std::to_string(e.dimensions);
}

std::vector<int32_t> tokens_of(Engine& e, const std::string& text) {
    const auto length = static_cast<int32_t>(std::min<size_t>(text.size(), INT32_MAX));
    std::vector<int32_t> tokens(std::min<size_t>(text.size() + 16, 65536));
    int32_t count = e.api.tokenize(e.vocab, text.data(), length, tokens.data(), static_cast<int32_t>(tokens.size()), true, false);
    if (count < 0) {
        tokens.resize(static_cast<size_t>(-static_cast<int64_t>(count)));
        count = e.api.tokenize(e.vocab, text.data(), length, tokens.data(), static_cast<int32_t>(tokens.size()), true, false);
        if (count < 0) throw EmbedFailure("tokenizer failed on a chunk of " + std::to_string(text.size()) + " bytes");
    }
    tokens.resize(static_cast<size_t>(count));
    if (tokens.size() > e.max_tokens) tokens.resize(e.max_tokens);
    if (tokens.empty()) throw EmbedFailure("tokenizer returned no tokens for a chunk of " + std::to_string(text.size()) + " bytes");
    return tokens;
}

// Embeds on a loaded engine without waiting for the ready state (the loader's warm-up runs before it is set).
std::vector<std::vector<float>> embed_loaded(Engine& e, const std::vector<std::string>& texts,
                                             EmbedClock::time_point deadline,
                                             const std::shared_ptr<std::atomic_bool>& cancelled) {
    std::lock_guard run(e.run);
    std::vector<std::vector<int32_t>> tokens;
    tokens.reserve(texts.size());
    for (const auto& text : texts) tokens.push_back(tokens_of(e, text));
    std::vector<std::vector<float>> vectors(texts.size());
    llama_batch batch = e.api.batch_init(static_cast<int32_t>(e.batch_tokens), 0, 1);
    struct BatchFree {
        Engine& e;
        llama_batch& batch;
        ~BatchFree() { e.api.batch_free(batch); }
    } free_batch{e, batch};
    size_t next = 0;
    while (next < texts.size()) {
        if (cancelled && cancelled->load()) throw std::runtime_error("meaning search cancelled");
        if (EmbedClock::now() >= deadline) throw std::runtime_error("meaning search timed out while embedding");
        // One batch: whole documents only, at most `sequences` of them and `batch_tokens` tokens.
        const size_t first = next;
        batch.n_tokens = 0;
        while (next < texts.size() && next - first < e.sequences &&
               static_cast<size_t>(batch.n_tokens) + tokens[next].size() <= e.batch_tokens) {
            const auto seq = static_cast<llama_seq_id>(next - first);
            for (size_t i = 0; i < tokens[next].size(); ++i) {
                const int32_t at = batch.n_tokens++;
                batch.token[at] = tokens[next][i];
                batch.pos[at] = static_cast<llama_pos>(i);
                batch.n_seq_id[at] = 1;
                batch.seq_id[at][0] = seq;
                batch.logits[at] = 1;
            }
            ++next;
        }
        if (next == first) throw EmbedFailure("a chunk is longer than the embedding batch");  // max_tokens <= batch_tokens
        if (llama_memory_t memory = e.api.get_memory(e.context)) e.api.memory_clear(memory, true);
        const int32_t status = e.api.decode(e.context, batch);
        if (status != 0)
            throw EmbedFailure("the GPU embedding run failed (llama_decode returned " + std::to_string(status) + ")" +
                               recent_log() + ". Fix: restart shgrep; if it repeats, check the GPU driver");
        for (size_t index = first; index < next; ++index) {
            const float* values = e.api.get_embeddings_seq(e.context, static_cast<llama_seq_id>(index - first));
            if (!values) throw EmbedFailure("the model returned no sentence embedding" + recent_log());
            double norm = 0;
            for (size_t d = 0; d < e.dimensions; ++d) norm += static_cast<double>(values[d]) * values[d];
            const float scale = norm > 0 ? static_cast<float>(1.0 / std::sqrt(norm)) : 0.0f;
            vectors[index].resize(e.dimensions);
            for (size_t d = 0; d < e.dimensions; ++d) vectors[index][d] = values[d] * scale;
        }
    }
    return vectors;
}

// Waits until loading finished; returns the ready engine or throws.
Engine& ready_engine(EmbedClock::time_point deadline, const std::shared_ptr<std::atomic_bool>& cancelled) {
    start_embedder();
    auto& e = engine();
    std::unique_lock lock(e.mutex);
    for (;;) {
        if (e.state == State::ready) return e;
        if (e.state == State::failed) {
            // The model file was missing and is there now: load it without restarting shgrep.
            std::error_code error;
            if (e.model_missing && e.runtime_loaded && fs::exists(model_file(exe_folder()), error)) {
                e.model_missing = false;
                e.state = State::idle;
                lock.unlock();
                start_embedder();
                lock.lock();
                continue;
            }
            throw EmbedFailure(e.failure);
        }
        if (cancelled && cancelled->load()) throw std::runtime_error("meaning search cancelled while the model was loading");
        if (EmbedClock::now() >= deadline)
            throw std::runtime_error("meaning search timed out while the model is loading (" + e.step + "); retry shortly");
        e.changed.wait_for(lock, std::chrono::milliseconds(50));
    }
}
}

bool embed_built() { return true; }

void start_embedder() {
    auto& e = engine();
    {
        std::lock_guard lock(e.mutex);
        if (e.state != State::idle) return;
        e.state = State::loading;
        e.step = "starting";
    }
    // Detached: a model load cannot be interrupted, and process exit releases the GPU.
    std::thread([] {
        auto& e = engine();
        std::string failure;
        try {
            load(e);
            set_step("first test embedding on the GPU");
            (void)embed_loaded(e, {"task: code retrieval | query: ready"}, EmbedClock::now() + std::chrono::minutes(5), {});
        } catch (const std::exception& error) {
            failure = error.what();
        } catch (...) {
            failure = "unknown error while loading the embedding model";
        }
        {
            std::lock_guard lock(e.mutex);
            if (failure.empty()) {
                e.state = State::ready;
            } else {
                e.state = State::failed;
                e.failure = failure;
            }
        }
        e.changed.notify_all();
    }).detach();
}

std::string embedder_state() {
    auto& e = engine();
    std::lock_guard lock(e.mutex);
    switch (e.state) {
    case State::idle: return "not started";
    case State::loading: return "loading: " + e.step;
    case State::ready: return "ready: " + e.ready_text;
    case State::failed: return "failed: " + e.failure;
    }
    return "unknown";
}

size_t embed_dimensions() {
    auto& e = engine();
    std::lock_guard lock(e.mutex);
    return e.state == State::ready ? e.dimensions : 0;
}

std::string embed_model_identity() {
    auto& e = engine();
    std::lock_guard lock(e.mutex);
    return e.state == State::ready ? e.identity : std::string();
}

std::vector<float> embed_query(std::string_view question, EmbedClock::time_point deadline,
                               const std::shared_ptr<std::atomic_bool>& cancelled) {
    Engine& e = ready_engine(deadline, cancelled);
    auto vectors = embed_loaded(e, {"task: code retrieval | query: " + std::string(question)}, deadline, cancelled);
    return std::move(vectors.front());
}

std::vector<std::vector<float>> embed_documents(const std::vector<EmbedDocument>& documents,
                                                EmbedClock::time_point deadline,
                                                const std::shared_ptr<std::atomic_bool>& cancelled) {
    if (documents.empty()) return {};
    Engine& e = ready_engine(deadline, cancelled);
    std::vector<std::string> texts;
    texts.reserve(documents.size());
    for (const auto& document : documents)
        texts.push_back("title: " + std::string(document.title) + " | text: " + std::string(document.text));
    return embed_loaded(e, texts, deadline, cancelled);
}
#endif
}
