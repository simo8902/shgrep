#pragma once
#include <atomic>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace shgrep {
// Meaning search with an embedding model (issue #87, build 2). The GPU build (CMake SHGREP_EMBED=ON) loads
// llama.cpp's DLLs (llama.dll, ggml.dll, ggml-base.dll, ggml-cpu.dll, ggml-hip.dll) and the GGUF model from
// shgrep.exe's folder at startup; the portable build has none of it.
// CONTRACT: enforced, no fallback. When the DLLs, the GPU or the model are unusable, every call throws EmbedFailure
//   with the exact cause and the fix; nothing moves to the CPU and nothing answers with BM25 alone.

// The model, its DLLs or the GPU are not usable. what() names the file or device, the error text and the fix.
struct EmbedFailure : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// True in the GPU build (SHGREP_EMBED).
bool embed_built();

// Starts loading the DLLs and the model on a background thread and returns at once. Only the first call does
// anything; it is a no-op in the portable build.
void start_embedder();

// One line for status output: "off (portable build)", "not started", "loading: <step>", "ready: <device>, <model>,
// <n> dimensions" or "failed: <cause>".
std::string embedder_state();

// Length of every vector; 0 until the model is ready.
size_t embed_dimensions();

// What makes vectors comparable: the model's description, its file size and the vector length, e.g.
// "gemma-embedding2 0.3B Q8_0|322408000|768". Empty until the model is ready. Saved vectors with another identity
// are not reused.
std::string embed_model_identity();

using EmbedClock = std::chrono::steady_clock;

// L2-normalised vector of a natural-language question, with the model's query prompt
// ("task: code retrieval | query: <question>"). Waits for loading until the deadline; while the model is still
// loading at the deadline it throws std::runtime_error with the loading step. Throws EmbedFailure when unusable.
std::vector<float> embed_query(std::string_view question, EmbedClock::time_point deadline,
                               const std::shared_ptr<std::atomic_bool>& cancelled);

// One code chunk: title is shown to the model as the file name ("title: <title> | text: <text>").
struct EmbedDocument {
    std::string_view title, text;
};
// L2-normalised vectors, one per document, in order (each document is cut to SHGREP_EMBED_MAX_TOKENS, default
// 1024 tokens). Same waiting and failure rules as embed_query.
std::vector<std::vector<float>> embed_documents(const std::vector<EmbedDocument>& documents,
                                                EmbedClock::time_point deadline,
                                                const std::shared_ptr<std::atomic_bool>& cancelled);
}
