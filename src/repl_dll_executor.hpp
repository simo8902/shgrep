#pragma once
#include <clang/Interpreter/IncrementalExecutor.h>
#include <llvm/ExecutionEngine/Orc/Shared/ExecutorAddress.h>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace clang { class CompilerInstance; }
namespace shgrep {
class DllExecutor final : public clang::IncrementalExecutor {
    struct Impl;
    std::unique_ptr<Impl> impl_;
public:
    DllExecutor(clang::CompilerInstance& compiler, std::filesystem::path directory,
                std::vector<std::filesystem::path> library_directories, const void* bridge,
                void (*bootstrap_phase)(const char*));
    void finishBootstrap() noexcept;
    ~DllExecutor() override;
    llvm::Error addModule(clang::PartialTranslationUnit& unit) override;
    llvm::Error removeModule(clang::PartialTranslationUnit& unit) override;
    llvm::Error runCtors() const override;
    llvm::Error cleanUp() override;
    llvm::Expected<llvm::orc::ExecutorAddr>
    getSymbolAddress(llvm::StringRef name, SymbolNameKind kind) const override;
    llvm::Error LoadDynamicLibrary(const char* name) override;
    bool failed() const noexcept;
    const std::string& emissionDiagnostics() const noexcept;
};
} // namespace shgrep
