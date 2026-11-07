#include "repl.hpp"
#include "repl_compiler_api.hpp"
#include "repl_ipc.hpp"
#include "repl_cpp.hpp"
#include "repl_headers_vfs.hpp"
#include "repl_dll_executor.hpp"
#include "repl_prelude.hpp"
#include <clang/AST/ASTConsumer.h>
#include <clang/AST/Attr.h>
#include <clang/AST/Decl.h>
#include <clang/AST/EvaluatedExprVisitor.h>
#include <clang/AST/DeclTemplate.h>
#include <clang/AST/Type.h>
#include <clang/Basic/SourceManager.h>
#include <clang/Basic/Stack.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendPluginRegistry.h>
#include <clang/Interpreter/Interpreter.h>
#include <clang/Sema/Sema.h>
#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/thread.h>
#include <llvm/Support/Process.h>
#include <llvm/Support/VersionTuple.h>
#include <llvm/WindowsDriver/MSVCPaths.h>
#include <llvm/Support/raw_ostream.h>
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <io.h>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string_view>
#include <thread>
#include <vector>

namespace {
using J = shgrep::Json;
using shgrep::repl_ipc::Handle;
Handle channel_in, channel_out;
shgrep::repl_ipc::Reader channel_reader;
std::mutex channel_mutex;
std::atomic_bool cell_active = false;
clang::Interpreter* interpreter = nullptr;
using CellEncoder = const char* (*)(const void*, int, size_t*);
CellEncoder encode_cell = nullptr;
void (*flush_cell)() = nullptr;
const std::string* emission_context = nullptr;
void startup_phase(const char* phase) {
    shgrep::repl_ipc::write(channel_out.value, J::Object{{"kind", "startup"}, {"phase", phase}});
}

// Clang's value-printing transformation can leave intermediate temporary
// destructors unregistered. Feed their definitions through normal codegen
// while the current incremental module is still open.
class TemporaryDestructorConsumer final : public clang::ASTConsumer {
    clang::CompilerInstance& compiler_;
    std::set<const clang::CXXDestructorDecl*> registered_;

    class Temporaries final : public clang::EvaluatedExprVisitor<Temporaries> {
        std::vector<const clang::CXXDestructorDecl*>& destructors_;
    public:
        Temporaries(clang::ASTContext& context,
                    std::vector<const clang::CXXDestructorDecl*>& destructors)
            : clang::EvaluatedExprVisitor<Temporaries>(context), destructors_(destructors) {}
        bool shouldVisitDiscardedStmt() const { return false; }
        void VisitCXXBindTemporaryExpr(clang::CXXBindTemporaryExpr* expression) {
            destructors_.push_back(expression->getTemporary()->getDestructor());
            Visit(expression->getSubExpr());
        }
    };

public:
    explicit TemporaryDestructorConsumer(clang::CompilerInstance& compiler)
        : compiler_(compiler) {}

    bool HandleTopLevelDecl(clang::DeclGroupRef group) override {
        std::vector<const clang::CXXDestructorDecl*> destructors;
        Temporaries visitor(compiler_.getASTContext(), destructors);
        for (auto* declaration : group)
            if (auto* statement = llvm::dyn_cast<clang::TopLevelStmtDecl>(declaration);
                statement && statement->isSemiMissing() && statement->getStmt())
                visitor.Visit(statement->getStmt());

        for (const auto* temporary_destructor : destructors) {
            auto* destructor = const_cast<clang::CXXDestructorDecl*>(temporary_destructor);
            const auto* canonical = destructor->getCanonicalDecl();
            if (registered_.contains(canonical) || destructor->isInvalidDecl() ||
                destructor->isDeleted() || destructor->isTrivial() ||
                destructor->getDeclContext()->isDependentContext() ||
                destructor->hasAttr<clang::DLLImportAttr>())
                continue;

            auto& sema = compiler_.getSema();
            sema.MarkFunctionReferenced(destructor->getLocation(), destructor);
            if (destructor->isDefaulted() && !destructor->hasBody())
                sema.DefineImplicitDestructor(destructor->getLocation(), destructor);
            sema.PerformPendingInstantiations(/*LocalOnly=*/false, /*AtEndOfTU=*/false);
            // Errors fail the cell through the parser's error check, which withdraws the input. A rejected decl
            //   would leave the parser early, with the input's state still in place.
            if (compiler_.getDiagnostics().hasErrorOccurred()) return true;
            auto* definition = destructor->getDefinition();
            // External declarations still use normal linker resolution.
            if (!definition || !definition->hasBody()) continue;
            if (!definition->hasAttr<clang::UsedAttr>())
                definition->addAttr(clang::UsedAttr::CreateImplicit(compiler_.getASTContext()));
            // Record before dispatch: this calls the same consumer chain.
            registered_.insert(canonical);
            if (!compiler_.getASTConsumer().HandleTopLevelDecl(clang::DeclGroupRef(definition)))
                return false;
        }
        return true;
    }
};

class TemporaryDestructorAction final : public clang::PluginASTAction {
public:
    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
        clang::CompilerInstance& compiler, llvm::StringRef) override {
        return std::make_unique<TemporaryDestructorConsumer>(compiler);
    }
    bool ParseArgs(const clang::CompilerInstance&,
                   const std::vector<std::string>& arguments) override {
        return arguments.empty();
    }
    ActionType getActionType() override { return CmdlineBeforeMainAction; }
};
clang::FrontendPluginRegistry::Add<TemporaryDestructorAction> temporary_destructor_action(
    "shgrep-temporary-destructors", "Register destructors used by final C++ expressions");

std::string saved_declarations() {
    std::map<std::string, std::string> names;
    const auto& context = interpreter->getASTContext();
    const auto& sources = context.getSourceManager();
    for (const auto* unit : context.getTranslationUnitDecl()->redecls()) {
        for (const auto* declaration : unit->decls()) {
            const auto* named = llvm::dyn_cast<clang::NamedDecl>(declaration);
            if (!named || named->isImplicit() || named->getNameAsString().empty()) continue;
            const auto location = sources.getPresumedLoc(named->getLocation());
            if (!location.isValid() || !std::string_view(location.getFilename()).starts_with("shgrep_cell_")) continue;
            const auto* value = llvm::dyn_cast<clang::ValueDecl>(named);
            names[named->getQualifiedNameAsString()] = value ? value->getType().getAsString() : "type or namespace";
        }
    }
    if (names.empty()) return "No persisted C++ declarations.";
    std::string text;
    for (const auto& [name, type] : names) text += name + ": " + type + "\n";
    return text;
}
// SAFETY: native cells write to a pipe that a drain thread empties into memory, keeping at most max_frame / 2
//   (128 MiB) and counting and discarding the rest. A noisy cell therefore never fills a disk or blocks on a full
//   pipe, and take() reports the overflow, as the limit was before.
class Output {
    static constexpr size_t limit = shgrep::repl_ipc::max_frame / 2;
    Handle read_;
    std::thread drain_;
    std::atomic_bool paused_{false};
    std::mutex mutex_;
    std::string text_;   // captured since reset(); mutex_
    bool over_ = false;  // more than `limit` arrived since reset(); mutex_

    void keep(const char* data, size_t size) {
        std::lock_guard lock(mutex_);
        const size_t room = limit - std::min(limit, text_.size());
        if (size > room) over_ = true;
        text_.append(data, std::min(size, room));
    }
    void start() {
        paused_.store(false);
        drain_ = std::thread([this] {
            std::vector<char> buffer(1u << 16);
            while (!paused_.load()) {
                DWORD got = 0;
                if (!ReadFile(read_.value, buffer.data(), static_cast<DWORD>(buffer.size()), &got, nullptr)) {
                    if (GetLastError() == ERROR_OPERATION_ABORTED) continue;  // stop() cancelled the read
                    return;
                }
                keep(buffer.data(), got);
            }
        });
    }
    // Ends the drain thread. A cancelled read consumes nothing, so every byte is either kept or still in the pipe.
    void stop() {
        if (!drain_.joinable()) return;
        paused_.store(true);
        const HANDLE thread = drain_.native_handle();
        do CancelSynchronousIo(thread);  // repeated: the thread may not have entered ReadFile yet
        while (WaitForSingleObject(thread, 10) == WAIT_TIMEOUT);
        drain_.join();
    }
    // Keeps what is in the pipe now; a writer still running cannot make this loop forever.
    void pump() {
        DWORD available = 0;
        if (!PeekNamedPipe(read_.value, nullptr, 0, nullptr, &available, nullptr)) return;
        std::vector<char> buffer(1u << 16);
        while (available) {
            DWORD got = 0;
            if (!ReadFile(read_.value, buffer.data(), std::min<DWORD>(available, static_cast<DWORD>(buffer.size())), &got, nullptr) || !got)
                return;
            keep(buffer.data(), got);
            available -= std::min(available, got);
        }
    }

public:
    Output() {
        Handle write;
        if (!CreatePipe(std::out_ptr<HANDLE>(read_), std::out_ptr<HANDLE>(write), nullptr, 1u << 20))
            throw std::runtime_error("cannot create C++ output capture");
        const int descriptor = _open_osfhandle(reinterpret_cast<intptr_t>(write.value), _O_WRONLY | _O_BINARY);
        if (descriptor < 0) throw std::runtime_error("cannot create C++ output capture");
        write.release();  // _open_osfhandle owns the handle only after success
        const bool redirected = !_dup2(descriptor, 1) && !_dup2(descriptor, 2);
        _close(descriptor);  // fds 1 and 2 hold their own duplicates
        if (!redirected) throw std::runtime_error("cannot redirect C++ worker output");
        // Native cells cannot accidentally consume the private protocol through std::cin.
        const int null_input = _open("NUL", _O_RDONLY);
        if (null_input < 0) throw std::runtime_error("cannot detach C++ worker stdin");
        const bool detached = _dup2(null_input, 0) == 0;
        _close(null_input);
        if (!detached) throw std::runtime_error("cannot detach C++ worker stdin");
        const auto capture = reinterpret_cast<HANDLE>(_get_osfhandle(1));
        if (!SetStdHandle(STD_OUTPUT_HANDLE, capture) || !SetStdHandle(STD_ERROR_HANDLE, capture) ||
            !SetStdHandle(STD_INPUT_HANDLE, reinterpret_cast<HANDLE>(_get_osfhandle(0))))
            throw std::runtime_error("cannot redirect native C++ runtime handles");
        start();
    }
    ~Output() { stop(); }  // read_ closes after the drain thread joins
    Output(const Output&) = delete;
    Output& operator=(const Output&) = delete;
    void flush() {
        std::cout.flush(); std::cerr.flush(); std::clog.flush();
        llvm::outs().flush(); llvm::errs().flush();
        if (flush_cell) flush_cell();
        fflush(nullptr);
    }
    void reset() {
        flush();
        stop();
        pump();
        {
            std::lock_guard lock(mutex_);
            text_.clear();
            over_ = false;
        }
        start();
    }
    std::string take() {
        flush();
        stop();
        pump();
        std::string text;
        bool over = false;
        {
            std::lock_guard lock(mutex_);
            text = std::move(text_);
            over = over_;
        }
        start();
        if (over) throw std::runtime_error("C++ output exceeds 128 MiB");
        return text;
    }
};
std::string result_text(const clang::Value& value, J::Object& reply) {
    if (!value.hasValue()) return {};
    const auto* record = value.getType().getNonReferenceType()->getAsCXXRecordDecl();
    const bool facade = record && record->getQualifiedNameAsString() == "shgrep::cpp::Value";
    const auto* specialization = llvm::dyn_cast_or_null<clang::ClassTemplateSpecializationDecl>(record);
    const auto standard_argument = [&](unsigned index, const char* name) {
        if (!specialization || specialization->getTemplateArgs().size() <= index ||
            specialization->getTemplateArgs()[index].getKind() != clang::TemplateArgument::Type)
            return false;
        const auto* argument = specialization->getTemplateArgs()[index].getAsType()->getAsCXXRecordDecl();
        return argument && argument->getQualifiedNameAsString() == name;
    };
    const bool string = specialization && record->getQualifiedNameAsString() == "std::basic_string" &&
        specialization->getTemplateArgs().size() == 3 &&
        specialization->getTemplateArgs()[0].getKind() == clang::TemplateArgument::Type &&
        specialization->getTemplateArgs()[0].getAsType()->isCharType() &&
        standard_argument(1, "std::char_traits") && standard_argument(2, "std::allocator");
    if (facade || string) {
        if (!encode_cell) throw std::runtime_error("C++ result encoder is unavailable");
        size_t length = 0;
        const char* bytes = encode_cell(value.getPtr(), string ? 1 : 0, &length);
        if (!bytes || length > shgrep::repl_ipc::max_frame / 2)
            throw std::runtime_error("C++ result encoding failed or exceeded 128 MiB");
        J data = J::parse(std::string(bytes, length));
        if (const auto* text = std::get_if<std::string>(&data.value)) return *text;
        reply["value"] = std::move(data);
        return {};
    }
    std::string text;
    llvm::raw_string_ostream stream(text);
    value.printData(stream);
    return text;
}

// A cell split into its leading preprocessor block (directives with their \ continuations, and the blank and //
// comment lines between them) and the rest. The block ends after the last directive at which #if/#endif balance, so
// no conditional spans both parts; head is empty when the cell does not start with a directive.
struct CellParts {
    std::string head;
    std::string body;
    size_t body_line = 1;  // 1-based line of the cell where body starts
};

CellParts split_cell(const std::string& code) {
    size_t pos = 0, line = 1, head_end = 0, body_line = 1;
    int depth = 0;
    while (pos < code.size()) {
        const size_t eol = code.find('\n', pos);
        const size_t next = eol == std::string::npos ? code.size() : eol + 1;
        std::string_view text(code.data() + pos, (eol == std::string::npos ? code.size() : eol) - pos);
        if (!text.empty() && text.back() == '\r') text.remove_suffix(1);
        const size_t first = text.find_first_not_of(" \t");
        const std::string_view trimmed = first == std::string_view::npos ? std::string_view{} : text.substr(first);
        if (trimmed.empty() || trimmed.starts_with("//")) {
            pos = next;
            ++line;
            continue;
        }
        if (!trimmed.starts_with('#')) break;
        std::string_view name = trimmed.substr(1);
        name.remove_prefix(std::min(name.find_first_not_of(" \t"), name.size()));
        if (name.starts_with("if")) ++depth;  // #if, #ifdef, #ifndef
        else if (name.starts_with("endif")) --depth;
        if (depth < 0) break;  // unbalanced: keep the block found so far
        // A directive continues onto the next line while its line ends with a backslash.
        std::string_view rest = text;
        size_t end = next;
        ++line;
        while (!rest.empty() && rest.back() == '\\' && end < code.size()) {
            const size_t more = code.find('\n', end);
            rest = std::string_view(code.data() + end, (more == std::string::npos ? code.size() : more) - end);
            if (!rest.empty() && rest.back() == '\r') rest.remove_suffix(1);
            end = more == std::string::npos ? code.size() : more + 1;
            ++line;
        }
        pos = end;
        if (depth == 0) {
            head_end = pos;
            body_line = line;
        }
    }
    if (head_end == 0) return {{}, code, 1};
    return {code.substr(0, head_end), code.substr(head_end), body_line};
}
} // namespace

extern "C" const char* shgrep_cpp_bridge(const char* method, const char* arguments) {
    thread_local std::string response;
    std::lock_guard lock(channel_mutex);
    try {
        if (!cell_active.load()) throw std::runtime_error("facade calls require an active REPL request");
        const std::string name(method ? method : "");
        if (name == "s.vars") {
            response = J(J::Object{{"ok", true}, {"value", saved_declarations()}}).dump();
        } else {
            shgrep::repl_ipc::write(channel_out.value, J::Object{
                {"kind", "call"}, {"method", name}, {"arguments", J::parse(arguments ? arguments : "{}")}});
            const J reply = channel_reader.read(channel_in.value);
            if (!reply.get("kind") || reply.get("kind")->string() != "reply")
                throw std::runtime_error("invalid parent response to C++ facade call");
            response = reply.dump();
        }
    } catch (const std::exception& error) {
        response = J(J::Object{{"ok", false}, {"error", error.what()}}).dump();
    }
    return response.c_str();
}

namespace {
std::string utf8_path(const std::filesystem::path& path) {
    const auto text = path.generic_u8string();
    return std::string(reinterpret_cast<const char*>(text.data()), text.size());
}

struct InstalledRuntime {
    std::vector<std::filesystem::path> headers;
    std::vector<std::filesystem::path> library_directories;
};

// vswhere is installed with Visual Studio Installer and reports all product editions.
// Inherit only the three standard handles so the child cannot retain the worker IPC pipes.
std::vector<std::filesystem::path> visual_studio_installations(std::string& problem) {
    const DWORD length = GetEnvironmentVariableW(L"ProgramFiles(x86)", nullptr, 0);
    if (!length) { problem = "ProgramFiles(x86) is not set"; return {}; }
    std::wstring base(length, L'\0');
    const DWORD written = GetEnvironmentVariableW(L"ProgramFiles(x86)", base.data(), length);
    if (!written || written >= length) { problem = "cannot read ProgramFiles(x86)"; return {}; }
    base.resize(written);
    const auto executable = std::filesystem::path(base) / L"Microsoft Visual Studio" / L"Installer" / L"vswhere.exe";
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    Handle read, write;
    if (!CreatePipe(std::out_ptr<HANDLE>(read), std::out_ptr<HANDLE>(write), &security, 0)) {
        problem = "cannot create vswhere output pipe"; return {};
    }
    if (!SetHandleInformation(read.value, HANDLE_FLAG_INHERIT, 0)) {
        problem = "cannot isolate vswhere output pipe"; return {};
    }
    Handle null_file(CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!null_file.value || null_file.value == INVALID_HANDLE_VALUE) {
        problem = "cannot open NUL for vswhere"; return {};
    }
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    if (!size) { problem = "cannot size vswhere handle list"; return {}; }
    std::vector<unsigned char> storage(size);
    auto* attributes = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &size)) {
        problem = "cannot initialize vswhere handle list"; return {};
    }
    HANDLE handles[] = {null_file.value, write.value};
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   handles, sizeof(handles), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(attributes);
        problem = "cannot isolate vswhere child handles"; return {};
    }
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = null_file.value;
    startup.StartupInfo.hStdOutput = write.value;
    startup.StartupInfo.hStdError = null_file.value;
    startup.lpAttributeList = attributes;
    std::wstring command = L"\"" + executable.wstring() +
        L"\" -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath -utf8";
    PROCESS_INFORMATION info{};
    const BOOL created = CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
                                        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                                        nullptr, nullptr, &startup.StartupInfo, &info);
    const DWORD error = GetLastError();
    DeleteProcThreadAttributeList(attributes);
    if (!created) {
        problem = "cannot start vswhere (Windows error " + std::to_string(error) + ")";
        return {};
    }
    Handle process(info.hProcess), thread(info.hThread);
    write.reset();
    std::string output;
    const ULONGLONG deadline = GetTickCount64() + 20000;
    bool failed = false;
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(read.value, nullptr, 0, nullptr, &available, nullptr)) {
            const DWORD pipe_error = GetLastError();
            if (pipe_error != ERROR_BROKEN_PIPE) {
                problem = "cannot read vswhere output (Windows error " + std::to_string(pipe_error) + ")";
                failed = true;
            }
            break;
        }
        if (available) {
            char buffer[4096];
            DWORD count = 0;
            if (!ReadFile(read.value, buffer, std::min<DWORD>(available, sizeof(buffer)), &count, nullptr) || !count) {
                problem = "cannot read vswhere output"; failed = true; break;
            }
            output.append(buffer, count);
            if (output.size() > (1u << 20)) { problem = "vswhere output exceeded 1 MiB"; failed = true; break; }
        } else if (GetTickCount64() >= deadline) {
            problem = "vswhere timed out"; failed = true; break;
        } else {
            WaitForSingleObject(process.value, 20);
        }
    }
    if (failed) {
        TerminateProcess(process.value, 1);
        WaitForSingleObject(process.value, 1000);
        return {};
    }
    if (WaitForSingleObject(process.value, 1000) != WAIT_OBJECT_0) {
        TerminateProcess(process.value, 1);
        WaitForSingleObject(process.value, 1000);
        problem = "vswhere did not exit"; return {};
    }
    DWORD exit_code = 0;
    if (!GetExitCodeProcess(process.value, &exit_code) || exit_code != 0) {
        problem = "vswhere failed with exit code " + std::to_string(exit_code); return {};
    }
    if (output.starts_with("\xEF\xBB\xBF")) output.erase(0, 3);
    std::vector<std::filesystem::path> installations;
    for (size_t start = 0; start < output.size();) {
        size_t end = output.find('\n', start);
        if (end == std::string::npos) end = output.size();
        std::string line = output.substr(start, end - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) installations.push_back(std::filesystem::u8path(line));
        start = end + 1;
    }
    if (installations.empty()) problem = "vswhere found no Visual Studio installations with C++ tools";
    return installations;
}

InstalledRuntime discover_runtime(llvm::vfs::FileSystem& filesystem) {
    // The host interprets Clang value metadata from cells. Keep the build's
    // toolset family while cells use the shared /MD runtime.
    llvm::VersionTuple required_version;
    if (required_version.tryParse(SHGREP_REPL_MSVC_VERSION) ||
        !required_version.getMinor())
        throw std::runtime_error("invalid MSVC toolset version recorded in shgrep-compiler.dll");
    auto matching_toolset = [&](const std::filesystem::path& root) {
        llvm::VersionTuple version;
        return !version.tryParse(utf8_path(root.filename())) &&
               version.getMajor() == required_version.getMajor() &&
               version.getMinor() == required_version.getMinor();
    };
    auto is_directory = [&](const std::filesystem::path& path) {
        const auto status = filesystem.status(utf8_path(path));
        return status && status->isDirectory();
    };
    auto require_file = [&](const std::filesystem::path& path) {
        const auto status = filesystem.status(utf8_path(path));
        if (!status || !status->isRegularFile())
            throw std::runtime_error("C++ REPL requires an installed MSVC toolset and Windows SDK; "
                                     "missing or inaccessible file: " + utf8_path(path));
    };
    std::string toolchain;
    llvm::ToolsetLayout layout = llvm::ToolsetLayout::VS2017OrNewer;
    const bool from_environment = llvm::findVCToolChainViaEnvironment(filesystem, toolchain, layout);
    std::filesystem::path toolset_root;
    if (from_environment) {
        toolset_root = std::filesystem::u8path(toolchain).lexically_normal();
        if (toolset_root.filename().empty()) toolset_root = toolset_root.parent_path();
        if (layout != llvm::ToolsetLayout::VS2017OrNewer)
            throw std::runtime_error("C++ REPL requires a modern MSVC x64 toolset matching " +
                                     std::string(SHGREP_REPL_MSVC_VERSION));
        if (!matching_toolset(toolset_root))
            throw std::runtime_error("C++ REPL MSVC toolset mismatch: shgrep was built with " +
                std::string(SHGREP_REPL_MSVC_VERSION) + "; discovered " + utf8_path(toolset_root) +
                ". Install the matching major.minor toolset or set VCToolsInstallDir to it");
    } else {
        const bool setup_found =
            llvm::findVCToolChainViaSetupConfig(filesystem,
                llvm::StringRef(SHGREP_REPL_MSVC_VERSION), toolchain, layout) ||
            llvm::findVCToolChainViaSetupConfig(filesystem, std::nullopt, toolchain, layout);
        llvm::VersionTuple best_version;
        std::string scan_problem;
        auto regular_file = [&](const std::filesystem::path& path) {
            const auto status = filesystem.status(utf8_path(path));
            return status && status->isRegularFile();
        };
        auto consider = [&](const std::filesystem::path& candidate) {
            if (!matching_toolset(candidate) || !is_directory(candidate)) return;
            const auto include = candidate / L"include";
            const auto lib = candidate / L"lib/x64";
            if (!regular_file(include / L"vcruntime.h") || !regular_file(include / L"vector") ||
                !regular_file(lib / L"msvcrt.lib") || !regular_file(lib / L"msvcprt.lib") ||
                !regular_file(lib / L"vcruntime.lib") || !regular_file(lib / L"oldnames.lib")) return;
            llvm::VersionTuple version;
            if (version.tryParse(utf8_path(candidate.filename()))) return;
            if (toolset_root.empty() || version > best_version) {
                best_version = version;
                toolset_root = candidate;
            }
        };
        auto scan = [&](const std::filesystem::path& directory) {
            if (!is_directory(directory)) return;
            std::error_code ec;
            for (auto it = filesystem.dir_begin(utf8_path(directory), ec),
                      end = llvm::vfs::directory_iterator(); !ec && it != end; it.increment(ec))
                consider(std::filesystem::u8path(it->path().str()));
            if (ec && scan_problem.empty())
                scan_problem = "cannot enumerate " + utf8_path(directory) + ": " + ec.message();
        };
        if (setup_found && layout == llvm::ToolsetLayout::VS2017OrNewer) {
            auto setup_root = std::filesystem::u8path(toolchain).lexically_normal();
            if (setup_root.filename().empty()) setup_root = setup_root.parent_path();
            consider(setup_root);
            scan(setup_root.parent_path());
        }
        if (toolset_root.empty()) {
            std::string vswhere_problem;
            for (const auto& installation : visual_studio_installations(vswhere_problem))
                scan(installation / L"VC/Tools/MSVC");
            if (toolset_root.empty()) {
                std::string detail = !scan_problem.empty() ? scan_problem : vswhere_problem;
                if (detail.empty()) detail = "no complete matching major.minor toolset was found";
                throw std::runtime_error("C++ REPL cannot discover MSVC C++ Build Tools matching " +
                    std::string(SHGREP_REPL_MSVC_VERSION) + ": " + detail +
                    "; install the matching Desktop development with C++ workload or set VCToolsInstallDir");
            }
        }
    }

    auto sdk_directory = llvm::sys::Process::GetEnv("WindowsSdkDir");
    auto sdk_version = llvm::sys::Process::GetEnv("WindowsSDKVersion");
    if (sdk_directory && sdk_directory->empty()) sdk_directory.reset();
    if (sdk_version) {
        while (!sdk_version->empty() && (sdk_version->back() == '/' || sdk_version->back() == '\\'))
            sdk_version->pop_back();
        if (sdk_version->empty()) sdk_version.reset();
    }
    std::optional<llvm::StringRef> sdk_directory_ref, sdk_version_ref;
    if (sdk_directory) sdk_directory_ref = *sdk_directory;
    if (sdk_version) sdk_version_ref = *sdk_version;
    std::string sdk_path, include_version, library_version;
    int sdk_major = 0;
    if (!llvm::getWindowsSDKDir(filesystem, sdk_directory_ref, sdk_version_ref, std::nullopt,
                               sdk_path, sdk_major, include_version, library_version) ||
        sdk_major != 10 || include_version.empty() || library_version.empty())
        throw std::runtime_error("C++ REPL cannot discover a Windows 10/11 SDK; install it "
                                 "with C++ Build Tools or set WindowsSdkDir and WindowsSDKVersion");
    const auto sdk_root = std::filesystem::u8path(sdk_path);
    const auto sdk_include = sdk_root / L"Include" / std::filesystem::u8path(include_version);
    const auto msvc_include = toolset_root / L"include";
    require_file(msvc_include / L"vcruntime.h");
    require_file(msvc_include / L"vector");
    require_file(sdk_include / L"ucrt/stdio.h");
    require_file(sdk_include / L"shared/sdkddkver.h");
    require_file(sdk_include / L"um/Windows.h");
    InstalledRuntime result;
    result.headers = {msvc_include, sdk_include / L"ucrt", sdk_include / L"shared", sdk_include / L"um"};
    // These are optional SDK components; use them when installed.
    for (const auto* name : {L"winrt", L"cppwinrt"}) {
        auto path = sdk_include / name;
        if (is_directory(path)) result.headers.push_back(std::move(path));
    }
    const auto msvc_library = toolset_root / L"lib/x64";
    const auto sdk_library = sdk_root / L"Lib" / std::filesystem::u8path(library_version);
    result.library_directories = {msvc_library, sdk_library / L"ucrt", sdk_library / L"um"};
    result.library_directories[1] /= L"x64";
    result.library_directories[2] /= L"x64";
    for (const auto* name : {L"msvcrt.lib", L"msvcprt.lib", L"vcruntime.lib", L"oldnames.lib"})
        require_file(msvc_library / name);
    require_file(result.library_directories[1] / L"ucrt.lib");
    require_file(result.library_directories[2] / L"kernel32.lib");
    return result;
}



} // namespace

static int run_repl_worker_session() {
    try {
        channel_in = shgrep::repl_ipc::duplicate(GetStdHandle(STD_INPUT_HANDLE));
        channel_out = shgrep::repl_ipc::duplicate(GetStdHandle(STD_OUTPUT_HANDLE));
        startup_phase("reading worker initialization");
        const J startup = channel_reader.read(channel_in.value);
        if (!startup.get("kind") || startup.get("kind")->string() != "initialize" ||
            !startup.get("directory"))
            throw std::runtime_error("C++ worker requires a session initialization message");
        const auto session_directory = std::filesystem::u8path(startup.get("directory")->string());
        startup_phase("preparing output capture");
        Output output;
        startup_phase("initializing LLVM native target");
        llvm::InitializeNativeTarget();
        llvm::InitializeNativeTargetAsmPrinter();
        llvm::InitializeNativeTargetAsmParser();

        clang::IncrementalCompilerBuilder builder;
        std::wstring executable(32768, L'\0');
        const DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
        if (!length || length >= executable.size()) throw std::runtime_error("cannot locate C++ worker runtime");
        executable.resize(length);
        const auto directory = std::filesystem::path(executable).parent_path();
        // This is only a virtual mount point: no runtime directory is created.
        const auto runtime = directory / L"shgrep.dat.mount";
        startup_phase("mounting shgrep.dat");
        const auto filesystem = shgrep::repl_headers::create_header_filesystem(directory / L"shgrep.dat", runtime);
        startup_phase("discovering MSVC and Windows SDK");
        const auto installed = discover_runtime(*filesystem);
        const auto resource = runtime / (L"llvm/lib/clang/" SHGREP_LLVM_VERSION_MAJOR);
        std::vector<std::filesystem::path> headers{resource / L"include"};
        headers.insert(headers.end(), installed.headers.begin(), installed.headers.end());
        std::vector<std::string> arguments{"-std=c++26", "-fno-color-diagnostics", "-fexceptions", "-fcxx-exceptions",
            "-fms-runtime-lib=dll", "-D_ITERATOR_DEBUG_LEVEL=0",
            "-fms-compatibility-version=" + std::to_string(_MSC_VER / 100) + "." + std::to_string(_MSC_VER % 100),
            "-fno-emulated-tls", "-ftls-model=global-dynamic", "-nostdinc", "-nostdinc++", "-resource-dir=" + utf8_path(resource)};
        for (const auto& header : headers) {
            const auto status = filesystem->status(utf8_path(header));
            if (!status || !status->isDirectory())
                throw std::runtime_error("missing or inaccessible C++ compiler include directory: " + utf8_path(header));
            arguments.push_back("-isystem");
            arguments.push_back(utf8_path(header));
        }
        std::vector<const char*> compiler_arguments;
        for (const auto& argument : arguments) compiler_arguments.push_back(argument.c_str());
        builder.SetCompilerArgs(compiler_arguments);
        startup_phase("creating Clang compiler");
        auto compiler = builder.CreateCpp();
        if (!compiler) throw std::runtime_error(llvm::toString(compiler.takeError()));
        (*compiler)->setVirtualFileSystem(filesystem);
        (*compiler)->getFrontendOpts().AddPluginActions.push_back("shgrep-temporary-destructors");
        startup_phase("creating native DLL executor and interpreter");
        auto executor = std::make_unique<clang::IncrementalExecutorBuilder>();
        auto native_executor = std::make_unique<shgrep::DllExecutor>(**compiler, session_directory,
            installed.library_directories, reinterpret_cast<const void*>(&shgrep_cpp_bridge), startup_phase);
        auto* native = native_executor.get();
        // Impl is pinned until worker exit, so this buffer survives executor teardown.
        emission_context = &native->emissionDiagnostics();
        executor->IE = std::move(native_executor);
        auto created = clang::Interpreter::create(std::move(*compiler), std::move(executor));
        if (!created) throw std::runtime_error(llvm::toString(created.takeError()));
        auto owned = std::move(*created);
        interpreter = owned.get();
        // Keep parsing separate so a native bootstrap failure identifies its stage.
        const std::string bootstrap_source = std::string(shgrep_cpp_prelude) + R"SHGREP_NATIVE(
#include <cstdio>
#include <iostream>
#include <cstdint>
#include <io.h>
#include <fcntl.h>
extern "C" const char* shgrep_cell_encode(const void* value, int kind, size_t* length) {
    try {
        thread_local std::string encoded;
        encoded = kind == 1 ? shgrep::Json(*static_cast<const std::string*>(value)).dump()
                            : static_cast<const shgrep::cpp::Value*>(value)->data.dump();
        *length = encoded.size();
        return encoded.data();
    } catch (...) { *length = 0; return nullptr; }
}
extern "C" void shgrep_cell_flush() {
    std::cout.flush(); std::cerr.flush(); std::clog.flush();
    std::fflush(nullptr);
}
extern "C" int shgrep_cell_capture(intptr_t output, int* consumed) {
    *consumed = 0;
    const int descriptor = _open_osfhandle(output, _O_RDWR | _O_BINARY);
    if (descriptor < 0) return -1;
    *consumed = 1;
    int failed = _dup2(descriptor, 1) || _dup2(descriptor, 2);
    _close(descriptor);
    const int null_input = _open("NUL", _O_RDONLY);
    if (null_input < 0) return -1;
    failed = failed || _dup2(null_input, 0);
    _close(null_input);
    return failed ? -1 : 0;
}
)SHGREP_NATIVE";
        startup_phase("parsing bootstrap cell");
        auto bootstrap = owned->Parse(bootstrap_source);
        if (!bootstrap)
            throw std::runtime_error(llvm::toString(bootstrap.takeError()) + "\n" + output.take());
        startup_phase("linking/loading/executing bootstrap cell");
        if (auto error = owned->Execute(*bootstrap))
            throw std::runtime_error(llvm::toString(std::move(error)) + "\n" + output.take());
        native->finishBootstrap();
        startup_phase("resolving cell runtime and redirecting shared CRT output");
        auto lookup = [&](const char* name) {
            auto symbol = native->getSymbolAddress(name, clang::IncrementalExecutor::IRName);
            if (!symbol) throw std::runtime_error(llvm::toString(symbol.takeError()));
            return symbol->getValue();
        };
        encode_cell = reinterpret_cast<CellEncoder>(lookup("shgrep_cell_encode"));
        flush_cell = reinterpret_cast<void (*)()>(lookup("shgrep_cell_flush"));
        const auto capture = reinterpret_cast<int (*)(intptr_t, int*)>(lookup("shgrep_cell_capture"));
        auto capture_handle = shgrep::repl_ipc::duplicate(GetStdHandle(STD_OUTPUT_HANDLE));
        int consumed = 0;
        const int capture_error = capture(reinterpret_cast<intptr_t>(capture_handle.value), &consumed);
        if (consumed) capture_handle.value = nullptr; // owned and closed by the cell runtime
        if (capture_error) throw std::runtime_error("cannot redirect the shared C++ runtime output");
        output.reset();
        shgrep::repl_ipc::write(channel_out.value, J::Object{{"kind", "ready"}, {"ok", true}});
        uint64_t cell = 0;
        for (;;) {
            const J request = channel_reader.read(channel_in.value);
            if (request.get("kind") && request.get("kind")->string() == "shutdown") {
                output.flush();
                return 0;
            }
            if (!request.get("code")) throw std::runtime_error("C++ worker requires code");
            output.reset();
            J::Object reply{{"kind", "result"}, {"ok", true}};
            bool compiler_failed = false;
            std::string rendered;
            {
                std::lock_guard lock(channel_mutex);
                cell_active.store(true);
            }
            try {
                clang::Value value;
                const std::string file = "shgrep_cell_" + std::to_string(++cell) + ".cpp";
                const CellParts parts = split_cell(request.get("code")->string());
                // The leading #include block runs as its own input first. clang-repl withdraws every declaration of a
                // failed input, those of headers it included too, but keeps the preprocessor state, so the headers'
                // include guards would stay defined and a later #include of them would add nothing (#70).
                // Failed compilation can retain invalid template specializations in earlier translation units (#86).
                // Retire the interpreter instead of reusing that state or replaying cells with side effects.
                if (!parts.head.empty())
                    if (auto error = owned->ParseAndExecute("#line 1 \"" + file + "\"\n" + parts.head)) {
                        compiler_failed = true;
                        throw std::runtime_error(llvm::toString(std::move(error)));
                    }
                if (parts.body.find_first_not_of(" \t\r\n") != std::string::npos) {
                    const std::string code = "#line " + std::to_string(parts.body_line) + " \"" + file + "\"\n" + parts.body;
                    if (auto error = owned->ParseAndExecute(code, &value)) {
                        compiler_failed = true;
                        throw std::runtime_error(llvm::toString(std::move(error)));
                    }
                }
                rendered = result_text(value, reply);
            } catch (const shgrep::cpp::IndexWarmingError& error) {
                reply["ok"] = false;
                reply["error"] = error.what();
                reply["error_code"] = "index_warming";
                reply["error_data"] = error.details;
            } catch (const shgrep::cpp::SymbolLookupError& error) {
                reply["ok"] = false;
                reply["error"] = error.what();
                reply["error_code"] = "symbol_lookup";
                reply["error_data"] = error.details;
            } catch (const std::exception& error) {
                reply["ok"] = false;
                reply["error"] = error.what();
            } catch (...) {
                reply["ok"] = false;
                reply["error"] = "C++ cell threw a non-standard exception";
            }
            // Finish in-flight facade calls before returning the cell response.
            std::lock_guard lock(channel_mutex);
            cell_active.store(false);
            std::string text = output.take();
            if (!rendered.empty()) {
                if (!text.empty() && text.back() != '\n') text += '\n';
                text += rendered;
            }
            reply["text"] = std::move(text);
            if (native->failed()) {
                reply["kind"] = "fatal";
                reply["error"] = (reply.contains("error") ? reply["error"].string() : "C++ DLL executor failed") +
                                 std::string("\n") + reply["text"].string();
            }
            if (compiler_failed) reply["reset_required"] = true;
            shgrep::repl_ipc::write(channel_out.value, reply);
            // The complete error response is sent before shutdown; no later cell reaches this interpreter.
            if (native->failed() || compiler_failed) return 1;
        }
    } catch (const std::exception& error) {
        if (channel_out.value) {
            try { shgrep::repl_ipc::write(channel_out.value, J::Object{
                {"kind", "fatal"}, {"ok", false}, {"error", error.what()}}); } catch (...) {}
        }
        return 1;
    }
}

namespace {
std::string crash_address(const void* pointer) {
    char formatted[64];
    std::snprintf(formatted, sizeof(formatted), "%p", pointer);
    std::string result = formatted;
    HMODULE module = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                          reinterpret_cast<LPCWSTR>(pointer), &module)) {
        wchar_t path[1024];
        const DWORD length = GetModuleFileNameW(module, path, 1024);
        const auto displacement = reinterpret_cast<uintptr_t>(pointer) -
                                  reinterpret_cast<uintptr_t>(module);
        std::snprintf(formatted, sizeof(formatted), "+0x%llX",
                      static_cast<unsigned long long>(displacement));
        result += " (";
        if (length && length < 1024)
            result += utf8_path(std::filesystem::path(std::wstring(path, length)).filename());
        else
            result += "module";
        result += formatted;
        result += ')';
    }
    return result;
}

int report_worker_exception(EXCEPTION_POINTERS* exception) noexcept {
    // Let ordinary C++ exceptions reach the existing C++ boundary unchanged.
    if (!exception || !exception->ExceptionRecord ||
        exception->ExceptionRecord->ExceptionCode == 0xE06D7363u)
        return EXCEPTION_CONTINUE_SEARCH;
    try {
        const auto& record = *exception->ExceptionRecord;
        char code[32];
        std::snprintf(code, sizeof(code), "0x%08lX", record.ExceptionCode);
        std::string detail = std::string("Unhandled Windows exception ") + code +
                             "\nFault address: " + crash_address(record.ExceptionAddress);
        if ((record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
             record.ExceptionCode == EXCEPTION_GUARD_PAGE) && record.NumberParameters >= 2) {
            detail += "\nMemory access: " + std::to_string(record.ExceptionInformation[0]) +
                      "; address: " + crash_address(reinterpret_cast<const void*>(
                          record.ExceptionInformation[1]));
        }
        // Filters run before stack unwinding. Include the original fault address
        // separately because this best-effort trace also contains SEH frames.
        void* frames[32]{};
        const USHORT count = CaptureStackBackTrace(0, 32, frames, nullptr);
        detail += "\nException-filter stack (module offsets):";
        for (USHORT i = 0; i < count; ++i)
            detail += "\n  " + std::to_string(i) + ": " + crash_address(frames[i]);
        if (!count) detail += " unavailable";
        if (emission_context && !emission_context->empty())
            detail += "\nNative emission context:\n" + *emission_context;
        if (channel_out.value)
            shgrep::repl_ipc::write(channel_out.value, J::Object{
                {"kind", "fatal"}, {"ok", false}, {"error", std::move(detail)}});
    } catch (...) {
        // Diagnostics must never turn an unhandled failure into recovery.
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Keep SEH in a function with no C++ objects requiring unwinding (/EHsc).
int run_guarded_worker_session() {
    __try {
        return run_repl_worker_session();
    } __except (report_worker_exception(GetExceptionInformation())) {
        return 1;
    }
}
} // namespace

int shgrep::run_compiler_worker() {
    int result = 1;
    // The interpreter and both TLS/global teardown stay on this persistent
    // execution thread. Windows performs the remaining thread notifications
    // after explicit CRT TLS destruction and global cleanup have completed.
    // Parsing the bootstrap headers needs Clang's requested compiler stack.
    llvm::thread execution(std::optional<unsigned>{static_cast<unsigned>(clang::DesiredStackSize)}, [&] {
        clang::noteBottomOfStack();
        result = run_guarded_worker_session();
    });
    if (!execution.joinable())
        throw std::runtime_error("cannot create C++ compiler execution thread");
    execution.join();
    interpreter = nullptr;
    return result;
}
