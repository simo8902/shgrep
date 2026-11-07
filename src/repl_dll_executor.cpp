#include "repl_dll_executor.hpp"
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Mangle.h>
#include <clang/AST/Type.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Interpreter/PartialTranslationUnit.h>
#include <lld/Common/Driver.h>
#include <llvm/ExecutionEngine/Orc/JITTargetMachineBuilder.h>
#include <llvm/IR/Constants.h>
#include <llvm/Object/COFF.h>
#include <llvm/Support/Endian.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/IR/GlobalAlias.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/EHPersonalities.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>
#include <windows.h>
#include <algorithm>
#include <cstddef>
#include <deque>
#include <functional>
#include <optional>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <utility>

// winnt.h macros shadow the llvm::COFF enumerators used below.
#undef IMAGE_FILE_MACHINE_AMD64
#undef IMAGE_SCN_MEM_EXECUTE
#undef IMAGE_REL_BASED_ABSOLUTE
#undef IMAGE_REL_BASED_DIR64
LLD_HAS_DRIVER(coff)

namespace {
std::string utf8(const std::filesystem::path& path) {
    const auto text = path.generic_u8string();
    return {reinterpret_cast<const char*>(text.data()), text.size()};
}
std::string symbol_name(llvm::StringRef name) {
    if (name.starts_with("\01")) name = name.drop_front();
    return name.str();
}
llvm::Constant* address(llvm::Type* type, uintptr_t value) {
    return llvm::ConstantExpr::getIntToPtr(
        llvm::ConstantInt::get(llvm::Type::getInt64Ty(type->getContext()), value), type);
}
llvm::Error error(const std::string& message) {
    return llvm::createStringError(llvm::inconvertibleErrorCode(), "%s", message.c_str());
}
class BoundedDiagnosticStream final : public llvm::raw_ostream {
    static constexpr size_t kSectionBytes = 64 * 1024;
    std::string& text_;
    const size_t limit_;
    uint64_t position_ = 0;
    bool truncated_ = false;

    void write_impl(const char* data, size_t size) override {
        position_ += size;
        const size_t available = limit_ - text_.size();
        const size_t copied = std::min(size, available);
        text_.append(data, copied);
        truncated_ = truncated_ || copied != size;
    }
    uint64_t current_pos() const override { return position_; }

public:
    explicit BoundedDiagnosticStream(std::string& text)
        : llvm::raw_ostream(true), text_(text), limit_(text.size() + kSectionBytes) {}
    bool full() const noexcept { return text_.size() == limit_; }
    void finish() {
        if (truncated_ || full()) text_ += "\n[diagnostic section truncated]\n";
    }
};

// CONTRACT: SHGREP_REPL_EMISSION_DIAGNOSTICS=1 records LLVM IR snapshots of each cell's DLL (exception and RTTI
//   tables, initialized globals, aliases, symbol rebindings) and appends them to link failures and worker crash
//   reports. They exist to debug this executor, cost time on every cell and run to hundreds of kilobytes, so they
//   are off by default; errors then carry only the compiler's and linker's own messages.
bool emission_diagnostics_enabled() {
    wchar_t value[4];
    const DWORD length = GetEnvironmentVariableW(L"SHGREP_REPL_EMISSION_DIAGNOSTICS", value, 4);
    return length == 1 && value[0] == L'1';
}

bool coff_diagnostic_metadata(const llvm::GlobalValue& value) {
    auto name = value.getName();
    if (name.starts_with("\01")) name = name.drop_front();
    if (name.starts_with("_CT") || name.starts_with("_TI") ||
        name.starts_with("??_R")) return true;
    if (const auto* object = llvm::dyn_cast<llvm::GlobalObject>(&value))
        return object->hasSection() &&
            (object->getSection().starts_with(".xdata") ||
             object->getSection().starts_with(".pdata") ||
             object->getSection().starts_with(".CRT"));
    return false;
}

bool metadata(const llvm::GlobalValue& value) {
    const auto name = value.getName();
    if (name.starts_with("llvm.") || name.starts_with("??_") ||
        name.starts_with("\01??_")) return true;
    return coff_diagnostic_metadata(value);
}
void collect_names(clang::DeclContext* context, clang::ASTNameGenerator& generator,
                   std::set<std::string>& names) {
    if (context->isDependentContext()) return;
    for (auto* declaration : context->decls()) {
        if (declaration->isInvalidDecl()) continue;
        if (llvm::isa<clang::VarDecl, clang::FunctionDecl>(declaration)) {
            const auto* value = llvm::cast<clang::ValueDecl>(declaration);
            // Emitted external symbols already use the IR export/binding path.
            if (value->isExternallyVisible()) continue;
            if (value->getType().isNull() || value->getType()->isDependentType()) continue;
            if (const auto* function = llvm::dyn_cast<clang::FunctionDecl>(declaration);
                function && function->isDependentContext()) continue;
            // Persist the declaration's ordinary symbol. ABI variants and
            // thunks are handled by the existing emitted-IR export path.
            const auto name = generator.getName(declaration);
            if (!name.empty()) names.insert(symbol_name(name));
        } else if (auto* space = llvm::dyn_cast<clang::NamespaceDecl>(declaration))
            collect_names(space, generator, names);
        else if (auto* linkage = llvm::dyn_cast<clang::LinkageSpecDecl>(declaration))
            collect_names(linkage, generator, names);
        else if (auto* record = llvm::dyn_cast<clang::CXXRecordDecl>(declaration))
            if (record->isCompleteDefinition()) collect_names(record, generator, names);
    }
}

// Expand constant-expression operands before replacing a TLS address with a
// call. A PHI's operand must be evaluated on its incoming edge.
bool contains_tls(llvm::Value* value, const llvm::GlobalVariable* variable) {
    if (value == variable) return true;
    auto* expression = llvm::dyn_cast<llvm::ConstantExpr>(value);
    if (!expression) return false;
    for (const auto& operand : expression->operands())
        if (contains_tls(operand.get(), variable)) return true;
    return false;
}
llvm::Value* expand(llvm::Value* value, llvm::Instruction* before,
                    const llvm::GlobalVariable* variable) {
    auto* expression = llvm::dyn_cast<llvm::ConstantExpr>(value);
    if (!expression || !contains_tls(value, variable)) return value;
    auto* instruction = expression->getAsInstruction();
    instruction->insertBefore(before->getIterator());
    for (unsigned i = 0; i != instruction->getNumOperands(); ++i)
        instruction->setOperand(i, expand(instruction->getOperand(i), instruction, variable));
    return instruction;
}
void replace_tls(llvm::Module& module, llvm::GlobalVariable& variable, uintptr_t accessor) {
    llvm::removeFromUsedLists(module, [&](llvm::Constant* value) {
        return value->stripPointerCasts() == &variable;
    });
    std::vector<llvm::Instruction*> instructions;
    for (auto& function : module)
        for (auto& block : function)
            for (auto& instruction : block) instructions.push_back(&instruction);
    auto* type = llvm::FunctionType::get(variable.getType(), false);
    for (auto* instruction : instructions) {
        if (auto* phi = llvm::dyn_cast<llvm::PHINode>(instruction)) {
            for (unsigned i = 0; i != phi->getNumIncomingValues(); ++i) {
                auto* before = phi->getIncomingBlock(i)->getTerminator();
                auto* value = expand(phi->getIncomingValue(i), before, &variable);
                phi->setIncomingValue(i, value);
            }
        } else {
            for (unsigned i = 0; i != instruction->getNumOperands(); ++i)
                instruction->setOperand(i, expand(instruction->getOperand(i), instruction, &variable));
        }
    }
    variable.removeDeadConstantUsers();
    // Expansion may have inserted new instructions.
    std::map<llvm::Function*, llvm::DenseMap<llvm::BasicBlock*, llvm::ColorVector>> colors;
    std::vector<llvm::Use*> uses;
    for (auto& use : variable.uses()) uses.push_back(&use);
    for (auto* use : uses) {
        auto* instruction = llvm::dyn_cast<llvm::Instruction>(use->getUser());
        if (!instruction)
            throw std::runtime_error("native TLS address in an unsupported constant initializer: " +
                                     symbol_name(variable.getName()));
        llvm::Instruction* before = instruction;
        if (auto* phi = llvm::dyn_cast<llvm::PHINode>(instruction))
            before = phi->getIncomingBlock(use->getOperandNo())->getTerminator();
        llvm::IRBuilder<> builder(before);
        llvm::SmallVector<llvm::OperandBundleDef, 1> bundles;
        auto* function = before->getFunction();
        if (function->hasPersonalityFn() &&
            llvm::isFuncletEHPersonality(llvm::classifyEHPersonality(function->getPersonalityFn()))) {
            auto [coloring, inserted] = colors.try_emplace(function);
            if (inserted) coloring->second = llvm::colorEHFunclets(*function);
            const auto& block_colors = coloring->second[before->getParent()];
            if (block_colors.size() > 1)
                throw std::runtime_error("cannot insert a native TLS accessor in a shared exception funclet");
            if (!block_colors.empty()) {
                for (auto& candidate : *block_colors.front()) {
                    if (llvm::isa<llvm::PHINode>(candidate)) continue;
                    if (auto* pad = llvm::dyn_cast<llvm::FuncletPadInst>(&candidate))
                        bundles.emplace_back("funclet", std::vector<llvm::Value*>{pad});
                    break;
                }
            }
        }
        auto* call = builder.CreateCall(type,
            address(llvm::PointerType::getUnqual(module.getContext()), accessor), {}, bundles);
        if (auto* intrinsic = llvm::dyn_cast<llvm::IntrinsicInst>(instruction);
            intrinsic && intrinsic->getIntrinsicID() == llvm::Intrinsic::threadlocal_address) {
            intrinsic->replaceAllUsesWith(call);
            intrinsic->eraseFromParent();
        } else use->set(call);
    }
}

struct NativeTlsHooks {
    std::string array, original_rva, dispatch, drain, dtor_data;
};

NativeTlsHooks emit_tls_hooks(llvm::Module& module, const std::string& prefix) {
    NativeTlsHooks hooks{prefix + "tls_callbacks", prefix + "tls_original_rva",
                         prefix + "tls_dispatch", prefix + "tls_drain", prefix + "tls_dtor_data"};
    auto& context = module.getContext();
    auto* pointer = llvm::PointerType::getUnqual(context);
    auto* i8 = llvm::Type::getInt8Ty(context);
    auto* i32 = llvm::Type::getInt32Ty(context);
    auto* i64 = llvm::Type::getInt64Ty(context);
    auto* void_type = llvm::Type::getVoidTy(context);
    for (const auto* name : {&hooks.array, &hooks.original_rva, &hooks.dispatch, &hooks.drain})
        if (module.getNamedValue(*name)) throw std::runtime_error("reserved C++ TLS helper name: " + *name);
    auto* original = new llvm::GlobalVariable(module, i64, false, llvm::GlobalValue::ExternalLinkage,
        llvm::ConstantInt::get(i64, UINT64_MAX), hooks.original_rva);
    original->setDLLStorageClass(llvm::GlobalValue::DLLExportStorageClass);
    original->setExternallyInitialized(true);
    auto* drained = new llvm::GlobalVariable(module, i8, false, llvm::GlobalValue::PrivateLinkage,
        llvm::ConstantInt::get(i8, 0), prefix + "tls_drained");
    drained->setThreadLocalMode(llvm::GlobalVariable::GeneralDynamicTLSModel);
    auto* image = module.getNamedGlobal("__ImageBase");
    if (!image) image = new llvm::GlobalVariable(module, i8, false,
        llvm::GlobalValue::ExternalLinkage, nullptr, "__ImageBase");
    if (image->hasInitializer() || image->isThreadLocal())
        throw std::runtime_error("C++ cell overrides the native image-base symbol");
    auto* dtor = module.getNamedGlobal("__dyn_tls_dtor_callback");
    if (!dtor) dtor = new llvm::GlobalVariable(module, pointer, true,
        llvm::GlobalValue::ExternalLinkage, nullptr, "__dyn_tls_dtor_callback");
    if (dtor->hasInitializer() || dtor->getValueType() != pointer || dtor->isThreadLocal() ||
        dtor->hasDLLImportStorageClass())
        throw std::runtime_error("unsupported native CRT TLS destructor callback declaration");

    auto* callback_type = llvm::FunctionType::get(void_type, {pointer, i32, pointer}, false);
    auto* dispatch = llvm::Function::Create(callback_type, llvm::GlobalValue::ExternalLinkage,
                                             hooks.dispatch, module);
    dispatch->setDLLStorageClass(llvm::GlobalValue::DLLExportStorageClass);
    auto* entry = llvm::BasicBlock::Create(context, "entry", dispatch);
    auto* loop = llvm::BasicBlock::Create(context, "callbacks", dispatch);
    auto* choose = llvm::BasicBlock::Create(context, "choose", dispatch);
    auto* invoke = llvm::BasicBlock::Create(context, "invoke", dispatch);
    auto* next = llvm::BasicBlock::Create(context, "next", dispatch);
    auto* done = llvm::BasicBlock::Create(context, "done", dispatch);
    llvm::IRBuilder<> builder(entry);
    auto* offset = builder.CreateLoad(i64, original);
    offset->setVolatile(true); // the file preparer fills this before loading
    auto* start = builder.CreateIntToPtr(
        builder.CreateAdd(builder.CreatePtrToInt(image, i64), offset), pointer);
    auto* reason = dispatch->getArg(1);
    auto* detach = builder.CreateOr(
        builder.CreateICmpEQ(reason, builder.getInt32(DLL_THREAD_DETACH)),
        builder.CreateICmpEQ(reason, builder.getInt32(DLL_PROCESS_DETACH)));
    auto* native_dtor = builder.CreateLoad(pointer, dtor);
    builder.CreateBr(loop);
    builder.SetInsertPoint(loop);
    auto* cursor = builder.CreatePHI(pointer, 2);
    cursor->addIncoming(start, entry);
    auto* callback = builder.CreateLoad(pointer, cursor);
    builder.CreateCondBr(builder.CreateIsNull(callback), done, choose);
    builder.SetInsertPoint(choose);
    auto* skip_dtor = builder.CreateAnd(detach,
        builder.CreateICmpNE(builder.CreateLoad(i8, drained), builder.getInt8(0)));
    builder.CreateCondBr(builder.CreateAnd(skip_dtor, builder.CreateICmpEQ(callback, native_dtor)),
                         next, invoke);
    builder.SetInsertPoint(invoke);
    // Mark before invoking so recursive teardown cannot run this thread's CRT
    // destructor list twice. Other TLS callbacks are always forwarded normally.
    auto* is_dtor_detach = builder.CreateAnd(detach, builder.CreateICmpEQ(callback, native_dtor));
    builder.CreateStore(builder.CreateSelect(is_dtor_detach, builder.getInt8(1),
                                             builder.CreateLoad(i8, drained)), drained);
    builder.CreateCall(callback_type, callback,
                       {dispatch->getArg(0), reason, dispatch->getArg(2)});
    builder.CreateBr(next);
    builder.SetInsertPoint(next);
    auto* following = builder.CreateConstGEP1_64(pointer, cursor, 1);
    cursor->addIncoming(following, next);
    builder.CreateBr(loop);
    builder.SetInsertPoint(done);
    builder.CreateRetVoid();

    auto* drain = llvm::Function::Create(llvm::FunctionType::get(void_type, false),
        llvm::GlobalValue::ExternalLinkage, hooks.drain, module);
    drain->setDLLStorageClass(llvm::GlobalValue::DLLExportStorageClass);
    auto* drain_entry = llvm::BasicBlock::Create(context, "entry", drain);
    auto* drain_invoke = llvm::BasicBlock::Create(context, "drain", drain);
    auto* drain_done = llvm::BasicBlock::Create(context, "done", drain);
    builder.SetInsertPoint(drain_entry);
    builder.CreateCondBr(builder.CreateICmpEQ(builder.CreateLoad(i8, drained), builder.getInt8(0)),
                         drain_invoke, drain_done);
    builder.SetInsertPoint(drain_invoke);
    builder.CreateStore(builder.getInt8(1), drained);
    builder.CreateCall(callback_type, builder.CreateLoad(pointer, dtor),
        {image, builder.getInt32(DLL_THREAD_DETACH), llvm::ConstantPointerNull::get(pointer)});
    builder.CreateBr(drain_done);
    builder.SetInsertPoint(drain_done);
    builder.CreateRetVoid();

    auto* array_type = llvm::ArrayType::get(pointer, 2);
    auto* callbacks = new llvm::GlobalVariable(module, array_type, true,
        llvm::GlobalValue::ExternalLinkage,
        llvm::ConstantArray::get(array_type, {dispatch, llvm::ConstantPointerNull::get(pointer)}), hooks.array);
    callbacks->setDLLStorageClass(llvm::GlobalValue::DLLExportStorageClass);
    return hooks;
}

void coff_check(llvm::Error failure) {
    if (failure) throw std::runtime_error(llvm::toString(std::move(failure)));
}

// Change only our generated, unsigned image before LoadLibraryEx. Keep the TLS
// template/index and all original callback entries intact. The existing DIR64
// relocation on AddressOfCallBacks also relocates its replacement value.
void prepare_tls_image(const std::filesystem::path& path, const NativeTlsHooks& hooks) {
    std::vector<uint8_t> bytes;
    {
        auto input = llvm::MemoryBuffer::getFile(utf8(path), false, false);
        if (!input) throw std::system_error(input.getError(), "cannot read generated C++ DLL");
        auto parsed = llvm::object::COFFObjectFile::create((*input)->getMemBufferRef());
        if (!parsed) throw std::runtime_error(llvm::toString(parsed.takeError()));
        const auto& object = **parsed;
        const auto* header = object.getPE32PlusHeader();
        if (!header || object.getMachine() != llvm::COFF::IMAGE_FILE_MACHINE_AMD64)
            throw std::runtime_error("generated DLL is not a native x64 PE image");
        const auto* tls = object.getTLSDirectory64();
        const auto* tls_directory = object.getDataDirectory(llvm::COFF::TLS_TABLE);
        if (!tls || !tls_directory || tls_directory->Size < sizeof(*tls))
            throw std::runtime_error("generated DLL has no supported native x64 TLS directory");
        const uint64_t image_base = object.getImageBase();
        const uint64_t image_size = header->SizeOfImage;
        if (image_base > UINT64_MAX - image_size)
            throw std::runtime_error("generated DLL image range overflows");
        const auto source = (*input)->getBuffer();
        bytes.assign(reinterpret_cast<const uint8_t*>(source.data()),
                     reinterpret_cast<const uint8_t*>(source.data()) + source.size());
        auto file_offset = [&](const void* data, size_t size) -> size_t {
            const auto begin = reinterpret_cast<uintptr_t>(source.data());
            const auto at = reinterpret_cast<uintptr_t>(data);
            if (at < begin || at - begin > source.size() || size > source.size() - (at - begin))
                throw std::runtime_error("generated DLL field is not file-backed");
            return static_cast<size_t>(at - begin);
        };
        auto rva_offset = [&](uint32_t rva, uint32_t size) {
            if (rva >= image_size || size > image_size - rva)
                throw std::runtime_error("generated DLL RVA is outside its image");
            llvm::ArrayRef<uint8_t> contents;
            coff_check(object.getRvaAndSizeAsBytes(rva, size, contents));
            return file_offset(contents.data(), size);
        };
        auto export_rva = [&](const std::string& name) -> uint32_t {
            for (const auto& exported : object.export_directories()) {
                llvm::StringRef symbol;
                coff_check(exported.getSymbolName(symbol));
                if (symbol != name) continue;
                bool forwarded = false;
                coff_check(exported.isForwarder(forwarded));
                if (forwarded) throw std::runtime_error("forwarded native TLS helper export");
                uint32_t rva = 0;
                coff_check(exported.getExportRVA(rva));
                if (!rva) throw std::runtime_error("null native TLS helper export");
                return rva;
            }
            throw std::runtime_error("missing native TLS helper export: " + name);
        };
        auto executable = [&](uint32_t rva) {
            if (rva >= image_size) return false;
            for (const auto& section : object.sections()) {
                const auto* coff = object.getCOFFSection(section);
                const uint64_t start = coff->VirtualAddress;
                const uint64_t end = start + uint32_t(coff->VirtualSize);
                if (rva >= start && rva < end)
                    return (coff->Characteristics & llvm::COFF::IMAGE_SCN_MEM_EXECUTE) != 0;
            }
            return false;
        };
        auto image_rva = [&](uint64_t va) -> uint32_t {
            if (va < image_base || va - image_base >= image_size || va - image_base > UINT32_MAX)
                throw std::runtime_error("native TLS callback address is outside its DLL");
            return static_cast<uint32_t>(va - image_base);
        };
        const uint32_t callbacks = export_rva(hooks.array);
        const uint32_t original_field = export_rva(hooks.original_rva);
        const uint32_t dispatch = export_rva(hooks.dispatch);
        const uint32_t drain = export_rva(hooks.drain);
        const uint32_t dtor_field = export_rva(hooks.dtor_data);
        const auto callbacks_offset = rva_offset(callbacks, 16);
        const auto original_offset = rva_offset(original_field, 8);
        const uint64_t native_dtor = llvm::support::endian::read64le(
            bytes.data() + rva_offset(dtor_field, 8));
        if (!executable(image_rva(native_dtor)) || !executable(dispatch) || !executable(drain))
            throw std::runtime_error("native TLS teardown callback is not executable DLL code");
        if (llvm::support::endian::read64le(bytes.data() + callbacks_offset) != image_base + dispatch ||
            llvm::support::endian::read64le(bytes.data() + callbacks_offset + 8) != 0 ||
            llvm::support::endian::read64le(bytes.data() + original_offset) != UINT64_MAX)
            throw std::runtime_error("unexpected native TLS helper data layout");
        const uint32_t original_callbacks = image_rva(uint64_t(tls->AddressOfCallBacks));
        unsigned dtor_count = 0;
        bool terminated = false;
        std::set<uint32_t> original_entries;
        uint32_t original_terminator = 0;
        for (uint64_t i = 0; i != 4096; ++i) {
            const uint64_t rva = uint64_t(original_callbacks) + i * 8;
            if (rva > UINT32_MAX) throw std::runtime_error("native TLS callback array overflows");
            const uint64_t callback = llvm::support::endian::read64le(
                bytes.data() + rva_offset(static_cast<uint32_t>(rva), 8));
            if (!callback) {
                terminated = true;
                original_terminator = static_cast<uint32_t>(rva);
                break;
            }
            original_entries.insert(static_cast<uint32_t>(rva));
            if (!executable(image_rva(callback)))
                throw std::runtime_error("native TLS callback is not executable DLL code");
            if (callback == native_dtor) ++dtor_count;
        }
        if (!terminated || dtor_count != 1 || original_callbacks == callbacks)
            throw std::runtime_error("unsupported CRT TLS callback list; cannot guarantee ordered teardown");
        const uint64_t callback_field_wide = uint64_t(tls_directory->RelativeVirtualAddress) +
            offsetof(llvm::object::coff_tls_directory64, AddressOfCallBacks);
        if (callback_field_wide > UINT32_MAX)
            throw std::runtime_error("native TLS directory address overflows");
        const uint32_t callback_field = static_cast<uint32_t>(callback_field_wide);
        std::set<uint32_t> required_relocations{callback_field, callbacks, dtor_field};
        required_relocations.insert(original_entries.begin(), original_entries.end());
        const auto pointer_fields = required_relocations;
        std::set<uint32_t> seen_relocations;
        for (const auto& relocation : object.base_relocs()) {
            uint8_t type = 0;
            uint32_t rva = 0;
            coff_check(relocation.getType(type));
            coff_check(relocation.getRVA(rva));
            if (type == llvm::COFF::IMAGE_REL_BASED_ABSOLUTE) continue;
            if (type != llvm::COFF::IMAGE_REL_BASED_DIR64 || uint64_t(rva) + 8 > image_size ||
                !seen_relocations.insert(rva).second)
                throw std::runtime_error("unsupported or duplicate native x64 base relocation");
            auto overlaps = [&](uint64_t field) {
                return uint64_t(rva) < field + 8 && field < uint64_t(rva) + 8;
            };
            if (overlaps(original_field) || overlaps(uint64_t(callbacks) + 8) ||
                overlaps(original_terminator))
                throw std::runtime_error("non-pointer TLS helper data has a base relocation");
            for (auto field : pointer_fields)
                if (rva != field && overlaps(field))
                    throw std::runtime_error("overlapping native TLS pointer relocation");
            required_relocations.erase(rva);
        }
        if (!required_relocations.empty())
            throw std::runtime_error("native TLS image lacks required ASLR relocations");
        const auto callback_offset = rva_offset(callback_field, 8);
        if (callback_offset != file_offset(&tls->AddressOfCallBacks, 8))
            throw std::runtime_error("inconsistent native TLS directory mapping");
        llvm::support::endian::write64le(bytes.data() + original_offset, original_callbacks);
        llvm::support::endian::write64le(bytes.data() + callback_offset, image_base + callbacks);
        // Generated user-mode DLLs are unsigned; leave the optional checksum unset.
        llvm::support::endian::write32le(bytes.data() + file_offset(&header->CheckSum, 4), 0);
    } // release the file mapping before replacing it on Windows
    auto temporary = path;
    temporary += L".tls.tmp";
    {
        std::error_code ec;
        llvm::raw_fd_ostream output(utf8(temporary), ec, llvm::sys::fs::OF_None);
        if (ec) throw std::system_error(ec, "cannot prepare native TLS image");
        output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        output.flush();
        if (output.has_error()) {
            const auto failure = output.error();
            output.clear_error();
            throw std::system_error(failure, "cannot write prepared native TLS image");
        }
    }
    if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        throw std::runtime_error("cannot replace prepared C++ DLL (Windows error " +
                                 std::to_string(GetLastError()) + ")");
}
} // namespace

struct shgrep::DllExecutor::Impl {
    struct Symbol { uintptr_t value; bool tls; };
    struct Module {
        HMODULE handle = nullptr;
        void (*initialize)() = nullptr;
        void (*drain_tls)() = nullptr;
        bool tls_drained = false;
        enum { pending, running, complete } state = pending;
    };
    clang::CompilerInstance& compiler;
    std::filesystem::path directory;
    std::vector<std::filesystem::path> library_directories;
    std::unique_ptr<llvm::TargetMachine> machine;
    std::map<std::string, Symbol> symbols;
    std::deque<Module> modules;
    std::vector<HMODULE> external_modules;
    std::mutex dtor_mutex;
    std::vector<void (*)()> destructors;
    bool cleaned = false, broken = false;
    uint64_t next_module = 0;
    DWORD execution_thread = GetCurrentThreadId();
    const void* bridge;
    HMODULE compiler_module = nullptr;
    void (*bootstrap_phase)(const char*) = nullptr;
    std::string emission_diagnostics;
    const bool record_emission = emission_diagnostics_enabled();

    void capture_emission(const char* stage, const llvm::Module& module) noexcept {
        if (!record_emission) return;
        try {
            BoundedDiagnosticStream out(emission_diagnostics);
            out << "\n--- " << stage << " ---\n";
            // Preserve the native exception/RTTI tables before ordinary globals
            // consume the bounded section.
            for (const auto& global : module.globals()) {
                if (out.full()) break;
                if (coff_diagnostic_metadata(global)) { global.print(out); out << '\n'; }
            }
            for (const auto& function : module) {
                if (out.full()) break;
                if (!function.hasPersonalityFn()) continue;
                out << "personality ";
                function.printAsOperand(out, false, &module);
                out << " = ";
                function.getPersonalityFn()->printAsOperand(out, true, &module);
                out << '\n';
            }
            for (const auto& global : module.globals()) {
                if (out.full()) break;
                if (global.hasInitializer() && !coff_diagnostic_metadata(global)) {
                    global.print(out);
                    out << '\n';
                }
            }
            for (const auto& alias : module.aliases()) {
                if (out.full()) break;
                alias.print(out);
                out << '\n';
            }
            out.finish();
        } catch (...) {
            // A best-effort snapshot must not change the cell's behavior.
        }
    }

    void capture_bindings(llvm::Module& module,
                          const std::map<llvm::GlobalValue*, Symbol>& bindings,
                          const std::set<llvm::GlobalValue*>& image_relative_targets) noexcept {
        if (!record_emission) return;
        try {
            BoundedDiagnosticStream out(emission_diagnostics);
            out << "\n--- symbol rebindings ---\n";
            for (const auto& [value, binding] : bindings) {
                if (out.full()) break;
                value->printAsOperand(out, true, &module);
                out << (binding.tls ? " -> TLS accessor " : " -> absolute address ")
                    << static_cast<uint64_t>(binding.value) << '\n';
                for (const auto* user : value->users()) {
                    if (out.full()) break;
                    if (llvm::isa<llvm::Instruction>(user)) continue;
                    out << "  constant/global user: ";
                    user->printAsOperand(out, true, &module);
                    out << '\n';
                }
            }
            out.finish();

            BoundedDiagnosticStream functions(emission_diagnostics);
            functions << "\n--- function binding decisions ---\n";
            // Destructors and unresolved declarations precede ordinary
            // definitions so a large standard-library cell cannot hide them.
            for (unsigned pass = 0; pass != 3; ++pass) {
                for (auto& function : module) {
                    if (functions.full()) break;
                    const auto key = symbol_name(function.getName());
                    const unsigned priority = key.starts_with("??1") ? 0 :
                        (function.isDeclarationForLinker() ? 1 : 2);
                    if (priority != pass) continue;
                    function.printAsOperand(functions, true, &module);
                    functions << " type=";
                    function.getFunctionType()->print(functions);
                    functions << " body=" << !function.isDeclaration()
                        << " declaration_for_linker=" << function.isDeclarationForLinker()
                        << " linkage=" << static_cast<unsigned>(function.getLinkage())
                        << " prior_owner=" << symbols.contains(key)
                        << " metadata=" << metadata(function)
                        << " image_relative=" << image_relative_targets.contains(&function)
                        << " decision=";
                    if (bindings.contains(&function)) functions << "rebind";
                    else if (image_relative_targets.contains(&function))
                        functions << "retain-image-relative";
                    else if (metadata(function)) functions << "retain-metadata";
                    else if (function.isDeclarationForLinker()) functions << "linker-declaration";
                    else functions << "local-definition";
                    functions << '\n';
                }
                if (functions.full()) break;
            }
            functions.finish();
        } catch (...) {
            // Diagnostics do not participate in binding or validation.
        }
    }

    void phase(const char* name) const {
        if (bootstrap_phase) bootstrap_phase(name);
    }

    Impl(clang::CompilerInstance& ci, std::filesystem::path dir,
         std::vector<std::filesystem::path> libraries, const void* callback,
         void (*phase_callback)(const char*))
        : compiler(ci), directory(std::move(dir)), library_directories(std::move(libraries)),
          bridge(callback), bootstrap_phase(phase_callback) {
        if (!directory.is_absolute() || !std::filesystem::is_directory(directory))
            throw std::runtime_error("C++ worker requires its parent's private session directory");
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(bridge), &compiler_module))
            throw std::runtime_error("cannot locate the loaded compiler backend");
        auto builder = llvm::orc::JITTargetMachineBuilder::detectHost();
        if (!builder) throw std::runtime_error(llvm::toString(builder.takeError()));
        builder->getOptions().EmulatedTLS = false;
        builder->setRelocationModel(llvm::Reloc::PIC_);
        auto target = builder->createTargetMachine();
        if (!target) throw std::runtime_error(llvm::toString(target.takeError()));
        machine = std::move(*target);
    }
    static int register_destructor(Impl* self, void (*callback)()) noexcept {
        try {
            std::lock_guard lock(self->dtor_mutex);
            if (self->cleaned) return -1;
            self->destructors.push_back(callback);
            return 0;
        } catch (...) { return -1; }
    }
    void redirect_atexit(llvm::Module& module) {
        auto* original = module.getFunction("atexit");
        if (!original || !original->isDeclaration()) return;
        auto* type = original->getFunctionType();
        if (type->getNumParams() != 1 || !type->getReturnType()->isIntegerTy(32))
            throw std::runtime_error("unsupported atexit signature in C++ cell");
        auto* shim = llvm::Function::Create(type, llvm::GlobalValue::InternalLinkage,
                                             "__shgrep_atexit", module);
        llvm::IRBuilder<> builder(llvm::BasicBlock::Create(module.getContext(), "entry", shim));
        auto* pointer = llvm::PointerType::getUnqual(module.getContext());
        auto* host_type = llvm::FunctionType::get(builder.getInt32Ty(), {pointer, pointer}, false);
        auto* result = builder.CreateCall(host_type, address(pointer,
            reinterpret_cast<uintptr_t>(&register_destructor)),
            {address(pointer, reinterpret_cast<uintptr_t>(this)), shim->getArg(0)});
        builder.CreateRet(result);
        original->replaceAllUsesWith(shim);
        original->eraseFromParent();
    }

    std::map<std::string, Symbol> bind_existing(
        llvm::Module& module, const std::set<std::string>& persistent) {
        std::map<llvm::GlobalValue*, Symbol> bindings;
        std::vector<llvm::GlobalAlias*> aliases;

        // COFF image-relative constants need named targets in this image.
        // Replacing A in A - __ImageBase with an integer loses the additive
        // relocation symbol, even though the resulting IR still verifies.
        std::set<llvm::GlobalValue*> image_relative_targets;
        std::function<void(llvm::Constant*)> retain_targets;
        retain_targets = [&](llvm::Constant* constant) {
            if (auto* global = llvm::dyn_cast<llvm::GlobalValue>(constant)) {
                if (!image_relative_targets.insert(global).second) return;
                if (auto* alias = llvm::dyn_cast<llvm::GlobalAlias>(global))
                    retain_targets(alias->getAliasee());
                return;
            }
            for (const auto& operand : constant->operands())
                if (auto* nested = llvm::dyn_cast<llvm::Constant>(operand.get()))
                    retain_targets(nested);
        };
        std::function<bool(llvm::Constant*)> contains_image_base;
        contains_image_base = [&](llvm::Constant* constant) {
            if (auto* global = llvm::dyn_cast<llvm::GlobalValue>(constant))
                return symbol_name(global->getName()) == "__ImageBase";
            for (const auto& operand : constant->operands())
                if (auto* nested = llvm::dyn_cast<llvm::Constant>(operand.get());
                    nested && contains_image_base(nested)) return true;
            return false;
        };
        std::set<llvm::Constant*> scanned_constants;
        std::function<void(llvm::Constant*)> inspect_relocations;
        inspect_relocations = [&](llvm::Constant* constant) {
            if (llvm::isa<llvm::GlobalValue>(constant) ||
                !scanned_constants.insert(constant).second) return;
            if (auto* expression = llvm::dyn_cast<llvm::ConstantExpr>(constant);
                expression && expression->getOpcode() == llvm::Instruction::Sub &&
                contains_image_base(llvm::cast<llvm::Constant>(expression->getOperand(1))))
                retain_targets(llvm::cast<llvm::Constant>(expression->getOperand(0)));
            for (const auto& operand : constant->operands())
                if (auto* nested = llvm::dyn_cast<llvm::Constant>(operand.get()))
                    inspect_relocations(nested);
        };
        for (auto& global : module.globals())
            if (global.hasInitializer()) inspect_relocations(global.getInitializer());
        auto bind = [&](llvm::GlobalValue& value, Symbol symbol) {
            if (image_relative_targets.contains(&value)) {
                if (value.isDeclarationForLinker())
                    throw std::runtime_error(
                        "cannot bind a COFF image-relative target without a local definition: " +
                        symbol_name(value.getName()));
                if (auto* variable = llvm::dyn_cast<llvm::GlobalVariable>(&value);
                    variable && variable->isThreadLocal())
                    throw std::runtime_error("unsupported image-relative native TLS target: " +
                                             symbol_name(value.getName()));
                return;
            }
            bindings.emplace(&value, symbol);
        };
        auto publish = [&](const llvm::GlobalValue& value) {
            return !metadata(value) &&
                (!value.hasLocalLinkage() || persistent.contains(symbol_name(value.getName())));
        };
        auto locate = [&](llvm::GlobalValue& value) {
            if (value.getName().starts_with("llvm.")) return;
            const auto key = symbol_name(value.getName());
            auto owner = symbols.find(key);
            if (!metadata(value) && owner != symbols.end() &&
                (publish(value) || value.isDeclaration())) {
                bind(value, owner->second);
                return;
            }
            if (!value.isDeclarationForLinker()) return;
            FARPROC host = nullptr;
            if (key == "shgrep_cpp_bridge")
                host = reinterpret_cast<FARPROC>(const_cast<void*>(bridge));
            else if (key.starts_with("__clang_Interpreter_") ||
                     key.find("__clang_Interpreter_NewTag") != std::string::npos)
                host = GetProcAddress(compiler_module, key.c_str());
            if (!host) for (auto external : external_modules) {
                host = GetProcAddress(external, key.c_str());
                if (host) break;
            }
            if (host) {
                if (auto* variable = llvm::dyn_cast<llvm::GlobalVariable>(&value);
                    variable && variable->isThreadLocal())
                    throw std::runtime_error("cannot bind native TLS to an ordinary DLL address: " + key);
                bind(value, Symbol{reinterpret_cast<uintptr_t>(host), false});
            }
        };
        for (auto& function : module) locate(function);
        for (auto& variable : module.globals()) locate(variable);
        for (auto& alias : module.aliases()) {
            aliases.push_back(&alias);
            locate(alias);
        }

        std::function<bool(llvm::Value*, std::set<llvm::Value*>&)> touches_binding;
        touches_binding = [&](llvm::Value* value, std::set<llvm::Value*>& visited) {
            if (auto* global = llvm::dyn_cast<llvm::GlobalValue>(value); global && bindings.contains(global))
                return true;
            if (!visited.insert(value).second) return false;
            if (auto* alias = llvm::dyn_cast<llvm::GlobalAlias>(value))
                return touches_binding(alias->getAliasee(), visited);
            if (auto* expression = llvm::dyn_cast<llvm::ConstantExpr>(value))
                for (const auto& operand : expression->operands())
                    if (touches_binding(operand.get(), visited)) return true;
            return false;
        };
        std::set<llvm::GlobalAlias*> visiting;
        std::function<std::optional<Symbol>(llvm::GlobalAlias*)> resolve_alias;
        resolve_alias = [&](llvm::GlobalAlias* alias) -> std::optional<Symbol> {
            if (alias->getAddressSpace() != 0) {
                std::set<llvm::Value*> visited;
                if (bindings.contains(alias) || touches_binding(alias->getAliasee(), visited))
                    throw std::runtime_error("unsupported C++ alias address space");
                return std::nullopt;
            }
            if (auto found = bindings.find(alias); found != bindings.end()) return found->second;
            if (!visiting.insert(alias).second)
                throw std::runtime_error("cyclic C++ alias: " + symbol_name(alias->getName()));
            llvm::APInt offset(64, 0);
            auto* base = alias->getAliasee()->stripAndAccumulateConstantOffsets(
                module.getDataLayout(), offset, true);
            std::optional<Symbol> resolved;
            if (auto* nested = llvm::dyn_cast<llvm::GlobalAlias>(base))
                resolved = resolve_alias(nested);
            else if (auto* global = llvm::dyn_cast<llvm::GlobalValue>(base)) {
                if (auto found = bindings.find(global); found != bindings.end()) resolved = found->second;
            }
            visiting.erase(alias);
            if (!resolved) {
                std::set<llvm::Value*> visited;
                if (touches_binding(alias->getAliasee(), visited))
                    throw std::runtime_error("unsupported C++ alias address expression: " +
                                             symbol_name(alias->getName()));
                return std::nullopt;
            }
            if (resolved->tls)
                throw std::runtime_error("native TLS aliases require an owner accessor: " +
                                         symbol_name(alias->getName()));
            if (offset.isNegative()) {
                const uint64_t magnitude = (-offset).getZExtValue();
                if (magnitude > resolved->value) throw std::runtime_error("C++ alias address underflow");
                resolved->value -= magnitude;
            } else {
                const uint64_t amount = offset.getZExtValue();
                if (amount > UINTPTR_MAX - resolved->value) throw std::runtime_error("C++ alias address overflow");
                resolved->value += amount;
            }
            bindings.emplace(alias, *resolved);
            return resolved;
        };
        std::map<std::string, Symbol> inherited_aliases;
        for (auto* alias : aliases) {
            auto resolved = resolve_alias(alias);
            if (!resolved) continue;
            if (resolved->tls)
                throw std::runtime_error("unsupported native TLS alias: " + symbol_name(alias->getName()));
            if (publish(*alias)) inherited_aliases.emplace(symbol_name(alias->getName()), *resolved);
        }

        capture_emission("before rebinding", module);
        capture_bindings(module, bindings, image_relative_targets);

        // Bookkeeping refers to GlobalValues, not absolute integer addresses.
        // The original definitions are already retained in their owning images.
        llvm::removeFromUsedLists(module, [&](llvm::Constant* value) {
            auto* global = llvm::dyn_cast<llvm::GlobalValue>(value->stripPointerCasts());
            return global && bindings.contains(global);
        });
        for (const auto& [value, binding] : bindings)
            for (auto* user : value->users())
                if (llvm::isa<llvm::BlockAddress>(user))
                    throw std::runtime_error("cannot bind a C++ function with a block-address use: " +
                                             symbol_name(value->getName()));

        // Resolve aliases first, while every aliasee and its offsets are still
        // available. No alias whose target becomes a numeric address is exported.
        for (auto* alias : aliases)
            if (auto found = bindings.find(alias); found != bindings.end())
                alias->replaceAllUsesWith(address(alias->getType(), found->second.value));
        for (const auto& [value, binding] : bindings) {
            if (llvm::isa<llvm::GlobalAlias>(value)) continue;
            if (binding.tls) {
                auto* variable = llvm::dyn_cast<llvm::GlobalVariable>(value);
                if (!variable || !variable->isThreadLocal())
                    throw std::runtime_error("inconsistent native TLS declaration: " + symbol_name(value->getName()));
                replace_tls(module, *variable, binding.value);
            } else value->replaceAllUsesWith(address(value->getType(), binding.value));
        }
        for (const auto& [value, binding] : bindings) {
            (void)binding;
            if (auto* function = llvm::dyn_cast<llvm::Function>(value)) function->deleteBody();
            else if (auto* variable = llvm::dyn_cast<llvm::GlobalVariable>(value)) variable->setInitializer(nullptr);
        }
        for (const auto& [value, binding] : bindings) {
            (void)binding;
            value->removeDeadConstantUsers();
            if (!value->use_empty())
                throw std::runtime_error("cannot preserve the existing definition of " + symbol_name(value->getName()));
            value->eraseFromParent();
        }
        capture_emission("after rebinding", module);
        return inherited_aliases;
    }

    llvm::Error add(clang::PartialTranslationUnit& unit) {
        if (broken || cleaned) return error("C++ DLL executor is no longer usable");
        auto module = std::move(unit.TheModule);
        if (!module) return error("C++ cell has no LLVM module");
        const auto id = ++next_module;
        emission_diagnostics.clear();
        const std::string prefix = "__shgrep_" + std::to_string(id) + "_";
        module->setDataLayout(machine->createDataLayout());
        phase("collecting bootstrap symbol names");
        std::set<std::string> persistent;
        if (unit.TUPart) {
            clang::ASTNameGenerator generator(compiler.getASTContext());
            collect_names(unit.TUPart, generator, persistent);
        }
        phase("binding bootstrap symbols");
        redirect_atexit(*module);
        auto inherited_aliases = bind_existing(*module, persistent);
        phase("preparing bootstrap exports");
        struct Export { std::string key, name; bool tls; bool publish; };
        std::vector<Export> exports;
        std::vector<llvm::GlobalValue*> values;
        for (auto& function : *module) values.push_back(&function);
        for (auto& global : module->globals()) values.push_back(&global);
        for (auto& alias : module->aliases()) values.push_back(&alias);
        for (auto* value : values) {
            const auto key = symbol_name(value->getName());
            if (value->getName().starts_with("llvm.")) continue;
            const bool is_metadata = metadata(*value);
            const bool publish = !is_metadata &&
                (!value->hasLocalLinkage() || persistent.contains(key));
            if (value->isDeclarationForLinker()) continue;
            if (auto* global = llvm::dyn_cast<llvm::GlobalVariable>(value);
                global && global->isThreadLocal()) {
                auto* accessor_type = llvm::FunctionType::get(global->getType(), false);
                const std::string export_name = prefix + "tls_" + std::to_string(exports.size());
                auto* accessor = llvm::Function::Create(accessor_type, llvm::GlobalValue::ExternalLinkage,
                                                        export_name, *module);
                accessor->setDLLStorageClass(llvm::GlobalValue::DLLExportStorageClass);
                llvm::IRBuilder<> builder(llvm::BasicBlock::Create(module->getContext(), "entry", accessor));
                // The owning image's TLS guard and initializer must be used,
                // including on threads which existed before this DLL loaded.
                if (module->getNamedGlobal("__tls_guard") || module->getFunction("__dyn_tls_on_demand_init")) {
                    auto init = module->getOrInsertFunction("__dyn_tls_on_demand_init",
                                                            builder.getVoidTy());
                    builder.CreateCall(init);
                }
                builder.CreateRet(global);
                exports.push_back({key, export_name, true, publish});
            } else if (!is_metadata || llvm::isa<llvm::Function>(value)) {
                const std::string export_name = prefix + "symbol_" + std::to_string(exports.size());
                // A separate exported alias preserves the original linkage and
                // COMDAT selection of inline functions, statics and templates.
                auto* alias = llvm::GlobalAlias::create(llvm::GlobalValue::ExternalLinkage,
                                                        export_name, value);
                alias->setDLLStorageClass(llvm::GlobalValue::DLLExportStorageClass);
                exports.push_back({key, export_name, false, publish});
            }
        }

        phase("building bootstrap TLS hooks");
        const auto tls_hooks = emit_tls_hooks(*module, prefix);

        // Clang's cell statements are global constructors. Run them explicitly
        // after LoadLibraryEx releases the loader lock.
        phase("building bootstrap constructors");
        std::vector<std::pair<uint64_t, llvm::Constant*>> constructors;
        if (auto* list = module->getNamedGlobal("llvm.global_ctors")) {
            if (list->hasInitializer()) {
                auto* entries = llvm::dyn_cast<llvm::ConstantArray>(list->getInitializer());
                if (!entries && !list->getInitializer()->isNullValue())
                    throw std::runtime_error("unsupported C++ constructor table");
                if (entries) for (const auto& operand : entries->operands()) {
                    auto* entry = llvm::cast<llvm::ConstantStruct>(operand.get());
                    auto* function = llvm::cast<llvm::Constant>(entry->getOperand(1));
                    if (!function->isNullValue())
                        constructors.emplace_back(llvm::cast<llvm::ConstantInt>(entry->getOperand(0))->getZExtValue(),
                                                   function);
                }
            }
            list->eraseFromParent();
        }
        std::stable_sort(constructors.begin(), constructors.end(),
                         [](const auto& a, const auto& b) { return a.first < b.first; });
        const std::string initialize_name = prefix + "initialize";
        auto* initialize_type = llvm::FunctionType::get(llvm::Type::getVoidTy(module->getContext()), false);
        auto* initialize = llvm::Function::Create(initialize_type, llvm::GlobalValue::ExternalLinkage,
                                                  initialize_name, *module);
        initialize->setDLLStorageClass(llvm::GlobalValue::DLLExportStorageClass);
        llvm::IRBuilder<> builder(llvm::BasicBlock::Create(module->getContext(), "entry", initialize));
        for (const auto& [priority, function] : constructors) {
            (void)priority;
            builder.CreateCall(initialize_type, function);
        }
        builder.CreateRetVoid();
        phase("verifying bootstrap LLVM module");
        std::string diagnostics;
        llvm::raw_string_ostream diagnostic_stream(diagnostics);
        if (llvm::verifyModule(*module, &diagnostic_stream))
            throw std::runtime_error("invalid C++ DLL module: " + diagnostics);
        bool needs_tls = false;
        for (const auto& global : module->globals())
            if (global.isThreadLocal() && (!global.use_empty() || global.hasInitializer()))
                needs_tls = true;
        const auto object_path = directory / (std::to_wstring(id) + L".obj");
        const auto dll_path = directory / (std::to_wstring(id) + L".dll");
        std::error_code ec;
        {
            phase("creating bootstrap object");
            llvm::raw_fd_ostream object(utf8(object_path), ec, llvm::sys::fs::OF_None);
            if (ec) throw std::system_error(ec, "cannot create C++ session object");
            capture_emission("before object emission", *module);
            phase("generating bootstrap machine code");
            llvm::legacy::PassManager passes;
            if (machine->addPassesToEmitFile(passes, object, nullptr, llvm::CodeGenFileType::ObjectFile, false))
                throw std::runtime_error("LLVM cannot emit Windows objects");
            passes.run(*module);
            object.flush();
            if (object.has_error()) {
                auto failure = object.error();
                object.clear_error();
                throw std::system_error(failure, "cannot write C++ session object");
            }
        }
        std::vector<std::string> arguments{
            "lld-link", "/dll", "/machine:x64", "/subsystem:console", "/incremental:no",
            "/debug:none", "/manifest:no", "/noimplib",
            "/out:" + utf8(dll_path), utf8(object_path)};
        if (needs_tls) arguments.push_back("/include:_tls_used");
        arguments.push_back("/export:" + tls_hooks.dtor_data + "=__dyn_tls_dtor_callback,DATA");
        for (const auto& path : library_directories) arguments.push_back("/libpath:" + utf8(path));
        // Native TLS startup remains linked into each DLL; the main runtime
        // implementations are shared DLLs installed with the VC Redistributable.
        for (const char* library : {"msvcrt.lib", "msvcprt.lib", "vcruntime.lib", "ucrt.lib",
                                    "oldnames.lib", "kernel32.lib"})
            arguments.emplace_back(library);
        std::vector<const char*> argv;
        for (const auto& argument : arguments) argv.push_back(argument.c_str());
        std::string out, err;
        llvm::raw_string_ostream out_stream(out), err_stream(err);
        const lld::DriverDef driver{lld::WinLink, &lld::coff::link};
        phase("linking bootstrap DLL");
        const auto linked = lld::lldMain(argv, out_stream, err_stream, {driver});
        if (!linked.canRunAgain || linked.retCode) {
            std::string failure = !linked.canRunAgain
                ? "LLD cannot safely continue; reset the C++ session: " + err + out
                : "cannot link C++ cell DLL: " + err + out;
            if (!emission_diagnostics.empty())
                failure += "\nNative emission context:\n" + emission_diagnostics;
            throw std::runtime_error(failure);
        }
        phase("preparing bootstrap native TLS image");
        prepare_tls_image(dll_path, tls_hooks);
        phase("loading bootstrap DLL");
        HMODULE handle = LoadLibraryExW(dll_path.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (!handle)
            throw std::runtime_error("cannot load C++ cell DLL; check the matching x64 VC++ Redistributable "
                                     "(Windows error " + std::to_string(GetLastError()) + ")");
        // Pin successful loads until the worker exits. A returned Value can
        // compile another PTU while this module's initializer is still active.
        phase("resolving bootstrap DLL exports");
        modules.push_back({handle});
        auto& loaded = modules.back();
        loaded.initialize = reinterpret_cast<void (*)()>(GetProcAddress(handle, initialize_name.c_str()));
        loaded.drain_tls = reinterpret_cast<void (*)()>(GetProcAddress(handle, tls_hooks.drain.c_str()));
        if (!loaded.initialize || !loaded.drain_tls)
            throw std::runtime_error("missing C++ cell initialization/teardown export");
        for (const auto& exported : exports) {
            auto pointer = GetProcAddress(handle, exported.name.c_str());
            if (!pointer) throw std::runtime_error("missing C++ cell export: " + exported.key);
            if (exported.publish)
                symbols.try_emplace(exported.key, Symbol{reinterpret_cast<uintptr_t>(pointer), exported.tls});
        }
        for (const auto& [key, binding] : inherited_aliases) symbols.try_emplace(key, binding);
        return llvm::Error::success();
    }
};

shgrep::DllExecutor::DllExecutor(clang::CompilerInstance& compiler, std::filesystem::path directory,
    std::vector<std::filesystem::path> libraries, const void* bridge,
    void (*bootstrap_phase)(const char*))
    : impl_(std::make_unique<Impl>(compiler, std::move(directory), std::move(libraries),
                                   bridge, bootstrap_phase)) {}
void shgrep::DllExecutor::finishBootstrap() noexcept { impl_->bootstrap_phase = nullptr; }
shgrep::DllExecutor::~DllExecutor() {
    // Native TLS callbacks on remaining worker threads can execute until
    // process exit. Their atexit shims retain Impl and their code retains the mappings.
    // Both are reclaimed by process exit, never by per-cell unloading.
    (void)impl_.release();
}
bool shgrep::DllExecutor::failed() const noexcept { return impl_->broken; }
const std::string& shgrep::DllExecutor::emissionDiagnostics() const noexcept {
    return impl_->emission_diagnostics;
}
llvm::Error shgrep::DllExecutor::addModule(clang::PartialTranslationUnit& unit) {
    try { return impl_->add(unit); }
    catch (const std::exception& failure) { impl_->broken = true; return error(failure.what()); }
    catch (...) { impl_->broken = true; return error("native failure while linking/loading a C++ cell"); }
}
llvm::Error shgrep::DllExecutor::removeModule(clang::PartialTranslationUnit&) {
    // Removing an executed module could invalidate escaped pointers or native
    // TLS destructors. The facade resets the complete worker for s.clear().
    return error("individual DLL cells cannot be unloaded; clear the complete C++ session");
}
llvm::Error shgrep::DllExecutor::runCtors() const {
    try {
        for (size_t i = 0; i < impl_->modules.size(); ++i) {
            auto& module = impl_->modules[i];
            if (module.state != Impl::Module::pending) continue;
            module.state = Impl::Module::running;
            impl_->phase("running bootstrap DLL constructors");
            module.initialize();
            module.state = Impl::Module::complete;
        }
        return llvm::Error::success();
    } catch (const std::exception& failure) {
        impl_->broken = true;
        return error(std::string("C++ cell initialization failed; session must reset: ") + failure.what());
    } catch (...) {
        impl_->broken = true;
        return error("C++ cell initialization threw; session must reset");
    }
}
llvm::Error shgrep::DllExecutor::cleanUp() {
    if (GetCurrentThreadId() != impl_->execution_thread)
        return error("C++ cleanup must run on its execution thread");
    if (impl_->cleaned) return llvm::Error::success();
    // Native TLS destructors run before globals, on their owning thread and
    // outside the Windows loader lock. Retained images preserve callback code.
    try {
        for (size_t i = impl_->modules.size(); i != 0; --i) {
            auto& module = impl_->modules[i - 1];
            if (module.tls_drained) continue;
            if (!module.drain_tls) throw std::runtime_error("missing native TLS teardown entry point");
            module.tls_drained = true;
            module.drain_tls();
        }
    } catch (...) {
        std::lock_guard lock(impl_->dtor_mutex);
        impl_->broken = true;
        impl_->cleaned = true;
        return error("native TLS destructor failed during C++ shutdown");
    }
    for (;;) {
        void (*callback)() = nullptr;
        {
            std::lock_guard lock(impl_->dtor_mutex);
            if (impl_->cleaned) return llvm::Error::success();
            if (impl_->destructors.empty()) {
                impl_->cleaned = true;
                return llvm::Error::success();
            }
            callback = impl_->destructors.back();
            impl_->destructors.pop_back();
        }
        try { callback(); }
        catch (...) {
            std::lock_guard lock(impl_->dtor_mutex);
            impl_->cleaned = true;
            impl_->broken = true;
            return error("C++ session destructor threw during shutdown");
        }
    }
}
llvm::Expected<llvm::orc::ExecutorAddr> shgrep::DllExecutor::getSymbolAddress(
    llvm::StringRef name, SymbolNameKind) const {
    const auto key = symbol_name(name);
    auto found = impl_->symbols.find(key);
    if (found != impl_->symbols.end()) {
        if (found->second.tls) return error("a TLS variable requires its owner accessor: " + key);
        return llvm::orc::ExecutorAddr(found->second.value);
    }
    for (auto module : impl_->external_modules)
        if (auto pointer = GetProcAddress(module, key.c_str()))
            return llvm::orc::ExecutorAddr(reinterpret_cast<uintptr_t>(pointer));
    return error("C++ DLL symbol is unavailable: " + key);
}
llvm::Error shgrep::DllExecutor::LoadDynamicLibrary(const char* name) {
    if (!name || !*name) return error("dynamic library path is empty");
    try {
        auto path = std::filesystem::u8path(name);
        DWORD flags = LOAD_LIBRARY_SEARCH_DEFAULT_DIRS;
        if (path.has_parent_path()) {
            path = std::filesystem::absolute(path);
            flags |= LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR;
        }
        HMODULE module = LoadLibraryExW(path.c_str(), nullptr, flags);
        if (!module) return error("cannot load C++ dynamic library (Windows error " +
                                  std::to_string(GetLastError()) + ")");
        // Loaded libraries, like cell images, are pinned until worker exit.
        impl_->external_modules.push_back(module);
        return llvm::Error::success();
    } catch (const std::exception& failure) { return error(failure.what()); }
}
