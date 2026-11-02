module;
#include <memory>
#include <string>
#include <span>
#include <mutex>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>

module sba.lift;

import sba.arch;
import sba.binary;
import :decode;
import :target;
import :parse;

namespace SBA::Lift {

    constexpr auto T = SBA::Arch::Target::X86_64;

    static void initialize_x86_64(const char* triple)
    {
        static std::once_flag initialized;
        std::call_once(initialized, [&]() {
            LLVMInitializeX86TargetInfo();
            LLVMInitializeX86Target();
            LLVMInitializeX86TargetMC();
            LLVMInitializeX86Disassembler();

            std::string error;
            target<T> = llvm::TargetRegistry::lookupTarget(triple, error);

            info_reg<T>  = target<T>->createMCRegInfo(triple);
            info_inst<T> = target<T>->createMCInstrInfo();
            info_cpu<T>  = target<T>->createMCSubtargetInfo(triple, "", "");
            info_asm<T>  = target<T>->createMCAsmInfo(*info_reg<T>, triple, {});

            auto num_regs = info_reg<T>->getNumRegs();
            llvm_registers<T>.assign(num_regs, NO_REG);
            for (size_t i = 1; i < num_regs; ++i)
                llvm_registers<T>[i] = extract_r<T>(info_reg<T>->getName(i));

            const auto& info = *info_inst<T>;
            for (unsigned i = 0; i < info.getNumOpcodes(); ++i)
                if (info.getName(i) == "LOCK_PREFIX") {
                    atomic_prefix_opcode<T> = i;
                    break;
                }
        });
    }

    template <>
    Decoder<T>::Decoder(const SBA::Binary::Object& object)
    {
        const char* triple = object.triple();
        initialize_x86_64(triple);
        context = std::make_unique<llvm::MCContext>(
            llvm::Triple(triple),
            info_asm<T>,
            info_reg<T>,
            info_cpu<T>
        );
        disassembler.reset(
            target<T>->createMCDisassembler(*info_cpu<T>, *context)
        );
    }

    template <>
    Decoder<T>::~Decoder() = default;

    template <>
    std::optional<MCInstruction> Decoder<T>::decode(
        uint64_t address,
        std::span<const uint8_t> bytes) const
    {
        if (!disassembler)
            return std::nullopt;

        MCInstruction result;
        uint64_t length = 0;

        auto status = disassembler->getInstruction(
            result,
            length,
            llvm::ArrayRef<uint8_t>(bytes.data(), bytes.size()),
            address,
            llvm::nulls()
        );

        if (status != llvm::MCDisassembler::Success)
            return std::nullopt;

        result.length((uint8_t)length);

        if (result.getOpcode() == atomic_prefix_opcode<T>) {
            if (bytes.size() <= length)
                return std::nullopt;

            uint64_t next_length = 0;

            status = disassembler->getInstruction(
                result,
                next_length,
                llvm::ArrayRef<uint8_t>(bytes.data()+length, bytes.size()-length),
                address + length,
                llvm::nulls()
            );

            if (status != llvm::MCDisassembler::Success)
                return std::nullopt;

            result.length((uint8_t)(length + next_length));
            result.atomic(true);
        }

        return result;
    }

}
