module;
#include <memory>
#include <string>
#include <span>
#include <mutex>
#include <cassert>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/MCTargetOptions.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>

module sba.lift;

import sba.arch;
import sba.binary;
import :decoder;
import :target;
import :parser;

namespace SBA::Lift {

	using SBA::Arch::Target;

	template <Target T>
	void initialize_target(const char* triple)
	{
		static std::once_flag initialized;
		std::call_once(initialized, [&]() {
			if constexpr (T == Target::X86_64) {
				LLVMInitializeX86TargetInfo();
				LLVMInitializeX86Target();
				LLVMInitializeX86TargetMC();
				LLVMInitializeX86Disassembler();
			} else if constexpr (T == Target::AArch64) {
				LLVMInitializeAArch64TargetInfo();
				LLVMInitializeAArch64Target();
				LLVMInitializeAArch64TargetMC();
				LLVMInitializeAArch64Disassembler();
			}

			std::string error;
			target<T> = llvm::TargetRegistry::lookupTarget(triple, error);
			assert(target<T>);

			info_reg<T>  = target<T>->createMCRegInfo(triple);
			info_inst<T> = target<T>->createMCInstrInfo();
			info_cpu<T>  = target<T>->createMCSubtargetInfo(triple, "", "");

			info_asm<T>  = target<T>->createMCAsmInfo(
				*info_reg<T>, triple, {}
			);

			auto num_regs = info_reg<T>->getNumRegs();
			llvm_registers<T>.assign(num_regs, NO_REG);
			for (size_t i = 1; i < num_regs; ++i)
				llvm_registers<T>[i] = Operand {
					.r = extract_r<T>(info_reg<T>->getName(i))
				};
		});
	}

	Decoder::Decoder(const SBA::Binary::Object& object)
	{
		const char* triple = object.triple();

		switch (object.arch()) {
			case Target::X86_64: {
				initialize_target<Target::X86_64>(triple);
				context = std::make_unique<llvm::MCContext>(
					llvm::Triple(triple),
					info_asm<Target::X86_64>,
					info_reg<Target::X86_64>,
					info_cpu<Target::X86_64>
				);
				disassembler.reset(
					target<Target::X86_64>->createMCDisassembler(
						*info_cpu<Target::X86_64>,
						*context
					)
				);
				break;
			}
			case Target::AArch64: {
				initialize_target<Target::AArch64>(triple);
				context = std::make_unique<llvm::MCContext>(
					llvm::Triple(triple),
					info_asm<Target::AArch64>,
					info_reg<Target::AArch64>,
					info_cpu<Target::AArch64>
				);
				disassembler.reset(
					target<Target::AArch64>->createMCDisassembler(
						*info_cpu<Target::AArch64>,
						*context
					)
				);
				break;
			}
			default:
				break;
		}
	}

	Decoder::~Decoder() = default;

	std::optional<MCInstruction> Decoder::decode(
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
		return result;
	}

}
