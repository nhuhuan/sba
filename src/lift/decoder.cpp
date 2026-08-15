module;
#include <memory>
#include <string>
#include <span>
#include <mutex>
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

module sba.lift.decoder;

import sba.binary.object;

namespace SBA::Lift {

	static void initialize_llvm(SBA::Binary::Arch arch)
	{
		static std::once_flag x86_initialized;
		static std::once_flag aarch64_initialized;

		if (arch == SBA::Binary::Arch::X86_64) {
			std::call_once(x86_initialized, []() {
				LLVMInitializeX86TargetInfo();
				LLVMInitializeX86Target();
				LLVMInitializeX86TargetMC();
				LLVMInitializeX86Disassembler();
			});
		} else if (arch == SBA::Binary::Arch::AARCH64) {
			std::call_once(aarch64_initialized, []() {
				LLVMInitializeAArch64TargetInfo();
				LLVMInitializeAArch64Target();
				LLVMInitializeAArch64TargetMC();
				LLVMInitializeAArch64Disassembler();
			});
		}
	}

	DecoderContext::DecoderContext(
		SBA::Binary::Arch arch,
		SBA::Binary::OS os,
		SBA::Binary::Endian endian) :
		triple(SBA::Binary::Object::triple(arch, os))
	{
		initialize_llvm(arch);

		std::string error;
		target = llvm::TargetRegistry::lookupTarget(triple, error);

		register_info.reset(target->createMCRegInfo(triple));
		instruction_info.reset(target->createMCInstrInfo());
		cpu_info.reset(target->createMCSubtargetInfo(triple, "", ""));

		llvm::MCTargetOptions options;
		assembly_info.reset(
			target->createMCAsmInfo(*register_info, triple, options)
		);
	}

	DecoderContext::~DecoderContext() = default;

	Decoder::Decoder(const DecoderContext& dcontext)
	{
		context = std::make_unique<llvm::MCContext>(
			llvm::Triple(dcontext.triple),
			dcontext.assembly_info.get(),
			dcontext.register_info.get(),
			dcontext.cpu_info.get()
		);

		disassembler.reset(
			dcontext.target->createMCDisassembler(
				*dcontext.cpu_info,
				*context
			)
		);
	}

	Decoder::~Decoder() = default;

	std::optional<DecoderInstruction> Decoder::decode(
		uint64_t address,
		std::span<const uint8_t> bytes) const
	{
		if (bytes.empty())
			return std::nullopt;

		llvm::MCInst inst;
		uint64_t size = 0;
		llvm::ArrayRef<uint8_t> llvm_bytes(bytes.data(), bytes.size());

		auto status = disassembler->getInstruction(
			inst,
			size,
			llvm_bytes,
			address,
			llvm::nulls()
		);

		if (status == llvm::MCDisassembler::Success && size > 0)
			return DecoderInstruction{
				.size = (uint8_t)size,
				.inst = std::move(inst)
			};

		return std::nullopt;
	}

}
