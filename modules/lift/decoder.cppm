module;
#include <memory>
#include <optional>
#include <span>
#include <llvm/MC/MCInst.h>

namespace llvm {
	class MCRegisterInfo;
	class MCInstrInfo;
	class MCSubtargetInfo;
	class MCAsmInfo;
	class MCContext;
	class MCDisassembler;
	class Target;
}

export module sba.lift.decoder;

import sba.binary.types;

export namespace SBA::Lift {

	struct DecoderInstruction {
		uint8_t size = 0;
		llvm::MCInst inst;
	};

	struct DecoderContext {
		const char* triple = nullptr;
		const llvm::Target* target = nullptr;
		std::unique_ptr<const llvm::MCRegisterInfo> register_info;
		std::unique_ptr<const llvm::MCInstrInfo> instruction_info;
		std::unique_ptr<const llvm::MCSubtargetInfo> cpu_info;
		std::unique_ptr<const llvm::MCAsmInfo> assembly_info;

		DecoderContext(
			SBA::Binary::Arch arch,
			SBA::Binary::OS os,
			SBA::Binary::Endian endian
		);
		~DecoderContext();
	};

	class Decoder {
	public:
		Decoder(const DecoderContext& dcontext);
		~Decoder();

		std::optional<DecoderInstruction> decode(
			uint64_t address,
			std::span<const uint8_t> bytes
		) const;

	private:
		std::unique_ptr<llvm::MCContext> context;
		std::unique_ptr<llvm::MCDisassembler> disassembler;
	};

}
