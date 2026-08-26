module;
#include <memory>
#include <optional>
#include <span>
#include <llvm/MC/MCInst.h>

namespace llvm {
	class MCContext;
	class MCDisassembler;
}

export module sba.lift:decoder;

import sba.binary;

export namespace SBA::Lift {

	class MCInst : public llvm::MCInst {
	public:
		uint8_t length() const noexcept { return len_; }
		void length(uint8_t len) noexcept { len_ = len; }

	private:
		uint8_t len_ = 0;
	};

	class Decoder {
	public:
		Decoder(const SBA::Binary::Object& object);
		~Decoder();

		std::optional<MCInst> decode(
			uint64_t address,
			std::span<const uint8_t> bytes
		) const;

	private:
		std::unique_ptr<llvm::MCContext> context;
		std::unique_ptr<llvm::MCDisassembler> disassembler;
	};

}
