module;
#include <cstdint>
#include <string>
#include <llvm/MC/MCInst.h>

export module sba.lift:parser;

import sba.arch;
import sba.ir;
import :cache;
import :encoder;
import :target;

namespace SBA::Lift {

	using namespace SBA::IR;
	using SBA::Arch::Target;

	template <Target T>
	Register extract_register(const std::string& name) noexcept;

	template <Target T>
	Affine extract_affine(
		const llvm::MCOperand& op,
		uint8_t llength) noexcept;

}

namespace SBA::Lift {

	template <Target T>
	inline Operand parse_register(uint32_t reg_id) noexcept {
		return llvm_registers<T>[reg_id];
	}

	template <Target T>
	inline Operand parse_register(const llvm::MCOperand& op) noexcept {
		return parse_register<T>(op.getReg());
	}

	inline Operand parse_immediate(
		const llvm::MCOperand& op,
		Stream& stream,
		Cache& cache) noexcept
	{
		return encode_immediate(op.getImm(), stream, cache);
	}

	template <Target T>
	inline Operand parse_affine(
		const llvm::MCOperand& op,
		uint8_t llength,
		Stream& stream,
		Cache& cache) noexcept
	{
		return encode_affine(extract_affine<T>(op, llength), stream, cache);
	}

	template <Target T>
	inline Operand parse_memory(
		const llvm::MCOperand& op,
		uint8_t llength,
		Stream& stream,
		Cache& cache) noexcept
	{
		return encode_memory(extract_affine<T>(op, llength), stream, cache);
	}

}
