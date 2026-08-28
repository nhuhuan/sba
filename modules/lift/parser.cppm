module;
#include <cstdint>
#include <string>
#include <llvm/MC/MCInst.h>

export module sba.lift:parser;

import sba.arch;
import sba.ir;
import :cache;
import :target;

namespace SBA::Lift {

	using namespace SBA::IR;
	using SBA::Arch::Target;

	template <Target T>
	Register extract_r(const std::string& name) noexcept;

	template <Target T>
	Affine extract_a(
		const llvm::MCOperand& op,
		uint8_t llength) noexcept;

}

namespace SBA::Lift {

	template <Target T>
	inline Operand parse_r(uint32_t reg_id) noexcept {
		return llvm_registers<T>[reg_id];
	}

	template <Target T>
	inline Operand parse_r(const llvm::MCOperand& op) noexcept {
		return parse_r<T>(op.getReg());
	}

	inline Operand parse_i(
		Context& ctx,
		Cache& cache,
		const llvm::MCOperand& op) noexcept
	{
		return ctx.encode(cache, op.getImm());
	}

	template <Target T>
	inline Operand parse_a(
		Context& ctx,
		Cache& cache,
		const llvm::MCOperand& op,
		uint8_t llength) noexcept
	{
		return ctx.encode(cache, extract_a<T>(op, llength), false);
	}

	template <Target T>
	inline Operand parse_m(
		Context& ctx,
		Cache& cache,
		const llvm::MCOperand& op,
		uint8_t llength) noexcept
	{
		return ctx.encode(cache, extract_a<T>(op, llength));
	}

}
