module;
#include <cstdint>
#include <string_view>
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
	Register extract_r(std::string_view name) noexcept;

	template <Target T>
	Affine extract_a(const llvm::MCOperand& op) noexcept;

}

namespace SBA::Lift {

	template <Target T>
	inline Operand parse_r(uint32_t reg_id, uint8_t negated = 0) noexcept {
		auto op = llvm_registers<T>[reg_id];
		op.r.negated = negated;
		return op;
	}

	template <Target T>
	inline Operand parse_r(const llvm::MCOperand& op, uint8_t negated = 0) noexcept {
		return parse_r<T>(op.getReg(), negated);
	}

	inline Operand parse_i(
		Context& ctx,
		Cache& cache,
		const llvm::MCOperand& op,
		uint8_t negated = 0) noexcept
	{
		int64_t val = op.getImm();
		val = (!negated) ? val : -val;
		return ctx.encode(cache, (uint64_t)val);
	}

	template <Target T>
	inline Operand parse_a(
		Context& ctx,
		Cache& cache,
		const llvm::MCOperand& op,
		uint8_t llength,
		uint8_t dereferenced,
		uint8_t negated = 0) noexcept
	{
		auto aff = extract_a<T>(op);
		aff.llength = llength;
		aff.dereferenced = dereferenced;
		aff.negated = negated;
		return ctx.encode(cache, aff);
	}

}
