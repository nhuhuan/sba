module;
#include <bit>
#include <cstdint>
#include <string_view>
#include <llvm/MC/MCInst.h>

export module sba.lift:parse;

import sba.arch;
import sba.ir;
import sba.util;
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
	inline Register parse_r(
		const llvm::MCOperand& op,
		uint32_t offset = 0,
		uint32_t length = 0,
		uint8_t negated = 0) noexcept
	{
		auto res = llvm_registers<T>[op.getReg()];
		if (length != 0)
			res = res[offset, offset + length];
		if (negated)
			res = -res;
		return res;
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
		uint8_t negated = 0) noexcept
	{
		auto aff = extract_a<T>(op);
		aff.deref = 0;
		aff.negated = negated;
		return ctx.encode(cache, aff);
	}

	template <Target T>
	inline Operand parse_m(
		Context& ctx,
		Cache& cache,
		const llvm::MCOperand& op,
		uint32_t length_m,
		uint8_t negated = 0) noexcept
	{
		auto aff = extract_a<T>(op);
		aff.deref = 1;
		aff.negated = negated;
		aff.llength_m = SBA::Util::bits_to_lbytes(length_m);
		return ctx.encode(cache, aff);
	}

}
