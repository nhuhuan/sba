module;
#include <bit>
#include <cassert>
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
	inline Operand parse_r(
		const llvm::MCOperand& op,
		uint8_t negated = 0,
		uint32_t length = 0) noexcept
	{
		auto res = llvm_registers<T>[op.getReg()];
		res.r.length = length ? length : res.r.length;
		res.r.negated = negated;
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
		aff.dereferenced = 0;
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
		assert(std::has_single_bit(length_m) && length_m >= 8);
		auto aff = extract_a<T>(op);
		aff.llength_m = SBA::Util::bits_to_lbytes(length_m);
		aff.dereferenced = 1;
		aff.negated = negated;
		return ctx.encode(cache, aff);
	}

}
