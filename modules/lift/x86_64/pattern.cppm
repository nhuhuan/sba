module;
#include <cstdint>

export module sba.lift:x86_64_pattern;

import sba.arch;
import sba.ir;
import sba.util;
import :emit;

namespace SBA::Lift::X86_64 {

	using SBA::Util::bytes;
	using SBA::Util::bits;

	using Reg = SBA::Arch::X86_64::Reg;
	using enum Reg;

	using O = SBA::IR::Operator;
	using MCO = SBA::Lift::MCOperation;

	using r = DynamicRegister;
	using i = DynamicImmediate;
	using a = DynamicAffine;
	using m = DynamicMemory;

	inline constexpr Operand R(Reg reg, uint8_t llength = 3) noexcept {
		return {
			.r = {
				(uint32_t)SBA::IR::Operand::Type::REGISTER,
				(uint32_t)reg,
				0,
				llength,
				0
			}
		};
	}

	inline constexpr Affine A(
		Reg base,
		Reg index,
		uint8_t shift = 0,
		int64_t displacement = 0,
		uint8_t llength_addr = 3) noexcept
	{
		return Affine {
			.displacement = (int32_t)displacement,
			.base         = (uint8_t)base,
			.index        = (uint8_t)index,
			.shift        = shift,
			.extra        = 0,
			.llength      = 0,
			.llength_addr = llength_addr,
			.dereferenced = 0,
			.negated      = 0
		};
	}

	inline constexpr Affine A(
		Reg base,
		int64_t displacement,
		uint8_t llength_addr = 3) noexcept
	{
		return A(base, NONE, 0, displacement, llength_addr);
	}

	inline constexpr Affine M(
		Reg base,
		Reg index,
		uint8_t shift,
		int64_t displacement,
		uint8_t llength,
		uint8_t llength_addr = 3) noexcept
	{
		Affine m = A(base, index, shift, displacement, llength_addr);
		m.dereferenced = 1;
		m.llength = llength;
		return m;
	}

	inline constexpr Affine M(
		Reg base,
		int64_t displacement,
		uint8_t llength,
		uint8_t llength_addr = 3) noexcept
	{
		return M(base, NONE, 0, displacement, llength, llength_addr);
	}

	inline constexpr Affine M(
		Reg base,
		uint8_t llength,
		uint8_t llength_addr = 3) noexcept
	{
		return M(base, NONE, 0, 0, llength, llength_addr);
	}

	inline constexpr bool HAS_REP(MCInstruction inst) noexcept {
		return inst.getFlags() & 0x8;
	}

	inline constexpr bool HAS_REPE(MCInstruction inst) noexcept {
		return inst.getFlags() & 0x8;
	}

	inline constexpr bool HAS_REPNE(MCInstruction inst) noexcept {
		return inst.getFlags() & 0x4;
	}

	inline constexpr O CC[16] = {
		O::SELECT_O,
		O::SELECT_NO,
		O::SELECT_LTU,
		O::SELECT_GEU,
		O::SELECT_EQ,
		O::SELECT_NE,
		O::SELECT_LEU,
		O::SELECT_GTU,
		O::SELECT_S,
		O::SELECT_NS,
		O::SELECT_P,
		O::SELECT_NP,
		O::SELECT_LT,
		O::SELECT_GE,
		O::SELECT_LE,
		O::SELECT_GT
	};

	/* 0. Fixed Operands */

	template <O op, typename... Args>
	constexpr MCO mco(Args&&... args) noexcept {
		return { op, static_cast<MCOperand>(args)... };
	}

	/* 1. Data Copy */

	template <O op>
	constexpr MCO r_x1(MCOperand x) noexcept {
		return { op, x, r(0) };
	}

	template <O op>
	constexpr MCO r_1x(MCOperand x) noexcept {
		return { op, r(0), x };
	}

	template <O op>
	constexpr MCO i_x1(MCOperand x) noexcept {
		return { op, x, i(0) };
	}

	template <O op>
	constexpr MCO rr_x1(MCOperand x) noexcept {
		return { op, x, r(0) };
	}

	template <O op>
	constexpr MCO rr_2x(MCOperand x) noexcept {
		return { op, r(1), x };
	}

	template <O op>
	constexpr MCO rm_x1(MCOperand x) noexcept {
		return { op, x, r(0) };
	}

	template <O op, uint8_t lm>
	constexpr MCO rm_2x(MCOperand x) noexcept {
		return { op, m(1, lm), x };
	}

	template <O op, uint8_t lm>
	constexpr MCO m_x1(MCOperand x) noexcept {
		return { op, x, m(0, lm) };
	}

	template <O op, uint8_t lm>
	constexpr MCO m_1x(MCOperand x) noexcept {
		return { op, m(0, lm), x };
	}

	template <O op>
	constexpr MCO rr_12() noexcept {
		return { op, r(0), r(1) };
	}

	template <O op>
	constexpr MCO ri_12() noexcept {
		return { op, r(0), i(1) };
	}

	template <O op>
	constexpr MCO ra_12() noexcept {
		return { op, r(0), a(1) };
	}

	template <O op, uint8_t lm>
	constexpr MCO rm_12() noexcept {
		return { op, r(0), m(1, lm) };
	}

	template <O op, uint8_t lm>
	constexpr MCO mr_12() noexcept {
		return { op, m(0, lm), r(5) };
	}

	template <O op, uint8_t lm>
	constexpr MCO mi_12() noexcept {
		return { op, m(0, lm), i(5) };
	}

	/* 2. Unary ALU */

	template <O op>
	constexpr MCO rr_12x(MCOperand x) noexcept {
		return { op, r(0), r(1), x };
	}

	template <O op, uint8_t lm>
	constexpr MCO m_11() noexcept {
		return { op, m(0, lm), m(0, lm) };
	}

	template <O op, uint8_t lm>
	constexpr MCO m_11x(MCOperand x) noexcept {
		return { op, m(0, lm), m(0, lm), x };
	}

	template <O op>
	constexpr MCO rrr_13() noexcept {
		return { op, r(0), r(2) };
	}

	template <O op, uint8_t lm>
	constexpr MCO rrm_13() noexcept {
		return { op, r(0), m(2, lm) };
	}

	template <O op>
	constexpr MCO rrr_x3(MCOperand x) noexcept {
		return { op, x, r(2) };
	}

	template <O op, uint8_t lm>
	constexpr MCO rrm_x3(MCOperand x) noexcept {
		return { op, x, m(2, lm) };
	}

	/* 3. Binary ALU */

	template <O op>
	constexpr MCO rrr_123() noexcept {
		return { op, r(0), r(1), r(2) };
	}

	template <O op>
	constexpr MCO rri_123() noexcept {
		return { op, r(0), r(1), i(2) };
	}

	template <O op, uint8_t lm>
	constexpr MCO rrm_123() noexcept {
		return { op, r(0), r(1), m(2, lm) };
	}

	template <O op>
	constexpr MCO r_xx1(MCOperand x1, MCOperand x2) noexcept {
		return { op, x1, x2, r(0) };
	}

	template <O op, uint8_t lm>
	constexpr MCO m_xx1(MCOperand x1, MCOperand x2) noexcept {
		return { op, x1, x2, m(0, lm) };
	}

	template <O op, uint8_t lm>
	constexpr MCO mr_112() noexcept {
		return { op, m(0, lm), m(0, lm), r(5) };
	}

	template <O op, uint8_t lm>
	constexpr MCO mi_112() noexcept {
		return { op, m(0, lm), m(0, lm), i(5) };
	}

	template <O op>
	constexpr MCO rrr_123x(MCOperand x) noexcept {
		return { op, r(0), r(1), r(2), x };
	}

	template <O op>
	constexpr MCO rri_123x(MCOperand x) noexcept {
		return { op, r(0), r(1), i(2), x };
	}

	template <O op, uint8_t lm>
	constexpr MCO rrm_123x(MCOperand x) noexcept {
		return { op, r(0), r(1), m(2, lm), x };
	}

	template <O op, uint8_t lm>
	constexpr MCO mr_112x(MCOperand x) noexcept {
		return { op, m(0, lm), m(0, lm), r(5), x };
	}

	template <O op, uint8_t lm>
	constexpr MCO mi_112x(MCOperand x) noexcept {
		return { op, m(0, lm), m(0, lm), i(5), x };
	}

	template <O op>
	constexpr MCO rrr_1xx(MCOperand x1, MCOperand x2) noexcept {
		return { op, r(0), x1, x2 };
	}

	template <O op, uint8_t lm>
	constexpr MCO rrm_1xx(MCOperand x1, MCOperand x2) noexcept {
		return { op, r(0), x1, x2 };
	}

	/* 4. Comparison */

	template <O op, bool neg = false>
	constexpr MCO rrr_x23(MCOperand x) noexcept {
		return { op, x, r(1), neg ? -r(2) : r(2) };
	}

	template <O op, bool neg = false>
	constexpr MCO rri_x23(MCOperand x) noexcept {
		return { op, x, r(1), neg ? -i(2) : i(2) };
	}

	template <O op, uint8_t lm, bool neg = false>
	constexpr MCO rrm_x23(MCOperand x) noexcept {
		return { op, x, r(1), neg ? -m(2, lm) : m(2, lm) };
	}

	template <O op, bool neg = false>
	constexpr MCO rr_x12(MCOperand x) noexcept {
		return { op, x, r(0), neg ? -r(1) : r(1) };
	}

	template <O op, bool neg = false>
	constexpr MCO ri_x12(MCOperand x) noexcept {
		return { op, x, r(0), neg ? -i(1) : i(1) };
	}

	template <O op, uint8_t lm, bool neg = false>
	constexpr MCO rm_x12(MCOperand x) noexcept {
		return { op, x, r(0), neg ? -m(1, lm) : m(1, lm) };
	}

	template <O op, uint8_t lm, bool neg = false>
	constexpr MCO mr_x12(MCOperand x) noexcept {
		return { op, x, m(0, lm), neg ? -r(5) : r(5) };
	}

	template <O op, uint8_t lm, bool neg = false>
	constexpr MCO mi_x12(MCOperand x) noexcept {
		return { op, x, m(0, lm), neg ? -i(5) : i(5) };
	}

	template <O op, bool neg = false>
	constexpr MCO i_xx1(MCOperand x1, MCOperand x2) noexcept {
		return { op, x1, x2, neg ? -i(0) : i(0) };
	}

	template <O op, bool neg = false>
	constexpr MCO rr_x1x(MCOperand x1, MCOperand x2) noexcept {
		return { op, x1, r(0), neg ? -x2 : x2 };
	}

	template <O op, bool neg = false>
	constexpr MCO rr_x2x(MCOperand x1, MCOperand x2) noexcept {
		return { op, x1, r(1), neg ? -x2 : x2 };
	}

	template <O op, uint8_t lm, bool neg = false>
	constexpr MCO rm_x2x(MCOperand x1, MCOperand x2) noexcept {
		return { op, x1, m(1, lm), neg ? -x2 : x2 };
	}

	template <O op, bool neg = false>
	constexpr MCO rrr_x3x(MCOperand x1, MCOperand x2) noexcept {
		return { op, x1, r(2), neg ? -x2 : x2 };
	}

	template <O op, uint8_t lm, bool neg = false>
	constexpr MCO rrm_x3x(MCOperand x1, MCOperand x2) noexcept {
		return { op, x1, m(2, lm), neg ? -x2 : x2 };
	}

	template <O op, uint8_t lm, bool neg = false>
	constexpr MCO m_x1x(MCOperand x1, MCOperand x2) noexcept {
		return { op, x1, m(0, lm), neg ? -x2 : x2 };
	}

	template <O op>
	constexpr MCO rr_xx2(MCOperand x1, MCOperand x2) noexcept {
		return { op, x1, x2, r(1) };
	}

	/* 5. Atomic / Exchange */

	template <O op>
	constexpr MCO rr_1x2x(MCOperand x1, MCOperand x2) noexcept {
		return { op, r(0), x1, r(1), x2 };
	}

	template <O op, uint8_t lm>
	constexpr MCO rm_1x2x(MCOperand x1, MCOperand x2) noexcept {
		return { op, m(0, lm), x1, r(5), x2 };
	}

}
