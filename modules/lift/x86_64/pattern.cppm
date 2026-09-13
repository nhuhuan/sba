module;
#include <cstdint>

export module sba.lift:pattern_x86_64;

import sba.arch;
import sba.ir;
import :emit;

namespace SBA::Lift::X86_64 {

	using O = SBA::IR::Operator;
	using MCO = SBA::Lift::MCOperation;

	using r = DynamicRegister;
	using i = DynamicImmediate;
	using a = DynamicAffine;
	using m = DynamicMemory;

	inline constexpr Operand REG(
		SBA::Arch::X86_64::Reg reg,
		uint8_t llength = 3) noexcept
	{
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

	/* 0. Temporary Copy */

	template <O op>
	constexpr MCO r_r1(MCOperand reg) noexcept {
		return { op, reg, r(0) };
	}

	template <O op>
	constexpr MCO r_1r(MCOperand reg) noexcept {
		return { op, r(0), reg };
	}

	template <O op>
	constexpr MCO r_rr(MCOperand reg1, MCOperand reg2) noexcept {
		return { op, reg1, reg2 };
	}

	template <O op>
	constexpr MCO rr_r1(MCOperand reg) noexcept {
		return { op, reg, r(0) };
	}

	template <O op>
	constexpr MCO rr_2r(MCOperand reg) noexcept {
		return { op, r(1), reg };
	}

	template <O op>
	constexpr MCO rm_r1(MCOperand reg) noexcept {
		return { op, reg, r(0) };
	}

	template <O op, uint8_t lm>
	constexpr MCO rm_2r(MCOperand reg) noexcept {
		return { op, m(1, lm), reg };
	}

	/* 1. Data Copy */

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
	constexpr MCO r_11() noexcept {
		return { op, r(0), r(0) };
	}

	template <O op, uint8_t lm>
	constexpr MCO m_11() noexcept {
		return { op, m(0, lm), m(0, lm) };
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

	template <O op, uint8_t lm>
	constexpr MCO mr_112() noexcept {
		return { op, m(0, lm), m(0, lm), r(5) };
	}

	template <O op, uint8_t lm>
	constexpr MCO mi_112() noexcept {
		return { op, m(0, lm), m(0, lm), i(5) };
	}

	template <O op>
	constexpr MCO rrr_123r(MCOperand reg) noexcept {
		return { op, r(0), r(1), r(2), reg };
	}

	template <O op>
	constexpr MCO rri_123r(MCOperand reg) noexcept {
		return { op, r(0), r(1), i(2), reg };
	}

	template <O op, uint8_t lm>
	constexpr MCO rrm_123r(MCOperand reg) noexcept {
		return { op, r(0), r(1), m(2, lm), reg };
	}

	template <O op, uint8_t lm>
	constexpr MCO mr_112r(MCOperand reg) noexcept {
		return { op, m(0, lm), m(0, lm), r(5), reg };
	}

	template <O op, uint8_t lm>
	constexpr MCO mi_112r(MCOperand reg) noexcept {
		return { op, m(0, lm), m(0, lm), i(5), reg };
	}

	/* 4. Comparison */

	template <O op, bool neg = false>
	constexpr MCO rrr_r23(MCOperand reg) noexcept {
		return { op, reg, r(1), neg ? -r(2) : r(2) };
	}

	template <O op, bool neg = false>
	constexpr MCO rri_r23(MCOperand reg) noexcept {
		return { op, reg, r(1), neg ? -i(2) : i(2) };
	}

	template <O op, uint8_t lm, bool neg = false>
	constexpr MCO rrm_r23(MCOperand reg) noexcept {
		return { op, reg, r(1), neg ? -m(2, lm) : m(2, lm) };
	}

	template <O op, bool neg = false>
	constexpr MCO rr_r12(MCOperand reg) noexcept {
		return { op, reg, r(0), neg ? -r(1) : r(1) };
	}

	template <O op, bool neg = false>
	constexpr MCO ri_r12(MCOperand reg) noexcept {
		return { op, reg, r(0), neg ? -i(1) : i(1) };
	}

	template <O op, uint8_t lm, bool neg = false>
	constexpr MCO rm_r12(MCOperand reg) noexcept {
		return { op, reg, r(0), neg ? -m(1, lm) : m(1, lm) };
	}

	template <O op, uint8_t lm, bool neg = false>
	constexpr MCO mr_r12(MCOperand reg) noexcept {
		return { op, reg, m(0, lm), neg ? -r(5) : r(5) };
	}

	template <O op, uint8_t lm, bool neg = false>
	constexpr MCO mi_r12(MCOperand reg) noexcept {
		return { op, reg, m(0, lm), neg ? -i(5) : i(5) };
	}

	template <O op, bool neg = false>
	constexpr MCO i_rr1(MCOperand reg1, MCOperand reg2) noexcept {
		return { op, reg1, reg2, neg ? -i(0) : i(0) };
	}

	template <O op>
	constexpr MCO r_r1i(MCOperand reg, MCOperand imm) noexcept {
		return { op, reg, r(0), imm };
	}

	template <O op, uint8_t lm>
	constexpr MCO m_r1i(MCOperand reg, MCOperand imm) noexcept {
		return { op, reg, m(0, lm), imm };
	}

}
