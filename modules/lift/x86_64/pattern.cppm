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

	inline constexpr Operand RAX = {
		.r = {
			(uint32_t)SBA::IR::Operand::Type::REGISTER,
			(uint32_t)SBA::Arch::X86_64::Reg::RAX,
			0,
			3,
			0
		}
	};

	inline constexpr Operand TMP1 = {
		.r = {
			(uint32_t)SBA::IR::Operand::Type::REGISTER,
			(uint32_t)SBA::Arch::X86_64::Reg::TMP1,
			0,
			3,
			0
		}
	};

	inline constexpr Operand TMP2 = {
		.r = {
			(uint32_t)SBA::IR::Operand::Type::REGISTER,
			(uint32_t)SBA::Arch::X86_64::Reg::TMP2,
			0,
			3,
			0
		}
	};

	inline constexpr Operand FLAGS = {
		.r = {
			(uint32_t)SBA::IR::Operand::Type::REGISTER,
			(uint32_t)SBA::Arch::X86_64::Reg::FLAGS,
			0,
			3,
			0
		}
	};

	/* 0. Temporary Copy */

	template <O op, uint8_t l>
	constexpr MCO r_R1(MCOperand reg) noexcept {
		return { op, reg.llength(l), r(0) };
	}

	template <O op, uint8_t l>
	constexpr MCO r_1R(MCOperand reg) noexcept {
		return { op, r(0), reg.llength(l) };
	}

	template <O op, uint8_t l>
	constexpr MCO r_RR(MCOperand reg1, MCOperand reg2) noexcept {
		return { op, reg1.llength(l), reg2.llength(l) };
	}

	template <O op, uint8_t l>
	constexpr MCO rr_R1(MCOperand reg) noexcept {
		return { op, reg.llength(l), r(0) };
	}

	template <O op, uint8_t l>
	constexpr MCO rr_2R(MCOperand reg) noexcept {
		return { op, r(1), reg.llength(l) };
	}

	template <O op, uint8_t l, uint8_t lm = l>
	constexpr MCO rm_R1(MCOperand reg) noexcept {
		return { op, reg.llength(l), r(0) };
	}

	template <O op, uint8_t l, uint8_t lm = l>
	constexpr MCO rm_2R(MCOperand reg) noexcept {
		return { op, m(1, lm), reg.llength(l) };
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

	template <O op, uint8_t l, uint8_t lm = l>
	constexpr MCO rm_12() noexcept {
		return { op, r(0), m(1, lm) };
	}

	template <O op, uint8_t l, uint8_t lm = l>
	constexpr MCO mr_12() noexcept {
		return { op, m(0, lm), r(5) };
	}

	template <O op, uint8_t l, uint8_t lm = l>
	constexpr MCO mi_12() noexcept {
		return { op, m(0, lm), i(5) };
	}

	/* 2. Unary ALU */

	template <O op>
	constexpr MCO r_11() noexcept {
		return { op, r(0), r(0) };
	}

	template <O op, uint8_t l, uint8_t lm = l>
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

	template <O op, uint8_t l, uint8_t lm = l>
	constexpr MCO rrm_123() noexcept {
		return { op, r(0), r(1), m(2, lm) };
	}

	template <O op, uint8_t l, uint8_t lm = l>
	constexpr MCO mr_112() noexcept {
		return { op, m(0, lm), m(0, lm), r(5) };
	}

	template <O op, uint8_t l, uint8_t lm = l>
	constexpr MCO mi_112() noexcept {
		return { op, m(0, lm), m(0, lm), i(5) };
	}

	template <O op, uint8_t l>
	constexpr MCO rrr_123R(MCOperand reg) noexcept {
		return { op, r(0), r(1), r(2), reg.llength(l) };
	}

	template <O op, uint8_t l>
	constexpr MCO rri_123R(MCOperand reg) noexcept {
		return { op, r(0), r(1), i(2), reg.llength(l) };
	}

	template <O op, uint8_t l, uint8_t lm = l>
	constexpr MCO rrm_123R(MCOperand reg) noexcept {
		return { op, r(0), r(1), m(2, lm), reg.llength(l) };
	}

	template <O op, uint8_t l, uint8_t lm = l>
	constexpr MCO mr_112R(MCOperand reg) noexcept {
		return { op, m(0, lm), m(0, lm), r(5), reg.llength(l) };
	}

	template <O op, uint8_t l, uint8_t lm = l>
	constexpr MCO mi_112R(MCOperand reg) noexcept {
		return { op, m(0, lm), m(0, lm), i(5), reg.llength(l) };
	}

	/* 4. Comparison */

	template <O op, uint8_t l, bool neg = false>
	constexpr MCO rrr_R23(MCOperand reg) noexcept {
		return { op, reg.llength(l), r(1), neg ? -r(2) : r(2) };
	}

	template <O op, uint8_t l, bool neg = false>
	constexpr MCO rri_R23(MCOperand reg) noexcept {
		return { op, reg.llength(l), r(1), neg ? -i(2) : i(2) };
	}

	template <O op, uint8_t l, uint8_t lm = l, bool neg = false>
	constexpr MCO rrm_R23(MCOperand reg) noexcept {
		return { op, reg.llength(l), r(1), neg ? -m(2, lm) : m(2, lm) };
	}

	template <O op, uint8_t l, bool neg = false>
	constexpr MCO rr_R12(MCOperand reg) noexcept {
		return { op, reg.llength(l), r(0), neg ? -r(1) : r(1) };
	}

	template <O op, uint8_t l, bool neg = false>
	constexpr MCO ri_R12(MCOperand reg) noexcept {
		return { op, reg.llength(l), r(0), neg ? -i(1) : i(1) };
	}

	template <O op, uint8_t l, uint8_t lm = l, bool neg = false>
	constexpr MCO rm_R12(MCOperand reg) noexcept {
		return { op, reg.llength(l), r(0), neg ? -m(1, lm) : m(1, lm) };
	}

	template <O op, uint8_t l, uint8_t lm = l, bool neg = false>
	constexpr MCO mr_R12(MCOperand reg) noexcept {
		return { op, reg.llength(l), m(0, lm), neg ? -r(5) : r(5) };
	}

	template <O op, uint8_t l, uint8_t lm = l, bool neg = false>
	constexpr MCO mi_R12(MCOperand reg) noexcept {
		return { op, reg.llength(l), m(0, lm), neg ? -i(5) : i(5) };
	}

	template <O op, uint8_t l, bool neg = false>
	constexpr MCO i_RR1(MCOperand reg1, MCOperand reg2) noexcept {
		return { op, reg1.llength(l), reg2.llength(l), neg ? -i(0) : i(0) };
	}

	template <O op, uint8_t l>
	constexpr MCO r_R1I(MCOperand reg, MCOperand imm) noexcept {
		return { op, reg.llength(l), r(0), imm };
	}

	template <O op, uint8_t l, uint8_t lm = l>
	constexpr MCO m_R1I(MCOperand reg, MCOperand imm) noexcept {
		return { op, reg.llength(l), m(0, lm), imm };
	}

}
