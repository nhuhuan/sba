module;
#include <cstdint>

export module sba.ir:constant;

import :syntax;

namespace {
	using enum SBA::IR::Operand::Type;
}

export namespace SBA::IR {

	inline constexpr Operand NO_REG  = { .r = { (uint32_t)REGISTER, 0, 0, 0, 0 } };
	inline constexpr Operand ANY_REG = { .r = { (uint32_t)REGISTER, 1, 0, 0, 0 } };
	inline constexpr Operand ANY_MEM = { .a = { (uint32_t)AFFINE,   0 } };

	inline constexpr Operand TMP1    = { .r = { (uint32_t)REGISTER, 2, 0, 3, 0 } };
	inline constexpr Operand TMP2    = { .r = { (uint32_t)REGISTER, 3, 0, 3, 0 } };
	inline constexpr Operand PC      = { .r = { (uint32_t)REGISTER, 4, 0, 3, 0 } };
	inline constexpr Operand SP      = { .r = { (uint32_t)REGISTER, 5, 0, 3, 0 } };
	inline constexpr Operand FP      = { .r = { (uint32_t)REGISTER, 6, 0, 3, 0 } };
	inline constexpr Operand FLAGS   = { .r = { (uint32_t)REGISTER, 7, 0, 3, 0 } };

}
