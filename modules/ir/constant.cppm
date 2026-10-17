module;
#include <cstdint>

export module sba.ir:constant;

import :syntax;

namespace {
	using enum SBA::IR::Operand::Type;
}

export namespace SBA::IR {

	inline constexpr Operand NO_REG  = { .r = Register(0) };
	inline constexpr Operand ANY_REG = { .r = Register(1) };
	inline constexpr Operand ANY_MEM = { .a = { (uint32_t)AFFINE, 0 } };
}
