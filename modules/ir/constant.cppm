module;
#include <cstdint>

export module sba.ir:constant;

import :syntax;

export namespace SBA::IR {

	inline constexpr Operand NO_REGISTER = Operand {
		.r = {
			.type = (uint32_t)Operand::Type::REGISTER,
			.index = 0,
			.offset = 0,
			.llength = 0
		}
	};

	inline constexpr Operand ANY_REGISTER = Operand {
		.r = {
			.type = (uint32_t)Operand::Type::REGISTER,
			.index = 1,
			.offset = 0,
			.llength = 0
		}
	};

	inline constexpr Operand ANY_MEMORY = Operand {
		.m = {
			.type = (uint32_t)Operand::Type::MEMORY,
			.index = 0
		}
	};

}
