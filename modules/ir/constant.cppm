module;
#include <cstdint>

export module sba.ir:constant;

import :syntax;

export namespace SBA::IR {

	inline constexpr Operand NO_REGISTER = Operand {
		.reg = {
			.type = (uint32_t)OperandType::REGISTER,
			.index = 0,
			.offset = 0,
			.llength = 0
		}
	};

	inline constexpr Operand ANY_REGISTER = Operand {
		.reg = {
			.type = (uint32_t)OperandType::REGISTER,
			.index = 1,
			.offset = 0,
			.llength = 0
		}
	};

	inline constexpr Operand ANY_MEMORY = Operand {
		.mem = {
			.type = (uint32_t)OperandType::MEMORY,
			.index = 0
		}
	};

}
