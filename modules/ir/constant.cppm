module;
#include <cstdint>

export module sba.ir.constant;

import sba.ir.syntax;

export namespace SBA::IR {

	inline constexpr Operand NO_REGISTER = Operand {
		.reg = {
			.type = (uint32_t)OperandType::REGISTER,
			.llength = 0,
			.id = 0,
			.offset = 0
		}
	};

	inline constexpr Operand ANY_REGISTER = Operand {
		.reg = {
			.type = (uint32_t)OperandType::REGISTER,
			.llength = 0,
			.id = 1,
			.offset = 0
		}
	};

	inline constexpr Operand ANY_MEMORY = Operand {
		.mem = {
			.type = (uint32_t)OperandType::MEMORY,
			.ext = 0,
			.index = 0
		}
	};

}
