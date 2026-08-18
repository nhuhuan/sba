module;
#include <cstdint>

export module sba.ir.stream;

import sba.ir.syntax;
import sba.ir.constant;
import sba.util.container;

export namespace SBA::IR {

	struct IRStream {
		SBA::Util::PVector<uint8_t,  (1ULL << INST_BITS)>  inst;
		SBA::Util::PVector<uint32_t, (1ULL << IMM_BITS)>   imm32;
		SBA::Util::PVector<uint64_t, (1ULL << IMM_BITS)>   imm64;
		SBA::Util::PVector<uint32_t, (1ULL << PCREL_BITS)> pcrel;
		SBA::Util::PVector<Memory,   (1ULL << MEM_BITS)>   mem;

		IRStream() {
			mem.push_back(
				Memory {
					.displacement = 0,
					.base = (uint8_t)ANY_REGISTER.reg.index,
					.index = 0,
					.shift = 0,
					.extra = 0,
					.llength = 0,
					.llength_addr = 3
				}
			);
		}
	};

}
