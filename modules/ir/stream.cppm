module;
#include <cstdint>

export module sba.ir.stream;

import sba.ir.syntax;
import sba.ir.constant;
import sba.util.container;

export namespace SBA::IR {

	struct IRStream {
		SBA::Util::PVector<uint8_t>   raw;
		SBA::Util::PVector<uint32_t>  imm32;
		SBA::Util::PVector<uint64_t>  imm64;
		SBA::Util::PVector<uint32_t>  pcrel;
		SBA::Util::PVector<Memory>    mem;
		SBA::Util::PVector<MemoryExt> memext;

		IRStream() {
			mem.push_back(
				Memory {
					.displacement = 0,
					.base = ANY_REGISTER.reg.id,
					.llength = 0,
					.llength_addr = 3
				}
			);
		}
	};

}
