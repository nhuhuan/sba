module;
#include <cstdint>

export module sba.ir.stream;

import sba.ir.syntax;
import sba.ir.constant;
import sba.util.container;

export namespace SBA::IR {

	struct IRStream {
		SBA::Util::PVector<uint8_t,  (1ULL << 32)> raw;
		SBA::Util::PVector<uint32_t, (1ULL << 32)> imm32;
		SBA::Util::PVector<uint64_t, (1ULL << 32)> imm64;
		SBA::Util::PVector<uint32_t, (1ULL << 32)> pcrel;
		SBA::Util::PVector<Memory,   (1ULL << 32)> mem;

		IRStream() {
			mem.push_back(
				Memory {
					.displacement = 0,
					.base = (uint8_t)ANY_REGISTER.reg.id,
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
