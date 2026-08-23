module;
#include <cstdint>

export module sba.lift:cache;

import sba.util;

export namespace SBA::Lift {

	struct IRCache {
		SBA::Util::PMap<uint64_t, uint32_t> inst;
		SBA::Util::PMap<uint32_t, uint32_t> imm32;
		SBA::Util::PMap<uint64_t, uint32_t> imm64;
		SBA::Util::PMap<uint64_t, uint32_t> aff;
	};

}
