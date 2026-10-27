module;
#include <cstdint>

export module sba.lift:cache;

import sba.util;

export namespace SBA::Lift {

	/* ------------------------------- Cache -------------------------------- */

	struct Cache {
		SBA::Util::PMap<uint64_t, uint32_t> ins;
		SBA::Util::PMap<uint32_t, uint32_t> i32;
		SBA::Util::PMap<uint64_t, uint32_t> i64;
		SBA::Util::PMap<uint64_t, uint32_t> a;
	};

}
