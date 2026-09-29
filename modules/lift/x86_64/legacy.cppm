module;
#include <cstdint>
#include <span>

export module sba.lift:x86_64_legacy;

import sba.arch;
import sba.ir;
import :emit;
import :x86_64_pattern;
import :x86_64_dispatch;

namespace SBA::Lift::X86_64 {

	#define P(Suffix, ...) \
		template <uint8_t l> \
		static constexpr Pattern Suffix = { __VA_ARGS__ }

	#define PM(Suffix, ...) \
		template <uint8_t l, uint8_t lm = l> \
		static constexpr Pattern Suffix = { __VA_ARGS__ }

	struct P_LEGACY_ABORT {
		P(_,   { mco<O::ABORT>() });
		P(i,   { mco<O::ABORT>() });
		P(rr,  { mco<O::ABORT>() });
		PM(rm, { mco<O::ABORT>() });
		PM(mr, { mco<O::ABORT>() });
	};

	/* -----------------------------------------------------------------------*/

	struct AAA    : P_LEGACY_ABORT {};
	struct AAS    : P_LEGACY_ABORT {};
	struct DAA    : P_LEGACY_ABORT {};
	struct DAS    : P_LEGACY_ABORT {};
	struct AAD    : P_LEGACY_ABORT {};
	struct AAM    : P_LEGACY_ABORT {};
	struct LDS    : P_LEGACY_ABORT {};
	struct LES    : P_LEGACY_ABORT {};
	struct ARPL   : P_LEGACY_ABORT {};
	struct SALC   : P_LEGACY_ABORT {};
	struct INTO   : P_LEGACY_ABORT {};
	struct BOUNDS : P_LEGACY_ABORT {};

	using Mnemonics_LGC = SBA::Util::TypeList<
		AAA, AAS, DAA, DAS, AAD, AAM,
		LDS, LES, ARPL, SALC, INTO, BOUNDS
	>;

	#undef PM
	#undef P

}
