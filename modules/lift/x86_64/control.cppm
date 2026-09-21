module;
#include <cstdint>
#include <span>

export module sba.lift:x86_64_control;

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

	template <uint8_t l_rcx>
	struct P_JCXZ {
		P(_, { i_xx1<O::ADD>(R(TMP1,3),R(RIP,3)),
		       mco<O::CMP>(R(TMP2,3),R(RCX,l_rcx),0ULL),
		       mco<O::SELECT_EQ>(R(RIP,3),R(TMP2,3),R(TMP1,3),R(RIP,3)) });
	};

	template <O cc>
	struct P_LOOP_CC {
		P(_, { mco<O::VAL>(R(RCX,3),A(RCX,-1)),
		       i_xx1<O::ADD>(R(TMP1,3),R(RIP,3)),
		       mco<cc>(R(TMP1,3),R(FLAGS,0),R(TMP1,3),R(RIP,3)),
		       mco<O::CMP>(R(TMP2,3),R(RCX,3),0ULL),
		       mco<O::SELECT_NE>(R(RIP,3),R(TMP2,3),R(TMP1,3),R(RIP,3)) });
	};

	/* -----------------------------------------------------------------------*/

	struct JMP {
		P(_,  { i_xx1<O::ADD>(R(RIP,3),R(RIP,3)) });
		P(r,  { r_x1<O::VAL>(R(RIP,3)) });
		PM(m, { m_x1<O::VAL,lm>(R(RIP,3)) });
	};
	struct JCC {
		template <uint8_t l>
		static Instruction _(Context& ctx, Cache& cache, const MCInstruction& inst)
		{
			uint8_t cc = inst.getOperand(1).getImm();
			MCO ops[] = {
				i_xx1<O::ADD>(R(TMP1,3),R(RIP,3)),
				{ CC[cc],R(RIP,3),R(FLAGS,0),R(TMP1,3),R(RIP,3) }
			};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}
	};
	struct CALL {
		P(_,  { mco<O::VAL>(R(RSP,3),A(RSP,-bytes<int64_t>(l))),
		        mco<O::VAL>(M(RSP,l),R(RIP,3)),
		        i_xx1<O::ADD>(R(RIP,3),R(RIP,3)) });
		P(r,  { mco<O::VAL>(R(RSP,3),A(RSP,-bytes<int64_t>(l))),
		        mco<O::VAL>(M(RSP,l),R(RIP,3)),
		        r_x1<O::VAL>(R(RIP,3)) });
		PM(m, { mco<O::VAL>(R(RSP,3),A(RSP,-bytes<int64_t>(l))),
		        mco<O::VAL>(M(RSP,l),R(RIP,3)),
		        m_x1<O::VAL,lm>(R(RIP,3)) });
	};
	struct RET {
		P(_, { mco<O::VAL>(R(RIP,3),M(RSP,l)),
		       mco<O::VAL>(R(RSP,3),A(RSP,bytes<int64_t>(l))) });
	};
	struct RETI {
		P(_, { mco<O::VAL>(R(RIP,3),M(RSP,l)),
		       mco<O::VAL>(R(RSP,3),A(RSP,bytes<int64_t>(l))),
		       i_xx1<O::ADD>(R(RSP,3),R(RSP,3)) });
	};
	struct JCXZ   : P_JCXZ<1> {};
	struct JECXZ  : P_JCXZ<2> {};
	struct JRCXZ  : P_JCXZ<3> {};
	struct LOOPE  : P_LOOP_CC<O::SELECT_EQ> {};
	struct LOOPNE : P_LOOP_CC<O::SELECT_NE> {};
	struct LOOP {
		P(_, { mco<O::VAL>(R(RCX,3),A(RCX,-1)),
		       i_xx1<O::ADD>(R(TMP1,3),R(RIP,3)),
		       mco<O::CMP>(R(TMP2,3),R(RCX,3),0ULL),
		       mco<O::SELECT_NE>(R(RIP,3),R(TMP2,3),R(TMP1,3),R(RIP,3)) });
	};

	using Mnemonics_CTL = SBA::Util::TypeList<
		JMP, JCC, CALL, RET, RETI,
		JCXZ, JECXZ, JRCXZ,
		LOOPNE, LOOPE, LOOP
	>;

	#undef PM
	#undef P

}
