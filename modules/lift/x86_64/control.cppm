module;
#include <cstdint>

export module sba.lift:x86_64_control;

import sba.arch;
import sba.ir;
import :emit;
import :x86_64_pattern;

namespace SBA::Lift::X86_64 {

	#define P(Suffix, ...) \
		template <uint8_t l> \
		static constexpr Pattern Suffix = { __VA_ARGS__ }

	#define PM(Suffix, ...) \
		template <uint8_t l, uint8_t lm = l> \
		static constexpr Pattern Suffix = { __VA_ARGS__ }

	template <uint8_t l_rcx>
	struct P_JCXZ {
		template <uint8_t l>
		static Instruction _(Context& ctx, Cache& cache, const MCInstruction& inst)
		{
			int32_t rel = inst.getOperand(0).getImm();
			MCOP ops[] = {
				mcop<O::CMP>(R(TMP1), R(RCX)[0,l_rcx], 0ULL),
				mcop<O::SELECT_EQ>(R(RIP), R(TMP1), A(RIP+rel), R(RIP))
			};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}
	};

	template <O cc>
	struct P_LOOP_CC {
		template <uint8_t l>
		static Instruction _(Context& ctx, Cache& cache, const MCInstruction& inst)
		{
			int32_t rel = inst.getOperand(0).getImm();
			MCOP ops[] = {
				mcop<O::VAL>(R(RCX), A(RCX-1)),
				mcop<cc>(R(TMP1), R(FLAGS), A(RIP+rel), R(RIP)),
				mcop<O::CMP>(R(TMP2), R(RCX), 0ULL),
				mcop<O::SELECT_NE>(R(RIP), R(TMP2), R(TMP1), R(RIP))
			};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}
	};

	/* -----------------------------------------------------------------------*/

	struct JMP {
		P(_,  { i_xx1<O::ADD>(R(RIP), R(RIP)) });
		P(r,  { r_x1<O::VAL>(R(RIP)) });
		PM(m, { m_x1<O::VAL,lm>(R(RIP)) });
	};
	struct JCC {
		template <uint8_t l>
		static Instruction _(Context& ctx, Cache& cache, const MCInstruction& inst)
		{
			uint8_t cc = inst.getOperand(1).getImm();
			int32_t rel = inst.getOperand(0).getImm();
			MCOP ops[] = {
				{ CC[cc], R(RIP), R(FLAGS), A(RIP+rel), R(RIP) }
			};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}
	};
	struct CALL {
		P(_,  { mcop<O::VAL>(R(RSP), A(RSP-bits_to_bytes(l))),
				mcop<O::VAL>(M(RSP)[l], R(RIP)),
				i_xx1<O::ADD>(R(RIP), R(RIP)) });
		P(r,  { mcop<O::VAL>(R(RSP), A(RSP-bits_to_bytes(l))),
				mcop<O::VAL>(M(RSP)[l], R(RIP)),
				r_x1<O::VAL>(R(RIP)) });
		PM(m, { mcop<O::VAL>(R(RSP), A(RSP-bits_to_bytes(l))),
				mcop<O::VAL>(M(RSP)[l], R(RIP)),
				m_x1<O::VAL,lm>(R(RIP)) });
	};
	struct RET {
		P(_, { mcop<O::VAL>(R(RIP), M(RSP)[l]),
			   mcop<O::VAL>(R(RSP), A(RSP+bits_to_bytes(l))) });
	};
	struct RETI {
		template <uint8_t l>
		static Instruction _(Context& ctx, Cache& cache, const MCInstruction& inst)
		{
			int32_t imm = inst.getOperand(0).getImm();
			MCOP ops[] = {
				mcop<O::VAL>(R(RIP), M(RSP)[l]),
				mcop<O::VAL>(R(RSP), A(RSP+(bits_to_bytes(l)+imm)))
			};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}
	};
	struct JCXZ   : P_JCXZ<16> {};
	struct JECXZ  : P_JCXZ<32> {};
	struct JRCXZ  : P_JCXZ<64> {};
	struct LOOPE  : P_LOOP_CC<O::SELECT_EQ> {};
	struct LOOPNE : P_LOOP_CC<O::SELECT_NE> {};
	struct LOOP {
		template <uint8_t l>
		static Instruction _(Context& ctx, Cache& cache, const MCInstruction& inst)
		{
			int32_t rel = inst.getOperand(0).getImm();
			MCOP ops[] = {
				mcop<O::VAL>(R(RCX), A(RCX-1)),
				mcop<O::CMP>(R(TMP1), R(RCX), 0ULL),
				mcop<O::SELECT_NE>(R(RIP), R(TMP1), A(RIP+rel), R(RIP))
			};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}
	};

	using Mnemonics_CTL = SBA::Util::TypeList<
		JMP, JCC, CALL, RET, RETI,
		JCXZ, JECXZ, JRCXZ,
		LOOPNE, LOOPE, LOOP
	>;

	#undef PM
	#undef P

}
