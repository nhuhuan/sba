module;
#include <cstdint>
#include <span>

export module sba.lift:data_x86_64;

import sba.arch;
import sba.ir;
import :emit;
import :pattern_x86_64;
import :dispatch_x86_64;

namespace SBA::Lift::X86_64 {

	#define R(reg, ...) \
		REG(SBA::Arch::X86_64::Reg::reg __VA_OPT__(,) __VA_ARGS__)

	#define P(Suffix, ...) \
		template <uint8_t l> \
		static constexpr Pattern Suffix = { __VA_ARGS__ }

	#define PM(Suffix, ...) \
		template <uint8_t l, uint8_t lm = l> \
		static constexpr Pattern Suffix = { __VA_ARGS__ }

	template <O op>
	struct P_MOV {
		P(rr,  { rr_12<op>() });
		PM(rm, { rm_12<op,lm>() });
	};

	template <uint8_t l>
	struct P_SEXT_A {
		template <uint8_t>
		static constexpr Pattern _ = { { _rr<O::SEXT>(R(RAX,l),R(RAX,l-1)) } };
	};

	template <uint8_t l>
	struct P_SEXT_DA {
		template <uint8_t>
		static constexpr Pattern _ = { { _rri<O::ASHR>(R(RDX,l),R(RAX,l),(8<<l)-1) } };
	};

	/* -----------------------------------------------------------------------*/

	struct MOV : P_MOV<O::VAL> {
		P(ri,  { ri_12<O::VAL>() });
		PM(mr, { mr_12<O::VAL,lm>() });
		PM(mi, { mi_12<O::VAL,lm>() });
	};
	struct MOVSX : P_MOV<O::SEXT> {};
	struct MOVZX : P_MOV<O::ZEXT> {};
	struct CBW  : P_SEXT_A<1> {};
	struct CWDE : P_SEXT_A<2> {};
	struct CDQE : P_SEXT_A<3> {};
	struct CWD  : P_SEXT_DA<1> {};
	struct CDQ  : P_SEXT_DA<2> {};
	struct CQO  : P_SEXT_DA<3> {};
	struct LEA {
		P(r,   { ra_12<O::VAL>() });
	};
	struct XCHG {
		P(rr,  { rr_r1<O::VAL>(R(TMP1,l)), rr_12<O::VAL>(),    rr_2r<O::VAL>(R(TMP1,l)) });
		PM(rm, { rm_r1<O::VAL>(R(TMP1,l)), rm_12<O::VAL,lm>(), rm_2r<O::VAL,lm>(R(TMP1,l)) });
		P(ar,  { r_r1<O::VAL>(R(TMP1,l)),  r_1r<O::VAL>(R(RAX,l)), r_rr<O::VAL>(R(RAX,l),R(TMP1,l)) });
	};
	struct CMOV {
		template <uint8_t l>
		static Instruction rr(
			Context& ctx,
			Cache& cache,
			const MCInstruction& inst)
		{
			uint8_t cc = inst.getOperand(3).getImm();
			MCO ops[] = {
				{ CC[cc], r(0), R(FLAGS,l), r(2), r(1) }
			};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}

		template <uint8_t l, uint8_t lm = l>
		static Instruction rm(
			Context& ctx,
			Cache& cache,
			const MCInstruction& inst)
		{
			uint8_t cc = inst.getOperand(7).getImm();
			MCO ops[] = {
				{ CC[cc], r(0), R(FLAGS,l), m(2,lm), r(1) }
			};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}
	};
	struct SETCC {
		template <uint8_t l>
		static Instruction r(
			Context& ctx,
			Cache& cache,
			const MCInstruction& inst)
		{
			uint8_t cc = inst.getOperand(1).getImm();
			MCO ops[] = {{ CC[cc], X86_64::r(0), R(FLAGS,0), 1ULL, 0ULL }};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}

		template <uint8_t l, uint8_t lm = l>
		static Instruction m(
			Context& ctx,
			Cache& cache,
			const MCInstruction& inst)
		{
			uint8_t cc = inst.getOperand(5).getImm();
			MCO ops[] = {{ CC[cc], X86_64::m(0,lm), R(FLAGS,0), 1ULL, 0ULL }};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}
	};

	using Mnemonics_DATA = SBA::Util::TypeList<
		MOVSX, MOVZX, MOV, LEA, XCHG,
		CBW, CWDE, CDQE, CWD, CDQ, CQO,
		CMOV, SETCC
	>;

	#undef R
	#undef PM
	#undef P

}
