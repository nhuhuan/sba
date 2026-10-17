module;
#include <cstdint>
#include <span>

export module sba.lift:x86_64_data;

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

	template <O op>
	struct P_MOV_EXT {
		P(rr,  { rr_12<op>() });
		PM(rm, { rm_12<op,lm>() });
	};

	template <uint8_t l>
	struct P_SEXT_A {
		template <uint8_t>
		static constexpr Pattern _ = { { mco<O::SEXT>(R(RAX,l),R(RAX,(l/2))) } };
	};

	template <uint8_t l>
	struct P_SEXT_DA {
		template <uint8_t>
		static constexpr Pattern _ = { { mco<O::ASHR>(R(RDX,l),R(RAX,l),l-1) } };
	};

	/* -----------------------------------------------------------------------*/

	struct MOV {
		P(rr,  { rr_12<O::VAL>() });
		P(ri,  { ri_12<O::VAL>() });
		PM(rm, { rm_12<O::VAL,lm>() });
		PM(mr, { mr_12<O::VAL,lm>() });
		PM(mi, { mi_12<O::VAL,lm>() });
		template <>
		constexpr Pattern rr<32> = { { mco<O::ZEXT>(r(0,64),r(1,32)) } };
		template <>
		constexpr Pattern ri<32> = { { mco<O::ZEXT>(r(0,64),i(1)) } };
		template <>
		constexpr Pattern rm<32, 32> = { { mco<O::ZEXT>(r(0,64),m(1,32)) } };
	};
	struct MOVSX : P_MOV_EXT<O::SEXT> {};
	struct MOVZX : P_MOV_EXT<O::ZEXT> {};
	struct CBW  : P_SEXT_A<16> {};
	struct CWDE : P_SEXT_A<32> {};
	struct CDQE : P_SEXT_A<64> {};
	struct CWD  : P_SEXT_DA<16> {};
	struct CDQ  : P_SEXT_DA<32> {};
	struct CQO  : P_SEXT_DA<64> {};
	struct LEA {
		P(r,   { ra_12<O::VAL>() });
	};
	struct XCHG {
		P(rr,  { rr_x1<O::VAL>(R(TMP1,l)),
				 rr_12<O::VAL>(),
				 rr_2x<O::VAL>(R(TMP1,l)) });
		PM(rm, { rrm_x1<O::VAL>(R(TMP1,l)),
				 rrm_13<O::VAL,lm>(),
				 rrm_3x<O::VAL,lm>(R(TMP1,l)) });
		P(ar,  { r_x1<O::VAL>(R(TMP1,l)),
				 r_1x<O::VAL>(R(RAX,l)),
				 mco<O::VAL>(R(RAX,l),R(TMP1,l)) });
	};
	struct CMPXCHG {
		P(rr,  { rr_x1<O::VAL>(R(TMP3,l)),
				 mco<O::CMP>(R(FLAGS,l),R(TMP3,l),R(RAX,l)),
				 rr_1x2x<O::SELECT_EQ>(R(FLAGS,l),R(TMP3,l)),
				 mco<O::SELECT_EQ>(R(RAX,l),R(FLAGS,l),R(RAX,l),R(TMP3,l)) });
		PM(rm, { mr_x1<O::VAL,lm>(R(TMP3,l)),
				 mco<O::CMP>(R(FLAGS,l),R(TMP3,l),R(RAX,l)),
				 mr_1x2x<O::SELECT_EQ,lm>(R(FLAGS,l),R(TMP3,l)),
				 mco<O::SELECT_EQ>(R(RAX,l),R(FLAGS,l),R(RAX,l),R(TMP3,l)) });
	};
	struct CMPXCHG8B {
		template <uint8_t l>
		static constexpr Pattern _ = { {
			mco<O::VAL>(R(TMP3,64),m(0,64)),
			mco<O::CAT>(R(TMP4,64),R(RDX,32),R(RAX,32)),
			mco<O::CMP>(R(FLAGS,64),R(TMP3,64),R(TMP4,64)),
			mco<O::CAT>(R(TMP2,64),R(RCX,32),R(RBX,32)),
			mco<O::SELECT_EQ>(m(0,64),R(FLAGS,64),R(TMP2,64),R(TMP3,64)),
			mco<O::SELECT_EQ>(R(RAX,32),R(FLAGS,64),R(RAX,32),R(TMP3,0,32)),
			mco<O::SELECT_EQ>(R(RDX,32),R(FLAGS,64),R(RDX,32),R(TMP3,32,32))
		} };
	};
	struct CMPXCHG16B {
		template <uint8_t l>
		static constexpr Pattern _ = { {
			mco<O::VAL>(R(TMP3,128),m(0,128)),
			mco<O::CAT>(R(TMP4,128),R(RDX,64),R(RAX,64)),
			mco<O::CMP>(R(FLAGS,64),R(TMP3,128),R(TMP4,128)),
			mco<O::CAT>(R(TMP2,128),R(RCX,64),R(RBX,64)),
			mco<O::SELECT_EQ>(m(0,128),R(FLAGS,64),R(TMP2,128),R(TMP3,128)),
			mco<O::SELECT_EQ>(R(RAX,64),R(FLAGS,64),R(RAX,64),R(TMP3,0,64)),
			mco<O::SELECT_EQ>(R(RDX,64),R(FLAGS,64),R(RDX,64),R(TMP3,64,64))
		} };
	};
	struct XADD {
		P(rr,  { rr_x1<O::VAL>(R(TMP1,l)),
				 rr_112<O::ADD>(),
				 rr_2x<O::VAL>(R(TMP1,l)) },
			   { rr_x12<O::CMP,true>(R(FLAGS,l)) });
		PM(rm, { rrm_x3<O::VAL,lm>(R(TMP1,l)),
				 rrm_331<O::ADD,lm>(),
				 rrm_1x<O::VAL>(R(TMP1,l)) },
			   { rrm_x31<O::CMP,lm,true>(R(FLAGS,l)) });
	};
	struct CMOV {
		template <uint8_t l>
		static Instruction rr(
			Context& ctx,
			Cache& cache,
			const MCInstruction& inst)
		{
			uint8_t cc = inst.getOperand(3).getImm();
			MCO ops[] = { { CC[cc],r(0),R(FLAGS,l),r(2),r(1) } };
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}

		template <uint8_t l, uint8_t lm = l>
		static Instruction rm(
			Context& ctx,
			Cache& cache,
			const MCInstruction& inst)
		{
			uint8_t cc = inst.getOperand(7).getImm();
			MCO ops[] = { { CC[cc],r(0),R(FLAGS,l),m(2,lm),r(1) } };
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}
	};
	struct SETCC {
		template <uint8_t l>
		static Instruction r(Context& ctx, Cache& cache, const MCInstruction& inst)
		{
			uint8_t cc = inst.getOperand(1).getImm();
			MCO ops[] = { { CC[cc],X86_64::r(0),R(FLAGS,64),1ULL,0ULL } };
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}

		template <uint8_t l, uint8_t lm = l>
		static Instruction m(Context& ctx, Cache& cache, const MCInstruction& inst)
		{
			uint8_t cc = inst.getOperand(5).getImm();
			MCO ops[] = { { CC[cc],X86_64::m(0,lm),R(FLAGS,64),1ULL,0ULL } };
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}
	};
	struct PUSH {
		P(r,   { mco<O::VAL>(R(RSP),A(RSP,-bits_to_bytes(l))),
				 r_x1<O::VAL>(M(RSP,l)) });
		P(i,   { mco<O::VAL>(R(RSP),A(RSP,-bits_to_bytes(l))),
				 i_x1<O::VAL>(M(RSP,l)) });
		PM(m,  { mco<O::VAL>(R(RSP),A(RSP,-bits_to_bytes(l))),
				 m_x1<O::VAL,lm>(M(RSP,l)) });
	};
	struct POP {
		P(r,   { r_1x<O::VAL>(M(RSP,l)),
				 mco<O::VAL>(R(RSP),A(RSP,bits_to_bytes(l))) });
		PM(m,  { m_1x<O::VAL,lm>(M(RSP,l)),
				 mco<O::VAL>(R(RSP),A(RSP,bits_to_bytes(l))) });
	};
	struct PUSHF {
		P(_,   { mco<O::VAL>(R(RSP),A(RSP,-bits_to_bytes(l))),
				 mco<O::VAL>(M(RSP,l),R(FLAGS,l)) });
	};
	struct POPF {
		P(_,   { mco<O::VAL>(R(FLAGS,l),M(RSP,l)),
				 mco<O::VAL>(R(RSP),A(RSP,bits_to_bytes(l))) });
	};
	struct LEAVE {
		P(_,   { mco<O::VAL>(R(RSP),R(RBP)),
				 mco<O::VAL>(R(RBP,l),M(RSP,l)),
				 mco<O::VAL>(R(RSP),A(RSP,bits_to_bytes(l))) });
	};

	using Mnemonics_DAT = SBA::Util::TypeList<
		MOVSX, MOVZX, MOV, LEA, XCHG, CMPXCHG,
		CMPXCHG8B, CMPXCHG16B, XADD,
		PUSH, POP, PUSHF, POPF, LEAVE,
		CBW, CWDE, CDQE, CWD, CDQ, CQO,
		CMOV, SETCC
	>;

	#undef PM
	#undef P

}
