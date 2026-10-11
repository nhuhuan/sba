module;
#include <cstdint>
#include <span>

export module sba.lift:x86_64_vector;

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

	struct P_VEC_MOV {
		P(rr,  { rr_12<O::VAL>() });
		PM(rm, { rm_12<O::VAL,4>() });
		PM(mr, { mr_12<O::VAL,4>() });
	};

	template <uint8_t l_vec>
	struct P_VEC_MOVS {
		P(rr,  { mco<O::VAL>(r(0,l_vec),r(2,l_vec)) });
		PM(rm, { rm_12<O::ZEXT,l_vec>() });
		PM(mr, { mr_12<O::VAL,l_vec>() });
	};

	template <O op, uint8_t l_vec>
	struct P_VEC_ALU {
		P(rr,  { rrr_123<op>() });
		PM(rm, { rrm_123<op,l_vec>() });
	};

	template <uint8_t l_vec>
	struct P_VEC_CMP {
		P(rr,  { rr_x12<O::CMP>(R(FLAGS,0)) });
		PM(rm, { rm_x12<O::CMP,l_vec>(R(FLAGS,0)) });
	};

	/* -----------------------------------------------------------------------*/

	struct MOVAPS : P_VEC_MOV {};
	struct MOVUPS : P_VEC_MOV {};
	struct MOVAPD : P_VEC_MOV {};
	struct MOVUPD : P_VEC_MOV {};
	struct MOVDQA : P_VEC_MOV {};
	struct MOVDQU : P_VEC_MOV {};
	struct MOVSS : P_VEC_MOVS<2> {};
	struct MOVSD : P_VEC_MOVS<3> {};
	struct ADDSS : P_VEC_ALU<O::FADD,2> {};
	struct ADDSD : P_VEC_ALU<O::FADD,3> {};
	struct SUBSS : P_VEC_ALU<O::FSUB,2> {};
	struct SUBSD : P_VEC_ALU<O::FSUB,3> {};
	struct MULSS : P_VEC_ALU<O::FMUL,2> {};
	struct MULSD : P_VEC_ALU<O::FMUL,3> {};
	struct DIVSS : P_VEC_ALU<O::FDIV,2> {};
	struct DIVSD : P_VEC_ALU<O::FDIV,3> {};
	struct XORPS : P_VEC_ALU<O::XOR,4> {};
	struct XORPD : P_VEC_ALU<O::XOR,4> {};
	struct ANDPS : P_VEC_ALU<O::AND,4> {};
	struct ANDPD : P_VEC_ALU<O::AND,4> {};
	struct ORPS  : P_VEC_ALU<O::OR,4> {};
	struct ORPD  : P_VEC_ALU<O::OR,4> {};
	struct COMISS  : P_VEC_CMP<2> {};
	struct COMISD  : P_VEC_CMP<3> {};
	struct UCOMISS : P_VEC_CMP<2> {};
	struct UCOMISD : P_VEC_CMP<3> {};

	using Mnemonics_VEC = SBA::Util::TypeList<
		MOVAPS, MOVUPS, MOVAPD, MOVUPD, MOVDQA, MOVDQU,
		MOVSS, MOVSD,
		ADDSS, ADDSD, SUBSS, SUBSD, MULSS, MULSD, DIVSS, DIVSD,
		XORPS, XORPD, ANDPS, ANDPD, ORPS, ORPD,
		COMISS, COMISD, UCOMISS, UCOMISD
	>;

	#undef PM
	#undef P

}
