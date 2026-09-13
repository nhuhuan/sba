module;
#include <cstdint>
#include <span>

export module sba.lift:alu_x86_64;

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

	template <O op, bool neg = false>
	struct P_ALU {
		P(rr,   { rrr_123<op>() },    { rrr_r23<O::CMP,neg>(R(FLAGS,l)) });
		P(ri,   { rri_123<op>() },    { rri_r23<O::CMP,neg>(R(FLAGS,l)) });
		PM(rm,  { rrm_123<op,lm>() }, { rrm_r23<O::CMP,lm,neg>(R(FLAGS,l)) });
		PM(mr,  { mr_112<op,lm>() },  { mr_r12<O::CMP,lm,neg>(R(FLAGS,l)) });
		PM(mi,  { mi_112<op,lm>() },  { mi_r12<O::CMP,lm,neg>(R(FLAGS,l)) });
	};

	template <O op, bool neg = false>
	struct P_ALUC {
		P(rr,   { rrr_123r<op>(R(FLAGS,l)) },    { rrr_r23<O::CMP,neg>(R(FLAGS,l)) });
		P(ri,   { rri_123r<op>(R(FLAGS,l)) },    { rri_r23<O::CMP,neg>(R(FLAGS,l)) });
		PM(rm,  { rrm_123r<op,lm>(R(FLAGS,l)) }, { rrm_r23<O::CMP,lm,neg>(R(FLAGS,l)) });
		PM(mr,  { mr_112r<op,lm>(R(FLAGS,l)) },  { mr_r12<O::CMP,lm,neg>(R(FLAGS,l)) });
		PM(mi,  { mi_112r<op,lm>(R(FLAGS,l)) },  { mi_r12<O::CMP,lm,neg>(R(FLAGS,l)) });
	};

	template <O op, bool neg = false>
	struct P_CMP {
		P(rr,  { rr_r12<op,neg>(R(FLAGS,l)) });
		P(ri,  { ri_r12<op,neg>(R(FLAGS,l)) });
		P(i,   { i_rr1<op,neg>(R(FLAGS,l),R(RAX,l)) });
		PM(rm, { rm_r12<op,lm,neg>(R(FLAGS,l)) });
		PM(mr, { mr_r12<op,lm,neg>(R(FLAGS,l)) });
		PM(mi, { mi_r12<op,lm,neg>(R(FLAGS,l)) });
	};

	template <O op, bool neg = false>
	struct P_STEP {
		P(r,   { rr_12i<op>(1) },   { rr_r2i<O::CMP,neg>(R(FLAGS,l),1) });
		PM(m,  { m_11i<op,lm>(1) }, { m_r1i<O::CMP,lm,neg>(R(FLAGS,l),1) });
	};

	template <O op_h, O op_l>
	struct P_MUL {
		P(r,   { r_rr1<op_h>(R(RDX,l),R(RAX,l)),    r_rr1<op_l>(R(RAX,l),R(RAX,l)) },    { r_rri<O::CMP>(R(FLAGS,l),R(RDX,l),0) });
		PM(m,  { m_rr1<op_h,lm>(R(RDX,l),R(RAX,l)), m_rr1<op_l,lm>(R(RAX,l),R(RAX,l)) }, { m_rri<O::CMP>(R(FLAGS,l),R(RDX,l),0) });
	};

	template <O op_h, O op_l>
	struct P_DIV {
		P(r,   { r_rrr<O::CAT>(R(TMP1,l+1),R(RDX,l),R(RAX,l)), r_rr1<op_h>(R(RDX,l),R(TMP1,l+1)),    r_rr1<op_l>(R(RAX,l),R(TMP1,l+1)) },    { r_r<O::CLB>(R(FLAGS,l)) });
		PM(m,  { m_rrr<O::CAT>(R(TMP1,l+1),R(RDX,l),R(RAX,l)), m_rr1<op_h,lm>(R(RDX,l),R(TMP1,l+1)), m_rr1<op_l,lm>(R(RAX,l),R(TMP1,l+1)) }, { m_r<O::CLB>(R(FLAGS,l)) });
	};

	template <O op>
	struct P_SHIFT {
		P(ri,   { rri_123<op>() },           { rri_r1i<O::CMP>(R(FLAGS,l),0) });
		PM(mi,  { mi_112<op,lm>() },         { mi_r1i<O::CMP,lm>(R(FLAGS,l),0) });
		P(r1,   { rr_12i<op>(1) },           { rr_r1i<O::CMP>(R(FLAGS,l),0) });
		PM(m1,  { m_11i<op,lm>(1) },         { m_r1i<O::CMP,lm>(R(FLAGS,l),0) });
		P(rCL,  { rr_12r<op>(R(RCX,0)) },    { rr_r1i<O::CMP>(R(FLAGS,l),0) });
		PM(mCL, { m_11r<op,lm>(R(RCX,0)) },  { m_r1i<O::CMP,lm>(R(FLAGS,l),0) });
	};

	template <O op>
	struct P_BITCNT {
		P(rr,  { rr_12<op>() },    { rr_r2i<O::CMP>(R(FLAGS,l),0) });
		PM(rm, { rm_12<op,lm>() }, { rm_r2i<O::CMP,lm>(R(FLAGS,l),0) });
	};

	/* -----------------------------------------------------------------------*/

	struct ADD  : P_ALU<O::ADD, true> {};
	struct SUB  : P_ALU<O::SUB> {};
	struct ADC  : P_ALUC<O::CADD, true> {};
	struct SBB  : P_ALUC<O::CSUB> {};
	struct AND  : P_ALU<O::AND> {};
	struct OR   : P_ALU<O::OR> {};
	struct XOR  : P_ALU<O::XOR> {};
	struct CMP  : P_CMP<O::CMP> {};
	struct TEST : P_CMP<O::AND> {};
	struct MUL  : P_MUL<O::UMULH, O::MUL> {};
	struct IMUL : P_MUL<O::MULH,  O::MUL> {
		P(rr,  { rrr_123<O::MUL>() },    { rrr_r23<O::CMP>(R(FLAGS,l)) });
		P(ri,  { rri_123<O::MUL>() },    { rri_r23<O::CMP>(R(FLAGS,l)) });
		PM(rm, { rrm_123<O::MUL,lm>() }, { rrm_r23<O::CMP,lm>(R(FLAGS,l)) });
	};
	struct DIV  : P_DIV<O::UMOD, O::UDIV> {};
	struct IDIV : P_DIV<O::MOD,  O::DIV> {};
	struct INC  : P_STEP<O::ADD, true> {};
	struct DEC  : P_STEP<O::SUB> {};
	struct NEG {
		P(r,   { rr_12<O::NEG>() },   { rr_ri2<O::CMP>(R(FLAGS,l),0) });
		PM(m,  { m_11<O::NEG,lm>() }, { m_ri1<O::CMP,lm>(R(FLAGS,l),0) });
	};
	struct NOT {
		P(r,   { rr_12<O::NOT>() });
		PM(m,  { m_11<O::NOT,lm>() });
	};
	struct SHL : P_SHIFT<O::SHL> {};
	struct SHR : P_SHIFT<O::SHR> {};
	struct SAR : P_SHIFT<O::ASHR> {};
	struct ROL : P_SHIFT<O::ROL> {};
	struct ROR : P_SHIFT<O::ROR> {};
	struct BSWAP {
		P(r, { rr_12<O::REV>() });
	};
	struct LZCNT  : P_BITCNT<O::CLZ> {};
	struct TZCNT  : P_BITCNT<O::CTZ> {};
	struct POPCNT : P_BITCNT<O::POP> {};
	struct BSF {
		P(rr,  { rrr_13<O::CTZ>() },    { rrr_r3i<O::CMP>(R(FLAGS,l),0) });
		PM(rm, { rrm_13<O::CTZ,lm>() }, { rrm_r3i<O::CMP,lm>(R(FLAGS,l),0) });
	};
	struct BSR {
		P(rr,  { rrr_r3<O::CLZ>(R(TMP1,l)),    rrr_1ir<O::SUB>((8 << l) - 1,R(TMP1,l)) },    { rrr_r3i<O::CMP>(R(FLAGS,l),0) });
		PM(rm, { rrm_r3<O::CLZ,lm>(R(TMP1,l)), rrm_1ir<O::SUB,lm>((8 << l) - 1,R(TMP1,l)) }, { rrm_r3i<O::CMP,lm>(R(FLAGS,l),0) });
	};

	using Mnemonics_ALU = SBA::Util::TypeList<
		ADD, SUB, AND, OR, XOR, CMP, TEST, ADC, SBB,
		INC, DEC, NEG, NOT, MUL, IMUL, DIV, IDIV,
		SHL, SHR, SAR, ROL, ROR, BSWAP,
		LZCNT, TZCNT, POPCNT, BSF, BSR
	>;

	#undef R
	#undef PM
	#undef P

}
