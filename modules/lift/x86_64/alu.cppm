module;
#include <cstdint>
#include <span>

export module sba.lift:x86_64_alu;

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

	template <O op, bool neg = false>
	struct P_ALU {
		P(rr,   { rrr_123<op>() },    { rrr_x23<O::CMP,neg>(R(FLAGS,l)) });
		P(ri,   { rri_123<op>() },    { rri_x23<O::CMP,neg>(R(FLAGS,l)) });
		PM(rm,  { rrm_123<op,lm>() }, { rrm_x23<O::CMP,lm,neg>(R(FLAGS,l)) });
		PM(mr,  { mr_112<op,lm>() },  { mr_x12<O::CMP,lm,neg>(R(FLAGS,l)) });
		PM(mi,  { mi_112<op,lm>() },  { mi_x12<O::CMP,lm,neg>(R(FLAGS,l)) });
		template <>
		constexpr Pattern rr<2> = {
			{ rrr_123<op>(),mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rrr_x23<O::CMP,neg>(R(FLAGS,2)) }
		};
		template <>
		constexpr Pattern ri<2> = {
			{ rri_123<op>(),mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rri_x23<O::CMP,neg>(R(FLAGS,2)) }
		};
		template <>
		constexpr Pattern rm<2, 2> = {
			{ rrm_123<op,2>(),mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rrm_x23<O::CMP,2,neg>(R(FLAGS,2)) }
		};
	};

	template <O op, bool neg = false>
	struct P_ALUC {
		P(rr,   { rrr_123x<op>(R(FLAGS,l)) },    { rrr_x23<O::CMP,neg>(R(FLAGS,l)) });
		P(ri,   { rri_123x<op>(R(FLAGS,l)) },    { rri_x23<O::CMP,neg>(R(FLAGS,l)) });
		PM(rm,  { rrm_123x<op,lm>(R(FLAGS,l)) }, { rrm_x23<O::CMP,lm,neg>(R(FLAGS,l)) });
		PM(mr,  { mr_112x<op,lm>(R(FLAGS,l)) },  { mr_x12<O::CMP,lm,neg>(R(FLAGS,l)) });
		PM(mi,  { mi_112x<op,lm>(R(FLAGS,l)) },  { mi_x12<O::CMP,lm,neg>(R(FLAGS,l)) });
		template <>
		constexpr Pattern rr<2> = {
			{ rrr_123x<op>(R(FLAGS,2)),mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rrr_x23<O::CMP,neg>(R(FLAGS,2)) }
		};
		template <>
		constexpr Pattern ri<2> = {
			{ rri_123x<op>(R(FLAGS,2)),mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rri_x23<O::CMP,neg>(R(FLAGS,2)) }
		};
		template <>
		constexpr Pattern rm<2,2> = {
			{ rrm_123x<op,2>(R(FLAGS,2)),mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rrm_x23<O::CMP,2,neg>(R(FLAGS,2)) } };
	};

	template <O op, bool neg = false>
	struct P_CMP {
		P(rr,  { rr_x12<op,neg>(R(FLAGS,l)) });
		P(ri,  { ri_x12<op,neg>(R(FLAGS,l)) });
		P(i,   { i_xx1<op,neg>(R(FLAGS,l),R(RAX,l)) });
		PM(rm, { rm_x12<op,lm,neg>(R(FLAGS,l)) });
		PM(mr, { mr_x12<op,lm,neg>(R(FLAGS,l)) });
		PM(mi, { mi_x12<op,lm,neg>(R(FLAGS,l)) });
	};

	template <O op, int64_t val>
	struct P_STEP {
		P(r,   { rr_12x<op>(1) },   { rr_x2x<O::CMP>(R(FLAGS,l),val) });
		PM(m,  { m_11x<op,lm>(1) }, { m_x1x<O::CMP,lm>(R(FLAGS,l),val) });
	};

	template <O op_h, O op_l>
	struct P_MUL {
		P(r,   { r_xx1<op_h>(R(RDX,l),R(RAX,l)), r_xx1<op_l>(R(RAX,l),R(RAX,l)) },
			   { mco<O::CMP>(R(FLAGS,l),R(RDX,l),0) });
		PM(m,  { m_xx1<op_h,lm>(R(RDX,l),R(RAX,l)), m_xx1<op_l,lm>(R(RAX,l),R(RAX,l)) },
			   { mco<O::CMP>(R(FLAGS,l),R(RDX,l),0) });
	};

	template <O op_h, O op_l>
	struct P_DIV {
		P(r,   { mco<O::CAT>(R(TMP1,l+1),R(RDX,l),R(RAX,l)),
				 r_xx1<op_h>(R(RDX,l),R(TMP1,l+1)),
				 r_xx1<op_l>(R(RAX,l),R(TMP1,l+1)) },
			   { mco<O::CLB>(R(FLAGS,l)) });
		PM(m,  { mco<O::CAT>(R(TMP1,l+1),R(RDX,l),R(RAX,l)),
				 m_xx1<op_h,lm>(R(RDX,l),R(TMP1,l+1)),
				 m_xx1<op_l,lm>(R(RAX,l),R(TMP1,l+1)) },
			   { mco<O::CLB>(R(FLAGS,l)) });
	};

	template <O op>
	struct P_SHIFT {
		P(ri,   { rri_123<op>() },           { rr_x1x<O::CMP>(R(FLAGS,l),0) });
		PM(mi,  { mi_112<op,lm>() },         { m_x1x<O::CMP,lm>(R(FLAGS,l),0) });
		P(r1,   { rr_12x<op>(1) },           { rr_x1x<O::CMP>(R(FLAGS,l),0) });
		PM(m1,  { m_11x<op,lm>(1) },         { m_x1x<O::CMP,lm>(R(FLAGS,l),0) });
		P(rCL,  { rr_12x<op>(R(RCX,0)) },    { rr_x1x<O::CMP>(R(FLAGS,l),0) });
		PM(mCL, { m_11x<op,lm>(R(RCX,0)) },  { m_x1x<O::CMP,lm>(R(FLAGS,l),0) });
	};

	template <O op>
	struct P_SHIFT_2 {
		P(rr,  { rrr_123<op>() });
		PM(rm, { rmr_123<op,lm>() });
		template <>
		constexpr Pattern rr<2> = { { rrr_123<op>(), mco<O::ZEXT>(r(0,3),r(0,2)) } };
		template <>
		constexpr Pattern rm<2,2> = { { rmr_123<op,2>(), mco<O::ZEXT>(r(0,3),r(0,2)) } };
	};

	template <O op>
	struct P_BITCNT {
		P(rr,  { rr_12<op>() },    { rr_x2x<O::CMP>(R(FLAGS,l),0) });
		PM(rm, { rm_12<op,lm>() }, { rm_x2x<O::CMP,lm>(R(FLAGS,l),0) });
	};

	template <O op>
	struct P_BLS_MASK {
		P(rr,  { rr_x2x<O::ADD>(R(TMP1,l),-1ULL),rr_12x<op>(R(TMP1,l)) },
			   { rr_x1x<O::CMP>(R(FLAGS,l),0) });
		PM(rm, { rm_x2x<O::ADD,lm>(R(TMP1,l),-1ULL),rm_12x<op,lm>(R(TMP1,l)) },
			   { rm_x1x<O::CMP,lm>(R(FLAGS,l),0) });
		template <>
		constexpr Pattern rr<2> = {
			{ rr_x2x<O::ADD>(R(TMP1,2),-1ULL),rr_12x<op>(R(TMP1,2)),mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rr_x1x<O::CMP>(R(FLAGS,2),0) }
		};
		template <>
		constexpr Pattern rm<2,2> = {
			{ rm_x2x<O::ADD,2>(R(TMP1,2),-1ULL),rm_12x<op,2>(R(TMP1,2)),mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rm_x1x<O::CMP,2>(R(FLAGS,2),0) }
		};
	};

	template <Operand c>
	struct P_CADD_EXT {
		P(rr,  { rrr_123x<O::CADD>(c) },
			   { rrr_x23x<O::CCMP,true>(R(FLAGS,l),c) });
		PM(rm, { rrm_123x<O::CADD,lm>(c) },
			   { rrm_x23x<O::CCMP,lm,true>(R(FLAGS,l),c) });
		template <>
		constexpr Pattern rr<2> = {
			{ rrr_123x<O::CADD>(c),mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rrr_x23x<O::CCMP,true>(R(FLAGS,2),c) }
		};
		template <>
		constexpr Pattern rm<2,2> = {
			{ rrm_123x<O::CADD,2>(c),mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rrm_x23x<O::CCMP,2,true>(R(FLAGS,2),c) }
		};
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
		P(rr,  { rrr_123<O::MUL>() },    { rrr_x23<O::CMP>(R(FLAGS,l)) });
		P(ri,  { rri_123<O::MUL>() },    { rri_x23<O::CMP>(R(FLAGS,l)) });
		PM(rm, { rrm_123<O::MUL,lm>() }, { rrm_x23<O::CMP,lm>(R(FLAGS,l)) });
	};
	struct DIV  : P_DIV<O::UMOD, O::UDIV> {};
	struct IDIV : P_DIV<O::MOD,  O::DIV> {};
	struct INC  : P_STEP<O::ADD,-1> {};
	struct DEC  : P_STEP<O::SUB,1> {};
	struct NEG {
		P(r,   { rr_12<O::NEG>() },   { rr_xx2<O::CMP>(R(FLAGS,l),0) });
		PM(m,  { m_11<O::NEG,lm>() }, { m_xx1<O::CMP,lm>(R(FLAGS,l),0) });
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
	struct MOVBE {
		P(rr,  { rr_12<O::REV>() });
		PM(rm, { rm_12<O::REV,lm>() });
		PM(mr, { mr_12<O::REV,lm>() });
	};
	struct LZCNT  : P_BITCNT<O::CLZ> {};
	struct TZCNT  : P_BITCNT<O::CTZ> {};
	struct POPCNT : P_BITCNT<O::POP> {};
	struct BSF {
		P(rr,  { rrr_13<O::CTZ>() },    { rrr_x3x<O::CMP>(R(FLAGS,l),0) });
		PM(rm, { rrm_13<O::CTZ,lm>() }, { rrm_x3x<O::CMP,lm>(R(FLAGS,l),0) });
	};
	struct BSR {
		P(rr,  { rrr_x3<O::CLZ>(R(TMP1,l)), rrr_1xx<O::SUB>(bits(l)-1,R(TMP1,l)) },
			   { rrr_x3x<O::CMP>(R(FLAGS,l),0) });
		PM(rm, { rrm_x3<O::CLZ,lm>(R(TMP1,l)), rrm_1xx<O::SUB,lm>(bits(l)-1,R(TMP1,l)) },
			   { rrm_x3x<O::CMP,lm>(R(FLAGS,l),0) });
	};
	struct ANDN {
		P(rr,  { rrr_x2<O::NOT>(R(TMP1,l)),rrr_1x3<O::AND>(R(TMP1,l)) },
			   { rrr_x1x<O::CMP>(R(FLAGS,l),0) });
		PM(rm, { rrm_x2<O::NOT>(R(TMP1,l)),rrm_1x3<O::AND,lm>(R(TMP1,l)) },
			   { rrm_x1x<O::CMP,lm>(R(FLAGS,l),0) });
		template <>
		constexpr Pattern rr<2> = {
			{ rrr_x2<O::NOT>(R(TMP1,2)),rrr_1x3<O::AND>(R(TMP1,2)),mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rrr_x1x<O::CMP>(R(FLAGS,2),0) }
		};
		template <>
		constexpr Pattern rm<2,2> = {
			{ rrm_x2<O::NOT>(R(TMP1,2)),rrm_1x3<O::AND,2>(R(TMP1,2)),mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rrm_x1x<O::CMP,2>(R(FLAGS,2),0) }
		};
	};
	struct BLSI {
		P(rr,  { rr_x2<O::NEG>(R(TMP1,l)),rr_12x<O::AND>(R(TMP1,l)) },
			   { rr_x1x<O::CMP>(R(FLAGS,l),0) });
		PM(rm, { rm_x2<O::NEG,lm>(R(TMP1,l)),rm_12x<O::AND,lm>(R(TMP1,l)) },
			   { rm_x1x<O::CMP,lm>(R(FLAGS,l),0) });
		template <>
		constexpr Pattern rr<2> = {
			{ rr_x2<O::NEG>(R(TMP1,2)),rr_12x<O::AND>(R(TMP1,2)),mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rr_x1x<O::CMP>(R(FLAGS,2),0) }
		};
		template <>
		constexpr Pattern rm<2,2> = {
			{ rm_x2<O::NEG,2>(R(TMP1,2)),rm_12x<O::AND,2>(R(TMP1,2)),mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rm_x1x<O::CMP,2>(R(FLAGS,2),0) }
		};
	};
	struct BLSR   : P_BLS_MASK<O::AND> {};
	struct BLSMSK : P_BLS_MASK<O::XOR> {};
	struct BZHI {
		P(rr,  { rrr_xx3<O::SHL>(R(TMP1,l),1),
				 rr_12x<O::AND>(A(TMP1,-1)) },
			   { rrr_x1x<O::CMP>(R(FLAGS,l),0) });
		PM(rm, { rmr_xx3<O::SHL,lm>(R(TMP1,l),1),
				 rm_12x<O::AND,lm>(A(TMP1,-1)) },
			   { rmr_x1x<O::CMP,lm>(R(FLAGS,l),0) });
		template <>
		constexpr Pattern rr<2> = {
			{ rrr_xx3<O::SHL>(R(TMP1,2),1),
			  rr_12x<O::AND>(A(TMP1,-1)),
			  mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rrr_x1x<O::CMP>(R(FLAGS,2),0) }
		};
		template <>
		constexpr Pattern rm<2,2> = {
			{ rmr_xx3<O::SHL,2>(R(TMP1,2),1),
			  rm_12x<O::AND,2>(A(TMP1,-1)),
			  mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rmr_x1x<O::CMP,2>(R(FLAGS,2),0) }
		};
	};
	struct BEXTR {
		P(rr,  { rrr_x3x<O::AND>(R(TMP1,l),0x3FULL),
				 rrr_x2x<O::SHR>(R(TMP2,l),R(TMP1,l)),
				 rrr_x3x<O::SHR>(R(TMP1,l),8),
				 mco<O::SHL>(R(TMP1,l),1,R(TMP1,0,0)),
				 mco<O::AND>(r(0),R(TMP2,l),A(TMP1,-1)) },
			   { rrr_x1x<O::CMP>(R(FLAGS,l),0) });
		PM(rm, { rmr_x3x<O::AND,lm>(R(TMP1,l),0x3FULL),
				 rmr_x2x<O::SHR,lm>(R(TMP2,l),R(TMP1,l)),
				 rmr_x3x<O::SHR,lm>(R(TMP1,l),8),
				 mco<O::SHL>(R(TMP1,l),1,R(TMP1,0,0)),
				 mco<O::AND>(r(0),R(TMP2,l),A(TMP1,-1)) },
			   { rmr_x1x<O::CMP,lm>(R(FLAGS,l),0) });
		template <>
		constexpr Pattern rr<2> = {
			{ rrr_x3x<O::AND>(R(TMP1,2),0x3FULL),
			  rrr_x2x<O::SHR>(R(TMP2,2),R(TMP1,2)),
			  rrr_x3x<O::SHR>(R(TMP1,2),8),
			  mco<O::SHL>(R(TMP1,2),1,R(TMP1,0,0)),
			  mco<O::AND>(r(0),R(TMP2,2),A(TMP1,-1)),
			  mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rrr_x1x<O::CMP>(R(FLAGS,2),0) }
		};
		template <>
		constexpr Pattern rm<2,2> = {
			{ rmr_x3x<O::AND,2>(R(TMP1,2),0x3FULL),
			  rmr_x2x<O::SHR,2>(R(TMP2,2),R(TMP1,2)),
			  rmr_x3x<O::SHR,2>(R(TMP1,2),8),
			  mco<O::SHL>(R(TMP1,2),1,R(TMP1,0,0)),
			  mco<O::AND>(r(0),R(TMP2,2),A(TMP1,-1)),
			  mco<O::ZEXT>(r(0,3),r(0,2)) },
			{ rmr_x1x<O::CMP,2>(R(FLAGS,2),0) }
		};
	};
	struct SARX : P_SHIFT_2<O::ASHR> {};
	struct SHLX : P_SHIFT_2<O::SHL> {};
	struct SHRX : P_SHIFT_2<O::SHR> {};
	struct MULX {
		P(rr,  { rrr_1x3<O::UMULH>(R(RDX,l)),rrr_2x3<O::MUL>(R(RDX,l)) });
		PM(rm, { rrm_1x3<O::UMULH,lm>(R(RDX,l)),rrm_2x3<O::MUL,lm>(R(RDX,l)) });
		template <>
		constexpr Pattern rr<2> = {
			{ rrr_1x3<O::UMULH>(R(RDX,2)),mco<O::ZEXT>(r(0,3),r(0,2)),
			  rrr_2x3<O::MUL>(R(RDX,2)),mco<O::ZEXT>(r(1,3),r(1,2)) }
		};
		template <>
		constexpr Pattern rm<2,2> = {
			{ rrm_1x3<O::UMULH,2>(R(RDX,2)),mco<O::ZEXT>(r(0,3),r(0,2)),
			  rrm_2x3<O::MUL,2>(R(RDX,2)),mco<O::ZEXT>(r(1,3),r(1,2)) }
		};
	};
	struct ADCX : P_CADD_EXT<R2(FLAGS,1,0)>  {}; /* CF */
	struct ADOX : P_CADD_EXT<R2(FLAGS,1,11)> {}; /* OF */

	using Mnemonics_ALU = SBA::Util::TypeList<
		ADD, SUB, AND, OR, XOR, CMP, TEST, ADC, SBB,
		INC, DEC, NEG, NOT, MUL, IMUL, DIV, IDIV,
		SHL, SHR, SAR, ROL, ROR, BSWAP, MOVBE,
		LZCNT, TZCNT, POPCNT, BSF, BSR,
		ANDN, BLSR, BLSMSK, BLSI, BZHI, BEXTR,
		SARX, SHLX, SHRX, MULX, ADCX, ADOX
	>;

	#undef PM
	#undef P

}
