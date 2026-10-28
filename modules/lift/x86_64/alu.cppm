module;
#include <cstdint>

export module sba.lift:x86_64_alu;

import sba.ir;
import :x86_64_pattern;

namespace SBA::Lift::X86_64 {

    #define P(Suffix, ...) \
        template <uint8_t l> \
        static constexpr Pattern Suffix = { __VA_ARGS__ }

    #define PM(Suffix, ...) \
        template <uint8_t l, uint8_t lm = l> \
        static constexpr Pattern Suffix = { __VA_ARGS__ }

    template <O op, bool neg = false>
    struct P_ALU {
        P(rr,   { rrr_123<op>(),
                  zero_high32<l>(DR(0)) },
                { rrr_x23<O::CMP,neg>(R(FLAGS)[0,l]) });
        P(ri,   { rri_123<op>(),
                  zero_high32<l>(DR(0)) },
                { rri_x23<O::CMP,neg>(R(FLAGS)[0,l]) });
        PM(rm,  { rrm_123<op,lm>(),
                  zero_high32<l>(DR(0)) },
                { rrm_x23<O::CMP,lm,neg>(R(FLAGS)[0,l]) });
        PM(mr,  { mr_112<op,lm>() },
                { mr_x12<O::CMP,lm,neg>(R(FLAGS)[0,l]) });
        PM(mi,  { mi_112<op,lm>() },
                { mi_x12<O::CMP,lm,neg>(R(FLAGS)[0,l]) });
    };

    template <O op, bool neg = false>
    struct P_ALUC {
        P(rr,   { rrr_123x<op>(R(FLAGS)[0,l]),
                  zero_high32<l>(DR(0)) },
                { rrr_x23<O::CMP,neg>(R(FLAGS)[0,l]) });
        P(ri,   { rri_123x<op>(R(FLAGS)[0,l]),
                  zero_high32<l>(DR(0)) },
                { rri_x23<O::CMP,neg>(R(FLAGS)[0,l]) });
        PM(rm,  { rrm_123x<op,lm>(R(FLAGS)[0,l]),
                  zero_high32<l>(DR(0)) },
                { rrm_x23<O::CMP,lm,neg>(R(FLAGS)[0,l]) });
        PM(mr,  { mr_112x<op,lm>(R(FLAGS)[0,l]) },
                { mr_x12<O::CMP,lm,neg>(R(FLAGS)[0,l]) });
        PM(mi,  { mi_112x<op,lm>(R(FLAGS)[0,l]) },
                { mi_x12<O::CMP,lm,neg>(R(FLAGS)[0,l]) });
    };

    template <O op, bool neg = false>
    struct P_CMP {
        P(rr,  { rr_x12<op,neg>(R(FLAGS)[0,l]) });
        P(ri,  { ri_x12<op,neg>(R(FLAGS)[0,l]) });
        P(i,   { i_xx1<op,neg>(R(FLAGS)[0,l], R(RAX)[0,l]) });
        PM(rm, { rm_x12<op,lm,neg>(R(FLAGS)[0,l]) });
        PM(mr, { mr_x12<op,lm,neg>(R(FLAGS)[0,l]) });
        PM(mi, { mi_x12<op,lm,neg>(R(FLAGS)[0,l]) });
    };

    template <O op, int64_t val>
    struct P_STEP {
        P(r,   { rr_12x<op>(1),
                 zero_high32<l>(DR(0)) },
               { rr_x2x<O::CMP>(R(FLAGS)[0,l], val) });
        PM(m,  { m_11x<op,lm>(1) },
               { m_x1x<O::CMP,lm>(R(FLAGS)[0,l], val) });
    };

    template <O op_h, O op_l>
    struct P_MUL {
        P(r,   { r_xx1<op_l>(R(TMP1)[0,l], R(RAX)[0,l]),
                 r_xx1<op_h>(R(RDX)[0,l], R(RAX)[0,l]),
                 mcop<O::VAL>(R(RAX)[0,l], R(TMP1)[0,l]),
                 zero_high32<l>(R(RAX)),
                 zero_high32<l>(R(RDX)) },
               { mcop<O::CMP>(R(FLAGS)[0,l], R(RDX)[0,l], 0) });
        PM(m,  { m_xx1<op_l,lm>(R(TMP1)[0,l], R(RAX)[0,l]),
                 m_xx1<op_h,lm>(R(RDX)[0,l], R(RAX)[0,l]),
                 mcop<O::VAL>(R(RAX)[0,l], R(TMP1)[0,l]),
                 zero_high32<l>(R(RAX)),
                 zero_high32<l>(R(RDX)) },
               { mcop<O::CMP>(R(FLAGS)[0,l], R(RDX)[0,l], 0) });
        template <>
        constexpr Pattern r<8> = {
            { r_xx1<op_l>(R(TMP1)[0,8], R(RAX)[0,8]),
              r_xx1<op_h>(R(RAX)[8,16], R(RAX)[0,8]),
              mcop<O::VAL>(R(RAX)[0,8], R(TMP1)[0,8]) },
            { mcop<O::CMP>(R(FLAGS)[0,8], R(RAX)[8,16], 0) }
        };
        template <>
        constexpr Pattern m<8,8> = {
            { m_xx1<op_l,8>(R(TMP1)[0,8], R(RAX)[0,8]),
              m_xx1<op_h,8>(R(RAX)[8,16], R(RAX)[0,8]),
              mcop<O::VAL>(R(RAX)[0,8], R(TMP1)[0,8]) },
            { mcop<O::CMP>(R(FLAGS)[0,8], R(RAX)[8,16], 0) }
        };
    };

    template <O op_h, O op_l>
    struct P_DIV {
        P(r,   { mcop<O::CAT>(R(TMP1)[0,l*2], R(RDX)[0,l], R(RAX)[0,l]),
                 r_xx1<op_h>(R(TMP2)[0,l], R(TMP1)[0,l*2]),
                 r_xx1<op_l>(R(RAX)[0,l], R(TMP1)[0,l*2]),
                 mcop<O::VAL>(R(RDX)[0,l], R(TMP2)[0,l]),
                 zero_high32<l>(R(RAX)),
                 zero_high32<l>(R(RDX)) },
               { mcop<O::CLB>(R(FLAGS)[0,l]) });
        PM(m,  { mcop<O::CAT>(R(TMP1)[0,l*2], R(RDX)[0,l], R(RAX)[0,l]),
                 m_xx1<op_h,lm>(R(TMP2)[0,l], R(TMP1)[0,l*2]),
                 m_xx1<op_l,lm>(R(RAX)[0,l], R(TMP1)[0,l*2]),
                 mcop<O::VAL>(R(RDX)[0,l], R(TMP2)[0,l]),
                 zero_high32<l>(R(RAX)),
                 zero_high32<l>(R(RDX)) },
               { mcop<O::CLB>(R(FLAGS)[0,l]) });
        template <>
        constexpr Pattern r<8> = {
            { r_xx1<op_h>(R(TMP1)[0,8], R(RAX)[0,16]),
              r_xx1<op_l>(R(RAX)[0,8], R(RAX)[0,16]),
              mcop<O::VAL>(R(RAX)[8,16], R(TMP1)[0,8]) },
            { mcop<O::CLB>(R(FLAGS)[0,8]) }
        };
        template <>
        constexpr Pattern m<8,8> = {
            { m_xx1<op_h,8>(R(TMP1)[0,8], R(RAX)[0,16]),
              m_xx1<op_l,8>(R(RAX)[0,8], R(RAX)[0,16]),
              mcop<O::VAL>(R(RAX)[8,16], R(TMP1)[0,8]) },
            { mcop<O::CLB>(R(FLAGS)[0,8]) }
        };
    };

    template <O op>
    struct P_SHIFT {
        P(ri,   { rri_123<op>(),
                  zero_high32<l>(DR(0)) },
                { r_x1x<O::CMP>(R(FLAGS)[0,l], 0) });
        P(r1,   { rr_12x<op>(1),
                  zero_high32<l>(DR(0)) },
                { r_x1x<O::CMP>(R(FLAGS)[0,l], 0) });
        P(rCL,  { rr_12x<op>(R(RCX)[0,8]),
                  zero_high32<l>(DR(0)) },
                { r_x1x<O::CMP>(R(FLAGS)[0,l], 0) });
        PM(mi,  { mi_112<op,lm>() },
                { m_x1x<O::CMP,lm>(R(FLAGS)[0,l], 0) });
        PM(m1,  { m_11x<op,lm>(1) },
                { m_x1x<O::CMP,lm>(R(FLAGS)[0,l], 0) });
        PM(mCL, { m_11x<op,lm>(R(RCX)[0,8]) },
                { m_x1x<O::CMP,lm>(R(FLAGS)[0,l], 0) });
    };

    template <O op>
    struct P_SHIFT_2 {
        P(rr,  { rrr_123<op>(),
                 zero_high32<l>(DR(0)) });
        PM(rm, { rmr_123<op,lm>(),
                 zero_high32<l>(DR(0)) });
    };

    template <O op>
    struct P_BITCNT {
        P(rr,  { rr_12<op>(),
                 zero_high32<l>(DR(0)) },
               { rr_x2x<O::CMP>(R(FLAGS)[0,l], 0) });
        PM(rm, { rm_12<op,lm>(),
                 zero_high32<l>(DR(0)) },
               { rm_x2x<O::CMP,lm>(R(FLAGS)[0,l], 0) });
    };

    template <O op>
    struct P_BLS_MASK {
        P(rr,  { rr_x2x<O::ADD>(R(TMP1)[0,l], -1ULL),
                 rr_12x<op>(R(TMP1)[0,l]),
                 zero_high32<l>(DR(0)) },
               { r_x1x<O::CMP>(R(FLAGS)[0,l], 0) });
        PM(rm, { rm_x2x<O::ADD,lm>(R(TMP1)[0,l], -1ULL),
                 rm_12x<op,lm>(R(TMP1)[0,l]),
                 zero_high32<l>(DR(0)) },
               { r_x1x<O::CMP>(R(FLAGS)[0,l], 0) });
    };

    template <Operand c>
    struct P_CADD_EXT {
        P(rr,  { rrr_123x<O::CADD>(c),
                 zero_high32<l>(DR(0)) },
               { rrr_x23x<O::CCMP,true>(R(FLAGS)[0,l], c) });
        PM(rm, { rrm_123x<O::CADD,lm>(c),
                 zero_high32<l>(DR(0)) },
               { rrm_x23x<O::CCMP,lm,true>(R(FLAGS)[0,l], c) });
    };

    /* -----------------------------------------------------------------------*/

    struct ADD  : P_ALU<O::ADD,true> {};
    struct SUB  : P_ALU<O::SUB> {};
    struct ADC  : P_ALUC<O::CADD,true> {};
    struct SBB  : P_ALUC<O::CSUB> {};
    struct AND  : P_ALU<O::AND> {};
    struct OR   : P_ALU<O::OR> {};
    struct XOR  : P_ALU<O::XOR> {};
    struct CMP  : P_CMP<O::CMP> {};
    struct TEST : P_CMP<O::AND> {};
    struct MUL  : P_MUL<O::UMULH, O::MUL> {};
    struct IMUL : P_MUL<O::MULH, O::MUL> {
        P(rr,  { rrr_123<O::MUL>(),
                 zero_high32<l>(DR(0)) },
               { rrr_x23<O::CMP>(R(FLAGS)[0,l]) });
        P(ri,  { rri_123<O::MUL>(),
                 zero_high32<l>(DR(0)) },
               { rri_x23<O::CMP>(R(FLAGS)[0,l]) });
        PM(rm, { rrm_123<O::MUL,lm>(),
                 zero_high32<l>(DR(0)) },
               { rrm_x23<O::CMP,lm>(R(FLAGS)[0,l]) });
    };
    struct DIV  : P_DIV<O::UMOD, O::UDIV> {};
    struct IDIV : P_DIV<O::MOD, O::DIV> {};
    struct INC  : P_STEP<O::ADD,-1> {};
    struct DEC  : P_STEP<O::SUB,1> {};
    struct NEG {
        P(r,   { rr_12<O::NEG>(),
                 zero_high32<l>(DR(0)) },
               { rr_xx2<O::CMP>(R(FLAGS)[0,l], 0) });
        PM(m,  { m_11<O::NEG,lm>() },
               { m_xx1<O::CMP,lm>(R(FLAGS)[0,l], 0) });
    };
    struct NOT {
        P(r,   { rr_12<O::NOT>(),
                 zero_high32<l>(DR(0)) });
        PM(m,  { m_11<O::NOT,lm>() });
    };
    struct SHL : P_SHIFT<O::SHL> {};
    struct SHR : P_SHIFT<O::SHR> {};
    struct SAR : P_SHIFT<O::ASHR> {};
    struct ROL : P_SHIFT<O::ROL> {};
    struct ROR : P_SHIFT<O::ROR> {};
    struct BSWAP {
        P(r,   { rr_12<O::REV>(),
                 zero_high32<l>(DR(0)) });
    };
    struct MOVBE {
        P(rr,  { rr_12<O::REV>(),
                 zero_high32<l>(DR(0)) });
        PM(rm, { rm_12<O::REV,lm>(),
                 zero_high32<l>(DR(0)) });
        PM(mr, { mr_12<O::REV,lm>() });
    };
    struct LZCNT  : P_BITCNT<O::CLZ> {};
    struct TZCNT  : P_BITCNT<O::CTZ> {};
    struct POPCNT : P_BITCNT<O::POP> {};
    struct BSF    : P_BITCNT<O::CTZ> {};
    struct BSR {
        P(rr,  { rr_x2<O::CLZ>(R(TMP1)[0,l]),
                 r_1xx<O::SUB>(l-1, R(TMP1)[0,l]),
                 zero_high32<l>(DR(0)) },
               { rr_x2x<O::CMP>(R(FLAGS)[0,l], 0) });
        PM(rm, { rm_x2<O::CLZ,lm>(R(TMP1)[0,l]),
                 r_1xx<O::SUB>(l-1, R(TMP1)[0,l]),
                 zero_high32<l>(DR(0)) },
               { rm_x2x<O::CMP,lm>(R(FLAGS)[0,l], 0) });
    };
    struct ANDN {
        P(rr,  { rr_x2<O::NOT>(R(TMP1)[0,l]),
                 rrr_1x3<O::AND>(R(TMP1)[0,l]),
                 zero_high32<l>(DR(0)) },
               { r_x1x<O::CMP>(R(FLAGS)[0,l], 0) });
        PM(rm, { rr_x2<O::NOT>(R(TMP1)[0,l]),
                 rrm_1x3<O::AND,lm>(R(TMP1)[0,l]),
                 zero_high32<l>(DR(0)) },
               { r_x1x<O::CMP>(R(FLAGS)[0,l], 0) });
    };
    struct BLSI {
        P(rr,  { rr_x2<O::NEG>(R(TMP1)[0,l]),
                 rr_12x<O::AND>(R(TMP1)[0,l]),
                 zero_high32<l>(DR(0)) },
               { r_x1x<O::CMP>(R(FLAGS)[0,l], 0) });
        PM(rm, { rm_x2<O::NEG,lm>(R(TMP1)[0,l]),
                 rm_12x<O::AND,lm>(R(TMP1)[0,l]),
                 zero_high32<l>(DR(0)) },
               { r_x1x<O::CMP>(R(FLAGS)[0,l], 0) });
    };
    struct BLSR   : P_BLS_MASK<O::AND> {};
    struct BLSMSK : P_BLS_MASK<O::XOR> {};
    struct BZHI {
        P(rr,  { rrr_xx3<O::SHL>(R(TMP1)[0,l], 1),
                 rr_12x<O::AND>(A(TMP1-1)),
                 zero_high32<l>(DR(0)) },
               { r_x1x<O::CMP>(R(FLAGS)[0,l], 0) });
        PM(rm, { rmr_xx3<O::SHL>(R(TMP1)[0,l], 1),
                 rm_12x<O::AND,lm>(A(TMP1-1)),
                 zero_high32<l>(DR(0)) },
               { r_x1x<O::CMP>(R(FLAGS)[0,l], 0) });
    };
    struct BEXTR {
        P(rr,  { mcop<O::SHR>(R(TMP1)[0,l], DR(1)[0,l], DR(2)[0,8]),
                 mcop<O::SHL>(R(TMP2)[0,l], 1, DR(2)[8,16]),
                 mcop<O::AND>(DR(0), R(TMP1)[0,l], A(TMP2-1)),
                 zero_high32<l>(DR(0)) },
               { r_x1x<O::CMP>(R(FLAGS)[0,l], 0) });
        PM(rm, { mcop<O::SHR>(R(TMP1)[0,l], DM(1)[lm], DR(6)[0,8]),
                 mcop<O::SHL>(R(TMP2)[0,l], 1, DR(6)[8,16]),
                 mcop<O::AND>(DR(0), R(TMP1)[0,l], A(TMP2-1)),
                 zero_high32<l>(DR(0)) },
               { r_x1x<O::CMP>(R(FLAGS)[0,l], 0) });
    };
    struct SARX : P_SHIFT_2<O::ASHR> {};
    struct SHLX : P_SHIFT_2<O::SHL> {};
    struct SHRX : P_SHIFT_2<O::SHR> {};
    struct MULX {
        P(rr,  { rrr_1x3<O::UMULH>(R(RDX)[0,l]),
                 zero_high32<l>(DR(0)),
                 rrr_2x3<O::MUL>(R(RDX)[0,l]),
                 zero_high32<l>(DR(1)) });
        PM(rm, { rrm_1x3<O::UMULH,lm>(R(RDX)[0,l]),
                 zero_high32<l>(DR(0)),
                 rrm_2x3<O::MUL,lm>(R(RDX)[0,l]),
                 zero_high32<l>(DR(1)) });
    };
    struct ADCX : P_CADD_EXT<R(FLAGS)[0]>  {}; /* CF */
    struct ADOX : P_CADD_EXT<R(FLAGS)[11]> {}; /* OF */

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
