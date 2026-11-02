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
        template <uint8_t l>
        static constexpr Pattern r = (l == 8) ?
            Pattern {
                { r_xx1<op_l>(R(TMP1)[0,8], R(RAX)[0,8]),
                  r_xx1<op_h>(R(RAX)[8,16], R(RAX)[0,8]),
                  mcop<O::VAL>(R(RAX)[0,8], R(TMP1)[0,8]) },
                { mcop<O::CMP>(R(FLAGS)[0,8], R(RAX)[8,16], 0) }
            } :
            Pattern {
                { r_xx1<op_l>(R(TMP1)[0,l], R(RAX)[0,l]),
                  r_xx1<op_h>(R(RDX)[0,l], R(RAX)[0,l]),
                  mcop<O::VAL>(R(RAX)[0,l], R(TMP1)[0,l]),
                  zero_high32<l>(R(RAX)),
                  zero_high32<l>(R(RDX)) },
                { mcop<O::CMP>(R(FLAGS)[0,l], R(RDX)[0,l], 0) }
            };

        template <uint8_t l, uint8_t lm = l>
        static constexpr Pattern m = (l == 8 && lm == 8) ?
            Pattern {
                { m_xx1<op_l,8>(R(TMP1)[0,8], R(RAX)[0,8]),
                  m_xx1<op_h,8>(R(RAX)[8,16], R(RAX)[0,8]),
                  mcop<O::VAL>(R(RAX)[0,8], R(TMP1)[0,8]) },
                { mcop<O::CMP>(R(FLAGS)[0,8], R(RAX)[8,16], 0) }
            } :
            Pattern {
                { m_xx1<op_l,lm>(R(TMP1)[0,l], R(RAX)[0,l]),
                  m_xx1<op_h,lm>(R(RDX)[0,l], R(RAX)[0,l]),
                  mcop<O::VAL>(R(RAX)[0,l], R(TMP1)[0,l]),
                  zero_high32<l>(R(RAX)),
                  zero_high32<l>(R(RDX)) },
                { mcop<O::CMP>(R(FLAGS)[0,l], R(RDX)[0,l], 0) }
            };
    };

    template <O op_h, O op_l>
    struct P_DIV {
        template <uint8_t l>
        static constexpr Pattern r = (l == 8) ?
            Pattern {
                { r_xx1<op_h>(R(TMP1)[0,8], R(RAX)[0,16]),
                  r_xx1<op_l>(R(RAX)[0,8], R(RAX)[0,16]),
                  mcop<O::VAL>(R(RAX)[8,16], R(TMP1)[0,8]) },
                { mcop<O::CLB>(R(FLAGS)[0,8]) }
            } :
            Pattern {
                { mcop<O::CAT>(R(TMP1)[0,l*2], R(RDX)[0,l], R(RAX)[0,l]),
                  r_xx1<op_h>(R(TMP2)[0,l], R(TMP1)[0,l*2]),
                  r_xx1<op_l>(R(RAX)[0,l], R(TMP1)[0,l*2]),
                  mcop<O::VAL>(R(RDX)[0,l], R(TMP2)[0,l]),
                  zero_high32<l>(R(RAX)),
                  zero_high32<l>(R(RDX)) },
                { mcop<O::CLB>(R(FLAGS)[0,l]) }
            };

        template <uint8_t l, uint8_t lm = l>
        static constexpr Pattern m = (l == 8 && lm == 8) ?
            Pattern {
                { m_xx1<op_h,8>(R(TMP1)[0,8], R(RAX)[0,16]),
                  m_xx1<op_l,8>(R(RAX)[0,8], R(RAX)[0,16]),
                  mcop<O::VAL>(R(RAX)[8,16], R(TMP1)[0,8]) },
                { mcop<O::CLB>(R(FLAGS)[0,8]) }
            } :
            Pattern {
                { mcop<O::CAT>(R(TMP1)[0,l*2], R(RDX)[0,l], R(RAX)[0,l]),
                  m_xx1<op_h,lm>(R(TMP2)[0,l], R(TMP1)[0,l*2]),
                  m_xx1<op_l,lm>(R(RAX)[0,l], R(TMP1)[0,l*2]),
                  mcop<O::VAL>(R(RDX)[0,l], R(TMP2)[0,l]),
                  zero_high32<l>(R(RAX)),
                  zero_high32<l>(R(RDX)) },
                { mcop<O::CLB>(R(FLAGS)[0,l]) }
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

    template <O op, bool inv = false>
    struct P_BT_CHG {
        template <uint8_t l>
        static constexpr MCOP invert() noexcept {
            if constexpr (inv)
                return mcop<O::NOT>(R(TMP1)[0,l], R(TMP1)[0,l]);
            else
                return mcop<O::_>();
        }
        P(rr,  { mcop<O::SHL>(R(TMP1)[0,l], 1ULL, DR(2)[0,8]),
                 invert<l>(),
                 mcop<O::SHR>(R(TMP2)[0,1], DR(1)[0,l], DR(2)[0,8]),
                 mcop<op>(DR(0), DR(1)[0,l], R(TMP1)[0,l]),
                 zero_high32<l>(DR(0)) },
               { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP2)[0,1]) });
        P(ri,  { mcop<O::SHL>(R(TMP1)[0,l], 1ULL, DI(2)),
                 invert<l>(),
                 mcop<O::SHR>(R(TMP2)[0,1], DR(1)[0,l], DI(2)),
                 mcop<op>(DR(0), DR(1)[0,l], R(TMP1)[0,l]),
                 zero_high32<l>(DR(0)) },
               { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP2)[0,1]) });
        PM(mr, { mcop<O::SHL>(R(TMP1)[0,lm], 1ULL, DR(5)[0,8]),
                 invert<lm>(),
                 mcop<O::SHR>(R(TMP2)[0,1], DM(0)[lm], DR(5)[0,8]),
                 mcop<op>(DM(0)[lm], DM(0)[lm], R(TMP1)[0,lm]) },
               { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP2)[0,1]) });
        PM(mi, { mcop<O::SHL>(R(TMP1)[0,lm], 1ULL, DI(5)),
                 invert<lm>(),
                 mcop<O::SHR>(R(TMP2)[0,1], DM(0)[lm], DI(5)),
                 mcop<op>(DM(0)[lm], DM(0)[lm], R(TMP1)[0,lm]) },
               { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP2)[0,1]) });
    };

    template <O op_dest, O op_src>
    struct P_SHD {
        P(rrCL,  { mcop<op_dest>(R(TMP1)[0,l], DR(1)[0,l], R(RCX)[0,8]),
                   mcop<O::SUB>(R(TMP2)[0,8], l, R(RCX)[0,8]),
                   mcop<op_src>(R(TMP2)[0,l], DR(2)[0,l], R(TMP2)[0,8]),
                   mcop<O::OR>(DR(0), R(TMP1)[0,l], R(TMP2)[0,l]),
                   zero_high32<l>(DR(0)) },
                 { r_x1x<O::CMP>(R(FLAGS)[0,l], 0) });
        PM(mrCL, { mcop<op_dest>(R(TMP1)[0,lm], DM(0)[lm], R(RCX)[0,8]),
                   mcop<O::SUB>(R(TMP2)[0,8], lm, R(RCX)[0,8]),
                   mcop<op_src>(R(TMP2)[0,lm], DR(5)[0,lm], R(TMP2)[0,8]),
                   mcop<O::OR>(DM(0)[lm], R(TMP1)[0,lm], R(TMP2)[0,lm]) },
                 { m_x1x<O::CMP,lm>(R(FLAGS)[0,l], 0) });
        template <uint8_t l>
        static Instruction rri(
            Context& ctx,
            Cache& cache,
            const MCInstruction& inst)
        {
            uint64_t shift = (uint64_t)inst.getOperand(3).getImm() % l;
            if (shift == 0)
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst);
            MCOP core[] = {
                mcop<op_dest>(R(TMP1)[0,l], DR(1)[0,l], shift),
                mcop<op_src>(R(TMP2)[0,l], DR(2)[0,l], l-shift),
                mcop<O::OR>(DR(0), R(TMP1)[0,l], R(TMP2)[0,l]),
                zero_high32<l>(DR(0))
            };
            MCOP flag[] = { r_x1x<O::CMP>(R(FLAGS)[0,l], 0) };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core, flag);
        }
        template <uint8_t l, uint8_t lm = l>
        static Instruction mri(
            Context& ctx,
            Cache& cache,
            const MCInstruction& inst)
        {
            uint64_t shift = (uint64_t)inst.getOperand(6).getImm() % lm;
            if (shift == 0)
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst);
            MCOP core[] = {
                mcop<op_dest>(R(TMP1)[0,lm], DM(0)[lm], shift),
                mcop<op_src>(R(TMP2)[0,lm], DR(5)[0,lm], lm-shift),
                mcop<O::OR>(DM(0)[lm], R(TMP1)[0,lm], R(TMP2)[0,lm])
            };
            MCOP flag[] = { m_x1x<O::CMP,lm>(R(FLAGS)[0,l], 0) };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core, flag);
        }
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
    struct BT {
        P(rr,  { mcop<O::SHR>(R(FLAGS)[0,1], DR(0)[0,l], DR(1)[0,8]) });
        P(ri,  { mcop<O::SHR>(R(FLAGS)[0,1], DR(0)[0,l], DI(1)) });
        PM(mr, { mcop<O::SHR>(R(FLAGS)[0,1], DM(0)[lm], DR(5)[0,8]) });
        PM(mi, { mcop<O::SHR>(R(FLAGS)[0,1], DM(0)[lm], DI(5)) });
    };
    struct BTS : P_BT_CHG<O::OR> {};
    struct BTC : P_BT_CHG<O::XOR> {};
    struct BTR : P_BT_CHG<O::AND,true> {};
    struct SHLD : P_SHD<O::SHL, O::SHR> {};
    struct SHRD : P_SHD<O::SHR, O::SHL> {};
    struct ROL {
        P(r1,   { mcop<O::SHL>(R(TMP1)[0,l], DR(1)[0,l], 1),
                  mcop<O::VAL>(R(TMP2)[0,1], DR(1)[l-1,l]),
                  mcop<O::OR>(DR(0), R(TMP1)[0,l], R(TMP2)[0,1]),
                  zero_high32<l>(DR(0)) },
                { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP2)[0,1]) });
        P(rCL,  { mcop<O::SHL>(R(TMP1)[0,l], DR(1)[0,l], R(RCX)[0,8]),
                  mcop<O::SUB>(R(TMP2)[0,8], l, R(RCX)[0,8]),
                  mcop<O::SHR>(R(TMP2)[0,l], DR(1)[0,l], R(TMP2)[0,8]),
                  mcop<O::OR>(DR(0), R(TMP1)[0,l], R(TMP2)[0,l]),
                  zero_high32<l>(DR(0)) },
                { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP2)[0,1]) });
        PM(m1,  { mcop<O::SHL>(R(TMP1)[0,lm], DM(0)[lm], 1),
                  mcop<O::SHR>(R(TMP2)[0,1], DM(0)[lm], lm-1),
                  mcop<O::OR>(DM(0)[lm], R(TMP1)[0,lm], R(TMP2)[0,1]) },
                { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP2)[0,1]) });
        PM(mCL, { mcop<O::SHL>(R(TMP1)[0,lm], DM(0)[lm], R(RCX)[0,8]),
                  mcop<O::SUB>(R(TMP2)[0,8], lm, R(RCX)[0,8]),
                  mcop<O::SHR>(R(TMP2)[0,lm], DM(0)[lm], R(TMP2)[0,8]),
                  mcop<O::OR>(DM(0)[lm], R(TMP1)[0,lm], R(TMP2)[0,lm]) },
                { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP2)[0,1]) });
        template <uint8_t l>
        static Instruction ri(
            Context& ctx,
            Cache& cache,
            const MCInstruction& inst)
        {
            uint64_t k = (uint64_t)inst.getOperand(2).getImm() % l;
            if (k == 0) {
                MCOP core[] = {
                    mcop<O::VAL>(DR(0), DR(1)[0,l]),
                    zero_high32<l>(DR(0))
                };
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core);
            }
            if (k == 1) {
                MCOP core[] = {
                    mcop<O::SHL>(R(TMP1)[0,l], DR(1)[0,l], 1),
                    mcop<O::VAL>(R(TMP2)[0,1], DR(1)[l-1,l]),
                    mcop<O::OR>(DR(0), R(TMP1)[0,l], R(TMP2)[0,1]),
                    zero_high32<l>(DR(0))
                };
                MCOP flag[] = { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP2)[0,1]) };
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core, flag);
            }
            MCOP core[] = {
                mcop<O::SHL>(R(TMP1)[0,l], DR(1)[0,l], k),
                mcop<O::SHR>(R(TMP2)[0,l], DR(1)[0,l], l-k),
                mcop<O::OR>(DR(0), R(TMP1)[0,l], R(TMP2)[0,l]),
                zero_high32<l>(DR(0))
            };
            MCOP flag[] = { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP2)[0,1]) };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core, flag);
        }
        template <uint8_t l, uint8_t lm = l>
        static Instruction mi(
            Context& ctx,
            Cache& cache,
            const MCInstruction& inst)
        {
            uint64_t k = (uint64_t)inst.getOperand(5).getImm() % lm;
            if (k == 0)
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst);
            if (k == 1) {
                MCOP core[] = {
                    mcop<O::SHL>(R(TMP1)[0,lm], DM(0)[lm], 1),
                    mcop<O::SHR>(R(TMP2)[0,1], DM(0)[lm], lm-1),
                    mcop<O::OR>(DM(0)[lm], R(TMP1)[0,lm], R(TMP2)[0,1])
                };
                MCOP flag[] = { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP2)[0,1]) };
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core, flag);
            }
            MCOP core[] = {
                mcop<O::SHL>(R(TMP1)[0,lm], DM(0)[lm], k),
                mcop<O::SHR>(R(TMP2)[0,lm], DM(0)[lm], lm-k),
                mcop<O::OR>(DM(0)[lm], R(TMP1)[0,lm], R(TMP2)[0,lm])
            };
            MCOP flag[] = { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP2)[0,1]) };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core, flag);
        }
    };
    struct ROR {
        P(r1,   { mcop<O::SHL>(R(TMP1)[0,l], DR(1)[0,1], l-1),
                  mcop<O::SHR>(R(TMP2)[0,l], DR(1)[0,l], 1),
                  mcop<O::OR>(DR(0), R(TMP1)[0,l], R(TMP2)[0,l]),
                  zero_high32<l>(DR(0)) },
                { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP1)[l-1,l]) });
        P(rCL,  { mcop<O::SUB>(R(TMP1)[0,8], l, R(RCX)[0,8]),
                  mcop<O::SHL>(R(TMP1)[0,l], DR(1)[0,l], R(TMP1)[0,8]),
                  mcop<O::SHR>(R(TMP2)[0,l], DR(1)[0,l], R(RCX)[0,8]),
                  mcop<O::OR>(DR(0), R(TMP1)[0,l], R(TMP2)[0,l]),
                  zero_high32<l>(DR(0)) },
                { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP1)[l-1,l]) });
        PM(m1,  { mcop<O::AND>(R(TMP1)[0,lm], DM(0)[lm], 1ULL),
                  mcop<O::SHL>(R(TMP1)[0,lm], R(TMP1)[0,lm], lm-1),
                  mcop<O::SHR>(R(TMP2)[0,lm], DM(0)[lm], 1),
                  mcop<O::OR>(DM(0)[lm], R(TMP1)[0,lm], R(TMP2)[0,lm]) },
                { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP1)[lm-1,lm]) });
        PM(mCL, { mcop<O::SUB>(R(TMP1)[0,8], lm, R(RCX)[0,8]),
                  mcop<O::SHL>(R(TMP1)[0,lm], DM(0)[lm], R(TMP1)[0,8]),
                  mcop<O::SHR>(R(TMP2)[0,lm], DM(0)[lm], R(RCX)[0,8]),
                  mcop<O::OR>(DM(0)[lm], R(TMP1)[0,lm], R(TMP2)[0,lm]) },
                { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP1)[lm-1,lm]) });
        template <uint8_t l>
        static Instruction ri(
            Context& ctx,
            Cache& cache,
            const MCInstruction& inst)
        {
            uint64_t k = (uint64_t)inst.getOperand(2).getImm() % l;
            if (k == 0) {
                MCOP core[] = {
                    mcop<O::VAL>(DR(0), DR(1)[0,l]),
                    zero_high32<l>(DR(0))
                };
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core);
            }
            if (k == 1) {
                MCOP core[] = {
                    mcop<O::SHL>(R(TMP1)[0,l], DR(1)[0,1], l-1),
                    mcop<O::SHR>(R(TMP2)[0,l], DR(1)[0,l], 1),
                    mcop<O::OR>(DR(0), R(TMP1)[0,l], R(TMP2)[0,l]),
                    zero_high32<l>(DR(0))
                };
                MCOP flag[] = { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP1)[l-1,l]) };
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core, flag);
            }
            MCOP core[] = {
                mcop<O::SHL>(R(TMP1)[0,l], DR(1)[0,l], l-k),
                mcop<O::SHR>(R(TMP2)[0,l], DR(1)[0,l], k),
                mcop<O::OR>(DR(0), R(TMP1)[0,l], R(TMP2)[0,l]),
                zero_high32<l>(DR(0))
            };
            MCOP flag[] = { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP1)[l-1,l]) };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core, flag);
        }
        template <uint8_t l, uint8_t lm = l>
        static Instruction mi(
            Context& ctx,
            Cache& cache,
            const MCInstruction& inst)
        {
            uint64_t k = (uint64_t)inst.getOperand(5).getImm() % lm;
            if (k == 0)
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst);
            if (k == 1) {
                MCOP core[] = {
                    mcop<O::AND>(R(TMP1)[0,lm], DM(0)[lm], 1ULL),
                    mcop<O::SHL>(R(TMP1)[0,lm], R(TMP1)[0,lm], lm-1),
                    mcop<O::SHR>(R(TMP2)[0,lm], DM(0)[lm], 1),
                    mcop<O::OR>(DM(0)[lm], R(TMP1)[0,lm], R(TMP2)[0,lm])
                };
                MCOP flag[] = { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP1)[lm-1,lm]) };
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core, flag);
            }
            MCOP core[] = {
                mcop<O::SHL>(R(TMP1)[0,lm], DM(0)[lm], lm-k),
                mcop<O::SHR>(R(TMP2)[0,lm], DM(0)[lm], k),
                mcop<O::OR>(DM(0)[lm], R(TMP1)[0,lm], R(TMP2)[0,lm])
            };
            MCOP flag[] = { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP1)[lm-1,lm]) };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core, flag);
        }
    };
    struct RCL {
        P(r1,   { mcop<O::VAL>(R(TMP1)[0,1], DR(1)[l-1,l]),
                  mcop<O::SHL>(R(TMP2)[0,l], DR(1)[0,l], 1),
                  mcop<O::OR>(DR(0), R(TMP2)[0,l], R(FLAGS)[0,1]),
                  zero_high32<l>(DR(0)) },
                { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP1)[0,1]) });
        P(rCL,  { mcop<O::SUB>(R(TMP1)[0,8], l, R(RCX)[0,8]),
                  mcop<O::SHR>(R(FLAGS)[0,1], DR(1)[0,l], R(TMP1)[0,8]),
                  mcop<O::CLB>(DR(0)[0,l]),
                  zero_high32<l>(DR(0)) });
        PM(m1,  { mcop<O::SHR>(R(TMP1)[0,1], DM(0)[lm], lm-1),
                  mcop<O::SHL>(R(TMP2)[0,lm], DM(0)[lm], 1),
                  mcop<O::OR>(DM(0)[lm], R(TMP2)[0,lm], R(FLAGS)[0,1]) },
                { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP1)[0,1]) });
        PM(mCL, { mcop<O::SUB>(R(TMP1)[0,8], lm, R(RCX)[0,8]),
                  mcop<O::SHR>(R(FLAGS)[0,1], DM(0)[lm], R(TMP1)[0,8]),
                  mcop<O::CLB>(DM(0)[lm]) });
        template <uint8_t l>
        static Instruction ri(
            Context& ctx,
            Cache& cache,
            const MCInstruction& inst)
        {
            uint64_t k = (uint64_t)inst.getOperand(2).getImm() % (l+1);
            if (k == 0) {
                MCOP core[] = {
                    mcop<O::VAL>(DR(0), DR(1)[0,l]),
                    zero_high32<l>(DR(0))
                };
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core);
            }
            if (k == 1) {
                MCOP core[] = {
                    mcop<O::VAL>(R(TMP1)[0,1], DR(1)[l-1,l]),
                    mcop<O::SHL>(R(TMP2)[0,l], DR(1)[0,l], 1),
                    mcop<O::OR>(DR(0), R(TMP2)[0,l], R(FLAGS)[0,1]),
                    zero_high32<l>(DR(0))
                };
                MCOP flag[] = { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP1)[0,1]) };
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core, flag);
            }
            MCOP core[] = {
                mcop<O::SHL>(R(TMP1)[0,l], R(FLAGS)[0,1], k-1),
                mcop<O::VAL>(R(FLAGS)[0,1], DR(1)[l-k,l-k+1]),
                mcop<O::SHL>(R(TMP2)[0,l], DR(1)[0,l], k),
                mcop<O::OR>(R(TMP1)[0,l], R(TMP1)[0,l], R(TMP2)[0,l]),
                mcop<O::SHR>(R(TMP2)[0,l], DR(1)[0,l], l+1-k),
                mcop<O::OR>(DR(0), R(TMP1)[0,l], R(TMP2)[0,l]),
                zero_high32<l>(DR(0))
            };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core);
        }
        template <uint8_t l, uint8_t lm = l>
        static Instruction mi(
            Context& ctx,
            Cache& cache,
            const MCInstruction& inst)
        {
            uint64_t k = (uint64_t)inst.getOperand(5).getImm() % (lm+1);
            if (k == 0)
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst);
            if (k == 1) {
                MCOP core[] = {
                    mcop<O::SHR>(R(TMP1)[0,1], DM(0)[lm], lm-1),
                    mcop<O::SHL>(R(TMP2)[0,lm], DM(0)[lm], 1),
                    mcop<O::OR>(DM(0)[lm], R(TMP2)[0,lm], R(FLAGS)[0,1])
                };
                MCOP flag[] = { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP1)[0,1]) };
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core, flag);
            }
            MCOP core[] = {
                mcop<O::SHL>(R(TMP1)[0,lm], R(FLAGS)[0,1], k-1),
                mcop<O::SHR>(R(FLAGS)[0,1], DM(0)[lm], lm-k),
                mcop<O::SHL>(R(TMP2)[0,lm], DM(0)[lm], k),
                mcop<O::OR>(R(TMP1)[0,lm], R(TMP1)[0,lm], R(TMP2)[0,lm]),
                mcop<O::SHR>(R(TMP2)[0,lm], DM(0)[lm], lm+1-k),
                mcop<O::OR>(DM(0)[lm], R(TMP1)[0,lm], R(TMP2)[0,lm])
            };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core);
        }
    };
    struct RCR {
        P(r1,   { mcop<O::VAL>(R(TMP1)[0,1], DR(1)[0,1]),
                  mcop<O::SHL>(R(TMP2)[0,l], R(FLAGS)[0,1], l-1),
                  mcop<O::SHR>(DR(0), DR(1)[0,l], 1),
                  mcop<O::OR>(DR(0), DR(0), R(TMP2)[0,l]),
                  zero_high32<l>(DR(0)) },
                { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP1)[0,1]) });
        P(rCL,  { mcop<O::SUB>(R(TMP1)[0,8], R(RCX)[0,8], 1),
                  mcop<O::SHR>(R(FLAGS)[0,1], DR(1)[0,l], R(TMP1)[0,8]),
                  mcop<O::CLB>(DR(0)[0,l]),
                  zero_high32<l>(DR(0)) });
        PM(m1,  { mcop<O::SHL>(R(TMP1)[0,lm], R(FLAGS)[0,1], lm-1),
                  mcop<O::AND>(R(FLAGS)[0,1], DM(0)[lm], 1ULL),
                  mcop<O::SHR>(R(TMP2)[0,lm], DM(0)[lm], 1),
                  mcop<O::OR>(DM(0)[lm], R(TMP1)[0,lm], R(TMP2)[0,lm]) });
        PM(mCL, { mcop<O::SUB>(R(TMP1)[0,8], R(RCX)[0,8], 1),
                  mcop<O::SHR>(R(FLAGS)[0,1], DM(0)[lm], R(TMP1)[0,8]),
                  mcop<O::CLB>(DM(0)[lm]) });
        template <uint8_t l>
        static Instruction ri(
            Context& ctx,
            Cache& cache,
            const MCInstruction& inst)
        {
            uint64_t k = (uint64_t)inst.getOperand(2).getImm() % (l+1);
            if (k == 0) {
                MCOP core[] = {
                    mcop<O::VAL>(DR(0), DR(1)[0,l]),
                    zero_high32<l>(DR(0))
                };
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core);
            }
            if (k == 1) {
                MCOP core[] = {
                    mcop<O::VAL>(R(TMP1)[0,1], DR(1)[0,1]),
                    mcop<O::SHL>(R(TMP2)[0,l], R(FLAGS)[0,1], l-1),
                    mcop<O::SHR>(DR(0), DR(1)[0,l], 1),
                    mcop<O::OR>(DR(0), DR(0), R(TMP2)[0,l]),
                    zero_high32<l>(DR(0))
                };
                MCOP flag[] = { mcop<O::VAL>(R(FLAGS)[0,1], R(TMP1)[0,1]) };
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core, flag);
            }
            MCOP core[] = {
                mcop<O::SHL>(R(TMP1)[0,l], R(FLAGS)[0,1], l-k),
                mcop<O::VAL>(R(FLAGS)[0,1], DR(1)[k-1,k]),
                mcop<O::SHR>(R(TMP2)[0,l], DR(1)[0,l], k),
                mcop<O::OR>(R(TMP1)[0,l], R(TMP1)[0,l], R(TMP2)[0,l]),
                mcop<O::SHL>(R(TMP2)[0,l], DR(1)[0,l], l+1-k),
                mcop<O::OR>(DR(0), R(TMP1)[0,l], R(TMP2)[0,l]),
                zero_high32<l>(DR(0))
            };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core);
        }
        template <uint8_t l, uint8_t lm = l>
        static Instruction mi(
            Context& ctx,
            Cache& cache,
            const MCInstruction& inst)
        {
            uint64_t k = (uint64_t)inst.getOperand(5).getImm() % (lm+1);
            if (k == 0)
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst);
            if (k == 1) {
                MCOP core[] = {
                    mcop<O::SHL>(R(TMP1)[0,lm], R(FLAGS)[0,1], lm-1),
                    mcop<O::AND>(R(FLAGS)[0,1], DM(0)[lm], 1ULL),
                    mcop<O::SHR>(R(TMP2)[0,lm], DM(0)[lm], 1),
                    mcop<O::OR>(DM(0)[lm], R(TMP1)[0,lm], R(TMP2)[0,lm])
                };
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core);
            }
            MCOP core[] = {
                mcop<O::SHL>(R(TMP1)[0,lm], R(FLAGS)[0,1], lm-k),
                mcop<O::SHR>(R(FLAGS)[0,1], DM(0)[lm], k-1),
                mcop<O::SHR>(R(TMP2)[0,lm], DM(0)[lm], k),
                mcop<O::OR>(R(TMP1)[0,lm], R(TMP1)[0,lm], R(TMP2)[0,lm]),
                mcop<O::SHL>(R(TMP2)[0,lm], DM(0)[lm], lm+1-k),
                mcop<O::OR>(DM(0)[lm], R(TMP1)[0,lm], R(TMP2)[0,lm])
            };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, core);
        }
    };

    using Mnemonics_ALU = SBA::Util::TypeList<
        ADD, SUB, AND, OR, XOR, CMP, TEST, ADC, SBB,
        INC, DEC, NEG, NOT, MUL, IMUL, DIV, IDIV,
        SHL, SHR, SAR, ROL, ROR, BSWAP, MOVBE,
        LZCNT, TZCNT, POPCNT, BSF, BSR,
        ANDN, BLSR, BLSMSK, BLSI, BZHI, BEXTR,
        SARX, SHLX, SHRX, MULX, ADCX, ADOX,
        BT, BTS, BTR, BTC, SHLD, SHRD, RCL, RCR
    >;

    #undef PM
    #undef P

}
