module;
#include <cstdint>

export module sba.lift:x86_64_data;

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

    template <O op>
    struct P_MOV_EXT {
        P(rr,  { rr_12<op>(),
                 zero_high32<l>(DR(0)) });
        PM(rm, { rm_12<op,lm>(),
                 zero_high32<l>(DR(0)) });
    };

    template <uint8_t l>
    struct P_SEXT_A {
        template <uint8_t>
        static constexpr Pattern _ = { { mcop<O::SEXT>(R(RAX)[0,l], R(RAX)[0,(l/2)]) } };
    };

    template <uint8_t l>
    struct P_SEXT_DA {
        template <uint8_t>
        static constexpr Pattern _ = { { mcop<O::ASHR>(R(RDX)[0,l], R(RAX)[0,l], l-1) } };
    };

    /* -----------------------------------------------------------------------*/

    struct MOV : P_MOV_EXT<O::VAL> {
        P(ri,  { ri_12<O::VAL>(),
                 zero_high32<l>(DR(0)) });
        PM(mr, { mr_12<O::VAL,lm>() });
        PM(mi, { mi_12<O::VAL,lm>() });
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
        P(rr,  { r_x1<O::VAL>(R(TMP1)[0,l]),
                 rr_12<O::VAL>(),
                 zero_high32<l>(DR(0)),
                 rr_2x<O::VAL>(R(TMP1)[0,l]),
                 zero_high32<l>(DR(1)) });
        PM(rm, { r_x1<O::VAL>(R(TMP1)[0,l]),
                 rrm_13<O::VAL,lm>(),
                 zero_high32<l>(DR(0)),
                 rrm_3x<O::VAL,lm>(R(TMP1)[0,l]) });
        P(ar,  { r_x1<O::VAL>(R(TMP1)[0,l]),
                 r_1x<O::VAL>(R(RAX)[0,l]),
                 zero_high32<l>(DR(0)),
                 mcop<O::VAL>(R(RAX)[0,l], R(TMP1)[0,l]),
                 zero_high32<l>(R(RAX)) });
    };
    struct CMPXCHG {
        P(rr,  { r_x1<O::VAL>(R(TMP3)[0,l]),
                 mcop<O::CMP>(R(FLAGS)[0,l], R(TMP3)[0,l], R(RAX)[0,l]),
                 rr_1x2x<O::SELECT_EQ>(R(FLAGS)[0,l], R(TMP3)[0,l]),
                 mcop<O::SELECT_EQ>(R(RAX)[0,l], R(FLAGS)[0,l], R(RAX)[0,l], R(TMP3)[0,l]) });
        PM(rm, { m_x1<O::VAL,lm>(R(TMP3)[0,l]),
                 mcop<O::CMP>(R(FLAGS)[0,l], R(TMP3)[0,l], R(RAX)[0,l]),
                 mr_1x2x<O::SELECT_EQ,lm>(R(FLAGS)[0,l], R(TMP3)[0,l]),
                 mcop<O::SELECT_EQ>(R(RAX)[0,l], R(FLAGS)[0,l], R(RAX)[0,l], R(TMP3)[0,l]) });
    };
    struct CMPXCHG8B {
        template <uint8_t l>
        static constexpr Pattern _ = { {
            mcop<O::VAL>(R(TMP3), DM(0)[64]),
            mcop<O::CAT>(R(TMP4), R(RDX)[0,32], R(RAX)[0,32]),
            mcop<O::CMP>(R(FLAGS), R(TMP3), R(TMP4)),
            mcop<O::CAT>(R(TMP2), R(RCX)[0,32], R(RBX)[0,32]),
            mcop<O::SELECT_EQ>(DM(0)[64], R(FLAGS), R(TMP2), R(TMP3)),
            mcop<O::SELECT_EQ>(R(RAX)[0,32], R(FLAGS), R(RAX)[0,32], R(TMP3)[0,32]),
            mcop<O::SELECT_EQ>(R(RDX)[0,32], R(FLAGS), R(RDX)[0,32], R(TMP3)[32,64])
        } };
    };
    struct CMPXCHG16B {
        template <uint8_t l>
        static constexpr Pattern _ = { {
            mcop<O::VAL>(R(TMP3)[0,128], DM(0)[128]),
            mcop<O::CAT>(R(TMP4)[0,128], R(RDX), R(RAX)),
            mcop<O::CMP>(R(FLAGS), R(TMP3)[0,128], R(TMP4)[0,128]),
            mcop<O::CAT>(R(TMP2)[0,128], R(RCX), R(RBX)),
            mcop<O::SELECT_EQ>(DM(0)[128], R(FLAGS), R(TMP2)[0,128], R(TMP3)[0,128]),
            mcop<O::SELECT_EQ>(R(RAX), R(FLAGS), R(RAX), R(TMP3)[0,64]),
            mcop<O::SELECT_EQ>(R(RDX), R(FLAGS), R(RDX), R(TMP3)[64,128])
        } };
    };
    struct XADD {
        P(rr,  { r_x1<O::VAL>(R(TMP1)[0,l]),
                 rr_112<O::ADD>(),
                 zero_high32<l>(DR(0)),
                 rr_2x<O::VAL>(R(TMP1)[0,l]),
                 zero_high32<l>(DR(1)) },
               { rr_x12<O::CMP,true>(R(FLAGS)[0,l]) });
        PM(rm, { rrm_x3<O::VAL,lm>(R(TMP1)[0,l]),
                 rrm_331<O::ADD,lm>(),
                 r_1x<O::VAL>(R(TMP1)[0,l]),
                 zero_high32<l>(DR(0)) },
               { rrm_x31<O::CMP,lm,true>(R(FLAGS)[0,l]) });
    };
    struct CMOV {
        template <uint8_t l>
        static Instruction rr(
            Context& ctx,
            Cache& cache,
            const MCInstruction& inst)
        {
            uint8_t cc = inst.getOperand(3).getImm();
            MCOP ops[] = { { CC[cc], DR(0), R(FLAGS)[0,l], DR(2), DR(1) } };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
        }

        template <uint8_t l, uint8_t lm = l>
        static Instruction rm(
            Context& ctx,
            Cache& cache,
            const MCInstruction& inst)
        {
            uint8_t cc = inst.getOperand(7).getImm();
            MCOP ops[] = { { CC[cc], DR(0), R(FLAGS)[0,l], DM(2)[lm], DR(1) } };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
        }
    };
    struct SETCC {
        template <uint8_t l>
        static Instruction r(Context& ctx, Cache& cache, const MCInstruction& inst)
        {
            uint8_t cc = inst.getOperand(1).getImm();
            MCOP ops[] = { { CC[cc], DR(0), R(FLAGS), 1ULL, 0ULL } };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
        }

        template <uint8_t l, uint8_t lm = l>
        static Instruction m(Context& ctx, Cache& cache, const MCInstruction& inst)
        {
            uint8_t cc = inst.getOperand(5).getImm();
            MCOP ops[] = { { CC[cc], DM(0)[lm], R(FLAGS), 1ULL, 0ULL } };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
        }
    };
    struct PUSH {
        P(r,   { mcop<O::VAL>(R(RSP), A(RSP-bits_to_bytes(l))),
                 r_x1<O::VAL>(M(RSP)[l]) });
        P(i,   { mcop<O::VAL>(R(RSP), A(RSP-bits_to_bytes(l))),
                 i_x1<O::VAL>(M(RSP)[l]) });
        PM(m,  { mcop<O::VAL>(R(RSP), A(RSP-bits_to_bytes(l))),
                 m_x1<O::VAL,lm>(M(RSP)[l]) });
    };
    struct POP {
        P(r,   { r_1x<O::VAL>(M(RSP)[l]),
                 mcop<O::VAL>(R(RSP), A(RSP+bits_to_bytes(l))) });
        PM(m,  { m_1x<O::VAL,lm>(M(RSP)[l]),
                 mcop<O::VAL>(R(RSP), A(RSP+bits_to_bytes(l))) });
    };
    struct PUSHF {
        P(_, { mcop<O::VAL>(R(RSP), A(RSP-bits_to_bytes(l))),
               mcop<O::VAL>(M(RSP)[l], R(FLAGS)[0,l]) });
    };
    struct POPF {
        P(_, { mcop<O::VAL>(R(FLAGS)[0,l], M(RSP)[l]),
               mcop<O::VAL>(R(RSP), A(RSP+bits_to_bytes(l))) });
    };
    struct LEAVE {
        P(_, { mcop<O::VAL>(R(RSP), R(RBP)),
               mcop<O::VAL>(R(RBP)[0,l], M(RSP)[l]),
               mcop<O::VAL>(R(RSP), A(RSP+bits_to_bytes(l))) });
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
