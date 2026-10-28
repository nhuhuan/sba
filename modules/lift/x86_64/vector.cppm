module;
#include <cstdint>

export module sba.lift:x86_64_vector;

import sba.ir;
import :x86_64_pattern;

namespace SBA::Lift::X86_64 {

    #define P(Suffix, ...) \
        template <uint8_t l> \
        static constexpr Pattern Suffix = { __VA_ARGS__ }

    #define PM(Suffix, ...) \
        template <uint8_t l, uint8_t lm = l> \
        static constexpr Pattern Suffix = { __VA_ARGS__ }

    struct P_VEC_MOV {
        P(rr,  { rr_12<O::VAL>() });
        PM(rm, { rm_12<O::VAL,128>() });
        PM(mr, { mr_12<O::VAL,128>() });
    };

    template <uint32_t l_vec>
    struct P_VEC_MOVS {
        P(rr,  { mcop<O::VAL>(DR(0)[0,l_vec], DR(2)[0,l_vec]) });
        PM(rm, { rm_12<O::ZEXT,l_vec>() });
        PM(mr, { mr_12<O::VAL,l_vec>() });
    };

    template <O op, uint32_t l_vec>
    struct P_VEC_ALU {
        P(rr,  { rrr_123<op>() });
        PM(rm, { rrm_123<op,l_vec>() });
    };

    template <uint32_t l_vec>
    struct P_VEC_CMP {
        P(rr,  { rr_x12<O::CMP>(R(FLAGS)) });
        PM(rm, { rm_x12<O::CMP,l_vec>(R(FLAGS)) });
    };

    /* -----------------------------------------------------------------------*/

    struct MOVAPS  : P_VEC_MOV {};
    struct MOVUPS  : P_VEC_MOV {};
    struct MOVAPD  : P_VEC_MOV {};
    struct MOVUPD  : P_VEC_MOV {};
    struct MOVDQA  : P_VEC_MOV {};
    struct MOVDQU  : P_VEC_MOV {};
    struct MOVSS   : P_VEC_MOVS<32> {};
    struct MOVSD   : P_VEC_MOVS<64> {};
    struct ADDSS   : P_VEC_ALU<O::FADD,32> {};
    struct ADDSD   : P_VEC_ALU<O::FADD,64> {};
    struct SUBSS   : P_VEC_ALU<O::FSUB,32> {};
    struct SUBSD   : P_VEC_ALU<O::FSUB,64> {};
    struct MULSS   : P_VEC_ALU<O::FMUL,32> {};
    struct MULSD   : P_VEC_ALU<O::FMUL,64> {};
    struct DIVSS   : P_VEC_ALU<O::FDIV,32> {};
    struct DIVSD   : P_VEC_ALU<O::FDIV,64> {};
    struct XORPS   : P_VEC_ALU<O::XOR,128> {};
    struct XORPD   : P_VEC_ALU<O::XOR,128> {};
    struct ANDPS   : P_VEC_ALU<O::AND,128> {};
    struct ANDPD   : P_VEC_ALU<O::AND,128> {};
    struct ORPS    : P_VEC_ALU<O::OR,128> {};
    struct ORPD    : P_VEC_ALU<O::OR,128> {};
    struct COMISS  : P_VEC_CMP<32> {};
    struct COMISD  : P_VEC_CMP<64> {};
    struct UCOMISS : P_VEC_CMP<32> {};
    struct UCOMISD : P_VEC_CMP<64> {};

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
