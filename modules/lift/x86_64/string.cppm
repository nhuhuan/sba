module;
#include <cstdint>

export module sba.lift:x86_64_string;

import sba.arch;
import sba.ir;
import :emit;
import :x86_64_pattern;

namespace SBA::Lift::X86_64 {

    template <uint8_t l, uint8_t lm = l>
    struct P_MOVS {
        template <uint8_t>
        static Instruction _(Context& ctx, Cache& cache, const MCInstruction& inst)
        {
            if (HAS_REP(inst)) {
                static constexpr MCOP ops[] = {
                    mcop<O::S_VAL>(M(RDI)[lm], M(RSI)[lm], R(RCX)),
                    mcop<O::VAL>(R(RDI), A(RDI+(RCX<<bits_to_lbytes(lm)))),
                    mcop<O::VAL>(R(RSI), A(RSI+(RCX<<bits_to_lbytes(lm)))),
                    mcop<O::VAL>(R(RCX), 0ULL)
                };
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
            }
            static constexpr MCOP ops[] = {
                mcop<O::VAL>(M(RDI)[lm], M(RSI)[lm]),
                mcop<O::VAL>(R(RDI), A(RDI+bits_to_bytes(lm))),
                mcop<O::VAL>(R(RSI), A(RSI+bits_to_bytes(lm)))
            };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
        }
    };

    template <uint8_t l, uint8_t lm = l>
    struct P_CMPS {
        template <O s_op>
        static Instruction rep(Context& ctx, Cache& cache, const MCInstruction& inst)
        {
            static constexpr MCOP ops[] = {
                mcop<s_op>(R(TMP1), M(RSI)[lm], M(RDI)[lm], R(RCX)),
                mcop<O::VAL>(R(RSI), A(RSI+(TMP1<<bits_to_lbytes(lm)))),
                mcop<O::VAL>(R(RDI), A(RDI+(TMP1<<bits_to_lbytes(lm)))),
                mcop<O::SUB>(R(RCX), R(RCX), R(TMP1)),
                mcop<O::CMP>(R(FLAGS)[0,lm], M(RSI-bits_to_bytes(lm))[lm], M(RDI-bits_to_bytes(lm))[lm])
            };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
        }

        template <uint8_t>
        static Instruction _(Context& ctx, Cache& cache, const MCInstruction& inst)
        {
            if (HAS_REPNE(inst)) return rep<O::S_NE>(ctx, cache, inst);
            if (HAS_REPE(inst))  return rep<O::S_EQ>(ctx, cache, inst);
            static constexpr MCOP ops[] = {
                mcop<O::VAL>(R(RSI), A(RSI+bits_to_bytes(lm))),
                mcop<O::VAL>(R(RDI), A(RDI+bits_to_bytes(lm))),
                mcop<O::CMP>(R(FLAGS)[0,lm], M(RSI-bits_to_bytes(lm))[lm], M(RDI-bits_to_bytes(lm))[lm])
            };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
        }
    };

    template <uint8_t l, uint8_t lm = l>
    struct P_STOS {
        template <uint8_t>
        static Instruction _(Context& ctx, Cache& cache, const MCInstruction& inst)
        {
            if (HAS_REP(inst)) {
                static constexpr MCOP ops[] = {
                    mcop<O::S_VAL>(M(RDI)[lm], R(RAX)[0,lm], R(RCX)),
                    mcop<O::VAL>(R(RDI), A(RDI+(RCX<<bits_to_lbytes(lm)))),
                    mcop<O::VAL>(R(RCX), 0ULL)
                };
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
            }
            static constexpr MCOP ops[] = {
                mcop<O::VAL>(M(RDI)[lm], R(RAX)[0,lm]),
                mcop<O::VAL>(R(RDI), A(RDI+bits_to_bytes(lm)))
            };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
        }
    };

    template <uint8_t l, uint8_t lm = l>
    struct P_LODS {
        template <uint8_t>
        static Instruction _(Context& ctx, Cache& cache, const MCInstruction& inst)
        {
            if (HAS_REP(inst)) {
                static constexpr MCOP ops[] = {
                    mcop<O::VAL>(R(RAX)[0,lm], M(RSI+(RCX<<bits_to_lbytes(lm))-bits_to_bytes(lm))[lm]),
                    mcop<O::VAL>(R(RSI), A(RSI+(RCX<<bits_to_lbytes(lm)))),
                    mcop<O::VAL>(R(RCX), 0ULL)
                };
                return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
            }
            static constexpr MCOP ops[] = {
                mcop<O::VAL>(R(RAX)[0,lm], M(RSI)[lm]),
                mcop<O::VAL>(R(RSI), A(RSI+bits_to_bytes(lm)))
            };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
        }
    };

    template <uint8_t l, uint8_t lm = l>
    struct P_SCAS {
        template <O s_op>
        static Instruction rep(Context& ctx, Cache& cache, const MCInstruction& inst)
        {
            static constexpr MCOP ops[] = {
                mcop<s_op>(R(TMP1), R(RAX)[0,lm], M(RDI)[lm], R(RCX)),
                mcop<O::VAL>(R(RDI), A(RDI+(TMP1<<bits_to_lbytes(lm)))),
                mcop<O::SUB>(R(RCX), R(RCX), R(TMP1)),
                mcop<O::CMP>(R(FLAGS)[0,lm], R(RAX)[0,lm], M(RDI-bits_to_bytes(lm))[lm])
            };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
        }

        template <uint8_t>
        static Instruction _(Context& ctx, Cache& cache, const MCInstruction& inst)
        {
            if (HAS_REPNE(inst)) return rep<O::S_NE>(ctx, cache, inst);
            if (HAS_REPE(inst))  return rep<O::S_EQ>(ctx, cache, inst);
            static constexpr MCOP ops[] = {
                mcop<O::VAL>(R(RDI), A(RDI+bits_to_bytes(lm))),
                mcop<O::CMP>(R(FLAGS)[0,lm], R(RAX)[0,lm], M(RDI-bits_to_bytes(lm))[lm])
            };
            return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
        }
    };

    /* -----------------------------------------------------------------------*/

    struct MOVSB : P_MOVS<8> {};
    struct MOVSW : P_MOVS<16> {};
    struct MOVSL : P_MOVS<32> {};
    struct MOVSQ : P_MOVS<64> {};
    struct CMPSB : P_CMPS<8> {};
    struct CMPSW : P_CMPS<16> {};
    struct CMPSL : P_CMPS<32> {};
    struct CMPSQ : P_CMPS<64> {};
    struct STOSB : P_STOS<8> {};
    struct STOSW : P_STOS<16> {};
    struct STOSL : P_STOS<32> {};
    struct STOSQ : P_STOS<64> {};
    struct LODSB : P_LODS<8> {};
    struct LODSW : P_LODS<16> {};
    struct LODSL : P_LODS<32> {};
    struct LODSQ : P_LODS<64> {};
    struct SCASB : P_SCAS<8> {};
    struct SCASW : P_SCAS<16> {};
    struct SCASL : P_SCAS<32> {};
    struct SCASQ : P_SCAS<64> {};

    using Mnemonics_STR = SBA::Util::TypeList<
        MOVSB, MOVSW, MOVSL, MOVSQ,
        CMPSB, CMPSW, CMPSL, CMPSQ,
        STOSB, STOSW, STOSL, STOSQ,
        LODSB, LODSW, LODSL, LODSQ,
        SCASB, SCASW, SCASL, SCASQ
    >;

}