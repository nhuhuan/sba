module;
#include <array>
#include <cstdint>
#include <initializer_list>
#include <span>

export module sba.lift:x86_64_pattern;

import sba.arch;
import sba.ir;
import sba.util;
import :emit;

namespace SBA::Lift::X86_64 {

    using SBA::Util::bits_to_bytes;
    using SBA::Util::bits_to_lbytes;

    using enum SBA::Arch::X86_64::Reg;

    using O = SBA::IR::Operator;
    using MCOP = SBA::Lift::MCOperation;

    struct Pattern {
        struct List {
            std::array<MCOperation, SBA::IR::MAX_OPERATIONS> data{};
            size_t count = 0;

            constexpr List() noexcept = default;
            constexpr List(std::initializer_list<MCOperation> ops) noexcept {
                for (const auto& op : ops)
                    if (op.opcode != Operator::_)
                        data[count++] = op;
            }
            constexpr operator std::span<const MCOperation>() const noexcept {
                return { data.data(), count };
            }
        };

        List logic;
        List flags = {};
    };

    inline constexpr bool HAS_REP(MCInstruction inst) noexcept {
        return inst.getFlags() & 0x8;
    }

    inline constexpr bool HAS_REPE(MCInstruction inst) noexcept {
        return inst.getFlags() & 0x8;
    }

    inline constexpr bool HAS_REPNE(MCInstruction inst) noexcept {
        return inst.getFlags() & 0x4;
    }

    inline constexpr O CC[16] = {
        O::SELECT_O,
        O::SELECT_NO,
        O::SELECT_LTU,
        O::SELECT_GEU,
        O::SELECT_EQ,
        O::SELECT_NE,
        O::SELECT_LEU,
        O::SELECT_GTU,
        O::SELECT_S,
        O::SELECT_NS,
        O::SELECT_P,
        O::SELECT_NP,
        O::SELECT_LT,
        O::SELECT_GE,
        O::SELECT_LE,
        O::SELECT_GT
    };

    /* 0. Fixed Operands */

    template <O op, typename... Args>
    constexpr MCOP mcop(Args&&... args) noexcept {
        return { op, static_cast<MCOperand>(args)... };
    }

    template <uint8_t l>
    constexpr MCOP zero_high32(DRegister reg) noexcept {
        if constexpr (l == 32)
            return mcop<O::ZEXT>(reg[0, 64], reg[0, 32]);
        else
            return mcop<O::_>();
    }

    template <uint8_t l>
    constexpr MCOP zero_high32(Register reg) noexcept {
        if constexpr (l == 32)
            return mcop<O::ZEXT>(reg, reg[0, 32]);
        else
            return mcop<O::_>();
    }

    /* 1. Data Copy */

    template <O op>
    constexpr MCOP r_1() noexcept {
        return { op, DR(0) };
    }

    template <O op>
    constexpr MCOP r_x1(MCOperand x) noexcept {
        return { op, x, DR(0) };
    }

    template <O op>
    constexpr MCOP r_1x(MCOperand x) noexcept {
        return { op, DR(0), x };
    }

    template <O op>
    constexpr MCOP i_x1(MCOperand x) noexcept {
        return { op, x, DI(0) };
    }

    template <O op>
    constexpr MCOP rr_2x(MCOperand x) noexcept {
        return { op, DR(1), x };
    }

    template <O op, uint8_t lm>
    constexpr MCOP m_x1(MCOperand x) noexcept {
        return { op, x, DM(0)[lm] };
    }

    template <O op, uint8_t lm>
    constexpr MCOP m_1x(MCOperand x) noexcept {
        return { op, DM(0)[lm], x };
    }

    template <O op>
    constexpr MCOP rr_12() noexcept {
        return { op, DR(0), DR(1) };
    }

    template <O op>
    constexpr MCOP ri_12() noexcept {
        return { op, DR(0), DI(1) };
    }

    template <O op>
    constexpr MCOP ra_12() noexcept {
        return { op, DR(0), DA(1) };
    }

    template <O op, uint8_t lm>
    constexpr MCOP rm_12() noexcept {
        return { op, DR(0), DM(1)[lm] };
    }

    template <O op, uint8_t lm>
    constexpr MCOP mr_12() noexcept {
        return { op, DM(0)[lm], DR(5) };
    }

    template <O op, uint8_t lm>
    constexpr MCOP mi_12() noexcept {
        return { op, DM(0)[lm], DI(5) };
    }

    /* 2. Unary ALU */

    template <O op>
    constexpr MCOP rr_12x(MCOperand x) noexcept {
        return { op, DR(0), DR(1), x };
    }

    template <O op, uint8_t lm>
    constexpr MCOP m_11() noexcept {
        return { op, DM(0)[lm], DM(0)[lm] };
    }

    template <O op, uint8_t lm>
    constexpr MCOP m_11x(MCOperand x) noexcept {
        return { op, DM(0)[lm], DM(0)[lm], x };
    }

    template <O op, uint8_t lm>
    constexpr MCOP rrm_13() noexcept {
        return { op, DR(0), DM(2)[lm] };
    }

    template <O op, uint8_t lm>
    constexpr MCOP rrm_x3(MCOperand x) noexcept {
        return { op, x, DM(2)[lm] };
    }

    /* 3. Binary ALU */

    template <O op>
    constexpr MCOP rr_112() noexcept {
        return { op, DR(0), DR(0), DR(1) };
    }

    template <O op>
    constexpr MCOP rrr_123() noexcept {
        return { op, DR(0), DR(1), DR(2) };
    }

    template <O op>
    constexpr MCOP rri_123() noexcept {
        return { op, DR(0), DR(1), DI(2) };
    }

    template <O op, uint8_t lm>
    constexpr MCOP rrm_123() noexcept {
        return { op, DR(0), DR(1), DM(2)[lm] };
    }

    template <O op>
    constexpr MCOP r_xx1(MCOperand x1, MCOperand x2) noexcept {
        return { op, x1, x2, DR(0) };
    }

    template <O op, uint8_t lm>
    constexpr MCOP m_xx1(MCOperand x1, MCOperand x2) noexcept {
        return { op, x1, x2, DM(0)[lm] };
    }

    template <O op, uint8_t lm>
    constexpr MCOP mr_112() noexcept {
        return { op, DM(0)[lm], DM(0)[lm], DR(5) };
    }

    template <O op, uint8_t lm>
    constexpr MCOP mi_112() noexcept {
        return { op, DM(0)[lm], DM(0)[lm], DI(5) };
    }

    template <O op>
    constexpr MCOP rrr_123x(MCOperand x) noexcept {
        return { op, DR(0), DR(1), DR(2), x };
    }

    template <O op>
    constexpr MCOP rri_123x(MCOperand x) noexcept {
        return { op, DR(0), DR(1), DI(2), x };
    }

    template <O op, uint8_t lm>
    constexpr MCOP rrm_123x(MCOperand x) noexcept {
        return { op, DR(0), DR(1), DM(2)[lm], x };
    }

    template <O op, uint8_t lm>
    constexpr MCOP mr_112x(MCOperand x) noexcept {
        return { op, DM(0)[lm], DM(0)[lm], DR(5), x };
    }

    template <O op, uint8_t lm>
    constexpr MCOP mi_112x(MCOperand x) noexcept {
        return { op, DM(0)[lm], DM(0)[lm], DI(5), x };
    }

    template <O op>
    constexpr MCOP rr_x2(MCOperand x) noexcept {
        return { op, x, DR(1) };
    }

    template <O op, uint8_t lm>
    constexpr MCOP rm_x2(MCOperand x) noexcept {
        return { op, x, DM(1)[lm] };
    }

    template <O op, uint8_t lm>
    constexpr MCOP rm_12x(MCOperand x) noexcept {
        return { op, DR(0), DM(1)[lm], x };
    }

    template <O op>
    constexpr MCOP rrr_1x3(MCOperand x) noexcept {
        return { op, DR(0), x, DR(2) };
    }

    template <O op>
    constexpr MCOP rrr_2x3(MCOperand x) noexcept {
        return { op, DR(1), x, DR(2) };
    }

    template <O op, uint8_t lm>
    constexpr MCOP rrm_1x3(MCOperand x) noexcept {
        return { op, DR(0), x, DM(2)[lm] };
    }

    template <O op, uint8_t lm>
    constexpr MCOP rrm_2x3(MCOperand x) noexcept {
        return { op, DR(1), x, DM(2)[lm] };
    }

    template <O op>
    constexpr MCOP rrr_xx3(MCOperand x1, MCOperand x2) noexcept {
        return { op, x1, x2, DR(2) };
    }

    template <O op, uint8_t lm>
    constexpr MCOP rmr_123() noexcept {
        return { op, DR(0), DM(1)[lm], DR(6) };
    }

    template <O op>
    constexpr MCOP rmr_xx3(MCOperand x1, MCOperand x2) noexcept {
        return { op, x1, x2, DR(6) };
    }

    template <O op>
    constexpr MCOP r_1xx(MCOperand x1, MCOperand x2) noexcept {
        return { op, DR(0), x1, x2 };
    }

    /* 4. Comparison */

    template <O op, bool neg = false>
    constexpr MCOP rrr_x23(MCOperand x) noexcept {
        return { op, x, DR(1), neg ? -DR(2) : DR(2) };
    }

    template <O op, bool neg = false>
    constexpr MCOP rrr_x23x(MCOperand x1, MCOperand x2) noexcept {
        return { op, x1, DR(1), neg ? -DR(2) : DR(2), x2 };
    }

    template <O op, bool neg = false>
    constexpr MCOP rri_x23(MCOperand x) noexcept {
        return { op, x, DR(1), neg ? -DI(2) : DI(2) };
    }

    template <O op, uint8_t lm, bool neg = false>
    constexpr MCOP rrm_x23(MCOperand x) noexcept {
        return { op, x, DR(1), neg ? -DM(2)[lm] : DM(2)[lm] };
    }

    template <O op, uint8_t lm, bool neg = false>
    constexpr MCOP rrm_x23x(MCOperand x1, MCOperand x2) noexcept {
        return { op, x1, DR(1), neg ? -DM(2)[lm] : DM(2)[lm], x2 };
    }

    template <O op, bool neg = false>
    constexpr MCOP rr_x12(MCOperand x) noexcept {
        return { op, x, DR(0), neg ? -DR(1) : DR(1) };
    }

    template <O op, bool neg = false>
    constexpr MCOP ri_x12(MCOperand x) noexcept {
        return { op, x, DR(0), neg ? -DI(1) : DI(1) };
    }

    template <O op, uint8_t lm, bool neg = false>
    constexpr MCOP rm_x12(MCOperand x) noexcept {
        return { op, x, DR(0), neg ? -DM(1)[lm] : DM(1)[lm] };
    }

    template <O op, uint8_t lm, bool neg = false>
    constexpr MCOP mr_x12(MCOperand x) noexcept {
        return { op, x, DM(0)[lm], neg ? -DR(5) : DR(5) };
    }

    template <O op, uint8_t lm, bool neg = false>
    constexpr MCOP mi_x12(MCOperand x) noexcept {
        return { op, x, DM(0)[lm], neg ? -DI(5) : DI(5) };
    }

    template <O op, bool neg = false>
    constexpr MCOP i_xx1(MCOperand x1, MCOperand x2) noexcept {
        return { op, x1, x2, neg ? -DI(0) : DI(0) };
    }

    template <O op>
    constexpr MCOP r_x1x(MCOperand x1, MCOperand x2) noexcept {
        return { op, x1, DR(0), x2 };
    }

    template <O op>
    constexpr MCOP rr_x2x(MCOperand x1, MCOperand x2) noexcept {
        return { op, x1, DR(1), x2 };
    }

    template <O op, uint8_t lm>
    constexpr MCOP rm_x2x(MCOperand x1, MCOperand x2) noexcept {
        return { op, x1, DM(1)[lm], x2 };
    }

    template <O op, uint8_t lm, bool neg = false>
    constexpr MCOP rrm_x31(MCOperand x) noexcept {
        return { op, x, DM(2)[lm], neg ? -DR(0) : DR(0) };
    }

    template <O op, uint8_t lm>
    constexpr MCOP m_x1x(MCOperand x1, MCOperand x2) noexcept {
        return { op, x1, DM(0)[lm], x2 };
    }

    template <O op>
    constexpr MCOP rr_xx2(MCOperand x1, MCOperand x2) noexcept {
        return { op, x1, x2, DR(1) };
    }

    /* 5. Atomic / Exchange */

    template <O op, uint8_t lm>
    constexpr MCOP rrm_3x(MCOperand x) noexcept {
        return { op, DM(2)[lm], x };
    }

    template <O op, uint8_t lm>
    constexpr MCOP rrm_331() noexcept {
        return { op, DM(2)[lm], DM(2)[lm], DR(0) };
    }

    template <O op>
    constexpr MCOP rr_1x2x(MCOperand x1, MCOperand x2) noexcept {
        return { op, DR(0), x1, DR(1), x2 };
    }

    template <O op, uint8_t lm>
    constexpr MCOP mr_1x2x(MCOperand x1, MCOperand x2) noexcept {
        return { op, DM(0)[lm], x1, DR(5), x2 };
    }

}
