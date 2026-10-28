module;
#include <array>
#include <concepts>
#include <cstdint>
#include <span>

export module sba.lift:emit;

import sba.arch;
import sba.ir;
import :cache;
import :target;
import :decode;
import :parse;

export namespace SBA::Lift {

    using namespace SBA::IR;
    using SBA::Arch::Target;

    /* -------------------------- Dynamic Operands -------------------------- */

    struct DRegister {
        uint8_t index;
        uint32_t offset = 0;
        uint32_t length = 0;
        bool negated = false;

        constexpr DRegister operator-() const noexcept {
            return { index, offset, length, !negated };
        }

        constexpr DRegister operator[](uint32_t s, uint32_t e) const noexcept {
            return { index, s, e - s, negated };
        }

        constexpr DRegister operator[](uint32_t bit) const noexcept {
            return (*this)[bit, bit + 1];
        }
    };

    struct DImmediate {
        uint8_t index;
        bool negated = false;
        constexpr DImmediate operator-() const noexcept {
            return { index, !negated };
        }
    };

    struct DMemory {
        uint8_t index;
        uint32_t length_m = 0;
        bool negated = false;

        constexpr DMemory operator-() const noexcept {
            return { index, length_m, !negated };
        }

        constexpr DMemory operator[](uint32_t l) const noexcept {
            return { index, l, negated };
        }
    };

    struct DAffine {
        uint8_t index;
        bool negated = false;
        constexpr DAffine operator-() const noexcept {
            return { index, !negated };
        }
    };

    using DR = DRegister;
    using DI = DImmediate;
    using DM = DMemory;
    using DA = DAffine;

    /* -------------------------- Static Operands --------------------------- */

    constexpr Register R(Register reg) noexcept {
        return reg;
    }

    constexpr Register R(RegEnum auto reg) noexcept {
        return Register((uint8_t)reg);
    }

    constexpr Affine A(Affine addr) noexcept {
        addr.deref = 0;
        return addr;
    }

    constexpr Affine A(Register base) noexcept {
        return Affine(0, base.index);
    }

    constexpr Affine A(RegEnum auto base) noexcept {
        return A(R(base));
    }

    constexpr Affine M(Affine addr) noexcept {
        addr.deref = 1;
        addr.llength_m = SBA::Util::bits_to_lbytes(DEFAULT_WIDTH);
        return addr;
    }

    constexpr Affine M(Register base) noexcept {
        return M(A(base));
    }

    constexpr Affine M(RegEnum auto base) noexcept {
        return M(R(base));
    }

    /* ----------------------------- MCOperand ------------------------------ */

    struct MCOperand {
        enum class Type : uint8_t {
            OPERAND,
            IMMEDIATE,
            AFFINE,
            DREGISTER,
            DIMMEDIATE,
            DMEMORY,
            DAFFINE
        } type;

        union {
            Operand    O_;
            uint64_t   I_;
            Affine     A_;
            DRegister  r_;
            DImmediate i_;
            DMemory    m_;
            DAffine    a_;
        };

        constexpr MCOperand() noexcept : type(Type::OPERAND), O_(NO_REG) {}
        constexpr MCOperand(Operand v) noexcept : type(Type::OPERAND), O_(v) {}
        constexpr MCOperand(Register v) noexcept : type(Type::OPERAND), O_(v) {}
        constexpr MCOperand(uint64_t v) noexcept : type(Type::IMMEDIATE), I_(v) {}
        constexpr MCOperand(Affine v) noexcept : type(Type::AFFINE), A_(v) {}
        constexpr MCOperand(DRegister v) noexcept : type(Type::DREGISTER), r_(v) {}
        constexpr MCOperand(DImmediate v) noexcept : type(Type::DIMMEDIATE), i_(v) {}
        constexpr MCOperand(DMemory v) noexcept : type(Type::DMEMORY), m_(v) {}
        constexpr MCOperand(DAffine v) noexcept : type(Type::DAFFINE), a_(v) {}

        template <SBA::Arch::Target T>
        inline Operand encode(
            Context& ctx,
            Cache& cache,
            const MCInstruction& inst) const
        {
            switch (type) {
                case Type::OPERAND:
                    return O_;
                case Type::IMMEDIATE:
                    return ctx.encode(cache, I_);
                case Type::AFFINE:
                    return ctx.encode(cache, A_);
                case Type::DREGISTER:
                    return parse_r<T>(inst.getOperand(r_.index),
                                      r_.offset, r_.length, r_.negated);
                case Type::DIMMEDIATE:
                    return parse_i(ctx, cache,
                                      inst.getOperand(i_.index), i_.negated);
                case Type::DAFFINE:
                    return parse_a<T>(ctx, cache,
                                      inst.getOperand(a_.index), a_.negated);
                case Type::DMEMORY:
                    return parse_m<T>(ctx, cache,
                                      inst.getOperand(m_.index),
                                      m_.length_m, m_.negated);
                default:
                    return NO_REG;
            }
        }
    };

    /* ---------------------------- MCOperation ----------------------------- */

    struct MCOperation {
        Operator opcode = Operator::_;
        std::array<MCOperand, MAX_ARITY> operands{};

        constexpr MCOperation() noexcept = default;

        template <typename... Args>
            requires (sizeof...(Args) <= MAX_ARITY &&
                     (std::convertible_to<Args, MCOperand> && ...))
        constexpr MCOperation(
            Operator opcode,
            Args&&... args) noexcept
            : opcode(opcode), operands { static_cast<MCOperand>(args)... } {}
    };

    template <Target T, typename... MCOperations>
    inline Instruction emit(
        Context& ctx,
        Cache& cache,
        const MCInstruction& inst,
        MCOperations&&... ops)
    {
        std::array<Operator, MAX_OPERATIONS> opcodes;
        std::array<Operand, MAX_OPERANDS> operands;
        size_t opcode_count = 0;
        size_t operand_count = 0;

        auto serialize = [&](auto&& arg) {
            std::span<const MCOperation> ops(arg);
            for (const auto& op : ops) {
                opcodes[opcode_count++] = op.opcode;
                for (size_t i = 0; i < arity(op.opcode); ++i)
                    operands[operand_count++] =
                        op.operands[i].encode<T>(ctx, cache, inst);
            }
        };

        (serialize(ops), ...);

        return ctx.encode(
            cache,
            inst.length(),
            { opcodes.data(), opcode_count },
            { operands.data(), operand_count }
        );
    }

}
