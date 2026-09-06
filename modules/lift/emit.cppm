module;
#include <array>
#include <cassert>
#include <concepts>
#include <cstdint>
#include <span>

export module sba.lift:emit;

import sba.arch;
import sba.ir;
import :decode;
import :cache;
import :parse;

namespace SBA::Lift {

	using namespace SBA::IR;
	using SBA::Arch::Target;

	struct DynamicRegister {
		uint8_t index;
		bool negated;

		constexpr DynamicRegister(uint8_t idx) noexcept
			: index(idx), negated(false) {}

		constexpr DynamicRegister operator-() const noexcept {
			DynamicRegister res = *this;
			res.negated = !negated;
			return res;
		}
	};

	struct DynamicImmediate {
		uint8_t index;
		bool negated;

		constexpr DynamicImmediate(uint8_t idx) noexcept
			: index(idx), negated(false) {}

		constexpr DynamicImmediate operator-() const noexcept {
			DynamicImmediate res = *this;
			res.negated = !negated;
			return res;
		}
	};

	struct DynamicMemory {
		uint8_t index;
		uint8_t llength;
		bool negated;

		constexpr DynamicMemory(uint8_t idx, uint8_t l) noexcept
			: index(idx), llength(l), negated(false) {}

		constexpr DynamicMemory operator-() const noexcept {
			DynamicMemory res = *this;
			res.negated = !negated;
			return res;
		}
	};

	struct DynamicAffine {
		uint8_t index;
		bool negated;

		constexpr DynamicAffine(uint8_t idx) noexcept
			: index(idx), negated(false) {}

		constexpr DynamicAffine operator-() const noexcept {
			DynamicAffine res = *this;
			res.negated = !negated;
			return res;
		}
	};

	struct MCOperand {
		enum class Type : uint8_t {
			OPERAND,
			REGISTER,
			IMMEDIATE,
			AFFINE,
			DYN_REGISTER,
			DYN_IMMEDIATE,
			DYN_MEMORY,
			DYN_AFFINE
		} type;

		union {
			DynamicRegister  r_;
			DynamicImmediate i_;
			DynamicMemory    m_;
			DynamicAffine    a_;

			Operand  O_;
			Register R_;
			uint64_t I_;
			Affine   A_;
		};

		constexpr MCOperand() noexcept
			: type(Type::OPERAND), O_(NO_REG) {}

		constexpr MCOperand(Operand val) noexcept
			: type(Type::OPERAND), O_(val) {}

		constexpr MCOperand(Register val) noexcept
			: type(Type::REGISTER), R_(val) {}

		constexpr MCOperand(uint64_t val) noexcept
			: type(Type::IMMEDIATE), I_(val) {}

		constexpr MCOperand(Affine val) noexcept
			: type(Type::AFFINE), A_(val) {}

		constexpr MCOperand(DynamicRegister d) noexcept
			: type(Type::DYN_REGISTER), r_(d) {}

		constexpr MCOperand(DynamicImmediate d) noexcept
			: type(Type::DYN_IMMEDIATE), i_(d) {}

		constexpr MCOperand(DynamicMemory d) noexcept
			: type(Type::DYN_MEMORY), m_(d) {}

		constexpr MCOperand(DynamicAffine d) noexcept
			: type(Type::DYN_AFFINE), a_(d) {}

		constexpr MCOperand llength(uint8_t l) const noexcept {
			MCOperand res = *this;
			switch (res.type) {
				case Type::OPERAND:
					res.O_.r.llength = l;
					break;
				case Type::REGISTER:
					res.R_.llength   = l;
					break;
				case Type::AFFINE:
					res.A_.llength   = l;
					break;
				default:
					assert(false);
			}
			return res;
		}

		template <Target T>
		inline Operand encode(
			Context& ctx,
			Cache& cache,
			const MCInstruction& inst) const
		{
			switch (type) {
				case Type::OPERAND:
					return O_;

				case Type::REGISTER:
					return ctx.encode(R_);

				case Type::IMMEDIATE:
					return ctx.encode(cache, I_);

				case Type::AFFINE:
					return ctx.encode(cache, A_);

				case Type::DYN_REGISTER:
					return parse_r<T>(
						inst.getOperand(r_.index),
						!!r_.negated
					);

				case Type::DYN_IMMEDIATE:
					return parse_i(
						ctx,
						cache,
						inst.getOperand(i_.index),
						!!i_.negated
					);

				case Type::DYN_MEMORY:
					return parse_a<T>(
						ctx,
						cache,
						inst.getOperand(m_.index),
						m_.llength,
						1,
						!!m_.negated
					);

				case Type::DYN_AFFINE:
					return parse_a<T>(
						ctx,
						cache,
						inst.getOperand(a_.index),
						0,
						0,
						!!a_.negated
					);

				default:
					return NO_REG;
			}
		}
	};

	struct MCOperation {
		Operator op;
		MCOperand dst;
		std::array<MCOperand, MAX_ARITY> src;

		constexpr MCOperation() noexcept = default;

		template <typename... Args>
			requires (sizeof...(Args) <= MAX_ARITY &&
			         (std::convertible_to<Args, MCOperand> && ...))
		constexpr MCOperation(
			Operator o,
			MCOperand d,
			Args&&... args) noexcept
			: op(o), dst(d), src{ static_cast<MCOperand>(args)... } {}
	};

	template <Target T>
	inline Instruction emit(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst,
		std::span<const MCOperation> ops)
	{
		std::array<Operator, MAX_OPERATIONS> opcodes;
		std::array<Operand, MAX_OPERANDS> operands;
		size_t opcode_count = 0;
		size_t operand_count = 0;

		for (const auto& op : ops) {
			opcodes[opcode_count++] = op.op;
			operands[operand_count++] = op.dst.encode<T>(ctx, cache, inst);
			for (size_t i = 0; i < arity(op.op); ++i)
				operands[operand_count++] = op.src[i].encode<T>(ctx, cache, inst);
		}

		return ctx.encode(
			cache,
			Instruction::Type::STORE,
			inst.length(),
			{ opcodes.data(), opcode_count },
			{ operands.data(), operand_count }
		);
	}

}
