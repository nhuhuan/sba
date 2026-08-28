module;
#include <array>
#include <cstdint>
#include <span>
#include <llvm/MC/MCInst.h>

export module sba.lift:emit;

import sba.arch;
import sba.ir;
import :decoder;
import :cache;
import :parser;

namespace SBA::Lift {

	using namespace SBA::IR;
	using SBA::Arch::Target;

	struct MCOperand {
		enum class Type : uint8_t {
			OPERAND,
			REGISTER,
			IMMEDIATE,
			MEMORY,
			AFFINE,
			MC_REGISTER,
			MC_IMMEDIATE,
			MC_MEMORY,
			MC_AFFINE
		} type;

		union {
			struct {
				uint8_t index;
			} mc_r_;

			struct {
				uint8_t index;
			} mc_i_;

			struct {
				uint8_t index;
				uint8_t llength;
			} mc_m_;

			struct {
				uint8_t index;
				uint8_t llength;
			} mc_a_;

			Operand  o_;
			Register r_;
			uint64_t i_;
			Affine   m_;
			Affine   a_;
		};

		static constexpr MCOperand o(Operand val) noexcept {
			return MCOperand {
				.type = Type::OPERAND,
				.o_   = val
			};
		}

		static constexpr MCOperand r(Register val) noexcept {
			return MCOperand {
				.type = Type::REGISTER,
				.r_   = val
			};
		}

		static constexpr MCOperand i(uint64_t val) noexcept {
			return MCOperand {
				.type = Type::IMMEDIATE,
				.i_   = val
			};
		}

		static constexpr MCOperand m(Affine val) noexcept {
			return MCOperand {
				.type = Type::MEMORY,
				.m_   = val
			};
		}

		static constexpr MCOperand a(Affine val) noexcept {
			return MCOperand {
				.type = Type::AFFINE,
				.a_   = val
			};
		}

		static constexpr MCOperand mc_r(uint8_t index) noexcept {
			return MCOperand {
				.type  = Type::MC_REGISTER,
				.mc_r_ = { .index = index }
			};
		}

		static constexpr MCOperand mc_i(uint8_t index) noexcept {
			return MCOperand {
				.type  = Type::MC_IMMEDIATE,
				.mc_i_ = { .index = index }
			};
		}

		static constexpr MCOperand mc_m(uint8_t index, uint8_t llength) noexcept
		{
			return MCOperand {
				.type  = Type::MC_MEMORY,
				.mc_m_ = { .index = index, .llength = llength }
			};
		}

		static constexpr MCOperand mc_a(uint8_t index, uint8_t llength) noexcept
		{
			return MCOperand {
				.type  = Type::MC_AFFINE,
				.mc_a_ = { .index = index, .llength = llength }
			};
		}

		template <Target T>
		inline Operand encode(
			Context& ctx,
			Cache& cache,
			const MCInstruction& inst) const
		{
			switch (type) {
				case Type::REGISTER:
					return ctx.encode(r_);

				case Type::OPERAND:
					return o_;

				case Type::IMMEDIATE:
					return ctx.encode(cache, i_);

				case Type::MEMORY:
					return ctx.encode(cache, m_);

				case Type::AFFINE:
					return ctx.encode(cache, a_, false);

				case Type::MC_REGISTER:
					return parse_r<T>(
						inst.getOperand(mc_r_.index)
					);

				case Type::MC_IMMEDIATE:
					return parse_i(
						ctx, cache, inst.getOperand(mc_i_.index)
					);

				case Type::MC_MEMORY:
					return parse_m<T>(
						ctx,
						cache,
						inst.getOperand(mc_m_.index),
						mc_m_.llength
					);

				case Type::MC_AFFINE:
					return parse_a<T>(
						ctx,
						cache,
						inst.getOperand(mc_a_.index),
						mc_a_.llength
					);

				default:
					return NO_REGISTER;
			}
		}
	};

	struct MCOperation {
		Operator op;
		MCOperand dst;
		std::array<MCOperand, MAX_ARITY> src = {};
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
