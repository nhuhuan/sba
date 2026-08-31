module;
#include <cassert>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <bit>

export module sba.ir:context;

import sba.util;
import :syntax;
import :constant;
import :semantics;

export namespace SBA::IR {

	struct InstructionTag {
		uint8_t tag;

		constexpr InstructionTag(uint8_t t) noexcept : tag(t) {}

		constexpr InstructionTag(
			Instruction::Type type,
			uint8_t count,
			uint8_t length) noexcept
		{
			auto t = (type != Instruction::Type::STORE) ?
					 ((uint8_t)type | 0x8) : (count & 0x7);
			tag = (t << 4) | (length & 0xf);
		}

		constexpr Instruction::Type type() const noexcept {
			uint8_t t = tag >> 4;
			return (t & 0x8) ?
				   (Instruction::Type)(t & 0x7) : Instruction::Type::STORE;
		}

		constexpr uint8_t count() const noexcept {
			uint8_t t = tag >> 4;
			return (t & 0x8) ? 0 : (t & 0x7);
		}

		constexpr uint8_t length() const noexcept {
			return tag & 0xf;
		}
	};

	class View;

	struct Context {
		SBA::Util::PVector<uint8_t,  (1ULL << INST_BITS)> inst;
		SBA::Util::PVector<uint32_t, (1ULL << IMM_BITS)>  i32;
		SBA::Util::PVector<uint64_t, (1ULL << IMM_BITS)>  i64;
		SBA::Util::PVector<Affine,   (1ULL << AFF_BITS)>  aff;

		View operator[](Instruction i) const noexcept;

		Register r(Operand op) const noexcept { return op.r; }
		Affine   a(Operand op) const noexcept { return aff[op.a.index]; }
		uint64_t i(Operand op) const noexcept {
			return op.i.wide ? i64[op.i.index] : i32[op.i.index];
		}

		Context() {
			aff.push_back(
				Affine {
					.displacement = 0,
					.base         = (uint8_t)r(ANY_REG).index,
					.index        = (uint8_t)r(NO_REG).index,
					.shift        = 0,
					.extra        = (uint8_t)r(NO_REG).index,
					.llength      = 0,
					.llength_addr = 3,
					.dereferenced = 1,
					.negated      = 0
				}
			);
		}

		Operand encode(Register val) noexcept { return Operand { .r = val }; }

		template <typename C>
		Operand encode(C& cache, uint64_t val) noexcept {
			if (val <= std::numeric_limits<uint32_t>::max()) {
				auto index = cache.i32.get_or_insert(
					(uint32_t)val,
					[&] { return i32.push_back((uint32_t)val); }
				);

				if (index)
					return Operand {
						.i = {
							.type  = (uint32_t)Operand::Type::IMMEDIATE,
							.wide  = 0,
							.index = (uint32_t)*index
						}
					};
			}

			auto index = cache.i64.get_or_insert(
				val,
				[&] { return i64.push_back(val); }
			);

			assert(index);

			return Operand {
				.i = {
					.type  = (uint32_t)Operand::Type::IMMEDIATE,
					.wide  = 1,
					.index = (uint32_t)*index
				}
			};
		}

		template <typename C>
		Operand encode(C& cache, Affine val) noexcept {
			auto index = cache.a.get_or_insert(
				std::bit_cast<uint64_t>(val),
				[&] { return aff.push_back(val); }
			);

			assert(index);

			return Operand {
				.a = {
					.type  = (uint32_t)Operand::Type::AFFINE,
					.index = (uint32_t)*index
				}
			};
		}

		template <typename C>
		Instruction encode(
			C& cache,
			Instruction::Type type,
			uint8_t length,
			std::span<const Operator> opcodes,
			std::span<const Operand> operands) noexcept
		{
			InstructionTag t(type, (uint8_t)opcodes.size(), length);

			uint64_t h = SBA::Util::wyhash(&t.tag, sizeof(t.tag), 0);
			if (!opcodes.empty())
				h = SBA::Util::wyhash(opcodes.data(), opcodes.size_bytes(), h);
			if (!operands.empty())
				h = SBA::Util::wyhash(operands.data(), operands.size_bytes(), h);

			auto index = cache.inst.get_or_insert(
				h,
				[&]() -> std::optional<uint32_t> {
					auto opcode_size = opcodes.size_bytes();
					auto operand_size = operands.size_bytes();
					auto size = opcode_size + operand_size + 1;

					auto idx = inst.reserve(size);
					if (!idx)
						return std::nullopt;

					uint32_t offset = *idx;
					inst[offset++] = t.tag;

					if (!opcodes.empty()) {
						std::memcpy(&inst[offset], opcodes.data(), opcode_size);
						offset += opcode_size;
					}

					if (!operands.empty()) {
						std::memcpy(&inst[offset], operands.data(), operand_size);
						offset += operand_size;
					}

					return *idx;
				}
			);

			assert(index);

			return Instruction {
				.index = *index
			};
		}
	};

}
