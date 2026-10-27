module;
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <bit>
#include <type_traits>

export module sba.ir:context;

import sba.util;
import :syntax;
import :semantics;

export namespace SBA::IR {

	class View;

	/* ------------------------------ Context ------------------------------- */

	class Context {
	public:
		Context() {
			ins.reserve(1);
			ins[0] = Instruction::Tag(0);
			aff.push_back(Affine(0, ANY_REG.index));
			aff.push_back(Affine(1, ANY_REG.index));
		}

		View operator[](Instruction i) const noexcept;

		template <typename T>
		T decode(Operand op) const noexcept {
			if constexpr (std::is_same_v<T, Register>)
				return op.r;
			else if constexpr (std::is_same_v<T, Affine>)
				return aff[op.a.index];
			else if constexpr (std::is_same_v<T, uint64_t>)
				return op.i.wide ? i64[op.i.index] : i32[op.i.index];
			else
				static_assert(false);
		}

		Operand encode(Register val) noexcept { return val; }

		template <typename C>
		Operand encode(C& cache, uint64_t val) noexcept {
			if (val <= std::numeric_limits<uint32_t>::max()) {
				auto index = cache.i32.get_or_insert(
					(uint32_t)val,
					[&] { return i32.push_back((uint32_t)val); }
				);

				if (index)
					return Operand(Operand::Type::IMMEDIATE, (uint32_t)*index, false);
			}

			auto index = cache.i64.get_or_insert(
				val,
				[&] { return i64.push_back(val); }
			);

			if (index)
				return Operand(Operand::Type::IMMEDIATE, (uint32_t)*index, true);

			std::abort();
		}

		template <typename C>
		Operand encode(C& cache, Affine val) noexcept {
			auto index = cache.a.get_or_insert(
				std::bit_cast<uint64_t>(val),
				[&] { return aff.push_back(val); }
			);

			if (index)
				return Operand(Operand::Type::AFFINE, (uint32_t)*index);

			std::abort();
		}

		template <typename C>
		Instruction encode(
			C& cache,
			uint8_t length,
			std::span<const Operator> opcodes,
			std::span<const Operand> operands) noexcept
		{
			Instruction::Tag t((uint8_t)opcodes.size(), length);

			uint64_t h = SBA::Util::wyhash(&t.tag, sizeof(t.tag), 0);
			if (!opcodes.empty())
				h = SBA::Util::wyhash(opcodes.data(), opcodes.size_bytes(), h);
			if (!operands.empty())
				h = SBA::Util::wyhash(operands.data(), operands.size_bytes(), h);

			auto index = cache.ins.get_or_insert(
				h,
				[&]() -> std::optional<uint32_t> {
					auto opcode_size = opcodes.size_bytes();
					auto operand_size = operands.size_bytes();
					auto size = opcode_size + operand_size + 1;

					auto idx = ins.reserve(size);
					if (!idx)
						return std::nullopt;

					uint32_t offset = *idx;
					ins[offset++] = t.tag;

					if (!opcodes.empty()) {
						std::memcpy(&ins[offset], opcodes.data(), opcode_size);
						offset += opcode_size;
					}

					if (!operands.empty()) {
						std::memcpy(&ins[offset], operands.data(), operand_size);
						offset += operand_size;
					}

					return *idx;
				}
			);

			if (index)
				return Instruction(*index);

			std::abort();
		}

	private:
		SBA::Util::PVector<uint8_t,  (1ULL << INDEX_INS)> ins;
		SBA::Util::PVector<uint32_t, (1ULL << INDEX_IMM)> i32;
		SBA::Util::PVector<uint64_t, (1ULL << INDEX_IMM)> i64;
		SBA::Util::PVector<Affine,   (1ULL << INDEX_AFF)> aff;
	};

}
