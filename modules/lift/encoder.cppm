module;
#include <cassert>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <bit>

export module sba.lift:encoder;

import sba.ir;
import sba.util;
import :cache;

namespace SBA::Lift {

	inline constexpr uint8_t header(
		SBA::IR::Instruction::Type type,
		uint8_t count,
		uint8_t length) noexcept
	{
		uint8_t tag = (type != SBA::IR::Instruction::Type::STORE) ?
					  ((uint8_t)type | 0x8) : (count & 0x7);
		return (tag << 4) | (length & 0xf);
	}

	inline uint64_t hash(
		uint8_t header,
		std::span<const SBA::IR::Operator> opcodes,
		std::span<const SBA::IR::Operand> operands) noexcept
	{
		uint64_t s = SBA::Util::wyhash(&header, sizeof(header), 0);
		if (!opcodes.empty())
			s = SBA::Util::wyhash(opcodes.data(), opcodes.size_bytes(), s);
		if (!operands.empty())
			s = SBA::Util::wyhash(operands.data(), operands.size_bytes(), s);
		return s;
	}

}

namespace SBA::Lift {

	inline SBA::IR::Operand encode_register(SBA::IR::Register r) noexcept {
		return SBA::IR::Operand {.r = r};
	}

	inline SBA::IR::Operand encode_immediate(
		uint64_t val,
		SBA::IR::Stream& stream,
		Cache& cache) noexcept
	{
		if (val <= std::numeric_limits<uint32_t>::max()) {
			auto index = cache.i32.get_or_insert(
				(uint32_t)val,
				[&] { return stream.i32.push_back((uint32_t)val); }
			);

			if (index)
				return SBA::IR::Operand {
					.i = {
						.type  = (uint32_t)SBA::IR::Operand::Type::IMMEDIATE,
						.wide  = 0,
						.index = (uint32_t)*index
					}
				};
		}

		auto index = cache.i64.get_or_insert(
			val,
			[&] { return stream.i64.push_back(val); }
		);

		assert(index);

		return SBA::IR::Operand {
			.i = {
				.type  = (uint32_t)SBA::IR::Operand::Type::IMMEDIATE,
				.wide  = 1,
				.index = (uint32_t)*index
			}
		};
	}

	inline SBA::IR::Operand encode_affine(
		SBA::IR::Affine aff,
		SBA::IR::Stream& stream,
		Cache& cache) noexcept
	{
		auto index = cache.a.get_or_insert(
			std::bit_cast<uint64_t>(aff),
			[&] { return stream.a.push_back(aff); }
		);

		assert(index);

		return SBA::IR::Operand {
			.a = {
				.type  = (uint32_t)SBA::IR::Operand::Type::AFFINE,
				.index = (uint32_t)*index
			}
		};
	}

	inline SBA::IR::Operand encode_memory(
		SBA::IR::Affine aff,
		SBA::IR::Stream& stream,
		Cache& cache) noexcept
	{
		auto index = cache.a.get_or_insert(
			std::bit_cast<uint64_t>(aff),
			[&] { return stream.a.push_back(aff); }
		);

		assert(index);

		return SBA::IR::Operand {
			.m = {
				.type  = (uint32_t)SBA::IR::Operand::Type::MEMORY,
				.index = (uint32_t)*index
			}
		};
	}

	inline SBA::IR::Instruction encode_instruction(
		SBA::IR::Instruction::Type type,
		uint8_t length,
		std::span<const SBA::IR::Operator> opcodes,
		std::span<const SBA::IR::Operand> operands,
		SBA::IR::Stream& stream,
		Cache& cache) noexcept
	{
		uint8_t hdr = header(type, (uint8_t)opcodes.size(), length);

		auto index = cache.inst.get_or_insert(
			hash(hdr, opcodes, operands),
			[&]() -> std::optional<uint32_t> {
				size_t size = 1 + opcodes.size_bytes() + operands.size_bytes();

				auto index = stream.inst.reserve(size);
				if (!index)
					return std::nullopt;

				uint32_t offset = *index;
				stream.inst[offset++] = hdr;

				if (!opcodes.empty()) {
					size_t bytes = opcodes.size_bytes();
					std::memcpy(&stream.inst[offset], opcodes.data(), bytes);
					offset += bytes;
				}

				if (!operands.empty()) {
					size_t bytes = operands.size_bytes();
					std::memcpy(&stream.inst[offset], operands.data(), bytes);
					offset += bytes;
				}

				return *index;
			}
		);

		assert(index);

		return SBA::IR::Instruction {
			.index = *index
		};
	}

}
