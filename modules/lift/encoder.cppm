module;
#include <cassert>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <vector>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCRegisterInfo.h>

export module sba.lift:encoder;

import sba.binary;
import sba.ir;
import sba.util;
import :decoder;
import :cache;

namespace SBA::Lift {

	using namespace SBA::IR;

	template <SBA::Binary::Arch T>
	Operand extract_register(const std::string& name) noexcept;

	template <SBA::Binary::Arch T>
	uint32_t extract_affine(
		std::span<const llvm::MCOperand> ops,
		uint8_t llength,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx) noexcept;

}

namespace SBA::Lift {

	template <SBA::Binary::Arch T>
	inline Operand parse_affine(
		std::span<const llvm::MCOperand> ops,
		uint8_t llength,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx) noexcept
	{
		return Operand {
			.aff = {
				.type = (uint32_t)OperandType::AFFINE,
				.index = extract_affine<T>(ops, llength, stream, cache, dctx)
			}
		};
	}

	template <SBA::Binary::Arch T>
	inline Operand parse_memory(
		std::span<const llvm::MCOperand> ops,
		uint8_t llength,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx) noexcept
	{
		return Operand {
			.mem = {
				.type = (uint32_t)OperandType::MEMORY,
				.index = extract_affine<T>(ops, llength, stream, cache, dctx)
			}
		};
	}

	template <SBA::Binary::Arch T>
	inline Operand parse_register(
		uint32_t reg_id,
		const DecoderContext& dctx) noexcept
	{
		static const std::vector<Operand> reg_map = [&]() {
			auto num_regs = dctx.register_info->getNumRegs();
			std::vector<Operand> res(num_regs, NO_REGISTER);
			for (int i = 1; i < num_regs; ++i)
				res[i] = extract_register<T>(dctx.register_info->getName(i));
			return res;
		}();

		return reg_id ? reg_map[reg_id] : NO_REGISTER;
	}

	template <SBA::Binary::Arch T>
	inline Operand parse_register(
		const llvm::MCOperand& op,
		const DecoderContext& dctx) noexcept
	{
		return parse_register<T>(op.getReg(), dctx);
	}

	inline Operand parse_immediate(
		const llvm::MCOperand& op,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx) noexcept
	{
		uint64_t imm = op.getImm();

		if (imm <= std::numeric_limits<uint32_t>::max()) {
			auto index = cache.imm32.get_or_insert(
				imm,
				[&] {return stream.imm32.push_back(imm);}
			);
			if (index)
				return Operand {
					.imm = {
						.type = (uint32_t)OperandType::IMMEDIATE,
						.wide = 0,
						.index = (uint32_t)*index
					}
				};
		}

		auto index = cache.imm64.get_or_insert(
			imm,
			[&] {return stream.imm64.push_back(imm);}
		);
		assert(index);

		return Operand {
			.imm = {
				.type = (uint32_t)OperandType::IMMEDIATE,
				.wide = 1,
				.index = (uint32_t)*index
			}
		};
	}

	static inline constexpr uint8_t header(
		InstructionType type,
		uint8_t count,
		uint8_t length) noexcept
	{
		uint8_t tag = (type != InstructionType::STORE) ?
					  ((uint8_t)type | 0x8) : (count & 0x7);
		return (tag << 4) | (length & 0xf);
	}

	static inline uint64_t hash(
		uint8_t header,
		std::span<const Operator> opcodes,
		std::span<const Operand> operands) noexcept
	{
		uint64_t s = SBA::Util::wyhash(&header, sizeof(header), 0);
		if (!opcodes.empty())
			s = SBA::Util::wyhash(opcodes.data(), opcodes.size_bytes(), s);
		if (!operands.empty())
			s = SBA::Util::wyhash(operands.data(), operands.size_bytes(), s);
		return s;
	}

	inline Instruction serialize_inst(
		InstructionType type,
		uint8_t length,
		std::span<const Operator> opcodes,
		std::span<const Operand> operands,
		IRStream& stream,
		IRCache& cache) noexcept
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

		return Instruction {
			.index = *index
		};
	}

}
