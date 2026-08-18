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

export module sba.lift.encoder;

import sba.binary.types;
import sba.lift.decoder;
import sba.lift.cache;
import sba.ir.syntax;
import sba.ir.constant;
import sba.ir.stream;
import sba.ir.semantics;
import sba.util.wyhash;

export namespace SBA::Lift {

	using namespace SBA::IR;

	template <SBA::Binary::Arch Target>
	std::optional<Operand> parse_memory(
		std::span<const llvm::MCOperand> ops,
		uint8_t llength,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx) noexcept;

	template <SBA::Binary::Arch Target>
	Operand parse_register(const std::string& name) noexcept;

	template <SBA::Binary::Arch Target>
	inline Operand parse_register(
		uint32_t reg_id,
		const DecoderContext& dctx) noexcept
	{
		static const std::vector<Operand> reg_map = [&]() {
			auto num_regs = dctx.register_info->getNumRegs();
			std::vector<Operand> res(num_regs, NO_REGISTER);
			for (int i = 1; i < num_regs; ++i)
				res[i] = parse_register<Target>(dctx.register_info->getName(i));
			return res;
		}();

		return reg_id ? reg_map[reg_id] : NO_REGISTER;
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

	inline Operand parse_pcrel(
		const llvm::MCOperand& op,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx) noexcept
	{
		uint32_t imm = op.getImm();
		auto index = cache.pcrel.get_or_insert(
			imm,
			[&] {return stream.pcrel.push_back(imm);}
		);
		assert(index);

		return Operand {
			.pcrel = {
				.type = (uint32_t)OperandType::PC_RELATIVE,
				.index = (uint32_t)*index
			}
		};
	}

	inline constexpr uint8_t inst_header(
		InstructionType type,
		uint8_t count,
		uint8_t length) noexcept
	{
		uint8_t tag = (type == InstructionType::STORE)
					? (count & 0x7)
					: (((uint8_t)type & 0x7) | 0x8);
		return (tag << 4) | (length & 0xF);
	}

	inline uint64_t hash_inst(
		uint8_t header,
		std::span<const Operator> opcodes,
		std::span<const Operand> operands) noexcept
	{
		uint64_t seed = SBA::Util::wyhash(&header, sizeof(header), 0);
		if (!opcodes.empty())
			seed = SBA::Util::wyhash(
				opcodes.data(),
				opcodes.size_bytes(),
				seed
			);
		if (!operands.empty())
			seed = SBA::Util::wyhash(
				operands.data(),
				operands.size_bytes(),
				seed
			);
		return seed;
	}

	inline Instruction serialize_inst(
		InstructionType type,
		uint8_t length,
		std::span<const Operator> opcodes,
		std::span<const Operand> operands,
		IRStream& stream,
		IRCache& cache) noexcept
	{
		uint8_t header = inst_header(type, (uint8_t)opcodes.size(), length);

		auto index = cache.inst.get_or_insert(
			hash_inst(header, opcodes, operands),
			[&]() -> std::optional<uint32_t> {
				size_t size = 1 + opcodes.size_bytes() + operands.size_bytes();

				auto index = stream.inst.reserve(size);
				if (!index)
					return std::nullopt;

				uint32_t offset = *index;
				stream.inst[offset++] = header;

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
