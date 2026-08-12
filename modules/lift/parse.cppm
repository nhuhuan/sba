module;
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCRegisterInfo.h>

export module sba.lift:parse;

import sba.binary.types;
import sba.lift.decoder;
import sba.lift.dedup;
import sba.ir.syntax;
import sba.ir.constant;
import sba.ir.stream;
import sba.ir.semantics;

namespace SBA::Lift {

	using namespace SBA::IR;

	struct StoreDesc {
		Operator op;
		Operand dst;
		std::span<const Operand> src;
	};

	template <SBA::Binary::Arch TargetArch>
	Operand parse_register(const std::string& name) noexcept;

	template <SBA::Binary::Arch TargetArch>
	inline Operand parse_register(
		uint32_t reg_id,
		const DecoderContext& dctx) noexcept
	{
		return (!reg_id)
			? NO_REGISTER
			: parse_register<TargetArch>(dctx.register_info->getName(reg_id));
	}

	inline Operand parse_immediate(
		const llvm::MCOperand& op,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx) noexcept
	{
		uint64_t imm = op.getImm();

		if (imm <= std::numeric_limits<uint32_t>::max())
			return Operand {
				.imm = {
					.type = (uint32_t)OperandType::IMMEDIATE,
					.wide = 0,
					.index = cache.imm32.get_or_insert(
						(uint32_t)imm,
						[&] {return stream.imm32.push_back((uint32_t)imm);}
					)
				}
			};
		else
			return Operand {
				.imm = {
					.type = (uint32_t)OperandType::IMMEDIATE,
					.wide = 1,
					.index = cache.imm64.get_or_insert(
						imm,
						[&] {return stream.imm64.push_back(imm);}
					)
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

		return Operand {
			.pcrel = {
				.type = (uint32_t)OperandType::PC_RELATIVE,
				.index = cache.pcrel.get_or_insert(
					imm,
					[&] {return stream.pcrel.push_back(imm);}
				)
			}
		};
	}

	template <SBA::Binary::Arch TargetArch>
	inline std::optional<Operand> parse_memory(
		std::span<const llvm::MCOperand> ops,
		uint8_t llength,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx) noexcept
	{
		auto base = parse_register<TargetArch>(ops[0].getReg(), dctx);
		auto index = parse_register<TargetArch>(ops[2].getReg(), dctx);

		if (!ops[2].getReg() && !ops[4].getReg()) {
			Memory mem {
				.displacement = ops[3].getImm(),
				.base = base.reg.id,
				.llength = llength,
				.llength_addr = base.reg.llength
			};
			return Operand {
				.mem = {
					.type = (uint32_t)OperandType::MEMORY,
					.ext = 0,
					.index = cache.mem.get_or_insert(
						mem,
						[&] {return stream.mem.push_back(std::move(mem));}
					)
				}
			};
		}
		else {
			MemoryExt mem {
				.displacement = ops[3].getImm(),
				.base = base.reg.id,
				.index = index.reg.id,
				.segment = ops[4].getReg(),
				.scale = ops[1].getImm(),
				.llength = llength,
				.llength_addr = std::max(base.reg.llength, index.reg.llength)
			};
			return Operand {
				.mem = {
					.type = (uint32_t)OperandType::MEMORY,
					.ext = 1,
					.index = cache.memext.get_or_insert(
						mem,
						[&] {return stream.memext.push_back(std::move(mem));}
					)
				}
			};
		}
	}

	inline uint32_t serialize_stores(
		IRStream& stream,
		std::span<const StoreDesc> descs) noexcept
	{
		size_t total_size = 0;
		for (const auto& desc : descs)
			total_size += sizeof(Operator)
						+ sizeof(Operand) * (1 + desc.src.size());

		uint32_t index = stream.raw.reserve(total_size);
		uint32_t offset = index;

		for (const auto& desc : descs) {
			stream.raw[offset] = (uint8_t)desc.op;
			offset += sizeof(Operator);

			std::memcpy(&stream.raw[offset], &desc.dst,
			            sizeof(Operand));
			offset += sizeof(Operand);

			for (const auto& src : desc.src) {
				std::memcpy(&stream.raw[offset], &src,
				            sizeof(Operand));
				offset += sizeof(Operand);
			}
		}

		return index;
	}

}
