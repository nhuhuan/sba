module;
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <vector>
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

	struct StoreOp {
		Operator op;
		Operand dst;
		std::span<const Operand> src;
	};

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

	inline uint32_t serialize_stores(
		IRStream& stream,
		std::span<const StoreOp> stores) noexcept
	{
		size_t total_size = 0;
		for (const auto& store : stores)
			total_size += sizeof(Operator)
						+ sizeof(Operand) * (1 + store.src.size());

		uint32_t index = stream.raw.reserve(total_size);
		uint32_t offset = index;

		for (const auto& store : stores) {
			stream.raw[offset] = (uint8_t)store.op;
			offset += sizeof(Operator);

			std::memcpy(&stream.raw[offset], &store.dst,
			            sizeof(Operand));
			offset += sizeof(Operand);

			for (const auto& src : store.src) {
				std::memcpy(&stream.raw[offset], &src,
				            sizeof(Operand));
				offset += sizeof(Operand);
			}
		}

		return index;
	}

}
