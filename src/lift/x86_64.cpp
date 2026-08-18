module;
#include <bit>
#include <cstdint>
#include <string>
#include <optional>
#include <algorithm>
#include <cctype>
#include <span>
#include <llvm/MC/MCInst.h>

module sba.lift;

import sba.arch.x86_64;
import sba.lift.decoder;
import sba.lift.dedup;
import sba.ir.syntax;
import sba.ir.stream;

import :parse;

namespace SBA::Lift {

	using namespace SBA::IR;
	using namespace SBA::Arch::X86_64;

	template <>
	Operand parse_register<SBA::Binary::Arch::X86_64>(
		const std::string& name) noexcept
	{
		auto reg_name = name;
		std::transform(reg_name.begin(), reg_name.end(), reg_name.begin(),
			[](unsigned char c) {
				return (char)std::toupper(c);
			}
		);

		auto it = std::find_if(
			register_map.begin(),
			register_map.end(),
			[&](const RegMap& e) {
				return e.name == reg_name;
			}
		);

		if (it != register_map.end())
			return Operand {
				.reg = {
					.type = (uint32_t)OperandType::REGISTER,
					.llength = it->llength,
					.id = (uint32_t)it->base,
					.offset = it->offset
				}
			};

		return NO_REGISTER;
	}

	template <>
	std::optional<Operand> parse_memory<SBA::Binary::Arch::X86_64>(
		std::span<const llvm::MCOperand> ops,
		uint8_t llength,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx) noexcept
	{
		auto base = parse_register<SBA::Binary::Arch::X86_64>(
			ops[0].getReg(),
			dctx
		);
		auto index = parse_register<SBA::Binary::Arch::X86_64>(
			ops[2].getReg(),
			dctx
		);
		auto segment = parse_register<SBA::Binary::Arch::X86_64>(
			ops[4].getReg(),
			dctx
		);

		Memory mem {
			.displacement = (int32_t)ops[3].getImm(),
			.base = (uint8_t)base.reg.id,
			.index = (uint8_t)index.reg.id,
			.shift = (uint8_t)std::countr_zero((unsigned)ops[1].getImm()),
			.extra = (uint8_t)segment.reg.id,
			.llength = llength,
			.llength_addr =
				(uint8_t)std::max(base.reg.llength, index.reg.llength)
		};

		return Operand {
			.mem = {
				.type = (uint32_t)OperandType::MEMORY,
				.index = (uint32_t)*cache.mem.get_or_insert(
					mem,
					[&] {return stream.mem.push_back(mem);}
				)
			}
		};
	}

	template <>
	std::optional<Operation> lift_arch<SBA::Binary::Arch::X86_64>(
		const DecoderInstruction& inst,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx) noexcept
	{
		return std::nullopt;
	}

}
