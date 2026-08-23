module;
#include <bit>
#include <cstdint>
#include <string>
#include <optional>
#include <algorithm>
#include <cctype>
#include <span>
#include <cassert>
#include <llvm/MC/MCInst.h>

module sba.lift;

import sba.arch.x86_64;
import sba.ir;
import :decoder;
import :cache;
import :encoder;

namespace SBA::Lift {

	using namespace SBA::IR;
	using namespace SBA::Arch::X86_64;

	template <>
	Operand extract_register<SBA::Binary::Arch::X86_64>(
		const std::string& name) noexcept
	{
		auto reg_name = name;
		std::transform(
			reg_name.begin(),
			reg_name.end(),
			reg_name.begin(),
			[](unsigned char c) {return (char)std::toupper(c);}
		);

		auto it = std::find_if(
			register_map.begin(),
			register_map.end(),
			[&](const RegMap& e) {return e.name == reg_name;}
		);

		if (it != register_map.end())
			return Operand {
				.reg = {
					.type = (uint32_t)OperandType::REGISTER,
					.index = (uint32_t)it->base,
					.offset = it->offset,
					.llength = it->llength
				}
			};

		return NO_REGISTER;
	}

	template <>
	uint32_t extract_affine<SBA::Binary::Arch::X86_64>(
		std::span<const llvm::MCOperand> ops,
		uint8_t llength,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx) noexcept
	{
		auto b = stream.reg(
			parse_register<SBA::Binary::Arch::X86_64>(ops[0], dctx)
		);
		auto i = stream.reg(
			parse_register<SBA::Binary::Arch::X86_64>(ops[2], dctx)
		);
		auto s = stream.reg(
			parse_register<SBA::Binary::Arch::X86_64>(ops[4], dctx)
		);

		Affine aff {
			.displacement = (int32_t)ops[3].getImm(),
			.base = (uint8_t)b.index,
			.index = (uint8_t)i.index,
			.shift = (uint8_t)std::countr_zero((unsigned)ops[1].getImm()),
			.extra = (uint8_t)s.index,
			.llength = llength,
			.llength_addr = (uint8_t)std::max(b.llength, i.llength)
		};

		auto index = cache.aff.get_or_insert(
			std::bit_cast<uint64_t>(aff),
			[&] {return stream.aff.push_back(aff);}
		);
		assert(index);

		return *index;
	}

	template <>
	std::optional<Instruction> lift_arch<SBA::Binary::Arch::X86_64>(
		const DecoderInstruction& inst,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx) noexcept
	{
		return std::nullopt;
	}

}
