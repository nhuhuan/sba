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

import sba.arch;
import sba.ir;
import :decoder;
import :cache;
import :target;
import :parser;

namespace SBA::Lift {

	using namespace SBA::IR;
	using namespace SBA::Arch::X86_64;

	template <>
	Register extract_register<SBA::Arch::Target::X86_64>(
		const std::string& name) noexcept
	{
		auto reg_name = name;
		std::transform(
			reg_name.begin(),
			reg_name.end(),
			reg_name.begin(),
			[](unsigned char c) { return (char)std::toupper(c); }
		);

		auto it = std::find_if(
			registers.begin(),
			registers.end(),
			[&](const RegEntry& e) { return e.name == reg_name; }
		);

		if (it != registers.end())
			return Register {
				.type    = (uint32_t)Operand::Type::REGISTER,
				.index   = (uint32_t)it->base,
				.offset  = it->offset,
				.llength = it->llength
			};

		return NO_REGISTER.r;
	}

	template <>
	Affine extract_affine<SBA::Arch::Target::X86_64>(
		const llvm::MCOperand& op,
		uint8_t llength) noexcept
	{
		const auto* ops = &op;
		auto b = parse_register<SBA::Arch::Target::X86_64>(ops[0]).r;
		auto i = parse_register<SBA::Arch::Target::X86_64>(ops[2]).r;
		auto s = parse_register<SBA::Arch::Target::X86_64>(ops[4]).r;

		return Affine {
			.displacement = (int32_t)ops[3].getImm(),
			.base         = (uint8_t)b.index,
			.index        = (uint8_t)i.index,
			.shift        = (uint8_t)std::countr_zero((unsigned)ops[1].getImm()),
			.extra        = (uint8_t)s.index,
			.llength      = llength,
			.llength_addr = (uint8_t)std::max(b.llength, i.llength)
		};
	}

	template <>
	std::optional<Instruction> lift_target<SBA::Arch::Target::X86_64>(
		const MCInst& inst,
		Stream& stream,
		Cache& cache) noexcept
	{
		return std::nullopt;
	}

}
