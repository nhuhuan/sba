module;
#include <bit>
#include <cstdint>
#include <string_view>
#include <algorithm>
#include <cctype>
#include <llvm/MC/MCInst.h>

module sba.lift;

import sba.arch;
import sba.ir;
import :parser;

namespace SBA::Lift {

	using namespace SBA::IR;
	using namespace SBA::Arch::X86_64;
	using SBA::Arch::Target;

	template <>
	Register extract_r<Target::X86_64>(
		std::string_view name) noexcept
	{
		auto it = std::find_if(
			registers.begin(),
			registers.end(),
			[&](const RegEntry& e) {
				return std::equal(
					e.name.begin(), e.name.end(),
					name.begin(), name.end(),
					[](char a, char b) {
						return std::toupper((unsigned char)a)
							== std::toupper((unsigned char)b);
					}
				);
			}
		);

		if (it != registers.end())
			return Register {
				.type    = (uint32_t)Operand::Type::REGISTER,
				.index   = (uint32_t)it->base,
				.offset  = it->offset,
				.llength = it->llength,
				.negated = 0
			};

		return NO_REG.r;
	}

	template <>
	Affine extract_a<Target::X86_64>(
		const llvm::MCOperand& op) noexcept
	{
		const auto* ops = &op;
		auto b = parse_r<Target::X86_64>(ops[0]).r;
		auto i = parse_r<Target::X86_64>(ops[2]).r;
		auto s = parse_r<Target::X86_64>(ops[4]).r;

		return Affine {
			.displacement = (int32_t)ops[3].getImm(),
			.base         = (uint8_t)b.index,
			.index        = (uint8_t)i.index,
			.shift        = (uint8_t)std::countr_zero((unsigned)ops[1].getImm()),
			.extra        = (uint8_t)s.index,
			.llength      = 0,
			.llength_addr = (uint8_t)std::max(b.llength, i.llength),
			.dereferenced = 0,
			.negated      = 0
		};
	}

}
