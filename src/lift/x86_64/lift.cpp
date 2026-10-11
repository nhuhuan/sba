module;
#include <cassert>
#include <optional>
#include <vector>
#include <llvm/MC/MCInstrInfo.h>

module sba.lift;

import sba.arch;
import sba.ir;
import :decode;
import :cache;
import :target;
import :x86_64_dispatch;
import :x86_64_data;
import :x86_64_alu;
import :x86_64_control;
import :x86_64_string;
import :x86_64_system;
import :x86_64_vector;
import :x86_64_hypervisor;
import :x86_64_legacy;

namespace SBA::Lift {

	using namespace SBA::IR;
	using namespace SBA::Lift::X86_64;
	using SBA::Arch::Target;
	using SBA::Arch::Mode;

	template <Mode M>
	inline std::optional<Instruction> lift_x86_64(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst) noexcept
	{
		static const std::vector<Rule> dispatch_rules = [&]() {
			assert(info_inst<Target::X86_64>);
			auto num_opcodes = info_inst<Target::X86_64>->getNumOpcodes();
			std::vector<Rule> rules(num_opcodes, nullptr);
			dispatch(rules, Mnemonics_DAT{},
							Mnemonics_ALU{},
							Mnemonics_STR{},
							Mnemonics_CTL{},
							Mnemonics_SYS<M>{},
							Mnemonics_VEC{},
							Mnemonics_HPV<M>{},
							Mnemonics_LGC{});
			return rules;
		}();

		unsigned opcode = inst.getOpcode();
		if (opcode < dispatch_rules.size() && dispatch_rules[opcode])
			return dispatch_rules[opcode](ctx, cache, inst);

		return std::nullopt;
	}

	template <>
	std::optional<Instruction> lift_target<Target::X86_64, Mode::USER>(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst) noexcept
	{
		return lift_x86_64<SBA::Arch::Mode::USER>(ctx, cache, inst);
	}

	template <>
	std::optional<Instruction> lift_target<Target::X86_64, Mode::KERNEL>(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst) noexcept
	{
		return lift_x86_64<SBA::Arch::Mode::KERNEL>(ctx, cache, inst);
	}

}
