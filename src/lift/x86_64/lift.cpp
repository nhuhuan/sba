module;
#include <cassert>
#include <optional>
#include <vector>
#include <llvm/MC/MCInstrInfo.h>

module sba.lift;

import sba.arch;
import sba.ir;
import :decoder;
import :cache;
import :target;
import :pattern_x86_64;

namespace SBA::Lift {

	using namespace SBA::IR;
	using namespace SBA::Lift::X86_64;
	using SBA::Arch::Target;

	template <>
	std::optional<Instruction> lift_target<Target::X86_64>(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst) noexcept
	{
		static const std::vector<LiftFn> dispatch_table = [&]() {
			assert(info_inst<Target::X86_64>);
			auto num_opcodes = info_inst<Target::X86_64>->getNumOpcodes();
			std::vector<LiftFn> table(num_opcodes, nullptr);
			return table;
		}();

		unsigned opcode = inst.getOpcode();
		if (opcode < dispatch_table.size() && dispatch_table[opcode])
			return dispatch_table[opcode](ctx, cache, inst);

		return std::nullopt;
	}

}
