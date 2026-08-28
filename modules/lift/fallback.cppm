module;
#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCInstrDesc.h>

export module sba.lift:fallback;

import sba.arch;
import sba.ir;
import :decoder;
import :cache;
import :target;
import :parser;
import :emit;

namespace SBA::Lift {

	using namespace SBA::IR;
	using SBA::Arch::Target;

	template <Target T>
	inline Instruction lift_fallback(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst)
	{
		const auto& desc = info_inst<T>->get(inst.getOpcode());
		std::array<MCOperation, MAX_OPERATIONS> ops;
		size_t count = 0;

		for (int i = 0; i < desc.getNumDefs(); ++i) {
			assert(count < ops.size());
			ops[count++] = { Operator::CLOBBERED, MCOperand::mc_r((uint8_t)i) };
		}

		for (auto reg : desc.implicit_defs()) {
			auto dst = parse_r<T>(reg);
			if (dst != NO_REGISTER) {
				assert(count < ops.size());
				ops[count++] = { Operator::CLOBBERED, MCOperand::r(dst.r) };
			}
		}

		if (desc.mayStore()) {
			assert(count < ops.size());
			ops[count++] = { Operator::CLOBBERED, MCOperand::o(ANY_MEMORY) };
		}

		return emit<T>(ctx, cache, inst, { ops.data(), count });
	}

}
