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
import :encoder;
import :target;
import :parser;

namespace SBA::Lift {

	using namespace SBA::IR;
	using SBA::Arch::Target;

	inline constexpr size_t MAX_OPS_PER_INST = 5;

	template <Target T>
	inline Instruction lift_fallback(
		const MCInst& inst,
		Stream& stream,
		Cache& cache)
	{
		const auto& desc = info_inst<T>->get(inst.getOpcode());
		std::array<Operator, MAX_OPS_PER_INST> opcodes;
		std::array<SBA::IR::Operand, MAX_OPS_PER_INST> operands;
		size_t count = 0;

		auto add_clobber = [&](SBA::IR::Operand dst) {
			assert(count < opcodes.size());
			opcodes[count] = Operator::CLOBBERED;
			operands[count] = dst;
			count++;
		};

		for (int i = 0; i < desc.getNumDefs(); ++i) {
			auto dst = parse_register<T>(
				inst.getOperand(i).getReg()
			);
			if (dst != NO_REGISTER)
				add_clobber(dst);
		}

		for (auto reg : desc.implicit_defs()) {
			auto dst = parse_register<T>(reg);
			if (dst != NO_REGISTER)
				add_clobber(dst);
		}

		if (desc.mayStore())
			add_clobber(ANY_MEMORY);

		return encode_instruction(
			Instruction::Type::STORE,
			inst.length(),
			{opcodes.data(), count},
			{operands.data(), count},
			stream,
			cache
		);
	}

}
