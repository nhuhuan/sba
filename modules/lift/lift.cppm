module;
#include <cassert>
#include <cstdint>
#include <span>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCInstrDesc.h>

export module sba.lift;

import sba.binary;
import sba.ir;
import :encoder;
export import :decoder;
export import :cache;

namespace SBA::Lift {

	using namespace SBA::IR;
	inline constexpr size_t MAX_OPS_PER_INST = 5;

	template <SBA::Binary::Arch T>
	std::optional<Instruction> lift_arch(
		const DecoderInstruction& inst,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx
	) noexcept;

	template <SBA::Binary::Arch T>
	inline Instruction lift_default(
		const DecoderInstruction& inst,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx)
	{
		const auto& desc = dctx.instruction_info->get(inst.inst.getOpcode());
		std::array<Operator, MAX_OPS_PER_INST> opcodes;
		std::array<Operand, MAX_OPS_PER_INST> operands;
		size_t count = 0;

		auto add_clobber = [&](Operand dst) {
			assert(count < opcodes.size());
			opcodes[count] = Operator::CLOBBERED;
			operands[count] = dst;
			count++;
		};

		for (int i = 0; i < desc.getNumDefs(); ++i) {
			auto dst = parse_register<T>(
				inst.inst.getOperand(i).getReg(),
				dctx
			);
			if (dst != NO_REGISTER)
				add_clobber(dst);
		}

		for (auto reg : desc.implicit_defs()) {
			auto dst = parse_register<T>(reg, dctx);
			if (dst != NO_REGISTER)
				add_clobber(dst);
		}

		if (desc.mayStore())
			add_clobber(ANY_MEMORY);

		return serialize_inst(
			InstructionType::STORE,
			inst.size,
			{opcodes.data(), count},
			{operands.data(), count},
			stream,
			cache
		);
	}

}

export namespace SBA::Lift {

	template <SBA::Binary::Arch T>
	inline Instruction lift(
		const DecoderInstruction& inst,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx)
	{
		auto op = lift_arch<T>(inst, stream, cache, dctx);
		return op ? *op : lift_default<T>(inst, stream, cache, dctx);
	}

}
