module;
#include <cassert>
#include <cstdint>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCInstrDesc.h>

export module sba.lift;

import sba.binary.types;
import sba.lift.decoder;
import sba.lift.dedup;
import sba.ir.syntax;
import sba.ir.constant;
import sba.ir.stream;
import sba.ir.semantics;

import :parse;

namespace SBA::Lift {

	using namespace SBA::IR;
	inline constexpr size_t MAX_STORES_PER_INST = 5;

	template <SBA::Binary::Arch Target>
	std::optional<Operation> lift_arch(
		const DecoderInstruction& inst,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx
	) noexcept;

	template <SBA::Binary::Arch Target>
	inline Operation lift_default(
		const DecoderInstruction& inst,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx)
	{
		const auto& desc = dctx.instruction_info->get(inst.inst.getOpcode());
		std::array<StoreOp, MAX_STORES_PER_INST> stores;
		size_t count = 0;

		auto add_clobber = [&](Operand dst) {
			assert(count < stores.size());
			stores[count++] = {Operator::CLOBBERED, dst, {}};
		};

		for (int i = 0; i < desc.getNumDefs(); ++i) {
			auto dest = parse_register<Target>(
				inst.inst.getOperand(i).getReg(),
				dctx
			);
			if (dest != NO_REGISTER)
				add_clobber(dest);
		}

		for (auto reg : desc.implicit_defs()) {
			auto dest = parse_register<Target>(reg, dctx);
			if (dest != NO_REGISTER)
				add_clobber(dest);
		}

		if (desc.mayStore())
			add_clobber(ANY_MEMORY);

		return Operation {
			.type = (uint64_t)OperationType::STORE,
			.length = inst.size,
			.count = count,
			.index = serialize_stores(stream, {stores.data(), count})
		};
	}

}

export namespace SBA::Lift {

	template <SBA::Binary::Arch Target>
	inline Operation lift(
		const DecoderInstruction& inst,
		IRStream& stream,
		IRCache& cache,
		const DecoderContext& dctx)
	{
		auto op = lift_arch<Target>(inst, stream, cache, dctx);
		return op ? *op : lift_default<Target>(inst, stream, cache, dctx);
	}

}
