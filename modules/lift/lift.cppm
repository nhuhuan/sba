module;
#include <optional>

export module sba.lift;

import sba.arch;
import sba.ir;
import :fallback;
export import :decode;
export import :cache;

namespace SBA::Lift {

	using namespace SBA::IR;

	template <SBA::Arch::Target T, SBA::Arch::Mode M>
	std::optional<Instruction> lift_target(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst
	) noexcept;

}

export namespace SBA::Lift {

	template <SBA::Arch::Target T, SBA::Arch::Mode M = SBA::Arch::Mode::USER>
	inline Instruction lift(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst)
	{
		if (!inst.valid())
			return lift_invalid(ctx, cache);

		auto op = lift_target<T, M>(ctx, cache, inst);
		return op ? *op : lift_fallback<T>(ctx, cache, inst);
	}

}
