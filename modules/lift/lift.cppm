module;
#include <optional>

export module sba.lift;

import sba.arch;
import sba.ir;
import :fallback;
export import :decoder;
export import :cache;

namespace SBA::Lift {

	using namespace SBA::IR;
	using SBA::Arch::Target;

	template <Target T>
	std::optional<Instruction> lift_target(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst
	) noexcept;

}

export namespace SBA::Lift {

	template <SBA::Arch::Target T>
	inline Instruction lift(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst)
	{
		auto op = lift_target<T>(ctx, cache, inst);
		return op ? *op : lift_fallback<T>(ctx, cache, inst);
	}

}
