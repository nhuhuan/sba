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
		const MCInst& inst,
		Stream& stream,
		Cache& cache
	) noexcept;

}

export namespace SBA::Lift {

	template <SBA::Arch::Target T>
	inline Instruction lift(
		const MCInst& inst,
		Stream& stream,
		Cache& cache)
	{
		auto op = lift_target<T>(inst, stream, cache);
		return op ? *op : lift_fallback<T>(inst, stream, cache);
	}

}
