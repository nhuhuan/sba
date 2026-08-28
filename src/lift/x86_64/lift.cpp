module;
#include <optional>

module sba.lift;

import sba.arch;
import sba.ir;
import :decoder;
import :cache;

namespace SBA::Lift {

	using namespace SBA::IR;
	using SBA::Arch::Target;

	template <>
	std::optional<Instruction> lift_target<Target::X86_64>(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst) noexcept
	{
		return std::nullopt;
	}

}
