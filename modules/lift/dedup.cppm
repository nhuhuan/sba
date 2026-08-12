module;
#include <cstdint>
#include <vector>
#include <unordered_map>

export module sba.lift.dedup;

import sba.ir.syntax;
import sba.ir.stream;
import sba.ir.semantics;
import sba.util.container;

export namespace SBA::Lift {

	struct Hasher;
	struct IRCache;

}

namespace SBA::Lift {

	using namespace SBA::IR;

	struct Hasher {
		const SBA::Util::PVector<uint8_t>* raw = nullptr;

		std::size_t operator()(const Memory& m) const noexcept;
		std::size_t operator()(const MemoryExt& m) const noexcept;

		std::size_t operator()(const Operation& op) const noexcept;
		bool operator()(const Operation& lhs,
						const Operation& rhs) const noexcept;
	};

	struct IRCache {
		SBA::Util::PMap<uint32_t, uint32_t> imm32;
		SBA::Util::PMap<uint64_t, uint32_t> imm64;
		SBA::Util::PMap<uint32_t, uint32_t> pcrel;
		SBA::Util::PMap<Memory, uint32_t, Hasher> mem;
		SBA::Util::PMap<MemoryExt, uint32_t, Hasher> memext;
		SBA::Util::PMap<Operation, uint32_t, Hasher, Hasher> op;

		IRCache(const IRStream& stream)
			: op(Hasher{&stream.raw},
				 Hasher{&stream.raw}) {}
	};

}
