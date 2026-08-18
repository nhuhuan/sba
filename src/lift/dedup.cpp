module;
#include <cstdint>
#include <vector>
#include <functional>

module sba.lift.dedup;

namespace SBA::Lift {

	using namespace SBA::IR;

	inline void hash_combine(std::size_t& seed, uint64_t val) noexcept
	{
		if constexpr(sizeof(std::size_t) == 8) {
			seed ^= std::hash<uint64_t>{}(val) + 0x9e3779b97f4a7c15ULL +
					(seed << 6) + (seed >> 2);
		} else {
			seed ^= std::hash<uint64_t>{}(val) + 0x9e3779b9U +
					(seed << 6) + (seed >> 2);
		}
	}

	std::size_t Hasher::operator()(const Memory& m) const noexcept
	{
		std::size_t seed = 0;
		hash_combine(seed, (uint64_t)(uint32_t)m.displacement);
		hash_combine(seed, ((uint64_t)m.base << 24)        |
						   ((uint64_t)m.index << 16)       |
						   ((uint64_t)m.extra << 12)       |
						   ((uint64_t)m.shift << 8)        |
						   ((uint64_t)m.llength_addr << 4) |
						   ((uint64_t)m.llength));
		return seed;
	}

	std::size_t Hasher::operator()(const Operation& op) const noexcept
	{
		std::size_t seed = 0;
		hash_combine(seed, op.type);
		hash_combine(seed, op.length);

		auto index = op.index;
		for (uint32_t i = 0; i < op.count; ++i) {
			auto opcode = (Operator)(*raw)[index];
			auto count = sizeof(Operand) * (1 + arity(opcode))
					   + sizeof(Operator);

			for (uint32_t j = 0; j < count; ++j)
				hash_combine(seed, (*raw)[index + j]);

			index += count;
		}
		return seed;
	}

	bool Equal::operator()(
		const Operation& lhs,
		const Operation& rhs) const noexcept
	{
		if (lhs.type != rhs.type || lhs.length != rhs.length ||
			lhs.count != rhs.count)
				return false;

		auto l_index = lhs.index;
		auto r_index = rhs.index;

		for (uint32_t i = 0; i < lhs.count; ++i) {
			auto l_opcode = (Operator)(*raw)[l_index];
			auto r_opcode = (Operator)(*raw)[r_index];
			auto count = sizeof(Operand) * (1 + arity(l_opcode))
					   + sizeof(Operator);

			if (l_opcode != r_opcode)
				return false;

			for (uint32_t j = 0; j < count; ++j)
				if ((*raw)[l_index + j] != (*raw)[r_index + j])
					return false;

			l_index += count;
			r_index += count;
		}
		return true;
	}

}
