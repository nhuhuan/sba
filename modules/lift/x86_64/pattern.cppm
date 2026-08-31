module;
#include <cctype>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

export module sba.lift:pattern_x86_64;

import sba.arch;
import sba.ir;
import :decoder;
import :cache;
import :emit;

namespace SBA::Lift::X86_64 {

	using O = SBA::IR::Operator;
	using MCO = SBA::Lift::MCOperation;

	using r = DynamicRegister;
	using i = DynamicImmediate;
	using a = DynamicAffine;
	using m = DynamicMemory;

	using LiftFn = Instruction(*)(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst
	);

	template <const auto& Rule>
	inline Instruction lifter(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst)
	{
		return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, Rule);
	}

	struct Suffix {
		enum class Type : uint8_t {
			RR,
			RM,
			MR,
			RI,
			MI,
			RA
		} type;
		uint8_t l;
	};

	inline constexpr uint8_t parse_l(std::string_view s) noexcept {
		if (s.starts_with("64")) return 3;
		if (s.starts_with("32")) return 2;
		if (s.starts_with("16")) return 1;
		return 0;
	}

	inline constexpr std::optional<Suffix> parse_suffix(
		std::string_view s) noexcept
	{
		if (auto pos = s.find("rm"); pos != std::string_view::npos) {
			std::string_view t = s.substr(pos + 2);
			std::string_view l =
				(!t.empty() && std::isdigit(t[0])) ? t : s.substr(0, pos);
			return Suffix{ Suffix::Type::RM, parse_l(l) };
		}

		if (auto pos = s.find("mr"); pos != std::string_view::npos)
			return Suffix{ Suffix::Type::MR, parse_l(s.substr(0, pos)) };

		if (auto pos = s.find("mi"); pos != std::string_view::npos)
			return Suffix{ Suffix::Type::MI, parse_l(s.substr(0, pos)) };

		if (s.contains("rr"))
			return Suffix{ Suffix::Type::RR, 0 };

		if (s.contains("ri") ||
			s == "64i32"     || s == "32i32"   || s == "16i16"   || s == "8i8")
			return Suffix{ Suffix::Type::RI, 0 };

		if (s.ends_with('r'))
			return Suffix{ Suffix::Type::RA, 0 };

		return std::nullopt;
	}

	#define DISPATCH(RULE)                                            \
		if constexpr (requires { lifter<Rule::RULE>; }) {             \
			out = lifter<Rule::RULE>;                                 \
			return true;                                              \
		}                                                             \
		break;

	#define DISPATCH_LENGTH(RULE)                                     \
		if constexpr (requires { lifter<Rule::template RULE<0>>; }) { \
			static constexpr LiftFn table[] = {                       \
				lifter<Rule::template RULE<0>>,                       \
				lifter<Rule::template RULE<1>>,                       \
				lifter<Rule::template RULE<2>>,                       \
				lifter<Rule::template RULE<3>>                        \
			};                                                        \
			out = table[suffix->l];                                   \
			return true;                                              \
		}                                                             \
		break;

	template <typename Rule>
	inline bool match(std::string_view name, std::string_view op, LiftFn& out) {
		if (!name.starts_with(op))
			return false;

		auto suffix = parse_suffix(name.substr(op.size()));
		if (!suffix)
			return false;

		switch (suffix->type) {
			case Suffix::Type::RR: DISPATCH(RR);
			case Suffix::Type::RI: DISPATCH(RI);
			case Suffix::Type::RA: DISPATCH(RA);
			case Suffix::Type::RM: DISPATCH_LENGTH(RM);
			case Suffix::Type::MR: DISPATCH_LENGTH(MR);
			case Suffix::Type::MI: DISPATCH_LENGTH(MI);
		}

		return false;
	}

	#undef DISPATCH
	#undef DISPATCH_LENGTH

}
