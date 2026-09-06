module;
#include <cctype>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <llvm/MC/MCInstrInfo.h>

export module sba.lift:dispatch_x86_64;

import sba.arch;
import sba.ir;
import :target;
import :decode;
import :cache;
import :emit;

namespace SBA::Lift::X86_64 {

	struct Suffix {
		enum class Type : uint8_t {
			RR,
			RM,
			MR,
			RI,
			MI,
			RA,
			raxI,
			raxR
		} type;
		uint8_t llength_d;
		std::optional<uint8_t> llength_m;
	};

	inline constexpr uint8_t llength(std::string_view s) noexcept {
		if (s.starts_with("64")) return 3;
		if (s.starts_with("32")) return 2;
		if (s.starts_with("16")) return 1;
		return 0;
	}

	inline constexpr std::optional<Suffix> parse_suffix(
		std::string_view s) noexcept
	{
		uint8_t dst_len = llength(s);

		if (auto pos = s.find("rm"); pos != std::string_view::npos) {
			std::string_view t = s.substr(pos + 2);
			uint8_t mem_len =
				(!t.empty() && std::isdigit(t[0])) ? llength(t) : dst_len;
			return Suffix { Suffix::Type::RM, dst_len, mem_len };
		}

		if (auto pos = s.find("mr"); pos != std::string_view::npos)
			return Suffix { Suffix::Type::MR, dst_len, dst_len };

		if (auto pos = s.find("mi"); pos != std::string_view::npos)
			return Suffix { Suffix::Type::MI, dst_len, dst_len };

		if (s.contains("rr"))
			return Suffix { Suffix::Type::RR, dst_len, std::nullopt };

		if (s.contains("ri"))
			return Suffix { Suffix::Type::RI, dst_len, std::nullopt };

		if (s.contains("ar"))
			return Suffix { Suffix::Type::raxR, dst_len, std::nullopt };

		if (s == "64i32" || s == "32i32" || s == "16i16" || s == "8i8")
			return Suffix { Suffix::Type::raxI, dst_len, std::nullopt };

		if (s.ends_with('r'))
			return Suffix { Suffix::Type::RA, dst_len, std::nullopt };

		return std::nullopt;
	}

}

namespace SBA::Lift::X86_64 {

	using Rule = Instruction(*)(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst
	);

	template <const auto& Pattern>
	inline Instruction emit(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst)
	{
		return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, Pattern);
	}

	#define DISPATCH(Suffix, LengthD)                                     \
		if constexpr (requires { emit<Mnemonic::template Suffix<0>>; }) { \
			static constexpr Rule rules[] = {                             \
				emit<Mnemonic::template Suffix<0>>,                       \
				emit<Mnemonic::template Suffix<1>>,                       \
				emit<Mnemonic::template Suffix<2>>,                       \
				emit<Mnemonic::template Suffix<3>>                        \
			};                                                            \
			rule = rules[LengthD];                                        \
			return true;                                                  \
		}                                                                 \
		break;

	#define DISPATCH_M(Suffix, LengthD, LengthM)                             \
		if constexpr (requires { emit<Mnemonic::template Suffix<0, 0>>; }) { \
			static constexpr Rule rules[4][4] = {                            \
				{ emit<Mnemonic::template Suffix<0, 0>>,                     \
				  emit<Mnemonic::template Suffix<0, 1>>,                     \
				  emit<Mnemonic::template Suffix<0, 2>>,                     \
				  emit<Mnemonic::template Suffix<0, 3>> },                   \
				{ emit<Mnemonic::template Suffix<1, 0>>,                     \
				  emit<Mnemonic::template Suffix<1, 1>>,                     \
				  emit<Mnemonic::template Suffix<1, 2>>,                     \
				  emit<Mnemonic::template Suffix<1, 3>> },                   \
				{ emit<Mnemonic::template Suffix<2, 0>>,                     \
				  emit<Mnemonic::template Suffix<2, 1>>,                     \
				  emit<Mnemonic::template Suffix<2, 2>>,                     \
				  emit<Mnemonic::template Suffix<2, 3>> },                   \
				{ emit<Mnemonic::template Suffix<3, 0>>,                     \
				  emit<Mnemonic::template Suffix<3, 1>>,                     \
				  emit<Mnemonic::template Suffix<3, 2>>,                     \
				  emit<Mnemonic::template Suffix<3, 3>> }                    \
			};                                                               \
			rule = rules[LengthD][LengthM];                                  \
			return true;                                                     \
		}                                                                    \
		break;

	template <typename Mnemonic>
	inline bool dispatch(
		std::string_view name,
		std::string_view opcode,
		Rule& rule)
	{
		if (!name.starts_with(opcode))
			return false;

		auto s = parse_suffix(name.substr(opcode.size()));
		if (!s)
			return false;

		switch (s->type) {
			case Suffix::Type::RR:   DISPATCH(RR,   s->llength_d);
			case Suffix::Type::RI:   DISPATCH(RI,   s->llength_d);
			case Suffix::Type::raxI: DISPATCH(raxI, s->llength_d);
			case Suffix::Type::raxR: DISPATCH(raxR, s->llength_d);
			case Suffix::Type::RA:   DISPATCH(RA,   s->llength_d);
			case Suffix::Type::RM:   DISPATCH_M(RM, s->llength_d, *s->llength_m);
			case Suffix::Type::MR:   DISPATCH_M(MR, s->llength_d, *s->llength_m);
			case Suffix::Type::MI:   DISPATCH_M(MI, s->llength_d, *s->llength_m);
		}

		return false;
	}

	#undef DISPATCH
	#undef DISPATCH_M

	template <typename... Mnemonics>
	inline void dispatch(std::span<Rule> rules) {
		const auto& info = *info_inst<SBA::Arch::Target::X86_64>;

		for (unsigned i = 0; i < info.getNumOpcodes(); ++i) {
			std::string_view name = info.getName(i);
			Rule& rule = rules[i];
			(dispatch<Mnemonics>(name, Mnemonics::name, rule) || ...);
		}
	}

	template <typename Fn>
	inline void dispatch(std::span<Rule> rules, Fn&& dispatcher) {
		const auto& info = *info_inst<SBA::Arch::Target::X86_64>;

		for (unsigned i = 0; i < info.getNumOpcodes(); ++i) {
			std::string_view name = info.getName(i);
			Rule& rule = rules[i];
			dispatcher(name, rule);
		}
	}

}
