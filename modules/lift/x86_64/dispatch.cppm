module;
#include <cassert>
#include <cctype>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <llvm/MC/MCInstrInfo.h>

export module sba.lift:dispatch_x86_64;

import sba.arch;
import sba.ir;
export import sba.util;
import :target;
import :decode;
import :cache;
import :emit;

namespace SBA::Lift::X86_64 {

	struct Suffix {
		enum class Schema : uint8_t {
			rr,
			rm,
			mr,
			ri,
			mi,
			r,
			m,
			rmb,
			mb,
			mbi,
			rmbi,
			i,
			ar,
			ao,
			oa,
			r1,
			m1,
			rCL,
			mCL,
			_
		} schema;

		enum class Modifier : uint8_t {
			ND,
			NF,
			NF_ND,
			EVEX,
			_
		} modifier;

		enum class Mask : uint8_t {
			Merge,
			Zero,
			_
		} mask;

		struct {
			std::optional<uint8_t> d;
			std::optional<uint8_t> m;
			std::optional<uint8_t> o;
			std::optional<uint8_t> v;
		} llength;
	};

	inline constexpr bool match_prefix(
		std::string_view& s,
		std::string_view prefix) noexcept
	{
		if (s.starts_with(prefix)) {
			s.remove_prefix(prefix.size());
			return true;
		}
		return false;
	}

	inline constexpr bool match_suffix(
		std::string_view& s,
		std::string_view suffix) noexcept
	{
		if (s.ends_with(suffix)) {
			s.remove_suffix(suffix.size());
			return true;
		}
		return false;
	}

	inline constexpr std::optional<uint8_t> match_llength(
		std::string_view& s) noexcept
	{
		match_prefix(s, "o");

		if (match_prefix(s, "Z")) {
			if (match_prefix(s, "512")) return 6;
			if (match_prefix(s, "256")) return 5;
			if (match_prefix(s, "128")) return 4;
			return 6;
		}

		if (match_prefix(s, "512")) return 6;
		if (match_prefix(s, "256")) return 5;
		if (match_prefix(s, "128")) return 4;
		if (match_prefix(s, "64"))  return 3;
		if (match_prefix(s, "32"))  return 2;
		if (match_prefix(s, "16"))  return 1;
		if (match_prefix(s, "8"))   return 0;

		return std::nullopt;
	}

	inline constexpr Suffix::Modifier match_modifier(
		std::string_view& s) noexcept
	{
		match_suffix(s, "_REV");

		if (match_suffix(s, "_NF_ND")) return Suffix::Modifier::NF_ND;
		if (match_suffix(s, "_ND"))    return Suffix::Modifier::ND;
		if (match_suffix(s, "_NF"))    return Suffix::Modifier::NF;
		if (match_suffix(s, "_EVEX"))  return Suffix::Modifier::EVEX;

		return Suffix::Modifier::_;
	}

	inline constexpr Suffix::Mask match_mask(
		std::string_view& s) noexcept
	{
		if (match_suffix(s, "kz")) return Suffix::Mask::Zero;
		if (match_suffix(s, "k"))  return Suffix::Mask::Merge;

		return Suffix::Mask::_;
	}

	inline constexpr Suffix::Schema match_schema(
		std::string_view& s) noexcept
	{
		if (match_prefix(s, "rmbi")) return Suffix::Schema::rmbi;
		if (match_prefix(s, "mbi"))  return Suffix::Schema::mbi;
		if (match_prefix(s, "rmb"))  return Suffix::Schema::rmb;
		if (match_prefix(s, "mb"))   return Suffix::Schema::mb;
		if (match_prefix(s, "b"))    return Suffix::Schema::mb;
		if (match_prefix(s, "rm"))   return Suffix::Schema::rm;
		if (match_prefix(s, "mr"))   return Suffix::Schema::mr;
		if (match_prefix(s, "mi"))   return Suffix::Schema::mi;
		if (match_prefix(s, "rr"))   return Suffix::Schema::rr;
		if (match_prefix(s, "ri"))   return Suffix::Schema::ri;
		if (match_prefix(s, "ar"))   return Suffix::Schema::ar;
		if (match_prefix(s, "i"))    return Suffix::Schema::i;
		if (match_prefix(s, "ao"))   return Suffix::Schema::ao;
		if (match_prefix(s, "oa"))   return Suffix::Schema::oa;
		if (match_prefix(s, "a"))    return Suffix::Schema::oa;
		if (match_prefix(s, "rCL"))  return Suffix::Schema::rCL;
		if (match_prefix(s, "mCL"))  return Suffix::Schema::mCL;
		if (match_prefix(s, "r1"))   return Suffix::Schema::r1;
		if (match_prefix(s, "m1"))   return Suffix::Schema::m1;
		if (match_prefix(s, "r"))    return Suffix::Schema::r;
		if (match_prefix(s, "m"))    return Suffix::Schema::m;

		return Suffix::Schema::_;
	}

	inline constexpr Suffix match_suffix(std::string_view s) noexcept {
		auto modifier = match_modifier(s);
		auto mask = match_mask(s);

		auto lv = s.starts_with('Z') ? match_llength(s) : std::nullopt;
		auto ld = match_llength(s);
		auto lo = s.starts_with('o') ? match_llength(s) : std::nullopt;
		auto schema = match_schema(s);
		lo = (schema == Suffix::Schema::ao) ? match_llength(s) : lo;

		auto lm = (schema == Suffix::Schema::rm) ?
			match_llength(s) : std::nullopt;

		return Suffix {
			.schema = schema,
			.modifier = modifier,
			.mask = mask,
			.llength = { .d = ld, .m = lm, .o = lo, .v = lv }
		};
	}

}

namespace SBA::Lift::X86_64 {

	struct Pattern {
		std::initializer_list<MCOperation> logic;
		std::initializer_list<MCOperation> flags = {};
	};

	using Rule = Instruction(*)(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst
	);

	template <const auto& Pattern, bool NoFlags = false>
	inline Instruction emit(
		Context& ctx,
		Cache& cache,
		const MCInstruction& inst)
	{
		if constexpr (NoFlags) {
			return emit<SBA::Arch::Target::X86_64>(
				ctx, cache, inst,
				std::span<const MCOperation>(Pattern.logic)
			);
		}
		else {
			return emit<SBA::Arch::Target::X86_64>(
				ctx, cache, inst,
				std::span<const MCOperation>(Pattern.logic),
				std::span<const MCOperation>(Pattern.flags)
			);
		}
	}

	#define DISPATCH(Mnemonic, Suffix, LengthD, NoFlags)                  \
		if constexpr (requires { Mnemonic::template Suffix<0>; }) {       \
			if constexpr (std::convertible_to<                            \
				decltype(Mnemonic::template Suffix<0>), Rule>)            \
			{                                                             \
				static constexpr Rule rules[] = {                         \
					Mnemonic::template Suffix<0>,                         \
					Mnemonic::template Suffix<1>,                         \
					Mnemonic::template Suffix<2>,                         \
					Mnemonic::template Suffix<3>                          \
				};                                                        \
				rule = rules[LengthD];                                    \
			}                                                             \
			else {                                                        \
				static constexpr Rule rules[2][4] = {                     \
					{ emit<Mnemonic::template Suffix<0>, false>,          \
					  emit<Mnemonic::template Suffix<1>, false>,          \
					  emit<Mnemonic::template Suffix<2>, false>,          \
					  emit<Mnemonic::template Suffix<3>, false> },        \
					{ emit<Mnemonic::template Suffix<0>, true>,           \
					  emit<Mnemonic::template Suffix<1>, true>,           \
					  emit<Mnemonic::template Suffix<2>, true>,           \
					  emit<Mnemonic::template Suffix<3>, true> }          \
				};                                                        \
				rule = rules[NoFlags][LengthD];                           \
			}                                                             \
			return true;                                                  \
		}                                                                 \
		break;

	#define DISPATCH_M(Mnemonic, Suffix, LengthD, LengthM, NoFlags)       \
		if constexpr (requires { Mnemonic::template Suffix<0, 0>; }) {    \
			if constexpr (std::convertible_to<                            \
				decltype(Mnemonic::template Suffix<0, 0>), Rule>)         \
			{                                                             \
				static constexpr Rule rules[4][4] = {                     \
					{ Mnemonic::template Suffix<0, 0>,                    \
					  Mnemonic::template Suffix<0, 1>,                    \
					  Mnemonic::template Suffix<0, 2>,                    \
					  Mnemonic::template Suffix<0, 3> },                  \
					{ Mnemonic::template Suffix<1, 0>,                    \
					  Mnemonic::template Suffix<1, 1>,                    \
					  Mnemonic::template Suffix<1, 2>,                    \
					  Mnemonic::template Suffix<1, 3> },                  \
					{ Mnemonic::template Suffix<2, 0>,                    \
					  Mnemonic::template Suffix<2, 1>,                    \
					  Mnemonic::template Suffix<2, 2>,                    \
					  Mnemonic::template Suffix<2, 3> },                  \
					{ Mnemonic::template Suffix<3, 0>,                    \
					  Mnemonic::template Suffix<3, 1>,                    \
					  Mnemonic::template Suffix<3, 2>,                    \
					  Mnemonic::template Suffix<3, 3> }                   \
				};                                                        \
				rule = rules[LengthD][LengthM];                           \
			}                                                             \
			else {                                                        \
				static constexpr Rule rules[2][4][4] = {                  \
					{ { emit<Mnemonic::template Suffix<0, 0>, false>,     \
						emit<Mnemonic::template Suffix<0, 1>, false>,     \
						emit<Mnemonic::template Suffix<0, 2>, false>,     \
						emit<Mnemonic::template Suffix<0, 3>, false> },   \
					  { emit<Mnemonic::template Suffix<1, 0>, false>,     \
						emit<Mnemonic::template Suffix<1, 1>, false>,     \
						emit<Mnemonic::template Suffix<1, 2>, false>,     \
						emit<Mnemonic::template Suffix<1, 3>, false> },   \
					  { emit<Mnemonic::template Suffix<2, 0>, false>,     \
						emit<Mnemonic::template Suffix<2, 1>, false>,     \
						emit<Mnemonic::template Suffix<2, 2>, false>,     \
						emit<Mnemonic::template Suffix<2, 3>, false> },   \
					  { emit<Mnemonic::template Suffix<3, 0>, false>,     \
						emit<Mnemonic::template Suffix<3, 1>, false>,     \
						emit<Mnemonic::template Suffix<3, 2>, false>,     \
						emit<Mnemonic::template Suffix<3, 3>, false> } }, \
					{ { emit<Mnemonic::template Suffix<0, 0>, true>,      \
						emit<Mnemonic::template Suffix<0, 1>, true>,      \
						emit<Mnemonic::template Suffix<0, 2>, true>,      \
						emit<Mnemonic::template Suffix<0, 3>, true> },    \
					  { emit<Mnemonic::template Suffix<1, 0>, true>,      \
						emit<Mnemonic::template Suffix<1, 1>, true>,      \
						emit<Mnemonic::template Suffix<1, 2>, true>,      \
						emit<Mnemonic::template Suffix<1, 3>, true> },    \
					  { emit<Mnemonic::template Suffix<2, 0>, true>,      \
						emit<Mnemonic::template Suffix<2, 1>, true>,      \
						emit<Mnemonic::template Suffix<2, 2>, true>,      \
						emit<Mnemonic::template Suffix<2, 3>, true> },    \
					  { emit<Mnemonic::template Suffix<3, 0>, true>,      \
						emit<Mnemonic::template Suffix<3, 1>, true>,      \
						emit<Mnemonic::template Suffix<3, 2>, true>,      \
						emit<Mnemonic::template Suffix<3, 3>, true> } }   \
				};                                                        \
				rule = rules[NoFlags][LengthD][LengthM];                  \
			}                                                             \
			return true;                                                  \
		}                                                                 \
		break;

	template <typename Mnemonic>
	inline bool dispatch(
		std::string_view name,
		std::string_view opcode,
		Rule& rule)
	{
		if (!name.starts_with(opcode))
			return false;

		std::string_view suffix = name.substr(opcode.size());
		auto s = match_suffix(suffix);

		uint8_t ld = s.llength.d.value_or(0);
		uint8_t lm = s.llength.m.value_or(ld);
		bool no_flags = (s.modifier == Suffix::Modifier::NF ||
						 s.modifier == Suffix::Modifier::NF_ND);

		switch (s.schema) {
			case Suffix::Schema::_:    DISPATCH(Mnemonic,   _,    ld,     no_flags);
			case Suffix::Schema::rr:   DISPATCH(Mnemonic,   rr,   ld,     no_flags);
			case Suffix::Schema::ri:   DISPATCH(Mnemonic,   ri,   ld,     no_flags);
			case Suffix::Schema::r:    DISPATCH(Mnemonic,   r,    ld,     no_flags);
			case Suffix::Schema::i:    DISPATCH(Mnemonic,   i,    ld,     no_flags);
			case Suffix::Schema::ar:   DISPATCH(Mnemonic,   ar,   ld,     no_flags);
			case Suffix::Schema::ao:   DISPATCH(Mnemonic,   ao,   ld,     no_flags);
			case Suffix::Schema::oa:   DISPATCH(Mnemonic,   oa,   ld,     no_flags);
			case Suffix::Schema::r1:   DISPATCH(Mnemonic,   r1,   ld,     no_flags);
			case Suffix::Schema::rCL:  DISPATCH(Mnemonic,   rCL,  ld,     no_flags);
			case Suffix::Schema::rm:   DISPATCH_M(Mnemonic, rm,   ld, lm, no_flags);
			case Suffix::Schema::mr:   DISPATCH_M(Mnemonic, mr,   ld, lm, no_flags);
			case Suffix::Schema::mi:   DISPATCH_M(Mnemonic, mi,   ld, lm, no_flags);
			case Suffix::Schema::m:    DISPATCH_M(Mnemonic, m,    ld, lm, no_flags);
			case Suffix::Schema::m1:   DISPATCH_M(Mnemonic, m1,   ld, lm, no_flags);
			case Suffix::Schema::mCL:  DISPATCH_M(Mnemonic, mCL,  ld, lm, no_flags);
			case Suffix::Schema::rmb:  DISPATCH_M(Mnemonic, rmb,  ld, lm, no_flags);
			case Suffix::Schema::mb:   DISPATCH_M(Mnemonic, mb,   ld, lm, no_flags);
			case Suffix::Schema::mbi:  DISPATCH_M(Mnemonic, mbi,  ld, lm, no_flags);
			case Suffix::Schema::rmbi: DISPATCH_M(Mnemonic, rmbi, ld, lm, no_flags);
			default: break;
		}

		return false;
	}

	#undef DISPATCH
	#undef DISPATCH_M

	template <typename... Mnemonics>
	inline void dispatch_sorted(
		std::span<Rule> rules,
		SBA::Util::TypeList<Mnemonics...>)
	{
		const auto& info = *info_inst<SBA::Arch::Target::X86_64>;

		for (unsigned i = 0; i < info.getNumOpcodes(); ++i) {
			std::string_view name = info.getName(i);
			(dispatch<Mnemonics>(
				name, SBA::Util::type_name<Mnemonics>(), rules[i]
			) || ...);
		}
	}

	template <typename... Lists>
	inline void dispatch(std::span<Rule> rules, Lists...) {
		using All = typename SBA::Util::Concat<Lists...>::type;
		using Sorted = typename SBA::Util::Sort<All>::type;
		dispatch_sorted(rules, Sorted{});
	}

}
