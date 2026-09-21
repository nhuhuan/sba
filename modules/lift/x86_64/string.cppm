module;
#include <cstdint>
#include <span>

export module sba.lift:x86_64_string;

import sba.arch;
import sba.ir;
import :emit;
import :x86_64_pattern;
import :x86_64_dispatch;

namespace SBA::Lift::X86_64 {

	template <uint8_t l, uint8_t lm = l>
	struct P_MOVS {
		template <uint8_t>
		static Instruction _(Context& ctx, Cache& cache, const MCInstruction& inst)
		{
			if (HAS_REP(inst)) {
				static constexpr MCO ops[] = {
					mco<O::S_VAL>(M(RDI,lm),M(RSI,lm),R(RCX,3)),
					mco<O::VAL>(R(RDI,3),A(RDI,RCX,lm)),
					mco<O::VAL>(R(RSI,3),A(RSI,RCX,lm)),
					mco<O::VAL>(R(RCX,3),0ULL)
				};
				return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
			}
			static constexpr MCO ops[] = {
				mco<O::VAL>(M(RDI,lm),M(RSI,lm)),
				mco<O::VAL>(R(RDI,3),A(RDI,bytes<int64_t>(lm))),
				mco<O::VAL>(R(RSI,3),A(RSI,bytes<int64_t>(lm)))
			};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}
	};

	template <uint8_t l, uint8_t lm = l>
	struct P_CMPS {
		template <O s_op>
		static Instruction rep(Context& ctx, Cache& cache, const MCInstruction& inst)
		{
			static constexpr MCO ops[] = {
				mco<s_op>(R(TMP1,3),M(RSI,lm),M(RDI,lm),R(RCX,3)),
				mco<O::VAL>(R(RSI,3),A(RSI,TMP1,lm)),
				mco<O::VAL>(R(RDI,3),A(RDI,TMP1,lm)),
				mco<O::SUB>(R(RCX,3),R(RCX,3),R(TMP1,3)),
				mco<O::CMP>(R(FLAGS,lm),M(RSI,-bytes<int64_t>(lm),lm),
				                        M(RDI,-bytes<int64_t>(lm),lm))
			};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}

		template <uint8_t>
		static Instruction _(Context& ctx, Cache& cache, const MCInstruction& inst)
		{
			if (HAS_REPNE(inst)) return rep<O::S_NE>(ctx, cache, inst);
			if (HAS_REPE(inst))  return rep<O::S_EQ>(ctx, cache, inst);
			static constexpr MCO ops[] = {
				mco<O::VAL>(R(RSI,3),A(RSI,bytes<int64_t>(lm))),
				mco<O::VAL>(R(RDI,3),A(RDI,bytes<int64_t>(lm))),
				mco<O::CMP>(R(FLAGS,lm),M(RSI,-bytes<int64_t>(lm),lm),
				                        M(RDI,-bytes<int64_t>(lm),lm))
			};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}
	};

	template <uint8_t l, uint8_t lm = l>
	struct P_STOS {
		template <uint8_t>
		static Instruction _(Context& ctx, Cache& cache, const MCInstruction& inst)
		{
			if (HAS_REP(inst)) {
				static constexpr MCO ops[] = {
					mco<O::S_VAL>(M(RDI,lm),R(RAX,lm),R(RCX,3)),
					mco<O::VAL>(R(RDI,3),A(RDI,RCX,lm)),
					mco<O::VAL>(R(RCX,3),0ULL)
				};
				return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
			}
			static constexpr MCO ops[] = {
				mco<O::VAL>(M(RDI,lm),R(RAX,lm)),
				mco<O::VAL>(R(RDI,3),A(RDI,bytes<int64_t>(lm)))
			};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}
	};

	template <uint8_t l, uint8_t lm = l>
	struct P_LODS {
		template <uint8_t>
		static Instruction _(Context& ctx, Cache& cache, const MCInstruction& inst)
		{
			if (HAS_REP(inst)) {
				static constexpr MCO ops[] = {
					mco<O::VAL>(R(RAX,lm),M(RSI,RCX,lm,-bytes<int64_t>(lm),lm)),
					mco<O::VAL>(R(RSI,3),A(RSI,RCX,lm)),
					mco<O::VAL>(R(RCX,3),0ULL)
				};
				return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
			}
			static constexpr MCO ops[] = {
				mco<O::VAL>(R(RAX,lm),M(RSI,lm)),
				mco<O::VAL>(R(RSI,3),A(RSI,bytes<int64_t>(lm)))
			};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}
	};

	template <uint8_t l, uint8_t lm = l>
	struct P_SCAS {
		template <O s_op>
		static Instruction rep(Context& ctx, Cache& cache, const MCInstruction& inst)
		{
			static constexpr MCO ops[] = {
				mco<s_op>(R(TMP1,3),R(RAX,lm),M(RDI,lm),R(RCX,3)),
				mco<O::VAL>(R(RDI,3),A(RDI,TMP1,lm)),
				mco<O::SUB>(R(RCX,3),R(RCX,3),R(TMP1,3)),
				mco<O::CMP>(R(FLAGS,lm),R(RAX,lm),
				                        M(RDI,-bytes<int64_t>(lm),lm))
			};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}

		template <uint8_t>
		static Instruction _(Context& ctx, Cache& cache, const MCInstruction& inst)
		{
			if (HAS_REPNE(inst)) return rep<O::S_NE>(ctx, cache, inst);
			if (HAS_REPE(inst))  return rep<O::S_EQ>(ctx, cache, inst);
			static constexpr MCO ops[] = {
				mco<O::VAL>(R(RDI,3),A(RDI,bytes<int64_t>(lm))),
				mco<O::CMP>(R(FLAGS,lm),R(RAX,lm),M(RDI,-bytes<int64_t>(lm),lm))
			};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}
	};

	/* -----------------------------------------------------------------------*/

	struct MOVSB : P_MOVS<0> {};
	struct MOVSW : P_MOVS<1> {};
	struct MOVSL : P_MOVS<2> {};
	struct MOVSQ : P_MOVS<3> {};
	struct CMPSB : P_CMPS<0> {};
	struct CMPSW : P_CMPS<1> {};
	struct CMPSL : P_CMPS<2> {};
	struct CMPSQ : P_CMPS<3> {};
	struct STOSB : P_STOS<0> {};
	struct STOSW : P_STOS<1> {};
	struct STOSL : P_STOS<2> {};
	struct STOSQ : P_STOS<3> {};
	struct LODSB : P_LODS<0> {};
	struct LODSW : P_LODS<1> {};
	struct LODSL : P_LODS<2> {};
	struct LODSQ : P_LODS<3> {};
	struct SCASB : P_SCAS<0> {};
	struct SCASW : P_SCAS<1> {};
	struct SCASL : P_SCAS<2> {};
	struct SCASQ : P_SCAS<3> {};

	using Mnemonics_STR = SBA::Util::TypeList<
		MOVSB, MOVSW, MOVSL, MOVSQ,
		CMPSB, CMPSW, CMPSL, CMPSQ,
		STOSB, STOSW, STOSL, STOSQ,
		LODSB, LODSW, LODSL, LODSQ,
		SCASB, SCASW, SCASL, SCASQ
	>;

}
