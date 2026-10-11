module;
#include <cstdint>
#include <span>

export module sba.lift:x86_64_system;

import sba.arch;
import sba.ir;
import :emit;
import :x86_64_pattern;
import :x86_64_dispatch;

namespace SBA::Lift::X86_64 {

	#define P(Suffix, ...) \
		template <uint8_t l> \
		static constexpr Pattern Suffix = { __VA_ARGS__ }

	#define PM(Suffix, ...) \
		template <uint8_t l, uint8_t lm = l> \
		static constexpr Pattern Suffix = { __VA_ARGS__ }


	struct P_NOOP {
		P(_,  {});
		P(r,  {});
		P(rr, {});
	};

	struct P_ABORT {
		P(_,  { mco<O::ABORT>() });
		P(r,  { mco<O::ABORT>() });
		P(rr, { mco<O::ABORT>() });
	};

	struct P_DRAIN {
		P(_, { mco<O::DRAIN>() });
	};

	struct P_WAIT_E {
		P(_,  { mco<O::WAIT_E>() });
		P(rr, { mco<O::WAIT_E>() });
	};

	struct P_UD1 {
		P(r,  { rr_12<O::VAL>(),
		        mco<O::ABORT>() });
		PM(m, { rm_12<O::VAL,lm>(),
		        mco<O::ABORT>() });
	};

	struct P_HYPERCALL {
		P(_, { mco<O::HYPERCALL>() });
	};

	/* -----------------------------------------------------------------------*/

	struct VMCALL  : P_HYPERCALL {};
	struct VMMCALL : P_HYPERCALL {};
	struct SYSCALL {
		P(_, { mco<O::VAL>(R(RCX),R(RIP)),
		       mco<O::VAL>(R(R11),R(FLAGS)),
		       mco<O::SYSCALL>() });
	};
	struct SYSRET {
		P(_, { mco<O::VAL>(R(RIP),R(RCX)),
		       mco<O::VAL>(R(FLAGS,l),R(R11,l)),
		       mco<O::SYSRET>() });
	};
	struct SYSENTER {
		P(_, { mco<O::VAL>(R(RCX,2),R(RSP,2)),
		       mco<O::VAL>(R(RDX,2),R(RIP,2)),
		       mco<O::SYSCALL>() });
	};
	struct SYSEXIT {
		P(_, { mco<O::VAL>(R(RIP,l),R(RDX,l)),
		       mco<O::VAL>(R(RSP,l),R(RCX,l)),
		       mco<O::SYSRET>() });
	};
	struct IRET {
		template <uint8_t l>
		static constexpr Pattern _ = { {
			mco<O::VAL>(R(RIP,l),M(RSP,l)),
			mco<O::VAL>(R(CS,1),M(RSP,bytes<int64_t>(l),1)),
			mco<O::VAL>(R(FLAGS,l),M(RSP,bytes<int64_t>(l)*2,l)),
			mco<O::VAL>(R(RSP),A(RSP,bytes<int64_t>(l)*3)),
			mco<O::SYSRET>()
		} };
		template <>
		constexpr Pattern _<3> = { {
			mco<O::VAL>(R(RIP),M(RSP,3)),
			mco<O::VAL>(R(CS,1),M(RSP,8,1)),
			mco<O::VAL>(R(FLAGS),M(RSP,16,3)),
			mco<O::VAL>(R(SS,1),M(RSP,32,1)),
			mco<O::VAL>(R(RSP),M(RSP,24,3)),
			mco<O::SYSRET>()
		} };
	};
	struct UIRET {
		template <uint8_t l>
		static constexpr Pattern _ = { {
			mco<O::VAL>(R(RIP),M(RSP,3)),
			mco<O::VAL>(R(FLAGS),M(RSP,8,3)),
			mco<O::VAL>(R(RSP),M(RSP,16,3))
		} };
	};
	struct INT {
		P(i, { mco<O::VAL>(R(RSP),A(RSP,-40)),
		       mco<O::VAL>(M(RSP,0,3),R(RIP)),
		       mco<O::VAL>(M(RSP,8,1),R(CS,1)),
		       mco<O::VAL>(M(RSP,16,3),R(FLAGS)),
		       mco<O::VAL>(M(RSP,24,3),A(RSP,40)),
		       mco<O::VAL>(M(RSP,32,1),R(SS,1)),
		       i_x1<O::VAL>(R(TMP1)),
		       mco<O::VAL>(R(RIP),M(IDTR,TMP1,4,0,3)) });
	};
	struct INT3 {
		P(_, { mco<O::VAL>(R(RSP),A(RSP,-40)),
		       mco<O::VAL>(M(RSP,0,3),R(RIP)),
		       mco<O::VAL>(M(RSP,8,1),R(CS,1)),
		       mco<O::VAL>(M(RSP,16,3),R(FLAGS)),
		       mco<O::VAL>(M(RSP,24,3),A(RSP,40)),
		       mco<O::VAL>(M(RSP,32,1),R(SS,1)),
		       mco<O::TRAP>() });
	};
	struct INT1  : INT3 {};
	struct ICEBP : INT3 {};
	template <SBA::Arch::Mode M>
	struct HLT;
		template <> struct HLT<SBA::Arch::Mode::USER>   : P_ABORT {};
		template <> struct HLT<SBA::Arch::Mode::KERNEL> {
			P(_, { mco<O::WAIT_I>() });
		};
	template <SBA::Arch::Mode M>
	struct MWAIT;
		template <> struct MWAIT<SBA::Arch::Mode::USER>   : P_ABORT {};
		template <> struct MWAIT<SBA::Arch::Mode::KERNEL> : P_WAIT_E {};
	template <SBA::Arch::Mode M>
	struct MWAITX;
		template <> struct MWAITX<SBA::Arch::Mode::USER>   : P_ABORT {};
		template <> struct MWAITX<SBA::Arch::Mode::KERNEL> : P_WAIT_E {};
	template <SBA::Arch::Mode M>
	struct MONITOR;
		template <> struct MONITOR<SBA::Arch::Mode::USER>   : P_ABORT {};
		template <> struct MONITOR<SBA::Arch::Mode::KERNEL> : P_NOOP {};
	template <SBA::Arch::Mode M>
	struct MONITORX;
		template <> struct MONITORX<SBA::Arch::Mode::USER>   : P_ABORT {};
		template <> struct MONITORX<SBA::Arch::Mode::KERNEL> : P_NOOP {};

	struct UMWAIT   : P_WAIT_E {};
	struct TPAUSE   : P_WAIT_E {};
	struct UMONITOR : P_NOOP {};

	struct CLFLUSHOPT : P_DRAIN {};
	struct CLWB       : P_DRAIN {};
	struct INVD       : P_DRAIN {};
	struct WBINVD     : P_DRAIN {};
	struct WBNOINVD   : P_DRAIN {};

	struct PAUSE {
		P(_, { mco<O::YIELD>() });
	};
	struct TRAP : P_ABORT {};
	struct LFENCE {
		P(_, { mco<O::FENCE_R>() });
	};
	struct SFENCE {
		P(_, { mco<O::FENCE_W>() });
	};
	struct MFENCE {
		P(_, { mco<O::FENCE_RW>() });
	};
	struct SERIALIZE {
		P(_, { mco<O::FENCE_I>() });
	};
	struct CPUID {
		P(_, { mco<O::FENCE_I>() });
	};
	struct CLFLUSH {
		P(_, { mco<O::FENCE_I>() });
	};
	struct UD1W  : P_UD1 {};
	struct UD1L  : P_UD1 {};
	struct UD1Q  : P_UD1 {};
	struct NOOP  : P_NOOP {};
	struct NOOPW : P_NOOP {};
	struct NOOPL : P_NOOP {};
	struct NOOPQ : P_NOOP {};
	struct FNOP  : P_NOOP {};

	template <SBA::Arch::Mode M = SBA::Arch::Mode::USER>
	using Mnemonics_SYS = SBA::Util::TypeList<
		SYSCALL, SYSENTER, VMCALL, VMMCALL,
		SYSRET, SYSEXIT, IRET, UIRET,
		INT, INT1, INT3, ICEBP,
		UD1W, UD1L, UD1Q,
		NOOP, NOOPW, NOOPL, NOOPQ, FNOP,
		LFENCE, SFENCE, MFENCE,
		SERIALIZE, CPUID, CLFLUSH,
		CLFLUSHOPT, CLWB,
		INVD, WBINVD, WBNOINVD,
		UMWAIT, TPAUSE, UMONITOR,
		MWAIT<M>, MWAITX<M>, MONITOR<M>, MONITORX<M>,
		TRAP,
		HLT<M>,
		PAUSE
	>;

	#undef PM
	#undef P

}
