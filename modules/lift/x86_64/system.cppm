module;
#include <cstdint>

export module sba.lift:x86_64_system;

import sba.arch;
import sba.ir;
import :emit;
import :x86_64_pattern;

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
		P(_,  { mcop<O::ABORT>() });
		P(r,  { mcop<O::ABORT>() });
		P(rr, { mcop<O::ABORT>() });
	};

	struct P_DRAIN {
		P(_, { mcop<O::DRAIN>() });
	};

	struct P_WAIT_E {
		P(_,  { mcop<O::WAIT_E>() });
		P(rr, { mcop<O::WAIT_E>() });
	};

	struct P_UD1 {
		P(r,  { rr_12<O::VAL>(),
				mcop<O::ABORT>() });
		PM(m, { rm_12<O::VAL,lm>(),
				mcop<O::ABORT>() });
	};

	struct P_HYPERCALL {
		P(_, { mcop<O::HYPERCALL>() });
	};

	struct P_SYSTEM_METRIC {
		P(_, { mcop<O::CLB>(R(RAX)[0,32]),
			   mcop<O::ZEXT>(R(RAX), R(RAX)[0,32]),
			   mcop<O::CLB>(R(RDX)[0,32]),
			   mcop<O::ZEXT>(R(RDX), R(RDX)[0,32]) });
	};

	struct P_RAND {
		P(r, { r_1<O::CLB>(),
			   zero_high32<l>(DR(0)) },
			 { mcop<O::CLB>(R(FLAGS)[0,l]) });
	};

	/* -----------------------------------------------------------------------*/

	struct VMCALL  : P_HYPERCALL {};
	struct VMMCALL : P_HYPERCALL {};
	struct SYSCALL {
		P(_, { mcop<O::VAL>(R(RCX), R(RIP)),
			   mcop<O::VAL>(R(R11), R(FLAGS)),
			   mcop<O::SYSCALL>() });
	};
	struct SYSRET {
		P(_, { mcop<O::VAL>(R(RIP), R(RCX)),
			   mcop<O::VAL>(R(FLAGS)[0,l], R(R11)[0,l]),
			   mcop<O::SYSRET>() });
	};
	struct SYSENTER {
		P(_, { mcop<O::VAL>(R(RCX)[0,32], R(RSP)[0,32]),
			   mcop<O::VAL>(R(RDX)[0,32], R(RIP)[0,32]),
			   mcop<O::SYSCALL>() });
	};
	struct SYSEXIT {
		P(_, { mcop<O::VAL>(R(RIP)[0,l], R(RDX)[0,l]),
			   mcop<O::VAL>(R(RSP)[0,l], R(RCX)[0,l]),
			   mcop<O::SYSRET>() });
	};
	struct IRET {
		template <uint8_t l>
		static constexpr Pattern _ = { {
			mcop<O::VAL>(R(RIP)[0,l], M(RSP)[l]),
			mcop<O::VAL>(R(CS)[0,16], M(RSP+bits_to_bytes(l))[16]),
			mcop<O::VAL>(R(FLAGS)[0,l], M(RSP+bits_to_bytes(l)*2)[l]),
			mcop<O::VAL>(R(RSP), A(RSP+bits_to_bytes(l)*3)),
			mcop<O::SYSRET>()
		} };
		template <>
		constexpr Pattern _<64> = { {
			mcop<O::VAL>(R(RIP), M(RSP)),
			mcop<O::VAL>(R(CS)[0,16], M(RSP+8)[16]),
			mcop<O::VAL>(R(FLAGS), M(RSP+16)),
			mcop<O::VAL>(R(SS)[0,16], M(RSP+32)[16]),
			mcop<O::VAL>(R(RSP), M(RSP+24)),
			mcop<O::SYSRET>()
		} };
	};
	struct UIRET {
		template <uint8_t l>
		static constexpr Pattern _ = { {
			mcop<O::VAL>(R(RIP), M(RSP)),
			mcop<O::VAL>(R(FLAGS), M(RSP+8)),
			mcop<O::VAL>(R(RSP), M(RSP+16))
		} };
	};
	struct INT {
		template <uint8_t l>
		static Instruction i(Context& ctx, Cache& cache, const MCInstruction& inst) {
			auto vec = inst.getOperand(0).getImm();
			const MCOP ops[] = {
				mcop<O::VAL>(R(RSP), A(RSP-40)),
				mcop<O::VAL>(M(RSP), R(RIP)),
				mcop<O::VAL>(M(RSP+8)[16], R(CS)[0,16]),
				mcop<O::VAL>(M(RSP+16), R(FLAGS)),
				mcop<O::VAL>(M(RSP+24), A(RSP+40)),
				mcop<O::VAL>(M(RSP+32)[16], R(SS)[0,16]),
				mcop<O::VAL>(R(RIP), M(IDTR+(vec<<4)))
			};
			return emit<SBA::Arch::Target::X86_64>(ctx, cache, inst, ops);
		}
	};
	struct INT3 {
		P(_, { mcop<O::VAL>(R(RSP), A(RSP-40)),
			   mcop<O::VAL>(M(RSP), R(RIP)),
			   mcop<O::VAL>(M(RSP+8)[16], R(CS)[0,16]),
			   mcop<O::VAL>(M(RSP+16), R(FLAGS)),
			   mcop<O::VAL>(M(RSP+24), A(RSP+40)),
			   mcop<O::VAL>(M(RSP+32)[16], R(SS)[0,16]),
			   mcop<O::TRAP>() });
	};
	struct INT1  : INT3 {};
	struct ICEBP : INT3 {};
	template <SBA::Arch::Mode M>
	struct HLT;
		template <> struct HLT<SBA::Arch::Mode::USER>   : P_ABORT {};
		template <> struct HLT<SBA::Arch::Mode::KERNEL> {
			P(_, { mcop<O::WAIT_I>() });
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
		P(_, { mcop<O::YIELD>() });
	};
	struct TRAP : P_ABORT {};
	struct LFENCE {
		P(_, { mcop<O::FENCE_R>() });
	};
	struct SFENCE {
		P(_, { mcop<O::FENCE_W>() });
	};
	struct MFENCE {
		P(_, { mcop<O::FENCE_RW>() });
	};
	struct SERIALIZE {
		P(_, { mcop<O::FENCE_I>() });
	};
	struct CPUID {
		P(_, { mcop<O::FENCE_I>() });
	};
	struct CLFLUSH {
		P(_, { mcop<O::FENCE_I>() });
	};
	struct UD1W  : P_UD1 {};
	struct UD1L  : P_UD1 {};
	struct UD1Q  : P_UD1 {};
	struct NOOP  : P_NOOP {};
	struct NOOPW : P_NOOP {};
	struct NOOPL : P_NOOP {};
	struct NOOPQ : P_NOOP {};
	struct FNOP  : P_NOOP {};
	struct XGETBV : P_SYSTEM_METRIC {};
	struct RDTSC  : P_SYSTEM_METRIC {};
	struct RDPMC  : P_SYSTEM_METRIC {};
	struct RDTSCP {
		P(_, { mcop<O::CLB>(R(RAX)[0,32]),
			   mcop<O::ZEXT>(R(RAX), R(RAX)[0,32]),
			   mcop<O::CLB>(R(RDX)[0,32]),
			   mcop<O::ZEXT>(R(RDX), R(RDX)[0,32]),
			   mcop<O::CLB>(R(RCX)[0,32]),
			   mcop<O::ZEXT>(R(RCX), R(RCX)[0,32]) });
	};
	struct RDFSBASE {
		P(_, { r_1x<O::VAL>(R(FS)[0,l]) });
	};
	struct RDGSBASE {
		P(_, { r_1x<O::VAL>(R(GS)[0,l]) });
	};
	struct WRFSBASE {
		P(_, { r_x1<O::VAL>(R(FS)[0,l]) });
	};
	struct WRGSBASE {
		P(_, { r_x1<O::VAL>(R(GS)[0,l]) });
	};
	struct RDRAND : P_RAND {};
	struct RDSEED : P_RAND {};

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
		PAUSE,
		RDTSC, RDTSCP, RDPMC, XGETBV,
		RDFSBASE, RDGSBASE, WRFSBASE, WRGSBASE,
		RDRAND, RDSEED
	>;

	#undef PM
	#undef P

}
