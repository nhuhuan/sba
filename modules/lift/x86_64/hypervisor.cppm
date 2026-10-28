module;
#include <cstdint>

export module sba.lift:x86_64_hypervisor;

import sba.arch;
import sba.ir;
import :x86_64_pattern;

namespace SBA::Lift::X86_64 {

    #define P(Suffix, ...) \
        template <uint8_t l> \
        static constexpr Pattern Suffix = { __VA_ARGS__ }

    #define PM(Suffix, ...) \
        template <uint8_t l, uint8_t lm = l> \
        static constexpr Pattern Suffix = { __VA_ARGS__ }

    struct P_HYPER_ABORT {
        P(_,   { mcop<O::ABORT>() });
        P(rr,  { mcop<O::ABORT>() });
        PM(m,  { mcop<O::ABORT>() });
        PM(rm, { mcop<O::ABORT>() });
        PM(mr, { mcop<O::ABORT>() });
    };

    /* Intel VT-x Virtualization */
    struct VMXON    : P_HYPER_ABORT {};
    struct VMXOFF   : P_HYPER_ABORT {};
    struct VMLAUNCH : P_HYPER_ABORT {};
    struct VMRESUME : P_HYPER_ABORT {};
    struct VMCLEAR  : P_HYPER_ABORT {};
    struct VMPTRLD  : P_HYPER_ABORT {};
    struct VMPTRST  : P_HYPER_ABORT {};
    struct VMREAD   : P_HYPER_ABORT {};
    struct VMWRITE  : P_HYPER_ABORT {};
    struct INVEPT   : P_HYPER_ABORT {};
    struct INVVPID  : P_HYPER_ABORT {};
    struct INVPCID  : P_HYPER_ABORT {};

    /* AMD SVM Virtualization */
    struct VMRUN    : P_HYPER_ABORT {};
    struct VMLOAD   : P_HYPER_ABORT {};
    struct VMSAVE   : P_HYPER_ABORT {};
    struct CLGI     : P_HYPER_ABORT {};
    struct STGI     : P_HYPER_ABORT {};
    struct INVLPGA  : P_HYPER_ABORT {};
    struct SKINIT   : P_HYPER_ABORT {};

    /* Firmware */
    struct RSM       : P_HYPER_ABORT {};

    template <SBA::Arch::Mode M = SBA::Arch::Mode::USER>
    using Mnemonics_HPV = SBA::Util::TypeList<
        VMXON, VMXOFF, VMLAUNCH, VMRESUME,
        VMCLEAR, VMPTRLD, VMPTRST, VMREAD, VMWRITE,
        INVEPT, INVVPID, INVPCID,
        VMRUN, VMLOAD, VMSAVE, CLGI, STGI, INVLPGA, SKINIT,
        RSM
    >;

    #undef PM
    #undef P

}
