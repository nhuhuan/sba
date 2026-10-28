module;
#include <array>
#include <cstdint>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCInstrDesc.h>

export module sba.lift:fallback;

import sba.arch;
import sba.ir;
import :decode;
import :cache;
import :target;
import :parse;
import :emit;

namespace SBA::Lift {

    using namespace SBA::IR;
    using SBA::Arch::Target;

    template <Target T>
    inline Instruction lift_fallback(
        Context& ctx,
        Cache& cache,
        const MCInstruction& inst)
    {
        const auto& desc = info_inst<T>->get(inst.getOpcode());
        std::array<MCOperation, MAX_OPERATIONS> ops;
        size_t count = 0;

        for (int i = 0; i < desc.getNumDefs(); ++i)
            ops[count++] = MCOperation(Operator::CLB,
                                       DRegister((uint8_t)i));

        for (auto reg : desc.implicit_defs()) {
            auto dst = parse_r<T>(reg);
            if (dst != NO_REG)
                ops[count++] = MCOperation(Operator::CLB, dst);
        }

        if (desc.mayStore())
            ops[count++] = MCOperation(Operator::CLB, ANY_MEM);

        return emit<T>(ctx, cache, inst, { ops.data(), count });
    }

}
