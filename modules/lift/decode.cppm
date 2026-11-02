module;
#include <memory>
#include <optional>
#include <span>
#include <llvm/MC/MCInst.h>

namespace llvm {
    class MCContext;
    class MCDisassembler;
}

export module sba.lift:decode;

import sba.arch;
import sba.binary;

export namespace SBA::Lift {

    /* --------------------------- MCInstruction ---------------------------- */

    class MCInstruction : public llvm::MCInst {
    public:
        uint8_t length() const noexcept { return len_; }
        void length(uint8_t len) noexcept { len_ = len; }
        bool atomic() const noexcept { return atomic_; }
        void atomic(bool a) noexcept { atomic_ = a; }
        bool valid() const noexcept { return getOpcode() != 0; }

    private:
        uint8_t len_ = 0;
        bool atomic_ = false;
    };

    /* ------------------------------ Decoder ------------------------------- */

    template <SBA::Arch::Target T>
    class Decoder {
    public:
        Decoder(const SBA::Binary::Object& object);
        ~Decoder();

        std::optional<MCInstruction> decode(
            uint64_t address,
            std::span<const uint8_t> bytes
        ) const;

    private:
        std::unique_ptr<llvm::MCContext> context;
        std::unique_ptr<llvm::MCDisassembler> disassembler;
    };

}
