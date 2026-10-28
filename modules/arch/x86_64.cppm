module;
#include <array>
#include <cstdint>
#include <string_view>

export module sba.arch:x86_64;

export namespace SBA::Arch::X86_64 {

    /* ------------------------------ Register ------------------------------ */

    #define REGISTER_LIST(REG) \
        REG(RIP,    64) \
        REG(RSP,    64) \
        REG(RBP,    64) \
        REG(RFLAGS, 64) \
        REG(CS,     16) \
        REG(DS,     16) \
        REG(SS,     16) \
        REG(ES,     16) \
        REG(FS,     16) \
        REG(GS,     16) \
        REG(RAX,    64) \
        REG(RBX,    64) \
        REG(RCX,    64) \
        REG(RDX,    64) \
        REG(RSI,    64) \
        REG(RDI,    64) \
        REG(R8,     64) \
        REG(R9,     64) \
        REG(R10,    64) \
        REG(R11,    64) \
        REG(R12,    64) \
        REG(R13,    64) \
        REG(R14,    64) \
        REG(R15,    64) \
        REG(CR0,    64) \
        REG(CR2,    64) \
        REG(CR3,    64) \
        REG(CR4,    64) \
        REG(CR8,    64) \
        REG(DR0,    64) \
        REG(DR1,    64) \
        REG(DR2,    64) \
        REG(DR3,    64) \
        REG(DR4,    64) \
        REG(DR5,    64) \
        REG(DR6,    64) \
        REG(DR7,    64) \
        REG(GDTR,   80) \
        REG(IDTR,   80) \
        REG(LDTR,   16) \
        REG(TR,     16) \
        REG(MSW,    16) \
        REG(ST0,    80) \
        REG(ST1,    80) \
        REG(ST2,    80) \
        REG(ST3,    80) \
        REG(ST4,    80) \
        REG(ST5,    80) \
        REG(ST6,    80) \
        REG(ST7,    80) \
        REG(ZMM0,   512) \
        REG(ZMM1,   512) \
        REG(ZMM2,   512) \
        REG(ZMM3,   512) \
        REG(ZMM4,   512) \
        REG(ZMM5,   512) \
        REG(ZMM6,   512) \
        REG(ZMM7,   512) \
        REG(ZMM8,   512) \
        REG(ZMM9,   512) \
        REG(ZMM10,  512) \
        REG(ZMM11,  512) \
        REG(ZMM12,  512) \
        REG(ZMM13,  512) \
        REG(ZMM14,  512) \
        REG(ZMM15,  512) \
        REG(ZMM16,  512) \
        REG(ZMM17,  512) \
        REG(ZMM18,  512) \
        REG(ZMM19,  512) \
        REG(ZMM20,  512) \
        REG(ZMM21,  512) \
        REG(ZMM22,  512) \
        REG(ZMM23,  512) \
        REG(ZMM24,  512) \
        REG(ZMM25,  512) \
        REG(ZMM26,  512) \
        REG(ZMM27,  512) \
        REG(ZMM28,  512) \
        REG(ZMM29,  512) \
        REG(ZMM30,  512) \
        REG(ZMM31,  512) \
        REG(K0,     64) \
        REG(K1,     64) \
        REG(K2,     64) \
        REG(K3,     64) \
        REG(K4,     64) \
        REG(K5,     64) \
        REG(K6,     64) \
        REG(K7,     64)

    enum class Reg : uint8_t {
        NONE,
        ANY,
        TMP1,
        TMP2,
        TMP3,
        TMP4,
        #define DEF_REG_ENUM(name, length) name,
        REGISTER_LIST(DEF_REG_ENUM)
        #undef DEF_REG_ENUM
        PC    = RIP,
        SP    = RSP,
        FP    = RBP,
        FLAGS = RFLAGS
    };

    static_assert((uint8_t)Reg::GS < 16);

    constexpr uint16_t length(Reg r) noexcept {
        switch (r) {
            case Reg::TMP1:
            case Reg::TMP2:
            case Reg::TMP3:
            case Reg::TMP4:
                return 64;
            #define DEF_REG_LEN(name, length) case Reg::name: return length;
            REGISTER_LIST(DEF_REG_LEN)
            #undef DEF_REG_LEN
            default: return 0;
        }
    }

    #define REGISTER_MAP(REG) \
        REG("AH",     RAX,    8, 8) \
        REG("AL",     RAX,    0, 8) \
        REG("AX",     RAX,    0, 16) \
        REG("EAX",    RAX,    0, 32) \
        REG("RAX",    RAX,    0, 64) \
        REG("BH",     RBX,    8, 8) \
        REG("BL",     RBX,    0, 8) \
        REG("BX",     RBX,    0, 16) \
        REG("EBX",    RBX,    0, 32) \
        REG("RBX",    RBX,    0, 64) \
        REG("CH",     RCX,    8, 8) \
        REG("CL",     RCX,    0, 8) \
        REG("CX",     RCX,    0, 16) \
        REG("ECX",    RCX,    0, 32) \
        REG("RCX",    RCX,    0, 64) \
        REG("DH",     RDX,    8, 8) \
        REG("DL",     RDX,    0, 8) \
        REG("DX",     RDX,    0, 16) \
        REG("EDX",    RDX,    0, 32) \
        REG("RDX",    RDX,    0, 64) \
        REG("DIL",    RDI,    0, 8) \
        REG("DI",     RDI,    0, 16) \
        REG("EDI",    RDI,    0, 32) \
        REG("RDI",    RDI,    0, 64) \
        REG("SIL",    RSI,    0, 8) \
        REG("SI",     RSI,    0, 16) \
        REG("ESI",    RSI,    0, 32) \
        REG("RSI",    RSI,    0, 64) \
        REG("BPL",    RBP,    0, 8) \
        REG("BP",     RBP,    0, 16) \
        REG("EBP",    RBP,    0, 32) \
        REG("RBP",    RBP,    0, 64) \
        REG("SPL",    RSP,    0, 8) \
        REG("SP",     RSP,    0, 16) \
        REG("ESP",    RSP,    0, 32) \
        REG("RSP",    RSP,    0, 64) \
        REG("R8B",    R8,     0, 8) \
        REG("R8W",    R8,     0, 16) \
        REG("R8D",    R8,     0, 32) \
        REG("R8",     R8,     0, 64) \
        REG("R9B",    R9,     0, 8) \
        REG("R9W",    R9,     0, 16) \
        REG("R9D",    R9,     0, 32) \
        REG("R9",     R9,     0, 64) \
        REG("R10B",   R10,    0, 8) \
        REG("R10W",   R10,    0, 16) \
        REG("R10D",   R10,    0, 32) \
        REG("R10",    R10,    0, 64) \
        REG("R11B",   R11,    0, 8) \
        REG("R11W",   R11,    0, 16) \
        REG("R11D",   R11,    0, 32) \
        REG("R11",    R11,    0, 64) \
        REG("R12B",   R12,    0, 8) \
        REG("R12W",   R12,    0, 16) \
        REG("R12D",   R12,    0, 32) \
        REG("R12",    R12,    0, 64) \
        REG("R13B",   R13,    0, 8) \
        REG("R13W",   R13,    0, 16) \
        REG("R13D",   R13,    0, 32) \
        REG("R13",    R13,    0, 64) \
        REG("R14B",   R14,    0, 8) \
        REG("R14W",   R14,    0, 16) \
        REG("R14D",   R14,    0, 32) \
        REG("R14",    R14,    0, 64) \
        REG("R15B",   R15,    0, 8) \
        REG("R15W",   R15,    0, 16) \
        REG("R15D",   R15,    0, 32) \
        REG("R15",    R15,    0, 64) \
        REG("IP",     RIP,    0, 16) \
        REG("EIP",    RIP,    0, 32) \
        REG("RIP",    RIP,    0, 64) \
        REG("FLAGS",  RFLAGS, 0, 16) \
        REG("EFLAGS", RFLAGS, 0, 32) \
        REG("RFLAGS", RFLAGS, 0, 64) \
        REG("CS",     CS,     0, 16) \
        REG("DS",     DS,     0, 16) \
        REG("SS",     SS,     0, 16) \
        REG("ES",     ES,     0, 16) \
        REG("FS",     FS,     0, 16) \
        REG("GS",     GS,     0, 16) \
        REG("CR0",    CR0,    0, 64) \
        REG("CR2",    CR2,    0, 64) \
        REG("CR3",    CR3,    0, 64) \
        REG("CR4",    CR4,    0, 64) \
        REG("CR8",    CR8,    0, 64) \
        REG("DR0",    DR0,    0, 64) \
        REG("DR1",    DR1,    0, 64) \
        REG("DR2",    DR2,    0, 64) \
        REG("DR3",    DR3,    0, 64) \
        REG("DR4",    DR4,    0, 64) \
        REG("DR5",    DR5,    0, 64) \
        REG("DR6",    DR6,    0, 64) \
        REG("DR7",    DR7,    0, 64) \
        REG("GDTR",   GDTR,   0, 80) \
        REG("IDTR",   IDTR,   0, 80) \
        REG("LDTR",   LDTR,   0, 16) \
        REG("TR",     TR,     0, 16) \
        REG("MSW",    MSW,    0, 16) \
        REG("ST0",    ST0,    0, 80) \
        REG("ST1",    ST1,    0, 80) \
        REG("ST2",    ST2,    0, 80) \
        REG("ST3",    ST3,    0, 80) \
        REG("ST4",    ST4,    0, 80) \
        REG("ST5",    ST5,    0, 80) \
        REG("ST6",    ST6,    0, 80) \
        REG("ST7",    ST7,    0, 80) \
        REG("MM0",    ST0,    0, 64) \
        REG("MM1",    ST1,    0, 64) \
        REG("MM2",    ST2,    0, 64) \
        REG("MM3",    ST3,    0, 64) \
        REG("MM4",    ST4,    0, 64) \
        REG("MM5",    ST5,    0, 64) \
        REG("MM6",    ST6,    0, 64) \
        REG("MM7",    ST7,    0, 64) \
        REG("K0",     K0,     0, 64) \
        REG("K1",     K1,     0, 64) \
        REG("K2",     K2,     0, 64) \
        REG("K3",     K3,     0, 64) \
        REG("K4",     K4,     0, 64) \
        REG("K5",     K5,     0, 64) \
        REG("K6",     K6,     0, 64) \
        REG("K7",     K7,     0, 64) \
        REG("XMM0",   ZMM0,   0, 128) \
        REG("YMM0",   ZMM0,   0, 256) \
        REG("ZMM0",   ZMM0,   0, 512) \
        REG("XMM1",   ZMM1,   0, 128) \
        REG("YMM1",   ZMM1,   0, 256) \
        REG("ZMM1",   ZMM1,   0, 512) \
        REG("XMM2",   ZMM2,   0, 128) \
        REG("YMM2",   ZMM2,   0, 256) \
        REG("ZMM2",   ZMM2,   0, 512) \
        REG("XMM3",   ZMM3,   0, 128) \
        REG("YMM3",   ZMM3,   0, 256) \
        REG("ZMM3",   ZMM3,   0, 512) \
        REG("XMM4",   ZMM4,   0, 128) \
        REG("YMM4",   ZMM4,   0, 256) \
        REG("ZMM4",   ZMM4,   0, 512) \
        REG("XMM5",   ZMM5,   0, 128) \
        REG("YMM5",   ZMM5,   0, 256) \
        REG("ZMM5",   ZMM5,   0, 512) \
        REG("XMM6",   ZMM6,   0, 128) \
        REG("YMM6",   ZMM6,   0, 256) \
        REG("ZMM6",   ZMM6,   0, 512) \
        REG("XMM7",   ZMM7,   0, 128) \
        REG("YMM7",   ZMM7,   0, 256) \
        REG("ZMM7",   ZMM7,   0, 512) \
        REG("XMM8",   ZMM8,   0, 128) \
        REG("YMM8",   ZMM8,   0, 256) \
        REG("ZMM8",   ZMM8,   0, 512) \
        REG("XMM9",   ZMM9,   0, 128) \
        REG("YMM9",   ZMM9,   0, 256) \
        REG("ZMM9",   ZMM9,   0, 512) \
        REG("XMM10",  ZMM10,  0, 128) \
        REG("YMM10",  ZMM10,  0, 256) \
        REG("ZMM10",  ZMM10,  0, 512) \
        REG("XMM11",  ZMM11,  0, 128) \
        REG("YMM11",  ZMM11,  0, 256) \
        REG("ZMM11",  ZMM11,  0, 512) \
        REG("XMM12",  ZMM12,  0, 128) \
        REG("YMM12",  ZMM12,  0, 256) \
        REG("ZMM12",  ZMM12,  0, 512) \
        REG("XMM13",  ZMM13,  0, 128) \
        REG("YMM13",  ZMM13,  0, 256) \
        REG("ZMM13",  ZMM13,  0, 512) \
        REG("XMM14",  ZMM14,  0, 128) \
        REG("YMM14",  ZMM14,  0, 256) \
        REG("ZMM14",  ZMM14,  0, 512) \
        REG("XMM15",  ZMM15,  0, 128) \
        REG("YMM15",  ZMM15,  0, 256) \
        REG("ZMM15",  ZMM15,  0, 512) \
        REG("XMM16",  ZMM16,  0, 128) \
        REG("YMM16",  ZMM16,  0, 256) \
        REG("ZMM16",  ZMM16,  0, 512) \
        REG("XMM17",  ZMM17,  0, 128) \
        REG("YMM17",  ZMM17,  0, 256) \
        REG("ZMM17",  ZMM17,  0, 512) \
        REG("XMM18",  ZMM18,  0, 128) \
        REG("YMM18",  ZMM18,  0, 256) \
        REG("ZMM18",  ZMM18,  0, 512) \
        REG("XMM19",  ZMM19,  0, 128) \
        REG("YMM19",  ZMM19,  0, 256) \
        REG("ZMM19",  ZMM19,  0, 512) \
        REG("XMM20",  ZMM20,  0, 128) \
        REG("YMM20",  ZMM20,  0, 256) \
        REG("ZMM20",  ZMM20,  0, 512) \
        REG("XMM21",  ZMM21,  0, 128) \
        REG("YMM21",  ZMM21,  0, 256) \
        REG("ZMM21",  ZMM21,  0, 512) \
        REG("XMM22",  ZMM22,  0, 128) \
        REG("YMM22",  ZMM22,  0, 256) \
        REG("ZMM22",  ZMM22,  0, 512) \
        REG("XMM23",  ZMM23,  0, 128) \
        REG("YMM23",  ZMM23,  0, 256) \
        REG("ZMM23",  ZMM23,  0, 512) \
        REG("XMM24",  ZMM24,  0, 128) \
        REG("YMM24",  ZMM24,  0, 256) \
        REG("ZMM24",  ZMM24,  0, 512) \
        REG("XMM25",  ZMM25,  0, 128) \
        REG("YMM25",  ZMM25,  0, 256) \
        REG("ZMM25",  ZMM25,  0, 512) \
        REG("XMM26",  ZMM26,  0, 128) \
        REG("YMM26",  ZMM26,  0, 256) \
        REG("ZMM26",  ZMM26,  0, 512) \
        REG("XMM27",  ZMM27,  0, 128) \
        REG("YMM27",  ZMM27,  0, 256) \
        REG("ZMM27",  ZMM27,  0, 512) \
        REG("XMM28",  ZMM28,  0, 128) \
        REG("YMM28",  ZMM28,  0, 256) \
        REG("ZMM28",  ZMM28,  0, 512) \
        REG("XMM29",  ZMM29,  0, 128) \
        REG("YMM29",  ZMM29,  0, 256) \
        REG("ZMM29",  ZMM29,  0, 512) \
        REG("XMM30",  ZMM30,  0, 128) \
        REG("YMM30",  ZMM30,  0, 256) \
        REG("ZMM30",  ZMM30,  0, 512) \
        REG("XMM31",  ZMM31,  0, 128) \
        REG("YMM31",  ZMM31,  0, 256) \
        REG("ZMM31",  ZMM31,  0, 512)

    struct RegEntry {
        std::string_view name;
        Reg base;
        uint16_t offset; /* bits */
        uint16_t length; /* bits */
    };

    inline constexpr std::array registers = {
        #define DEF_SUBREG(name, base, offset, length) \
            RegEntry{name, Reg::base, offset, length},
        REGISTER_MAP(DEF_SUBREG)
        #undef DEF_SUBREG
    };

    /* --------------------------------- ABI -------------------------------- */

    namespace ABI {

        namespace SystemV {
            inline constexpr std::array arg_registers = {
                Reg::RDI, Reg::RSI, Reg::RDX, Reg::RCX,
                Reg::R8, Reg::R9
            };

            inline constexpr std::array callee_saved_registers = {
                Reg::RBX, Reg::RSP, Reg::RBP,
                Reg::R12, Reg::R13, Reg::R14, Reg::R15
            };

            inline constexpr std::array return_registers = {
                Reg::RAX, Reg::RDX
            };
        }

        namespace Windows {
            inline constexpr std::array arg_registers = {
                Reg::RCX, Reg::RDX, Reg::R8, Reg::R9
            };

            inline constexpr std::array callee_saved_registers = {
                Reg::RBX, Reg::RBP, Reg::RDI, Reg::RSI,
                Reg::RSP, Reg::R12, Reg::R13, Reg::R14, Reg::R15
            };

            inline constexpr std::array return_registers = {
                Reg::RAX, Reg::RDX
            };
        }

    }

    /* ------------------------------ Interrupt ----------------------------- */

    namespace InterruptVector {
        inline constexpr uint8_t WINDOWS_SYSCALL     = 0x2E;
        inline constexpr uint8_t LINUX_SYSCALL       = 0x80;
        inline constexpr uint8_t DARWIN_BSD_SYSCALL  = 0x80;
        inline constexpr uint8_t DARWIN_MACH_SYSCALL = 0x81;
    }

}
