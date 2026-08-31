module;
#include <array>
#include <cstdint>
#include <string_view>

export module sba.arch:x86_64;

export namespace SBA::Arch::X86_64 {

	#define REGISTER_LIST(REG) \
		REG(RIP,    8) \
		REG(RSP,    8) \
		REG(RBP,    8) \
		REG(RFLAGS, 8) \
		REG(CS,     2) \
		REG(DS,     2) \
		REG(SS,     2) \
		REG(ES,     2) \
		REG(FS,     2) \
		REG(GS,     2) \
		REG(RAX,    8) \
		REG(RBX,    8) \
		REG(RCX,    8) \
		REG(RDX,    8) \
		REG(RSI,    8) \
		REG(RDI,    8) \
		REG(R8,     8) \
		REG(R9,     8) \
		REG(R10,    8) \
		REG(R11,    8) \
		REG(R12,    8) \
		REG(R13,    8) \
		REG(R14,    8) \
		REG(R15,    8) \
		REG(CR0,    8) \
		REG(CR2,    8) \
		REG(CR3,    8) \
		REG(CR4,    8) \
		REG(CR8,    8) \
		REG(DR0,    8) \
		REG(DR1,    8) \
		REG(DR2,    8) \
		REG(DR3,    8) \
		REG(DR4,    8) \
		REG(DR5,    8) \
		REG(DR6,    8) \
		REG(DR7,    8) \
		REG(GDTR,   10) \
		REG(IDTR,   10) \
		REG(LDTR,   2) \
		REG(TR,     2) \
		REG(MSW,    2) \
		REG(ST0,    10) \
		REG(ST1,    10) \
		REG(ST2,    10) \
		REG(ST3,    10) \
		REG(ST4,    10) \
		REG(ST5,    10) \
		REG(ST6,    10) \
		REG(ST7,    10) \
		REG(ZMM0,   64) \
		REG(ZMM1,   64) \
		REG(ZMM2,   64) \
		REG(ZMM3,   64) \
		REG(ZMM4,   64) \
		REG(ZMM5,   64) \
		REG(ZMM6,   64) \
		REG(ZMM7,   64) \
		REG(ZMM8,   64) \
		REG(ZMM9,   64) \
		REG(ZMM10,  64) \
		REG(ZMM11,  64) \
		REG(ZMM12,  64) \
		REG(ZMM13,  64) \
		REG(ZMM14,  64) \
		REG(ZMM15,  64) \
		REG(ZMM16,  64) \
		REG(ZMM17,  64) \
		REG(ZMM18,  64) \
		REG(ZMM19,  64) \
		REG(ZMM20,  64) \
		REG(ZMM21,  64) \
		REG(ZMM22,  64) \
		REG(ZMM23,  64) \
		REG(ZMM24,  64) \
		REG(ZMM25,  64) \
		REG(ZMM26,  64) \
		REG(ZMM27,  64) \
		REG(ZMM28,  64) \
		REG(ZMM29,  64) \
		REG(ZMM30,  64) \
		REG(ZMM31,  64) \
		REG(K0,     8) \
		REG(K1,     8) \
		REG(K2,     8) \
		REG(K3,     8) \
		REG(K4,     8) \
		REG(K5,     8) \
		REG(K6,     8) \
		REG(K7,     8)

	enum class Reg : uint8_t {
		NONE,
		ANY,
		TMP1,
		TMP2,

		#define DEF_REG_ENUM(name, length) name,
		REGISTER_LIST(DEF_REG_ENUM)
		#undef DEF_REG_ENUM

		PC    = RIP,
		SP    = RSP,
		FP    = RBP,
		FLAGS = RFLAGS
	};

	constexpr uint16_t length(Reg r) noexcept {
		switch (r) {
			case Reg::TMP1:
			case Reg::TMP2:
				return 8;
			#define DEF_REG_LEN(name, length) case Reg::name: return length;
			REGISTER_LIST(DEF_REG_LEN)
			#undef DEF_REG_LEN
			default: return 0;
		}
	}

	#define REGISTER_MAP(REG) \
		REG("AH",     RAX,    1, 0) \
		REG("AL",     RAX,    0, 0) \
		REG("AX",     RAX,    0, 1) \
		REG("EAX",    RAX,    0, 2) \
		REG("RAX",    RAX,    0, 3) \
		REG("BH",     RBX,    1, 0) \
		REG("BL",     RBX,    0, 0) \
		REG("BX",     RBX,    0, 1) \
		REG("EBX",    RBX,    0, 2) \
		REG("RBX",    RBX,    0, 3) \
		REG("CH",     RCX,    1, 0) \
		REG("CL",     RCX,    0, 0) \
		REG("CX",     RCX,    0, 1) \
		REG("ECX",    RCX,    0, 2) \
		REG("RCX",    RCX,    0, 3) \
		REG("DH",     RDX,    1, 0) \
		REG("DL",     RDX,    0, 0) \
		REG("DX",     RDX,    0, 1) \
		REG("EDX",    RDX,    0, 2) \
		REG("RDX",    RDX,    0, 3) \
		REG("DIL",    RDI,    0, 0) \
		REG("DI",     RDI,    0, 1) \
		REG("EDI",    RDI,    0, 2) \
		REG("RDI",    RDI,    0, 3) \
		REG("SIL",    RSI,    0, 0) \
		REG("SI",     RSI,    0, 1) \
		REG("ESI",    RSI,    0, 2) \
		REG("RSI",    RSI,    0, 3) \
		REG("BPL",    RBP,    0, 0) \
		REG("BP",     RBP,    0, 1) \
		REG("EBP",    RBP,    0, 2) \
		REG("RBP",    RBP,    0, 3) \
		REG("SPL",    RSP,    0, 0) \
		REG("SP",     RSP,    0, 1) \
		REG("ESP",    RSP,    0, 2) \
		REG("RSP",    RSP,    0, 3) \
		REG("R8B",    R8,     0, 0) \
		REG("R8W",    R8,     0, 1) \
		REG("R8D",    R8,     0, 2) \
		REG("R8",     R8,     0, 3) \
		REG("R9B",    R9,     0, 0) \
		REG("R9W",    R9,     0, 1) \
		REG("R9D",    R9,     0, 2) \
		REG("R9",     R9,     0, 3) \
		REG("R10B",   R10,    0, 0) \
		REG("R10W",   R10,    0, 1) \
		REG("R10D",   R10,    0, 2) \
		REG("R10",    R10,    0, 3) \
		REG("R11B",   R11,    0, 0) \
		REG("R11W",   R11,    0, 1) \
		REG("R11D",   R11,    0, 2) \
		REG("R11",    R11,    0, 3) \
		REG("R12B",   R12,    0, 0) \
		REG("R12W",   R12,    0, 1) \
		REG("R12D",   R12,    0, 2) \
		REG("R12",    R12,    0, 3) \
		REG("R13B",   R13,    0, 0) \
		REG("R13W",   R13,    0, 1) \
		REG("R13D",   R13,    0, 2) \
		REG("R13",    R13,    0, 3) \
		REG("R14B",   R14,    0, 0) \
		REG("R14W",   R14,    0, 1) \
		REG("R14D",   R14,    0, 2) \
		REG("R14",    R14,    0, 3) \
		REG("R15B",   R15,    0, 0) \
		REG("R15W",   R15,    0, 1) \
		REG("R15D",   R15,    0, 2) \
		REG("R15",    R15,    0, 3) \
		REG("IP",     RIP,    0, 1) \
		REG("EIP",    RIP,    0, 2) \
		REG("RIP",    RIP,    0, 3) \
		REG("FLAGS",  RFLAGS, 0, 1) \
		REG("EFLAGS", RFLAGS, 0, 2) \
		REG("RFLAGS", RFLAGS, 0, 3) \
		REG("CS",     CS,     0, 1) \
		REG("DS",     DS,     0, 1) \
		REG("SS",     SS,     0, 1) \
		REG("ES",     ES,     0, 1) \
		REG("FS",     FS,     0, 1) \
		REG("GS",     GS,     0, 1) \
		REG("CR0",    CR0,    0, 3) \
		REG("CR2",    CR2,    0, 3) \
		REG("CR3",    CR3,    0, 3) \
		REG("CR4",    CR4,    0, 3) \
		REG("CR8",    CR8,    0, 3) \
		REG("DR0",    DR0,    0, 3) \
		REG("DR1",    DR1,    0, 3) \
		REG("DR2",    DR2,    0, 3) \
		REG("DR3",    DR3,    0, 3) \
		REG("DR4",    DR4,    0, 3) \
		REG("DR5",    DR5,    0, 3) \
		REG("DR6",    DR6,    0, 3) \
		REG("DR7",    DR7,    0, 3) \
		REG("GDTR",   GDTR,   0, 15) \
		REG("IDTR",   IDTR,   0, 15) \
		REG("LDTR",   LDTR,   0, 1) \
		REG("TR",     TR,     0, 1) \
		REG("MSW",    MSW,    0, 1) \
		REG("ST0",    ST0,    0, 15) \
		REG("ST1",    ST1,    0, 15) \
		REG("ST2",    ST2,    0, 15) \
		REG("ST3",    ST3,    0, 15) \
		REG("ST4",    ST4,    0, 15) \
		REG("ST5",    ST5,    0, 15) \
		REG("ST6",    ST6,    0, 15) \
		REG("ST7",    ST7,    0, 15) \
		REG("MM0",    ST0,    0, 3) \
		REG("MM1",    ST1,    0, 3) \
		REG("MM2",    ST2,    0, 3) \
		REG("MM3",    ST3,    0, 3) \
		REG("MM4",    ST4,    0, 3) \
		REG("MM5",    ST5,    0, 3) \
		REG("MM6",    ST6,    0, 3) \
		REG("MM7",    ST7,    0, 3) \
		REG("K0",     K0,     0, 3) \
		REG("K1",     K1,     0, 3) \
		REG("K2",     K2,     0, 3) \
		REG("K3",     K3,     0, 3) \
		REG("K4",     K4,     0, 3) \
		REG("K5",     K5,     0, 3) \
		REG("K6",     K6,     0, 3) \
		REG("K7",     K7,     0, 3) \
		REG("XMM0",   ZMM0,   0, 4) \
		REG("YMM0",   ZMM0,   0, 5) \
		REG("ZMM0",   ZMM0,   0, 6) \
		REG("XMM1",   ZMM1,   0, 4) \
		REG("YMM1",   ZMM1,   0, 5) \
		REG("ZMM1",   ZMM1,   0, 6) \
		REG("XMM2",   ZMM2,   0, 4) \
		REG("YMM2",   ZMM2,   0, 5) \
		REG("ZMM2",   ZMM2,   0, 6) \
		REG("XMM3",   ZMM3,   0, 4) \
		REG("YMM3",   ZMM3,   0, 5) \
		REG("ZMM3",   ZMM3,   0, 6) \
		REG("XMM4",   ZMM4,   0, 4) \
		REG("YMM4",   ZMM4,   0, 5) \
		REG("ZMM4",   ZMM4,   0, 6) \
		REG("XMM5",   ZMM5,   0, 4) \
		REG("YMM5",   ZMM5,   0, 5) \
		REG("ZMM5",   ZMM5,   0, 6) \
		REG("XMM6",   ZMM6,   0, 4) \
		REG("YMM6",   ZMM6,   0, 5) \
		REG("ZMM6",   ZMM6,   0, 6) \
		REG("XMM7",   ZMM7,   0, 4) \
		REG("YMM7",   ZMM7,   0, 5) \
		REG("ZMM7",   ZMM7,   0, 6) \
		REG("XMM8",   ZMM8,   0, 4) \
		REG("YMM8",   ZMM8,   0, 5) \
		REG("ZMM8",   ZMM8,   0, 6) \
		REG("XMM9",   ZMM9,   0, 4) \
		REG("YMM9",   ZMM9,   0, 5) \
		REG("ZMM9",   ZMM9,   0, 6) \
		REG("XMM10",  ZMM10,  0, 4) \
		REG("YMM10",  ZMM10,  0, 5) \
		REG("ZMM10",  ZMM10,  0, 6) \
		REG("XMM11",  ZMM11,  0, 4) \
		REG("YMM11",  ZMM11,  0, 5) \
		REG("ZMM11",  ZMM11,  0, 6) \
		REG("XMM12",  ZMM12,  0, 4) \
		REG("YMM12",  ZMM12,  0, 5) \
		REG("ZMM12",  ZMM12,  0, 6) \
		REG("XMM13",  ZMM13,  0, 4) \
		REG("YMM13",  ZMM13,  0, 5) \
		REG("ZMM13",  ZMM13,  0, 6) \
		REG("XMM14",  ZMM14,  0, 4) \
		REG("YMM14",  ZMM14,  0, 5) \
		REG("ZMM14",  ZMM14,  0, 6) \
		REG("XMM15",  ZMM15,  0, 4) \
		REG("YMM15",  ZMM15,  0, 5) \
		REG("ZMM15",  ZMM15,  0, 6) \
		REG("XMM16",  ZMM16,  0, 4) \
		REG("YMM16",  ZMM16,  0, 5) \
		REG("ZMM16",  ZMM16,  0, 6) \
		REG("XMM17",  ZMM17,  0, 4) \
		REG("YMM17",  ZMM17,  0, 5) \
		REG("ZMM17",  ZMM17,  0, 6) \
		REG("XMM18",  ZMM18,  0, 4) \
		REG("YMM18",  ZMM18,  0, 5) \
		REG("ZMM18",  ZMM18,  0, 6) \
		REG("XMM19",  ZMM19,  0, 4) \
		REG("YMM19",  ZMM19,  0, 5) \
		REG("ZMM19",  ZMM19,  0, 6) \
		REG("XMM20",  ZMM20,  0, 4) \
		REG("YMM20",  ZMM20,  0, 5) \
		REG("ZMM20",  ZMM20,  0, 6) \
		REG("XMM21",  ZMM21,  0, 4) \
		REG("YMM21",  ZMM21,  0, 5) \
		REG("ZMM21",  ZMM21,  0, 6) \
		REG("XMM22",  ZMM22,  0, 4) \
		REG("YMM22",  ZMM22,  0, 5) \
		REG("ZMM22",  ZMM22,  0, 6) \
		REG("XMM23",  ZMM23,  0, 4) \
		REG("YMM23",  ZMM23,  0, 5) \
		REG("ZMM23",  ZMM23,  0, 6) \
		REG("XMM24",  ZMM24,  0, 4) \
		REG("YMM24",  ZMM24,  0, 5) \
		REG("ZMM24",  ZMM24,  0, 6) \
		REG("XMM25",  ZMM25,  0, 4) \
		REG("YMM25",  ZMM25,  0, 5) \
		REG("ZMM25",  ZMM25,  0, 6) \
		REG("XMM26",  ZMM26,  0, 4) \
		REG("YMM26",  ZMM26,  0, 5) \
		REG("ZMM26",  ZMM26,  0, 6) \
		REG("XMM27",  ZMM27,  0, 4) \
		REG("YMM27",  ZMM27,  0, 5) \
		REG("ZMM27",  ZMM27,  0, 6) \
		REG("XMM28",  ZMM28,  0, 4) \
		REG("YMM28",  ZMM28,  0, 5) \
		REG("ZMM28",  ZMM28,  0, 6) \
		REG("XMM29",  ZMM29,  0, 4) \
		REG("YMM29",  ZMM29,  0, 5) \
		REG("ZMM29",  ZMM29,  0, 6) \
		REG("XMM30",  ZMM30,  0, 4) \
		REG("YMM30",  ZMM30,  0, 5) \
		REG("ZMM30",  ZMM30,  0, 6) \
		REG("XMM31",  ZMM31,  0, 4) \
		REG("YMM31",  ZMM31,  0, 5) \
		REG("ZMM31",  ZMM31,  0, 6)

	struct RegEntry {
		std::string_view name;
		Reg base;
		uint8_t offset;
		uint8_t llength;
	};

	inline constexpr std::array registers = {
		#define DEF_SUBREG(name, base, offset, llength) \
			RegEntry{name, Reg::base, offset, llength},
		REGISTER_MAP(DEF_SUBREG)
		#undef DEF_SUBREG
	};

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

}
