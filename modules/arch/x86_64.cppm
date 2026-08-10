module;
#include <array>
#include <cstdint>
#include <string>

export module sba.arch.x86_64;

export namespace SBA::Arch {

	struct X86_64 {
		enum class SegmentReg : uint8_t {
			CS, DS, SS, ES, FS, GS
		};

		#define REGISTER_LIST(REG) \
			REG(RAX,    8) \
			REG(RBX,    8) \
			REG(RCX,    8) \
			REG(RDX,    8) \
			REG(RSI,    8) \
			REG(RDI,    8) \
			REG(RBP,    8) \
			REG(RSP,    8) \
			REG(R8,     8) \
			REG(R9,     8) \
			REG(R10,    8) \
			REG(R11,    8) \
			REG(R12,    8) \
			REG(R13,    8) \
			REG(R14,    8) \
			REG(R15,    8) \
			REG(RIP,    8) \
			REG(RFLAGS, 8) \
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

		enum class Reg : uint16_t {
			NONE = 0,
			ANY = 1,
			#define DEF_REG_ENUM(name, size) name,
			REGISTER_LIST(DEF_REG_ENUM)
			#undef DEF_REG_ENUM
		};

		static constexpr uint16_t length(Reg r) noexcept {
			switch (r) {
				#define DEF_REG_LEN(name, size) case Reg::name: return size;
				REGISTER_LIST(DEF_REG_LEN)
				#undef DEF_REG_LEN
				default: return 0;
			}
		}

		static constexpr Reg program_counter = Reg::RIP;
		static constexpr Reg stack_pointer   = Reg::RSP;
		static constexpr Reg frame_pointer   = Reg::RBP;
		static constexpr Reg status_flags    = Reg::RFLAGS;

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
			REG("EFLAGS", RFLAGS, 0, 2) \
			REG("FLAGS",  RFLAGS, 0, 1) \
			REG("EIP",    RIP,    0, 2) \
			REG("RIP",    RIP,    0, 3) \
			REG("RFLAGS", RFLAGS, 0, 3) \
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
			REG("ST7",    ST7,    0, 15)

		struct RegMap {
			std::string name;
			Reg base;
			uint8_t offset;
			uint8_t llength;
		};

		static inline constexpr std::array register_map = {
			#define DEF_SUBREG(name, base, offset, llength) \
				RegMap{name, Reg::base, offset, llength},
			REGISTER_MAP(DEF_SUBREG)
			#undef DEF_SUBREG
		};

		struct ABI {
			struct SystemV {
				static constexpr std::array arg_registers = {
					Reg::RDI, Reg::RSI, Reg::RDX, Reg::RCX,
					Reg::R8, Reg::R9
				};

				static constexpr std::array callee_saved_registers = {
					Reg::RBX, Reg::RSP, Reg::RBP,
					Reg::R12, Reg::R13, Reg::R14, Reg::R15
				};

				static constexpr std::array return_registers = {
					Reg::RAX, Reg::RDX
				};
			};
		};
	};

}
