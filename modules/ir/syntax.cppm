module;
#include <bit>
#include <cstddef>
#include <cstdint>

export module sba.ir:syntax;

export namespace SBA::IR {

	inline constexpr size_t IMM_BITS   = 29;
	inline constexpr size_t MEM_BITS   = 30;
	inline constexpr size_t PCREL_BITS = 30;
	inline constexpr size_t INST_BITS  = 32;

	enum class InstructionType : uint8_t {
		STORE,
		SYSCALL,
		FENCE,
		TRAP,
		HALT,
		NOP
	};

	enum class OperandType : uint8_t {
		REGISTER,
		IMMEDIATE,
		MEMORY,
		PC_RELATIVE
	};

	union Operand {
		struct {
			uint32_t type     : 2;
			uint32_t llength  : 4;
			uint32_t index    : 8;
			uint32_t offset   : 8;
			uint32_t          : 10;
		} reg;

		struct {
			uint32_t type  : 2;
			uint32_t wide  : 1;
			uint32_t index : IMM_BITS;
		} imm;

		struct {
			uint32_t type  : 2;
			uint32_t index : MEM_BITS;
		} mem;

		struct {
			uint32_t type  : 2;
			uint32_t index : PCREL_BITS;
		} pcrel;

		constexpr OperandType type() const noexcept {
			return (OperandType)reg.type;
		}

		constexpr explicit operator uint32_t() const noexcept {
			return std::bit_cast<uint32_t>(*this);
		}

		constexpr bool operator==(Operand other) const noexcept {
			return (uint32_t)*this == (uint32_t)other;
		}
	};

	struct Memory {
		int32_t displacement;
		uint8_t base;
		uint8_t index;
		uint8_t shift        : 4;
		uint8_t extra        : 4;
		uint8_t llength      : 4;
		uint8_t llength_addr : 4;

		constexpr bool operator==(const Memory&) const noexcept = default;
	};

	struct Instruction {
		uint32_t index : INST_BITS;

		constexpr bool operator==(const Instruction&) const noexcept = default;
	};

}
