module;
#include <bit>
#include <cstdint>

export module sba.ir.syntax;

export namespace SBA::IR {

	enum class OperationType : uint8_t {
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
			uint32_t type    : 2;
			uint32_t llength : 4;
			uint32_t id      : 16;
			uint32_t offset  : 8;
		} reg;

		struct {
			uint32_t type  : 2;
			uint32_t wide  : 1;
			uint32_t index : 29;
		} imm;

		struct {
			uint32_t type  : 2;
			uint32_t index : 30;
		} mem;

		struct {
			uint32_t type  : 2;
			uint32_t index : 30;
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

	struct Operation {
		uint64_t type   : 3;
		uint64_t length : 4;
		uint64_t count  : 3;
		uint64_t index  : 54;
	};

}
