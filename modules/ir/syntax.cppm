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
			uint32_t ext   : 1;
			uint32_t index : 29;
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
		int32_t  displacement;
		uint16_t base;
		uint8_t  llength      : 4;
		uint8_t  llength_addr : 4;

		constexpr bool operator==(const Memory& other) const noexcept {
			return displacement == other.displacement &&
				   base == other.base &&
				   llength == other.llength &&
				   llength_addr == other.llength_addr;
		}
	};

	struct MemoryExt {
		int32_t  displacement;
		uint16_t base;
		uint16_t index;
		uint16_t segment;
		uint8_t  scale;
		uint8_t  llength      : 4;
		uint8_t  llength_addr : 4;

		constexpr bool operator==(const MemoryExt& other) const noexcept {
			return displacement == other.displacement &&
				   base == other.base &&
				   index == other.index &&
				   segment == other.segment &&
				   scale == other.scale &&
				   llength == other.llength &&
				   llength_addr == other.llength_addr;
		}
	};

	struct Operation {
		uint64_t type   : 3;
		uint64_t length : 4;
		uint64_t count  : 3;
		uint64_t index  : 54;
	};

}
