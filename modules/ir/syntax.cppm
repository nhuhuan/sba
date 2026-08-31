module;
#include <bit>
#include <cstddef>
#include <cstdint>

export module sba.ir:syntax;

export namespace SBA::IR {

	inline constexpr size_t INST_BITS = 32;
	inline constexpr size_t IMM_BITS  = 29;
	inline constexpr size_t AFF_BITS  = 30;

	struct Register {
		uint32_t type    : 2;
		uint32_t index   : 8;
		uint32_t offset  : 8;
		uint32_t llength : 4;
		uint32_t negated : 1;
		uint32_t         : 9;

		constexpr bool operator==(const Register&) const noexcept = default;
	};

	struct Affine {
		int64_t  displacement : 32;
		uint64_t base         : 8;
		uint64_t index        : 8;
		uint64_t shift        : 3;
		uint64_t extra        : 4;
		uint64_t llength      : 4;
		uint64_t llength_addr : 3;
		uint64_t dereferenced : 1;
		uint64_t negated      : 1;

		constexpr bool operator==(const Affine&) const noexcept = default;
	};

	union Operand {
		enum class Type : uint8_t {
			REGISTER,
			IMMEDIATE,
			AFFINE
		};

		Register r;

		struct {
			uint32_t type  : 2;
			uint32_t wide  : 1;
			uint32_t index : IMM_BITS;
		} i;

		struct {
			uint32_t type  : 2;
			uint32_t index : AFF_BITS;
		} a;

		constexpr Type type() const noexcept {
			return (Type)r.type;
		}

		constexpr explicit operator uint32_t() const noexcept {
			return std::bit_cast<uint32_t>(*this);
		}

		constexpr bool operator==(Operand other) const noexcept {
			return (uint32_t)*this == (uint32_t)other;
		}
	};

	struct Instruction {
		enum class Type : uint8_t {
			STORE,
			SYSCALL,
			FENCE,
			TRAP,
			HALT,
			NOP
		};

		uint32_t index : INST_BITS;

		constexpr bool operator==(const Instruction&) const noexcept = default;
	};

}
