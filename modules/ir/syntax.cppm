module;
#include <bit>
#include <cstddef>
#include <cstdint>

export module sba.ir:syntax;

export namespace SBA::IR {

	inline constexpr size_t REFERENCE_INST = 32;
	inline constexpr size_t REFERENCE_IMM  = 29;
	inline constexpr size_t REFERENCE_AFF  = 30;

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
			uint32_t index : REFERENCE_IMM;
		} i;

		struct {
			uint32_t type  : 2;
			uint32_t index : REFERENCE_AFF;
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
			NOP,
			INVALID
		};

		struct Tag {
			uint8_t tag;

			constexpr Tag(uint8_t raw) noexcept : tag(raw) {}

			constexpr Tag(
				Instruction::Type type,
				uint8_t count,
				uint8_t length) noexcept
			{
				auto t = (type != Instruction::Type::STORE) ?
						 ((uint8_t)type | 0x8) : (count & 0x7);
				tag = (t << 4) | (length & 0xf);
			}

			constexpr Instruction::Type type() const noexcept {
				uint8_t t = tag >> 4;
				return (t & 0x8) ?
					   (Instruction::Type)(t & 0x7) : Instruction::Type::STORE;
			}

			constexpr uint8_t count() const noexcept {
				uint8_t t = tag >> 4;
				return (t & 0x8) ? 0 : (t & 0x7);
			}

			constexpr uint8_t length() const noexcept {
				return tag & 0xf;
			}
		};

		uint32_t index: REFERENCE_INST;

		constexpr bool operator==(const Instruction&) const noexcept = default;
	};

}
