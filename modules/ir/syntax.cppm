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
		uint32_t offset  : 8; /* bytes */
		uint32_t llength : 4; /* log2(bytes) */
		uint32_t negated : 1;
		uint32_t xoffset : 3; /* extra bits */
		uint32_t xlength : 6; /* bits */

		constexpr bool operator==(const Register&) const noexcept = default;

		constexpr uint32_t bit_offset() const noexcept {
			return (offset << 3) | xoffset;
		}

		constexpr uint32_t bit_length() const noexcept {
			return xlength != 0 ? xlength : (8u << llength);
		}
	};

	struct Affine {
		int64_t  displacement : 32;
		uint64_t base         : 8;
		uint64_t index        : 8;
		uint64_t shift        : 3;
		uint64_t extra        : 4;
		uint64_t llength      : 4; /* log2(bytes) */
		uint64_t llength_addr : 3; /* log2(bytes) */
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
		struct Tag {
			uint8_t tag;
			constexpr Tag(uint8_t raw) noexcept : tag(raw) {}
			constexpr Tag(uint8_t count, uint8_t length) noexcept {
				tag = ((count & 0xf) << 4) | (length & 0xf);
			}
			constexpr uint8_t count() const noexcept {
				return (tag >> 4) & 0xf;
			}
			constexpr uint8_t length() const noexcept {
				return tag & 0xf;
			}
			constexpr bool valid() const noexcept {
				return length() != 0;
			}
		};

		uint32_t index: REFERENCE_INST;

		constexpr bool operator==(const Instruction&) const noexcept = default;
	};

}
