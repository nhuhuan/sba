module;
#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>

export module sba.ir:syntax;

import sba.util;

export namespace SBA::IR {

	inline constexpr size_t INDEX_INST = 32;
	inline constexpr size_t INDEX_IMM  = 29;
	inline constexpr size_t INDEX_AFF  = 30;

	inline constexpr uint8_t TYPE_REG = 0;
	inline constexpr uint8_t TYPE_IMM = 1;
	inline constexpr uint8_t TYPE_AFF = 2;

	struct Register {
		uint32_t type    : 2;
		uint32_t index   : 8;
		uint32_t offset  : 9;  /* bits */
		uint32_t length  : 12; /* bits */
		uint32_t negated : 1;

		constexpr Register(
			uint32_t index,
			uint32_t offset = 0,
			uint32_t length = 64) noexcept
			: type((uint32_t)TYPE_REG),
			  index(index),
			  offset(offset),
			  length(length),
			  negated(0) {}

		constexpr Register() noexcept = default;

		constexpr bool operator==(const Register&) const noexcept = default;
	};

	struct Affine {
		uint64_t dereferenced : 1;
		uint64_t base         : 8;
		int64_t  displacement : 32; /* bytes */
		uint64_t index        : 8;
		uint64_t shift        : 3;
		uint64_t extra        : 4;
		uint64_t llength_m    : 4;  /* log2(bytes) */
		uint64_t llength_a    : 3;  /* log2(bytes) */
		uint64_t negated      : 1;

		constexpr Affine(
			uint64_t dereferenced,
			uint64_t base,
			int64_t  displacement,
			uint64_t index,
			uint64_t shift = 0,
			uint64_t extra = 0,
			uint64_t length_m = 0,
			uint64_t length_a = 64,
			uint64_t negated = 0) noexcept
			: dereferenced(dereferenced),
			  base(base),
			  displacement(displacement),
			  index(index),
			  shift(shift),
			  extra(extra),
			  llength_m(SBA::Util::bits_to_lbytes(length_m)),
			  llength_a(SBA::Util::bits_to_lbytes(length_a)),
			  negated(negated) {}

		constexpr Affine() noexcept = default;

		constexpr bool operator==(const Affine&) const noexcept = default;
	};

	union Operand {
		enum class Type : uint8_t {
			REGISTER  = TYPE_REG,
			IMMEDIATE = TYPE_IMM,
			AFFINE    = TYPE_AFF
		};

		Register r;

		struct {
			uint32_t type  : 2;
			uint32_t wide  : 1;
			uint32_t index : INDEX_IMM;
		} i;

		struct {
			uint32_t type  : 2;
			uint32_t index : INDEX_AFF;
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

		uint32_t index: INDEX_INST;

		constexpr bool operator==(const Instruction&) const noexcept = default;
	};

}
