module;
#include <bit>
#include <cstdint>

export module sba.ir:syntax;

import sba.util;

export namespace SBA::IR {

	inline constexpr uint8_t DEFAULT_WIDTH = 64;

	inline constexpr uint8_t INDEX_INS = 32;
	inline constexpr uint8_t INDEX_IMM = 29;
	inline constexpr uint8_t INDEX_AFF = 30;

	inline constexpr uint8_t TYPE_REG = 0;
	inline constexpr uint8_t TYPE_IMM = 1;
	inline constexpr uint8_t TYPE_AFF = 2;

	/* ------------------------------ Register ------------------------------ */

	struct Register {
		uint32_t type    : 2;
		uint32_t index   : 8;
		uint32_t offset  : 9;  /* bits */
		uint32_t length  : 12; /* bits */
		uint32_t negated : 1;

		constexpr Register(
			uint32_t index,
			uint32_t offset = 0,
			uint32_t length = DEFAULT_WIDTH) noexcept
			: type((uint32_t)TYPE_REG),
			  index(index),
			  offset(offset),
			  length(length),
			  negated(0) {}

		constexpr Register() noexcept = default;

		constexpr bool operator==(const Register&) const noexcept = default;

		constexpr Register operator-() const noexcept {
			Register res = *this;
			res.negated = !res.negated;
			return res;
		}

		constexpr Register operator[](uint32_t s, uint32_t e) const noexcept {
			Register res = *this;
			res.offset = s;
			res.length = e - s;
			return res;
		}

		constexpr Register operator[](uint32_t bit) const noexcept {
			return (*this)[bit,bit+1];
		}
	};

	/* ------------------------------- Affine ------------------------------- */

	struct Affine {
		uint64_t deref     : 1;
		uint64_t base      : 8;
		int64_t  disp      : 32; /* bytes */
		uint64_t index     : 8;
		uint64_t shift     : 3;
		uint64_t extra     : 4;
		uint64_t llength_m : 4;  /* log2(bytes) */
		uint64_t llength_a : 3;  /* log2(bytes) */
		uint64_t negated   : 1;

		constexpr Affine(
			uint64_t deref,
			uint64_t base,
			int32_t  disp = 0,
			uint64_t index = 0,
			uint64_t shift = 0,
			uint64_t extra = 0,
			uint64_t length_m = 0,
			uint64_t length_a = DEFAULT_WIDTH,
			uint64_t negated = 0) noexcept
			: deref(deref), base(base), disp(disp),
			  index(index), shift(shift), extra(extra),
			  llength_m(SBA::Util::bits_to_lbytes(length_m)),
			  llength_a(SBA::Util::bits_to_lbytes(length_a)),
			  negated(negated) {}

		constexpr Affine() noexcept = default;

		constexpr bool operator==(const Affine&) const noexcept = default;

		constexpr Affine operator-() const noexcept {
			Affine res = *this;
			res.negated = !res.negated;
			return res;
		}

		constexpr Affine operator[](uint32_t l) const noexcept {
			Affine res = *this;
			if (res.deref)
				res.llength_m = SBA::Util::bits_to_lbytes(l);
			else
				res.llength_a = SBA::Util::bits_to_lbytes(l);
			return res;
		}

		constexpr Affine operator[](uint32_t lm, uint32_t la) const noexcept {
			Affine res = *this;
			res.llength_m = SBA::Util::bits_to_lbytes(lm);
			res.llength_a = SBA::Util::bits_to_lbytes(la);
			return res;
		}
	};

	/* ------------------------------ Operand ------------------------------- */

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

		constexpr Operand() noexcept = default;

		constexpr Operand(Register reg) noexcept : r(reg) {}

		constexpr Operand(Type type, uint32_t index) noexcept
			: a { (uint32_t)type, index } {}

		constexpr Operand(Type type, uint32_t index, bool wide) noexcept
			: i { (uint32_t)type, wide ? 1u : 0u, index } {}

		constexpr Type type() const noexcept { return (Type)r.type; }

		constexpr explicit operator uint32_t() const noexcept {
			return std::bit_cast<uint32_t>(*this);
		}

		constexpr bool operator==(Operand other) const noexcept {
			return (uint32_t)*this == (uint32_t)other;
		}
	};

	/* ---------------------------- Instruction ----------------------------- */

	struct Instruction {
		struct Tag {
			uint8_t tag;
			constexpr Tag(uint8_t raw) noexcept : tag(raw) {}
			constexpr Tag(uint8_t count, uint8_t length) noexcept {
				tag = ((count & 0xf) << 4) | (length & 0xf);
			}
			constexpr operator uint8_t() const noexcept {
				return tag;
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

		uint32_t index: INDEX_INS;

		constexpr explicit Instruction(uint32_t idx) noexcept : index(idx) {}

		constexpr bool operator==(const Instruction&) const noexcept = default;
	};

	/* ----------------------------- Constants ------------------------------ */

	inline constexpr Instruction INVALID_INS = Instruction(0);
	inline constexpr Register    NO_REG      = Register(0);
	inline constexpr Register    ANY_REG     = Register(1);
	inline constexpr Operand     ANY_AFF     = Operand(Operand::Type::AFFINE, 0);
	inline constexpr Operand     ANY_MEM     = Operand(Operand::Type::AFFINE, 1);

}
