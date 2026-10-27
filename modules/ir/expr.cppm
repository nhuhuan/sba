module;
#include <concepts>
#include <cstdint>
#include <type_traits>

export module sba.ir:expr;

import sba.util;
import :syntax;

export namespace SBA::IR {

	/* ----------------------------- Operators ------------------------------ */

	constexpr Affine operator+(Register r, int32_t d) noexcept {
		return Affine(0, r.index, d * (r.negated ? -1 : 1), NO_REG.index, 0,
					  0, 0, DEFAULT_WIDTH, r.negated);
	}

	constexpr Affine operator-(Register r, int32_t d) noexcept {
		return r + (-d);
	}

	constexpr Affine operator+(int32_t d, Register r) noexcept {
		return r + d;
	}

	constexpr Affine operator-(int32_t d, Register r) noexcept {
		return -(r - d);
	}

	constexpr Affine operator+(Affine a, int32_t d) noexcept {
		a.disp += d * (a.negated ? -1 : 1);
		return a;
	}

	constexpr Affine operator-(Affine a, int32_t d) noexcept {
		return a + (-d);
	}

	constexpr Affine operator+(int32_t d, Affine a) noexcept {
		return a + d;
	}

	constexpr Affine operator-(int32_t d, Affine a) noexcept {
		return -(a - d);
	}

	constexpr Affine operator<<(Register r, uint8_t s) noexcept {
		return Affine(0, NO_REG.index, 0, r.index, s,
					  0, 0, DEFAULT_WIDTH, r.negated);
	}

	constexpr Affine operator+(Register r, Affine a) noexcept {
		if (r.negated == a.negated) {
			if (a.base == NO_REG.index)
				a.base = r.index;
			else if (a.index == NO_REG.index && a.shift == 0)
				a.index = r.index;
			else
				a = Affine(0, ANY_REG.index);
		}
		else {
			if (a.base == r.index)
				a.base = NO_REG.index;
			else if (a.index == r.index && a.shift == 0)
				a.index = NO_REG.index;
			else
				a = Affine(0, ANY_REG.index);
		}
		return a;
	}

	constexpr Affine operator-(Register r, Affine a) noexcept {
		return r + (-a);
	}

	constexpr Affine operator+(Affine a, Register r) noexcept {
		return r + a;
	}

	constexpr Affine operator-(Affine a, Register r) noexcept {
		return -(r - a);
	}

	constexpr Affine operator+(Register r1, Register r2) noexcept {
		if (r1.negated == r2.negated)
			return Affine(0, r1.index, 0, r2.index, 0,
						  0, 0, DEFAULT_WIDTH, r1.negated);
		return r1.index == r2.index
			? Affine(0, NO_REG.index)
			: Affine(0, ANY_REG.index);
	}

	constexpr Affine operator-(Register r1, Register r2) noexcept {
		return r1 + (-r2);
	}

	/* ---------------------------------------------------------------------- */

	template <typename T>
	concept RegEnum = std::is_enum_v<T>;

	constexpr Affine operator+(RegEnum auto r, int32_t d) noexcept {
		return Register((uint8_t)r) + d;
	}

	constexpr Affine operator-(RegEnum auto r, int32_t d) noexcept {
		return Register((uint8_t)r) - d;
	}

	constexpr Affine operator+(int32_t d, RegEnum auto r) noexcept {
		return d + Register((uint8_t)r);
	}

	constexpr Affine operator-(int32_t d, RegEnum auto r) noexcept {
		return d - Register((uint8_t)r);
	}

	constexpr Affine operator<<(RegEnum auto r, uint8_t s) noexcept {
		return Register((uint8_t)r) << s;
	}

	constexpr Affine operator+(RegEnum auto r, Affine a) noexcept {
		return Register((uint8_t)r) + a;
	}

	constexpr Affine operator-(RegEnum auto r, Affine a) noexcept {
		return Register((uint8_t)r) - a;
	}

	constexpr Affine operator+(Affine a, RegEnum auto r) noexcept {
		return a + Register((uint8_t)r);
	}

	constexpr Affine operator-(Affine a, RegEnum auto r) noexcept {
		return a - Register((uint8_t)r);
	}

	constexpr Affine operator+(RegEnum auto r1, RegEnum auto r2) noexcept {
		return Register((uint8_t)r1) + Register((uint8_t)r2);
	}

	constexpr Affine operator-(RegEnum auto r1, RegEnum auto r2) noexcept {
		return Register((uint8_t)r1) - Register((uint8_t)r2);
	}

	constexpr Affine operator+(RegEnum auto r1, Register r2) noexcept {
		return Register((uint8_t)r1) + r2;
	}

	constexpr Affine operator-(RegEnum auto r1, Register r2) noexcept {
		return Register((uint8_t)r1) - r2;
	}

	constexpr Affine operator+(Register r1, RegEnum auto r2) noexcept {
		return r1 + Register((uint8_t)r2);
	}

	constexpr Affine operator-(Register r1, RegEnum auto r2) noexcept {
		return r1 - Register((uint8_t)r2);
	}

}
