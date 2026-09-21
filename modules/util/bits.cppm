module;
#include <cstdint>

export module sba.util:bits;

export namespace SBA::Util {


	template <typename T = uint64_t>
	inline constexpr T bytes(uint8_t llength) noexcept {
		return static_cast<T>(1) << llength;
	}

	template <typename T = uint64_t>
	inline constexpr T bits(uint8_t llength) noexcept {
		return static_cast<T>(8) << llength;
	}

}
