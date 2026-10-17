module;
#include <bit>
#include <cstdint>

export module sba.util:bits;

export namespace SBA::Util {

	template <typename T = int64_t>
	inline constexpr T bits_to_bytes(uint32_t bits) noexcept {
		return static_cast<T>(bits / 8);
	}

	template <typename T = int64_t>
	inline constexpr T bytes_to_bits(uint32_t bytes) noexcept {
		return static_cast<T>(bytes * 8);
	}

	template <typename T = int64_t>
	inline constexpr T lbytes_to_bytes(uint32_t lbytes) noexcept {
		return static_cast<T>(1) << lbytes;
	}

	template <typename T = int64_t>
	inline constexpr T lbytes_to_bits(uint32_t lbytes) noexcept {
		return static_cast<T>(8) << lbytes;
	}

	inline constexpr uint32_t bits_to_lbytes(uint32_t bits) noexcept {
		return (uint32_t)std::countr_zero(bits / 8);
	}

}
