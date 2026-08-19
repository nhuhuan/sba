module;
#include <cstdint>
#include <cstddef>
#include <cstring>

export module sba.util:wyhash;

namespace SBA::Util {

	[[nodiscard]]
	inline constexpr uint64_t wyhash_mum(uint64_t A, uint64_t B) noexcept
	{
#if defined(__SIZEOF_INT128__)
		__uint128_t r = A;
		r *= B;
		return static_cast<uint64_t>(r) ^ static_cast<uint64_t>(r >> 64);
#else
		uint64_t ha = A >> 32, la = static_cast<uint32_t>(A);
		uint64_t hb = B >> 32, lb = static_cast<uint32_t>(B);
		uint64_t rh = ha * hb, rm0 = ha * lb, rm1 = la * hb, rl = la * lb;
		uint64_t t = rl + (rm0 << 32);
		uint64_t carry = t < rl;
		uint64_t lo = t + (rm1 << 32);
		carry += lo < t;
		uint64_t hi = rh + (rm0 >> 32) + (rm1 >> 32) + carry;
		return lo ^ hi;
#endif
	}

	[[nodiscard]]
	inline uint64_t wyhash_read4(const uint8_t* p) noexcept
	{
		uint32_t v;
		std::memcpy(&v, p, 4);
		return v;
	}

	[[nodiscard]]
	inline uint64_t wyhash_read8(const uint8_t* p) noexcept
	{
		uint64_t v;
		std::memcpy(&v, p, 8);
		return v;
	}

}

export namespace SBA::Util {

	[[nodiscard]]
	inline uint64_t wyhash(
		const void* key,
		size_t len,
		uint64_t seed = 0) noexcept
	{
		const uint8_t* p = static_cast<const uint8_t*>(key);
		static constexpr uint64_t secret[4] = {
			0xa0761d6478bd642fULL,
			0xe7037ed1a0b428dbULL,
			0x8ebc6af09c88c6e3ULL,
			0x589965cc75374cc3ULL
		};

		seed ^= wyhash_mum(seed ^ secret[0], secret[1]);
		uint64_t a = 0, b = 0;

		if (len <= 16) {
			if (len >= 4) {
				a = (wyhash_read4(p) << 32)
				  | wyhash_read4(p + ((len >> 3) << 2));
				b = (wyhash_read4(p + len - 4) << 32)
				  | wyhash_read4(p + len - 4 - ((len >> 3) << 2));
			} else if (len > 0) {
				a = (static_cast<uint64_t>(p[0]) << 16)
				  | (static_cast<uint64_t>(p[len >> 1]) << 8)
				  | p[len - 1];
				b = 0;
			} else
				a = b = 0;
		} else {
			size_t i = len;
			if (i > 48) {
				uint64_t seed1 = seed, seed2 = seed;
				do {
					seed = wyhash_mum(
						wyhash_read8(p) ^ secret[1],
						wyhash_read8(p + 8) ^ seed
					);
					seed1 = wyhash_mum(
						wyhash_read8(p + 16) ^ secret[2],
						wyhash_read8(p + 24) ^ seed1
					);
					seed2 = wyhash_mum(
						wyhash_read8(p + 32) ^ secret[3],
						wyhash_read8(p + 40) ^ seed2
					);
					p += 48;
					i -= 48;
				} while (i > 48);
				seed ^= seed1 ^ seed2;
			}
			while (i > 16) {
				seed = wyhash_mum(
					wyhash_read8(p) ^ secret[1],
					wyhash_read8(p + 8) ^ seed
				);
				p += 16;
				i -= 16;
			}
			a = wyhash_read8(p + i - 16);
			b = wyhash_read8(p + i - 8);
		}

		return wyhash_mum(
			secret[1] ^ len,
			wyhash_mum(a ^ secret[1], b ^ seed)
		);
	}

}
