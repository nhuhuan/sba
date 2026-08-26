module;
#include <cstdint>

export module sba.arch;

export import :x86_64;

export namespace SBA::Arch {

	enum class Target : uint8_t {
		X86_64,
		AArch64,
		Unknown
	};

}
