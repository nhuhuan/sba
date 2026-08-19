module;
#include <cstdint>

export module sba.binary:error;

export namespace SBA::Binary {

	enum class Error : uint8_t {
		INVALID_FORMAT,
		INVALID_SEGMENT,
		INVALID_SYMBOL,
		INVALID_RELOCATION,
		INVALID_ENTRY
	};

}
