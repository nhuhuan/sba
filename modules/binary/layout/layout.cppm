module;
#include <string>
#include <cstdint>
#include <span>

export module sba.binary.layout;

export namespace SBA::Binary {

	enum class Endian {
		LITTLE,
		BIG
	};

	enum SegmentFlag : uint8_t {
		EXECUTABLE = 1 << 0,
		WRITABLE   = 1 << 1,
		READABLE   = 1 << 2
	};

	enum class SymbolType : uint8_t {
		FUNCTION,
		OBJECT,
		THREAD_LOCAL,
		IFUNC,
		NOTYPE
	};

	enum class SymbolBind : uint8_t {
		LOCAL,
		GLOBAL,
		WEAK
	};

	enum class SymbolScope : uint8_t {
		PRIVATE,
		PUBLIC,
		FINAL
	};

	enum class SymbolMode : uint8_t {
		RELATIVE,
		ABSOLUTE,
		UNDEFINED,
		UNALLOCATED
	};

	struct Segment {
		uint64_t		address;
		uint64_t		size;
		uint64_t		file_size;
		uint8_t			flags;
		std::span<const uint8_t> bytes;
	};

	struct Symbol {
		uint64_t		address;
		uint64_t		size;
		SymbolType		type;
		SymbolBind		bind;
		SymbolScope		scope;
		SymbolMode		mode;
		std::string		name;
	};

	struct Export : public Symbol {
		uint32_t		ordinal = 0;
		std::string		forward_library_name;
		std::string		forward_symbol_name;
	};

	struct Import : public Symbol {
		uint32_t		ordinal = 0;
		std::string		library_name;
	};

	struct Relocation {
		uint64_t		address;
		uint64_t		target;
		int64_t			offset;
		uint32_t		type;
		std::string		name;
	};

}
