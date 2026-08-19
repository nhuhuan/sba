module;
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

export module sba.binary:types;

export namespace SBA::Binary {

	enum class Endian : uint8_t {
		LITTLE,
		BIG
	};

	enum class Arch : uint8_t {
		X86_64,
		AARCH64,
		UNKNOWN
	};

	enum class OS : uint8_t {
		LINUX,
		WINDOWS,
		DARWIN,
		UNKNOWN
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
		uint64_t	address;
		uint64_t	size;
		uint64_t	file_size;
		uint8_t		flags;
		std::unique_ptr<uint8_t[]> bytes;

		bool executable() const { return flags & EXECUTABLE; }
		bool writable()   const { return flags & WRITABLE; }
		bool readable()   const { return flags & READABLE; }

		bool contains(uint64_t addr) const;
		std::optional<uint64_t>
			read(uint64_t addr, uint8_t width, Endian endian) const;
	};

	struct Symbol {
		uint64_t	address;
		uint64_t	size;
		SymbolType	type;
		SymbolBind	bind;
		SymbolScope	scope;
		SymbolMode	mode;
		std::string	name;
	};

	struct Export : public Symbol {
		uint32_t	ordinal = 0;
		std::string	forward_library;
		std::string	forward_symbol;
	};

	struct Import : public Symbol {
		uint32_t	ordinal = 0;
		std::string	library_name;
	};

	struct Relocation {
		uint64_t	address;
		uint64_t	target;
		int64_t		addend;
		uint32_t	type;
		std::string	name;
	};

}
