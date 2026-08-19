module;
#include <cstdint>
#include <optional>
#include <llvm/Support/Endian.h>

module sba.binary;

import :types;

namespace SBA::Binary {

	template <typename T>
	static uint64_t read_scalar(const uint8_t* ptr, Endian e)
	{
		return (e == Endian::LITTLE) ?
			llvm::support::endian::read<T, llvm::endianness::little,
										llvm::support::unaligned>(ptr) :
			llvm::support::endian::read<T, llvm::endianness::big,
										llvm::support::unaligned>(ptr);
	}

	std::optional<uint64_t> Segment::read(
		uint64_t addr,
		uint8_t width,
		Endian endian) const
	{
		uint64_t offset = addr - address;

		if (offset + width > size)
			return std::nullopt;

		if (offset >= file_size)
			return 0;

		if (!bytes || offset + width > file_size)
			return std::nullopt;

		const uint8_t* ptr = bytes.get() + offset;

		switch (width) {
			case 1: return *ptr;
			case 2: return read_scalar<uint16_t>(ptr, endian);
			case 4: return read_scalar<uint32_t>(ptr, endian);
			case 8: return read_scalar<uint64_t>(ptr, endian);
			default: return std::nullopt;
		}
	}

	bool Segment::contains(uint64_t addr) const
	{
		return addr >= address && addr < (address + size);
	}

}
