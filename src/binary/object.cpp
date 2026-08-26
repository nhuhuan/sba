module;
#include <algorithm>
#include <cstdint>
#include <expected>
#include <optional>
#include <llvm/Object/Binary.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/Error.h>

module sba.binary;

import :object;
import :elf;

namespace SBA::Binary {

	static thread_local const Segment* tls_last_segment = nullptr;

	static const Segment* find_segment(const Object* obj, uint64_t addr)
	{
		if (tls_last_segment && tls_last_segment->contains(addr))
			return tls_last_segment;

		const auto& segs = obj->segments();
		auto it = std::lower_bound(segs.begin(), segs.end(), addr,
			[](const Segment& s, uint64_t val) {
				return s.address + s.size <= val;
			});

		if (it != segs.end() && it->contains(addr)) {
			tls_last_segment = &(*it);
			return tls_last_segment;
		}

		return nullptr;
	}

	std::expected<void, Error> Object::load(const std::string& path)
	{
		auto bin = llvm::object::createBinary(path);
		if (!bin) {
			llvm::consumeError(bin.takeError());
			return std::unexpected(Error::INVALID_FORMAT);
		}

		auto* generic_bin = bin.get().getBinary();
		auto* obj = llvm::dyn_cast<llvm::object::ObjectFile>(generic_bin);
		if (obj && obj->isELF()) {
			if (auto err = parse_elf(obj, arch_, os_, endian_,
									 entry_, segments_, symbols_,
									 exports_, imports_, relocs_);
			!err)
				return err;
			return validate();
		}

		return std::unexpected(Error::INVALID_FORMAT);
	}

	std::optional<uint64_t> Object::read(uint64_t addr, uint8_t width) const
	{
		const Segment* seg = find_segment(this, addr);

		if (!seg) [[unlikely]]
			return std::nullopt;

		return seg->read(addr, width, endian_);
	}

	std::expected<void, Error> Object::validate()
	{
		if (entry_ && !find_segment(this, *entry_))
			return std::unexpected(Error::INVALID_ENTRY);

		for (const auto& sym : symbols_)
			if (sym.mode != SymbolMode::UNALLOCATED &&
				sym.mode != SymbolMode::ABSOLUTE &&
				sym.mode != SymbolMode::UNDEFINED &&
				!find_segment(this, sym.address))
					return std::unexpected(Error::INVALID_SYMBOL);

		for (const auto& sym : exports_)
			if (sym.mode != SymbolMode::UNALLOCATED &&
				sym.mode != SymbolMode::ABSOLUTE &&
				!find_segment(this, sym.address))
					return std::unexpected(Error::INVALID_SYMBOL);

		auto& segs = segments_;
		std::sort(segs.begin(), segs.end(), [](const auto& a, const auto& b) {
			return a.address < b.address;
		});
		for (size_t i = 0; i + 1 < segs.size(); ++i)
			if (segs[i].address + segs[i].size > segs[i + 1].address)
				return std::unexpected(Error::INVALID_SEGMENT);

		return {};
	}

	const char* Object::triple() const
	{
		switch (arch_) {
			case Target::X86_64:
				switch (os_) {
					case OS::LINUX:   return "x86_64-pc-linux-gnu";
					case OS::WINDOWS: return "x86_64-w64-windows-gnu";
					case OS::DARWIN:  return "x86_64-apple-darwin";
					default:          return "";
				}
			case Target::AArch64:
				switch (os_) {
					case OS::LINUX:   return "aarch64-unknown-linux-gnu";
					case OS::WINDOWS: return "aarch64-pc-win32-coff";
					case OS::DARWIN:  return "aarch64-apple-darwin";
					default:          return "";
				}
			default:
				return "";
		}
	}

}
