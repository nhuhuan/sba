module;
#include <vector>
#include <expected>
#include <cstring>
#include <memory>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/Endian.h>
#include <llvm/BinaryFormat/ELF.h>
#include <llvm/ADT/iterator_range.h>

module sba.binary;

import :elf;
import :types;
import :error;

namespace SBA::Binary {

	template <typename ELFT>
	static std::expected<void, Error> parse_segments(
		const llvm::object::ELFFile<ELFT>& elf,
		std::vector<Segment>& out)
	{
		auto phdrs = elf.program_headers();
		if (!phdrs) {
			llvm::consumeError(phdrs.takeError());
			return std::unexpected(Error::INVALID_SEGMENT);
		}

		out.reserve(phdrs->size());
		for (const auto& phdr : *phdrs) {
			if (phdr.p_type != llvm::ELF::PT_LOAD)
			   continue;

			auto contents = elf.getSegmentContents(phdr);
			if (!contents) {
				llvm::consumeError(contents.takeError());
				return std::unexpected(Error::INVALID_SEGMENT);
			}

			auto flags = ((phdr.p_flags & llvm::ELF::PF_X) ?
								SegmentFlag::EXECUTABLE : 0) |
						 ((phdr.p_flags & llvm::ELF::PF_W) ?
								SegmentFlag::WRITABLE   : 0) |
						 ((phdr.p_flags & llvm::ELF::PF_R) ?
								SegmentFlag::READABLE   : 0);

			auto bytes = std::make_unique<uint8_t[]>(phdr.p_filesz);
			std::memcpy(bytes.get(), contents->begin(), phdr.p_filesz);

			out.push_back(Segment{
				(uint64_t)phdr.p_vaddr,
				(uint64_t)phdr.p_memsz,
				(uint64_t)phdr.p_filesz,
				(uint8_t)flags,
				std::move(bytes)
			});
		}

		return {};
	}

	static SymbolMode symbol_mode(const llvm::object::ELFSymbolRef& sym)
	{
		switch (sym.getRawDataRefImpl().d.b) {
			case llvm::ELF::SHN_UNDEF:  return SymbolMode::UNDEFINED;
			case llvm::ELF::SHN_ABS:    return SymbolMode::ABSOLUTE;
			case llvm::ELF::SHN_COMMON: return SymbolMode::UNALLOCATED;
			default:                    return SymbolMode::RELATIVE;
		}
	}

	static std::expected<Symbol, Error> symbol(
		const llvm::object::SymbolRef& symref,
		bool strict = false)
	{
		std::string name;
		auto exp_name = symref.getName();
		if (!exp_name) {
			llvm::consumeError(exp_name.takeError());
			if (strict)
				return std::unexpected(Error::INVALID_SYMBOL);
		}
		else
			name = exp_name->str();

		auto exp_addr = symref.getAddress();
		if (!exp_addr) {
			llvm::consumeError(exp_addr.takeError());
			return std::unexpected(Error::INVALID_SYMBOL);
		}

		auto exp_type = symref.getType();
		if (!exp_type) {
			llvm::consumeError(exp_type.takeError());
			return std::unexpected(Error::INVALID_SYMBOL);
		}

		llvm::object::ELFSymbolRef sym(symref);

		SymbolType type = SymbolType::NOTYPE;
		if (*exp_type == llvm::object::SymbolRef::ST_Function)
			type = SymbolType::FUNCTION;
		else if (*exp_type == llvm::object::SymbolRef::ST_Data)
			type = SymbolType::OBJECT;
		else if (sym.getOther() & llvm::ELF::STT_TLS)
			type = SymbolType::THREAD_LOCAL;
		else if (sym.getELFType() == llvm::ELF::STT_GNU_IFUNC)
			type = SymbolType::IFUNC;

		SymbolBind bind;
		switch (sym.getBinding()) {
			case llvm::ELF::STB_GLOBAL:
				bind = SymbolBind::GLOBAL;	break;
			case llvm::ELF::STB_WEAK:
				bind = SymbolBind::WEAK;	break;
			default:
				bind = SymbolBind::LOCAL;	break;
		}

		SymbolScope scope;
		switch (sym.getOther() & 0x3) {
			case llvm::ELF::STV_HIDDEN:
				scope = SymbolScope::PRIVATE;	break;
			case llvm::ELF::STV_PROTECTED:
				scope = SymbolScope::FINAL;		break;
			default:
				scope = SymbolScope::PUBLIC;	break;
		}

		return Symbol {
			*exp_addr,
			sym.getSize(),
			type,
			bind,
			scope,
			symbol_mode(sym),
			std::move(name)
		};
	}

	template <typename ELFT>
	static std::expected<void, Error> parse_dynamic_symbols(
		llvm::object::ELFObjectFile<ELFT>* obj,
		std::vector<Export>& exports,
		std::vector<Import>& imports)
	{
		for (const auto& symref :
				llvm::make_range(obj->dynamic_symbol_begin(),
								 obj->dynamic_symbol_end())) {
			auto exp_sym = symbol(symref, true);
			if (!exp_sym)
				return std::unexpected(exp_sym.error());

			auto& sym = *exp_sym;
			if (sym.name.empty())
				continue;

			if (sym.mode == SymbolMode::UNDEFINED)
				imports.push_back(Import{std::move(sym), 0, ""});
			else if (sym.bind != SymbolBind::LOCAL)
				exports.push_back(Export{std::move(sym), 0, "", ""});
		}

		return {};
	}

	template <typename ELFT>
	static void parse_symbol_table(
		llvm::object::ELFObjectFile<ELFT>* obj,
		std::vector<Symbol>& out)
	{
		for (const auto& symref : obj->symbols()) {
			auto exp_sym = symbol(symref);
			if (!exp_sym)
				continue;

			auto& sym = *exp_sym;
			if (sym.name.empty())
				continue;

			if (sym.mode == SymbolMode::UNDEFINED)
				continue;

			out.push_back(std::move(sym));
		}
	}

	template <typename ELFT>
	static std::expected<void, Error> parse_relocations(
		const llvm::object::ELFObjectFile<ELFT>* obj,
		Endian endian,
		const std::vector<Segment>& segments,
		std::vector<Relocation>& out)
	{
		const llvm::object::ObjectFile* generic_obj = obj;
		for (const auto& sec : generic_obj->dynamic_relocation_sections()) {
			for (const auto& rel : sec.relocations()) {
				uint64_t target = 0;
				std::string name;

				auto symref = rel.getSymbol();
				if (symref != generic_obj->symbol_end()) {
					auto exp_sym = symbol(*symref);
					if (!exp_sym)
						return std::unexpected(exp_sym.error());

					target = exp_sym->address;
					name = std::move(exp_sym->name);
				}

				int64_t addend = 0;
				auto exp_addend = obj->getRelocationAddend(rel.getRawDataRefImpl());
				if (!exp_addend) {
					uint64_t offset = rel.getOffset();
					uint8_t width = ELFT::Is64Bits ? 8 : 4;

					for (const auto& seg : segments)
						if (seg.contains(offset)) {
							auto val = seg.read(offset, width, endian);
							if (!val)
								return std::unexpected(Error::INVALID_RELOCATION);

							switch (width) {
								case 1:  addend = (int8_t)*val;  break;
								case 2:  addend = (int16_t)*val; break;
								case 4:  addend = (int32_t)*val; break;
								case 8:  addend = (int64_t)*val; break;
								default: break;
							}
							break;
						}

					llvm::consumeError(exp_addend.takeError());
				}
				else
					addend = *exp_addend;

				out.push_back({
					rel.getOffset(),
					target,
					addend,
					(uint32_t)rel.getType(),
					std::move(name)
				});
			}
		}
		return {};
	}

	static void parse_arch(const llvm::object::ObjectFile* obj, Target& arch)
	{
		auto llvm_arch = obj->getArch();
		switch (llvm_arch) {
			case llvm::Triple::x86_64:
				arch = Target::X86_64;
				break;
			case llvm::Triple::aarch64:
				arch = Target::AArch64;
				break;
			default:
				arch = Target::Unknown;
				break;
		}
	}

	static void parse_os(const llvm::object::ObjectFile* obj, OS& os)
	{
		auto triple = obj->makeTriple();
		if (triple.isOSLinux())
			os = OS::LINUX;
		else if (triple.isOSWindows())
			os = OS::WINDOWS;
		else if (triple.isOSDarwin())
			os = OS::DARWIN;
		else
			os = OS::UNKNOWN;
	}

	static void parse_endian(const llvm::object::ObjectFile* obj,
							 Endian& endian)
	{
		endian = obj->isLittleEndian() ? Endian::LITTLE : Endian::BIG;
	}

	template <typename ELFT>
	static void parse_entry(const llvm::object::ELFObjectFile<ELFT>* obj,
							std::optional<uint64_t>& entry)
	{
		auto e_entry = obj->getELFFile().getHeader().e_entry;
		if (e_entry != 0)
			entry = e_entry;
	}

	template <typename ELFT>
	static std::expected<void, Error> parse_elf(
		llvm::object::ELFObjectFile<ELFT>* object,
		Target& arch,
		OS& os,
		Endian& endian,
		std::optional<uint64_t>& entry,
		std::vector<Segment>& segments,
		std::vector<Symbol>& symbols,
		std::vector<Export>& exports,
		std::vector<Import>& imports,
		std::vector<Relocation>& relocs)
	{
		parse_arch(object, arch);

		parse_os(object, os);

		parse_endian(object, endian);

		parse_entry(object, entry);

		parse_symbol_table(object, symbols);

		if (auto err = parse_segments(object->getELFFile(), segments); !err)
			return err;

		if (auto err = parse_dynamic_symbols(object, exports, imports); !err)
			return err;

		if (auto err = parse_relocations(object, endian, segments, relocs); !err)
			return err;

		return {};
	}

	std::expected<void, Error> parse_elf(
		llvm::object::ObjectFile* object,
		Target& arch,
		OS& os,
		Endian& endian,
		std::optional<uint64_t>& entry,
		std::vector<Segment>& segments,
		std::vector<Symbol>& symbols,
		std::vector<Export>& exports,
		std::vector<Import>& imports,
		std::vector<Relocation>& relocs)
	{
		if (auto* obj = llvm::dyn_cast<llvm::object::ELF64LEObjectFile>(object))
			return parse_elf(obj, arch, os, endian, entry, segments,
							 symbols, exports, imports, relocs);
		if (auto* obj = llvm::dyn_cast<llvm::object::ELF64BEObjectFile>(object))
			return parse_elf(obj, arch, os, endian, entry, segments,
							 symbols, exports, imports, relocs);
		if (auto* obj = llvm::dyn_cast<llvm::object::ELF32LEObjectFile>(object))
			return parse_elf(obj, arch, os, endian, entry, segments,
							 symbols, exports, imports, relocs);
		if (auto* obj = llvm::dyn_cast<llvm::object::ELF32BEObjectFile>(object))
			return parse_elf(obj, arch, os, endian, entry, segments,
							 symbols, exports, imports, relocs);

		return std::unexpected(Error::INVALID_FORMAT);
	}

}
