module;
#include <cstdint>
#include <expected>
#include <optional>
#include <vector>
#include <llvm/Object/ObjectFile.h>

export module sba.binary:elf;

import :types;
import :error;

export namespace SBA::Binary {

	std::expected<void, Error> parse_elf(
		llvm::object::ObjectFile* object,
		Arch& arch,
		OS& os,
		Endian& endian,
		std::optional<uint64_t>& entry,
		std::vector<Segment>& segments,
		std::vector<Symbol>& symbols,
		std::vector<Export>& exports,
		std::vector<Import>& imports,
		std::vector<Relocation>& relocations
	);

}
