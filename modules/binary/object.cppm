module;
#include <cstdint>
#include <expected>
#include <optional>
#include <string_view>
#include <vector>

export module sba.binary:object;

import sba.arch;
import :types;
import :error;

export namespace SBA::Binary {

	using SBA::Arch::Target;

	class Object {
	public:
		Object() = default;
		~Object() = default;

		Target arch() const { return arch_; }
		OS os() const { return os_; }
		Endian endian() const { return endian_; }
		std::optional<uint64_t> entry() const { return entry_; }
		const std::vector<Segment>& segments() const { return segments_; }
		const std::vector<Symbol>& symbols() const { return symbols_; }
		const std::vector<Export>& exports() const { return exports_; }
		const std::vector<Import>& imports() const { return imports_; }
		const std::vector<Relocation>& relocs() const { return relocs_; }

		const char* triple() const;
		std::optional<uint64_t> read(uint64_t addr, uint8_t width) const;
		std::expected<void, Error> load(std::string_view path);

	private:
		Target arch_;
		OS os_;
		Endian endian_;
		std::optional<uint64_t> entry_;
		std::vector<Segment> segments_;
		std::vector<Symbol> symbols_;
		std::vector<Export> exports_;
		std::vector<Import> imports_;
		std::vector<Relocation> relocs_;

		std::expected<void, Error> validate();
	};

}
