module;
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

export module sba.binary:object;

import :types;
import :error;

export namespace SBA::Binary {

	class Object {
	public:
		Object() = default;
		~Object() = default;

		Arch arch() const { return arch_; }
		OS os() const { return os_; }
		Endian endian() const { return endian_; }
		std::optional<uint64_t> entry() const { return entry_; }
		const std::vector<Segment>& segments() const { return segments_; }
		const std::vector<Symbol>& symbols() const { return symbols_; }
		const std::vector<Export>& exports() const { return exports_; }
		const std::vector<Import>& imports() const { return imports_; }
		const std::vector<Relocation>& relocs() const { return relocs_; }
		std::optional<uint64_t> read(uint64_t addr, uint8_t width) const;

		static const char* triple(Arch arch, OS os);
		std::expected<void, Error> load(const std::string& path);

	private:
		Arch arch_;
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
