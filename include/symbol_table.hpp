#pragma once

#include "die_parser.hpp"
#include "demangler.hpp"
#include <elfio/elfio.hpp>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>

namespace dwarf {

// Forward declarations
class DwarfParser;

// ELF symbol binding
enum class SymbolBinding : uint8_t {
    LOCAL = 0,      // STB_LOCAL
    GLOBAL = 1,     // STB_GLOBAL
    WEAK = 2        // STB_WEAK
};

// ELF symbol type
enum class SymbolType : uint8_t {
    NOTYPE = 0,     // STT_NOTYPE
    OBJECT = 1,     // STT_OBJECT (data object)
    FUNC = 2,       // STT_FUNC (function)
    SECTION = 3,    // STT_SECTION
    FILE = 4,       // STT_FILE
    COMMON = 5,     // STT_COMMON
    TLS = 6         // STT_TLS (thread-local storage)
};

// ELF symbol visibility
enum class SymbolVisibility : uint8_t {
    DEFAULT = 0,    // STV_DEFAULT
    INTERNAL = 1,   // STV_INTERNAL
    HIDDEN = 2,     // STV_HIDDEN
    PROTECTED = 3   // STV_PROTECTED
};

// Represents an ELF symbol
struct Symbol {
    std::string name;               // Symbol name (raw)
    std::string demangled_name;     // Demangled name (for C++)
    uint64_t address = 0;           // Symbol value (address)
    uint64_t size = 0;              // Symbol size
    SymbolBinding binding = SymbolBinding::LOCAL;
    SymbolType type = SymbolType::NOTYPE;
    SymbolVisibility visibility = SymbolVisibility::DEFAULT;
    uint16_t section_index = 0;     // Section this symbol is in
    std::string section_name;       // Section name
    bool is_defined = false;        // Whether symbol is defined (not UND)
    bool is_dynamic = false;        // From .dynsym (dynamic symbol table)

    // DWARF linkage (if available)
    std::shared_ptr<DIE> dwarf_die; // Associated DWARF DIE
    bool has_dwarf_info = false;

    // Helper methods
    bool isFunction() const { return type == SymbolType::FUNC; }
    bool isObject() const { return type == SymbolType::OBJECT; }
    bool isGlobal() const { return binding == SymbolBinding::GLOBAL; }
    bool isWeak() const { return binding == SymbolBinding::WEAK; }
    bool isLocal() const { return binding == SymbolBinding::LOCAL; }
    bool containsAddress(uint64_t addr) const {
        return addr >= address && addr < address + size;
    }

    std::string getBindingString() const;
    std::string getTypeString() const;
    std::string getVisibilityString() const;
};

// Symbol lookup result with match quality
struct SymbolMatch {
    std::shared_ptr<Symbol> symbol;
    enum class MatchType {
        EXACT,          // Exact address match
        CONTAINS,       // Address within symbol range
        NEAREST_BEFORE, // Nearest symbol before address
        NAME_MATCH      // Name lookup match
    } match_type;
    int64_t offset = 0; // Offset from symbol start (for CONTAINS/NEAREST)
};

// Symbol table configuration
struct SymbolTableConfig {
    bool load_dynamic = true;       // Load .dynsym
    bool load_static = true;        // Load .symtab
    bool demangle_names = true;     // Demangle C++ names
    bool link_dwarf = true;         // Link with DWARF info
    bool include_undefined = false; // Include undefined symbols
};

// Symbol table parser and manager
class SymbolTable {
public:
    explicit SymbolTable(const ELFIO::elfio& elf, SymbolTableConfig config = {});

    // Load symbols from ELF
    bool load();

    // Symbol lookup methods
    std::optional<SymbolMatch> findByAddress(uint64_t address) const;
    std::optional<SymbolMatch> findExact(uint64_t address) const;
    std::optional<SymbolMatch> findContaining(uint64_t address) const;
    std::optional<SymbolMatch> findNearest(uint64_t address) const;

    // Name-based lookup
    std::vector<std::shared_ptr<Symbol>> findByName(const std::string& name) const;
    std::vector<std::shared_ptr<Symbol>> findByDemangledName(const std::string& name) const;
    std::vector<std::shared_ptr<Symbol>> findByPattern(const std::string& pattern) const;

    // Filtered queries
    std::vector<std::shared_ptr<Symbol>> getFunctions() const;
    std::vector<std::shared_ptr<Symbol>> getObjects() const;
    std::vector<std::shared_ptr<Symbol>> getGlobalSymbols() const;
    std::vector<std::shared_ptr<Symbol>> getDefinedSymbols() const;
    std::vector<std::shared_ptr<Symbol>> getDynamicSymbols() const;
    std::vector<std::shared_ptr<Symbol>> getStaticSymbols() const;

    // Get all symbols
    const std::vector<std::shared_ptr<Symbol>>& getAllSymbols() const { return symbols_; }
    size_t size() const { return symbols_.size(); }
    bool empty() const { return symbols_.empty(); }

    // Link with DWARF information
    void linkWithDwarf(DwarfParser& parser);

    // Statistics
    struct Stats {
        size_t total_symbols = 0;
        size_t functions = 0;
        size_t objects = 0;
        size_t global_symbols = 0;
        size_t local_symbols = 0;
        size_t weak_symbols = 0;
        size_t defined_symbols = 0;
        size_t undefined_symbols = 0;
        size_t dynamic_symbols = 0;
        size_t static_symbols = 0;
        size_t dwarf_linked = 0;
    };
    Stats getStats() const;

    // Printing
    void printSymbols(bool verbose = false) const;
    void printSymbol(const Symbol& sym, bool verbose = false) const;

private:
    const ELFIO::elfio& elf_;
    SymbolTableConfig config_;
    std::vector<std::shared_ptr<Symbol>> symbols_;

    // Indexes for fast lookup
    std::map<uint64_t, std::vector<std::shared_ptr<Symbol>>> address_index_;
    std::multimap<std::string, std::shared_ptr<Symbol>> name_index_;
    std::multimap<std::string, std::shared_ptr<Symbol>> demangled_index_;

    // Internal methods
    bool loadSymbolTable(const ELFIO::section* section, bool is_dynamic);
    void buildIndexes();
    std::string getSectionName(uint16_t index) const;

    // Conversion helpers
    static SymbolBinding toBinding(uint8_t info);
    static SymbolType toType(uint8_t info);
    static SymbolVisibility toVisibility(uint8_t other);
};

// Integration helper: resolve address to symbol + source info
struct ResolvedAddress {
    uint64_t address = 0;

    // Symbol info
    std::shared_ptr<Symbol> symbol;
    int64_t symbol_offset = 0;      // Offset within symbol

    // Source info (from DWARF)
    std::string source_file;
    uint32_t line = 0;
    uint32_t column = 0;

    // Function info
    std::string function_name;
    bool is_inlined = false;

    // Format as string
    std::string toString() const;
    std::string toShortString() const;  // "function+0x10 at file:line"
};

// Address resolver combining symbol table and DWARF
class AddressResolver {
public:
    AddressResolver(SymbolTable& symbols, DwarfParser& dwarf);

    // Resolve an address to full context
    ResolvedAddress resolve(uint64_t address) const;

    // Batch resolve
    std::vector<ResolvedAddress> resolveMany(const std::vector<uint64_t>& addresses) const;

    // Format helpers
    std::string formatAddress(uint64_t address) const;
    std::string formatAddressShort(uint64_t address) const;

private:
    SymbolTable& symbols_;
    DwarfParser& dwarf_;
};

} // namespace dwarf
