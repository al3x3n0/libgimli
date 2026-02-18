#include "symbol_table.hpp"
#include "dwarf_parser.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <regex>

namespace dwarf {

// Symbol helper methods
std::string Symbol::getBindingString() const {
    switch (binding) {
        case SymbolBinding::LOCAL: return "LOCAL";
        case SymbolBinding::GLOBAL: return "GLOBAL";
        case SymbolBinding::WEAK: return "WEAK";
        default: return "UNKNOWN";
    }
}

std::string Symbol::getTypeString() const {
    switch (type) {
        case SymbolType::NOTYPE: return "NOTYPE";
        case SymbolType::OBJECT: return "OBJECT";
        case SymbolType::FUNC: return "FUNC";
        case SymbolType::SECTION: return "SECTION";
        case SymbolType::FILE: return "FILE";
        case SymbolType::COMMON: return "COMMON";
        case SymbolType::TLS: return "TLS";
        default: return "UNKNOWN";
    }
}

std::string Symbol::getVisibilityString() const {
    switch (visibility) {
        case SymbolVisibility::DEFAULT: return "DEFAULT";
        case SymbolVisibility::INTERNAL: return "INTERNAL";
        case SymbolVisibility::HIDDEN: return "HIDDEN";
        case SymbolVisibility::PROTECTED: return "PROTECTED";
        default: return "UNKNOWN";
    }
}

// SymbolTable implementation
SymbolTable::SymbolTable(const ELFIO::elfio& elf, SymbolTableConfig config)
    : elf_(elf), config_(config) {}

bool SymbolTable::load() {
    symbols_.clear();
    address_index_.clear();
    name_index_.clear();
    demangled_index_.clear();

    // Find and load symbol tables
    for (const auto& section : elf_.sections) {
        if (section->get_type() == ELFIO::SHT_SYMTAB && config_.load_static) {
            loadSymbolTable(section.get(), false);
        } else if (section->get_type() == ELFIO::SHT_DYNSYM && config_.load_dynamic) {
            loadSymbolTable(section.get(), true);
        }
    }

    // Build indexes for fast lookup
    buildIndexes();

    return !symbols_.empty();
}

bool SymbolTable::loadSymbolTable(const ELFIO::section* section, bool is_dynamic) {
    if (!section) return false;

    const ELFIO::symbol_section_accessor symbols(elf_, const_cast<ELFIO::section*>(section));
    size_t count = symbols.get_symbols_num();

    for (size_t i = 0; i < count; ++i) {
        std::string name;
        ELFIO::Elf64_Addr value;
        ELFIO::Elf_Xword size;
        unsigned char bind;
        unsigned char type;
        ELFIO::Elf_Half section_index;
        unsigned char other;

        if (!symbols.get_symbol(i, name, value, size, bind, type, section_index, other)) {
            continue;
        }

        // Skip empty names
        if (name.empty()) {
            continue;
        }

        // Skip undefined symbols if not requested
        bool is_defined = (section_index != ELFIO::SHN_UNDEF);
        if (!is_defined && !config_.include_undefined) {
            continue;
        }

        auto sym = std::make_shared<Symbol>();
        sym->name = name;
        sym->address = value;
        sym->size = size;
        sym->binding = toBinding(bind);
        sym->type = toType(type);
        sym->visibility = toVisibility(other);
        sym->section_index = section_index;
        sym->section_name = getSectionName(section_index);
        sym->is_defined = is_defined;
        sym->is_dynamic = is_dynamic;

        // Demangle C++ names
        if (config_.demangle_names) {
            sym->demangled_name = Demangler::demangle(name);
        } else {
            sym->demangled_name = name;
        }

        symbols_.push_back(sym);
    }

    return true;
}

void SymbolTable::buildIndexes() {
    for (const auto& sym : symbols_) {
        // Address index (only for defined symbols with valid addresses)
        if (sym->is_defined && sym->address != 0) {
            address_index_[sym->address].push_back(sym);
        }

        // Name indexes
        name_index_.emplace(sym->name, sym);
        if (sym->demangled_name != sym->name) {
            demangled_index_.emplace(sym->demangled_name, sym);
        }
    }

    // Sort address index entries by size (prefer larger symbols)
    for (auto& [addr, syms] : address_index_) {
        std::sort(syms.begin(), syms.end(),
            [](const auto& a, const auto& b) {
                // Prefer functions over objects
                if (a->isFunction() != b->isFunction()) {
                    return a->isFunction();
                }
                // Then prefer larger symbols
                return a->size > b->size;
            });
    }
}

std::string SymbolTable::getSectionName(uint16_t index) const {
    if (index == ELFIO::SHN_UNDEF) return "UND";
    if (index == ELFIO::SHN_ABS) return "ABS";
    if (index == ELFIO::SHN_COMMON) return "COM";
    if (index >= elf_.sections.size()) return "???";

    return elf_.sections[index]->get_name();
}

SymbolBinding SymbolTable::toBinding(uint8_t info) {
    switch (info) {
        case ELFIO::STB_LOCAL: return SymbolBinding::LOCAL;
        case ELFIO::STB_GLOBAL: return SymbolBinding::GLOBAL;
        case ELFIO::STB_WEAK: return SymbolBinding::WEAK;
        default: return SymbolBinding::LOCAL;
    }
}

SymbolType SymbolTable::toType(uint8_t info) {
    switch (info) {
        case ELFIO::STT_NOTYPE: return SymbolType::NOTYPE;
        case ELFIO::STT_OBJECT: return SymbolType::OBJECT;
        case ELFIO::STT_FUNC: return SymbolType::FUNC;
        case ELFIO::STT_SECTION: return SymbolType::SECTION;
        case ELFIO::STT_FILE: return SymbolType::FILE;
        case ELFIO::STT_COMMON: return SymbolType::COMMON;
        case ELFIO::STT_TLS: return SymbolType::TLS;
        default: return SymbolType::NOTYPE;
    }
}

SymbolVisibility SymbolTable::toVisibility(uint8_t other) {
    uint8_t vis = other & 0x03;
    switch (vis) {
        case ELFIO::STV_DEFAULT: return SymbolVisibility::DEFAULT;
        case ELFIO::STV_INTERNAL: return SymbolVisibility::INTERNAL;
        case ELFIO::STV_HIDDEN: return SymbolVisibility::HIDDEN;
        case ELFIO::STV_PROTECTED: return SymbolVisibility::PROTECTED;
        default: return SymbolVisibility::DEFAULT;
    }
}

std::optional<SymbolMatch> SymbolTable::findByAddress(uint64_t address) const {
    // Try exact match first
    auto exact = findExact(address);
    if (exact) return exact;

    // Try containing match
    auto containing = findContaining(address);
    if (containing) return containing;

    // Fall back to nearest
    return findNearest(address);
}

std::optional<SymbolMatch> SymbolTable::findExact(uint64_t address) const {
    auto it = address_index_.find(address);
    if (it != address_index_.end() && !it->second.empty()) {
        SymbolMatch match;
        match.symbol = it->second.front();
        match.match_type = SymbolMatch::MatchType::EXACT;
        match.offset = 0;
        return match;
    }
    return std::nullopt;
}

std::optional<SymbolMatch> SymbolTable::findContaining(uint64_t address) const {
    // Look for symbols that contain this address
    // Start from the address and search backwards
    auto it = address_index_.upper_bound(address);

    while (it != address_index_.begin()) {
        --it;
        for (const auto& sym : it->second) {
            if (sym->containsAddress(address)) {
                SymbolMatch match;
                match.symbol = sym;
                match.match_type = SymbolMatch::MatchType::CONTAINS;
                match.offset = static_cast<int64_t>(address - sym->address);
                return match;
            }
        }
    }

    return std::nullopt;
}

std::optional<SymbolMatch> SymbolTable::findNearest(uint64_t address) const {
    if (address_index_.empty()) return std::nullopt;

    auto it = address_index_.upper_bound(address);
    if (it == address_index_.begin()) {
        return std::nullopt;  // No symbol before this address
    }

    --it;
    if (!it->second.empty()) {
        SymbolMatch match;
        match.symbol = it->second.front();
        match.match_type = SymbolMatch::MatchType::NEAREST_BEFORE;
        match.offset = static_cast<int64_t>(address - match.symbol->address);
        return match;
    }

    return std::nullopt;
}

std::vector<std::shared_ptr<Symbol>> SymbolTable::findByName(const std::string& name) const {
    std::vector<std::shared_ptr<Symbol>> result;

    auto range = name_index_.equal_range(name);
    for (auto it = range.first; it != range.second; ++it) {
        result.push_back(it->second);
    }

    return result;
}

std::vector<std::shared_ptr<Symbol>> SymbolTable::findByDemangledName(const std::string& name) const {
    std::vector<std::shared_ptr<Symbol>> result;

    // Search in demangled index
    auto range = demangled_index_.equal_range(name);
    for (auto it = range.first; it != range.second; ++it) {
        result.push_back(it->second);
    }

    // Also search in name index (for non-mangled names)
    auto range2 = name_index_.equal_range(name);
    for (auto it = range2.first; it != range2.second; ++it) {
        // Avoid duplicates
        if (std::find(result.begin(), result.end(), it->second) == result.end()) {
            result.push_back(it->second);
        }
    }

    return result;
}

std::vector<std::shared_ptr<Symbol>> SymbolTable::findByPattern(const std::string& pattern) const {
    std::vector<std::shared_ptr<Symbol>> result;

    try {
        std::regex re(pattern, std::regex::ECMAScript | std::regex::icase);

        for (const auto& sym : symbols_) {
            if (std::regex_search(sym->name, re) ||
                std::regex_search(sym->demangled_name, re)) {
                result.push_back(sym);
            }
        }
    } catch (const std::regex_error&) {
        // Invalid regex, try simple substring match
        for (const auto& sym : symbols_) {
            if (sym->name.find(pattern) != std::string::npos ||
                sym->demangled_name.find(pattern) != std::string::npos) {
                result.push_back(sym);
            }
        }
    }

    return result;
}

std::vector<std::shared_ptr<Symbol>> SymbolTable::getFunctions() const {
    std::vector<std::shared_ptr<Symbol>> result;
    for (const auto& sym : symbols_) {
        if (sym->isFunction()) {
            result.push_back(sym);
        }
    }
    return result;
}

std::vector<std::shared_ptr<Symbol>> SymbolTable::getObjects() const {
    std::vector<std::shared_ptr<Symbol>> result;
    for (const auto& sym : symbols_) {
        if (sym->isObject()) {
            result.push_back(sym);
        }
    }
    return result;
}

std::vector<std::shared_ptr<Symbol>> SymbolTable::getGlobalSymbols() const {
    std::vector<std::shared_ptr<Symbol>> result;
    for (const auto& sym : symbols_) {
        if (sym->isGlobal()) {
            result.push_back(sym);
        }
    }
    return result;
}

std::vector<std::shared_ptr<Symbol>> SymbolTable::getDefinedSymbols() const {
    std::vector<std::shared_ptr<Symbol>> result;
    for (const auto& sym : symbols_) {
        if (sym->is_defined) {
            result.push_back(sym);
        }
    }
    return result;
}

std::vector<std::shared_ptr<Symbol>> SymbolTable::getDynamicSymbols() const {
    std::vector<std::shared_ptr<Symbol>> result;
    for (const auto& sym : symbols_) {
        if (sym->is_dynamic) {
            result.push_back(sym);
        }
    }
    return result;
}

std::vector<std::shared_ptr<Symbol>> SymbolTable::getStaticSymbols() const {
    std::vector<std::shared_ptr<Symbol>> result;
    for (const auto& sym : symbols_) {
        if (!sym->is_dynamic) {
            result.push_back(sym);
        }
    }
    return result;
}

void SymbolTable::linkWithDwarf(DwarfParser& parser) {
    if (!config_.link_dwarf) return;

    // Get DWARF functions and link with symbols
    auto dwarf_functions = parser.getFunctions();

    for (auto& sym : symbols_) {
        if (!sym->isFunction()) continue;

        // Try to find matching DWARF DIE
        for (const auto& func_die : dwarf_functions) {
            // Match by address
            auto low_pc = func_die->getAttribute(DwarfAttribute::DW_AT_low_pc);
            if (low_pc) {
                uint64_t func_addr = 0;
                auto addr_attr = std::dynamic_pointer_cast<AddressAttributeValue>(low_pc);
                auto uint_attr = std::dynamic_pointer_cast<UnsignedAttributeValue>(low_pc);

                if (addr_attr) {
                    func_addr = addr_attr->getAddress();
                } else if (uint_attr) {
                    func_addr = uint_attr->getValue();
                }

                if (func_addr == sym->address) {
                    sym->dwarf_die = func_die;
                    sym->has_dwarf_info = true;
                    break;
                }
            }

            // Also try matching by linkage name
            auto linkage_name = func_die->getAttribute(DwarfAttribute::DW_AT_linkage_name);
            if (linkage_name) {
                auto str = std::dynamic_pointer_cast<StringAttributeValue>(linkage_name);
                if (str && str->getValue() == sym->name) {
                    sym->dwarf_die = func_die;
                    sym->has_dwarf_info = true;
                    break;
                }
            }

            // Try matching by name
            if (func_die->getName() == sym->name ||
                func_die->getName() == sym->demangled_name) {
                sym->dwarf_die = func_die;
                sym->has_dwarf_info = true;
                break;
            }
        }
    }

    // Also link variables
    auto dwarf_variables = parser.getVariables();

    for (auto& sym : symbols_) {
        if (!sym->isObject()) continue;
        if (sym->has_dwarf_info) continue;

        for (const auto& var_die : dwarf_variables) {
            // Match by address
            auto location = var_die->getAttribute(DwarfAttribute::DW_AT_location);
            // For now, just match by name (location parsing is complex)

            if (var_die->getName() == sym->name) {
                sym->dwarf_die = var_die;
                sym->has_dwarf_info = true;
                break;
            }
        }
    }
}

SymbolTable::Stats SymbolTable::getStats() const {
    Stats stats;
    stats.total_symbols = symbols_.size();

    for (const auto& sym : symbols_) {
        if (sym->isFunction()) stats.functions++;
        if (sym->isObject()) stats.objects++;
        if (sym->isGlobal()) stats.global_symbols++;
        if (sym->isLocal()) stats.local_symbols++;
        if (sym->isWeak()) stats.weak_symbols++;
        if (sym->is_defined) stats.defined_symbols++;
        else stats.undefined_symbols++;
        if (sym->is_dynamic) stats.dynamic_symbols++;
        else stats.static_symbols++;
        if (sym->has_dwarf_info) stats.dwarf_linked++;
    }

    return stats;
}

void SymbolTable::printSymbols(bool verbose) const {
    std::cout << "Symbol Table (" << symbols_.size() << " symbols)\n";
    std::cout << std::string(60, '=') << "\n";

    if (verbose) {
        std::cout << std::left
                  << std::setw(18) << "Address"
                  << std::setw(10) << "Size"
                  << std::setw(8) << "Type"
                  << std::setw(8) << "Bind"
                  << std::setw(8) << "Section"
                  << "Name\n";
        std::cout << std::string(60, '-') << "\n";
    }

    for (const auto& sym : symbols_) {
        printSymbol(*sym, verbose);
    }
}

void SymbolTable::printSymbol(const Symbol& sym, bool verbose) const {
    if (verbose) {
        std::cout << std::left
                  << "0x" << std::hex << std::setw(16) << std::setfill('0') << sym.address
                  << std::dec << std::setfill(' ')
                  << std::setw(10) << sym.size
                  << std::setw(8) << sym.getTypeString()
                  << std::setw(8) << sym.getBindingString()
                  << std::setw(8) << sym.section_name;

        if (sym.demangled_name != sym.name) {
            std::cout << sym.demangled_name << " [" << sym.name << "]";
        } else {
            std::cout << sym.name;
        }

        if (sym.has_dwarf_info) {
            std::cout << " <DWARF>";
        }

        std::cout << "\n";
    } else {
        std::cout << "0x" << std::hex << sym.address << std::dec
                  << " " << sym.getTypeString().substr(0, 1)
                  << " " << sym.demangled_name << "\n";
    }
}

// ResolvedAddress implementation
std::string ResolvedAddress::toString() const {
    std::ostringstream oss;
    oss << "0x" << std::hex << address << std::dec;

    if (symbol) {
        oss << " <" << symbol->demangled_name;
        if (symbol_offset != 0) {
            oss << "+0x" << std::hex << symbol_offset << std::dec;
        }
        oss << ">";
    }

    if (!source_file.empty()) {
        oss << " at " << source_file;
        if (line > 0) {
            oss << ":" << line;
            if (column > 0) {
                oss << ":" << column;
            }
        }
    }

    if (is_inlined && !function_name.empty()) {
        oss << " [inlined: " << function_name << "]";
    }

    return oss.str();
}

std::string ResolvedAddress::toShortString() const {
    std::ostringstream oss;

    if (symbol) {
        oss << symbol->demangled_name;
        if (symbol_offset != 0) {
            oss << "+0x" << std::hex << symbol_offset << std::dec;
        }
    } else {
        oss << "0x" << std::hex << address << std::dec;
    }

    if (!source_file.empty() && line > 0) {
        // Extract just filename
        size_t pos = source_file.find_last_of("/\\");
        std::string filename = (pos != std::string::npos)
            ? source_file.substr(pos + 1)
            : source_file;
        oss << " at " << filename << ":" << line;
    }

    return oss.str();
}

// AddressResolver implementation
AddressResolver::AddressResolver(SymbolTable& symbols, DwarfParser& dwarf)
    : symbols_(symbols), dwarf_(dwarf) {}

ResolvedAddress AddressResolver::resolve(uint64_t address) const {
    ResolvedAddress result;
    result.address = address;

    // Find symbol
    auto sym_match = symbols_.findByAddress(address);
    if (sym_match) {
        result.symbol = sym_match->symbol;
        result.symbol_offset = sym_match->offset;
    }

    // Find source location using DWARF
    auto source_loc = dwarf_.getSourceLocation(address);
    if (source_loc) {
        result.source_file = source_loc->file;
        result.line = source_loc->line;
        result.column = source_loc->column;
    }

    // Find function name from DWARF (might be more detailed than symbol)
    auto func = dwarf_.getFunctionAt(address);
    if (func) {
        result.function_name = func->getName();

        // Check for inlined functions
        auto inlined = dwarf_.getInlinedFunctionAt(address);
        if (inlined && inlined != func) {
            result.is_inlined = true;
            result.function_name = inlined->getName();
        }
    }

    return result;
}

std::vector<ResolvedAddress> AddressResolver::resolveMany(const std::vector<uint64_t>& addresses) const {
    std::vector<ResolvedAddress> results;
    results.reserve(addresses.size());

    for (uint64_t addr : addresses) {
        results.push_back(resolve(addr));
    }

    return results;
}

std::string AddressResolver::formatAddress(uint64_t address) const {
    return resolve(address).toString();
}

std::string AddressResolver::formatAddressShort(uint64_t address) const {
    return resolve(address).toShortString();
}

} // namespace dwarf
