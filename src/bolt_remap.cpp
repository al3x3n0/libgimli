#include "bolt_remap.hpp"

#include "symbol_table.hpp"

#include <elfio/elfio.hpp>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <unordered_map>

namespace dwarf {

std::optional<uint64_t> BoltAddressRemap::apply(uint64_t old_addr) const {
    auto it = old_to_new.find(old_addr);
    if (it != old_to_new.end()) return it->second;
    for (const auto& span : spans) {
        if (span.old_size == 0) continue;
        if (old_addr >= span.old_base && old_addr < span.old_base + span.old_size) {
            return span.new_base + (old_addr - span.old_base);
        }
    }
    return std::nullopt;
}

bool elfHasBoltMarkers(const ELFIO::elfio& elf) {
    for (const auto& section : elf.sections) {
        const std::string& name = section->get_name();
        if (name.rfind(".bolt.", 0) == 0) return true;
    }
    return false;
}

namespace {

// Returns name -> best (largest) function symbol {address, size} for a binary.
std::unordered_map<std::string, std::pair<uint64_t, uint64_t>> functionsByName(
    const ELFIO::elfio& elf) {
    std::unordered_map<std::string, std::pair<uint64_t, uint64_t>> out;
    SymbolTable table(elf);
    if (!table.load()) return out;
    for (const auto& sym : table.getFunctions()) {
        if (!sym || sym->name.empty() || sym->address == 0) continue;
        auto it = out.find(sym->name);
        // Prefer the largest-sized symbol for a given name (mirrors bolt_map_detect).
        if (it == out.end() || sym->size > it->second.second) {
            out[sym->name] = {sym->address, sym->size};
        }
    }
    return out;
}

} // namespace

BoltAddressRemap buildBoltRemapFromElves(const ELFIO::elfio& lhs, const ELFIO::elfio& rhs) {
    BoltAddressRemap remap;
    remap.origin = "auto";

    auto old_funcs = functionsByName(lhs);
    auto new_funcs = functionsByName(rhs);
    if (old_funcs.empty() || new_funcs.empty()) return remap;

    for (const auto& kv : old_funcs) {
        auto it_new = new_funcs.find(kv.first);
        if (it_new == new_funcs.end()) continue;
        const uint64_t old_addr = kv.second.first;
        const uint64_t old_size = kv.second.second;
        const uint64_t new_addr = it_new->second.first;
        if (old_addr == new_addr) continue; // no relocation for this function
        remap.old_to_new[old_addr] = new_addr;
        if (old_size > 0) {
            remap.spans.push_back(BoltAddressRemap::FunctionSpan{old_addr, old_size, new_addr});
        }
    }
    return remap;
}

BoltAddressRemap loadBoltRemapFromFile(const std::string& path, std::string& error) {
    BoltAddressRemap remap;
    remap.origin = "file:" + path;

    std::ifstream in(path);
    if (!in) {
        error = "cannot open bolt map file: " + path;
        return BoltAddressRemap{};
    }

    std::string line;
    size_t line_no = 0;
    while (std::getline(in, line)) {
        ++line_no;
        // Strip comments and surrounding whitespace.
        auto hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        std::istringstream ss(line);
        std::string old_tok, new_tok;
        if (!(ss >> old_tok >> new_tok)) {
            if (line.find_first_not_of(" \t\r\n") == std::string::npos) continue; // blank
            error = "malformed bolt map line " + std::to_string(line_no) + ": " + line;
            return BoltAddressRemap{};
        }
        char* end = nullptr;
        const uint64_t old_addr = std::strtoull(old_tok.c_str(), &end, 0);
        if (end == old_tok.c_str()) {
            error = "invalid old address on line " + std::to_string(line_no) + ": " + old_tok;
            return BoltAddressRemap{};
        }
        const uint64_t new_addr = std::strtoull(new_tok.c_str(), &end, 0);
        if (end == new_tok.c_str()) {
            error = "invalid new address on line " + std::to_string(line_no) + ": " + new_tok;
            return BoltAddressRemap{};
        }
        remap.old_to_new[old_addr] = new_addr;
    }
    return remap;
}

} // namespace dwarf
