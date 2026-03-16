#pragma once

#include "debug_macro_parser.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace dwarf {

struct LegacyArangeEntry {
    uint64_t cu_offset = 0;
    uint64_t address = 0;
    uint64_t length = 0;
};

struct LegacyPublicNameEntry {
    uint64_t cu_offset = 0;
    uint64_t die_offset = 0;
    std::string name;
};

class DebugMacinfoParser {
public:
    explicit DebugMacinfoParser(const std::vector<uint8_t>& debug_macinfo);

    std::vector<MacroDefinition> getDefinitions(uint64_t offset) const;
    std::vector<MacroDefinition> lookupMacro(const std::string& name, uint64_t offset) const;

    bool empty() const { return debug_macinfo_.empty(); }
    size_t size() const { return debug_macinfo_.size(); }

private:
    const std::vector<uint8_t>& debug_macinfo_;

    struct Entry {
        uint8_t type = 0;
        uint64_t operand0 = 0;
        uint64_t operand1 = 0;
        std::string text;
    };

    std::vector<Entry> parseEntries(uint64_t offset) const;
    void parseMacroString(const std::string& str, std::string& name, std::string& value, bool& is_function_like) const;
};

class DebugArangesParser {
public:
    explicit DebugArangesParser(const std::vector<uint8_t>& debug_aranges);

    std::vector<LegacyArangeEntry> parse() const;

private:
    const std::vector<uint8_t>& debug_aranges_;
};

class DebugPubTableParser {
public:
    explicit DebugPubTableParser(const std::vector<uint8_t>& section);

    std::vector<LegacyPublicNameEntry> parse() const;

private:
    const std::vector<uint8_t>& section_;
};

} // namespace dwarf
