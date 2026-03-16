#include "legacy_dwarf_parser.hpp"
#include "dwarf_utils.hpp"
#include <cstring>

namespace dwarf {

namespace {

uint64_t readInitialLength(const std::vector<uint8_t>& bytes, uint64_t& offset, bool& is_dwarf64) {
    uint64_t max = bytes.size();
    uint32_t initial = DwarfUtils::readU32(bytes.data(), offset, max);
    is_dwarf64 = (initial == 0xffffffffu);
    return is_dwarf64 ? DwarfUtils::readU64(bytes.data(), offset, max) : initial;
}

uint64_t readSizedOffset(const std::vector<uint8_t>& bytes, uint64_t& offset, bool is_dwarf64, uint64_t max) {
    return is_dwarf64 ? DwarfUtils::readU64(bytes.data(), offset, max)
                      : DwarfUtils::readU32(bytes.data(), offset, max);
}

std::string readCStringBounded(const std::vector<uint8_t>& bytes, uint64_t& offset, uint64_t end) {
    if (offset >= end || end > bytes.size()) return {};
    const char* base = reinterpret_cast<const char*>(bytes.data() + offset);
    size_t max_len = static_cast<size_t>(end - offset);
    size_t len = strnlen(base, max_len);
    if (len == max_len) {
        offset = end;
        return {};
    }
    offset += len + 1;
    return std::string(base, len);
}

} // namespace

DebugMacinfoParser::DebugMacinfoParser(const std::vector<uint8_t>& debug_macinfo)
    : debug_macinfo_(debug_macinfo) {}

std::vector<DebugMacinfoParser::Entry> DebugMacinfoParser::parseEntries(uint64_t offset) const {
    std::vector<Entry> entries;
    if (offset >= debug_macinfo_.size()) return entries;

    while (offset < debug_macinfo_.size()) {
        uint8_t type = DwarfUtils::readU8(debug_macinfo_.data(), offset, debug_macinfo_.size());
        if (type == 0) {
            break;
        }

        Entry entry;
        entry.type = type;
        switch (type) {
            case 0x01: // define
            case 0x02: // undef
                entry.operand0 = DwarfUtils::readULEB128(debug_macinfo_.data(), offset, debug_macinfo_.size());
                entry.text = readCStringBounded(debug_macinfo_, offset, debug_macinfo_.size());
                break;
            case 0x03: // start_file
                entry.operand0 = DwarfUtils::readULEB128(debug_macinfo_.data(), offset, debug_macinfo_.size());
                entry.operand1 = DwarfUtils::readULEB128(debug_macinfo_.data(), offset, debug_macinfo_.size());
                break;
            case 0x04: // end_file
                break;
            case 0xff: // vendor_ext
                entry.operand0 = DwarfUtils::readULEB128(debug_macinfo_.data(), offset, debug_macinfo_.size());
                entry.text = readCStringBounded(debug_macinfo_, offset, debug_macinfo_.size());
                break;
            default:
                offset = debug_macinfo_.size();
                break;
        }
        entries.push_back(std::move(entry));
    }

    return entries;
}

void DebugMacinfoParser::parseMacroString(const std::string& str,
                                          std::string& name,
                                          std::string& value,
                                          bool& is_function_like) const {
    name.clear();
    value.clear();
    is_function_like = false;
    if (str.empty()) return;

    size_t split = str.find_first_of(" \t");
    std::string head = (split == std::string::npos) ? str : str.substr(0, split);
    if (split != std::string::npos) {
        size_t body = str.find_first_not_of(" \t", split);
        if (body != std::string::npos) value = str.substr(body);
    }

    size_t paren = head.find('(');
    if (paren != std::string::npos && head.back() == ')') {
        is_function_like = true;
    }
    name = head;
}

std::vector<MacroDefinition> DebugMacinfoParser::getDefinitions(uint64_t offset) const {
    std::vector<MacroDefinition> definitions;
    for (const auto& entry : parseEntries(offset)) {
        if (entry.type != 0x01) continue;
        MacroDefinition def;
        def.line = entry.operand0;
        parseMacroString(entry.text, def.name, def.value, def.is_function_like);
        definitions.push_back(std::move(def));
    }
    return definitions;
}

std::vector<MacroDefinition> DebugMacinfoParser::lookupMacro(const std::string& name, uint64_t offset) const {
    std::vector<MacroDefinition> results;
    for (const auto& def : getDefinitions(offset)) {
        std::string short_name = def.name;
        size_t paren = short_name.find('(');
        if (paren != std::string::npos) short_name = short_name.substr(0, paren);
        if (short_name == name) {
            results.push_back(def);
        }
    }
    return results;
}

DebugArangesParser::DebugArangesParser(const std::vector<uint8_t>& debug_aranges)
    : debug_aranges_(debug_aranges) {}

std::vector<LegacyArangeEntry> DebugArangesParser::parse() const {
    std::vector<LegacyArangeEntry> entries;
    uint64_t offset = 0;
    while (offset + 4 <= debug_aranges_.size()) {
        uint64_t unit_start = offset;
        bool is_dwarf64 = false;
        uint64_t unit_length = readInitialLength(debug_aranges_, offset, is_dwarf64);
        uint64_t length_field_size = is_dwarf64 ? 12 : 4;
        uint64_t unit_end = unit_start + length_field_size + unit_length;
        if (unit_end > debug_aranges_.size() || unit_end < offset) break;

        uint16_t version = DwarfUtils::readU16(debug_aranges_.data(), offset, unit_end);
        if (version != 2) {
            offset = unit_end;
            continue;
        }
        uint64_t cu_offset = readSizedOffset(debug_aranges_, offset, is_dwarf64, unit_end);
        uint8_t address_size = DwarfUtils::readU8(debug_aranges_.data(), offset, unit_end);
        uint8_t segment_size = DwarfUtils::readU8(debug_aranges_.data(), offset, unit_end);
        uint64_t tuple_size = static_cast<uint64_t>(address_size + segment_size) * 2;
        if (tuple_size == 0) {
            offset = unit_end;
            continue;
        }

        uint64_t header_size = offset - unit_start;
        uint64_t aligned = ((header_size + tuple_size - 1) / tuple_size) * tuple_size;
        offset = unit_start + aligned;
        if (offset > unit_end) {
            offset = unit_end;
            continue;
        }

        while (offset + tuple_size <= unit_end) {
            uint64_t tuple_off = offset;
            uint64_t address = 0;
            uint64_t length = 0;
            if (segment_size != 0) {
                tuple_off += segment_size;
            }
            if (address_size == 8) {
                address = DwarfUtils::readU64(debug_aranges_.data(), tuple_off, unit_end);
                if (segment_size != 0) tuple_off += segment_size;
                length = DwarfUtils::readU64(debug_aranges_.data(), tuple_off, unit_end);
            } else {
                address = DwarfUtils::readU32(debug_aranges_.data(), tuple_off, unit_end);
                if (segment_size != 0) tuple_off += segment_size;
                length = DwarfUtils::readU32(debug_aranges_.data(), tuple_off, unit_end);
            }
            offset += tuple_size;
            if (address == 0 && length == 0) break;
            entries.push_back({cu_offset, address, length});
        }

        offset = unit_end;
    }
    return entries;
}

DebugPubTableParser::DebugPubTableParser(const std::vector<uint8_t>& section)
    : section_(section) {}

std::vector<LegacyPublicNameEntry> DebugPubTableParser::parse() const {
    std::vector<LegacyPublicNameEntry> entries;
    uint64_t offset = 0;
    while (offset + 4 <= section_.size()) {
        uint64_t unit_start = offset;
        bool is_dwarf64 = false;
        uint64_t unit_length = readInitialLength(section_, offset, is_dwarf64);
        uint64_t length_field_size = is_dwarf64 ? 12 : 4;
        uint64_t unit_end = unit_start + length_field_size + unit_length;
        if (unit_end > section_.size() || unit_end < offset) break;

        uint16_t version = DwarfUtils::readU16(section_.data(), offset, unit_end);
        if (version < 2 || version > 4) {
            offset = unit_end;
            continue;
        }
        uint64_t cu_offset = readSizedOffset(section_, offset, is_dwarf64, unit_end);
        (void)readSizedOffset(section_, offset, is_dwarf64, unit_end); // cu_length

        while (offset < unit_end) {
            uint64_t die_rel = readSizedOffset(section_, offset, is_dwarf64, unit_end);
            if (die_rel == 0) break;
            std::string name = readCStringBounded(section_, offset, unit_end);
            if (name.empty() && offset >= unit_end) break;
            entries.push_back({cu_offset, cu_offset + die_rel, name});
        }
        offset = unit_end;
    }
    return entries;
}

} // namespace dwarf
