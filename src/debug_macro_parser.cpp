#include "debug_macro_parser.hpp"
#include "dwarf_utils.hpp"
#include <cstring>
#include <functional>
#include <limits>

namespace dwarf {

static const std::vector<uint8_t>& emptyBytes() {
    static const std::vector<uint8_t> kEmpty;
    return kEmpty;
}

DebugMacroParser::DebugMacroParser(const std::vector<uint8_t>& debug_macro)
    : DebugMacroParser(debug_macro,
                       /*debug_str=*/nullptr,
                       /*debug_str_sup=*/nullptr,
                       /*debug_str_offsets=*/nullptr,
                       /*debug_line=*/nullptr) {}

DebugMacroParser::DebugMacroParser(const std::vector<uint8_t>& debug_macro,
                                   const std::vector<uint8_t>* debug_str,
                                   const std::vector<uint8_t>* debug_str_sup,
                                   const std::vector<uint8_t>* debug_str_offsets,
                                   const std::vector<uint8_t>* debug_line)
    : debug_macro_(&debug_macro)
    , debug_str_(debug_str)
    , debug_str_sup_(debug_str_sup)
    , debug_str_offsets_(debug_str_offsets)
    , debug_line_(debug_line) {}

const std::vector<uint8_t>& DebugMacroParser::debugMacro() const { return debug_macro_ ? *debug_macro_ : emptyBytes(); }
const std::vector<uint8_t>& DebugMacroParser::debugStr() const { return debug_str_ ? *debug_str_ : emptyBytes(); }
const std::vector<uint8_t>& DebugMacroParser::debugStrSup() const { return debug_str_sup_ ? *debug_str_sup_ : emptyBytes(); }
const std::vector<uint8_t>& DebugMacroParser::debugStrOffsets() const { return debug_str_offsets_ ? *debug_str_offsets_ : emptyBytes(); }
const std::vector<uint8_t>& DebugMacroParser::debugLine() const { return debug_line_ ? *debug_line_ : emptyBytes(); }

void DebugMacroParser::setStrOffsetsBase(uint64_t str_offsets_base, uint8_t offset_size) {
    str_offsets_base_ = str_offsets_base;
    str_offsets_entry_size_ = (offset_size == 8) ? 8 : 4;
    str_offsets_end_ = debugStrOffsets().size();

    // Best-effort normalize if the base points at either:
    // - the start of a DWARF5 .debug_str_offsets contribution header, or
    // - the start of the offsets table (immediately after the header).
    //
    // Also record the contribution's end so we don't read into the next one.
    struct Contribution {
        uint64_t table_start = 0;
        uint64_t unit_end = 0;
        bool ok = false;
    };

    auto tryParseContributionAt = [&](uint64_t contribution_start) -> Contribution {
        Contribution out;
        const auto& so = debugStrOffsets();
        if (so.empty()) return out;
        if (contribution_start >= so.size()) return out;

        uint64_t off = contribution_start;
        uint32_t initial_length = DwarfUtils::readU32(so.data(), off, so.size());
        bool is64 = (initial_length == 0xffffffffu);
        uint64_t unit_length = is64 ? DwarfUtils::readU64(so.data(), off, so.size())
                                    : initial_length;
        uint64_t length_field_size = is64 ? 12 : 4;
        uint64_t unit_end = contribution_start + length_field_size + unit_length;
        if (unit_end > so.size() || unit_end < off) return out;

        uint16_t version = DwarfUtils::readU16(so.data(), off, unit_end);
        uint16_t padding = DwarfUtils::readU16(so.data(), off, unit_end);
        if (version != 5) return out;
        if (padding != 0) return out;

        out.table_start = off;
        out.unit_end = unit_end;
        out.ok = true;
        return out;
    };

    const auto& so = debugStrOffsets();
    if (!so.empty() && str_offsets_base_ < so.size()) {
        // Case 1: base points at contribution header.
        auto c = tryParseContributionAt(str_offsets_base_);
        if (c.ok) {
            str_offsets_base_ = c.table_start;
            str_offsets_end_ = c.unit_end;
            return;
        }

        // Case 2: base points at table start; header is just before it.
        // DWARF32 header size = 4 (len) + 2 (ver) + 2 (pad) = 8
        // DWARF64 header size = 12 (len) + 2 (ver) + 2 (pad) = 16
        if (str_offsets_base_ >= 8) {
            auto c32 = tryParseContributionAt(str_offsets_base_ - 8);
            if (c32.ok && c32.table_start == str_offsets_base_) {
                str_offsets_end_ = c32.unit_end;
                return;
            }
        }
        if (str_offsets_base_ >= 16) {
            auto c64 = tryParseContributionAt(str_offsets_base_ - 16);
            if (c64.ok && c64.table_start == str_offsets_base_) {
                str_offsets_end_ = c64.unit_end;
                return;
            }
        }
    }
}

std::optional<DebugMacroHeader> DebugMacroParser::parseHeader(uint64_t& offset) {
    const auto& m = debugMacro();
    if (offset + 4 > m.size()) {
        return std::nullopt;
    }
    clearDecodeError();

    DebugMacroHeader header;

    uint64_t unit_start = offset;
    uint64_t section_end = m.size();

    // unit_length (DWARF32 or DWARF64)
    uint32_t initial_length = readU32(offset, section_end);
    if (hasDecodeError()) return std::nullopt;
    if (initial_length == 0xffffffffu) {
        header.is_dwarf64 = true;
        header.unit_length = readU64(offset, section_end);
        if (hasDecodeError()) return std::nullopt;
    } else {
        header.is_dwarf64 = false;
        header.unit_length = initial_length;
    }

    uint64_t length_field_size = header.is_dwarf64 ? 12 : 4;
    if (header.unit_length > (m.size() - unit_start - length_field_size)) {
        return std::nullopt;
    }
    uint64_t unit_end = unit_start + length_field_size + header.unit_length;
    if (unit_end > m.size() || unit_end < offset) {
        return std::nullopt;
    }
    header.unit_start = unit_start;
    header.unit_end = unit_end;

    // Read version
    header.version = readU16(offset, unit_end);
    if (hasDecodeError()) return std::nullopt;
    if (header.version != 5) {
        // Only DWARF 5 .debug_macro is supported
        return std::nullopt;
    }

    // Read flags
    header.flags = readU8(offset, unit_end);
    if (hasDecodeError()) return std::nullopt;
    // DWARF5 defines only the low 3 bits; higher bits are reserved.
    if ((header.flags & 0xF8) != 0) {
        return std::nullopt;
    }

    // Determine offset size from flags
    header.offset_size = (header.flags & 0x01) ? 8 : 4;

    // Check for debug_line_offset
    header.has_debug_line_offset = (header.flags & 0x02) != 0;
    if (header.has_debug_line_offset) {
        header.debug_line_offset = readOffset(offset, header.offset_size, unit_end);
        if (hasDecodeError()) return std::nullopt;
    } else {
        header.debug_line_offset = 0;
    }

    // Check for opcode operands table (vendor extension)
    header.has_opcode_operands_table = (header.flags & 0x04) != 0;
    if (header.has_opcode_operands_table) {
        // Parse the opcode operands table.
        uint8_t opcode_count = readU8(offset, unit_end);
        if (hasDecodeError()) return std::nullopt;
        for (uint8_t i = 0; i < opcode_count; ++i) {
            uint8_t opcode = readU8(offset, unit_end);
            uint64_t operand_count = readULEB128(offset, unit_end);
            if (hasDecodeError()) return std::nullopt;
            if (operand_count > (unit_end - offset)) return std::nullopt;
            std::vector<uint64_t> forms;
            forms.reserve(static_cast<size_t>(operand_count));
            for (uint64_t j = 0; j < operand_count; ++j) {
                // DWARF encodes forms as ULEB128 values (even though most are <= 0xff).
                uint64_t form = readULEB128(offset, unit_end);
                if (hasDecodeError()) return std::nullopt;
                forms.push_back(form);
            }
            header.opcode_operand_forms[opcode] = std::move(forms);
        }
    }

    return header;
}

void DebugMacroParser::gatherMacroUnitEntries(uint64_t unit_offset,
                                              std::unordered_set<uint64_t>& visited,
                                              std::vector<MacroEntry>& out) {
    if (unit_offset >= debugMacro().size()) return;
    if (visited.find(unit_offset) != visited.end()) return;
    visited.insert(unit_offset);

    uint64_t offset = unit_offset;
    auto header_opt = parseHeader(offset);
    if (!header_opt) return;
    const DebugMacroHeader& header = *header_opt;

    // Parse entries until end-of-unit.
    while (offset < header.unit_end) {
        auto eopt = parseEntry(offset, header.unit_end, header);
        if (!eopt) break;
        out.push_back(*eopt);

        // Follow imports within the same .debug_macro section.
        if (eopt->type == DW_MACRO::DW_MACRO_import) {
            gatherMacroUnitEntries(eopt->import_offset, visited, out);
        }
    }
}

std::vector<MacroEntry> DebugMacroParser::parseMacroUnit(uint64_t offset) {
    std::vector<MacroEntry> entries;

    if (offset >= debugMacro().size()) {
        return entries;
    }

    auto header_opt = parseHeader(offset);
    if (!header_opt) {
        return entries;
    }

    const DebugMacroHeader& header = *header_opt;
    uint64_t unit_end = header.unit_end;

    // Parse entries until end of unit
    while (offset < unit_end) {
        auto entry_opt = parseEntry(offset, unit_end, header);
        if (!entry_opt) {
            break; // End of unit or error
        }

        entries.push_back(*entry_opt);
    }

    return entries;
}

std::optional<MacroEntry> DebugMacroParser::parseEntry(uint64_t& offset, uint64_t unit_end, const DebugMacroHeader& header) {
    if (offset >= unit_end) {
        return std::nullopt;
    }
    clearDecodeError();

    uint8_t opcode = readU8(offset, unit_end);
    if (hasDecodeError()) return std::nullopt;
    if (opcode == 0) {
        return std::nullopt; // End of macro list
    }

    MacroEntry entry;
    entry.type = static_cast<DW_MACRO>(opcode);
    entry.line = 0;
    entry.file_index = 0;
    entry.import_offset = 0;

    switch (entry.type) {
        case DW_MACRO::DW_MACRO_define: {
            entry.line = readULEB128(offset, unit_end);
            if (hasDecodeError()) return std::nullopt;
            std::string macro_str = readString(offset, unit_end);
            bool is_func;
            parseMacroString(macro_str, entry.name, entry.value, is_func);
            break;
        }

        case DW_MACRO::DW_MACRO_undef: {
            entry.line = readULEB128(offset, unit_end);
            if (hasDecodeError()) return std::nullopt;
            entry.name = readString(offset, unit_end);
            break;
        }

        case DW_MACRO::DW_MACRO_start_file: {
            entry.line = readULEB128(offset, unit_end);
            if (hasDecodeError()) return std::nullopt;
            entry.file_index = readULEB128(offset, unit_end);
            if (hasDecodeError()) return std::nullopt;
            break;
        }

        case DW_MACRO::DW_MACRO_end_file: {
            // No operands
            break;
        }

        case DW_MACRO::DW_MACRO_define_strp: {
            entry.line = readULEB128(offset, unit_end);
            if (hasDecodeError()) return std::nullopt;
            uint64_t str_offset = readOffset(offset, header.offset_size, unit_end);
            if (hasDecodeError()) return std::nullopt;
            std::string macro_str = getStringFromStrp(str_offset);
            bool is_func;
            parseMacroString(macro_str, entry.name, entry.value, is_func);
            break;
        }

        case DW_MACRO::DW_MACRO_undef_strp: {
            entry.line = readULEB128(offset, unit_end);
            if (hasDecodeError()) return std::nullopt;
            uint64_t str_offset = readOffset(offset, header.offset_size, unit_end);
            if (hasDecodeError()) return std::nullopt;
            entry.name = getStringFromStrp(str_offset);
            break;
        }

        case DW_MACRO::DW_MACRO_import: {
            entry.import_offset = readOffset(offset, header.offset_size, unit_end);
            if (hasDecodeError()) return std::nullopt;
            break;
        }

        case DW_MACRO::DW_MACRO_define_sup: {
            entry.line = readULEB128(offset, unit_end);
            if (hasDecodeError()) return std::nullopt;
            uint64_t str_offset = readOffset(offset, header.offset_size, unit_end);
            if (hasDecodeError()) return std::nullopt;
            std::string macro_str = getStringFromSupStrp(str_offset);
            if (macro_str.empty()) {
                entry.name = "<sup:" + std::to_string(str_offset) + ">";
                break;
            }
            bool is_func;
            parseMacroString(macro_str, entry.name, entry.value, is_func);
            break;
        }

        case DW_MACRO::DW_MACRO_undef_sup: {
            entry.line = readULEB128(offset, unit_end);
            if (hasDecodeError()) return std::nullopt;
            uint64_t str_offset = readOffset(offset, header.offset_size, unit_end);
            if (hasDecodeError()) return std::nullopt;
            std::string s = getStringFromSupStrp(str_offset);
            if (s.empty()) {
                entry.name = "<sup:" + std::to_string(str_offset) + ">";
            } else {
                entry.name = s;
            }
            break;
        }

        case DW_MACRO::DW_MACRO_import_sup: {
            entry.import_offset = readOffset(offset, header.offset_size, unit_end);
            if (hasDecodeError()) return std::nullopt;
            break;
        }

        case DW_MACRO::DW_MACRO_define_strx: {
            entry.line = readULEB128(offset, unit_end);
            if (hasDecodeError()) return std::nullopt;
            uint64_t index = readULEB128(offset, unit_end);
            if (hasDecodeError()) return std::nullopt;
            std::string macro_str = getStringFromStrx(index);
            bool is_func;
            parseMacroString(macro_str, entry.name, entry.value, is_func);
            break;
        }

        case DW_MACRO::DW_MACRO_undef_strx: {
            entry.line = readULEB128(offset, unit_end);
            if (hasDecodeError()) return std::nullopt;
            uint64_t index = readULEB128(offset, unit_end);
            if (hasDecodeError()) return std::nullopt;
            entry.name = getStringFromStrx(index);
            break;
        }

        default:
            // Unknown opcode. If an opcode operands table is present, we can skip according to
            // its operand forms and continue parsing the unit.
            if (header.has_opcode_operands_table) {
	                auto it = header.opcode_operand_forms.find(opcode);
	                if (it != header.opcode_operand_forms.end()) {
	                    std::function<bool(uint64_t, int)> skipForm;
	                    skipForm = [&](uint64_t form, int depth) -> bool {
	                        if (depth > 4) {
	                            return false;
	                        }
	                        switch (static_cast<DwarfForm>(form)) {
	                            case DwarfForm::DW_FORM_flag_present:
	                                return true;
                            case DwarfForm::DW_FORM_flag:
                            case DwarfForm::DW_FORM_ref1:
                            case DwarfForm::DW_FORM_data1:
                                readU8(offset, unit_end);
                                return !hasDecodeError() && offset <= unit_end;
                            case DwarfForm::DW_FORM_ref2:
                            case DwarfForm::DW_FORM_data2:
                                readU16(offset, unit_end);
                                return !hasDecodeError() && offset <= unit_end;
                            case DwarfForm::DW_FORM_ref4:
                            case DwarfForm::DW_FORM_data4:
                                (void)readU32(offset, unit_end);
                                return !hasDecodeError() && offset <= unit_end;
                            case DwarfForm::DW_FORM_ref8:
                            case DwarfForm::DW_FORM_data8:
                            case DwarfForm::DW_FORM_ref_sig8:
                                (void)readU64(offset, unit_end);
                                return !hasDecodeError() && offset <= unit_end;
                            case DwarfForm::DW_FORM_data16:
                                if (16 > (unit_end - offset)) return false;
                                offset += 16;
                                return true;
	                            case DwarfForm::DW_FORM_udata:
	                            case DwarfForm::DW_FORM_ref_udata:
	                            case DwarfForm::DW_FORM_strx:
                            case DwarfForm::DW_FORM_GNU_str_index:
	                            case DwarfForm::DW_FORM_addrx:
                            case DwarfForm::DW_FORM_GNU_addr_index:
	                            case DwarfForm::DW_FORM_loclistx:
                            case DwarfForm::DW_FORM_rnglistx:
                                (void)readULEB128(offset, unit_end);
                                return !hasDecodeError() && offset <= unit_end;
                            case DwarfForm::DW_FORM_sdata:
                                (void)readSLEB128(offset, unit_end);
                                return !hasDecodeError() && offset <= unit_end;
	                            case DwarfForm::DW_FORM_string:
	                                (void)readString(offset, unit_end);
	                                return offset <= unit_end;
                            case DwarfForm::DW_FORM_strx1:
                            case DwarfForm::DW_FORM_addrx1:
                                readU8(offset, unit_end);
                                return !hasDecodeError() && offset <= unit_end;
                            case DwarfForm::DW_FORM_strx2:
                            case DwarfForm::DW_FORM_addrx2:
                                readU16(offset, unit_end);
                                return !hasDecodeError() && offset <= unit_end;
                            case DwarfForm::DW_FORM_strx3:
                            case DwarfForm::DW_FORM_addrx3:
                                if (3 > (unit_end - offset)) return false;
                                offset += 3;
                                return true;
                            case DwarfForm::DW_FORM_strx4:
                            case DwarfForm::DW_FORM_addrx4:
                                (void)readU32(offset, unit_end);
                                return !hasDecodeError() && offset <= unit_end;
                            case DwarfForm::DW_FORM_strp:
                            case DwarfForm::DW_FORM_sec_offset:
                            case DwarfForm::DW_FORM_line_strp:
                            case DwarfForm::DW_FORM_strp_sup:
                            case DwarfForm::DW_FORM_GNU_strp_alt:
                            case DwarfForm::DW_FORM_GNU_ref_alt:
                            case DwarfForm::DW_FORM_addr:
                            case DwarfForm::DW_FORM_ref_addr:
                                (void)readOffset(offset, header.offset_size, unit_end);
                                return !hasDecodeError() && offset <= unit_end;
                            case DwarfForm::DW_FORM_ref_sup4:
                                (void)readU32(offset, unit_end);
                                return !hasDecodeError() && offset <= unit_end;
                            case DwarfForm::DW_FORM_ref_sup8:
                                (void)readU64(offset, unit_end);
                                return !hasDecodeError() && offset <= unit_end;
                            case DwarfForm::DW_FORM_block1: {
                                uint64_t len = readU8(offset, unit_end);
                                if (hasDecodeError()) return false;
                                if (len > (unit_end - offset)) return false;
                                offset += len;
                                return true;
                            }
                            case DwarfForm::DW_FORM_block2: {
                                uint64_t len = readU16(offset, unit_end);
                                if (hasDecodeError()) return false;
                                if (len > (unit_end - offset)) return false;
                                offset += len;
                                return true;
                            }
                            case DwarfForm::DW_FORM_block4: {
                                uint64_t len = readU32(offset, unit_end);
                                if (hasDecodeError()) return false;
                                if (len > (unit_end - offset)) return false;
                                offset += len;
                                return true;
                            }
                            case DwarfForm::DW_FORM_block:
                            case DwarfForm::DW_FORM_exprloc: {
                                uint64_t len = readULEB128(offset, unit_end);
                                if (hasDecodeError()) return false;
                                if (len > (unit_end - offset)) return false;
                                offset += len;
                                return true;
                            }
                            case DwarfForm::DW_FORM_indirect: {
                                uint64_t f = readULEB128(offset, unit_end);
                                if (hasDecodeError()) return false;
                                if (offset > unit_end) return false;
                                return skipForm(f, depth + 1);
                            }
	                            default:
	                                return false;
	                        }
	                    };

	                    for (uint64_t f : it->second) {
	                        if (!skipForm(f, 0)) {
	                            offset = unit_end;
	                            return std::nullopt;
	                        }
	                    }
                    // Return a placeholder entry so callers can keep consuming subsequent entries.
                    return entry;
                }
            }

            // Otherwise we cannot reliably recover. Clamp to unit end so callers don't attempt to
            // re-parse mid-unit.
            offset = unit_end;
            return std::nullopt;
    }

    if (hasDecodeError() || offset > unit_end) {
        offset = unit_end;
        return std::nullopt;
    }
    return entry;
}

void DebugMacroParser::parseMacroString(const std::string& str, std::string& name,
                                         std::string& value, bool& is_function_like) {
    // Macro string format: "NAME VALUE" or "NAME(PARAMS) VALUE"
    is_function_like = false;
    name.clear();
    value.clear();

    if (str.empty()) {
        return;
    }

    size_t pos = 0;

    // Find end of name (space, '(', or end of string)
    while (pos < str.size() && str[pos] != ' ' && str[pos] != '(') {
        pos++;
    }

    name = str.substr(0, pos);

    if (pos >= str.size()) {
        return; // Name only, no value
    }

    if (str[pos] == '(') {
        is_function_like = true;
        // Include parameters in name for function-like macros
        size_t paren_end = str.find(')', pos);
        if (paren_end != std::string::npos) {
            name = str.substr(0, paren_end + 1);
            pos = paren_end + 1;
        }
    }

    // Skip space between name and value
    if (pos < str.size() && str[pos] == ' ') {
        pos++;
    }

    // Rest is the value
    if (pos < str.size()) {
        value = str.substr(pos);
    }
}

std::vector<MacroDefinition> DebugMacroParser::getDefinitions(uint64_t offset) {
    std::vector<MacroDefinition> definitions;
    std::vector<MacroEntry> entries;
    std::unordered_set<uint64_t> visited;
    gatherMacroUnitEntries(offset, visited, entries);

    for (const auto& entry : entries) {
        if (entry.type == DW_MACRO::DW_MACRO_define ||
            entry.type == DW_MACRO::DW_MACRO_define_strp ||
            entry.type == DW_MACRO::DW_MACRO_define_sup ||
            entry.type == DW_MACRO::DW_MACRO_define_strx) {
            MacroDefinition def;
            def.line = entry.line;
            def.name = entry.name;
            def.value = entry.value;
            def.is_function_like = (entry.name.find('(') != std::string::npos);
            definitions.push_back(def);
        }
    }

    return definitions;
}

std::vector<MacroUndefinition> DebugMacroParser::getUndefinitions(uint64_t offset) {
    std::vector<MacroUndefinition> undefinitions;
    std::vector<MacroEntry> entries;
    std::unordered_set<uint64_t> visited;
    gatherMacroUnitEntries(offset, visited, entries);

    for (const auto& entry : entries) {
        if (entry.type == DW_MACRO::DW_MACRO_undef ||
            entry.type == DW_MACRO::DW_MACRO_undef_strp ||
            entry.type == DW_MACRO::DW_MACRO_undef_sup ||
            entry.type == DW_MACRO::DW_MACRO_undef_strx) {
            MacroUndefinition undef;
            undef.line = entry.line;
            undef.name = entry.name;
            undefinitions.push_back(undef);
        }
    }

    return undefinitions;
}

std::vector<MacroDefinition> DebugMacroParser::lookupMacro(const std::string& name, uint64_t offset) {
    std::vector<MacroDefinition> results;
    auto definitions = getDefinitions(offset);

    for (const auto& def : definitions) {
        // Extract just the name part (before '(' for function-like macros)
        std::string def_name = def.name;
        size_t paren_pos = def_name.find('(');
        if (paren_pos != std::string::npos) {
            def_name = def_name.substr(0, paren_pos);
        }

        if (def_name == name) {
            results.push_back(def);
        }
    }

    return results;
}

std::string DebugMacroParser::getStringFromStrp(uint64_t str_offset) const {
    const auto& s = debugStr();
    if (str_offset >= s.size()) {
        return "";
    }

    const char* str = reinterpret_cast<const char*>(s.data() + str_offset);
    size_t max_len = s.size() - str_offset;
    size_t len = strnlen(str, max_len);
    if (len == max_len) {
        // Unterminated string payload.
        return "";
    }

    return std::string(str, len);
}

std::string DebugMacroParser::getStringFromSupStrp(uint64_t str_offset) const {
    const auto& s = debugStrSup();
    if (s.empty() || str_offset >= s.size()) {
        return "";
    }

    const char* str = reinterpret_cast<const char*>(s.data() + str_offset);
    size_t max_len = s.size() - str_offset;
    size_t len = strnlen(str, max_len);
    if (len == max_len) {
        // Unterminated string payload.
        return "";
    }
    return std::string(str, len);
}

std::string DebugMacroParser::getStringFromStrx(uint64_t index) const {
    // Look up in debug_str_offsets using str_offsets_base_
    if (str_offsets_entry_size_ == 0) return "";
    if (index > (std::numeric_limits<uint64_t>::max() / str_offsets_entry_size_)) return "";
    uint64_t entry_offset = str_offsets_base_ + (index * str_offsets_entry_size_);

    if (entry_offset > str_offsets_end_) {
        return "";
    }
    if (str_offsets_entry_size_ > (str_offsets_end_ - entry_offset)) {
        return "";
    }

    // Read the string offset from the offsets table
    uint64_t tmp = entry_offset;
    const auto& so = debugStrOffsets();
    uint64_t str_offset = (str_offsets_entry_size_ == 8)
                              ? DwarfUtils::readU64(so.data(), tmp, str_offsets_end_)
                              : DwarfUtils::readU32(so.data(), tmp, str_offsets_end_);

    return getStringFromStrp(str_offset);
}

// Reading helpers

uint8_t DebugMacroParser::readU8(uint64_t& offset, uint64_t max) const {
    if (max > debugMacro().size() || offset + 1 > max) {
        decode_error_ = true;
        return 0;
    }
    return DwarfUtils::readU8(debugMacro().data(), offset, max);
}

uint16_t DebugMacroParser::readU16(uint64_t& offset, uint64_t max) const {
    if (max > debugMacro().size() || offset + 2 > max) {
        decode_error_ = true;
        return 0;
    }
    return DwarfUtils::readU16(debugMacro().data(), offset, max);
}

uint32_t DebugMacroParser::readU32(uint64_t& offset, uint64_t max) const {
    if (max > debugMacro().size() || offset + 4 > max) {
        decode_error_ = true;
        return 0;
    }
    return DwarfUtils::readU32(debugMacro().data(), offset, max);
}

uint64_t DebugMacroParser::readU64(uint64_t& offset, uint64_t max) const {
    if (max > debugMacro().size() || offset + 8 > max) {
        decode_error_ = true;
        return 0;
    }
    return DwarfUtils::readU64(debugMacro().data(), offset, max);
}

uint64_t DebugMacroParser::readOffset(uint64_t& offset, uint8_t size, uint64_t max) const {
    if (size == 8) {
        return readU64(offset, max);
    } else if (size == 4) {
        return readU32(offset, max);
    }
    decode_error_ = true;
    return 0;
}

uint64_t DebugMacroParser::readULEB128(uint64_t& offset, uint64_t max) const {
    if (max > debugMacro().size() || offset >= max) {
        decode_error_ = true;
        return 0;
    }

    uint64_t result = 0;
    unsigned shift = 0;
    const auto& m = debugMacro();
    while (offset < max) {
        uint8_t byte = m[offset++];
        uint64_t bits = static_cast<uint64_t>(byte & 0x7f);
        if (shift > 63 || (shift == 63 && bits > 1)) {
            decode_error_ = true;
            return 0;
        }
        result |= (bits << shift);
        if ((byte & 0x80) == 0) return result;
        shift += 7;
    }
    decode_error_ = true;
    return 0;
}

int64_t DebugMacroParser::readSLEB128(uint64_t& offset, uint64_t max) const {
    if (max > debugMacro().size() || offset >= max) {
        decode_error_ = true;
        return 0;
    }

    uint64_t result = 0;
    unsigned shift = 0;
    uint8_t byte = 0;
    const auto& m = debugMacro();
    while (offset < max) {
        byte = m[offset++];
        uint64_t bits = static_cast<uint64_t>(byte & 0x7f);
        if (shift > 63 || (shift == 63 && bits != 0 && bits != 0x7f)) {
            decode_error_ = true;
            return 0;
        }
        result |= (bits << shift);
        shift += 7;
        if ((byte & 0x80) == 0) {
            if (shift < 64 && (byte & 0x40)) result |= (~0ULL << shift);
            return static_cast<int64_t>(result);
        }
    }
    decode_error_ = true;
    return 0;
}

std::string DebugMacroParser::readString(uint64_t& offset, uint64_t max) const {
    if (offset >= max) {
        return "";
    }
    if (max > debugMacro().size()) {
        decode_error_ = true;
        return "";
    }

    const auto& m = debugMacro();
    const char* str = reinterpret_cast<const char*>(m.data() + offset);
    size_t max_len = static_cast<size_t>(max - offset);
    size_t len = strnlen(str, max_len);
    if (len == max_len) {
        // Unterminated string; consume to end-of-unit and treat as malformed.
        offset = max;
        decode_error_ = true;
        return "";
    }
    offset += len + 1;
    return std::string(str, len);
}

void DebugMacroParser::clearDecodeError() const {
    decode_error_ = false;
}

bool DebugMacroParser::hasDecodeError() const {
    return decode_error_;
}

} // namespace dwarf
