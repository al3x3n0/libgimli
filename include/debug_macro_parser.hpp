#pragma once

#include "dwarf_types.hpp"
#include <vector>
#include <string>
#include <cstdint>
#include <optional>
#include <unordered_set>
#include <unordered_map>

namespace dwarf {

// DWARF 5 Macro information entry types
enum class DW_MACRO : uint8_t {
    DW_MACRO_define = 0x01,
    DW_MACRO_undef = 0x02,
    DW_MACRO_start_file = 0x03,
    DW_MACRO_end_file = 0x04,
    DW_MACRO_define_strp = 0x05,
    DW_MACRO_undef_strp = 0x06,
    DW_MACRO_import = 0x07,
    DW_MACRO_define_sup = 0x08,
    DW_MACRO_undef_sup = 0x09,
    DW_MACRO_import_sup = 0x0a,
    DW_MACRO_define_strx = 0x0b,
    DW_MACRO_undef_strx = 0x0c
};

// Macro definition
struct MacroDefinition {
    uint64_t line;          // Source line number
    std::string name;       // Macro name
    std::string value;      // Macro value (empty for function-like with no body)
    bool is_function_like;  // True if macro has parameters
};

// Macro undefinition
struct MacroUndefinition {
    uint64_t line;          // Source line number
    std::string name;       // Macro name
};

// File inclusion information
struct MacroFileChange {
    uint64_t line;          // Line number in including file
    uint64_t file_index;    // Index into file table
    bool is_start;          // true for start_file, false for end_file
};

// Macro import (transparent include)
struct MacroImport {
    uint64_t offset;        // Offset to imported macro unit
};

// Generic macro entry
struct MacroEntry {
    DW_MACRO type;
    uint64_t line;
    std::string name;
    std::string value;
    uint64_t file_index;
    uint64_t import_offset;
};

// Header for a .debug_macro unit
struct DebugMacroHeader {
    uint64_t unit_start = 0;
    uint64_t unit_end = 0;      // absolute section offset of end-of-unit
    uint64_t unit_length = 0;   // length of unit content (excluding initial length field(s))
    bool is_dwarf64 = false;

    uint16_t version;
    uint8_t flags;
    bool has_debug_line_offset;
    bool has_opcode_operands_table;
    uint64_t debug_line_offset;
    uint8_t offset_size;    // 4 or 8

    // If has_opcode_operands_table is set, this maps opcode -> operand forms (DW_FORM_* values).
    // This allows best-effort skipping (and continued parsing) for opcodes we don't explicitly handle.
    std::unordered_map<uint8_t, std::vector<uint64_t>> opcode_operand_forms;
};

// Parser for DWARF 5 .debug_macro section
class DebugMacroParser {
public:
    explicit DebugMacroParser(const std::vector<uint8_t>& debug_macro);
    DebugMacroParser(const std::vector<uint8_t>& debug_macro,
                     const std::vector<uint8_t>* debug_str,
                     const std::vector<uint8_t>* debug_str_sup,
                     const std::vector<uint8_t>* debug_str_offsets,
                     const std::vector<uint8_t>* debug_line);

    // Parse macro information starting at offset
    std::vector<MacroEntry> parseMacroUnit(uint64_t offset);

    // Get all macro definitions
    std::vector<MacroDefinition> getDefinitions(uint64_t offset);

    // Get all macro undefinitions
    std::vector<MacroUndefinition> getUndefinitions(uint64_t offset);

    // Lookup macro by name (returns all definitions)
    std::vector<MacroDefinition> lookupMacro(const std::string& name, uint64_t offset);

    // Set context for indexed string lookups (DWARF 5)
    void setStrOffsetsBase(uint64_t str_offsets_base, uint8_t offset_size = 4);

    // Check if section is empty
    bool empty() const { return !debug_macro_ || debug_macro_->empty(); }
    size_t size() const { return debug_macro_ ? debug_macro_->size() : 0; }

private:
    const std::vector<uint8_t>* debug_macro_ = nullptr;
    const std::vector<uint8_t>* debug_str_ = nullptr;
    const std::vector<uint8_t>* debug_str_sup_ = nullptr;
    const std::vector<uint8_t>* debug_str_offsets_ = nullptr;
    const std::vector<uint8_t>* debug_line_ = nullptr;

    uint64_t str_offsets_base_ = 0;
    uint8_t str_offsets_entry_size_ = 4;
    uint64_t str_offsets_end_ = 0; // end of the .debug_str_offsets contribution

    const std::vector<uint8_t>& debugMacro() const;
    const std::vector<uint8_t>& debugStr() const;
    const std::vector<uint8_t>& debugStrSup() const;
    const std::vector<uint8_t>& debugStrOffsets() const;
    const std::vector<uint8_t>& debugLine() const;

    void gatherMacroUnitEntries(uint64_t unit_offset,
                               std::unordered_set<uint64_t>& visited,
                               std::vector<MacroEntry>& out);

    // Parse a single macro entry
    std::optional<MacroEntry> parseEntry(uint64_t& offset, uint64_t unit_end, const DebugMacroHeader& header);

    // Parse header
    std::optional<DebugMacroHeader> parseHeader(uint64_t& offset);

    // Parse macro definition string into name and value
    void parseMacroString(const std::string& str, std::string& name, std::string& value, bool& is_function_like);

    // String resolution
    std::string getStringFromStrp(uint64_t str_offset) const;
    std::string getStringFromSupStrp(uint64_t str_offset) const;
    std::string getStringFromStrx(uint64_t index) const;

    // Reading helpers
    uint8_t readU8(uint64_t& offset, uint64_t max) const;
    uint16_t readU16(uint64_t& offset, uint64_t max) const;
    uint32_t readU32(uint64_t& offset, uint64_t max) const;
    uint64_t readU64(uint64_t& offset, uint64_t max) const;
    uint64_t readOffset(uint64_t& offset, uint8_t size, uint64_t max) const;
    uint64_t readULEB128(uint64_t& offset, uint64_t max) const;
    int64_t readSLEB128(uint64_t& offset, uint64_t max) const;
    std::string readString(uint64_t& offset, uint64_t max) const;
    void clearDecodeError() const;
    bool hasDecodeError() const;

    mutable bool decode_error_ = false;
};

} // namespace dwarf
