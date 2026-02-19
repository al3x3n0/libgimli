#pragma once

#include "dwarf_types.hpp"
#include <vector>
#include <string>
#include <cstdint>
#include <optional>
#include <unordered_map>

namespace dwarf {

// DWARF 5 .debug_names index kinds
enum class DW_IDX : uint8_t {
    DW_IDX_compile_unit = 1,
    DW_IDX_type_unit = 2,
    DW_IDX_die_offset = 3,
    DW_IDX_parent = 4,
    DW_IDX_type_hash = 5
};

// Entry in the name table
struct NameEntry {
    std::string name;
    uint64_t hash;
    std::vector<uint64_t> die_offsets;    // DIE offsets for this name
    std::vector<uint64_t> cu_indices;      // CU indices for each DIE
    std::vector<DwarfTag> tags;            // Tags for each DIE
};

// Header for a .debug_names unit
struct DebugNamesHeader {
    uint64_t unit_length;
    uint16_t version;
    uint16_t padding;
    uint32_t comp_unit_count;
    uint32_t local_type_unit_count;
    uint32_t foreign_type_unit_count;
    uint32_t bucket_count;
    uint32_t name_count;
    uint32_t abbrev_table_size;
    uint32_t augmentation_string_size;
    std::string augmentation_string;
    bool is_dwarf64;
    uint64_t header_size;
};

// Abbreviation entry for name index
struct NameIndexAbbrev {
    uint64_t code;
    DwarfTag tag;
    std::vector<std::pair<DW_IDX, DwarfForm>> attributes;
};

// Parser for DWARF 5 .debug_names section
class DebugNamesParser {
public:
    DebugNamesParser(const std::vector<uint8_t>& debug_names,
                     const std::vector<uint8_t>& debug_str = {});

    // Parse the entire section
    bool parse();

    // Lookup functions
    std::vector<NameEntry> lookupName(const std::string& name) const;
    std::vector<NameEntry> lookupNameByTag(const std::string& name, DwarfTag tag) const;
    std::vector<uint64_t> lookupDIEOffsets(const std::string& name) const;

    // Get all names in the index
    std::vector<std::string> getAllNames() const;

    // Check if section is empty
    bool empty() const { return debug_names_.empty(); }
    size_t size() const { return debug_names_.size(); }

    // Get parsed header
    const DebugNamesHeader& getHeader() const { return header_; }

    // Get CU offsets
    const std::vector<uint64_t>& getCUOffsets() const { return cu_offsets_; }

private:
    struct Unit {
        DebugNamesHeader header{};
        uint64_t unit_start = 0;
        uint64_t unit_end = 0;
        uint64_t entry_pool_base = 0; // Absolute section offset to the entry pool start.

        std::vector<uint64_t> cu_offsets;
        std::vector<uint64_t> tu_offsets;
        std::vector<uint32_t> buckets;
        std::vector<uint32_t> hashes;
        std::vector<uint64_t> name_offsets;  // Offsets into .debug_str
        std::vector<uint64_t> entry_offsets; // Offsets into entry pool (relative to entry_pool_base)
        std::unordered_map<uint64_t, NameIndexAbbrev> abbrevs;
    };

    const std::vector<uint8_t>& debug_names_;
    const std::vector<uint8_t>& debug_str_;

    std::vector<Unit> units_;

    // Back-compat: mirror the first unit for callers that assume a single-unit parser.
    DebugNamesHeader header_;
    std::vector<uint64_t> cu_offsets_;

    // Name lookup cache (populated on first lookup)
    mutable std::unordered_map<std::string, std::vector<NameEntry>> name_cache_;
    mutable bool cache_populated_ = false;
    bool parsed_ = false;

    // Parsing helpers
    bool parseOneUnit(uint64_t& offset);
    bool parseHeader(Unit& unit, uint64_t& offset);
    bool parseCUList(Unit& unit, uint64_t& offset);
    bool parseTUList(Unit& unit, uint64_t& offset);
    bool parseForeignTUSignatures(Unit& unit, uint64_t& offset);
    bool parseBuckets(Unit& unit, uint64_t& offset);
    bool parseHashes(Unit& unit, uint64_t& offset);
    bool parseNameOffsets(Unit& unit, uint64_t& offset);
    bool parseEntryOffsets(Unit& unit, uint64_t& offset);
    bool parseAbbrevTable(Unit& unit, uint64_t& offset);
    void populateCache() const;

    // Hash function (DWARF 5 specified)
    static uint64_t hashName(const std::string& name);

    // Reading helpers
    uint8_t readU8(uint64_t& offset, uint64_t end) const;
    uint16_t readU16(uint64_t& offset, uint64_t end) const;
    uint32_t readU32(uint64_t& offset, uint64_t end) const;
    uint64_t readU64(uint64_t& offset, uint64_t end) const;
    uint64_t readOffset(uint64_t& offset, uint64_t end, bool is_dwarf64) const;
    uint64_t readULEB128(uint64_t& offset, uint64_t end) const;
    std::string readString(uint64_t offset) const;
    void clearDecodeError() const;
    bool hasDecodeError() const;

    mutable bool decode_error_ = false;
};

} // namespace dwarf
