#pragma once

#include "dwarf_types.hpp"
#include <elfio/elfio.hpp>
#include <memory>
#include <vector>
#include <map>

namespace dwarf {

// Forward declaration
class AttributeParser;

class DIE {
public:
    DIE(DwarfTag tag, uint64_t offset, uint64_t size);
    
    // Getters
    DwarfTag getTag() const { return tag_; }
    uint64_t getOffset() const { return offset_; }
    uint64_t getSize() const { return size_; }
    uint64_t getCUBaseOffset() const { return cu_base_offset_; } // CU header start (biased)
    uint8_t getOffsetSize() const { return offset_size_; }       // 4 for DWARF32, 8 for DWARF64
    bool hasAttribute(DwarfAttribute attr) const;
    std::shared_ptr<AttributeValue> getAttribute(DwarfAttribute attr) const;
    const std::map<DwarfAttribute, std::shared_ptr<AttributeValue>>& getAttributes() const { return attributes_; }
    
    // Setters
    void addAttribute(DwarfAttribute attr, std::shared_ptr<AttributeValue> value);
    
    // Children management
    void addChild(std::shared_ptr<DIE> child);
    const std::vector<std::shared_ptr<DIE>>& getChildren() const { return children_; }
    
    // Utility methods
    std::string getTagName() const;
    std::string getName() const;
    std::string toString(int indent = 0) const;
    
    // Type-related methods
    std::shared_ptr<DIE> getType() const;
    uint64_t getByteSize() const;
    bool isType() const;
    
    // Size management
    void setSize(uint64_t size) { size_ = size; }
    void setCUBaseOffset(uint64_t cu_base_offset) { cu_base_offset_ = cu_base_offset; }
    void setOffsetSize(uint8_t offset_size) { offset_size_ = offset_size; }
    
private:
    DwarfTag tag_;
    uint64_t offset_;
    uint64_t size_;
    uint64_t cu_base_offset_ = 0;
    uint8_t offset_size_ = 4;
    std::map<DwarfAttribute, std::shared_ptr<AttributeValue>> attributes_;
    std::vector<std::shared_ptr<DIE>> children_;
};

class DIEParser {
public:
    DIEParser(const ELFIO::elfio& elf, const std::vector<uint8_t>& debug_info,
              const std::vector<uint8_t>& debug_abbrev, const std::vector<uint8_t>& debug_str,
              const std::vector<uint8_t>& debug_line = {},
              const std::vector<uint8_t>& debug_ranges = {},
              const std::vector<uint8_t>& debug_loc = {},
              const std::vector<uint8_t>& debug_str_offsets = {},
              const std::vector<uint8_t>& debug_addr = {},
              const std::vector<uint8_t>& debug_line_str = {},
              const std::vector<uint8_t>& debug_rnglists = {},
              const std::vector<uint8_t>& debug_loclists = {},
              const std::vector<uint8_t>& debug_str_sup = {},
              bool verbose = false,
              uint64_t debug_info_offset_bias = 0,
              uint64_t supplementary_debug_info_offset_bias = 0);
    
    // Main parsing methods
    std::vector<std::shared_ptr<DIE>> parseCompilationUnits();
    std::shared_ptr<DIE> parseDIE(uint64_t& offset,
                                  const std::vector<uint8_t>& abbrev_data,
                                  uint64_t abbrev_offset = 0,
                                  uint64_t cu_base_offset = 0,
                                  uint8_t offset_size = 4);
    
    // Utility methods
    std::string getString(uint64_t offset) const;
    std::vector<uint8_t> getAbbrevData(uint64_t offset) const;
    bool isValidOffset(uint64_t offset) const;
    
private:
    [[maybe_unused]] const ELFIO::elfio& elf_;
    const std::vector<uint8_t>& debug_info_;
    const std::vector<uint8_t>& debug_abbrev_;
    const std::vector<uint8_t>& debug_str_;
    std::shared_ptr<dwarf::AttributeParser> attribute_parser_;
    bool verbose_;
    uint64_t debug_info_offset_bias_ = 0;
    
    // Parsing helpers
    uint64_t readULEB128(uint64_t& offset) const;
    uint64_t readULEB128FromAbbrev(uint64_t& offset) const;
    int64_t readSLEB128FromAbbrev(uint64_t& offset) const;
    int64_t readSLEB128(uint64_t& offset) const;
    uint8_t readU8(uint64_t& offset) const;
    uint8_t readU8FromAbbrev(uint64_t& offset) const;
    uint16_t readU16(uint64_t& offset) const;
    uint32_t readU32(uint64_t& offset) const;
    uint64_t readU64(uint64_t& offset) const;
    
    // Abbreviation table parsing
    struct AbbreviationAttrSpec {
        DwarfAttribute attr;
        DwarfForm form;
        int64_t implicit_const = 0;
        bool has_implicit_const = false;
    };

    struct AbbreviationEntry {
        uint64_t code;
        DwarfTag tag;
        bool has_children;
        std::vector<AbbreviationAttrSpec> attributes;
    };
    
    std::map<uint64_t, AbbreviationEntry> parseAbbreviationTable();
    AbbreviationEntry parseAbbreviationEntry(uint64_t& offset) const;
    AbbreviationEntry lookupAbbreviationEntry(uint64_t code, uint64_t abbrev_offset = 0) const;
};

} // namespace dwarf
