#pragma once

#include "dwarf_types.hpp"
#include "die_parser.hpp"
#include "rnglists_parser.hpp"
#include "loclists_parser.hpp"
#include <memory>
#include <vector>
#include <map>

namespace dwarf {

// Forward declarations
class DwarfParser;
class TypeSystem;

// Line number program state machine registers (per DWARF spec section 6.2.2)
struct LineState {
    uint64_t address = 0;              // Program counter value
    uint32_t op_index = 0;             // For VLIW architectures
    uint32_t file = 1;                 // Source file index (1-based)
    uint32_t line = 1;                 // Source line number (1-based)
    uint32_t column = 0;               // Source column number
    bool is_stmt = false;              // Recommended breakpoint location
    bool basic_block = false;          // Beginning of basic block
    bool end_sequence = false;         // End of sequence marker
    bool prologue_end = false;         // Function prologue end (DWARF 3+)
    bool epilogue_begin = false;       // Function epilogue begin (DWARF 3+)
    uint32_t isa = 0;                  // Instruction set architecture
    uint32_t discriminator = 0;        // Block discriminator (DWARF 4+)

    // Reset registers to initial state
    void reset(bool default_is_stmt) {
        address = 0;
        op_index = 0;
        file = 1;
        line = 1;
        column = 0;
        is_stmt = default_is_stmt;
        basic_block = false;
        end_sequence = false;
        prologue_end = false;
        epilogue_begin = false;
        isa = 0;
        discriminator = 0;
    }
};

// Attribute parser for handling DWARF attributes
class AttributeParser {
public:
    AttributeParser(const std::vector<uint8_t>& debug_info,
                   const std::vector<uint8_t>& debug_abbrev,
                   const std::vector<uint8_t>& debug_str,
                   const std::vector<uint8_t>& debug_line = {},
                   const std::vector<uint8_t>& debug_ranges = {},
                   const std::vector<uint8_t>& debug_loc = {},
                   const std::vector<uint8_t>& debug_str_offsets = {},
                   const std::vector<uint8_t>& debug_addr = {},
                   const std::vector<uint8_t>& debug_line_str = {},
                   const std::vector<uint8_t>& debug_rnglists = {},
                   const std::vector<uint8_t>& debug_loclists = {},
                   const std::vector<uint8_t>& debug_str_sup = {});

    // Set CU context for resolving DWARF 5 indexed forms and CU-relative references
    void setCUContext(uint64_t rnglists_base, uint64_t loclists_base,
                      uint64_t addr_base, uint64_t str_offsets_base,
                      uint64_t base_address);
    void setCUOffset(uint64_t offset) { cu_debug_info_offset_ = offset; }
    void setCUDebugInfoEnd(uint64_t end) { cu_debug_info_end_ = (end <= debug_info_.size()) ? end : debug_info_.size(); }
    void setAddressSize(uint8_t size) { address_size_ = size; }
    void setDwarfVersion(DwarfVersion version) { dwarf_version_ = version; }
    void setIsDwarf64(bool is_dwarf64) { is_dwarf64_ = is_dwarf64; }
    void setDebugInfoOffsetBias(uint64_t bias) { debug_info_offset_bias_ = bias; }
    void setSupplementaryDebugInfoOffsetBias(uint64_t bias) { sup_debug_info_offset_bias_ = bias; }
    
    // Main parsing methods
    std::shared_ptr<AttributeValue> parseAttribute(DwarfForm form, uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseAttribute(DwarfAttribute attr, DwarfForm form, uint64_t& offset) const;
    std::vector<std::shared_ptr<AttributeValue>> parseAttributeList(const std::vector<std::pair<DwarfAttribute, DwarfForm>>& attr_specs, uint64_t& offset) const;
    
    // Specific attribute parsers
    std::shared_ptr<AttributeValue> parseAddressAttribute(DwarfForm form, uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseDataAttribute(DwarfForm form, uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseStringAttribute(DwarfForm form, uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseReferenceAttribute(DwarfForm form, uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseBlockAttribute(DwarfForm form, uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseExpressionAttribute(DwarfForm form, uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFlagAttribute(DwarfForm form, uint64_t& offset) const;
    
    // Complex attribute parsers
    std::shared_ptr<AttributeValue> parseLocationAttribute(DwarfAttribute attr, DwarfForm form, uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseRangeAttribute(DwarfAttribute attr, DwarfForm form, uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseLineAttribute(DwarfAttribute attr, DwarfForm form, uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseTypeAttribute(DwarfAttribute attr, DwarfForm form, uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseConstValueAttribute(DwarfAttribute attr, DwarfForm form, uint64_t& offset) const;
    
    // Utility methods
    std::string getString(uint64_t offset) const;
    std::string readString(uint64_t& offset) const;
    std::vector<uint8_t> getBlock(uint64_t offset, uint64_t size) const;
    bool isValidOffset(uint64_t offset) const;
    
    // Debug methods
    void printAttributeValue(std::shared_ptr<AttributeValue> value, const std::string& name) const;
    std::string attributeValueToString(std::shared_ptr<AttributeValue> value) const;
    
private:
    const std::vector<uint8_t>& debug_info_;
    [[maybe_unused]] const std::vector<uint8_t>& debug_abbrev_;
    const std::vector<uint8_t>& debug_str_;
    const std::vector<uint8_t>& debug_str_sup_;
    const std::vector<uint8_t>& debug_line_;
    const std::vector<uint8_t>& debug_ranges_;
    const std::vector<uint8_t>& debug_loc_;
    const std::vector<uint8_t>& debug_str_offsets_;
    const std::vector<uint8_t>& debug_addr_;
    const std::vector<uint8_t>& debug_line_str_;
    const std::vector<uint8_t>& debug_rnglists_;
    const std::vector<uint8_t>& debug_loclists_;

    // DWARF 5 parsers
    mutable std::unique_ptr<RngListsParser> rnglists_parser_;
    mutable std::unique_ptr<LocListsParser> loclists_parser_;

    // CU context for resolving DWARF 5 indexed forms and CU-relative references
    mutable uint64_t cu_debug_info_offset_ = 0;  // Offset of CU header in .debug_info
    mutable uint64_t cu_debug_info_end_ = 0;     // End of CU contribution in .debug_info (exclusive)
    mutable uint64_t cu_rnglists_base_ = 0;
    mutable uint64_t cu_rnglists_end_ = 0;         // contribution end (exclusive)
    mutable uint64_t cu_rnglists_offsets_end_ = 0; // offsets array end (exclusive)
    mutable bool cu_rnglists_is_dwarf64_ = false;  // from rnglists contribution header
    mutable uint8_t cu_rnglists_seg_size_ = 0;     // segment_selector_size from header
    mutable uint64_t cu_loclists_base_ = 0;
    mutable uint64_t cu_loclists_end_ = 0;         // contribution end (exclusive)
    mutable uint64_t cu_loclists_offsets_end_ = 0; // offsets array end (exclusive)
    mutable bool cu_loclists_is_dwarf64_ = false;  // from loclists contribution header
    mutable uint8_t cu_loclists_seg_size_ = 0;     // segment_selector_size from header
    mutable uint64_t cu_addr_base_ = 0;
    // End offset (exclusive) of the current CU's .debug_addr contribution.
    // Used to prevent DW_FORM_addrx* from reading into the next contribution.
    mutable uint64_t cu_addr_end_ = 0;
    // Size (in bytes) of a .debug_addr table entry: segment_selector_size + address_size.
    // We currently ignore the segment selector value but must skip it when reading addresses.
    mutable uint8_t cu_addr_seg_size_ = 0;
    mutable uint8_t cu_addr_entry_stride_ = 0;
    mutable uint64_t cu_str_offsets_base_ = 0;
    // End offset (exclusive) of the current CU's .debug_str_offsets contribution.
    // Used to prevent DW_FORM_strx* from reading into the next contribution.
    mutable uint64_t cu_str_offsets_end_ = 0;
    mutable uint64_t cu_base_address_ = 0;
    mutable uint8_t address_size_ = 8;
    mutable DwarfVersion dwarf_version_ = DwarfVersion::DWARF4;
    mutable bool is_dwarf64_ = false;
    mutable uint64_t debug_info_offset_bias_ = 0;
    mutable uint64_t sup_debug_info_offset_bias_ = 0;
    
    // Data reading helpers
    uint64_t readULEB128(uint64_t& offset) const;
    int64_t readSLEB128(uint64_t& offset) const;
    uint8_t readU8(uint64_t& offset) const;
    int8_t readS8(uint64_t& offset) const;
    uint16_t readU16(uint64_t& offset) const;
    uint32_t readU32(uint64_t& offset) const;
    uint64_t readU64(uint64_t& offset) const;
    
    // Form-specific parsers
    std::shared_ptr<AttributeValue> parseFormAddr(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormData1(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormData2(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormData4(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormData8(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormSdata(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormUdata(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormString(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormStrp(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormStrpSup(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormRef1(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormRef2(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormRef4(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormRef8(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormRefSup4(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormRefSup8(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormRefUdata(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormFlag(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormFlagPresent(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormBlock1(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormBlock2(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormBlock4(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormBlock(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormExprloc(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormIndirect(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormSecOffset(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormRefAddr(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormRefSig8(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormStrx(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormAddrx(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormData16(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormLineStrp(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormImplicitConst(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormRnglistx(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormLoclistx(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormAddrx1(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormAddrx2(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormAddrx3(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormAddrx4(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormStrx1(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormStrx2(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormStrx3(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseFormStrx4(uint64_t& offset) const;
    
    // Location expression parsers
    std::shared_ptr<AttributeValue> parseLocationExpression(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseLocationList(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseLocationListPointer(uint64_t& offset) const;
    
    // Range list parsers
    std::shared_ptr<AttributeValue> parseRangeList(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseRangeListPointer(uint64_t& offset) const;
    
    // Line number parsers
    std::shared_ptr<AttributeValue> parseLineNumberProgram(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseLineNumberProgramPointer(uint64_t& offset) const;
    
    // Type reference parsers
    std::shared_ptr<AttributeValue> parseTypeReference(uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseTypeSignature(uint64_t& offset) const;
    
    // Constant value parsers
    std::shared_ptr<AttributeValue> parseConstantValue(DwarfAttribute attr, DwarfForm form, uint64_t& offset) const;
    std::shared_ptr<AttributeValue> parseConstantExpression(DwarfAttribute attr, DwarfForm form, uint64_t& offset) const;
    
    // Helper methods
    bool isLittleEndian() const;
    uint64_t getAddressSize() const;
    uint64_t getOffsetSize() const;
    std::string formatAddress(uint64_t address) const;
    std::string formatOffset(uint64_t offset) const;
    uint64_t currentDebugInfoEnd() const;
    void advanceOffsetBounded(uint64_t& offset, uint64_t amount) const;
    std::string readCStringFromSection(const std::vector<uint8_t>& section,
                                       uint64_t offset,
                                       uint64_t* consumed = nullptr,
                                       bool* terminated = nullptr) const;
};

// Specialized attribute value classes for complex attributes
class LocationAttributeValue : public AttributeValue {
public:
    enum class LocationType {
        EXPRESSION,  // Single expression (from DW_FORM_exprloc)
        LIST,        // Location list with PC ranges
        INVALID
    };

    // Entry for location list (stores address range and expression)
    struct LocationEntry {
        uint64_t start;
        uint64_t end;
        std::vector<uint8_t> expression;
        bool is_default;  // For DW_LLE_default_location

        LocationEntry(uint64_t s = 0, uint64_t e = 0,
                      const std::vector<uint8_t>& expr = {},
                      bool def = false)
            : start(s), end(e), expression(expr), is_default(def) {}
    };

    // Constructor for single expression
    LocationAttributeValue(LocationType type, const std::vector<uint8_t>& data);

    // Constructor for location list with all entries
    LocationAttributeValue(const std::vector<LocationEntry>& entries);

    AttributeValueType getType() const override { return AttributeValueType::EXPRESSION; }
    std::string toString() const override;

    LocationType getLocationType() const { return type_; }
    const std::vector<uint8_t>& getData() const { return data_; }

    // Get all location entries (for LIST type)
    const std::vector<LocationEntry>& getEntries() const { return entries_; }

    // Get the expression for a specific PC address
    // Returns empty vector if no matching entry found
    std::vector<uint8_t> getExpressionForPC(uint64_t pc) const;

    // Check if address is covered by any entry
    bool containsPC(uint64_t pc) const;

private:
    LocationType type_;
    std::vector<uint8_t> data_;  // For single expression
    std::vector<LocationEntry> entries_;  // For location list
};

class RangeAttributeValue : public AttributeValue {
public:
    struct RangeEntry {
        uint64_t start;
        uint64_t end;
        bool is_base_address;
    };
    
    RangeAttributeValue(const std::vector<RangeEntry>& ranges);
    AttributeValueType getType() const override { return AttributeValueType::BLOCK; }
    std::string toString() const override;
    
    const std::vector<RangeEntry>& getRanges() const { return ranges_; }
    
private:
    std::vector<RangeEntry> ranges_;
};

class LineAttributeValue : public AttributeValue {
public:
    struct LineEntry {
        uint64_t address;
        uint32_t file;
        uint32_t line;
        uint32_t column;
        bool is_stmt;
        bool is_basic_block;
        bool is_end_sequence;
        bool prologue_end;       // DWARF 3+
        bool epilogue_begin;     // DWARF 3+
        uint32_t isa;            // DWARF 3+
        uint32_t discriminator;  // DWARF 4+
    };

    struct FileEntry {
        std::string filename;
        uint64_t dir_index;
        uint64_t mtime;
        uint64_t size;
    };

    LineAttributeValue(const std::vector<LineEntry>& lines,
                       const std::vector<std::string>& directories = {},
                       const std::vector<FileEntry>& files = {});
    AttributeValueType getType() const override { return AttributeValueType::BLOCK; }
    std::string toString() const override;

    const std::vector<LineEntry>& getLines() const { return lines_; }
    const std::vector<std::string>& getDirectories() const { return directories_; }
    const std::vector<FileEntry>& getFiles() const { return files_; }

private:
    std::vector<LineEntry> lines_;
    std::vector<std::string> directories_;
    std::vector<FileEntry> files_;
};

class TypeAttributeValue : public AttributeValue {
public:
    TypeAttributeValue(uint64_t offset, const std::string& name = "");
    AttributeValueType getType() const override { return AttributeValueType::REFERENCE; }
    std::string toString() const override;
    
    uint64_t getOffset() const { return offset_; }
    const std::string& getName() const { return name_; }
    
private:
    uint64_t offset_;
    std::string name_;
};

} // namespace dwarf
