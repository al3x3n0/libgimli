#pragma once

#include "dwarf_types.hpp"
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <vector>
#include <map>

namespace dwarf {

// Utility functions for DWARF parsing
class DwarfUtils {
public:
    struct PreservedAttributePayload {
        enum class Kind {
            EXPRESSION,
            BLOCK
        };

        Kind kind = Kind::EXPRESSION;
        std::vector<uint8_t> bytes;
        std::vector<std::string> tokens;
    };

    struct DecodedPayloadSemantics {
        DwarfAttribute attribute = DwarfAttribute::DW_AT_name;
        PreservedAttributePayload::Kind payload_kind = PreservedAttributePayload::Kind::EXPRESSION;
        std::vector<uint8_t> bytes;
        std::vector<std::string> tokens;
        std::string assembly;
    };

    struct SizeContext {
        uint8_t address_size = 4;
        uint8_t offset_size = 4;
        // Optional explicit ref_addr size. If 0, offset_size is used.
        uint8_t ref_addr_size = 0;
        // DWARF2-style ref_addr uses address size instead of offset size.
        bool ref_addr_uses_address_size = false;
    };

    // Tag name conversion
    static std::string tagToString(DwarfTag tag);
    static DwarfTag stringToTag(const std::string& str);
    
    // Attribute name conversion
    static std::string attributeToString(DwarfAttribute attr);
    static DwarfAttribute stringToAttribute(const std::string& str);
    
    // Form name conversion
    static std::string formToString(DwarfForm form);
    static DwarfForm stringToForm(const std::string& str);
    
    // Operation name conversion
    static std::string operationToString(DwarfOp op);
    static DwarfOp stringToOperation(const std::string& str);
    static const std::vector<DwarfOp>& knownGnuExtensionOperations();
    static bool isKnownGnuExtensionOperation(DwarfOp op);
    
    // Data reading utilities
    static uint64_t readULEB128(const uint8_t* data, uint64_t& offset, size_t max_offset);
    static int64_t readSLEB128(const uint8_t* data, uint64_t& offset, size_t max_offset);
    static uint8_t readU8(const uint8_t* data, uint64_t& offset, size_t max_offset);
    static uint16_t readU16(const uint8_t* data, uint64_t& offset, size_t max_offset);
    static uint32_t readU32(const uint8_t* data, uint64_t& offset, size_t max_offset);
    static uint64_t readU64(const uint8_t* data, uint64_t& offset, size_t max_offset);
    
    // Endianness handling
    static uint16_t swapBytes(uint16_t value);
    static uint32_t swapBytes(uint32_t value);
    static uint64_t swapBytes(uint64_t value);
    
    // String utilities
    static std::string formatAddress(uint64_t address, bool hex = true);
    static std::string formatOffset(uint64_t offset, bool hex = true);
    static std::string formatSize(uint64_t size, bool hex = false);
    static std::string formatKeyValueFields(const std::vector<std::pair<std::string, std::string>>& fields,
                                            const std::string& prefix = " [",
                                            const std::string& separator = ", ",
                                            const std::string& suffix = "]");
    static std::string formatDiagnosticContext(const std::optional<uint64_t>& cu_offset,
                                               const std::optional<uint64_t>& die_offset,
                                               const std::string& attribute);
    static std::string formatDebugMessage(const std::string& message);
    static void printDebugMessage(std::ostream& os, const std::string& message);
    
    // Validation utilities
    static bool isValidTag(DwarfTag tag);
    static bool isValidAttribute(DwarfAttribute attr);
    static bool isValidForm(DwarfForm form);
    static bool isValidOperation(DwarfOp op);
    
    // Debug utilities
    static std::string hexDump(const uint8_t* data, size_t size, size_t offset = 0);
    static std::string hexDump(const std::vector<uint8_t>& data, size_t offset = 0);
    static void printHexDump(const uint8_t* data, size_t size, size_t offset = 0);
    static void printHexDump(const std::vector<uint8_t>& data, size_t offset = 0);
    
    // Type utilities
    static bool isTypeTag(DwarfTag tag);
    static bool isSubprogramTag(DwarfTag tag);
    static bool isVariableTag(DwarfTag tag);
    static bool isScopeTag(DwarfTag tag);
    
    // Size utilities
    static size_t getFormSize(DwarfForm form, const uint8_t* data, size_t offset, size_t max_offset);
    static size_t getFormSize(DwarfForm form, const uint8_t* data, size_t offset, size_t max_offset,
                              const SizeContext& ctx);
    static size_t getOperationSize(DwarfOp op, const uint8_t* data, size_t offset, size_t max_offset);
    static size_t getOperationSize(DwarfOp op, const uint8_t* data, size_t offset, size_t max_offset,
                                   const SizeContext& ctx);
    
    // Expression utilities
    static std::string expressionToAssembly(const std::vector<uint8_t>& expression);
    static std::string expressionToAssembly(const std::vector<uint8_t>& expression,
                                            const SizeContext& ctx);
    static std::vector<std::string> expressionToTokens(const std::vector<uint8_t>& expression);
    static std::vector<std::string> expressionToTokens(const std::vector<uint8_t>& expression,
                                                       const SizeContext& ctx);
    static std::optional<PreservedAttributePayload> decodePreservedPayloadAttribute(
        DwarfAttribute attr, const std::shared_ptr<AttributeValue>& value);
    static std::optional<PreservedAttributePayload> decodePreservedPayloadAttribute(
        DwarfAttribute attr, const std::shared_ptr<AttributeValue>& value, const SizeContext& ctx);
    static std::optional<DecodedPayloadSemantics> decodeCallSitePayloadAttribute(
        DwarfAttribute attr, const std::shared_ptr<AttributeValue>& value);
    static std::optional<DecodedPayloadSemantics> decodeCallSitePayloadAttribute(
        DwarfAttribute attr, const std::shared_ptr<AttributeValue>& value, const SizeContext& ctx);
    static std::optional<DecodedPayloadSemantics> decodeDiscriminantPayloadAttribute(
        DwarfAttribute attr, const std::shared_ptr<AttributeValue>& value);
    static std::optional<DecodedPayloadSemantics> decodeDiscriminantPayloadAttribute(
        DwarfAttribute attr, const std::shared_ptr<AttributeValue>& value, const SizeContext& ctx);
    
    // File utilities
    static bool fileExists(const std::string& filename);
    static std::string getFileExtension(const std::string& filename);
    static bool isElfFile(const std::string& filename);
    static bool isDwarfFile(const std::string& filename);
    
    // Error handling
    static std::string getLastError();
    static void setLastError(const std::string& error);
    static void clearLastError();

    // Object endianness (DWARF data uses the object file's endianness).
    // Default is little-endian.
    static void setObjectLittleEndian(bool little);
    static bool objectIsLittleEndian();

    // Range query helpers
    struct AddressRange {
        uint64_t start;
        uint64_t end;
        bool is_base_address;

        AddressRange(uint64_t s = 0, uint64_t e = 0, bool base = false)
            : start(s), end(e), is_base_address(base) {}

        bool contains(uint64_t address) const {
            return !is_base_address && address >= start && address < end;
        }

        bool overlaps(const AddressRange& other) const {
            if (is_base_address || other.is_base_address) return false;
            return start < other.end && other.start < end;
        }

        bool operator<(const AddressRange& other) const {
            return start < other.start;
        }
    };

    // Check if an address is in any of the given ranges
    static bool isAddressInRanges(uint64_t address, const std::vector<AddressRange>& ranges);

    // Get all ranges containing a specific address
    static std::vector<AddressRange> getRangesContainingAddress(
        uint64_t address, const std::vector<AddressRange>& ranges);

    // Merge overlapping ranges into non-overlapping ranges
    static std::vector<AddressRange> mergeOverlappingRanges(
        const std::vector<AddressRange>& ranges);

    // Get the total size covered by ranges (handling overlaps)
    static uint64_t getTotalRangeSize(const std::vector<AddressRange>& ranges);

    // Check if a range list covers a continuous address range
    static bool isContinuousRange(const std::vector<AddressRange>& ranges);

    // Get the bounding range (min start to max end)
    static AddressRange getBoundingRange(const std::vector<AddressRange>& ranges);

private:
    static std::string last_error_;
    static bool object_little_endian_;
    
    // Internal helpers
    static bool isLittleEndian();
    static std::string formatNumber(uint64_t value, bool hex, int width = 0);
};

// Constants
namespace constants {
    // DWARF version constants
    constexpr uint8_t DWARF_VERSION_2 = 2;
    constexpr uint8_t DWARF_VERSION_3 = 3;
    constexpr uint8_t DWARF_VERSION_4 = 4;
    constexpr uint8_t DWARF_VERSION_5 = 5;
    
    // Address size constants
    constexpr uint8_t ADDR_SIZE_32 = 4;
    constexpr uint8_t ADDR_SIZE_64 = 8;
    
    // Section name constants
    constexpr const char* DEBUG_INFO_SECTION = ".debug_info";
    constexpr const char* DEBUG_ABBREV_SECTION = ".debug_abbrev";
    constexpr const char* DEBUG_STR_SECTION = ".debug_str";
    constexpr const char* DEBUG_LINE_SECTION = ".debug_line";
    constexpr const char* DEBUG_RANGES_SECTION = ".debug_ranges";
    constexpr const char* DEBUG_LOC_SECTION = ".debug_loc";
    constexpr const char* DEBUG_TYPES_SECTION = ".debug_types";
    constexpr const char* DEBUG_MACRO_SECTION = ".debug_macro";
    constexpr const char* DEBUG_STR_OFFSETS_SECTION = ".debug_str_offsets";
    constexpr const char* DEBUG_ADDR_SECTION = ".debug_addr";
    constexpr const char* DEBUG_LINE_STR_SECTION = ".debug_line_str";
    constexpr const char* DEBUG_NAMES_SECTION = ".debug_names";
    constexpr const char* DEBUG_RNGLISTS_SECTION = ".debug_rnglists";
    constexpr const char* DEBUG_LOCLISTS_SECTION = ".debug_loclists";
    constexpr const char* DEBUG_ARANGES_SECTION = ".debug_aranges";
    constexpr const char* DEBUG_PUBNAMES_SECTION = ".debug_pubnames";
    constexpr const char* DEBUG_PUBTYPES_SECTION = ".debug_pubtypes";
    constexpr const char* DEBUG_MACINFO_SECTION = ".debug_macinfo";
    constexpr const char* DEBUG_SUP_SECTION = ".debug_sup";
    constexpr const char* DEBUG_STR_SUP_SECTION = ".debug_str_sup";
    constexpr const char* DEBUG_FRAME_SECTION = ".debug_frame";
    constexpr const char* EH_FRAME_SECTION = ".eh_frame";

    // Magic numbers
    constexpr uint32_t DWARF_MAGIC = 0xFFFFFFFF;
    constexpr uint32_t DWARF_EXTENDED_MAGIC = 0xFFFFFFFE;
    
    // Default values
    constexpr uint64_t DEFAULT_ADDRESS_SIZE = 8;
    constexpr uint8_t DEFAULT_DWARF_VERSION = 4;
}

} // namespace dwarf
