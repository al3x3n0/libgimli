#pragma once

#include "dwarf_types.hpp"
#include <vector>
#include <cstdint>
#include <optional>

namespace dwarf {

// Parser for DWARF 5 .debug_rnglists section
class RngListsParser {
public:
    RngListsParser(const std::vector<uint8_t>& debug_rnglists,
                   const std::vector<uint8_t>& debug_addr = {});

    // Parse header at the given offset, returns header and advances offset past it
    std::optional<RngListsHeader> parseHeader(uint64_t& offset) const;

    // Parse a range list starting at the given offset
    // base_address is the current base address for offset_pair entries
    // Returns list of range entries (with resolved addresses)
    std::vector<RngListEntry> parseRangeList(uint64_t offset,
                                              uint64_t base_address = 0,
                                              uint8_t address_size = 8,
                                              uint64_t end_offset = 0,
                                              uint8_t segment_selector_size = 0) const;

    // Resolve DW_FORM_rnglistx index to actual offset
    // header_offset is the start of the rnglists contribution for this CU
    // rnglists_base is DW_AT_rnglists_base value
    uint64_t resolveRngListx(uint64_t index,
                             uint64_t header_offset,
                             uint64_t rnglists_base,
                             bool is_dwarf64 = false,
                             uint64_t offsets_end = 0,
                             uint64_t unit_end = 0) const;

    // Set the debug_addr section for resolving indexed addresses
    void setDebugAddr(const std::vector<uint8_t>& debug_addr,
                      uint64_t addr_base = 0,
                      uint8_t addr_seg_size = 0,
                      uint8_t addr_entry_stride = 0,
                      uint64_t addr_end = 0);

    // Check if section is empty
    bool empty() const { return debug_rnglists_.empty(); }
    size_t size() const { return debug_rnglists_.size(); }

private:
    const std::vector<uint8_t>& debug_rnglists_;
    const std::vector<uint8_t>* debug_addr_;
    uint64_t addr_base_ = 0;
    uint8_t addr_seg_size_ = 0;
    uint8_t addr_entry_stride_ = 0;
    uint64_t addr_end_ = 0; // exclusive end bound for this CU's .debug_addr contribution

    // Reading helpers
    uint8_t readU8(uint64_t& offset) const;
    uint16_t readU16(uint64_t& offset) const;
    uint32_t readU32(uint64_t& offset) const;
    uint64_t readU64(uint64_t& offset) const;
    uint64_t readAddress(uint64_t& offset, uint8_t address_size) const;
    uint64_t readULEB128(uint64_t& offset) const;
    int64_t readSLEB128(uint64_t& offset) const;

    // Resolve indexed address from debug_addr
    uint64_t resolveAddrx(uint64_t index, uint8_t address_size) const;
};

} // namespace dwarf
