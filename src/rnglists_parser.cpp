#include "rnglists_parser.hpp"
#include "dwarf_utils.hpp"
#include <stdexcept>

namespace dwarf {

RngListsParser::RngListsParser(const std::vector<uint8_t>& debug_rnglists,
                               const std::vector<uint8_t>& debug_addr)
    : debug_rnglists_(debug_rnglists)
    , debug_addr_(&debug_addr)
    , addr_base_(0)
    , addr_seg_size_(0)
    , addr_entry_stride_(0)
{
}

void RngListsParser::setDebugAddr(const std::vector<uint8_t>& debug_addr,
                                  uint64_t addr_base,
                                  uint8_t addr_seg_size,
                                  uint8_t addr_entry_stride,
                                  uint64_t addr_end) {
    debug_addr_ = &debug_addr;
    addr_base_ = addr_base;
    addr_seg_size_ = addr_seg_size;
    addr_entry_stride_ = addr_entry_stride;
    addr_end_ = addr_end;
}

std::optional<RngListsHeader> RngListsParser::parseHeader(uint64_t& offset) const {
    if (offset >= debug_rnglists_.size()) {
        return std::nullopt;
    }

    RngListsHeader header;
    uint64_t start_offset = offset;

    // Read unit_length (4 or 12 bytes for DWARF64)
    uint32_t initial_length = readU32(offset);
    if (initial_length == 0xffffffff) {
        header.is_dwarf64 = true;
        header.unit_length = readU64(offset);
    } else {
        header.is_dwarf64 = false;
        header.unit_length = initial_length;
    }

    // Read version (should be 5)
    header.version = readU16(offset);
    if (header.version != 5) {
        // Not a valid DWARF 5 rnglists header
        return std::nullopt;
    }

    // Read address_size
    header.address_size = readU8(offset);

    // Read segment_selector_size
    header.segment_selector_size = readU8(offset);

    // Read offset_entry_count
    header.offset_entry_count = readU32(offset);

    // Calculate header size
    header.header_size = offset - start_offset;

    return header;
}

std::vector<RngListEntry> RngListsParser::parseRangeList(uint64_t offset,
                                                          uint64_t base_address,
                                                          uint8_t address_size,
                                                          uint64_t end_offset,
                                                          uint8_t segment_selector_size) const {
    std::vector<RngListEntry> entries;
    uint64_t current_base = base_address;

    uint64_t max = debug_rnglists_.size();
    if (end_offset != 0) {
        max = std::min<uint64_t>(max, end_offset);
    }

    auto readU8B = [&](uint64_t& off) -> std::optional<uint8_t> {
        if (off >= max) return std::nullopt;
        return DwarfUtils::readU8(debug_rnglists_.data(), off, max);
    };
    auto readU32B = [&](uint64_t& off) -> std::optional<uint32_t> {
        if (off + 4 > max) return std::nullopt;
        return DwarfUtils::readU32(debug_rnglists_.data(), off, max);
    };
    auto readU64B = [&](uint64_t& off) -> std::optional<uint64_t> {
        if (off + 8 > max) return std::nullopt;
        return DwarfUtils::readU64(debug_rnglists_.data(), off, max);
    };
    auto readAddrB = [&](uint64_t& off) -> std::optional<uint64_t> {
        // Segment selector precedes the address if present; we ignore its value.
        if (segment_selector_size != 0) {
            if (off + segment_selector_size > max) return std::nullopt;
            off += segment_selector_size;
        }
        if (address_size == 4) {
            auto v = readU32B(off);
            if (!v) return std::nullopt;
            return static_cast<uint64_t>(*v);
        }
        if (address_size == 8) {
            return readU64B(off);
        }
        return std::nullopt;
    };
    auto readULEB128B = [&](uint64_t& off) -> std::optional<uint64_t> {
        if (off >= max) return std::nullopt;
        return DwarfUtils::readULEB128(debug_rnglists_.data(), off, max);
    };

    while (offset < max) {
        auto entry_type_opt = readU8B(offset);
        if (!entry_type_opt) return entries;
        uint8_t entry_type = *entry_type_opt;
        DW_RLE rle_type = static_cast<DW_RLE>(entry_type);

        RngListEntry entry;
        entry.type = rle_type;
        entry.is_base_address = false;

        switch (rle_type) {
            case DW_RLE::DW_RLE_end_of_list:
                // End of list marker
                return entries;

            case DW_RLE::DW_RLE_base_addressx: {
                // Indexed base address
                auto index_opt = readULEB128B(offset);
                if (!index_opt) return entries;
                uint64_t index = *index_opt;
                current_base = resolveAddrx(index, address_size);
                entry.start = current_base;
                entry.end = current_base;
                entry.is_base_address = true;
                entries.push_back(entry);
                break;
            }

            case DW_RLE::DW_RLE_startx_endx: {
                // Indexed start and end addresses
                auto start_index_opt = readULEB128B(offset);
                auto end_index_opt = readULEB128B(offset);
                if (!start_index_opt || !end_index_opt) return entries;
                uint64_t start_index = *start_index_opt;
                uint64_t end_index = *end_index_opt;
                entry.start = resolveAddrx(start_index, address_size);
                entry.end = resolveAddrx(end_index, address_size);
                entries.push_back(entry);
                break;
            }

            case DW_RLE::DW_RLE_startx_length: {
                // Indexed start address with length
                auto start_index_opt = readULEB128B(offset);
                auto length_opt = readULEB128B(offset);
                if (!start_index_opt || !length_opt) return entries;
                uint64_t start_index = *start_index_opt;
                uint64_t length = *length_opt;
                entry.start = resolveAddrx(start_index, address_size);
                entry.end = entry.start + length;
                entries.push_back(entry);
                break;
            }

            case DW_RLE::DW_RLE_offset_pair: {
                // Start and end offsets from base address
                auto start_offset_opt = readULEB128B(offset);
                auto end_offset_opt = readULEB128B(offset);
                if (!start_offset_opt || !end_offset_opt) return entries;
                uint64_t start_offset_val = *start_offset_opt;
                uint64_t end_offset_val = *end_offset_opt;
                entry.start = current_base + start_offset_val;
                entry.end = current_base + end_offset_val;
                entries.push_back(entry);
                break;
            }

            case DW_RLE::DW_RLE_base_address: {
                // Direct base address
                auto base_opt = readAddrB(offset);
                if (!base_opt) return entries;
                current_base = *base_opt;
                entry.start = current_base;
                entry.end = current_base;
                entry.is_base_address = true;
                entries.push_back(entry);
                break;
            }

            case DW_RLE::DW_RLE_start_end: {
                // Direct start and end addresses
                auto start_opt = readAddrB(offset);
                auto end_opt = readAddrB(offset);
                if (!start_opt || !end_opt) return entries;
                entry.start = *start_opt;
                entry.end = *end_opt;
                entries.push_back(entry);
                break;
            }

            case DW_RLE::DW_RLE_start_length: {
                // Direct start address with length
                auto start_opt = readAddrB(offset);
                auto length_opt = readULEB128B(offset);
                if (!start_opt || !length_opt) return entries;
                entry.start = *start_opt;
                uint64_t length = *length_opt;
                entry.end = entry.start + length;
                entries.push_back(entry);
                break;
            }

            default:
                // Unknown entry type, stop parsing
                return entries;
        }
    }

    return entries;
}

uint64_t RngListsParser::resolveRngListx(uint64_t index,
                                          uint64_t header_offset,
                                          uint64_t rnglists_base,
                                          bool is_dwarf64,
                                          uint64_t offsets_end,
                                          uint64_t unit_end) const {
    (void)header_offset;
    // The offsets array starts at rnglists_base
    // Each entry is 4 bytes (DWARF32) or 8 bytes (DWARF64)
    uint64_t offset_size = is_dwarf64 ? 8 : 4;
    uint64_t offset_array_pos = rnglists_base + (index * offset_size);

    uint64_t bound_end = offsets_end ? offsets_end : debug_rnglists_.size();
    uint64_t contrib_end = unit_end ? unit_end : debug_rnglists_.size();
    if (offset_array_pos + offset_size > bound_end) {
        return 0; // Invalid index
    }

    uint64_t temp_offset = offset_array_pos;
    uint64_t list_offset;
    if (is_dwarf64) {
        list_offset = readU64(temp_offset);
    } else {
        list_offset = readU32(temp_offset);
    }

    // The offset is relative to rnglists_base
    uint64_t abs = rnglists_base + list_offset;
    if (abs >= contrib_end) return 0;
    if (abs >= debug_rnglists_.size()) return 0;
    return abs;
}

uint64_t RngListsParser::resolveAddrx(uint64_t index, uint8_t address_size) const {
    if (!debug_addr_ || debug_addr_->empty()) {
        return 0;
    }

    uint64_t stride = addr_entry_stride_ ? addr_entry_stride_ : address_size;
    uint64_t offset = addr_base_ + (index * stride);
    uint64_t addr_field = offset + addr_seg_size_;
    uint64_t end = addr_end_ ? addr_end_ : debug_addr_->size();
    if (addr_field + address_size > end) {
        return 0;
    }

    if (address_size == 4) {
        uint64_t temp = addr_field;
        return DwarfUtils::readU32(debug_addr_->data(), temp, debug_addr_->size());
    } else {
        uint64_t temp = addr_field;
        return DwarfUtils::readU64(debug_addr_->data(), temp, debug_addr_->size());
    }
}

// Reading helpers

uint8_t RngListsParser::readU8(uint64_t& offset) const {
    if (offset >= debug_rnglists_.size()) {
        throw std::out_of_range("RngListsParser: read past end of section");
    }
    return DwarfUtils::readU8(debug_rnglists_.data(), offset, debug_rnglists_.size());
}

uint16_t RngListsParser::readU16(uint64_t& offset) const {
    if (offset + 2 > debug_rnglists_.size()) {
        throw std::out_of_range("RngListsParser: read past end of section");
    }
    return DwarfUtils::readU16(debug_rnglists_.data(), offset, debug_rnglists_.size());
}

uint32_t RngListsParser::readU32(uint64_t& offset) const {
    if (offset + 4 > debug_rnglists_.size()) {
        throw std::out_of_range("RngListsParser: read past end of section");
    }
    return DwarfUtils::readU32(debug_rnglists_.data(), offset, debug_rnglists_.size());
}

uint64_t RngListsParser::readU64(uint64_t& offset) const {
    if (offset + 8 > debug_rnglists_.size()) {
        throw std::out_of_range("RngListsParser: read past end of section");
    }
    return DwarfUtils::readU64(debug_rnglists_.data(), offset, debug_rnglists_.size());
}

uint64_t RngListsParser::readAddress(uint64_t& offset, uint8_t address_size) const {
    if (address_size == 4) {
        return readU32(offset);
    } else {
        return readU64(offset);
    }
}

uint64_t RngListsParser::readULEB128(uint64_t& offset) const {
    if (offset >= debug_rnglists_.size()) {
        throw std::out_of_range("RngListsParser: ULEB128 read past end");
    }
    return DwarfUtils::readULEB128(debug_rnglists_.data(), offset, debug_rnglists_.size());
}

int64_t RngListsParser::readSLEB128(uint64_t& offset) const {
    if (offset >= debug_rnglists_.size()) {
        throw std::out_of_range("RngListsParser: SLEB128 read past end");
    }
    return DwarfUtils::readSLEB128(debug_rnglists_.data(), offset, debug_rnglists_.size());
}

} // namespace dwarf
