#include "attribute_parser.hpp"
#include "dwarf_utils.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <functional>

namespace dwarf {

AttributeParser::AttributeParser(const std::vector<uint8_t>& debug_info,
                               const std::vector<uint8_t>& debug_abbrev,
                               const std::vector<uint8_t>& debug_str,
                               const std::vector<uint8_t>& debug_line,
                               const std::vector<uint8_t>& debug_ranges,
                               const std::vector<uint8_t>& debug_loc,
                               const std::vector<uint8_t>& debug_str_offsets,
                               const std::vector<uint8_t>& debug_addr,
                               const std::vector<uint8_t>& debug_line_str,
                               const std::vector<uint8_t>& debug_rnglists,
                               const std::vector<uint8_t>& debug_loclists,
                               const std::vector<uint8_t>& debug_str_sup)
    : debug_info_(debug_info), debug_abbrev_(debug_abbrev), debug_str_(debug_str),
      debug_str_sup_(debug_str_sup),
      debug_line_(debug_line), debug_ranges_(debug_ranges), debug_loc_(debug_loc),
      debug_str_offsets_(debug_str_offsets), debug_addr_(debug_addr), debug_line_str_(debug_line_str),
      debug_rnglists_(debug_rnglists), debug_loclists_(debug_loclists) {
    // Conservative defaults: whole .debug_addr section, no segment selector.
    cu_addr_end_ = debug_addr_.size();
    cu_addr_seg_size_ = 0;
    cu_addr_entry_stride_ = address_size_;
    // Conservative defaults: whole .debug_str_offsets section.
    cu_str_offsets_end_ = debug_str_offsets_.size();
    // Conservative defaults: whole rnglists/loclists sections.
    cu_rnglists_end_ = debug_rnglists_.size();
    cu_rnglists_offsets_end_ = debug_rnglists_.size();
    cu_rnglists_is_dwarf64_ = false;
    cu_rnglists_seg_size_ = 0;
    cu_loclists_end_ = debug_loclists_.size();
    cu_loclists_offsets_end_ = debug_loclists_.size();
    cu_loclists_is_dwarf64_ = false;
    cu_loclists_seg_size_ = 0;
    cu_debug_info_end_ = debug_info_.size();

    // Initialize DWARF 5 parsers if sections are available
    if (!debug_rnglists_.empty()) {
        rnglists_parser_ = std::make_unique<RngListsParser>(debug_rnglists_, debug_addr_);
    }
    if (!debug_loclists_.empty()) {
        loclists_parser_ = std::make_unique<LocListsParser>(debug_loclists_, debug_addr_);
    }
}

void AttributeParser::setCUContext(uint64_t rnglists_base, uint64_t loclists_base,
                                    uint64_t addr_base, uint64_t str_offsets_base,
                                    uint64_t base_address) {
    struct RngLocContribution {
        uint64_t offsets_base = 0;
        uint64_t offsets_end = 0;
        uint64_t unit_end = 0;
        uint32_t offset_entry_count = 0;
        bool is_dwarf64 = false;
        uint8_t seg_size = 0;
        bool ok = false;
    };

    auto tryParseRngListsContributionAt = [&](uint64_t contribution_start) -> RngLocContribution {
        RngLocContribution out;
        if (debug_rnglists_.empty()) return out;
        if (contribution_start >= debug_rnglists_.size()) return out;

        uint64_t off = contribution_start;
        uint32_t initial_length = DwarfUtils::readU32(debug_rnglists_.data(), off, debug_rnglists_.size());
        bool is64 = (initial_length == 0xffffffff);
        uint64_t unit_length = is64 ? DwarfUtils::readU64(debug_rnglists_.data(), off, debug_rnglists_.size())
                                    : initial_length;
        uint64_t length_field_size = is64 ? 12 : 4;
        uint64_t unit_end = contribution_start + length_field_size + unit_length;
        if (unit_end > debug_rnglists_.size() || unit_end < off) return out;

        uint16_t version = DwarfUtils::readU16(debug_rnglists_.data(), off, unit_end);
        uint8_t addr_size = DwarfUtils::readU8(debug_rnglists_.data(), off, unit_end);
        uint8_t seg_size = DwarfUtils::readU8(debug_rnglists_.data(), off, unit_end); // segment_selector_size
        uint32_t offset_entry_count = DwarfUtils::readU32(debug_rnglists_.data(), off, unit_end);

        if (version != 5) return out;
        if (addr_size != address_size_) return out;

        uint64_t offsets_base = off;
        uint64_t offset_size = is64 ? 8 : 4;
        uint64_t offsets_end = offsets_base + (static_cast<uint64_t>(offset_entry_count) * offset_size);
        if (offsets_end > unit_end) return out;

        out.offsets_base = offsets_base;
        out.offsets_end = offsets_end;
        out.unit_end = unit_end;
        out.offset_entry_count = offset_entry_count;
        out.is_dwarf64 = is64;
        out.seg_size = seg_size;
        out.ok = true;
        return out;
    };

    auto tryParseLocListsContributionAt = [&](uint64_t contribution_start) -> RngLocContribution {
        RngLocContribution out;
        if (debug_loclists_.empty()) return out;
        if (contribution_start >= debug_loclists_.size()) return out;

        uint64_t off = contribution_start;
        uint32_t initial_length = DwarfUtils::readU32(debug_loclists_.data(), off, debug_loclists_.size());
        bool is64 = (initial_length == 0xffffffff);
        uint64_t unit_length = is64 ? DwarfUtils::readU64(debug_loclists_.data(), off, debug_loclists_.size())
                                    : initial_length;
        uint64_t length_field_size = is64 ? 12 : 4;
        uint64_t unit_end = contribution_start + length_field_size + unit_length;
        if (unit_end > debug_loclists_.size() || unit_end < off) return out;

        uint16_t version = DwarfUtils::readU16(debug_loclists_.data(), off, unit_end);
        uint8_t addr_size = DwarfUtils::readU8(debug_loclists_.data(), off, unit_end);
        uint8_t seg_size = DwarfUtils::readU8(debug_loclists_.data(), off, unit_end); // segment_selector_size
        uint32_t offset_entry_count = DwarfUtils::readU32(debug_loclists_.data(), off, unit_end);

        if (version != 5) return out;
        if (addr_size != address_size_) return out;

        uint64_t offsets_base = off;
        uint64_t offset_size = is64 ? 8 : 4;
        uint64_t offsets_end = offsets_base + (static_cast<uint64_t>(offset_entry_count) * offset_size);
        if (offsets_end > unit_end) return out;

        out.offsets_base = offsets_base;
        out.offsets_end = offsets_end;
        out.unit_end = unit_end;
        out.offset_entry_count = offset_entry_count;
        out.is_dwarf64 = is64;
        out.seg_size = seg_size;
        out.ok = true;
        return out;
    };

    auto normalizeRngListsBaseAndContribution = [&](uint64_t base) -> RngLocContribution {
        RngLocContribution out;
        if (debug_rnglists_.empty() || base >= debug_rnglists_.size()) return out;

        // Case 1: base points at contribution header.
        out = tryParseRngListsContributionAt(base);
        if (out.ok) return out;

        // Case 2: base points at offsets array start; try header just before it.
        // DWARF32 header size: 4(len)+2(ver)+1(addr)+1(seg)+4(count) = 12
        // DWARF64 header size: 12(len)+2(ver)+1(addr)+1(seg)+4(count) = 20
        if (base >= 12) {
            auto c32 = tryParseRngListsContributionAt(base - 12);
            if (c32.ok && c32.offsets_base == base) return c32;
        }
        if (base >= 20) {
            auto c64 = tryParseRngListsContributionAt(base - 20);
            if (c64.ok && c64.offsets_base == base) return c64;
        }
        return out;
    };

    auto normalizeLocListsBaseAndContribution = [&](uint64_t base) -> RngLocContribution {
        RngLocContribution out;
        if (debug_loclists_.empty() || base >= debug_loclists_.size()) return out;

        out = tryParseLocListsContributionAt(base);
        if (out.ok) return out;

        if (base >= 12) {
            auto c32 = tryParseLocListsContributionAt(base - 12);
            if (c32.ok && c32.offsets_base == base) return c32;
        }
        if (base >= 20) {
            auto c64 = tryParseLocListsContributionAt(base - 20);
            if (c64.ok && c64.offsets_base == base) return c64;
        }
        return out;
    };

    // Default to "whole section" bounds if we can't parse a header.
    cu_rnglists_base_ = rnglists_base;
    cu_rnglists_end_ = debug_rnglists_.size();
    cu_rnglists_offsets_end_ = debug_rnglists_.size();
    cu_rnglists_is_dwarf64_ = is_dwarf64_;
    cu_rnglists_seg_size_ = 0;
    if (auto c = normalizeRngListsBaseAndContribution(rnglists_base); c.ok) {
        cu_rnglists_base_ = c.offsets_base;
        cu_rnglists_end_ = c.unit_end;
        cu_rnglists_offsets_end_ = c.offsets_end;
        cu_rnglists_is_dwarf64_ = c.is_dwarf64;
        cu_rnglists_seg_size_ = c.seg_size;
    }

    cu_loclists_base_ = loclists_base;
    cu_loclists_end_ = debug_loclists_.size();
    cu_loclists_offsets_end_ = debug_loclists_.size();
    cu_loclists_is_dwarf64_ = is_dwarf64_;
    cu_loclists_seg_size_ = 0;
    if (auto c = normalizeLocListsBaseAndContribution(loclists_base); c.ok) {
        cu_loclists_base_ = c.offsets_base;
        cu_loclists_end_ = c.unit_end;
        cu_loclists_offsets_end_ = c.offsets_end;
        cu_loclists_is_dwarf64_ = c.is_dwarf64;
        cu_loclists_seg_size_ = c.seg_size;
    }

    // Some producers may set *_base attributes to the start of the contribution
    // (including the DWARF5 section header) rather than the start of the table.
    // Best-effort normalize to the table start.
    struct DebugAddrContribution {
        uint64_t table_start = 0;
        uint64_t unit_end = 0;  // end of contribution (exclusive)
        uint8_t addr_size = 0;
        uint8_t seg_size = 0;
        uint8_t entry_stride = 0;
        bool ok = false;
    };

    auto tryParseDebugAddrContributionAt = [&](uint64_t contribution_start) -> DebugAddrContribution {
        DebugAddrContribution out;
        if (debug_addr_.empty()) return out;
        if (contribution_start >= debug_addr_.size()) return out;

        uint64_t off = contribution_start;
        uint32_t initial_length = DwarfUtils::readU32(debug_addr_.data(), off, debug_addr_.size());
        bool is64 = (initial_length == 0xffffffff);
        uint64_t unit_length = is64 ? DwarfUtils::readU64(debug_addr_.data(), off, debug_addr_.size())
                                    : initial_length;
        uint64_t length_field_size = is64 ? 12 : 4;
        uint64_t unit_end = contribution_start + length_field_size + unit_length;
        if (unit_end > debug_addr_.size() || unit_end < off) return out;

        uint16_t version = DwarfUtils::readU16(debug_addr_.data(), off, unit_end);
        uint8_t addr_size = DwarfUtils::readU8(debug_addr_.data(), off, unit_end);
        uint8_t seg_size = DwarfUtils::readU8(debug_addr_.data(), off, unit_end);

        if (version != 5) return out;
        if (addr_size != address_size_) return out;

        // Entry is segment selector (optional) followed by address.
        uint8_t stride = static_cast<uint8_t>(seg_size + addr_size);
        if (stride == 0) return out;

        out.table_start = off;
        out.unit_end = unit_end;
        out.addr_size = addr_size;
        out.seg_size = seg_size;
        out.entry_stride = stride;
        out.ok = true;
        return out;
    };

    auto normalizeAddrBaseAndContribution = [&](uint64_t base) -> DebugAddrContribution {
        DebugAddrContribution out;
        if (debug_addr_.empty() || base >= debug_addr_.size()) return out;

        // Case 1: base points at the contribution start (header).
        out = tryParseDebugAddrContributionAt(base);
        if (out.ok) return out;

        // Case 2: base points at the table start. Try to locate the header just before it.
        // DWARF32 header size = 4 (len) + 2 (ver) + 1 (addr) + 1 (seg) = 8
        // DWARF64 header size = 12 (len) + 2 (ver) + 1 (addr) + 1 (seg) = 16
        if (base >= 8) {
            auto c32 = tryParseDebugAddrContributionAt(base - 8);
            if (c32.ok && c32.table_start == base) return c32;
        }
        if (base >= 16) {
            auto c64 = tryParseDebugAddrContributionAt(base - 16);
            if (c64.ok && c64.table_start == base) return c64;
        }

        return out;
    };

    auto normalizeStrOffsetsBase = [&](uint64_t base) -> uint64_t {
        if (debug_str_offsets_.empty() || base >= debug_str_offsets_.size()) return base;

        uint64_t off = base;
        uint32_t initial_length = DwarfUtils::readU32(debug_str_offsets_.data(), off, debug_str_offsets_.size());
        bool is64 = (initial_length == 0xffffffff);
        uint64_t unit_length = is64 ? DwarfUtils::readU64(debug_str_offsets_.data(), off, debug_str_offsets_.size())
                                    : initial_length;
        uint64_t length_field_size = is64 ? 12 : 4;
        uint64_t unit_end = base + length_field_size + unit_length;
        if (unit_end > debug_str_offsets_.size() || unit_end < off) return base;

        uint16_t version = DwarfUtils::readU16(debug_str_offsets_.data(), off, unit_end);
        uint16_t padding = DwarfUtils::readU16(debug_str_offsets_.data(), off, unit_end);
        if (version == 5 && padding == 0) {
            return off; // table start
        }
        return base;
    };

    // Default contribution bounds to "whole section" if we can't parse a header.
    cu_addr_base_ = addr_base;
    cu_addr_end_ = debug_addr_.size();
    cu_addr_seg_size_ = 0;
    cu_addr_entry_stride_ = address_size_;

    auto addr_contrib = normalizeAddrBaseAndContribution(addr_base);
    if (addr_contrib.ok) {
        cu_addr_base_ = addr_contrib.table_start;
        cu_addr_end_ = addr_contrib.unit_end;
        cu_addr_seg_size_ = addr_contrib.seg_size;
        cu_addr_entry_stride_ = addr_contrib.entry_stride;
    }

    // Default .debug_str_offsets bounds to "whole section" if we can't parse a header.
    cu_str_offsets_base_ = str_offsets_base;
    cu_str_offsets_end_ = debug_str_offsets_.size();

    struct DebugStrOffsetsContribution {
        uint64_t table_start = 0;
        uint64_t unit_end = 0;
        bool ok = false;
    };

    auto tryParseStrOffsetsContributionAt = [&](uint64_t contribution_start) -> DebugStrOffsetsContribution {
        DebugStrOffsetsContribution out;
        if (debug_str_offsets_.empty()) return out;
        if (contribution_start >= debug_str_offsets_.size()) return out;

        uint64_t off = contribution_start;
        uint32_t initial_length = DwarfUtils::readU32(debug_str_offsets_.data(), off, debug_str_offsets_.size());
        bool is64 = (initial_length == 0xffffffff);
        uint64_t unit_length = is64 ? DwarfUtils::readU64(debug_str_offsets_.data(), off, debug_str_offsets_.size())
                                    : initial_length;
        uint64_t length_field_size = is64 ? 12 : 4;
        uint64_t unit_end = contribution_start + length_field_size + unit_length;
        if (unit_end > debug_str_offsets_.size() || unit_end < off) return out;

        uint16_t version = DwarfUtils::readU16(debug_str_offsets_.data(), off, unit_end);
        uint16_t padding = DwarfUtils::readU16(debug_str_offsets_.data(), off, unit_end);
        if (version != 5) return out;
        if (padding != 0) return out;

        out.table_start = off;
        out.unit_end = unit_end;
        out.ok = true;
        return out;
    };

    auto normalizeStrOffsetsBaseAndContribution = [&](uint64_t base) -> DebugStrOffsetsContribution {
        DebugStrOffsetsContribution out;
        if (debug_str_offsets_.empty() || base >= debug_str_offsets_.size()) return out;

        // Case 1: base points at contribution header.
        out = tryParseStrOffsetsContributionAt(base);
        if (out.ok) return out;

        // Case 2: base points at table start; try header just before it.
        // DWARF32 header size = 4 (len) + 2 (ver) + 2 (pad) = 8
        // DWARF64 header size = 12 (len) + 2 (ver) + 2 (pad) = 16
        if (base >= 8) {
            auto c32 = tryParseStrOffsetsContributionAt(base - 8);
            if (c32.ok && c32.table_start == base) return c32;
        }
        if (base >= 16) {
            auto c64 = tryParseStrOffsetsContributionAt(base - 16);
            if (c64.ok && c64.table_start == base) return c64;
        }
        return out;
    };

    auto so_contrib = normalizeStrOffsetsBaseAndContribution(str_offsets_base);
    if (so_contrib.ok) {
        cu_str_offsets_base_ = so_contrib.table_start;
        cu_str_offsets_end_ = so_contrib.unit_end;
    } else {
        // Preserve old behavior (header normalization) even if we couldn't determine unit end.
        cu_str_offsets_base_ = normalizeStrOffsetsBase(str_offsets_base);
    }
    cu_base_address_ = base_address;

    // Update parsers with addr_base for indexed address resolution
    if (rnglists_parser_) {
        rnglists_parser_->setDebugAddr(debug_addr_,
                                       cu_addr_base_,
                                       cu_addr_seg_size_,
                                       cu_addr_entry_stride_,
                                       cu_addr_end_);
    }
    if (loclists_parser_) {
        loclists_parser_->setDebugAddr(debug_addr_,
                                       cu_addr_base_,
                                       cu_addr_seg_size_,
                                       cu_addr_entry_stride_,
                                       cu_addr_end_);
    }
}

std::shared_ptr<AttributeValue> AttributeParser::parseAttribute(DwarfForm form, uint64_t& offset) const {
    switch (form) {
        case DwarfForm::DW_FORM_addr:
            return parseFormAddr(offset);
        case DwarfForm::DW_FORM_data1:
            return parseFormData1(offset);
        case DwarfForm::DW_FORM_data2:
            return parseFormData2(offset);
        case DwarfForm::DW_FORM_data4:
            return parseFormData4(offset);
        case DwarfForm::DW_FORM_data8:
            return parseFormData8(offset);
        case DwarfForm::DW_FORM_sdata:
            return parseFormSdata(offset);
        case DwarfForm::DW_FORM_udata:
            return parseFormUdata(offset);
        case DwarfForm::DW_FORM_string:
            return parseFormString(offset);
        case DwarfForm::DW_FORM_strp:
            return parseFormStrp(offset);
        case DwarfForm::DW_FORM_strp_sup:
            return parseFormStrpSup(offset);
        case DwarfForm::DW_FORM_GNU_strp_alt:
            return parseFormGnuStrpAlt(offset);
        case DwarfForm::DW_FORM_ref1:
            return parseFormRef1(offset);
        case DwarfForm::DW_FORM_ref2:
            return parseFormRef2(offset);
        case DwarfForm::DW_FORM_ref4:
            return parseFormRef4(offset);
        case DwarfForm::DW_FORM_ref8:
            return parseFormRef8(offset);
        case DwarfForm::DW_FORM_ref_sup4:
            return parseFormRefSup4(offset);
        case DwarfForm::DW_FORM_ref_sup8:
            return parseFormRefSup8(offset);
        case DwarfForm::DW_FORM_GNU_ref_alt:
            return parseFormGnuRefAlt(offset);
        case DwarfForm::DW_FORM_ref_udata:
            return parseFormRefUdata(offset);
        case DwarfForm::DW_FORM_flag:
            return parseFormFlag(offset);
        case DwarfForm::DW_FORM_flag_present:
            return parseFormFlagPresent(offset);
        case DwarfForm::DW_FORM_block1:
            return parseFormBlock1(offset);
        case DwarfForm::DW_FORM_block2:
            return parseFormBlock2(offset);
        case DwarfForm::DW_FORM_block4:
            return parseFormBlock4(offset);
        case DwarfForm::DW_FORM_block:
            return parseFormBlock(offset);
        case DwarfForm::DW_FORM_exprloc:
            return parseFormExprloc(offset);
        case DwarfForm::DW_FORM_indirect:
            return parseFormIndirect(offset);
        case DwarfForm::DW_FORM_sec_offset:
            return parseFormSecOffset(offset);
        case DwarfForm::DW_FORM_ref_addr:
            return parseFormRefAddr(offset);
        case DwarfForm::DW_FORM_ref_sig8:
            return parseFormRefSig8(offset);
        case DwarfForm::DW_FORM_strx:
            return parseFormStrx(offset);
        case DwarfForm::DW_FORM_GNU_str_index:
            return parseFormStrx(offset);
        case DwarfForm::DW_FORM_addrx:
            return parseFormAddrx(offset);
        case DwarfForm::DW_FORM_GNU_addr_index:
            return parseFormAddrx(offset);
        case DwarfForm::DW_FORM_data16:
            return parseFormData16(offset);
        case DwarfForm::DW_FORM_line_strp:
            return parseFormLineStrp(offset);
        case DwarfForm::DW_FORM_implicit_const:
            return parseFormImplicitConst(offset);
        case DwarfForm::DW_FORM_loclistx:
            return parseFormLoclistx(offset);
        case DwarfForm::DW_FORM_rnglistx:
            return parseFormRnglistx(offset);
        case DwarfForm::DW_FORM_addrx1:
            return parseFormAddrx1(offset);
        case DwarfForm::DW_FORM_addrx2:
            return parseFormAddrx2(offset);
        case DwarfForm::DW_FORM_addrx3:
            return parseFormAddrx3(offset);
        case DwarfForm::DW_FORM_addrx4:
            return parseFormAddrx4(offset);
        case DwarfForm::DW_FORM_strx1:
            return parseFormStrx1(offset);
        case DwarfForm::DW_FORM_strx2:
            return parseFormStrx2(offset);
        case DwarfForm::DW_FORM_strx3:
            return parseFormStrx3(offset);
        case DwarfForm::DW_FORM_strx4:
            return parseFormStrx4(offset);
        default:
            // Best-effort skip for unsupported forms so subsequent attributes in the
            // same DIE can still be decoded.
            if (!debug_info_.empty()) {
                const uint64_t form_payload_offset = offset;
                DwarfUtils::SizeContext szctx;
                szctx.address_size = address_size_;
                szctx.offset_size = is_dwarf64_ ? 8 : 4;
                szctx.ref_addr_uses_address_size = (dwarf_version_ == DwarfVersion::DWARF2);
                const uint64_t end = currentDebugInfoEnd();
                std::string skip_severity;
                std::function<size_t(uint16_t, uint64_t, int)> mirroredVendorFormSize =
                    [&](uint16_t vendor_form, uint64_t form_offset, int depth) -> size_t {
                        if (depth <= 0) return 0;
                        if ((vendor_form & 0xff00u) != 0x1f00u) {
                            return DwarfUtils::getFormSize(static_cast<DwarfForm>(vendor_form),
                                                           debug_info_.data(),
                                                           static_cast<size_t>(form_offset),
                                                           static_cast<size_t>(end),
                                                           szctx);
                        }

                        const uint8_t low = static_cast<uint8_t>(vendor_form & 0xffu);
                        if (low == 0x16) {
                            uint64_t nested_off = form_offset;
                            uint64_t nested = DwarfUtils::readULEB128(debug_info_.data(), nested_off, end);
                            size_t head = static_cast<size_t>(nested_off - form_offset);
                            if (head == 0) return 0;
                            size_t tail = mirroredVendorFormSize(static_cast<uint16_t>(nested), nested_off, depth - 1);
                            return head + tail;
                        }

                        switch (low) {
                            case 0x01: // addr
                            case 0x03: // block2
                            case 0x04: // block4
                            case 0x05: // data2
                            case 0x06: // data4
                            case 0x07: // data8
                            case 0x08: // string
                            case 0x09: // block
                            case 0x0a: // block1
                            case 0x0b: // data1
                            case 0x0c: // flag
                            case 0x0d: // sdata
                            case 0x0e: // strp
                            case 0x0f: // udata
                            case 0x10: // ref_addr
                            case 0x11: // ref1
                            case 0x12: // ref2
                            case 0x13: // ref4
                            case 0x14: // ref8
                            case 0x15: // ref_udata
                            case 0x17: // sec_offset
                            case 0x18: // exprloc
                            case 0x19: // flag_present
                            case 0x1a: // strx
                            case 0x1b: // addrx
                            case 0x1c: // ref_sup4
                            case 0x1d: // strp_sup
                            case 0x1e: // data16
                            case 0x1f: // line_strp
                            case 0x22: // loclistx
                            case 0x23: // rnglistx
                            case 0x24: // ref_sup8
                            case 0x25: // strx1
                            case 0x26: // strx2
                            case 0x27: // strx3
                            case 0x28: // strx4
                            case 0x29: // addrx1
                            case 0x2a: // addrx2
                            case 0x2b: // addrx3
                            case 0x2c: // addrx4
                                return DwarfUtils::getFormSize(static_cast<DwarfForm>(low),
                                                               debug_info_.data(),
                                                               static_cast<size_t>(form_offset),
                                                               static_cast<size_t>(end),
                                                               szctx);
                            default:
                                return 0;
                        }
                    };
                size_t n = DwarfUtils::getFormSize(form,
                                                   debug_info_.data(),
                                                   static_cast<size_t>(offset),
                                                   static_cast<size_t>(end),
                                                   szctx);
                if (n == 0) {
                    uint16_t fv = static_cast<uint16_t>(form);
                    if ((fv & 0xff00u) == 0x1f00u) {
                        n = mirroredVendorFormSize(fv, offset, 4);
                        if (n != 0) skip_severity = "known_shape";
                    }
                    if (n == 0 && (fv & 0xff00u) == 0x1f00u) {
                        // Conservative vendor-form fallback: many unknown forms in
                        // the 0x1fxx space carry offset-sized payloads.
                        n = (is_dwarf64_ ? 8u : 4u);
                        if (n != 0) skip_severity = "fallback_offset_sized";
                    }
                }
                const uint16_t fv = static_cast<uint16_t>(form);
                if (n != 0 && ((fv & 0xff00u) == 0x1f00u)) {
                    ++unsupported_vendor_form_skip_count_;
                    ++unsupported_vendor_form_skip_histogram_[fv];
                    ++unsupported_vendor_form_skip_severity_buckets_[skip_severity.empty() ? "unspecified" : skip_severity];
                    if (unsupported_vendor_form_skip_samples_.size() < 8) {
                        unsupported_vendor_form_skip_samples_.push_back(
                            VendorFormSkipSample{fv, form_payload_offset,
                                                 skip_severity.empty() ? "unspecified" : skip_severity});
                    }
                }
                advanceOffsetBounded(offset, n);
            }
            return nullptr;
    }
}

std::shared_ptr<AttributeValue> AttributeParser::parseAttribute(DwarfAttribute attr, DwarfForm form, uint64_t& offset) const {
    if (attr == DwarfAttribute::DW_AT_str_offsets_base) {
        return parseOffsetScalarMetadataAttribute(attr, form, offset);
    }

    // Route to specialized parsers for specific attributes
    switch (attr) {
        case DwarfAttribute::DW_AT_stmt_list:
            return parseLineAttribute(attr, form, offset);

        case DwarfAttribute::DW_AT_sibling:
        case DwarfAttribute::DW_AT_discr:
            return parseReferenceMetadataAttribute(attr, form, offset);

        case DwarfAttribute::DW_AT_location:
        case DwarfAttribute::DW_AT_frame_base:
        case DwarfAttribute::DW_AT_data_member_location:
        case DwarfAttribute::DW_AT_vtable_elem_location:
        case DwarfAttribute::DW_AT_segment:
        case DwarfAttribute::DW_AT_static_link:
        case DwarfAttribute::DW_AT_use_location:
        case DwarfAttribute::DW_AT_return_addr:
            return parseLocationAttribute(attr, form, offset);

        case DwarfAttribute::DW_AT_ranges:
            return parseRangeAttribute(attr, form, offset);

        case DwarfAttribute::DW_AT_name:
        case DwarfAttribute::DW_AT_linkage_name:
        case DwarfAttribute::DW_AT_GNU_dwo_name:
            return parseStringMetadataAttribute(attr, form, offset);

        case DwarfAttribute::DW_AT_type:
        case DwarfAttribute::DW_AT_abstract_origin:
        case DwarfAttribute::DW_AT_specification:
        case DwarfAttribute::DW_AT_import:
            return parseTypeAttribute(attr, form, offset);

        case DwarfAttribute::DW_AT_containing_type:
        case DwarfAttribute::DW_AT_friend:
        case DwarfAttribute::DW_AT_common_reference:
        case DwarfAttribute::DW_AT_call_origin:
        case DwarfAttribute::DW_AT_base_types:
        case DwarfAttribute::DW_AT_namelist_item:
        case DwarfAttribute::DW_AT_trampoline:
        case DwarfAttribute::DW_AT_extension:
            return parseReferenceMetadataAttribute(attr, form, offset);

        case DwarfAttribute::DW_AT_entry_pc:
        case DwarfAttribute::DW_AT_call_return_pc:
        case DwarfAttribute::DW_AT_low_pc:
            return parseAddressMetadataAttribute(attr, form, offset);

        case DwarfAttribute::DW_AT_high_pc:
            return parseHighPCAttribute(attr, form, offset);

        case DwarfAttribute::DW_AT_binary_scale:
        case DwarfAttribute::DW_AT_decimal_scale:
        case DwarfAttribute::DW_AT_decimal_sign:
        case DwarfAttribute::DW_AT_digit_count:
        case DwarfAttribute::DW_AT_endianity:
        case DwarfAttribute::DW_AT_address_class:
        case DwarfAttribute::DW_AT_visibility:
        case DwarfAttribute::DW_AT_accessibility:
        case DwarfAttribute::DW_AT_virtuality:
        case DwarfAttribute::DW_AT_inline:
        case DwarfAttribute::DW_AT_priority:
        case DwarfAttribute::DW_AT_calling_convention:
        case DwarfAttribute::DW_AT_encoding:
        case DwarfAttribute::DW_AT_identifier_case:
        case DwarfAttribute::DW_AT_ordering:
        case DwarfAttribute::DW_AT_language:
        case DwarfAttribute::DW_AT_discr_value:
        case DwarfAttribute::DW_AT_decl_column:
        case DwarfAttribute::DW_AT_decl_file:
        case DwarfAttribute::DW_AT_decl_line:
        case DwarfAttribute::DW_AT_call_column:
        case DwarfAttribute::DW_AT_call_file:
        case DwarfAttribute::DW_AT_call_line:
        case DwarfAttribute::DW_AT_string_length_bit_size:
        case DwarfAttribute::DW_AT_string_length_byte_size:
        case DwarfAttribute::DW_AT_signature:
        case DwarfAttribute::DW_AT_dwo_id:
        case DwarfAttribute::DW_AT_GNU_dwo_id:
            return parseScalarMetadataAttribute(attr, form, offset);

        case DwarfAttribute::DW_AT_addr_base:
        case DwarfAttribute::DW_AT_rnglists_base:
        case DwarfAttribute::DW_AT_loclists_base:
        case DwarfAttribute::DW_AT_macro_info:
        case DwarfAttribute::DW_AT_macros:
            return parseOffsetScalarMetadataAttribute(attr, form, offset);

        case DwarfAttribute::DW_AT_picture_string:
        case DwarfAttribute::DW_AT_description:
        case DwarfAttribute::DW_AT_producer:
        case DwarfAttribute::DW_AT_comp_dir:
        case DwarfAttribute::DW_AT_dwo_name:
            return parseStringMetadataAttribute(attr, form, offset);

        case DwarfAttribute::DW_AT_small:
        case DwarfAttribute::DW_AT_threads_scaled:
        case DwarfAttribute::DW_AT_mutable:
        case DwarfAttribute::DW_AT_declaration:
        case DwarfAttribute::DW_AT_external:
        case DwarfAttribute::DW_AT_volatile:
        case DwarfAttribute::DW_AT_artificial:
        case DwarfAttribute::DW_AT_variable_parameter:
        case DwarfAttribute::DW_AT_object_pointer:
        case DwarfAttribute::DW_AT_is_optional:
        case DwarfAttribute::DW_AT_prototyped:
        case DwarfAttribute::DW_AT_use_UTF8:
        case DwarfAttribute::DW_AT_explicit:
        case DwarfAttribute::DW_AT_elemental:
        case DwarfAttribute::DW_AT_pure:
        case DwarfAttribute::DW_AT_recursive:
        case DwarfAttribute::DW_AT_main_subprogram:
        case DwarfAttribute::DW_AT_const_expr:
        case DwarfAttribute::DW_AT_enum_class:
        case DwarfAttribute::DW_AT_reference:
        case DwarfAttribute::DW_AT_rvalue_reference:
        case DwarfAttribute::DW_AT_call_all_calls:
        case DwarfAttribute::DW_AT_call_all_source_calls:
        case DwarfAttribute::DW_AT_call_all_tail_calls:
            return parseFlagMetadataAttribute(attr, form, offset);

        case DwarfAttribute::DW_AT_call_value:
        case DwarfAttribute::DW_AT_call_parameter:
        case DwarfAttribute::DW_AT_discr_list:
            return parseExpressionBlockMetadataAttribute(attr, form, offset);

        case DwarfAttribute::DW_AT_const_value:
        case DwarfAttribute::DW_AT_default_value:
        case DwarfAttribute::DW_AT_data_location:
        case DwarfAttribute::DW_AT_string_length:
        case DwarfAttribute::DW_AT_lower_bound:
        case DwarfAttribute::DW_AT_upper_bound:
        case DwarfAttribute::DW_AT_count:
        case DwarfAttribute::DW_AT_allocated:
        case DwarfAttribute::DW_AT_associated:
        case DwarfAttribute::DW_AT_rank:
        case DwarfAttribute::DW_AT_byte_stride:
        case DwarfAttribute::DW_AT_bit_stride:
        case DwarfAttribute::DW_AT_start_scope:
        case DwarfAttribute::DW_AT_data_bit_offset:
            return parseConstValueAttribute(attr, form, offset);

        case DwarfAttribute::DW_AT_byte_size:
        case DwarfAttribute::DW_AT_bit_offset:
        case DwarfAttribute::DW_AT_bit_size:
            return parseConstantReferenceExpressionMetadataAttribute(attr, form, offset);

        default:
            // Fall back to generic parsing
            return parseAttribute(form, offset);
    }
}

std::vector<std::shared_ptr<AttributeValue>> AttributeParser::parseAttributeList(
    const std::vector<std::pair<DwarfAttribute, DwarfForm>>& attr_specs, uint64_t& offset) const {

    std::vector<std::shared_ptr<AttributeValue>> attributes;

    for (const auto& attr_spec : attr_specs) {
        auto attr_value = parseAttribute(attr_spec.first, attr_spec.second, offset);
        if (attr_value) {
            attributes.push_back(attr_value);
        }
    }

    return attributes;
}

std::shared_ptr<AttributeValue> AttributeParser::parseAddressAttribute(DwarfForm form, uint64_t& offset) const {
    switch (form) {
        case DwarfForm::DW_FORM_addr:
            return parseFormAddr(offset);
        case DwarfForm::DW_FORM_addrx:
            return parseFormAddrx(offset);
        case DwarfForm::DW_FORM_GNU_addr_index:
            return parseFormAddrx(offset);
        case DwarfForm::DW_FORM_addrx1:
            return parseFormAddrx1(offset);
        case DwarfForm::DW_FORM_addrx2:
            return parseFormAddrx2(offset);
        case DwarfForm::DW_FORM_addrx3:
            return parseFormAddrx3(offset);
        case DwarfForm::DW_FORM_addrx4:
            return parseFormAddrx4(offset);
        default:
            return nullptr;
    }
}

std::shared_ptr<AttributeValue> AttributeParser::parseDataAttribute(DwarfForm form, uint64_t& offset) const {
    switch (form) {
        case DwarfForm::DW_FORM_data1:
            return parseFormData1(offset);
        case DwarfForm::DW_FORM_data2:
            return parseFormData2(offset);
        case DwarfForm::DW_FORM_data4:
            return parseFormData4(offset);
        case DwarfForm::DW_FORM_data8:
            return parseFormData8(offset);
        case DwarfForm::DW_FORM_sdata:
            return parseFormSdata(offset);
        case DwarfForm::DW_FORM_udata:
            return parseFormUdata(offset);
        case DwarfForm::DW_FORM_data16:
            return parseFormData16(offset);
        default:
            return nullptr;
    }
}

std::shared_ptr<AttributeValue> AttributeParser::parseStringAttribute(DwarfForm form, uint64_t& offset) const {
    switch (form) {
        case DwarfForm::DW_FORM_string:
            return parseFormString(offset);
        case DwarfForm::DW_FORM_strp:
            return parseFormStrp(offset);
        case DwarfForm::DW_FORM_strp_sup:
            return parseFormStrpSup(offset);
        case DwarfForm::DW_FORM_GNU_strp_alt:
            return parseFormGnuStrpAlt(offset);
        case DwarfForm::DW_FORM_strx:
            return parseFormStrx(offset);
        case DwarfForm::DW_FORM_GNU_str_index:
            return parseFormStrx(offset);
        case DwarfForm::DW_FORM_strx1:
            return parseFormStrx1(offset);
        case DwarfForm::DW_FORM_strx2:
            return parseFormStrx2(offset);
        case DwarfForm::DW_FORM_strx3:
            return parseFormStrx3(offset);
        case DwarfForm::DW_FORM_strx4:
            return parseFormStrx4(offset);
        case DwarfForm::DW_FORM_line_strp:
            return parseFormLineStrp(offset);
        default:
            return nullptr;
    }
}

std::shared_ptr<AttributeValue> AttributeParser::parseReferenceAttribute(DwarfForm form, uint64_t& offset) const {
    switch (form) {
        case DwarfForm::DW_FORM_ref1:
            return parseFormRef1(offset);
        case DwarfForm::DW_FORM_ref2:
            return parseFormRef2(offset);
        case DwarfForm::DW_FORM_ref4:
            return parseFormRef4(offset);
        case DwarfForm::DW_FORM_ref8:
            return parseFormRef8(offset);
        case DwarfForm::DW_FORM_ref_sup4:
            return parseFormRefSup4(offset);
        case DwarfForm::DW_FORM_ref_sup8:
            return parseFormRefSup8(offset);
        case DwarfForm::DW_FORM_GNU_ref_alt:
            return parseFormGnuRefAlt(offset);
        case DwarfForm::DW_FORM_ref_udata:
            return parseFormRefUdata(offset);
        case DwarfForm::DW_FORM_ref_addr:
            return parseFormRefAddr(offset);
        case DwarfForm::DW_FORM_ref_sig8:
            return parseFormRefSig8(offset);
        default:
            return nullptr;
    }
}

std::shared_ptr<AttributeValue> AttributeParser::parseBlockAttribute(DwarfForm form, uint64_t& offset) const {
    switch (form) {
        case DwarfForm::DW_FORM_block1:
            return parseFormBlock1(offset);
        case DwarfForm::DW_FORM_block2:
            return parseFormBlock2(offset);
        case DwarfForm::DW_FORM_block4:
            return parseFormBlock4(offset);
        case DwarfForm::DW_FORM_block:
            return parseFormBlock(offset);
        default:
            return nullptr;
    }
}

std::shared_ptr<AttributeValue> AttributeParser::parseExpressionAttribute(DwarfForm form, uint64_t& offset) const {
    switch (form) {
        case DwarfForm::DW_FORM_exprloc:
            return parseFormExprloc(offset);
        default:
            return nullptr;
    }
}

std::shared_ptr<AttributeValue> AttributeParser::parseFlagAttribute(DwarfForm form, uint64_t& offset) const {
    switch (form) {
        case DwarfForm::DW_FORM_flag:
            return parseFormFlag(offset);
        case DwarfForm::DW_FORM_flag_present:
            return parseFormFlagPresent(offset);
        default:
            return nullptr;
    }
}

std::shared_ptr<AttributeValue> AttributeParser::parseLocationAttribute(DwarfAttribute attr, DwarfForm form, uint64_t& offset) const {
    (void)attr;
    switch (form) {
        case DwarfForm::DW_FORM_exprloc:
            return parseLocationExpression(offset);
        case DwarfForm::DW_FORM_loclistx:
            return parseFormLoclistx(offset);
        case DwarfForm::DW_FORM_sec_offset:
            return parseLocationListPointer(offset);
        case DwarfForm::DW_FORM_block1:
        case DwarfForm::DW_FORM_block2:
        case DwarfForm::DW_FORM_block4:
        case DwarfForm::DW_FORM_block:
            return std::make_shared<LocationAttributeValue>(
                LocationAttributeValue::LocationType::EXPRESSION,
                std::static_pointer_cast<BlockAttributeValue>(parseBlockAttribute(form, offset))->getData());
        default:
            parseAttribute(form, offset);
            if ((static_cast<uint16_t>(form) & 0xff00u) == 0x1f00u) {
                return nullptr;
            }
            return std::make_shared<LocationAttributeValue>(
                LocationAttributeValue::LocationType::INVALID,
                std::vector<uint8_t>{});
    }
}

std::shared_ptr<AttributeValue> AttributeParser::parseRangeAttribute(DwarfAttribute attr, DwarfForm form, uint64_t& offset) const {
    (void)attr;
    switch (form) {
        case DwarfForm::DW_FORM_sec_offset:
            return parseRangeListPointer(offset);
        case DwarfForm::DW_FORM_rnglistx:
            return parseFormRnglistx(offset);
        default:
            parseAttribute(form, offset);
            if ((static_cast<uint16_t>(form) & 0xff00u) == 0x1f00u) {
                return nullptr;
            }
            return std::make_shared<RangeAttributeValue>(
                std::vector<RangeAttributeValue::RangeEntry>{});
    }
}

std::shared_ptr<AttributeValue> AttributeParser::parseLineAttribute(DwarfAttribute attr, DwarfForm form, uint64_t& offset) const {
    (void)attr;
    switch (form) {
        case DwarfForm::DW_FORM_sec_offset:
            return parseLineNumberProgramPointer(offset);
        default:
            parseAttribute(form, offset);
            if ((static_cast<uint16_t>(form) & 0xff00u) == 0x1f00u) {
                return nullptr;
            }
            return std::make_shared<LineAttributeValue>(
                std::vector<LineAttributeValue::LineEntry>{},
                std::vector<std::string>{},
                std::vector<LineAttributeValue::FileEntry>{},
                std::vector<LineAttributeValue::DirectoryEntry>{});
    }
}

std::shared_ptr<AttributeValue> AttributeParser::parseTypeAttribute(DwarfAttribute attr, DwarfForm form, uint64_t& offset) const {
    (void)attr;
    switch (form) {
        case DwarfForm::DW_FORM_ref1:
            return std::make_shared<TypeAttributeValue>(std::static_pointer_cast<ReferenceAttributeValue>(parseFormRef1(offset))->getOffset());
        case DwarfForm::DW_FORM_ref2:
            return std::make_shared<TypeAttributeValue>(std::static_pointer_cast<ReferenceAttributeValue>(parseFormRef2(offset))->getOffset());
        case DwarfForm::DW_FORM_ref4:
            return std::make_shared<TypeAttributeValue>(std::static_pointer_cast<ReferenceAttributeValue>(parseFormRef4(offset))->getOffset());
        case DwarfForm::DW_FORM_ref8:
            return std::make_shared<TypeAttributeValue>(std::static_pointer_cast<ReferenceAttributeValue>(parseFormRef8(offset))->getOffset());
        case DwarfForm::DW_FORM_ref_sup4:
            return std::make_shared<TypeAttributeValue>(std::static_pointer_cast<ReferenceAttributeValue>(parseFormRefSup4(offset))->getOffset());
        case DwarfForm::DW_FORM_ref_sup8:
            return std::make_shared<TypeAttributeValue>(std::static_pointer_cast<ReferenceAttributeValue>(parseFormRefSup8(offset))->getOffset());
        case DwarfForm::DW_FORM_GNU_ref_alt:
            return std::make_shared<TypeAttributeValue>(std::static_pointer_cast<ReferenceAttributeValue>(parseFormGnuRefAlt(offset))->getOffset());
        case DwarfForm::DW_FORM_ref_udata:
            return std::make_shared<TypeAttributeValue>(std::static_pointer_cast<ReferenceAttributeValue>(parseFormRefUdata(offset))->getOffset());
        case DwarfForm::DW_FORM_ref_addr: {
            // Absolute .debug_info offset.
            auto ref = std::static_pointer_cast<ReferenceAttributeValue>(parseFormRefAddr(offset));
            return std::make_shared<TypeAttributeValue>(ref->getOffset());
        }
        case DwarfForm::DW_FORM_ref_sig8:
            return parseTypeSignature(offset);
        default:
            parseAttribute(form, offset);
            if ((static_cast<uint16_t>(form) & 0xff00u) == 0x1f00u) {
                return nullptr;
            }
            return std::make_shared<TypeAttributeValue>(0);
    }
}

std::shared_ptr<AttributeValue> AttributeParser::parseConstValueAttribute(DwarfAttribute attr, DwarfForm form, uint64_t& offset) const {
    auto value = parseConstantValue(attr, form, offset);
    if (value) {
        return value;
    }
    auto raw = parseAttribute(form, offset);
    if ((static_cast<uint16_t>(form) & 0xff00u) == 0x1f00u) {
        return raw;
    }
    return nullptr;
}

std::shared_ptr<AttributeValue> AttributeParser::parseReferenceMetadataAttribute(DwarfAttribute attr,
                                                                                 DwarfForm form,
                                                                                 uint64_t& offset) const {
    (void)attr;
    auto value = parseReferenceAttribute(form, offset);
    if (value) {
        return value;
    }
    auto raw = parseAttribute(form, offset);
    if ((static_cast<uint16_t>(form) & 0xff00u) == 0x1f00u) {
        return raw;
    }
    return nullptr;
}

std::shared_ptr<AttributeValue> AttributeParser::parseAddressMetadataAttribute(DwarfAttribute attr,
                                                                               DwarfForm form,
                                                                               uint64_t& offset) const {
    (void)attr;
    auto value = parseAddressAttribute(form, offset);
    if (value) {
        return value;
    }
    auto raw = parseAttribute(form, offset);
    if ((static_cast<uint16_t>(form) & 0xff00u) == 0x1f00u) {
        return raw;
    }
    return nullptr;
}

std::shared_ptr<AttributeValue> AttributeParser::parseHighPCAttribute(DwarfAttribute attr,
                                                                      DwarfForm form,
                                                                      uint64_t& offset) const {
    (void)attr;
    if (auto value = parseAddressAttribute(form, offset)) {
        return value;
    }
    if (auto value = parseDataAttribute(form, offset)) {
        return value;
    }
    if (form == DwarfForm::DW_FORM_implicit_const) {
        return parseFormImplicitConst(offset);
    }
    auto raw = parseAttribute(form, offset);
    if ((static_cast<uint16_t>(form) & 0xff00u) == 0x1f00u) {
        return raw;
    }
    return nullptr;
}

std::shared_ptr<AttributeValue> AttributeParser::parseScalarMetadataAttribute(DwarfAttribute attr,
                                                                              DwarfForm form,
                                                                              uint64_t& offset) const {
    (void)attr;
    auto value = parseDataAttribute(form, offset);
    if (value) {
        return value;
    }
    if (form == DwarfForm::DW_FORM_implicit_const) {
        return parseFormImplicitConst(offset);
    }
    auto raw = parseAttribute(form, offset);
    if ((static_cast<uint16_t>(form) & 0xff00u) == 0x1f00u) {
        return raw;
    }
    return nullptr;
}

std::shared_ptr<AttributeValue> AttributeParser::parseOffsetScalarMetadataAttribute(DwarfAttribute attr,
                                                                                    DwarfForm form,
                                                                                    uint64_t& offset) const {
    (void)attr;
    std::shared_ptr<AttributeValue> value;
    if (form == DwarfForm::DW_FORM_sec_offset) {
        value = parseFormSecOffset(offset);
    } else {
        value = parseDataAttribute(form, offset);
    }
    if (value) {
        return value;
    }
    auto raw = parseAttribute(form, offset);
    if ((static_cast<uint16_t>(form) & 0xff00u) == 0x1f00u) {
        return raw;
    }
    return nullptr;
}

std::shared_ptr<AttributeValue> AttributeParser::parseStringMetadataAttribute(DwarfAttribute attr,
                                                                              DwarfForm form,
                                                                              uint64_t& offset) const {
    (void)attr;
    auto value = parseStringAttribute(form, offset);
    if (value) {
        return value;
    }
    auto raw = parseAttribute(form, offset);
    if ((static_cast<uint16_t>(form) & 0xff00u) == 0x1f00u) {
        return raw;
    }
    return nullptr;
}

std::shared_ptr<AttributeValue> AttributeParser::parseFlagMetadataAttribute(DwarfAttribute attr,
                                                                            DwarfForm form,
                                                                            uint64_t& offset) const {
    (void)attr;
    auto value = parseFlagAttribute(form, offset);
    if (value) {
        return value;
    }
    auto raw = parseAttribute(form, offset);
    if ((static_cast<uint16_t>(form) & 0xff00u) == 0x1f00u) {
        return raw;
    }
    return nullptr;
}

std::shared_ptr<AttributeValue> AttributeParser::parseExpressionBlockMetadataAttribute(DwarfAttribute attr,
                                                                                       DwarfForm form,
                                                                                       uint64_t& offset) const {
    (void)attr;
    if (auto expr = parseExpressionAttribute(form, offset)) {
        return expr;
    }
    if (auto block = parseBlockAttribute(form, offset)) {
        return block;
    }
    auto raw = parseAttribute(form, offset);
    if ((static_cast<uint16_t>(form) & 0xff00u) == 0x1f00u) {
        return raw;
    }
    return nullptr;
}

std::shared_ptr<AttributeValue> AttributeParser::parseConstantReferenceExpressionMetadataAttribute(DwarfAttribute attr,
                                                                                                   DwarfForm form,
                                                                                                   uint64_t& offset) const {
    (void)attr;
    if (auto value = parseDataAttribute(form, offset)) {
        return value;
    }
    if (form == DwarfForm::DW_FORM_implicit_const) {
        return parseFormImplicitConst(offset);
    }
    if (auto expr = parseExpressionAttribute(form, offset)) {
        return expr;
    }
    if (auto ref = parseReferenceAttribute(form, offset)) {
        return ref;
    }
    auto raw = parseAttribute(form, offset);
    if ((static_cast<uint16_t>(form) & 0xff00u) == 0x1f00u) {
        return raw;
    }
    return nullptr;
}

uint64_t AttributeParser::currentDebugInfoEnd() const {
    const uint64_t max = debug_info_.size();
    return (cu_debug_info_end_ <= max) ? cu_debug_info_end_ : max;
}

void AttributeParser::advanceOffsetBounded(uint64_t& offset, uint64_t amount) const {
    const uint64_t max = currentDebugInfoEnd();
    if (offset >= max) {
        offset = max;
        return;
    }
    if (amount > (max - offset)) {
        offset = max;
        return;
    }
    offset += amount;
}

std::string AttributeParser::readCStringFromSection(const std::vector<uint8_t>& section,
                                                    uint64_t offset,
                                                    uint64_t* consumed,
                                                    bool* terminated) const {
    if (consumed) *consumed = 0;
    if (terminated) *terminated = false;
    size_t section_end = section.size();
    if (&section == &debug_info_) {
        section_end = static_cast<size_t>(currentDebugInfoEnd());
    }
    if (offset >= section_end) return "";

    const uint8_t* start = section.data() + offset;
    size_t remaining = section_end - static_cast<size_t>(offset);
    const void* term = std::memchr(start, 0, remaining);

    if (term == nullptr) {
        if (consumed) *consumed = remaining;
        return std::string(reinterpret_cast<const char*>(start), remaining);
    }

    size_t n = static_cast<const uint8_t*>(term) - start;
    if (consumed) *consumed = n + 1;
    if (terminated) *terminated = true;
    return std::string(reinterpret_cast<const char*>(start), n);
}

std::string AttributeParser::getString(uint64_t offset) const {
    return readCStringFromSection(debug_str_, offset);
}

std::string AttributeParser::readString(uint64_t& offset) const {
    uint64_t consumed = 0;
    std::string value = readCStringFromSection(debug_str_, offset, &consumed, nullptr);
    if (consumed == 0) return value;
    uint64_t max = debug_str_.size();
    if (offset > max) {
        offset = max;
    } else if (consumed > (max - offset)) {
        offset = max;
    } else {
        offset += consumed;
    }
    return value;
}

std::vector<uint8_t> AttributeParser::getBlock(uint64_t offset, uint64_t size) const {
    const uint64_t max = currentDebugInfoEnd();
    if (offset > max) return {};
    if (size > (max - offset)) return {};
    return std::vector<uint8_t>(debug_info_.begin() + offset, debug_info_.begin() + offset + size);
}

bool AttributeParser::isValidOffset(uint64_t offset) const {
    return offset < debug_info_.size();
}

void AttributeParser::printAttributeValue(std::shared_ptr<AttributeValue> value, const std::string& name) const {
    if (!value) {
        std::cout << name << ": <null>" << std::endl;
        return;
    }
    
    std::cout << name << ": " << value->toString() << std::endl;
}

std::string AttributeParser::attributeValueToString(std::shared_ptr<AttributeValue> value) const {
    if (!value) return "<null>";
    return value->toString();
}

// Data reading helpers
uint64_t AttributeParser::readULEB128(uint64_t& offset) const {
    return DwarfUtils::readULEB128(debug_info_.data(), offset, currentDebugInfoEnd());
}

int64_t AttributeParser::readSLEB128(uint64_t& offset) const {
    return DwarfUtils::readSLEB128(debug_info_.data(), offset, currentDebugInfoEnd());
}

uint8_t AttributeParser::readU8(uint64_t& offset) const {
    return DwarfUtils::readU8(debug_info_.data(), offset, currentDebugInfoEnd());
}

int8_t AttributeParser::readS8(uint64_t& offset) const {
    return static_cast<int8_t>(DwarfUtils::readU8(debug_info_.data(), offset, currentDebugInfoEnd()));
}

uint16_t AttributeParser::readU16(uint64_t& offset) const {
    return DwarfUtils::readU16(debug_info_.data(), offset, currentDebugInfoEnd());
}

uint32_t AttributeParser::readU32(uint64_t& offset) const {
    return DwarfUtils::readU32(debug_info_.data(), offset, currentDebugInfoEnd());
}

uint64_t AttributeParser::readU64(uint64_t& offset) const {
    return DwarfUtils::readU64(debug_info_.data(), offset, currentDebugInfoEnd());
}

// Form-specific parsers
std::shared_ptr<AttributeValue> AttributeParser::parseFormAddr(uint64_t& offset) const {
    uint64_t addr = (address_size_ == 8) ? readU64(offset) : readU32(offset);
    return std::make_shared<AddressAttributeValue>(addr);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormData1(uint64_t& offset) const {
    uint8_t val = readU8(offset);
    return std::make_shared<UnsignedAttributeValue>(val);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormData2(uint64_t& offset) const {
    uint16_t val = readU16(offset);
    return std::make_shared<UnsignedAttributeValue>(val);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormData4(uint64_t& offset) const {
    uint32_t val = readU32(offset);
    return std::make_shared<UnsignedAttributeValue>(val);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormData8(uint64_t& offset) const {
    uint64_t val = readU64(offset);
    return std::make_shared<UnsignedAttributeValue>(val);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormSdata(uint64_t& offset) const {
    int64_t val = readSLEB128(offset);
    return std::make_shared<SignedAttributeValue>(val);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormUdata(uint64_t& offset) const {
    uint64_t val = readULEB128(offset);
    return std::make_shared<UnsignedAttributeValue>(val);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormString(uint64_t& offset) const {
    uint64_t consumed = 0;
    std::string value = readCStringFromSection(debug_info_, offset, &consumed, nullptr);
    advanceOffsetBounded(offset, consumed);
    return std::make_shared<StringAttributeValue>(value);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormStrp(uint64_t& offset) const {
    uint64_t str_offset = is_dwarf64_ ? readU64(offset) : readU32(offset);
    return std::make_shared<StringAttributeValue>(getString(str_offset));
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormStrpSup(uint64_t& offset) const {
    uint64_t str_offset = is_dwarf64_ ? readU64(offset) : readU32(offset);
    if (str_offset < debug_str_sup_.size()) {
        return std::make_shared<StringAttributeValue>(readCStringFromSection(debug_str_sup_, str_offset));
    }
    return std::make_shared<StringAttributeValue>("<strp_sup:" + std::to_string(str_offset) + ">");
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormGnuStrpAlt(uint64_t& offset) const {
    uint64_t str_offset = is_dwarf64_ ? readU64(offset) : readU32(offset);
    if (str_offset < debug_str_sup_.size()) {
        return std::make_shared<StringAttributeValue>(readCStringFromSection(debug_str_sup_, str_offset));
    }
    return std::make_shared<StringAttributeValue>("<gnu_strp_alt:" + std::to_string(str_offset) + ">");
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormRef1(uint64_t& offset) const {
    uint8_t ref = readU8(offset);
    // CU-relative offset - add CU base to get absolute offset
    return std::make_shared<ReferenceAttributeValue>(cu_debug_info_offset_ + ref);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormRef2(uint64_t& offset) const {
    uint16_t ref = readU16(offset);
    // CU-relative offset - add CU base to get absolute offset
    return std::make_shared<ReferenceAttributeValue>(cu_debug_info_offset_ + ref);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormRef4(uint64_t& offset) const {
    uint32_t ref = readU32(offset);
    // CU-relative offset - add CU base to get absolute offset
    return std::make_shared<ReferenceAttributeValue>(cu_debug_info_offset_ + ref);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormRef8(uint64_t& offset) const {
    uint64_t ref = readU64(offset);
    // CU-relative offset - add CU base to get absolute offset
    return std::make_shared<ReferenceAttributeValue>(cu_debug_info_offset_ + ref);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormRefSup4(uint64_t& offset) const {
    uint32_t ref = readU32(offset);
    // Section-relative offset into the supplementary .debug_info.
    return std::make_shared<ReferenceAttributeValue>(sup_debug_info_offset_bias_ + ref);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormRefSup8(uint64_t& offset) const {
    uint64_t ref = readU64(offset);
    // Section-relative offset into the supplementary .debug_info.
    return std::make_shared<ReferenceAttributeValue>(sup_debug_info_offset_bias_ + ref);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormGnuRefAlt(uint64_t& offset) const {
    // GNU ref_alt uses the unit's DWARF format width and is section-relative
    // to the alternate/supplementary .debug_info namespace.
    uint64_t ref = is_dwarf64_ ? readU64(offset) : readU32(offset);
    return std::make_shared<ReferenceAttributeValue>(sup_debug_info_offset_bias_ + ref);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormRefUdata(uint64_t& offset) const {
    uint64_t ref = readULEB128(offset);
    // CU-relative offset - add CU base to get absolute offset
    return std::make_shared<ReferenceAttributeValue>(cu_debug_info_offset_ + ref);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormFlag(uint64_t& offset) const {
    uint8_t flag = readU8(offset);
    return std::make_shared<FlagAttributeValue>(flag != 0);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormFlagPresent(uint64_t& offset) const {
    (void)offset;
    return std::make_shared<FlagAttributeValue>(true);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormBlock1(uint64_t& offset) const {
    uint8_t length = readU8(offset);
    std::vector<uint8_t> data = getBlock(offset, length);
    advanceOffsetBounded(offset, length);
    return std::make_shared<BlockAttributeValue>(data);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormBlock2(uint64_t& offset) const {
    uint16_t length = readU16(offset);
    std::vector<uint8_t> data = getBlock(offset, length);
    advanceOffsetBounded(offset, length);
    return std::make_shared<BlockAttributeValue>(data);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormBlock4(uint64_t& offset) const {
    uint32_t length = readU32(offset);
    std::vector<uint8_t> data = getBlock(offset, length);
    advanceOffsetBounded(offset, length);
    return std::make_shared<BlockAttributeValue>(data);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormBlock(uint64_t& offset) const {
    uint64_t length = readULEB128(offset);
    std::vector<uint8_t> data = getBlock(offset, length);
    advanceOffsetBounded(offset, length);
    return std::make_shared<BlockAttributeValue>(data);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormExprloc(uint64_t& offset) const {
    uint64_t length = readULEB128(offset);
    std::vector<uint8_t> data = getBlock(offset, length);
    advanceOffsetBounded(offset, length);
    return std::make_shared<ExpressionAttributeValue>(data);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormIndirect(uint64_t& offset) const {
    uint64_t form = readULEB128(offset);
    return parseAttribute(static_cast<DwarfForm>(form), offset);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormSecOffset(uint64_t& offset) const {
    uint64_t sec_offset = is_dwarf64_ ? readU64(offset) : readU32(offset);
    return std::make_shared<UnsignedAttributeValue>(sec_offset);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormRefAddr(uint64_t& offset) const {
    // DW_FORM_ref_addr size is address_size in DWARF2 and offset_size in DWARF3+.
    bool use_addr_size = (dwarf_version_ == DwarfVersion::DWARF2);
    uint8_t size = use_addr_size ? address_size_ : (is_dwarf64_ ? 8 : 4);
    uint64_t ref = (size == 8) ? readU64(offset) : readU32(offset);
    // ref_addr is a section-relative reference to .debug_info/.debug_info.dwo.
    // Apply the DIEParser-provided bias so DWO DIE offsets won't collide with main .debug_info.
    return std::make_shared<ReferenceAttributeValue>(debug_info_offset_bias_ + ref);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormRefSig8(uint64_t& offset) const {
    uint64_t sig = readU64(offset);
    return std::make_shared<ReferenceAttributeValue>(sig);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormStrx(uint64_t& offset) const {
    uint64_t index = readULEB128(offset);

    uint8_t offset_size = is_dwarf64_ ? 8 : 4;
    uint64_t pos = cu_str_offsets_base_ + (index * offset_size);
    if (pos + offset_size <= cu_str_offsets_end_) {
        uint64_t temp_off = pos;
        uint64_t str_offset = (offset_size == 8)
            ? DwarfUtils::readU64(debug_str_offsets_.data(), temp_off, debug_str_offsets_.size())
            : DwarfUtils::readU32(debug_str_offsets_.data(), temp_off, debug_str_offsets_.size());
        if (str_offset < debug_str_.size()) {
            return std::make_shared<StringAttributeValue>(getString(str_offset));
        }
    }

    return std::make_shared<StringAttributeValue>("<strx:" + std::to_string(index) + ">");
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormAddrx(uint64_t& offset) const {
    uint64_t index = readULEB128(offset);

    // Look up in debug_addr using cu_addr_base_
    uint64_t addr_offset = cu_addr_base_ + (index * static_cast<uint64_t>(cu_addr_entry_stride_));
    uint64_t addr_field = addr_offset + cu_addr_seg_size_;
    if (addr_field + address_size_ <= cu_addr_end_) {
        uint64_t addr = 0;
        uint64_t temp_off = addr_field;
        if (address_size_ == 8) addr = DwarfUtils::readU64(debug_addr_.data(), temp_off, debug_addr_.size());
        else addr = DwarfUtils::readU32(debug_addr_.data(), temp_off, debug_addr_.size());
        return std::make_shared<AddressAttributeValue>(addr);
    }

    return std::make_shared<AddressAttributeValue>(index);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormData16(uint64_t& offset) const {
    std::vector<uint8_t> data = getBlock(offset, 16);
    advanceOffsetBounded(offset, 16);
    return std::make_shared<BlockAttributeValue>(data);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormLineStrp(uint64_t& offset) const {
    uint64_t str_offset = is_dwarf64_ ? readU64(offset) : readU32(offset);
    
    // Use the line string table to resolve the actual string
    if (str_offset < debug_line_str_.size()) {
        return std::make_shared<StringAttributeValue>(readCStringFromSection(debug_line_str_, str_offset));
    }
    
    return std::make_shared<StringAttributeValue>("<line_strp:" + std::to_string(str_offset) + ">");
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormImplicitConst(uint64_t& offset) const {
    (void)offset;
    // Implicit constant value comes from the abbreviation table and is supplied by DIEParser.
    // This form consumes no bytes in .debug_info.
    return std::make_shared<SignedAttributeValue>(implicit_const_value_.value_or(0));
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormRnglistx(uint64_t& offset) const {
    uint64_t index = readULEB128(offset);

    if (rnglists_parser_ && !debug_rnglists_.empty()) {
        // Resolve the index to an offset and parse the range list
        uint64_t list_offset = rnglists_parser_->resolveRngListx(index,
                                                                 0,
                                                                 cu_rnglists_base_,
                                                                 cu_rnglists_is_dwarf64_,
                                                                 cu_rnglists_offsets_end_,
                                                                 cu_rnglists_end_);
        if (list_offset > 0) {
            std::vector<RngListEntry> rng_entries = rnglists_parser_->parseRangeList(
                list_offset, cu_base_address_, address_size_, cu_rnglists_end_, cu_rnglists_seg_size_);

            // Convert to RangeAttributeValue format
            std::vector<RangeAttributeValue::RangeEntry> ranges;
            for (const auto& entry : rng_entries) {
                if (entry.type != DW_RLE::DW_RLE_end_of_list) {
                    ranges.push_back({entry.start, entry.end, entry.is_base_address});
                }
            }
            return std::make_shared<RangeAttributeValue>(ranges);
        }
    }

    // Fallback: return the index if parsing fails
    return std::make_shared<UnsignedAttributeValue>(index);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormLoclistx(uint64_t& offset) const {
    uint64_t index = readULEB128(offset);

    if (loclists_parser_ && !debug_loclists_.empty()) {
        // Resolve the index to an offset and parse the location list
        uint64_t list_offset = loclists_parser_->resolveLocListx(index,
                                                                 0,
                                                                 cu_loclists_base_,
                                                                 cu_loclists_is_dwarf64_,
                                                                 cu_loclists_offsets_end_,
                                                                 cu_loclists_end_);
        if (list_offset > 0) {
            std::vector<LocListEntry> loc_entries = loclists_parser_->parseLocationList(
                list_offset, cu_base_address_, address_size_, cu_loclists_end_, cu_loclists_seg_size_);

            // Convert LocListEntry to LocationAttributeValue::LocationEntry
            std::vector<LocationAttributeValue::LocationEntry> entries;
            for (const auto& entry : loc_entries) {
                if (entry.type == DW_LLE::DW_LLE_end_of_list) {
                    continue;  // Skip end markers
                }
                entries.emplace_back(
                    entry.start,
                    entry.end,
                    entry.expression,
                    entry.is_default
                );
            }

            if (!entries.empty()) {
                return std::make_shared<LocationAttributeValue>(entries);
            }
        }
    }

    // Fallback: return the index if parsing fails
    return std::make_shared<UnsignedAttributeValue>(index);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormAddrx1(uint64_t& offset) const {
    uint8_t index = readU8(offset);
    // Look up in debug_addr using cu_addr_base_
    uint64_t addr_offset = cu_addr_base_ + (static_cast<uint64_t>(index) * cu_addr_entry_stride_);
    uint64_t addr_field = addr_offset + cu_addr_seg_size_;
    if (addr_field + address_size_ <= cu_addr_end_) {
        uint64_t addr = 0;
        if (address_size_ == 8) {
            uint64_t temp_off = addr_field;
            addr = DwarfUtils::readU64(debug_addr_.data(), temp_off, debug_addr_.size());
        } else {
            uint64_t temp_off = addr_field;
            addr = DwarfUtils::readU32(debug_addr_.data(), temp_off, debug_addr_.size());
        }
        return std::make_shared<AddressAttributeValue>(addr);
    }
    return std::make_shared<AddressAttributeValue>(index);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormAddrx2(uint64_t& offset) const {
    uint16_t index = readU16(offset);
    uint64_t addr_offset = cu_addr_base_ + (static_cast<uint64_t>(index) * cu_addr_entry_stride_);
    uint64_t addr_field = addr_offset + cu_addr_seg_size_;
    if (addr_field + address_size_ <= cu_addr_end_) {
        uint64_t addr = 0;
        if (address_size_ == 8) {
            uint64_t temp_off = addr_field;
            addr = DwarfUtils::readU64(debug_addr_.data(), temp_off, debug_addr_.size());
        } else {
            uint64_t temp_off = addr_field;
            addr = DwarfUtils::readU32(debug_addr_.data(), temp_off, debug_addr_.size());
        }
        return std::make_shared<AddressAttributeValue>(addr);
    }
    return std::make_shared<AddressAttributeValue>(index);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormAddrx3(uint64_t& offset) const {
    // Read 3-byte index
    uint32_t index = readU8(offset) | (readU8(offset) << 8) | (readU8(offset) << 16);
    uint64_t addr_offset = cu_addr_base_ + (static_cast<uint64_t>(index) * cu_addr_entry_stride_);
    uint64_t addr_field = addr_offset + cu_addr_seg_size_;
    if (addr_field + address_size_ <= cu_addr_end_) {
        uint64_t addr = 0;
        if (address_size_ == 8) {
            uint64_t temp_off = addr_field;
            addr = DwarfUtils::readU64(debug_addr_.data(), temp_off, debug_addr_.size());
        } else {
            uint64_t temp_off = addr_field;
            addr = DwarfUtils::readU32(debug_addr_.data(), temp_off, debug_addr_.size());
        }
        return std::make_shared<AddressAttributeValue>(addr);
    }
    return std::make_shared<AddressAttributeValue>(index);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormAddrx4(uint64_t& offset) const {
    uint32_t index = readU32(offset);
    uint64_t addr_offset = cu_addr_base_ + (static_cast<uint64_t>(index) * cu_addr_entry_stride_);
    uint64_t addr_field = addr_offset + cu_addr_seg_size_;
    if (addr_field + address_size_ <= cu_addr_end_) {
        uint64_t addr = 0;
        if (address_size_ == 8) {
            uint64_t temp_off = addr_field;
            addr = DwarfUtils::readU64(debug_addr_.data(), temp_off, debug_addr_.size());
        } else {
            uint64_t temp_off = addr_field;
            addr = DwarfUtils::readU32(debug_addr_.data(), temp_off, debug_addr_.size());
        }
        return std::make_shared<AddressAttributeValue>(addr);
    }
    return std::make_shared<AddressAttributeValue>(index);
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormStrx1(uint64_t& offset) const {
    uint8_t index = readU8(offset);
    uint8_t offset_size = is_dwarf64_ ? 8 : 4;
    uint64_t pos = cu_str_offsets_base_ + (static_cast<uint64_t>(index) * offset_size);
    if (pos + offset_size <= cu_str_offsets_end_) {
        uint64_t temp_off = pos;
        uint64_t str_offset = (offset_size == 8)
            ? DwarfUtils::readU64(debug_str_offsets_.data(), temp_off, debug_str_offsets_.size())
            : DwarfUtils::readU32(debug_str_offsets_.data(), temp_off, debug_str_offsets_.size());
        if (str_offset < debug_str_.size()) {
            return std::make_shared<StringAttributeValue>(getString(str_offset));
        }
    }
    return std::make_shared<StringAttributeValue>("<strx1:" + std::to_string(index) + ">");
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormStrx2(uint64_t& offset) const {
    uint16_t index = readU16(offset);
    uint8_t offset_size = is_dwarf64_ ? 8 : 4;
    uint64_t pos = cu_str_offsets_base_ + (static_cast<uint64_t>(index) * offset_size);
    if (pos + offset_size <= cu_str_offsets_end_) {
        uint64_t temp_off = pos;
        uint64_t str_offset = (offset_size == 8)
            ? DwarfUtils::readU64(debug_str_offsets_.data(), temp_off, debug_str_offsets_.size())
            : DwarfUtils::readU32(debug_str_offsets_.data(), temp_off, debug_str_offsets_.size());
        if (str_offset < debug_str_.size()) {
            return std::make_shared<StringAttributeValue>(getString(str_offset));
        }
    }
    return std::make_shared<StringAttributeValue>("<strx2:" + std::to_string(index) + ">");
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormStrx3(uint64_t& offset) const {
    // Read 3-byte index
    uint32_t index = readU8(offset) | (readU8(offset) << 8) | (readU8(offset) << 16);
    uint8_t offset_size = is_dwarf64_ ? 8 : 4;
    uint64_t pos = cu_str_offsets_base_ + (static_cast<uint64_t>(index) * offset_size);
    if (pos + offset_size <= cu_str_offsets_end_) {
        uint64_t temp_off = pos;
        uint64_t str_offset = (offset_size == 8)
            ? DwarfUtils::readU64(debug_str_offsets_.data(), temp_off, debug_str_offsets_.size())
            : DwarfUtils::readU32(debug_str_offsets_.data(), temp_off, debug_str_offsets_.size());
        if (str_offset < debug_str_.size()) {
            return std::make_shared<StringAttributeValue>(getString(str_offset));
        }
    }
    return std::make_shared<StringAttributeValue>("<strx3:" + std::to_string(index) + ">");
}

std::shared_ptr<AttributeValue> AttributeParser::parseFormStrx4(uint64_t& offset) const {
    uint32_t index = readU32(offset);
    uint8_t offset_size = is_dwarf64_ ? 8 : 4;
    uint64_t pos = cu_str_offsets_base_ + (static_cast<uint64_t>(index) * offset_size);
    if (pos + offset_size <= cu_str_offsets_end_) {
        uint64_t temp_off = pos;
        uint64_t str_offset = (offset_size == 8)
            ? DwarfUtils::readU64(debug_str_offsets_.data(), temp_off, debug_str_offsets_.size())
            : DwarfUtils::readU32(debug_str_offsets_.data(), temp_off, debug_str_offsets_.size());
        if (str_offset < debug_str_.size()) {
            return std::make_shared<StringAttributeValue>(getString(str_offset));
        }
    }
    return std::make_shared<StringAttributeValue>("<strx4:" + std::to_string(index) + ">");
}

// Complex attribute parsers
std::shared_ptr<AttributeValue> AttributeParser::parseLocationExpression(uint64_t& offset) const {
    uint64_t length = readULEB128(offset);
    std::vector<uint8_t> data = getBlock(offset, length);
    advanceOffsetBounded(offset, length);
    return std::make_shared<LocationAttributeValue>(LocationAttributeValue::LocationType::EXPRESSION, data);
}

std::shared_ptr<AttributeValue> AttributeParser::parseLocationList(uint64_t& offset) const {
    // Parse DWARF 4 location list entries
    std::vector<LocationAttributeValue::LocationEntry> entries;

    uint64_t base_address = cu_base_address_;
    uint64_t max_addr = (address_size_ == 8) ? UINT64_MAX : 0xffffffffULL;

    auto readLocU16 = [this](uint64_t& off) -> uint16_t {
        return DwarfUtils::readU16(debug_loc_.data(), off, debug_loc_.size());
    };
    auto readLocU32 = [this](uint64_t& off) -> uint32_t {
        return DwarfUtils::readU32(debug_loc_.data(), off, debug_loc_.size());
    };
    auto readLocU64 = [this](uint64_t& off) -> uint64_t {
        return DwarfUtils::readU64(debug_loc_.data(), off, debug_loc_.size());
    };
    auto readLocBlock = [this](uint64_t& off, uint64_t size) -> std::vector<uint8_t> {
        if (off + size > debug_loc_.size()) return {};
        std::vector<uint8_t> out(debug_loc_.begin() + off, debug_loc_.begin() + off + size);
        off += size;
        return out;
    };

    while (offset < debug_loc_.size()) {
        uint64_t start = (address_size_ == 8) ? readLocU64(offset) : readLocU32(offset);
        uint64_t end = (address_size_ == 8) ? readLocU64(offset) : readLocU32(offset);

        if (start == 0 && end == 0) {
            break; // End of list
        }

        // Handle base address selection (DWARF 4)
        if (start == max_addr) {
            // Base address selection entry: end becomes the new base address
            base_address = end;
            continue;
        }

        uint64_t expr_length = readLocU16(offset);
        std::vector<uint8_t> expr_data = readLocBlock(offset, expr_length);

        // Begin/end are offsets relative to the current base address.
        entries.emplace_back(
            base_address + start,
            base_address + end,
            expr_data,
            false  // is_default
        );
    }

    if (!entries.empty()) {
        return std::make_shared<LocationAttributeValue>(entries);
    }

    // Return empty location value if no entries
    std::vector<uint8_t> empty_data;
    return std::make_shared<LocationAttributeValue>(LocationAttributeValue::LocationType::LIST, empty_data);
}

std::shared_ptr<AttributeValue> AttributeParser::parseLocationListPointer(uint64_t& offset) const {
    uint64_t list_offset = is_dwarf64_ ? readU64(offset) : readU32(offset);

    // DWARF 5: location list pointer refers into .debug_loclists if present.
    if (dwarf_version_ >= DwarfVersion::DWARF5 && loclists_parser_ && !debug_loclists_.empty()) {
        if (list_offset < debug_loclists_.size()) {
            std::vector<LocListEntry> loc_entries = loclists_parser_->parseLocationList(
                list_offset, cu_base_address_, address_size_);

            std::vector<LocationAttributeValue::LocationEntry> entries;
            for (const auto& entry : loc_entries) {
                if (entry.type == DW_LLE::DW_LLE_end_of_list) continue;
                entries.emplace_back(entry.start, entry.end, entry.expression, entry.is_default);
            }

            if (!entries.empty()) {
                return std::make_shared<LocationAttributeValue>(entries);
            }
        }
    }

    // DWARF 2-4: location list pointer refers into .debug_loc.
    if (list_offset < debug_loc_.size()) {
        uint64_t temp_offset = list_offset;
        return parseLocationList(temp_offset);
    }

    std::vector<uint8_t> empty_data;
    return std::make_shared<LocationAttributeValue>(LocationAttributeValue::LocationType::LIST, empty_data);
}

std::shared_ptr<AttributeValue> AttributeParser::parseRangeList(uint64_t& offset) const {
    std::vector<RangeAttributeValue::RangeEntry> ranges;

    uint64_t base_address = cu_base_address_;
    uint64_t max_addr = (address_size_ == 8) ? UINT64_MAX : 0xffffffffULL;

    auto readRangesU32 = [this](uint64_t& off) -> uint32_t {
        return DwarfUtils::readU32(debug_ranges_.data(), off, debug_ranges_.size());
    };
    auto readRangesU64 = [this](uint64_t& off) -> uint64_t {
        return DwarfUtils::readU64(debug_ranges_.data(), off, debug_ranges_.size());
    };

    while (offset < debug_ranges_.size()) {
        uint64_t start = (address_size_ == 8) ? readRangesU64(offset) : readRangesU32(offset);
        uint64_t end = (address_size_ == 8) ? readRangesU64(offset) : readRangesU32(offset);

        if (start == 0 && end == 0) {
            break; // End of list
        }

        // Handle special range values
        bool is_end_of_list = (start == max_addr && end == max_addr);
        bool is_base_address = (start == max_addr);
        
        if (is_end_of_list) {
            break;
        } else if (is_base_address) {
            // This is a base address selection entry
            base_address = end;
            ranges.push_back({end, 0, true}); // Mark as base address
        } else {
            ranges.push_back({base_address + start, base_address + end, false});
        }
    }
    
    return std::make_shared<RangeAttributeValue>(ranges);
}

std::shared_ptr<AttributeValue> AttributeParser::parseRangeListPointer(uint64_t& offset) const {
    uint64_t list_offset = is_dwarf64_ ? readU64(offset) : readU32(offset);

    // DWARF 5: range list pointer refers into .debug_rnglists if present.
    if (dwarf_version_ >= DwarfVersion::DWARF5 && rnglists_parser_ && !debug_rnglists_.empty()) {
        if (list_offset < debug_rnglists_.size()) {
            std::vector<RngListEntry> rng_entries = rnglists_parser_->parseRangeList(
                list_offset, cu_base_address_, address_size_);

            std::vector<RangeAttributeValue::RangeEntry> ranges;
            for (const auto& entry : rng_entries) {
                if (entry.type == DW_RLE::DW_RLE_end_of_list) continue;
                ranges.push_back({entry.start, entry.end, entry.is_base_address});
            }
            return std::make_shared<RangeAttributeValue>(ranges);
        }
    }

    // DWARF 2-4: range list pointer refers into .debug_ranges.
    if (list_offset < debug_ranges_.size()) {
        uint64_t temp_offset = list_offset;
        return parseRangeList(temp_offset);
    }

    std::vector<RangeAttributeValue::RangeEntry> empty_ranges;
    return std::make_shared<RangeAttributeValue>(empty_ranges);
}

std::shared_ptr<AttributeValue> AttributeParser::parseLineNumberProgram(uint64_t& offset) const {
    std::vector<LineAttributeValue::LineEntry> lines;
    std::vector<std::string> directories;
    std::vector<LineAttributeValue::DirectoryEntry> directory_entries;
    std::vector<LineAttributeValue::FileEntry> files;

    if (debug_line_.empty() || offset >= debug_line_.size()) {
        return std::make_shared<LineAttributeValue>(lines, directories, files, directory_entries);
    }

    uint64_t unit_start = offset;
    uint32_t initial_length = DwarfUtils::readU32(debug_line_.data(), offset, debug_line_.size());
    bool is_dwarf64 = (initial_length == 0xFFFFFFFF);
    uint64_t unit_length = is_dwarf64
                               ? DwarfUtils::readU64(debug_line_.data(), offset, debug_line_.size())
                               : initial_length;
    uint64_t length_field_size = is_dwarf64 ? 12 : 4;
    uint64_t unit_end = unit_start + length_field_size + unit_length;
    if (unit_end > debug_line_.size() || unit_end < offset) {
        // Malformed unit length; bail with an empty line table.
        return std::make_shared<LineAttributeValue>(lines, directories, files, directory_entries);
    }

    // Bounded reads within this line-table unit.
    auto readU8 = [this, unit_end](uint64_t& off) -> uint8_t {
        return DwarfUtils::readU8(debug_line_.data(), off, unit_end);
    };
    auto readS8 = [this, unit_end](uint64_t& off) -> int8_t {
        return static_cast<int8_t>(DwarfUtils::readU8(debug_line_.data(), off, unit_end));
    };
    auto readU16 = [this, unit_end](uint64_t& off) -> uint16_t {
        return DwarfUtils::readU16(debug_line_.data(), off, unit_end);
    };
    auto readU32 = [this, unit_end](uint64_t& off) -> uint32_t {
        return DwarfUtils::readU32(debug_line_.data(), off, unit_end);
    };
    auto readU64 = [this, unit_end](uint64_t& off) -> uint64_t {
        return DwarfUtils::readU64(debug_line_.data(), off, unit_end);
    };
    auto readULEB128 = [this, unit_end](uint64_t& off) -> uint64_t {
        return DwarfUtils::readULEB128(debug_line_.data(), off, unit_end);
    };
    auto readSLEB128 = [this, unit_end](uint64_t& off) -> int64_t {
        return DwarfUtils::readSLEB128(debug_line_.data(), off, unit_end);
    };
    auto readOffset = [&](uint64_t& off) -> uint64_t {
        return is_dwarf64 ? readU64(off) : readU32(off);
    };

    auto readCString = [this](uint64_t& off, uint64_t end) -> std::string {
        if (off >= end) return "";
        uint64_t cur = off;
        while (cur < end && debug_line_[cur] != 0) {
            ++cur;
        }
        if (cur >= end) {
            off = end;
            return "";
        }
        std::string s(reinterpret_cast<const char*>(debug_line_.data() + off),
                      static_cast<size_t>(cur - off));
        off = cur + 1;
        return s;
    };

    auto readCStringFromSection = [](const std::vector<uint8_t>& sec, uint64_t sec_off) -> std::string {
        if (sec_off >= sec.size()) return "";
        const char* base = reinterpret_cast<const char*>(sec.data() + sec_off);
        size_t max_len = sec.size() - static_cast<size_t>(sec_off);
        size_t len = strnlen(base, max_len);
        return std::string(base, len);
    };

    auto skipForm = [&](DwarfForm form, uint64_t& off, uint64_t end, uint8_t addr_size_bytes) -> bool {
        switch (form) {
            case DwarfForm::DW_FORM_string:
                (void)readCString(off, end);
                return true;
            case DwarfForm::DW_FORM_line_strp:
            case DwarfForm::DW_FORM_strp:
            case DwarfForm::DW_FORM_sec_offset: {
                uint64_t tmp = off;
                (void)(is_dwarf64 ? DwarfUtils::readU64(debug_line_.data(), tmp, end)
                                  : DwarfUtils::readU32(debug_line_.data(), tmp, end));
                off = tmp;
                return true;
            }
            case DwarfForm::DW_FORM_udata:
                (void)DwarfUtils::readULEB128(debug_line_.data(), off, end);
                return true;
            case DwarfForm::DW_FORM_sdata:
                (void)DwarfUtils::readSLEB128(debug_line_.data(), off, end);
                return true;
            case DwarfForm::DW_FORM_data1:
            case DwarfForm::DW_FORM_flag:
            case DwarfForm::DW_FORM_ref1:
                if (off + 1 > end) return false;
                off += 1;
                return true;
            case DwarfForm::DW_FORM_data2:
            case DwarfForm::DW_FORM_ref2:
                if (off + 2 > end) return false;
                off += 2;
                return true;
            case DwarfForm::DW_FORM_data4:
            case DwarfForm::DW_FORM_ref4:
                if (off + 4 > end) return false;
                off += 4;
                return true;
            case DwarfForm::DW_FORM_data8:
            case DwarfForm::DW_FORM_ref8:
            case DwarfForm::DW_FORM_ref_sig8:
                if (off + 8 > end) return false;
                off += 8;
                return true;
            case DwarfForm::DW_FORM_data16:
                if (off + 16 > end) return false;
                off += 16;
                return true;
            case DwarfForm::DW_FORM_addr:
                if (off + addr_size_bytes > end) return false;
                off += addr_size_bytes;
                return true;
            case DwarfForm::DW_FORM_flag_present:
                return true;
            case DwarfForm::DW_FORM_block1: {
                if (off + 1 > end) return false;
                uint8_t n = debug_line_[off++];
                if (off + n > end) return false;
                off += n;
                return true;
            }
            case DwarfForm::DW_FORM_block2: {
                if (off + 2 > end) return false;
                uint64_t tmp = off;
                uint16_t n = DwarfUtils::readU16(debug_line_.data(), tmp, end);
                off = tmp;
                if (off + n > end) return false;
                off += n;
                return true;
            }
            case DwarfForm::DW_FORM_block4: {
                if (off + 4 > end) return false;
                uint64_t tmp = off;
                uint32_t n = DwarfUtils::readU32(debug_line_.data(), tmp, end);
                off = tmp;
                if (off + n > end) return false;
                off += n;
                return true;
            }
            case DwarfForm::DW_FORM_block: {
                uint64_t n = DwarfUtils::readULEB128(debug_line_.data(), off, end);
                if (off + n > end) return false;
                off += n;
                return true;
            }
            default:
                return false;
        }
    };

    // Parse header
    uint16_t version = readU16(offset);
    uint8_t address_size = (version >= 5) ? readU8(offset) : address_size_;
    uint8_t segment_selector_size = (version >= 5) ? readU8(offset) : 0;
    (void)segment_selector_size;

    uint64_t header_length = is_dwarf64 ? readU64(offset) : readU32(offset);
    uint64_t header_end = offset + header_length;
    if (header_end > unit_end) {
        return std::make_shared<LineAttributeValue>(lines, directories, files, directory_entries);
    }

    // Common header fields
    uint8_t min_instruction_length = readU8(offset);
    uint8_t max_operations_per_instruction = (version >= 4) ? readU8(offset) : 1;
    uint8_t default_is_stmt = readU8(offset);
    int8_t line_base = readS8(offset);
    uint8_t line_range = readU8(offset);
    uint8_t opcode_base = readU8(offset);

    std::vector<uint8_t> standard_opcode_lengths;
    for (int i = 1; i < opcode_base && offset < header_end; ++i) {
        standard_opcode_lengths.push_back(readU8(offset));
    }

    if (version < 5) {
        while (offset < header_end) {
            std::string dir = readCString(offset, header_end);
            if (dir.empty()) break;
            directories.push_back(std::move(dir));
        }
        while (offset < header_end) {
            std::string filename = readCString(offset, header_end);
            if (filename.empty()) break;
            uint64_t dir_index = readULEB128(offset);
            uint64_t mtime = readULEB128(offset);
            uint64_t size = readULEB128(offset);
            files.push_back({std::move(filename), dir_index, mtime, size, {}, {}});
        }
    } else {
        // DWARF 5 directory table
        constexpr uint64_t DW_LNCT_path = 1;
        constexpr uint64_t DW_LNCT_directory_index = 2;
        constexpr uint64_t DW_LNCT_timestamp = 3;
        constexpr uint64_t DW_LNCT_size = 4;
        constexpr uint64_t DW_LNCT_MD5 = 5;
        auto parseLineField = [&](DwarfForm form) -> std::shared_ptr<AttributeValue> {
            switch (form) {
                case DwarfForm::DW_FORM_string:
                    return std::make_shared<StringAttributeValue>(readCString(offset, header_end));
                case DwarfForm::DW_FORM_line_strp: {
                    uint64_t str_off = readOffset(offset);
                    return std::make_shared<StringAttributeValue>(readCStringFromSection(debug_line_str_, str_off));
                }
                case DwarfForm::DW_FORM_strp: {
                    uint64_t str_off = readOffset(offset);
                    return std::make_shared<StringAttributeValue>(readCStringFromSection(debug_str_, str_off));
                }
                case DwarfForm::DW_FORM_udata:
                    return std::make_shared<UnsignedAttributeValue>(readULEB128(offset));
                case DwarfForm::DW_FORM_sdata:
                    return std::make_shared<SignedAttributeValue>(readSLEB128(offset));
                case DwarfForm::DW_FORM_data1:
                    return std::make_shared<UnsignedAttributeValue>(readU8(offset));
                case DwarfForm::DW_FORM_data2:
                    return std::make_shared<UnsignedAttributeValue>(readU16(offset));
                case DwarfForm::DW_FORM_data4:
                    return std::make_shared<UnsignedAttributeValue>(readU32(offset));
                case DwarfForm::DW_FORM_data8:
                    return std::make_shared<UnsignedAttributeValue>(readU64(offset));
                case DwarfForm::DW_FORM_sec_offset:
                    return std::make_shared<UnsignedAttributeValue>(readOffset(offset));
                case DwarfForm::DW_FORM_flag:
                    return std::make_shared<FlagAttributeValue>(readU8(offset) != 0);
                case DwarfForm::DW_FORM_flag_present:
                    return std::make_shared<FlagAttributeValue>(true);
                case DwarfForm::DW_FORM_data16: {
                    if (offset + 16 > header_end) {
                        offset = header_end;
                        return nullptr;
                    }
                    std::vector<uint8_t> data(debug_line_.begin() + static_cast<std::ptrdiff_t>(offset),
                                              debug_line_.begin() + static_cast<std::ptrdiff_t>(offset + 16));
                    offset += 16;
                    return std::make_shared<BlockAttributeValue>(data);
                }
                case DwarfForm::DW_FORM_block1:
                case DwarfForm::DW_FORM_block2:
                case DwarfForm::DW_FORM_block4:
                case DwarfForm::DW_FORM_block: {
                    uint64_t tmp = offset;
                    if (!skipForm(form, tmp, header_end, address_size)) {
                        offset = header_end;
                        return nullptr;
                    }
                    uint64_t payload_off = offset;
                    std::vector<uint8_t> data;
                    if (form == DwarfForm::DW_FORM_block1) {
                        uint64_t size = readU8(offset);
                        payload_off = offset;
                        data.assign(debug_line_.begin() + static_cast<std::ptrdiff_t>(payload_off),
                                    debug_line_.begin() + static_cast<std::ptrdiff_t>(payload_off + size));
                        offset += size;
                    } else if (form == DwarfForm::DW_FORM_block2) {
                        uint64_t size = readU16(offset);
                        payload_off = offset;
                        data.assign(debug_line_.begin() + static_cast<std::ptrdiff_t>(payload_off),
                                    debug_line_.begin() + static_cast<std::ptrdiff_t>(payload_off + size));
                        offset += size;
                    } else if (form == DwarfForm::DW_FORM_block4) {
                        uint64_t size = readU32(offset);
                        payload_off = offset;
                        data.assign(debug_line_.begin() + static_cast<std::ptrdiff_t>(payload_off),
                                    debug_line_.begin() + static_cast<std::ptrdiff_t>(payload_off + size));
                        offset += size;
                    } else {
                        uint64_t size = readULEB128(offset);
                        payload_off = offset;
                        data.assign(debug_line_.begin() + static_cast<std::ptrdiff_t>(payload_off),
                                    debug_line_.begin() + static_cast<std::ptrdiff_t>(payload_off + size));
                        offset += size;
                    }
                    return std::make_shared<BlockAttributeValue>(data);
                }
                case DwarfForm::DW_FORM_addr: {
                    uint64_t value = (address_size == 8) ? readU64(offset) : readU32(offset);
                    return std::make_shared<AddressAttributeValue>(value);
                }
                default:
                    if (!skipForm(form, offset, header_end, address_size)) {
                        offset = header_end;
                    }
                    return nullptr;
            }
        };

        uint8_t directory_entry_format_count = readU8(offset);
        std::vector<std::pair<uint64_t, DwarfForm>> dir_format;
        dir_format.reserve(directory_entry_format_count);
        for (uint8_t i = 0; i < directory_entry_format_count; ++i) {
            uint64_t content_type = readULEB128(offset);
            auto form = static_cast<DwarfForm>(readULEB128(offset));
            dir_format.push_back({content_type, form});
        }

        uint64_t directories_count = readULEB128(offset);
        for (uint64_t i = 0; i < directories_count; ++i) {
            LineAttributeValue::DirectoryEntry dir_entry;
            for (const auto& [content_type, form] : dir_format) {
                auto value = parseLineField(form);
                if (!value && offset >= header_end) {
                    offset = header_end;
                    break;
                }
                if (!value) continue;
                if (content_type == DW_LNCT_path) {
                    if (auto path = std::dynamic_pointer_cast<StringAttributeValue>(value)) {
                        dir_entry.path = path->getValue();
                        continue;
                    }
                }
                dir_entry.preserved_fields.push_back({content_type, value});
            }
            directories.push_back(dir_entry.path);
            directory_entries.push_back(std::move(dir_entry));
        }

        // DWARF 5 file table
        uint8_t file_entry_format_count = readU8(offset);
        std::vector<std::pair<uint64_t, DwarfForm>> file_format;
        file_format.reserve(file_entry_format_count);
        for (uint8_t i = 0; i < file_entry_format_count; ++i) {
            uint64_t content_type = readULEB128(offset);
            auto form = static_cast<DwarfForm>(readULEB128(offset));
            file_format.push_back({content_type, form});
        }

        uint64_t files_count = readULEB128(offset);
        for (uint64_t i = 0; i < files_count; ++i) {
            LineAttributeValue::FileEntry entry{"", 0, 0, 0, {}, {}};
            for (const auto& [content_type, form] : file_format) {
                auto value = parseLineField(form);
                if (!value && offset >= header_end) {
                    offset = header_end;
                    break;
                }
                if (!value) continue;
                if (content_type == DW_LNCT_path) {
                    if (auto path = std::dynamic_pointer_cast<StringAttributeValue>(value)) {
                        entry.filename = path->getValue();
                        continue;
                    }
                } else if (content_type == DW_LNCT_directory_index) {
                    if (auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(value)) {
                        entry.dir_index = u->getValue();
                        continue;
                    }
                } else if (content_type == DW_LNCT_timestamp) {
                    if (auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(value)) {
                        entry.mtime = u->getValue();
                        continue;
                    }
                } else if (content_type == DW_LNCT_size) {
                    if (auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(value)) {
                        entry.size = u->getValue();
                        continue;
                    }
                } else if (content_type == DW_LNCT_MD5) {
                    if (auto b = std::dynamic_pointer_cast<BlockAttributeValue>(value)) {
                        entry.md5 = b->getData();
                        continue;
                    }
                }
                entry.preserved_fields.push_back({content_type, value});
            }
            files.push_back(std::move(entry));
        }
    }

    // Ensure we're at the instruction start
    offset = header_end;

    // Initialize state machine
    LineState state;
    state.reset(default_is_stmt != 0);

    // Helper lambda to append a row to the line table
    auto appendRow = [&]() {
        lines.push_back({
            state.address,
            state.file,
            state.line,
            state.column,
            state.is_stmt,
            state.basic_block,
            state.end_sequence,
            state.prologue_end,
            state.epilogue_begin,
            state.isa,
            state.discriminator
        });
        // Reset after appending
        state.basic_block = false;
        state.prologue_end = false;
        state.epilogue_begin = false;
        state.discriminator = 0;
    };

    // Process opcodes
    while (offset < unit_end) {
        uint8_t opcode = readU8(offset);

        if (opcode == 0) {
            // Extended opcode
            uint64_t ext_length = readULEB128(offset);
            uint64_t ext_end = offset + ext_length;
            if (ext_end > unit_end || offset >= unit_end) {
                break;
            }
            uint8_t extended_opcode = readU8(offset);

            switch (static_cast<DwarfLineExtOp>(extended_opcode)) {
                case DwarfLineExtOp::DW_LNE_end_sequence:
                    state.end_sequence = true;
                    appendRow();
                    state.reset(default_is_stmt != 0);
                    break;

                case DwarfLineExtOp::DW_LNE_set_address:
                    if (address_size == 8) {
                        state.address = readU64(offset);
                    } else {
                        state.address = readU32(offset);
                    }
                    state.op_index = 0;
                    break;

                case DwarfLineExtOp::DW_LNE_define_file: {
                    std::string filename = readCString(offset, ext_end);
                    uint64_t dir_index = DwarfUtils::readULEB128(debug_line_.data(), offset, ext_end);
                    uint64_t mtime = DwarfUtils::readULEB128(debug_line_.data(), offset, ext_end);
                    uint64_t size = DwarfUtils::readULEB128(debug_line_.data(), offset, ext_end);
                    files.push_back({filename, dir_index, mtime, size, {}, {}});
                    break;
                }

                case DwarfLineExtOp::DW_LNE_set_discriminator:
                    state.discriminator = static_cast<uint32_t>(DwarfUtils::readULEB128(debug_line_.data(), offset, ext_end));
                    break;

                default:
                    // Unknown extended opcode - skip to end
                    offset = ext_end;
                    break;
            }

            // Ensure we're at the end of the extended opcode
            if (offset < ext_end) {
                offset = ext_end;
            }
        } else if (opcode < opcode_base) {
            // Standard opcode
            switch (static_cast<DwarfLineOp>(opcode)) {
                case DwarfLineOp::DW_LNS_copy:
                    appendRow();
                    break;

                case DwarfLineOp::DW_LNS_advance_pc: {
                    uint64_t operation_advance = readULEB128(offset);
                    if (max_operations_per_instruction == 1) {
                        state.address += operation_advance * min_instruction_length;
                    } else {
                        uint32_t new_op_index = state.op_index + static_cast<uint32_t>(operation_advance);
                        state.address += (new_op_index / max_operations_per_instruction) * min_instruction_length;
                        state.op_index = new_op_index % max_operations_per_instruction;
                    }
                    break;
                }

                case DwarfLineOp::DW_LNS_advance_line:
                    state.line = static_cast<uint32_t>(static_cast<int32_t>(state.line) + readSLEB128(offset));
                    break;

                case DwarfLineOp::DW_LNS_set_file:
                    state.file = static_cast<uint32_t>(readULEB128(offset));
                    break;

                case DwarfLineOp::DW_LNS_set_column:
                    state.column = static_cast<uint32_t>(readULEB128(offset));
                    break;

                case DwarfLineOp::DW_LNS_negate_stmt:
                    state.is_stmt = !state.is_stmt;
                    break;

                case DwarfLineOp::DW_LNS_set_basic_block:
                    state.basic_block = true;
                    break;

                case DwarfLineOp::DW_LNS_const_add_pc: {
                    // Same as special opcode 255 but without line change
                    uint8_t adjusted_opcode = 255 - opcode_base;
                    if (max_operations_per_instruction == 1) {
                        state.address += (adjusted_opcode / line_range) * min_instruction_length;
                    } else {
                        uint32_t operation_advance = adjusted_opcode / line_range;
                        uint32_t new_op_index = state.op_index + operation_advance;
                        state.address += (new_op_index / max_operations_per_instruction) * min_instruction_length;
                        state.op_index = new_op_index % max_operations_per_instruction;
                    }
                    break;
                }

                case DwarfLineOp::DW_LNS_fixed_advance_pc:
                    state.address += readU16(offset);
                    state.op_index = 0;
                    break;

                case DwarfLineOp::DW_LNS_set_prologue_end:
                    state.prologue_end = true;
                    break;

                case DwarfLineOp::DW_LNS_set_epilogue_begin:
                    state.epilogue_begin = true;
                    break;

                case DwarfLineOp::DW_LNS_set_isa:
                    state.isa = static_cast<uint32_t>(readULEB128(offset));
                    break;

                default:
                    // Unknown standard opcode - skip using standard_opcode_lengths
                    if (opcode - 1 < static_cast<int>(standard_opcode_lengths.size())) {
                        for (int i = 0; i < standard_opcode_lengths[opcode - 1]; ++i) {
                            (void)readULEB128(offset);
                        }
                    }
                    break;
            }
        } else {
            // Special opcode (opcode >= opcode_base)
            uint8_t adjusted_opcode = opcode - opcode_base;

            // Calculate address and line increments
            if (max_operations_per_instruction == 1) {
                state.address += (adjusted_opcode / line_range) * min_instruction_length;
            } else {
                uint32_t operation_advance = adjusted_opcode / line_range;
                uint32_t new_op_index = state.op_index + operation_advance;
                state.address += (new_op_index / max_operations_per_instruction) * min_instruction_length;
                state.op_index = new_op_index % max_operations_per_instruction;
            }

            state.line = static_cast<uint32_t>(static_cast<int32_t>(state.line) +
                         line_base + (adjusted_opcode % line_range));

            // Append row and reset flags
            appendRow();
        }
    }

    return std::make_shared<LineAttributeValue>(lines, directories, files, directory_entries);
}

std::shared_ptr<AttributeValue> AttributeParser::parseLineNumberProgramPointer(uint64_t& offset) const {
    // DW_FORM_sec_offset uses the CU's DWARF format (DWARF32/DWARF64).
    uint64_t program_offset = is_dwarf64_ ? readU64(offset) : readU32(offset);

    // Parse the line number program at the given offset
    if (program_offset < debug_line_.size()) {
        uint64_t temp_offset = program_offset;
        return parseLineNumberProgram(temp_offset);
    }

    std::vector<LineAttributeValue::LineEntry> empty_lines;
    std::vector<std::string> empty_dirs;
    std::vector<LineAttributeValue::FileEntry> empty_files;
    std::vector<LineAttributeValue::DirectoryEntry> empty_dir_entries;
    return std::make_shared<LineAttributeValue>(empty_lines, empty_dirs, empty_files, empty_dir_entries);
}

std::shared_ptr<AttributeValue> AttributeParser::parseTypeReference(uint64_t& offset) const {
    uint64_t type_offset = readU32(offset);
    // CU-relative offset - add CU base to get absolute offset
    return std::make_shared<TypeAttributeValue>(cu_debug_info_offset_ + type_offset);
}

std::shared_ptr<AttributeValue> AttributeParser::parseTypeSignature(uint64_t& offset) const {
    uint64_t signature = readU64(offset);
    return std::make_shared<TypeAttributeValue>(signature, "<signature>", true);
}

std::shared_ptr<AttributeValue> AttributeParser::parseConstantValue(DwarfAttribute attr, DwarfForm form, uint64_t& offset) const {
    (void)attr;
    switch (form) {
        case DwarfForm::DW_FORM_data1:
        case DwarfForm::DW_FORM_data2:
        case DwarfForm::DW_FORM_data4:
        case DwarfForm::DW_FORM_data8:
        case DwarfForm::DW_FORM_udata:
            return parseDataAttribute(form, offset);
        case DwarfForm::DW_FORM_sdata:
            return parseDataAttribute(form, offset);
        case DwarfForm::DW_FORM_flag:
        case DwarfForm::DW_FORM_flag_present:
            return parseFlagAttribute(form, offset);
        case DwarfForm::DW_FORM_string:
        case DwarfForm::DW_FORM_strp:
        case DwarfForm::DW_FORM_strp_sup:
        case DwarfForm::DW_FORM_GNU_strp_alt:
        case DwarfForm::DW_FORM_strx:
        case DwarfForm::DW_FORM_GNU_str_index:
        case DwarfForm::DW_FORM_strx1:
        case DwarfForm::DW_FORM_strx2:
        case DwarfForm::DW_FORM_strx3:
        case DwarfForm::DW_FORM_strx4:
        case DwarfForm::DW_FORM_line_strp:
            return parseStringAttribute(form, offset);
        case DwarfForm::DW_FORM_block:
        case DwarfForm::DW_FORM_block1:
        case DwarfForm::DW_FORM_block2:
        case DwarfForm::DW_FORM_block4:
            return parseBlockAttribute(form, offset);
        case DwarfForm::DW_FORM_exprloc:
            return parseExpressionAttribute(form, offset);
        case DwarfForm::DW_FORM_implicit_const:
            return parseFormImplicitConst(offset);
        default:
            return nullptr;
    }
}

std::shared_ptr<AttributeValue> AttributeParser::parseConstantExpression(DwarfAttribute attr, DwarfForm form, uint64_t& offset) const {
    (void)attr;
    return parseExpressionAttribute(form, offset);
}

// Helper methods
bool AttributeParser::isLittleEndian() const {
    return DwarfUtils::objectIsLittleEndian();
}

uint64_t AttributeParser::getAddressSize() const {
    return address_size_;
}

uint64_t AttributeParser::getOffsetSize() const {
    return is_dwarf64_ ? 8 : 4;
}

std::string AttributeParser::formatAddress(uint64_t address) const {
    return DwarfUtils::formatAddress(address, true);
}

std::string AttributeParser::formatOffset(uint64_t offset) const {
    return DwarfUtils::formatOffset(offset, true);
}

// Specialized attribute value implementations
LocationAttributeValue::LocationAttributeValue(LocationType type, const std::vector<uint8_t>& data)
    : type_(type), data_(data) {
}

LocationAttributeValue::LocationAttributeValue(const std::vector<LocationEntry>& entries)
    : type_(LocationType::LIST), entries_(entries) {
    // Set data_ to first non-default entry's expression for backward compatibility
    for (const auto& entry : entries) {
        if (!entry.expression.empty() && !entry.is_default) {
            data_ = entry.expression;
            break;
        }
    }
}

std::string LocationAttributeValue::toString() const {
    std::stringstream ss;
    ss << "Location(";
    switch (type_) {
        case LocationType::EXPRESSION:
            ss << "expression, " << data_.size() << " bytes)";
            break;
        case LocationType::LIST:
            ss << "list, " << entries_.size() << " entries)";
            break;
        case LocationType::INVALID:
            ss << "invalid)";
            break;
    }
    return ss.str();
}

std::vector<uint8_t> LocationAttributeValue::getExpressionForPC(uint64_t pc) const {
    if (type_ == LocationType::EXPRESSION) {
        // Single expression applies to all PCs
        return data_;
    }

    // Search for a matching range in the location list
    for (const auto& entry : entries_) {
        if (entry.is_default) {
            // Default location is used when no other entry matches
            continue;
        }
        if (pc >= entry.start && pc < entry.end) {
            return entry.expression;
        }
    }

    // Check for default location as fallback
    for (const auto& entry : entries_) {
        if (entry.is_default) {
            return entry.expression;
        }
    }

    return {};  // No matching entry found
}

bool LocationAttributeValue::containsPC(uint64_t pc) const {
    if (type_ == LocationType::EXPRESSION) {
        // Single expression applies to all PCs
        return true;
    }

    for (const auto& entry : entries_) {
        if (entry.is_default) {
            return true;  // Default means it covers everything
        }
        if (pc >= entry.start && pc < entry.end) {
            return true;
        }
    }

    return false;
}

RangeAttributeValue::RangeAttributeValue(const std::vector<RangeEntry>& ranges)
    : ranges_(ranges) {
}

std::string RangeAttributeValue::toString() const {
    std::stringstream ss;
    ss << "RangeList(" << ranges_.size() << " entries)";
    return ss.str();
}

LineAttributeValue::LineAttributeValue(const std::vector<LineEntry>& lines,
                                       const std::vector<std::string>& directories,
                                       const std::vector<FileEntry>& files,
                                       const std::vector<DirectoryEntry>& directory_entries)
    : lines_(lines), directories_(directories), directory_entries_(directory_entries), files_(files) {
}

std::string LineAttributeValue::toString() const {
    std::stringstream ss;
    ss << "LineList(" << lines_.size() << " entries)";
    return ss.str();
}

TypeAttributeValue::TypeAttributeValue(uint64_t offset,
                                       const std::string& name,
                                       bool is_signature_reference)
    : offset_(offset), name_(name), is_signature_reference_(is_signature_reference) {
}

std::string TypeAttributeValue::toString() const {
    std::stringstream ss;
    ss << "Type(";
    if (!name_.empty()) {
        ss << name_ << ", ";
    }
    ss << (is_signature_reference_ ? "signature: 0x" : "offset: 0x")
       << std::hex << offset_ << std::dec << ")";
    return ss.str();
}

// BlockAttributeValue toString implementation
std::string BlockAttributeValue::toString() const {
    std::ostringstream oss;
    oss << "block[" << data_.size() << "]: ";
    for (size_t i = 0; i < std::min(data_.size(), size_t(16)); ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)data_[i] << " ";
    }
    if (data_.size() > 16) {
        oss << "...";
    }
    return oss.str();
}

// ExpressionAttributeValue toString implementation
std::string ExpressionAttributeValue::toString() const {
    std::ostringstream oss;
    oss << "expr[" << expression_.size() << "]: ";
    for (size_t i = 0; i < std::min(expression_.size(), size_t(16)); ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)expression_[i] << " ";
    }
    if (expression_.size() > 16) {
        oss << "...";
    }
    return oss.str();
}

} // namespace dwarf
