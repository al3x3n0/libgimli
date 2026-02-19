#include "debug_names_parser.hpp"
#include "dwarf_utils.hpp"
#include <stdexcept>
#include <cstring>

namespace dwarf {

DebugNamesParser::DebugNamesParser(const std::vector<uint8_t>& debug_names,
                                   const std::vector<uint8_t>& debug_str)
    : debug_names_(debug_names)
    , debug_str_(debug_str)
{
}

bool DebugNamesParser::parse() {
    units_.clear();
    header_ = DebugNamesHeader{};
    cu_offsets_.clear();
    name_cache_.clear();
    cache_populated_ = false;
    parsed_ = false;

    if (debug_names_.empty()) return false;

    uint64_t offset = 0;
    while (offset + 4 <= debug_names_.size()) {
        clearDecodeError();
        // Some producers may pad the section with zeros.
        uint64_t tmp = offset;
        uint32_t initial_length = readU32(tmp, debug_names_.size());
        if (hasDecodeError()) return false;
        if (initial_length == 0) break;

        if (!parseOneUnit(offset)) return false;
    }

    if (units_.empty()) return false;

    // Back-compat: expose first unit via getHeader/getCUOffsets.
    header_ = units_[0].header;
    cu_offsets_ = units_[0].cu_offsets;
    parsed_ = true;
    return true;
}

bool DebugNamesParser::parseOneUnit(uint64_t& offset) {
    Unit unit;
    uint64_t unit_start = offset;

    if (!parseHeader(unit, offset)) return false;
    unit.unit_start = unit_start;

    // Parse CU list
    if (!parseCUList(unit, offset)) return false;

    // Parse TU list (local type units)
    if (!parseTUList(unit, offset)) return false;

    // Skip foreign TU list signatures
    if (!parseForeignTUSignatures(unit, offset)) return false;

    // Parse buckets, hashes, name offsets, entry offsets
    if (!parseBuckets(unit, offset)) return false;
    if (!parseHashes(unit, offset)) return false;
    if (!parseNameOffsets(unit, offset)) return false;
    if (!parseEntryOffsets(unit, offset)) return false;

    // Abbrev table
    if (!parseAbbrevTable(unit, offset)) return false;

    // Entry pool starts immediately after the abbrev table.
    unit.entry_pool_base = offset;
    if (unit.entry_pool_base > unit.unit_end) return false;

    units_.push_back(std::move(unit));

    // Skip to the end of this unit (entry pool consumes the remainder).
    offset = units_.back().unit_end;
    return true;
}

bool DebugNamesParser::parseHeader(Unit& unit, uint64_t& offset) {
    if (offset + 4 > debug_names_.size()) return false;

    uint64_t start_offset = offset;
    uint64_t section_end = debug_names_.size();
    clearDecodeError();

    // Read unit_length
    uint32_t initial_length = readU32(offset, section_end);
    if (hasDecodeError()) return false;
    if (initial_length == 0xffffffff) {
        unit.header.is_dwarf64 = true;
        unit.header.unit_length = readU64(offset, section_end);
        if (hasDecodeError()) return false;
    } else {
        unit.header.is_dwarf64 = false;
        unit.header.unit_length = initial_length;
    }

    uint64_t length_field_size = unit.header.is_dwarf64 ? 12 : 4;
    if (unit.header.unit_length > (debug_names_.size() - start_offset - length_field_size)) {
        return false;
    }
    uint64_t unit_end = start_offset + length_field_size + unit.header.unit_length;
    if (unit_end > debug_names_.size()) return false;

    unit.unit_start = start_offset;
    unit.unit_end = unit_end;

    // Read version (should be 5)
    unit.header.version = readU16(offset, unit_end);
    if (hasDecodeError()) return false;
    if (unit.header.version != 5) {
        return false;
    }

    // Read padding
    unit.header.padding = readU16(offset, unit_end);
    if (hasDecodeError()) return false;

    // Read counts
    unit.header.comp_unit_count = readU32(offset, unit_end);
    unit.header.local_type_unit_count = readU32(offset, unit_end);
    unit.header.foreign_type_unit_count = readU32(offset, unit_end);
    unit.header.bucket_count = readU32(offset, unit_end);
    unit.header.name_count = readU32(offset, unit_end);
    unit.header.abbrev_table_size = readU32(offset, unit_end);
    unit.header.augmentation_string_size = readU32(offset, unit_end);
    if (hasDecodeError()) return false;

    // Read augmentation string
    if (unit.header.augmentation_string_size > 0) {
        if (unit.header.augmentation_string_size > (unit_end - offset)) {
            return false;
        }
        unit.header.augmentation_string = std::string(
            reinterpret_cast<const char*>(debug_names_.data() + offset),
            unit.header.augmentation_string_size);
        offset += unit.header.augmentation_string_size;
    }

    unit.header.header_size = offset - start_offset;
    return true;
}

bool DebugNamesParser::parseCUList(Unit& unit, uint64_t& offset) {
    unit.cu_offsets.clear();
    unit.cu_offsets.reserve(unit.header.comp_unit_count);

    for (uint32_t i = 0; i < unit.header.comp_unit_count; ++i) {
        unit.cu_offsets.push_back(readOffset(offset, unit.unit_end, unit.header.is_dwarf64));
        if (hasDecodeError() || offset > unit.unit_end) return false;
    }

    return true;
}

bool DebugNamesParser::parseTUList(Unit& unit, uint64_t& offset) {
    unit.tu_offsets.clear();
    unit.tu_offsets.reserve(unit.header.local_type_unit_count);

    for (uint32_t i = 0; i < unit.header.local_type_unit_count; ++i) {
        unit.tu_offsets.push_back(readOffset(offset, unit.unit_end, unit.header.is_dwarf64));
        if (hasDecodeError() || offset > unit.unit_end) return false;
    }

    return true;
}

bool DebugNamesParser::parseForeignTUSignatures(Unit& unit, uint64_t& offset) {
    // Signatures are always 8 bytes each (type signature).
    uint64_t need = static_cast<uint64_t>(unit.header.foreign_type_unit_count) * 8;
    if (need > (unit.unit_end - offset)) return false;
    offset += need;
    return true;
}

bool DebugNamesParser::parseBuckets(Unit& unit, uint64_t& offset) {
    unit.buckets.clear();
    unit.buckets.reserve(unit.header.bucket_count);

    for (uint32_t i = 0; i < unit.header.bucket_count; ++i) {
        unit.buckets.push_back(readU32(offset, unit.unit_end));
        if (hasDecodeError() || offset > unit.unit_end) return false;
    }

    return true;
}

bool DebugNamesParser::parseHashes(Unit& unit, uint64_t& offset) {
    unit.hashes.clear();
    unit.hashes.reserve(unit.header.name_count);

    for (uint32_t i = 0; i < unit.header.name_count; ++i) {
        unit.hashes.push_back(readU32(offset, unit.unit_end));
        if (hasDecodeError() || offset > unit.unit_end) return false;
    }

    return true;
}

bool DebugNamesParser::parseNameOffsets(Unit& unit, uint64_t& offset) {
    unit.name_offsets.clear();
    unit.name_offsets.reserve(unit.header.name_count);

    for (uint32_t i = 0; i < unit.header.name_count; ++i) {
        unit.name_offsets.push_back(readOffset(offset, unit.unit_end, unit.header.is_dwarf64));
        if (hasDecodeError() || offset > unit.unit_end) return false;
    }

    return true;
}

bool DebugNamesParser::parseEntryOffsets(Unit& unit, uint64_t& offset) {
    unit.entry_offsets.clear();
    unit.entry_offsets.reserve(unit.header.name_count);

    for (uint32_t i = 0; i < unit.header.name_count; ++i) {
        unit.entry_offsets.push_back(readOffset(offset, unit.unit_end, unit.header.is_dwarf64));
        if (hasDecodeError() || offset > unit.unit_end) return false;
    }

    return true;
}

bool DebugNamesParser::parseAbbrevTable(Unit& unit, uint64_t& offset) {
    unit.abbrevs.clear();

    if (unit.header.abbrev_table_size > (unit.unit_end - offset)) return false;
    uint64_t table_end = offset + unit.header.abbrev_table_size;

    while (offset < table_end) {
        uint64_t before = offset;
        uint64_t code = readULEB128(offset, table_end);
        if (hasDecodeError()) return false;
        if (code == 0) break; // end-of-table marker

        NameIndexAbbrev abbrev;
        abbrev.code = code;
        abbrev.tag = static_cast<DwarfTag>(readULEB128(offset, table_end));
        if (hasDecodeError()) return false;

        while (true) {
            uint64_t attr_before = offset;
            uint64_t idx = readULEB128(offset, table_end);
            uint64_t form = readULEB128(offset, table_end);
            if (hasDecodeError()) return false;
            if (idx == 0 && form == 0) break;

            abbrev.attributes.push_back({static_cast<DW_IDX>(idx), static_cast<DwarfForm>(form)});
            if (offset <= attr_before) return false;
        }

        unit.abbrevs[code] = std::move(abbrev);
        if (offset <= before) return false;
    }

    // The abbrev table occupies exactly abbrev_table_size bytes, even if we hit a terminator early.
    offset = table_end;
    return true;
}

void DebugNamesParser::populateCache() const {
    if (cache_populated_) {
        return;
    }

    if (!parsed_ || units_.empty()) {
        cache_populated_ = true;
        return;
    }
    clearDecodeError();

    auto readSLEB128 = [&](uint64_t& off, uint64_t end) -> int64_t {
        if (end > debug_names_.size() || off >= end) {
            decode_error_ = true;
            return 0;
        }
        uint64_t result = 0;
        unsigned shift = 0;
        uint8_t byte = 0;
        while (off < end) {
            byte = debug_names_[off++];
            uint64_t bits = static_cast<uint64_t>(byte & 0x7f);
            if (shift >= 64 && bits != 0) {
                decode_error_ = true;
                return 0;
            }
            result |= (bits << shift);
            shift += 7;
            if ((byte & 0x80) == 0) {
                if (shift < 64 && (byte & 0x40)) result |= (~0ULL << shift);
                return static_cast<int64_t>(result);
            }
            if (shift >= 64) {
                decode_error_ = true;
                return 0;
            }
        }
        decode_error_ = true;
        return 0;
    };

    auto skipCString = [&](uint64_t& off, uint64_t end) -> void {
        while (off < end) {
            if (debug_names_[off++] == 0) break;
        }
    };

    auto skipForm = [&](auto&& self, DwarfForm form, uint64_t& off, uint64_t end, bool is_dwarf64) -> bool {
        auto need = [&](uint64_t n) -> bool {
            if (off + n > end) return false;
            off += n;
            return true;
        };

        switch (form) {
            case DwarfForm::DW_FORM_flag_present:
            case DwarfForm::DW_FORM_implicit_const:
                return true;
            case DwarfForm::DW_FORM_data1:
            case DwarfForm::DW_FORM_flag:
            case DwarfForm::DW_FORM_ref1:
            case DwarfForm::DW_FORM_strx1:
            case DwarfForm::DW_FORM_addrx1:
                return need(1);
            case DwarfForm::DW_FORM_data2:
            case DwarfForm::DW_FORM_ref2:
            case DwarfForm::DW_FORM_strx2:
            case DwarfForm::DW_FORM_addrx2:
                return need(2);
            case DwarfForm::DW_FORM_data4:
            case DwarfForm::DW_FORM_ref4:
            case DwarfForm::DW_FORM_strx4:
            case DwarfForm::DW_FORM_addrx4:
                return need(4);
            case DwarfForm::DW_FORM_data8:
            case DwarfForm::DW_FORM_ref8:
            case DwarfForm::DW_FORM_ref_sig8:
                return need(8);
            case DwarfForm::DW_FORM_data16:
                return need(16);
            case DwarfForm::DW_FORM_udata:
            case DwarfForm::DW_FORM_ref_udata:
            case DwarfForm::DW_FORM_strx:
            case DwarfForm::DW_FORM_addrx:
            case DwarfForm::DW_FORM_loclistx:
            case DwarfForm::DW_FORM_rnglistx:
                (void)readULEB128(off, end);
                return !hasDecodeError() && off <= end;
            case DwarfForm::DW_FORM_sdata:
                (void)readSLEB128(off, end);
                return !hasDecodeError() && off <= end;
            case DwarfForm::DW_FORM_string:
                skipCString(off, end);
                return true;
            case DwarfForm::DW_FORM_sec_offset:
            case DwarfForm::DW_FORM_strp:
            case DwarfForm::DW_FORM_line_strp:
            case DwarfForm::DW_FORM_strp_sup:
            case DwarfForm::DW_FORM_ref_sup4:
            case DwarfForm::DW_FORM_ref_sup8:
            case DwarfForm::DW_FORM_ref_addr:
                return need(is_dwarf64 ? 8 : 4);
            case DwarfForm::DW_FORM_exprloc:
            case DwarfForm::DW_FORM_block: {
                uint64_t n = readULEB128(off, end);
                return need(n);
            }
            case DwarfForm::DW_FORM_block1: {
                uint64_t n = readU8(off, end);
                return need(n);
            }
            case DwarfForm::DW_FORM_block2: {
                uint64_t n = readU16(off, end);
                return need(n);
            }
            case DwarfForm::DW_FORM_block4: {
                uint64_t n = readU32(off, end);
                return need(n);
            }
            case DwarfForm::DW_FORM_indirect: {
                uint64_t f = readULEB128(off, end);
                if (hasDecodeError()) return false;
                return self(self, static_cast<DwarfForm>(f), off, end, is_dwarf64);
            }
            default:
                return false;
        }
    };

    auto readFormUnsigned = [&](DwarfForm form, uint64_t& off, uint64_t end, bool is_dwarf64) -> std::optional<uint64_t> {
        switch (form) {
            case DwarfForm::DW_FORM_data1: return readU8(off, end);
            case DwarfForm::DW_FORM_data2: return readU16(off, end);
            case DwarfForm::DW_FORM_data4: return readU32(off, end);
            case DwarfForm::DW_FORM_data8: return readU64(off, end);
            case DwarfForm::DW_FORM_udata: return readULEB128(off, end);
            case DwarfForm::DW_FORM_sdata: return static_cast<uint64_t>(readSLEB128(off, end));
            case DwarfForm::DW_FORM_ref1: return readU8(off, end);
            case DwarfForm::DW_FORM_ref2: return readU16(off, end);
            case DwarfForm::DW_FORM_ref4: return readU32(off, end);
            case DwarfForm::DW_FORM_ref8: return readU64(off, end);
            case DwarfForm::DW_FORM_ref_udata: return readULEB128(off, end);
            case DwarfForm::DW_FORM_flag: return readU8(off, end);
            case DwarfForm::DW_FORM_flag_present: return 1;
            case DwarfForm::DW_FORM_sec_offset:
            case DwarfForm::DW_FORM_ref_addr:
                return is_dwarf64 ? readU64(off, end) : readU32(off, end);
            case DwarfForm::DW_FORM_implicit_const:
                return 0;
            default: {
                // For unknown forms, attempt to skip. If skipping succeeds, return a dummy.
                uint64_t tmp = off;
                if (skipForm(skipForm, form, tmp, end, is_dwarf64)) {
                    off = tmp;
                    return 0;
                }
                return std::nullopt;
            }
        }
    };

    for (const auto& unit : units_) {
        for (uint32_t i = 0; i < unit.header.name_count; ++i) {
            std::string name = readString(unit.name_offsets[i]);
            if (name.empty()) continue;

            NameEntry entry;
            entry.name = name;
            entry.hash = unit.hashes[i];

            if (unit.entry_offsets[i] > (unit.unit_end - unit.entry_pool_base)) continue;
            uint64_t entry_offset = unit.entry_pool_base + unit.entry_offsets[i];
            if (entry_offset >= unit.unit_end) continue;

            while (entry_offset < unit.unit_end) {
                uint64_t entry_before = entry_offset;
                uint64_t abbrev_code = readULEB128(entry_offset, unit.unit_end);
                if (hasDecodeError()) {
                    entry_offset = unit.unit_end;
                    break;
                }
                if (abbrev_code == 0) break;

                auto it = unit.abbrevs.find(abbrev_code);
                if (it == unit.abbrevs.end()) break;

                const NameIndexAbbrev& abbrev = it->second;
                entry.tags.push_back(abbrev.tag);

                uint64_t die_offset = 0;
                uint64_t cu_index = 0;

                for (const auto& attr : abbrev.attributes) {
                    auto v = readFormUnsigned(attr.second, entry_offset, unit.unit_end, unit.header.is_dwarf64);
                    if (!v.has_value() || hasDecodeError()) {
                        // Unable to skip this form reliably; abandon this name's entry list.
                        entry_offset = unit.unit_end;
                        break;
                    }

                    switch (attr.first) {
                        case DW_IDX::DW_IDX_compile_unit:
                            cu_index = *v;
                            break;
                        case DW_IDX::DW_IDX_die_offset:
                            die_offset = *v;
                            break;
                        default:
                            break;
                    }
                }

                if (entry_offset > unit.unit_end) break;
                if (entry_offset <= entry_before) break;
                // DW_IDX_die_offset is an offset within a CU. Convert it to an absolute .debug_info
                // section offset using the corresponding CU's section offset, when possible.
                uint64_t abs_die_offset = die_offset;
                if (cu_index < unit.cu_offsets.size()) {
                    abs_die_offset = unit.cu_offsets[static_cast<size_t>(cu_index)] + die_offset;
                }

                entry.die_offsets.push_back(abs_die_offset);
                entry.cu_indices.push_back(cu_index);
            }

            if (!entry.die_offsets.empty()) {
                name_cache_[name].push_back(std::move(entry));
            }
        }
    }

    cache_populated_ = true;
}

std::vector<NameEntry> DebugNamesParser::lookupName(const std::string& name) const {
    // Fast path: memoized lookup.
    if (auto it = name_cache_.find(name); it != name_cache_.end()) {
        return it->second;
    }

    if (!parsed_ || units_.empty() || name.empty()) {
        return {};
    }
    clearDecodeError();

    auto readSLEB128 = [&](uint64_t& off, uint64_t end) -> int64_t {
        if (end > debug_names_.size() || off >= end) {
            decode_error_ = true;
            return 0;
        }
        uint64_t result = 0;
        unsigned shift = 0;
        uint8_t byte = 0;
        while (off < end) {
            byte = debug_names_[off++];
            uint64_t bits = static_cast<uint64_t>(byte & 0x7f);
            if (shift >= 64 && bits != 0) {
                decode_error_ = true;
                return 0;
            }
            result |= (bits << shift);
            shift += 7;
            if ((byte & 0x80) == 0) {
                if (shift < 64 && (byte & 0x40)) result |= (~0ULL << shift);
                return static_cast<int64_t>(result);
            }
            if (shift >= 64) {
                decode_error_ = true;
                return 0;
            }
        }
        decode_error_ = true;
        return 0;
    };

    auto skipCString = [&](uint64_t& off, uint64_t end) -> void {
        while (off < end) {
            if (debug_names_[off++] == 0) break;
        }
    };

    auto skipForm = [&](auto&& self, DwarfForm form, uint64_t& off, uint64_t end, bool is_dwarf64) -> bool {
        auto need = [&](uint64_t n) -> bool {
            if (off + n > end) return false;
            off += n;
            return true;
        };

        switch (form) {
            case DwarfForm::DW_FORM_flag_present:
            case DwarfForm::DW_FORM_implicit_const:
                return true;
            case DwarfForm::DW_FORM_data1:
            case DwarfForm::DW_FORM_flag:
            case DwarfForm::DW_FORM_ref1:
            case DwarfForm::DW_FORM_strx1:
            case DwarfForm::DW_FORM_addrx1:
                return need(1);
            case DwarfForm::DW_FORM_data2:
            case DwarfForm::DW_FORM_ref2:
            case DwarfForm::DW_FORM_strx2:
            case DwarfForm::DW_FORM_addrx2:
                return need(2);
            case DwarfForm::DW_FORM_data4:
            case DwarfForm::DW_FORM_ref4:
            case DwarfForm::DW_FORM_strx4:
            case DwarfForm::DW_FORM_addrx4:
                return need(4);
            case DwarfForm::DW_FORM_data8:
            case DwarfForm::DW_FORM_ref8:
            case DwarfForm::DW_FORM_ref_sig8:
                return need(8);
            case DwarfForm::DW_FORM_data16:
                return need(16);
            case DwarfForm::DW_FORM_udata:
            case DwarfForm::DW_FORM_ref_udata:
            case DwarfForm::DW_FORM_strx:
            case DwarfForm::DW_FORM_addrx:
            case DwarfForm::DW_FORM_loclistx:
            case DwarfForm::DW_FORM_rnglistx:
                (void)readULEB128(off, end);
                return !hasDecodeError() && off <= end;
            case DwarfForm::DW_FORM_sdata:
                (void)readSLEB128(off, end);
                return !hasDecodeError() && off <= end;
            case DwarfForm::DW_FORM_string:
                skipCString(off, end);
                return true;
            case DwarfForm::DW_FORM_sec_offset:
            case DwarfForm::DW_FORM_strp:
            case DwarfForm::DW_FORM_line_strp:
            case DwarfForm::DW_FORM_strp_sup:
            case DwarfForm::DW_FORM_ref_sup4:
            case DwarfForm::DW_FORM_ref_sup8:
            case DwarfForm::DW_FORM_ref_addr:
                return need(is_dwarf64 ? 8 : 4);
            case DwarfForm::DW_FORM_exprloc:
            case DwarfForm::DW_FORM_block: {
                uint64_t n = readULEB128(off, end);
                return need(n);
            }
            case DwarfForm::DW_FORM_block1: {
                uint64_t n = readU8(off, end);
                return need(n);
            }
            case DwarfForm::DW_FORM_block2: {
                uint64_t n = readU16(off, end);
                return need(n);
            }
            case DwarfForm::DW_FORM_block4: {
                uint64_t n = readU32(off, end);
                return need(n);
            }
            case DwarfForm::DW_FORM_indirect: {
                uint64_t f = readULEB128(off, end);
                if (hasDecodeError()) return false;
                return self(self, static_cast<DwarfForm>(f), off, end, is_dwarf64);
            }
            default:
                return false;
        }
    };

    auto readFormUnsigned = [&](DwarfForm form, uint64_t& off, uint64_t end, bool is_dwarf64) -> std::optional<uint64_t> {
        switch (form) {
            case DwarfForm::DW_FORM_data1: return readU8(off, end);
            case DwarfForm::DW_FORM_data2: return readU16(off, end);
            case DwarfForm::DW_FORM_data4: return readU32(off, end);
            case DwarfForm::DW_FORM_data8: return readU64(off, end);
            case DwarfForm::DW_FORM_udata: return readULEB128(off, end);
            case DwarfForm::DW_FORM_sdata: return static_cast<uint64_t>(readSLEB128(off, end));
            case DwarfForm::DW_FORM_ref1: return readU8(off, end);
            case DwarfForm::DW_FORM_ref2: return readU16(off, end);
            case DwarfForm::DW_FORM_ref4: return readU32(off, end);
            case DwarfForm::DW_FORM_ref8: return readU64(off, end);
            case DwarfForm::DW_FORM_ref_udata: return readULEB128(off, end);
            case DwarfForm::DW_FORM_flag: return readU8(off, end);
            case DwarfForm::DW_FORM_flag_present: return 1;
            case DwarfForm::DW_FORM_sec_offset:
            case DwarfForm::DW_FORM_ref_addr:
                return is_dwarf64 ? readU64(off, end) : readU32(off, end);
            case DwarfForm::DW_FORM_implicit_const:
                return 0;
            default: {
                uint64_t tmp = off;
                if (skipForm(skipForm, form, tmp, end, is_dwarf64)) {
                    off = tmp;
                    return 0;
                }
                return std::nullopt;
            }
        }
    };

    const uint32_t h32 = static_cast<uint32_t>(hashName(name));
    std::vector<NameEntry> results;

    for (const auto& unit : units_) {
        if (unit.header.bucket_count == 0 || unit.header.name_count == 0) continue;
        if (unit.buckets.empty() || unit.hashes.size() < unit.header.name_count ||
            unit.name_offsets.size() < unit.header.name_count || unit.entry_offsets.size() < unit.header.name_count) {
            continue;
        }

        uint32_t bucket_idx = h32 % unit.header.bucket_count;
        if (bucket_idx >= unit.buckets.size()) continue;

        uint32_t start_1based = unit.buckets[bucket_idx];
        if (start_1based == 0) continue;

        uint64_t j = static_cast<uint64_t>(start_1based - 1);
        if (j >= unit.header.name_count) continue;

        for (; j < unit.header.name_count; ++j) {
            uint32_t hj = unit.hashes[static_cast<size_t>(j)];
            if (hj < h32) continue;
            if (hj > h32) break;

            // Hash match; confirm the actual string.
            std::string s = readString(unit.name_offsets[static_cast<size_t>(j)]);
            if (s != name) continue;

            NameEntry entry;
            entry.name = name;
            entry.hash = hj;

            uint64_t rel = unit.entry_offsets[static_cast<size_t>(j)];
            if (rel > (unit.unit_end - unit.entry_pool_base)) continue;
            uint64_t entry_offset = unit.entry_pool_base + rel;
            if (entry_offset >= unit.unit_end) continue;

            while (entry_offset < unit.unit_end) {
                uint64_t entry_before = entry_offset;
                uint64_t abbrev_code = readULEB128(entry_offset, unit.unit_end);
                if (hasDecodeError()) {
                    entry_offset = unit.unit_end;
                    break;
                }
                if (abbrev_code == 0) break;

                auto it = unit.abbrevs.find(abbrev_code);
                if (it == unit.abbrevs.end()) break;

                const NameIndexAbbrev& abbrev = it->second;
                entry.tags.push_back(abbrev.tag);

                uint64_t die_offset = 0;
                uint64_t cu_index = 0;

                for (const auto& attr : abbrev.attributes) {
                    auto v = readFormUnsigned(attr.second, entry_offset, unit.unit_end, unit.header.is_dwarf64);
                    if (!v.has_value() || hasDecodeError()) {
                        entry_offset = unit.unit_end;
                        break;
                    }

                    switch (attr.first) {
                        case DW_IDX::DW_IDX_compile_unit:
                            cu_index = *v;
                            break;
                        case DW_IDX::DW_IDX_die_offset:
                            die_offset = *v;
                            break;
                        default:
                            break;
                    }
                }

                if (entry_offset > unit.unit_end) break;
                if (entry_offset <= entry_before) break;
                uint64_t abs_die_offset = die_offset;
                if (cu_index < unit.cu_offsets.size()) {
                    abs_die_offset = unit.cu_offsets[static_cast<size_t>(cu_index)] + die_offset;
                }

                entry.die_offsets.push_back(abs_die_offset);
                entry.cu_indices.push_back(cu_index);
            }

            if (!entry.die_offsets.empty()) {
                results.push_back(std::move(entry));
            }
        }
    }

    // Memoize per-name, but don't mark the whole cache populated.
    name_cache_[name] = results;
    return results;
}

std::vector<NameEntry> DebugNamesParser::lookupNameByTag(const std::string& name, DwarfTag tag) const {
    std::vector<NameEntry> results;
    auto entries = lookupName(name);

    for (const auto& entry : entries) {
        NameEntry filtered = entry;
        filtered.die_offsets.clear();
        filtered.cu_indices.clear();
        filtered.tags.clear();

        for (size_t i = 0; i < entry.tags.size(); ++i) {
            if (entry.tags[i] == tag) {
                filtered.die_offsets.push_back(entry.die_offsets[i]);
                filtered.cu_indices.push_back(entry.cu_indices[i]);
                filtered.tags.push_back(entry.tags[i]);
            }
        }

        if (!filtered.die_offsets.empty()) {
            results.push_back(filtered);
        }
    }

    return results;
}

std::vector<uint64_t> DebugNamesParser::lookupDIEOffsets(const std::string& name) const {
    std::vector<uint64_t> offsets;
    auto entries = lookupName(name);

    for (const auto& entry : entries) {
        offsets.insert(offsets.end(), entry.die_offsets.begin(), entry.die_offsets.end());
    }

    return offsets;
}

std::vector<std::string> DebugNamesParser::getAllNames() const {
    populateCache();

    std::vector<std::string> names;
    names.reserve(name_cache_.size());

    for (const auto& pair : name_cache_) {
        names.push_back(pair.first);
    }

    return names;
}

uint64_t DebugNamesParser::hashName(const std::string& name) {
    // DWARF 5 specified hash function (DJB hash)
    uint64_t hash = 5381;
    for (char c : name) {
        hash = ((hash << 5) + hash) + static_cast<unsigned char>(c);
    }
    return hash;
}

// Reading helpers

uint8_t DebugNamesParser::readU8(uint64_t& offset, uint64_t end) const {
    if (offset + 1 > end || end > debug_names_.size()) {
        decode_error_ = true;
        return 0;
    }
    return DwarfUtils::readU8(debug_names_.data(), offset, end);
}

uint16_t DebugNamesParser::readU16(uint64_t& offset, uint64_t end) const {
    if (offset + 2 > end || end > debug_names_.size()) {
        decode_error_ = true;
        return 0;
    }
    return DwarfUtils::readU16(debug_names_.data(), offset, end);
}

uint32_t DebugNamesParser::readU32(uint64_t& offset, uint64_t end) const {
    if (offset + 4 > end || end > debug_names_.size()) {
        decode_error_ = true;
        return 0;
    }
    return DwarfUtils::readU32(debug_names_.data(), offset, end);
}

uint64_t DebugNamesParser::readU64(uint64_t& offset, uint64_t end) const {
    if (offset + 8 > end || end > debug_names_.size()) {
        decode_error_ = true;
        return 0;
    }
    return DwarfUtils::readU64(debug_names_.data(), offset, end);
}

uint64_t DebugNamesParser::readOffset(uint64_t& offset, uint64_t end, bool is_dwarf64) const {
    return is_dwarf64 ? readU64(offset, end) : readU32(offset, end);
}

uint64_t DebugNamesParser::readULEB128(uint64_t& offset, uint64_t end) const {
    if (end > debug_names_.size() || offset >= end) {
        decode_error_ = true;
        return 0;
    }

    uint64_t result = 0;
    unsigned shift = 0;
    while (offset < end) {
        uint8_t byte = debug_names_[offset++];
        uint64_t bits = static_cast<uint64_t>(byte & 0x7f);
        if (shift >= 64 && bits != 0) {
            decode_error_ = true;
            return 0;
        }
        result |= (bits << shift);
        if ((byte & 0x80) == 0) {
            return result;
        }
        shift += 7;
        if (shift >= 64) {
            decode_error_ = true;
            return 0;
        }
    }
    decode_error_ = true;
    return 0;
}

std::string DebugNamesParser::readString(uint64_t str_offset) const {
    if (str_offset >= debug_str_.size()) {
        return "";
    }

    const char* str = reinterpret_cast<const char*>(debug_str_.data() + str_offset);
    size_t max_len = debug_str_.size() - str_offset;
    size_t len = strnlen(str, max_len);

    return std::string(str, len);
}

void DebugNamesParser::clearDecodeError() const {
    decode_error_ = false;
}

bool DebugNamesParser::hasDecodeError() const {
    return decode_error_;
}

} // namespace dwarf
