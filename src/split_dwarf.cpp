#include "split_dwarf.hpp"
#include "die_parser.hpp"
#include <elfio/elfio.hpp>
#include <fstream>
#include <algorithm>
#include <cstring>
#include <limits>

namespace dwarf {

// SplitDwarfLoader implementation

SplitDwarfLoader::SplitDwarfLoader() {
    // Add current directory as default search path
    search_paths_.push_back(".");
}

void SplitDwarfLoader::addSearchPath(const std::string& path) {
    if (std::find(search_paths_.begin(), search_paths_.end(), path) == search_paths_.end()) {
        search_paths_.push_back(path);
    }
}

void SplitDwarfLoader::setSearchPaths(const std::vector<std::string>& paths) {
    search_paths_ = paths;
}

void SplitDwarfLoader::addSkeletonUnit(const SkeletonUnit& skeleton) {
    skeleton_units_.push_back(skeleton);
}

bool SplitDwarfLoader::loadDWO(const SkeletonUnit& skeleton) {
    if (skeleton.dwo_name.empty()) {
        return false;
    }

    // Check if already loaded
    if (isDWOLoaded(skeleton.dwo_id)) {
        return true;
    }

    // Resolve the DWO path
    std::string dwo_path = resolveDWOPath(skeleton.dwo_name, skeleton.comp_dir);
    if (dwo_path.empty()) {
        return false;
    }

    return loadSectionsFromDWO(dwo_path, skeleton.dwo_id);
}

bool SplitDwarfLoader::loadDWOFile(const std::string& path) {
    // Load without a specific DWO ID - will extract from file
    return loadSectionsFromDWO(path, 0);
}

bool SplitDwarfLoader::isDWOLoaded(uint64_t dwo_id) const {
    return dwo_sections_.find(dwo_id) != dwo_sections_.end();
}

std::optional<SplitDwarfLoader::DWOSections> SplitDwarfLoader::getDWOSections(uint64_t dwo_id) const {
    auto it = dwo_sections_.find(dwo_id);
    if (it != dwo_sections_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::string SplitDwarfLoader::resolveDWOPath(const std::string& dwo_name, const std::string& comp_dir) const {
    // If absolute path, check directly
    if (!dwo_name.empty() && dwo_name[0] == '/') {
        std::ifstream f(dwo_name);
        if (f.good()) {
            return dwo_name;
        }
    }

    // Try comp_dir + dwo_name
    if (!comp_dir.empty()) {
        std::string path = comp_dir;
        if (path.back() != '/') {
            path += '/';
        }
        path += dwo_name;
        std::ifstream f(path);
        if (f.good()) {
            return path;
        }
    }

    // Try search paths
    return findFile(dwo_name);
}

bool SplitDwarfLoader::loadSectionsFromDWO(const std::string& path, uint64_t dwo_id) {
    ELFIO::elfio reader;
    if (!reader.load(path)) {
        return false;
    }

    DWOSections sections;

    // Load DWO-specific sections
    for (const auto& section : reader.sections) {
        std::string name = section->get_name();
        const char* data = section->get_data();
        size_t size = section->get_size();

        if (data == nullptr || size == 0) {
            continue;
        }

        std::vector<uint8_t> section_data(data, data + size);

        if (name == ".debug_info.dwo") {
            sections.debug_info = std::move(section_data);
        } else if (name == ".debug_abbrev.dwo") {
            sections.debug_abbrev = std::move(section_data);
        } else if (name == ".debug_str.dwo") {
            sections.debug_str = std::move(section_data);
        } else if (name == ".debug_str_offsets.dwo") {
            sections.debug_str_offsets = std::move(section_data);
        } else if (name == ".debug_line.dwo") {
            sections.debug_line = std::move(section_data);
        } else if (name == ".debug_line_str.dwo") {
            sections.debug_line_str = std::move(section_data);
        } else if (name == ".debug_loclists.dwo") {
            sections.debug_loclists = std::move(section_data);
        } else if (name == ".debug_rnglists.dwo") {
            sections.debug_rnglists = std::move(section_data);
        } else if (name == ".debug_macro.dwo") {
            sections.debug_macro = std::move(section_data);
        } else if (name == ".debug_addr.dwo") {
            sections.debug_addr = std::move(section_data);
        }
    }

    // If no dwo_id provided, try to extract from debug_info
    if (dwo_id == 0 && !sections.debug_info.empty()) {
        // Prefer parsing the DWO CU DIE for DW_AT_dwo_id / DW_AT_GNU_dwo_id.
        try {
            const std::vector<uint8_t> empty;
            const std::vector<uint8_t>& dwo_str = sections.debug_str.empty() ? empty : sections.debug_str;
            DIEParser parser(reader,
                             sections.debug_info,
                             sections.debug_abbrev,
                             dwo_str,
                             /*debug_line=*/sections.debug_line,
                             /*debug_ranges=*/empty,
                             /*debug_loc=*/empty,
                             /*debug_str_offsets=*/sections.debug_str_offsets,
                             /*debug_addr=*/sections.debug_addr,
                             /*debug_line_str=*/sections.debug_line_str,
                             /*debug_rnglists=*/sections.debug_rnglists,
                             /*debug_loclists=*/sections.debug_loclists,
                             /*debug_str_sup=*/empty,
                             /*verbose=*/false,
                             /*debug_info_offset_bias=*/0,
                             /*supplementary_debug_info_offset_bias=*/0);
            auto cus = parser.parseCompilationUnits();
            if (!cus.empty() && cus[0]) {
                auto tryAttrU64 = [&](DwarfAttribute a) -> uint64_t {
                    auto v = cus[0]->getAttribute(a);
                    auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(v);
                    return u ? u->getValue() : 0;
                };
                dwo_id = tryAttrU64(DwarfAttribute::DW_AT_dwo_id);
                if (dwo_id == 0) dwo_id = tryAttrU64(DwarfAttribute::DW_AT_GNU_dwo_id);
            }
        } catch (...) {
            // fall through to hash fallback
        }

        if (dwo_id == 0) {
            // Stable fallback: path hash.
            for (char c : path) {
                dwo_id = dwo_id * 31 + static_cast<unsigned char>(c);
            }
        }
    }

    if (dwo_id != 0) {
        dwo_sections_[dwo_id] = std::move(sections);

        DWOFileInfo info;
        info.path = path;
        info.dwo_id = dwo_id;
        info.is_loaded = true;
        loaded_dwos_[dwo_id] = info;

        return true;
    }

    return false;
}

std::string SplitDwarfLoader::findFile(const std::string& filename) const {
    for (const auto& dir : search_paths_) {
        std::string path = dir;
        if (!path.empty() && path.back() != '/') {
            path += '/';
        }
        path += filename;

        std::ifstream f(path);
        if (f.good()) {
            return path;
        }
    }
    return "";
}

// DWPLoader implementation

DWPLoader::DWPLoader() = default;

bool DWPLoader::parseIndexData(const std::vector<uint8_t>& index_data, bool is_tu_index) {
    return parseIndex(index_data, is_tu_index);
}

bool DWPLoader::load(const std::string& path) {
    ELFIO::elfio reader;
    if (!reader.load(path)) {
        return false;
    }

    path_ = path;

    // Load all .dwo sections
    for (const auto& section : reader.sections) {
        std::string name = section->get_name();
        const char* data = section->get_data();
        size_t size = section->get_size();

        if (data == nullptr || size == 0) {
            continue;
        }

        std::vector<uint8_t> section_data(data, data + size);

        if (name == ".debug_info.dwo") {
            debug_info_dwo_ = std::move(section_data);
        } else if (name == ".debug_abbrev.dwo") {
            debug_abbrev_dwo_ = std::move(section_data);
        } else if (name == ".debug_str.dwo") {
            debug_str_dwo_ = std::move(section_data);
        } else if (name == ".debug_str_offsets.dwo") {
            debug_str_offsets_dwo_ = std::move(section_data);
        } else if (name == ".debug_line.dwo") {
            debug_line_dwo_ = std::move(section_data);
        } else if (name == ".debug_line_str.dwo") {
            debug_line_str_dwo_ = std::move(section_data);
        } else if (name == ".debug_loclists.dwo") {
            debug_loclists_dwo_ = std::move(section_data);
        } else if (name == ".debug_rnglists.dwo") {
            debug_rnglists_dwo_ = std::move(section_data);
        } else if (name == ".debug_macro.dwo") {
            debug_macro_dwo_ = std::move(section_data);
        } else if (name == ".debug_addr.dwo") {
            debug_addr_dwo_ = std::move(section_data);
        } else if (name == ".debug_cu_index") {
            parseIndex(section_data, false);
        } else if (name == ".debug_tu_index") {
            parseIndex(section_data, true);
        }
    }

    is_loaded_ = true;
    return true;
}

std::optional<DWPIndex::UnitEntry> DWPLoader::findUnit(uint64_t signature) const {
    auto it = index_.units.find(signature);
    if (it != index_.units.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<SplitDwarfLoader::DWOSections> DWPLoader::getSectionsForUnit(uint64_t signature) const {
    auto entry_opt = findUnit(signature);
    if (!entry_opt) {
        return std::nullopt;
    }

    const auto& entry = *entry_opt;
    SplitDwarfLoader::DWOSections sections;

    sections.debug_info = extractSection(debug_info_dwo_, entry.info_offset, entry.info_size);
    sections.debug_abbrev = extractSection(debug_abbrev_dwo_, entry.abbrev_offset, entry.abbrev_size);
    sections.debug_line = extractSection(debug_line_dwo_, entry.line_offset, entry.line_size);
    sections.debug_loclists = extractSection(debug_loclists_dwo_, entry.loclists_offset, entry.loclists_size);
    sections.debug_str_offsets = extractSection(debug_str_offsets_dwo_, entry.str_offsets_offset, entry.str_offsets_size);
    sections.debug_macro = extractSection(debug_macro_dwo_, entry.macro_offset, entry.macro_size);
    sections.debug_rnglists = extractSection(debug_rnglists_dwo_, entry.rnglists_offset, entry.rnglists_size);
    sections.debug_addr = extractSection(debug_addr_dwo_, entry.addr_offset, entry.addr_size);

    // String section is shared
    sections.debug_str = debug_str_dwo_;
    sections.debug_line_str = debug_line_str_dwo_;

    return sections;
}

	bool DWPLoader::parseIndex(const std::vector<uint8_t>& index_data, bool is_tu_index) {
	    (void)is_tu_index; // Same format for CU and TU index

    if (index_data.size() < 16) {
        return false;
    }

    uint64_t offset = 0;

    // Read header
    auto readU32 = [&]() -> uint32_t {
        if (offset + 4 > index_data.size()) return 0;
        uint32_t v = index_data[offset] |
                    (index_data[offset + 1] << 8) |
                    (index_data[offset + 2] << 16) |
                    (index_data[offset + 3] << 24);
        offset += 4;
        return v;
    };

    auto readU64 = [&]() -> uint64_t {
        if (offset + 8 > index_data.size()) return 0;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= static_cast<uint64_t>(index_data[offset + i]) << (i * 8);
        }
        offset += 8;
        return v;
    };

	    index_.version = readU32();
	    index_.section_count = readU32();
	    index_.unit_count = readU32();
	    index_.slot_count = readU32();

	    // DWARF Split DWARF package (.dwp) index versions in the wild are typically >= 2.
	    // Some producers/consumers historically used version 1; the overall layout is commonly
	    // compatible. Prefer attempting to parse when the remaining bounds checks succeed rather
	    // than hard-failing.
	    if (index_.version < 1) {
	        return false; // Unsupported version
	    }
	    if (index_.section_count == 0 || index_.slot_count == 0) {
	        return false;
	    }

    // Read section column meanings (DW_SECT_* ids)
    // Immediately after the header comes section_count 32-bit section identifiers.
    std::vector<uint32_t> section_ids;
    section_ids.reserve(index_.section_count);
    for (uint32_t i = 0; i < index_.section_count; ++i) {
        if (offset + 4 > index_data.size()) return false;
        section_ids.push_back(readU32());
    }

	    // Layout:
	    // section_ids: section_count * 4
	    // hash table: slot_count * 8 (signatures)
	    // index table: slot_count * 4 (1-based row indices)
	    // section offsets: unit_count * section_count * 4
	    // section sizes: unit_count * section_count * 4

	    auto checkedMul = [](uint64_t a, uint64_t b, uint64_t& out) -> bool {
	        if (a == 0 || b == 0) {
	            out = 0;
	            return true;
	        }
	        if (a > (std::numeric_limits<uint64_t>::max() / b)) {
	            return false;
	        }
	        out = a * b;
	        return true;
	    };
	    auto checkedAdd = [](uint64_t a, uint64_t b, uint64_t& out) -> bool {
	        if (a > (std::numeric_limits<uint64_t>::max() - b)) {
	            return false;
	        }
	        out = a + b;
	        return true;
	    };

	    uint64_t hash_table_offset = offset;
	    uint64_t slot_sig_bytes = 0;
	    uint64_t slot_idx_bytes = 0;
	    uint64_t unit_col_count = 0;
	    uint64_t unit_table_bytes = 0;
	    if (!checkedMul(index_.slot_count, 8, slot_sig_bytes)) return false;
	    if (!checkedMul(index_.slot_count, 4, slot_idx_bytes)) return false;
	    if (!checkedMul(index_.unit_count, index_.section_count, unit_col_count)) return false;
	    if (!checkedMul(unit_col_count, 4, unit_table_bytes)) return false;

	    uint64_t index_table_offset = 0;
	    uint64_t section_offsets_offset = 0;
	    uint64_t section_sizes_offset = 0;
	    uint64_t end_of_offsets = 0;
	    uint64_t end_of_sizes = 0;
	    if (!checkedAdd(hash_table_offset, slot_sig_bytes, index_table_offset)) return false;
	    if (!checkedAdd(index_table_offset, slot_idx_bytes, section_offsets_offset)) return false;
	    if (!checkedAdd(section_offsets_offset, unit_table_bytes, section_sizes_offset)) return false;
	    if (!checkedAdd(section_offsets_offset, unit_table_bytes, end_of_offsets)) return false;
	    if (!checkedAdd(section_sizes_offset, unit_table_bytes, end_of_sizes)) return false;
	    if (index_table_offset > index_data.size()) return false;
	    if (section_offsets_offset > index_data.size()) return false;
	    if (section_sizes_offset > index_data.size()) return false;
	    if (end_of_offsets > index_data.size()) return false;
	    if (end_of_sizes > index_data.size()) return false;

    // Scan hash table
    for (uint32_t slot = 0; slot < index_.slot_count; ++slot) {
        offset = hash_table_offset + slot * 8;
        uint64_t signature = readU64();

        if (signature == 0) {
            continue; // Empty slot
        }

        offset = index_table_offset + slot * 4;
        uint32_t index = readU32();

        if (index == 0 || index > index_.unit_count) {
            continue;
        }

        // Read section offsets and sizes for this unit
        DWPIndex::UnitEntry entry;
        entry.signature = signature;

        // Index is 1-based
        uint32_t row = index - 1;

        auto readRowColumn = [&](uint32_t col, uint32_t& off, uint32_t& sz) {
            uint64_t off_pos = section_offsets_offset + (row * index_.section_count + col) * 4;
            uint64_t sz_pos = section_sizes_offset + (row * index_.section_count + col) * 4;

            if (off_pos + 4 <= index_data.size()) {
                off = index_data[off_pos] |
                      (index_data[off_pos + 1] << 8) |
                      (index_data[off_pos + 2] << 16) |
                      (index_data[off_pos + 3] << 24);
            }
            if (sz_pos + 4 <= index_data.size()) {
                sz = index_data[sz_pos] |
                     (index_data[sz_pos + 1] << 8) |
                     (index_data[sz_pos + 2] << 16) |
                     (index_data[sz_pos + 3] << 24);
            }
        };

        // Map columns using section_ids (DW_SECT_* ids). Common DWARF 5 ids:
        // 1=INFO, 3=ABBREV, 4=LINE, 5=LOCLISTS, 6=STR_OFFSETS, 7=MACRO, 8=RNGLISTS, 9=ADDR.
        for (uint32_t col = 0; col < index_.section_count && col < section_ids.size(); ++col) {
            uint32_t off = 0, sz = 0;
            readRowColumn(col, off, sz);

            switch (section_ids[col]) {
                case 1: // DW_SECT_INFO
                    entry.info_offset = off; entry.info_size = sz;
                    break;
                case 3: // DW_SECT_ABBREV
                    entry.abbrev_offset = off; entry.abbrev_size = sz;
                    break;
                case 4: // DW_SECT_LINE
                    entry.line_offset = off; entry.line_size = sz;
                    break;
                case 5: // DW_SECT_LOCLISTS
                    entry.loclists_offset = off; entry.loclists_size = sz;
                    break;
                case 6: // DW_SECT_STR_OFFSETS
                    entry.str_offsets_offset = off; entry.str_offsets_size = sz;
                    break;
                case 7: // DW_SECT_MACRO
                    entry.macro_offset = off; entry.macro_size = sz;
                    break;
                case 8: // DW_SECT_RNGLISTS
                    entry.rnglists_offset = off; entry.rnglists_size = sz;
                    break;
                case 9: // DW_SECT_ADDR
                    entry.addr_offset = off; entry.addr_size = sz;
                    break;
                default:
                    break;
            }
        }

        index_.units[signature] = entry;
    }

    return true;
}

std::vector<uint8_t> DWPLoader::extractSection(
    const std::vector<uint8_t>& section, uint32_t offset, uint32_t size) const {

    if (offset + size > section.size() || size == 0) {
        return {};
    }

    return std::vector<uint8_t>(section.begin() + offset, section.begin() + offset + size);
}

} // namespace dwarf
