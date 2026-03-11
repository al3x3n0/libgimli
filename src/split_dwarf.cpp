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

    // Some producers record an absolute-looking path but omit the leading slash in the string
    // payload. Recover that case before falling back to search-path probing.
    if (!dwo_name.empty() && dwo_name[0] != '/' && dwo_name.find('/') != std::string::npos) {
        std::string rooted = "/" + dwo_name;
        std::ifstream f(rooted);
        if (f.good()) {
            return rooted;
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
    bool ok = parseIndex(index_data, is_tu_index);
    if (is_tu_index) {
        has_tu_index_section_ = true;
        tu_index_valid_ = ok;
        if (ok) tu_index_ = index_;
        else tu_index_ = DWPIndex{};
    } else {
        has_cu_index_section_ = true;
        cu_index_valid_ = ok;
        if (ok) cu_index_ = index_;
        else cu_index_ = DWPIndex{};
    }
    if (cu_index_valid_) index_ = cu_index_;
    else if (tu_index_valid_) index_ = tu_index_;
    else index_ = DWPIndex{};
    return ok;
}

bool DWPLoader::load(const std::string& path) {
    ELFIO::elfio reader;
    if (!reader.load(path)) {
        return false;
    }

    path_ = path;
    index_ = DWPIndex{};
    cu_index_ = DWPIndex{};
    tu_index_ = DWPIndex{};
    has_cu_index_section_ = false;
    cu_index_valid_ = false;
    has_tu_index_section_ = false;
    tu_index_valid_ = false;
    debug_info_dwo_.clear();
    debug_abbrev_dwo_.clear();
    debug_str_dwo_.clear();
    debug_str_offsets_dwo_.clear();
    debug_line_dwo_.clear();
    debug_line_str_dwo_.clear();
    debug_loclists_dwo_.clear();
    debug_rnglists_dwo_.clear();
    debug_macro_dwo_.clear();
    debug_addr_dwo_.clear();

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
            has_cu_index_section_ = true;
            cu_index_valid_ = parseIndex(section_data, false);
            if (cu_index_valid_) {
                cu_index_ = index_;
            }
        } else if (name == ".debug_tu_index") {
            has_tu_index_section_ = true;
            tu_index_valid_ = parseIndex(section_data, true);
            if (tu_index_valid_) {
                tu_index_ = index_;
            }
        }
    }

    // Prefer CU index for default lookups; fall back to TU index if CU is absent.
    if (cu_index_valid_) {
        index_ = cu_index_;
    } else if (tu_index_valid_) {
        index_ = tu_index_;
    } else {
        index_ = DWPIndex{};
    }

    is_loaded_ = true;
    return true;
}

std::optional<DWPIndex::UnitEntry> DWPLoader::findUnit(uint64_t signature) const {
    auto it_cu = cu_index_.units.find(signature);
    if (it_cu != cu_index_.units.end()) {
        return it_cu->second;
    }
    auto it_tu = tu_index_.units.find(signature);
    if (it_tu != tu_index_.units.end()) {
        return it_tu->second;
    }
    auto it = index_.units.find(signature);
    if (it != index_.units.end()) { // defensive fallback
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

    index_ = DWPIndex{};
    if (index_data.size() < 16) {
        return false;
    }

    DWPIndex parsed{};
    bool decode_error = false;

    auto readU32 = [&](uint64_t& off) -> uint32_t {
        if (off + 4 > index_data.size()) {
            decode_error = true;
            return 0;
        }
        uint32_t v = static_cast<uint32_t>(index_data[off]) |
                     (static_cast<uint32_t>(index_data[off + 1]) << 8) |
                     (static_cast<uint32_t>(index_data[off + 2]) << 16) |
                     (static_cast<uint32_t>(index_data[off + 3]) << 24);
        off += 4;
        return v;
    };

    auto readU64 = [&](uint64_t& off) -> uint64_t {
        if (off + 8 > index_data.size()) {
            decode_error = true;
            return 0;
        }
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= static_cast<uint64_t>(index_data[off + i]) << (i * 8);
        }
        off += 8;
        return v;
    };

    uint64_t offset = 0;
    parsed.version = readU32(offset);
    parsed.section_count = readU32(offset);
    parsed.unit_count = readU32(offset);
    parsed.slot_count = readU32(offset);
    if (decode_error) return false;

    // DWARF Split DWARF package (.dwp) index versions in the wild are typically >= 2.
    // Some producers/consumers historically used version 1; the overall layout is commonly
    // compatible. Prefer attempting to parse when the remaining bounds checks succeed rather
    // than hard-failing.
    if (parsed.version < 1) {
        return false; // Unsupported version
    }
    if (parsed.section_count == 0 || parsed.slot_count == 0) {
        return false;
    }

    // Read section column meanings (DW_SECT_* ids)
    // Immediately after the header comes section_count 32-bit section identifiers.
    std::vector<uint32_t> section_ids;
    section_ids.reserve(parsed.section_count);
    for (uint32_t i = 0; i < parsed.section_count; ++i) {
        section_ids.push_back(readU32(offset));
        if (decode_error) return false;
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
    if (!checkedMul(parsed.slot_count, 8, slot_sig_bytes)) return false;
    if (!checkedMul(parsed.slot_count, 4, slot_idx_bytes)) return false;
    if (!checkedMul(parsed.unit_count, parsed.section_count, unit_col_count)) return false;
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
    for (uint32_t slot = 0; slot < parsed.slot_count; ++slot) {
        uint64_t sig_off = hash_table_offset + static_cast<uint64_t>(slot) * 8;
        uint64_t idx_off = index_table_offset + static_cast<uint64_t>(slot) * 4;
        if (sig_off + 8 > index_data.size()) return false;
        if (idx_off + 4 > index_data.size()) return false;

        uint64_t tmp = sig_off;
        uint64_t signature = readU64(tmp);
        if (decode_error) return false;

        if (signature == 0) {
            continue; // Empty slot
        }

        tmp = idx_off;
        uint32_t index = readU32(tmp);
        if (decode_error) return false;

        if (index == 0 || index > parsed.unit_count) {
            continue;
        }

        // Read section offsets and sizes for this unit.
        DWPIndex::UnitEntry entry;
        entry.signature = signature;

        // Index is 1-based.
        uint64_t row = static_cast<uint64_t>(index - 1);

        auto readRowColumn = [&](uint32_t col, uint32_t& off, uint32_t& sz) -> bool {
            uint64_t cell = row * static_cast<uint64_t>(parsed.section_count) + col;
            uint64_t off_pos = section_offsets_offset + cell * 4;
            uint64_t sz_pos = section_sizes_offset + cell * 4;
            if (off_pos + 4 > index_data.size()) return false;
            if (sz_pos + 4 > index_data.size()) return false;

            uint64_t t = off_pos;
            off = readU32(t);
            t = sz_pos;
            sz = readU32(t);
            if (decode_error) return false;
            return true;
        };

        // Map columns using section_ids (DW_SECT_* ids). Common DWARF 5 ids:
        // 1=INFO, 3=ABBREV, 4=LINE, 5=LOCLISTS, 6=STR_OFFSETS, 7=MACRO, 8=RNGLISTS, 9=ADDR.
        for (uint32_t col = 0; col < parsed.section_count && col < section_ids.size(); ++col) {
            uint32_t off = 0, sz = 0;
            if (!readRowColumn(col, off, sz)) return false;

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

        parsed.units[signature] = entry;
    }

    index_ = std::move(parsed);
    return true;
}

std::vector<uint8_t> DWPLoader::extractSection(
    const std::vector<uint8_t>& section, uint32_t offset, uint32_t size) const {

    if (size == 0) {
        return {};
    }

    size_t off = static_cast<size_t>(offset);
    size_t sz = static_cast<size_t>(size);
    if (off > section.size()) {
        return {};
    }
    if (sz > (section.size() - off)) {
        return {};
    }

    return std::vector<uint8_t>(section.begin() + off, section.begin() + off + sz);
}

} // namespace dwarf
