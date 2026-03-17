#pragma once

#include "dwarf_types.hpp"
#include <vector>
#include <string>
#include <map>
#include <memory>
#include <cstdint>
#include <optional>

namespace dwarf {

// Forward declarations
class DIE;
class AttributeParser;

// DWO file information
struct DWOFileInfo {
    std::string path;               // Path to .dwo file
    uint64_t dwo_id;                // DW_AT_GNU_dwo_id or DW_AT_dwo_id
    std::string dwo_name;           // DW_AT_GNU_dwo_name or DW_AT_dwo_name
    std::string comp_dir;           // Compilation directory
    bool is_loaded = false;
};

// Skeleton unit information (from main executable)
struct SkeletonUnit {
    uint64_t offset;                // Offset in .debug_info
    uint64_t dwo_id;                // DWO ID for matching
    std::string dwo_name;           // DWO filename
    std::string comp_dir;           // Compilation directory
    uint64_t addr_base;             // DW_AT_addr_base
    uint64_t rnglists_base;         // DW_AT_rnglists_base
    uint64_t loclists_base;         // DW_AT_loclists_base
    uint64_t str_offsets_base;      // DW_AT_str_offsets_base
    uint64_t low_pc;                // DW_AT_low_pc
    uint64_t high_pc;               // DW_AT_high_pc
    std::vector<uint8_t> ranges;    // DW_AT_ranges data
};

// Split DWARF loader - handles loading and linking .dwo files
class SplitDwarfLoader {
public:
    SplitDwarfLoader();

    // Set search paths for .dwo files
    void addSearchPath(const std::string& path);
    void setSearchPaths(const std::vector<std::string>& paths);

    // Register a skeleton unit from the main executable
    void addSkeletonUnit(const SkeletonUnit& skeleton);

    // Find and load the .dwo file for a skeleton unit
    bool loadDWO(const SkeletonUnit& skeleton);

    // Load a .dwo file by path
    bool loadDWOFile(const std::string& path);

    // Check if a .dwo file is loaded for the given DWO ID
    bool isDWOLoaded(uint64_t dwo_id) const;

    // Get loaded DWO sections for a DWO ID
    struct DWOSections {
        std::vector<uint8_t> debug_info;
        std::vector<uint8_t> debug_abbrev;
        std::vector<uint8_t> debug_str;
        std::vector<uint8_t> debug_str_offsets;
        std::vector<uint8_t> debug_line;
        std::vector<uint8_t> debug_line_str;
        std::vector<uint8_t> debug_addr;
        std::vector<uint8_t> debug_loclists;
        std::vector<uint8_t> debug_rnglists;
        std::vector<uint8_t> debug_macro;
    };

    std::optional<DWOSections> getDWOSections(uint64_t dwo_id) const;

    // Resolve a .dwo file path
    std::string resolveDWOPath(const std::string& dwo_name, const std::string& comp_dir) const;

    // Get all skeleton units
    const std::vector<SkeletonUnit>& getSkeletonUnits() const { return skeleton_units_; }

    // Get all loaded DWO info
    const std::map<uint64_t, DWOFileInfo>& getLoadedDWOs() const { return loaded_dwos_; }

private:
    std::vector<std::string> search_paths_;
    std::vector<SkeletonUnit> skeleton_units_;
    std::map<uint64_t, DWOFileInfo> loaded_dwos_;
    std::map<uint64_t, DWOSections> dwo_sections_;

    // Helper to load sections from a .dwo file
    bool loadSectionsFromDWO(const std::string& path, uint64_t dwo_id);

    // Helper to find a file in search paths
    std::string findFile(const std::string& filename) const;
};

// DWARF package file (.dwp) support
struct DWPIndex {
    // Unit index entry
    struct UnitEntry {
        uint64_t signature;         // Unit signature/DWO ID
        uint32_t info_offset;       // Offset in .debug_info.dwo
        uint32_t info_size;         // Size in .debug_info.dwo
        uint32_t abbrev_offset;     // Offset in .debug_abbrev.dwo
        uint32_t abbrev_size;       // Size in .debug_abbrev.dwo
        uint32_t line_offset;       // Offset in .debug_line.dwo
        uint32_t line_size;         // Size in .debug_line.dwo
        uint32_t loclists_offset;   // Offset in .debug_loclists.dwo
        uint32_t loclists_size;     // Size in .debug_loclists.dwo
        uint32_t str_offsets_offset;// Offset in .debug_str_offsets.dwo
        uint32_t str_offsets_size;  // Size in .debug_str_offsets.dwo
        uint32_t macro_offset;      // Offset in .debug_macro.dwo
        uint32_t macro_size;        // Size in .debug_macro.dwo
        uint32_t rnglists_offset;   // Offset in .debug_rnglists.dwo
        uint32_t rnglists_size;     // Size in .debug_rnglists.dwo
        uint32_t addr_offset;       // Offset in .debug_addr.dwo
        uint32_t addr_size;         // Size in .debug_addr.dwo
    };

    uint32_t version;
    uint32_t section_count;
    uint32_t unit_count;
    uint32_t slot_count;
    std::map<uint64_t, UnitEntry> units;  // signature -> entry
    std::vector<uint32_t> unknown_section_ids;
};

// DWARF package file loader
class DWPLoader {
public:
    DWPLoader();

    // Load a .dwp file
    bool load(const std::string& path);

    // Check if loaded
    bool isLoaded() const { return is_loaded_; }
    const std::string& getPath() const { return path_; }

    // Find unit by signature/DWO ID
    std::optional<DWPIndex::UnitEntry> findUnit(uint64_t signature) const;

    // Get sections for a unit
    std::optional<SplitDwarfLoader::DWOSections> getSectionsForUnit(uint64_t signature) const;

    // Parse a CU/TU index blob (primarily for unit testing).
    bool parseIndexData(const std::vector<uint8_t>& index_data, bool is_tu_index);

    // Get the index
    const DWPIndex& getIndex() const { return index_; }
    bool hasCUIndexSection() const { return has_cu_index_section_; }
    bool isCUIndexValid() const { return cu_index_valid_; }
    bool hasTUIndexSection() const { return has_tu_index_section_; }
    bool isTUIndexValid() const { return tu_index_valid_; }
    size_t getCUIndexedUnitCount() const { return cu_index_.units.size(); }
    size_t getTUIndexedUnitCount() const { return tu_index_.units.size(); }
    const std::vector<uint32_t>& getUnknownCUSectionIds() const { return cu_index_.unknown_section_ids; }
    const std::vector<uint32_t>& getUnknownTUSectionIds() const { return tu_index_.unknown_section_ids; }
    bool hasUnknownSectionIds() const {
        return !cu_index_.unknown_section_ids.empty() || !tu_index_.unknown_section_ids.empty();
    }

private:
    bool is_loaded_ = false;
    std::string path_;
    DWPIndex index_;
    DWPIndex cu_index_;
    DWPIndex tu_index_;
    bool has_cu_index_section_ = false;
    bool cu_index_valid_ = false;
    bool has_tu_index_section_ = false;
    bool tu_index_valid_ = false;

    // Raw section data from the .dwp file
    std::vector<uint8_t> debug_info_dwo_;
    std::vector<uint8_t> debug_abbrev_dwo_;
    std::vector<uint8_t> debug_str_dwo_;
    std::vector<uint8_t> debug_str_offsets_dwo_;
    std::vector<uint8_t> debug_line_dwo_;
    std::vector<uint8_t> debug_line_str_dwo_;
    std::vector<uint8_t> debug_loclists_dwo_;
    std::vector<uint8_t> debug_rnglists_dwo_;
    std::vector<uint8_t> debug_macro_dwo_;
    std::vector<uint8_t> debug_addr_dwo_;

    // Parse the CU/TU index
    bool parseIndex(const std::vector<uint8_t>& index_data, bool is_tu_index);

    // Extract a slice from a section
    std::vector<uint8_t> extractSection(const std::vector<uint8_t>& section,
                                        uint32_t offset, uint32_t size) const;
};

} // namespace dwarf
