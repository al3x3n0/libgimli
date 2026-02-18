#pragma once

#include "dwarf_types.hpp"
#include "attribute_parser.hpp"
#include <vector>
#include <string>
#include <map>
#include <optional>
#include <cstdint>

namespace dwarf {

// Source location information
struct SourceLocation {
    std::string file;           // Full path or filename
    std::string directory;      // Directory (if separate)
    uint32_t line = 0;          // Line number (1-based)
    uint32_t column = 0;        // Column number (0 = unknown)
    uint64_t address = 0;       // Code address
    bool is_stmt = false;       // Is this a statement boundary?
    bool is_basic_block = false;
    bool is_end_sequence = false;
    bool is_prologue_end = false;
    bool is_epilogue_begin = false;
    uint32_t discriminator = 0; // For multiple blocks on same line

    bool valid() const { return line > 0 && !file.empty(); }
};

// Address range for a source location
struct AddressRange {
    uint64_t start;
    uint64_t end;
    SourceLocation location;
};

// Compilation unit line info
struct CULineInfo {
    uint64_t cu_offset;
    std::string comp_dir;
    std::vector<std::string> directories;
    std::vector<std::string> files;  // Full paths
    std::vector<SourceLocation> line_table;
};

// Source location resolver - provides address<->line lookups
class SourceLocationResolver {
public:
    SourceLocationResolver();

    // Add line info from a compilation unit
    void addCULineInfo(const CULineInfo& cu_info);

    // Add line info from parsed line table
    void addLineTable(const std::vector<LineAttributeValue::LineEntry>& entries,
                     const std::vector<std::string>& directories,
                     const std::vector<LineAttributeValue::FileEntry>& files,
                     const std::string& comp_dir = "");

    // Address to source location lookup
    std::optional<SourceLocation> getSourceLocation(uint64_t address) const;

    // Get all locations for an address (for inlined functions)
    std::vector<SourceLocation> getAllSourceLocations(uint64_t address) const;

    // Line to address lookup
    std::vector<uint64_t> getAddressesForLine(const std::string& file, uint32_t line) const;

    // Get address range for a line
    std::optional<AddressRange> getAddressRangeForLine(const std::string& file, uint32_t line) const;

    // Get all lines in a file
    std::vector<SourceLocation> getLinesInFile(const std::string& file) const;

    // Get address range for a file
    std::optional<std::pair<uint64_t, uint64_t>> getAddressRangeForFile(const std::string& file) const;

    // Find nearest source location (when exact address not found)
    std::optional<SourceLocation> getNearestSourceLocation(uint64_t address) const;

    // Check if an address is within any known code range
    bool isValidCodeAddress(uint64_t address) const;

    // Get all files
    std::vector<std::string> getAllFiles() const;

    // Clear all data
    void clear();

private:
    // Line entries sorted by address for binary search
    std::vector<SourceLocation> sorted_locations_;

    // Map from file -> line -> addresses for reverse lookup
    std::map<std::string, std::map<uint32_t, std::vector<uint64_t>>> file_line_map_;

    // All known files
    std::vector<std::string> all_files_;

    // Helper to build full path
    std::string buildFullPath(const std::string& directory, const std::string& filename) const;

    // Helper to normalize path
    std::string normalizePath(const std::string& path) const;

    // Binary search helper
    std::vector<SourceLocation>::const_iterator findLocation(uint64_t address) const;
};

} // namespace dwarf
