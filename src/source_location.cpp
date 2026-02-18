#include "source_location.hpp"
#include <algorithm>
#include <set>

namespace dwarf {

SourceLocationResolver::SourceLocationResolver() = default;

void SourceLocationResolver::addCULineInfo(const CULineInfo& cu_info) {
    for (const auto& loc : cu_info.line_table) {
        sorted_locations_.push_back(loc);

        // Add to reverse lookup map
        if (!loc.file.empty() && loc.line > 0) {
            file_line_map_[loc.file][loc.line].push_back(loc.address);
        }
    }

    // Add files
    for (const auto& file : cu_info.files) {
        if (std::find(all_files_.begin(), all_files_.end(), file) == all_files_.end()) {
            all_files_.push_back(file);
        }
    }

    // Re-sort by address
    std::sort(sorted_locations_.begin(), sorted_locations_.end(),
              [](const SourceLocation& a, const SourceLocation& b) {
                  return a.address < b.address;
              });
}

void SourceLocationResolver::addLineTable(
    const std::vector<LineAttributeValue::LineEntry>& entries,
    const std::vector<std::string>& directories,
    const std::vector<LineAttributeValue::FileEntry>& files,
    const std::string& comp_dir) {

    // Build file paths
    std::vector<std::string> file_paths;
    for (const auto& file : files) {
        std::string dir;
        if (file.dir_index > 0 && file.dir_index <= directories.size()) {
            dir = directories[file.dir_index - 1];
        } else if (!comp_dir.empty()) {
            dir = comp_dir;
        }
        file_paths.push_back(buildFullPath(dir, file.filename));
    }

    // Add entries
    for (const auto& entry : entries) {
        if (entry.is_end_sequence) {
            continue; // Skip end sequence markers for lookups
        }

        SourceLocation loc;
        loc.address = entry.address;
        loc.line = entry.line;
        loc.column = entry.column;
        loc.is_stmt = entry.is_stmt;
        loc.is_basic_block = entry.is_basic_block;
        loc.is_end_sequence = entry.is_end_sequence;
        loc.is_prologue_end = entry.prologue_end;
        loc.is_epilogue_begin = entry.epilogue_begin;
        loc.discriminator = entry.discriminator;

        // File index is 1-based in DWARF
        if (entry.file > 0 && entry.file <= file_paths.size()) {
            loc.file = file_paths[entry.file - 1];
        }

        sorted_locations_.push_back(loc);

        // Add to reverse lookup map
        if (!loc.file.empty() && loc.line > 0) {
            file_line_map_[loc.file][loc.line].push_back(loc.address);
        }
    }

    // Add all files
    for (const auto& path : file_paths) {
        if (std::find(all_files_.begin(), all_files_.end(), path) == all_files_.end()) {
            all_files_.push_back(path);
        }
    }

    // Re-sort by address
    std::sort(sorted_locations_.begin(), sorted_locations_.end(),
              [](const SourceLocation& a, const SourceLocation& b) {
                  return a.address < b.address;
              });
}

std::optional<SourceLocation> SourceLocationResolver::getSourceLocation(uint64_t address) const {
    if (sorted_locations_.empty()) {
        return std::nullopt;
    }

    auto it = findLocation(address);
    if (it != sorted_locations_.end() && it->address == address) {
        return *it;
    }

    // If not exact match, return the previous entry (address is within that range)
    if (it != sorted_locations_.begin()) {
        --it;
        // Check if address is within a reasonable range
        auto next = it + 1;
        if (next == sorted_locations_.end() || address < next->address) {
            SourceLocation loc = *it;
            loc.address = address; // Update to queried address
            return loc;
        }
    }

    return std::nullopt;
}

std::vector<SourceLocation> SourceLocationResolver::getAllSourceLocations(uint64_t address) const {
    std::vector<SourceLocation> results;

    auto it = findLocation(address);

    // Collect all entries at this address
    while (it != sorted_locations_.end() && it->address == address) {
        results.push_back(*it);
        ++it;
    }

    // If no exact match, try the range approach
    if (results.empty()) {
        auto loc = getSourceLocation(address);
        if (loc) {
            results.push_back(*loc);
        }
    }

    return results;
}

std::vector<uint64_t> SourceLocationResolver::getAddressesForLine(
    const std::string& file, uint32_t line) const {

    std::vector<uint64_t> results;

    // Try exact file match
    auto file_it = file_line_map_.find(file);
    if (file_it != file_line_map_.end()) {
        auto line_it = file_it->second.find(line);
        if (line_it != file_it->second.end()) {
            return line_it->second;
        }
    }

    // Try matching by filename only (without directory)
    std::string basename = file;
    size_t last_slash = file.find_last_of('/');
    if (last_slash != std::string::npos) {
        basename = file.substr(last_slash + 1);
    }

    for (const auto& [filepath, lines] : file_line_map_) {
        size_t pos = filepath.find_last_of('/');
        std::string fb = (pos != std::string::npos) ? filepath.substr(pos + 1) : filepath;
        if (fb == basename) {
            auto line_it = lines.find(line);
            if (line_it != lines.end()) {
                results.insert(results.end(), line_it->second.begin(), line_it->second.end());
            }
        }
    }

    return results;
}

std::optional<AddressRange> SourceLocationResolver::getAddressRangeForLine(
    const std::string& file, uint32_t line) const {

    auto addresses = getAddressesForLine(file, line);
    if (addresses.empty()) {
        return std::nullopt;
    }

    // Find min and max addresses
    uint64_t min_addr = *std::min_element(addresses.begin(), addresses.end());
    uint64_t max_addr = *std::max_element(addresses.begin(), addresses.end());

    // Find the end of the range (next line's start or reasonable estimate)
    auto it = findLocation(max_addr);
    if (it != sorted_locations_.end()) {
        ++it;
        if (it != sorted_locations_.end()) {
            max_addr = it->address;
        }
    }

    AddressRange range;
    range.start = min_addr;
    range.end = max_addr;

    auto loc = getSourceLocation(min_addr);
    if (loc) {
        range.location = *loc;
    }

    return range;
}

std::vector<SourceLocation> SourceLocationResolver::getLinesInFile(const std::string& file) const {
    std::vector<SourceLocation> results;

    for (const auto& loc : sorted_locations_) {
        if (loc.file == file ||
            (loc.file.size() > file.size() &&
             loc.file.substr(loc.file.size() - file.size()) == file)) {
            results.push_back(loc);
        }
    }

    return results;
}

std::optional<std::pair<uint64_t, uint64_t>> SourceLocationResolver::getAddressRangeForFile(
    const std::string& file) const {

    auto lines = getLinesInFile(file);
    if (lines.empty()) {
        return std::nullopt;
    }

    uint64_t min_addr = UINT64_MAX;
    uint64_t max_addr = 0;

    for (const auto& loc : lines) {
        min_addr = std::min(min_addr, loc.address);
        max_addr = std::max(max_addr, loc.address);
    }

    return std::make_pair(min_addr, max_addr);
}

std::optional<SourceLocation> SourceLocationResolver::getNearestSourceLocation(uint64_t address) const {
    if (sorted_locations_.empty()) {
        return std::nullopt;
    }

    auto it = findLocation(address);

    // Check exact match
    if (it != sorted_locations_.end() && it->address == address) {
        return *it;
    }

    // Find nearest
    const SourceLocation* best = nullptr;
    uint64_t best_distance = UINT64_MAX;

    if (it != sorted_locations_.end()) {
        uint64_t dist = (it->address > address) ? (it->address - address) : (address - it->address);
        if (dist < best_distance) {
            best_distance = dist;
            best = &(*it);
        }
    }

    if (it != sorted_locations_.begin()) {
        --it;
        uint64_t dist = (it->address > address) ? (it->address - address) : (address - it->address);
        if (dist < best_distance) {
            best_distance = dist;
            best = &(*it);
        }
    }

    if (best) {
        SourceLocation loc = *best;
        loc.address = address;
        return loc;
    }

    return std::nullopt;
}

bool SourceLocationResolver::isValidCodeAddress(uint64_t address) const {
    if (sorted_locations_.empty()) {
        return false;
    }

    uint64_t min_addr = sorted_locations_.front().address;
    uint64_t max_addr = sorted_locations_.back().address;

    return address >= min_addr && address <= max_addr;
}

std::vector<std::string> SourceLocationResolver::getAllFiles() const {
    return all_files_;
}

void SourceLocationResolver::clear() {
    sorted_locations_.clear();
    file_line_map_.clear();
    all_files_.clear();
}

std::string SourceLocationResolver::buildFullPath(
    const std::string& directory, const std::string& filename) const {

    if (filename.empty()) {
        return "";
    }

    // If filename is absolute, return as-is
    if (!filename.empty() && filename[0] == '/') {
        return normalizePath(filename);
    }

    if (directory.empty()) {
        return normalizePath(filename);
    }

    // Combine directory and filename
    std::string path = directory;
    if (path.back() != '/') {
        path += '/';
    }
    path += filename;

    return normalizePath(path);
}

std::string SourceLocationResolver::normalizePath(const std::string& path) const {
    // Simple normalization - remove ./ and handle ../
    std::vector<std::string> components;
    std::string current;

    for (size_t i = 0; i < path.size(); ++i) {
        if (path[i] == '/') {
            if (!current.empty()) {
                if (current == "..") {
                    if (!components.empty() && components.back() != "..") {
                        components.pop_back();
                    } else {
                        components.push_back(current);
                    }
                } else if (current != ".") {
                    components.push_back(current);
                }
                current.clear();
            }
        } else {
            current += path[i];
        }
    }

    if (!current.empty()) {
        if (current == "..") {
            if (!components.empty() && components.back() != "..") {
                components.pop_back();
            } else {
                components.push_back(current);
            }
        } else if (current != ".") {
            components.push_back(current);
        }
    }

    // Rebuild path
    std::string result;
    if (!path.empty() && path[0] == '/') {
        result = "/";
    }

    for (size_t i = 0; i < components.size(); ++i) {
        if (i > 0) {
            result += '/';
        }
        result += components[i];
    }

    return result.empty() ? "." : result;
}

std::vector<SourceLocation>::const_iterator SourceLocationResolver::findLocation(
    uint64_t address) const {

    return std::lower_bound(sorted_locations_.begin(), sorted_locations_.end(), address,
                           [](const SourceLocation& loc, uint64_t addr) {
                               return loc.address < addr;
                           });
}

} // namespace dwarf
