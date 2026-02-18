#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dwarf {

struct DebugSupEntry {
    uint64_t entry_offset = 0;
    uint64_t entry_size = 0;  // total bytes including length field(s)

    bool is_dwarf64 = false;
    uint16_t version = 0;
    uint8_t is_supplementary = 0;
    uint8_t reserved = 0;
    uint64_t signature = 0;
    std::string path;

    // Best-effort validation for the DWARF5 .debug_sup entry format.
    // Callers that require strict conformance should ignore entries where this is false.
    bool well_formed = true;
    uint32_t error_mask = 0;
};

class DebugSupParser {
public:
    explicit DebugSupParser(const std::vector<uint8_t>& debug_sup) : debug_sup_(debug_sup) {}

    // Parse all entries in .debug_sup. On malformed input, returns the entries
    // parsed so far (best-effort).
    std::vector<DebugSupEntry> parse() const;

private:
    const std::vector<uint8_t>& debug_sup_;
};

} // namespace dwarf
