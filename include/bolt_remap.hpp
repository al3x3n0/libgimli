#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace ELFIO {
class elfio;
}

namespace dwarf {

// Exact old->new code-address remap used to reconcile BOLT-style relocation
// between two binaries during DWARF comparison. The "old" side corresponds to
// the lhs binary and "new" to the rhs binary.
//
// Granularity is function-level: exact function-entry keys plus within-function
// spans so that an old address inside a relocated function maps to the matching
// offset in the new function body. Addresses that are neither an exact key nor
// covered by a span are considered unmapped and are left unchanged (so a genuine
// difference still surfaces as DIFFERENT).
struct BoltAddressRemap {
    struct FunctionSpan {
        uint64_t old_base = 0;
        uint64_t old_size = 0;
        uint64_t new_base = 0;
    };

    // Exact function-entry mapping (old address -> new address).
    std::unordered_map<uint64_t, uint64_t> old_to_new;
    // Within-function spans for offset-relative addresses.
    std::vector<FunctionSpan> spans;
    // Human-readable provenance, e.g. "auto", "file:<path>", "explicit".
    std::string origin;

    bool empty() const { return old_to_new.empty() && spans.empty(); }
    size_t size() const { return old_to_new.size(); }

    // Returns the reconciled new address for an old address, or nullopt when the
    // address is not covered by this remap.
    std::optional<uint64_t> apply(uint64_t old_addr) const;
};

// True if the ELF carries BOLT markers (any section whose name starts ".bolt.").
bool elfHasBoltMarkers(const ELFIO::elfio& elf);

// Builds a remap by matching STT_FUNC symbols by name across two ELFs:
// old address (lhs) -> new address (rhs). Only names present on both sides with
// non-zero addresses are included. origin is set to "auto".
BoltAddressRemap buildBoltRemapFromElves(const ELFIO::elfio& lhs, const ELFIO::elfio& rhs);

// Loads an explicit remap from a text file with lines of the form
// "<old_hex_or_dec> <new_hex_or_dec>" (# comments and blank lines ignored).
// On failure returns an empty remap and sets `error`.
BoltAddressRemap loadBoltRemapFromFile(const std::string& path, std::string& error);

} // namespace dwarf
