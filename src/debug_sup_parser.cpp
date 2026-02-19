#include "debug_sup_parser.hpp"
#include "dwarf_utils.hpp"

namespace dwarf {

enum DebugSupEntryError : uint32_t {
    kErrBadLength = 1u << 0,
    kErrShortHeader = 1u << 1,
    kErrBadVersion = 1u << 2,
    kErrBadIsSupplementary = 1u << 3,
    kErrBadReserved = 1u << 4,
    kErrMissingNulPath = 1u << 5,
    kErrBadPathByte = 1u << 6,
    kErrPathTooLong = 1u << 7,
};

static bool isAcceptablePathByte(uint8_t c) {
    // Paths in object files are byte strings; in practice they are usually UTF-8.
    // Reject control characters (except allow >=0x80 for UTF-8 bytes).
    if (c == 0x7f) return false;
    if (c < 0x20) return false;
    return true;
}

std::vector<DebugSupEntry> DebugSupParser::parse() const {
    std::vector<DebugSupEntry> out;
    uint64_t off = 0;

    while (off + 4 <= debug_sup_.size()) {
        DebugSupEntry e;
        e.entry_offset = off;

        uint64_t len_off = off;
        uint32_t initial_length = DwarfUtils::readU32(debug_sup_.data(), len_off, debug_sup_.size());
        off = len_off;

        if (initial_length == 0) {
            break;
        }

        uint64_t unit_length = initial_length;
        if (initial_length == 0xffffffff) {
            if (off + 8 > debug_sup_.size()) {
                // Can't read 64-bit length. No safe way to resync.
                e.well_formed = false;
                e.error_mask |= kErrBadLength;
                e.entry_size = debug_sup_.size() - e.entry_offset;
                out.push_back(std::move(e));
                break;
            }
            unit_length = DwarfUtils::readU64(debug_sup_.data(), off, debug_sup_.size());
            e.is_dwarf64 = true;
        }

        // unit_length is the number of bytes following the initial length field(s).
        uint64_t content_start = off;
        if (unit_length > debug_sup_.size() - content_start) {
            // No safe way to resync without a valid unit_length.
            e.well_formed = false;
            e.error_mask |= kErrBadLength;
            e.entry_size = debug_sup_.size() - e.entry_offset;
            out.push_back(std::move(e));
            break;
        }
        uint64_t content_end = content_start + unit_length;

        e.entry_size = content_end - e.entry_offset;

        // Minimum header: version(2) + is_sup(1) + reserved(1) + signature(8) + NUL(1)
        if (content_end - content_start < 13) {
            e.well_formed = false;
            e.error_mask |= kErrShortHeader;
            out.push_back(std::move(e));
            off = content_end;
            continue;
        }

        if (off + 2 > content_end) break;
        e.version = DwarfUtils::readU16(debug_sup_.data(), off, debug_sup_.size());
        if (e.version != 5) {
            e.well_formed = false;
            e.error_mask |= kErrBadVersion;
        }

        // DWARF5 .debug_sup header fields:
        // u8 is_supplementary_file, u8 reserved, u64 signature, then NUL-terminated path.
        if (off + 2 > content_end) break;
        e.is_supplementary = DwarfUtils::readU8(debug_sup_.data(), off, debug_sup_.size());
        e.reserved = DwarfUtils::readU8(debug_sup_.data(), off, debug_sup_.size());
        if (e.is_supplementary != 0 && e.is_supplementary != 1) {
            e.well_formed = false;
            e.error_mask |= kErrBadIsSupplementary;
        }
        if (e.reserved != 0) {
            e.well_formed = false;
            e.error_mask |= kErrBadReserved;
        }

        if (off + 8 > content_end) break;
        e.signature = DwarfUtils::readU64(debug_sup_.data(), off, debug_sup_.size());

        // Path string, NUL-terminated, constrained to the entry.
        bool found_nul = false;
        while (off < content_end) {
            uint8_t c = debug_sup_[off++];
            if (c == 0) {
                found_nul = true;
                break;
            }
            if (!isAcceptablePathByte(c)) {
                e.path.clear();
                e.well_formed = false;
                e.error_mask |= kErrBadPathByte;
                break;
            }
            e.path.push_back(static_cast<char>(c));
            if (e.path.size() > 4096) {
                e.path.clear();
                e.well_formed = false;
                e.error_mask |= kErrPathTooLong;
                break;
            }
        }
        if (!found_nul) {
            // Malformed entry: path string must be NUL-terminated within the entry.
            e.path.clear();
            e.well_formed = false;
            e.error_mask |= kErrMissingNulPath;
        }

        out.push_back(std::move(e));

        // Skip any remaining bytes in the entry.
        off = content_end;
    }

    return out;
}

} // namespace dwarf
