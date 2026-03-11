#include "dwarf_support_matrix.hpp"

namespace dwarf {

const std::vector<SupportMatrixRow>& getSupportMatrixRows() {
    static const std::vector<SupportMatrixRow> kRows = {
        {"forms", "DW_FORM_strx,strx1..4", "supported",
         "resolves via .debug_str_offsets with contribution bounds"},
        {"forms", "DW_FORM_addrx,addrx1..4", "supported",
         "resolves via .debug_addr with bounded contribution reads"},
        {"forms", "DW_FORM_GNU_str_index/DW_FORM_GNU_addr_index", "supported",
         "GNU indexed predecessors parsed as strx/addrx aliases"},
        {"forms", "DW_FORM_loclistx", "supported",
         "DWARF v5 indexed location lists"},
        {"forms", "DW_FORM_rnglistx", "supported",
         "DWARF v5 indexed range lists"},
        {"forms", "DW_FORM_line_strp", "supported",
         "line string table lookups"},
        {"forms", "DW_FORM_strp_sup", "supported",
         "supplementary string section lookups"},
        {"forms", "DW_FORM_ref_sup4/ref_sup8", "supported",
         "supplementary references with bias"},
        {"forms", "DW_FORM_GNU_strp_alt/DW_FORM_GNU_ref_alt", "supported",
         "GNU alternate forms parsed with supplementary string/reference semantics"},
        {"forms", "DW_FORM_data16", "supported",
         "parsed as 16-byte block"},
        {"forms", "DW_FORM_implicit_const", "supported",
         "abbrev SLEB128 propagated as signed attribute value"},
        {"expr", "core stack/arithmetic/compare", "supported",
         "includes lit/reg/breg ranges, branch ops, and utility string round-trip mapping"},
        {"expr", "typed ops (*_type/convert/reinterpret)", "supported",
         "includes GNU predecessor opcodes"},
        {"expr", "indexed ops (DW_OP_addrx/DW_OP_constx)", "supported",
         "includes GNU *_index variants plus utility round-trip and operand-size decoding"},
        {"expr", "piecewise ops (piece/bit_piece)", "supported",
         "composite locations with implicit/unavailable pieces"},
        {"expr", "TLS ops", "supported",
         "DW_OP_form_tls_address and GNU equivalent"},
        {"expr", "entry/call ops", "supported",
         "entry_value/call2/call4/call_ref"},
        {"expr", "WebAssembly extension (DW_OP_WASM_location)", "supported",
         "tokenization includes kind/index annotations; concrete/symbolic evaluators return synthetic WASM location values"},
        {"expr", "GNU extensions", "partial",
         "major GNU ops supported (including known-predecessor utility operand sizing, e.g. *_index/parameter_ref/encoded_addr, with context-aware addr/offset sizes for tokenization helpers); unknown vendor ops are rejected"},
        {"split-dwarf", ".dwo discovery/loading", "supported",
         "skeleton attributes drive DWO loading"},
        {"split-dwarf", ".dwp index parsing", "supported",
         "CU/TU index parsing with bounded section extraction"},
        {"split-dwarf", "DWO debug_addr in expr eval", "supported",
         "indexed ops resolve against .debug_addr.dwo when available"},
        {"split-dwarf", "unknown DWP section ids", "partial",
         "unknown sections are skipped safely"}
    };
    return kRows;
}

} // namespace dwarf

