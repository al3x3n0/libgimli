// dwarf_dump - DWARF debugging information dump utility
// Similar to llvm-dwarfdump or readelf --debug-dump

#include "dwarf_parser.hpp"
#include "call_stack.hpp"
#include "cfi_parser.hpp"
#include "source_location.hpp"
#include "expression_compare.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
#include <getopt.h>
#include <limits>
#include <set>
#include <fstream>

using namespace dwarf;

// Helper to extract low_pc from DIE
static uint64_t getDIELowPC(const std::shared_ptr<DIE>& die) {
    if (!die) return 0;
    auto attr = die->getAttribute(DwarfAttribute::DW_AT_low_pc);
    if (!attr) return 0;
    auto addr_attr = std::dynamic_pointer_cast<AddressAttributeValue>(attr);
    if (addr_attr) return addr_attr->getAddress();
    auto uint_attr = std::dynamic_pointer_cast<UnsignedAttributeValue>(attr);
    if (uint_attr) return uint_attr->getValue();
    return 0;
}

// Command-line options
struct Options {
    std::string input_file;
    bool dump_info = false;         // -i, --debug-info
    bool dump_abbrev = false;       // -a, --debug-abbrev
    bool dump_line = false;         // -l, --debug-line
    bool dump_frames = false;       // -f, --debug-frame
    bool dump_ranges = false;       // -r, --debug-ranges
    bool dump_str = false;          // -s, --debug-str
    bool dump_loc = false;          // -o, --debug-loc
    bool dump_names = false;        // -n, --debug-names
    bool dump_macro = false;        // -m, --debug-macro
    bool dump_all = false;          // -A, --all
    bool show_form = false;         // --show-form
    bool verbose = false;           // -v, --verbose
    bool show_children = true;      // Show DIE children
    uint64_t die_offset = 0;        // --die-offset
    std::string find_name;          // --find
    bool summary = false;           // --summary
};

void printUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " [options] <elf-file>\n\n"
              << "DWARF Debugging Information Dump Utility\n\n"
              << "Subcommands:\n"
              << "  " << prog << " compare-expr <lhs-elf> <rhs-elf> [options]\n"
              << "    Compare DWARF location expressions across two binaries.\n"
              << "\n"
              << "Section Options:\n"
              << "  -i, --debug-info      Dump .debug_info section\n"
              << "  -a, --debug-abbrev    Dump .debug_abbrev section\n"
              << "  -l, --debug-line      Dump .debug_line section (line number program)\n"
              << "  -f, --debug-frame     Dump .debug_frame/.eh_frame (CFI)\n"
              << "  -r, --debug-ranges    Dump .debug_ranges/.debug_rnglists\n"
              << "  -s, --debug-str       Dump .debug_str section\n"
              << "  -o, --debug-loc       Dump .debug_loc/.debug_loclists\n"
              << "  -n, --debug-names     Dump .debug_names (accelerated lookup)\n"
              << "  -m, --debug-macro     Dump .debug_macro\n"
              << "  -A, --all             Dump all sections\n"
              << "\n"
              << "Display Options:\n"
              << "  --show-form           Show attribute form alongside value\n"
              << "  --no-children         Don't show DIE children\n"
              << "  -v, --verbose         Verbose output\n"
              << "  --summary             Show summary statistics only\n"
              << "\n"
              << "Filter Options:\n"
              << "  --die-offset=OFFSET   Dump only DIE at given offset\n"
              << "  --find=NAME           Find DIEs with given name\n"
              << "\n"
              << "Examples:\n"
              << "  " << prog << " -i program          # Dump debug_info\n"
              << "  " << prog << " -l program          # Dump line tables\n"
              << "  " << prog << " --find=main program # Find 'main' function\n"
              << "  " << prog << " -A program          # Dump everything\n"
              << "  " << prog << " compare-expr a b --format=json --max-different=0\n";
}

void printCompareExprUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " compare-expr <lhs-elf> <rhs-elf> [options]\n\n"
              << "Options:\n"
              << "  --tag=<variable|subprogram>      DIE tag to compare (default: variable)\n"
              << "  --attr=<location|frame_base>     Attribute to compare (default: location)\n"
              << "  --name=<SYMBOL>                  Compare only selected symbol name (repeatable)\n"
              << "  --name-file=<PATH>               Add symbol names from file (one per line, '#' comments)\n"
              << "  --name-prefix=<TEXT>             Keep rows whose symbol name starts with TEXT\n"
              << "  --name-contains=<TEXT>           Keep rows whose symbol name contains TEXT\n"
              << "  --key-mode=<name|linkage>        Match key mode (default: name)\n"
              << "  --strict-attr-present            Compare only pairs where attr exists on both sides\n"
              << "  --format=<text|json>             Report format (default: text)\n"
              << "  --output=<PATH>                  Write report to file instead of stdout\n"
              << "  --summary-only                   Emit only summary line/object (no rows)\n"
              << "  --only-verdict=<KIND>            Keep only verdict kind (repeatable: equivalent|different|unknown)\n"
              << "  --sort=<name|verdict>            Sort rows by name or verdict\n"
              << "  --max-rows=<N>                   Limit rows in report (0 = all)\n"
              << "  --include-missing                Include missing symbols (default)\n"
              << "  --no-include-missing             Exclude missing symbols\n"
              << "  --lhs-location-list-pc=<PC>      Select lhs location-list expression by PC\n"
              << "  --rhs-location-list-pc=<PC>      Select rhs location-list expression by PC\n"
              << "  --lhs-eval-pc=<PC>               Evaluation PC for lhs expressions\n"
              << "  --rhs-eval-pc=<PC>               Evaluation PC for rhs expressions\n"
              << "  --lhs-cfa=<VAL>                  Set lhs CFA in eval context\n"
              << "  --rhs-cfa=<VAL>                  Set rhs CFA in eval context\n"
              << "  --cfa=<VAL>                      Set CFA on both sides\n"
              << "  --lhs-frame-base=<VAL>           Set lhs frame_base in eval context\n"
              << "  --rhs-frame-base=<VAL>           Set rhs frame_base in eval context\n"
              << "  --frame-base=<VAL>               Set frame_base on both sides\n"
              << "  --lhs-tls-base=<VAL>             Set lhs tls_base in eval context\n"
              << "  --rhs-tls-base=<VAL>             Set rhs tls_base in eval context\n"
              << "  --tls-base=<VAL>                 Set tls_base on both sides\n"
              << "  --lhs-object-address=<VAL>       Set lhs object_address in eval context\n"
              << "  --rhs-object-address=<VAL>       Set rhs object_address in eval context\n"
              << "  --object-address=<VAL>           Set object_address on both sides\n"
              << "  --lhs-address-size=<N>           Set lhs address_size (1..8)\n"
              << "  --rhs-address-size=<N>           Set rhs address_size (1..8)\n"
              << "  --address-size=<N>               Set address_size on both sides (1..8)\n"
              << "  --lhs-offset-size=<N>            Set lhs offset_size (4 or 8)\n"
              << "  --rhs-offset-size=<N>            Set rhs offset_size (4 or 8)\n"
              << "  --offset-size=<N>                Set offset_size on both sides (4 or 8)\n"
              << "  --lhs-reg=<IDX:VAL>              Set lhs register value (repeatable)\n"
              << "  --rhs-reg=<IDX:VAL>              Set rhs register value (repeatable)\n"
              << "  --reg=<IDX:VAL>                  Set register value on both sides\n"
              << "  --differential-trials=<N>        Concrete differential trials (default: 64)\n"
              << "  --register-count=<N>             Synthetic register count per trial (default: 64)\n"
              << "  --seed=<VAL>                     Differential seed (default: 0x9e3779b97f4a7c15)\n"
              << "  --no-differential                Disable concrete differential search\n"
              << "  --max-different=<N>              Gate threshold (default: 0)\n"
              << "  --max-unknown=<N>                Gate threshold (default: unlimited)\n"
              << "  --max-missing-lhs=<N>            Gate threshold (default: unlimited)\n"
              << "  --max-missing-rhs=<N>            Gate threshold (default: unlimited)\n"
              << "  --fail-on-unknown                Gate fails if unknown>0\n"
              << "  --fail-on-missing                Gate fails if missing>0\n"
              << "  --report-only                    Do not enforce gate thresholds (always exit 0 on compare)\n"
              << "\n"
              << "Policy presets:\n"
              << "  --strict                         Equivalent-only gate (no different/unknown/missing)\n"
              << "  --allow-unknown                 Disable unknown failures\n"
              << "  --allow-missing                 Disable missing failures\n";
}

// Helper to format hex values
std::string hex(uint64_t val, int width = 0) {
    std::ostringstream oss;
    if (width > 0) {
        oss << "0x" << std::hex << std::setw(width) << std::setfill('0') << val;
    } else {
        oss << "0x" << std::hex << val;
    }
    return oss.str();
}

// Get tag name
std::string getTagName(DwarfTag tag) {
    switch (tag) {
        case DwarfTag::DW_TAG_compile_unit: return "DW_TAG_compile_unit";
        case DwarfTag::DW_TAG_subprogram: return "DW_TAG_subprogram";
        case DwarfTag::DW_TAG_variable: return "DW_TAG_variable";
        case DwarfTag::DW_TAG_formal_parameter: return "DW_TAG_formal_parameter";
        case DwarfTag::DW_TAG_base_type: return "DW_TAG_base_type";
        case DwarfTag::DW_TAG_pointer_type: return "DW_TAG_pointer_type";
        case DwarfTag::DW_TAG_structure_type: return "DW_TAG_structure_type";
        case DwarfTag::DW_TAG_class_type: return "DW_TAG_class_type";
        case DwarfTag::DW_TAG_member: return "DW_TAG_member";
        case DwarfTag::DW_TAG_array_type: return "DW_TAG_array_type";
        case DwarfTag::DW_TAG_typedef: return "DW_TAG_typedef";
        case DwarfTag::DW_TAG_const_type: return "DW_TAG_const_type";
        case DwarfTag::DW_TAG_volatile_type: return "DW_TAG_volatile_type";
        case DwarfTag::DW_TAG_enumeration_type: return "DW_TAG_enumeration_type";
        case DwarfTag::DW_TAG_enumerator: return "DW_TAG_enumerator";
        case DwarfTag::DW_TAG_subroutine_type: return "DW_TAG_subroutine_type";
        case DwarfTag::DW_TAG_lexical_block: return "DW_TAG_lexical_block";
        case DwarfTag::DW_TAG_inlined_subroutine: return "DW_TAG_inlined_subroutine";
        case DwarfTag::DW_TAG_union_type: return "DW_TAG_union_type";
        case DwarfTag::DW_TAG_unspecified_parameters: return "DW_TAG_unspecified_parameters";
        default: return "DW_TAG_unknown(" + std::to_string(static_cast<int>(tag)) + ")";
    }
}

// Get attribute name
std::string getAttrName(DwarfAttribute attr) {
    switch (attr) {
        case DwarfAttribute::DW_AT_name: return "DW_AT_name";
        case DwarfAttribute::DW_AT_comp_dir: return "DW_AT_comp_dir";
        case DwarfAttribute::DW_AT_producer: return "DW_AT_producer";
        case DwarfAttribute::DW_AT_language: return "DW_AT_language";
        case DwarfAttribute::DW_AT_low_pc: return "DW_AT_low_pc";
        case DwarfAttribute::DW_AT_high_pc: return "DW_AT_high_pc";
        case DwarfAttribute::DW_AT_stmt_list: return "DW_AT_stmt_list";
        case DwarfAttribute::DW_AT_type: return "DW_AT_type";
        case DwarfAttribute::DW_AT_byte_size: return "DW_AT_byte_size";
        case DwarfAttribute::DW_AT_encoding: return "DW_AT_encoding";
        case DwarfAttribute::DW_AT_location: return "DW_AT_location";
        case DwarfAttribute::DW_AT_decl_file: return "DW_AT_decl_file";
        case DwarfAttribute::DW_AT_decl_line: return "DW_AT_decl_line";
        case DwarfAttribute::DW_AT_decl_column: return "DW_AT_decl_column";
        case DwarfAttribute::DW_AT_external: return "DW_AT_external";
        case DwarfAttribute::DW_AT_frame_base: return "DW_AT_frame_base";
        case DwarfAttribute::DW_AT_linkage_name: return "DW_AT_linkage_name";
        case DwarfAttribute::DW_AT_abstract_origin: return "DW_AT_abstract_origin";
        case DwarfAttribute::DW_AT_specification: return "DW_AT_specification";
        case DwarfAttribute::DW_AT_inline: return "DW_AT_inline";
        case DwarfAttribute::DW_AT_ranges: return "DW_AT_ranges";
        case DwarfAttribute::DW_AT_call_file: return "DW_AT_call_file";
        case DwarfAttribute::DW_AT_call_line: return "DW_AT_call_line";
        case DwarfAttribute::DW_AT_call_column: return "DW_AT_call_column";
        default: return "DW_AT_unknown(" + std::to_string(static_cast<int>(attr)) + ")";
    }
}

// Dump a single DIE
void dumpDIE(const std::shared_ptr<DIE>& die, int indent, const Options& opts) {
    std::string prefix(indent * 2, ' ');

    // Print offset and tag
    std::cout << prefix << hex(die->getOffset(), 8) << ": "
              << getTagName(die->getTag());

    // Print name if available
    std::string name = die->getName();
    if (!name.empty()) {
        std::cout << " \"" << name << "\"";
    }

    std::cout << "\n";

    // Print attributes
    for (const auto& [attr, value] : die->getAttributes()) {
        std::cout << prefix << "            "
                  << getAttrName(attr) << "\t";

        if (value) {
            std::cout << value->toString();
        } else {
            std::cout << "(null)";
        }

        std::cout << "\n";
    }

    // Recursively print children
    if (opts.show_children) {
        for (const auto& child : die->getChildren()) {
            dumpDIE(child, indent + 1, opts);
        }
    }
}

// Dump debug_info section
void dumpDebugInfo(const DwarfParser& parser, const Options& opts) {
    std::cout << "\n.debug_info contents:\n\n";

    auto cus = parser.getCompilationUnits();
    for (size_t i = 0; i < cus.size(); ++i) {
        std::cout << "Compile Unit " << i << ":\n";
        dumpDIE(cus[i], 0, opts);
        std::cout << "\n";
    }
}

// Dump line number program
void dumpDebugLine(const DwarfParser& parser, const Options& opts) {
    (void)opts;
    std::cout << "\n.debug_line contents:\n\n";

    if (!parser.hasSourceLocationInfo()) {
        std::cout << "  (no line info available)\n";
        return;
    }

    auto files = parser.getAllSourceFiles();
    std::cout << "Files (" << files.size() << "):\n";
    for (size_t i = 0; i < files.size(); ++i) {
        std::cout << "  [" << i << "] " << files[i] << "\n";
    }
    std::cout << "\n";

    // Print line table for each file
    for (const auto& file : files) {
        auto lines = parser.getLinesInFile(file);
        if (lines.empty()) continue;

        // Extract just filename
        std::string filename = file;
        size_t pos = file.find_last_of('/');
        if (pos != std::string::npos) {
            filename = file.substr(pos + 1);
        }

        std::cout << "Line table for " << filename << ":\n";
        std::cout << "  Address            Line   Column   File\n";

        for (const auto& loc : lines) {
            std::cout << "  " << hex(loc.address, 16)
                      << "  " << std::setw(5) << loc.line
                      << "  " << std::setw(6) << loc.column;

            if (loc.is_stmt) std::cout << " is_stmt";
            if (loc.is_prologue_end) std::cout << " prologue_end";
            if (loc.is_epilogue_begin) std::cout << " epilogue_begin";
            if (loc.is_end_sequence) std::cout << " end_sequence";
            if (loc.discriminator > 0) std::cout << " discriminator(" << loc.discriminator << ")";

            std::cout << "\n";
        }
        std::cout << "\n";
    }
}

// Dump CFI (Call Frame Information)
void dumpDebugFrame(const DwarfParser& parser, const Options& opts) {
    (void)opts;
    std::cout << "\n.debug_frame/.eh_frame contents:\n\n";

    if (!parser.hasCFI()) {
        std::cout << "  (no CFI available)\n";
        return;
    }

    // Get functions and show unwind info for each
    auto functions = parser.getFunctions();
    std::cout << "Unwind information for " << functions.size() << " functions:\n\n";

    for (const auto& func : functions) {
        uint64_t low_pc = getDIELowPC(func);
        if (low_pc == 0) continue;

        std::string name = func->getName();
        if (name.empty()) name = "(unknown)";

        std::cout << name << " at " << hex(low_pc) << ":\n";

        UnwindInfo info = parser.getUnwindInfo(low_pc);
        if (!info.valid) {
            std::cout << "  (no unwind info)\n\n";
            continue;
        }

        // Show CFA rule
        std::cout << "  CFA: ";
        if (info.cfa.type == CFA_Type::REGISTER_OFFSET) {
            std::cout << "reg" << info.cfa.reg_num << " + " << info.cfa.offset;
        } else {
            std::cout << "(expression)";
        }
        std::cout << "\n";

        // Show register rules
        for (const auto& [reg_num, rule] : info.registers) {
            std::cout << "  reg" << reg_num << ": ";
            if (rule.type == CFA_RegRule::UNDEFINED) {
                std::cout << "undefined";
            } else if (rule.type == CFA_RegRule::SAME_VALUE) {
                std::cout << "same_value";
            } else if (rule.type == CFA_RegRule::OFFSET) {
                std::cout << "CFA" << std::showpos << rule.offset << std::noshowpos;
            } else if (rule.type == CFA_RegRule::VAL_OFFSET) {
                std::cout << "val_CFA" << std::showpos << rule.offset << std::noshowpos;
            } else if (rule.type == CFA_RegRule::REGISTER) {
                std::cout << "reg" << rule.reg_num;
            } else if (rule.type == CFA_RegRule::EXPRESSION) {
                std::cout << "(expression)";
            } else if (rule.type == CFA_RegRule::VAL_EXPRESSION) {
                std::cout << "(val_expression)";
            } else {
                std::cout << "?";
            }
            std::cout << "\n";
        }

        std::cout << "  Return address register: " << info.return_address_register << "\n\n";
    }
}

// Find DIEs by name
void findByName(const DwarfParser& parser, const std::string& name, const Options& opts) {
    std::cout << "\nSearching for \"" << name << "\":\n\n";

    // Try accelerated lookup first
    auto dies = parser.findDIEsByNameFast(name);

    if (dies.empty()) {
        std::cout << "  (no matches found)\n";
        return;
    }

    std::cout << "Found " << dies.size() << " match(es):\n\n";
    for (const auto& die : dies) {
        dumpDIE(die, 0, opts);
        std::cout << "\n";
    }
}

// Print summary statistics
void printSummary(const DwarfParser& parser) {
    std::cout << "\nDWARF Summary:\n";
    std::cout << "  File: " << parser.getFilename() << "\n";
    std::cout << "  DWARF version: " << static_cast<int>(parser.getVersion()) << "\n";
    std::cout << "  Address size: " << static_cast<int>(parser.getAddressSize()) << " bytes\n";
    std::cout << "  Compilation units: " << parser.getCompilationUnits().size() << "\n";
    std::cout << "  Functions: " << parser.getFunctions().size() << "\n";
    std::cout << "  Variables: " << parser.getVariables().size() << "\n";
    std::cout << "  Types: " << parser.getTypes().size() << "\n";
    std::cout << "  Source files: " << parser.getAllSourceFiles().size() << "\n";
    std::cout << "  Has accelerated lookup: " << (parser.hasAcceleratedLookup() ? "yes" : "no") << "\n";
    std::cout << "  Has CFI: " << (parser.hasCFI() ? "yes" : "no") << "\n";
    std::cout << "  Has macro info: " << (parser.hasMacroInfo() ? "yes" : "no") << "\n";
    std::cout << "  Has split DWARF: " << (parser.hasSplitDwarf() ? "yes" : "no") << "\n";
}

static bool parseTag(const std::string& s, DwarfTag& out) {
    if (s == "variable") {
        out = DwarfTag::DW_TAG_variable;
        return true;
    }
    if (s == "subprogram") {
        out = DwarfTag::DW_TAG_subprogram;
        return true;
    }
    return false;
}

static bool parseAttribute(const std::string& s, DwarfAttribute& out) {
    if (s == "location") {
        out = DwarfAttribute::DW_AT_location;
        return true;
    }
    if (s == "frame_base") {
        out = DwarfAttribute::DW_AT_frame_base;
        return true;
    }
    return false;
}

static bool parseUIntOption(const std::string& raw, uint64_t& out) {
    if (raw.empty()) return false;
    try {
        size_t consumed = 0;
        uint64_t v = std::stoull(raw, &consumed, 0);
        if (consumed != raw.size()) return false;
        out = v;
        return true;
    } catch (...) {
        return false;
    }
}

static bool parseRegisterAssignment(const std::string& raw, size_t& reg_index, uint64_t& reg_value) {
    auto colon = raw.find(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= raw.size()) return false;
    uint64_t idx = 0;
    uint64_t val = 0;
    if (!parseUIntOption(raw.substr(0, colon), idx)) return false;
    if (!parseUIntOption(raw.substr(colon + 1), val)) return false;
    reg_index = static_cast<size_t>(idx);
    reg_value = val;
    return true;
}

static bool parseByteSizedOption(const std::string& raw, uint8_t& out, uint8_t min_v, uint8_t max_v) {
    uint64_t parsed = 0;
    if (!parseUIntOption(raw, parsed)) return false;
    if (parsed < min_v || parsed > max_v) return false;
    out = static_cast<uint8_t>(parsed);
    return true;
}

static bool parseVerdictName(const std::string& raw, ExpressionVerificationResult::Verdict& out) {
    if (raw == "equivalent") {
        out = ExpressionVerificationResult::Verdict::EQUIVALENT;
        return true;
    }
    if (raw == "different") {
        out = ExpressionVerificationResult::Verdict::DIFFERENT;
        return true;
    }
    if (raw == "unknown") {
        out = ExpressionVerificationResult::Verdict::UNKNOWN;
        return true;
    }
    return false;
}

static std::string trim(const std::string& s) {
    size_t b = 0;
    while (b < s.size() && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
    size_t e = s.size();
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
    return s.substr(b, e - b);
}

static bool appendNamesFromFile(const std::string& path,
                                std::vector<std::string>& out_names,
                                std::string& error) {
    std::ifstream in(path);
    if (!in) {
        error = "cannot open name file '" + path + "'";
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        out_names.push_back(t);
    }
    return true;
}

static int runCompareExpr(int argc, char* argv[]) {
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printCompareExprUsage(argv[0]);
            return 0;
        }
    }

    if (argc < 4) {
        printCompareExprUsage(argv[0]);
        return 1;
    }

    std::string lhs_file = argv[2];
    std::string rhs_file = argv[3];

    CrossBinaryCompareOptions cmp_opts;
    std::vector<std::string> selected_names;
    std::string name_prefix_filter;
    std::string name_contains_filter;
    std::string format = "text";
    std::string output_path;
    std::set<ExpressionVerificationResult::Verdict> verdict_filters;
    std::string sort_mode = "name";
    bool summary_only = false;
    size_t max_rows = 0;
    CrossBinaryGateOptions gate_opts;
    bool report_only = false;

    for (int i = 4; i < argc; ++i) {
        std::string arg = argv[i];
        auto split = arg.find('=');
        auto key = (split == std::string::npos) ? arg : arg.substr(0, split);
        auto val = (split == std::string::npos) ? std::string() : arg.substr(split + 1);

        if (key == "--tag") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (!parseTag(val, cmp_opts.tag)) {
                std::cerr << "Error: invalid --tag value '" << val << "'\n";
                return 1;
            }
            continue;
        }
        if (key == "--attr") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (!parseAttribute(val, cmp_opts.attribute)) {
                std::cerr << "Error: invalid --attr value '" << val << "'\n";
                return 1;
            }
            continue;
        }
        if (key == "--name") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val.empty()) {
                std::cerr << "Error: invalid --name value (empty)\n";
                return 1;
            }
            selected_names.push_back(val);
            continue;
        }
        if (key == "--name-file") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val.empty()) {
                std::cerr << "Error: invalid --name-file value (empty)\n";
                return 1;
            }
            std::string err;
            if (!appendNamesFromFile(val, selected_names, err)) {
                std::cerr << "Error: " << err << "\n";
                return 1;
            }
            continue;
        }
        if (key == "--name-prefix") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val.empty()) {
                std::cerr << "Error: invalid --name-prefix value (empty)\n";
                return 1;
            }
            name_prefix_filter = val;
            continue;
        }
        if (key == "--name-contains") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val.empty()) {
                std::cerr << "Error: invalid --name-contains value (empty)\n";
                return 1;
            }
            name_contains_filter = val;
            continue;
        }
        if (key == "--key-mode") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val == "name") cmp_opts.key_mode = CompareKeyMode::NAME_ONLY;
            else if (val == "linkage") cmp_opts.key_mode = CompareKeyMode::LINKAGE_OR_NAME;
            else {
                std::cerr << "Error: invalid --key-mode value '" << val << "'\n";
                return 1;
            }
            continue;
        }
        if (key == "--strict-attr-present") {
            cmp_opts.require_attribute_on_both = true;
            continue;
        }
        if (key == "--format") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val != "text" && val != "json") {
                std::cerr << "Error: invalid --format value '" << val << "'\n";
                return 1;
            }
            format = val;
            continue;
        }
        if (key == "--output") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val.empty()) {
                std::cerr << "Error: invalid --output value (empty)\n";
                return 1;
            }
            output_path = val;
            continue;
        }
        if (key == "--summary-only") {
            summary_only = true;
            continue;
        }
        if (key == "--only-verdict") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            ExpressionVerificationResult::Verdict v;
            if (!parseVerdictName(val, v)) {
                std::cerr << "Error: invalid --only-verdict value '" << val
                          << "' (expected equivalent|different|unknown)\n";
                return 1;
            }
            verdict_filters.insert(v);
            continue;
        }
        if (key == "--sort") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val != "name" && val != "verdict") {
                std::cerr << "Error: invalid --sort value '" << val << "' (expected name|verdict)\n";
                return 1;
            }
            sort_mode = val;
            continue;
        }
        if (key == "--max-rows") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --max-rows value '" << val << "'\n";
                return 1;
            }
            max_rows = static_cast<size_t>(parsed);
            continue;
        }
        if (key == "--include-missing") {
            cmp_opts.include_missing = true;
            continue;
        }
        if (key == "--no-include-missing") {
            cmp_opts.include_missing = false;
            continue;
        }
        if (key == "--lhs-location-list-pc") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --lhs-location-list-pc value '" << val << "'\n";
                return 1;
            }
            cmp_opts.use_location_list_pc = true;
            cmp_opts.lhs_location_list_pc = parsed;
            continue;
        }
        if (key == "--rhs-location-list-pc") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --rhs-location-list-pc value '" << val << "'\n";
                return 1;
            }
            cmp_opts.use_location_list_pc = true;
            cmp_opts.rhs_location_list_pc = parsed;
            continue;
        }
        if (key == "--lhs-eval-pc") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --lhs-eval-pc value '" << val << "'\n";
                return 1;
            }
            cmp_opts.lhs_evaluation_pc = parsed;
            continue;
        }
        if (key == "--rhs-eval-pc") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --rhs-eval-pc value '" << val << "'\n";
                return 1;
            }
            cmp_opts.rhs_evaluation_pc = parsed;
            continue;
        }
        if (key == "--lhs-cfa" || key == "--rhs-cfa" || key == "--cfa" ||
            key == "--lhs-frame-base" || key == "--rhs-frame-base" || key == "--frame-base" ||
            key == "--lhs-tls-base" || key == "--rhs-tls-base" || key == "--tls-base" ||
            key == "--lhs-object-address" || key == "--rhs-object-address" || key == "--object-address") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid " << key << " value '" << val << "'\n";
                return 1;
            }
            if (key == "--lhs-cfa" || key == "--cfa") cmp_opts.lhs_context.cfa = parsed;
            if (key == "--rhs-cfa" || key == "--cfa") cmp_opts.rhs_context.cfa = parsed;
            if (key == "--lhs-frame-base" || key == "--frame-base") cmp_opts.lhs_context.frame_base = parsed;
            if (key == "--rhs-frame-base" || key == "--frame-base") cmp_opts.rhs_context.frame_base = parsed;
            if (key == "--lhs-tls-base" || key == "--tls-base") cmp_opts.lhs_context.tls_base = parsed;
            if (key == "--rhs-tls-base" || key == "--tls-base") cmp_opts.rhs_context.tls_base = parsed;
            if (key == "--lhs-object-address" || key == "--object-address") {
                cmp_opts.lhs_context.object_address = parsed;
            }
            if (key == "--rhs-object-address" || key == "--object-address") {
                cmp_opts.rhs_context.object_address = parsed;
            }
            continue;
        }
        if (key == "--lhs-address-size" || key == "--rhs-address-size" || key == "--address-size") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint8_t parsed = 0;
            if (!parseByteSizedOption(val, parsed, 1, 8)) {
                std::cerr << "Error: invalid " << key << " value '" << val
                          << "' (expected integer in [1,8])\n";
                return 1;
            }
            if (key == "--lhs-address-size" || key == "--address-size") cmp_opts.lhs_context.address_size = parsed;
            if (key == "--rhs-address-size" || key == "--address-size") cmp_opts.rhs_context.address_size = parsed;
            continue;
        }
        if (key == "--lhs-offset-size" || key == "--rhs-offset-size" || key == "--offset-size") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint8_t parsed = 0;
            if (!parseByteSizedOption(val, parsed, 4, 8) || (parsed != 4 && parsed != 8)) {
                std::cerr << "Error: invalid " << key << " value '" << val
                          << "' (expected 4 or 8)\n";
                return 1;
            }
            if (key == "--lhs-offset-size" || key == "--offset-size") cmp_opts.lhs_context.offset_size = parsed;
            if (key == "--rhs-offset-size" || key == "--offset-size") cmp_opts.rhs_context.offset_size = parsed;
            continue;
        }
        if (key == "--lhs-reg" || key == "--rhs-reg" || key == "--reg") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            size_t reg_index = 0;
            uint64_t reg_value = 0;
            if (!parseRegisterAssignment(val, reg_index, reg_value)) {
                std::cerr << "Error: invalid " << key << " value '" << val
                          << "' (expected IDX:VAL)\n";
                return 1;
            }
            auto apply_reg = [&](std::vector<uint64_t>& regs) {
                if (regs.size() <= reg_index) regs.resize(reg_index + 1, 0);
                regs[reg_index] = reg_value;
            };
            if (key == "--lhs-reg" || key == "--reg") apply_reg(cmp_opts.lhs_registers);
            if (key == "--rhs-reg" || key == "--reg") apply_reg(cmp_opts.rhs_registers);
            continue;
        }
        if (key == "--differential-trials") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --differential-trials value '" << val << "'\n";
                return 1;
            }
            cmp_opts.verification_options.differential_trials = static_cast<size_t>(parsed);
            continue;
        }
        if (key == "--register-count") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed) || parsed == 0) {
                std::cerr << "Error: invalid --register-count value '" << val
                          << "' (expected positive integer)\n";
                return 1;
            }
            cmp_opts.verification_options.register_count = static_cast<size_t>(parsed);
            continue;
        }
        if (key == "--seed") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --seed value '" << val << "'\n";
                return 1;
            }
            cmp_opts.verification_options.seed = parsed;
            continue;
        }
        if (key == "--no-differential") {
            cmp_opts.verification_options.run_differential = false;
            continue;
        }
        if (key == "--max-different") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --max-different value '" << val << "'\n";
                return 1;
            }
            gate_opts.max_different = static_cast<size_t>(parsed);
            continue;
        }
        if (key == "--max-unknown") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --max-unknown value '" << val << "'\n";
                return 1;
            }
            gate_opts.max_unknown = static_cast<size_t>(parsed);
            continue;
        }
        if (key == "--max-missing-lhs") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --max-missing-lhs value '" << val << "'\n";
                return 1;
            }
            gate_opts.max_missing_lhs = static_cast<size_t>(parsed);
            continue;
        }
        if (key == "--max-missing-rhs") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --max-missing-rhs value '" << val << "'\n";
                return 1;
            }
            gate_opts.max_missing_rhs = static_cast<size_t>(parsed);
            continue;
        }
        if (key == "--fail-on-unknown") {
            gate_opts.fail_on_unknown = true;
            continue;
        }
        if (key == "--fail-on-missing") {
            gate_opts.fail_on_missing = true;
            continue;
        }
        if (key == "--report-only") {
            report_only = true;
            continue;
        }
        if (key == "--strict") {
            gate_opts.max_different = 0;
            gate_opts.max_unknown = 0;
            gate_opts.max_missing_lhs = 0;
            gate_opts.max_missing_rhs = 0;
            gate_opts.fail_on_unknown = true;
            gate_opts.fail_on_missing = true;
            continue;
        }
        if (key == "--allow-unknown") {
            gate_opts.fail_on_unknown = false;
            gate_opts.max_unknown = std::numeric_limits<size_t>::max();
            continue;
        }
        if (key == "--allow-missing") {
            gate_opts.fail_on_missing = false;
            gate_opts.max_missing_lhs = std::numeric_limits<size_t>::max();
            gate_opts.max_missing_rhs = std::numeric_limits<size_t>::max();
            continue;
        }
        std::cerr << "Error: unknown compare-expr option '" << arg << "'\n";
        return 1;
    }

    DwarfParser lhs(lhs_file);
    DwarfParser rhs(rhs_file);
    if (!lhs.load()) {
        std::cerr << "Error: failed to load lhs ELF '" << lhs_file << "'\n";
        return 1;
    }
    if (!rhs.load()) {
        std::cerr << "Error: failed to load rhs ELF '" << rhs_file << "'\n";
        return 1;
    }

    CrossBinaryExpressionComparator cmp;
    std::vector<NamedExpressionComparison> comparisons;
    if (!selected_names.empty()) {
        std::set<std::string> seen;
        for (const auto& name : selected_names) {
            if (!seen.insert(name).second) continue;
            comparisons.push_back(cmp.compareNamedInParsers(lhs, rhs, name, cmp_opts));
        }
    } else {
        comparisons = cmp.compareParsersByName(lhs, rhs, cmp_opts);
    }

    if (!verdict_filters.empty()) {
        std::vector<NamedExpressionComparison> filtered;
        filtered.reserve(comparisons.size());
        for (const auto& row : comparisons) {
            if (verdict_filters.count(row.verification.verdict) != 0) {
                filtered.push_back(row);
            }
        }
        comparisons.swap(filtered);
    }

    if (!name_prefix_filter.empty() || !name_contains_filter.empty()) {
        std::vector<NamedExpressionComparison> filtered;
        filtered.reserve(comparisons.size());
        for (const auto& row : comparisons) {
            bool ok = true;
            if (!name_prefix_filter.empty()) {
                ok = row.name.rfind(name_prefix_filter, 0) == 0;
            }
            if (ok && !name_contains_filter.empty()) {
                ok = row.name.find(name_contains_filter) != std::string::npos;
            }
            if (ok) filtered.push_back(row);
        }
        comparisons.swap(filtered);
    }

    if (sort_mode == "verdict") {
        auto rank = [](ExpressionVerificationResult::Verdict v) {
            switch (v) {
                case ExpressionVerificationResult::Verdict::DIFFERENT: return 0;
                case ExpressionVerificationResult::Verdict::UNKNOWN: return 1;
                case ExpressionVerificationResult::Verdict::EQUIVALENT: return 2;
            }
            return 3;
        };
        std::sort(comparisons.begin(), comparisons.end(),
                  [&](const NamedExpressionComparison& a, const NamedExpressionComparison& b) {
                      int ar = rank(a.verification.verdict);
                      int br = rank(b.verification.verdict);
                      if (ar != br) return ar < br;
                      return a.name < b.name;
                  });
    } else {
        std::sort(comparisons.begin(), comparisons.end(),
                  [](const NamedExpressionComparison& a, const NamedExpressionComparison& b) {
                      return a.name < b.name;
                  });
    }

    std::string report;
    if (summary_only) {
        auto s = cmp.summarize(comparisons);
        if (format == "json") {
            std::ostringstream oss;
            oss << "{"
                << "\"summary\":{"
                << "\"total\":" << s.total << ","
                << "\"equivalent\":" << s.equivalent << ","
                << "\"different\":" << s.different << ","
                << "\"unknown\":" << s.unknown << ","
                << "\"missing_lhs\":" << s.missing_lhs << ","
                << "\"missing_rhs\":" << s.missing_rhs
                << "}"
                << "}\n";
            report = oss.str();
        } else {
            std::ostringstream oss;
            oss << "summary total=" << s.total
                << " equivalent=" << s.equivalent
                << " different=" << s.different
                << " unknown=" << s.unknown
                << " missing_lhs=" << s.missing_lhs
                << " missing_rhs=" << s.missing_rhs
                << "\n";
            report = oss.str();
        }
    } else if (format == "json") {
        report = cmp.renderJsonReport(comparisons, max_rows) + "\n";
    } else {
        report = cmp.renderTextReport(comparisons, max_rows);
    }

    if (!output_path.empty()) {
        std::ofstream out(output_path);
        if (!out) {
            std::cerr << "Error: cannot open output file '" << output_path << "'\n";
            return 1;
        }
        out << report;
    } else {
        std::cout << report;
    }

    auto gate = cmp.evaluateGate(comparisons, gate_opts);
    if (!report_only && !gate.pass) {
        std::cerr << "compare-expr gate FAILED: " << gate.reason << "\n";
        return 2;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc >= 2 && std::string(argv[1]) == "compare-expr") {
        return runCompareExpr(argc, argv);
    }

    Options opts;

    static struct option long_options[] = {
        {"debug-info", no_argument, nullptr, 'i'},
        {"debug-abbrev", no_argument, nullptr, 'a'},
        {"debug-line", no_argument, nullptr, 'l'},
        {"debug-frame", no_argument, nullptr, 'f'},
        {"debug-ranges", no_argument, nullptr, 'r'},
        {"debug-str", no_argument, nullptr, 's'},
        {"debug-loc", no_argument, nullptr, 'o'},
        {"debug-names", no_argument, nullptr, 'n'},
        {"debug-macro", no_argument, nullptr, 'm'},
        {"all", no_argument, nullptr, 'A'},
        {"verbose", no_argument, nullptr, 'v'},
        {"show-form", no_argument, nullptr, 1001},
        {"no-children", no_argument, nullptr, 1002},
        {"die-offset", required_argument, nullptr, 1003},
        {"find", required_argument, nullptr, 1004},
        {"summary", no_argument, nullptr, 1005},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "ialfrsonmAvh", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'i': opts.dump_info = true; break;
            case 'a': opts.dump_abbrev = true; break;
            case 'l': opts.dump_line = true; break;
            case 'f': opts.dump_frames = true; break;
            case 'r': opts.dump_ranges = true; break;
            case 's': opts.dump_str = true; break;
            case 'o': opts.dump_loc = true; break;
            case 'n': opts.dump_names = true; break;
            case 'm': opts.dump_macro = true; break;
            case 'A': opts.dump_all = true; break;
            case 'v': opts.verbose = true; break;
            case 1001: opts.show_form = true; break;
            case 1002: opts.show_children = false; break;
            case 1003: {
                uint64_t parsed = 0;
                if (!parseUIntOption(optarg ? std::string(optarg) : std::string(), parsed)) {
                    std::cerr << "Error: invalid --die-offset value '" << (optarg ? optarg : "") << "'\n";
                    return 1;
                }
                opts.die_offset = parsed;
                break;
            }
            case 1004: opts.find_name = optarg; break;
            case 1005: opts.summary = true; break;
            case 'h':
            default:
                printUsage(argv[0]);
                return opt == 'h' ? 0 : 1;
        }
    }

    if (optind >= argc) {
        std::cerr << "Error: No input file specified\n";
        printUsage(argv[0]);
        return 1;
    }

    opts.input_file = argv[optind];

    // If no specific section requested, default to summary
    if (!opts.dump_info && !opts.dump_abbrev && !opts.dump_line &&
        !opts.dump_frames && !opts.dump_ranges && !opts.dump_str &&
        !opts.dump_loc && !opts.dump_names && !opts.dump_macro &&
        !opts.dump_all && opts.find_name.empty() && opts.die_offset == 0) {
        opts.summary = true;
    }

    // Load DWARF info
    DwarfParser parser(opts.input_file);
    if (!opts.verbose) {
        // Suppress debug output
        std::cerr.setstate(std::ios_base::failbit);
    }

    if (!parser.load()) {
        std::cerr.clear();
        std::cerr << "Error: Failed to load DWARF info from " << opts.input_file << "\n";
        return 1;
    }

    std::cerr.clear();

    // Process options
    if (opts.summary || opts.dump_all) {
        printSummary(parser);
    }

    if (!opts.find_name.empty()) {
        findByName(parser, opts.find_name, opts);
    }

    if (opts.die_offset != 0) {
        auto die = parser.findDIEByOffset(opts.die_offset);
        if (die) {
            std::cout << "\nDIE at offset " << hex(opts.die_offset) << ":\n\n";
            dumpDIE(die, 0, opts);
        } else {
            std::cout << "\nNo DIE found at offset " << hex(opts.die_offset) << "\n";
        }
    }

    if (opts.dump_info || opts.dump_all) {
        dumpDebugInfo(parser, opts);
    }

    if (opts.dump_line || opts.dump_all) {
        dumpDebugLine(parser, opts);
    }

    if (opts.dump_frames || opts.dump_all) {
        dumpDebugFrame(parser, opts);
    }

    // Other sections would be implemented similarly...

    return 0;
}
