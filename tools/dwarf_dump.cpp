// dwarf_dump - DWARF debugging information dump utility
// Similar to llvm-dwarfdump or readelf --debug-dump

#include "dwarf_parser.hpp"
#include "call_stack.hpp"
#include "cfi_parser.hpp"
#include "source_location.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <cstring>
#include <getopt.h>

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
              << "  " << prog << " -A program          # Dump everything\n";
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

int main(int argc, char* argv[]) {
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
            case 1003: opts.die_offset = std::stoull(optarg, nullptr, 0); break;
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
