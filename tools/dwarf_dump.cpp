// dwarf_dump - DWARF debugging information dump utility
// Similar to llvm-dwarfdump or readelf --debug-dump

#include "dwarf_parser.hpp"
#include "call_stack.hpp"
#include "cfi_parser.hpp"
#include "source_location.hpp"
#include "expression_compare.hpp"
#include "cfi_symbolic.hpp"
#include "dwarf_compare.hpp"
#include "dwarf_support_matrix.hpp"
#include "dwarf_utils.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <algorithm>
#include <deque>
#include <cstring>
#include <getopt.h>
#include <limits>
#include <map>
#include <set>
#include <fstream>
#include <array>
#include <optional>

using namespace dwarf;

static std::string formatCompactHexBytes(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << "0x";
    for (uint8_t byte : bytes) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(byte);
    }
    return oss.str();
}

static std::string formatCompactU32HexList(const std::vector<uint32_t>& values) {
    std::ostringstream oss;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i != 0) oss << ";";
        oss << "0x" << std::hex << values[i] << std::dec;
    }
    return oss.str();
}

struct ExpressionGapTelemetry {
    size_t expression_site_count = 0;
    size_t expression_op_count = 0;
    size_t unknown_opcode_sites = 0;
    size_t unknown_vendor_opcode_sites = 0;
    std::map<uint8_t, uint64_t> unknown_opcode_histogram;
    std::map<std::string, uint64_t> unknown_opcode_attribute_histogram;
};

struct VendorOpcodeAggregate {
    uint8_t opcode = 0;
    uint64_t total_occurrences = 0;
    uint64_t expression_sites = 0;
    uint64_t standalone_expression_sites = 0;
    std::set<std::string> sample_files;
    std::set<std::string> producers;
    std::map<std::string, uint64_t> attribute_histogram;
    std::map<std::string, uint64_t> pattern_histogram;
    std::string selection_blocker;
};

struct VendorOpcodeTriageReport {
    size_t input_files = 0;
    size_t loaded_files = 0;
    size_t failed_files = 0;
    size_t expression_site_count = 0;
    size_t vendor_expression_site_count = 0;
    size_t vendor_opcode_occurrences = 0;
    std::vector<std::string> load_errors;
    std::map<uint8_t, VendorOpcodeAggregate> aggregates;
    bool has_selection = false;
    uint8_t selected_opcode = 0;
    std::string selected_profile_name;
    std::string selection_status = "no_safe_family_selected";
    std::string selection_reason = "no_vendor_opcodes_observed";
};

static bool isUnknownExpressionOpcode(uint8_t opcode);

static bool isUnknownVendorExpressionOpcode(uint8_t opcode) {
    return opcode >= 0xe0 && isUnknownExpressionOpcode(opcode);
}

static std::string formatCompactHexByte(uint8_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setfill('0') << std::setw(2)
        << static_cast<unsigned>(value) << std::dec;
    return oss.str();
}

static std::string getDIECUProducer(const std::shared_ptr<DIE>& cu) {
    if (!cu) return {};
    auto attr = cu->getAttribute(DwarfAttribute::DW_AT_producer);
    auto s = std::dynamic_pointer_cast<StringAttributeValue>(attr);
    return s ? s->getValue() : std::string();
}

static std::string summarizeTopStringHistogram(const std::map<std::string, uint64_t>& hist,
                                               size_t limit) {
    std::vector<std::pair<std::string, uint64_t>> items(hist.begin(), hist.end());
    std::sort(items.begin(), items.end(),
              [](const auto& a, const auto& b) {
                  if (a.second != b.second) return a.second > b.second;
                  return a.first < b.first;
              });
    std::ostringstream oss;
    const size_t count = std::min<size_t>(items.size(), limit);
    for (size_t i = 0; i < count; ++i) {
        if (i != 0) oss << ";";
        oss << items[i].first << ":" << items[i].second;
    }
    return oss.str();
}

static std::vector<std::pair<uint8_t, VendorOpcodeAggregate*>> rankedVendorOpcodeAggregates(
    VendorOpcodeTriageReport& report) {
    std::vector<std::pair<uint8_t, VendorOpcodeAggregate*>> ranked;
    ranked.reserve(report.aggregates.size());
    for (auto& kv : report.aggregates) {
        ranked.push_back({kv.first, &kv.second});
    }
    std::sort(ranked.begin(), ranked.end(),
              [](const auto& a, const auto& b) {
                  if (a.second->total_occurrences != b.second->total_occurrences) {
                      return a.second->total_occurrences > b.second->total_occurrences;
                  }
                  if (a.second->expression_sites != b.second->expression_sites) {
                      return a.second->expression_sites > b.second->expression_sites;
                  }
                  return a.first < b.first;
              });
    return ranked;
}

static void scanExpressionForVendorTriage(const std::vector<uint8_t>& expr,
                                          const std::string& attr_name,
                                          const std::string& file_path,
                                          const std::string& producer,
                                          VendorOpcodeTriageReport& out) {
    if (expr.empty()) return;
    ++out.expression_site_count;

    size_t off = 0;
    size_t vendor_unknown_in_expr = 0;
    std::map<uint8_t, uint64_t> occurrences_by_opcode;
    while (off < expr.size()) {
        uint8_t opcode = expr[off++];
        if (isUnknownVendorExpressionOpcode(opcode)) {
            ++vendor_unknown_in_expr;
            occurrences_by_opcode[opcode] += 1;
        }
        const size_t opsz = DwarfUtils::getOperationSize(static_cast<DwarfOp>(opcode),
                                                         expr.data(),
                                                         off,
                                                         expr.size());
        off += std::min(opsz, expr.size() - off);
    }

    if (occurrences_by_opcode.empty()) return;

    ++out.vendor_expression_site_count;
    out.vendor_opcode_occurrences += vendor_unknown_in_expr;
    const std::string expr_hex = formatCompactHexBytes(expr);
    const std::string producer_name = producer.empty() ? "<unknown>" : producer;

    for (const auto& kv : occurrences_by_opcode) {
        VendorOpcodeAggregate& agg = out.aggregates[kv.first];
        agg.opcode = kv.first;
        agg.total_occurrences += kv.second;
        agg.expression_sites += 1;
        if (vendor_unknown_in_expr == 1) {
            agg.standalone_expression_sites += 1;
        }
        agg.sample_files.insert(file_path);
        agg.producers.insert(producer_name);
        agg.attribute_histogram[attr_name] += 1;
        agg.pattern_histogram[expr_hex] += 1;
    }
}

static void collectVendorOpcodeTriageFromDIE(const std::shared_ptr<DIE>& die,
                                             const std::string& file_path,
                                             const std::string& producer,
                                             VendorOpcodeTriageReport& out) {
    if (!die) return;
    for (const auto& kv : die->getAttributes()) {
        const auto attr = kv.first;
        const auto& value = kv.second;
        const std::string attr_name = DwarfUtils::attributeToString(attr);
        if (auto loc = std::dynamic_pointer_cast<LocationAttributeValue>(value)) {
            if (loc->getLocationType() == LocationAttributeValue::LocationType::EXPRESSION) {
                scanExpressionForVendorTriage(loc->getData(), attr_name, file_path, producer, out);
            } else if (loc->getLocationType() == LocationAttributeValue::LocationType::LIST) {
                for (const auto& entry : loc->getEntries()) {
                    scanExpressionForVendorTriage(entry.expression, attr_name, file_path, producer, out);
                }
            }
        } else if (auto expr = std::dynamic_pointer_cast<ExpressionAttributeValue>(value)) {
            scanExpressionForVendorTriage(expr->getExpression(), attr_name, file_path, producer, out);
        } else if (auto preserved = DwarfUtils::decodePreservedPayloadAttribute(attr, value)) {
            scanExpressionForVendorTriage(preserved->bytes, attr_name, file_path, producer, out);
        }
    }
    for (const auto& child : die->getChildren()) {
        collectVendorOpcodeTriageFromDIE(child, file_path, producer, out);
    }
}

static VendorOpcodeTriageReport collectVendorOpcodeTriage(const std::vector<std::string>& input_files,
                                                          bool verbose) {
    VendorOpcodeTriageReport report;
    report.input_files = input_files.size();
    for (const auto& path : input_files) {
        DwarfParser parser(path);
        parser.setVerbose(verbose);
        if (!parser.load()) {
            ++report.failed_files;
            report.load_errors.push_back(path);
            continue;
        }
        ++report.loaded_files;
        for (const auto& cu : parser.getCompilationUnits()) {
            collectVendorOpcodeTriageFromDIE(cu, path, getDIECUProducer(cu), report);
        }
    }

    if (report.aggregates.empty()) {
        report.selection_status = "no_safe_family_selected";
        report.selection_reason = report.loaded_files == 0
            ? "no_loadable_inputs"
            : "no_vendor_opcodes_observed";
        return report;
    }

    auto ranked = rankedVendorOpcodeAggregates(report);
    for (auto& ranked_item : ranked) {
        VendorOpcodeAggregate& agg = *ranked_item.second;
        if (agg.sample_files.size() < 2) {
            agg.selection_blocker = "insufficient_independent_samples";
            continue;
        }
        agg.selection_blocker = "no_profiled_semantics_mapping";
    }

    report.selection_status = "no_safe_family_selected";
    report.selection_reason = ranked.front().second->selection_blocker.empty()
        ? "no_vendor_opcodes_observed"
        : ranked.front().second->selection_blocker;
    return report;
}

static std::string renderVendorOpcodeTriageText(VendorOpcodeTriageReport& report) {
    std::ostringstream out;
    out << "Vendor Expression Opcode Triage\n";
    out << "kind=vendor_expression_triage\n";
    out << "schema_version=1\n";
    out << "input_files=" << report.input_files << "\n";
    out << "loaded_files=" << report.loaded_files << "\n";
    out << "failed_files=" << report.failed_files << "\n";
    out << "expression_site_count=" << report.expression_site_count << "\n";
    out << "vendor_expression_site_count=" << report.vendor_expression_site_count << "\n";
    out << "vendor_opcode_occurrences=" << report.vendor_opcode_occurrences << "\n";
    out << "selection_status=" << report.selection_status << "\n";
    out << "selection_reason=" << report.selection_reason << "\n";
    if (report.has_selection) {
        out << "selected_profile=" << report.selected_profile_name << "\n";
        out << "selected_opcode=" << formatCompactHexByte(report.selected_opcode) << "\n";
    } else {
        out << "selected_profile=\n";
        out << "selected_opcode=\n";
    }
    if (!report.load_errors.empty()) {
        out << "load_errors=";
        for (size_t i = 0; i < report.load_errors.size(); ++i) {
            if (i != 0) out << ";";
            out << report.load_errors[i];
        }
        out << "\n";
    }
    auto ranked = rankedVendorOpcodeAggregates(report);
    for (const auto& ranked_item : ranked) {
        const VendorOpcodeAggregate& agg = *ranked_item.second;
        std::map<std::string, uint64_t> sample_files_hist;
        for (const auto& file : agg.sample_files) sample_files_hist[file] = 1;
        std::map<std::string, uint64_t> producers_hist;
        for (const auto& producer : agg.producers) producers_hist[producer] = 1;
        out << "opcode=" << formatCompactHexByte(agg.opcode)
            << " total_occurrences=" << agg.total_occurrences
            << " expression_sites=" << agg.expression_sites
            << " independent_sample_count=" << agg.sample_files.size()
            << " producer_count=" << agg.producers.size()
            << " standalone_expression_sites=" << agg.standalone_expression_sites
            << " top_attributes=" << summarizeTopStringHistogram(agg.attribute_histogram, 4)
            << " top_patterns=" << summarizeTopStringHistogram(agg.pattern_histogram, 3)
            << " sample_files=" << summarizeTopStringHistogram(sample_files_hist, 4)
            << " producers=" << summarizeTopStringHistogram(producers_hist, 4)
            << " selection_blocker=" << agg.selection_blocker
            << "\n";
    }
    return out.str();
}

static std::string renderVendorOpcodeTriageJson(VendorOpcodeTriageReport& report, int schema_version) {
    auto esc = [](const std::string& s) {
        std::string out;
        out.reserve(s.size() + 8);
        for (char c : s) {
            switch (c) {
                case '\\': out += "\\\\"; break;
                case '"': out += "\\\""; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default: out += c; break;
            }
        }
        return out;
    };

    auto renderStringArray = [&](const std::set<std::string>& values) {
        std::ostringstream out;
        out << "[";
        size_t index = 0;
        for (const auto& value : values) {
            if (index++ != 0) out << ",";
            out << "\"" << esc(value) << "\"";
        }
        out << "]";
        return out.str();
    };

    auto renderStringHistogram = [&](const std::map<std::string, uint64_t>& hist) {
        std::vector<std::pair<std::string, uint64_t>> items(hist.begin(), hist.end());
        std::sort(items.begin(), items.end(),
                  [](const auto& a, const auto& b) {
                      if (a.second != b.second) return a.second > b.second;
                      return a.first < b.first;
                  });
        std::ostringstream out;
        out << "[";
        for (size_t i = 0; i < items.size(); ++i) {
            if (i != 0) out << ",";
            out << "{"
                << "\"name\":\"" << esc(items[i].first) << "\","
                << "\"count\":" << items[i].second
                << "}";
        }
        out << "]";
        return out.str();
    };

    std::ostringstream out;
    out << "{";
    out << "\"kind\":\"vendor_expression_triage\",";
    out << "\"schema_version\":" << schema_version << ",";
    out << "\"input_files\":" << report.input_files << ",";
    out << "\"loaded_files\":" << report.loaded_files << ",";
    out << "\"failed_files\":" << report.failed_files << ",";
    out << "\"expression_site_count\":" << report.expression_site_count << ",";
    out << "\"vendor_expression_site_count\":" << report.vendor_expression_site_count << ",";
    out << "\"vendor_opcode_occurrences\":" << report.vendor_opcode_occurrences << ",";
    out << "\"selection_status\":\"" << esc(report.selection_status) << "\",";
    out << "\"selection_reason\":\"" << esc(report.selection_reason) << "\",";
    if (report.has_selection) {
        out << "\"selected_profile\":\"" << esc(report.selected_profile_name) << "\",";
        out << "\"selected_opcode\":" << static_cast<uint64_t>(report.selected_opcode) << ",";
    } else {
        out << "\"selected_profile\":null,";
        out << "\"selected_opcode\":null,";
    }
    out << "\"load_errors\":[";
    for (size_t i = 0; i < report.load_errors.size(); ++i) {
        if (i != 0) out << ",";
        out << "\"" << esc(report.load_errors[i]) << "\"";
    }
    out << "],";
    out << "\"ranked_vendor_opcodes\":[";
    auto ranked = rankedVendorOpcodeAggregates(report);
    for (size_t i = 0; i < ranked.size(); ++i) {
        if (i != 0) out << ",";
        const VendorOpcodeAggregate& agg = *ranked[i].second;
        out << "{"
            << "\"opcode\":" << static_cast<uint64_t>(agg.opcode) << ","
            << "\"total_occurrences\":" << agg.total_occurrences << ","
            << "\"expression_sites\":" << agg.expression_sites << ","
            << "\"independent_sample_count\":" << agg.sample_files.size() << ","
            << "\"producer_count\":" << agg.producers.size() << ","
            << "\"standalone_expression_sites\":" << agg.standalone_expression_sites << ","
            << "\"selection_blocker\":\"" << esc(agg.selection_blocker) << "\","
            << "\"sample_files\":" << renderStringArray(agg.sample_files) << ","
            << "\"producers\":" << renderStringArray(agg.producers) << ","
            << "\"attribute_histogram\":" << renderStringHistogram(agg.attribute_histogram) << ","
            << "\"pattern_histogram\":" << renderStringHistogram(agg.pattern_histogram)
            << "}";
    }
    out << "]";
    out << "}";
    return out.str();
}

static bool isUnknownExpressionOpcode(uint8_t opcode) {
    const std::string name = DwarfUtils::operationToString(static_cast<DwarfOp>(opcode));
    return name.rfind("DW_OP_unknown_", 0) == 0;
}

static void scanExpressionForTelemetry(const std::vector<uint8_t>& expr,
                                       const std::string& attr_name,
                                       ExpressionGapTelemetry& out) {
    if (expr.empty()) return;
    ++out.expression_site_count;
    bool site_has_unknown = false;
    bool site_has_unknown_vendor = false;
    size_t off = 0;
    while (off < expr.size()) {
        uint8_t opcode = expr[off++];
        ++out.expression_op_count;
        if (isUnknownExpressionOpcode(opcode)) {
            site_has_unknown = true;
            if (opcode >= 0xe0) site_has_unknown_vendor = true;
            out.unknown_opcode_histogram[opcode] += 1;
            out.unknown_opcode_attribute_histogram[attr_name] += 1;
        }
        const size_t opsz = DwarfUtils::getOperationSize(static_cast<DwarfOp>(opcode),
                                                         expr.data(),
                                                         off,
                                                         expr.size());
        off += std::min(opsz, expr.size() - off);
    }
    if (site_has_unknown) ++out.unknown_opcode_sites;
    if (site_has_unknown_vendor) ++out.unknown_vendor_opcode_sites;
}

static void collectExpressionGapTelemetryFromDIE(const std::shared_ptr<DIE>& die,
                                                 ExpressionGapTelemetry& out) {
    if (!die) return;
    for (const auto& kv : die->getAttributes()) {
        const auto attr = kv.first;
        const auto& value = kv.second;
        const std::string attr_name = DwarfUtils::attributeToString(attr);
        if (auto loc = std::dynamic_pointer_cast<LocationAttributeValue>(value)) {
            if (loc->getLocationType() == LocationAttributeValue::LocationType::EXPRESSION) {
                scanExpressionForTelemetry(loc->getData(), attr_name, out);
            } else if (loc->getLocationType() == LocationAttributeValue::LocationType::LIST) {
                for (const auto& entry : loc->getEntries()) {
                    scanExpressionForTelemetry(entry.expression, attr_name, out);
                }
            }
        } else if (auto expr = std::dynamic_pointer_cast<ExpressionAttributeValue>(value)) {
            scanExpressionForTelemetry(expr->getExpression(), attr_name, out);
        } else if (auto preserved = DwarfUtils::decodePreservedPayloadAttribute(attr, value)) {
            scanExpressionForTelemetry(preserved->bytes, attr_name, out);
        }
    }
    for (const auto& child : die->getChildren()) {
        collectExpressionGapTelemetryFromDIE(child, out);
    }
}

static ExpressionGapTelemetry collectExpressionGapTelemetry(const DwarfParser& parser) {
    ExpressionGapTelemetry out;
    for (const auto& cu : parser.getCompilationUnits()) {
        collectExpressionGapTelemetryFromDIE(cu, out);
    }
    return out;
}

static std::optional<DwarfUtils::DecodedPayloadSemantics> decodeSemanticAttributeForDump(
    DwarfAttribute attr, const std::shared_ptr<AttributeValue>& value) {
    switch (attr) {
        case DwarfAttribute::DW_AT_call_value:
        case DwarfAttribute::DW_AT_call_parameter:
            return DwarfUtils::decodeCallSitePayloadAttribute(attr, value);
        case DwarfAttribute::DW_AT_discr_list:
            return DwarfUtils::decodeDiscriminantPayloadAttribute(attr, value);
        default:
            return std::nullopt;
    }
}

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
    std::string dwp_file;           // --dwp
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
    bool show_support = false;      // --show-support
    std::string output_format = "text"; // --format (for --show-support in main mode)
    int support_schema_version = 1; // --schema-version for --show-support json
    bool support_schema_version_set = false;
};

void printUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " [options] <elf-file>\n\n"
              << "DWARF Debugging Information Dump Utility\n\n"
              << "Subcommands:\n"
              << "  " << prog << " compare-expr <lhs-elf> <rhs-elf> [options]\n"
              << "    Compare DWARF location expressions across two binaries.\n"
              << "  " << prog << " compare-cfi <lhs-elf> <rhs-elf> [options]\n"
              << "    Compare unwind/CFI semantics across two binaries.\n"
              << "  " << prog << " verify-reloc <elf> [options]\n"
              << "    Verify relocation/index integrity of DWARF references.\n"
              << "  " << prog << " triage-vendor-ops <elf> [<elf> ...] [options]\n"
              << "    Rank unsupported non-GNU vendor expression opcodes across a local corpus.\n"
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
              << "  --show-support        Show DWARF v5/split-DWARF support matrix\n"
              << "  --format=<text|json>  Output format for --show-support in main mode\n"
              << "  --schema-version=<N>  JSON schema version for --show-support (1|2)\n"
              << "  --no-children         Don't show DIE children\n"
              << "  -v, --verbose         Verbose output\n"
              << "  --summary             Show summary statistics only\n"
              << "\n"
              << "Filter Options:\n"
              << "  --die-offset=OFFSET   Dump only DIE at given offset\n"
              << "  --find=NAME           Find DIEs with given name\n"
              << "  --dwp=PATH            Load .dwp package for split-DWARF lookups\n"
              << "\n"
              << "Examples:\n"
              << "  " << prog << " -i program          # Dump debug_info\n"
              << "  " << prog << " -l program          # Dump line tables\n"
              << "  " << prog << " --find=main program # Find 'main' function\n"
              << "  " << prog << " -A program          # Dump everything\n"
              << "  " << prog << " compare-expr a b --format=json --max-different=0\n"
              << "  " << prog << " verify-reloc program --format=json\n"
              << "  " << prog << " triage-vendor-ops a.o b.o --format=json\n";
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
              << "  --reloc-check                    Enable relocation/index sanity checks (optional)\n"
              << "  --normalize-loc                  Apply semantic normalization before compare and coalesce equivalent location-list entries\n"
              << "  --normalization-policy=<off|symbolic-canonical>  Canonicalize expressions before compare (default: symbolic-canonical)\n"
              << "  --range-aware                    Compare location lists over PC ranges/coverage\n"
              << "  --bolt-remap=<auto|off>          Reconcile BOLT-style code-address relocation (default: auto)\n"
              << "  --bolt-map=<file>                Load explicit old->new address remap (lines: <old_hex> <new_hex>)\n"
              << "  --vendor-op-profile=<P>          Non-GNU vendor opcode profile: none|synthetic-v1 (default: none)\n"
              << "  --verify-features=<LIST>         Enable compare checks: section-reloc,loc-normalize,range-aware (special: all,none)\n"
              << "  --emit-profile-only              Emit only active verification/gate profile\n"
              << "  --emit-solver-summary-only       Emit only solver/backend bucket summary\n"
              << "  --format=<text|json>             Report format (default: text)\n"
              << "  --schema-version=<N>             JSON schema version (currently supports 1)\n"
              << "  --output=<PATH>                  Write report to file instead of stdout\n"
              << "  --summary-only                   Emit only summary line/object (no rows)\n"
              << "  --verify-profile=<P>             Verification preset: off|minimal|default|full|strict|balanced|lenient\n"
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
              << "  --solver-timeout-ms=<N>          Z3 timeout per expression check in milliseconds (0 = no timeout)\n"
              << "  --max-different=<N>              Gate threshold (default: 0)\n"
              << "  --max-unknown=<N>                Gate threshold (default: unlimited)\n"
              << "  --max-missing-lhs=<N>            Gate threshold (default: unlimited)\n"
              << "  --max-missing-rhs=<N>            Gate threshold (default: unlimited)\n"
              << "  --fail-on-unknown                Gate fails if unknown>0\n"
              << "  --fail-on-missing                Gate fails if missing>0\n"
              << "  --fail-on-solver-result=<K>      Gate fails if any row has solver_result K (repeatable)\n"
              << "  --fail-on-verifier-backend=<K>   Gate fails if any row has verifier_backend K (repeatable)\n"
              << "  --min-equivalent-coverage=<R>    Range-aware min equivalent coverage ratio [0,1]\n"
              << "  --max-different-coverage=<R>     Range-aware max different coverage ratio [0,1]\n"
              << "  --fail-on-uncovered              Range-aware gate fails if uncovered segments exist\n"
              << "  --report-only                    Do not enforce gate thresholds (always exit 0 on compare)\n"
              << "  --gate-profile=<P>               Gate preset: strict|balanced|lenient\n"
              << "\n"
              << "Policy presets:\n"
              << "  --strict                         Equivalent-only gate (no different/unknown/missing)\n"
              << "  --allow-unknown                 Disable unknown failures\n"
              << "  --allow-missing                 Disable missing failures\n";
}

void printCompareCFIUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " compare-cfi <lhs-elf> <rhs-elf> [options]\n\n"
              << "Modes:\n"
              << "  FDE interval mode (default): compare by FDE index over code interval.\n"
              << "  All-FDE mode: use --all-fdes to compare all index-aligned FDE pairs.\n"
              << "  PC mode: provide both --lhs-pc and --rhs-pc to compare one state.\n"
              << "\n"
              << "Options:\n"
              << "  --lhs-fde-index=<N>              LHS FDE index (default: 0)\n"
              << "  --rhs-fde-index=<N>              RHS FDE index (default: 0)\n"
              << "  --all-fdes                       Compare all index-aligned FDE pairs\n"
              << "  --pair-by=<index|start-pc|range> Pairing strategy in --all-fdes mode (default: index)\n"
              << "  --lhs-pc=<PC>                    LHS PC for state compare mode\n"
              << "  --rhs-pc=<PC>                    RHS PC for state compare mode\n"
              << "  --lhs-func=<NAME>                Resolve lhs function name to low_pc for PC mode\n"
              << "  --rhs-func=<NAME>                Resolve rhs function name to low_pc for PC mode\n"
              << "  --func=<NAME>                    Resolve function name on both sides for PC mode\n"
              << "  --allow-range-mismatch           Don't require equal FDE address_range\n"
              << "  --strict-range                   Require equal FDE address_range (default)\n"
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
              << "  --differential-trials=<N>        Concrete differential trials\n"
              << "  --register-count=<N>             Synthetic register count per trial (>0)\n"
              << "  --seed=<VAL>                     Differential seed\n"
              << "  --no-differential                Disable concrete differential search\n"
              << "  --solver-timeout-ms=<N>          Z3 timeout per expression check in milliseconds (0 = no timeout)\n"
              << "  --format=<text|json>             Report format (default: text)\n"
              << "  --schema-version=<N>             JSON schema version (0=legacy,1=wrapped)\n"
              << "  --output=<PATH>                  Write report to file instead of stdout\n"
              << "  --summary-only                   Emit only summary (no rows)\n"
              << "  --max-rows=<N>                   Limit rows in all-fdes report (0 = all)\n"
              << "  --sort=<lhs-index|rhs-index|lhs-pc|rhs-pc|verdict>\n"
              << "                                   Sort row output (default: lhs-index)\n"
              << "  --show-equivalent                Include EQUIVALENT rows in row output\n"
              << "  --hide-equivalent                Exclude EQUIVALENT rows in row output\n"
              << "  --only-different                 Include only DIFFERENT rows in row output\n"
              << "  --only-unknown                   Include only UNKNOWN rows in row output\n"
              << "  --emit-profile-only              Emit only active gate profile\n"
              << "  --emit-solver-summary-only       Emit only solver/backend bucket summary\n"
              << "  --emit-gate-signature-only       Emit only gate signature line/object\n"
              << "  --report-only                    Do not enforce gate thresholds\n"
              << "  --gate-profile=<P>               Gate preset: strict|balanced|lenient\n"
              << "  --max-different=<N>              Gate threshold (default: 0)\n"
              << "  --max-unknown=<N>                Gate threshold (default: unlimited)\n"
              << "  --max-missing-lhs=<N>            Gate threshold (default: unlimited)\n"
              << "  --max-missing-rhs=<N>            Gate threshold (default: unlimited)\n"
              << "  --fail-on-unknown                Gate fails if unknown>0\n"
              << "  --fail-on-missing                Gate fails if missing>0\n"
              << "  --fail-on-solver-result=<K>      Gate fails if any row has solver_result K (repeatable)\n"
              << "  --fail-on-verifier-backend=<K>   Gate fails if any row has verifier_backend K (repeatable)\n"
              << "\n"
              << "Policy presets:\n"
              << "  --strict                         Equivalent-only gate (same as --gate-profile=strict)\n"
              << "  --allow-unknown                  Disable unknown failures\n"
              << "  --allow-missing                  Disable missing failures\n";
}

void printVerifyRelocUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " verify-reloc <elf> [options]\n\n"
              << "Options:\n"
              << "  --format=<text|json>             Report format (default: text)\n"
              << "  --output=<PATH>                  Write report to file instead of stdout\n"
              << "  --summary-only                   Emit only summary (no issue rows)\n"
              << "  --normalize-loc                  Compatibility alias for symbolic-canonical normalization\n"
              << "  --normalization-policy=<off|symbolic-canonical>  Select normalization policy used in profile output\n"
              << "  --verify-profile=<P>             Verification preset: off|minimal|default|full|strict|balanced|lenient\n"
              << "  --verify-features=<LIST>         Enable checks: section-reloc,loc-normalize,range-aware (special: all,none)\n"
              << "  --emit-profile-only              Emit only active verification/gate profile\n"
              << "  --only-code=<CODE>               Keep only selected issue code (repeatable)\n"
              << "  --only-section=<SECTION>         Keep only selected section (repeatable)\n"
              << "  --only-severity=<S>              Keep only selected severity (repeatable: error|warning)\n"
              << "  --sort-issues=<K>                Sort issues by severity|code|section|cu|die\n"
              << "  --top-codes=<N>                  Show top-N issue codes in summary (0 = disabled)\n"
              << "  --sort-top-codes=<K>             Sort top-code summary by count|code\n"
              << "  --min-count=<N>                  Suppress code summaries below count N\n"
              << "  --max-total=<N>                  Gate threshold for total issues (default: unlimited)\n"
              << "  --max-per-code=<CODE:N>          Gate threshold for specific issue code (repeatable)\n"
              << "  --max-per-section=<SECTION:N>    Gate threshold for specific section (repeatable)\n"
              << "  --fail-on-code=<CODE>            Shorthand for --max-per-code=CODE:0 (repeatable)\n"
              << "  --fail-on-section=<SECTION>      Shorthand for --max-per-section=SECTION:0 (repeatable)\n"
              << "  --gate-profile=<P>               Gate preset: strict|balanced|lenient\n"
              << "  --explain-gate[=<M>]             Gate explanation mode: off|on-fail|always\n"
              << "  --emit-gate-signature-only       Emit only gate signature line/object\n"
              << "  --max-issues=<N>                 Limit issue rows in report (0 = all)\n"
              << "  --max-errors=<N>                 Gate threshold for error issues (default: 0)\n"
              << "  --max-warnings=<N>               Gate threshold for warning issues (default: unlimited)\n"
              << "  --strict                         Equivalent to --max-errors=0 --max-warnings=0\n"
              << "  --report-only                    Do not enforce gate thresholds\n";
}

void printTriageVendorOpsUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " triage-vendor-ops <elf> [<elf> ...] [options]\n\n"
              << "Options:\n"
              << "  --format=<text|json>             Report format (default: text)\n"
              << "  --schema-version=<N>             JSON schema version (currently supports 1)\n"
              << "  --output=<PATH>                  Write report to file instead of stdout\n"
              << "  -v, --verbose                    Enable verbose parser loading\n"
              << "  --help                           Show this help message\n\n"
              << "Selection Rule:\n"
              << "  Rank unsupported non-GNU vendor expression opcodes by observed corpus frequency.\n"
              << "  A family is selectable only if it appears in at least two independent samples and\n"
              << "  has an explicitly modeled bounded semantics mapping. Otherwise the report stays\n"
              << "  fail-closed and emits selection_status=no_safe_family_selected.\n\n"
              << "Examples:\n"
              << "  " << prog << " triage-vendor-ops a.o b.o\n"
              << "  " << prog << " triage-vendor-ops a.o b.o --format=json --output=vendor_triage.json\n";
}

static bool isValidRelocSectionFilter(const std::string& s) {
    return s == ".debug_str_offsets" ||
           s == ".debug_loclists" ||
           s == ".debug_rnglists" ||
           s == "other";
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
    std::string name = DwarfUtils::tagToString(tag);
    if (name.rfind("DW_TAG_unknown_", 0) == 0) {
        return "DW_TAG_unknown(" + std::to_string(static_cast<int>(tag)) + ")";
    }
    return name;
}

// Get attribute name
std::string getAttrName(DwarfAttribute attr) {
    std::string name = DwarfUtils::attributeToString(attr);
    if (name.rfind("DW_AT_unknown_", 0) == 0) {
        return "DW_AT_unknown(" + std::to_string(static_cast<int>(attr)) + ")";
    }
    return name;
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
            if (auto decoded = decodeSemanticAttributeForDump(attr, value)) {
                std::cout << " ; semantic=" << decoded->assembly;
                if (opts.verbose) {
                    std::cout << " ; tokens=[";
                    for (size_t i = 0; i < decoded->tokens.size(); ++i) {
                        if (i) std::cout << ", ";
                        std::cout << decoded->tokens[i];
                    }
                    std::cout << "]"
                              << " ; bytes=" << formatCompactHexBytes(decoded->bytes);
                }
            }
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

void dumpDebugNames(const DwarfParser& parser, const Options& opts) {
    (void)opts;
    std::cout << "\n.debug_names contents:\n\n";

    if (!parser.hasAcceleratedLookup()) {
        std::cout << "  (no .debug_names available)\n";
        return;
    }

    const auto& headers = parser.getDebugNamesUnitHeaders();
    if (headers.empty()) {
        std::cout << "  (no parsed .debug_names units)\n";
        return;
    }

    std::cout << "  Unit count: " << headers.size() << "\n\n";
    for (size_t i = 0; i < headers.size(); ++i) {
        const auto& h = headers[i];
        std::cout << "  Unit " << i << ":\n";
        std::cout << "    version: " << h.version << "\n";
        std::cout << "    dwarf64: " << (h.is_dwarf64 ? "yes" : "no") << "\n";
        std::cout << "    unit_length: " << h.unit_length << "\n";
        std::cout << "    comp_units: " << h.comp_unit_count << "\n";
        std::cout << "    local_type_units: " << h.local_type_unit_count << "\n";
        std::cout << "    foreign_type_units: " << h.foreign_type_unit_count << "\n";
        std::cout << "    buckets: " << h.bucket_count << "\n";
        std::cout << "    names: " << h.name_count << "\n";
        std::cout << "    abbrev_table_size: " << h.abbrev_table_size << "\n";
        if (!h.augmentation_vendor_id.empty()) {
            std::cout << "    augmentation_vendor: " << h.augmentation_vendor_id << "\n";
        }
        if (h.augmentation_payload_size != 0) {
            std::cout << "    augmentation_payload_size: " << h.augmentation_payload_size << "\n";
        }
        std::cout << "\n";
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
    const auto& s = parser.getSplitDwarfStats();
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
    std::cout << "  Has macro info: " << ((parser.hasMacroInfo() || parser.hasLegacyMacroInfo()) ? "yes" : "no") << "\n";
    std::cout << "  Has split DWARF: " << (parser.hasSplitDwarf() ? "yes" : "no") << "\n";
    std::cout << "  Has loaded DWP: " << (parser.hasLoadedDWP() ? "yes" : "no") << "\n";
    if (parser.hasLoadedDWP()) {
        std::cout << "  DWP path: " << parser.getLoadedDWPPath() << "\n";
    }
    std::cout << "  Has DWP CU index: " << (parser.hasDWPIndexSection() ? "yes" : "no") << "\n";
    std::cout << "  DWP CU index valid: " << (parser.isDWPIndexValid() ? "yes" : "no") << "\n";
    std::cout << "  DWP indexed units: " << parser.getDWPIndexedUnitCount() << "\n";
    std::cout << "  Has DWP TU index: " << (parser.hasDWPTUIndexSection() ? "yes" : "no") << "\n";
    std::cout << "  DWP TU index valid: " << (parser.isDWPTUIndexValid() ? "yes" : "no") << "\n";
    std::cout << "  DWP TU indexed units: " << parser.getDWPTUIndexedUnitCount() << "\n";
    std::cout << "  Split DWP hits: " << s.dwp_hits << "\n";
    std::cout << "  Split DWO hits: " << s.dwo_hits << "\n";
    std::cout << "  Split DWO fallback hits: " << s.dwo_fallback_hits << "\n";
}

void printSupportMatrix(const DwarfParser* parser = nullptr,
                        const std::string& format = "text",
                        int schema_version = 1,
                        bool verbose = false) {
    struct RuntimeField {
        std::string key;
        std::string text_value;
        std::string json_value;
    };

    const auto& rows = getSupportMatrixRows();

    auto esc = [](const std::string& s) -> std::string {
        std::ostringstream out;
        for (char ch : s) {
            switch (ch) {
                case '\\': out << "\\\\"; break;
                case '"': out << "\\\""; break;
                case '\n': out << "\\n"; break;
                case '\r': out << "\\r"; break;
                case '\t': out << "\\t"; break;
                default:
                    if (static_cast<unsigned char>(ch) < 0x20) {
                        out << "\\u00";
                        const char* hex = "0123456789abcdef";
                        unsigned v = static_cast<unsigned char>(ch);
                        out << hex[(v >> 4) & 0xf] << hex[v & 0xf];
                    } else {
                        out << ch;
                    }
                    break;
            }
        }
        return out.str();
    };

    std::vector<RuntimeField> runtime_fields;
    if (parser) {
        const auto& s = parser->getSplitDwarfStats();
        const auto& t = parser->getSupportTelemetry();
        const ExpressionGapTelemetry expr_t = collectExpressionGapTelemetry(*parser);
        auto pushBool = [&](const char* key, bool v) {
            runtime_fields.push_back({key, v ? "yes" : "no", v ? "true" : "false"});
        };
        auto pushInt = [&](const char* key, uint64_t v) {
            runtime_fields.push_back({key, std::to_string(v), std::to_string(v)});
        };
        auto pushString = [&](const char* key, const std::string& v) {
            runtime_fields.push_back({key, v, "\"" + esc(v) + "\""});
        };

        pushInt("dwarf_version", static_cast<uint64_t>(parser->getVersion()));
        pushInt("address_size", static_cast<uint64_t>(parser->getAddressSize()));
        pushBool("has_split_dwarf", parser->hasSplitDwarf());
        pushBool("has_loaded_dwp", parser->hasLoadedDWP());
        pushString("dwp_path", parser->getLoadedDWPPath());
        pushBool("has_dwp_cu_index", parser->hasDWPIndexSection());
        pushBool("dwp_cu_index_valid", parser->isDWPIndexValid());
        pushInt("dwp_cu_index_units", parser->getDWPIndexedUnitCount());
        pushBool("has_dwp_tu_index", parser->hasDWPTUIndexSection());
        pushBool("dwp_tu_index_valid", parser->isDWPTUIndexValid());
        pushInt("dwp_tu_index_units", parser->getDWPTUIndexedUnitCount());
        if (verbose && !parser->getUnknownDWPCUSectionIds().empty()) {
            pushString("unknown_dwp_cu_section_ids",
                       formatCompactU32HexList(parser->getUnknownDWPCUSectionIds()));
        }
        if (verbose && !parser->getUnknownDWPTUSectionIds().empty()) {
            pushString("unknown_dwp_tu_section_ids",
                       formatCompactU32HexList(parser->getUnknownDWPTUSectionIds()));
        }
        pushInt("dwp_hits", s.dwp_hits);
        pushInt("dwo_hits", s.dwo_hits);
        pushInt("dwo_fallback_hits", s.dwo_fallback_hits);
        pushInt("fallback_no_index", s.fallback_no_index);
        pushInt("fallback_invalid_index", s.fallback_invalid_index);
        pushInt("fallback_sig_miss", s.fallback_sig_miss);
        pushBool("has_debug_names", parser->hasAcceleratedLookup());
        pushBool("has_cfi", parser->hasCFI());
        pushInt("vendor_form_skips", static_cast<uint64_t>(t.vendor_form_skips));
        std::ostringstream examples;
        for (size_t i = 0; i < t.vendor_form_skip_examples.size(); ++i) {
            if (i != 0) examples << ";";
            examples << t.vendor_form_skip_examples[i];
        }
        pushString("vendor_form_skip_examples", examples.str());

        std::vector<std::pair<uint16_t, uint64_t>> hist(t.vendor_form_skip_histogram.begin(),
                                                        t.vendor_form_skip_histogram.end());
        std::sort(hist.begin(), hist.end(),
                  [](const auto& a, const auto& b) {
                      if (a.second != b.second) return a.second > b.second;
                      return a.first < b.first;
                  });
        std::ostringstream hist_ss;
        const size_t hist_limit = std::min<size_t>(hist.size(), 8);
        for (size_t i = 0; i < hist_limit; ++i) {
            if (i != 0) hist_ss << ";";
            hist_ss << "0x" << std::hex << hist[i].first << std::dec << ":" << hist[i].second;
        }
        pushString("vendor_form_skip_histogram", hist_ss.str());

        std::vector<std::pair<std::string, uint64_t>> buckets(t.vendor_form_skip_offset_buckets.begin(),
                                                               t.vendor_form_skip_offset_buckets.end());
        std::sort(buckets.begin(), buckets.end(),
                  [](const auto& a, const auto& b) {
                      if (a.second != b.second) return a.second > b.second;
                      return a.first < b.first;
                  });
        std::ostringstream bucket_ss;
        for (size_t i = 0; i < buckets.size(); ++i) {
            if (i != 0) bucket_ss << ";";
            bucket_ss << buckets[i].first << ":" << buckets[i].second;
        }
        pushString("vendor_form_skip_offset_buckets", bucket_ss.str());

        std::vector<std::pair<std::string, uint64_t>> severities(t.vendor_form_skip_severity_buckets.begin(),
                                                                  t.vendor_form_skip_severity_buckets.end());
        std::sort(severities.begin(), severities.end(),
                  [](const auto& a, const auto& b) {
                      if (a.second != b.second) return a.second > b.second;
                      return a.first < b.first;
                  });
        std::ostringstream severity_ss;
        for (size_t i = 0; i < severities.size(); ++i) {
            if (i != 0) severity_ss << ";";
            severity_ss << severities[i].first << ":" << severities[i].second;
        }
        pushString("vendor_form_skip_severity_buckets", severity_ss.str());

        pushInt("expression_site_count", static_cast<uint64_t>(expr_t.expression_site_count));
        pushInt("expression_op_count", static_cast<uint64_t>(expr_t.expression_op_count));
        pushInt("unknown_expression_opcode_sites", static_cast<uint64_t>(expr_t.unknown_opcode_sites));
        pushInt("unknown_vendor_expression_opcode_sites",
                static_cast<uint64_t>(expr_t.unknown_vendor_opcode_sites));

        std::vector<std::pair<uint8_t, uint64_t>> unknown_ops(expr_t.unknown_opcode_histogram.begin(),
                                                              expr_t.unknown_opcode_histogram.end());
        std::sort(unknown_ops.begin(), unknown_ops.end(),
                  [](const auto& a, const auto& b) {
                      if (a.second != b.second) return a.second > b.second;
                      return a.first < b.first;
                  });
        std::ostringstream unknown_ops_ss;
        const size_t unknown_ops_limit = std::min<size_t>(unknown_ops.size(), 8);
        for (size_t i = 0; i < unknown_ops_limit; ++i) {
            if (i != 0) unknown_ops_ss << ";";
            unknown_ops_ss << "0x" << std::hex << static_cast<unsigned>(unknown_ops[i].first)
                           << std::dec << ":" << unknown_ops[i].second;
        }
        pushString("unknown_expression_opcode_histogram", unknown_ops_ss.str());

        std::vector<std::pair<std::string, uint64_t>> unknown_attrs(expr_t.unknown_opcode_attribute_histogram.begin(),
                                                                     expr_t.unknown_opcode_attribute_histogram.end());
        std::sort(unknown_attrs.begin(), unknown_attrs.end(),
                  [](const auto& a, const auto& b) {
                      if (a.second != b.second) return a.second > b.second;
                      return a.first < b.first;
                  });
        std::ostringstream unknown_attrs_ss;
        for (size_t i = 0; i < unknown_attrs.size(); ++i) {
            if (i != 0) unknown_attrs_ss << ";";
            unknown_attrs_ss << unknown_attrs[i].first << ":" << unknown_attrs[i].second;
        }
        pushString("unknown_expression_opcode_attributes", unknown_attrs_ss.str());
    }

    if (format == "json") {
        std::ostringstream out;
        out << "{";
        out << "\"kind\":\"dwarf_support\",";
        out << "\"schema_version\":" << schema_version << ",";
        out << "\"rows\":[";
        for (size_t i = 0; i < rows.size(); ++i) {
            const auto& r = rows[i];
            if (i > 0) out << ",";
            out << "{"
                << "\"area\":\"" << esc(r.area) << "\","
                << "\"feature\":\"" << esc(r.feature) << "\","
                << "\"status\":\"" << esc(r.status) << "\","
                << "\"notes\":\"" << esc(r.notes) << "\""
                << "}";
        }
        out << "]";
        if (!runtime_fields.empty()) {
            out << ",\"runtime\":{";
            for (size_t i = 0; i < runtime_fields.size(); ++i) {
                if (i > 0) out << ",";
                out << "\"" << esc(runtime_fields[i].key) << "\":" << runtime_fields[i].json_value;
            }
            if (parser && schema_version >= 2) {
                if (!parser->getUnknownDWPCUSectionIds().empty()) {
                    out << ",\"unknown_dwp_cu_section_ids\":[";
                    const auto& ids = parser->getUnknownDWPCUSectionIds();
                    for (size_t i = 0; i < ids.size(); ++i) {
                        if (i > 0) out << ",";
                        out << ids[i];
                    }
                    out << "]";
                }
                if (!parser->getUnknownDWPTUSectionIds().empty()) {
                    out << ",\"unknown_dwp_tu_section_ids\":[";
                    const auto& ids = parser->getUnknownDWPTUSectionIds();
                    for (size_t i = 0; i < ids.size(); ++i) {
                        if (i > 0) out << ",";
                        out << ids[i];
                    }
                    out << "]";
                }
                const auto& t = parser->getSupportTelemetry();
                const auto& examples = t.vendor_form_skip_examples_structured;
                out << ",\"vendor_form_skip_examples_structured\":[";
                for (size_t i = 0; i < examples.size(); ++i) {
                    if (i > 0) out << ",";
                    out << "{"
                        << "\"form\":" << static_cast<uint64_t>(examples[i].form) << ","
                        << "\"offset\":" << examples[i].offset << ","
                        << "\"cu_offset\":" << examples[i].cu_offset << ","
                        << "\"die_offset\":" << examples[i].die_offset << ","
                        << "\"attr\":\"" << esc(DwarfUtils::attributeToString(examples[i].attr)) << "\","
                        << "\"severity\":\"" << esc(examples[i].severity) << "\""
                        << "}";
                }
                out << "]";

                std::vector<std::pair<uint16_t, uint64_t>> hist(t.vendor_form_skip_histogram.begin(),
                                                                t.vendor_form_skip_histogram.end());
                std::sort(hist.begin(), hist.end(),
                          [](const auto& a, const auto& b) {
                              if (a.second != b.second) return a.second > b.second;
                              return a.first < b.first;
                          });
                out << ",\"vendor_form_skip_histogram_structured\":[";
                for (size_t i = 0; i < hist.size(); ++i) {
                    if (i > 0) out << ",";
                    out << "{"
                        << "\"form\":" << static_cast<uint64_t>(hist[i].first) << ","
                        << "\"count\":" << hist[i].second
                        << "}";
                }
                out << "]";

                std::vector<std::pair<std::string, uint64_t>> buckets(t.vendor_form_skip_offset_buckets.begin(),
                                                                       t.vendor_form_skip_offset_buckets.end());
                std::sort(buckets.begin(), buckets.end(),
                          [](const auto& a, const auto& b) {
                              if (a.second != b.second) return a.second > b.second;
                              return a.first < b.first;
                          });
                out << ",\"vendor_form_skip_offset_buckets_structured\":[";
                for (size_t i = 0; i < buckets.size(); ++i) {
                    if (i > 0) out << ",";
                    out << "{"
                        << "\"bucket\":\"" << esc(buckets[i].first) << "\","
                        << "\"count\":" << buckets[i].second
                        << "}";
                }
                out << "]";

                std::vector<std::pair<std::string, uint64_t>> severities(t.vendor_form_skip_severity_buckets.begin(),
                                                                          t.vendor_form_skip_severity_buckets.end());
                std::sort(severities.begin(), severities.end(),
                          [](const auto& a, const auto& b) {
                              if (a.second != b.second) return a.second > b.second;
                              return a.first < b.first;
                          });
                out << ",\"vendor_form_skip_severity_buckets_structured\":[";
                for (size_t i = 0; i < severities.size(); ++i) {
                    if (i > 0) out << ",";
                    out << "{"
                        << "\"severity\":\"" << esc(severities[i].first) << "\","
                        << "\"count\":" << severities[i].second
                        << "}";
                }
                out << "]";

                const ExpressionGapTelemetry expr_t = collectExpressionGapTelemetry(*parser);
                std::vector<std::pair<uint8_t, uint64_t>> unknown_ops(expr_t.unknown_opcode_histogram.begin(),
                                                                      expr_t.unknown_opcode_histogram.end());
                std::sort(unknown_ops.begin(), unknown_ops.end(),
                          [](const auto& a, const auto& b) {
                              if (a.second != b.second) return a.second > b.second;
                              return a.first < b.first;
                          });
                out << ",\"unknown_expression_opcode_histogram_structured\":[";
                for (size_t i = 0; i < unknown_ops.size(); ++i) {
                    if (i > 0) out << ",";
                    out << "{"
                        << "\"opcode\":" << static_cast<uint64_t>(unknown_ops[i].first) << ","
                        << "\"count\":" << unknown_ops[i].second
                        << "}";
                }
                out << "]";

                std::vector<std::pair<std::string, uint64_t>> unknown_attrs(expr_t.unknown_opcode_attribute_histogram.begin(),
                                                                             expr_t.unknown_opcode_attribute_histogram.end());
                std::sort(unknown_attrs.begin(), unknown_attrs.end(),
                          [](const auto& a, const auto& b) {
                              if (a.second != b.second) return a.second > b.second;
                              return a.first < b.first;
                          });
                out << ",\"unknown_expression_opcode_attributes_structured\":[";
                for (size_t i = 0; i < unknown_attrs.size(); ++i) {
                    if (i > 0) out << ",";
                    out << "{"
                        << "\"attribute\":\"" << esc(unknown_attrs[i].first) << "\","
                        << "\"count\":" << unknown_attrs[i].second
                        << "}";
                }
                out << "]";
            }
            out << "}";
        }
        out << "}\n";
        std::cout << out.str();
        return;
    }

    std::cout << "DWARF v5 Support Matrix\n";
    std::cout << "area\tfeature\tstatus\tnotes\n";
    for (const auto& r : rows) {
        std::cout << r.area << "\t" << r.feature << "\t" << r.status << "\t" << r.notes << "\n";
    }

    if (!runtime_fields.empty()) {
        std::cout << "\nRuntime (loaded file)\n";
        for (const auto& f : runtime_fields) {
            std::cout << f.key << "=" << f.text_value << "\n";
        }
    }
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

static bool parseVendorExpressionProfile(const std::string& s, VendorExpressionProfile& out) {
    if (s == "none") {
        out = VendorExpressionProfile::NONE;
        return true;
    }
    if (s == "synthetic-v1") {
        out = VendorExpressionProfile::SYNTHETIC_V1;
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

static bool parseRatioOption(const std::string& raw, double& out) {
    if (raw.empty()) return false;
    try {
        size_t consumed = 0;
        double v = std::stod(raw, &consumed);
        if (consumed != raw.size()) return false;
        if (v < 0.0 || v > 1.0) return false;
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

static std::string jsonEscape(const std::string& s) {
    std::ostringstream out;
    for (char ch : s) {
        switch (ch) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20) {
                    out << "\\u00";
                    const char* hex = "0123456789abcdef";
                    unsigned v = static_cast<unsigned char>(ch);
                    out << hex[(v >> 4) & 0xf] << hex[v & 0xf];
                } else {
                    out << ch;
                }
                break;
        }
    }
    return out.str();
}

enum class RelocIssueSeverity {
    ERROR,
    WARNING
};

struct RelocIssue {
    RelocIssueSeverity severity = RelocIssueSeverity::ERROR;
    std::string code;
    std::string section;
    uint64_t cu_offset = 0;
    uint64_t die_offset = 0;
    std::string attribute;
    std::string detail;
};

static const char* relocSeverityToString(RelocIssueSeverity s) {
    switch (s) {
        case RelocIssueSeverity::ERROR: return "error";
        case RelocIssueSeverity::WARNING: return "warning";
    }
    return "error";
}

static bool parseRelocSeverityFilter(const std::string& s, RelocIssueSeverity& out) {
    if (s == "error") {
        out = RelocIssueSeverity::ERROR;
        return true;
    }
    if (s == "warning") {
        out = RelocIssueSeverity::WARNING;
        return true;
    }
    return false;
}

static bool hasPlaceholderPrefix(const std::string& value) {
    return value.rfind("<strx", 0) == 0 || value.rfind("<line_strp:", 0) == 0;
}

struct RelocSectionCounts {
    size_t debug_str_offsets = 0;
    size_t debug_loclists = 0;
    size_t debug_rnglists = 0;
    size_t other = 0;
};

struct VerifyRelocFeatures {
    bool section_reloc = true;
    bool loc_normalize = true;
    bool range_aware = true;
};

static bool applyVerifyFeatureToken(const std::string& token, VerifyRelocFeatures& features) {
    if (token == "all") {
        features.section_reloc = true;
        features.loc_normalize = true;
        features.range_aware = true;
        return true;
    }
    if (token == "none") {
        features.section_reloc = false;
        features.loc_normalize = false;
        features.range_aware = false;
        return true;
    }
    if (token == "section-reloc") {
        features.section_reloc = true;
        return true;
    }
    if (token == "loc-normalize") {
        features.loc_normalize = true;
        return true;
    }
    if (token == "range-aware") {
        features.range_aware = true;
        return true;
    }
    return false;
}

static bool parseVerifyFeaturesOption(const std::string& raw, VerifyRelocFeatures& features) {
    if (raw.empty()) return false;
    size_t start = 0;
    bool saw_token = false;
    while (start <= raw.size()) {
        size_t end = raw.find(',', start);
        std::string token = (end == std::string::npos)
            ? raw.substr(start)
            : raw.substr(start, end - start);
        if (token.empty()) return false;
        if (!applyVerifyFeatureToken(token, features)) return false;
        saw_token = true;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return saw_token;
}

static bool parseVerifyFeatureProfile(const std::string& raw, VerifyRelocFeatures& features) {
    if (raw == "default" || raw == "full") {
        features.section_reloc = true;
        features.loc_normalize = true;
        features.range_aware = true;
        return true;
    }
    if (raw == "minimal") {
        features.section_reloc = true;
        features.loc_normalize = false;
        features.range_aware = false;
        return true;
    }
    if (raw == "off" || raw == "none") {
        features.section_reloc = false;
        features.loc_normalize = false;
        features.range_aware = false;
        return true;
    }
    return false;
}

static std::string renderNormalizationPolicyName(CrossBinaryCompareOptions::NormalizationPolicy policy) {
    return policy == CrossBinaryCompareOptions::NormalizationPolicy::SYMBOLIC_CANONICAL
        ? "symbolic_canonical"
        : "off";
}

static void applyNormalizationPolicy(CrossBinaryCompareOptions& opts,
                                    CrossBinaryCompareOptions::NormalizationPolicy policy) {
    opts.normalization_policy = policy;
    opts.enable_location_semantic_normalization = policy == CrossBinaryCompareOptions::NormalizationPolicy::SYMBOLIC_CANONICAL;
}

static bool parseNormalizationPolicy(const std::string& raw,
                                   CrossBinaryCompareOptions::NormalizationPolicy& policy) {
    if (raw == "off") {
        policy = CrossBinaryCompareOptions::NormalizationPolicy::OFF;
        return true;
    }
    if (raw == "symbolic-canonical" || raw == "symbolic_canonical") {
        policy = CrossBinaryCompareOptions::NormalizationPolicy::SYMBOLIC_CANONICAL;
        return true;
    }
    return false;
}

static void applyNormalizationPolicy(CrossBinaryCompareOptions& opts, bool enabled) {
    applyNormalizationPolicy(opts, enabled
                                ? CrossBinaryCompareOptions::NormalizationPolicy::SYMBOLIC_CANONICAL
                                : CrossBinaryCompareOptions::NormalizationPolicy::OFF);
}

static bool applyVerifyRelocGateProfile(const std::string& raw,
                                        std::string& gate_profile,
                                        size_t& max_total,
                                        size_t& max_errors,
                                        size_t& max_warnings,
                                        bool explain_gate_explicit,
                                        std::string& explain_gate_mode) {
    if (raw == "strict") {
        gate_profile = "strict";
        max_total = 0;
        max_errors = 0;
        max_warnings = 0;
        if (!explain_gate_explicit) explain_gate_mode = "on-fail";
        return true;
    }
    if (raw == "balanced") {
        gate_profile = "balanced";
        max_total = 100;
        max_errors = 0;
        max_warnings = 25;
        if (!explain_gate_explicit) explain_gate_mode = "off";
        return true;
    }
    if (raw == "lenient") {
        gate_profile = "lenient";
        max_total = 1000;
        max_errors = 25;
        max_warnings = std::numeric_limits<size_t>::max();
        if (!explain_gate_explicit) explain_gate_mode = "off";
        return true;
    }
    return false;
}

static bool applyCompareExprGateProfile(const std::string& raw,
                                        CrossBinaryGateOptions& gate_opts) {
    if (raw == "strict") {
        gate_opts.max_different = 0;
        gate_opts.max_unknown = 0;
        gate_opts.max_missing_lhs = 0;
        gate_opts.max_missing_rhs = 0;
        gate_opts.fail_on_unknown = true;
        gate_opts.fail_on_missing = true;
        gate_opts.min_equivalent_coverage = 1.0;
        gate_opts.max_different_coverage = 0.0;
        gate_opts.fail_on_uncovered = true;
        return true;
    }
    if (raw == "balanced") {
        gate_opts.max_different = 0;
        gate_opts.max_unknown = 25;
        gate_opts.max_missing_lhs = std::numeric_limits<size_t>::max();
        gate_opts.max_missing_rhs = std::numeric_limits<size_t>::max();
        gate_opts.fail_on_unknown = false;
        gate_opts.fail_on_missing = false;
        gate_opts.min_equivalent_coverage = 0.90;
        gate_opts.max_different_coverage = 0.10;
        gate_opts.fail_on_uncovered = false;
        return true;
    }
    if (raw == "lenient") {
        gate_opts.max_different = 1000;
        gate_opts.max_unknown = std::numeric_limits<size_t>::max();
        gate_opts.max_missing_lhs = std::numeric_limits<size_t>::max();
        gate_opts.max_missing_rhs = std::numeric_limits<size_t>::max();
        gate_opts.fail_on_unknown = false;
        gate_opts.fail_on_missing = false;
        gate_opts.min_equivalent_coverage = 0.0;
        gate_opts.max_different_coverage = 1.0;
        gate_opts.fail_on_uncovered = false;
        return true;
    }
    return false;
}

static bool applyCompareCfiGateProfile(const std::string& raw,
                                       size_t& max_different,
                                       size_t& max_unknown,
                                       size_t& max_missing_lhs,
                                       size_t& max_missing_rhs,
                                       bool& fail_on_unknown,
                                       bool& fail_on_missing) {
    if (raw == "strict") {
        max_different = 0;
        max_unknown = 0;
        max_missing_lhs = 0;
        max_missing_rhs = 0;
        fail_on_unknown = true;
        fail_on_missing = true;
        return true;
    }
    if (raw == "balanced") {
        max_different = 0;
        max_unknown = 25;
        max_missing_lhs = std::numeric_limits<size_t>::max();
        max_missing_rhs = std::numeric_limits<size_t>::max();
        fail_on_unknown = false;
        fail_on_missing = false;
        return true;
    }
    if (raw == "lenient") {
        max_different = 1000;
        max_unknown = std::numeric_limits<size_t>::max();
        max_missing_lhs = std::numeric_limits<size_t>::max();
        max_missing_rhs = std::numeric_limits<size_t>::max();
        fail_on_unknown = false;
        fail_on_missing = false;
        return true;
    }
    return false;
}

static std::string renderVerifyFeaturesText(const VerifyRelocFeatures& features) {
    std::vector<std::string> names;
    if (features.section_reloc) names.push_back("section-reloc");
    if (features.loc_normalize) names.push_back("loc-normalize");
    if (features.range_aware) names.push_back("range-aware");
    if (names.empty()) return "none";
    std::ostringstream out;
    for (size_t i = 0; i < names.size(); ++i) {
        if (i != 0) out << ",";
        out << names[i];
    }
    return out.str();
}

static std::string renderCodeCountsText(const std::map<std::string, size_t>& code_counts) {
    if (code_counts.empty()) return "none";
    std::ostringstream out;
    bool first = true;
    for (const auto& kv : code_counts) {
        if (!first) out << ",";
        first = false;
        out << kv.first << ":" << kv.second;
    }
    return out.str();
}

static std::vector<std::pair<std::string, size_t>> topCodeCounts(
    const std::map<std::string, size_t>& code_counts,
    size_t top_n,
    const std::string& sort_mode) {
    std::vector<std::pair<std::string, size_t>> ranked(code_counts.begin(), code_counts.end());
    if (sort_mode == "code") {
        std::sort(ranked.begin(), ranked.end(),
                  [](const auto& a, const auto& b) {
                      if (a.first != b.first) return a.first < b.first;
                      return a.second > b.second;
                  });
    } else {
        std::sort(ranked.begin(), ranked.end(),
                  [](const auto& a, const auto& b) {
                      if (a.second != b.second) return a.second > b.second;
                      return a.first < b.first;
                  });
    }
    if (top_n != 0 && ranked.size() > top_n) ranked.resize(top_n);
    return ranked;
}

static std::map<std::string, size_t> filterCodeCountsByMin(
    const std::map<std::string, size_t>& code_counts,
    size_t min_count) {
    if (min_count <= 1) return code_counts;
    std::map<std::string, size_t> filtered;
    for (const auto& kv : code_counts) {
        if (kv.second >= min_count) filtered.insert(kv);
    }
    return filtered;
}

static std::string renderTopCodesText(const std::vector<std::pair<std::string, size_t>>& top_codes) {
    if (top_codes.empty()) return "none";
    std::ostringstream out;
    for (size_t i = 0; i < top_codes.size(); ++i) {
        if (i != 0) out << ",";
        out << top_codes[i].first << ":" << top_codes[i].second;
    }
    return out.str();
}

static std::string renderSeveritySetText(const std::set<RelocIssueSeverity>& severities) {
    if (severities.empty()) return "none";
    std::ostringstream out;
    bool first = true;
    for (RelocIssueSeverity s : severities) {
        if (!first) out << ",";
        first = false;
        out << relocSeverityToString(s);
    }
    return out.str();
}

static bool parseRelocSortMode(const std::string& s) {
    return s == "severity" || s == "code" || s == "section" || s == "cu" || s == "die";
}

static bool parseTopCodeSortMode(const std::string& s) {
    return s == "count" || s == "code";
}

static bool parseExplainGateMode(const std::string& s) {
    return s == "off" || s == "on-fail" || s == "always";
}

static bool parseMaxPerCodeOption(const std::string& raw,
                                  std::string& code,
                                  size_t& limit) {
    auto colon = raw.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= raw.size()) return false;
    std::string code_part = raw.substr(0, colon);
    std::string limit_part = raw.substr(colon + 1);
    uint64_t parsed = 0;
    if (!parseUIntOption(limit_part, parsed)) return false;
    code = code_part;
    limit = static_cast<size_t>(parsed);
    return true;
}

static std::string renderMaxPerCodeText(const std::map<std::string, size_t>& limits) {
    if (limits.empty()) return "none";
    std::ostringstream out;
    bool first = true;
    for (const auto& kv : limits) {
        if (!first) out << ",";
        first = false;
        out << kv.first << ":" << kv.second;
    }
    return out.str();
}

static bool parseMaxPerSectionOption(const std::string& raw,
                                     std::string& section,
                                     size_t& limit) {
    auto colon = raw.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= raw.size()) return false;
    std::string section_part = raw.substr(0, colon);
    std::string limit_part = raw.substr(colon + 1);
    if (!isValidRelocSectionFilter(section_part)) return false;
    uint64_t parsed = 0;
    if (!parseUIntOption(limit_part, parsed)) return false;
    section = section_part;
    limit = static_cast<size_t>(parsed);
    return true;
}

static std::string renderMaxPerSectionText(const std::map<std::string, size_t>& limits) {
    if (limits.empty()) return "none";
    std::ostringstream out;
    bool first = true;
    for (const auto& kv : limits) {
        if (!first) out << ",";
        first = false;
        out << kv.first << ":" << kv.second;
    }
    return out.str();
}

static size_t sectionCountValue(const RelocSectionCounts& counts, const std::string& section) {
    if (section == ".debug_str_offsets") return counts.debug_str_offsets;
    if (section == ".debug_loclists") return counts.debug_loclists;
    if (section == ".debug_rnglists") return counts.debug_rnglists;
    return counts.other;
}

static int relocSeverityRank(RelocIssueSeverity s) {
    return (s == RelocIssueSeverity::ERROR) ? 0 : 1;
}

static void addSectionCount(RelocSectionCounts& counts, const std::string& section) {
    if (section == ".debug_str_offsets") {
        ++counts.debug_str_offsets;
        return;
    }
    if (section == ".debug_loclists") {
        ++counts.debug_loclists;
        return;
    }
    if (section == ".debug_rnglists") {
        ++counts.debug_rnglists;
        return;
    }
    ++counts.other;
}

static void scanRelocIssuesInDIE(const std::shared_ptr<DIE>& die,
                                 uint64_t cu_offset,
                                 const VerifyRelocFeatures& features,
                                 std::vector<RelocIssue>& out) {
    if (!die) return;
    for (const auto& kv : die->getAttributes()) {
        const auto attr = kv.first;
        const auto& value = kv.second;
        if (features.section_reloc) {
            if (auto s = std::dynamic_pointer_cast<StringAttributeValue>(value)) {
                if (hasPlaceholderPrefix(s->getValue())) {
                    out.push_back({RelocIssueSeverity::ERROR,
                                   "UNRESOLVED_INDEXED_STRING",
                                   ".debug_str_offsets",
                                   cu_offset,
                                   die->getOffset(),
                                   getAttrName(attr),
                                   "attribute resolved to placeholder '" + s->getValue() + "'"});
                }
            }
        }
        if (features.loc_normalize || features.range_aware) {
            if (auto loc = std::dynamic_pointer_cast<LocationAttributeValue>(value)) {
                if (loc->getLocationType() == LocationAttributeValue::LocationType::LIST) {
                    for (const auto& entry : loc->getEntries()) {
                        if (features.range_aware && !entry.is_default && entry.end <= entry.start) {
                            out.push_back({RelocIssueSeverity::ERROR,
                                           "INVALID_LOCATION_RANGE",
                                           ".debug_loclists",
                                           cu_offset,
                                           die->getOffset(),
                                           getAttrName(attr),
                                           "location list entry has end <= start"});
                            break;
                        }
                        if (features.loc_normalize && !entry.is_default && entry.expression.empty()) {
                            out.push_back({RelocIssueSeverity::WARNING,
                                           "EMPTY_LOCATION_EXPRESSION",
                                           ".debug_loclists",
                                           cu_offset,
                                           die->getOffset(),
                                           getAttrName(attr),
                                           "location list entry has empty expression"});
                            break;
                        }
                    }
                }
            }
        }
        if (features.range_aware) {
            if (auto ranges = std::dynamic_pointer_cast<RangeAttributeValue>(value)) {
                for (const auto& entry : ranges->getRanges()) {
                    if (!entry.is_base_address && entry.end <= entry.start) {
                        out.push_back({RelocIssueSeverity::ERROR,
                                       "INVALID_RANGE_ENTRY",
                                       ".debug_rnglists",
                                       cu_offset,
                                       die->getOffset(),
                                       getAttrName(attr),
                                       "range list entry has end <= start"});
                        break;
                    }
                }
            }
        }
    }

    for (const auto& child : die->getChildren()) {
        scanRelocIssuesInDIE(child, cu_offset, features, out);
    }
}

static int runVerifyReloc(int argc, char* argv[]) {
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printVerifyRelocUsage(argv[0]);
            return 0;
        }
    }
    if (argc < 3) {
        printVerifyRelocUsage(argv[0]);
        return 1;
    }

    std::string input_file = argv[2];
    std::string format = "text";
    std::string output_path;
    bool summary_only = false;
    std::set<std::string> only_codes;
    std::set<std::string> only_sections;
    std::set<RelocIssueSeverity> only_severities;
    std::string sort_issues = "cu";
    size_t top_codes = 0;
    std::string sort_top_codes = "count";
    size_t min_count = 1;
    size_t max_total = std::numeric_limits<size_t>::max();
    std::map<std::string, size_t> max_per_code;
    std::map<std::string, size_t> max_per_section;
    std::set<std::string> fail_on_codes;
    std::set<std::string> fail_on_sections;
    std::string verify_profile = "custom";
    std::string gate_profile = "custom";
    std::string explain_gate_mode = "off";
    bool explain_gate_explicit = false;
    bool emit_profile_only = false;
    bool emit_gate_signature_only = false;
    VerifyRelocFeatures verify_features;
    CrossBinaryCompareOptions::NormalizationPolicy normalization_policy =
        CrossBinaryCompareOptions::NormalizationPolicy::SYMBOLIC_CANONICAL;
    size_t max_issues = 0;
    size_t max_errors = 0;
    size_t max_warnings = std::numeric_limits<size_t>::max();
    bool report_only = false;

    auto syncNormalizationPolicy = [&]() {
        normalization_policy = verify_features.loc_normalize
            ? CrossBinaryCompareOptions::NormalizationPolicy::SYMBOLIC_CANONICAL
            : CrossBinaryCompareOptions::NormalizationPolicy::OFF;
    };

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        auto split = arg.find('=');
        auto key = (split == std::string::npos) ? arg : arg.substr(0, split);
        auto val = (split == std::string::npos) ? std::string() : arg.substr(split + 1);

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
        if (key == "--normalize-loc") {
            verify_features.loc_normalize = true;
            syncNormalizationPolicy();
            continue;
        }
        if (key == "--normalization-policy") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            CrossBinaryCompareOptions::NormalizationPolicy parsed_policy;
            if (!parseNormalizationPolicy(val, parsed_policy)) {
                std::cerr << "Error: invalid --normalization-policy value '" << val
                          << "' (expected off|symbolic-canonical)\n";
                return 1;
            }
            normalization_policy = parsed_policy;
            verify_features.loc_normalize =
                parsed_policy == CrossBinaryCompareOptions::NormalizationPolicy::SYMBOLIC_CANONICAL;
            continue;
        }
        if (key == "--emit-profile-only") {
            emit_profile_only = true;
            continue;
        }
        if (key == "--verify-profile") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            bool is_feature_profile = parseVerifyFeatureProfile(val, verify_features);
            bool is_gate_profile = applyVerifyRelocGateProfile(
                val,
                gate_profile,
                max_total,
                max_errors,
                max_warnings,
                explain_gate_explicit,
                explain_gate_mode);
            if (!is_feature_profile && !is_gate_profile) {
                std::cerr << "Error: invalid --verify-profile value '" << val
                          << "' (expected off|minimal|default|full|strict|balanced|lenient)\n";
                return 1;
            }
            verify_profile = val;
            if (is_gate_profile && !is_feature_profile) {
                verify_features.section_reloc = true;
                verify_features.loc_normalize = true;
                verify_features.range_aware = true;
            }
            syncNormalizationPolicy();
            continue;
        }
        if (key == "--verify-features") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (!parseVerifyFeaturesOption(val, verify_features)) {
                std::cerr << "Error: invalid --verify-features value '" << val
                          << "' (expected comma-separated section-reloc|loc-normalize|range-aware|all|none)\n";
                return 1;
            }
            syncNormalizationPolicy();
            continue;
        }
        if (key == "--emit-gate-signature-only") {
            emit_gate_signature_only = true;
            continue;
        }
        if (key == "--explain-gate") {
            explain_gate_explicit = true;
            if (val.empty() && i + 1 < argc) {
                std::string next = argv[i + 1];
                if (next == "off" || next == "on-fail" || next == "always") {
                    val = argv[++i];
                }
            }
            if (val.empty()) {
                explain_gate_mode = "always";
            } else if (!parseExplainGateMode(val)) {
                std::cerr << "Error: invalid --explain-gate value '" << val
                          << "' (expected off|on-fail|always)\n";
                return 1;
            } else {
                explain_gate_mode = val;
            }
            continue;
        }
        if (key == "--only-code") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val.empty()) {
                std::cerr << "Error: invalid --only-code value (empty)\n";
                return 1;
            }
            only_codes.insert(val);
            continue;
        }
        if (key == "--only-section") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val.empty() || !isValidRelocSectionFilter(val)) {
                std::cerr << "Error: invalid --only-section value '" << val
                          << "' (expected .debug_str_offsets|.debug_loclists|.debug_rnglists|other)\n";
                return 1;
            }
            only_sections.insert(val);
            continue;
        }
        if (key == "--only-severity") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            RelocIssueSeverity sev = RelocIssueSeverity::ERROR;
            if (!parseRelocSeverityFilter(val, sev)) {
                std::cerr << "Error: invalid --only-severity value '" << val
                          << "' (expected error|warning)\n";
                return 1;
            }
            only_severities.insert(sev);
            continue;
        }
        if (key == "--sort-issues") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (!parseRelocSortMode(val)) {
                std::cerr << "Error: invalid --sort-issues value '" << val
                          << "' (expected severity|code|section|cu|die)\n";
                return 1;
            }
            sort_issues = val;
            continue;
        }
        if (key == "--max-issues") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --max-issues value '" << val << "'\n";
                return 1;
            }
            max_issues = static_cast<size_t>(parsed);
            continue;
        }
        if (key == "--gate-profile") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (!applyVerifyRelocGateProfile(
                    val,
                    gate_profile,
                    max_total,
                    max_errors,
                    max_warnings,
                    explain_gate_explicit,
                    explain_gate_mode)) {
                std::cerr << "Error: invalid --gate-profile value '" << val
                          << "' (expected strict|balanced|lenient)\n";
                return 1;
            }
            continue;
        }
        if (key == "--max-total") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --max-total value '" << val << "'\n";
                return 1;
            }
            max_total = static_cast<size_t>(parsed);
            continue;
        }
        if (key == "--max-per-code") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            std::string code;
            size_t limit = 0;
            if (!parseMaxPerCodeOption(val, code, limit)) {
                std::cerr << "Error: invalid --max-per-code value '" << val
                          << "' (expected CODE:N)\n";
                return 1;
            }
            max_per_code[code] = limit;
            continue;
        }
        if (key == "--max-per-section") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            std::string section;
            size_t limit = 0;
            if (!parseMaxPerSectionOption(val, section, limit)) {
                std::cerr << "Error: invalid --max-per-section value '" << val
                          << "' (expected SECTION:N where SECTION is "
                          << ".debug_str_offsets|.debug_loclists|.debug_rnglists|other)\n";
                return 1;
            }
            max_per_section[section] = limit;
            continue;
        }
        if (key == "--fail-on-code") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val.empty()) {
                std::cerr << "Error: invalid --fail-on-code value (empty)\n";
                return 1;
            }
            fail_on_codes.insert(val);
            max_per_code[val] = 0;
            continue;
        }
        if (key == "--fail-on-section") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val.empty() || !isValidRelocSectionFilter(val)) {
                std::cerr << "Error: invalid --fail-on-section value '" << val
                          << "' (expected .debug_str_offsets|.debug_loclists|.debug_rnglists|other)\n";
                return 1;
            }
            fail_on_sections.insert(val);
            max_per_section[val] = 0;
            continue;
        }
        if (key == "--top-codes") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --top-codes value '" << val << "'\n";
                return 1;
            }
            top_codes = static_cast<size_t>(parsed);
            continue;
        }
        if (key == "--sort-top-codes") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (!parseTopCodeSortMode(val)) {
                std::cerr << "Error: invalid --sort-top-codes value '" << val
                          << "' (expected count|code)\n";
                return 1;
            }
            sort_top_codes = val;
            continue;
        }
        if (key == "--min-count") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --min-count value '" << val << "'\n";
                return 1;
            }
            min_count = static_cast<size_t>(parsed);
            continue;
        }
        if (key == "--max-errors") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --max-errors value '" << val << "'\n";
                return 1;
            }
            max_errors = static_cast<size_t>(parsed);
            continue;
        }
        if (key == "--max-warnings") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --max-warnings value '" << val << "'\n";
                return 1;
            }
            max_warnings = static_cast<size_t>(parsed);
            continue;
        }
        if (key == "--strict") {
            max_errors = 0;
            max_warnings = 0;
            continue;
        }
        if (key == "--report-only") {
            report_only = true;
            continue;
        }

        std::cerr << "Error: unknown verify-reloc option '" << arg << "'\n";
        return 1;
    }

    DwarfParser parser(input_file);
    if (!parser.load()) {
        std::cerr << "Error: failed to load ELF '" << input_file << "'\n";
        return 1;
    }

    std::vector<RelocIssue> issues;
    for (const auto& cu : parser.getCompilationUnits()) {
        uint64_t cu_offset = cu ? cu->getOffset() : 0;
        scanRelocIssuesInDIE(cu, cu_offset, verify_features, issues);
    }
    if (!only_codes.empty()) {
        std::vector<RelocIssue> filtered;
        filtered.reserve(issues.size());
        for (const auto& issue : issues) {
            if (only_codes.count(issue.code) != 0) filtered.push_back(issue);
        }
        issues.swap(filtered);
    }
    if (!only_sections.empty()) {
        std::vector<RelocIssue> filtered;
        filtered.reserve(issues.size());
        for (const auto& issue : issues) {
            if (only_sections.count(issue.section) != 0) filtered.push_back(issue);
        }
        issues.swap(filtered);
    }
    if (!only_severities.empty()) {
        std::vector<RelocIssue> filtered;
        filtered.reserve(issues.size());
        for (const auto& issue : issues) {
            if (only_severities.count(issue.severity) != 0) filtered.push_back(issue);
        }
        issues.swap(filtered);
    }
    auto cmp_by_common = [](const RelocIssue& a, const RelocIssue& b) {
        if (a.cu_offset != b.cu_offset) return a.cu_offset < b.cu_offset;
        if (a.die_offset != b.die_offset) return a.die_offset < b.die_offset;
        if (a.code != b.code) return a.code < b.code;
        if (a.section != b.section) return a.section < b.section;
        if (a.attribute != b.attribute) return a.attribute < b.attribute;
        return a.detail < b.detail;
    };
    if (sort_issues == "severity") {
        std::sort(issues.begin(), issues.end(), [&](const RelocIssue& a, const RelocIssue& b) {
            int ar = relocSeverityRank(a.severity);
            int br = relocSeverityRank(b.severity);
            if (ar != br) return ar < br;
            return cmp_by_common(a, b);
        });
    } else if (sort_issues == "code") {
        std::sort(issues.begin(), issues.end(), [&](const RelocIssue& a, const RelocIssue& b) {
            if (a.code != b.code) return a.code < b.code;
            return cmp_by_common(a, b);
        });
    } else if (sort_issues == "section") {
        std::sort(issues.begin(), issues.end(), [&](const RelocIssue& a, const RelocIssue& b) {
            if (a.section != b.section) return a.section < b.section;
            return cmp_by_common(a, b);
        });
    } else if (sort_issues == "die") {
        std::sort(issues.begin(), issues.end(), [&](const RelocIssue& a, const RelocIssue& b) {
            if (a.die_offset != b.die_offset) return a.die_offset < b.die_offset;
            return cmp_by_common(a, b);
        });
    } else {
        std::sort(issues.begin(), issues.end(), cmp_by_common); // default: cu
    }

    size_t error_count = 0;
    size_t warning_count = 0;
    RelocSectionCounts section_counts;
    std::map<std::string, size_t> code_counts;
    for (const auto& issue : issues) {
        if (issue.severity == RelocIssueSeverity::ERROR) ++error_count;
        else ++warning_count;
        addSectionCount(section_counts, issue.section);
        ++code_counts[issue.code];
    }
    std::map<std::string, size_t> filtered_code_counts = filterCodeCountsByMin(code_counts, min_count);
    std::vector<std::pair<std::string, size_t>> top_code_counts = topCodeCounts(
        filtered_code_counts, top_codes, sort_top_codes);
    bool gate_pass = true;
    std::string gate_reason = "gate passed";
    std::string gate_trigger = "none";
    std::string gate_trigger_detail = "";
    if (issues.size() > max_total) {
        gate_pass = false;
        gate_reason = "total issue count exceeds limit";
        gate_trigger = "max_total";
    } else if (error_count > max_errors || warning_count > max_warnings) {
        gate_pass = false;
        if (error_count > max_errors) {
            gate_reason = "error issue count exceeds limit";
            gate_trigger = "max_errors";
        } else {
            gate_reason = "warning issue count exceeds limit";
            gate_trigger = "max_warnings";
        }
    } else {
        for (const auto& kv : max_per_code) {
            auto it = code_counts.find(kv.first);
            size_t observed = (it == code_counts.end()) ? 0 : it->second;
            if (observed > kv.second) {
                gate_pass = false;
                gate_reason = "per-code issue count exceeds limit for " + kv.first;
                gate_trigger = "max_per_code";
                gate_trigger_detail = kv.first;
                break;
            }
        }
        if (gate_pass) {
            for (const auto& kv : max_per_section) {
                size_t observed = sectionCountValue(section_counts, kv.first);
                if (observed > kv.second) {
                    gate_pass = false;
                    gate_reason = "per-section issue count exceeds limit for " + kv.first;
                    gate_trigger = "max_per_section";
                    gate_trigger_detail = kv.first;
                    break;
                }
            }
        }
    }

    auto format_limit = [](size_t v) -> std::string {
        if (v == std::numeric_limits<size_t>::max()) return "inf";
        return std::to_string(v);
    };
    std::ostringstream gate_expl;
    gate_expl << "total=" << issues.size() << "/" << format_limit(max_total)
              << ";errors=" << error_count << "/" << format_limit(max_errors)
              << ";warnings=" << warning_count << "/" << format_limit(max_warnings);
    if (!max_per_code.empty()) {
        gate_expl << ";per_code=";
        bool first = true;
        for (const auto& kv : max_per_code) {
            if (!first) gate_expl << ",";
            first = false;
            auto it = code_counts.find(kv.first);
            size_t observed = (it == code_counts.end()) ? 0 : it->second;
            gate_expl << kv.first << ":" << observed << "/" << kv.second;
        }
    }
    if (!max_per_section.empty()) {
        gate_expl << ";per_section=";
        bool first = true;
        for (const auto& kv : max_per_section) {
            if (!first) gate_expl << ",";
            first = false;
            size_t observed = sectionCountValue(section_counts, kv.first);
            gate_expl << kv.first << ":" << observed << "/" << kv.second;
        }
    }
    std::string gate_explanation = gate_expl.str();
    bool emit_gate_explanation =
        (explain_gate_mode == "always") ||
        (explain_gate_mode == "on-fail" && !gate_pass);
    std::string gate_signature = "pass=" + std::string(gate_pass ? "1" : "0") +
        ";trigger=" + gate_trigger +
        ";detail=" + gate_trigger_detail;
    std::ostringstream out;
    size_t shown = (max_issues == 0) ? issues.size() : std::min(max_issues, issues.size());
    bool truncated = shown < issues.size();
    if (emit_profile_only) {
        if (format == "json") {
            out << "{"
                << "\"profile\":{"
                << "\"verify_profile\":\"" << jsonEscape(verify_profile) << "\","
                << "\"gate_profile\":\"" << jsonEscape(gate_profile) << "\","
                << "\"normalization_policy\":\"" << renderNormalizationPolicyName(normalization_policy) << "\","
                << "\"verify_features\":[";
            bool first = true;
            if (verify_features.section_reloc) {
                if (!first) out << ",";
                first = false;
                out << "\"section-reloc\"";
            }
            if (verify_features.loc_normalize) {
                if (!first) out << ",";
                first = false;
                out << "\"loc-normalize\"";
            }
            if (verify_features.range_aware) {
                if (!first) out << ",";
                first = false;
                out << "\"range-aware\"";
            }
            out << "],"
                << "\"gate\":{"
                << "\"pass\":" << (gate_pass ? "true" : "false") << ","
                << "\"trigger\":\"" << jsonEscape(gate_trigger) << "\","
                << "\"trigger_detail\":\"" << jsonEscape(gate_trigger_detail) << "\","
                << "\"signature\":\"" << jsonEscape(gate_signature) << "\","
                << "\"thresholds\":{"
                << "\"max_total\":" << max_total << ","
                << "\"max_errors\":" << max_errors << ","
                << "\"max_warnings\":";
            if (max_warnings == std::numeric_limits<size_t>::max()) out << "null";
            else out << max_warnings;
            out << "},"
                << "\"observed\":{"
                << "\"total\":" << issues.size() << ","
                << "\"errors\":" << error_count << ","
                << "\"warnings\":" << warning_count
                << "}"
                << "},"
                << "\"gate_signature\":\"" << jsonEscape(gate_signature) << "\""
                << "}"
                << "}\n";
        } else {
            out << "verify_profile=" << verify_profile
                << " gate_profile=" << gate_profile
                << " normalization_policy=" << renderNormalizationPolicyName(normalization_policy)
                << " verify_features=" << renderVerifyFeaturesText(verify_features)
                << " gate_trigger=" << gate_trigger
                << " gate_signature=" << gate_signature
                << "\n";
        }
    } else if (emit_gate_signature_only) {
        if (format == "json") {
            out << "{"
                << "\"gate\":{"
                << "\"signature\":\"" << jsonEscape(gate_signature) << "\""
                << "}"
                << "}\n";
        } else {
            out << "gate_signature=" << gate_signature << "\n";
        }
    } else if (format == "json") {
        out << "{"
            << "\"summary\":{"
            << "\"total\":" << issues.size() << ","
            << "\"errors\":" << error_count << ","
            << "\"warnings\":" << warning_count << ","
            << "\"section_counts\":{"
            << "\"debug_str_offsets\":" << section_counts.debug_str_offsets << ","
            << "\"debug_loclists\":" << section_counts.debug_loclists << ","
            << "\"debug_rnglists\":" << section_counts.debug_rnglists << ","
            << "\"other\":" << section_counts.other
            << "},"
            << "\"code_counts\":{";
        {
            bool first = true;
            for (const auto& kv : filtered_code_counts) {
                if (!first) out << ",";
                first = false;
                out << "\"" << jsonEscape(kv.first) << "\":" << kv.second;
            }
        }
        out
            << "}"
            << ",\"top_codes\":[";
        for (size_t i = 0; i < top_code_counts.size(); ++i) {
            if (i != 0) out << ",";
            out << "{"
                << "\"code\":\"" << jsonEscape(top_code_counts[i].first) << "\","
                << "\"count\":" << top_code_counts[i].second
                << "}";
        }
        out
            << "]"
            << "},"
            << "\"truncated\":" << (truncated ? "true" : "false") << ","
            << "\"sort_issues\":\"" << jsonEscape(sort_issues) << "\","
            << "\"sort_top_codes\":\"" << jsonEscape(sort_top_codes) << "\","
            << "\"verify_profile\":\"" << jsonEscape(verify_profile) << "\","
            << "\"gate_profile\":\"" << jsonEscape(gate_profile) << "\","
            << "\"normalization_policy\":\"" << renderNormalizationPolicyName(normalization_policy) << "\","
            << "\"explain_gate_mode\":\"" << jsonEscape(explain_gate_mode) << "\","
            << "\"min_count\":" << min_count << ","
            << "\"max_total\":" << max_total << ","
            << "\"max_per_code\":{";
        {
            bool first = true;
            for (const auto& kv : max_per_code) {
                if (!first) out << ",";
                first = false;
                out << "\"" << jsonEscape(kv.first) << "\":" << kv.second;
            }
        }
        out
            << "},"
            << "\"max_per_section\":{";
        {
            bool first = true;
            for (const auto& kv : max_per_section) {
                if (!first) out << ",";
                first = false;
                out << "\"" << jsonEscape(kv.first) << "\":" << kv.second;
            }
        }
        out
            << "},"
            << "\"fail_on_codes\":[";
        {
            bool first = true;
            for (const auto& code : fail_on_codes) {
                if (!first) out << ",";
                first = false;
                out << "\"" << jsonEscape(code) << "\"";
            }
        }
        out
            << "],"
            << "\"fail_on_sections\":[";
        {
            bool first = true;
            for (const auto& section : fail_on_sections) {
                if (!first) out << ",";
                first = false;
                out << "\"" << jsonEscape(section) << "\"";
            }
        }
        out
            << "],"
            << "\"only_codes\":[";
        {
            bool first = true;
            for (const auto& code : only_codes) {
                if (!first) out << ",";
                first = false;
                out << "\"" << jsonEscape(code) << "\"";
            }
        }
        out << "],"
            << "\"only_sections\":[";
        {
            bool first = true;
            for (const auto& section : only_sections) {
                if (!first) out << ",";
                first = false;
                out << "\"" << jsonEscape(section) << "\"";
            }
        }
        out << "],"
            << "\"only_severities\":[";
        {
            bool first = true;
            for (RelocIssueSeverity sev : only_severities) {
                if (!first) out << ",";
                first = false;
                out << "\"" << relocSeverityToString(sev) << "\"";
            }
        }
        out << "],"
            << "\"verify_features\":[";
        {
            bool first = true;
            if (verify_features.section_reloc) {
                if (!first) out << ",";
                first = false;
                out << "\"section-reloc\"";
            }
            if (verify_features.loc_normalize) {
                if (!first) out << ",";
                first = false;
                out << "\"loc-normalize\"";
            }
            if (verify_features.range_aware) {
                if (!first) out << ",";
                first = false;
                out << "\"range-aware\"";
            }
        }
        out << "],"
            << "\"gate\":{"
            << "\"pass\":" << (gate_pass ? "true" : "false") << ","
            << "\"reason\":\"" << jsonEscape(gate_reason) << "\","
            << "\"trigger\":\"" << jsonEscape(gate_trigger) << "\","
            << "\"trigger_detail\":\"" << jsonEscape(gate_trigger_detail) << "\","
            << "\"signature\":\"" << jsonEscape(gate_signature) << "\","
            << "\"observed\":{"
            << "\"total\":" << issues.size() << ","
            << "\"errors\":" << error_count << ","
            << "\"warnings\":" << warning_count << ","
            << "\"per_code\":{";
        {
            bool first = true;
            for (const auto& kv : code_counts) {
                if (!first) out << ",";
                first = false;
                out << "\"" << jsonEscape(kv.first) << "\":" << kv.second;
            }
        }
        out
            << "},"
            << "\"per_section\":{"
            << "\"debug_str_offsets\":" << section_counts.debug_str_offsets << ","
            << "\"debug_loclists\":" << section_counts.debug_loclists << ","
            << "\"debug_rnglists\":" << section_counts.debug_rnglists << ","
            << "\"other\":" << section_counts.other
            << "}"
            << "},"
            << "\"thresholds\":{"
            << "\"profile\":\"" << jsonEscape(gate_profile) << "\","
            << "\"max_total\":" << max_total << ","
            << "\"max_errors\":" << max_errors << ","
            << "\"max_warnings\":";
        if (max_warnings == std::numeric_limits<size_t>::max()) out << "null";
        else out << max_warnings;
        out
            << ",\"max_per_code\":{";
        {
            bool first = true;
            for (const auto& kv : max_per_code) {
                if (!first) out << ",";
                first = false;
                out << "\"" << jsonEscape(kv.first) << "\":" << kv.second;
            }
        }
        out
            << "},"
            << "\"max_per_section\":{";
        {
            bool first = true;
            for (const auto& kv : max_per_section) {
                if (!first) out << ",";
                first = false;
                out << "\"" << jsonEscape(kv.first) << "\":" << kv.second;
            }
        }
        out
            << "}"
            << "}";
        if (emit_gate_explanation) {
            out << ",\"explanation\":\"" << jsonEscape(gate_explanation) << "\"";
        }
        out
            << "}";
        if (!summary_only) {
            out << ",\"issues\":[";
            for (size_t i = 0; i < shown; ++i) {
                if (i != 0) out << ",";
                const auto& issue = issues[i];
                out << "{"
                    << "\"severity\":\"" << relocSeverityToString(issue.severity) << "\","
                    << "\"code\":\"" << jsonEscape(issue.code) << "\","
                    << "\"section\":\"" << jsonEscape(issue.section) << "\","
                    << "\"cu_offset\":" << issue.cu_offset << ","
                    << "\"die_offset\":" << issue.die_offset << ","
                    << "\"attribute\":\"" << jsonEscape(issue.attribute) << "\","
                    << "\"detail\":\"" << jsonEscape(issue.detail) << "\""
                    << "}";
            }
            out << "]";
        }
        out << "}\n";
    } else {
        out << "summary total=" << issues.size()
            << " errors=" << error_count
            << " warnings=" << warning_count
            << " section_debug_str_offsets=" << section_counts.debug_str_offsets
            << " section_debug_loclists=" << section_counts.debug_loclists
            << " section_debug_rnglists=" << section_counts.debug_rnglists
            << " section_other=" << section_counts.other
            << " code_counts=" << renderCodeCountsText(filtered_code_counts)
            << " top_codes=" << renderTopCodesText(top_code_counts)
            << " sort_issues=" << sort_issues
            << " sort_top_codes=" << sort_top_codes
            << " verify_profile=" << verify_profile
            << " gate_profile=" << gate_profile
            << " normalization_policy=" << renderNormalizationPolicyName(normalization_policy)
            << " explain_gate_mode=" << explain_gate_mode
            << " min_count=" << min_count
            << " max_total=" << max_total
            << " max_per_code=" << renderMaxPerCodeText(max_per_code)
            << " max_per_section=" << renderMaxPerSectionText(max_per_section)
            << " fail_on_codes=";
        if (fail_on_codes.empty()) {
            out << "none";
        } else {
            bool first = true;
            for (const auto& code : fail_on_codes) {
                if (!first) out << ",";
                first = false;
                out << code;
            }
        }
        out
            << " fail_on_sections=";
        if (fail_on_sections.empty()) {
            out << "none";
        } else {
            bool first = true;
            for (const auto& section : fail_on_sections) {
                if (!first) out << ",";
                first = false;
                out << section;
            }
        }
        out
            << " only_codes=";
        if (only_codes.empty()) {
            out << "none";
        } else {
            bool first = true;
            for (const auto& code : only_codes) {
                if (!first) out << ",";
                first = false;
                out << code;
            }
        }
        out
            << " only_sections=";
        if (only_sections.empty()) {
            out << "none";
        } else {
            bool first = true;
            for (const auto& section : only_sections) {
                if (!first) out << ",";
                first = false;
                out << section;
            }
        }
        out
            << " only_severities=" << renderSeveritySetText(only_severities)
            << " verify_features=" << renderVerifyFeaturesText(verify_features)
            << " gate_pass=" << (gate_pass ? "1" : "0")
            << "\n";
        out << "gate_trigger=" << gate_trigger << "\n";
        out << "gate_trigger_detail=" << gate_trigger_detail << "\n";
        out << "gate_signature=" << gate_signature << "\n";
        out << "gate_observed="
            << "total:" << issues.size()
            << ",errors:" << error_count
            << ",warnings:" << warning_count
            << ",per_code:" << renderCodeCountsText(code_counts)
            << ",per_section:"
            << ".debug_str_offsets:" << section_counts.debug_str_offsets << ";"
            << ".debug_loclists:" << section_counts.debug_loclists << ";"
            << ".debug_rnglists:" << section_counts.debug_rnglists << ";"
            << "other:" << section_counts.other
            << "\n";
        if (emit_gate_explanation) {
            out << "gate_explanation=" << gate_explanation << "\n";
        }
        if (!summary_only) {
            out << "severity|code|section|cu_offset|die_offset|attribute|detail\n";
            for (size_t i = 0; i < shown; ++i) {
                const auto& issue = issues[i];
                out << relocSeverityToString(issue.severity) << "|"
                    << issue.code << "|"
                    << issue.section << "|"
                    << issue.cu_offset << "|"
                    << issue.die_offset << "|"
                    << issue.attribute << "|"
                    << issue.detail << "\n";
            }
            if (truncated) {
                out << "... truncated " << (issues.size() - shown) << " rows\n";
            }
        }
        if (!gate_pass) out << "gate_reason=" << gate_reason << "\n";
    }

    if (!output_path.empty()) {
        std::ofstream f(output_path);
        if (!f) {
            std::cerr << "Error: cannot open output file '" << output_path << "'\n";
            return 1;
        }
        f << out.str();
    } else {
        std::cout << out.str();
    }

    if (!report_only && !gate_pass) {
        std::cerr << "verify-reloc gate FAILED: " << gate_reason << "\n";
        return 2;
    }
    return 0;
}

static int runTriageVendorOps(int argc, char* argv[]) {
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printTriageVendorOpsUsage(argv[0]);
            return 0;
        }
    }
    if (argc < 3) {
        printTriageVendorOpsUsage(argv[0]);
        return 1;
    }

    std::vector<std::string> input_files;
    std::string format = "text";
    std::string output_path;
    int schema_version = 1;
    bool verbose = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        auto split = arg.find('=');
        auto key = (split == std::string::npos) ? arg : arg.substr(0, split);
        auto val = (split == std::string::npos) ? std::string() : arg.substr(split + 1);

        if (key == "-v" || key == "--verbose") {
            verbose = true;
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
        if (key == "--schema-version") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --schema-version value '" << val << "'\n";
                return 1;
            }
            schema_version = static_cast<int>(parsed);
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
        if (key == "--help" || key == "-h") {
            continue;
        }
        if (!arg.empty() && arg[0] == '-') {
            std::cerr << "Error: unknown triage-vendor-ops option '" << arg << "'\n";
            return 1;
        }
        input_files.push_back(arg);
    }

    if (input_files.empty()) {
        std::cerr << "Error: triage-vendor-ops requires at least one input file\n";
        return 1;
    }
    if (format != "json" && schema_version != 1) {
        std::cerr << "Error: --schema-version requires --format=json\n";
        return 1;
    }
    if (schema_version != 1) {
        std::cerr << "Error: unsupported schema version " << schema_version
                  << " for triage-vendor-ops (supported: 1)\n";
        return 1;
    }

    VendorOpcodeTriageReport report = collectVendorOpcodeTriage(input_files, verbose);
    const std::string rendered = (format == "json")
        ? renderVendorOpcodeTriageJson(report, schema_version)
        : renderVendorOpcodeTriageText(report);

    if (!output_path.empty()) {
        std::ofstream file(output_path);
        if (!file) {
            std::cerr << "Error: cannot open output file '" << output_path << "'\n";
            return 1;
        }
        file << rendered;
    } else {
        std::cout << rendered;
    }

    return report.failed_files == report.input_files ? 1 : 0;
}

static bool resolveFunctionPC(const DwarfParser& parser,
                              const std::string& name,
                              uint64_t& out_pc,
                              std::string& out_err) {
    std::vector<std::shared_ptr<DIE>> candidates;
    for (const auto& fn : parser.getFunctions()) {
        if (!fn) continue;
        if (fn->getName() == name) {
            candidates.push_back(fn);
            continue;
        }
        auto ln_attr = fn->getAttribute(DwarfAttribute::DW_AT_linkage_name);
        auto ln = std::dynamic_pointer_cast<StringAttributeValue>(ln_attr);
        if (ln && ln->getValue() == name) {
            candidates.push_back(fn);
        }
    }
    if (candidates.empty()) {
        out_err = "function '" + name + "' not found";
        return false;
    }

    uint64_t best_pc = 0;
    bool has_pc = false;
    for (const auto& fn : candidates) {
        uint64_t pc = getDIELowPC(fn);
        if (!has_pc || (pc != 0 && pc < best_pc)) {
            best_pc = pc;
            has_pc = true;
        }
    }
    if (!has_pc || best_pc == 0) {
        out_err = "function '" + name + "' has no low_pc";
        return false;
    }
    out_pc = best_pc;
    return true;
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
    // Holds an explicitly-loaded BOLT remap; must outlive the comparison call
    // since cmp_opts.bolt_remap points at it.
    BoltAddressRemap explicit_bolt_map;
    std::vector<std::string> selected_names;
    std::string name_prefix_filter;
    std::string name_contains_filter;
    std::string format = "text";
    int schema_version = 0;
    std::string output_path;
    std::set<ExpressionVerificationResult::Verdict> verdict_filters;
    std::string sort_mode = "name";
    bool summary_only = false;
    bool emit_profile_only = false;
    bool emit_solver_summary_only = false;
    size_t max_rows = 0;
    CrossBinaryGateOptions gate_opts;
    bool report_only = false;
    std::string verify_profile = "custom";
    std::string gate_profile = "custom";

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
        if (key == "--reloc-check") {
            cmp_opts.enable_relocation_checks = true;
            continue;
        }
        if (key == "--normalize-loc") {
            applyNormalizationPolicy(cmp_opts, true);
            continue;
        }
        if (key == "--normalization-policy") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            CrossBinaryCompareOptions::NormalizationPolicy policy;
            if (!parseNormalizationPolicy(val, policy)) {
                std::cerr << "Error: invalid --normalization-policy value '" << val
                          << "' (expected off|symbolic-canonical)\n";
                return 1;
            }
            applyNormalizationPolicy(cmp_opts, policy);
            continue;
        }
        if (key == "--range-aware") {
            cmp_opts.enable_range_aware_location_compare = true;
            continue;
        }
        if (key == "--bolt-remap") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val == "auto") {
                cmp_opts.bolt_auto_remap = true;
            } else if (val == "off" || val == "none") {
                cmp_opts.bolt_auto_remap = false;
            } else {
                std::cerr << "Error: invalid --bolt-remap value '" << val
                          << "' (expected auto|off)\n";
                return 1;
            }
            continue;
        }
        if (key == "--bolt-map") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val.empty()) {
                std::cerr << "Error: invalid --bolt-map value (empty)\n";
                return 1;
            }
            std::string bolt_err;
            explicit_bolt_map = loadBoltRemapFromFile(val, bolt_err);
            if (!bolt_err.empty()) {
                std::cerr << "Error: " << bolt_err << "\n";
                return 1;
            }
            cmp_opts.address_remap = [&explicit_bolt_map](uint64_t old_addr) {
                return explicit_bolt_map.apply(old_addr);
            };
            continue;
        }
        if (key == "--vendor-op-profile") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (!parseVendorExpressionProfile(val, cmp_opts.vendor_expression_profile)) {
                std::cerr << "Error: invalid --vendor-op-profile value '" << val
                          << "' (expected none|synthetic-v1)\n";
                return 1;
            }
            continue;
        }
        if (key == "--verify-features") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            VerifyRelocFeatures features;
            features.section_reloc = cmp_opts.enable_relocation_checks;
            features.loc_normalize = cmp_opts.enable_location_semantic_normalization;
            features.range_aware = cmp_opts.enable_range_aware_location_compare;
            if (!parseVerifyFeaturesOption(val, features)) {
                std::cerr << "Error: invalid --verify-features value '" << val
                          << "' (expected comma-separated section-reloc|loc-normalize|range-aware|all|none)\n";
                return 1;
            }
            cmp_opts.enable_relocation_checks = features.section_reloc;
            applyNormalizationPolicy(cmp_opts, features.loc_normalize);
            cmp_opts.enable_range_aware_location_compare = features.range_aware;
            verify_profile = "custom";
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
        if (key == "--schema-version") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --schema-version value '" << val << "'\n";
                return 1;
            }
            schema_version = static_cast<int>(parsed);
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
        if (key == "--emit-profile-only") {
            emit_profile_only = true;
            continue;
        }
        if (key == "--emit-solver-summary-only") {
            emit_solver_summary_only = true;
            continue;
        }
        if (key == "--verify-profile") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            VerifyRelocFeatures features;
            features.section_reloc = cmp_opts.enable_relocation_checks;
            features.loc_normalize = cmp_opts.enable_location_semantic_normalization;
            features.range_aware = cmp_opts.enable_range_aware_location_compare;
            bool is_feature_profile = parseVerifyFeatureProfile(val, features);
            bool is_gate_profile = applyCompareExprGateProfile(val, gate_opts);
            if (!is_feature_profile && !is_gate_profile) {
                std::cerr << "Error: invalid --verify-profile value '" << val
                          << "' (expected off|minimal|default|full|strict|balanced|lenient)\n";
                return 1;
            }
            if (is_gate_profile && !is_feature_profile) {
                features.section_reloc = true;
                features.loc_normalize = true;
                features.range_aware = true;
            }
            if (is_gate_profile) gate_profile = val;
            cmp_opts.enable_relocation_checks = features.section_reloc;
            applyNormalizationPolicy(cmp_opts, features.loc_normalize);
            cmp_opts.enable_range_aware_location_compare = features.range_aware;
            verify_profile = val;
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
        if (key == "--solver-timeout-ms") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed) || parsed > std::numeric_limits<uint32_t>::max()) {
                std::cerr << "Error: invalid --solver-timeout-ms value '" << val
                          << "' (expected integer in [0,4294967295])\n";
                return 1;
            }
            cmp_opts.verification_options.solver_timeout_ms = static_cast<uint32_t>(parsed);
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
            gate_profile = "custom";
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
            gate_profile = "custom";
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
            gate_profile = "custom";
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
            gate_profile = "custom";
            continue;
        }
        if (key == "--fail-on-unknown") {
            gate_opts.fail_on_unknown = true;
            gate_profile = "custom";
            continue;
        }
        if (key == "--fail-on-missing") {
            gate_opts.fail_on_missing = true;
            gate_profile = "custom";
            continue;
        }
        if (key == "--fail-on-solver-result") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val.empty()) {
                std::cerr << "Error: invalid --fail-on-solver-result value (empty)\n";
                return 1;
            }
            gate_opts.fail_on_solver_results.insert(val);
            gate_profile = "custom";
            continue;
        }
        if (key == "--fail-on-verifier-backend") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val.empty()) {
                std::cerr << "Error: invalid --fail-on-verifier-backend value (empty)\n";
                return 1;
            }
            gate_opts.fail_on_verifier_backends.insert(val);
            gate_profile = "custom";
            continue;
        }
        if (key == "--min-equivalent-coverage") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            double parsed = 0.0;
            if (!parseRatioOption(val, parsed)) {
                std::cerr << "Error: invalid --min-equivalent-coverage value '" << val
                          << "' (expected ratio in [0,1])\n";
                return 1;
            }
            gate_opts.min_equivalent_coverage = parsed;
            gate_profile = "custom";
            continue;
        }
        if (key == "--max-different-coverage") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            double parsed = 0.0;
            if (!parseRatioOption(val, parsed)) {
                std::cerr << "Error: invalid --max-different-coverage value '" << val
                          << "' (expected ratio in [0,1])\n";
                return 1;
            }
            gate_opts.max_different_coverage = parsed;
            gate_profile = "custom";
            continue;
        }
        if (key == "--fail-on-uncovered") {
            gate_opts.fail_on_uncovered = true;
            gate_profile = "custom";
            continue;
        }
        if (key == "--report-only") {
            report_only = true;
            continue;
        }
        if (key == "--gate-profile") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (!applyCompareExprGateProfile(val, gate_opts)) {
                std::cerr << "Error: invalid --gate-profile value '" << val
                          << "' (expected strict|balanced|lenient)\n";
                return 1;
            }
            gate_profile = val;
            continue;
        }
        if (key == "--strict") {
            applyCompareExprGateProfile("strict", gate_opts);
            gate_profile = "strict";
            continue;
        }
        if (key == "--allow-unknown") {
            gate_opts.fail_on_unknown = false;
            gate_opts.max_unknown = std::numeric_limits<size_t>::max();
            gate_profile = "custom";
            continue;
        }
        if (key == "--allow-missing") {
            gate_opts.fail_on_missing = false;
            gate_opts.max_missing_lhs = std::numeric_limits<size_t>::max();
            gate_opts.max_missing_rhs = std::numeric_limits<size_t>::max();
            gate_profile = "custom";
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

    if (format == "json" && schema_version != 0 && schema_version != 1) {
        std::cerr << "Error: unsupported --schema-version " << schema_version
                  << " (supported: 0,1)\n";
        return 1;
    }
    if ((emit_profile_only ? 1 : 0) + (emit_solver_summary_only ? 1 : 0) > 1) {
        std::cerr << "Error: cannot combine --emit-profile-only with --emit-solver-summary-only\n";
        return 1;
    }

    CompareExprReportOptions report_opts;
    report_opts.compare_options = cmp_opts;
    report_opts.gate_options = gate_opts;
    report_opts.selected_names = std::move(selected_names);
    report_opts.name_prefix_filter = name_prefix_filter;
    report_opts.name_contains_filter = name_contains_filter;
    report_opts.verdict_filters = verdict_filters;
    report_opts.sort_mode = sort_mode;
    report_opts.verify_profile = verify_profile;
    report_opts.gate_profile = gate_profile;
    report_opts.max_rows = max_rows;
    report_opts.schema_version = schema_version;
    report_opts.summary_only = summary_only;
    report_opts.emit_profile_only = emit_profile_only;
    report_opts.emit_solver_summary_only = emit_solver_summary_only;
    report_opts.report_only = report_only;

    auto exec = executeCompareExpr(lhs,
                                   rhs,
                                   format == "json" ? CompareOutputFormat::JSON : CompareOutputFormat::TEXT,
                                   report_opts);

    if (!output_path.empty()) {
        std::ofstream out(output_path);
        if (!out) {
            std::cerr << "Error: cannot open output file '" << output_path << "'\n";
            return 1;
        }
        out << exec.report;
    } else {
        std::cout << exec.report;
    }

    if (!report_only && !exec.gate.pass) {
        std::cerr << "compare-expr gate FAILED: " << exec.gate.reason << "\n";
        return 2;
    }
    return 0;
}

static int runCompareCFI(int argc, char* argv[]) {
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printCompareCFIUsage(argv[0]);
            return 0;
        }
    }
    if (argc < 4) {
        printCompareCFIUsage(argv[0]);
        return 1;
    }

    std::string lhs_file = argv[2];
    std::string rhs_file = argv[3];

    size_t lhs_fde_index = 0;
    size_t rhs_fde_index = 0;
    bool all_fdes = false;
    std::string pair_by = "index";
    bool lhs_pc_set = false;
    bool rhs_pc_set = false;
    uint64_t lhs_pc = 0;
    uint64_t rhs_pc = 0;
    std::string lhs_func;
    std::string rhs_func;
    std::string format = "text";
    int schema_version = 1;
    std::string output_path;
    bool summary_only = false;
    size_t max_rows = 0;
    std::string sort_mode = "lhs-index";
    bool show_equivalent_rows = true;
    bool equivalent_filter_explicit = false;
    bool only_different_rows = false;
    bool only_unknown_rows = false;
    bool emit_profile_only = false;
    bool emit_solver_summary_only = false;
    bool emit_gate_signature_only = false;
    bool report_only = false;
    std::string gate_profile = "custom";
    size_t max_different = 0;
    size_t max_unknown = std::numeric_limits<size_t>::max();
    size_t max_missing_lhs = std::numeric_limits<size_t>::max();
    size_t max_missing_rhs = std::numeric_limits<size_t>::max();
    bool fail_on_unknown = false;
    bool fail_on_missing = false;
    std::set<std::string> fail_on_solver_results;
    std::set<std::string> fail_on_verifier_backends;
    SymbolicCFICompareOptions cmp_opts;

    for (int i = 4; i < argc; ++i) {
        std::string arg = argv[i];
        auto split = arg.find('=');
        auto key = (split == std::string::npos) ? arg : arg.substr(0, split);
        auto val = (split == std::string::npos) ? std::string() : arg.substr(split + 1);

        if (key == "--lhs-fde-index") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --lhs-fde-index value '" << val << "'\n";
                return 1;
            }
            lhs_fde_index = static_cast<size_t>(parsed);
            continue;
        }
        if (key == "--rhs-fde-index") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --rhs-fde-index value '" << val << "'\n";
                return 1;
            }
            rhs_fde_index = static_cast<size_t>(parsed);
            continue;
        }
        if (key == "--all-fdes") {
            all_fdes = true;
            continue;
        }
        if (key == "--pair-by") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val != "index" && val != "start-pc" && val != "range") {
                std::cerr << "Error: invalid --pair-by value '" << val
                          << "' (expected index|start-pc|range)\n";
                return 1;
            }
            pair_by = val;
            continue;
        }
        if (key == "--lhs-pc") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (!parseUIntOption(val, lhs_pc)) {
                std::cerr << "Error: invalid --lhs-pc value '" << val << "'\n";
                return 1;
            }
            lhs_pc_set = true;
            continue;
        }
        if (key == "--rhs-pc") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (!parseUIntOption(val, rhs_pc)) {
                std::cerr << "Error: invalid --rhs-pc value '" << val << "'\n";
                return 1;
            }
            rhs_pc_set = true;
            continue;
        }
        if (key == "--lhs-func" || key == "--rhs-func" || key == "--func") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val.empty()) {
                std::cerr << "Error: invalid " << key << " value (empty)\n";
                return 1;
            }
            if (key == "--lhs-func" || key == "--func") lhs_func = val;
            if (key == "--rhs-func" || key == "--func") rhs_func = val;
            continue;
        }
        if (key == "--allow-range-mismatch") {
            cmp_opts.require_same_range = false;
            continue;
        }
        if (key == "--strict-range") {
            cmp_opts.require_same_range = true;
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
            if (key == "--lhs-object-address" || key == "--object-address") cmp_opts.lhs_context.object_address = parsed;
            if (key == "--rhs-object-address" || key == "--object-address") cmp_opts.rhs_context.object_address = parsed;
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
            cmp_opts.expression_options.differential_trials = static_cast<size_t>(parsed);
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
            cmp_opts.expression_options.register_count = static_cast<size_t>(parsed);
            continue;
        }
        if (key == "--seed") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --seed value '" << val << "'\n";
                return 1;
            }
            cmp_opts.expression_options.seed = parsed;
            continue;
        }
        if (key == "--no-differential") {
            cmp_opts.expression_options.run_differential = false;
            continue;
        }
        if (key == "--solver-timeout-ms") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed) || parsed > std::numeric_limits<uint32_t>::max()) {
                std::cerr << "Error: invalid --solver-timeout-ms value '" << val
                          << "' (expected integer in [0,4294967295])\n";
                return 1;
            }
            cmp_opts.expression_options.solver_timeout_ms = static_cast<uint32_t>(parsed);
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
        if (key == "--schema-version") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --schema-version value '" << val << "'\n";
                return 1;
            }
            schema_version = static_cast<int>(parsed);
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
        if (key == "--sort") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val != "lhs-index" && val != "rhs-index" &&
                val != "lhs-pc" && val != "rhs-pc" && val != "verdict") {
                std::cerr << "Error: invalid --sort value '" << val
                          << "' (expected lhs-index|rhs-index|lhs-pc|rhs-pc|verdict)\n";
                return 1;
            }
            sort_mode = val;
            continue;
        }
        if (key == "--show-equivalent") {
            show_equivalent_rows = true;
            equivalent_filter_explicit = true;
            continue;
        }
        if (key == "--hide-equivalent") {
            show_equivalent_rows = false;
            equivalent_filter_explicit = true;
            continue;
        }
        if (key == "--only-different") {
            only_different_rows = true;
            continue;
        }
        if (key == "--only-unknown") {
            only_unknown_rows = true;
            continue;
        }
        if (key == "--emit-profile-only") {
            emit_profile_only = true;
            continue;
        }
        if (key == "--emit-solver-summary-only") {
            emit_solver_summary_only = true;
            continue;
        }
        if (key == "--emit-gate-signature-only") {
            emit_gate_signature_only = true;
            continue;
        }
        if (key == "--report-only") {
            report_only = true;
            continue;
        }
        if (key == "--gate-profile") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (!applyCompareCfiGateProfile(
                    val,
                    max_different,
                    max_unknown,
                    max_missing_lhs,
                    max_missing_rhs,
                    fail_on_unknown,
                    fail_on_missing)) {
                std::cerr << "Error: invalid --gate-profile value '" << val
                          << "' (expected strict|balanced|lenient)\n";
                return 1;
            }
            gate_profile = val;
            continue;
        }
        if (key == "--max-different") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --max-different value '" << val << "'\n";
                return 1;
            }
            max_different = static_cast<size_t>(parsed);
            gate_profile = "custom";
            continue;
        }
        if (key == "--max-unknown") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --max-unknown value '" << val << "'\n";
                return 1;
            }
            max_unknown = static_cast<size_t>(parsed);
            gate_profile = "custom";
            continue;
        }
        if (key == "--max-missing-lhs") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --max-missing-lhs value '" << val << "'\n";
                return 1;
            }
            max_missing_lhs = static_cast<size_t>(parsed);
            gate_profile = "custom";
            continue;
        }
        if (key == "--max-missing-rhs") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            uint64_t parsed = 0;
            if (!parseUIntOption(val, parsed)) {
                std::cerr << "Error: invalid --max-missing-rhs value '" << val << "'\n";
                return 1;
            }
            max_missing_rhs = static_cast<size_t>(parsed);
            gate_profile = "custom";
            continue;
        }
        if (key == "--fail-on-unknown") {
            fail_on_unknown = true;
            gate_profile = "custom";
            continue;
        }
        if (key == "--fail-on-missing") {
            fail_on_missing = true;
            gate_profile = "custom";
            continue;
        }
        if (key == "--fail-on-solver-result") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val.empty()) {
                std::cerr << "Error: invalid --fail-on-solver-result value (empty)\n";
                return 1;
            }
            fail_on_solver_results.insert(val);
            gate_profile = "custom";
            continue;
        }
        if (key == "--fail-on-verifier-backend") {
            if (val.empty() && i + 1 < argc) val = argv[++i];
            if (val.empty()) {
                std::cerr << "Error: invalid --fail-on-verifier-backend value (empty)\n";
                return 1;
            }
            fail_on_verifier_backends.insert(val);
            gate_profile = "custom";
            continue;
        }
        if (key == "--strict") {
            applyCompareCfiGateProfile(
                "strict",
                max_different,
                max_unknown,
                max_missing_lhs,
                max_missing_rhs,
                fail_on_unknown,
                fail_on_missing);
            gate_profile = "strict";
            continue;
        }
        if (key == "--allow-unknown") {
            fail_on_unknown = false;
            max_unknown = std::numeric_limits<size_t>::max();
            gate_profile = "custom";
            continue;
        }
        if (key == "--allow-missing") {
            fail_on_missing = false;
            max_missing_lhs = std::numeric_limits<size_t>::max();
            max_missing_rhs = std::numeric_limits<size_t>::max();
            gate_profile = "custom";
            continue;
        }
        std::cerr << "Error: unknown compare-cfi option '" << arg << "'\n";
        return 1;
    }

    if ((!lhs_func.empty() || !rhs_func.empty()) && (lhs_pc_set || rhs_pc_set)) {
        std::cerr << "Error: do not mix --*-pc with --*-func in compare-cfi\n";
        return 1;
    }
    {
        int emit_modes = (emit_profile_only ? 1 : 0) +
                         (emit_solver_summary_only ? 1 : 0) +
                         (emit_gate_signature_only ? 1 : 0);
        if (emit_modes > 1) {
            std::cerr << "Error: emit-only modes are mutually exclusive\n";
            return 1;
        }
    }
    if (all_fdes && (lhs_pc_set || rhs_pc_set || !lhs_func.empty() || !rhs_func.empty())) {
        std::cerr << "Error: --all-fdes cannot be combined with PC/function selector mode\n";
        return 1;
    }
    if (!all_fdes && pair_by != "index") {
        std::cerr << "Error: --pair-by is only valid with --all-fdes\n";
        return 1;
    }
    if (lhs_pc_set != rhs_pc_set) {
        std::cerr << "Error: PC mode requires both --lhs-pc and --rhs-pc\n";
        return 1;
    }
    bool pc_mode = lhs_pc_set && rhs_pc_set;
    bool func_mode = !lhs_func.empty() || !rhs_func.empty();
    if (func_mode && (lhs_func.empty() || rhs_func.empty())) {
        std::cerr << "Error: function mode requires both lhs and rhs function names\n";
        return 1;
    }
    if (only_different_rows && only_unknown_rows) {
        std::cerr << "Error: --only-different and --only-unknown are mutually exclusive\n";
        return 1;
    }
    if (format == "json" && schema_version != 1) {
        std::cerr << "Error: unsupported --schema-version " << schema_version
                  << " (supported: 1)\n";
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
    if (!lhs.hasCFI() || !rhs.hasCFI()) {
        std::cerr << "Error: one or both binaries lack CFI data\n";
        return 1;
    }
    if (func_mode) {
        std::string err;
        if (!::resolveFunctionPC(lhs, lhs_func, lhs_pc, err)) {
            std::cerr << "Error: lhs " << err << "\n";
            return 1;
        }
        if (!::resolveFunctionPC(rhs, rhs_func, rhs_pc, err)) {
            std::cerr << "Error: rhs " << err << "\n";
            return 1;
        }
        lhs_pc_set = rhs_pc_set = true;
        pc_mode = true;
    }

    CompareCFIReportOptions report_opts;
    report_opts.all_fdes = all_fdes;
    report_opts.pc_mode = pc_mode;
    report_opts.func_mode = func_mode;
    report_opts.lhs_fde_index = lhs_fde_index;
    report_opts.rhs_fde_index = rhs_fde_index;
    report_opts.lhs_pc = lhs_pc;
    report_opts.rhs_pc = rhs_pc;
    report_opts.lhs_func = lhs_func;
    report_opts.rhs_func = rhs_func;
    report_opts.pair_by = pair_by;
    report_opts.sort_mode = sort_mode;
    report_opts.gate_profile = gate_profile;
    report_opts.max_rows = max_rows;
    report_opts.schema_version = schema_version;
    report_opts.show_equivalent_rows = show_equivalent_rows;
    report_opts.equivalent_filter_explicit = equivalent_filter_explicit;
    report_opts.only_different_rows = only_different_rows;
    report_opts.only_unknown_rows = only_unknown_rows;
    report_opts.summary_only = summary_only;
    report_opts.emit_profile_only = emit_profile_only;
    report_opts.emit_solver_summary_only = emit_solver_summary_only;
    report_opts.emit_gate_signature_only = emit_gate_signature_only;
    report_opts.report_only = report_only;
    report_opts.max_different = max_different;
    report_opts.max_unknown = max_unknown;
    report_opts.max_missing_lhs = max_missing_lhs;
    report_opts.max_missing_rhs = max_missing_rhs;
    report_opts.fail_on_unknown = fail_on_unknown;
    report_opts.fail_on_missing = fail_on_missing;
    report_opts.fail_on_solver_results = fail_on_solver_results;
    report_opts.fail_on_verifier_backends = fail_on_verifier_backends;
    report_opts.compare_options = cmp_opts;

    auto exec = executeCompareCFI(lhs,
                                  rhs,
                                  format == "json" ? CompareOutputFormat::JSON : CompareOutputFormat::TEXT,
                                  report_opts);

    if (!output_path.empty()) {
        std::ofstream file(output_path);
        if (!file) {
            std::cerr << "Error: cannot open output file '" << output_path << "'\n";
            return 1;
        }
        file << exec.report;
    } else {
        std::cout << exec.report;
    }

    if (!report_only && !exec.gate_pass) {
        std::cerr << "compare-cfi gate FAILED: " << exec.gate_reason << "\n";
        return 2;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc >= 2 && std::string(argv[1]) == "compare-expr") {
        return runCompareExpr(argc, argv);
    }
    if (argc >= 2 && std::string(argv[1]) == "compare-cfi") {
        return runCompareCFI(argc, argv);
    }
    if (argc >= 2 && std::string(argv[1]) == "verify-reloc") {
        return runVerifyReloc(argc, argv);
    }
    if (argc >= 2 && std::string(argv[1]) == "triage-vendor-ops") {
        return runTriageVendorOps(argc, argv);
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
        {"show-support", no_argument, nullptr, 1006},
        {"format", required_argument, nullptr, 1007},
        {"dwp", required_argument, nullptr, 1008},
        {"schema-version", required_argument, nullptr, 1009},
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
            case 1006: opts.show_support = true; break;
            case 1007:
                opts.output_format = optarg ? std::string(optarg) : std::string();
                if (opts.output_format != "text" && opts.output_format != "json") {
                    std::cerr << "Error: invalid --format '" << opts.output_format
                              << "' (expected text|json)\n";
                    return 1;
                }
                break;
            case 1008:
                opts.dwp_file = optarg ? std::string(optarg) : std::string();
                if (opts.dwp_file.empty()) {
                    std::cerr << "Error: --dwp requires a path\n";
                    return 1;
                }
                break;
            case 1009: {
                uint64_t parsed = 0;
                if (!parseUIntOption(optarg ? std::string(optarg) : std::string(), parsed)) {
                    std::cerr << "Error: invalid --schema-version value '" << (optarg ? optarg : "") << "'\n";
                    return 1;
                }
                opts.support_schema_version = static_cast<int>(parsed);
                opts.support_schema_version_set = true;
                break;
            }
            case 'h':
            default:
                printUsage(argv[0]);
                return opt == 'h' ? 0 : 1;
        }
    }

    if (opts.output_format != "text" && !opts.show_support) {
        std::cerr << "Error: --format is only supported with --show-support in main mode\n";
        return 1;
    }
    if (opts.support_schema_version_set && !opts.show_support) {
        std::cerr << "Error: --schema-version is only supported with --show-support in main mode\n";
        return 1;
    }
    if (opts.support_schema_version_set && opts.output_format != "json") {
        std::cerr << "Error: --schema-version requires --format=json with --show-support\n";
        return 1;
    }
    if (opts.output_format == "json" &&
        opts.show_support &&
        opts.support_schema_version != 1 &&
        opts.support_schema_version != 2) {
        std::cerr << "Error: unsupported --schema-version " << opts.support_schema_version
                  << " for --show-support (supported: 1,2)\n";
        return 1;
    }

    if (optind >= argc) {
        if (opts.show_support) {
            printSupportMatrix(nullptr, opts.output_format, opts.support_schema_version, opts.verbose);
            return 0;
        }
        std::cerr << "Error: No input file specified\n";
        printUsage(argv[0]);
        return 1;
    }

    opts.input_file = argv[optind];

    // If no specific section requested, default to summary
    if (!opts.dump_info && !opts.dump_abbrev && !opts.dump_line &&
        !opts.dump_frames && !opts.dump_ranges && !opts.dump_str &&
        !opts.dump_loc && !opts.dump_names && !opts.dump_macro &&
        !opts.dump_all && !opts.show_support &&
        opts.find_name.empty() && opts.die_offset == 0) {
        opts.summary = true;
    }

    // Load DWARF info
    DwarfParser parser(opts.input_file);
    parser.setVerbose(opts.verbose);
    if (!opts.verbose) {
        // Suppress debug output
        std::cerr.setstate(std::ios_base::failbit);
    }

    if (!opts.dwp_file.empty()) {
        if (!parser.loadDWPFile(opts.dwp_file)) {
            std::cerr.clear();
            std::cerr << "Error: Failed to load DWP file " << opts.dwp_file << "\n";
            return 1;
        }
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
    if (opts.show_support) {
        if (opts.summary || opts.dump_all) {
            std::cout << "\n";
        }
        printSupportMatrix(&parser, opts.output_format, opts.support_schema_version, opts.verbose);
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

    if (opts.dump_names || opts.dump_all) {
        dumpDebugNames(parser, opts);
    }

    // Other sections would be implemented similarly...

    return 0;
}
