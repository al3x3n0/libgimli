#include "cfg_reconstruction.hpp"
#include <elfio/elfio.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <getopt.h>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct Options {
    std::string input_file;
    std::string format = "text";
    std::string mapping_level = "function";
    bool show_unmapped = false;
    bool require_bolt = false;
    bool emit_dfg_json = false;
    bool dfg_summary_only = false;
    bool emit_analysis_json = false;
    bool has_max_indirect_call_increase_total = false;
    int64_t max_indirect_call_increase_total = 0;
    bool has_max_resolution_rate_drop_total = false;
    double max_resolution_rate_drop_total = 0.0;
    uint64_t min_size = 0;
};

struct FuncSymbol {
    std::string name;
    std::string section_name;
    uint64_t address = 0;
    uint64_t size = 0;
};

struct Mapping {
    std::string name;
    uint64_t old_address = 0;
    uint64_t old_size = 0;
    uint64_t new_address = 0;
    uint64_t new_size = 0;
};

struct FunctionBytes {
    std::string name;
    uint64_t address = 0;
    uint64_t size = 0;
    std::vector<uint8_t> bytes;
};

struct BlockMapping {
    std::string function_name;
    uint64_t old_block = 0;
    uint64_t new_block = 0;
    uint64_t old_size = 0;
    uint64_t new_size = 0;
};

struct FunctionDFGPair {
    std::string function_name;
    dwarf::DataFlowGraph old_dfg;
    dwarf::DataFlowGraph new_dfg;
};

struct DFGStats {
    size_t nodes = 0;
    size_t edges = 0;
    size_t cross_block_edges = 0;
    size_t unique_regs = 0;
};

struct CFGStats {
    size_t blocks = 0;
    size_t edges = 0;
    double avg_out_degree = 0.0;
    int64_t cyclomatic_complexity = 1;
};

struct FunctionAnalysis {
    std::string function_name;
    CFGStats old_cfg;
    CFGStats new_cfg;
    DFGStats old_dfg;
    DFGStats new_dfg;
    size_t matched_blocks = 0;
    double matched_block_coverage = 0.0;
    dwarf::FunctionPointerAnalysisResult old_fp;
    dwarf::FunctionPointerAnalysisResult new_fp;
    double old_resolution_rate = 0.0;
    double new_resolution_rate = 0.0;
    double old_avg_best_confidence = 0.0;
    double new_avg_best_confidence = 0.0;
};

struct AnalysisSummary {
    size_t functions = 0;
    size_t total_indirect_calls_old = 0;
    size_t total_indirect_calls_new = 0;
    size_t resolved_calls_old = 0;
    size_t resolved_calls_new = 0;
    double resolution_rate_old = 0.0;
    double resolution_rate_new = 0.0;
    double avg_best_confidence_old = 0.0;
    double avg_best_confidence_new = 0.0;
    std::string max_indirect_call_increase_function;
    int64_t max_indirect_call_increase = 0;
    std::string worst_resolution_drop_function;
    double worst_resolution_drop = 0.0;
};

struct AnalysisGate {
    bool enabled = false;
    bool pass = true;
    std::string trigger;
    std::string detail;
};

DFGStats computeDFGStats(const dwarf::DataFlowGraph& dfg) {
    DFGStats s;
    s.nodes = dfg.nodes.size();
    s.edges = dfg.edges.size();
    std::set<uint16_t> regs;
    for (const auto& n : dfg.nodes) {
        for (uint16_t r : n.defs) regs.insert(r);
        for (uint16_t r : n.uses) regs.insert(r);
    }
    for (const auto& e : dfg.edges) {
        regs.insert(e.reg);
        if (e.cross_block) ++s.cross_block_edges;
    }
    s.unique_regs = regs.size();
    return s;
}

CFGStats computeCFGStats(const dwarf::ControlFlowGraph& cfg) {
    CFGStats s;
    s.blocks = cfg.blocks.size();
    for (const auto& b : cfg.blocks) s.edges += b.successors.size();
    if (s.blocks == 0) return s;
    s.avg_out_degree = static_cast<double>(s.edges) / static_cast<double>(s.blocks);
    s.cyclomatic_complexity = static_cast<int64_t>(s.edges) - static_cast<int64_t>(s.blocks) + 2;
    return s;
}

double bestConfidenceForCallsite(const std::vector<FuncSymbol>& symbols,
                                 const dwarf::FunctionPointerCallsite& cs) {
    double best = 0.0;
    for (uint64_t addr : cs.candidate_target_addresses) {
        for (const auto& sym : symbols) {
            if (sym.address == addr) {
                if (1.0 > best) best = 1.0;
                continue;
            }
            if (sym.size > 0 && addr >= sym.address && addr < sym.address + sym.size) {
                if (0.7 > best) best = 0.7;
            }
        }
    }
    return best;
}

void computeFunctionPointerQuality(const std::vector<FuncSymbol>& symbols,
                                   const dwarf::FunctionPointerAnalysisResult& fp,
                                   double& out_resolution_rate,
                                   double& out_avg_best_confidence) {
    size_t resolved = 0;
    double sum_best = 0.0;
    for (const auto& cs : fp.callsites) {
        const double best = bestConfidenceForCallsite(symbols, cs);
        if (best > 0.0) {
            ++resolved;
            sum_best += best;
        }
    }
    if (fp.indirect_calls > 0) {
        out_resolution_rate = static_cast<double>(resolved) / static_cast<double>(fp.indirect_calls);
    } else {
        out_resolution_rate = 0.0;
    }
    if (resolved > 0) {
        out_avg_best_confidence = sum_best / static_cast<double>(resolved);
    } else {
        out_avg_best_confidence = 0.0;
    }
}

AnalysisSummary computeAnalysisSummary(const std::vector<FunctionAnalysis>& analyses,
                                      const std::vector<FuncSymbol>& original_symbols,
                                      const std::vector<FuncSymbol>& optimized_symbols) {
    AnalysisSummary s;
    s.functions = analyses.size();
    int64_t best_delta_icalls = 0;
    bool seen_delta = false;
    double worst_delta_resolution = 0.0;
    double sum_best_old = 0.0;
    double sum_best_new = 0.0;
    for (const auto& a : analyses) {
        const int64_t delta_icalls =
            static_cast<int64_t>(a.new_fp.indirect_calls) - static_cast<int64_t>(a.old_fp.indirect_calls);
        if (!seen_delta || delta_icalls > best_delta_icalls) {
            seen_delta = true;
            best_delta_icalls = delta_icalls;
            s.max_indirect_call_increase = delta_icalls;
            s.max_indirect_call_increase_function = a.function_name;
        }
        const double delta_resolution = a.new_resolution_rate - a.old_resolution_rate;
        if (delta_resolution < worst_delta_resolution) {
            worst_delta_resolution = delta_resolution;
            s.worst_resolution_drop = delta_resolution;
            s.worst_resolution_drop_function = a.function_name;
        }

        s.total_indirect_calls_old += a.old_fp.indirect_calls;
        s.total_indirect_calls_new += a.new_fp.indirect_calls;
        for (const auto& cs : a.old_fp.callsites) {
            const double best = bestConfidenceForCallsite(original_symbols, cs);
            if (best > 0.0) {
                ++s.resolved_calls_old;
                sum_best_old += best;
            }
        }
        for (const auto& cs : a.new_fp.callsites) {
            const double best = bestConfidenceForCallsite(optimized_symbols, cs);
            if (best > 0.0) {
                ++s.resolved_calls_new;
                sum_best_new += best;
            }
        }
    }
    if (s.total_indirect_calls_old > 0) {
        s.resolution_rate_old =
            static_cast<double>(s.resolved_calls_old) / static_cast<double>(s.total_indirect_calls_old);
    }
    if (s.total_indirect_calls_new > 0) {
        s.resolution_rate_new =
            static_cast<double>(s.resolved_calls_new) / static_cast<double>(s.total_indirect_calls_new);
    }
    if (s.resolved_calls_old > 0) {
        s.avg_best_confidence_old = sum_best_old / static_cast<double>(s.resolved_calls_old);
    }
    if (s.resolved_calls_new > 0) {
        s.avg_best_confidence_new = sum_best_new / static_cast<double>(s.resolved_calls_new);
    }
    return s;
}

AnalysisGate evaluateAnalysisGate(const Options& opts, const AnalysisSummary& summary) {
    AnalysisGate gate;
    gate.enabled = opts.has_max_indirect_call_increase_total || opts.has_max_resolution_rate_drop_total;
    if (!gate.enabled) return gate;

    const int64_t observed_indirect_increase =
        static_cast<int64_t>(summary.total_indirect_calls_new) - static_cast<int64_t>(summary.total_indirect_calls_old);
    const double observed_resolution_drop = summary.resolution_rate_old - summary.resolution_rate_new;

    if (opts.has_max_indirect_call_increase_total &&
        observed_indirect_increase > opts.max_indirect_call_increase_total) {
        gate.pass = false;
        gate.trigger = "max_indirect_call_increase_total";
        std::ostringstream oss;
        oss << "observed=" << observed_indirect_increase
            << " threshold=" << opts.max_indirect_call_increase_total;
        gate.detail = oss.str();
        return gate;
    }
    if (opts.has_max_resolution_rate_drop_total &&
        observed_resolution_drop > opts.max_resolution_rate_drop_total) {
        gate.pass = false;
        gate.trigger = "max_resolution_rate_drop_total";
        std::ostringstream oss;
        oss << "observed=" << observed_resolution_drop
            << " threshold=" << opts.max_resolution_rate_drop_total;
        gate.detail = oss.str();
        return gate;
    }
    gate.pass = true;
    gate.trigger = "none";
    gate.detail = "within thresholds";
    return gate;
}

bool startsWith(const std::string& s, const std::string& prefix) {
    return s.rfind(prefix, 0) == 0;
}

bool isBoltMarkerSection(const std::string& section_name) {
    return startsWith(section_name, ".bolt.");
}

bool isOriginalTextSection(const std::string& section_name) {
    return section_name == ".bolt.org.text" || startsWith(section_name, ".bolt.org.text.");
}

bool isOptimizedTextSection(const std::string& section_name) {
    if (isOriginalTextSection(section_name)) return false;
    if (section_name == ".text") return true;
    if (startsWith(section_name, ".text.")) return true;
    if (section_name == ".bolt.text") return true;
    if (startsWith(section_name, ".bolt.text.")) return true;
    return false;
}

const ELFIO::section* findSection(const ELFIO::elfio& elf, const std::string& section_name) {
    for (const auto& section : elf.sections) {
        if (section->get_name() == section_name) return section.get();
    }
    return nullptr;
}

bool extractFunctionBytes(const ELFIO::elfio& elf, const FuncSymbol& sym, FunctionBytes& out) {
    const ELFIO::section* section = findSection(elf, sym.section_name);
    if (!section) return false;
    const uint64_t sec_addr = section->get_address();
    const uint64_t sec_size = section->get_size();
    if (sym.address < sec_addr) return false;
    const uint64_t start_off = sym.address - sec_addr;
    if (start_off >= sec_size) return false;
    uint64_t wanted = sym.size;
    if (wanted == 0 || start_off + wanted > sec_size) {
        wanted = sec_size - start_off;
    }
    const char* data = section->get_data();
    if (!data) return false;

    out.name = sym.name;
    out.address = sym.address;
    out.size = wanted;
    out.bytes.resize(static_cast<size_t>(wanted));
    std::memcpy(out.bytes.data(), data + start_off, static_cast<size_t>(wanted));
    return true;
}

std::vector<std::string> resolveFunctionNamesAtAddress(const std::vector<FuncSymbol>& symbols, uint64_t address) {
    std::set<std::string> names;
    for (const auto& sym : symbols) {
        if (sym.address == address) {
            names.insert(sym.name);
            continue;
        }
        if (sym.size > 0 && address >= sym.address && address < sym.address + sym.size) {
            names.insert(sym.name);
        }
    }
    return std::vector<std::string>(names.begin(), names.end());
}

struct SymbolScoreEvidence {
    double confidence = 0.0;
    std::string reason;
};

std::map<std::string, SymbolScoreEvidence> resolveFunctionNameScoresAtAddress(const std::vector<FuncSymbol>& symbols, uint64_t address) {
    std::map<std::string, SymbolScoreEvidence> scores;
    for (const auto& sym : symbols) {
        double conf = 0.0;
        const char* reason = nullptr;
        if (sym.address == address) {
            conf = 1.0;
            reason = "exact_start";
        } else if (sym.size > 0 && address >= sym.address && address < sym.address + sym.size) {
            conf = 0.7;
            reason = "in_function_range";
        } else {
            continue;
        }
        auto it = scores.find(sym.name);
        if (it == scores.end() || conf > it->second.confidence) {
            scores[sym.name] = SymbolScoreEvidence{conf, reason ? reason : "unknown"};
        }
    }
    return scores;
}

std::map<std::string, SymbolScoreEvidence> mergeFunctionNameScores(const std::vector<FuncSymbol>& symbols,
                                                                    const std::vector<uint64_t>& candidate_addresses) {
    std::map<std::string, SymbolScoreEvidence> merged;
    for (uint64_t addr : candidate_addresses) {
        const auto part = resolveFunctionNameScoresAtAddress(symbols, addr);
        for (const auto& kv : part) {
            auto it = merged.find(kv.first);
            if (it == merged.end() || kv.second.confidence > it->second.confidence) {
                merged[kv.first] = kv.second;
            }
        }
    }
    return merged;
}

std::string jsonEscape(const std::string& in) {
    std::ostringstream out;
    for (char c : in) {
        switch (c) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out << "\\u00" << std::hex << std::setw(2) << std::setfill('0')
                        << static_cast<unsigned int>(static_cast<unsigned char>(c))
                        << std::dec << std::setfill(' ');
                } else {
                    out << c;
                }
        }
    }
    return out.str();
}

const FuncSymbol* selectBest(const std::vector<FuncSymbol>& symbols) {
    if (symbols.empty()) return nullptr;
    return &(*std::max_element(symbols.begin(), symbols.end(), [](const FuncSymbol& a, const FuncSymbol& b) {
        if (a.size != b.size) return a.size < b.size;
        return a.address > b.address;
    }));
}

bool parseUint64(const char* raw, uint64_t& out) {
    if (!raw || *raw == '\0') return false;
    char* end = nullptr;
    errno = 0;
    unsigned long long value = std::strtoull(raw, &end, 0);
    if (errno != 0 || end == raw || *end != '\0') return false;
    out = static_cast<uint64_t>(value);
    return true;
}

bool parseInt64(const char* raw, int64_t& out) {
    if (!raw || *raw == '\0') return false;
    char* end = nullptr;
    errno = 0;
    long long value = std::strtoll(raw, &end, 0);
    if (errno != 0 || end == raw || *end != '\0') return false;
    out = static_cast<int64_t>(value);
    return true;
}

bool parseDouble(const char* raw, double& out) {
    if (!raw || *raw == '\0') return false;
    char* end = nullptr;
    errno = 0;
    const double value = std::strtod(raw, &end);
    if (errno != 0 || end == raw || *end != '\0') return false;
    out = value;
    return true;
}

void printUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " [options] <elf-file>\n\n"
              << "Detects function address mappings in BOLT-optimized binaries.\n\n"
              << "Options:\n"
              << "  --format=<text|json>   Output format (default: text)\n"
              << "  --mapping-level=<function|block>\n"
              << "                        Report function mapping (default) or AArch64 basic-block mapping\n"
              << "  --show-unmapped        Emit symbols that do not map across old/new text\n"
              << "  --min-size=<N>         Ignore functions smaller than N bytes\n"
              << "  --require-bolt         Exit with code 2 when BOLT markers are absent\n"
              << "  --emit-dfg-json        Include per-function AArch64 register DFG in JSON output\n"
              << "  --dfg-summary-only     Emit only per-function DFG stats (requires --emit-dfg-json)\n"
              << "  --emit-analysis-json   Include comparative CFG/DFG metrics in JSON output\n"
              << "  --max-indirect-call-increase-total=<N>\n"
              << "                        Gate fail when total indirect-call increase exceeds N\n"
              << "  --max-resolution-rate-drop-total=<R>\n"
              << "                        Gate fail when total resolution-rate drop exceeds R\n"
              << "  -h, --help             Show this help\n";
}

} // namespace

int main(int argc, char** argv) {
    Options opts;

    static option long_options[] = {
        {"format", required_argument, nullptr, 1},
        {"mapping-level", required_argument, nullptr, 2},
        {"show-unmapped", no_argument, nullptr, 3},
        {"min-size", required_argument, nullptr, 4},
        {"require-bolt", no_argument, nullptr, 5},
        {"emit-dfg-json", no_argument, nullptr, 6},
        {"dfg-summary-only", no_argument, nullptr, 7},
        {"emit-analysis-json", no_argument, nullptr, 8},
        {"max-indirect-call-increase-total", required_argument, nullptr, 9},
        {"max-resolution-rate-drop-total", required_argument, nullptr, 10},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };

    while (true) {
        int option_index = 0;
        int c = getopt_long(argc, argv, "h", long_options, &option_index);
        if (c == -1) break;
        if (c == 'h') {
            printUsage(argv[0]);
            return 0;
        }
        if (c == 1) {
            opts.format = optarg ? optarg : "";
            if (opts.format != "text" && opts.format != "json") {
                std::cerr << "Error: invalid --format '" << opts.format << "' (expected text|json)\n";
                return 1;
            }
            continue;
        }
        if (c == 2) {
            opts.mapping_level = optarg ? optarg : "";
            if (opts.mapping_level != "function" && opts.mapping_level != "block") {
                std::cerr << "Error: invalid --mapping-level '" << opts.mapping_level
                          << "' (expected function|block)\n";
                return 1;
            }
            continue;
        }
        if (c == 3) {
            opts.show_unmapped = true;
            continue;
        }
        if (c == 4) {
            if (!parseUint64(optarg, opts.min_size)) {
                std::cerr << "Error: invalid --min-size value '" << (optarg ? optarg : "") << "'\n";
                return 1;
            }
            continue;
        }
        if (c == 5) {
            opts.require_bolt = true;
            continue;
        }
        if (c == 6) {
            opts.emit_dfg_json = true;
            continue;
        }
        if (c == 7) {
            opts.dfg_summary_only = true;
            continue;
        }
        if (c == 8) {
            opts.emit_analysis_json = true;
            continue;
        }
        if (c == 9) {
            if (!parseInt64(optarg, opts.max_indirect_call_increase_total)) {
                std::cerr << "Error: invalid --max-indirect-call-increase-total value '"
                          << (optarg ? optarg : "") << "'\n";
                return 1;
            }
            opts.has_max_indirect_call_increase_total = true;
            continue;
        }
        if (c == 10) {
            if (!parseDouble(optarg, opts.max_resolution_rate_drop_total)) {
                std::cerr << "Error: invalid --max-resolution-rate-drop-total value '"
                          << (optarg ? optarg : "") << "'\n";
                return 1;
            }
            opts.has_max_resolution_rate_drop_total = true;
            continue;
        }
        std::cerr << "Error: unknown option\n";
        return 1;
    }

    if (optind >= argc) {
        printUsage(argv[0]);
        return 1;
    }
    opts.input_file = argv[optind++];
    if (optind != argc) {
        std::cerr << "Error: unexpected argument '" << argv[optind] << "'\n";
        return 1;
    }
    if (opts.emit_dfg_json && opts.format != "json") {
        std::cerr << "Error: --emit-dfg-json requires --format=json\n";
        return 1;
    }
    if (opts.dfg_summary_only && !opts.emit_dfg_json) {
        std::cerr << "Error: --dfg-summary-only requires --emit-dfg-json\n";
        return 1;
    }
    if (opts.emit_analysis_json && opts.format != "json") {
        std::cerr << "Error: --emit-analysis-json requires --format=json\n";
        return 1;
    }
    if ((opts.has_max_indirect_call_increase_total || opts.has_max_resolution_rate_drop_total) &&
        opts.mapping_level != "block") {
        std::cerr << "Error: analysis gates require --mapping-level=block\n";
        return 1;
    }

    ELFIO::elfio elf;
    if (!elf.load(opts.input_file)) {
        std::cerr << "Error: failed to load ELF file '" << opts.input_file << "'\n";
        return 1;
    }

    bool bolt_detected = false;
    std::set<std::string> bolt_sections;
    for (const auto& section : elf.sections) {
        const std::string sec_name = section->get_name();
        if (isBoltMarkerSection(sec_name)) {
            bolt_detected = true;
            bolt_sections.insert(sec_name);
        }
    }
    const auto reloc_ranges_by_section = dwarf::CFGReconstructor::collectRelocationRangesBySection(elf);

    std::map<std::string, std::vector<FuncSymbol>> original_by_name;
    std::map<std::string, std::vector<FuncSymbol>> optimized_by_name;
    std::vector<FuncSymbol> original_symbols;
    std::vector<FuncSymbol> optimized_symbols;
    size_t original_symbol_count = 0;
    size_t optimized_symbol_count = 0;

    for (const auto& section : elf.sections) {
        if (section->get_type() != ELFIO::SHT_SYMTAB && section->get_type() != ELFIO::SHT_DYNSYM) {
            continue;
        }
        ELFIO::symbol_section_accessor symbols(elf, const_cast<ELFIO::section*>(section.get()));
        const size_t symbol_count = symbols.get_symbols_num();
        for (size_t i = 0; i < symbol_count; ++i) {
            std::string name;
            ELFIO::Elf64_Addr value = 0;
            ELFIO::Elf_Xword size = 0;
            unsigned char bind = 0;
            unsigned char type = 0;
            ELFIO::Elf_Half section_index = 0;
            unsigned char other = 0;
            (void)bind;
            (void)other;

            if (!symbols.get_symbol(i, name, value, size, bind, type, section_index, other)) continue;
            if (name.empty()) continue;
            if (type != ELFIO::STT_FUNC) continue;
            if (section_index == ELFIO::SHN_UNDEF || section_index >= elf.sections.size()) continue;
            if (value == 0) continue;
            if (size < opts.min_size) continue;

            const std::string sec_name = elf.sections[section_index]->get_name();
            FuncSymbol sym{name, sec_name, static_cast<uint64_t>(value), static_cast<uint64_t>(size)};
            if (isOriginalTextSection(sec_name)) {
                ++original_symbol_count;
                original_by_name[name].push_back(sym);
                original_symbols.push_back(sym);
            } else if (isOptimizedTextSection(sec_name)) {
                ++optimized_symbol_count;
                optimized_by_name[name].push_back(sym);
                optimized_symbols.push_back(sym);
            }
        }
    }

    std::vector<Mapping> mappings;
    mappings.reserve(original_by_name.size());
    size_t unmapped_original = 0;
    size_t unmapped_optimized = 0;

    for (const auto& kv : original_by_name) {
        const auto& name = kv.first;
        const auto* old_best = selectBest(kv.second);
        auto it_new = optimized_by_name.find(name);
        if (old_best == nullptr || it_new == optimized_by_name.end()) {
            ++unmapped_original;
            continue;
        }
        const auto* new_best = selectBest(it_new->second);
        if (!new_best) {
            ++unmapped_original;
            continue;
        }
        mappings.push_back(Mapping{name, old_best->address, old_best->size, new_best->address, new_best->size});
    }
    for (const auto& kv : optimized_by_name) {
        if (original_by_name.find(kv.first) == original_by_name.end()) {
            ++unmapped_optimized;
        }
    }

    std::sort(mappings.begin(), mappings.end(), [](const Mapping& a, const Mapping& b) {
        if (a.old_address != b.old_address) return a.old_address < b.old_address;
        return a.name < b.name;
    });

    std::vector<BlockMapping> block_mappings;
    std::vector<FunctionDFGPair> function_dfgs;
    std::vector<FunctionAnalysis> analyses;
    if (opts.mapping_level == "block") {
        if (elf.get_machine() != ELFIO::EM_AARCH64) {
            std::cerr << "Error: block mapping currently supports AArch64 only\n";
            return 1;
        }
        dwarf::CFGReconstructionOptions cfg_opts;
        cfg_opts.include_fallthrough_edges = true;
        cfg_opts.normalize_pc_relative_immediates = true;
        for (const auto& m : mappings) {
            FuncSymbol old_sym{m.name, ".bolt.org.text", m.old_address, m.old_size};
            FuncSymbol new_sym{m.name, ".text", m.new_address, m.new_size};

            auto old_it = original_by_name.find(m.name);
            auto new_it = optimized_by_name.find(m.name);
            if (old_it == original_by_name.end() || new_it == optimized_by_name.end()) continue;
            const FuncSymbol* best_old = selectBest(old_it->second);
            const FuncSymbol* best_new = selectBest(new_it->second);
            if (!best_old || !best_new) continue;

            old_sym = *best_old;
            new_sym = *best_new;

            FunctionBytes old_fb;
            FunctionBytes new_fb;
            if (!extractFunctionBytes(elf, old_sym, old_fb)) continue;
            if (!extractFunctionBytes(elf, new_sym, new_fb)) continue;
            if (old_fb.bytes.empty() || new_fb.bytes.empty()) continue;

            dwarf::ControlFlowGraph old_cfg;
            dwarf::ControlFlowGraph new_cfg;
            dwarf::CFGReconstructionOptions old_cfg_opts = cfg_opts;
            dwarf::CFGReconstructionOptions new_cfg_opts = cfg_opts;
            auto old_reloc_it = reloc_ranges_by_section.find(old_sym.section_name);
            if (old_reloc_it != reloc_ranges_by_section.end()) {
                old_cfg_opts.relocation_ranges = old_reloc_it->second;
            }
            auto new_reloc_it = reloc_ranges_by_section.find(new_sym.section_name);
            if (new_reloc_it != reloc_ranges_by_section.end()) {
                new_cfg_opts.relocation_ranges = new_reloc_it->second;
            }
            if (!dwarf::CFGReconstructor::reconstruct(
                    old_fb.bytes,
                    old_fb.address,
                    old_fb.size,
                    dwarf::CFGArchitecture::AARCH64,
                    old_cfg,
                    old_cfg_opts)) {
                continue;
            }
            if (!dwarf::CFGReconstructor::reconstruct(
                    new_fb.bytes,
                    new_fb.address,
                    new_fb.size,
                    dwarf::CFGArchitecture::AARCH64,
                    new_cfg,
                    new_cfg_opts)) {
                continue;
            }

            const auto cfg_matches = dwarf::CFGMatcher::matchBlocks(old_cfg, new_cfg);
            for (const auto& match : cfg_matches) {
                block_mappings.push_back(BlockMapping{
                    m.name,
                    match.old_block,
                    match.new_block,
                    match.old_size,
                    match.new_size
                });
            }

            dwarf::DataFlowGraph old_dfg;
            dwarf::DataFlowGraph new_dfg;
            bool dfg_ok = false;
            if (opts.emit_dfg_json || opts.emit_analysis_json) {
                dfg_ok = dwarf::DFGBuilder::buildAArch64RegisterDFG(
                             old_fb.bytes, old_fb.address, old_fb.size, old_cfg, old_dfg) &&
                         dwarf::DFGBuilder::buildAArch64RegisterDFG(
                             new_fb.bytes, new_fb.address, new_fb.size, new_cfg, new_dfg);
            }

            if (opts.emit_dfg_json && dfg_ok) {
                function_dfgs.push_back(FunctionDFGPair{m.name, old_dfg, new_dfg});
            }

            if (opts.emit_analysis_json) {
                const size_t max_blocks = std::max(old_cfg.blocks.size(), new_cfg.blocks.size());
                FunctionAnalysis a;
                a.function_name = m.name;
                a.old_cfg = computeCFGStats(old_cfg);
                a.new_cfg = computeCFGStats(new_cfg);
                a.old_dfg = dfg_ok ? computeDFGStats(old_dfg) : DFGStats{};
                a.new_dfg = dfg_ok ? computeDFGStats(new_dfg) : DFGStats{};
                a.matched_blocks = cfg_matches.size();
                a.matched_block_coverage =
                    (max_blocks == 0) ? 1.0 : static_cast<double>(cfg_matches.size()) / static_cast<double>(max_blocks);
                if (dfg_ok) {
                    (void)dwarf::FunctionPointerAnalyzer::analyzeAArch64(
                        old_fb.bytes, old_fb.address, old_fb.size, old_dfg, a.old_fp);
                    (void)dwarf::FunctionPointerAnalyzer::analyzeAArch64(
                        new_fb.bytes, new_fb.address, new_fb.size, new_dfg, a.new_fp);
                    computeFunctionPointerQuality(
                        original_symbols, a.old_fp, a.old_resolution_rate, a.old_avg_best_confidence);
                    computeFunctionPointerQuality(
                        optimized_symbols, a.new_fp, a.new_resolution_rate, a.new_avg_best_confidence);
                }
                analyses.push_back(a);
            }

            if (opts.emit_dfg_json && !dfg_ok) {
                continue;
            }

            if (opts.emit_dfg_json) {
                // DFG already appended above if available.
            }
        }
        std::sort(block_mappings.begin(), block_mappings.end(), [](const BlockMapping& a, const BlockMapping& b) {
            if (a.old_block != b.old_block) return a.old_block < b.old_block;
            return a.function_name < b.function_name;
        });
        std::sort(function_dfgs.begin(), function_dfgs.end(), [](const FunctionDFGPair& a, const FunctionDFGPair& b) {
            return a.function_name < b.function_name;
        });
        std::sort(analyses.begin(), analyses.end(), [](const FunctionAnalysis& a, const FunctionAnalysis& b) {
            return a.function_name < b.function_name;
        });
    }
    const AnalysisSummary analysis_summary = computeAnalysisSummary(analyses, original_symbols, optimized_symbols);
    const AnalysisGate analysis_gate = evaluateAnalysisGate(opts, analysis_summary);

    if (opts.format == "json") {
        std::cout << "{";
        std::cout << "\"input\":\"" << jsonEscape(opts.input_file) << "\",";
        std::cout << "\"mapping_level\":\"" << jsonEscape(opts.mapping_level) << "\",";
        std::cout << "\"bolt_detected\":" << (bolt_detected ? "true" : "false") << ",";
        std::cout << "\"bolt_sections\":[";
        bool first = true;
        for (const auto& sec : bolt_sections) {
            if (!first) std::cout << ",";
            first = false;
            std::cout << "\"" << jsonEscape(sec) << "\"";
        }
        std::cout << "],";
        std::cout << "\"counts\":{"
                  << "\"original_symbols\":" << original_symbol_count << ","
                  << "\"optimized_symbols\":" << optimized_symbol_count << ","
                  << "\"mappings\":" << mappings.size() << ","
                  << "\"block_mappings\":" << block_mappings.size() << ","
                  << "\"unmapped_original\":" << unmapped_original << ","
                  << "\"unmapped_optimized\":" << unmapped_optimized
                  << "},";
        std::cout << "\"mappings\":[";
        for (size_t i = 0; i < mappings.size(); ++i) {
            const auto& m = mappings[i];
            if (i != 0) std::cout << ",";
            const int64_t delta = static_cast<int64_t>(m.new_address) - static_cast<int64_t>(m.old_address);
            std::cout << "{"
                      << "\"name\":\"" << jsonEscape(m.name) << "\","
                      << "\"old_address\":" << m.old_address << ","
                      << "\"new_address\":" << m.new_address << ","
                      << "\"delta\":" << delta << ","
                      << "\"old_size\":" << m.old_size << ","
                      << "\"new_size\":" << m.new_size
                      << "}";
        }
        std::cout << "]";
        if (opts.mapping_level == "block") {
            std::cout << ",\"block_mappings\":[";
            for (size_t i = 0; i < block_mappings.size(); ++i) {
                const auto& b = block_mappings[i];
                if (i != 0) std::cout << ",";
                const int64_t delta = static_cast<int64_t>(b.new_block) - static_cast<int64_t>(b.old_block);
                std::cout << "{"
                          << "\"function\":\"" << jsonEscape(b.function_name) << "\","
                          << "\"old_block\":" << b.old_block << ","
                          << "\"new_block\":" << b.new_block << ","
                          << "\"delta\":" << delta << ","
                          << "\"old_size\":" << b.old_size << ","
                          << "\"new_size\":" << b.new_size
                          << "}";
            }
            std::cout << "]";
        }
        if (opts.emit_dfg_json) {
            std::cout << ",\"dfg\":[";
            for (size_t i = 0; i < function_dfgs.size(); ++i) {
                if (i != 0) std::cout << ",";
                const auto& f = function_dfgs[i];
                std::cout << "{";
                std::cout << "\"function\":\"" << jsonEscape(f.function_name) << "\",";
                if (opts.dfg_summary_only) {
                    const DFGStats old_stats = computeDFGStats(f.old_dfg);
                    const DFGStats new_stats = computeDFGStats(f.new_dfg);
                    std::cout << "\"old_stats\":{"
                              << "\"nodes\":" << old_stats.nodes << ","
                              << "\"edges\":" << old_stats.edges << ","
                              << "\"cross_block_edges\":" << old_stats.cross_block_edges << ","
                              << "\"unique_regs\":" << old_stats.unique_regs
                              << "},";
                    std::cout << "\"new_stats\":{"
                              << "\"nodes\":" << new_stats.nodes << ","
                              << "\"edges\":" << new_stats.edges << ","
                              << "\"cross_block_edges\":" << new_stats.cross_block_edges << ","
                              << "\"unique_regs\":" << new_stats.unique_regs
                              << "}";
                } else {
                    std::cout << "\"old\":{";
                    std::cout << "\"nodes\":[";
                    for (size_t ni = 0; ni < f.old_dfg.nodes.size(); ++ni) {
                        if (ni != 0) std::cout << ",";
                        const auto& n = f.old_dfg.nodes[ni];
                        std::cout << "{";
                        std::cout << "\"instruction_address\":" << n.instruction_address << ",";
                        std::cout << "\"block_start\":" << n.block_start << ",";
                        std::cout << "\"defs\":[";
                        for (size_t ri = 0; ri < n.defs.size(); ++ri) {
                            if (ri != 0) std::cout << ",";
                            std::cout << n.defs[ri];
                        }
                        std::cout << "],\"uses\":[";
                        for (size_t ri = 0; ri < n.uses.size(); ++ri) {
                            if (ri != 0) std::cout << ",";
                            std::cout << n.uses[ri];
                        }
                        std::cout << "]}";
                    }
                    std::cout << "],\"edges\":[";
                    for (size_t ei = 0; ei < f.old_dfg.edges.size(); ++ei) {
                        if (ei != 0) std::cout << ",";
                        const auto& e = f.old_dfg.edges[ei];
                        std::cout << "{"
                                  << "\"from\":" << e.from_node << ","
                                  << "\"to\":" << e.to_node << ","
                                  << "\"reg\":" << e.reg << ","
                                  << "\"cross_block\":" << (e.cross_block ? "true" : "false")
                                  << "}";
                    }
                    std::cout << "]},\"new\":{";
                    std::cout << "\"nodes\":[";
                    for (size_t ni = 0; ni < f.new_dfg.nodes.size(); ++ni) {
                        if (ni != 0) std::cout << ",";
                        const auto& n = f.new_dfg.nodes[ni];
                        std::cout << "{";
                        std::cout << "\"instruction_address\":" << n.instruction_address << ",";
                        std::cout << "\"block_start\":" << n.block_start << ",";
                        std::cout << "\"defs\":[";
                        for (size_t ri = 0; ri < n.defs.size(); ++ri) {
                            if (ri != 0) std::cout << ",";
                            std::cout << n.defs[ri];
                        }
                        std::cout << "],\"uses\":[";
                        for (size_t ri = 0; ri < n.uses.size(); ++ri) {
                            if (ri != 0) std::cout << ",";
                            std::cout << n.uses[ri];
                        }
                        std::cout << "]}";
                    }
                    std::cout << "],\"edges\":[";
                    for (size_t ei = 0; ei < f.new_dfg.edges.size(); ++ei) {
                        if (ei != 0) std::cout << ",";
                        const auto& e = f.new_dfg.edges[ei];
                        std::cout << "{"
                                  << "\"from\":" << e.from_node << ","
                                  << "\"to\":" << e.to_node << ","
                                  << "\"reg\":" << e.reg << ","
                                  << "\"cross_block\":" << (e.cross_block ? "true" : "false")
                                  << "}";
                    }
                    std::cout << "]}";
                }
                std::cout << "}";
            }
            std::cout << "]";
        }
        if (opts.emit_analysis_json) {
            std::cout << ",\"analysis\":[";
            for (size_t i = 0; i < analyses.size(); ++i) {
                if (i != 0) std::cout << ",";
                const auto& a = analyses[i];
                std::cout << "{"
                          << "\"function\":\"" << jsonEscape(a.function_name) << "\","
                          << "\"matched_blocks\":" << a.matched_blocks << ","
                          << "\"matched_block_coverage\":" << a.matched_block_coverage << ","
                          << "\"delta_indirect_calls\":"
                          << (static_cast<int64_t>(a.new_fp.indirect_calls) -
                              static_cast<int64_t>(a.old_fp.indirect_calls))
                          << ","
                          << "\"old_resolution_rate\":" << a.old_resolution_rate << ","
                          << "\"new_resolution_rate\":" << a.new_resolution_rate << ","
                          << "\"delta_resolution_rate\":" << (a.new_resolution_rate - a.old_resolution_rate) << ","
                          << "\"old_avg_best_confidence\":" << a.old_avg_best_confidence << ","
                          << "\"new_avg_best_confidence\":" << a.new_avg_best_confidence << ","
                          << "\"delta_avg_best_confidence\":"
                          << (a.new_avg_best_confidence - a.old_avg_best_confidence) << ","
                          << "\"old_cfg\":{"
                          << "\"blocks\":" << a.old_cfg.blocks << ","
                          << "\"edges\":" << a.old_cfg.edges << ","
                          << "\"avg_out_degree\":" << a.old_cfg.avg_out_degree << ","
                          << "\"cyclomatic_complexity\":" << a.old_cfg.cyclomatic_complexity
                          << "},"
                          << "\"new_cfg\":{"
                          << "\"blocks\":" << a.new_cfg.blocks << ","
                          << "\"edges\":" << a.new_cfg.edges << ","
                          << "\"avg_out_degree\":" << a.new_cfg.avg_out_degree << ","
                          << "\"cyclomatic_complexity\":" << a.new_cfg.cyclomatic_complexity
                          << "},"
                          << "\"old_dfg\":{"
                          << "\"nodes\":" << a.old_dfg.nodes << ","
                          << "\"edges\":" << a.old_dfg.edges << ","
                          << "\"cross_block_edges\":" << a.old_dfg.cross_block_edges << ","
                          << "\"unique_regs\":" << a.old_dfg.unique_regs
                          << "},"
                          << "\"new_dfg\":{"
                          << "\"nodes\":" << a.new_dfg.nodes << ","
                          << "\"edges\":" << a.new_dfg.edges << ","
                          << "\"cross_block_edges\":" << a.new_dfg.cross_block_edges << ","
                          << "\"unique_regs\":" << a.new_dfg.unique_regs
                          << "},"
                          << "\"old_fp\":{"
                          << "\"indirect_calls\":" << a.old_fp.indirect_calls << ","
                          << "\"callsites\":[";
                for (size_t ci = 0; ci < a.old_fp.callsites.size(); ++ci) {
                    if (ci != 0) std::cout << ",";
                    const auto& cs = a.old_fp.callsites[ci];
                    std::cout << "{"
                              << "\"instruction_address\":" << cs.instruction_address << ","
                              << "\"pointer_reg\":" << cs.pointer_reg << ","
                              << "\"reaching_def_instructions\":[";
                    for (size_t di = 0; di < cs.reaching_def_instructions.size(); ++di) {
                        if (di != 0) std::cout << ",";
                        std::cout << cs.reaching_def_instructions[di];
                    }
                    std::cout << "],\"candidate_target_addresses\":[";
                    for (size_t ti = 0; ti < cs.candidate_target_addresses.size(); ++ti) {
                        if (ti != 0) std::cout << ",";
                        std::cout << cs.candidate_target_addresses[ti];
                    }
                    std::cout << "],\"candidate_target_symbols\":[";
                    std::set<std::string> syms;
                    for (uint64_t cand : cs.candidate_target_addresses) {
                        const auto names = resolveFunctionNamesAtAddress(original_symbols, cand);
                        syms.insert(names.begin(), names.end());
                    }
                    bool first_sym = true;
                    for (const auto& name : syms) {
                        if (!first_sym) std::cout << ",";
                        first_sym = false;
                        std::cout << "\"" << jsonEscape(name) << "\"";
                    }
                    std::cout << "],\"candidate_target_symbol_scores\":[";
                    const auto scores = mergeFunctionNameScores(original_symbols, cs.candidate_target_addresses);
                    bool first_score = true;
                    for (const auto& kv : scores) {
                        if (!first_score) std::cout << ",";
                        first_score = false;
                        std::cout << "{"
                                  << "\"name\":\"" << jsonEscape(kv.first) << "\","
                                  << "\"confidence\":" << kv.second.confidence << ","
                                  << "\"reason\":\"" << jsonEscape(kv.second.reason) << "\""
                                  << "}";
                    }
                    std::cout << "]}";
                }
                std::cout << "]},"
                          << "\"new_fp\":{"
                          << "\"indirect_calls\":" << a.new_fp.indirect_calls << ","
                          << "\"callsites\":[";
                for (size_t ci = 0; ci < a.new_fp.callsites.size(); ++ci) {
                    if (ci != 0) std::cout << ",";
                    const auto& cs = a.new_fp.callsites[ci];
                    std::cout << "{"
                              << "\"instruction_address\":" << cs.instruction_address << ","
                              << "\"pointer_reg\":" << cs.pointer_reg << ","
                              << "\"reaching_def_instructions\":[";
                    for (size_t di = 0; di < cs.reaching_def_instructions.size(); ++di) {
                        if (di != 0) std::cout << ",";
                        std::cout << cs.reaching_def_instructions[di];
                    }
                    std::cout << "],\"candidate_target_addresses\":[";
                    for (size_t ti = 0; ti < cs.candidate_target_addresses.size(); ++ti) {
                        if (ti != 0) std::cout << ",";
                        std::cout << cs.candidate_target_addresses[ti];
                    }
                    std::cout << "],\"candidate_target_symbols\":[";
                    std::set<std::string> syms;
                    for (uint64_t cand : cs.candidate_target_addresses) {
                        const auto names = resolveFunctionNamesAtAddress(optimized_symbols, cand);
                        syms.insert(names.begin(), names.end());
                    }
                    bool first_sym = true;
                    for (const auto& name : syms) {
                        if (!first_sym) std::cout << ",";
                        first_sym = false;
                        std::cout << "\"" << jsonEscape(name) << "\"";
                    }
                    std::cout << "],\"candidate_target_symbol_scores\":[";
                    const auto scores = mergeFunctionNameScores(optimized_symbols, cs.candidate_target_addresses);
                    bool first_score = true;
                    for (const auto& kv : scores) {
                        if (!first_score) std::cout << ",";
                        first_score = false;
                        std::cout << "{"
                                  << "\"name\":\"" << jsonEscape(kv.first) << "\","
                                  << "\"confidence\":" << kv.second.confidence << ","
                                  << "\"reason\":\"" << jsonEscape(kv.second.reason) << "\""
                                  << "}";
                    }
                    std::cout << "]}";
                }
                std::cout << "]}"
                          << "}";
            }
            std::cout << "]";
            std::cout << ",\"analysis_summary\":{"
                      << "\"functions\":" << analysis_summary.functions << ","
                      << "\"total_indirect_calls_old\":" << analysis_summary.total_indirect_calls_old << ","
                      << "\"total_indirect_calls_new\":" << analysis_summary.total_indirect_calls_new << ","
                      << "\"delta_indirect_calls\":"
                      << (static_cast<int64_t>(analysis_summary.total_indirect_calls_new) -
                          static_cast<int64_t>(analysis_summary.total_indirect_calls_old))
                      << ","
                      << "\"resolved_calls_old\":" << analysis_summary.resolved_calls_old << ","
                      << "\"resolved_calls_new\":" << analysis_summary.resolved_calls_new << ","
                      << "\"resolution_rate_old\":" << analysis_summary.resolution_rate_old << ","
                      << "\"resolution_rate_new\":" << analysis_summary.resolution_rate_new << ","
                      << "\"avg_best_confidence_old\":" << analysis_summary.avg_best_confidence_old << ","
                      << "\"avg_best_confidence_new\":" << analysis_summary.avg_best_confidence_new << ","
                      << "\"max_indirect_call_increase_function\":\""
                      << jsonEscape(analysis_summary.max_indirect_call_increase_function) << "\","
                      << "\"max_indirect_call_increase\":" << analysis_summary.max_indirect_call_increase << ","
                      << "\"worst_resolution_drop_function\":\""
                      << jsonEscape(analysis_summary.worst_resolution_drop_function) << "\","
                      << "\"worst_resolution_drop\":" << analysis_summary.worst_resolution_drop
                      << "}";
            std::cout << ",\"analysis_gate\":{"
                      << "\"enabled\":" << (analysis_gate.enabled ? "true" : "false") << ","
                      << "\"pass\":" << (analysis_gate.pass ? "true" : "false") << ","
                      << "\"trigger\":\"" << jsonEscape(analysis_gate.trigger) << "\","
                      << "\"detail\":\"" << jsonEscape(analysis_gate.detail) << "\""
                      << "}";
        }
        if (opts.show_unmapped) {
            std::cout << ",\"unmapped\":{";
            std::cout << "\"original_only\":[";
            bool first_unmapped = true;
            for (const auto& kv : original_by_name) {
                if (optimized_by_name.find(kv.first) != optimized_by_name.end()) continue;
                if (!first_unmapped) std::cout << ",";
                first_unmapped = false;
                std::cout << "\"" << jsonEscape(kv.first) << "\"";
            }
            std::cout << "],\"optimized_only\":[";
            first_unmapped = true;
            for (const auto& kv : optimized_by_name) {
                if (original_by_name.find(kv.first) != original_by_name.end()) continue;
                if (!first_unmapped) std::cout << ",";
                first_unmapped = false;
                std::cout << "\"" << jsonEscape(kv.first) << "\"";
            }
            std::cout << "]}";
        }
        std::cout << "}\n";
    } else {
        std::cout << "input=" << opts.input_file << "\n";
        std::cout << "mapping_level=" << opts.mapping_level << "\n";
        std::cout << "bolt_detected=" << (bolt_detected ? "true" : "false") << "\n";
        std::cout << "bolt_sections=";
        if (bolt_sections.empty()) {
            std::cout << "none\n";
        } else {
            bool first = true;
            for (const auto& sec : bolt_sections) {
                if (!first) std::cout << ",";
                first = false;
                std::cout << sec;
            }
            std::cout << "\n";
        }
        std::cout << "original_symbols=" << original_symbol_count << "\n";
        std::cout << "optimized_symbols=" << optimized_symbol_count << "\n";
        std::cout << "mappings=" << mappings.size() << "\n";
        std::cout << "block_mappings=" << block_mappings.size() << "\n";
        if (opts.emit_dfg_json) {
            std::cout << "dfg_functions=" << function_dfgs.size() << "\n";
        }
        if (opts.emit_analysis_json) {
            std::cout << "analysis_functions=" << analyses.size() << "\n";
            std::cout << "analysis_total_indirect_calls_old=" << analysis_summary.total_indirect_calls_old << "\n";
            std::cout << "analysis_total_indirect_calls_new=" << analysis_summary.total_indirect_calls_new << "\n";
            std::cout << "analysis_resolution_rate_old=" << analysis_summary.resolution_rate_old << "\n";
            std::cout << "analysis_resolution_rate_new=" << analysis_summary.resolution_rate_new << "\n";
            std::cout << "analysis_max_indirect_call_increase_function="
                      << analysis_summary.max_indirect_call_increase_function << "\n";
            std::cout << "analysis_max_indirect_call_increase="
                      << analysis_summary.max_indirect_call_increase << "\n";
            std::cout << "analysis_worst_resolution_drop_function="
                      << analysis_summary.worst_resolution_drop_function << "\n";
            std::cout << "analysis_worst_resolution_drop="
                      << analysis_summary.worst_resolution_drop << "\n";
            std::cout << "analysis_gate_enabled=" << (analysis_gate.enabled ? "true" : "false") << "\n";
            std::cout << "analysis_gate_pass=" << (analysis_gate.pass ? "true" : "false") << "\n";
            std::cout << "analysis_gate_trigger=" << analysis_gate.trigger << "\n";
        }
        std::cout << "unmapped_original=" << unmapped_original << "\n";
        std::cout << "unmapped_optimized=" << unmapped_optimized << "\n";
        if (!mappings.empty()) {
            std::cout << "name|old_addr|new_addr|delta|old_size|new_size\n";
            for (const auto& m : mappings) {
                const int64_t delta = static_cast<int64_t>(m.new_address) - static_cast<int64_t>(m.old_address);
                std::cout << m.name << "|0x" << std::hex << m.old_address
                          << "|0x" << m.new_address << std::dec
                          << "|" << delta
                          << "|" << m.old_size
                          << "|" << m.new_size << "\n";
            }
        }
        if (opts.mapping_level == "block" && !block_mappings.empty()) {
            std::cout << "function|old_block|new_block|delta|old_size|new_size\n";
            for (const auto& b : block_mappings) {
                const int64_t delta = static_cast<int64_t>(b.new_block) - static_cast<int64_t>(b.old_block);
                std::cout << b.function_name
                          << "|0x" << std::hex << b.old_block
                          << "|0x" << b.new_block << std::dec
                          << "|" << delta
                          << "|" << b.old_size
                          << "|" << b.new_size << "\n";
            }
        }
        if (opts.show_unmapped) {
            for (const auto& kv : original_by_name) {
                if (optimized_by_name.find(kv.first) != optimized_by_name.end()) continue;
                std::cout << "unmapped_original_name=" << kv.first << "\n";
            }
            for (const auto& kv : optimized_by_name) {
                if (original_by_name.find(kv.first) != original_by_name.end()) continue;
                std::cout << "unmapped_optimized_name=" << kv.first << "\n";
            }
        }
    }

    if (!bolt_detected && opts.require_bolt) {
        std::cerr << "Error: input file does not look BOLT-optimized (no .bolt.* sections found)\n";
        return 2;
    }
    if (analysis_gate.enabled && !analysis_gate.pass) {
        std::cerr << "Error: analysis gate failed (" << analysis_gate.trigger << "): "
                  << analysis_gate.detail << "\n";
        return 2;
    }

    return 0;
}
