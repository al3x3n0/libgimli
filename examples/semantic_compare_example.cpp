#include "dwarf_parser.hpp"
#include "expression_compare.hpp"
#include "cfi_symbolic.hpp"

#include <iostream>
#include <string>

using namespace dwarf;

namespace {

const char* verdictToString(ExpressionVerificationResult::Verdict v) {
    switch (v) {
        case ExpressionVerificationResult::Verdict::EQUIVALENT: return "EQUIVALENT";
        case ExpressionVerificationResult::Verdict::DIFFERENT: return "DIFFERENT";
        case ExpressionVerificationResult::Verdict::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

int loadParser(DwarfParser& parser, const std::string& path) {
    if (!parser.load() || !parser.isValid()) {
        std::cerr << "failed to load ELF/DWARF: " << path << "\n";
        return 1;
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <lhs.elf> <rhs.elf>\n";
        return 1;
    }

    const std::string lhs_path = argv[1];
    const std::string rhs_path = argv[2];

    DwarfParser lhs(lhs_path);
    DwarfParser rhs(rhs_path);
    if (loadParser(lhs, lhs_path) != 0 || loadParser(rhs, rhs_path) != 0) return 1;

    // 1) Cross-binary location expression compare for variables by name.
    CrossBinaryExpressionComparator cmp;
    CrossBinaryCompareOptions compare_opts;
    compare_opts.tag = DwarfTag::DW_TAG_variable;
    compare_opts.attribute = DwarfAttribute::DW_AT_location;
    compare_opts.include_missing = true;
    compare_opts.verification_options.solver_timeout_ms = 200;

    auto rows = cmp.compareParsersByName(lhs, rhs, compare_opts);
    auto summary = cmp.summarize(rows);

    CrossBinaryGateOptions gate_opts;
    gate_opts.max_different = 0;
    gate_opts.fail_on_solver_results.insert("unknown");
    gate_opts.fail_on_verifier_backends.insert("unspecified");
    auto gate = cmp.evaluateGate(rows, gate_opts);

    std::cout << "[compare-expr API]\n";
    std::cout << "summary: total=" << summary.total
              << " eq=" << summary.equivalent
              << " diff=" << summary.different
              << " unk=" << summary.unknown
              << " missing_lhs=" << summary.missing_lhs
              << " missing_rhs=" << summary.missing_rhs << "\n";
    std::cout << "gate: pass=" << (gate.pass ? 1 : 0)
              << " trigger=" << gate.trigger
              << " detail=" << gate.trigger_detail
              << " reason=" << gate.reason
              << " signature=" << gate.signature << "\n";
    std::cout << "json_report_sample:\n" << cmp.renderJsonReport(rows, /*max_rows=*/2) << "\n";

    // 2) Symbolic CFI compare example (index 0 vs 0 if both binaries have FDEs).
    std::cout << "\n[compare-cfi API]\n";
    if (!lhs.hasCFI() || !rhs.hasCFI()) {
        std::cout << "CFI not available in one of the binaries\n";
        return 0;
    }
    if (lhs.getCFIParser().getFDEs().empty() || rhs.getCFIParser().getFDEs().empty()) {
        std::cout << "No FDE entries available in one of the binaries\n";
        return 0;
    }

    SymbolicCFIVerifier cfi_verifier;
    SymbolicCFICompareOptions cfi_opts;
    cfi_opts.expression_options.solver_timeout_ms = 200;
    auto cfi = cfi_verifier.compareFDEByIndex(lhs.getCFIParser(), 0, rhs.getCFIParser(), 0, cfi_opts);

    std::cout << "verdict=" << verdictToString(cfi.verdict)
              << " backend=" << cfi.verifier_backend
              << " solver_result=" << cfi.solver_result
              << " points_checked=" << cfi.points_checked
              << " reason=" << cfi.reason << "\n";
    if (!cfi.counterexample_witness.empty()) {
        std::cout << "witness=" << cfi.counterexample_witness << "\n";
    }

    return 0;
}
