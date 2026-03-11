#pragma once

#include "cfi_symbolic.hpp"
#include "expression_compare.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace dwarf {

enum class CompareOutputFormat {
    TEXT,
    JSON
};

struct CompareExprReportOptions {
    CrossBinaryCompareOptions compare_options;
    CrossBinaryGateOptions gate_options;
    std::vector<std::string> selected_names;
    std::string name_prefix_filter;
    std::string name_contains_filter;
    std::set<ExpressionVerificationResult::Verdict> verdict_filters;
    std::string sort_mode = "name";
    std::string verify_profile = "custom";
    std::string gate_profile = "custom";
    size_t max_rows = 0;
    int schema_version = 0;
    bool summary_only = false;
    bool emit_profile_only = false;
    bool emit_solver_summary_only = false;
    bool report_only = false;
};

struct CompareExprExecutionResult {
    std::vector<NamedExpressionComparison> comparisons;
    CrossBinaryGateResult gate;
    std::string gate_signature;
    std::string report;
};

struct CFICompareRow {
    size_t lhs_index = 0;
    size_t rhs_index = 0;
    ExpressionVerificationResult::Verdict verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
    std::string reason;
    size_t points_checked = 0;
    bool has_mismatch_pc = false;
    uint64_t mismatch_pc = 0;
    bool has_lhs_fde = false;
    bool has_rhs_fde = false;
    uint64_t lhs_initial_location = 0;
    uint64_t lhs_address_range = 0;
    uint64_t rhs_initial_location = 0;
    uint64_t rhs_address_range = 0;
    std::string lhs_function_name;
    std::string rhs_function_name;
    std::string lhs_summary;
    std::string rhs_summary;
    std::string verifier_backend;
    std::string solver_result;
    std::string counterexample_model;
    std::string counterexample_witness;
};

struct CompareCFIReportOptions {
    bool all_fdes = false;
    bool pc_mode = false;
    bool func_mode = false;
    size_t lhs_fde_index = 0;
    size_t rhs_fde_index = 0;
    uint64_t lhs_pc = 0;
    uint64_t rhs_pc = 0;
    std::string lhs_func;
    std::string rhs_func;
    std::string pair_by = "index";
    std::string sort_mode = "lhs-index";
    std::string gate_profile = "custom";
    size_t max_rows = 0;
    int schema_version = 1;
    bool show_equivalent_rows = true;
    bool equivalent_filter_explicit = false;
    bool only_different_rows = false;
    bool only_unknown_rows = false;
    bool summary_only = false;
    bool emit_profile_only = false;
    bool emit_solver_summary_only = false;
    bool emit_gate_signature_only = false;
    bool report_only = false;
    size_t max_different = 0;
    size_t max_unknown = static_cast<size_t>(-1);
    size_t max_missing_lhs = static_cast<size_t>(-1);
    size_t max_missing_rhs = static_cast<size_t>(-1);
    bool fail_on_unknown = false;
    bool fail_on_missing = false;
    std::set<std::string> fail_on_solver_results;
    std::set<std::string> fail_on_verifier_backends;
    SymbolicCFICompareOptions compare_options;
};

struct CompareCFIExecutionResult {
    std::vector<CFICompareRow> rows;
    size_t equivalent = 0;
    size_t different = 0;
    size_t unknown = 0;
    size_t missing_lhs = 0;
    size_t missing_rhs = 0;
    bool gate_pass = true;
    std::string gate_reason;
    std::string gate_trigger = "none";
    std::string gate_trigger_detail;
    std::string gate_signature;
    std::map<std::string, size_t> solver_result_counts;
    std::map<std::string, size_t> verifier_backend_counts;
    std::string report;
};

CompareExprExecutionResult executeCompareExpr(const DwarfParser& lhs,
                                              const DwarfParser& rhs,
                                              CompareOutputFormat format,
                                              const CompareExprReportOptions& options = {});

bool resolveFunctionPC(const DwarfParser& parser,
                       const std::string& name,
                       uint64_t& out_pc,
                       std::string& error);

CompareCFIExecutionResult executeCompareCFI(const DwarfParser& lhs,
                                            const DwarfParser& rhs,
                                            CompareOutputFormat format,
                                            const CompareCFIReportOptions& options = {});

} // namespace dwarf
