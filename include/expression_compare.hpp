#pragma once

#include "die_parser.hpp"
#include "dwarf_parser.hpp"
#include "symbolic_verifier.hpp"
#include <limits>
#include <memory>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace dwarf {

enum class CompareKeyMode {
    NAME_ONLY,
    LINKAGE_OR_NAME
};

struct CrossBinaryCompareOptions {
    DwarfTag tag = DwarfTag::DW_TAG_variable;
    DwarfAttribute attribute = DwarfAttribute::DW_AT_location;
    CompareKeyMode key_mode = CompareKeyMode::NAME_ONLY;
    // If true, only compare paired DIEs where both sides have `attribute`.
    bool require_attribute_on_both = false;
    bool include_missing = true;
    bool use_location_list_pc = false;
    uint64_t lhs_location_list_pc = 0;
    uint64_t rhs_location_list_pc = 0;
    uint64_t lhs_evaluation_pc = 0;
    uint64_t rhs_evaluation_pc = 0;
    EvaluationContext lhs_context;
    EvaluationContext rhs_context;
    std::vector<uint64_t> lhs_registers;
    std::vector<uint64_t> rhs_registers;
    ExpressionVerificationOptions verification_options;
    VendorExpressionProfile vendor_expression_profile = VendorExpressionProfile::NONE;
    // Optional extension checks (disabled by default to preserve existing behavior).
    bool enable_relocation_checks = false;
    bool enable_location_semantic_normalization = false;
    bool enable_range_aware_location_compare = false;
};

struct LocationRangeSegmentVerdict {
    uint64_t start = 0;
    uint64_t end = 0;
    ExpressionVerificationResult::Verdict verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
    bool lhs_present = false;
    bool rhs_present = false;
    std::string reason;
    std::string reason_class;
    std::string isolation_kind;
    std::string solver_result;
    std::string diagnosis_origin;
    std::optional<uint8_t> lhs_unsupported_opcode;
    std::optional<uint8_t> rhs_unsupported_opcode;
    bool lhs_unsupported_vendor_extension = false;
    bool rhs_unsupported_vendor_extension = false;
};

struct NamedExpressionComparison {
    std::string name;
    DwarfTag tag = DwarfTag::DW_TAG_variable;
    bool lhs_present = false;
    bool rhs_present = false;
    uint64_t lhs_offset = 0;
    uint64_t rhs_offset = 0;
    ExpressionVerificationResult verification;
    bool range_aware = false;
    uint64_t coverage_total = 0;
    uint64_t coverage_equivalent = 0;
    uint64_t coverage_different = 0;
    uint64_t coverage_unknown = 0;
    uint64_t coverage_uncovered = 0;
    uint64_t coverage_unsupported = 0;
    size_t unsupported_segment_count = 0;
    std::vector<std::string> relocation_issues;
    std::vector<LocationRangeSegmentVerdict> range_segments;
};

struct CrossBinaryComparisonSummary {
    size_t total = 0;
    size_t equivalent = 0;
    size_t different = 0;
    size_t unknown = 0;
    size_t missing_lhs = 0;
    size_t missing_rhs = 0;
    uint64_t coverage_total = 0;
    uint64_t coverage_equivalent = 0;
    uint64_t coverage_different = 0;
    uint64_t coverage_unknown = 0;
    uint64_t coverage_uncovered = 0;
    uint64_t coverage_unsupported = 0;
    size_t normalized_equal = 0;
    size_t normalization_attempted = 0;
    size_t normalization_changed = 0;
    size_t unsupported_isolated_rows = 0;
    size_t unsupported_row_count = 0;
    size_t unsupported_segment_count = 0;
    std::map<std::string, size_t> unknown_reason_counts;
    std::map<std::string, size_t> unknown_reason_class_counts;
    std::map<std::string, size_t> unknown_solver_result_counts;
    std::map<std::string, size_t> unknown_lhs_attribute_kind_counts;
    std::map<std::string, size_t> unknown_rhs_attribute_kind_counts;
    std::map<std::string, size_t> unsupported_opcode_counts;
    std::map<std::string, size_t> unsupported_isolation_kind_counts;
    std::map<std::string, size_t> normalization_kind_counts;
};

struct CrossBinaryGateOptions {
    // Hard limits. Any summary field above limit causes failure.
    size_t max_different = 0;
    size_t max_unknown = std::numeric_limits<size_t>::max();
    size_t max_missing_lhs = std::numeric_limits<size_t>::max();
    size_t max_missing_rhs = std::numeric_limits<size_t>::max();

    // Optional stricter toggles for common CI policies.
    bool fail_on_unknown = false;
    bool fail_on_missing = false;
    // Disallow specific solver result buckets (e.g. "unknown", "encoding_error", "unsat", "sat").
    std::set<std::string> fail_on_solver_results;
    // Disallow specific verifier backends (e.g. "z3", "structural", "structural+z3").
    std::set<std::string> fail_on_verifier_backends;
    // Optional range-aware coverage gates.
    // Enabled when corresponding threshold differs from default permissive values.
    double min_equivalent_coverage = 0.0;
    double max_different_coverage = 1.0;
    bool fail_on_uncovered = false;
};

struct CrossBinaryGateResult {
    bool pass = true;
    std::string reason;
    std::string trigger = "none";
    std::string trigger_detail;
    std::string signature;
    CrossBinaryComparisonSummary summary;
};

class CrossBinaryExpressionComparator {
public:
    explicit CrossBinaryExpressionComparator(ExpressionVerifier verifier = ExpressionVerifier())
        : verifier_(std::move(verifier)) {}

    std::vector<NamedExpressionComparison> compareParsersByName(
        const DwarfParser& lhs,
        const DwarfParser& rhs,
        const CrossBinaryCompareOptions& opts = {}) const;

    std::vector<NamedExpressionComparison> compareDIEListsByName(
        const std::vector<std::shared_ptr<DIE>>& lhs_roots,
        const std::vector<std::shared_ptr<DIE>>& rhs_roots,
        const CrossBinaryCompareOptions& opts = {}) const;

    NamedExpressionComparison compareNamedInParsers(
        const DwarfParser& lhs,
        const DwarfParser& rhs,
        const std::string& name,
        const CrossBinaryCompareOptions& opts = {}) const;

    CrossBinaryComparisonSummary summarize(
        const std::vector<NamedExpressionComparison>& comparisons) const;

    // max_rows=0 means include all rows.
    std::string renderTextReport(
        const std::vector<NamedExpressionComparison>& comparisons,
        size_t max_rows = 0) const;

    // max_rows=0 means include all rows.
    std::string renderJsonReport(
        const std::vector<NamedExpressionComparison>& comparisons,
        size_t max_rows = 0) const;

    CrossBinaryGateResult evaluateGate(
        const std::vector<NamedExpressionComparison>& comparisons,
        const CrossBinaryGateOptions& opts = {}) const;

private:
    ExpressionVerifier verifier_;
};

} // namespace dwarf
