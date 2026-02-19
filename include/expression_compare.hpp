#pragma once

#include "die_parser.hpp"
#include "dwarf_parser.hpp"
#include "symbolic_verifier.hpp"
#include <limits>
#include <memory>
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
};

struct NamedExpressionComparison {
    std::string name;
    DwarfTag tag = DwarfTag::DW_TAG_variable;
    bool lhs_present = false;
    bool rhs_present = false;
    uint64_t lhs_offset = 0;
    uint64_t rhs_offset = 0;
    ExpressionVerificationResult verification;
};

struct CrossBinaryComparisonSummary {
    size_t total = 0;
    size_t equivalent = 0;
    size_t different = 0;
    size_t unknown = 0;
    size_t missing_lhs = 0;
    size_t missing_rhs = 0;
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
};

struct CrossBinaryGateResult {
    bool pass = true;
    std::string reason;
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
