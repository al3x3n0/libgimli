#pragma once

#include "cfi_parser.hpp"
#include "symbolic_verifier.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dwarf {

struct SymbolicCFICompareOptions {
    bool require_same_range = true;
    bool treat_missing_register_rule_as_undefined = true;
    EvaluationContext lhs_context;
    EvaluationContext rhs_context;
    std::vector<uint64_t> lhs_registers;
    std::vector<uint64_t> rhs_registers;
    ExpressionVerificationOptions expression_options;
};

struct SymbolicCFIStateComparisonResult {
    ExpressionVerificationResult::Verdict verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
    std::string reason;
    std::string lhs_summary;
    std::string rhs_summary;
};

struct SymbolicCFIIntervalComparisonResult {
    ExpressionVerificationResult::Verdict verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
    std::string reason;
    size_t points_checked = 0;
    uint64_t mismatch_relative_pc = 0;
    bool has_mismatch_relative_pc = false;
};

class SymbolicCFIVerifier {
public:
    explicit SymbolicCFIVerifier(ExpressionVerifier expr_verifier = ExpressionVerifier())
        : expr_verifier_(std::move(expr_verifier)) {}

    SymbolicCFIStateComparisonResult compareUnwindInfo(
        const UnwindInfo& lhs,
        const UnwindInfo& rhs,
        uint64_t lhs_pc,
        uint64_t rhs_pc,
        const SymbolicCFICompareOptions& opts = {}) const;

    SymbolicCFIStateComparisonResult compareParsersAtPC(
        const CFIParser& lhs,
        const CFIParser& rhs,
        uint64_t lhs_pc,
        uint64_t rhs_pc,
        const SymbolicCFICompareOptions& opts = {}) const;

    SymbolicCFIIntervalComparisonResult compareFDEByIndex(
        const CFIParser& lhs,
        size_t lhs_fde_index,
        const CFIParser& rhs,
        size_t rhs_fde_index,
        const SymbolicCFICompareOptions& opts = {}) const;

private:
    ExpressionVerifier expr_verifier_;
};

} // namespace dwarf

