#pragma once

#include "expression_evaluator.hpp"
#include "symbolic_expression.hpp"
#include "die_parser.hpp"
#include <memory>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dwarf {

struct ExpressionVerificationOptions {
    // Number of concrete differential trials used to search for counterexamples
    // when symbolic equivalence is not established.
    size_t differential_trials = 64;
    // Number of synthetic registers generated per trial.
    size_t register_count = 64;
    // Base seed for deterministic trial generation.
    uint64_t seed = 0x9e3779b97f4a7c15ULL;
    // Enable/disable concrete differential search.
    bool run_differential = true;
};

struct ExpressionVerificationResult {
    enum class Verdict {
        EQUIVALENT,
        DIFFERENT,
        UNKNOWN
    };

    Verdict verdict = Verdict::UNKNOWN;
    std::string reason;
    std::string lhs_summary;
    std::string rhs_summary;
};

struct DIEExpressionSelectionOptions {
    DwarfAttribute attribute = DwarfAttribute::DW_AT_location;
    // For LocationAttributeValue::LIST selection.
    bool use_pc_for_location_list = false;
    uint64_t location_list_pc = 0;
    // If not selecting by PC and a default entry exists, prefer it.
    bool prefer_default_entry = true;
    // Evaluation PC passed to expression evaluators/verifier.
    uint64_t evaluation_pc = 0;
};

class ExpressionVerifier {
public:
    ExpressionVerifier() = default;

    // Verifies expressions under a shared context/pc/register set.
    ExpressionVerificationResult verify(const std::vector<uint8_t>& lhs,
                                        const std::vector<uint8_t>& rhs,
                                        const EvaluationContext& ctx,
                                        uint64_t pc = 0,
                                        const std::vector<uint64_t>& regs = {},
                                        const ExpressionVerificationOptions& opts = {}) const;

    // Verifies expressions under independent contexts/pc/register sets.
    ExpressionVerificationResult verifyWithContexts(const std::vector<uint8_t>& lhs,
                                                    const EvaluationContext& lhs_ctx,
                                                    uint64_t lhs_pc,
                                                    const std::vector<uint64_t>& lhs_regs,
                                                    const std::vector<uint8_t>& rhs,
                                                    const EvaluationContext& rhs_ctx,
                                                    uint64_t rhs_pc,
                                                    const std::vector<uint64_t>& rhs_regs,
                                                    const ExpressionVerificationOptions& opts = {}) const;

    // Extracts expression-bearing attributes from two DIEs and verifies them.
    ExpressionVerificationResult verifyDIEAttributeExpressions(
        const std::shared_ptr<DIE>& lhs_die,
        const EvaluationContext& lhs_ctx,
        const std::vector<uint64_t>& lhs_regs,
        const std::shared_ptr<DIE>& rhs_die,
        const EvaluationContext& rhs_ctx,
        const std::vector<uint64_t>& rhs_regs,
        const DIEExpressionSelectionOptions& lhs_sel = {},
        const DIEExpressionSelectionOptions& rhs_sel = {},
        const ExpressionVerificationOptions& opts = {}) const;
};

} // namespace dwarf
