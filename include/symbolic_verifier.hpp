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
    // Deprecated heuristic options kept for CLI/API compatibility.
    // They no longer influence verification verdicts.
    size_t differential_trials = 64;
    size_t register_count = 64;
    uint64_t seed = 0x9e3779b97f4a7c15ULL;
    bool run_differential = true;
    // Optional Z3 timeout per equivalence query (0 = solver default/no timeout).
    uint32_t solver_timeout_ms = 0;
    // Apply algebraic/canonical rewrite to evaluated expressions before comparison.
    // Enabled by default so semantically-equivalent-but-syntactically-different
    // expressions (including in the CFI path) are reconciled symbolically instead
    // of failing on a raw byte mismatch.
    bool enable_symbolic_normalization = true;
    // Optional callback reconciling an lhs "old" code address to its rhs "new"
    // address. When set, absolute address constants in the lhs expression (e.g. a
    // DW_OP_addr inside a CFA expression) are remapped before comparison so
    // BOLT-relocated addresses are not reported as differences.
    AddressRemapFn address_remap;
};

struct ExpressionVerificationResult {
    enum class Verdict {
        EQUIVALENT,
        DIFFERENT,
        UNKNOWN
    };

    Verdict verdict = Verdict::UNKNOWN;
    std::string reason;
    std::string reason_class;
    std::string isolation_kind;
    bool normalization_attempted = false;
    std::string normalization_status;
    std::string normalization_reason;
    bool normalization_applied = false;
    bool normalization_equal = false;
    std::string normalization_kind;
    std::string normalization_note;
    std::string lhs_normalization_rule_class;
    std::string rhs_normalization_rule_class;
    std::string lhs_raw_summary;
    std::string rhs_raw_summary;
    std::string lhs_normalized_summary;
    std::string rhs_normalized_summary;
    std::string lhs_normalization_reason;
    std::string rhs_normalization_reason;
    bool lhs_normalization_changed = false;
    bool rhs_normalization_changed = false;
    std::string lhs_summary;
    std::string rhs_summary;
    std::string verifier_backend;
    std::string solver_result;
    std::string counterexample_model;
    std::string counterexample_witness;
    std::string lhs_attribute_kind;
    std::string rhs_attribute_kind;
    std::string lhs_attribute_detail;
    std::string rhs_attribute_detail;
    std::optional<uint8_t> lhs_unsupported_opcode;
    std::optional<uint8_t> rhs_unsupported_opcode;
    bool lhs_unsupported_vendor_extension = false;
    bool rhs_unsupported_vendor_extension = false;
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
