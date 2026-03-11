#pragma once

#include "symbolic_expression.hpp"
#include "symbolic_verifier.hpp"
#include <string>

namespace dwarf {

struct SMTVerificationResult {
    ExpressionVerificationResult::Verdict verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
    std::string reason;
    std::string solver_result;
    std::string model;
    std::string witness;
};

class SMTExpressionVerifier {
public:
    SMTExpressionVerifier() = default;

    static bool isAvailable();

    SMTVerificationResult verify(const SymbolicExpressionResult& lhs,
                                 const SymbolicExpressionResult& rhs,
                                 uint32_t timeout_ms = 0) const;
};

} // namespace dwarf
