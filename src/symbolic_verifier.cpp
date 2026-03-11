#include "symbolic_verifier.hpp"
#include "attribute_parser.hpp"
#include "smt_verifier.hpp"

#include <sstream>

namespace dwarf {

namespace {

std::string formatUnsupportedDetail(const char* side, uint8_t opcode, bool vendor_extension) {
    std::ostringstream ss;
    ss << side << " unsupported opcode 0x"
       << std::hex << static_cast<unsigned>(opcode) << std::dec;
    if (vendor_extension) ss << " [vendor/extension]";
    return ss.str();
}

std::string summarizeSymResult(const SymbolicExpressionResult& r) {
    std::ostringstream ss;
    switch (r.type) {
        case SymbolicExpressionResult::Type::ADDRESS:
            ss << "ADDRESS:" << (r.expression ? r.expression->toString() : "<null>");
            break;
        case SymbolicExpressionResult::Type::VALUE:
            ss << "VALUE:" << (r.expression ? r.expression->toString() : "<null>");
            break;
        case SymbolicExpressionResult::Type::REGISTER:
            ss << "REGISTER:" << (r.expression ? r.expression->toString() : "<null>");
            break;
        case SymbolicExpressionResult::Type::COMPOSITE:
            ss << "COMPOSITE[";
            for (size_t i = 0; i < r.pieces.size(); ++i) {
                if (i != 0) ss << ";";
                const auto& p = r.pieces[i];
                ss << "k=" << static_cast<int>(p.kind)
                   << ",bs=" << p.byte_size
                   << ",bits=" << p.bit_size
                   << ",bo=" << p.bit_offset;
                if (p.location) ss << ",loc=" << p.location->toString();
                if (!p.implicit_bytes.empty()) {
                    ss << ",impl=";
                    for (uint8_t b : p.implicit_bytes) {
                        ss << std::hex;
                        if (b < 0x10) ss << "0";
                        ss << static_cast<unsigned>(b);
                        ss << std::dec;
                    }
                }
            }
            ss << "]";
            break;
        case SymbolicExpressionResult::Type::INVALID:
            ss << "INVALID:" << r.error;
            break;
    }
    return ss.str();
}

bool extractExpressionFromAttribute(const std::shared_ptr<DIE>& die,
                                    const DIEExpressionSelectionOptions& sel,
                                    std::vector<uint8_t>& out_expr,
                                    std::string& out_reason) {
    if (!die) {
        out_reason = "null DIE";
        return false;
    }

    auto attr = die->getAttribute(sel.attribute);
    if (!attr) {
        out_reason = "attribute missing";
        return false;
    }

    if (auto loc = std::dynamic_pointer_cast<LocationAttributeValue>(attr)) {
        if (loc->getLocationType() == LocationAttributeValue::LocationType::EXPRESSION) {
            out_expr = loc->getData();
            if (out_expr.empty()) {
                out_reason = "empty location expression";
                return false;
            }
            return true;
        }
        if (loc->getLocationType() == LocationAttributeValue::LocationType::LIST) {
            if (sel.use_pc_for_location_list) {
                out_expr = loc->getExpressionForPC(sel.location_list_pc);
                if (!out_expr.empty()) return true;
            }

            const auto& entries = loc->getEntries();
            if (sel.prefer_default_entry) {
                for (const auto& e : entries) {
                    if (e.is_default && !e.expression.empty()) {
                        out_expr = e.expression;
                        return true;
                    }
                }
            }
            for (const auto& e : entries) {
                if (!e.is_default && !e.expression.empty()) {
                    out_expr = e.expression;
                    return true;
                }
            }
            if (!sel.prefer_default_entry) {
                for (const auto& e : entries) {
                    if (e.is_default && !e.expression.empty()) {
                        out_expr = e.expression;
                        return true;
                    }
                }
            }

            out_expr = loc->getData();
            if (!out_expr.empty()) return true;

            out_reason = "location list has no selectable expression";
            return false;
        }

        out_reason = "invalid location attribute";
        return false;
    }

    if (auto expr = std::dynamic_pointer_cast<ExpressionAttributeValue>(attr)) {
        out_expr = expr->getExpression();
        if (out_expr.empty()) {
            out_reason = "empty expression attribute";
            return false;
        }
        return true;
    }

    if (auto block = std::dynamic_pointer_cast<BlockAttributeValue>(attr)) {
        out_expr = block->getData();
        if (out_expr.empty()) {
            out_reason = "empty block expression";
            return false;
        }
        return true;
    }

    out_reason = "attribute is not expression-like";
    return false;
}

} // namespace

ExpressionVerificationResult ExpressionVerifier::verify(const std::vector<uint8_t>& lhs,
                                                        const std::vector<uint8_t>& rhs,
                                                        const EvaluationContext& ctx,
                                                        uint64_t pc,
                                                        const std::vector<uint64_t>& regs,
                                                        const ExpressionVerificationOptions& opts) const {
    return verifyWithContexts(lhs, ctx, pc, regs, rhs, ctx, pc, regs, opts);
}

ExpressionVerificationResult ExpressionVerifier::verifyWithContexts(
    const std::vector<uint8_t>& lhs,
    const EvaluationContext& lhs_ctx,
    uint64_t lhs_pc,
    const std::vector<uint64_t>& lhs_regs,
    const std::vector<uint8_t>& rhs,
    const EvaluationContext& rhs_ctx,
    uint64_t rhs_pc,
    const std::vector<uint64_t>& rhs_regs,
    const ExpressionVerificationOptions& opts) const {
    ExpressionVerificationResult out;

    SymbolicExpressionEvaluator sym;
    SymbolicExpressionResult l = sym.evaluate(lhs, lhs_ctx, lhs_pc, lhs_regs);
    SymbolicExpressionResult r = sym.evaluate(rhs, rhs_ctx, rhs_pc, rhs_regs);

    out.lhs_summary = summarizeSymResult(l);
    out.rhs_summary = summarizeSymResult(r);
    out.lhs_unsupported_opcode = l.unsupported_opcode;
    out.rhs_unsupported_opcode = r.unsupported_opcode;
    out.lhs_unsupported_vendor_extension = l.unsupported_vendor_extension;
    out.rhs_unsupported_vendor_extension = r.unsupported_vendor_extension;

    if (l.type == SymbolicExpressionResult::Type::INVALID && l.unsupported_opcode.has_value()) {
        out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
        out.reason = formatUnsupportedDetail("lhs", *l.unsupported_opcode, l.unsupported_vendor_extension);
        out.verifier_backend = "structural";
        out.solver_result = "unsupported_opcode";
        return out;
    }
    if (r.type == SymbolicExpressionResult::Type::INVALID && r.unsupported_opcode.has_value()) {
        out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
        out.reason = formatUnsupportedDetail("rhs", *r.unsupported_opcode, r.unsupported_vendor_extension);
        out.verifier_backend = "structural";
        out.solver_result = "unsupported_opcode";
        return out;
    }

    SMTExpressionVerifier smt;
    SMTVerificationResult smt_result = smt.verify(l, r, opts.solver_timeout_ms);
    out.verdict = smt_result.verdict;
    out.reason = smt_result.reason;
    out.verifier_backend = SMTExpressionVerifier::isAvailable() ? "z3" : "solver-unavailable";
    out.solver_result = smt_result.solver_result;
    out.counterexample_model = smt_result.model;
    out.counterexample_witness = smt_result.witness;
    return out;
}

ExpressionVerificationResult ExpressionVerifier::verifyDIEAttributeExpressions(
    const std::shared_ptr<DIE>& lhs_die,
    const EvaluationContext& lhs_ctx,
    const std::vector<uint64_t>& lhs_regs,
    const std::shared_ptr<DIE>& rhs_die,
    const EvaluationContext& rhs_ctx,
    const std::vector<uint64_t>& rhs_regs,
    const DIEExpressionSelectionOptions& lhs_sel,
    const DIEExpressionSelectionOptions& rhs_sel,
    const ExpressionVerificationOptions& opts) const {
    ExpressionVerificationResult out;

    std::vector<uint8_t> lhs_expr;
    std::string lhs_reason;
    if (!extractExpressionFromAttribute(lhs_die, lhs_sel, lhs_expr, lhs_reason)) {
        out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
        out.reason = "lhs expression extraction failed: " + lhs_reason;
        return out;
    }

    std::vector<uint8_t> rhs_expr;
    std::string rhs_reason;
    if (!extractExpressionFromAttribute(rhs_die, rhs_sel, rhs_expr, rhs_reason)) {
        out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
        out.reason = "rhs expression extraction failed: " + rhs_reason;
        return out;
    }

    return verifyWithContexts(lhs_expr, lhs_ctx, lhs_sel.evaluation_pc, lhs_regs,
                              rhs_expr, rhs_ctx, rhs_sel.evaluation_pc, rhs_regs,
                              opts);
}

} // namespace dwarf
