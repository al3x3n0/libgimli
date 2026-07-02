#include "symbolic_verifier.hpp"
#include "attribute_parser.hpp"
#include "dwarf_utils.hpp"
#include "smt_verifier.hpp"

#include <sstream>

namespace dwarf {

namespace {

struct ExtractedExpressionDetail {
    std::string kind = "missing";
    std::string detail;
};

std::string classifyVerificationResult(ExpressionVerificationResult::Verdict verdict,
                                       const std::string& solver_result,
                                       const std::string& reason,
                                       const std::string& isolation_kind) {
    if (verdict == ExpressionVerificationResult::Verdict::EQUIVALENT) return "equivalent";
    if (verdict == ExpressionVerificationResult::Verdict::DIFFERENT) return "different";
    if (!isolation_kind.empty()) return "unsupported_isolated";
    if (solver_result == "unsupported_opcode") return "unsupported_isolated";
    if (reason.find("extraction failed") != std::string::npos) return "extraction_failure";
    if (solver_result == "solver_unavailable") return "solver_unavailable";
    if (solver_result == "unknown") return "solver_unknown";
    return "unknown";
}

std::string formatUnsupportedDetail(const char* side, uint8_t opcode, bool vendor_extension) {
    std::ostringstream ss;
    ss << side << " unsupported opcode 0x"
       << std::hex << static_cast<unsigned>(opcode) << std::dec;
    if (vendor_extension) ss << " [vendor/extension]";
    return ss.str();
}

std::string truncatePreview(const std::string& input, size_t max_len = 96) {
    if (input.size() <= max_len) return input;
    if (max_len <= 3) return input.substr(0, max_len);
    return input.substr(0, max_len - 3) + "...";
}

std::string attributeValueTypeToString(AttributeValueType type) {
    switch (type) {
        case AttributeValueType::UNSIGNED: return "unsigned";
        case AttributeValueType::SIGNED: return "signed";
        case AttributeValueType::STRING: return "string";
        case AttributeValueType::REFERENCE: return "reference";
        case AttributeValueType::BLOCK: return "block";
        case AttributeValueType::FLAG: return "flag";
        case AttributeValueType::ADDRESS: return "address";
        case AttributeValueType::EXPRESSION: return "expression";
    }
    return "unknown";
}

std::string buildAttrDetail(DwarfAttribute attr_name,
                            const std::string& kind,
                            const std::string& extra = std::string(),
                            const std::shared_ptr<AttributeValue>& attr = nullptr) {
    std::ostringstream ss;
    ss << "attr=" << DwarfUtils::attributeToString(attr_name)
       << " kind=" << kind;
    if (attr) {
        std::string preview = truncatePreview(attr->toString());
        if (!preview.empty()) {
            ss << " preview=" << preview;
        }
    }
    if (!extra.empty()) {
        ss << " " << extra;
    }
    return ss.str();
}

bool extractExpressionFromAttribute(const std::shared_ptr<DIE>& die,
                                    const DIEExpressionSelectionOptions& sel,
                                    std::vector<uint8_t>& out_expr,
                                    std::string& out_reason,
                                    ExtractedExpressionDetail& out_detail) {
    if (!die) {
        out_reason = "null DIE";
        out_detail.kind = "missing";
        out_detail.detail = buildAttrDetail(sel.attribute, out_detail.kind, out_reason);
        return false;
    }

    auto attr = die->getAttribute(sel.attribute);
    if (!attr) {
        out_reason = "attribute missing";
        out_detail.kind = "missing";
        out_detail.detail = buildAttrDetail(sel.attribute, out_detail.kind, out_reason);
        return false;
    }

    if (auto loc = std::dynamic_pointer_cast<LocationAttributeValue>(attr)) {
        if (loc->getLocationType() == LocationAttributeValue::LocationType::EXPRESSION) {
            out_detail.kind = "location_expression";
            out_detail.detail = buildAttrDetail(sel.attribute, out_detail.kind, std::string(), attr);
            out_expr = loc->getData();
            if (out_expr.empty()) {
                out_reason = "empty location expression";
                out_detail.detail = buildAttrDetail(sel.attribute, out_detail.kind, out_reason, attr);
                return false;
            }
            return true;
        }
        if (loc->getLocationType() == LocationAttributeValue::LocationType::LIST) {
            const auto& entries = loc->getEntries();
            bool has_default = false;
            for (const auto& e : entries) {
                if (e.is_default) {
                    has_default = true;
                    break;
                }
            }
            out_detail.kind = "location_list";
            {
                std::ostringstream extra;
                extra << "entries=" << entries.size()
                      << " has_default=" << (has_default ? "1" : "0");
                if (sel.use_pc_for_location_list) {
                    extra << " selection=pc(" << DwarfUtils::formatAddress(sel.location_list_pc, false) << ")";
                } else {
                    extra << " selection=" << (sel.prefer_default_entry ? "default" : "first-nondefault");
                }
                out_detail.detail = buildAttrDetail(sel.attribute, out_detail.kind, extra.str(), attr);
            }

            if (sel.use_pc_for_location_list) {
                out_expr = loc->getExpressionForPC(sel.location_list_pc);
                if (!out_expr.empty()) return true;
            }

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
            out_detail.detail = buildAttrDetail(sel.attribute, out_detail.kind,
                                                "entries=" + std::to_string(entries.size()) +
                                                    " has_default=" + std::string(has_default ? "1" : "0") +
                                                    (sel.use_pc_for_location_list
                                                        ? " selection=pc(" + DwarfUtils::formatAddress(sel.location_list_pc, false) + ")"
                                                        : std::string(sel.prefer_default_entry ? " selection=default"
                                                                                               : " selection=first-nondefault")) +
                                                    " " + out_reason,
                                                attr);
            return false;
        }

        out_reason = "invalid location attribute";
        out_detail.kind = "location_attribute";
        out_detail.detail = buildAttrDetail(sel.attribute, out_detail.kind, out_reason, attr);
        return false;
    }

    if (auto expr = std::dynamic_pointer_cast<ExpressionAttributeValue>(attr)) {
        out_detail.kind = "expression";
        out_detail.detail = buildAttrDetail(sel.attribute, out_detail.kind, std::string(), attr);
        out_expr = expr->getExpression();
        if (out_expr.empty()) {
            out_reason = "empty expression attribute";
            out_detail.detail = buildAttrDetail(sel.attribute, out_detail.kind, out_reason, attr);
            return false;
        }
        return true;
    }

    if (auto block = std::dynamic_pointer_cast<BlockAttributeValue>(attr)) {
        out_detail.kind = "block";
        out_detail.detail = buildAttrDetail(sel.attribute, out_detail.kind, std::string(), attr);
        out_expr = block->getData();
        if (out_expr.empty()) {
            out_reason = "empty block expression";
            out_detail.detail = buildAttrDetail(sel.attribute, out_detail.kind, out_reason, attr);
            return false;
        }
        return true;
    }

    out_reason = "attribute is not expression-like";
    out_detail.kind = "non_expression_like";
    out_detail.detail = buildAttrDetail(sel.attribute,
                                        out_detail.kind,
                                        "value_type=" + attributeValueTypeToString(attr->getType()) + " " + out_reason,
                                        attr);
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

    out.lhs_summary = summarizeSymbolicResult(l);
    out.rhs_summary = summarizeSymbolicResult(r);
    out.lhs_unsupported_opcode = l.unsupported_opcode;
    out.rhs_unsupported_opcode = r.unsupported_opcode;
    out.lhs_unsupported_vendor_extension = l.unsupported_vendor_extension;
    out.rhs_unsupported_vendor_extension = r.unsupported_vendor_extension;

    if (l.type == SymbolicExpressionResult::Type::INVALID && l.unsupported_opcode.has_value()) {
        out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
        out.reason = formatUnsupportedDetail("lhs", *l.unsupported_opcode, l.unsupported_vendor_extension);
        out.reason_class = "unsupported_isolated";
        out.isolation_kind = "unsupported_opcode";
        if (!out.lhs_attribute_detail.empty()) {
            out.reason += " " + out.lhs_attribute_detail;
        }
        out.verifier_backend = "structural";
        out.solver_result = "unsupported_opcode";
        return out;
    }
    if (r.type == SymbolicExpressionResult::Type::INVALID && r.unsupported_opcode.has_value()) {
        out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
        out.reason = formatUnsupportedDetail("rhs", *r.unsupported_opcode, r.unsupported_vendor_extension);
        out.reason_class = "unsupported_isolated";
        out.isolation_kind = "unsupported_opcode";
        if (!out.rhs_attribute_detail.empty()) {
            out.reason += " " + out.rhs_attribute_detail;
        }
        out.verifier_backend = "structural";
        out.solver_result = "unsupported_opcode";
        return out;
    }

    // Canonicalize both expression trees before comparison so semantically
    // equivalent but syntactically different forms reconcile symbolically rather
    // than failing on a raw byte/structure mismatch (e.g. the CFI path). On a
    // mismatch that normalization cannot resolve, the downstream verifier still
    // reports DIFFERENT.
    if (opts.enable_symbolic_normalization) {
        bool changed = false;
        std::string rule_class;
        if (l.expression) l.expression = rewriteSymExpr(l.expression, changed, rule_class);
        if (r.expression) r.expression = rewriteSymExpr(r.expression, changed, rule_class);
    }

    SMTExpressionVerifier smt;
    SMTVerificationResult smt_result = smt.verify(l, r, opts.solver_timeout_ms);
    out.verdict = smt_result.verdict;
    out.reason = smt_result.reason;
    out.verifier_backend = SMTExpressionVerifier::isAvailable() ? "z3" : "solver-unavailable";
    out.solver_result = smt_result.solver_result;
    out.counterexample_model = smt_result.model;
    out.counterexample_witness = smt_result.witness;
    out.reason_class = classifyVerificationResult(out.verdict, out.solver_result, out.reason, out.isolation_kind);
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
    ExtractedExpressionDetail lhs_detail;
    if (!extractExpressionFromAttribute(lhs_die, lhs_sel, lhs_expr, lhs_reason, lhs_detail)) {
        out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
        out.lhs_attribute_kind = lhs_detail.kind;
        out.lhs_attribute_detail = lhs_detail.detail;
        out.reason = "lhs expression extraction failed: " + lhs_reason;
        out.reason_class = "extraction_failure";
        if (!out.lhs_attribute_detail.empty()) {
            out.reason += " (" + out.lhs_attribute_detail + ")";
        }
        return out;
    }
    out.lhs_attribute_kind = lhs_detail.kind;
    out.lhs_attribute_detail = lhs_detail.detail;

    std::vector<uint8_t> rhs_expr;
    std::string rhs_reason;
    ExtractedExpressionDetail rhs_detail;
    if (!extractExpressionFromAttribute(rhs_die, rhs_sel, rhs_expr, rhs_reason, rhs_detail)) {
        out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
        out.rhs_attribute_kind = rhs_detail.kind;
        out.rhs_attribute_detail = rhs_detail.detail;
        out.reason = "rhs expression extraction failed: " + rhs_reason;
        out.reason_class = "extraction_failure";
        if (!out.rhs_attribute_detail.empty()) {
            out.reason += " (" + out.rhs_attribute_detail + ")";
        }
        return out;
    }
    out.rhs_attribute_kind = rhs_detail.kind;
    out.rhs_attribute_detail = rhs_detail.detail;

    out = verifyWithContexts(lhs_expr, lhs_ctx, lhs_sel.evaluation_pc, lhs_regs,
                             rhs_expr, rhs_ctx, rhs_sel.evaluation_pc, rhs_regs,
                             opts);
    out.lhs_attribute_kind = lhs_detail.kind;
    out.rhs_attribute_kind = rhs_detail.kind;
    out.lhs_attribute_detail = lhs_detail.detail;
    out.rhs_attribute_detail = rhs_detail.detail;
    if (out.solver_result == "unsupported_opcode") {
        if (out.lhs_unsupported_opcode.has_value() && !out.lhs_attribute_detail.empty() &&
            out.reason.find(out.lhs_attribute_detail) == std::string::npos) {
            out.reason += " " + out.lhs_attribute_detail;
        }
        if (out.rhs_unsupported_opcode.has_value() && !out.rhs_attribute_detail.empty() &&
            out.reason.find(out.rhs_attribute_detail) == std::string::npos) {
            out.reason += " " + out.rhs_attribute_detail;
        }
    }
    out.reason_class = classifyVerificationResult(out.verdict, out.solver_result, out.reason, out.isolation_kind);
    return out;
}

} // namespace dwarf
