#include "symbolic_verifier.hpp"
#include "attribute_parser.hpp"

#include <algorithm>
#include <memory>
#include <sstream>

namespace dwarf {

namespace {

uint64_t mix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    x = x ^ (x >> 31);
    return x;
}

class SyntheticMemoryContext : public MemoryContext {
public:
    bool readMemory(uint64_t address, size_t size, void* buffer) const override {
        if (buffer == nullptr) return false;
        uint8_t* out = static_cast<uint8_t*>(buffer);
        for (size_t i = 0; i < size; ++i) {
            uint64_t v = mix64(address + static_cast<uint64_t>(i));
            out[i] = static_cast<uint8_t>(v & 0xff);
        }
        return true;
    }

    bool writeMemory(uint64_t address, size_t size, const void* buffer) override {
        (void)address;
        (void)size;
        (void)buffer;
        return true;
    }
};

std::string hexU64(uint64_t v) {
    std::ostringstream ss;
    ss << "0x" << std::hex << v;
    return ss.str();
}

bool isCommutative(SymExpr::Kind k) {
    switch (k) {
        case SymExpr::Kind::ADD:
        case SymExpr::Kind::MUL:
        case SymExpr::Kind::AND:
        case SymExpr::Kind::OR:
        case SymExpr::Kind::XOR:
        case SymExpr::Kind::EQ:
        case SymExpr::Kind::NE:
            return true;
        default:
            return false;
    }
}

bool symExprEquivalent(const SymExprPtr& a, const SymExprPtr& b) {
    if (a == b) return true;
    if (!a || !b) return false;
    if (a->kind != b->kind) return false;

    switch (a->kind) {
        case SymExpr::Kind::CONST_U64:
            return a->const_u64 == b->const_u64;
        case SymExpr::Kind::BYTES:
            return a->raw_bytes == b->raw_bytes;
        case SymExpr::Kind::VAR:
        case SymExpr::Kind::UNKNOWN:
            return a->name == b->name;
        case SymExpr::Kind::LOAD:
        case SymExpr::Kind::MASK:
        case SymExpr::Kind::SEXT:
            if (a->aux_bytes != b->aux_bytes) return false;
            break;
        default:
            break;
    }

    if (a->args.size() != b->args.size()) return false;
    if (a->args.size() == 2 && isCommutative(a->kind)) {
        bool direct = symExprEquivalent(a->args[0], b->args[0]) &&
                      symExprEquivalent(a->args[1], b->args[1]);
        if (direct) return true;
        return symExprEquivalent(a->args[0], b->args[1]) &&
               symExprEquivalent(a->args[1], b->args[0]);
    }

    for (size_t i = 0; i < a->args.size(); ++i) {
        if (!symExprEquivalent(a->args[i], b->args[i])) return false;
    }
    return true;
}

bool symPieceEquivalent(const SymPiece& a, const SymPiece& b) {
    if (a.kind != b.kind) return false;
    if (a.byte_size != b.byte_size) return false;
    if (a.bit_size != b.bit_size) return false;
    if (a.bit_offset != b.bit_offset) return false;
    if (a.implicit_bytes != b.implicit_bytes) return false;
    return symExprEquivalent(a.location, b.location);
}

bool symResultEquivalent(const SymbolicExpressionResult& a, const SymbolicExpressionResult& b) {
    if (a.type != b.type) return false;
    switch (a.type) {
        case SymbolicExpressionResult::Type::ADDRESS:
        case SymbolicExpressionResult::Type::VALUE:
        case SymbolicExpressionResult::Type::REGISTER:
            return symExprEquivalent(a.expression, b.expression);
        case SymbolicExpressionResult::Type::COMPOSITE:
            if (a.pieces.size() != b.pieces.size()) return false;
            for (size_t i = 0; i < a.pieces.size(); ++i) {
                if (!symPieceEquivalent(a.pieces[i], b.pieces[i])) return false;
            }
            return true;
        case SymbolicExpressionResult::Type::INVALID:
            return false;
    }
    return false;
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

bool concretePieceEquivalent(const PieceDescriptor& a, const PieceDescriptor& b) {
    return a.kind == b.kind &&
           a.location == b.location &&
           a.byte_size == b.byte_size &&
           a.bit_size == b.bit_size &&
           a.bit_offset == b.bit_offset &&
           a.implicit_value == b.implicit_value;
}

bool concreteResultEquivalent(const ExpressionResult& a, const ExpressionResult& b) {
    if (a.type != b.type) return false;
    if (a.type == ExpressionResult::COMPOSITE) {
        if (a.pieces.size() != b.pieces.size()) return false;
        for (size_t i = 0; i < a.pieces.size(); ++i) {
            if (!concretePieceEquivalent(a.pieces[i], b.pieces[i])) return false;
        }
        return true;
    }
    if (a.type == ExpressionResult::INVALID) return false;
    return a.value == b.value;
}

std::string summarizeConcreteResult(const ExpressionResult& r) {
    std::ostringstream ss;
    switch (r.type) {
        case ExpressionResult::ADDRESS:
            ss << "ADDRESS:" << hexU64(r.value);
            break;
        case ExpressionResult::VALUE:
            ss << "VALUE:" << hexU64(r.value);
            break;
        case ExpressionResult::REGISTER:
            ss << "REGISTER:" << hexU64(r.value);
            break;
        case ExpressionResult::COMPOSITE:
            ss << "COMPOSITE:" << r.pieces.size() << "_pieces";
            break;
        case ExpressionResult::INVALID:
            ss << "INVALID:" << r.description;
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

            // Backward-compat fallback in case entries are absent but data_ was set.
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

    if (l.type == SymbolicExpressionResult::Type::INVALID ||
        r.type == SymbolicExpressionResult::Type::INVALID) {
        out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
        out.reason = "symbolic evaluation invalid: lhs='" + l.error + "', rhs='" + r.error + "'";
        return out;
    }

    if (symResultEquivalent(l, r)) {
        out.verdict = ExpressionVerificationResult::Verdict::EQUIVALENT;
        out.reason = "symbolic equivalence established";
        return out;
    }

    if (!opts.run_differential || opts.differential_trials == 0) {
        out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
        out.reason = "symbolic forms differ and differential check is disabled";
        return out;
    }

    auto mem = std::make_shared<SyntheticMemoryContext>();
    ExpressionEvaluator ev_l(mem);
    ExpressionEvaluator ev_r(mem);

    size_t comparable = 0;
    const size_t reg_count = std::max({opts.register_count, lhs_regs.size(), rhs_regs.size()});
    for (size_t i = 0; i < opts.differential_trials; ++i) {
        uint64_t trial_seed = mix64(opts.seed + static_cast<uint64_t>(i));
        std::vector<uint64_t> trial_regs_l(reg_count, 0);
        std::vector<uint64_t> trial_regs_r(reg_count, 0);
        for (size_t j = 0; j < reg_count; ++j) {
            uint64_t v = mix64(trial_seed + static_cast<uint64_t>(j));
            trial_regs_l[j] = v;
            trial_regs_r[j] = v;
        }
        for (size_t j = 0; j < lhs_regs.size(); ++j) {
            trial_regs_l[j] = lhs_regs[j];
        }
        for (size_t j = 0; j < rhs_regs.size(); ++j) {
            trial_regs_r[j] = rhs_regs[j];
        }

        EvaluationContext trial_ctx_l = lhs_ctx;
        if (trial_ctx_l.entry_registers.empty()) {
            trial_ctx_l.entry_registers = trial_regs_l;
        }
        EvaluationContext trial_ctx_r = rhs_ctx;
        if (trial_ctx_r.entry_registers.empty()) {
            trial_ctx_r.entry_registers = trial_regs_r;
        }

        ExpressionResult cr_l = ev_l.evaluate(lhs, trial_ctx_l, lhs_pc, trial_regs_l);
        ExpressionResult cr_r = ev_r.evaluate(rhs, trial_ctx_r, rhs_pc, trial_regs_r);
        if (cr_l.type == ExpressionResult::INVALID || cr_r.type == ExpressionResult::INVALID) {
            continue;
        }
        ++comparable;
        if (!concreteResultEquivalent(cr_l, cr_r)) {
            out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
            out.reason = "differential counterexample at trial " + std::to_string(i) +
                         ": lhs=" + summarizeConcreteResult(cr_l) +
                         ", rhs=" + summarizeConcreteResult(cr_r);
            return out;
        }
    }

    out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
    if (comparable == 0) {
        out.reason = "symbolic forms differ and no comparable concrete trials were available";
    } else {
        out.reason = "symbolic forms differ; no concrete counterexample in " +
                     std::to_string(comparable) + " comparable trials";
    }
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
