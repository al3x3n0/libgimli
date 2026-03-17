#include "smt_verifier.hpp"
#include "dwarf_utils.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <unordered_map>
#include <vector>
#if DWARF_HAS_Z3
#include <z3++.h>
#endif

namespace dwarf {

#if DWARF_HAS_Z3

namespace {

uint64_t decodeBytesToU64(const std::vector<uint8_t>& bytes, bool little_endian) {
    if (bytes.empty()) return 0;
    if (bytes.size() > 8) return 0;

    uint64_t out = 0;
    if (little_endian) {
        for (size_t i = 0; i < bytes.size(); ++i) {
            out |= static_cast<uint64_t>(bytes[i]) << (i * 8);
        }
        return out;
    }

    for (uint8_t b : bytes) {
        out = (out << 8) | static_cast<uint64_t>(b);
    }
    return out;
}

std::string sanitizeSymbol(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    out = "sym_";
    for (char ch : in) {
        unsigned char u = static_cast<unsigned char>(ch);
        if (std::isalnum(u) || ch == '_') out.push_back(ch);
        else out.push_back('_');
    }
    if (out.size() == 4) out += "anon";
    return out;
}

class Encoder {
public:
    explicit Encoder(z3::context& ctx, bool little_endian)
        : ctx_(ctx),
          little_endian_(little_endian),
          memory_(ctx_.constant("mem", ctx_.array_sort(ctx_.bv_sort(64), ctx_.bv_sort(8)))) {}

    z3::expr encodeValue(const SymExprPtr& expr) {
        if (!expr) return mkVar("opaque_null_expr");
        auto it = cache_.find(expr.get());
        if (it != cache_.end()) return it->second;
        z3::expr encoded = encodeRaw(expr);
        cache_.emplace(expr.get(), encoded);
        return encoded;
    }

private:
    z3::context& ctx_;
    bool little_endian_;
    z3::expr memory_;
    std::unordered_map<const SymExpr*, z3::expr> cache_;
    std::unordered_map<std::string, z3::expr> variables_;
    std::unordered_map<std::string, size_t> symbol_counts_;

    z3::expr bvZero() { return ctx_.bv_val(0, 64); }
    z3::expr bvOne() { return ctx_.bv_val(1, 64); }

    z3::expr mkVar(const std::string& name) {
        auto it = variables_.find(name);
        if (it != variables_.end()) return it->second;
        std::string base = sanitizeSymbol(name);
        size_t suffix = symbol_counts_[base]++;
        std::string full = (suffix == 0) ? base : (base + "_" + std::to_string(suffix));
        z3::expr v = ctx_.bv_const(full.c_str(), 64);
        variables_.emplace(name, v);
        return v;
    }

    z3::expr mkOpaqueShapeVar(const std::string& prefix, const SymExprPtr& expr) {
        if (!expr) return mkVar(prefix + "_null_expr");
        return mkVar(prefix + "_" + expr->toString());
    }

    z3::expr nonZero(const z3::expr& v) { return v != bvZero(); }

    z3::expr toBool01(const z3::expr& pred) { return z3::ite(pred, bvOne(), bvZero()); }

    z3::expr maskedShift(const z3::expr& amount) {
        z3::expr lo6 = amount.extract(5, 0);
        return z3::zext(lo6, 58);
    }

    z3::expr loadN(const z3::expr& addr, uint64_t size_bytes) {
        if (size_bytes == 0 || size_bytes > 8) {
            std::ostringstream ss;
            ss << "opaque_invalid_load_bytes_" << size_bytes;
            return mkVar(ss.str());
        }

        std::vector<z3::expr> bytes;
        bytes.reserve(static_cast<size_t>(size_bytes));
        for (uint64_t i = 0; i < size_bytes; ++i) {
            z3::expr a = addr + ctx_.bv_val(i, 64);
            bytes.push_back(z3::select(memory_, a));
        }

        z3::expr value = little_endian_ ? bytes.back() : bytes.front();
        if (little_endian_) {
            for (size_t i = bytes.size() - 1; i > 0; --i) {
                value = z3::concat(value, bytes[i - 1]);
            }
        } else {
            for (size_t i = 1; i < bytes.size(); ++i) {
                value = z3::concat(value, bytes[i]);
            }
        }

        unsigned bits = static_cast<unsigned>(size_bytes * 8);
        if (bits < 64) value = z3::zext(value, 64 - bits);
        return value;
    }

    z3::expr encodeRaw(const SymExprPtr& expr) {
        switch (expr->kind) {
            case SymExpr::Kind::CONST_U64:
                return ctx_.bv_val(expr->const_u64, 64);
            case SymExpr::Kind::BYTES:
                if (expr->raw_bytes.size() > 8) return mkVar("wide_bytes_" + expr->toString());
                return ctx_.bv_val(decodeBytesToU64(expr->raw_bytes, little_endian_), 64);
            case SymExpr::Kind::VAR:
                return mkVar(expr->name);
            case SymExpr::Kind::UNKNOWN:
                return mkVar("unknown_" + expr->name);

            case SymExpr::Kind::NEG: {
                if (expr->args.size() != 1) return mkOpaqueShapeVar("opaque_neg_arity", expr);
                return -encodeValue(expr->args[0]);
            }
            case SymExpr::Kind::NOT: {
                if (expr->args.size() != 1) return mkOpaqueShapeVar("opaque_not_arity", expr);
                return ~encodeValue(expr->args[0]);
            }
            case SymExpr::Kind::ABS: {
                if (expr->args.size() != 1) return mkOpaqueShapeVar("opaque_abs_arity", expr);
                z3::expr v = encodeValue(expr->args[0]);
                return z3::ite(z3::slt(v, bvZero()), -v, v);
            }

            case SymExpr::Kind::ADD:
            case SymExpr::Kind::SUB:
            case SymExpr::Kind::MUL:
            case SymExpr::Kind::DIV:
            case SymExpr::Kind::MOD:
            case SymExpr::Kind::AND:
            case SymExpr::Kind::OR:
            case SymExpr::Kind::XOR:
            case SymExpr::Kind::SHL:
            case SymExpr::Kind::SHR:
            case SymExpr::Kind::SHRA:
            case SymExpr::Kind::EQ:
            case SymExpr::Kind::NE:
            case SymExpr::Kind::LT:
            case SymExpr::Kind::LE:
            case SymExpr::Kind::GT:
            case SymExpr::Kind::GE: {
                if (expr->args.size() != 2) return mkOpaqueShapeVar("opaque_binary_arity", expr);
                z3::expr a = encodeValue(expr->args[0]);
                z3::expr b = encodeValue(expr->args[1]);
                switch (expr->kind) {
                    case SymExpr::Kind::ADD: return a + b;
                    case SymExpr::Kind::SUB: return a - b;
                    case SymExpr::Kind::MUL: return a * b;
                    case SymExpr::Kind::DIV: return z3::udiv(a, b);
                    case SymExpr::Kind::MOD: return z3::urem(a, b);
                    case SymExpr::Kind::AND: return a & b;
                    case SymExpr::Kind::OR: return a | b;
                    case SymExpr::Kind::XOR: return a ^ b;
                    case SymExpr::Kind::SHL: return z3::shl(a, maskedShift(b));
                    case SymExpr::Kind::SHR: return z3::lshr(a, maskedShift(b));
                    case SymExpr::Kind::SHRA: return z3::ashr(a, maskedShift(b));
                    case SymExpr::Kind::EQ: return toBool01(a == b);
                    case SymExpr::Kind::NE: return toBool01(a != b);
                    case SymExpr::Kind::LT: return toBool01(z3::slt(a, b));
                    case SymExpr::Kind::LE: return toBool01(z3::sle(a, b));
                    case SymExpr::Kind::GT: return toBool01(z3::sgt(a, b));
                    case SymExpr::Kind::GE: return toBool01(z3::sge(a, b));
                    default: break;
                }
                return mkOpaqueShapeVar("opaque_binary_dispatch", expr);
            }

            case SymExpr::Kind::ITE: {
                if (expr->args.size() != 3) return mkOpaqueShapeVar("opaque_ite_arity", expr);
                z3::expr cond = encodeValue(expr->args[0]);
                z3::expr t = encodeValue(expr->args[1]);
                z3::expr f = encodeValue(expr->args[2]);
                return z3::ite(nonZero(cond), t, f);
            }

            case SymExpr::Kind::LOAD: {
                if (expr->args.size() != 1) return mkOpaqueShapeVar("opaque_load_arity", expr);
                if (expr->aux_bytes > 8) {
                    return mkVar("wide_load_" + expr->toString());
                }
                return loadN(encodeValue(expr->args[0]), expr->aux_bytes);
            }

            case SymExpr::Kind::MASK: {
                if (expr->args.size() != 1) return mkOpaqueShapeVar("opaque_mask_arity", expr);
                z3::expr v = encodeValue(expr->args[0]);
                if (expr->aux_bytes == 0 || expr->aux_bytes >= 8) return v;
                unsigned bits = static_cast<unsigned>(expr->aux_bytes * 8);
                z3::expr lo = v.extract(bits - 1, 0);
                return z3::zext(lo, 64 - bits);
            }

            case SymExpr::Kind::SEXT: {
                if (expr->args.size() != 1) return mkOpaqueShapeVar("opaque_sext_arity", expr);
                z3::expr v = encodeValue(expr->args[0]);
                if (expr->aux_bytes == 0 || expr->aux_bytes >= 8) return v;
                unsigned bits = static_cast<unsigned>(expr->aux_bytes * 8);
                z3::expr lo = v.extract(bits - 1, 0);
                return z3::sext(lo, 64 - bits);
            }
        }
        return mkOpaqueShapeVar("opaque_invalid_kind", expr);
    }
};

bool samePieceMetadata(const SymPiece& lhs, const SymPiece& rhs) {
    return lhs.kind == rhs.kind &&
           lhs.byte_size == rhs.byte_size &&
           lhs.bit_size == rhs.bit_size &&
           lhs.bit_offset == rhs.bit_offset &&
           lhs.implicit_bytes == rhs.implicit_bytes;
}

const std::vector<uint8_t>* largeBytesLiteral(const SymExprPtr& expr) {
    if (!expr || expr->kind != SymExpr::Kind::BYTES) return nullptr;
    if (expr->raw_bytes.size() <= 8) return nullptr;
    return &expr->raw_bytes;
}

bool structurallyEqualExpr(const SymExprPtr& lhs, const SymExprPtr& rhs) {
    if (!lhs || !rhs) return lhs == rhs;
    return lhs->toString() == rhs->toString();
}

bool needsUnsupportedStructuralPrecheck(const SymExprPtr& expr) {
    if (!expr) return false;
    switch (expr->kind) {
        case SymExpr::Kind::BYTES:
            return expr->raw_bytes.size() > 8;
        case SymExpr::Kind::LOAD:
            if (expr->aux_bytes == 0 || expr->aux_bytes > 8) return true;
            break;
        case SymExpr::Kind::NEG:
        case SymExpr::Kind::NOT:
        case SymExpr::Kind::ABS:
            return expr->args.size() != 1;
        case SymExpr::Kind::ADD:
        case SymExpr::Kind::SUB:
        case SymExpr::Kind::MUL:
        case SymExpr::Kind::DIV:
        case SymExpr::Kind::MOD:
        case SymExpr::Kind::AND:
        case SymExpr::Kind::OR:
        case SymExpr::Kind::XOR:
        case SymExpr::Kind::SHL:
        case SymExpr::Kind::SHR:
        case SymExpr::Kind::SHRA:
        case SymExpr::Kind::EQ:
        case SymExpr::Kind::NE:
        case SymExpr::Kind::LT:
        case SymExpr::Kind::LE:
        case SymExpr::Kind::GT:
        case SymExpr::Kind::GE:
            return expr->args.size() != 2;
        case SymExpr::Kind::ITE:
            return expr->args.size() != 3;
        case SymExpr::Kind::MASK:
        case SymExpr::Kind::SEXT:
            return expr->args.size() != 1;
        default:
            break;
    }
    for (const auto& arg : expr->args) {
        if (needsUnsupportedStructuralPrecheck(arg)) return true;
    }
    return false;
}

enum class SymbolicShapeClass {
    ENCODABLE,
    INVALID_STRUCTURE,
    INVALID_LOAD_SIZE,
    INVALID_KIND
};

SymbolicShapeClass classifySymbolicShape(const SymExprPtr& expr) {
    if (!expr) return SymbolicShapeClass::INVALID_STRUCTURE;
    switch (expr->kind) {
        case SymExpr::Kind::CONST_U64:
        case SymExpr::Kind::BYTES:
        case SymExpr::Kind::VAR:
        case SymExpr::Kind::UNKNOWN:
            break;
        case SymExpr::Kind::NEG:
        case SymExpr::Kind::NOT:
        case SymExpr::Kind::ABS:
        case SymExpr::Kind::MASK:
        case SymExpr::Kind::SEXT:
            if (expr->args.size() != 1) return SymbolicShapeClass::INVALID_STRUCTURE;
            break;
        case SymExpr::Kind::LOAD:
            if (expr->args.size() != 1) return SymbolicShapeClass::INVALID_STRUCTURE;
            if (expr->aux_bytes == 0) return SymbolicShapeClass::INVALID_LOAD_SIZE;
            break;
        case SymExpr::Kind::ADD:
        case SymExpr::Kind::SUB:
        case SymExpr::Kind::MUL:
        case SymExpr::Kind::DIV:
        case SymExpr::Kind::MOD:
        case SymExpr::Kind::AND:
        case SymExpr::Kind::OR:
        case SymExpr::Kind::XOR:
        case SymExpr::Kind::SHL:
        case SymExpr::Kind::SHR:
        case SymExpr::Kind::SHRA:
        case SymExpr::Kind::EQ:
        case SymExpr::Kind::NE:
        case SymExpr::Kind::LT:
        case SymExpr::Kind::LE:
        case SymExpr::Kind::GT:
        case SymExpr::Kind::GE:
            if (expr->args.size() != 2) return SymbolicShapeClass::INVALID_STRUCTURE;
            break;
        case SymExpr::Kind::ITE:
            if (expr->args.size() != 3) return SymbolicShapeClass::INVALID_STRUCTURE;
            break;
        default:
            return SymbolicShapeClass::INVALID_KIND;
    }
    for (const auto& arg : expr->args) {
        SymbolicShapeClass child = classifySymbolicShape(arg);
        if (child != SymbolicShapeClass::ENCODABLE) return child;
    }
    return SymbolicShapeClass::ENCODABLE;
}

std::optional<std::pair<std::string, std::string>> classifyDeterministicPrecheckResult(
    const SymExprPtr& lhs, const SymExprPtr& rhs, bool composite_piece) {
    SymbolicShapeClass lhs_class = classifySymbolicShape(lhs);
    SymbolicShapeClass rhs_class = classifySymbolicShape(rhs);
    SymbolicShapeClass merged = lhs_class != SymbolicShapeClass::ENCODABLE ? lhs_class : rhs_class;
    if (merged == SymbolicShapeClass::ENCODABLE) return std::nullopt;

    const bool same = structurallyEqualExpr(lhs, rhs);
    switch (merged) {
        case SymbolicShapeClass::INVALID_STRUCTURE:
            return std::make_pair(
                same ? (composite_piece ? "composite malformed symbolic piece matched structurally"
                                        : "malformed symbolic expressions matched structurally")
                     : (composite_piece ? "composite malformed symbolic piece mismatch"
                                        : "malformed symbolic expressions differ"),
                same ? (composite_piece ? "precheck_piece_invalid_symbolic_equal"
                                        : "precheck_invalid_symbolic_equal")
                     : (composite_piece ? "precheck_piece_invalid_symbolic_mismatch"
                                        : "precheck_invalid_symbolic_mismatch"));
        case SymbolicShapeClass::INVALID_LOAD_SIZE:
            return std::make_pair(
                same ? (composite_piece ? "composite zero-byte load piece matched structurally"
                                        : "zero-byte load expressions matched structurally")
                     : (composite_piece ? "composite zero-byte load piece mismatch"
                                        : "zero-byte load expressions differ"),
                same ? (composite_piece ? "precheck_piece_invalid_load_equal"
                                        : "precheck_invalid_load_equal")
                     : (composite_piece ? "precheck_piece_invalid_load_mismatch"
                                        : "precheck_invalid_load_mismatch"));
        case SymbolicShapeClass::INVALID_KIND:
            return std::make_pair(
                same ? (composite_piece ? "composite invalid-kind symbolic piece matched structurally"
                                        : "invalid-kind symbolic expressions matched structurally")
                     : (composite_piece ? "composite invalid-kind symbolic piece mismatch"
                                        : "invalid-kind symbolic expressions differ"),
                same ? (composite_piece ? "precheck_piece_invalid_symbol_kind_equal"
                                        : "precheck_invalid_symbol_kind_equal")
                     : (composite_piece ? "precheck_piece_invalid_symbol_kind_mismatch"
                                        : "precheck_invalid_symbol_kind_mismatch"));
        case SymbolicShapeClass::ENCODABLE:
            break;
    }
    return std::nullopt;
}

std::string formatModelWitness(const z3::model& model) {
    std::vector<std::pair<std::string, std::string>> entries;
    entries.reserve(model.num_consts());
    for (unsigned i = 0; i < model.num_consts(); ++i) {
        z3::func_decl d = model.get_const_decl(i);
        z3::expr v = model.get_const_interp(d);
        std::string name = d.name().str();
        if (name.rfind("sym_", 0) == 0) {
            name = name.substr(4);
        }
        std::string value;
        if (v.is_bv()) {
            uint64_t n = 0;
            if (v.is_numeral_u64(n)) {
                std::ostringstream oss;
                oss << "0x" << std::hex << n;
                value = oss.str();
            } else {
                value = v.to_string();
            }
        } else {
            value = v.to_string();
        }
        entries.emplace_back(std::move(name), std::move(value));
    }
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
        return a.first < b.first;
    });
    std::ostringstream out;
    for (size_t i = 0; i < entries.size(); ++i) {
        if (i != 0) out << ";";
        out << entries[i].first << "=" << entries[i].second;
    }
    return out.str();
}

SMTVerificationResult checkPredicateUnsat(z3::context& ctx, const z3::expr& predicate, uint32_t timeout_ms) {
    SMTVerificationResult out;
    z3::solver solver(ctx);
    if (timeout_ms != 0) {
        z3::params p(ctx);
        p.set("timeout", timeout_ms);
        solver.set(p);
    }
    solver.add(predicate);

    z3::check_result result = solver.check();
    if (result == z3::unsat) {
        out.verdict = ExpressionVerificationResult::Verdict::EQUIVALENT;
        out.reason = "SMT proof established equivalence (UNSAT for lhs != rhs)";
        out.solver_result = "unsat";
        return out;
    }
    if (result == z3::sat) {
        out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
        out.reason = "SMT found a counterexample (SAT for lhs != rhs)";
        out.solver_result = "sat";
        z3::model model = solver.get_model();
        out.model = model.to_string();
        out.witness = formatModelWitness(model);
        return out;
    }

    out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
    out.reason = "SMT solver returned unknown";
    out.solver_result = "unknown";
    std::string why = solver.reason_unknown();
    if (!why.empty()) out.reason += ": " + why;
    return out;
}

} // namespace

bool SMTExpressionVerifier::isAvailable() {
    return true;
}

SMTVerificationResult SMTExpressionVerifier::verify(const SymbolicExpressionResult& lhs,
                                                    const SymbolicExpressionResult& rhs,
                                                    uint32_t timeout_ms) const {
    SMTVerificationResult out;

    if (lhs.type == SymbolicExpressionResult::Type::INVALID ||
        rhs.type == SymbolicExpressionResult::Type::INVALID) {
        out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
        out.reason = "symbolic evaluation invalid";
        out.solver_result = "precheck_invalid_symbolic";
        return out;
    }

    if (lhs.type != rhs.type) {
        out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
        out.reason = "result type mismatch";
        out.solver_result = "precheck_type_mismatch";
        return out;
    }

    if (lhs.uninitialized != rhs.uninitialized) {
        out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
        out.reason = "uninitialized taint mismatch";
        out.solver_result = "precheck_uninitialized_mismatch";
        return out;
    }

    z3::context ctx;
    Encoder encoder(ctx, DwarfUtils::objectIsLittleEndian());

    if (lhs.type == SymbolicExpressionResult::Type::COMPOSITE) {
        if (lhs.pieces.size() != rhs.pieces.size()) {
            out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
            out.reason = "composite piece-count mismatch";
            return out;
        }

        z3::expr any_diff = ctx.bool_val(false);
        bool has_symbolic_piece = false;
        bool had_deterministic_piece_compare = false;
        for (size_t i = 0; i < lhs.pieces.size(); ++i) {
            const auto& l = lhs.pieces[i];
            const auto& r = rhs.pieces[i];
            if (!samePieceMetadata(l, r)) {
                out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
                out.reason = "composite piece metadata mismatch at index " + std::to_string(i);
                out.solver_result = "precheck_piece_metadata_mismatch";
                return out;
            }
            if (!l.location && !r.location) continue;
            if (!l.location || !r.location) {
                out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
                out.reason = "composite piece location presence mismatch at index " + std::to_string(i);
                out.solver_result = "precheck_piece_location_presence_mismatch";
                return out;
            }

            if (auto classification = classifyDeterministicPrecheckResult(l.location, r.location, true)) {
                const bool same = classification->second.find("_equal") != std::string::npos;
                out.verdict = same ? ExpressionVerificationResult::Verdict::EQUIVALENT
                                   : ExpressionVerificationResult::Verdict::DIFFERENT;
                out.reason = classification->first + " at index " + std::to_string(i);
                out.solver_result = classification->second;
                return out;
            }

            if (needsUnsupportedStructuralPrecheck(l.location) &&
                needsUnsupportedStructuralPrecheck(r.location) &&
                structurallyEqualExpr(l.location, r.location)) {
                had_deterministic_piece_compare = true;
                continue;
            }

            if (const auto* lbytes = largeBytesLiteral(l.location)) {
                if (const auto* rbytes = largeBytesLiteral(r.location)) {
                    had_deterministic_piece_compare = true;
                    if (*lbytes != *rbytes) {
                        out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
                        out.reason = "composite wide-byte piece mismatch at index " + std::to_string(i);
                        out.solver_result = "precheck_piece_wide_bytes_mismatch";
                        return out;
                    }
                    continue;
                }
            }

            z3::expr lv = encoder.encodeValue(l.location);
            z3::expr rv = encoder.encodeValue(r.location);
            has_symbolic_piece = true;
            any_diff = any_diff || (lv != rv);
        }

        if (!has_symbolic_piece) {
            out.verdict = ExpressionVerificationResult::Verdict::EQUIVALENT;
            out.reason = had_deterministic_piece_compare
                             ? "composite piece expressions matched exactly without SMT"
                             : "composite metadata matched with no symbolic locations";
            out.solver_result = had_deterministic_piece_compare
                                    ? "precheck_piece_structural_equal"
                                    : "precheck_no_symbolic_piece";
            return out;
        }
        return checkPredicateUnsat(ctx, any_diff, timeout_ms);
    }

    if (!lhs.expression || !rhs.expression) {
        out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
        out.reason = "missing symbolic expression";
        out.solver_result = "precheck_missing_expression";
        return out;
    }

    if (const auto* lbytes = largeBytesLiteral(lhs.expression)) {
        if (const auto* rbytes = largeBytesLiteral(rhs.expression)) {
            const bool same = (*lbytes == *rbytes);
            out.verdict = same ? ExpressionVerificationResult::Verdict::EQUIVALENT
                               : ExpressionVerificationResult::Verdict::DIFFERENT;
            out.reason = same ? "wide byte literals matched exactly"
                              : "wide byte literals differ";
            out.solver_result = same ? "precheck_wide_bytes_equal"
                                     : "precheck_wide_bytes_mismatch";
            return out;
        }
    }

    if (auto classification =
            classifyDeterministicPrecheckResult(lhs.expression, rhs.expression, false)) {
        const bool same = classification->second.find("_equal") != std::string::npos;
        out.verdict = same ? ExpressionVerificationResult::Verdict::EQUIVALENT
                           : ExpressionVerificationResult::Verdict::DIFFERENT;
        out.reason = classification->first;
        out.solver_result = classification->second;
        return out;
    }

    if (needsUnsupportedStructuralPrecheck(lhs.expression) &&
        needsUnsupportedStructuralPrecheck(rhs.expression) &&
        structurallyEqualExpr(lhs.expression, rhs.expression)) {
        out.verdict = ExpressionVerificationResult::Verdict::EQUIVALENT;
        out.reason = "symbolic expressions matched structurally without SMT";
        out.solver_result = "precheck_structural_equal";
        return out;
    }

    z3::expr l = encoder.encodeValue(lhs.expression);
    z3::expr r = encoder.encodeValue(rhs.expression);
    return checkPredicateUnsat(ctx, l != r, timeout_ms);
}

#else

bool SMTExpressionVerifier::isAvailable() {
    return false;
}

SMTVerificationResult SMTExpressionVerifier::verify(const SymbolicExpressionResult&,
                                                    const SymbolicExpressionResult&,
                                                    uint32_t) const {
    SMTVerificationResult out;
    out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
    out.reason = "SMT verification unavailable: library built without Z3 support";
    out.solver_result = "solver_unavailable";
    return out;
}

#endif

} // namespace dwarf
