#include "expression_compare.hpp"
#include "attribute_parser.hpp"
#include "dwarf_utils.hpp"
#include "symbolic_expression.hpp"

#include <algorithm>
#include <cmath>
#include <map>
#include <optional>
#include <sstream>
#include <set>
#include <unordered_map>

namespace dwarf {

namespace {

using DIEVec = std::vector<std::shared_ptr<DIE>>;
using NameMap = std::unordered_map<std::string, DIEVec>;

std::string getStringAttr(const std::shared_ptr<DIE>& die, DwarfAttribute attr) {
    if (!die) return "";
    auto v = die->getAttribute(attr);
    auto s = std::dynamic_pointer_cast<StringAttributeValue>(v);
    return s ? s->getValue() : "";
}

std::string keyForDIE(const std::shared_ptr<DIE>& die, CompareKeyMode mode) {
    if (!die) return "";
    if (mode == CompareKeyMode::LINKAGE_OR_NAME) {
        std::string linkage = getStringAttr(die, DwarfAttribute::DW_AT_linkage_name);
        if (!linkage.empty()) return linkage;
    }
    return die->getName();
}

bool hasAttributeOnDIE(const std::shared_ptr<DIE>& die, DwarfAttribute attr) {
    return die && die->hasAttribute(attr);
}

const char* verdictToString(ExpressionVerificationResult::Verdict v) {
    switch (v) {
        case ExpressionVerificationResult::Verdict::EQUIVALENT:
            return "EQUIVALENT";
        case ExpressionVerificationResult::Verdict::DIFFERENT:
            return "DIFFERENT";
        case ExpressionVerificationResult::Verdict::UNKNOWN:
            return "UNKNOWN";
    }
    return "UNKNOWN";
}

std::string jsonEscape(const std::string& s) {
    std::ostringstream out;
    for (char ch : s) {
        switch (ch) {
            case '\\': out << "\\\\"; break;
            case '\"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20) {
                    out << "\\u00";
                    const char* hex = "0123456789abcdef";
                    unsigned v = static_cast<unsigned char>(ch);
                    out << hex[(v >> 4) & 0xf] << hex[v & 0xf];
                } else {
                    out << ch;
                }
                break;
        }
    }
    return out.str();
}

std::string renderCountsText(const std::map<std::string, size_t>& counts) {
    if (counts.empty()) return "none";
    std::ostringstream out;
    bool first = true;
    for (const auto& kv : counts) {
        if (!first) out << ",";
        first = false;
        out << kv.first << ":" << kv.second;
    }
    return out.str();
}

std::string renderCountsJson(const std::map<std::string, size_t>& counts) {
    std::ostringstream out;
    out << "{";
    bool first = true;
    for (const auto& kv : counts) {
        if (!first) out << ",";
        first = false;
        out << "\"" << jsonEscape(kv.first) << "\":" << kv.second;
    }
    out << "}";
    return out.str();
}

std::string unsupportedOpcodeKey(const char* side, uint8_t opcode) {
    std::ostringstream out;
    out << side << ":0x" << std::hex << static_cast<unsigned>(opcode) << std::dec;
    return out.str();
}

bool isUnsupportedIsolated(const ExpressionVerificationResult& r) {
    return r.reason_class == "unsupported_isolated" &&
           r.isolation_kind == "unsupported_opcode";
}

struct NormalizedExpressionInfo {
    bool available = false;
    std::string kind;
    std::string key;
};

bool isCommutativeExprKind(SymExpr::Kind kind) {
    switch (kind) {
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

std::string canonicalizeBytes(const std::vector<uint8_t>& bytes) {
    std::ostringstream out;
    out << "bytes:";
    for (uint8_t b : bytes) {
        out << std::hex;
        if (b < 0x10) out << "0";
        out << static_cast<unsigned>(b);
    }
    return out.str();
}

std::string canonicalizeSymExpr(const SymExprPtr& expr) {
    if (!expr) return "null";
    std::vector<std::string> args;
    args.reserve(expr->args.size());
    for (const auto& arg : expr->args) {
        args.push_back(canonicalizeSymExpr(arg));
    }
    if (isCommutativeExprKind(expr->kind)) {
        std::sort(args.begin(), args.end());
    }

    std::ostringstream out;
    switch (expr->kind) {
        case SymExpr::Kind::CONST_U64:
            out << "const:0x" << std::hex << expr->const_u64;
            return out.str();
        case SymExpr::Kind::BYTES:
            return canonicalizeBytes(expr->raw_bytes);
        case SymExpr::Kind::VAR:
            return "var:" + expr->name;
        case SymExpr::Kind::UNKNOWN:
            return "unknown:" + expr->name;
        case SymExpr::Kind::LOAD:
            out << "load[" << expr->aux_bytes << "](";
            break;
        case SymExpr::Kind::MASK:
            out << "mask[" << expr->aux_bytes << "](";
            break;
        case SymExpr::Kind::SEXT:
            out << "sext[" << expr->aux_bytes << "](";
            break;
        case SymExpr::Kind::ADD: out << "add("; break;
        case SymExpr::Kind::SUB: out << "sub("; break;
        case SymExpr::Kind::MUL: out << "mul("; break;
        case SymExpr::Kind::DIV: out << "div("; break;
        case SymExpr::Kind::MOD: out << "mod("; break;
        case SymExpr::Kind::AND: out << "and("; break;
        case SymExpr::Kind::OR: out << "or("; break;
        case SymExpr::Kind::XOR: out << "xor("; break;
        case SymExpr::Kind::SHL: out << "shl("; break;
        case SymExpr::Kind::SHR: out << "shr("; break;
        case SymExpr::Kind::SHRA: out << "shra("; break;
        case SymExpr::Kind::NEG: out << "neg("; break;
        case SymExpr::Kind::NOT: out << "not("; break;
        case SymExpr::Kind::ABS: out << "abs("; break;
        case SymExpr::Kind::EQ: out << "eq("; break;
        case SymExpr::Kind::NE: out << "ne("; break;
        case SymExpr::Kind::LT: out << "lt("; break;
        case SymExpr::Kind::LE: out << "le("; break;
        case SymExpr::Kind::GT: out << "gt("; break;
        case SymExpr::Kind::GE: out << "ge("; break;
        case SymExpr::Kind::ITE: out << "ite("; break;
    }
    for (size_t i = 0; i < args.size(); ++i) {
        if (i != 0) out << ",";
        out << args[i];
    }
    out << ")";
    return out.str();
}

std::string canonicalizeCompositePiece(const SymPiece& piece) {
    std::ostringstream out;
    out << "piece(";
    switch (piece.kind) {
        case SymPiece::Kind::MEMORY: out << "mem"; break;
        case SymPiece::Kind::REGISTER: out << "reg"; break;
        case SymPiece::Kind::IMPLICIT: out << "impl"; break;
        case SymPiece::Kind::EMPTY: out << "empty"; break;
    }
    out << ",bs=" << piece.byte_size
        << ",bits=" << piece.bit_size
        << ",bo=" << piece.bit_offset;
    if (!piece.implicit_bytes.empty()) {
        out << "," << canonicalizeBytes(piece.implicit_bytes);
    } else if (piece.location) {
        out << "," << canonicalizeSymExpr(piece.location);
    }
    out << ")";
    return out.str();
}

NormalizedExpressionInfo normalizeExpressionSemantically(const std::vector<uint8_t>& expr,
                                                         const EvaluationContext& ctx,
                                                         uint64_t pc,
                                                         const std::vector<uint64_t>& regs) {
    NormalizedExpressionInfo out;
    if (expr.empty()) return out;

    SymbolicExpressionEvaluator evaluator;
    SymbolicExpressionResult result = evaluator.evaluate(expr, ctx, pc, regs);
    switch (result.type) {
        case SymbolicExpressionResult::Type::ADDRESS:
            out.available = static_cast<bool>(result.expression);
            out.kind = "symbolic_address";
            out.key = out.available ? "addr:" + canonicalizeSymExpr(result.expression) : "";
            return out;
        case SymbolicExpressionResult::Type::VALUE:
            out.available = static_cast<bool>(result.expression);
            out.kind = "symbolic_value";
            out.key = out.available ? "value:" + canonicalizeSymExpr(result.expression) : "";
            return out;
        case SymbolicExpressionResult::Type::REGISTER:
            out.available = static_cast<bool>(result.expression);
            out.kind = "symbolic_register";
            out.key = out.available ? "register:" + canonicalizeSymExpr(result.expression) : "";
            return out;
        case SymbolicExpressionResult::Type::COMPOSITE: {
            out.available = true;
            out.kind = "symbolic_composite";
            std::ostringstream key;
            key << "composite[";
            for (size_t i = 0; i < result.pieces.size(); ++i) {
                if (i != 0) key << ";";
                key << canonicalizeCompositePiece(result.pieces[i]);
            }
            key << "]";
            out.key = key.str();
            return out;
        }
        case SymbolicExpressionResult::Type::INVALID:
            return out;
    }
    return out;
}

bool selectExpressionBytes(const std::shared_ptr<DIE>& die,
                           DwarfAttribute attr,
                           bool use_location_list_pc,
                           uint64_t location_list_pc,
                           std::vector<uint8_t>& out_expr) {
    if (!die) return false;
    auto value = die->getAttribute(attr);
    if (!value) return false;
    if (auto loc = std::dynamic_pointer_cast<LocationAttributeValue>(value)) {
        if (loc->getLocationType() == LocationAttributeValue::LocationType::EXPRESSION) {
            out_expr = loc->getData();
            return !out_expr.empty();
        }
        if (loc->getLocationType() == LocationAttributeValue::LocationType::LIST) {
            if (use_location_list_pc) {
                out_expr = loc->getExpressionForPC(location_list_pc);
                if (!out_expr.empty()) return true;
            }
            for (const auto& e : loc->getEntries()) {
                if (e.is_default && !e.expression.empty()) {
                    out_expr = e.expression;
                    return true;
                }
            }
            for (const auto& e : loc->getEntries()) {
                if (!e.is_default && !e.expression.empty()) {
                    out_expr = e.expression;
                    return true;
                }
            }
            out_expr = loc->getData();
            return !out_expr.empty();
        }
        return false;
    }
    if (auto expr = std::dynamic_pointer_cast<ExpressionAttributeValue>(value)) {
        out_expr = expr->getExpression();
        return !out_expr.empty();
    }
    if (auto block = std::dynamic_pointer_cast<BlockAttributeValue>(value)) {
        out_expr = block->getData();
        return !out_expr.empty();
    }
    return false;
}

struct NormalizedLocationEntry {
    LocationAttributeValue::LocationEntry entry;
    std::string semantic_key;
};

void collectNamedByTag(const std::shared_ptr<DIE>& die,
                       DwarfTag tag,
                       CompareKeyMode mode,
                       NameMap& out) {
    if (!die) return;
    if (die->getTag() == tag) {
        std::string name = keyForDIE(die, mode);
        if (!name.empty()) {
            out[name].push_back(die);
        }
    }
    for (const auto& child : die->getChildren()) {
        collectNamedByTag(child, tag, mode, out);
    }
}

NameMap buildNameMap(const std::vector<std::shared_ptr<DIE>>& roots,
                     DwarfTag tag,
                     CompareKeyMode mode) {
    NameMap out;
    for (const auto& root : roots) {
        collectNamedByTag(root, tag, mode, out);
    }
    for (auto& kv : out) {
        auto& v = kv.second;
        std::sort(v.begin(), v.end(), [](const std::shared_ptr<DIE>& a, const std::shared_ptr<DIE>& b) {
            return a->getOffset() < b->getOffset();
        });
    }
    return out;
}

NamedExpressionComparison makeMissing(const std::string& name,
                                      DwarfTag tag,
                                      bool lhs_present,
                                      bool rhs_present,
                                      uint64_t lhs_offset,
                                      uint64_t rhs_offset,
                                      const std::string& why) {
    NamedExpressionComparison out;
    out.name = name;
    out.tag = tag;
    out.lhs_present = lhs_present;
    out.rhs_present = rhs_present;
    out.lhs_offset = lhs_offset;
    out.rhs_offset = rhs_offset;
    out.verification.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
    out.verification.reason = why;
    return out;
}

bool isLikelyRelocationPlaceholder(const std::string& s) {
    return s.rfind("<strx", 0) == 0 || s.rfind("<line_strp:", 0) == 0;
}

void collectRelocationIssuesFromTree(const std::shared_ptr<DIE>& die,
                                     std::vector<std::string>& out) {
    if (!die) return;
    for (const auto& kv : die->getAttributes()) {
        const auto attr = kv.first;
        const auto& value = kv.second;
        if (auto s = std::dynamic_pointer_cast<StringAttributeValue>(value)) {
            if (isLikelyRelocationPlaceholder(s->getValue())) {
                out.push_back("unresolved indexed string in " + DwarfUtils::attributeToString(attr));
            }
        }
        if (auto loc = std::dynamic_pointer_cast<LocationAttributeValue>(value)) {
            if (loc->getLocationType() == LocationAttributeValue::LocationType::LIST) {
                for (const auto& e : loc->getEntries()) {
                    if (!e.is_default && e.end <= e.start) {
                        out.push_back("invalid location range in " + DwarfUtils::attributeToString(attr));
                        break;
                    }
                }
            }
        }
        if (auto ranges = std::dynamic_pointer_cast<RangeAttributeValue>(value)) {
            for (const auto& r : ranges->getRanges()) {
                if (!r.is_base_address && r.end <= r.start) {
                    out.push_back("invalid range list entry in " + DwarfUtils::attributeToString(attr));
                    break;
                }
            }
        }
    }
    for (const auto& child : die->getChildren()) {
        collectRelocationIssuesFromTree(child, out);
    }
}

std::vector<NormalizedLocationEntry> normalizeLocationEntries(
    const std::vector<LocationAttributeValue::LocationEntry>& in,
    bool normalize,
    const EvaluationContext& ctx,
    uint64_t evaluation_pc,
    const std::vector<uint64_t>& regs) {
    std::vector<NormalizedLocationEntry> out;
    out.reserve(in.size());
    for (const auto& e : in) {
        if (e.is_default) continue;
        if (e.end <= e.start) continue;
        if (e.expression.empty()) continue;
        NormalizedLocationEntry normalized;
        normalized.entry = e;
        if (normalize) {
            uint64_t pc = (evaluation_pc != 0) ? evaluation_pc : e.start;
            auto norm = normalizeExpressionSemantically(e.expression, ctx, pc, regs);
            if (norm.available) normalized.semantic_key = norm.kind + ":" + norm.key;
        }
        out.push_back(std::move(normalized));
    }
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        if (a.entry.start != b.entry.start) return a.entry.start < b.entry.start;
        if (a.entry.end != b.entry.end) return a.entry.end < b.entry.end;
        if (a.semantic_key != b.semantic_key) return a.semantic_key < b.semantic_key;
        return a.entry.expression < b.entry.expression;
    });

    if (!normalize || out.empty()) return out;

    std::vector<NormalizedLocationEntry> merged;
    merged.push_back(out.front());
    for (size_t i = 1; i < out.size(); ++i) {
        auto& prev = merged.back();
        const auto& cur = out[i];
        const bool same_semantics = !prev.semantic_key.empty() &&
                                    prev.semantic_key == cur.semantic_key;
        const bool same_bytes = prev.entry.expression == cur.entry.expression;
        if (prev.entry.end >= cur.entry.start && (same_semantics || same_bytes)) {
            if (cur.entry.end > prev.entry.end) prev.entry.end = cur.entry.end;
            if (prev.semantic_key.empty()) prev.semantic_key = cur.semantic_key;
            continue;
        }
        merged.push_back(cur);
    }
    return merged;
}

const std::vector<uint8_t>* expressionForRange(
    const std::vector<NormalizedLocationEntry>& entries,
    uint64_t start,
    uint64_t end) {
    for (const auto& e : entries) {
        if (start >= e.entry.start && end <= e.entry.end) return &e.entry.expression;
    }
    return nullptr;
}

void appendUnique(std::vector<uint64_t>& points, uint64_t v) {
    if (points.empty() || points.back() != v) points.push_back(v);
}

NamedExpressionComparison compareOne(const std::string& name,
                                     DwarfTag tag,
                                     const std::shared_ptr<DIE>& lhs_die,
                                     const std::shared_ptr<DIE>& rhs_die,
                                     const CrossBinaryCompareOptions& opts,
                                     const ExpressionVerifier& verifier) {
    NamedExpressionComparison out;
    out.name = name;
    out.tag = tag;
    out.lhs_present = static_cast<bool>(lhs_die);
    out.rhs_present = static_cast<bool>(rhs_die);
    if (lhs_die) out.lhs_offset = lhs_die->getOffset();
    if (rhs_die) out.rhs_offset = rhs_die->getOffset();

    if (opts.enable_relocation_checks) {
        if (lhs_die) collectRelocationIssuesFromTree(lhs_die, out.relocation_issues);
        if (rhs_die) collectRelocationIssuesFromTree(rhs_die, out.relocation_issues);
        std::sort(out.relocation_issues.begin(), out.relocation_issues.end());
        out.relocation_issues.erase(std::unique(out.relocation_issues.begin(), out.relocation_issues.end()),
                                    out.relocation_issues.end());
    }

    if (!lhs_die || !rhs_die) {
        out.verification.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
        out.verification.reason = (!lhs_die && !rhs_die) ? "both DIEs missing"
                                                          : (!lhs_die ? "lhs DIE missing" : "rhs DIE missing");
        return out;
    }

    DIEExpressionSelectionOptions lhs_sel;
    lhs_sel.attribute = opts.attribute;
    lhs_sel.use_pc_for_location_list = opts.use_location_list_pc;
    lhs_sel.location_list_pc = opts.lhs_location_list_pc;
    lhs_sel.evaluation_pc = opts.lhs_evaluation_pc;

    DIEExpressionSelectionOptions rhs_sel;
    rhs_sel.attribute = opts.attribute;
    rhs_sel.use_pc_for_location_list = opts.use_location_list_pc;
    rhs_sel.location_list_pc = opts.rhs_location_list_pc;
    rhs_sel.evaluation_pc = opts.rhs_evaluation_pc;

    EvaluationContext lhs_ctx = opts.lhs_context;
    EvaluationContext rhs_ctx = opts.rhs_context;
    if (lhs_ctx.vendor_expression_profile == VendorExpressionProfile::NONE) {
        lhs_ctx.vendor_expression_profile = opts.vendor_expression_profile;
    }
    if (rhs_ctx.vendor_expression_profile == VendorExpressionProfile::NONE) {
        rhs_ctx.vendor_expression_profile = opts.vendor_expression_profile;
    }
    lhs_ctx.diagnostic_cu_offset = lhs_die->getCUBaseOffset();
    lhs_ctx.diagnostic_die_offset = lhs_die->getOffset();
    lhs_ctx.diagnostic_attribute = DwarfUtils::attributeToString(opts.attribute);
    rhs_ctx.diagnostic_cu_offset = rhs_die->getCUBaseOffset();
    rhs_ctx.diagnostic_die_offset = rhs_die->getOffset();
    rhs_ctx.diagnostic_attribute = DwarfUtils::attributeToString(opts.attribute);

    auto lhs_attr = lhs_die->getAttribute(opts.attribute);
    auto rhs_attr = rhs_die->getAttribute(opts.attribute);
    auto lhs_loc = std::dynamic_pointer_cast<LocationAttributeValue>(lhs_attr);
    auto rhs_loc = std::dynamic_pointer_cast<LocationAttributeValue>(rhs_attr);
    bool normalization_attempted = false;
    std::string lhs_normalized_summary;
    std::string rhs_normalized_summary;
    std::string normalization_kind;

    const bool use_range_aware_lists =
        opts.enable_range_aware_location_compare &&
        lhs_loc && rhs_loc &&
        lhs_loc->getLocationType() == LocationAttributeValue::LocationType::LIST &&
        rhs_loc->getLocationType() == LocationAttributeValue::LocationType::LIST;

    if (opts.enable_location_semantic_normalization && !use_range_aware_lists) {
        std::vector<uint8_t> lhs_expr;
        std::vector<uint8_t> rhs_expr;
        if (selectExpressionBytes(lhs_die, opts.attribute, opts.use_location_list_pc, opts.lhs_location_list_pc, lhs_expr) &&
            selectExpressionBytes(rhs_die, opts.attribute, opts.use_location_list_pc, opts.rhs_location_list_pc, rhs_expr)) {
            auto lhs_norm = normalizeExpressionSemantically(
                lhs_expr, lhs_ctx,
                opts.lhs_evaluation_pc != 0 ? opts.lhs_evaluation_pc : opts.lhs_location_list_pc,
                opts.lhs_registers);
            auto rhs_norm = normalizeExpressionSemantically(
                rhs_expr, rhs_ctx,
                opts.rhs_evaluation_pc != 0 ? opts.rhs_evaluation_pc : opts.rhs_location_list_pc,
                opts.rhs_registers);
            if (lhs_norm.available || rhs_norm.available) {
                normalization_attempted = true;
                normalization_kind = "symbolic_canonical";
                lhs_normalized_summary = lhs_norm.available ? lhs_norm.key : "";
                rhs_normalized_summary = rhs_norm.available ? rhs_norm.key : "";
                out.verification.normalization_applied = true;
                out.verification.normalization_kind = "symbolic_canonical";
                out.verification.lhs_normalized_summary = lhs_normalized_summary;
                out.verification.rhs_normalized_summary = rhs_normalized_summary;
                if (lhs_norm.available && rhs_norm.available && lhs_norm.key == rhs_norm.key) {
                    out.verification.normalization_equal = true;
                    out.verification.verdict = ExpressionVerificationResult::Verdict::EQUIVALENT;
                    out.verification.reason = "semantic normalization matched";
                    out.verification.reason_class = "equivalent";
                    out.verification.verifier_backend = "structural";
                    out.verification.solver_result = "normalized_equal";
                    return out;
                }
            }
        }
    }

    if (use_range_aware_lists) {
        out.range_aware = true;
        auto lhs_entries = normalizeLocationEntries(lhs_loc->getEntries(),
                                                    opts.enable_location_semantic_normalization,
                                                    lhs_ctx,
                                                    opts.lhs_evaluation_pc,
                                                    opts.lhs_registers);
        auto rhs_entries = normalizeLocationEntries(rhs_loc->getEntries(),
                                                    opts.enable_location_semantic_normalization,
                                                    rhs_ctx,
                                                    opts.rhs_evaluation_pc,
                                                    opts.rhs_registers);

        std::vector<uint64_t> points;
        points.reserve(lhs_entries.size() * 2 + rhs_entries.size() * 2);
        for (const auto& e : lhs_entries) {
            points.push_back(e.entry.start);
            points.push_back(e.entry.end);
        }
        for (const auto& e : rhs_entries) {
            points.push_back(e.entry.start);
            points.push_back(e.entry.end);
        }
        if (points.empty()) {
            out.verification.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
            out.verification.reason = "range-aware compare has no concrete location-list ranges";
            return out;
        }
        std::sort(points.begin(), points.end());
        std::vector<uint64_t> unique_points;
        unique_points.reserve(points.size());
        for (uint64_t p : points) appendUnique(unique_points, p);
        if (unique_points.size() < 2) {
            out.verification.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
            out.verification.reason = "range-aware compare has insufficient range boundaries";
            return out;
        }

        ExpressionVerificationResult::Verdict overall = ExpressionVerificationResult::Verdict::EQUIVALENT;
        size_t comparable_segments = 0;
        bool saw_generic_unknown = false;
        bool saw_unsupported_segment = false;
        for (size_t i = 0; i + 1 < unique_points.size(); ++i) {
            uint64_t start = unique_points[i];
            uint64_t end = unique_points[i + 1];
            if (end <= start) continue;

            LocationRangeSegmentVerdict segment;
            segment.start = start;
            segment.end = end;
            segment.lhs_present = expressionForRange(lhs_entries, start, end) != nullptr;
            segment.rhs_present = expressionForRange(rhs_entries, start, end) != nullptr;
            uint64_t width = end - start;
            out.coverage_total += width;

            if (!segment.lhs_present || !segment.rhs_present) {
                segment.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
                segment.reason = !segment.lhs_present ? "lhs has no covering location expression"
                                                      : "rhs has no covering location expression";
                out.coverage_uncovered += width;
                if (overall == ExpressionVerificationResult::Verdict::EQUIVALENT) {
                    overall = ExpressionVerificationResult::Verdict::UNKNOWN;
                }
                out.range_segments.push_back(std::move(segment));
                continue;
            }

            const auto* lhs_expr = expressionForRange(lhs_entries, start, end);
            const auto* rhs_expr = expressionForRange(rhs_entries, start, end);
            uint64_t lhs_pc = (opts.lhs_evaluation_pc != 0) ? opts.lhs_evaluation_pc : start;
            uint64_t rhs_pc = (opts.rhs_evaluation_pc != 0) ? opts.rhs_evaluation_pc : start;
            ExpressionVerificationResult vr;
            if (opts.enable_location_semantic_normalization) {
                auto lhs_norm = normalizeExpressionSemantically(*lhs_expr, lhs_ctx, lhs_pc, opts.lhs_registers);
                auto rhs_norm = normalizeExpressionSemantically(*rhs_expr, rhs_ctx, rhs_pc, opts.rhs_registers);
                if (lhs_norm.available || rhs_norm.available) {
                    vr.normalization_applied = true;
                    vr.normalization_kind = "symbolic_canonical";
                    vr.lhs_normalized_summary = lhs_norm.available ? lhs_norm.key : "";
                    vr.rhs_normalized_summary = rhs_norm.available ? rhs_norm.key : "";
                    if (lhs_norm.available && rhs_norm.available && lhs_norm.key == rhs_norm.key) {
                        vr.normalization_equal = true;
                        vr.verdict = ExpressionVerificationResult::Verdict::EQUIVALENT;
                        vr.reason = "semantic normalization matched";
                        vr.reason_class = "equivalent";
                        vr.verifier_backend = "structural";
                        vr.solver_result = "normalized_equal";
                    }
                }
            }
            if (vr.solver_result.empty()) {
                vr = verifier.verifyWithContexts(
                    *lhs_expr, lhs_ctx, lhs_pc, opts.lhs_registers,
                    *rhs_expr, rhs_ctx, rhs_pc, opts.rhs_registers,
                    opts.verification_options);
            }
            ++comparable_segments;
            segment.verdict = vr.verdict;
            segment.reason = vr.reason;
            segment.reason_class = vr.reason_class;
            segment.isolation_kind = vr.isolation_kind;
            segment.solver_result = vr.solver_result;
            segment.lhs_unsupported_opcode = vr.lhs_unsupported_opcode;
            segment.rhs_unsupported_opcode = vr.rhs_unsupported_opcode;
            segment.lhs_unsupported_vendor_extension = vr.lhs_unsupported_vendor_extension;
            segment.rhs_unsupported_vendor_extension = vr.rhs_unsupported_vendor_extension;
            if (vr.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT) {
                out.coverage_equivalent += width;
            } else if (vr.verdict == ExpressionVerificationResult::Verdict::DIFFERENT) {
                out.coverage_different += width;
                overall = ExpressionVerificationResult::Verdict::DIFFERENT;
            } else {
                out.coverage_unknown += width;
                if (isUnsupportedIsolated(vr)) {
                    out.coverage_unsupported += width;
                    ++out.unsupported_segment_count;
                    saw_unsupported_segment = true;
                    segment.diagnosis_origin = "range_segment";
                    if (!out.verification.lhs_unsupported_opcode.has_value()) {
                        out.verification.lhs_unsupported_opcode = vr.lhs_unsupported_opcode;
                        out.verification.lhs_unsupported_vendor_extension = vr.lhs_unsupported_vendor_extension;
                    }
                    if (!out.verification.rhs_unsupported_opcode.has_value()) {
                        out.verification.rhs_unsupported_opcode = vr.rhs_unsupported_opcode;
                        out.verification.rhs_unsupported_vendor_extension = vr.rhs_unsupported_vendor_extension;
                    }
                    if (out.verification.lhs_attribute_kind.empty()) {
                        out.verification.lhs_attribute_kind = "location_list_segment";
                        std::ostringstream detail;
                        detail << "attr=" << DwarfUtils::attributeToString(opts.attribute)
                               << " range=[" << DwarfUtils::formatAddress(start, false)
                               << "," << DwarfUtils::formatAddress(end, false) << ")";
                        out.verification.lhs_attribute_detail = detail.str();
                    }
                    if (out.verification.rhs_attribute_kind.empty()) {
                        out.verification.rhs_attribute_kind = "location_list_segment";
                        std::ostringstream detail;
                        detail << "attr=" << DwarfUtils::attributeToString(opts.attribute)
                               << " range=[" << DwarfUtils::formatAddress(start, false)
                               << "," << DwarfUtils::formatAddress(end, false) << ")";
                        out.verification.rhs_attribute_detail = detail.str();
                    }
                } else {
                    saw_generic_unknown = true;
                    segment.diagnosis_origin = vr.reason_class.empty() ? "range_segment" : "range_segment_compare";
                }
                if (overall == ExpressionVerificationResult::Verdict::EQUIVALENT) {
                    overall = ExpressionVerificationResult::Verdict::UNKNOWN;
                }
            }
            out.range_segments.push_back(std::move(segment));
        }

        out.verification.verdict = overall;
        out.verification.normalization_applied = opts.enable_location_semantic_normalization;
        out.verification.normalization_kind = opts.enable_location_semantic_normalization ? "symbolic_canonical" : "";
        if (comparable_segments == 0) {
            out.verification.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
            out.verification.reason = "range-aware compare found no segments with expressions on both sides";
        } else {
            std::ostringstream rs;
            rs << "range-aware coverage eq=" << out.coverage_equivalent
               << " diff=" << out.coverage_different
               << " unk=" << out.coverage_unknown
               << " unsupported=" << out.coverage_unsupported
               << " uncovered=" << out.coverage_uncovered
               << " total=" << out.coverage_total
               << " unsupported_segments=" << out.unsupported_segment_count;
            out.verification.reason = rs.str();
        }
        if (out.verification.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT) {
            out.verification.reason_class = "equivalent";
        } else if (out.verification.verdict == ExpressionVerificationResult::Verdict::DIFFERENT) {
            out.verification.reason_class = "different";
        } else if (saw_unsupported_segment && !saw_generic_unknown && out.coverage_uncovered == 0) {
            out.verification.reason_class = "unsupported_isolated";
            out.verification.isolation_kind = "unsupported_opcode";
            out.verification.solver_result = "unsupported_opcode";
        } else {
            out.verification.reason_class = "unknown";
            if (saw_unsupported_segment) {
                out.verification.isolation_kind = "range_segment";
                if (out.verification.solver_result.empty()) {
                    out.verification.solver_result = "range_segment_mixed";
                }
            }
        }
        return out;
    }

    out.verification = verifier.verifyDIEAttributeExpressions(
        lhs_die, lhs_ctx, opts.lhs_registers,
        rhs_die, rhs_ctx, opts.rhs_registers,
        lhs_sel, rhs_sel, opts.verification_options);
    if (normalization_attempted) {
        out.verification.normalization_applied = true;
        out.verification.normalization_kind = normalization_kind;
        out.verification.lhs_normalized_summary = lhs_normalized_summary;
        out.verification.rhs_normalized_summary = rhs_normalized_summary;
    }
    return out;
}

} // namespace

std::vector<NamedExpressionComparison> CrossBinaryExpressionComparator::compareParsersByName(
    const DwarfParser& lhs,
    const DwarfParser& rhs,
    const CrossBinaryCompareOptions& opts) const {
    return compareDIEListsByName(lhs.getCompilationUnits(), rhs.getCompilationUnits(), opts);
}

std::vector<NamedExpressionComparison> CrossBinaryExpressionComparator::compareDIEListsByName(
    const std::vector<std::shared_ptr<DIE>>& lhs_roots,
    const std::vector<std::shared_ptr<DIE>>& rhs_roots,
    const CrossBinaryCompareOptions& opts) const {
    std::vector<NamedExpressionComparison> out;

    NameMap lhs_map = buildNameMap(lhs_roots, opts.tag, opts.key_mode);
    NameMap rhs_map = buildNameMap(rhs_roots, opts.tag, opts.key_mode);

    std::set<std::string> names;
    for (const auto& kv : lhs_map) names.insert(kv.first);
    for (const auto& kv : rhs_map) names.insert(kv.first);

    for (const auto& name : names) {
        const auto lhs_it = lhs_map.find(name);
        const auto rhs_it = rhs_map.find(name);
        const DIEVec* lhs_vec = (lhs_it == lhs_map.end()) ? nullptr : &lhs_it->second;
        const DIEVec* rhs_vec = (rhs_it == rhs_map.end()) ? nullptr : &rhs_it->second;

        size_t lhs_n = lhs_vec ? lhs_vec->size() : 0;
        size_t rhs_n = rhs_vec ? rhs_vec->size() : 0;
        size_t paired = std::min(lhs_n, rhs_n);

        for (size_t i = 0; i < paired; ++i) {
            if (opts.require_attribute_on_both &&
                (!hasAttributeOnDIE((*lhs_vec)[i], opts.attribute) ||
                 !hasAttributeOnDIE((*rhs_vec)[i], opts.attribute))) {
                continue;
            }
            out.push_back(compareOne(name, opts.tag, (*lhs_vec)[i], (*rhs_vec)[i], opts, verifier_));
        }

        if (!opts.include_missing) continue;

        for (size_t i = paired; i < lhs_n; ++i) {
            out.push_back(makeMissing(name, opts.tag, true, false, (*lhs_vec)[i]->getOffset(), 0,
                                      "rhs DIE missing for name"));
        }
        for (size_t i = paired; i < rhs_n; ++i) {
            out.push_back(makeMissing(name, opts.tag, false, true, 0, (*rhs_vec)[i]->getOffset(),
                                      "lhs DIE missing for name"));
        }
    }

    return out;
}

NamedExpressionComparison CrossBinaryExpressionComparator::compareNamedInParsers(
    const DwarfParser& lhs,
    const DwarfParser& rhs,
    const std::string& name,
    const CrossBinaryCompareOptions& opts) const {
    NameMap lhs_map = buildNameMap(lhs.getCompilationUnits(), opts.tag, opts.key_mode);
    NameMap rhs_map = buildNameMap(rhs.getCompilationUnits(), opts.tag, opts.key_mode);

    std::shared_ptr<DIE> lhs_die;
    std::shared_ptr<DIE> rhs_die;

    auto lhs_it = lhs_map.find(name);
    if (lhs_it != lhs_map.end() && !lhs_it->second.empty()) lhs_die = lhs_it->second.front();
    auto rhs_it = rhs_map.find(name);
    if (rhs_it != rhs_map.end() && !rhs_it->second.empty()) rhs_die = rhs_it->second.front();

    return compareOne(name, opts.tag, lhs_die, rhs_die, opts, verifier_);
}

CrossBinaryComparisonSummary CrossBinaryExpressionComparator::summarize(
    const std::vector<NamedExpressionComparison>& comparisons) const {
    CrossBinaryComparisonSummary s;
    s.total = comparisons.size();
    for (const auto& c : comparisons) {
        if (!c.lhs_present) ++s.missing_lhs;
        if (!c.rhs_present) ++s.missing_rhs;
        if (c.verification.normalization_equal) ++s.normalized_equal;
        if (c.verification.normalization_applied) {
            s.normalization_kind_counts[c.verification.normalization_kind.empty() ? "unspecified"
                                                                                  : c.verification.normalization_kind]++;
        }
        s.coverage_total += c.coverage_total;
        s.coverage_equivalent += c.coverage_equivalent;
        s.coverage_different += c.coverage_different;
        s.coverage_unknown += c.coverage_unknown;
        s.coverage_uncovered += c.coverage_uncovered;
        s.coverage_unsupported += c.coverage_unsupported;
        s.unsupported_segment_count += c.unsupported_segment_count;
        switch (c.verification.verdict) {
            case ExpressionVerificationResult::Verdict::EQUIVALENT:
                ++s.equivalent;
                break;
            case ExpressionVerificationResult::Verdict::DIFFERENT:
                ++s.different;
                break;
            case ExpressionVerificationResult::Verdict::UNKNOWN:
                ++s.unknown;
                s.unknown_reason_counts[c.verification.reason.empty() ? "unspecified"
                                                                     : c.verification.reason]++;
                s.unknown_reason_class_counts[c.verification.reason_class.empty() ? "unspecified"
                                                                                 : c.verification.reason_class]++;
                s.unknown_solver_result_counts[c.verification.solver_result.empty() ? "unspecified"
                                                                                    : c.verification.solver_result]++;
                s.unknown_lhs_attribute_kind_counts[c.verification.lhs_attribute_kind.empty() ? "unspecified"
                                                                                               : c.verification.lhs_attribute_kind]++;
                s.unknown_rhs_attribute_kind_counts[c.verification.rhs_attribute_kind.empty() ? "unspecified"
                                                                                               : c.verification.rhs_attribute_kind]++;
                break;
        }
        if (c.verification.reason_class == "unsupported_isolated") ++s.unsupported_isolated_rows;
        if (c.verification.lhs_unsupported_opcode.has_value() ||
            c.verification.rhs_unsupported_opcode.has_value() ||
            c.unsupported_segment_count != 0) {
            ++s.unsupported_row_count;
        }
        if (c.unsupported_segment_count == 0 && c.verification.lhs_unsupported_opcode.has_value()) {
            s.unsupported_opcode_counts[unsupportedOpcodeKey("lhs", *c.verification.lhs_unsupported_opcode)]++;
        }
        if (c.unsupported_segment_count == 0 && c.verification.rhs_unsupported_opcode.has_value()) {
            s.unsupported_opcode_counts[unsupportedOpcodeKey("rhs", *c.verification.rhs_unsupported_opcode)]++;
        }
        for (const auto& segment : c.range_segments) {
            if (segment.lhs_unsupported_opcode.has_value()) {
                s.unsupported_opcode_counts[unsupportedOpcodeKey("lhs", *segment.lhs_unsupported_opcode)]++;
            }
            if (segment.rhs_unsupported_opcode.has_value()) {
                s.unsupported_opcode_counts[unsupportedOpcodeKey("rhs", *segment.rhs_unsupported_opcode)]++;
            }
        }
        if (!c.verification.isolation_kind.empty()) {
            s.unsupported_isolation_kind_counts[c.verification.isolation_kind]++;
        }
    }
    return s;
}

std::string CrossBinaryExpressionComparator::renderTextReport(
    const std::vector<NamedExpressionComparison>& comparisons,
    size_t max_rows) const {
    std::ostringstream out;
    CrossBinaryComparisonSummary s = summarize(comparisons);
    std::map<std::string, size_t> solver_counts;
    std::map<std::string, size_t> backend_counts;
    for (const auto& c : comparisons) {
        const std::string solver_key = c.verification.solver_result.empty() ? "unspecified"
                                                                            : c.verification.solver_result;
        const std::string backend_key = c.verification.verifier_backend.empty() ? "unspecified"
                                                                                : c.verification.verifier_backend;
        solver_counts[solver_key]++;
        backend_counts[backend_key]++;
    }

    out << "summary total=" << s.total
        << " equivalent=" << s.equivalent
        << " different=" << s.different
        << " unknown=" << s.unknown
        << " missing_lhs=" << s.missing_lhs
        << " missing_rhs=" << s.missing_rhs;
    if (s.coverage_total != 0) {
        out << " coverage_total=" << s.coverage_total
            << " coverage_eq=" << s.coverage_equivalent
            << " coverage_diff=" << s.coverage_different
            << " coverage_unknown=" << s.coverage_unknown
            << " coverage_unsupported=" << s.coverage_unsupported
            << " coverage_uncovered=" << s.coverage_uncovered;
    }
    out
        << "\n";
    out << "solver_result_counts=";
    bool first = true;
    for (const auto& kv : solver_counts) {
        if (!first) out << ",";
        first = false;
        out << kv.first << ":" << kv.second;
    }
    out << " verifier_backend_counts=";
    first = true;
    for (const auto& kv : backend_counts) {
        if (!first) out << ",";
        first = false;
        out << kv.first << ":" << kv.second;
    }
    out << "\n";
    out << "unknown_reason_counts=" << renderCountsText(s.unknown_reason_counts)
        << " unknown_reason_class_counts=" << renderCountsText(s.unknown_reason_class_counts)
        << " unknown_solver_result_counts=" << renderCountsText(s.unknown_solver_result_counts)
        << " unknown_lhs_attribute_kind_counts=" << renderCountsText(s.unknown_lhs_attribute_kind_counts)
        << " unknown_rhs_attribute_kind_counts=" << renderCountsText(s.unknown_rhs_attribute_kind_counts)
        << "\n";
    out << "unsupported_opcode_counts=" << renderCountsText(s.unsupported_opcode_counts)
        << " unsupported_isolation_kind_counts=" << renderCountsText(s.unsupported_isolation_kind_counts)
        << " unsupported_rows=" << s.unsupported_row_count
        << " unsupported_isolated_rows=" << s.unsupported_isolated_rows
        << " unsupported_segments=" << s.unsupported_segment_count
        << " normalized_equal=" << s.normalized_equal
        << " normalization_kind_counts=" << renderCountsText(s.normalization_kind_counts)
        << "\n";

    out << "name|tag|lhs_present|rhs_present|lhs_offset|rhs_offset|verdict|verifier_backend|solver_result|reason|reason_class|isolation_kind|normalization_applied|normalization_equal|normalization_kind|lhs_normalized_summary|rhs_normalized_summary|lhs_attribute_kind|rhs_attribute_kind|lhs_attribute_detail|rhs_attribute_detail|lhs_unsupported_opcode|rhs_unsupported_opcode|lhs_unsupported_vendor_extension|rhs_unsupported_vendor_extension|coverage_total|coverage_eq|coverage_diff|coverage_unknown|coverage_unsupported|coverage_uncovered|unsupported_segments|reloc_issues\n";
    size_t rows = (max_rows == 0) ? comparisons.size() : std::min(max_rows, comparisons.size());
    for (size_t i = 0; i < rows; ++i) {
        const auto& c = comparisons[i];
        std::ostringstream reloc;
        for (size_t k = 0; k < c.relocation_issues.size(); ++k) {
            if (k != 0) reloc << ";";
            reloc << c.relocation_issues[k];
        }
        out << c.name << "|"
            << DwarfUtils::tagToString(c.tag) << "|"
            << (c.lhs_present ? "1" : "0") << "|"
            << (c.rhs_present ? "1" : "0") << "|"
            << c.lhs_offset << "|"
            << c.rhs_offset << "|"
            << verdictToString(c.verification.verdict) << "|"
            << c.verification.verifier_backend << "|"
            << c.verification.solver_result << "|"
            << c.verification.reason << "|"
            << c.verification.reason_class << "|"
            << c.verification.isolation_kind << "|"
            << (c.verification.normalization_applied ? "1" : "0") << "|"
            << (c.verification.normalization_equal ? "1" : "0") << "|"
            << c.verification.normalization_kind << "|"
            << c.verification.lhs_normalized_summary << "|"
            << c.verification.rhs_normalized_summary << "|"
            << c.verification.lhs_attribute_kind << "|"
            << c.verification.rhs_attribute_kind << "|"
            << c.verification.lhs_attribute_detail << "|"
            << c.verification.rhs_attribute_detail << "|"
            << (c.verification.lhs_unsupported_opcode ? DwarfUtils::formatAddress(*c.verification.lhs_unsupported_opcode, false) : "") << "|"
            << (c.verification.rhs_unsupported_opcode ? DwarfUtils::formatAddress(*c.verification.rhs_unsupported_opcode, false) : "") << "|"
            << (c.verification.lhs_unsupported_vendor_extension ? "1" : "0") << "|"
            << (c.verification.rhs_unsupported_vendor_extension ? "1" : "0") << "|"
            << c.coverage_total << "|"
            << c.coverage_equivalent << "|"
            << c.coverage_different << "|"
            << c.coverage_unknown << "|"
            << c.coverage_unsupported << "|"
            << c.coverage_uncovered << "|"
            << c.unsupported_segment_count << "|"
            << reloc.str() << "\n";
    }
    if (rows < comparisons.size()) {
        out << "... truncated " << (comparisons.size() - rows) << " rows\n";
    }
    return out.str();
}

std::string CrossBinaryExpressionComparator::renderJsonReport(
    const std::vector<NamedExpressionComparison>& comparisons,
    size_t max_rows) const {
    std::ostringstream out;
    CrossBinaryComparisonSummary s = summarize(comparisons);
    std::map<std::string, size_t> solver_counts;
    std::map<std::string, size_t> backend_counts;
    for (const auto& c : comparisons) {
        const std::string solver_key = c.verification.solver_result.empty() ? "unspecified"
                                                                            : c.verification.solver_result;
        const std::string backend_key = c.verification.verifier_backend.empty() ? "unspecified"
                                                                                : c.verification.verifier_backend;
        solver_counts[solver_key]++;
        backend_counts[backend_key]++;
    }
    size_t rows = (max_rows == 0) ? comparisons.size() : std::min(max_rows, comparisons.size());
    bool truncated = rows < comparisons.size();

    out << "{";
    out << "\"summary\":{"
        << "\"total\":" << s.total << ","
        << "\"equivalent\":" << s.equivalent << ","
        << "\"different\":" << s.different << ","
        << "\"unknown\":" << s.unknown << ","
        << "\"missing_lhs\":" << s.missing_lhs << ","
        << "\"missing_rhs\":" << s.missing_rhs << ","
        << "\"coverage_total\":" << s.coverage_total << ","
        << "\"coverage_equivalent\":" << s.coverage_equivalent << ","
        << "\"coverage_different\":" << s.coverage_different << ","
        << "\"coverage_unknown\":" << s.coverage_unknown << ","
        << "\"coverage_unsupported\":" << s.coverage_unsupported << ","
        << "\"coverage_uncovered\":" << s.coverage_uncovered
        << "},";
    out << "\"solver_result_counts\":{";
    bool first = true;
    for (const auto& kv : solver_counts) {
        if (!first) out << ",";
        first = false;
        out << "\"" << jsonEscape(kv.first) << "\":" << kv.second;
    }
    out << "},";
    out << "\"verifier_backend_counts\":{";
    first = true;
    for (const auto& kv : backend_counts) {
        if (!first) out << ",";
        first = false;
        out << "\"" << jsonEscape(kv.first) << "\":" << kv.second;
    }
    out << "},";
    out << "\"unknown_reason_counts\":" << renderCountsJson(s.unknown_reason_counts) << ",";
    out << "\"unknown_reason_class_counts\":" << renderCountsJson(s.unknown_reason_class_counts) << ",";
    out << "\"unknown_solver_result_counts\":" << renderCountsJson(s.unknown_solver_result_counts) << ",";
    out << "\"unknown_lhs_attribute_kind_counts\":" << renderCountsJson(s.unknown_lhs_attribute_kind_counts) << ",";
    out << "\"unknown_rhs_attribute_kind_counts\":" << renderCountsJson(s.unknown_rhs_attribute_kind_counts) << ",";
    out << "\"unsupported_opcode_counts\":" << renderCountsJson(s.unsupported_opcode_counts) << ",";
    out << "\"unsupported_isolation_kind_counts\":" << renderCountsJson(s.unsupported_isolation_kind_counts) << ",";
    out << "\"unsupported_rows\":" << s.unsupported_row_count << ",";
    out << "\"unsupported_isolated_rows\":" << s.unsupported_isolated_rows << ",";
    out << "\"unsupported_segments\":" << s.unsupported_segment_count << ",";
    out << "\"normalized_equal\":" << s.normalized_equal << ",";
    out << "\"normalization_kind_counts\":" << renderCountsJson(s.normalization_kind_counts) << ",";
    out << "\"truncated\":" << (truncated ? "true" : "false") << ",";
    out << "\"comparisons\":[";
    for (size_t i = 0; i < rows; ++i) {
        if (i != 0) out << ",";
        const auto& c = comparisons[i];
        out << "{"
            << "\"name\":\"" << jsonEscape(c.name) << "\","
            << "\"tag\":\"" << jsonEscape(DwarfUtils::tagToString(c.tag)) << "\","
            << "\"lhs_present\":" << (c.lhs_present ? "true" : "false") << ","
            << "\"rhs_present\":" << (c.rhs_present ? "true" : "false") << ","
            << "\"lhs_offset\":" << c.lhs_offset << ","
            << "\"rhs_offset\":" << c.rhs_offset << ","
            << "\"verdict\":\"" << verdictToString(c.verification.verdict) << "\","
            << "\"verifier_backend\":\"" << jsonEscape(c.verification.verifier_backend) << "\","
            << "\"solver_result\":\"" << jsonEscape(c.verification.solver_result) << "\","
            << "\"reason\":\"" << jsonEscape(c.verification.reason) << "\","
            << "\"reason_class\":\"" << jsonEscape(c.verification.reason_class) << "\","
            << "\"isolation_kind\":\"" << jsonEscape(c.verification.isolation_kind) << "\","
            << "\"normalization_applied\":" << (c.verification.normalization_applied ? "true" : "false") << ","
            << "\"normalization_equal\":" << (c.verification.normalization_equal ? "true" : "false") << ","
            << "\"normalization_kind\":\"" << jsonEscape(c.verification.normalization_kind) << "\","
            << "\"lhs_normalized_summary\":\"" << jsonEscape(c.verification.lhs_normalized_summary) << "\","
            << "\"rhs_normalized_summary\":\"" << jsonEscape(c.verification.rhs_normalized_summary) << "\","
            << "\"lhs_attribute_kind\":\"" << jsonEscape(c.verification.lhs_attribute_kind) << "\","
            << "\"rhs_attribute_kind\":\"" << jsonEscape(c.verification.rhs_attribute_kind) << "\","
            << "\"lhs_attribute_detail\":\"" << jsonEscape(c.verification.lhs_attribute_detail) << "\","
            << "\"rhs_attribute_detail\":\"" << jsonEscape(c.verification.rhs_attribute_detail) << "\","
            << "\"lhs_unsupported_opcode\":"
            << (c.verification.lhs_unsupported_opcode ? std::to_string(*c.verification.lhs_unsupported_opcode) : "null") << ","
            << "\"rhs_unsupported_opcode\":"
            << (c.verification.rhs_unsupported_opcode ? std::to_string(*c.verification.rhs_unsupported_opcode) : "null") << ","
            << "\"lhs_unsupported_vendor_extension\":"
            << (c.verification.lhs_unsupported_vendor_extension ? "true" : "false") << ","
            << "\"rhs_unsupported_vendor_extension\":"
            << (c.verification.rhs_unsupported_vendor_extension ? "true" : "false") << ","
            << "\"counterexample_model\":\"" << jsonEscape(c.verification.counterexample_model) << "\","
            << "\"counterexample_witness\":\"" << jsonEscape(c.verification.counterexample_witness) << "\","
            << "\"range_aware\":" << (c.range_aware ? "true" : "false") << ","
            << "\"coverage_total\":" << c.coverage_total << ","
            << "\"coverage_equivalent\":" << c.coverage_equivalent << ","
            << "\"coverage_different\":" << c.coverage_different << ","
            << "\"coverage_unknown\":" << c.coverage_unknown << ","
            << "\"coverage_unsupported\":" << c.coverage_unsupported << ","
            << "\"coverage_uncovered\":" << c.coverage_uncovered << ","
            << "\"unsupported_segments\":" << c.unsupported_segment_count << ","
            << "\"relocation_issues\":[";
        for (size_t r = 0; r < c.relocation_issues.size(); ++r) {
            if (r != 0) out << ",";
            out << "\"" << jsonEscape(c.relocation_issues[r]) << "\"";
        }
        out << "],"
            << "\"range_segments\":[";
        for (size_t sg = 0; sg < c.range_segments.size(); ++sg) {
            if (sg != 0) out << ",";
            const auto& segment = c.range_segments[sg];
            out << "{"
                << "\"start\":" << segment.start << ","
                << "\"end\":" << segment.end << ","
                << "\"lhs_present\":" << (segment.lhs_present ? "true" : "false") << ","
                << "\"rhs_present\":" << (segment.rhs_present ? "true" : "false") << ","
                << "\"verdict\":\"" << verdictToString(segment.verdict) << "\","
                << "\"reason\":\"" << jsonEscape(segment.reason) << "\","
                << "\"reason_class\":\"" << jsonEscape(segment.reason_class) << "\","
                << "\"isolation_kind\":\"" << jsonEscape(segment.isolation_kind) << "\","
                << "\"solver_result\":\"" << jsonEscape(segment.solver_result) << "\","
                << "\"diagnosis_origin\":\"" << jsonEscape(segment.diagnosis_origin) << "\","
                << "\"lhs_unsupported_opcode\":"
                << (segment.lhs_unsupported_opcode ? std::to_string(*segment.lhs_unsupported_opcode) : "null") << ","
                << "\"rhs_unsupported_opcode\":"
                << (segment.rhs_unsupported_opcode ? std::to_string(*segment.rhs_unsupported_opcode) : "null") << ","
                << "\"lhs_unsupported_vendor_extension\":"
                << (segment.lhs_unsupported_vendor_extension ? "true" : "false") << ","
                << "\"rhs_unsupported_vendor_extension\":"
                << (segment.rhs_unsupported_vendor_extension ? "true" : "false")
                << "}";
        }
        out << "]"
            << "}";
    }
    out << "]";
    out << "}";
    return out.str();
}

CrossBinaryGateResult CrossBinaryExpressionComparator::evaluateGate(
    const std::vector<NamedExpressionComparison>& comparisons,
    const CrossBinaryGateOptions& opts) const {
    CrossBinaryGateResult out;
    out.summary = summarize(comparisons);
    auto updateSignature = [&out]() {
        out.signature = std::string("pass=") + (out.pass ? "1" : "0") +
                        ";trigger=" + out.trigger +
                        ";detail=" + out.trigger_detail;
    };
    auto failGate = [&out, &updateSignature](std::string reason, std::string trigger, std::string detail) {
        out.pass = false;
        out.reason = std::move(reason);
        out.trigger = std::move(trigger);
        out.trigger_detail = std::move(detail);
        updateSignature();
    };

    if (out.summary.different > opts.max_different) {
        failGate("different count exceeds limit",
                 "max_different",
                 std::to_string(out.summary.different) + "/" + std::to_string(opts.max_different));
        return out;
    }
    if (out.summary.unknown > opts.max_unknown) {
        failGate("unknown count exceeds limit",
                 "max_unknown",
                 std::to_string(out.summary.unknown) + "/" + std::to_string(opts.max_unknown));
        return out;
    }
    if (out.summary.missing_lhs > opts.max_missing_lhs) {
        failGate("missing_lhs count exceeds limit",
                 "max_missing_lhs",
                 std::to_string(out.summary.missing_lhs) + "/" + std::to_string(opts.max_missing_lhs));
        return out;
    }
    if (out.summary.missing_rhs > opts.max_missing_rhs) {
        failGate("missing_rhs count exceeds limit",
                 "max_missing_rhs",
                 std::to_string(out.summary.missing_rhs) + "/" + std::to_string(opts.max_missing_rhs));
        return out;
    }
    if (opts.fail_on_unknown && out.summary.unknown != 0) {
        failGate("unknown results are disallowed",
                 "fail_on_unknown",
                 std::to_string(out.summary.unknown));
        return out;
    }
    if (opts.fail_on_missing && (out.summary.missing_lhs != 0 || out.summary.missing_rhs != 0)) {
        failGate("missing symbols are disallowed",
                 "fail_on_missing",
                 std::to_string(out.summary.missing_lhs) + "+" + std::to_string(out.summary.missing_rhs));
        return out;
    }
    if (!opts.fail_on_solver_results.empty()) {
        for (const auto& c : comparisons) {
            const std::string solver = c.verification.solver_result.empty() ? "unspecified"
                                                                             : c.verification.solver_result;
            if (opts.fail_on_solver_results.count(solver) != 0) {
                failGate("disallowed solver_result encountered: " + solver,
                         "fail_on_solver_result",
                         solver);
                return out;
            }
        }
    }
    if (!opts.fail_on_verifier_backends.empty()) {
        for (const auto& c : comparisons) {
            const std::string backend = c.verification.verifier_backend.empty() ? "unspecified"
                                                                                 : c.verification.verifier_backend;
            if (opts.fail_on_verifier_backends.count(backend) != 0) {
                failGate("disallowed verifier_backend encountered: " + backend,
                         "fail_on_verifier_backend",
                         backend);
                return out;
            }
        }
    }
    if (out.summary.coverage_total != 0) {
        const double eq_ratio = static_cast<double>(out.summary.coverage_equivalent) /
                                static_cast<double>(out.summary.coverage_total);
        const double diff_ratio = static_cast<double>(out.summary.coverage_different) /
                                  static_cast<double>(out.summary.coverage_total);
        if (eq_ratio + 1e-12 < opts.min_equivalent_coverage) {
            failGate("equivalent coverage ratio below minimum",
                     "min_equivalent_coverage",
                     std::to_string(eq_ratio) + "/" + std::to_string(opts.min_equivalent_coverage));
            return out;
        }
        if (diff_ratio - 1e-12 > opts.max_different_coverage) {
            failGate("different coverage ratio exceeds maximum",
                     "max_different_coverage",
                     std::to_string(diff_ratio) + "/" + std::to_string(opts.max_different_coverage));
            return out;
        }
        if (opts.fail_on_uncovered && out.summary.coverage_uncovered != 0) {
            failGate("uncovered range-aware segments are disallowed",
                     "fail_on_uncovered",
                     std::to_string(out.summary.coverage_uncovered));
            return out;
        }
    }

    out.pass = true;
    out.reason = "gate passed";
    out.trigger = "none";
    out.trigger_detail.clear();
    updateSignature();
    return out;
}

} // namespace dwarf
