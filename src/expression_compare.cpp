#include "expression_compare.hpp"
#include "attribute_parser.hpp"
#include "dwarf_utils.hpp"

#include <algorithm>
#include <cmath>
#include <map>
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

std::vector<LocationAttributeValue::LocationEntry> normalizeLocationEntries(
    const std::vector<LocationAttributeValue::LocationEntry>& in,
    bool normalize) {
    std::vector<LocationAttributeValue::LocationEntry> out;
    out.reserve(in.size());
    for (const auto& e : in) {
        if (e.is_default) continue;
        if (e.end <= e.start) continue;
        if (e.expression.empty()) continue;
        out.push_back(e);
    }
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        if (a.start != b.start) return a.start < b.start;
        if (a.end != b.end) return a.end < b.end;
        return a.expression < b.expression;
    });

    if (!normalize || out.empty()) return out;

    std::vector<LocationAttributeValue::LocationEntry> merged;
    merged.push_back(out.front());
    for (size_t i = 1; i < out.size(); ++i) {
        auto& prev = merged.back();
        const auto& cur = out[i];
        if (prev.end >= cur.start && prev.expression == cur.expression) {
            if (cur.end > prev.end) prev.end = cur.end;
            continue;
        }
        merged.push_back(cur);
    }
    return merged;
}

const std::vector<uint8_t>* expressionForRange(
    const std::vector<LocationAttributeValue::LocationEntry>& entries,
    uint64_t start,
    uint64_t end) {
    for (const auto& e : entries) {
        if (start >= e.start && end <= e.end) return &e.expression;
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
    if (opts.enable_range_aware_location_compare &&
        lhs_loc && rhs_loc &&
        lhs_loc->getLocationType() == LocationAttributeValue::LocationType::LIST &&
        rhs_loc->getLocationType() == LocationAttributeValue::LocationType::LIST) {
        out.range_aware = true;
        auto lhs_entries = normalizeLocationEntries(lhs_loc->getEntries(),
                                                    opts.enable_location_semantic_normalization);
        auto rhs_entries = normalizeLocationEntries(rhs_loc->getEntries(),
                                                    opts.enable_location_semantic_normalization);

        std::vector<uint64_t> points;
        points.reserve(lhs_entries.size() * 2 + rhs_entries.size() * 2);
        for (const auto& e : lhs_entries) {
            points.push_back(e.start);
            points.push_back(e.end);
        }
        for (const auto& e : rhs_entries) {
            points.push_back(e.start);
            points.push_back(e.end);
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
            auto vr = verifier.verifyWithContexts(
                *lhs_expr, lhs_ctx, lhs_pc, opts.lhs_registers,
                *rhs_expr, rhs_ctx, rhs_pc, opts.rhs_registers,
                opts.verification_options);
            ++comparable_segments;
            segment.verdict = vr.verdict;
            segment.reason = vr.reason;
            if (vr.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT) {
                out.coverage_equivalent += width;
            } else if (vr.verdict == ExpressionVerificationResult::Verdict::DIFFERENT) {
                out.coverage_different += width;
                overall = ExpressionVerificationResult::Verdict::DIFFERENT;
            } else {
                out.coverage_unknown += width;
                if (overall == ExpressionVerificationResult::Verdict::EQUIVALENT) {
                    overall = ExpressionVerificationResult::Verdict::UNKNOWN;
                }
            }
            out.range_segments.push_back(std::move(segment));
        }

        out.verification.verdict = overall;
        if (comparable_segments == 0) {
            out.verification.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
            out.verification.reason = "range-aware compare found no segments with expressions on both sides";
        } else {
            std::ostringstream rs;
            rs << "range-aware coverage eq=" << out.coverage_equivalent
               << " diff=" << out.coverage_different
               << " unk=" << out.coverage_unknown
               << " uncovered=" << out.coverage_uncovered
               << " total=" << out.coverage_total;
            out.verification.reason = rs.str();
        }
        return out;
    }

    out.verification = verifier.verifyDIEAttributeExpressions(
        lhs_die, lhs_ctx, opts.lhs_registers,
        rhs_die, rhs_ctx, opts.rhs_registers,
        lhs_sel, rhs_sel, opts.verification_options);
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
        s.coverage_total += c.coverage_total;
        s.coverage_equivalent += c.coverage_equivalent;
        s.coverage_different += c.coverage_different;
        s.coverage_unknown += c.coverage_unknown;
        s.coverage_uncovered += c.coverage_uncovered;
        switch (c.verification.verdict) {
            case ExpressionVerificationResult::Verdict::EQUIVALENT:
                ++s.equivalent;
                break;
            case ExpressionVerificationResult::Verdict::DIFFERENT:
                ++s.different;
                break;
            case ExpressionVerificationResult::Verdict::UNKNOWN:
                ++s.unknown;
                break;
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

    out << "name|tag|lhs_present|rhs_present|lhs_offset|rhs_offset|verdict|verifier_backend|solver_result|reason|lhs_unsupported_opcode|rhs_unsupported_opcode|lhs_unsupported_vendor_extension|rhs_unsupported_vendor_extension|coverage_total|coverage_eq|coverage_diff|coverage_unknown|coverage_uncovered|reloc_issues\n";
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
            << (c.verification.lhs_unsupported_opcode ? DwarfUtils::formatAddress(*c.verification.lhs_unsupported_opcode, false) : "") << "|"
            << (c.verification.rhs_unsupported_opcode ? DwarfUtils::formatAddress(*c.verification.rhs_unsupported_opcode, false) : "") << "|"
            << (c.verification.lhs_unsupported_vendor_extension ? "1" : "0") << "|"
            << (c.verification.rhs_unsupported_vendor_extension ? "1" : "0") << "|"
            << c.coverage_total << "|"
            << c.coverage_equivalent << "|"
            << c.coverage_different << "|"
            << c.coverage_unknown << "|"
            << c.coverage_uncovered << "|"
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
            << "\"coverage_uncovered\":" << c.coverage_uncovered << ","
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
                << "\"reason\":\"" << jsonEscape(segment.reason) << "\""
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
