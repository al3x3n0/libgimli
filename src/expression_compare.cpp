#include "expression_compare.hpp"
#include "dwarf_utils.hpp"

#include <algorithm>
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

    out.verification = verifier.verifyDIEAttributeExpressions(
        lhs_die, opts.lhs_context, opts.lhs_registers,
        rhs_die, opts.rhs_context, opts.rhs_registers,
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
    out << "summary total=" << s.total
        << " equivalent=" << s.equivalent
        << " different=" << s.different
        << " unknown=" << s.unknown
        << " missing_lhs=" << s.missing_lhs
        << " missing_rhs=" << s.missing_rhs
        << "\n";

    out << "name|tag|lhs_present|rhs_present|lhs_offset|rhs_offset|verdict|reason\n";
    size_t rows = (max_rows == 0) ? comparisons.size() : std::min(max_rows, comparisons.size());
    for (size_t i = 0; i < rows; ++i) {
        const auto& c = comparisons[i];
        out << c.name << "|"
            << DwarfUtils::tagToString(c.tag) << "|"
            << (c.lhs_present ? "1" : "0") << "|"
            << (c.rhs_present ? "1" : "0") << "|"
            << c.lhs_offset << "|"
            << c.rhs_offset << "|"
            << verdictToString(c.verification.verdict) << "|"
            << c.verification.reason << "\n";
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
    size_t rows = (max_rows == 0) ? comparisons.size() : std::min(max_rows, comparisons.size());
    bool truncated = rows < comparisons.size();

    out << "{";
    out << "\"summary\":{"
        << "\"total\":" << s.total << ","
        << "\"equivalent\":" << s.equivalent << ","
        << "\"different\":" << s.different << ","
        << "\"unknown\":" << s.unknown << ","
        << "\"missing_lhs\":" << s.missing_lhs << ","
        << "\"missing_rhs\":" << s.missing_rhs
        << "},";
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
            << "\"reason\":\"" << jsonEscape(c.verification.reason) << "\""
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

    if (out.summary.different > opts.max_different) {
        out.pass = false;
        out.reason = "different count exceeds limit";
        return out;
    }
    if (out.summary.unknown > opts.max_unknown) {
        out.pass = false;
        out.reason = "unknown count exceeds limit";
        return out;
    }
    if (out.summary.missing_lhs > opts.max_missing_lhs) {
        out.pass = false;
        out.reason = "missing_lhs count exceeds limit";
        return out;
    }
    if (out.summary.missing_rhs > opts.max_missing_rhs) {
        out.pass = false;
        out.reason = "missing_rhs count exceeds limit";
        return out;
    }
    if (opts.fail_on_unknown && out.summary.unknown != 0) {
        out.pass = false;
        out.reason = "unknown results are disallowed";
        return out;
    }
    if (opts.fail_on_missing && (out.summary.missing_lhs != 0 || out.summary.missing_rhs != 0)) {
        out.pass = false;
        out.reason = "missing symbols are disallowed";
        return out;
    }

    out.pass = true;
    out.reason = "gate passed";
    return out;
}

} // namespace dwarf
