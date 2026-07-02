#include "dwarf_compare.hpp"

#include "bolt_remap.hpp"
#include "dwarf_utils.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <deque>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace dwarf {

namespace {

const char* verdictToString(ExpressionVerificationResult::Verdict v) {
    switch (v) {
        case ExpressionVerificationResult::Verdict::EQUIVALENT: return "EQUIVALENT";
        case ExpressionVerificationResult::Verdict::DIFFERENT: return "DIFFERENT";
        case ExpressionVerificationResult::Verdict::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

std::string jsonEscape(const std::string& s) {
    std::ostringstream out;
    for (char ch : s) {
        switch (ch) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
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

struct VerifyFeatures {
    bool section_reloc = false;
    bool loc_normalize = false;
    bool range_aware = false;
    std::string normalization_policy = "symbolic_canonical";
};

static std::string normalizationPolicyName(const CrossBinaryCompareOptions& opts) {
    if (opts.normalization_policy == CrossBinaryCompareOptions::NormalizationPolicy::SYMBOLIC_CANONICAL ||
        opts.enable_location_semantic_normalization) {
        return "symbolic_canonical";
    }
    return "off";
}

VerifyFeatures toVerifyFeatures(const CrossBinaryCompareOptions& opts) {
    VerifyFeatures out;
    out.section_reloc = opts.enable_relocation_checks;
    out.loc_normalize = opts.enable_location_semantic_normalization;
    out.range_aware = opts.enable_range_aware_location_compare;
    out.normalization_policy = normalizationPolicyName(opts);
    return out;
}

std::string renderVerifyFeaturesText(const VerifyFeatures& features) {
    std::ostringstream oss;
    bool first = true;
    if (features.section_reloc) {
        oss << "section-reloc";
        first = false;
    }
    if (features.loc_normalize) {
        if (!first) oss << ",";
        oss << "loc-normalize";
        first = false;
    }
    if (features.range_aware) {
        if (!first) oss << ",";
        oss << "range-aware";
        first = false;
    }
    if (first) oss << "none";
    return oss.str();
}

std::string renderVerifyFeaturesJson(const VerifyFeatures& features) {
    std::ostringstream oss;
    oss << "[";
    bool first = true;
    if (features.section_reloc) {
        oss << "\"section-reloc\"";
        first = false;
    }
    if (features.loc_normalize) {
        if (!first) oss << ",";
        oss << "\"loc-normalize\"";
        first = false;
    }
    if (features.range_aware) {
        if (!first) oss << ",";
        oss << "\"range-aware\"";
    }
    oss << "]";
    return oss.str();
}

template <typename Container>
std::string renderStringSetJson(const Container& c) {
    std::ostringstream oss;
    oss << "[";
    bool first = true;
    for (const auto& v : c) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << jsonEscape(v) << "\"";
    }
    oss << "]";
    return oss.str();
}

template <typename Container>
std::string renderStringSetText(const Container& c) {
    std::ostringstream oss;
    bool first = true;
    for (const auto& v : c) {
        if (!first) oss << ",";
        first = false;
        oss << v;
    }
    return oss.str();
}

template <typename MapT>
std::string renderCountsJson(const MapT& counts) {
    std::ostringstream oss;
    oss << "{";
    bool first = true;
    for (const auto& kv : counts) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << jsonEscape(kv.first) << "\":" << kv.second;
    }
    oss << "}";
    return oss.str();
}

template <typename MapT>
std::string renderCountsText(const MapT& counts) {
    std::ostringstream oss;
    bool first = true;
    for (const auto& kv : counts) {
        if (!first) oss << ",";
        first = false;
        oss << kv.first << ":" << kv.second;
    }
    return oss.str();
}

std::map<std::string, size_t> buildExprSolverCounts(const std::vector<NamedExpressionComparison>& comparisons) {
    std::map<std::string, size_t> counts;
    for (const auto& c : comparisons) {
        const std::string key = c.verification.solver_result.empty() ? "unspecified" : c.verification.solver_result;
        counts[key]++;
    }
    return counts;
}

std::map<std::string, size_t> buildExprBackendCounts(const std::vector<NamedExpressionComparison>& comparisons) {
    std::map<std::string, size_t> counts;
    for (const auto& c : comparisons) {
        const std::string key = c.verification.verifier_backend.empty() ? "unspecified" : c.verification.verifier_backend;
        counts[key]++;
    }
    return counts;
}

void sortExprComparisons(std::vector<NamedExpressionComparison>& comparisons, const std::string& sort_mode) {
    if (sort_mode == "verdict") {
        auto rank = [](ExpressionVerificationResult::Verdict v) {
            switch (v) {
                case ExpressionVerificationResult::Verdict::DIFFERENT: return 0;
                case ExpressionVerificationResult::Verdict::UNKNOWN: return 1;
                case ExpressionVerificationResult::Verdict::EQUIVALENT: return 2;
            }
            return 3;
        };
        std::sort(comparisons.begin(), comparisons.end(),
                  [&](const NamedExpressionComparison& a, const NamedExpressionComparison& b) {
                      int ar = rank(a.verification.verdict);
                      int br = rank(b.verification.verdict);
                      if (ar != br) return ar < br;
                      return a.name < b.name;
                  });
        return;
    }
    std::sort(comparisons.begin(), comparisons.end(),
              [](const NamedExpressionComparison& a, const NamedExpressionComparison& b) {
                  return a.name < b.name;
              });
}

std::string exprTagName(DwarfTag tag) {
    return tag == DwarfTag::DW_TAG_subprogram ? "subprogram" : "variable";
}

std::string exprAttrName(DwarfAttribute attr) {
    return attr == DwarfAttribute::DW_AT_frame_base ? "frame_base" : "location";
}

} // namespace

CompareExprExecutionResult executeCompareExpr(const DwarfParser& lhs,
                                              const DwarfParser& rhs,
                                              CompareOutputFormat format,
                                              const CompareExprReportOptions& options) {
    CompareExprExecutionResult result;

    CrossBinaryExpressionComparator cmp;
    if (!options.selected_names.empty()) {
        std::set<std::string> seen;
        for (const auto& name : options.selected_names) {
            if (!seen.insert(name).second) continue;
            result.comparisons.push_back(cmp.compareNamedInParsers(lhs, rhs, name, options.compare_options));
        }
    } else {
        result.comparisons = cmp.compareParsersByName(lhs, rhs, options.compare_options);
    }

    if (!options.verdict_filters.empty()) {
        std::vector<NamedExpressionComparison> filtered;
        filtered.reserve(result.comparisons.size());
        for (const auto& row : result.comparisons) {
            if (options.verdict_filters.count(row.verification.verdict) != 0) filtered.push_back(row);
        }
        result.comparisons.swap(filtered);
    }

    if (!options.name_prefix_filter.empty() || !options.name_contains_filter.empty()) {
        std::vector<NamedExpressionComparison> filtered;
        filtered.reserve(result.comparisons.size());
        for (const auto& row : result.comparisons) {
            bool ok = true;
            if (!options.name_prefix_filter.empty()) ok = row.name.rfind(options.name_prefix_filter, 0) == 0;
            if (ok && !options.name_contains_filter.empty()) {
                ok = row.name.find(options.name_contains_filter) != std::string::npos;
            }
            if (ok) filtered.push_back(row);
        }
        result.comparisons.swap(filtered);
    }

    sortExprComparisons(result.comparisons, options.sort_mode);
    result.gate = cmp.evaluateGate(result.comparisons, options.gate_options);

    std::string gate_trigger = "none";
    std::string gate_trigger_detail;
    const auto& gate = result.gate;
    if (gate.summary.different > options.gate_options.max_different) {
        gate_trigger = "max_different";
        gate_trigger_detail = std::to_string(gate.summary.different) + "/" + std::to_string(options.gate_options.max_different);
    } else if (gate.summary.unknown > options.gate_options.max_unknown) {
        gate_trigger = "max_unknown";
        gate_trigger_detail = std::to_string(gate.summary.unknown) + "/" + std::to_string(options.gate_options.max_unknown);
    } else if (gate.summary.missing_lhs > options.gate_options.max_missing_lhs) {
        gate_trigger = "max_missing_lhs";
        gate_trigger_detail = std::to_string(gate.summary.missing_lhs) + "/" + std::to_string(options.gate_options.max_missing_lhs);
    } else if (gate.summary.missing_rhs > options.gate_options.max_missing_rhs) {
        gate_trigger = "max_missing_rhs";
        gate_trigger_detail = std::to_string(gate.summary.missing_rhs) + "/" + std::to_string(options.gate_options.max_missing_rhs);
    } else if (options.gate_options.fail_on_unknown && gate.summary.unknown != 0) {
        gate_trigger = "fail_on_unknown";
        gate_trigger_detail = std::to_string(gate.summary.unknown);
    } else if (options.gate_options.fail_on_missing &&
               (gate.summary.missing_lhs != 0 || gate.summary.missing_rhs != 0)) {
        gate_trigger = "fail_on_missing";
        gate_trigger_detail = "lhs:" + std::to_string(gate.summary.missing_lhs) +
                              ",rhs:" + std::to_string(gate.summary.missing_rhs);
    } else if (!options.gate_options.fail_on_solver_results.empty()) {
        for (const auto& c : result.comparisons) {
            const std::string solver = c.verification.solver_result.empty() ? "unspecified" : c.verification.solver_result;
            if (options.gate_options.fail_on_solver_results.count(solver) != 0) {
                gate_trigger = "fail_on_solver_result";
                gate_trigger_detail = solver;
                break;
            }
        }
    } else if (!options.gate_options.fail_on_verifier_backends.empty()) {
        for (const auto& c : result.comparisons) {
            const std::string backend = c.verification.verifier_backend.empty() ? "unspecified" : c.verification.verifier_backend;
            if (options.gate_options.fail_on_verifier_backends.count(backend) != 0) {
                gate_trigger = "fail_on_verifier_backend";
                gate_trigger_detail = backend;
                break;
            }
        }
    } else if (gate.summary.coverage_total != 0) {
        const double eq_ratio = static_cast<double>(gate.summary.coverage_equivalent) /
                                static_cast<double>(gate.summary.coverage_total);
        const double diff_ratio = static_cast<double>(gate.summary.coverage_different) /
                                  static_cast<double>(gate.summary.coverage_total);
        if (eq_ratio + 1e-12 < options.gate_options.min_equivalent_coverage) {
            gate_trigger = "min_equivalent_coverage";
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(6) << eq_ratio << "/" << options.gate_options.min_equivalent_coverage;
            gate_trigger_detail = oss.str();
        } else if (diff_ratio - 1e-12 > options.gate_options.max_different_coverage) {
            gate_trigger = "max_different_coverage";
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(6) << diff_ratio << "/" << options.gate_options.max_different_coverage;
            gate_trigger_detail = oss.str();
        } else if (options.gate_options.fail_on_uncovered && gate.summary.coverage_uncovered != 0) {
            gate_trigger = "fail_on_uncovered";
            gate_trigger_detail = std::to_string(gate.summary.coverage_uncovered);
        }
    }

    result.gate_signature = "pass=" + std::string(gate.pass ? "1" : "0") +
                            ";trigger=" + gate_trigger +
                            ";detail=" + gate_trigger_detail;

    const auto verify_features = toVerifyFeatures(options.compare_options);
    const auto solver_counts = buildExprSolverCounts(result.comparisons);
    const auto backend_counts = buildExprBackendCounts(result.comparisons);

    if (options.emit_solver_summary_only) {
        std::ostringstream oss;
        if (format == CompareOutputFormat::JSON) {
            oss << "{"
                << "\"schema_version\":1,"
                << "\"solver_summary\":{"
                << "\"total\":" << result.comparisons.size() << ","
                << "\"solver_result_counts\":" << renderCountsJson(solver_counts) << ","
                << "\"verifier_backend_counts\":" << renderCountsJson(backend_counts)
                << "}"
                << "}\n";
        } else {
            oss << "solver_summary total=" << result.comparisons.size()
                << " solver_result_counts=" << renderCountsText(solver_counts)
                << " verifier_backend_counts=" << renderCountsText(backend_counts)
                << "\n";
        }
        result.report = oss.str();
        return result;
    }

    if (options.emit_profile_only) {
        std::ostringstream oss;
        if (format == CompareOutputFormat::JSON) {
            oss << "{"
                << "\"profile\":{"
                << "\"verify_profile\":\"" << jsonEscape(options.verify_profile) << "\","
                << "\"normalization_policy\":\"" << jsonEscape(normalizationPolicyName(options.compare_options)) << "\","
                << "\"vendor_op_profile\":\""
                << jsonEscape(vendorExpressionProfileName(options.compare_options.vendor_expression_profile)) << "\","
                << "\"verify_features\":" << renderVerifyFeaturesJson(verify_features) << ","
                << "\"solver_timeout_ms\":" << options.compare_options.verification_options.solver_timeout_ms << ","
                << "\"gate_profile\":\"" << jsonEscape(options.gate_profile) << "\","
                << "\"fail_on_solver_results\":" << renderStringSetJson(options.gate_options.fail_on_solver_results) << ","
                << "\"fail_on_verifier_backends\":" << renderStringSetJson(options.gate_options.fail_on_verifier_backends) << ","
                << "\"solver_result_counts\":" << renderCountsJson(solver_counts) << ","
                << "\"verifier_backend_counts\":" << renderCountsJson(backend_counts) << ","
                << "\"gate\":{"
                << "\"pass\":" << (gate.pass ? "true" : "false") << ","
                << "\"reason\":\"" << jsonEscape(gate.reason) << "\","
                << "\"trigger\":\"" << jsonEscape(gate_trigger) << "\","
                << "\"trigger_detail\":\"" << jsonEscape(gate_trigger_detail) << "\","
                << "\"signature\":\"" << jsonEscape(result.gate_signature) << "\""
                << "}"
                << "}"
                << "}\n";
        } else {
            oss << "verify_profile=" << options.verify_profile
                << " vendor_op_profile=" << vendorExpressionProfileName(options.compare_options.vendor_expression_profile)
                << " normalization_policy=" << normalizationPolicyName(options.compare_options)
                << " verify_features=" << renderVerifyFeaturesText(verify_features)
                << " solver_timeout_ms=" << options.compare_options.verification_options.solver_timeout_ms
                << " gate_profile=" << options.gate_profile
                << " fail_on_solver_results=" << renderStringSetText(options.gate_options.fail_on_solver_results)
                << " fail_on_verifier_backends=" << renderStringSetText(options.gate_options.fail_on_verifier_backends)
                << " solver_result_counts=" << renderCountsText(solver_counts)
                << " verifier_backend_counts=" << renderCountsText(backend_counts)
                << " gate_pass=" << (gate.pass ? "1" : "0")
                << " gate_reason=" << gate.reason
                << " gate_trigger=" << gate_trigger
                << " gate_signature=" << result.gate_signature
                << "\n";
        }
        result.report = oss.str();
        return result;
    }

    if (options.summary_only) {
        const auto summary = cmp.summarize(result.comparisons);
        std::ostringstream oss;
        if (format == CompareOutputFormat::JSON) {
            if (options.schema_version == 1) {
                oss << "{"
                    << "\"schema_version\":1,"
                    << "\"options\":{"
                    << "\"tag\":\"" << exprTagName(options.compare_options.tag) << "\","
                    << "\"attr\":\"" << exprAttrName(options.compare_options.attribute) << "\","
                    << "\"key_mode\":\"" << (options.compare_options.key_mode == CompareKeyMode::LINKAGE_OR_NAME ? "linkage" : "name") << "\","
                    << "\"include_missing\":" << (options.compare_options.include_missing ? "true" : "false") << ","
                    << "\"strict_attr_present\":" << (options.compare_options.require_attribute_on_both ? "true" : "false") << ","
                    << "\"reloc_check\":" << (options.compare_options.enable_relocation_checks ? "true" : "false") << ","
                    << "\"normalize_loc\":" << (options.compare_options.enable_location_semantic_normalization ? "true" : "false") << ","
                    << "\"normalization_policy\":\"" << jsonEscape(normalizationPolicyName(options.compare_options)) << "\","
                    << "\"range_aware\":" << (options.compare_options.enable_range_aware_location_compare ? "true" : "false") << ","
                    << "\"vendor_op_profile\":\""
                    << jsonEscape(vendorExpressionProfileName(options.compare_options.vendor_expression_profile)) << "\","
                    << "\"verify_profile\":\"" << jsonEscape(options.verify_profile) << "\","
                    << "\"verify_features\":" << renderVerifyFeaturesJson(verify_features) << ","
                    << "\"solver_timeout_ms\":" << options.compare_options.verification_options.solver_timeout_ms << ","
                    << "\"gate_profile\":\"" << jsonEscape(options.gate_profile) << "\","
                    << "\"fail_on_solver_results\":" << renderStringSetJson(options.gate_options.fail_on_solver_results) << ","
                    << "\"fail_on_verifier_backends\":" << renderStringSetJson(options.gate_options.fail_on_verifier_backends) << ","
                    << "\"summary_only\":true,"
                    << "\"max_rows\":" << options.max_rows << ","
                    << "\"report_only\":" << (options.report_only ? "true" : "false")
                    << "},"
                    << "\"report\":{"
                    << "\"summary\":{"
                    << "\"total\":" << summary.total << ","
                    << "\"equivalent\":" << summary.equivalent << ","
                    << "\"different\":" << summary.different << ","
                    << "\"unknown\":" << summary.unknown << ","
                    << "\"missing_lhs\":" << summary.missing_lhs << ","
                    << "\"missing_rhs\":" << summary.missing_rhs << ","
                    << "\"solver_result_counts\":" << renderCountsJson(solver_counts) << ","
                    << "\"verifier_backend_counts\":" << renderCountsJson(backend_counts) << ","
                    << "\"unknown_reason_counts\":" << renderCountsJson(summary.unknown_reason_counts) << ","
                    << "\"unknown_solver_result_counts\":" << renderCountsJson(summary.unknown_solver_result_counts) << ","
                    << "\"unknown_lhs_attribute_kind_counts\":" << renderCountsJson(summary.unknown_lhs_attribute_kind_counts) << ","
                    << "\"unknown_rhs_attribute_kind_counts\":" << renderCountsJson(summary.unknown_rhs_attribute_kind_counts) << ","
                    << "\"normalization_kind_counts\":" << renderCountsJson(summary.normalization_kind_counts) << ","
                    << "\"normalization_groups\":{"
                    << "\"rows\":{"
                    << "\"attempted\":" << summary.normalization_row_attempted << ","
                    << "\"equal\":" << summary.normalization_row_equal << ","
                    << "\"changed\":" << summary.normalization_row_changed << ","
                    << "\"lhs_rule_class_counts\":" << renderCountsJson(summary.normalization_row_lhs_rule_class_counts) << ","
                    << "\"rhs_rule_class_counts\":" << renderCountsJson(summary.normalization_row_rhs_rule_class_counts)
                    << "},"
                    << "\"segments\":{"
                    << "\"attempted\":" << summary.normalization_segment_attempted << ","
                    << "\"equal\":" << summary.normalization_segment_equal << ","
                    << "\"changed\":" << summary.normalization_segment_changed << ","
                    << "\"lhs_rule_class_counts\":" << renderCountsJson(summary.normalization_segment_lhs_rule_class_counts) << ","
                    << "\"rhs_rule_class_counts\":" << renderCountsJson(summary.normalization_segment_rhs_rule_class_counts)
                    << "}"
                    << "}"
                    << "}"
                    << "},"
                    << "\"gate\":{"
                    << "\"pass\":" << (gate.pass ? "true" : "false") << ","
                    << "\"reason\":\"" << jsonEscape(gate.reason) << "\","
                    << "\"trigger\":\"" << jsonEscape(gate_trigger) << "\","
                    << "\"trigger_detail\":\"" << jsonEscape(gate_trigger_detail) << "\","
                    << "\"signature\":\"" << jsonEscape(result.gate_signature) << "\""
                    << "}"
                    << "}\n";
            } else {
                oss << "{"
                    << "\"summary\":{"
                    << "\"total\":" << summary.total << ","
                    << "\"equivalent\":" << summary.equivalent << ","
                    << "\"different\":" << summary.different << ","
                    << "\"unknown\":" << summary.unknown << ","
                    << "\"missing_lhs\":" << summary.missing_lhs << ","
                    << "\"missing_rhs\":" << summary.missing_rhs
                    << "}"
                    << "}\n";
            }
        } else {
            oss << "summary total=" << summary.total
                << " equivalent=" << summary.equivalent
                << " different=" << summary.different
                << " unknown=" << summary.unknown
                << " missing_lhs=" << summary.missing_lhs
                << " missing_rhs=" << summary.missing_rhs
                << " normalization_groups="
                << "rows_attempted=" << summary.normalization_row_attempted
                << ",rows_equal=" << summary.normalization_row_equal
                << ",rows_changed=" << summary.normalization_row_changed
                << ",rows_lhs_rule_class_counts=" << renderCountsText(summary.normalization_row_lhs_rule_class_counts)
                << ",rows_rhs_rule_class_counts=" << renderCountsText(summary.normalization_row_rhs_rule_class_counts)
                << ",segments_attempted=" << summary.normalization_segment_attempted
                << ",segments_equal=" << summary.normalization_segment_equal
                << ",segments_changed=" << summary.normalization_segment_changed
                << ",segments_lhs_rule_class_counts=" << renderCountsText(summary.normalization_segment_lhs_rule_class_counts)
                << ",segments_rhs_rule_class_counts=" << renderCountsText(summary.normalization_segment_rhs_rule_class_counts)
                << "\n";
        }
        result.report = oss.str();
        return result;
    }

    if (format == CompareOutputFormat::JSON) {
        std::ostringstream oss;
        if (options.schema_version == 0) {
            oss << cmp.renderJsonReport(result.comparisons, options.max_rows) << "\n";
        } else {
            oss << "{"
                << "\"schema_version\":1,"
                << "\"options\":{"
                << "\"tag\":\"" << exprTagName(options.compare_options.tag) << "\","
                << "\"attr\":\"" << exprAttrName(options.compare_options.attribute) << "\","
                << "\"key_mode\":\"" << (options.compare_options.key_mode == CompareKeyMode::LINKAGE_OR_NAME ? "linkage" : "name") << "\","
                << "\"include_missing\":" << (options.compare_options.include_missing ? "true" : "false") << ","
                << "\"strict_attr_present\":" << (options.compare_options.require_attribute_on_both ? "true" : "false") << ","
                << "\"reloc_check\":" << (options.compare_options.enable_relocation_checks ? "true" : "false") << ","
                << "\"normalize_loc\":" << (options.compare_options.enable_location_semantic_normalization ? "true" : "false") << ","
                << "\"normalization_policy\":\"" << jsonEscape(normalizationPolicyName(options.compare_options)) << "\","
                << "\"range_aware\":" << (options.compare_options.enable_range_aware_location_compare ? "true" : "false") << ","
                << "\"vendor_op_profile\":\""
                << jsonEscape(vendorExpressionProfileName(options.compare_options.vendor_expression_profile)) << "\","
                << "\"verify_profile\":\"" << jsonEscape(options.verify_profile) << "\","
                << "\"verify_features\":" << renderVerifyFeaturesJson(verify_features) << ","
                << "\"solver_timeout_ms\":" << options.compare_options.verification_options.solver_timeout_ms << ","
                << "\"gate_profile\":\"" << jsonEscape(options.gate_profile) << "\","
                << "\"fail_on_solver_results\":" << renderStringSetJson(options.gate_options.fail_on_solver_results) << ","
                << "\"fail_on_verifier_backends\":" << renderStringSetJson(options.gate_options.fail_on_verifier_backends) << ","
                << "\"summary_only\":" << (options.summary_only ? "true" : "false") << ","
                << "\"max_rows\":" << options.max_rows << ","
                << "\"report_only\":" << (options.report_only ? "true" : "false")
                << "},"
                << "\"report\":" << cmp.renderJsonReport(result.comparisons, options.max_rows) << ","
                << "\"gate\":{"
                << "\"pass\":" << (gate.pass ? "true" : "false") << ","
                << "\"reason\":\"" << jsonEscape(gate.reason) << "\","
                << "\"trigger\":\"" << jsonEscape(gate_trigger) << "\","
                << "\"trigger_detail\":\"" << jsonEscape(gate_trigger_detail) << "\","
                << "\"signature\":\"" << jsonEscape(result.gate_signature) << "\""
                << "}"
                << "}\n";
        }
        result.report = oss.str();
        return result;
    }

    result.report = cmp.renderTextReport(result.comparisons, options.max_rows);
    return result;
}

bool resolveFunctionPC(const DwarfParser& parser,
                       const std::string& name,
                       uint64_t& out_pc,
                       std::string& error) {
    auto matches = parser.findDIEsByNameFast(name);
    if (matches.empty()) matches = parser.findDIEsByName(name);
    for (const auto& die : matches) {
        if (!die || die->getTag() != DwarfTag::DW_TAG_subprogram) continue;
        auto low_pc = die->getAttribute(DwarfAttribute::DW_AT_low_pc);
        if (!low_pc) continue;
        if (auto a = std::dynamic_pointer_cast<AddressAttributeValue>(low_pc)) {
            out_pc = a->getAddress();
            return true;
        }
        if (auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(low_pc)) {
            out_pc = u->getValue();
            return true;
        }
    }
    error = "cannot resolve function '" + name + "'";
    return false;
}

CompareCFIExecutionResult executeCompareCFI(const DwarfParser& lhs,
                                            const DwarfParser& rhs,
                                            CompareOutputFormat format,
                                            const CompareCFIReportOptions& options) {
    CompareCFIExecutionResult result;
    SymbolicCFIVerifier verifier;

    // Auto-detect a BOLT remap from the two ELFs when either carries BOLT markers.
    // It is reused both for remapped-pc FDE pairing and for reconciling absolute
    // address constants inside CFA expressions (opts.expression_options.address_remap).
    BoltAddressRemap cfi_remap;
    if (elfHasBoltMarkers(lhs.getELF()) || elfHasBoltMarkers(rhs.getELF())) {
        cfi_remap = buildBoltRemapFromElves(lhs.getELF(), rhs.getELF());
    }
    SymbolicCFICompareOptions cfi_opts = options.compare_options;
    if (!cfi_remap.empty()) {
        cfi_opts.expression_options.address_remap =
            [&cfi_remap](uint64_t old_addr) { return cfi_remap.apply(old_addr); };
    }

    auto resolveFuncName = [](const DwarfParser& p, uint64_t pc) -> std::string {
        auto die = p.getFunctionAt(pc);
        if (!die) return "";
        std::string n = die->getName();
        if (!n.empty()) return n;
        auto ln_attr = die->getAttribute(DwarfAttribute::DW_AT_linkage_name);
        auto ln = std::dynamic_pointer_cast<StringAttributeValue>(ln_attr);
        return ln ? ln->getValue() : "";
    };

    auto appendRowFromInterval = [&](CFICompareRow& row,
                                     const SymbolicCFIIntervalComparisonResult& r) {
        row.verdict = r.verdict;
        row.reason = r.reason;
        row.points_checked = r.points_checked;
        row.has_mismatch_pc = r.has_mismatch_relative_pc;
        row.mismatch_pc = r.mismatch_relative_pc;
        row.verifier_backend = r.verifier_backend;
        row.solver_result = r.solver_result;
        row.counterexample_model = r.counterexample_model;
        row.counterexample_witness = r.counterexample_witness;
    };

    auto appendRowFromState = [&](CFICompareRow& row,
                                  const SymbolicCFIStateComparisonResult& r) {
        row.verdict = r.verdict;
        row.reason = r.reason;
        row.points_checked = 1;
        row.lhs_summary = r.lhs_summary;
        row.rhs_summary = r.rhs_summary;
        row.verifier_backend = r.verifier_backend;
        row.solver_result = r.solver_result;
        row.counterexample_model = r.counterexample_model;
        row.counterexample_witness = r.counterexample_witness;
    };

    if (options.all_fdes) {
        const auto& lf = lhs.getCFIParser().getFDEs();
        const auto& rf = rhs.getCFIParser().getFDEs();
        std::vector<std::pair<size_t, size_t>> pairs;

        if (options.pair_by == "index") {
            const size_t n = std::min(lf.size(), rf.size());
            if (lf.size() > rf.size()) result.missing_rhs = lf.size() - rf.size();
            else if (rf.size() > lf.size()) result.missing_lhs = rf.size() - lf.size();
            for (size_t i = 0; i < n; ++i) pairs.emplace_back(i, i);
        } else if (options.pair_by == "start-pc") {
            std::map<uint64_t, std::deque<size_t>> lhs_by_pc;
            std::map<uint64_t, std::deque<size_t>> rhs_by_pc;
            for (size_t i = 0; i < lf.size(); ++i) lhs_by_pc[lf[i]->initial_location].push_back(i);
            for (size_t i = 0; i < rf.size(); ++i) rhs_by_pc[rf[i]->initial_location].push_back(i);
            std::set<uint64_t> keys;
            for (const auto& kv : lhs_by_pc) keys.insert(kv.first);
            for (const auto& kv : rhs_by_pc) keys.insert(kv.first);
            for (uint64_t k : keys) {
                auto& lq = lhs_by_pc[k];
                auto& rq = rhs_by_pc[k];
                const size_t n = std::min(lq.size(), rq.size());
                for (size_t i = 0; i < n; ++i) {
                    pairs.emplace_back(lq.front(), rq.front());
                    lq.pop_front();
                    rq.pop_front();
                }
                result.missing_rhs += lq.size();
                result.missing_lhs += rq.size();
            }
        } else if (options.pair_by == "remapped-pc") {
            // BOLT-aware pairing: match an lhs FDE to the rhs FDE whose start PC
            // equals the remapped lhs start (remap(lhs_start) == rhs_start), using
            // the remap auto-detected above. FDEs the remap does not cover fall
            // back to matching by the function name covering each FDE start.
            const BoltAddressRemap& remap = cfi_remap;

            std::map<uint64_t, std::deque<size_t>> rhs_by_pc;
            for (size_t i = 0; i < rf.size(); ++i) rhs_by_pc[rf[i]->initial_location].push_back(i);
            std::map<std::string, std::deque<size_t>> rhs_by_func;
            for (size_t i = 0; i < rf.size(); ++i) {
                std::string n = resolveFuncName(rhs, rf[i]->initial_location);
                if (!n.empty()) rhs_by_func[n].push_back(i);
            }

            std::vector<bool> rhs_used(rf.size(), false);
            auto takeFirstUnused = [&](std::deque<size_t>& q) -> long {
                while (!q.empty()) {
                    size_t idx = q.front();
                    q.pop_front();
                    if (!rhs_used[idx]) return static_cast<long>(idx);
                }
                return -1;
            };

            for (size_t i = 0; i < lf.size(); ++i) {
                uint64_t target = remap.apply(lf[i]->initial_location)
                                      .value_or(lf[i]->initial_location);
                long ridx = -1;
                auto it = rhs_by_pc.find(target);
                if (it != rhs_by_pc.end()) ridx = takeFirstUnused(it->second);
                if (ridx < 0) {
                    std::string n = resolveFuncName(lhs, lf[i]->initial_location);
                    auto fit = n.empty() ? rhs_by_func.end() : rhs_by_func.find(n);
                    if (fit != rhs_by_func.end()) ridx = takeFirstUnused(fit->second);
                }
                if (ridx >= 0) {
                    rhs_used[static_cast<size_t>(ridx)] = true;
                    pairs.emplace_back(i, static_cast<size_t>(ridx));
                } else {
                    ++result.missing_rhs;
                }
            }
            for (size_t i = 0; i < rf.size(); ++i) {
                if (!rhs_used[i]) ++result.missing_lhs;
            }
        } else {
            using Key = std::pair<uint64_t, uint64_t>;
            std::map<Key, std::deque<size_t>> lhs_by_range;
            std::map<Key, std::deque<size_t>> rhs_by_range;
            for (size_t i = 0; i < lf.size(); ++i) lhs_by_range[{lf[i]->initial_location, lf[i]->address_range}].push_back(i);
            for (size_t i = 0; i < rf.size(); ++i) rhs_by_range[{rf[i]->initial_location, rf[i]->address_range}].push_back(i);
            std::set<Key> keys;
            for (const auto& kv : lhs_by_range) keys.insert(kv.first);
            for (const auto& kv : rhs_by_range) keys.insert(kv.first);
            for (const auto& k : keys) {
                auto& lq = lhs_by_range[k];
                auto& rq = rhs_by_range[k];
                const size_t n = std::min(lq.size(), rq.size());
                for (size_t i = 0; i < n; ++i) {
                    pairs.emplace_back(lq.front(), rq.front());
                    lq.pop_front();
                    rq.pop_front();
                }
                result.missing_rhs += lq.size();
                result.missing_lhs += rq.size();
            }
        }

        for (const auto& p : pairs) {
            auto r = verifier.compareFDEByIndex(lhs.getCFIParser(), p.first, rhs.getCFIParser(), p.second, cfi_opts);
            CFICompareRow row;
            row.lhs_index = p.first;
            row.rhs_index = p.second;
            appendRowFromInterval(row, r);
            if (p.first < lf.size()) {
                row.has_lhs_fde = true;
                row.lhs_initial_location = lf[p.first]->initial_location;
                row.lhs_address_range = lf[p.first]->address_range;
                row.lhs_function_name = resolveFuncName(lhs, row.lhs_initial_location);
            }
            if (p.second < rf.size()) {
                row.has_rhs_fde = true;
                row.rhs_initial_location = rf[p.second]->initial_location;
                row.rhs_address_range = rf[p.second]->address_range;
                row.rhs_function_name = resolveFuncName(rhs, row.rhs_initial_location);
            }
            result.rows.push_back(std::move(row));
        }
    } else if (options.pc_mode) {
        auto r = verifier.compareParsersAtPC(lhs.getCFIParser(), rhs.getCFIParser(), options.lhs_pc, options.rhs_pc, cfi_opts);
        CFICompareRow row;
        appendRowFromState(row, r);
        auto lf = lhs.getCFIParser().findFDE(options.lhs_pc);
        auto rf = rhs.getCFIParser().findFDE(options.rhs_pc);
        if (lf) {
            row.has_lhs_fde = true;
            row.lhs_initial_location = lf->initial_location;
            row.lhs_address_range = lf->address_range;
            row.lhs_function_name = resolveFuncName(lhs, row.lhs_initial_location);
        }
        if (rf) {
            row.has_rhs_fde = true;
            row.rhs_initial_location = rf->initial_location;
            row.rhs_address_range = rf->address_range;
            row.rhs_function_name = resolveFuncName(rhs, row.rhs_initial_location);
        }
        result.rows.push_back(std::move(row));
    } else {
        auto r = verifier.compareFDEByIndex(lhs.getCFIParser(), options.lhs_fde_index, rhs.getCFIParser(), options.rhs_fde_index, cfi_opts);
        CFICompareRow row;
        row.lhs_index = options.lhs_fde_index;
        row.rhs_index = options.rhs_fde_index;
        appendRowFromInterval(row, r);
        const auto& lf = lhs.getCFIParser().getFDEs();
        const auto& rf = rhs.getCFIParser().getFDEs();
        if (options.lhs_fde_index < lf.size()) {
            row.has_lhs_fde = true;
            row.lhs_initial_location = lf[options.lhs_fde_index]->initial_location;
            row.lhs_address_range = lf[options.lhs_fde_index]->address_range;
            row.lhs_function_name = resolveFuncName(lhs, row.lhs_initial_location);
        }
        if (options.rhs_fde_index < rf.size()) {
            row.has_rhs_fde = true;
            row.rhs_initial_location = rf[options.rhs_fde_index]->initial_location;
            row.rhs_address_range = rf[options.rhs_fde_index]->address_range;
            row.rhs_function_name = resolveFuncName(rhs, row.rhs_initial_location);
        }
        result.rows.push_back(std::move(row));
    }

    for (const auto& row : result.rows) {
        if (row.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT) ++result.equivalent;
        if (row.verdict == ExpressionVerificationResult::Verdict::DIFFERENT) ++result.different;
        if (row.verdict == ExpressionVerificationResult::Verdict::UNKNOWN) ++result.unknown;
        const std::string solver_key = row.solver_result.empty() ? "unspecified" : row.solver_result;
        const std::string backend_key = row.verifier_backend.empty() ? "unspecified" : row.verifier_backend;
        result.solver_result_counts[solver_key]++;
        result.verifier_backend_counts[backend_key]++;
    }

    bool show_equivalent_rows = options.show_equivalent_rows;
    if (options.all_fdes && !options.equivalent_filter_explicit) show_equivalent_rows = false;

    std::vector<size_t> visible_rows;
    visible_rows.reserve(result.rows.size());
    for (size_t i = 0; i < result.rows.size(); ++i) {
        if (options.only_different_rows && result.rows[i].verdict != ExpressionVerificationResult::Verdict::DIFFERENT) continue;
        if (options.only_unknown_rows && result.rows[i].verdict != ExpressionVerificationResult::Verdict::UNKNOWN) continue;
        if (!show_equivalent_rows && result.rows[i].verdict == ExpressionVerificationResult::Verdict::EQUIVALENT) continue;
        visible_rows.push_back(i);
    }

    auto verdict_rank = [&](ExpressionVerificationResult::Verdict v) {
        switch (v) {
            case ExpressionVerificationResult::Verdict::DIFFERENT: return 0;
            case ExpressionVerificationResult::Verdict::UNKNOWN: return 1;
            case ExpressionVerificationResult::Verdict::EQUIVALENT: return 2;
        }
        return 3;
    };
    std::sort(visible_rows.begin(), visible_rows.end(), [&](size_t a, size_t b) {
        const auto& lhs_row = result.rows[a];
        const auto& rhs_row = result.rows[b];
        if (options.sort_mode == "rhs-index") {
            if (lhs_row.rhs_index != rhs_row.rhs_index) return lhs_row.rhs_index < rhs_row.rhs_index;
            return lhs_row.lhs_index < rhs_row.lhs_index;
        }
        if (options.sort_mode == "lhs-pc") {
            if (lhs_row.lhs_initial_location != rhs_row.lhs_initial_location) return lhs_row.lhs_initial_location < rhs_row.lhs_initial_location;
            return lhs_row.rhs_initial_location < rhs_row.rhs_initial_location;
        }
        if (options.sort_mode == "rhs-pc") {
            if (lhs_row.rhs_initial_location != rhs_row.rhs_initial_location) return lhs_row.rhs_initial_location < rhs_row.rhs_initial_location;
            return lhs_row.lhs_initial_location < rhs_row.lhs_initial_location;
        }
        if (options.sort_mode == "verdict") {
            const int ar = verdict_rank(lhs_row.verdict);
            const int br = verdict_rank(rhs_row.verdict);
            if (ar != br) return ar < br;
        }
        if (lhs_row.lhs_index != rhs_row.lhs_index) return lhs_row.lhs_index < rhs_row.lhs_index;
        return lhs_row.rhs_index < rhs_row.rhs_index;
    });

    result.gate_pass = true;
    result.gate_reason.clear();
    result.gate_trigger = "none";
    result.gate_trigger_detail.clear();

    if (result.different > options.max_different) {
        result.gate_pass = false;
        result.gate_trigger = "max_different";
        result.gate_trigger_detail = std::to_string(result.different) + "/" + std::to_string(options.max_different);
        result.gate_reason = "different=" + std::to_string(result.different) + " exceeds max_different=" + std::to_string(options.max_different);
    } else if (result.unknown > options.max_unknown) {
        result.gate_pass = false;
        result.gate_trigger = "max_unknown";
        result.gate_trigger_detail = std::to_string(result.unknown) + "/" + std::to_string(options.max_unknown);
        result.gate_reason = "unknown=" + std::to_string(result.unknown) + " exceeds max_unknown=" + std::to_string(options.max_unknown);
    } else if (result.missing_lhs > options.max_missing_lhs) {
        result.gate_pass = false;
        result.gate_trigger = "max_missing_lhs";
        result.gate_trigger_detail = std::to_string(result.missing_lhs) + "/" + std::to_string(options.max_missing_lhs);
        result.gate_reason = "missing_lhs=" + std::to_string(result.missing_lhs) + " exceeds max_missing_lhs=" + std::to_string(options.max_missing_lhs);
    } else if (result.missing_rhs > options.max_missing_rhs) {
        result.gate_pass = false;
        result.gate_trigger = "max_missing_rhs";
        result.gate_trigger_detail = std::to_string(result.missing_rhs) + "/" + std::to_string(options.max_missing_rhs);
        result.gate_reason = "missing_rhs=" + std::to_string(result.missing_rhs) + " exceeds max_missing_rhs=" + std::to_string(options.max_missing_rhs);
    } else if (options.fail_on_unknown && result.unknown > 0) {
        result.gate_pass = false;
        result.gate_trigger = "fail_on_unknown";
        result.gate_trigger_detail = std::to_string(result.unknown);
        result.gate_reason = "unknown result not allowed by fail-on-unknown";
    } else if (options.fail_on_missing && (result.missing_lhs > 0 || result.missing_rhs > 0)) {
        result.gate_pass = false;
        result.gate_trigger = "fail_on_missing";
        result.gate_trigger_detail = "lhs:" + std::to_string(result.missing_lhs) + ",rhs:" + std::to_string(result.missing_rhs);
        result.gate_reason = "missing FDE pairs not allowed by fail-on-missing";
    } else if (!options.fail_on_solver_results.empty()) {
        for (const auto& row : result.rows) {
            const std::string solver = row.solver_result.empty() ? "unspecified" : row.solver_result;
            if (options.fail_on_solver_results.count(solver) != 0) {
                result.gate_pass = false;
                result.gate_trigger = "fail_on_solver_result";
                result.gate_trigger_detail = solver;
                result.gate_reason = "solver_result=" + solver + " disallowed by fail-on-solver-result";
                break;
            }
        }
    } else if (!options.fail_on_verifier_backends.empty()) {
        for (const auto& row : result.rows) {
            const std::string backend = row.verifier_backend.empty() ? "unspecified" : row.verifier_backend;
            if (options.fail_on_verifier_backends.count(backend) != 0) {
                result.gate_pass = false;
                result.gate_trigger = "fail_on_verifier_backend";
                result.gate_trigger_detail = backend;
                result.gate_reason = "verifier_backend=" + backend + " disallowed by fail-on-verifier-backend";
                break;
            }
        }
    }
    if (result.gate_pass && result.gate_reason.empty()) result.gate_reason = "gate passed";
    result.gate_signature = "pass=" + std::string(result.gate_pass ? "1" : "0") +
                            ";trigger=" + result.gate_trigger +
                            ";detail=" + result.gate_trigger_detail;

    std::ostringstream out;
    const size_t shown = (options.max_rows == 0) ? visible_rows.size() : std::min(options.max_rows, visible_rows.size());
    if (options.emit_solver_summary_only) {
        if (format == CompareOutputFormat::JSON) {
            out << "{"
                << "\"schema_version\":" << options.schema_version << ","
                << "\"solver_summary\":{"
                << "\"total\":" << result.rows.size() << ","
                << "\"solver_result_counts\":" << renderCountsJson(result.solver_result_counts) << ","
                << "\"verifier_backend_counts\":" << renderCountsJson(result.verifier_backend_counts)
                << "}"
                << "}\n";
        } else {
            out << "solver_summary total=" << result.rows.size()
                << " solver_result_counts=" << renderCountsText(result.solver_result_counts)
                << " verifier_backend_counts=" << renderCountsText(result.verifier_backend_counts)
                << "\n";
        }
        result.report = out.str();
        return result;
    }

    if (options.emit_profile_only) {
        if (format == CompareOutputFormat::JSON) {
            out << "{"
                << "\"profile\":{"
                << "\"gate\":{"
                << "\"profile\":\"" << jsonEscape(options.gate_profile) << "\","
                << "\"solver_timeout_ms\":" << options.compare_options.expression_options.solver_timeout_ms << ","
                << "\"max_different\":" << options.max_different << ","
                << "\"max_unknown\":" << options.max_unknown << ","
                << "\"max_missing_lhs\":" << options.max_missing_lhs << ","
                << "\"max_missing_rhs\":" << options.max_missing_rhs << ","
                << "\"fail_on_unknown\":" << (options.fail_on_unknown ? "true" : "false") << ","
                << "\"fail_on_missing\":" << (options.fail_on_missing ? "true" : "false") << ","
                << "\"fail_on_solver_results\":" << renderStringSetJson(options.fail_on_solver_results) << ","
                << "\"fail_on_verifier_backends\":" << renderStringSetJson(options.fail_on_verifier_backends) << ","
                << "\"solver_result_counts\":" << renderCountsJson(result.solver_result_counts) << ","
                << "\"verifier_backend_counts\":" << renderCountsJson(result.verifier_backend_counts) << ","
                << "\"pass\":" << (result.gate_pass ? "true" : "false") << ","
                << "\"trigger\":\"" << jsonEscape(result.gate_trigger) << "\","
                << "\"trigger_detail\":\"" << jsonEscape(result.gate_trigger_detail) << "\","
                << "\"signature\":\"" << jsonEscape(result.gate_signature) << "\""
                << "}"
                << "}"
                << "}\n";
        } else {
            out << "gate_profile=" << options.gate_profile
                << " solver_timeout_ms=" << options.compare_options.expression_options.solver_timeout_ms
                << " thresholds=max_different:" << options.max_different
                << ",max_unknown:" << options.max_unknown
                << ",max_missing_lhs:" << options.max_missing_lhs
                << ",max_missing_rhs:" << options.max_missing_rhs
                << ",fail_on_unknown:" << (options.fail_on_unknown ? "1" : "0")
                << ",fail_on_missing:" << (options.fail_on_missing ? "1" : "0")
                << ",fail_on_solver_results:" << renderStringSetText(options.fail_on_solver_results)
                << ",fail_on_verifier_backends:" << renderStringSetText(options.fail_on_verifier_backends)
                << ",solver_result_counts:" << renderCountsText(result.solver_result_counts)
                << ",verifier_backend_counts:" << renderCountsText(result.verifier_backend_counts)
                << " gate_trigger=" << result.gate_trigger
                << " gate_signature=" << result.gate_signature
                << "\n";
        }
        result.report = out.str();
        return result;
    }

    if (options.emit_gate_signature_only) {
        if (format == CompareOutputFormat::JSON) {
            out << "{"
                << "\"gate\":{"
                << "\"signature\":\"" << jsonEscape(result.gate_signature) << "\""
                << "}"
                << "}\n";
        } else {
            out << "gate_signature=" << result.gate_signature << "\n";
        }
        result.report = out.str();
        return result;
    }

    const std::string mode = options.all_fdes ? "all-fdes" : (options.pc_mode ? (options.func_mode ? "func" : "pc") : "fde");
    if (format == CompareOutputFormat::JSON) {
        out << "{"
            << "\"schema_version\":" << options.schema_version << ","
            << "\"mode\":\"" << mode << "\","
            << "\"pair_by\":\"" << options.pair_by << "\","
            << "\"options\":{"
            << "\"all_fdes\":" << (options.all_fdes ? "true" : "false") << ","
            << "\"pc_mode\":" << (options.pc_mode ? "true" : "false") << ","
            << "\"func_mode\":" << (options.func_mode ? "true" : "false") << ","
            << "\"lhs_fde_index\":" << options.lhs_fde_index << ","
            << "\"rhs_fde_index\":" << options.rhs_fde_index << ","
            << "\"lhs_pc\":" << options.lhs_pc << ","
            << "\"rhs_pc\":" << options.rhs_pc << ","
            << "\"max_rows\":" << options.max_rows << ","
            << "\"sort\":\"" << options.sort_mode << "\","
            << "\"show_equivalent\":" << (show_equivalent_rows ? "true" : "false") << ","
            << "\"only_different\":" << (options.only_different_rows ? "true" : "false") << ","
            << "\"only_unknown\":" << (options.only_unknown_rows ? "true" : "false") << ","
            << "\"summary_only\":" << (options.summary_only ? "true" : "false") << ","
            << "\"report_only\":" << (options.report_only ? "true" : "false") << ","
            << "\"gate_profile\":\"" << jsonEscape(options.gate_profile) << "\","
            << "\"solver_timeout_ms\":" << options.compare_options.expression_options.solver_timeout_ms << ","
            << "\"max_different\":" << options.max_different << ","
            << "\"max_unknown\":" << options.max_unknown << ","
            << "\"max_missing_lhs\":" << options.max_missing_lhs << ","
            << "\"max_missing_rhs\":" << options.max_missing_rhs << ","
            << "\"fail_on_unknown\":" << (options.fail_on_unknown ? "true" : "false") << ","
            << "\"fail_on_missing\":" << (options.fail_on_missing ? "true" : "false") << ","
            << "\"fail_on_solver_results\":" << renderStringSetJson(options.fail_on_solver_results) << ","
            << "\"fail_on_verifier_backends\":" << renderStringSetJson(options.fail_on_verifier_backends)
            << "},"
            << "\"summary\":{"
            << "\"total\":" << result.rows.size() << ","
            << "\"equivalent\":" << result.equivalent << ","
            << "\"different\":" << result.different << ","
            << "\"unknown\":" << result.unknown << ","
            << "\"missing_lhs\":" << result.missing_lhs << ","
            << "\"missing_rhs\":" << result.missing_rhs << ","
            << "\"solver_result_counts\":" << renderCountsJson(result.solver_result_counts) << ","
            << "\"verifier_backend_counts\":" << renderCountsJson(result.verifier_backend_counts)
            << "},";
        if (!options.summary_only) {
            out << "\"rows\":[";
            for (size_t i = 0; i < shown; ++i) {
                if (i != 0) out << ",";
                const auto& row = result.rows[visible_rows[i]];
                out << "{"
                    << "\"lhs_index\":" << row.lhs_index << ","
                    << "\"rhs_index\":" << row.rhs_index << ","
                    << "\"verdict\":\"" << verdictToString(row.verdict) << "\","
                    << "\"verifier_backend\":\"" << jsonEscape(row.verifier_backend) << "\","
                    << "\"solver_result\":\"" << jsonEscape(row.solver_result) << "\","
                    << "\"reason\":\"" << jsonEscape(row.reason) << "\","
                    << "\"counterexample_model\":\"" << jsonEscape(row.counterexample_model) << "\","
                    << "\"counterexample_witness\":\"" << jsonEscape(row.counterexample_witness) << "\","
                    << "\"points_checked\":" << row.points_checked << ","
                    << "\"has_mismatch_relative_pc\":" << (row.has_mismatch_pc ? "true" : "false") << ","
                    << "\"mismatch_relative_pc\":" << row.mismatch_pc << ","
                    << "\"has_lhs_fde\":" << (row.has_lhs_fde ? "true" : "false") << ","
                    << "\"has_rhs_fde\":" << (row.has_rhs_fde ? "true" : "false") << ","
                    << "\"lhs_initial_location\":" << row.lhs_initial_location << ","
                    << "\"lhs_address_range\":" << row.lhs_address_range << ","
                    << "\"rhs_initial_location\":" << row.rhs_initial_location << ","
                    << "\"rhs_address_range\":" << row.rhs_address_range << ","
                    << "\"lhs_function_name\":\"" << jsonEscape(row.lhs_function_name) << "\","
                    << "\"rhs_function_name\":\"" << jsonEscape(row.rhs_function_name) << "\""
                    << "}";
            }
            out << "],";
        }
        out << "\"gate\":{"
            << "\"pass\":" << (result.gate_pass ? "true" : "false") << ","
            << "\"reason\":\"" << jsonEscape(result.gate_reason) << "\","
            << "\"trigger\":\"" << jsonEscape(result.gate_trigger) << "\","
            << "\"trigger_detail\":\"" << jsonEscape(result.gate_trigger_detail) << "\","
            << "\"signature\":\"" << jsonEscape(result.gate_signature) << "\""
            << "}"
            << "}\n";
        result.report = out.str();
        return result;
    }

    out << "mode=" << mode
        << " pair_by=" << options.pair_by
        << " sort=" << options.sort_mode
        << " total=" << result.rows.size()
        << " equivalent=" << result.equivalent
        << " different=" << result.different
        << " unknown=" << result.unknown
        << " missing_lhs=" << result.missing_lhs
        << " missing_rhs=" << result.missing_rhs
        << " solver_result_counts=" << renderCountsText(result.solver_result_counts)
        << " verifier_backend_counts=" << renderCountsText(result.verifier_backend_counts)
        << " gate_profile=" << options.gate_profile
        << " gate_pass=" << (result.gate_pass ? "1" : "0")
        << " gate_trigger=" << result.gate_trigger
        << " gate_signature=" << result.gate_signature
        << "\n";
    if (options.func_mode) {
        out << "lhs_func=" << options.lhs_func << " lhs_pc=0x" << std::hex << options.lhs_pc << std::dec << "\n";
        out << "rhs_func=" << options.rhs_func << " rhs_pc=0x" << std::hex << options.rhs_pc << std::dec << "\n";
    }
    if (!options.summary_only) {
        out << "lhs_index|rhs_index|lhs_initial_location|lhs_address_range|lhs_function_name|rhs_initial_location|rhs_address_range|rhs_function_name|verdict|verifier_backend|solver_result|points_checked|mismatch_relative_pc|reason\n";
        for (size_t i = 0; i < shown; ++i) {
            const auto& row = result.rows[visible_rows[i]];
            out << row.lhs_index << "|"
                << row.rhs_index << "|"
                << "0x" << std::hex << row.lhs_initial_location << "|"
                << "0x" << std::hex << row.lhs_address_range << "|"
                << row.lhs_function_name << "|"
                << "0x" << std::hex << row.rhs_initial_location << "|"
                << "0x" << std::hex << row.rhs_address_range << "|"
                << row.rhs_function_name << "|"
                << std::dec << verdictToString(row.verdict) << "|"
                << row.verifier_backend << "|"
                << row.solver_result << "|"
                << row.points_checked << "|";
            if (row.has_mismatch_pc) out << row.mismatch_pc;
            out << "|" << row.reason << "\n";
            if (!row.lhs_summary.empty()) out << "lhs=" << row.lhs_summary << "\n";
            if (!row.rhs_summary.empty()) out << "rhs=" << row.rhs_summary << "\n";
        }
        if (shown < visible_rows.size()) out << "... truncated " << (visible_rows.size() - shown) << " rows\n";
    }
    out << "gate_trigger=" << result.gate_trigger << "\n";
    out << "gate_trigger_detail=" << result.gate_trigger_detail << "\n";
    out << "gate_signature=" << result.gate_signature << "\n";
    if (!result.gate_pass) out << "gate_reason=" << result.gate_reason << "\n";
    result.report = out.str();
    return result;
}

} // namespace dwarf
