#include "cfi_symbolic.hpp"
#include "smt_verifier.hpp"

#include <algorithm>
#include <sstream>
#include <set>

namespace dwarf {

namespace {

std::string summarizeCFA(const CFADefinition& cfa) {
    std::ostringstream ss;
    if (cfa.type == CFA_Type::REGISTER_OFFSET) {
        ss << "cfa=reg" << cfa.reg_num << (cfa.offset >= 0 ? "+" : "") << cfa.offset;
    } else {
        ss << "cfa=expr(" << cfa.expression.size() << " bytes)";
    }
    return ss.str();
}

std::string summarizeRule(const RegisterRule& r) {
    std::ostringstream ss;
    ss << "type=" << static_cast<int>(r.type);
    switch (r.type) {
        case CFA_RegRule::OFFSET:
        case CFA_RegRule::VAL_OFFSET:
            ss << ",off=" << r.offset;
            break;
        case CFA_RegRule::REGISTER:
            ss << ",reg=" << r.reg_num;
            break;
        case CFA_RegRule::EXPRESSION:
        case CFA_RegRule::VAL_EXPRESSION:
            ss << ",expr_bytes=" << r.expression.size();
            break;
        default:
            break;
    }
    return ss.str();
}

std::string summarizeUnwind(const UnwindInfo& u) {
    std::ostringstream ss;
    ss << (u.valid ? "valid" : "invalid")
       << "," << summarizeCFA(u.cfa)
       << ",ra_reg=" << u.return_address_register
       << ",ra_sign_state=" << static_cast<unsigned>(u.aarch64_ra_sign_state)
       << ",regs={";
    bool first = true;
    for (const auto& kv : u.registers) {
        if (!first) ss << ";";
        first = false;
        ss << kv.first << ":" << summarizeRule(kv.second);
    }
    ss << "}";
    return ss.str();
}

void setVerifierMetadata(SymbolicCFIStateComparisonResult& out, const ExpressionVerificationResult& er) {
    out.verifier_backend = er.verifier_backend;
    out.solver_result = er.solver_result;
    out.counterexample_model = er.counterexample_model;
    out.counterexample_witness = er.counterexample_witness;
}

bool readU8(const std::vector<uint8_t>& ins, uint64_t& off, uint8_t& out) {
    if (off >= ins.size()) return false;
    out = ins[off++];
    return true;
}

bool readU16(const std::vector<uint8_t>& ins, uint64_t& off, uint16_t& out) {
    if (off + 2 > ins.size()) return false;
    out = static_cast<uint16_t>(ins[off]) |
          (static_cast<uint16_t>(ins[off + 1]) << 8);
    off += 2;
    return true;
}

bool readU32(const std::vector<uint8_t>& ins, uint64_t& off, uint32_t& out) {
    if (off + 4 > ins.size()) return false;
    out = static_cast<uint32_t>(ins[off]) |
          (static_cast<uint32_t>(ins[off + 1]) << 8) |
          (static_cast<uint32_t>(ins[off + 2]) << 16) |
          (static_cast<uint32_t>(ins[off + 3]) << 24);
    off += 4;
    return true;
}

bool readU64(const std::vector<uint8_t>& ins, uint64_t& off, uint64_t& out) {
    if (off + 8 > ins.size()) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) {
        out |= (static_cast<uint64_t>(ins[off + i]) << (8 * i));
    }
    off += 8;
    return true;
}

bool readULEB(const std::vector<uint8_t>& ins, uint64_t& off, uint64_t& out) {
    uint64_t result = 0;
    uint64_t shift = 0;
    while (off < ins.size()) {
        uint8_t byte = ins[off++];
        uint64_t bits = static_cast<uint64_t>(byte & 0x7f);
        if (shift > 63 || (shift == 63 && bits > 1)) return false;
        result |= (bits << shift);
        if ((byte & 0x80) == 0) {
            out = result;
            return true;
        }
        shift += 7;
    }
    return false;
}

bool readSLEB(const std::vector<uint8_t>& ins, uint64_t& off, int64_t& out) {
    int64_t result = 0;
    int shift = 0;
    uint8_t byte = 0;
    while (off < ins.size()) {
        byte = ins[off++];
        result |= (static_cast<int64_t>(byte & 0x7f) << shift);
        shift += 7;
        if ((byte & 0x80) == 0) {
            if (shift < 64 && (byte & 0x40)) result |= -(static_cast<int64_t>(1) << shift);
            out = result;
            return true;
        }
        if (shift >= 64) return false;
    }
    return false;
}

bool skipBlock(const std::vector<uint8_t>& ins, uint64_t& off) {
    uint64_t len = 0;
    if (!readULEB(ins, off, len)) return false;
    if (off + len > ins.size()) return false;
    off += len;
    return true;
}

std::vector<uint64_t> collectRelativeCutPoints(const FDE& fde) {
    std::set<uint64_t> rel;
    rel.insert(0);
    if (!fde.cie) return std::vector<uint64_t>(rel.begin(), rel.end());

    uint64_t loc = fde.initial_location;
    uint64_t off = 0;
    const auto& ins = fde.instructions;
    const CIE& cie = *fde.cie;

    auto add_loc = [&]() {
        if (loc < fde.initial_location) return;
        uint64_t d = loc - fde.initial_location;
        if (d < fde.address_range) rel.insert(d);
    };

    while (off < ins.size()) {
        uint8_t opcode = 0;
        if (!readU8(ins, off, opcode)) break;

        uint8_t primary = opcode & 0xc0;
        uint8_t operand = opcode & 0x3f;

        if (primary == 0x40) { // advance_loc
            loc += static_cast<uint64_t>(operand) * cie.code_alignment_factor;
            add_loc();
            continue;
        }
        if (primary == 0x80) { // offset
            uint64_t v = 0;
            if (!readULEB(ins, off, v)) break;
            continue;
        }
        if (primary == 0xc0) { // restore
            continue;
        }

        switch (opcode) {
            case 0x00: // nop
            case 0x0a: // remember_state
            case 0x0b: // restore_state
            case 0x2d: // aarch64_negate_ra_state / gnu_window_save
                break;
            case 0x1d: { // mips_advance_loc8
                uint64_t d = 0;
                if (!readU64(ins, off, d)) off = ins.size();
                else {
                    loc += d * cie.code_alignment_factor;
                    add_loc();
                }
                break;
            }
            case 0x01: { // set_loc
                if (cie.address_size == 8) {
                    uint64_t v = 0;
                    if (!readU64(ins, off, v)) off = ins.size();
                    else {
                        loc = v;
                        add_loc();
                    }
                } else if (cie.address_size == 4) {
                    uint32_t v = 0;
                    if (!readU32(ins, off, v)) off = ins.size();
                    else {
                        loc = v;
                        add_loc();
                    }
                } else {
                    off = ins.size();
                }
                break;
            }
            case 0x02: { // advance_loc1
                uint8_t d = 0;
                if (!readU8(ins, off, d)) off = ins.size();
                else {
                    loc += static_cast<uint64_t>(d) * cie.code_alignment_factor;
                    add_loc();
                }
                break;
            }
            case 0x03: { // advance_loc2
                uint16_t d = 0;
                if (!readU16(ins, off, d)) off = ins.size();
                else {
                    loc += static_cast<uint64_t>(d) * cie.code_alignment_factor;
                    add_loc();
                }
                break;
            }
            case 0x04: { // advance_loc4
                uint32_t d = 0;
                if (!readU32(ins, off, d)) off = ins.size();
                else {
                    loc += static_cast<uint64_t>(d) * cie.code_alignment_factor;
                    add_loc();
                }
                break;
            }
            case 0x05: // offset_extended
            case 0x06: // restore_extended
            case 0x07: // undefined
            case 0x08: // same_value
            case 0x0d: // def_cfa_register
            case 0x0e: // def_cfa_offset
            case 0x14: // val_offset
            case 0x2e: { // gnu_args_size
                uint64_t a = 0;
                if (!readULEB(ins, off, a)) off = ins.size();
                if (opcode == 0x05 || opcode == 0x14) {
                    uint64_t b = 0;
                    if (!readULEB(ins, off, b)) off = ins.size();
                }
                break;
            }
            case 0x09: // register
            case 0x0c: // def_cfa
            case 0x11: // offset_extended_sf
            case 0x12: // def_cfa_sf
            case 0x15: // val_offset_sf
            case 0x2f: { // gnu_negative_offset_extended
                uint64_t a = 0;
                int64_t b = 0;
                if (!readULEB(ins, off, a)) off = ins.size();
                if (opcode == 0x09 || opcode == 0x0c) {
                    uint64_t c = 0;
                    if (!readULEB(ins, off, c)) off = ins.size();
                } else {
                    if (!readSLEB(ins, off, b)) off = ins.size();
                }
                (void)b;
                break;
            }
            case 0x10: // expression
            case 0x16: { // val_expression
                uint64_t reg = 0;
                if (!readULEB(ins, off, reg)) {
                    off = ins.size();
                    break;
                }
                if (!skipBlock(ins, off)) off = ins.size();
                break;
            }
            case 0x13: { // def_cfa_offset_sf
                int64_t v = 0;
                if (!readSLEB(ins, off, v)) off = ins.size();
                break;
            }
            case 0x0f: { // def_cfa_expression (DWARF3+) or escape (DWARF2)
                if (cie.version < 3) {
                    uint64_t len = 0;
                    if (!readULEB(ins, off, len) || off + len > ins.size()) off = ins.size();
                    else off += len;
                } else {
                    if (!skipBlock(ins, off)) off = ins.size();
                }
                break;
            }
            default:
                off = ins.size();
                break;
        }
    }

    if (fde.address_range != 0) {
        rel.insert(fde.address_range - 1);
    }
    return std::vector<uint64_t>(rel.begin(), rel.end());
}

} // namespace

SymbolicCFIStateComparisonResult SymbolicCFIVerifier::compareUnwindInfo(
    const UnwindInfo& lhs,
    const UnwindInfo& rhs,
    uint64_t lhs_pc,
    uint64_t rhs_pc,
    const SymbolicCFICompareOptions& opts) const {
    SymbolicCFIStateComparisonResult out;
    out.lhs_summary = summarizeUnwind(lhs);
    out.rhs_summary = summarizeUnwind(rhs);

    if (!lhs.valid && !rhs.valid) {
        out.verdict = ExpressionVerificationResult::Verdict::EQUIVALENT;
        out.reason = "both unwind states invalid";
        out.verifier_backend = "structural";
        out.solver_result = "precheck_both_invalid";
        return out;
    }
    if (lhs.valid != rhs.valid) {
        out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
        out.reason = lhs.valid ? "rhs unwind invalid" : "lhs unwind invalid";
        out.verifier_backend = "structural";
        out.solver_result = lhs.valid ? "precheck_rhs_invalid" : "precheck_lhs_invalid";
        return out;
    }

    if (lhs.cfa.type != rhs.cfa.type) {
        out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
        out.reason = "CFA type mismatch";
        out.verifier_backend = "structural";
        out.solver_result = "precheck_cfa_type_mismatch";
        return out;
    }
    if (lhs.cfa.type == CFA_Type::REGISTER_OFFSET) {
        if (lhs.cfa.reg_num != rhs.cfa.reg_num || lhs.cfa.offset != rhs.cfa.offset) {
            out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
            out.reason = "CFA register/offset mismatch";
            out.verifier_backend = "structural";
            out.solver_result = "precheck_cfa_reg_offset_mismatch";
            return out;
        }
    } else {
        auto er = expr_verifier_.verifyWithContexts(
            lhs.cfa.expression, opts.lhs_context, lhs_pc, opts.lhs_registers,
            rhs.cfa.expression, opts.rhs_context, rhs_pc, opts.rhs_registers,
            opts.expression_options);
        if (er.verdict != ExpressionVerificationResult::Verdict::EQUIVALENT) {
            out.verdict = er.verdict;
            out.reason = "CFA expression mismatch: " + er.reason;
            setVerifierMetadata(out, er);
            return out;
        }
    }

    if (lhs.return_address_register != rhs.return_address_register) {
        out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
        out.reason = "return-address register mismatch";
        out.verifier_backend = "structural";
        out.solver_result = "precheck_ra_register_mismatch";
        return out;
    }
    if (lhs.aarch64_ra_sign_state != rhs.aarch64_ra_sign_state) {
        out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
        out.reason = "AArch64 RA sign-state mismatch";
        out.verifier_backend = "structural";
        out.solver_result = "precheck_aarch64_ra_sign_state_mismatch";
        return out;
    }

    std::set<uint64_t> regs;
    for (const auto& kv : lhs.registers) regs.insert(kv.first);
    for (const auto& kv : rhs.registers) regs.insert(kv.first);

    for (uint64_t reg : regs) {
        const RegisterRule* l = nullptr;
        const RegisterRule* r = nullptr;
        auto itl = lhs.registers.find(reg);
        if (itl != lhs.registers.end()) l = &itl->second;
        auto itr = rhs.registers.find(reg);
        if (itr != rhs.registers.end()) r = &itr->second;

        RegisterRule ldef;
        RegisterRule rdef;
        if (!l && opts.treat_missing_register_rule_as_undefined) {
            ldef.type = CFA_RegRule::UNDEFINED;
            l = &ldef;
        }
        if (!r && opts.treat_missing_register_rule_as_undefined) {
            rdef.type = CFA_RegRule::UNDEFINED;
            r = &rdef;
        }

        if (!l || !r) {
            out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
            out.reason = "register rule missing for reg " + std::to_string(reg);
            out.verifier_backend = "structural";
            out.solver_result = "precheck_register_rule_missing";
            return out;
        }
        if (l->type != r->type) {
            out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
            out.reason = "register rule type mismatch for reg " + std::to_string(reg);
            out.verifier_backend = "structural";
            out.solver_result = "precheck_register_rule_type_mismatch";
            return out;
        }

        switch (l->type) {
            case CFA_RegRule::OFFSET:
            case CFA_RegRule::VAL_OFFSET:
                if (l->offset != r->offset) {
                    out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
                    out.reason = "register offset mismatch for reg " + std::to_string(reg);
                    out.verifier_backend = "structural";
                    out.solver_result = "precheck_register_offset_mismatch";
                    return out;
                }
                break;
            case CFA_RegRule::REGISTER:
                if (l->reg_num != r->reg_num) {
                    out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
                    out.reason = "register indirection mismatch for reg " + std::to_string(reg);
                    out.verifier_backend = "structural";
                    out.solver_result = "precheck_register_indirection_mismatch";
                    return out;
                }
                break;
            case CFA_RegRule::EXPRESSION:
            case CFA_RegRule::VAL_EXPRESSION: {
                auto er = expr_verifier_.verifyWithContexts(
                    l->expression, opts.lhs_context, lhs_pc, opts.lhs_registers,
                    r->expression, opts.rhs_context, rhs_pc, opts.rhs_registers,
                    opts.expression_options);
                if (er.verdict != ExpressionVerificationResult::Verdict::EQUIVALENT) {
                    out.verdict = er.verdict;
                    out.reason = "register expression mismatch for reg " + std::to_string(reg) +
                                 ": " + er.reason;
                    setVerifierMetadata(out, er);
                    return out;
                }
                break;
            }
            case CFA_RegRule::UNDEFINED:
            case CFA_RegRule::SAME_VALUE:
            case CFA_RegRule::ARCHITECTURAL:
                break;
        }
    }

    out.verdict = ExpressionVerificationResult::Verdict::EQUIVALENT;
    out.reason = "symbolic unwind state equivalence established";
    out.verifier_backend = SMTExpressionVerifier::isAvailable()
        ? "structural+z3"
        : "structural+solver-unavailable";
    out.solver_result = "equivalent";
    return out;
}

SymbolicCFIStateComparisonResult SymbolicCFIVerifier::compareParsersAtPC(
    const CFIParser& lhs,
    const CFIParser& rhs,
    uint64_t lhs_pc,
    uint64_t rhs_pc,
    const SymbolicCFICompareOptions& opts) const {
    return compareUnwindInfo(lhs.getUnwindInfo(lhs_pc), rhs.getUnwindInfo(rhs_pc), lhs_pc, rhs_pc, opts);
}

SymbolicCFIIntervalComparisonResult SymbolicCFIVerifier::compareFDEByIndex(
    const CFIParser& lhs,
    size_t lhs_fde_index,
    const CFIParser& rhs,
    size_t rhs_fde_index,
    const SymbolicCFICompareOptions& opts) const {
    SymbolicCFIIntervalComparisonResult out;

    const auto& l_fdes = lhs.getFDEs();
    const auto& r_fdes = rhs.getFDEs();
    if (lhs_fde_index >= l_fdes.size() || rhs_fde_index >= r_fdes.size()) {
        out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
        out.reason = "FDE index out of range";
        out.verifier_backend = "structural";
        out.solver_result = "precheck_fde_index_out_of_range";
        return out;
    }

    const auto& lf = *l_fdes[lhs_fde_index];
    const auto& rf = *r_fdes[rhs_fde_index];
    if (!lf.cie || !rf.cie) {
        out.verdict = ExpressionVerificationResult::Verdict::UNKNOWN;
        out.reason = "missing CIE for FDE";
        out.verifier_backend = "structural";
        out.solver_result = "precheck_missing_cie";
        return out;
    }

    if (opts.require_same_range && lf.address_range != rf.address_range) {
        out.verdict = ExpressionVerificationResult::Verdict::DIFFERENT;
        out.reason = "FDE range mismatch";
        out.verifier_backend = "structural";
        out.solver_result = "precheck_fde_range_mismatch";
        return out;
    }

    uint64_t common_range = std::min(lf.address_range, rf.address_range);
    if (common_range == 0) {
        out.verdict = ExpressionVerificationResult::Verdict::EQUIVALENT;
        out.reason = "both FDE ranges empty";
        out.verifier_backend = "structural";
        out.solver_result = "precheck_both_ranges_empty";
        return out;
    }

    std::set<uint64_t> cutpoints;
    for (uint64_t d : collectRelativeCutPoints(lf)) {
        if (d < common_range) cutpoints.insert(d);
    }
    for (uint64_t d : collectRelativeCutPoints(rf)) {
        if (d < common_range) cutpoints.insert(d);
    }
    cutpoints.insert(0);
    cutpoints.insert(common_range - 1);

    for (uint64_t d : cutpoints) {
        uint64_t lpc = lf.initial_location + d;
        uint64_t rpc = rf.initial_location + d;
        auto r = compareParsersAtPC(lhs, rhs, lpc, rpc, opts);
        ++out.points_checked;
        if (r.verdict != ExpressionVerificationResult::Verdict::EQUIVALENT) {
            out.verdict = r.verdict;
            out.reason = "mismatch at relative pc " + std::to_string(d) + ": " + r.reason;
            out.mismatch_relative_pc = d;
            out.has_mismatch_relative_pc = true;
            out.verifier_backend = r.verifier_backend;
            out.solver_result = r.solver_result;
            out.counterexample_model = r.counterexample_model;
            out.counterexample_witness = r.counterexample_witness;
            return out;
        }
    }

    out.verdict = ExpressionVerificationResult::Verdict::EQUIVALENT;
    out.reason = "symbolic CFI interval equivalence established";
    out.verifier_backend = SMTExpressionVerifier::isAvailable()
        ? "structural+z3"
        : "structural+solver-unavailable";
    out.solver_result = "equivalent";
    return out;
}

} // namespace dwarf
