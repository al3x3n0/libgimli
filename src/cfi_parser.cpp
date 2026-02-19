#include "cfi_parser.hpp"
#include "expression_evaluator.hpp"
#include "dwarf_utils.hpp"
#include <algorithm>
#include <cstring>

namespace dwarf {

// UnwindInfo methods

uint64_t UnwindInfo::computeCFA(const std::vector<uint64_t>& reg_values) const {
    if (cfa.type == CFA_Type::REGISTER_OFFSET) {
        if (cfa.reg_num < reg_values.size()) {
            return reg_values[cfa.reg_num] + cfa.offset;
        }
        return 0;
    }
    // EXPRESSION type would need expression evaluator and memory access.
    return 0;
}

namespace {
static void encodeU64ToBuf(uint64_t v, size_t n, bool little_endian, void* out_buf) {
    if (!out_buf || n == 0) return;
    uint8_t* out = reinterpret_cast<uint8_t*>(out_buf);
    if (little_endian) {
        for (size_t i = 0; i < n; ++i) {
            out[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xff);
        }
        return;
    }
    for (size_t i = 0; i < n; ++i) {
        size_t shift = (n - 1 - i) * 8;
        out[i] = static_cast<uint8_t>((v >> shift) & 0xff);
    }
}

class WordReadMemoryContext final : public MemoryContext {
public:
    WordReadMemoryContext(const std::function<uint64_t(uint64_t)>& read_word, bool object_little_endian)
        : read_word_(read_word), object_little_endian_(object_little_endian) {}

    bool readMemory(uint64_t address, size_t size, void* buffer) const override {
        if (!read_word_ || !buffer) return false;
        // We only have word reads; best-effort fill with object endianness bytes.
        uint64_t word = read_word_(address);
        size_t n = (size < sizeof(uint64_t)) ? size : sizeof(uint64_t);
        encodeU64ToBuf(word, n, object_little_endian_, buffer);
        return true;
    }

    bool writeMemory(uint64_t address, size_t size, const void* buffer) override {
        (void)address; (void)size; (void)buffer;
        return false;
    }

private:
    std::function<uint64_t(uint64_t)> read_word_;
    bool object_little_endian_ = true;
};

static std::optional<uint64_t> evalDwarfExprU64(
    const std::vector<uint8_t>& expr,
    const std::vector<uint64_t>& regs,
    uint64_t cfa_value,
    uint8_t address_size,
    const std::function<uint64_t(uint64_t)>& read_memory) {

    if (expr.empty()) return std::nullopt;

    auto mem = std::make_shared<WordReadMemoryContext>(read_memory, DwarfUtils::objectIsLittleEndian());
    ExpressionEvaluator ev(mem);

    EvaluationContext ctx;
    ctx.cfa = cfa_value;
    ctx.address_size = address_size;
    ctx.entry_registers = regs;

    ExpressionResult r = ev.evaluate(expr, ctx, /*pc=*/0, regs);
    if (r.type == ExpressionResult::INVALID) return std::nullopt;
    return r.value;
}

static bool readInstrU8(const std::vector<uint8_t>& ins, uint64_t& off, uint8_t& out) {
    if (off >= ins.size()) return false;
    out = ins[off++];
    return true;
}

static bool readInstrU16(const std::vector<uint8_t>& ins, uint64_t& off, uint16_t& out) {
    if (off + 2 > ins.size()) return false;
    uint64_t tmp = off;
    out = DwarfUtils::readU16(ins.data(), tmp, ins.size());
    off = tmp;
    return true;
}

static bool readInstrU32(const std::vector<uint8_t>& ins, uint64_t& off, uint32_t& out) {
    if (off + 4 > ins.size()) return false;
    uint64_t tmp = off;
    out = DwarfUtils::readU32(ins.data(), tmp, ins.size());
    off = tmp;
    return true;
}

static bool readInstrU64(const std::vector<uint8_t>& ins, uint64_t& off, uint64_t& out) {
    if (off + 8 > ins.size()) return false;
    uint64_t tmp = off;
    out = DwarfUtils::readU64(ins.data(), tmp, ins.size());
    off = tmp;
    return true;
}

static bool readInstrULEB(const std::vector<uint8_t>& ins, uint64_t& off, uint64_t& out) {
    if (off >= ins.size()) return false;
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

static bool readInstrSLEB(const std::vector<uint8_t>& ins, uint64_t& off, int64_t& out) {
    if (off >= ins.size()) return false;
    int64_t result = 0;
    int shift = 0;
    uint8_t byte = 0;
    while (off < ins.size()) {
        byte = ins[off++];
        if (shift > 63 || (shift == 63 && (byte & 0x7f) != 0 && (byte & 0x7f) != 0x7f)) return false;
        result |= (static_cast<int64_t>(byte & 0x7f) << shift);
        shift += 7;
        if ((byte & 0x80) == 0) {
            if (shift < 64 && (byte & 0x40)) {
                result |= -(static_cast<int64_t>(1) << shift);
            }
            out = result;
            return true;
        }
    }
    return false;
}

static bool readBoundedU8(const std::vector<uint8_t>& data, uint64_t& off, uint64_t end, uint8_t& out) {
    if (off >= end || off >= data.size()) return false;
    out = data[off++];
    return true;
}

static bool readBoundedULEB(const std::vector<uint8_t>& data, uint64_t& off, uint64_t end, uint64_t& out) {
    if (off >= end || off >= data.size()) return false;
    uint64_t result = 0;
    uint64_t shift = 0;
    while (off < end && off < data.size()) {
        uint8_t byte = data[off++];
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

static bool readBoundedSLEB(const std::vector<uint8_t>& data, uint64_t& off, uint64_t end, int64_t& out) {
    if (off >= end || off >= data.size()) return false;
    int64_t result = 0;
    int shift = 0;
    uint8_t byte = 0;
    while (off < end && off < data.size()) {
        byte = data[off++];
        if (shift > 63 || (shift == 63 && (byte & 0x7f) != 0 && (byte & 0x7f) != 0x7f)) return false;
        result |= (static_cast<int64_t>(byte & 0x7f) << shift);
        shift += 7;
        if ((byte & 0x80) == 0) {
            if (shift < 64 && (byte & 0x40)) {
                result |= -(static_cast<int64_t>(1) << shift);
            }
            out = result;
            return true;
        }
    }
    return false;
}
} // namespace

uint64_t UnwindInfo::computeCFA(const std::vector<uint64_t>& reg_values,
                               const std::function<uint64_t(uint64_t)>& read_memory) const {
    if (cfa.type == CFA_Type::REGISTER_OFFSET) {
        if (cfa.reg_num < reg_values.size()) {
            return reg_values[cfa.reg_num] + cfa.offset;
        }
        return 0;
    }
    if (cfa.type == CFA_Type::EXPRESSION) {
        auto v = evalDwarfExprU64(cfa.expression, reg_values, /*cfa_value=*/0, address_size, read_memory);
        return v ? *v : 0;
    }
    return 0;
}

std::optional<uint64_t> UnwindInfo::getRegisterValue(
    uint64_t reg_num,
    const std::vector<uint64_t>& reg_values,
    uint64_t cfa_value,
    const std::function<uint64_t(uint64_t)>& read_memory) const {

    auto stripAArch64PAC = [&](uint64_t v) -> uint64_t {
        // GDB uses pseudo-registers:
        // - 34: ra_sign_state (toggled by DW_CFA_AARCH64_negate_ra_state)
        // - 36: pauth_cmask (mask of signature bits to clear)
        // If pauth_cmask isn't available, fall back to stripping the top byte (TBI tags/PAC bits).
        constexpr uint64_t kPAuthCMaskReg = 36;
        if (kPAuthCMaskReg < reg_values.size()) {
            uint64_t mask = reg_values[kPAuthCMaskReg];
            if (mask != 0) {
                return v & ~mask;
            }
        }
        return v & 0x00ffffffffffffffULL;
    };

    auto it = registers.find(reg_num);
    if (it == registers.end()) {
        return std::nullopt;
    }

    const RegisterRule& rule = it->second;
    std::optional<uint64_t> out;

    switch (rule.type) {
        case CFA_RegRule::UNDEFINED:
            out = std::nullopt;
            break;

        case CFA_RegRule::SAME_VALUE:
            if (reg_num < reg_values.size()) {
                out = reg_values[reg_num];
                break;
            }
            out = std::nullopt;
            break;

        case CFA_RegRule::OFFSET:
            // Value is stored at CFA + offset
            out = read_memory(cfa_value + rule.offset);
            break;

        case CFA_RegRule::VAL_OFFSET:
            // Value IS CFA + offset
            out = cfa_value + rule.offset;
            break;

        case CFA_RegRule::REGISTER:
            // Value is in another register
            if (rule.reg_num < reg_values.size()) {
                out = reg_values[rule.reg_num];
                break;
            }
            out = std::nullopt;
            break;

        case CFA_RegRule::EXPRESSION:
        case CFA_RegRule::VAL_EXPRESSION:
            break;

        case CFA_RegRule::ARCHITECTURAL:
            out = std::nullopt;
            break;
    }

    if (rule.type == CFA_RegRule::EXPRESSION) {
        auto addr = evalDwarfExprU64(rule.expression, reg_values, cfa_value, address_size, read_memory);
        if (!addr) return std::nullopt;
        out = read_memory(*addr);
    }

    if (rule.type == CFA_RegRule::VAL_EXPRESSION) {
        auto val = evalDwarfExprU64(rule.expression, reg_values, cfa_value, address_size, read_memory);
        out = val;
    }

    if (out && reg_num == return_address_register && aarch64_ra_sign_state != 0) {
        *out = stripAArch64PAC(*out);
    }
    return out;
}

// CFIParser implementation

CFIParser::CFIParser(const std::vector<uint8_t>& section_data,
                     bool is_eh_frame,
                     uint8_t address_size)
    : section_data_(section_data)
    , is_eh_frame_(is_eh_frame)
    , address_size_(address_size)
{
}

bool CFIParser::parse() {
    if (section_data_.empty()) {
        return false;
    }

    uint64_t offset = 0;

    while (offset < section_data_.size()) {
        uint64_t entry_start = offset;

        // Read length
        uint32_t length32 = readU32(offset);
        if (length32 == 0) {
            // Zero-length entry marks end
            break;
        }

        bool is_64bit = (length32 == 0xffffffff);
        uint64_t length;
        if (is_64bit) {
            length = readU64(offset);
        } else {
            length = length32;
        }

        if (length == 0) {
            break;
        }

        uint64_t entry_end = offset + length;
        if (entry_end > section_data_.size()) {
            break; // Truncated entry
        }

        // Read CIE ID / CIE pointer
        uint64_t id_or_pointer;
        if (is_64bit) {
            id_or_pointer = readU64(offset);
        } else {
            id_or_pointer = readU32(offset);
        }

        // Determine if this is a CIE or FDE
        bool is_cie;
        if (is_eh_frame_) {
            // In .eh_frame, CIE has id = 0
            is_cie = (id_or_pointer == 0);
        } else {
            // In .debug_frame, CIE has id = 0xffffffff (32-bit) or 0xffffffffffffffff (64-bit)
            is_cie = is_64bit ? (id_or_pointer == 0xffffffffffffffffULL)
                              : (id_or_pointer == 0xffffffff);
        }

        if (is_cie) {
            parseCIE(entry_start, length, is_64bit);
        } else {
            // For FDE, id_or_pointer is the CIE pointer
            uint64_t cie_pointer;
            if (is_eh_frame_) {
                // In .eh_frame, CIE pointer is relative to current position
                cie_pointer = offset - (is_64bit ? 8 : 4) - id_or_pointer;
            } else {
                // In .debug_frame, CIE pointer is absolute offset in section
                cie_pointer = id_or_pointer;
            }
            parseFDE(entry_start, length, cie_pointer, is_64bit);
        }

        offset = entry_end;
    }

    return !cies_.empty();
}

bool CFIParser::parseCIE(uint64_t offset, uint64_t length, bool is_64bit) {
    auto cie = std::make_shared<CIE>();
    cie->offset = offset;
    cie->length = length;

    // Skip past length and CIE ID (already read by caller)
    uint64_t pos = offset + (is_64bit ? 12 : 4) + (is_64bit ? 8 : 4);
    uint64_t end_pos = offset + (is_64bit ? 12 : 4) + length;

    // Version
    uint8_t version = 0;
    if (!readBoundedU8(section_data_, pos, end_pos, version)) {
        return false;
    }
    cie->version = version;

    // Augmentation string
    bool found_aug_nul = false;
    while (pos < end_pos) {
        uint8_t c8 = 0;
        if (!readBoundedU8(section_data_, pos, end_pos, c8)) {
            return false;
        }
        char c = static_cast<char>(c8);
        if (c == 0) {
            found_aug_nul = true;
            break;
        }
        cie->augmentation += c;
    }
    if (!found_aug_nul) {
        return false;
    }

    // DWARF 4+ has address_size and segment_selector_size
    if (cie->version >= 4) {
        uint8_t address_size = 0;
        uint8_t seg_sel_size = 0;
        if (!readBoundedU8(section_data_, pos, end_pos, address_size) ||
            !readBoundedU8(section_data_, pos, end_pos, seg_sel_size)) {
            return false;
        }
        cie->address_size = address_size;
        cie->segment_selector_size = seg_sel_size;
    } else {
        cie->address_size = address_size_;
        cie->segment_selector_size = 0;
    }

    // Code alignment factor
    uint64_t code_align = 0;
    if (!readBoundedULEB(section_data_, pos, end_pos, code_align)) {
        return false;
    }
    cie->code_alignment_factor = code_align;

    // Data alignment factor
    int64_t data_align = 0;
    if (!readBoundedSLEB(section_data_, pos, end_pos, data_align)) {
        return false;
    }
    cie->data_alignment_factor = data_align;

    // Return address register
    if (cie->version == 1) {
        uint8_t ra = 0;
        if (!readBoundedU8(section_data_, pos, end_pos, ra)) {
            return false;
        }
        cie->return_address_register = ra;
    } else {
        uint64_t ra = 0;
        if (!readBoundedULEB(section_data_, pos, end_pos, ra)) {
            return false;
        }
        cie->return_address_register = ra;
    }

    // Parse augmentation data if present (for .eh_frame)
    if (!cie->augmentation.empty() && cie->augmentation[0] == 'z') {
        cie->has_augmentation_data = true;
        uint64_t aug_length = 0;
        if (!readBoundedULEB(section_data_, pos, end_pos, aug_length)) {
            return false;
        }
        uint64_t aug_end = pos + aug_length;
        if (aug_end > end_pos) {
            // Malformed/truncated augmentation length; clamp to this CIE to avoid bleeding into next entries.
            aug_end = end_pos;
        }

        for (size_t i = 1; i < cie->augmentation.size() && pos < aug_end; ++i) {
            char aug_char = cie->augmentation[i];
            switch (aug_char) {
                case 'L':
                    if (pos < aug_end && pos < section_data_.size()) {
                        cie->lsda_pointer_encoding = section_data_[pos++];
                    }
                    break;
                case 'P': {
                    if (pos >= aug_end) break;
                    if (pos >= section_data_.size()) break;
                    cie->personality_encoding = section_data_[pos++];
                    uint64_t field_addr = section_base_ + pos;
                    cie->personality_routine = decodePointerBounded(pos, aug_end, cie->personality_encoding, field_addr);
                    break;
                }
                case 'R':
                    if (pos < aug_end && pos < section_data_.size()) {
                        cie->fde_pointer_encoding = section_data_[pos++];
                    }
                    break;
                case 'S':
                    cie->signal_frame = true;
                    break;
                default:
                    break;
            }
        }
        pos = aug_end;
    }

    // Rest is initial instructions
    if (pos < end_pos) {
        cie->initial_instructions = readBlock(pos, end_pos - pos);
    }

    // Execute initial instructions to get initial row
    cie->initial_row.location = 0;
    cie->initial_row.cfa.type = CFA_Type::REGISTER_OFFSET;
    cie->initial_row.cfa.reg_num = 0;
    cie->initial_row.cfa.offset = 0;
    cie->initial_row.aarch64_ra_sign_state = 0;

    std::vector<UnwindRow> dummy_table;
    executeInstructions(cie->initial_instructions, cie->initial_row, *cie, 0, 0, dummy_table);

    cies_.push_back(cie);
    cie_map_[cie->offset] = cie;

    return true;
}

bool CFIParser::parseFDE(uint64_t offset, uint64_t length, uint64_t cie_pointer, bool is_64bit) {
    auto fde = std::make_shared<FDE>();
    fde->offset = offset;
    fde->length = length;
    fde->cie_pointer = cie_pointer;

    // Find associated CIE
    auto cie_it = cie_map_.find(cie_pointer);
    if (cie_it == cie_map_.end()) {
        return false; // CIE not found
    }
    fde->cie = cie_it->second;

    // Skip past length and CIE pointer
    uint64_t pos = offset + (is_64bit ? 12 : 4) + (is_64bit ? 8 : 4);
    uint64_t end_pos = offset + (is_64bit ? 12 : 4) + length;

    // Initial location and address range
    uint8_t ptr_encoding = fde->cie->fde_pointer_encoding;
    if (ptr_encoding == 0) {
        ptr_encoding = (address_size_ == 8) ? 0x04 : 0x03; // DW_EH_PE_absptr
    }

    {
        uint64_t field_addr = section_base_ + pos;
        bool ok = false;
        fde->initial_location = decodePointerBounded(pos, end_pos, ptr_encoding, field_addr, &ok);
        if (!ok) return false;
    }
    {
        uint64_t field_addr = section_base_ + pos;
        // Size uses only low bits.
        bool ok = false;
        fde->address_range = decodePointerBounded(pos, end_pos, ptr_encoding & 0x0f, field_addr, &ok);
        if (!ok) return false;
    }

    // Parse augmentation data if present
    if (fde->cie->has_augmentation_data) {
        uint64_t aug_length = 0;
        if (!readBoundedULEB(section_data_, pos, end_pos, aug_length)) {
            return false;
        }
        uint64_t aug_end = pos + aug_length;
        if (aug_end > end_pos) {
            // Malformed/truncated augmentation length; clamp to this FDE.
            aug_end = end_pos;
        }

        // Check for LSDA pointer
        if (fde->cie->lsda_pointer_encoding != 0xff &&
            fde->cie->augmentation.find('L') != std::string::npos) {
            uint64_t field_addr = section_base_ + pos;
            fde->lsda_pointer = decodePointerBounded(pos, aug_end, fde->cie->lsda_pointer_encoding, field_addr);
        }

        pos = aug_end;
    }

    // Rest is FDE instructions
    if (pos < end_pos) {
        fde->instructions = readBlock(pos, end_pos - pos);
    }

    fdes_.push_back(fde);
    return true;
}

std::shared_ptr<FDE> CFIParser::findFDE(uint64_t pc) const {
    for (const auto& fde : fdes_) {
        if (pc >= fde->initial_location &&
            pc < fde->initial_location + fde->address_range) {
            return fde;
        }
    }
    return nullptr;
}

UnwindInfo CFIParser::getUnwindInfo(uint64_t pc) const {
    UnwindInfo info;
    info.pc = pc;

    auto fde = findFDE(pc);
    if (!fde || !fde->cie) {
        return info;
    }

    // Start with CIE's initial row
    UnwindRow row = fde->cie->initial_row;
    row.location = fde->initial_location;

    // Build unwind table by executing FDE instructions
    std::vector<UnwindRow> table;
    // Seed with the initial state at the start PC. Subsequent instructions may modify state
    // at the same location; executeInstructions() will coalesce same-location updates.
    table.push_back(row);
    executeInstructions(fde->instructions, row, *fde->cie,
                       fde->initial_location,
                       fde->initial_location + fde->address_range,
                       table);

    // Find the row for our PC
    // Best-effort: prefer the row with the largest location <= pc.
    // Note: Some producers may emit DW_CFA_set_loc that can move the location non-monotonically,
    // so don't assume table is sorted.
    const UnwindRow* best_row = &table.front();
    for (const auto& table_row : table) {
        if (table_row.location <= pc && table_row.location >= best_row->location) {
            best_row = &table_row;
        }
    }

    info.valid = true;
    info.address_size = fde->cie ? fde->cie->address_size : address_size_;
    info.cfa = best_row->cfa;
    info.registers = best_row->registers;
    info.return_address_register = fde->cie->return_address_register;
    info.aarch64_ra_sign_state = best_row->aarch64_ra_sign_state;

    return info;
}

void CFIParser::executeInstructions(const std::vector<uint8_t>& instructions,
                                    UnwindRow& row,
                                    const CIE& cie,
                                    uint64_t pc_begin,
                                    uint64_t pc_end,
                                    std::vector<UnwindRow>& table) const {
    std::stack<UnwindRow> state_stack;
    uint64_t offset = 0;

    while (offset < instructions.size()) {
        uint64_t prev_off = offset;
        offset = executeInstruction(offset, instructions, row, cie, state_stack);
        if (offset <= prev_off) {
            // Defensive: avoid infinite loops if a malformed/truncated operand fails to advance.
            break;
        }

        // Record the row. Multiple instructions can apply at the same location; keep the
        // final state for that location by replacing the last row when locations match.
        if (row.location >= pc_begin && row.location < pc_end) {
            if (!table.empty() && table.back().location == row.location) {
                table.back() = row;
            } else {
                table.push_back(row);
            }
        }
    }
}

uint64_t CFIParser::executeInstruction(uint64_t offset,
                                        const std::vector<uint8_t>& instructions,
                                        UnwindRow& row,
                                        const CIE& cie,
                                        std::stack<UnwindRow>& state_stack) const {
    if (offset >= instructions.size()) {
        return offset;
    }

    uint8_t opcode = instructions[offset++];

    // Check for high-bit encoded opcodes
    uint8_t primary = opcode & 0xc0;
    uint8_t operand = opcode & 0x3f;

    if (primary == 0x40) {
        // DW_CFA_advance_loc: advance location by operand * code_alignment_factor
        row.location += operand * cie.code_alignment_factor;
        return offset;
    }

    if (primary == 0x80) {
        // DW_CFA_offset: register operand, offset is ULEB128 * data_alignment_factor
        uint64_t reg = operand;
        uint64_t off_val = 0;
        if (!readInstrULEB(instructions, offset, off_val)) {
            return instructions.size();
        }

        RegisterRule rule;
        rule.type = CFA_RegRule::OFFSET;
        rule.offset = static_cast<int64_t>(off_val) * cie.data_alignment_factor;
        row.registers[reg] = rule;
        return offset;
    }

    if (primary == 0xc0) {
        // DW_CFA_restore: restore register operand to initial rule
        uint64_t reg = operand;
        auto it = cie.initial_row.registers.find(reg);
        if (it != cie.initial_row.registers.end()) {
            row.registers[reg] = it->second;
        } else {
            row.registers.erase(reg);
        }
        return offset;
    }

    // Regular opcodes
    switch (opcode) {
        case 0x00: // DW_CFA_nop
            break;

        case 0x1d: { // DW_CFA_MIPS_advance_loc8
            // 8-byte delta (target-specific extension). Used on some toolchains; harmless elsewhere.
            uint64_t delta = 0;
            if (!readInstrU64(instructions, offset, delta)) {
                return instructions.size();
            }
            row.location += delta * cie.code_alignment_factor;
            break;
        }

        case 0x01: { // DW_CFA_set_loc
            // Address is encoded in the object endianness.
            // Use the CIE's address_size (DWARF4+), not the parser default.
            if (cie.address_size == 8) {
                uint64_t v = 0;
                if (!readInstrU64(instructions, offset, v)) {
                    return instructions.size();
                }
                row.location = v;
            } else if (cie.address_size == 4) {
                uint32_t v = 0;
                if (!readInstrU32(instructions, offset, v)) {
                    return instructions.size();
                }
                row.location = v;
            } else {
                // Invalid CIE address_size. Cannot safely decode DW_CFA_set_loc operand.
                return instructions.size();
            }
            break;
        }

        case 0x02: { // DW_CFA_advance_loc1
            uint8_t delta = 0;
            if (!readInstrU8(instructions, offset, delta)) {
                return instructions.size();
            }
            row.location += static_cast<uint64_t>(delta) * cie.code_alignment_factor;
            break;
        }

        case 0x03: { // DW_CFA_advance_loc2
            uint16_t delta = 0;
            if (!readInstrU16(instructions, offset, delta)) {
                return instructions.size();
            }
            row.location += static_cast<uint64_t>(delta) * cie.code_alignment_factor;
            break;
        }

        case 0x04: { // DW_CFA_advance_loc4
            uint32_t delta = 0;
            if (!readInstrU32(instructions, offset, delta)) {
                return instructions.size();
            }
            row.location += static_cast<uint64_t>(delta) * cie.code_alignment_factor;
            break;
        }

        case 0x05: { // DW_CFA_offset_extended
            uint64_t reg = 0;
            uint64_t off = 0;
            if (!readInstrULEB(instructions, offset, reg) ||
                !readInstrULEB(instructions, offset, off)) {
                return instructions.size();
            }

            RegisterRule rule;
            rule.type = CFA_RegRule::OFFSET;
            rule.offset = static_cast<int64_t>(off) * cie.data_alignment_factor;
            row.registers[reg] = rule;
            break;
        }

        case 0x06: { // DW_CFA_restore_extended
            uint64_t reg = 0;
            if (!readInstrULEB(instructions, offset, reg)) {
                return instructions.size();
            }

            auto it = cie.initial_row.registers.find(reg);
            if (it != cie.initial_row.registers.end()) {
                row.registers[reg] = it->second;
            } else {
                row.registers.erase(reg);
            }
            break;
        }

        case 0x07: { // DW_CFA_undefined
            uint64_t reg = 0;
            if (!readInstrULEB(instructions, offset, reg)) {
                return instructions.size();
            }

            RegisterRule rule;
            rule.type = CFA_RegRule::UNDEFINED;
            row.registers[reg] = rule;
            break;
        }

        case 0x08: { // DW_CFA_same_value
            uint64_t reg = 0;
            if (!readInstrULEB(instructions, offset, reg)) {
                return instructions.size();
            }

            RegisterRule rule;
            rule.type = CFA_RegRule::SAME_VALUE;
            row.registers[reg] = rule;
            break;
        }

        case 0x09: { // DW_CFA_register
            uint64_t reg1 = 0;
            uint64_t reg2 = 0;
            if (!readInstrULEB(instructions, offset, reg1) ||
                !readInstrULEB(instructions, offset, reg2)) {
                return instructions.size();
            }

            RegisterRule rule;
            rule.type = CFA_RegRule::REGISTER;
            rule.reg_num = reg2;
            row.registers[reg1] = rule;
            break;
        }

        case 0x0a: // DW_CFA_remember_state
            state_stack.push(row);
            break;

        case 0x0b: // DW_CFA_restore_state
            if (!state_stack.empty()) {
                uint64_t saved_loc = row.location;
                row = state_stack.top();
                row.location = saved_loc;
                state_stack.pop();
            }
            break;

        case 0x0c: { // DW_CFA_def_cfa
            uint64_t reg = 0;
            uint64_t off = 0;
            if (!readInstrULEB(instructions, offset, reg) ||
                !readInstrULEB(instructions, offset, off)) {
                return instructions.size();
            }

            row.cfa.type = CFA_Type::REGISTER_OFFSET;
            row.cfa.reg_num = reg;
            row.cfa.offset = static_cast<int64_t>(off);
            break;
        }

        case 0x0d: { // DW_CFA_def_cfa_register
            uint64_t reg = 0;
            if (!readInstrULEB(instructions, offset, reg)) {
                return instructions.size();
            }

            row.cfa.type = CFA_Type::REGISTER_OFFSET;
            row.cfa.reg_num = reg;
            break;
        }

        case 0x0e: { // DW_CFA_def_cfa_offset
            uint64_t off = 0;
            if (!readInstrULEB(instructions, offset, off)) {
                return instructions.size();
            }

            row.cfa.type = CFA_Type::REGISTER_OFFSET;
            row.cfa.offset = static_cast<int64_t>(off);
            break;
        }

        case 0x0f: {
            // DW_CFA_escape (DWARF2) or DW_CFA_def_cfa_expression (DWARF3+).
            if (cie.version < 3) { // DW_CFA_escape
                if (offset >= instructions.size()) {
                    return instructions.size();
                }
                uint8_t len = instructions[offset++];
                uint64_t avail = (offset <= instructions.size()) ? (instructions.size() - offset) : 0;
                if (len > avail) {
                    return instructions.size();
                }
                offset += len; // skip opaque bytes
                break;
            }

            // DW_CFA_def_cfa_expression (DWARF3+)
            uint64_t len = 0;
            if (!readInstrULEB(instructions, offset, len)) {
                return instructions.size();
            }
            uint64_t avail = (offset <= instructions.size()) ? (instructions.size() - offset) : 0;
            if (len > avail) {
                return instructions.size();
            }
            std::vector<uint8_t> expr;
            expr.insert(expr.end(),
                                      instructions.begin() + static_cast<int64_t>(offset),
                                      instructions.begin() + static_cast<int64_t>(offset + len));
            offset += len;
            row.cfa.type = CFA_Type::EXPRESSION;
            row.cfa.expression = std::move(expr);
            break;
        }

        case 0x10: { // DW_CFA_expression
            uint64_t reg = 0;
            uint64_t len = 0;
            if (!readInstrULEB(instructions, offset, reg) ||
                !readInstrULEB(instructions, offset, len)) {
                return instructions.size();
            }

            uint64_t avail = (offset <= instructions.size()) ? (instructions.size() - offset) : 0;
            if (len > avail) {
                return instructions.size();
            }
            RegisterRule rule;
            rule.type = CFA_RegRule::EXPRESSION;
            rule.expression.insert(rule.expression.end(),
                                   instructions.begin() + static_cast<int64_t>(offset),
                                   instructions.begin() + static_cast<int64_t>(offset + len));
            offset += len;
            row.registers[reg] = rule;
            break;
        }

        case 0x11: { // DW_CFA_offset_extended_sf
            uint64_t reg = 0;
            int64_t off = 0;
            if (!readInstrULEB(instructions, offset, reg) ||
                !readInstrSLEB(instructions, offset, off)) {
                return instructions.size();
            }

            RegisterRule rule;
            rule.type = CFA_RegRule::OFFSET;
            rule.offset = off * cie.data_alignment_factor;
            row.registers[reg] = rule;
            break;
        }

        case 0x12: { // DW_CFA_def_cfa_sf
            uint64_t reg = 0;
            int64_t off = 0;
            if (!readInstrULEB(instructions, offset, reg) ||
                !readInstrSLEB(instructions, offset, off)) {
                return instructions.size();
            }

            row.cfa.type = CFA_Type::REGISTER_OFFSET;
            row.cfa.reg_num = reg;
            row.cfa.offset = off * cie.data_alignment_factor;
            break;
        }

        case 0x13: { // DW_CFA_def_cfa_offset_sf
            int64_t off = 0;
            if (!readInstrSLEB(instructions, offset, off)) {
                return instructions.size();
            }

            row.cfa.type = CFA_Type::REGISTER_OFFSET;
            row.cfa.offset = off * cie.data_alignment_factor;
            break;
        }

        case 0x14: { // DW_CFA_val_offset
            uint64_t reg = 0;
            uint64_t off = 0;
            if (!readInstrULEB(instructions, offset, reg) ||
                !readInstrULEB(instructions, offset, off)) {
                return instructions.size();
            }

            RegisterRule rule;
            rule.type = CFA_RegRule::VAL_OFFSET;
            rule.offset = static_cast<int64_t>(off) * cie.data_alignment_factor;
            row.registers[reg] = rule;
            break;
        }

        case 0x15: { // DW_CFA_val_offset_sf
            uint64_t reg = 0;
            int64_t off = 0;
            if (!readInstrULEB(instructions, offset, reg) ||
                !readInstrSLEB(instructions, offset, off)) {
                return instructions.size();
            }

            RegisterRule rule;
            rule.type = CFA_RegRule::VAL_OFFSET;
            rule.offset = off * cie.data_alignment_factor;
            row.registers[reg] = rule;
            break;
        }

        case 0x16: { // DW_CFA_val_expression
            uint64_t reg = 0;
            uint64_t len = 0;
            if (!readInstrULEB(instructions, offset, reg) ||
                !readInstrULEB(instructions, offset, len)) {
                return instructions.size();
            }

            uint64_t avail = (offset <= instructions.size()) ? (instructions.size() - offset) : 0;
            if (len > avail) {
                return instructions.size();
            }
            RegisterRule rule;
            rule.type = CFA_RegRule::VAL_EXPRESSION;
            rule.expression.insert(rule.expression.end(),
                                   instructions.begin() + static_cast<int64_t>(offset),
                                   instructions.begin() + static_cast<int64_t>(offset + len));
            offset += len;
            row.registers[reg] = rule;
            break;
        }

        case 0x2d: { // DW_CFA_AARCH64_negate_ra_state / DW_CFA_GNU_window_save
            // AArch64 extension used to track whether the return address is signed (PAC).
            // Other architectures may interpret 0x2d differently (e.g. SPARC window save),
            // so gate on a best-effort AArch64 heuristic.
            if (cie.return_address_register == 30 && cie.address_size == 8) {
                row.aarch64_ra_sign_state ^= 1;
            }
            break;
        }

        case 0x2e: { // DW_CFA_GNU_args_size
            // Skip a ULEB128 argument.
            uint64_t ignored = 0;
            if (!readInstrULEB(instructions, offset, ignored)) {
                return instructions.size();
            }
            break;
        }

        case 0x2f: { // DW_CFA_GNU_negative_offset_extended
            uint64_t reg = 0;
            uint64_t off = 0;
            if (!readInstrULEB(instructions, offset, reg) ||
                !readInstrULEB(instructions, offset, off)) {
                return instructions.size();
            }

            RegisterRule rule;
            rule.type = CFA_RegRule::OFFSET;
            rule.offset = -static_cast<int64_t>(off) * cie.data_alignment_factor;
            row.registers[reg] = rule;
            break;
        }

        default:
            // Unknown CFA opcode. Many opcodes carry operands, but without knowing the operand
            // layout we cannot safely skip forward. Continuing would desynchronize parsing and
            // produce incorrect unwind state. Abort this instruction stream.
            return instructions.size();
    }

    return offset;
}

uint64_t CFIParser::decodePointer(uint64_t& offset, uint8_t encoding, uint64_t pc_rel_base) const {
    return decodePointerBounded(offset, section_data_.size(), encoding, pc_rel_base);
}

uint64_t CFIParser::decodePointerBounded(uint64_t& offset,
                                        uint64_t end,
                                        uint8_t encoding,
                                        uint64_t pc_rel_base,
                                        bool* decoded_ok) const {
    if (decoded_ok) *decoded_ok = true;
    if (encoding == 0xff) {
        return 0; // Omitted
    }

    // DW_EH_PE_indirect (0x80) is meaningful at runtime; we don't have process memory here.
    // Ignore it for parsing purposes (offset advancement is unaffected).
    uint64_t base = 0;
    uint64_t value = 0;

    // High 4 bits determine base/application.
    // DW_EH_PE_aligned means the encoded value starts at an aligned address.
    uint8_t app = encoding & 0x70;
    if (app == 0x50) { // DW_EH_PE_aligned
        uint64_t align = (address_size_ == 8) ? 8 : 4;
        uint64_t mis = offset % align;
        if (mis != 0) {
            uint64_t pad = align - mis;
            // Best-effort: don't run past section bounds.
            if (offset + pad <= end) {
                offset += pad;
            } else {
                offset = end;
                if (decoded_ok) *decoded_ok = false;
                return 0;
            }
        }
    }

    auto canRead = [&](uint64_t n) -> bool { return offset + n <= end; };

    // Low 4 bits determine value format
    switch (encoding & 0x0f) {
        case 0x00: // DW_EH_PE_absptr
            if (!canRead((address_size_ == 8) ? 8 : 4)) {
                offset = end;
                if (decoded_ok) *decoded_ok = false;
                return 0;
            }
            value = (address_size_ == 8)
                        ? DwarfUtils::readU64(section_data_.data(), offset, end)
                        : DwarfUtils::readU32(section_data_.data(), offset, end);
            break;
        case 0x01: // DW_EH_PE_uleb128
            if (offset >= end) {
                offset = end;
                if (decoded_ok) *decoded_ok = false;
                return 0;
            }
            {
                uint64_t tmp = offset;
                if (!readBoundedULEB(section_data_, tmp, end, value)) {
                    offset = end;
                    if (decoded_ok) *decoded_ok = false;
                    return 0;
                }
                offset = tmp;
            }
            break;
        case 0x02: // DW_EH_PE_udata2
            if (!canRead(2)) {
                offset = end;
                if (decoded_ok) *decoded_ok = false;
                return 0;
            }
            value = DwarfUtils::readU16(section_data_.data(), offset, end);
            break;
        case 0x03: // DW_EH_PE_udata4
            if (!canRead(4)) {
                offset = end;
                if (decoded_ok) *decoded_ok = false;
                return 0;
            }
            value = DwarfUtils::readU32(section_data_.data(), offset, end);
            break;
        case 0x04: // DW_EH_PE_udata8
            if (!canRead(8)) {
                offset = end;
                if (decoded_ok) *decoded_ok = false;
                return 0;
            }
            value = DwarfUtils::readU64(section_data_.data(), offset, end);
            break;
        case 0x09: // DW_EH_PE_sleb128
            if (offset >= end) {
                offset = end;
                if (decoded_ok) *decoded_ok = false;
                return 0;
            }
            {
                int64_t sv = 0;
                uint64_t tmp = offset;
                if (!readBoundedSLEB(section_data_, tmp, end, sv)) {
                    offset = end;
                    if (decoded_ok) *decoded_ok = false;
                    return 0;
                }
                offset = tmp;
                value = static_cast<uint64_t>(sv);
            }
            break;
        case 0x0a: { // DW_EH_PE_sdata2
            if (!canRead(2)) {
                offset = end;
                if (decoded_ok) *decoded_ok = false;
                return 0;
            }
            int16_t v = static_cast<int16_t>(DwarfUtils::readU16(section_data_.data(), offset, end));
            value = static_cast<uint64_t>(static_cast<int64_t>(v));
            break;
        }
        case 0x0b: { // DW_EH_PE_sdata4
            if (!canRead(4)) {
                offset = end;
                if (decoded_ok) *decoded_ok = false;
                return 0;
            }
            int32_t v = static_cast<int32_t>(DwarfUtils::readU32(section_data_.data(), offset, end));
            value = static_cast<uint64_t>(static_cast<int64_t>(v));
            break;
        }
        case 0x0c: { // DW_EH_PE_sdata8
            if (!canRead(8)) {
                offset = end;
                if (decoded_ok) *decoded_ok = false;
                return 0;
            }
            value = DwarfUtils::readU64(section_data_.data(), offset, end);
            break;
        }
        default:
            offset = end;
            if (decoded_ok) *decoded_ok = false;
            return 0;
    }

    // Apply base/application.
    switch (app) {
        case 0x00: // DW_EH_PE_absptr
            base = 0;
            break;
        case 0x10: // DW_EH_PE_pcrel
            base = pc_rel_base;
            break;
        case 0x20: // DW_EH_PE_textrel
            base = 0; // Would need text section base
            break;
        case 0x30: // DW_EH_PE_datarel
            base = section_base_;
            break;
        case 0x40: // DW_EH_PE_funcrel
            base = 0; // Would need function base
            break;
        case 0x50: // DW_EH_PE_aligned
            base = 0;
            break;
        default:
            break;
    }

    return base + value;
}

// Reading helpers

uint8_t CFIParser::readU8(uint64_t& offset) const {
    return DwarfUtils::readU8(section_data_.data(), offset, section_data_.size());
}

uint16_t CFIParser::readU16(uint64_t& offset) const {
    return DwarfUtils::readU16(section_data_.data(), offset, section_data_.size());
}

uint32_t CFIParser::readU32(uint64_t& offset) const {
    return DwarfUtils::readU32(section_data_.data(), offset, section_data_.size());
}

uint64_t CFIParser::readU64(uint64_t& offset) const {
    return DwarfUtils::readU64(section_data_.data(), offset, section_data_.size());
}

uint64_t CFIParser::readAddress(uint64_t& offset) const {
    if (address_size_ == 8) {
        return readU64(offset);
    } else {
        return readU32(offset);
    }
}

uint64_t CFIParser::readULEB128(uint64_t& offset) const {
    return DwarfUtils::readULEB128(section_data_.data(), offset, section_data_.size());
}

int64_t CFIParser::readSLEB128(uint64_t& offset) const {
    return DwarfUtils::readSLEB128(section_data_.data(), offset, section_data_.size());
}

std::vector<uint8_t> CFIParser::readBlock(uint64_t& offset, uint64_t size) const {
    std::vector<uint8_t> block;
    for (uint64_t i = 0; i < size && offset < section_data_.size(); ++i) {
        block.push_back(section_data_[offset++]);
    }
    return block;
}

} // namespace dwarf
