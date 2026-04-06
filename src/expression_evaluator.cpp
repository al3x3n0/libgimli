#include "expression_evaluator.hpp"
#include "dwarf_utils.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>

#ifndef DWARF_UNUSED
#define DWARF_UNUSED(x) (void)(x)
#endif

namespace dwarf {

static uint64_t dwarfSectionOffsetBias(uint64_t cu_base_offset) {
    // Our DIE cache uses "biased" offsets for DWOs and supplementary debug info:
    // - DWO: bit 63 set, slot in bits [62:48]
    // - supplementary: bit 62 set
    //
    // In those cases, the low 48 bits store the real section offset. For non-biased
    // units, treat bias as 0 even if higher bits are set (defensive).
    constexpr uint64_t kLow48Mask = (1ULL << 48) - 1;
    constexpr uint64_t kBiasBits = (1ULL << 63) | (1ULL << 62);
    if ((cu_base_offset & kBiasBits) == 0) return 0;
    return cu_base_offset & ~kLow48Mask;
}

static uint64_t addSignedOffset(uint64_t base, int64_t offset) {
    if (offset >= 0) return base + static_cast<uint64_t>(offset);
    return base - static_cast<uint64_t>(-offset);
}

static uint64_t alignOffsetUp(uint64_t off, uint64_t align) {
    if (align <= 1) return off;
    uint64_t rem = off % align;
    return rem == 0 ? off : (off + (align - rem));
}

static uint64_t maskToBytes(uint64_t v, uint64_t byte_size) {
    if (byte_size == 0) return v;
    if (byte_size >= 8) return v;
    uint64_t bits = byte_size * 8;
    return v & ((1ULL << bits) - 1ULL);
}

static uint64_t signExtendBytes(uint64_t v, uint64_t byte_size) {
    if (byte_size == 0) return v;
    if (byte_size >= 8) return v;
    v = maskToBytes(v, byte_size);
    uint64_t shift = 64 - (byte_size * 8);
    return static_cast<uint64_t>(static_cast<int64_t>(v << shift) >> shift);
}

static uint64_t decodeU64FromBytes(const uint8_t* bytes, size_t n, bool little_endian) {
    if (!bytes || n == 0) return 0;
    if (n > 8) n = 8;
    uint64_t v = 0;
    if (little_endian) {
        for (size_t i = 0; i < n; ++i) {
            v |= (static_cast<uint64_t>(bytes[i]) << (i * 8));
        }
        return v;
    }
    for (size_t i = 0; i < n; ++i) {
        v = (v << 8) | static_cast<uint64_t>(bytes[i]);
    }
    return v;
}

static std::vector<uint8_t> encodeU64ToBytes(uint64_t v, size_t n, bool little_endian) {
    std::vector<uint8_t> out;
    out.resize(n);
    if (n == 0) return out;
    if (little_endian) {
        for (size_t i = 0; i < n; ++i) {
            out[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xff);
        }
        return out;
    }
    // Big-endian: emit the low n bytes with MSB first.
    for (size_t i = 0; i < n; ++i) {
        size_t shift = (n - 1 - i) * 8;
        out[i] = static_cast<uint8_t>((v >> shift) & 0xff);
    }
    return out;
}

static uint64_t decodeResultValueFromBytes(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return 0;
    return decodeU64FromBytes(bytes.data(),
                              std::min<size_t>(bytes.size(), 8),
                              DwarfUtils::objectIsLittleEndian());
}

static std::vector<uint8_t> lowBytesForResultValue(uint64_t v, uint64_t byte_size) {
    return encodeU64ToBytes(v,
                            static_cast<size_t>(std::min<uint64_t>(byte_size, 8)),
                            DwarfUtils::objectIsLittleEndian());
}

static std::string unsupportedOpMessage(uint8_t opcode, uint64_t offset, bool subexpression) {
    std::ostringstream oss;
    oss << (subexpression ? "Unsupported operation in subexpression: " : "Unsupported operation: ")
        << DwarfUtils::operationToString(static_cast<DwarfOp>(opcode))
        << " (opcode 0x" << std::hex << static_cast<unsigned>(opcode) << std::dec << ")";
    if (opcode >= 0xe0) {
        oss << " [vendor/extension opcode]";
    }
    oss << " at offset " << offset;
    return oss.str();
}

static const char* vendorProfileOpcodeName(VendorExpressionProfile profile, uint8_t opcode) {
    if (profile == VendorExpressionProfile::SYNTHETIC_V1) {
        switch (opcode) {
            case 0xf9: return "DW_OP_vendor_synthetic_constu";
            case 0xfd: return "DW_OP_vendor_synthetic_plus_uconst";
            case 0xfe: return "DW_OP_vendor_synthetic_deref_size";
            default: break;
        }
    }
    return nullptr;
}

ExpressionEvaluator::ExpressionEvaluator(std::shared_ptr<MemoryContext> memory_context) 
    : memory_context_(memory_context) {
    if (!memory_context_) {
        memory_context_ = std::make_shared<DefaultMemoryContext>();
    }
    initializeOpHandlers();
}

void ExpressionEvaluator::setMemoryContext(std::shared_ptr<MemoryContext> memory_context) {
    memory_context_ = memory_context ? memory_context : std::make_shared<DefaultMemoryContext>();
}

void ExpressionEvaluator::setContext(const EvaluationContext& context) {
    context_ = context;
}

ExpressionResult ExpressionEvaluator::evaluate(const std::vector<uint8_t>& expression,
                                               uint64_t pc,
                                               const std::vector<uint64_t>& registers) {
    // Use default context
    return evaluate(expression, context_, pc, registers);
}

ExpressionResult ExpressionEvaluator::evaluate(const std::vector<uint8_t>& expression,
                                               const EvaluationContext& context,
                                               uint64_t pc,
                                               const std::vector<uint64_t>& registers) {
    pc_ = pc;
    registers_ = registers;
    context_ = context;

    // Clear stack and pieces
    while (!stack_.empty()) {
        stack_.pop();
    }
    pieces_.clear();
    is_register_location_ = false;
    is_implicit_value_ = false;
    pending_implicit_bytes_.reset();
    uninitialized_taint_ = false;
    execution_error_ = false;
    execution_error_message_.clear();

    uint64_t offset = 0;
    // Expressions can contain branches (DW_OP_bra/DW_OP_skip). Guard against infinite loops.
    size_t steps = 0;
    const size_t max_steps = std::max<size_t>(1024, expression.size() * 16);

    while (offset < expression.size()) {
        if (++steps > max_steps) {
            return ExpressionResult(ExpressionResult::INVALID, 0, "Expression step limit exceeded");
        }
        uint64_t op_off = offset;
        uint8_t opcode = readU8(offset, expression);
        DwarfOp op = static_cast<DwarfOp>(opcode);

        auto handler_it = op_handlers_.find(op);
        if (handler_it != op_handlers_.end()) {
            (this->*handler_it->second)(offset, expression);
            if (execution_error_) {
                ExpressionResult r(ExpressionResult::INVALID, 0,
                                   execution_error_message_ + " at offset " + std::to_string(op_off));
                r.uninitialized = uninitialized_taint_;
                return r;
            }
        } else if (handleVendorProfileOpcode(opcode, offset, expression)) {
            if (execution_error_) {
                ExpressionResult r(ExpressionResult::INVALID, 0,
                                   execution_error_message_ + " at offset " + std::to_string(op_off));
                r.uninitialized = uninitialized_taint_;
                return r;
            }
        } else {
            std::string msg = unsupportedOpMessage(opcode, op_off, /*subexpression=*/false);
            if (const char* profile_name = vendorProfileOpcodeName(context_.vendor_expression_profile, opcode)) {
                std::ostringstream oss;
                oss << "Unsupported operation: " << profile_name
                    << " (opcode 0x" << std::hex << static_cast<unsigned>(opcode) << std::dec << ")"
                    << " at offset " << op_off;
                msg = oss.str();
            }
            ExpressionResult r(ExpressionResult::INVALID, 0, msg + diagnosticContextSuffix());
            r.uninitialized = uninitialized_taint_;
            r.unsupported_opcode = opcode;
            r.unsupported_vendor_extension = opcode >= 0xe0;
            return r;
        }
    }

    // Check if we have multiple pieces
    if (!pieces_.empty()) {
        ExpressionResult r(pieces_, "Composite location with " +
                                  std::to_string(pieces_.size()) + " pieces");
        r.uninitialized = uninitialized_taint_;
        if (r.uninitialized) r.description += " [uninitialized]";
        return r;
    }

    if (stack_.empty()) {
        ExpressionResult r(ExpressionResult::INVALID, 0, "Empty stack");
        r.uninitialized = uninitialized_taint_;
        return r;
    }

    uint64_t result = stack_.top();

    if (is_register_location_) {
        ExpressionResult r(ExpressionResult::REGISTER, result,
                           "Register: " + std::to_string(result));
        r.uninitialized = uninitialized_taint_;
        if (r.uninitialized) r.description += " [uninitialized]";
        return r;
    }

    if (is_implicit_value_) {
        ExpressionResult r(ExpressionResult::VALUE, result,
                           "Value: " + std::to_string(result));
        r.uninitialized = uninitialized_taint_;
        if (pending_implicit_bytes_) {
            r.raw_value_bytes = *pending_implicit_bytes_;
        }
        if (r.uninitialized) r.description += " [uninitialized]";
        return r;
    }

    ExpressionResult r(ExpressionResult::ADDRESS, result, "Address: 0x" +
                      DwarfUtils::formatAddress(result, true));
    r.uninitialized = uninitialized_taint_;
    if (r.uninitialized) r.description += " [uninitialized]";
    return r;
}

bool ExpressionEvaluator::executeInPlace(const std::vector<uint8_t>& expression) {
    if (expression.empty()) return true;

    constexpr int kMaxCallDepth = 16;
    if (call_depth_ >= kMaxCallDepth) {
        setExecutionError("DW_OP_call recursion depth exceeded");
        return false;
    }
    ++call_depth_;
    execution_error_ = false;
    execution_error_message_.clear();

    uint64_t offset = 0;
    bool ok = true;
    size_t steps = 0;
    const size_t max_steps = std::max<size_t>(1024, expression.size() * 16);
    while (offset < expression.size()) {
        if (++steps > max_steps) {
            setExecutionError("DW_OP_call subexpression step limit exceeded");
            ok = false;
            break;
        }
        uint8_t opcode = readU8(offset, expression);
        DwarfOp op = static_cast<DwarfOp>(opcode);

        auto handler_it = op_handlers_.find(op);
        if (handler_it != op_handlers_.end()) {
            (this->*handler_it->second)(offset, expression);
            if (execution_error_) {
                ok = false;
                break;
            }
        } else if (handleVendorProfileOpcode(opcode, offset, expression)) {
            if (execution_error_) {
                ok = false;
                break;
            }
        } else {
            setExecutionError(unsupportedOpMessage(opcode, offset - 1, /*subexpression=*/true));
            ok = false;
            break;
        }
    }

    --call_depth_;
    return ok;
}

bool ExpressionEvaluator::handleVendorProfileOpcode(uint8_t opcode,
                                                    uint64_t& offset,
                                                    const std::vector<uint8_t>& expression) {
    if (context_.vendor_expression_profile != VendorExpressionProfile::SYNTHETIC_V1) {
        return false;
    }

    switch (opcode) {
        case 0xf9:
            push(readULEB128(offset, expression));
            return true;
        case 0xfd: {
            uint64_t uconst = readULEB128(offset, expression);
            if (!requireStack(1, "DW_OP_vendor_synthetic_plus_uconst")) return true;
            uint64_t val = pop();
            push(val + uconst);
            return true;
        }
        case 0xfe: {
            uint8_t size = readU8(offset, expression);
            if (!requireStack(1, "DW_OP_vendor_synthetic_deref_size")) return true;
            uint64_t addr = pop();
            if (memory_context_) {
                std::vector<uint8_t> buf(size);
                if (memory_context_->readMemory(addr, size, buf.data())) {
                    push(decodeU64FromBytes(buf.data(), size, DwarfUtils::objectIsLittleEndian()));
                    pending_implicit_bytes_ = std::move(buf);
                } else {
                    setExecutionError("DW_OP_vendor_synthetic_deref_size memory read failed");
                }
            } else {
                setExecutionError("DW_OP_vendor_synthetic_deref_size requires memory context");
            }
            return true;
        }
        default:
            return false;
    }
}

bool ExpressionEvaluator::materializeResultAsValue(const ExpressionResult& result,
                                                   const std::vector<uint64_t>& register_bank,
                                                   const char* op_name,
                                                   uint64_t& out_value,
                                                   std::optional<std::vector<uint8_t>>& out_bytes) {
    out_bytes.reset();
    switch (result.type) {
        case ExpressionResult::VALUE:
            out_value = result.value;
            if (!result.raw_value_bytes.empty()) out_bytes = result.raw_value_bytes;
            return true;
        case ExpressionResult::REGISTER:
            if (result.value < register_bank.size()) {
                out_value = register_bank[static_cast<size_t>(result.value)];
                return true;
            }
            setExecutionError(std::string(op_name) + " register unavailable in register context");
            return false;
        case ExpressionResult::ADDRESS: {
            size_t n = pointerByteSize(op_name);
            if (execution_error_) return false;
            std::vector<uint8_t> buf(n);
            if (memory_context_ && memory_context_->readMemory(result.value, n, buf.data())) {
                out_value = decodeU64FromBytes(buf.data(), n, DwarfUtils::objectIsLittleEndian());
                out_bytes = std::move(buf);
                return true;
            }
            setExecutionError(std::string(op_name) + " memory read failed");
            return false;
        }
        default:
            setExecutionError(std::string(op_name) + " referent produced unsupported result");
            return false;
    }
}

void ExpressionEvaluator::push(uint64_t value) {
    stack_.push(value);
}

void ExpressionEvaluator::setExecutionError(std::string msg) const {
    if (!execution_error_) {
        execution_error_ = true;
        execution_error_message_ = std::move(msg) + diagnosticContextSuffix();
    }
}

std::string ExpressionEvaluator::diagnosticContextSuffix() const {
    return DwarfUtils::formatDiagnosticContext(
        context_.diagnostic_cu_offset,
        context_.diagnostic_die_offset,
        context_.diagnostic_attribute);
}

bool ExpressionEvaluator::requireStack(size_t n, const char* op_name) {
    if (stack_.size() >= n) return true;
    setExecutionError(std::string("Stack underflow in ") + op_name);
    return false;
}

uint64_t ExpressionEvaluator::pop() {
    if (stack_.empty()) return 0;
    uint64_t value = stack_.top();
    stack_.pop();
    return value;
}

uint64_t ExpressionEvaluator::top() const {
    return stack_.empty() ? 0 : stack_.top();
}

bool ExpressionEvaluator::empty() const {
    return stack_.empty();
}

size_t ExpressionEvaluator::size() const {
    return stack_.size();
}

void ExpressionEvaluator::printStack() const {
    std::cout << "Stack (size: " << stack_.size() << "): ";
    std::stack<uint64_t> temp = stack_;
    while (!temp.empty()) {
        std::cout << "0x" << std::hex << temp.top() << " ";
        temp.pop();
    }
    std::cout << std::dec << std::endl;
}

std::string ExpressionEvaluator::expressionToString(const std::vector<uint8_t>& expression) const {
    std::stringstream ss;
    uint64_t offset = 0;
    
    while (offset < expression.size()) {
        if (offset > 0) ss << " ";
        
        uint8_t opcode = readU8(offset, expression);
        DwarfOp op = static_cast<DwarfOp>(opcode);
        
        ss << DwarfUtils::operationToString(op);
        
        // Add operands for some operations
        switch (op) {
            case DwarfOp::DW_OP_addr:
                if (context_.address_size == 4) {
                    if (offset + 4 <= expression.size()) {
                        uint64_t addr = readU32(offset, expression);
                        ss << " 0x" << std::hex << addr << std::dec;
                    }
                } else {
                    if (offset + 8 <= expression.size()) {
                        uint64_t addr = readU64(offset, expression);
                        ss << " 0x" << std::hex << addr << std::dec;
                    }
                }
                break;
            case DwarfOp::DW_OP_const1u:
            case DwarfOp::DW_OP_const1s:
                if (offset < expression.size()) {
                    uint8_t val = readU8(offset, expression);
                    ss << " " << static_cast<int>(val);
                }
                break;
            case DwarfOp::DW_OP_const2u:
            case DwarfOp::DW_OP_const2s:
                if (offset + 1 < expression.size()) {
                    uint16_t val = readU16(offset, expression);
                    ss << " " << val;
                }
                break;
            case DwarfOp::DW_OP_const4u:
            case DwarfOp::DW_OP_const4s:
                if (offset + 3 < expression.size()) {
                    uint32_t val = readU32(offset, expression);
                    ss << " " << val;
                }
                break;
            case DwarfOp::DW_OP_const8u:
            case DwarfOp::DW_OP_const8s:
                if (offset + 7 < expression.size()) {
                    uint64_t val = readU64(offset, expression);
                    ss << " 0x" << std::hex << val << std::dec;
                }
                break;
            case DwarfOp::DW_OP_constu:
                if (offset < expression.size()) {
                    uint64_t val = readULEB128(offset, expression);
                    ss << " " << val;
                }
                break;
            case DwarfOp::DW_OP_consts:
                if (offset < expression.size()) {
                    int64_t val = readSLEB128(offset, expression);
                    ss << " " << val;
                }
                break;
            case DwarfOp::DW_OP_regx:
                if (offset < expression.size()) {
                    uint64_t reg = readULEB128(offset, expression);
                    ss << " " << reg;
                }
                break;
            case DwarfOp::DW_OP_bregx:
                if (offset < expression.size()) {
                    uint64_t reg = readULEB128(offset, expression);
                    int64_t offset_val = readSLEB128(offset, expression);
                    ss << " " << reg << " " << offset_val;
                }
                break;
            case DwarfOp::DW_OP_fbreg:
                if (offset < expression.size()) {
                    int64_t offset_val = readSLEB128(offset, expression);
                    ss << " " << offset_val;
                }
                break;
            case DwarfOp::DW_OP_pick:
                if (offset < expression.size()) {
                    uint8_t index = readU8(offset, expression);
                    ss << " " << static_cast<int>(index);
                }
                break;
            case DwarfOp::DW_OP_plus_uconst:
                if (offset < expression.size()) {
                    uint64_t val = readULEB128(offset, expression);
                    ss << " " << val;
                }
                break;
            case DwarfOp::DW_OP_bra:
            case DwarfOp::DW_OP_skip:
                if (offset + 1 < expression.size()) {
                    int16_t offset_val = readU16(offset, expression);
                    ss << " " << offset_val;
                }
                break;
            default:
                break;
        }
    }
    
    return ss.str();
}

void ExpressionEvaluator::initializeOpHandlers() {
    op_handlers_[DwarfOp::DW_OP_addr] = &ExpressionEvaluator::handleAddr;
    op_handlers_[DwarfOp::DW_OP_deref] = &ExpressionEvaluator::handleDeref;
    op_handlers_[DwarfOp::DW_OP_const1u] = &ExpressionEvaluator::handleConst1u;
    op_handlers_[DwarfOp::DW_OP_const1s] = &ExpressionEvaluator::handleConst1s;
    op_handlers_[DwarfOp::DW_OP_const2u] = &ExpressionEvaluator::handleConst2u;
    op_handlers_[DwarfOp::DW_OP_const2s] = &ExpressionEvaluator::handleConst2s;
    op_handlers_[DwarfOp::DW_OP_const4u] = &ExpressionEvaluator::handleConst4u;
    op_handlers_[DwarfOp::DW_OP_const4s] = &ExpressionEvaluator::handleConst4s;
    op_handlers_[DwarfOp::DW_OP_const8u] = &ExpressionEvaluator::handleConst8u;
    op_handlers_[DwarfOp::DW_OP_const8s] = &ExpressionEvaluator::handleConst8s;
    op_handlers_[DwarfOp::DW_OP_constu] = &ExpressionEvaluator::handleConstu;
    op_handlers_[DwarfOp::DW_OP_consts] = &ExpressionEvaluator::handleConsts;
    op_handlers_[DwarfOp::DW_OP_dup] = &ExpressionEvaluator::handleDup;
    op_handlers_[DwarfOp::DW_OP_drop] = &ExpressionEvaluator::handleDrop;
    op_handlers_[DwarfOp::DW_OP_over] = &ExpressionEvaluator::handleOver;
    op_handlers_[DwarfOp::DW_OP_pick] = &ExpressionEvaluator::handlePick;
    op_handlers_[DwarfOp::DW_OP_swap] = &ExpressionEvaluator::handleSwap;
    op_handlers_[DwarfOp::DW_OP_rot] = &ExpressionEvaluator::handleRot;
    op_handlers_[DwarfOp::DW_OP_xderef] = &ExpressionEvaluator::handleXderef;
    op_handlers_[DwarfOp::DW_OP_abs] = &ExpressionEvaluator::handleAbs;
    op_handlers_[DwarfOp::DW_OP_and] = &ExpressionEvaluator::handleAnd;
    op_handlers_[DwarfOp::DW_OP_div] = &ExpressionEvaluator::handleDiv;
    op_handlers_[DwarfOp::DW_OP_minus] = &ExpressionEvaluator::handleMinus;
    op_handlers_[DwarfOp::DW_OP_mod] = &ExpressionEvaluator::handleMod;
    op_handlers_[DwarfOp::DW_OP_mul] = &ExpressionEvaluator::handleMul;
    op_handlers_[DwarfOp::DW_OP_neg] = &ExpressionEvaluator::handleNeg;
    op_handlers_[DwarfOp::DW_OP_not] = &ExpressionEvaluator::handleNot;
    op_handlers_[DwarfOp::DW_OP_or] = &ExpressionEvaluator::handleOr;
    op_handlers_[DwarfOp::DW_OP_plus] = &ExpressionEvaluator::handlePlus;
    op_handlers_[DwarfOp::DW_OP_plus_uconst] = &ExpressionEvaluator::handlePlusUconst;
    op_handlers_[DwarfOp::DW_OP_shl] = &ExpressionEvaluator::handleShl;
    op_handlers_[DwarfOp::DW_OP_shr] = &ExpressionEvaluator::handleShr;
    op_handlers_[DwarfOp::DW_OP_shra] = &ExpressionEvaluator::handleShra;
    op_handlers_[DwarfOp::DW_OP_xor] = &ExpressionEvaluator::handleXor;
    op_handlers_[DwarfOp::DW_OP_bra] = &ExpressionEvaluator::handleBra;
    op_handlers_[DwarfOp::DW_OP_eq] = &ExpressionEvaluator::handleEq;
    op_handlers_[DwarfOp::DW_OP_ge] = &ExpressionEvaluator::handleGe;
    op_handlers_[DwarfOp::DW_OP_gt] = &ExpressionEvaluator::handleGt;
    op_handlers_[DwarfOp::DW_OP_le] = &ExpressionEvaluator::handleLe;
    op_handlers_[DwarfOp::DW_OP_lt] = &ExpressionEvaluator::handleLt;
    op_handlers_[DwarfOp::DW_OP_ne] = &ExpressionEvaluator::handleNe;
    op_handlers_[DwarfOp::DW_OP_skip] = &ExpressionEvaluator::handleSkip;
    op_handlers_[DwarfOp::DW_OP_regx] = &ExpressionEvaluator::handleRegx;
    op_handlers_[DwarfOp::DW_OP_fbreg] = &ExpressionEvaluator::handleFbreg;
    op_handlers_[DwarfOp::DW_OP_bregx] = &ExpressionEvaluator::handleBregx;
    op_handlers_[DwarfOp::DW_OP_piece] = &ExpressionEvaluator::handlePiece;
    op_handlers_[DwarfOp::DW_OP_deref_size] = &ExpressionEvaluator::handleDerefSize;
    op_handlers_[DwarfOp::DW_OP_xderef_size] = &ExpressionEvaluator::handleXderefSize;
    op_handlers_[DwarfOp::DW_OP_nop] = &ExpressionEvaluator::handleNop;
    op_handlers_[DwarfOp::DW_OP_push_object_address] = &ExpressionEvaluator::handlePushObjectAddress;
    op_handlers_[DwarfOp::DW_OP_call_frame_cfa] = &ExpressionEvaluator::handleCallFrameCfa;
    op_handlers_[DwarfOp::DW_OP_bit_piece] = &ExpressionEvaluator::handleBitPiece;
    op_handlers_[DwarfOp::DW_OP_implicit_value] = &ExpressionEvaluator::handleImplicitValue;
    op_handlers_[DwarfOp::DW_OP_stack_value] = &ExpressionEvaluator::handleStackValue;
    op_handlers_[DwarfOp::DW_OP_implicit_pointer] = &ExpressionEvaluator::handleImplicitPointer;
    op_handlers_[DwarfOp::DW_OP_addrx] = &ExpressionEvaluator::handleAddrx;
    op_handlers_[DwarfOp::DW_OP_constx] = &ExpressionEvaluator::handleConstx;
    op_handlers_[DwarfOp::DW_OP_entry_value] = &ExpressionEvaluator::handleEntryValue;
    op_handlers_[DwarfOp::DW_OP_const_type] = &ExpressionEvaluator::handleConstType;
    op_handlers_[DwarfOp::DW_OP_regval_type] = &ExpressionEvaluator::handleRegvalType;
    op_handlers_[DwarfOp::DW_OP_deref_type] = &ExpressionEvaluator::handleDerefType;
    op_handlers_[DwarfOp::DW_OP_xderef_type] = &ExpressionEvaluator::handleXderefType;
    op_handlers_[DwarfOp::DW_OP_convert] = &ExpressionEvaluator::handleConvert;
    op_handlers_[DwarfOp::DW_OP_reinterpret] = &ExpressionEvaluator::handleReinterpret;

    // Call operations
    op_handlers_[DwarfOp::DW_OP_call2] = &ExpressionEvaluator::handleCall2;
    op_handlers_[DwarfOp::DW_OP_call4] = &ExpressionEvaluator::handleCall4;
    op_handlers_[DwarfOp::DW_OP_call_ref] = &ExpressionEvaluator::handleCallRef;

    // TLS operations
    op_handlers_[DwarfOp::DW_OP_form_tls_address] = &ExpressionEvaluator::handleFormTlsAddress;

    // GNU Extensions
    op_handlers_[DwarfOp::DW_OP_GNU_push_tls_address] = &ExpressionEvaluator::handleGnuPushTlsAddress;
    op_handlers_[DwarfOp::DW_OP_GNU_uninit] = &ExpressionEvaluator::handleGnuUninit;
    op_handlers_[DwarfOp::DW_OP_GNU_encoded_addr] = &ExpressionEvaluator::handleGnuEncodedAddr;
    op_handlers_[DwarfOp::DW_OP_GNU_implicit_pointer] = &ExpressionEvaluator::handleGnuImplicitPointer;
    op_handlers_[DwarfOp::DW_OP_GNU_entry_value] = &ExpressionEvaluator::handleGnuEntryValue;
    op_handlers_[DwarfOp::DW_OP_GNU_const_type] = &ExpressionEvaluator::handleGnuConstType;
    op_handlers_[DwarfOp::DW_OP_GNU_regval_type] = &ExpressionEvaluator::handleGnuRegvalType;
    op_handlers_[DwarfOp::DW_OP_GNU_deref_type] = &ExpressionEvaluator::handleGnuDerefType;
    op_handlers_[DwarfOp::DW_OP_GNU_convert] = &ExpressionEvaluator::handleGnuConvert;
    op_handlers_[DwarfOp::DW_OP_GNU_reinterpret] = &ExpressionEvaluator::handleGnuReinterpret;
    op_handlers_[DwarfOp::DW_OP_GNU_parameter_ref] = &ExpressionEvaluator::handleGnuParameterRef;
    op_handlers_[DwarfOp::DW_OP_GNU_addr_index] = &ExpressionEvaluator::handleGnuAddrIndex;
    op_handlers_[DwarfOp::DW_OP_GNU_const_index] = &ExpressionEvaluator::handleGnuConstIndex;
    op_handlers_[DwarfOp::DW_OP_WASM_location] = &ExpressionEvaluator::handleWasmLocation;

    // Handle literal operations
    for (uint8_t i = 0; i <= 31; ++i) {
        op_handlers_[static_cast<DwarfOp>(static_cast<uint8_t>(DwarfOp::DW_OP_lit0) + i)] = &ExpressionEvaluator::handleLit;
    }
    
    // Handle register operations
    for (uint8_t i = 0; i <= 31; ++i) {
        op_handlers_[static_cast<DwarfOp>(static_cast<uint8_t>(DwarfOp::DW_OP_reg0) + i)] = &ExpressionEvaluator::handleReg;
        op_handlers_[static_cast<DwarfOp>(static_cast<uint8_t>(DwarfOp::DW_OP_breg0) + i)] = &ExpressionEvaluator::handleBreg;
    }
}

// Operation handlers implementation
void ExpressionEvaluator::handleAddr(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_addr operand is target address size.
    uint64_t addr = readAddressSized(offset, expression);
    if (execution_error_) return;
    push(addr);
}

void ExpressionEvaluator::handleDeref(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(1, "DW_OP_deref")) return;
    uint64_t addr = pop();
    
    if (memory_context_) {
        size_t n = pointerByteSize("DW_OP_deref");
        if (execution_error_) return;
        std::vector<uint8_t> buf(n);
        if (memory_context_->readMemory(addr, n, buf.data())) {
            push(decodeU64FromBytes(buf.data(), n, DwarfUtils::objectIsLittleEndian()));
        } else {
            setExecutionError("DW_OP_deref memory read failed");
        }
    } else {
        setExecutionError("DW_OP_deref requires memory context");
    }
}

void ExpressionEvaluator::handleConst1u(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint8_t val = readU8(offset, expression);
    push(val);
}

void ExpressionEvaluator::handleConst1s(uint64_t& offset, const std::vector<uint8_t>& expression) {
    int8_t val = static_cast<int8_t>(readU8(offset, expression));
    push(static_cast<uint64_t>(val));
}

void ExpressionEvaluator::handleConst2u(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint16_t val = readU16(offset, expression);
    push(val);
}

void ExpressionEvaluator::handleConst2s(uint64_t& offset, const std::vector<uint8_t>& expression) {
    int16_t val = static_cast<int16_t>(readU16(offset, expression));
    push(static_cast<uint64_t>(val));
}

void ExpressionEvaluator::handleConst4u(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint32_t val = readU32(offset, expression);
    push(val);
}

void ExpressionEvaluator::handleConst4s(uint64_t& offset, const std::vector<uint8_t>& expression) {
    int32_t val = static_cast<int32_t>(readU32(offset, expression));
    push(static_cast<uint64_t>(val));
}

void ExpressionEvaluator::handleConst8u(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t val = readU64(offset, expression);
    push(val);
}

void ExpressionEvaluator::handleConst8s(uint64_t& offset, const std::vector<uint8_t>& expression) {
    int64_t val = static_cast<int64_t>(readU64(offset, expression));
    push(static_cast<uint64_t>(val));
}

void ExpressionEvaluator::handleConstu(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t val = readULEB128(offset, expression);
    push(val);
}

void ExpressionEvaluator::handleConsts(uint64_t& offset, const std::vector<uint8_t>& expression) {
    int64_t val = readSLEB128(offset, expression);
    push(static_cast<uint64_t>(val));
}

void ExpressionEvaluator::handleDup(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(1, "DW_OP_dup")) return;
    uint64_t val = stack_.top();
    push(val);
}

void ExpressionEvaluator::handleDrop(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(1, "DW_OP_drop")) return;
    stack_.pop();
}

void ExpressionEvaluator::handleOver(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_over")) return;
    uint64_t val1 = pop();
    uint64_t val2 = pop();
    push(val2);
    push(val1);
    push(val2);
}

void ExpressionEvaluator::handlePick(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint8_t index = readU8(offset, expression);
    if (!requireStack(1, "DW_OP_pick")) return;
    if (index >= stack_.size()) {
        setExecutionError("DW_OP_pick index out of range");
        return;
    }
    
    std::stack<uint64_t> temp;
    for (uint8_t i = 0; i < index; ++i) {
        temp.push(stack_.top());
        stack_.pop();
    }
    uint64_t val = stack_.top();
    while (!temp.empty()) {
        stack_.push(temp.top());
        temp.pop();
    }
    push(val);
}

void ExpressionEvaluator::handleSwap(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_swap")) return;
    uint64_t val1 = pop();
    uint64_t val2 = pop();
    push(val1);
    push(val2);
}

void ExpressionEvaluator::handleRot(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(3, "DW_OP_rot")) return;
    uint64_t val1 = pop();
    uint64_t val2 = pop();
    uint64_t val3 = pop();
    // DW_OP_rot: (x y z -- y z x)
    push(val2);
    push(val1);
    push(val3);
}

void ExpressionEvaluator::handleXderef(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_xderef")) return;
    uint64_t addr = pop();
    uint64_t space = pop();
    DWARF_UNUSED(space);
    
    if (memory_context_) {
        size_t n = pointerByteSize("DW_OP_xderef");
        if (execution_error_) return;
        std::vector<uint8_t> buf(n);
        if (memory_context_->readMemory(addr, n, buf.data())) {
            push(decodeU64FromBytes(buf.data(), n, DwarfUtils::objectIsLittleEndian()));
        } else {
            setExecutionError("DW_OP_xderef memory read failed");
        }
    } else {
        setExecutionError("DW_OP_xderef requires memory context");
    }
}

void ExpressionEvaluator::handleAbs(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(1, "DW_OP_abs")) return;
    int64_t val = static_cast<int64_t>(pop());
    push(static_cast<uint64_t>(val < 0 ? -val : val));
}

void ExpressionEvaluator::handleAnd(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_and")) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 & val2);
}

void ExpressionEvaluator::handleDiv(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_div")) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    if (val2 != 0) {
        push(val1 / val2);
    } else {
        push(0); // Division by zero
    }
}

void ExpressionEvaluator::handleMinus(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_minus")) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 - val2);
}

void ExpressionEvaluator::handleMod(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_mod")) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    if (val2 != 0) {
        push(val1 % val2);
    } else {
        push(0); // Modulo by zero
    }
}

void ExpressionEvaluator::handleMul(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_mul")) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 * val2);
}

void ExpressionEvaluator::handleNeg(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(1, "DW_OP_neg")) return;
    uint64_t val = pop();
    push(-val);
}

void ExpressionEvaluator::handleNot(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(1, "DW_OP_not")) return;
    uint64_t val = pop();
    push(~val);
}

void ExpressionEvaluator::handleOr(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_or")) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 | val2);
}

void ExpressionEvaluator::handlePlus(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_plus")) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 + val2);
}

void ExpressionEvaluator::handlePlusUconst(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t uconst = readULEB128(offset, expression);
    if (!requireStack(1, "DW_OP_plus_uconst")) return;
    uint64_t val = pop();
    push(val + uconst);
}

void ExpressionEvaluator::handleShl(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_shl")) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 << (val2 & 63));
}

void ExpressionEvaluator::handleShr(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_shr")) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 >> (val2 & 63));
}

void ExpressionEvaluator::handleShra(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_shra")) return;
    uint64_t val2 = pop();
    int64_t val1 = static_cast<int64_t>(pop());
    push(static_cast<uint64_t>(val1 >> (val2 & 63)));
}

void ExpressionEvaluator::handleXor(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_xor")) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 ^ val2);
}

void ExpressionEvaluator::handleBra(uint64_t& offset, const std::vector<uint8_t>& expression) {
    int16_t target = static_cast<int16_t>(readU16(offset, expression));
    if (!requireStack(1, "DW_OP_bra")) return;
    uint64_t condition = pop();
    if (condition != 0) {
        int64_t base = static_cast<int64_t>(offset);
        int64_t next = base + static_cast<int64_t>(target);
        if (next < 0 || static_cast<uint64_t>(next) > expression.size()) {
            setExecutionError("DW_OP_bra target out of range");
            return;
        }
        offset = (next < 0) ? 0 : static_cast<uint64_t>(next);
    }
}

void ExpressionEvaluator::handleEq(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_eq")) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 == val2 ? 1 : 0);
}

void ExpressionEvaluator::handleGe(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_ge")) return;
    int64_t val2 = static_cast<int64_t>(pop());
    int64_t val1 = static_cast<int64_t>(pop());
    push(val1 >= val2 ? 1 : 0);
}

void ExpressionEvaluator::handleGt(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_gt")) return;
    int64_t val2 = static_cast<int64_t>(pop());
    int64_t val1 = static_cast<int64_t>(pop());
    push(val1 > val2 ? 1 : 0);
}

void ExpressionEvaluator::handleLe(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_le")) return;
    int64_t val2 = static_cast<int64_t>(pop());
    int64_t val1 = static_cast<int64_t>(pop());
    push(val1 <= val2 ? 1 : 0);
}

void ExpressionEvaluator::handleLt(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_lt")) return;
    int64_t val2 = static_cast<int64_t>(pop());
    int64_t val1 = static_cast<int64_t>(pop());
    push(val1 < val2 ? 1 : 0);
}

void ExpressionEvaluator::handleNe(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(2, "DW_OP_ne")) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 != val2 ? 1 : 0);
}

void ExpressionEvaluator::handleSkip(uint64_t& offset, const std::vector<uint8_t>& expression) {
    int16_t target = static_cast<int16_t>(readU16(offset, expression));
    int64_t base = static_cast<int64_t>(offset);
    int64_t next = base + static_cast<int64_t>(target);
    if (next < 0 || static_cast<uint64_t>(next) > expression.size()) {
        setExecutionError("DW_OP_skip target out of range");
        return;
    }
    offset = static_cast<uint64_t>(next);
}

void ExpressionEvaluator::handleLit(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // Extract the literal value from the opcode
    uint8_t opcode = expression[offset - 1]; // Get the opcode that was just processed
    uint8_t lit_value = opcode - static_cast<uint8_t>(DwarfOp::DW_OP_lit0);
    push(lit_value);
}

void ExpressionEvaluator::handleReg(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // Extract the register number from the opcode
    uint8_t opcode = expression[offset - 1]; // Get the opcode that was just processed
    uint8_t reg_num = opcode - static_cast<uint8_t>(DwarfOp::DW_OP_reg0);

    // For DW_OP_reg*, the result is the register number itself (not the value)
    // This indicates the value is IN the register, not at a memory address
    push(reg_num);
    is_register_location_ = true;
}

void ExpressionEvaluator::handleBreg(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // Extract the register number from the opcode
    uint8_t opcode = expression[offset - 1]; // Get the opcode that was just processed
    uint8_t reg_num = opcode - static_cast<uint8_t>(DwarfOp::DW_OP_breg0);
    int64_t offset_val = readSLEB128(offset, expression);
    if (reg_num < registers_.size()) {
        push(addSignedOffset(registers_[reg_num], offset_val));
    } else {
        push(addSignedOffset(0, offset_val));
    }
}

void ExpressionEvaluator::handleRegx(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t reg_num = readULEB128(offset, expression);

    // For DW_OP_regx, the result is the register number itself
    push(reg_num);
    is_register_location_ = true;
}

void ExpressionEvaluator::handleFbreg(uint64_t& offset, const std::vector<uint8_t>& expression) {
    int64_t offset_val = readSLEB128(offset, expression);
    // Use frame_base from context (should be set from DW_AT_frame_base evaluation)
    push(addSignedOffset(context_.frame_base, offset_val));
}

void ExpressionEvaluator::handleBregx(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t reg_num = readULEB128(offset, expression);
    int64_t offset_val = readSLEB128(offset, expression);
    if (reg_num < registers_.size()) {
        push(addSignedOffset(registers_[reg_num], offset_val));
    } else {
        push(addSignedOffset(0, offset_val));
    }
}

void ExpressionEvaluator::handlePiece(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t byte_size = readULEB128(offset, expression);

    PieceDescriptor piece;
    piece.byte_size = byte_size;
    piece.bit_size = byte_size * 8;
    piece.bit_offset = 0;

    if (!stack_.empty()) {
        // Previous expression computed a location
        if (is_implicit_value_) {
            piece.kind = PieceDescriptor::IMPLICIT;
            uint64_t v = pop();
            if (pending_implicit_bytes_) {
                piece.implicit_value = *pending_implicit_bytes_;
                // DW_OP_piece describes the size of this piece; trim or pad accordingly.
                if (piece.implicit_value.size() > byte_size) {
                    piece.implicit_value.resize(byte_size);
                }
            } else {
                if (byte_size > 8) {
                    setExecutionError("DW_OP_piece requires explicit bytes for values wider than 8 bytes");
                    return;
                }
                piece.implicit_value = encodeU64ToBytes(v,
                                                       static_cast<size_t>(byte_size),
                                                       DwarfUtils::objectIsLittleEndian());
            }
        } else if (is_register_location_) {
            piece.kind = PieceDescriptor::REGISTER;
            piece.location = pop();
        } else {
            piece.kind = PieceDescriptor::MEMORY;
            piece.location = pop();
        }
    } else {
        // Empty piece (undefined value)
        piece.kind = PieceDescriptor::EMPTY;
    }

    pieces_.push_back(piece);
    is_register_location_ = false;  // Reset for next piece
    is_implicit_value_ = false;
    pending_implicit_bytes_.reset();
}

void ExpressionEvaluator::handleDerefSize(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint8_t size = readU8(offset, expression);
    if (!requireStack(1, "DW_OP_deref_size")) return;
    uint64_t addr = pop();
    
    if (memory_context_) {
        std::vector<uint8_t> buf(size);
        if (memory_context_->readMemory(addr, size, buf.data())) {
            push(decodeU64FromBytes(buf.data(), size, DwarfUtils::objectIsLittleEndian()));
            pending_implicit_bytes_ = std::move(buf);
        } else {
            setExecutionError("DW_OP_deref_size memory read failed");
        }
    } else {
        setExecutionError("DW_OP_deref_size requires memory context");
    }
}

void ExpressionEvaluator::handleXderefSize(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint8_t size = readU8(offset, expression);
    if (!requireStack(2, "DW_OP_xderef_size")) return;
    uint64_t addr = pop();
    uint64_t space = pop();
    DWARF_UNUSED(space);
    
    if (memory_context_) {
        std::vector<uint8_t> buf(size);
        if (memory_context_->readMemory(addr, size, buf.data())) {
            push(decodeU64FromBytes(buf.data(), size, DwarfUtils::objectIsLittleEndian()));
            pending_implicit_bytes_ = std::move(buf);
        } else {
            setExecutionError("DW_OP_xderef_size memory read failed");
        }
    } else {
        setExecutionError("DW_OP_xderef_size requires memory context");
    }
}

void ExpressionEvaluator::handleNop(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    // No operation
}

void ExpressionEvaluator::handlePushObjectAddress(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    // Use object_address from context
    push(context_.object_address);
}

void ExpressionEvaluator::handleCallFrameCfa(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    // Use CFA from context (should be computed from CFI tables)
    push(context_.cfa);
}

void ExpressionEvaluator::handleBitPiece(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t bit_size = readULEB128(offset, expression);
    uint64_t bit_offset = readULEB128(offset, expression);

    PieceDescriptor piece;
    piece.bit_size = bit_size;
    piece.bit_offset = bit_offset;
    piece.byte_size = (bit_size + 7) / 8;

    if (!stack_.empty()) {
        if (is_implicit_value_) {
            piece.kind = PieceDescriptor::IMPLICIT;
            uint64_t v = pop();
            if (pending_implicit_bytes_) {
                piece.implicit_value = *pending_implicit_bytes_;
                if (piece.implicit_value.size() > piece.byte_size) {
                    piece.implicit_value.resize(piece.byte_size);
                }
            } else {
                if (piece.byte_size > 8) {
                    setExecutionError("DW_OP_bit_piece requires explicit bytes for values wider than 8 bytes");
                    return;
                }
                piece.implicit_value = encodeU64ToBytes(v,
                                                       static_cast<size_t>(piece.byte_size),
                                                       DwarfUtils::objectIsLittleEndian());
            }
        } else if (is_register_location_) {
            piece.kind = PieceDescriptor::REGISTER;
            piece.location = pop();
        } else {
            piece.kind = PieceDescriptor::MEMORY;
            piece.location = pop();
        }
    } else {
        piece.kind = PieceDescriptor::EMPTY;
    }

    pieces_.push_back(piece);
    is_register_location_ = false;
    is_implicit_value_ = false;
    pending_implicit_bytes_.reset();
}

void ExpressionEvaluator::handleImplicitValue(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t size = readULEB128(offset, expression);
    if (execution_error_) return;
    // DW_OP_implicit_value specifies that the object's value is embedded
    // directly in the DWARF expression, not in memory or a register.
    if (offset > expression.size() || size > expression.size() - offset) {
        setExecutionError("truncated DW_OP_implicit_value payload");
        offset = expression.size();
        return;
    }

    std::vector<uint8_t> bytes(expression.begin() + offset, expression.begin() + offset + size);
    offset += size;

    uint64_t value = 0;
    if (size == 0) {
        value = 0;
    } else if (size <= 8) {
        value = decodeU64FromBytes(bytes.data(), size, DwarfUtils::objectIsLittleEndian());
    } else {
        // Best-effort: keep the low 8 bytes as the stack value.
        if (DwarfUtils::objectIsLittleEndian()) {
            value = decodeU64FromBytes(bytes.data(), 8, /*little_endian=*/true);
        } else {
            value = decodeU64FromBytes(bytes.data() + (size - 8), 8, /*little_endian=*/false);
        }
    }
    push(value);
    is_implicit_value_ = true;
    pending_implicit_bytes_ = std::move(bytes);
}

void ExpressionEvaluator::handleStackValue(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(1, "DW_OP_stack_value")) return;

    if (is_register_location_) {
        // DW_OP_stack_value turns a register location into the value held in that register.
        uint64_t reg_num = top();
        uint64_t value = (reg_num < registers_.size()) ? registers_[static_cast<size_t>(reg_num)] : 0;
        stack_.top() = value;
        is_register_location_ = false;
        // Bytes (if needed by subsequent DW_OP_piece) should be derived from the concrete value.
        pending_implicit_bytes_.reset();
    }

    // DW_OP_stack_value specifies that the object does not exist in memory
    // but its value is still on the stack. The debugger should use the value
    // directly rather than treating it as a memory address.
    is_implicit_value_ = true;
}

void ExpressionEvaluator::handleImplicitPointer(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t die_offset = readOffsetSized(offset, expression);
    if (execution_error_) return;
    int64_t offset_val = readSLEB128(offset, expression);
    if (execution_error_) return;

    // DW_OP_implicit_pointer yields an address computed from another DIE's location
    // plus a constant offset.
    // The DIE reference is a section-relative offset (like DW_FORM_ref_addr), not CU-relative.
    uint64_t abs_die_offset = dwarfSectionOffsetBias(context_.cu_base_offset) + die_offset;

    if (!context_.resolve_dwarf_procedure) {
        setExecutionError("DW_OP_implicit_pointer requires DIE resolver");
        return;
    }

    auto proc = context_.resolve_dwarf_procedure(abs_die_offset, pc_);
    if (!proc) {
        setExecutionError("DW_OP_implicit_pointer referent not found");
        return;
    }

    ExpressionEvaluator sub(memory_context_);
    sub.setContext(context_);
    ExpressionResult r = sub.evaluate(*proc, context_, pc_, registers_);
    uninitialized_taint_ = uninitialized_taint_ || r.uninitialized;

    switch (r.type) {
        case ExpressionResult::ADDRESS:
        case ExpressionResult::VALUE:
            push(addSignedOffset(r.value, offset_val));
            pending_implicit_bytes_.reset();
            return;
        case ExpressionResult::REGISTER:
            if (r.value < registers_.size()) {
                push(addSignedOffset(registers_[static_cast<size_t>(r.value)], offset_val));
                pending_implicit_bytes_.reset();
            } else {
                setExecutionError("DW_OP_implicit_pointer register referent out of range");
            }
            return;
        default:
            break;
    }

    setExecutionError("DW_OP_implicit_pointer referent has unsupported result type");
}

void ExpressionEvaluator::handleAddrx(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t index = readULEB128(offset, expression);

    // Look up address in debug_addr_table using addr_base
    if (context_.debug_addr_table && index < context_.debug_addr_table->size()) {
        uint64_t address = (*context_.debug_addr_table)[index];
        push(address);
    } else {
        setExecutionError("DW_OP_addrx index out of range or debug_addr unavailable");
    }
}

void ExpressionEvaluator::handleConstx(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t index = readULEB128(offset, expression);

    // DW_OP_constx uses the same debug_addr table as DW_OP_addrx
    // but treats the value as a constant rather than an address
    if (context_.debug_addr_table && index < context_.debug_addr_table->size()) {
        uint64_t constant = (*context_.debug_addr_table)[index];
        push(constant);
    } else {
        setExecutionError("DW_OP_constx index out of range or debug_addr unavailable");
    }
}

void ExpressionEvaluator::handleEntryValue(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t size = readULEB128(offset, expression);
    if (execution_error_) return;

    if (offset > expression.size() || size > expression.size() - offset) {
        setExecutionError("truncated DW_OP_entry_value subexpression");
        offset = expression.size();
        return;
    }

    // Extract the sub-expression that describes the entry value
    std::vector<uint8_t> sub_expr(expression.begin() + offset,
                                   expression.begin() + offset + size);
    offset += size;

    // Evaluate the sub-expression using entry-time register values
    ExpressionEvaluator sub_evaluator(memory_context_);

    // Use entry registers from context instead of current registers
    auto result = sub_evaluator.evaluate(sub_expr, context_, pc_, context_.entry_registers);
    uninitialized_taint_ = uninitialized_taint_ || result.uninitialized;

    uint64_t value = 0;
    std::optional<std::vector<uint8_t>> materialized_bytes;
    if (!materializeResultAsValue(result, context_.entry_registers, "DW_OP_entry_value",
                                  value, materialized_bytes)) {
        return;
    }
    push(value);
    is_implicit_value_ = true;
    pending_implicit_bytes_ = std::move(materialized_bytes);
}

void ExpressionEvaluator::handleConstType(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // ULEB128 type die offset (reference to base type)
    uint64_t type_offset = readULEB128(offset, expression);
    if (execution_error_) return;
    uint64_t abs_type_offset = (type_offset == 0) ? 0 : (context_.cu_base_offset + type_offset);
    // 1-byte size of the constant value
    uint8_t size = readU8(offset, expression);
    if (execution_error_) return;

    if (offset > expression.size() || static_cast<uint64_t>(size) > expression.size() - offset) {
        setExecutionError("truncated DW_OP_const_type payload");
        offset = expression.size();
        return;
    }

    std::vector<uint8_t> bytes(expression.begin() + offset, expression.begin() + offset + size);
    offset += size;

    uint64_t value = decodeResultValueFromBytes(bytes);

    if (context_.resolve_base_type) {
        auto ti = context_.resolve_base_type(abs_type_offset);
        if (type_offset != 0 && !ti) {
            setExecutionError("DW_OP_const_type could not resolve referenced base type");
            return;
        }
        if (ti && ti->byte_size > 0) {
            if (ti->byte_size > 8) {
                pending_implicit_bytes_ = bytes;
                push(value);
                return;
            }
            if (ti->is_integer || ti->is_boolean || ti->is_address) {
                value = ti->is_signed ? signExtendBytes(value, ti->byte_size)
                                      : maskToBytes(value, ti->byte_size);
            } else {
                value = maskToBytes(value, ti->byte_size);
            }
            bytes = lowBytesForResultValue(value, ti->byte_size);
        }
    }

    push(value);
    pending_implicit_bytes_ = std::move(bytes);
}

void ExpressionEvaluator::handleRegvalType(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t reg_num = readULEB128(offset, expression);
    uint64_t type_offset = readULEB128(offset, expression);
    uint64_t abs_type_offset = (type_offset == 0) ? 0 : (context_.cu_base_offset + type_offset);

    // Get the register value and push it
    // The type information determines how to interpret the value
    uint64_t value = 0;
    if (reg_num < registers_.size()) {
        value = registers_[reg_num];
    }

    if (context_.resolve_base_type) {
        auto ti = context_.resolve_base_type(abs_type_offset);
        if (type_offset != 0 && !ti) {
            setExecutionError("DW_OP_regval_type could not resolve referenced base type");
            return;
        }
        if (ti && ti->byte_size > 0) {
            if (ti->byte_size > 8) {
                setExecutionError("DW_OP_regval_type does not support base types wider than 8 bytes");
                return;
            }
            if (ti->is_integer || ti->is_boolean || ti->is_address) {
                value = ti->is_signed ? signExtendBytes(value, ti->byte_size)
                                      : maskToBytes(value, ti->byte_size);
            } else {
                value = maskToBytes(value, ti->byte_size);
            }
            pending_implicit_bytes_ = lowBytesForResultValue(value, ti->byte_size);
        }
    }

    push(value);
}

void ExpressionEvaluator::handleDerefType(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // 1-byte size of the value to be dereferenced
    uint8_t size = readU8(offset, expression);
    // ULEB128 type die offset
    uint64_t type_offset = readULEB128(offset, expression);
    uint64_t abs_type_offset = (type_offset == 0) ? 0 : (context_.cu_base_offset + type_offset);

    if (!requireStack(1, "DW_OP_deref_type")) return;
    uint64_t addr = pop();

    // Dereference 'size' bytes from memory
    if (memory_context_) {
        std::vector<uint8_t> buf(size);
        if (memory_context_->readMemory(addr, size, buf.data())) {
            uint64_t value = decodeU64FromBytes(buf.data(), size, DwarfUtils::objectIsLittleEndian());
            if (context_.resolve_base_type) {
                auto ti = context_.resolve_base_type(abs_type_offset);
                if (type_offset != 0 && !ti) {
                    setExecutionError("DW_OP_deref_type could not resolve referenced base type");
                    return;
                }
                if (ti && ti->byte_size > 0) {
                    if (ti->byte_size > 8) {
                        setExecutionError("DW_OP_deref_type does not support base types wider than 8 bytes");
                        return;
                    }
                    if (ti->is_integer || ti->is_boolean || ti->is_address) {
                        value = ti->is_signed ? signExtendBytes(value, ti->byte_size)
                                              : maskToBytes(value, ti->byte_size);
                    } else {
                        value = maskToBytes(value, ti->byte_size);
                    }
                    buf = lowBytesForResultValue(value, ti->byte_size);
                }
            }
            push(value);
            pending_implicit_bytes_ = std::move(buf);
        } else {
            setExecutionError("DW_OP_deref_type memory read failed");
        }
    } else {
        setExecutionError("DW_OP_deref_type requires memory context");
    }
}

void ExpressionEvaluator::handleXderefType(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // 1-byte size
    uint8_t size = readU8(offset, expression);
    // ULEB128 type die offset
    uint64_t type_offset = readULEB128(offset, expression);
    uint64_t abs_type_offset = (type_offset == 0) ? 0 : (context_.cu_base_offset + type_offset);

    if (!requireStack(2, "DW_OP_xderef_type")) return;
    uint64_t addr = pop();
    uint64_t space = pop();  // Address space (ignored in basic implementation)
    DWARF_UNUSED(space);

    if (memory_context_) {
        std::vector<uint8_t> buf(size);
        if (memory_context_->readMemory(addr, size, buf.data())) {
            uint64_t value = decodeU64FromBytes(buf.data(), size, DwarfUtils::objectIsLittleEndian());
            if (context_.resolve_base_type) {
                auto ti = context_.resolve_base_type(abs_type_offset);
                if (type_offset != 0 && !ti) {
                    setExecutionError("DW_OP_xderef_type could not resolve referenced base type");
                    return;
                }
                if (ti && ti->byte_size > 0) {
                    if (ti->byte_size > 8) {
                        setExecutionError("DW_OP_xderef_type does not support base types wider than 8 bytes");
                        return;
                    }
                    if (ti->is_integer || ti->is_boolean || ti->is_address) {
                        value = ti->is_signed ? signExtendBytes(value, ti->byte_size)
                                              : maskToBytes(value, ti->byte_size);
                    } else {
                        value = maskToBytes(value, ti->byte_size);
                    }
                    buf = lowBytesForResultValue(value, ti->byte_size);
                }
            }
            push(value);
            pending_implicit_bytes_ = std::move(buf);
        } else {
            setExecutionError("DW_OP_xderef_type memory read failed");
        }
    } else {
        setExecutionError("DW_OP_xderef_type requires memory context");
    }
}

void ExpressionEvaluator::handleConvert(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t type_offset = readULEB128(offset, expression);
    uint64_t abs_type_offset = (type_offset == 0) ? 0 : (context_.cu_base_offset + type_offset);

    if (!requireStack(1, "DW_OP_convert")) return;
    uint64_t value = pop();

    if (type_offset != 0 && context_.resolve_base_type) {
        auto ti = context_.resolve_base_type(abs_type_offset);
        if (!ti) {
            setExecutionError("DW_OP_convert could not resolve referenced base type");
            return;
        }
        if (ti->byte_size > 0) {
            if (ti->byte_size > 8) {
                setExecutionError("DW_OP_convert does not support base types wider than 8 bytes");
                return;
            }
            if (ti->is_integer || ti->is_boolean || ti->is_address) {
                value = ti->is_signed ? signExtendBytes(value, ti->byte_size)
                                      : maskToBytes(value, ti->byte_size);
            } else {
                value = maskToBytes(value, ti->byte_size);
            }
            pending_implicit_bytes_ = lowBytesForResultValue(value, ti->byte_size);
        }
    }
    push(value);
}

void ExpressionEvaluator::handleReinterpret(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t type_offset = readULEB128(offset, expression);
    uint64_t abs_type_offset = (type_offset == 0) ? 0 : (context_.cu_base_offset + type_offset);

    if (!requireStack(1, "DW_OP_reinterpret")) return;
    uint64_t value = pop();

    if (type_offset != 0 && context_.resolve_base_type) {
        auto ti = context_.resolve_base_type(abs_type_offset);
        if (!ti) {
            setExecutionError("DW_OP_reinterpret could not resolve referenced base type");
            return;
        }
        if (ti->byte_size > 0) {
            if (ti->byte_size > 8) {
                setExecutionError("DW_OP_reinterpret does not support base types wider than 8 bytes");
                return;
            }
            value = maskToBytes(value, ti->byte_size);
            pending_implicit_bytes_ = lowBytesForResultValue(value, ti->byte_size);
        }
    }
    push(value);
}

// Call operations - call a DWARF procedure (DIE with location expression)
void ExpressionEvaluator::handleCall2(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint16_t die_offset = readU16(offset, expression);
    if (!context_.resolve_dwarf_procedure) {
        (void)die_offset;
        return;
    }
    uint64_t abs_off = context_.cu_base_offset + static_cast<uint64_t>(die_offset);
    auto expr = context_.resolve_dwarf_procedure(abs_off, pc_);
    if (!expr) return;
    if (!executeInPlace(*expr)) {
        if (execution_error_) {
            execution_error_message_ = std::string("DW_OP_call2 subexpression failed: ") + execution_error_message_;
        } else {
            setExecutionError("DW_OP_call2 subexpression failed");
        }
    }
}

void ExpressionEvaluator::handleCall4(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint32_t die_offset = readU32(offset, expression);
    if (!context_.resolve_dwarf_procedure) {
        (void)die_offset;
        return;
    }
    uint64_t abs_off = context_.cu_base_offset + static_cast<uint64_t>(die_offset);
    auto expr = context_.resolve_dwarf_procedure(abs_off, pc_);
    if (!expr) return;
    if (!executeInPlace(*expr)) {
        if (execution_error_) {
            execution_error_message_ = std::string("DW_OP_call4 subexpression failed: ") + execution_error_message_;
        } else {
            setExecutionError("DW_OP_call4 subexpression failed");
        }
    }
}

void ExpressionEvaluator::handleCallRef(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t die_offset = readOffsetSized(offset, expression);
    if (execution_error_) return;
    if (!context_.resolve_dwarf_procedure) {
        (void)die_offset;
        return;
    }
    // DW_OP_call_ref uses a reference that is an absolute section offset (not CU-relative).
    // Preserve any DWO/supplementary bias from cu_base_offset so lookups work with biased DIE caches.
    uint64_t abs_off = dwarfSectionOffsetBias(context_.cu_base_offset) + die_offset;
    auto expr = context_.resolve_dwarf_procedure(abs_off, pc_);
    if (!expr) return;
    if (!executeInPlace(*expr)) {
        if (execution_error_) {
            execution_error_message_ = std::string("DW_OP_call_ref subexpression failed: ") + execution_error_message_;
        } else {
            setExecutionError("DW_OP_call_ref subexpression failed");
        }
    }
}

// TLS operations
void ExpressionEvaluator::handleFormTlsAddress(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!requireStack(1, "DW_OP_form_tls_address")) return;
    uint64_t tls_offset = pop();

    // DW_OP_form_tls_address pops a TLS offset from the stack and pushes
    // the actual address of the thread-local variable.
    // The caller must provide the TLS base for the current thread.
    push(context_.tls_base + tls_offset);
}

// GNU Extensions
void ExpressionEvaluator::handleGnuPushTlsAddress(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_GNU_push_tls_address is equivalent to DW_OP_form_tls_address
    // It's the GNU extension that was standardized in DWARF 4
    handleFormTlsAddress(offset, expression);
}

void ExpressionEvaluator::handleGnuUninit(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    // DW_OP_GNU_uninit indicates the value is uninitialized
    // This taints the current expression result without changing the stack.
    uninitialized_taint_ = true;
}

void ExpressionEvaluator::handleGnuEncodedAddr(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_GNU_encoded_addr reads an encoded address
    // The encoding is specified by a one-byte value
    if (offset >= expression.size()) {
        setExecutionError("Truncated DW_OP_GNU_encoded_addr");
        return;
    }
    uint8_t encoding = readU8(offset, expression);

    constexpr uint8_t kFmtMask = 0x0f;
    constexpr uint8_t kAppMask = 0x70;
    constexpr uint8_t kIndMask = 0x80;

    if ((encoding & kAppMask) == 0x50) {
        size_t align = pointerByteSize("DW_OP_GNU_encoded_addr(aligned)");
        if (execution_error_) return;
        offset = alignOffsetUp(offset, align);
    }

    auto readEncoded = [&](uint8_t fmt) -> uint64_t {
        switch (fmt) {
            case 0x00: { // absptr
                return readAddressSized(offset, expression);
            }
            case 0x01: // uleb128
                return readULEB128(offset, expression);
            case 0x02: // udata2
                return readU16(offset, expression);
            case 0x03: // udata4
                return readU32(offset, expression);
            case 0x04: // udata8
                return readU64(offset, expression);
            case 0x09: // sleb128
                return static_cast<uint64_t>(readSLEB128(offset, expression));
            case 0x0a: { // sdata2
                int16_t v = static_cast<int16_t>(readU16(offset, expression));
                return static_cast<uint64_t>(static_cast<int64_t>(v));
            }
            case 0x0b: { // sdata4
                int32_t v = static_cast<int32_t>(readU32(offset, expression));
                return static_cast<uint64_t>(static_cast<int64_t>(v));
            }
            case 0x0c: { // sdata8
                int64_t v = static_cast<int64_t>(readU64(offset, expression));
                return static_cast<uint64_t>(v);
            }
            default:
                setExecutionError("DW_OP_GNU_encoded_addr uses unsupported encoding format");
                return 0;
        }
    };

    uint64_t raw = readEncoded(encoding & kFmtMask);
    if (execution_error_) return;
    uint64_t addr = raw;

    // Apply relative adjustments.
    switch (encoding & kAppMask) {
        case 0x00: // absolute
            break;
        case 0x10: // pcrel
            addr = pc_ + raw;
            break;
        case 0x20: // textrel
            addr = context_.text_base + raw;
            break;
        case 0x30: // datarel
            addr = context_.data_base + raw;
            break;
        case 0x40: // funcrel
            addr = context_.function_base + raw;
            break;
        case 0x50: // aligned
            break;
        default:
            setExecutionError("DW_OP_GNU_encoded_addr uses unsupported application mode");
            return;
    }

    if ((encoding & kIndMask) != 0) {
        if (!memory_context_) {
            setExecutionError("DW_OP_GNU_encoded_addr indirect requires memory context");
            return;
        }
        size_t n = pointerByteSize("DW_OP_GNU_encoded_addr");
        if (execution_error_) return;
        std::vector<uint8_t> buf(n);
        if (memory_context_->readMemory(addr, n, buf.data())) {
            addr = decodeU64FromBytes(buf.data(), n, DwarfUtils::objectIsLittleEndian());
        } else {
            setExecutionError("DW_OP_GNU_encoded_addr indirect memory read failed");
            return;
        }
    }

    push(addr);
}

void ExpressionEvaluator::handleGnuImplicitPointer(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_GNU_implicit_pointer is the predecessor to DW_OP_implicit_pointer
    // Same semantics as DW_OP_implicit_pointer.
    handleImplicitPointer(offset, expression);
}

void ExpressionEvaluator::handleGnuEntryValue(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_GNU_entry_value is the predecessor to DW_OP_entry_value
    // Same semantics - evaluate with entry-time register values
    handleEntryValue(offset, expression);
}

void ExpressionEvaluator::handleGnuConstType(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_GNU_const_type is the predecessor to DW_OP_const_type
    handleConstType(offset, expression);
}

void ExpressionEvaluator::handleGnuRegvalType(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_GNU_regval_type is the predecessor to DW_OP_regval_type
    handleRegvalType(offset, expression);
}

void ExpressionEvaluator::handleGnuDerefType(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_GNU_deref_type is the predecessor to DW_OP_deref_type
    handleDerefType(offset, expression);
}

void ExpressionEvaluator::handleGnuConvert(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_GNU_convert is the predecessor to DW_OP_convert
    handleConvert(offset, expression);
}

void ExpressionEvaluator::handleGnuReinterpret(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_GNU_reinterpret is the predecessor to DW_OP_reinterpret
    handleReinterpret(offset, expression);
}

void ExpressionEvaluator::handleGnuParameterRef(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_GNU_parameter_ref references a formal parameter DIE
    // to describe where an optimized-out parameter's value was passed
    uint64_t die_offset = readOffsetSized(offset, expression);
    if (execution_error_) return;

    // GNU parameter ref uses a section-relative DIE reference (not CU-relative).
    // Preserve any DWO/supplementary bias from cu_base_offset so lookups work with biased DIE caches.
    uint64_t abs_die_offset = dwarfSectionOffsetBias(context_.cu_base_offset) + die_offset;

    if (!context_.resolve_dwarf_procedure) {
        setExecutionError("DW_OP_GNU_parameter_ref requires DIE resolver");
        return;
    }

    auto proc = context_.resolve_dwarf_procedure(abs_die_offset, pc_);
    if (!proc) {
        setExecutionError("DW_OP_GNU_parameter_ref referent not found");
        return;
    }

    // Evaluate the referenced DIE's location expression. This opcode is often used
    // to recover optimized-out parameter values.
    ExpressionEvaluator sub(memory_context_);
    sub.setContext(context_);
    ExpressionResult r = sub.evaluate(*proc, context_, pc_, registers_);
    uninitialized_taint_ = uninitialized_taint_ || r.uninitialized;

    uint64_t value = 0;
    std::optional<std::vector<uint8_t>> materialized_bytes;
    if (!materializeResultAsValue(r, registers_, "DW_OP_GNU_parameter_ref",
                                  value, materialized_bytes)) {
        return;
    }
    push(value);
    is_implicit_value_ = true;
    pending_implicit_bytes_ = std::move(materialized_bytes);
}

void ExpressionEvaluator::handleGnuAddrIndex(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_GNU_addr_index is the predecessor to DW_OP_addrx
    handleAddrx(offset, expression);
}

void ExpressionEvaluator::handleGnuConstIndex(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_GNU_const_index is the predecessor to DW_OP_constx
    handleConstx(offset, expression);
}

void ExpressionEvaluator::handleWasmLocation(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // WebAssembly extension opcode:
    //   u8 wasm_location_type, and for kinds [0..2] a ULEB index.
    // We represent this as a synthetic register-location namespace:
    //   bits[63:56]=kind, bits[55:0]=index.
    if (offset >= expression.size()) {
        setExecutionError("truncated DW_OP_WASM_location");
        return;
    }

    uint8_t kind = readU8(offset, expression);
    uint64_t index = 0;
    if (kind <= 0x02) {
        index = readULEB128(offset, expression);
        if (execution_error_) return;
    }

    uint64_t encoded = (static_cast<uint64_t>(kind) << 56) |
                       (index & 0x00ffffffffffffffULL);
    push(encoded);
    is_register_location_ = true;
}

// Helper methods
uint64_t ExpressionEvaluator::readULEB128(uint64_t& offset, const std::vector<uint8_t>& data) const {
    if (offset >= data.size()) {
        setExecutionError("truncated uleb128");
        return 0;
    }

    uint64_t result = 0;
    uint64_t shift = 0;
    while (true) {
        if (offset >= data.size()) {
            setExecutionError("truncated uleb128");
            return result;
        }
        uint8_t byte = data[offset++];
        if (shift > 63 || (shift == 63 && (byte & 0x7f) > 1)) {
            setExecutionError("uleb128 overflow");
            return result;
        }
        result |= (static_cast<uint64_t>(byte & 0x7f) << shift);
        if ((byte & 0x80) == 0) break;
        shift += 7;
    }
    return result;
}

int64_t ExpressionEvaluator::readSLEB128(uint64_t& offset, const std::vector<uint8_t>& data) const {
    if (offset >= data.size()) {
        setExecutionError("truncated sleb128");
        return 0;
    }

    int64_t result = 0;
    int shift = 0;
    uint8_t byte = 0;
    while (true) {
        if (offset >= data.size()) {
            setExecutionError("truncated sleb128");
            return result;
        }
        byte = data[offset++];
        if (shift > 63 || (shift == 63 && (byte & 0x7f) != 0 && (byte & 0x7f) != 0x7f)) {
            setExecutionError("sleb128 overflow");
            return result;
        }
        result |= (static_cast<int64_t>(byte & 0x7f) << shift);
        shift += 7;
        if ((byte & 0x80) == 0) break;
    }
    if ((shift < 64) && (byte & 0x40)) {
        result |= -(static_cast<int64_t>(1) << shift);
    }
    return result;
}

uint8_t ExpressionEvaluator::readU8(uint64_t& offset, const std::vector<uint8_t>& data) const {
    uint64_t avail = (offset <= data.size()) ? (data.size() - offset) : 0;
    if (avail < 1) {
        setExecutionError("truncated u8");
        offset = data.size();
        return 0;
    }
    return DwarfUtils::readU8(data.data(), offset, data.size());
}

uint16_t ExpressionEvaluator::readU16(uint64_t& offset, const std::vector<uint8_t>& data) const {
    uint64_t avail = (offset <= data.size()) ? (data.size() - offset) : 0;
    if (avail < 2) {
        setExecutionError("truncated u16");
        offset = data.size();
        return 0;
    }
    return DwarfUtils::readU16(data.data(), offset, data.size());
}

uint32_t ExpressionEvaluator::readU32(uint64_t& offset, const std::vector<uint8_t>& data) const {
    uint64_t avail = (offset <= data.size()) ? (data.size() - offset) : 0;
    if (avail < 4) {
        setExecutionError("truncated u32");
        offset = data.size();
        return 0;
    }
    return DwarfUtils::readU32(data.data(), offset, data.size());
}

uint64_t ExpressionEvaluator::readU64(uint64_t& offset, const std::vector<uint8_t>& data) const {
    uint64_t avail = (offset <= data.size()) ? (data.size() - offset) : 0;
    if (avail < 8) {
        setExecutionError("truncated u64");
        offset = data.size();
        return 0;
    }
    return DwarfUtils::readU64(data.data(), offset, data.size());
}

uint64_t ExpressionEvaluator::readAddressSized(uint64_t& offset, const std::vector<uint8_t>& data) const {
    if (context_.address_size == 4) return readU32(offset, data);
    if (context_.address_size == 8) return readU64(offset, data);
    setExecutionError("invalid address_size");
    return 0;
}

uint64_t ExpressionEvaluator::readOffsetSized(uint64_t& offset, const std::vector<uint8_t>& data) const {
    if (context_.offset_size == 4) return readU32(offset, data);
    if (context_.offset_size == 8) return readU64(offset, data);
    setExecutionError("invalid offset_size");
    return 0;
}

size_t ExpressionEvaluator::pointerByteSize(const char* op_name) const {
    if (context_.address_size == 4) return 4;
    if (context_.address_size == 8) return 8;
    setExecutionError(std::string("invalid address_size in ") + op_name);
    return 0;
}

} // namespace dwarf
