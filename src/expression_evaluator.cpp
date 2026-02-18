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
        } else {
            return ExpressionResult(ExpressionResult::INVALID, 0,
                                    std::string("Unsupported operation: ") +
                                        DwarfUtils::operationToString(op) +
                                        " at offset " + std::to_string(op_off));
        }
    }

    // Check if we have multiple pieces
    if (!pieces_.empty()) {
        return ExpressionResult(pieces_, "Composite location with " +
                               std::to_string(pieces_.size()) + " pieces");
    }

    if (stack_.empty()) {
        return ExpressionResult(ExpressionResult::INVALID, 0, "Empty stack");
    }

    uint64_t result = stack_.top();

    if (is_register_location_) {
        return ExpressionResult(ExpressionResult::REGISTER, result,
                               "Register: " + std::to_string(result));
    }

    if (is_implicit_value_) {
        return ExpressionResult(ExpressionResult::VALUE, result,
                               "Value: " + std::to_string(result));
    }

    return ExpressionResult(ExpressionResult::ADDRESS, result, "Address: 0x" +
                           DwarfUtils::formatAddress(result, true));
}

bool ExpressionEvaluator::executeInPlace(const std::vector<uint8_t>& expression) {
    if (expression.empty()) return true;

    constexpr int kMaxCallDepth = 16;
    if (call_depth_ >= kMaxCallDepth) {
        return false;
    }
    ++call_depth_;

    uint64_t offset = 0;
    bool ok = true;
    size_t steps = 0;
    const size_t max_steps = std::max<size_t>(1024, expression.size() * 16);
    while (offset < expression.size()) {
        if (++steps > max_steps) {
            ok = false;
            break;
        }
        uint8_t opcode = readU8(offset, expression);
        DwarfOp op = static_cast<DwarfOp>(opcode);

        auto handler_it = op_handlers_.find(op);
        if (handler_it != op_handlers_.end()) {
            (this->*handler_it->second)(offset, expression);
        } else {
            ok = false;
            break;
        }
    }

    --call_depth_;
    return ok;
}

void ExpressionEvaluator::push(uint64_t value) {
    stack_.push(value);
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
            case DwarfOp::DW_OP_consts:
                if (offset < expression.size()) {
                    uint64_t val = readULEB128(offset, expression);
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
    uint64_t addr = 0;
    if (context_.address_size == 4) {
        addr = readU32(offset, expression);
    } else {
        addr = readU64(offset, expression);
    }
    push(addr);
}

void ExpressionEvaluator::handleDeref(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 1) return;
    uint64_t addr = pop();
    
    if (memory_context_) {
        size_t n = (context_.address_size == 4) ? 4 : 8;
        std::vector<uint8_t> buf(n);
        if (memory_context_->readMemory(addr, n, buf.data())) {
            push(decodeU64FromBytes(buf.data(), n, DwarfUtils::objectIsLittleEndian()));
        } else {
            push(addr); // Fallback to address if read fails
        }
    } else {
        push(addr); // No memory context available
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
    if (stack_.size() < 1) return;
    uint64_t val = stack_.top();
    push(val);
}

void ExpressionEvaluator::handleDrop(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (!stack_.empty()) {
        stack_.pop();
    }
}

void ExpressionEvaluator::handleOver(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
    uint64_t val1 = pop();
    uint64_t val2 = pop();
    push(val2);
    push(val1);
    push(val2);
}

void ExpressionEvaluator::handlePick(uint64_t& offset, const std::vector<uint8_t>& expression) {
    if (stack_.size() < 1) return;
    uint8_t index = readU8(offset, expression);
    if (index >= stack_.size()) return;
    
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
    if (stack_.size() < 2) return;
    uint64_t val1 = pop();
    uint64_t val2 = pop();
    push(val1);
    push(val2);
}

void ExpressionEvaluator::handleRot(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 3) return;
    uint64_t val1 = pop();
    uint64_t val2 = pop();
    uint64_t val3 = pop();
    push(val1);
    push(val3);
    push(val2);
}

void ExpressionEvaluator::handleXderef(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
    uint64_t addr = pop();
    uint64_t space = pop();
    DWARF_UNUSED(space);
    
    if (memory_context_) {
        size_t n = (context_.address_size == 4) ? 4 : 8;
        std::vector<uint8_t> buf(n);
        if (memory_context_->readMemory(addr, n, buf.data())) {
            push(decodeU64FromBytes(buf.data(), n, DwarfUtils::objectIsLittleEndian()));
        } else {
            push(addr); // Fallback to address if read fails
        }
    } else {
        push(addr); // No memory context available
    }
}

void ExpressionEvaluator::handleAbs(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 1) return;
    int64_t val = static_cast<int64_t>(pop());
    push(static_cast<uint64_t>(val < 0 ? -val : val));
}

void ExpressionEvaluator::handleAnd(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 & val2);
}

void ExpressionEvaluator::handleDiv(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
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
    if (stack_.size() < 2) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 - val2);
}

void ExpressionEvaluator::handleMod(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
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
    if (stack_.size() < 2) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 * val2);
}

void ExpressionEvaluator::handleNeg(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 1) return;
    uint64_t val = pop();
    push(-val);
}

void ExpressionEvaluator::handleNot(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 1) return;
    uint64_t val = pop();
    push(~val);
}

void ExpressionEvaluator::handleOr(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 | val2);
}

void ExpressionEvaluator::handlePlus(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 + val2);
}

void ExpressionEvaluator::handlePlusUconst(uint64_t& offset, const std::vector<uint8_t>& expression) {
    if (stack_.size() < 1) return;
    uint64_t val = pop();
    uint64_t uconst = readULEB128(offset, expression);
    push(val + uconst);
}

void ExpressionEvaluator::handleShl(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 << val2);
}

void ExpressionEvaluator::handleShr(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 >> val2);
}

void ExpressionEvaluator::handleShra(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
    uint64_t val2 = pop();
    int64_t val1 = static_cast<int64_t>(pop());
    push(static_cast<uint64_t>(val1 >> val2));
}

void ExpressionEvaluator::handleXor(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 ^ val2);
}

void ExpressionEvaluator::handleBra(uint64_t& offset, const std::vector<uint8_t>& expression) {
    if (stack_.size() < 1) return;
    uint64_t condition = pop();
    int16_t target = static_cast<int16_t>(readU16(offset, expression));
    if (condition != 0) {
        int64_t base = static_cast<int64_t>(offset);
        int64_t next = base + static_cast<int64_t>(target);
        offset = (next < 0) ? 0 : static_cast<uint64_t>(next);
    }
}

void ExpressionEvaluator::handleEq(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 == val2 ? 1 : 0);
}

void ExpressionEvaluator::handleGe(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 >= val2 ? 1 : 0);
}

void ExpressionEvaluator::handleGt(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 > val2 ? 1 : 0);
}

void ExpressionEvaluator::handleLe(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 <= val2 ? 1 : 0);
}

void ExpressionEvaluator::handleLt(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 < val2 ? 1 : 0);
}

void ExpressionEvaluator::handleNe(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 2) return;
    uint64_t val2 = pop();
    uint64_t val1 = pop();
    push(val1 != val2 ? 1 : 0);
}

void ExpressionEvaluator::handleSkip(uint64_t& offset, const std::vector<uint8_t>& expression) {
    int16_t target = static_cast<int16_t>(readU16(offset, expression));
    int64_t base = static_cast<int64_t>(offset);
    int64_t next = base + static_cast<int64_t>(target);
    offset = (next < 0) ? 0 : static_cast<uint64_t>(next);
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
                } else if (piece.implicit_value.size() < byte_size) {
                    piece.implicit_value.resize(byte_size, 0);
                }
            } else {
                piece.implicit_value = encodeU64ToBytes(v,
                                                       static_cast<size_t>(std::min<uint64_t>(byte_size, 8)),
                                                       DwarfUtils::objectIsLittleEndian());
                // If the requested piece is larger than 8 bytes but we don't have explicit bytes,
                // best-effort: pad with zeros.
                if (piece.implicit_value.size() < byte_size) {
                    piece.implicit_value.resize(byte_size, 0);
                }
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
    if (stack_.size() < 1) return;
    uint8_t size = readU8(offset, expression);
    uint64_t addr = pop();
    
    // In a real implementation, this would dereference memory with the given size
    // For now, we simulate by checking if we have a memory context
    if (memory_context_) {
        std::vector<uint8_t> buf(size);
        if (memory_context_->readMemory(addr, size, buf.data())) {
            push(decodeU64FromBytes(buf.data(), size, DwarfUtils::objectIsLittleEndian()));
        } else {
            push(addr); // Fallback to address if read fails
        }
    } else {
        push(addr); // No memory context available
    }
}

void ExpressionEvaluator::handleXderefSize(uint64_t& offset, const std::vector<uint8_t>& expression) {
    if (stack_.size() < 2) return;
    uint8_t size = readU8(offset, expression);
    uint64_t addr = pop();
    uint64_t space = pop();
    DWARF_UNUSED(space);
    
    // In a real implementation, this would dereference memory in the given address space
    // For now, we simulate by checking if we have a memory context
    if (memory_context_) {
        std::vector<uint8_t> buf(size);
        if (memory_context_->readMemory(addr, size, buf.data())) {
            push(decodeU64FromBytes(buf.data(), size, DwarfUtils::objectIsLittleEndian()));
        } else {
            push(addr); // Fallback to address if read fails
        }
    } else {
        push(addr); // No memory context available
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
                } else if (piece.implicit_value.size() < piece.byte_size) {
                    piece.implicit_value.resize(piece.byte_size, 0);
                }
            } else {
                piece.implicit_value = encodeU64ToBytes(v,
                                                       static_cast<size_t>(std::min<uint64_t>(piece.byte_size, 8)),
                                                       DwarfUtils::objectIsLittleEndian());
                if (piece.implicit_value.size() < piece.byte_size) {
                    piece.implicit_value.resize(piece.byte_size, 0);
                }
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
    // DW_OP_implicit_value specifies that the object's value is embedded
    // directly in the DWARF expression, not in memory or a register.
    if (offset > expression.size() || size > expression.size() - offset) {
        // Malformed expression; don't read past the end.
        push(0);
        is_implicit_value_ = true;
        pending_implicit_bytes_ = std::vector<uint8_t>{};
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
    // DW_OP_stack_value specifies that the object does not exist in memory
    // but its value is still on the stack. The debugger should use the value
    // directly rather than treating it as a memory address.
    is_implicit_value_ = true;
}

void ExpressionEvaluator::handleImplicitPointer(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t die_offset = 0;
    if (context_.offset_size == 8) {
        die_offset = readU64(offset, expression);
    } else {
        die_offset = readU32(offset, expression);
    }
    int64_t offset_val = readSLEB128(offset, expression);

    // DW_OP_implicit_pointer yields an address computed from another DIE's location
    // plus a constant offset.
    // The DIE reference is a section-relative offset (like DW_FORM_ref_addr), not CU-relative.
    uint64_t abs_die_offset = dwarfSectionOffsetBias(context_.cu_base_offset) + die_offset;

    if (!context_.resolve_dwarf_procedure) {
        // Best-effort fallback: push the referenced DIE offset (as a "pointer") plus offset.
        push(addSignedOffset(abs_die_offset, offset_val));
        return;
    }

    auto proc = context_.resolve_dwarf_procedure(abs_die_offset, pc_);
    if (!proc) {
        push(0);
        return;
    }

    ExpressionEvaluator sub(memory_context_);
    sub.setContext(context_);
    ExpressionResult r = sub.evaluate(*proc, context_, pc_, registers_);

    if (r.type == ExpressionResult::ADDRESS) {
        push(addSignedOffset(r.value, offset_val));
        return;
    }

    // If we can't derive an address, return 0 as an "unknown pointer".
    push(0);
}

void ExpressionEvaluator::handleAddrx(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t index = readULEB128(offset, expression);

    // Look up address in debug_addr_table using addr_base
    if (context_.debug_addr_table && index < context_.debug_addr_table->size()) {
        uint64_t address = (*context_.debug_addr_table)[index];
        push(address);
    } else {
        // Fallback: use index as offset from addr_base
        push(context_.addr_base + (index * context_.address_size));
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
        push(index);  // Fallback
    }
}

void ExpressionEvaluator::handleEntryValue(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t size = readULEB128(offset, expression);

    if (offset > expression.size() || size > expression.size() - offset) {
        // Malformed expression; don't read past the end.
        push(0);
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

    if (result.type != ExpressionResult::INVALID) {
        push(result.value);
    } else {
        push(0);  // Fallback
    }
}

void ExpressionEvaluator::handleConstType(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // ULEB128 type die offset (reference to base type)
    uint64_t type_offset = readULEB128(offset, expression);
    uint64_t abs_type_offset = (type_offset == 0) ? 0 : (context_.cu_base_offset + type_offset);
    // 1-byte size of the constant value
    uint8_t size = readU8(offset, expression);

    if (offset > expression.size() || static_cast<uint64_t>(size) > expression.size() - offset) {
        push(0);
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

    // Best-effort type-aware normalization for integer base types.
    if (context_.resolve_base_type) {
        auto ti = context_.resolve_base_type(abs_type_offset);
        if (ti && ti->byte_size > 0 && ti->byte_size <= 8) {
            if (ti->is_integer) {
                value = ti->is_signed ? signExtendBytes(value, ti->byte_size)
                                      : maskToBytes(value, ti->byte_size);
            } else {
                value = maskToBytes(value, ti->byte_size);
            }
        }
    }

    push(value);
    // Preserve the raw bytes so stack_value + piece can emit correct IMPLICIT pieces.
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
        if (ti && ti->byte_size > 0 && ti->byte_size <= 8) {
            if (ti->is_integer) {
                value = ti->is_signed ? signExtendBytes(value, ti->byte_size)
                                      : maskToBytes(value, ti->byte_size);
            } else {
                value = maskToBytes(value, ti->byte_size);
            }
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

    if (stack_.size() < 1) return;
    uint64_t addr = pop();

    // Dereference 'size' bytes from memory
    if (memory_context_) {
        std::vector<uint8_t> buf(size);
        if (memory_context_->readMemory(addr, size, buf.data())) {
            uint64_t value = decodeU64FromBytes(buf.data(), size, DwarfUtils::objectIsLittleEndian());
            if (context_.resolve_base_type) {
                auto ti = context_.resolve_base_type(abs_type_offset);
                if (ti && ti->byte_size > 0 && ti->byte_size <= 8) {
                    if (ti->is_integer) {
                        value = ti->is_signed ? signExtendBytes(value, ti->byte_size)
                                              : maskToBytes(value, ti->byte_size);
                    } else {
                        value = maskToBytes(value, ti->byte_size);
                    }
                }
            }
            push(value);
        } else {
            push(addr);  // Fallback
        }
    } else {
        push(addr);
    }
}

void ExpressionEvaluator::handleXderefType(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // 1-byte size
    uint8_t size = readU8(offset, expression);
    // ULEB128 type die offset
    uint64_t type_offset = readULEB128(offset, expression);
    uint64_t abs_type_offset = (type_offset == 0) ? 0 : (context_.cu_base_offset + type_offset);

    if (stack_.size() < 2) return;
    uint64_t addr = pop();
    uint64_t space = pop();  // Address space (ignored in basic implementation)
    DWARF_UNUSED(space);

    if (memory_context_) {
        std::vector<uint8_t> buf(size);
        if (memory_context_->readMemory(addr, size, buf.data())) {
            uint64_t value = decodeU64FromBytes(buf.data(), size, DwarfUtils::objectIsLittleEndian());
            if (context_.resolve_base_type) {
                auto ti = context_.resolve_base_type(abs_type_offset);
                if (ti && ti->byte_size > 0 && ti->byte_size <= 8) {
                    if (ti->is_integer) {
                        value = ti->is_signed ? signExtendBytes(value, ti->byte_size)
                                              : maskToBytes(value, ti->byte_size);
                    } else {
                        value = maskToBytes(value, ti->byte_size);
                    }
                }
            }
            push(value);
        } else {
            push(addr);
        }
    } else {
        push(addr);
    }
}

void ExpressionEvaluator::handleConvert(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t type_offset = readULEB128(offset, expression);
    uint64_t abs_type_offset = (type_offset == 0) ? 0 : (context_.cu_base_offset + type_offset);

    if (stack_.size() < 1) return;
    uint64_t value = pop();

    // type_offset of 0 means convert to generic type (untyped)
    // In a full implementation, we would look up the type and apply conversions
    // For now, just push the value back (no conversion without type info)
    if (type_offset != 0 && context_.resolve_base_type) {
        auto ti = context_.resolve_base_type(abs_type_offset);
        if (ti && ti->byte_size > 0 && ti->byte_size <= 8) {
            if (ti->is_integer) {
                value = ti->is_signed ? signExtendBytes(value, ti->byte_size)
                                      : maskToBytes(value, ti->byte_size);
            } else {
                value = maskToBytes(value, ti->byte_size);
            }
        }
    }
    push(value);
}

void ExpressionEvaluator::handleReinterpret(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t type_offset = readULEB128(offset, expression);
    uint64_t abs_type_offset = (type_offset == 0) ? 0 : (context_.cu_base_offset + type_offset);

    if (stack_.size() < 1) return;
    uint64_t value = pop();

    // Reinterpret: same bits, different type interpretation
    // Unlike convert, this doesn't change the bit representation
    // Just push the value as-is (the type info is metadata)
    if (type_offset != 0 && context_.resolve_base_type) {
        auto ti = context_.resolve_base_type(abs_type_offset);
        if (ti && ti->byte_size > 0 && ti->byte_size <= 8) {
            value = maskToBytes(value, ti->byte_size);
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
    (void)executeInPlace(*expr);
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
    (void)executeInPlace(*expr);
}

void ExpressionEvaluator::handleCallRef(uint64_t& offset, const std::vector<uint8_t>& expression) {
    uint64_t die_offset = 0;
    if (context_.offset_size == 8) {
        die_offset = readU64(offset, expression);
    } else {
        die_offset = readU32(offset, expression);
    }
    if (!context_.resolve_dwarf_procedure) {
        (void)die_offset;
        return;
    }
    // DW_OP_call_ref uses a reference that is an absolute section offset (not CU-relative).
    // Preserve any DWO/supplementary bias from cu_base_offset so lookups work with biased DIE caches.
    uint64_t abs_off = dwarfSectionOffsetBias(context_.cu_base_offset) + die_offset;
    auto expr = context_.resolve_dwarf_procedure(abs_off, pc_);
    if (!expr) return;
    (void)executeInPlace(*expr);
}

// TLS operations
void ExpressionEvaluator::handleFormTlsAddress(uint64_t& offset, const std::vector<uint8_t>& expression) {
    DWARF_UNUSED(offset);
    DWARF_UNUSED(expression);
    if (stack_.size() < 1) return;
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
    // This is informational - doesn't change the stack
}

void ExpressionEvaluator::handleGnuEncodedAddr(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_GNU_encoded_addr reads an encoded address
    // The encoding is specified by a one-byte value
    if (offset >= expression.size()) return;
    uint8_t encoding = readU8(offset, expression);

    // Encoding follows the DW_EH_PE_* scheme (as used by GCC).
    // We implement the common subset needed in practice:
    // - formats: absptr/udata{2,4,8}/sdata{2,4,8}/uleb128/sleb128
    // - application: absolute/pcrel
    // - indirect: ignored (best-effort)
    constexpr uint8_t kFmtMask = 0x0f;
    constexpr uint8_t kAppMask = 0x70;
    constexpr uint8_t kIndMask = 0x80;

    auto readEncoded = [&](uint8_t fmt) -> uint64_t {
        switch (fmt) {
            case 0x00: { // absptr
                if (context_.address_size == 4) return readU32(offset, expression);
                return readU64(offset, expression);
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
                // Unknown/unsupported, best-effort: treat as absptr.
                if (context_.address_size == 4) return readU32(offset, expression);
                return readU64(offset, expression);
        }
    };

    uint64_t raw = readEncoded(encoding & kFmtMask);
    uint64_t addr = raw;

    // Apply relative adjustments.
    switch (encoding & kAppMask) {
        case 0x00: // absolute
            break;
        case 0x10: // pcrel
            addr = pc_ + raw;
            break;
        default:
            // Other bases (datarel/textrel/funcrel/aligned) need more context.
            break;
    }

    // If indirect is set, the value is the address of the address.
    // Without a stronger memory model, we best-effort dereference pointer-sized.
    if ((encoding & kIndMask) && memory_context_) {
        size_t n = (context_.address_size == 4) ? 4 : 8;
        std::vector<uint8_t> buf(n);
        if (memory_context_->readMemory(addr, n, buf.data())) {
            addr = decodeU64FromBytes(buf.data(), n, DwarfUtils::objectIsLittleEndian());
        }
    }

    push(addr);
}

void ExpressionEvaluator::handleGnuImplicitPointer(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_GNU_implicit_pointer is the predecessor to DW_OP_implicit_pointer
    // Same format: DIE offset (4 bytes in 32-bit, 8 in 64-bit) + SLEB128 offset
    uint64_t die_offset = 0;
    if (context_.offset_size == 8) {
        die_offset = readU64(offset, expression);
    } else {
        die_offset = readU32(offset, expression);
    }
    int64_t offset_val = readSLEB128(offset, expression);

    // GNU predecessor to DW_OP_implicit_pointer: same semantics.
    uint64_t abs_die_offset = dwarfSectionOffsetBias(context_.cu_base_offset) + die_offset;

    if (!context_.resolve_dwarf_procedure) {
        push(addSignedOffset(abs_die_offset, offset_val));
        return;
    }

    auto proc = context_.resolve_dwarf_procedure(abs_die_offset, pc_);
    if (!proc) {
        push(0);
        return;
    }

    ExpressionEvaluator sub(memory_context_);
    sub.setContext(context_);
    ExpressionResult r = sub.evaluate(*proc, context_, pc_, registers_);
    if (r.type == ExpressionResult::ADDRESS) {
        push(addSignedOffset(r.value, offset_val));
        return;
    }

    push(0);
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
    uint64_t die_offset = 0;
    if (context_.offset_size == 8) {
        die_offset = readU64(offset, expression);
    } else {
        die_offset = readU32(offset, expression);
    }

    // GNU parameter ref uses a section-relative DIE reference (not CU-relative).
    // Preserve any DWO/supplementary bias from cu_base_offset so lookups work with biased DIE caches.
    uint64_t abs_die_offset = dwarfSectionOffsetBias(context_.cu_base_offset) + die_offset;

    if (!context_.resolve_dwarf_procedure) {
        // Best-effort fallback: push the referenced DIE offset as a stand-in.
        push(abs_die_offset);
        return;
    }

    auto proc = context_.resolve_dwarf_procedure(abs_die_offset, pc_);
    if (!proc) {
        push(0);
        return;
    }

    // Evaluate the referenced DIE's location expression. This opcode is often used
    // to recover optimized-out parameter values.
    ExpressionEvaluator sub(memory_context_);
    sub.setContext(context_);
    ExpressionResult r = sub.evaluate(*proc, context_, pc_, registers_);

    switch (r.type) {
        case ExpressionResult::ADDRESS:
        case ExpressionResult::VALUE:
            push(r.value);
            return;
        case ExpressionResult::REGISTER:
            if (r.value < registers_.size()) {
                push(registers_[static_cast<size_t>(r.value)]);
            } else {
                push(0);
            }
            return;
        default:
            push(0);
            return;
    }
}

void ExpressionEvaluator::handleGnuAddrIndex(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_GNU_addr_index is the predecessor to DW_OP_addrx
    handleAddrx(offset, expression);
}

void ExpressionEvaluator::handleGnuConstIndex(uint64_t& offset, const std::vector<uint8_t>& expression) {
    // DW_OP_GNU_const_index is the predecessor to DW_OP_constx
    handleConstx(offset, expression);
}

// Helper methods
uint64_t ExpressionEvaluator::readULEB128(uint64_t& offset, const std::vector<uint8_t>& data) const {
    return DwarfUtils::readULEB128(data.data(), offset, data.size());
}

int64_t ExpressionEvaluator::readSLEB128(uint64_t& offset, const std::vector<uint8_t>& data) const {
    return DwarfUtils::readSLEB128(data.data(), offset, data.size());
}

uint8_t ExpressionEvaluator::readU8(uint64_t& offset, const std::vector<uint8_t>& data) const {
    return DwarfUtils::readU8(data.data(), offset, data.size());
}

uint16_t ExpressionEvaluator::readU16(uint64_t& offset, const std::vector<uint8_t>& data) const {
    return DwarfUtils::readU16(data.data(), offset, data.size());
}

uint32_t ExpressionEvaluator::readU32(uint64_t& offset, const std::vector<uint8_t>& data) const {
    return DwarfUtils::readU32(data.data(), offset, data.size());
}

uint64_t ExpressionEvaluator::readU64(uint64_t& offset, const std::vector<uint8_t>& data) const {
    return DwarfUtils::readU64(data.data(), offset, data.size());
}

} // namespace dwarf
