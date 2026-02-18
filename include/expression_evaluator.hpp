#pragma once

#include "dwarf_types.hpp"
#include <vector>
#include <stack>
#include <memory>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace dwarf {

// Simple memory context interface for expression evaluation
class MemoryContext {
public:
    virtual ~MemoryContext() = default;
    virtual bool readMemory(uint64_t address, size_t size, void* buffer) const = 0;
    virtual bool writeMemory(uint64_t address, size_t size, const void* buffer) = 0;
};

// Default memory context that always fails
class DefaultMemoryContext : public MemoryContext {
public:
    bool readMemory(uint64_t address, size_t size, void* buffer) const override {
        (void)address;
        (void)size;
        (void)buffer;
        // Default implementation always fails
        return false;
    }

    bool writeMemory(uint64_t address, size_t size, const void* buffer) override {
        (void)address;
        (void)size;
        (void)buffer;
        // Default implementation always fails
        return false;
    }
};

// Evaluation context for providing runtime information to the expression evaluator
struct EvaluationContext {
    // Frame information
    uint64_t frame_base = 0;           // From DW_AT_frame_base evaluation
    uint64_t cfa = 0;                  // Canonical Frame Address from CFI
    uint64_t object_address = 0;       // Object address for DW_OP_push_object_address
    uint64_t tls_base = 0;             // Thread-local storage base for DW_OP_form_tls_address

    // DWARF 5 address table (debug_addr section)
    const std::vector<uint64_t>* debug_addr_table = nullptr;
    uint64_t addr_base = 0;            // Base offset in debug_addr

    // Entry values (for DW_OP_entry_value)
    std::vector<uint64_t> entry_registers;

    // Unit information
    uint8_t address_size = 8;          // Target address size in bytes (4 or 8 typically)
    uint8_t offset_size = 4;           // DWARF DIE reference size in bytes (4 for DWARF32, 8 for DWARF64)
    uint64_t cu_base_offset = 0;       // CU header start offset in DIE offset space (bias-aware)

    struct BaseTypeInfo {
        uint64_t byte_size = 0;
        bool is_integer = false;
        bool is_signed = false;
        DW_ATE encoding = DW_ATE::DW_ATE_unsigned;
    };

    // Optional callbacks to make certain ops (typed ops, DW_OP_call*) meaningful.
    std::function<std::optional<BaseTypeInfo>(uint64_t /*type_die_offset*/)> resolve_base_type;
    std::function<std::optional<std::vector<uint8_t>>(uint64_t /*die_offset*/, uint64_t /*pc*/)> resolve_dwarf_procedure;

    // Default constructor
    EvaluationContext() = default;
};

// Piece descriptor for composite location descriptions
struct PieceDescriptor {
    enum Kind {
        MEMORY,     // Value at memory address
        REGISTER,   // Value in register
        IMPLICIT,   // Implicit value (from stack)
        EMPTY       // Undefined piece
    } kind = EMPTY;

    uint64_t location = 0;      // Address or register number
    uint64_t byte_size = 0;     // Size in bytes (for DW_OP_piece)
    uint64_t bit_size = 0;      // Size in bits (for DW_OP_bit_piece)
    uint64_t bit_offset = 0;    // Bit offset within location
    std::vector<uint8_t> implicit_value;  // For DW_OP_implicit_value

    PieceDescriptor() = default;
};

// Expression evaluation result
struct ExpressionResult {
    enum Type {
        ADDRESS,        // Single memory address
        VALUE,          // Implicit value (not in memory)
        REGISTER,       // Value in a register
        COMPOSITE,      // Multiple pieces
        INVALID
    };

    Type type;
    uint64_t value;
    std::string description;
    std::vector<PieceDescriptor> pieces;  // For COMPOSITE type

    ExpressionResult(Type t, uint64_t v, const std::string& desc = "")
        : type(t), value(v), description(desc) {}

    ExpressionResult(const std::vector<PieceDescriptor>& p, const std::string& desc = "")
        : type(COMPOSITE), value(0), description(desc), pieces(p) {}
};

// Expression evaluator for DWARF location expressions
class ExpressionEvaluator {
public:
    ExpressionEvaluator(std::shared_ptr<MemoryContext> memory_context = nullptr);

    // Main evaluation method
    ExpressionResult evaluate(const std::vector<uint8_t>& expression,
                             uint64_t pc = 0,
                             const std::vector<uint64_t>& registers = {});

    // Extended evaluation method with full context
    ExpressionResult evaluate(const std::vector<uint8_t>& expression,
                             const EvaluationContext& context,
                             uint64_t pc = 0,
                             const std::vector<uint64_t>& registers = {});

    // Set evaluation context
    void setContext(const EvaluationContext& context);

    // Set memory context
    void setMemoryContext(std::shared_ptr<MemoryContext> memory_context);

    // Access to pieces for composite locations
    const std::vector<PieceDescriptor>& getPieces() const { return pieces_; }
    bool hasMultiplePieces() const { return pieces_.size() > 1; }
    
    // Stack operations
    void push(uint64_t value);
    uint64_t pop();
    uint64_t top() const;
    bool empty() const;
    size_t size() const;
    
    // Debugging
    void printStack() const;
    std::string expressionToString(const std::vector<uint8_t>& expression) const;
    
private:
    std::stack<uint64_t> stack_;
    uint64_t pc_;
    std::vector<uint64_t> registers_;
    std::shared_ptr<MemoryContext> memory_context_;
    EvaluationContext context_;
    std::vector<PieceDescriptor> pieces_;
    bool is_register_location_ = false;  // True if result is register, not address
    bool is_implicit_value_ = false;      // True if result is a value, not a location
    // For DW_OP_implicit_value (and stack_value + piece), track the bytes representing
    // the current implicit value so DW_OP_piece/DW_OP_bit_piece can emit IMPLICIT pieces.
    std::optional<std::vector<uint8_t>> pending_implicit_bytes_;
    int call_depth_ = 0;
    
    // Operation handlers
    void handleAddr(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleDeref(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleConst1u(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleConst1s(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleConst2u(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleConst2s(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleConst4u(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleConst4s(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleConst8u(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleConst8s(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleConstu(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleConsts(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleDup(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleDrop(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleOver(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handlePick(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleSwap(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleRot(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleXderef(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleAbs(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleAnd(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleDiv(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleMinus(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleMod(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleMul(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleNeg(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleNot(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleOr(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handlePlus(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handlePlusUconst(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleShl(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleShr(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleShra(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleXor(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleBra(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleEq(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleGe(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleGt(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleLe(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleLt(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleNe(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleSkip(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleLit(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleReg(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleBreg(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleRegx(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleFbreg(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleBregx(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handlePiece(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleDerefSize(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleXderefSize(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleNop(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handlePushObjectAddress(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleCallFrameCfa(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleBitPiece(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleImplicitValue(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleStackValue(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleImplicitPointer(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleAddrx(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleConstx(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleEntryValue(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleConstType(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleRegvalType(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleDerefType(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleXderefType(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleConvert(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleReinterpret(uint64_t& offset, const std::vector<uint8_t>& expression);

    // Call operations
    void handleCall2(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleCall4(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleCallRef(uint64_t& offset, const std::vector<uint8_t>& expression);

    // TLS operations
    void handleFormTlsAddress(uint64_t& offset, const std::vector<uint8_t>& expression);

    // GNU Extensions
    void handleGnuPushTlsAddress(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleGnuUninit(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleGnuEncodedAddr(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleGnuImplicitPointer(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleGnuEntryValue(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleGnuConstType(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleGnuRegvalType(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleGnuDerefType(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleGnuConvert(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleGnuReinterpret(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleGnuParameterRef(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleGnuAddrIndex(uint64_t& offset, const std::vector<uint8_t>& expression);
    void handleGnuConstIndex(uint64_t& offset, const std::vector<uint8_t>& expression);

    // Helper methods
    uint64_t readULEB128(uint64_t& offset, const std::vector<uint8_t>& data) const;
    int64_t readSLEB128(uint64_t& offset, const std::vector<uint8_t>& data) const;
    uint8_t readU8(uint64_t& offset, const std::vector<uint8_t>& data) const;
    uint16_t readU16(uint64_t& offset, const std::vector<uint8_t>& data) const;
    uint32_t readU32(uint64_t& offset, const std::vector<uint8_t>& data) const;
    uint64_t readU64(uint64_t& offset, const std::vector<uint8_t>& data) const;

    bool executeInPlace(const std::vector<uint8_t>& expression);
    
    // Operation dispatch
    using OpHandler = void (ExpressionEvaluator::*)(uint64_t&, const std::vector<uint8_t>&);
    std::map<DwarfOp, OpHandler> op_handlers_;
    void initializeOpHandlers();
};

} // namespace dwarf
