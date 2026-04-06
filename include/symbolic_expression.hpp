#pragma once

#include "expression_evaluator.hpp"
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace dwarf {

// A small symbolic term language suitable for representing DWARF stack-machine results.
// This is intentionally minimal: it is meant for debugging/inspection, not SMT completeness.
struct SymExpr;
using SymExprPtr = std::shared_ptr<const SymExpr>;

struct SymExpr {
    enum class Kind {
        CONST_U64,
        BYTES,       // Raw byte literal value (used when value does not fit u64)
        VAR,         // Named variable (e.g. "reg31", "frame_base", "cfa", "tls_base")
        ADD,
        SUB,
        MUL,
        DIV,
        MOD,
        AND,
        OR,
        XOR,
        SHL,
        SHR,
        SHRA,
        NEG,
        NOT,
        ABS,
        EQ,
        NE,
        LT,
        LE,
        GT,
        GE,
        ITE,         // ite(cond, then_value, else_value)
        LOAD,        // load(addr, size_bytes)
        MASK,        // maskN(x) - keep low N bytes
        SEXT,        // sextN(x) - sign-extend from N bytes
        UNKNOWN
    };

    Kind kind = Kind::UNKNOWN;
    uint64_t const_u64 = 0;
    uint64_t aux_bytes = 0; // Used by LOAD/MASK/SEXT
    std::vector<uint8_t> raw_bytes; // Used by BYTES
    std::string name;
    std::vector<SymExprPtr> args;

    static SymExprPtr makeConst(uint64_t v);
    static SymExprPtr makeBytes(std::vector<uint8_t> bytes);
    static SymExprPtr makeVar(std::string n);
    static SymExprPtr makeUnknown(std::string why);
    static SymExprPtr makeUnary(Kind k, SymExprPtr a);
    static SymExprPtr makeBinary(Kind k, SymExprPtr a, SymExprPtr b);
    static SymExprPtr makeITE(SymExprPtr cond, SymExprPtr t, SymExprPtr f);
    static SymExprPtr makeLoad(SymExprPtr addr, uint64_t size_bytes);
    static SymExprPtr makeMask(SymExprPtr v, uint64_t size_bytes);
    static SymExprPtr makeSExt(SymExprPtr v, uint64_t size_bytes);

    // Best-effort string form, stable enough to be used in tests.
    std::string toString() const;
};

struct SymPiece {
    enum class Kind { MEMORY, REGISTER, IMPLICIT, EMPTY } kind = Kind::EMPTY;
    // address expression for MEMORY, const(reg) for REGISTER.
    // For IMPLICIT, this may carry a symbolic value term when merged across branches.
    SymExprPtr location;
    uint64_t byte_size = 0;
    uint64_t bit_size = 0;
    uint64_t bit_offset = 0;
    std::vector<uint8_t> implicit_bytes;
};

struct SymbolicExpressionResult {
    enum class Type { ADDRESS, VALUE, REGISTER, COMPOSITE, INVALID };
    Type type = Type::INVALID;

    // For ADDRESS/VALUE: expression is the result term.
    // For REGISTER: expression is const(regnum) (location form).
    SymExprPtr expression;

    // For COMPOSITE:
    std::vector<SymPiece> pieces;

    std::string error;
    bool uninitialized = false;
    std::optional<uint8_t> unsupported_opcode;
    bool unsupported_vendor_extension = false;

    SymbolicExpressionResult() = default;
    SymbolicExpressionResult(Type t,
                             SymExprPtr expr,
                             std::vector<SymPiece> pcs,
                             std::string err,
                             bool uninit = false,
                             std::optional<uint8_t> unsupported = std::nullopt,
                             bool vendor_extension = false)
        : type(t),
          expression(std::move(expr)),
          pieces(std::move(pcs)),
          error(std::move(err)),
          uninitialized(uninit),
          unsupported_opcode(unsupported),
          unsupported_vendor_extension(vendor_extension) {}
};

enum class SymStackValueKind {
    ADDRESS,
    VALUE,
    REGISTER
};

class SymbolicExpressionEvaluator {
public:
    SymbolicExpressionEvaluator() = default;

    SymbolicExpressionResult evaluate(const std::vector<uint8_t>& expr,
                                      const EvaluationContext& ctx,
                                      uint64_t pc = 0,
                                      const std::vector<uint64_t>& regs = {});

private:
    uint64_t pc_ = 0;
    EvaluationContext ctx_;
    std::vector<uint64_t> regs_;
    int call_depth_ = 0;
    int branch_depth_ = 0;

    std::vector<SymExprPtr> stack_;
    std::vector<SymStackValueKind> stack_kinds_;
    std::vector<std::optional<std::vector<uint8_t>>> stack_implicit_bytes_;
    std::vector<SymPiece> pieces_;
    bool uninitialized_taint_ = false;

    SymExprPtr pop();
    SymExprPtr top() const;
    SymStackValueKind topKind() const;
    std::optional<std::vector<uint8_t>> topImplicitBytes() const;
    void setTopKind(SymStackValueKind kind);
    void push(SymExprPtr v, SymStackValueKind kind = SymStackValueKind::ADDRESS);
    void pushWithImplicitBytes(SymExprPtr v, std::vector<uint8_t> bytes,
                               SymStackValueKind kind = SymStackValueKind::VALUE);

    SymExprPtr regValueExpr(uint64_t regnum) const;
    SymExprPtr materializeForComputation(const SymExprPtr& v, SymStackValueKind kind) const;
    SymExprPtr frameBaseExpr() const;
    SymExprPtr cfaExpr() const;
    SymExprPtr tlsBaseExpr() const;
    SymExprPtr objectAddrExpr() const;

    SymbolicExpressionResult evaluateFromOffset(const std::vector<uint8_t>& expr, uint64_t start_off);
    bool executeProcedureSubexprInPlace(const std::vector<uint8_t>& subexpr);
    std::optional<SymbolicExpressionResult> handleVendorProfileOpcode(uint8_t opcode,
                                                                      const std::vector<uint8_t>& expr,
                                                                      uint64_t& off);
    SymbolicExpressionResult evalEntryValueSubexpr(const std::vector<uint8_t>& subexpr);
    SymbolicExpressionResult materializeResultAsValue(const SymbolicExpressionResult& result,
                                                      const std::vector<uint64_t>& register_bank,
                                                      const char* op_name) const;
    std::string diagnosticContextSuffix() const;
    void appendDiagnosticContext(SymbolicExpressionResult& result) const;
};

} // namespace dwarf
