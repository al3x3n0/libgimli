#include "dwarf_parser.hpp"
#include "type_system.hpp"
#include "expression_evaluator.hpp"
#include "symbolic_expression.hpp"
#include "symbolic_verifier.hpp"
#include "expression_compare.hpp"
#include "dwarf_utils.hpp"
#include "rnglists_parser.hpp"
#include "loclists_parser.hpp"
#include "split_dwarf.hpp"
#include "die_parser.hpp"
#include "attribute_parser.hpp"
#include "debug_sup_parser.hpp"
#include "debug_names_parser.hpp"
#include "debug_macro_parser.hpp"
#include "call_stack.hpp"
#include "cfi_symbolic.hpp"
#include <iostream>
#include <cassert>
#include <cstring>
#include <filesystem>
#include <random>
#include <unordered_map>

using namespace dwarf;

static void appendU64(std::vector<uint8_t>& out, uint64_t v);
static void appendU32(std::vector<uint8_t>& out, uint32_t v);
static void appendU16(std::vector<uint8_t>& out, uint16_t v);
static void appendULEB(std::vector<uint8_t>& out, uint64_t v);

void testDwarfUtils() {
    std::cout << "Testing DwarfUtils..." << std::endl;

    // Test tag conversion
    assert(DwarfUtils::tagToString(DwarfTag::DW_TAG_compile_unit) == "DW_TAG_compile_unit");
    assert(DwarfUtils::tagToString(DwarfTag::DW_TAG_subprogram) == "DW_TAG_subprogram");

    // Test attribute conversion
    assert(DwarfUtils::attributeToString(DwarfAttribute::DW_AT_name) == "DW_AT_name");
    assert(DwarfUtils::attributeToString(DwarfAttribute::DW_AT_type) == "DW_AT_type");
    assert(DwarfUtils::stringToAttribute("DW_AT_name") == DwarfAttribute::DW_AT_name);

    // Test form conversion
    assert(DwarfUtils::formToString(DwarfForm::DW_FORM_strp) == "DW_FORM_strp");
    assert(DwarfUtils::stringToForm("DW_FORM_strp") == DwarfForm::DW_FORM_strp);

    // Test operation conversion
    assert(DwarfUtils::operationToString(DwarfOp::DW_OP_const1u) == "DW_OP_const1u");
    assert(DwarfUtils::stringToOperation("DW_OP_const1u") == DwarfOp::DW_OP_const1u);

    // Test size helpers are linkable and plausible
    {
        uint8_t bytes[] = {0x7f}; // ULEB128 127
        size_t sz = DwarfUtils::getFormSize(DwarfForm::DW_FORM_udata, bytes, 0, 1);
        assert(sz == 1);
    }
    {
        uint8_t expr[] = {static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x2a};
        size_t opsz = DwarfUtils::getOperationSize(DwarfOp::DW_OP_const1u, expr, 1, 2);
        assert(opsz == 1);
        auto asm_s = DwarfUtils::expressionToAssembly(std::vector<uint8_t>(expr, expr + 2));
        assert(!asm_s.empty());
    }

    // Test type utilities
    assert(DwarfUtils::isTypeTag(DwarfTag::DW_TAG_base_type));
    assert(DwarfUtils::isTypeTag(DwarfTag::DW_TAG_pointer_type));
    assert(!DwarfUtils::isTypeTag(DwarfTag::DW_TAG_subprogram));

    assert(DwarfUtils::isSubprogramTag(DwarfTag::DW_TAG_subprogram));
    assert(!DwarfUtils::isSubprogramTag(DwarfTag::DW_TAG_base_type));

    assert(DwarfUtils::isVariableTag(DwarfTag::DW_TAG_variable));
    assert(DwarfUtils::isVariableTag(DwarfTag::DW_TAG_formal_parameter));
    assert(!DwarfUtils::isVariableTag(DwarfTag::DW_TAG_base_type));

    // Test range helper functions
    std::vector<DwarfUtils::AddressRange> ranges = {
        {0x1000, 0x2000, false},
        {0x3000, 0x4000, false},
        {0x5000, 0x6000, false}
    };

    // Test isAddressInRanges
    assert(DwarfUtils::isAddressInRanges(0x1500, ranges));
    assert(DwarfUtils::isAddressInRanges(0x3500, ranges));
    assert(!DwarfUtils::isAddressInRanges(0x2500, ranges));  // In gap
    assert(!DwarfUtils::isAddressInRanges(0x0500, ranges));  // Before first
    assert(!DwarfUtils::isAddressInRanges(0x7000, ranges));  // After last

    // Test getRangesContainingAddress
    auto containing = DwarfUtils::getRangesContainingAddress(0x1500, ranges);
    assert(containing.size() == 1);
    assert(containing[0].start == 0x1000);

    // Test with overlapping ranges
    std::vector<DwarfUtils::AddressRange> overlapping = {
        {0x1000, 0x3000, false},
        {0x2000, 0x4000, false},
        {0x5000, 0x6000, false}
    };

    // Address in overlap should be in multiple ranges
    auto multiple = DwarfUtils::getRangesContainingAddress(0x2500, overlapping);
    assert(multiple.size() == 2);

    // Test mergeOverlappingRanges
    auto merged = DwarfUtils::mergeOverlappingRanges(overlapping);
    assert(merged.size() == 2);  // Two merged ranges: [0x1000-0x4000] and [0x5000-0x6000]
    assert(merged[0].start == 0x1000);
    assert(merged[0].end == 0x4000);
    assert(merged[1].start == 0x5000);
    assert(merged[1].end == 0x6000);

    // Test getTotalRangeSize
    uint64_t total_size = DwarfUtils::getTotalRangeSize(overlapping);
    assert(total_size == (0x4000 - 0x1000) + (0x6000 - 0x5000));  // 0x3000 + 0x1000 = 0x4000

    // Test isContinuousRange
    assert(!DwarfUtils::isContinuousRange(ranges));  // Has gaps

    std::vector<DwarfUtils::AddressRange> continuous = {
        {0x1000, 0x2000, false},
        {0x2000, 0x3000, false}  // Adjacent (continuous)
    };
    assert(DwarfUtils::isContinuousRange(continuous));

    // Test getBoundingRange
    auto bounding = DwarfUtils::getBoundingRange(ranges);
    assert(bounding.start == 0x1000);
    assert(bounding.end == 0x6000);

    std::cout << "DwarfUtils tests passed!" << std::endl;
}

void testExpressionEvaluator() {
    std::cout << "Testing ExpressionEvaluator..." << std::endl;
    
    ExpressionEvaluator evaluator;
    
    // Test simple constant
    std::vector<uint8_t> expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        42, 0, 0, 0  // 42 in little-endian
    };
    
    auto result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 42);
    
    // Test addition
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        10, 0, 0, 0,
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        32, 0, 0, 0,
        static_cast<uint8_t>(DwarfOp::DW_OP_plus)
    };
    
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 42);
    
    // Test stack operations
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        5, 0, 0, 0,
        static_cast<uint8_t>(DwarfOp::DW_OP_dup)
    };
    
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 5);
    assert(evaluator.size() == 2); // Should have 2 values on stack

    // Stack reorder ops sanity: rot should map (1,2,3) -> (2,3,1), so top is 1.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x01,
        static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x02,
        static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x03,
        static_cast<uint8_t>(DwarfOp::DW_OP_rot),
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::VALUE);
    assert(result.value == 1);

    // Test DW_OP_stack_value (should return VALUE type instead of ADDRESS)
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        100, 0, 0, 0,  // 100 in little-endian
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
    };

    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::VALUE);
    assert(result.value == 100);

    // Test DW_OP_stack_value on a register location converts it to register VALUE.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_reg0),
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
    };
    result = evaluator.evaluate(expression, /*pc=*/0, /*registers=*/{0x12345678});
    assert(result.type == ExpressionResult::VALUE);
    assert(result.value == 0x12345678);

    // Test DW_OP_stack_value + DW_OP_piece from register location emits IMPLICIT piece bytes.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_reg0),
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        static_cast<uint8_t>(DwarfOp::DW_OP_piece),
        0x01, // piece size = 1 byte
    };
    result = evaluator.evaluate(expression, /*pc=*/0, /*registers=*/{0x12345678});
    assert(result.type == ExpressionResult::COMPOSITE);
    assert(result.pieces.size() == 1);
    assert(result.pieces[0].kind == PieceDescriptor::IMPLICIT);
    assert(result.pieces[0].implicit_value.size() == 1);
    assert(result.pieces[0].implicit_value[0] == 0x78);

    // Malformed stack_value with empty stack should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("DW_OP_stack_value") != std::string::npos);

    // Malformed plus_uconst with empty stack should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_plus_uconst),
        0x01
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("DW_OP_plus_uconst") != std::string::npos);

    // Malformed bra with empty stack should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_bra),
        0x00, 0x00
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("DW_OP_bra") != std::string::npos);

    // Malformed plus with empty stack should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_plus)
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("DW_OP_plus") != std::string::npos);

    // Malformed drop with empty stack should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_drop)
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("DW_OP_drop") != std::string::npos);

    // Malformed pick with out-of-range index should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const1u),
        0x2a,
        static_cast<uint8_t>(DwarfOp::DW_OP_pick),
        0x01
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("DW_OP_pick") != std::string::npos);

    // Malformed deref with empty stack should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_deref)
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("DW_OP_deref") != std::string::npos);

    // Malformed form_tls_address with empty stack should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_form_tls_address)
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("DW_OP_form_tls_address") != std::string::npos);

    // Truncated fixed-width operand should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        0x11, 0x22, 0x33 // missing one byte
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("truncated u32") != std::string::npos);

    // Truncated branch displacement operand should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const1u),
        0x01,
        static_cast<uint8_t>(DwarfOp::DW_OP_bra),
        0x10 // missing 2nd byte
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("truncated u16") != std::string::npos);

    // Truncated ULEB128 operand should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const1u),
        0x01,
        static_cast<uint8_t>(DwarfOp::DW_OP_plus_uconst),
        0x80 // continuation without terminator
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("truncated uleb128") != std::string::npos);

    // Overflow ULEB128 operand should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const1u),
        0x01,
        static_cast<uint8_t>(DwarfOp::DW_OP_plus_uconst),
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("uleb128 overflow") != std::string::npos);

    // Truncated SLEB128 operand should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_fbreg),
        0x80 // continuation without terminator
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("truncated sleb128") != std::string::npos);

    // Overflow SLEB128 operand should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_bregx),
        0x00, // register 0
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("sleb128 overflow") != std::string::npos);

    // Invalid address_size for DW_OP_addr should be INVALID.
    {
        EvaluationContext bad_addr_ctx;
        bad_addr_ctx.address_size = 3;
        expression = {
            static_cast<uint8_t>(DwarfOp::DW_OP_addr),
            0x00, 0x00, 0x00, 0x00
        };
        result = evaluator.evaluate(expression, bad_addr_ctx);
        assert(result.type == ExpressionResult::INVALID);
        assert(result.description.find("invalid address_size") != std::string::npos);
    }

    // Invalid offset_size for DW_OP_call_ref should be INVALID.
    {
        EvaluationContext bad_off_ctx;
        bad_off_ctx.offset_size = 3;
        expression = {
            static_cast<uint8_t>(DwarfOp::DW_OP_call_ref),
            0x00, 0x00, 0x00, 0x00
        };
        result = evaluator.evaluate(expression, bad_off_ctx);
        assert(result.type == ExpressionResult::INVALID);
        assert(result.description.find("invalid offset_size") != std::string::npos);
    }

    // Truncated DW_OP_implicit_value payload should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value),
        0x02, // size = 2
        0x11  // missing one byte
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("DW_OP_implicit_value") != std::string::npos);

    // Truncated DW_OP_entry_value subexpression should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_entry_value),
        0x02, // subexpr size = 2
        static_cast<uint8_t>(DwarfOp::DW_OP_lit1) // only 1 byte present
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("DW_OP_entry_value") != std::string::npos);

    // Truncated DW_OP_const_type payload should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const_type),
        0x00, // type offset
        0x02, // size = 2
        0x11  // missing one byte
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("DW_OP_const_type") != std::string::npos);

    // Out-of-range DW_OP_skip target should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_skip),
        0x01, 0x00 // jump past end
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("DW_OP_skip target out of range") != std::string::npos);

    // Out-of-range taken DW_OP_bra target should be INVALID.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const1u),
        0x01, // condition true
        static_cast<uint8_t>(DwarfOp::DW_OP_bra),
        0x7f, 0x00 // jump far past end
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("DW_OP_bra target out of range") != std::string::npos);

    // Malformed DW_OP_call2 subexpression failure should be INVALID (not silently ignored).
    EvaluationContext bad_call_ctx;
    bad_call_ctx.cu_base_offset = 0;
    bad_call_ctx.resolve_dwarf_procedure = [](uint64_t die_offset, uint64_t pc) -> std::optional<std::vector<uint8_t>> {
        (void)pc;
        if (die_offset != 0x33) return std::nullopt;
        return std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_plus)}; // underflow in callee
    };
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_call2),
        0x33, 0x00
    };
    result = evaluator.evaluate(expression, bad_call_ctx);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("DW_OP_call2") != std::string::npos);

    // Unsupported opcode inside DW_OP_call2 subexpression should surface as INVALID.
    bad_call_ctx.resolve_dwarf_procedure = [](uint64_t die_offset, uint64_t pc) -> std::optional<std::vector<uint8_t>> {
        (void)pc;
        if (die_offset != 0x34) return std::nullopt;
        return std::vector<uint8_t>{0xff}; // unsupported opcode in callee
    };
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_call2),
        0x34, 0x00
    };
    result = evaluator.evaluate(expression, bad_call_ctx);
    assert(result.type == ExpressionResult::INVALID);
    assert(result.description.find("DW_OP_call2") != std::string::npos);
    assert(result.description.find("Unsupported operation") != std::string::npos);

    // Test DW_OP_implicit_value (should return VALUE type)
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value),
        4,  // size = 4 bytes
        0x78, 0x56, 0x34, 0x12  // value = 0x12345678
    };

    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::VALUE);
    assert(result.value == 0x12345678);

    // Test register location (DW_OP_reg0)
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_reg0)
    };

    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::REGISTER);
    assert(result.value == 0);

    // Test DW_OP_fbreg with context
    EvaluationContext ctx;
    ctx.frame_base = 0x7fff0000;

    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_fbreg),
        0x10  // offset = 16 (SLEB128)
    };

    result = evaluator.evaluate(expression, ctx);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 0x7fff0010);

    // Test DW_OP_call_frame_cfa with context
    ctx.cfa = 0x7fff1000;

    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_call_frame_cfa)
    };

    result = evaluator.evaluate(expression, ctx);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 0x7fff1000);

    // Test DW_OP_piece (composite location)
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_reg0),
        static_cast<uint8_t>(DwarfOp::DW_OP_piece),
        4,  // 4 bytes
        static_cast<uint8_t>(DwarfOp::DW_OP_reg1),
        static_cast<uint8_t>(DwarfOp::DW_OP_piece),
        4   // 4 bytes
    };

    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::COMPOSITE);
    assert(result.pieces.size() == 2);
    assert(result.pieces[0].kind == PieceDescriptor::REGISTER);
    assert(result.pieces[0].location == 0);
    assert(result.pieces[0].byte_size == 4);
    assert(result.pieces[1].kind == PieceDescriptor::REGISTER);
    assert(result.pieces[1].location == 1);

    // Test DW_OP_breg with registers
    std::vector<uint64_t> registers(32, 0);
    registers[6] = 0x7fff0000;  // rbp = 0x7fff0000

    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_breg6),
        0x10  // offset = 16 (positive SLEB128)
    };

    result = evaluator.evaluate(expression, EvaluationContext{}, 0, registers);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 0x7fff0010);

    // Test DW_OP_breg with negative SLEB128 offset (-16 == 0x70)
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_breg6),
        0x70
    };
    result = evaluator.evaluate(expression, EvaluationContext{}, 0, registers);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 0x7ffefff0);

    // Test DW_OP_fbreg with negative SLEB128 offset
    EvaluationContext ctx_neg;
    ctx_neg.frame_base = 0x7fff0000;
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_fbreg),
        0x70
    };
    result = evaluator.evaluate(expression, ctx_neg);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 0x7ffefff0);

    // Test DW_OP_addr and DW_OP_deref operand sizing for 32-bit address size.
    class MapMemoryContext final : public MemoryContext {
    public:
        void setBytes(uint64_t address, const std::vector<uint8_t>& bytes) {
            mem_[address] = bytes;
        }

        void setU32(uint64_t address, uint32_t value) {
            uint8_t b[4] = {
                static_cast<uint8_t>(value & 0xff),
                static_cast<uint8_t>((value >> 8) & 0xff),
                static_cast<uint8_t>((value >> 16) & 0xff),
                static_cast<uint8_t>((value >> 24) & 0xff),
            };
            mem_[address] = std::vector<uint8_t>(b, b + 4);
        }

        bool readMemory(uint64_t address, size_t size, void* buffer) const override {
            auto it = mem_.find(address);
            if (it == mem_.end() || !buffer) return false;
            if (it->second.size() < size) return false;
            std::memcpy(buffer, it->second.data(), size);
            return true;
        }

        bool writeMemory(uint64_t address, size_t size, const void* buffer) override {
            (void)address; (void)size; (void)buffer;
            return false;
        }

    private:
        std::unordered_map<uint64_t, std::vector<uint8_t>> mem_;
    };

    auto mem = std::make_shared<MapMemoryContext>();
    mem->setU32(0x1000, 0x12345678);
    ExpressionEvaluator eval_mem(mem);

    EvaluationContext ctx32;
    ctx32.address_size = 4;
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_addr),
        0x00, 0x10, 0x00, 0x00, // 0x1000 (4-byte address)
        static_cast<uint8_t>(DwarfOp::DW_OP_deref)
    };
    result = eval_mem.evaluate(expression, ctx32);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 0x12345678);

    // Test DW_OP_deref_size (read N bytes, little-endian)
    mem->setBytes(0x3000, {0x78, 0x56, 0x34, 0x12, 0xAA});
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_addr),
        0x00, 0x30, 0x00, 0x00, // 0x3000
        static_cast<uint8_t>(DwarfOp::DW_OP_deref_size),
        0x01, // size = 1
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
    };
    result = eval_mem.evaluate(expression, ctx32);
    assert(result.type == ExpressionResult::VALUE);
    assert(result.value == 0x78);

    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_addr),
        0x00, 0x30, 0x00, 0x00, // 0x3000
        static_cast<uint8_t>(DwarfOp::DW_OP_deref_size),
        0x04, // size = 4
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
    };
    result = eval_mem.evaluate(expression, ctx32);
    assert(result.type == ExpressionResult::VALUE);
    assert(result.value == 0x12345678);

    // Test DW_OP_call_ref with a procedure resolver (stack is preserved across the call).
    EvaluationContext call_ctx;
    call_ctx.offset_size = 4;
    call_ctx.cu_base_offset = 0x1000;
    call_ctx.resolve_dwarf_procedure = [](uint64_t die_offset, uint64_t pc) -> std::optional<std::vector<uint8_t>> {
        (void)pc;
        if (die_offset != 0x1234) return std::nullopt;
        std::vector<uint8_t> proc = {
            static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
            32, 0, 0, 0,
            static_cast<uint8_t>(DwarfOp::DW_OP_plus),
        };
        return proc;
    };

    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        10, 0, 0, 0,
        static_cast<uint8_t>(DwarfOp::DW_OP_call_ref),
        0x34, 0x12, 0x00, 0x00, // section offset 0x1234 (DW_OP_call_ref is DW_FORM_ref_addr-like)
    };
    result = evaluator.evaluate(expression, call_ctx);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 42);

    // Test DW_OP_call2 / DW_OP_call4 are CU-relative.
    call_ctx.resolve_dwarf_procedure = [](uint64_t die_offset, uint64_t pc) -> std::optional<std::vector<uint8_t>> {
        (void)pc;
        if (die_offset != 0x1200) return std::nullopt;
        std::vector<uint8_t> proc = {
            static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
            32, 0, 0, 0,
            static_cast<uint8_t>(DwarfOp::DW_OP_plus),
        };
        return proc;
    };
    call_ctx.cu_base_offset = 0x1000;

    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        10, 0, 0, 0,
        static_cast<uint8_t>(DwarfOp::DW_OP_call2),
        0x00, 0x02, // 0x0200
    };
    result = evaluator.evaluate(expression, call_ctx);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 42);

    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        10, 0, 0, 0,
        static_cast<uint8_t>(DwarfOp::DW_OP_call4),
        0x00, 0x02, 0x00, 0x00, // 0x0200
    };
    result = evaluator.evaluate(expression, call_ctx);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 42);

    // Test DW_OP_implicit_pointer (resolve referenced DIE location, then add offset).
    EvaluationContext imp_ctx;
    imp_ctx.address_size = 4;
    imp_ctx.offset_size = 4;
    imp_ctx.cu_base_offset = 0x2000; // non-zero to ensure we don't treat DIE ref as CU-relative
    imp_ctx.resolve_dwarf_procedure = [](uint64_t die_offset, uint64_t pc) -> std::optional<std::vector<uint8_t>> {
        (void)pc;
        if (die_offset != 0x1234) return std::nullopt;
        // Referenced DIE has a location expression that yields address 0x2000.
        std::vector<uint8_t> proc = {
            static_cast<uint8_t>(DwarfOp::DW_OP_addr),
            0x00, 0x20, 0x00, 0x00, // 0x2000
        };
        return proc;
    };

    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_implicit_pointer),
        0x34, 0x12, 0x00, 0x00, // section offset 0x1234
        0x04, // +4 (SLEB128)
    };
    result = evaluator.evaluate(expression, imp_ctx);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 0x2004);

    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_implicit_pointer),
        0x34, 0x12, 0x00, 0x00,
        0x7c, // -4 (SLEB128)
    };
    result = evaluator.evaluate(expression, imp_ctx);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 0x1ffc);

    // Test DW_OP_GNU_parameter_ref (evaluate referenced DIE location/value).
    EvaluationContext param_ctx;
    param_ctx.address_size = 4;
    param_ctx.offset_size = 4;
    param_ctx.cu_base_offset = 0x1000; // non-zero; operand is section offset, not CU-relative
    param_ctx.resolve_dwarf_procedure = [](uint64_t die_offset, uint64_t pc) -> std::optional<std::vector<uint8_t>> {
        (void)pc;
        if (die_offset == 0x1200) {
            return std::vector<uint8_t>{
                static_cast<uint8_t>(DwarfOp::DW_OP_addr),
                0x00, 0x20, 0x00, 0x00, // 0x2000
            };
        }
        if (die_offset == 0x1204) {
            return std::vector<uint8_t>{
                static_cast<uint8_t>(DwarfOp::DW_OP_reg3),
            };
        }
        return std::nullopt;
    };

    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_GNU_parameter_ref),
        0x00, 0x12, 0x00, 0x00, // section offset 0x1200
    };
    result = evaluator.evaluate(expression, param_ctx);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 0x2000);

    // If referenced expression yields a register location, we push the register value.
    registers.assign(32, 0);
    registers[3] = 0x99;
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_GNU_parameter_ref),
        0x04, 0x12, 0x00, 0x00, // section offset 0x1204
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
    };
    result = evaluator.evaluate(expression, param_ctx, 0, registers);
    assert(result.type == ExpressionResult::VALUE);
    assert(result.value == 0x99);

    // Typed ops: best-effort integer normalization via resolve_base_type.
    EvaluationContext typed_ctx;
    typed_ctx.resolve_base_type = [](uint64_t type_off) -> std::optional<EvaluationContext::BaseTypeInfo> {
        EvaluationContext::BaseTypeInfo ti;
        if (type_off == 1) {
            ti.byte_size = 1;
            ti.is_integer = true;
            ti.is_signed = true;
            return ti;
        }
        if (type_off == 2) {
            ti.byte_size = 1;
            ti.is_integer = true;
            ti.is_signed = false;
            return ti;
        }
        return std::nullopt;
    };

    // DW_OP_const_type (signed 1-byte): 0xFF => -1 (sign-extended)
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const_type),
        0x01, // type_off = 1 (ULEB128)
        0x01, // size = 1
        0xFF, // value bytes
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
    };
    result = evaluator.evaluate(expression, typed_ctx);
    assert(result.type == ExpressionResult::VALUE);
    assert(result.value == static_cast<uint64_t>(-1));

    // DW_OP_regval_type (unsigned 1-byte): mask register value down to 8 bits.
    registers.assign(32, 0);
    registers[3] = 0x1234;
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_regval_type),
        0x03, // reg 3
        0x02, // type_off = 2
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
    };
    result = evaluator.evaluate(expression, typed_ctx, 0, registers);
    assert(result.type == ExpressionResult::VALUE);
    assert(result.value == 0x34);

    // DW_OP_convert (signed 1-byte): 0xFF => -1
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        0xFF, 0xFF, 0xFF, 0xFF,
        static_cast<uint8_t>(DwarfOp::DW_OP_convert),
        0x01, // type_off = 1
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
    };
    result = evaluator.evaluate(expression, typed_ctx);
    assert(result.type == ExpressionResult::VALUE);
    assert(result.value == static_cast<uint64_t>(-1));

    // DW_OP_deref_type (signed 1-byte): deref 1 byte 0xFF => -1
    mem->setBytes(0x2000, {0xFF});
    EvaluationContext ctx32_typed = typed_ctx;
    ctx32_typed.address_size = 4;
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_addr),
        0x00, 0x20, 0x00, 0x00, // 0x2000
        static_cast<uint8_t>(DwarfOp::DW_OP_deref_type),
        0x01, // size
        0x01, // type_off = 1
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
    };
    result = eval_mem.evaluate(expression, ctx32_typed);
    assert(result.type == ExpressionResult::VALUE);
    assert(result.value == static_cast<uint64_t>(-1));

    // Test DW_OP_bra conditional branch semantics (branch taken when condition != 0).
    // Control-flow:
    //   if (cond) push 0x55 else push 0xAA
    // Uses DW_OP_bra and DW_OP_skip with signed 16-bit relative offsets.
    {
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u),
            0x01, // cond = 1
            static_cast<uint8_t>(DwarfOp::DW_OP_bra),
            0x05, 0x00, // +5 bytes to label_true
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u),
            0xAA, // false value
            static_cast<uint8_t>(DwarfOp::DW_OP_skip),
            0x02, 0x00, // +2 bytes to end
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u),
            0x55, // true value
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        };

        auto r1 = evaluator.evaluate(expr, EvaluationContext{});
        assert(r1.type == ExpressionResult::VALUE);
        assert(r1.value == 0x55);

        expr[1] = 0x00; // cond = 0
        auto r0 = evaluator.evaluate(expr, EvaluationContext{});
        assert(r0.type == ExpressionResult::VALUE);
        assert(r0.value == 0xAA);
    }

    // Signed comparison semantics for DW_OP_{lt,le,gt,ge}.
    {
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_const1s), 0xff, // -1
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x01, // 1
            static_cast<uint8_t>(DwarfOp::DW_OP_lt),            // -1 < 1 => true
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        };
        auto r = evaluator.evaluate(expr, EvaluationContext{});
        assert(r.type == ExpressionResult::VALUE);
        assert(r.value == 1);

        expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_const1s), 0xff, // -1
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x01, // 1
            static_cast<uint8_t>(DwarfOp::DW_OP_ge),            // -1 >= 1 => false
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        };
        r = evaluator.evaluate(expr, EvaluationContext{});
        assert(r.type == ExpressionResult::VALUE);
        assert(r.value == 0);
    }

    // Shift counts are masked to avoid undefined behavior for counts >= 64.
    {
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x01,
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x41, // 65 -> 1
            static_cast<uint8_t>(DwarfOp::DW_OP_shl),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        };
        auto r = evaluator.evaluate(expr, EvaluationContext{});
        assert(r.type == ExpressionResult::VALUE);
        assert(r.value == 0x02);

        expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x80,
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x41, // 65 -> 1
            static_cast<uint8_t>(DwarfOp::DW_OP_shr),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        };
        r = evaluator.evaluate(expr, EvaluationContext{});
        assert(r.type == ExpressionResult::VALUE);
        assert(r.value == 0x40);

        expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_const1s), 0xfe, // -2
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x41, // 65 -> 1
            static_cast<uint8_t>(DwarfOp::DW_OP_shra),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        };
        r = evaluator.evaluate(expr, EvaluationContext{});
        assert(r.type == ExpressionResult::VALUE);
        assert(r.value == static_cast<uint64_t>(-1));
    }

    // Test literal operations (DW_OP_lit0 to DW_OP_lit31)
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_lit15)
    };

    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 15);

    // expressionToString should decode DW_OP_consts as signed SLEB.
    {
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_consts),
            0x7f // SLEB128(-1)
        };
        auto text = evaluator.expressionToString(expr);
        assert(text.find("-1") != std::string::npos);
    }

    std::cout << "ExpressionEvaluator tests passed!" << std::endl;
}

void testExpressionEvaluatorUnsupportedOp() {
    std::cout << "Testing ExpressionEvaluator unsupported opcode handling..." << std::endl;

    ExpressionEvaluator eval;
    EvaluationContext ctx;
    ctx.address_size = 8;
    ctx.offset_size = 4;
    ctx.cu_base_offset = 0;
    std::vector<uint64_t> regs(64, 0);

    // 0xff is not a defined DW_OP in our enum; evaluator should return INVALID (not silently succeed).
    std::vector<uint8_t> expr = {0xff};
    auto r = eval.evaluate(expr, ctx, /*pc=*/0, regs);
    assert(r.type == ExpressionResult::INVALID);

    std::cout << "ExpressionEvaluator unsupported opcode tests passed!" << std::endl;
}

void testExpressionEvaluatorImplicitPiece() {
    std::cout << "Testing ExpressionEvaluator implicit pieces..." << std::endl;

    ExpressionEvaluator evaluator;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // A constant value turned into an implicit piece using DW_OP_stack_value + DW_OP_piece.
    std::vector<uint8_t> expr = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        0x78, 0x56, 0x34, 0x12, // 0x12345678
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        static_cast<uint8_t>(DwarfOp::DW_OP_piece),
        0x04, // ULEB128(4)
    };

    auto r = evaluator.evaluate(expr, ctx);
    assert(r.type == ExpressionResult::COMPOSITE);
    assert(r.pieces.size() == 1);
    assert(r.pieces[0].kind == PieceDescriptor::IMPLICIT);
    assert(r.pieces[0].byte_size == 4);
    assert(r.pieces[0].implicit_value.size() == 4);
    assert(r.pieces[0].implicit_value[0] == 0x78);
    assert(r.pieces[0].implicit_value[1] == 0x56);
    assert(r.pieces[0].implicit_value[2] == 0x34);
    assert(r.pieces[0].implicit_value[3] == 0x12);

    std::cout << "ExpressionEvaluator implicit piece tests passed!" << std::endl;
}

void testExpressionEvaluatorTypedOpsUseCUBaseOffset() {
    std::cout << "Testing ExpressionEvaluator typed ops CU-relative type offsets..." << std::endl;

    ExpressionEvaluator evaluator;
    EvaluationContext ctx;
    ctx.cu_base_offset = 0x1000;
    ctx.resolve_base_type = [](uint64_t type_die_offset) -> std::optional<EvaluationContext::BaseTypeInfo> {
        if (type_die_offset != 0x1001) return std::nullopt;
        EvaluationContext::BaseTypeInfo ti;
        ti.byte_size = 1;
        ti.is_integer = true;
        ti.is_signed = true;
        return ti;
    };

    // const1u 0xFF, convert(type_off=1), stack_value => -1
    std::vector<uint8_t> expr = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const1u),
        0xFF,
        static_cast<uint8_t>(DwarfOp::DW_OP_convert),
        0x01, // ULEB128(1) type offset, CU-relative
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
    };

    auto r = evaluator.evaluate(expr, ctx);
    assert(r.type == ExpressionResult::VALUE);
    assert(r.value == static_cast<uint64_t>(-1));

    std::cout << "ExpressionEvaluator typed ops CU-relative tests passed!" << std::endl;
}

void testExpressionEvaluatorTypedOpsMaskNonIntegerTypes() {
    std::cout << "Testing ExpressionEvaluator typed ops mask for non-integer base types..." << std::endl;

    ExpressionEvaluator evaluator;
    EvaluationContext ctx;
    ctx.cu_base_offset = 0x1000;
    ctx.resolve_base_type = [](uint64_t type_die_offset) -> std::optional<EvaluationContext::BaseTypeInfo> {
        // "float" base type at CU+4, 4 bytes.
        if (type_die_offset != 0x1004) return std::nullopt;
        EvaluationContext::BaseTypeInfo ti;
        ti.byte_size = 4;
        ti.is_integer = false;
        ti.is_signed = false;
        ti.encoding = DW_ATE::DW_ATE_float;
        return ti;
    };

    // const8u 0x1122334455667788, reinterpret(float32) => masked to 4 bytes.
    std::vector<uint8_t> expr = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const8u),
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        static_cast<uint8_t>(DwarfOp::DW_OP_reinterpret),
        0x04, // ULEB128(4) type offset, CU-relative
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
    };

    auto r = evaluator.evaluate(expr, ctx);
    assert(r.type == ExpressionResult::VALUE);
    assert(r.value == 0x55667788);

    // Same input, convert(float32) => also masked best-effort.
    expr = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const8u),
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        static_cast<uint8_t>(DwarfOp::DW_OP_convert),
        0x04,
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
    };
    r = evaluator.evaluate(expr, ctx);
    assert(r.type == ExpressionResult::VALUE);
    assert(r.value == 0x55667788);

    std::cout << "ExpressionEvaluator typed ops non-integer mask tests passed!" << std::endl;
}

void testExpressionEvaluatorConstTypeProvidesImplicitBytesForPiece() {
    std::cout << "Testing ExpressionEvaluator const_type provides implicit bytes for piece..." << std::endl;

    // Build an implicit value larger than 8 bytes so the numeric stack value can't
    // carry all bytes. We require DW_OP_piece to get the full byte vector.
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const_type));
    expr.push_back(0x00); // ULEB128(0) type offset
    expr.push_back(0x09); // size=9
    for (uint8_t i = 1; i <= 9; ++i) expr.push_back(i);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    expr.push_back(0x09); // ULEB128(9)

    ExpressionEvaluator ev;
    EvaluationContext ctx;
    auto r = ev.evaluate(expr, ctx);
    assert(r.type == ExpressionResult::COMPOSITE);
    assert(r.pieces.size() == 1);
    assert(r.pieces[0].kind == PieceDescriptor::IMPLICIT);
    assert(r.pieces[0].implicit_value.size() == 9);
    for (uint8_t i = 1; i <= 9; ++i) {
        assert(r.pieces[0].implicit_value[i - 1] == i);
    }

    std::cout << "ExpressionEvaluator const_type implicit bytes tests passed!" << std::endl;
}

void testExpressionEvaluatorPieceTruncatesImplicitBytes() {
    std::cout << "Testing ExpressionEvaluator piece truncates implicit bytes..." << std::endl;

    // implicit_value holds 9 bytes, but piece requests 4. The piece must be 4 bytes.
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
    expr.push_back(0x09); // size=9
    for (uint8_t i = 1; i <= 9; ++i) expr.push_back(i);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    expr.push_back(0x04); // piece size=4

    ExpressionEvaluator ev;
    EvaluationContext ctx;
    auto r = ev.evaluate(expr, ctx);
    assert(r.type == ExpressionResult::COMPOSITE);
    assert(r.pieces.size() == 1);
    assert(r.pieces[0].kind == PieceDescriptor::IMPLICIT);
    assert(r.pieces[0].implicit_value.size() == 4);
    assert(r.pieces[0].implicit_value[0] == 1);
    assert(r.pieces[0].implicit_value[1] == 2);
    assert(r.pieces[0].implicit_value[2] == 3);
    assert(r.pieces[0].implicit_value[3] == 4);

    std::cout << "ExpressionEvaluator piece truncates implicit bytes tests passed!" << std::endl;
}

void testExpressionEvaluatorDerefEndianness() {
    std::cout << "Testing ExpressionEvaluator deref endianness..." << std::endl;

    // Flip object endianness temporarily.
    bool prev = DwarfUtils::objectIsLittleEndian();
    DwarfUtils::setObjectLittleEndian(false);

    class MapMemoryContextBE final : public MemoryContext {
    public:
        void setBytes(uint64_t address, const std::vector<uint8_t>& bytes) {
            mem_[address] = bytes;
        }
        bool readMemory(uint64_t address, size_t size, void* buffer) const override {
            auto it = mem_.find(address);
            if (it == mem_.end() || !buffer) return false;
            if (it->second.size() < size) return false;
            std::memcpy(buffer, it->second.data(), size);
            return true;
        }
        bool writeMemory(uint64_t address, size_t size, const void* buffer) override {
            (void)address; (void)size; (void)buffer;
            return false;
        }
    private:
        std::unordered_map<uint64_t, std::vector<uint8_t>> mem_;
    };

    auto mem = std::make_shared<MapMemoryContextBE>();
    // Big-endian bytes for 0x12345678 at 0x1000.
    mem->setBytes(0x1000, {0x12, 0x34, 0x56, 0x78});
    ExpressionEvaluator ev(mem);

    EvaluationContext ctx32;
    ctx32.address_size = 4;
    std::vector<uint8_t> expr = {
        static_cast<uint8_t>(DwarfOp::DW_OP_addr),
        0x00, 0x00, 0x10, 0x00, // 0x1000 (big-endian)
        static_cast<uint8_t>(DwarfOp::DW_OP_deref_size),
        0x04,
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
    };
    auto r = ev.evaluate(expr, ctx32);
    assert(r.type == ExpressionResult::VALUE);
    assert(r.value == 0x12345678);

    // Restore endianness.
    DwarfUtils::setObjectLittleEndian(prev);

    std::cout << "ExpressionEvaluator deref endianness tests passed!" << std::endl;
}

void testExpressionEvaluatorImplicitValueEndianness() {
    std::cout << "Testing ExpressionEvaluator implicit_value endianness..." << std::endl;

    bool prev = DwarfUtils::objectIsLittleEndian();
    DwarfUtils::setObjectLittleEndian(false);

    // DW_OP_implicit_value(size=4, bytes=0x12 0x34 0x56 0x78) should decode to 0x12345678 on big-endian.
    std::vector<uint8_t> expr = {
        static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value),
        0x04, // ULEB128(4)
        0x12, 0x34, 0x56, 0x78,
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
    };

    ExpressionEvaluator ev;
    EvaluationContext ctx;
    auto r = ev.evaluate(expr, ctx);
    assert(r.type == ExpressionResult::VALUE);
    assert(r.value == 0x12345678);

    DwarfUtils::setObjectLittleEndian(prev);

    std::cout << "ExpressionEvaluator implicit_value endianness tests passed!" << std::endl;
}

void testExpressionEvaluatorPieceImplicitBytesEndianness() {
    std::cout << "Testing ExpressionEvaluator piece implicit bytes endianness..." << std::endl;

    bool prev = DwarfUtils::objectIsLittleEndian();
    DwarfUtils::setObjectLittleEndian(false);

    // const4u bytes represent 0x12345678 in big-endian. stack_value + piece should emit same byte order.
    std::vector<uint8_t> expr = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        0x12, 0x34, 0x56, 0x78,
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        static_cast<uint8_t>(DwarfOp::DW_OP_piece),
        0x04, // ULEB128(4)
    };

    ExpressionEvaluator ev;
    EvaluationContext ctx;
    auto r = ev.evaluate(expr, ctx);
    assert(r.type == ExpressionResult::COMPOSITE);
    assert(r.pieces.size() == 1);
    assert(r.pieces[0].kind == PieceDescriptor::IMPLICIT);
    assert(r.pieces[0].implicit_value.size() == 4);
    assert(r.pieces[0].implicit_value[0] == 0x12);
    assert(r.pieces[0].implicit_value[1] == 0x34);
    assert(r.pieces[0].implicit_value[2] == 0x56);
    assert(r.pieces[0].implicit_value[3] == 0x78);

    DwarfUtils::setObjectLittleEndian(prev);

    std::cout << "ExpressionEvaluator piece implicit bytes endianness tests passed!" << std::endl;
}

void testExpressionEvaluatorConstTypeEndianness() {
    std::cout << "Testing ExpressionEvaluator const_type endianness..." << std::endl;

    bool prev = DwarfUtils::objectIsLittleEndian();
    DwarfUtils::setObjectLittleEndian(false);

    // DW_OP_const_type(type_off=0, size=4, bytes=0x12 0x34 0x56 0x78) should decode to 0x12345678 on big-endian.
    std::vector<uint8_t> expr = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const_type),
        0x00, // ULEB128(0) -> no type info
        0x04, // size
        0x12, 0x34, 0x56, 0x78,
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
    };

    ExpressionEvaluator ev;
    EvaluationContext ctx;
    auto r = ev.evaluate(expr, ctx);
    assert(r.type == ExpressionResult::VALUE);
    assert(r.value == 0x12345678);

    DwarfUtils::setObjectLittleEndian(prev);

    std::cout << "ExpressionEvaluator const_type endianness tests passed!" << std::endl;
}

void testExpressionEvaluatorGnuEncodedAddr() {
    std::cout << "Testing ExpressionEvaluator DW_OP_GNU_encoded_addr..." << std::endl;

    // absptr encoding: read address_size bytes.
    {
        ExpressionEvaluator ev;
        EvaluationContext ctx;
        ctx.address_size = 8;
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr),
            0x00, // DW_EH_PE_absptr
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        };
        auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
        assert(r.type == ExpressionResult::VALUE);
        assert(r.value == 0x1122334455667788ULL);
    }

    // pcrel + udata4 encoding: address = pc + u32.
    {
        ExpressionEvaluator ev;
        EvaluationContext ctx;
        ctx.address_size = 8;
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr),
            0x13, // DW_EH_PE_pcrel | DW_EH_PE_udata4
            0x20, 0x00, 0x00, 0x00, // +0x20
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        };
        auto r = ev.evaluate(expr, ctx, /*pc=*/0x1000, /*registers=*/{});
        assert(r.type == ExpressionResult::VALUE);
        assert(r.value == 0x1020);
    }

    // Truncated encoding byte should be invalid.
    {
        ExpressionEvaluator ev;
        EvaluationContext ctx;
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr),
        };
        auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
        assert(r.type == ExpressionResult::INVALID);
        assert(r.description.find("DW_OP_GNU_encoded_addr") != std::string::npos);
    }

    std::cout << "ExpressionEvaluator DW_OP_GNU_encoded_addr tests passed!" << std::endl;
}

void testExpressionEvaluatorBranchLoopIsGuarded() {
    std::cout << "Testing ExpressionEvaluator branch loop guard..." << std::endl;

    // This expression intentionally loops:
    // const1u 7; stack_value; skip -3 (to stack_value).
    // Older behavior could incorrectly treat -3 as a huge unsigned offset, exiting the expression.
    std::vector<uint8_t> expr = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const1u),
        0x07,
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        static_cast<uint8_t>(DwarfOp::DW_OP_skip),
        0xfd, 0xff, // int16(-3) little-endian
    };

    ExpressionEvaluator ev;
    EvaluationContext ctx;
    auto r = ev.evaluate(expr, ctx);
    assert(r.type == ExpressionResult::INVALID);

    std::cout << "ExpressionEvaluator branch loop guard tests passed!" << std::endl;
}

void testExpressionEvaluatorTlsAddressOps() {
    std::cout << "Testing ExpressionEvaluator TLS address ops..." << std::endl;

    ExpressionEvaluator ev;
    EvaluationContext ctx;
    ctx.tls_base = 0x70000000ULL;

    // constu 0x123, form_tls_address => 0x70000123
    std::vector<uint8_t> expr = {
        static_cast<uint8_t>(DwarfOp::DW_OP_constu),
        0xa3, 0x02, // ULEB128(0x123)
        static_cast<uint8_t>(DwarfOp::DW_OP_form_tls_address),
    };
    auto r = ev.evaluate(expr, ctx);
    assert(r.type == ExpressionResult::ADDRESS);
    assert(r.value == 0x70000123ULL);

    // GNU predecessor: constu 0x20, GNU_push_tls_address => 0x70000020
    expr = {
        static_cast<uint8_t>(DwarfOp::DW_OP_constu),
        0x20,
        static_cast<uint8_t>(DwarfOp::DW_OP_GNU_push_tls_address),
    };
    r = ev.evaluate(expr, ctx);
    assert(r.type == ExpressionResult::ADDRESS);
    assert(r.value == 0x70000020ULL);

    std::cout << "ExpressionEvaluator TLS address ops tests passed!" << std::endl;
}

void testExpressionEvaluatorCallRefUsesSectionOffsetNotCUOffset() {
    std::cout << "Testing ExpressionEvaluator DW_OP_call_ref uses section offset (not CU-relative)..." << std::endl;

    // Build an expression that calls a DWARF procedure by absolute DIE offset.
    // If DW_OP_call_ref incorrectly adds cu_base_offset, the lookup will miss.
    const uint64_t proc_die_off = 0x1234;
    const uint64_t expected_addr = 0xDEADBEEFCAFEBABEULL;

    EvaluationContext ctx;
    ctx.address_size = 8;
    ctx.offset_size = 4;
    ctx.cu_base_offset = 0x100; // non-zero to expose CU-relative vs section-relative bug
    ctx.resolve_dwarf_procedure = [&](uint64_t die_offset, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
        if (die_offset != proc_die_off) return std::nullopt;
        std::vector<uint8_t> proc;
        proc.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
        appendU64(proc, expected_addr);
        return proc;
    };

    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call_ref));
    appendU32(expr, static_cast<uint32_t>(proc_die_off));

    ExpressionEvaluator ev;
    auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
    assert(r.type == ExpressionResult::ADDRESS);
    assert(r.value == expected_addr);

    std::cout << "ExpressionEvaluator DW_OP_call_ref tests passed!" << std::endl;
}

void testExpressionEvaluatorGnuParameterRefRespectsOffsetSize64() {
    std::cout << "Testing ExpressionEvaluator DW_OP_GNU_parameter_ref respects offset_size=8..." << std::endl;

    EvaluationContext ctx;
    ctx.address_size = 8;
    ctx.offset_size = 8;
    ctx.cu_base_offset = 0x1000;
    ctx.resolve_dwarf_procedure = [](uint64_t die_offset, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
        if (die_offset != 0x1200) return std::nullopt;
        std::vector<uint8_t> proc;
        proc.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
        appendU64(proc, 0xABCDEF0012345678ULL);
        return proc;
    };

    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_parameter_ref));
    appendU64(expr, 0x1200); // 8-byte DIE ref

    ExpressionEvaluator ev;
    auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
    assert(r.type == ExpressionResult::ADDRESS);
    assert(r.value == 0xABCDEF0012345678ULL);

    std::cout << "ExpressionEvaluator DW_OP_GNU_parameter_ref offset_size=8 tests passed!" << std::endl;
}

void testExpressionEvaluatorSectionRelativeOpsPreserveDWOBias() {
    std::cout << "Testing ExpressionEvaluator section-relative ops preserve DWO bias..." << std::endl;

    // Simulate a DWO-biased CU base offset:
    // bit 63 set, slot=1 in bits [62:48], CU header at 0x1000 in low bits.
    const uint64_t bias = (1ULL << 63) | (1ULL << 48);
    const uint64_t cu_base = bias + 0x1000;

    // 1) DW_OP_call_ref: operand is section offset; should resolve to (bias + die_off).
    {
        EvaluationContext ctx;
        ctx.address_size = 8;
        ctx.offset_size = 4;
        ctx.cu_base_offset = cu_base;
        ctx.resolve_dwarf_procedure = [&](uint64_t die_offset, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
            if (die_offset != bias + 0x1234) return std::nullopt;
            std::vector<uint8_t> proc;
            proc.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
            appendU64(proc, 0x1111222233334444ULL);
            return proc;
        };

        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call_ref));
        appendU32(expr, 0x1234);

        ExpressionEvaluator ev;
        auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
        assert(r.type == ExpressionResult::ADDRESS);
        assert(r.value == 0x1111222233334444ULL);
    }

    // 2) DW_OP_implicit_pointer: operand is section offset; should resolve to (bias + die_off).
    {
        EvaluationContext ctx;
        ctx.address_size = 8;
        ctx.offset_size = 4;
        ctx.cu_base_offset = cu_base;
        ctx.resolve_dwarf_procedure = [&](uint64_t die_offset, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
            if (die_offset != bias + 0x2000) return std::nullopt;
            std::vector<uint8_t> proc;
            proc.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
            appendU64(proc, 0x777788889999AAAALL);
            return proc;
        };

        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_pointer));
        appendU32(expr, 0x2000);
        expr.push_back(0x00); // +0 (SLEB128)

        ExpressionEvaluator ev;
        auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
        assert(r.type == ExpressionResult::ADDRESS);
        assert(r.value == 0x777788889999AAAALL);
    }

    // 3) DW_OP_GNU_parameter_ref: operand is section offset; should resolve to (bias + die_off).
    {
        EvaluationContext ctx;
        ctx.address_size = 8;
        ctx.offset_size = 4;
        ctx.cu_base_offset = cu_base;
        ctx.resolve_dwarf_procedure = [&](uint64_t die_offset, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
            if (die_offset != bias + 0x3000) return std::nullopt;
            std::vector<uint8_t> proc;
            proc.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
            appendU64(proc, 0xABCDEF0012345678ULL);
            return proc;
        };

        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_parameter_ref));
        appendU32(expr, 0x3000);

        ExpressionEvaluator ev;
        auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
        assert(r.type == ExpressionResult::ADDRESS);
        assert(r.value == 0xABCDEF0012345678ULL);
    }

    std::cout << "ExpressionEvaluator DWO bias preservation tests passed!" << std::endl;
}

void testExpressionEvaluatorSectionRelativeOpsPreserveSupplementaryBias() {
    std::cout << "Testing ExpressionEvaluator section-relative ops preserve supplementary bias..." << std::endl;

    // Supplementary bias uses bit 62 set; CU header at 0x2000 in low bits.
    const uint64_t bias = (1ULL << 62);
    const uint64_t cu_base = bias + 0x2000;

    // DW_OP_call_ref should resolve to (bias + die_off).
    {
        EvaluationContext ctx;
        ctx.address_size = 8;
        ctx.offset_size = 4;
        ctx.cu_base_offset = cu_base;
        ctx.resolve_dwarf_procedure = [&](uint64_t die_offset, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
            if (die_offset != bias + 0x4444) return std::nullopt;
            std::vector<uint8_t> proc;
            proc.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
            appendU64(proc, 0x0101010102020202ULL);
            return proc;
        };

        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call_ref));
        appendU32(expr, 0x4444);

        ExpressionEvaluator ev;
        auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
        assert(r.type == ExpressionResult::ADDRESS);
        assert(r.value == 0x0101010102020202ULL);
    }

    // DW_OP_implicit_pointer should resolve to (bias + die_off).
    {
        EvaluationContext ctx;
        ctx.address_size = 8;
        ctx.offset_size = 4;
        ctx.cu_base_offset = cu_base;
        ctx.resolve_dwarf_procedure = [&](uint64_t die_offset, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
            if (die_offset != bias + 0x5555) return std::nullopt;
            std::vector<uint8_t> proc;
            proc.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
            appendU64(proc, 0x0303030304040404ULL);
            return proc;
        };

        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_pointer));
        appendU32(expr, 0x5555);
        expr.push_back(0x00); // +0

        ExpressionEvaluator ev;
        auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
        assert(r.type == ExpressionResult::ADDRESS);
        assert(r.value == 0x0303030304040404ULL);
    }

    // DW_OP_GNU_parameter_ref should resolve to (bias + die_off).
    {
        EvaluationContext ctx;
        ctx.address_size = 8;
        ctx.offset_size = 4;
        ctx.cu_base_offset = cu_base;
        ctx.resolve_dwarf_procedure = [&](uint64_t die_offset, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
            if (die_offset != bias + 0x6666) return std::nullopt;
            std::vector<uint8_t> proc;
            proc.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
            appendU64(proc, 0x0505050506060606ULL);
            return proc;
        };

        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_parameter_ref));
        appendU32(expr, 0x6666);

        ExpressionEvaluator ev;
        auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
        assert(r.type == ExpressionResult::ADDRESS);
        assert(r.value == 0x0505050506060606ULL);
    }

    std::cout << "ExpressionEvaluator supplementary bias preservation tests passed!" << std::endl;
}

void testExpressionEvaluatorMixedSectionRelativeOpsUnderDWOBias() {
    std::cout << "Testing ExpressionEvaluator mixed section-relative ops under DWO bias..." << std::endl;

    const uint64_t bias = (1ULL << 63) | (1ULL << 48);
    const uint64_t cu_base = bias + 0x1000;

    EvaluationContext ctx;
    ctx.address_size = 8;
    ctx.offset_size = 4;
    ctx.cu_base_offset = cu_base;
    ctx.resolve_dwarf_procedure = [&](uint64_t die_offset, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
        if (die_offset == bias + 0x1234) {
            // Adds 32 to the current top of stack.
            return std::vector<uint8_t>{
                static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
                32, 0, 0, 0,
                static_cast<uint8_t>(DwarfOp::DW_OP_plus),
            };
        }
        if (die_offset == bias + 0x2000) {
            std::vector<uint8_t> proc;
            proc.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
            appendU64(proc, 0x2000);
            return proc;
        }
        if (die_offset == bias + 0x3000) {
            std::vector<uint8_t> proc;
            proc.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
            appendU64(proc, 0x1000);
            return proc;
        }
        return std::nullopt;
    };

    // Expression:
    // 10
    // call_ref(0x1234) => 10+32 = 42
    // implicit_pointer(0x2000, +4) => 0x2004
    // gnu_parameter_ref(0x3000) => 0x1000
    // plus => 0x3004
    // plus => 0x302E
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const4u));
    expr.push_back(10); expr.push_back(0); expr.push_back(0); expr.push_back(0);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call_ref));
    appendU32(expr, 0x1234);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_pointer));
    appendU32(expr, 0x2000);
    expr.push_back(0x04); // +4
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_parameter_ref));
    appendU32(expr, 0x3000);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus));

    ExpressionEvaluator ev;
    auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
    assert(r.type == ExpressionResult::ADDRESS);
    assert(r.value == 0x302E);

    std::cout << "ExpressionEvaluator mixed DWO-bias tests passed!" << std::endl;
}

void testExpressionEvaluatorSectionRelativeOpsIgnoreHighBitsWhenUnbiased() {
    std::cout << "Testing ExpressionEvaluator section-relative ops ignore high cu_base_offset bits when unbiased..." << std::endl;

    // No bias bits set, but high bits present (defensive case).
    const uint64_t cu_base = (1ULL << 60) + 0x1000;

    // 1) DW_OP_call_ref should resolve to die_offset directly (not cu_base + die_offset).
    {
        EvaluationContext ctx;
        ctx.address_size = 8;
        ctx.offset_size = 4;
        ctx.cu_base_offset = cu_base;
        ctx.resolve_dwarf_procedure = [&](uint64_t die_offset, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
            if (die_offset != 0x1234) return std::nullopt;
            std::vector<uint8_t> proc;
            proc.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
            appendU64(proc, 0xA0A0A0A0B0B0B0B0ULL);
            return proc;
        };

        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call_ref));
        appendU32(expr, 0x1234);

        ExpressionEvaluator ev;
        auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
        assert(r.type == ExpressionResult::ADDRESS);
        assert(r.value == 0xA0A0A0A0B0B0B0B0ULL);
    }

    // 2) DW_OP_implicit_pointer should resolve to die_offset directly and then add the SLEB offset.
    {
        EvaluationContext ctx;
        ctx.address_size = 8;
        ctx.offset_size = 4;
        ctx.cu_base_offset = cu_base;
        ctx.resolve_dwarf_procedure = [&](uint64_t die_offset, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
            if (die_offset != 0x2000) return std::nullopt;
            std::vector<uint8_t> proc;
            proc.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
            appendU64(proc, 0x4000);
            return proc;
        };

        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_pointer));
        appendU32(expr, 0x2000);
        expr.push_back(0x04); // +4

        ExpressionEvaluator ev;
        auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
        assert(r.type == ExpressionResult::ADDRESS);
        assert(r.value == 0x4004);
    }

    // 3) DW_OP_GNU_parameter_ref should resolve to die_offset directly.
    {
        EvaluationContext ctx;
        ctx.address_size = 8;
        ctx.offset_size = 4;
        ctx.cu_base_offset = cu_base;
        ctx.resolve_dwarf_procedure = [&](uint64_t die_offset, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
            if (die_offset != 0x3000) return std::nullopt;
            std::vector<uint8_t> proc;
            proc.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
            appendU64(proc, 0x5555);
            return proc;
        };

        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_parameter_ref));
        appendU32(expr, 0x3000);

        ExpressionEvaluator ev;
        auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
        assert(r.type == ExpressionResult::ADDRESS);
        assert(r.value == 0x5555);
    }

    std::cout << "ExpressionEvaluator unbiased high-bits tests passed!" << std::endl;
}

void testVariableLocationCompositeBitPieceOffsets() {
    std::cout << "Testing VariableLocationEvaluator composite bit_piece offsets..." << std::endl;

    // Memory at 0x1000: 0xB2 = 0b10110010
    std::unordered_map<uint64_t, std::vector<uint8_t>> mem;
    mem[0x1000] = {0xB2};
    auto reader = [&](uint64_t addr, size_t n, void* out) -> bool {
        auto it = mem.find(addr);
        if (it == mem.end()) return false;
        if (it->second.size() < n) return false;
        std::memcpy(out, it->second.data(), n);
        return true;
    };

    VariableLocationEvaluator eval;
    eval.setMemoryReader(reader);

    EvaluationContext ctx;
    ctx.address_size = 8;
    eval.setContext(ctx);

    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
    appendU64(expr, 0x1000);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bit_piece));
    expr.push_back(0x03); // bit_size = 3
    expr.push_back(0x01); // bit_offset = 1

    auto loc = eval.evaluateExpression(expr, /*pc=*/0);
    assert(loc.type == VariableLocationType::COMPOSITE);
    assert(loc.pieces.size() == 1);
    assert(loc.pieces[0].type == VariableLocationType::MEMORY);
    assert(loc.pieces[0].location == 0x1000);
    assert(loc.pieces[0].size_bits == 3);
    assert(loc.pieces[0].offset_bits == 1);

    auto bytes = eval.readValue(loc, /*size=*/1);
    assert(bytes.has_value());
    assert(bytes->size() == 1);
    // Bits [1..3] of 0xB2 (LSB-first) are 1,0,0 => value 0b001.
    assert((*bytes)[0] == 0x01);

    std::cout << "VariableLocationEvaluator bit_piece offset tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorBasic() {
    std::cout << "Testing SymbolicExpressionEvaluator basic..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;
    ctx.frame_base = 0x1000;

    // fbreg(-0x20) => 0x1000 - 0x20 = 0xfe0 (const-folded)
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_fbreg));
    // SLEB(-32) = 0x60
    expr.push_back(0x60);

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
    assert(r.expression);
    assert(r.expression->toString() == "0xfe0");

    std::cout << "SymbolicExpressionEvaluator basic tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorMalformedOperands() {
    std::cout << "Testing SymbolicExpressionEvaluator malformed/truncated operands..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // Truncated fixed-width operand (DW_OP_const4u expects 4 bytes).
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const4u));
        expr.push_back(0x11);
        expr.push_back(0x22);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("truncated u32") != std::string::npos);
    }

    // Truncated branch displacement operand (DW_OP_bra expects 2-byte S16).
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit1));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
        expr.push_back(0x01);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("truncated u16") != std::string::npos);
    }

    // Truncated skip displacement operand (DW_OP_skip expects 2-byte S16).
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
        expr.push_back(0x01);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("truncated u16") != std::string::npos);
    }

    // Stack underflow on binary op.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit1));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus));
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("stack underflow") != std::string::npos);
    }

    // Stack underflow on conditional branch (missing condition operand).
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
        appendU16(expr, 0);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("stack underflow") != std::string::npos);
    }

    // Stack underflow on stack-manipulation op (OVER requires 2 stack entries).
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit1));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_over));
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("stack underflow") != std::string::npos);
    }

    // Stack underflow on PICK out-of-range (needs idx+1 entries).
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit1));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_pick));
        expr.push_back(1);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("stack underflow") != std::string::npos);
    }

    // Truncated PICK operand should report decode error before stack-underflow logic.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_pick));
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("truncated u8") != std::string::npos);
    }

    // Stack underflow on stack_value without input value.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("stack underflow") != std::string::npos);
    }

    // Truncated PLUS_UCONST operand should report decode error before stack-underflow logic.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus_uconst));
        expr.push_back(0x80); // unterminated ULEB
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("truncated uleb128") != std::string::npos);
    }

    // Truncated DEREF_SIZE immediate should report decode error before stack-underflow logic.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_deref_size));
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("truncated u8") != std::string::npos);
    }

    // Unterminated ULEB128 operand.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_constu));
        expr.push_back(0x80); // continuation bit set, but no following byte
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("truncated uleb128") != std::string::npos);
    }

    // ULEB128 overflow (>64-bit payload).
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_constu));
        for (int i = 0; i < 9; ++i) expr.push_back(0x80);
        expr.push_back(0x02);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("uleb128 overflow") != std::string::npos);
    }

    // Unterminated SLEB128 operand.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_consts));
        expr.push_back(0x80); // continuation bit set, but no following byte
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("truncated sleb128") != std::string::npos);
    }

    // SLEB128 overflow (>64-bit payload).
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_consts));
        for (int i = 0; i < 9; ++i) expr.push_back(0x80);
        expr.push_back(0x02);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("sleb128 overflow") != std::string::npos);
    }

    // Truncated payload for DW_OP_implicit_value(len=2, only 1 byte present).
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 2);
        expr.push_back(0xaa);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("truncated byte payload") != std::string::npos);
    }

    // Invalid address_size for pointer-sized operand decoding.
    {
        EvaluationContext bad = ctx;
        bad.address_size = 3;
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
        appendU64(expr, 0x1234);
        auto r = se.evaluate(expr, bad);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("invalid address_size") != std::string::npos);
    }

    // Invalid address_size for deref-family pointer-width loads.
    {
        EvaluationContext bad = ctx;
        bad.address_size = 3;
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_lit1),
            static_cast<uint8_t>(DwarfOp::DW_OP_deref),
        };
        auto r = se.evaluate(expr, bad);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("invalid address_size") != std::string::npos);

        expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_lit1), // addr-space
            static_cast<uint8_t>(DwarfOp::DW_OP_lit2), // addr
            static_cast<uint8_t>(DwarfOp::DW_OP_xderef),
        };
        r = se.evaluate(expr, bad);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("invalid address_size") != std::string::npos);
    }

    // Invalid address_size for GNU encoded addr with indirect flag.
    {
        EvaluationContext bad = ctx;
        bad.address_size = 3;
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr),
            0x80, // DW_EH_PE_absptr | DW_EH_PE_indirect
            0x00, 0x00, 0x00, 0x00
        };
        auto r = se.evaluate(expr, bad);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("invalid address_size") != std::string::npos);
    }

    // Invalid offset_size for section-relative reference decoding.
    {
        EvaluationContext bad = ctx;
        bad.offset_size = 3;
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call_ref));
        appendU32(expr, 0x20);
        auto r = se.evaluate(expr, bad);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("invalid offset_size") != std::string::npos);
    }

    std::cout << "SymbolicExpressionEvaluator malformed/truncated operand tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorLoad() {
    std::cout << "Testing SymbolicExpressionEvaluator load modeling..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
    appendU64(expr, 0x1000);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_deref_size));
    expr.push_back(4);

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::VALUE);
    assert(r.expression);
    assert(r.expression->toString() == "load(0x1000,4)");

    std::cout << "SymbolicExpressionEvaluator load tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorPieces() {
    std::cout << "Testing SymbolicExpressionEvaluator pieces..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg5));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(expr, 8);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
    appendU64(expr, 0x2000);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(expr, 8);

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
    assert(r.pieces.size() == 2);
    assert(r.pieces[0].kind == SymPiece::Kind::REGISTER);
    assert(r.pieces[0].location);
    assert(r.pieces[0].location->toString() == "0x5");
    assert(r.pieces[0].byte_size == 8);
    assert(r.pieces[1].kind == SymPiece::Kind::MEMORY);
    assert(r.pieces[1].location);
    assert(r.pieces[1].location->toString() == "0x2000");
    assert(r.pieces[1].byte_size == 8);

    std::cout << "SymbolicExpressionEvaluator pieces tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorUnavailablePieces() {
    std::cout << "Testing SymbolicExpressionEvaluator unavailable piece semantics..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // DW_OP_piece with empty stack means unavailable piece.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 4);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 2);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 2);
        assert(r.pieces[0].kind == SymPiece::Kind::EMPTY);
        assert(r.pieces[0].byte_size == 4);
        assert(r.pieces[1].kind == SymPiece::Kind::EMPTY);
        assert(r.pieces[1].byte_size == 2);
    }

    // bit_piece with empty stack means unavailable piece bits.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bit_piece));
        appendULEB(expr, 3);
        appendULEB(expr, 1);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 1);
        assert(r.pieces[0].kind == SymPiece::Kind::EMPTY);
        assert(r.pieces[0].bit_size == 3);
        assert(r.pieces[0].bit_offset == 1);
    }

    // Mixed available/unavailable pieces.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
        appendU64(expr, 0x2000);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 8);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 4);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 2);
        assert(r.pieces[0].kind == SymPiece::Kind::MEMORY);
        assert(r.pieces[0].location && r.pieces[0].location->toString() == "0x2000");
        assert(r.pieces[1].kind == SymPiece::Kind::EMPTY);
        assert(r.pieces[1].byte_size == 4);
    }

    std::cout << "SymbolicExpressionEvaluator unavailable piece tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorStackValuePieces() {
    std::cout << "Testing SymbolicExpressionEvaluator stack_value piece semantics..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // Constant value + stack_value + piece => implicit value piece.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit7));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 1);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 1);
        assert(r.pieces[0].kind == SymPiece::Kind::IMPLICIT);
        assert(r.pieces[0].byte_size == 1);
        assert(r.pieces[0].location && r.pieces[0].location->toString() == "0x7");
    }

    // Register location + stack_value + piece => implicit piece with register value.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 8);
        auto r = se.evaluate(expr, ctx, 0, {0x1234});
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 1);
        assert(r.pieces[0].kind == SymPiece::Kind::IMPLICIT);
        assert(r.pieces[0].byte_size == 8);
        assert(r.pieces[0].location && r.pieces[0].location->toString() == "0x1234");
    }

    // Address-like value explicitly marked with stack_value should remain an implicit value piece.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
        appendU64(expr, 0x2000);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 8);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 1);
        assert(r.pieces[0].kind == SymPiece::Kind::IMPLICIT);
        assert(r.pieces[0].byte_size == 8);
        assert(r.pieces[0].location && r.pieces[0].location->toString() == "0x2000");
    }

    std::cout << "SymbolicExpressionEvaluator stack_value piece tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorAddrxConstx() {
    std::cout << "Testing SymbolicExpressionEvaluator addrx/constx..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;
    std::vector<uint64_t> addr_table = {0x1111, 0x2222};
    ctx.debug_addr_table = &addr_table;

    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addrx));
        appendULEB(expr, 1);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "0x2222");
    }
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_constx));
        appendULEB(expr, 0);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "0x1111");
    }
    {
        EvaluationContext ctx2;
        ctx2.address_size = 8;
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addrx));
        appendULEB(expr, 7);
        auto r = se.evaluate(expr, ctx2);
        assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "addrx(7)");
    }

    std::cout << "SymbolicExpressionEvaluator addrx/constx tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorEntryValue() {
    std::cout << "Testing SymbolicExpressionEvaluator entry_value..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;
    ctx.entry_registers = std::vector<uint64_t>(64, 0);
    ctx.entry_registers[5] = 0xdeadbeef;

    // entry_value({reg5})
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_entry_value));
    // subexpr bytes:
    std::vector<uint8_t> sub;
    sub.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg5));
    appendULEB(expr, sub.size());
    expr.insert(expr.end(), sub.begin(), sub.end());

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::VALUE);
    assert(r.expression && r.expression->toString() == "0xdeadbeef");

    std::cout << "SymbolicExpressionEvaluator entry_value tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorImplicitValueLarge() {
    std::cout << "Testing SymbolicExpressionEvaluator implicit_value large..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
    appendULEB(expr, 9);
    for (int i = 0; i < 9; ++i) expr.push_back(static_cast<uint8_t>(i));

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::VALUE);
    assert(r.expression);
    assert(r.expression->toString() == "bytes(0x000102030405060708)");

    std::cout << "SymbolicExpressionEvaluator implicit_value large tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorBytesComparisons() {
    std::cout << "Testing SymbolicExpressionEvaluator bytes comparisons..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    auto appendImplicit9 = [](std::vector<uint8_t>& expr, uint8_t seed) {
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 9);
        for (int i = 0; i < 9; ++i) expr.push_back(static_cast<uint8_t>(seed + i));
    };

    // bytes == bytes (same payload) should fold to const true.
    {
        std::vector<uint8_t> expr;
        appendImplicit9(expr, 0x10);
        appendImplicit9(expr, 0x10);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_eq));

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "0x1");
    }

    // bytes != bytes (different payload) should fold to const true.
    {
        std::vector<uint8_t> expr;
        appendImplicit9(expr, 0x10);
        appendImplicit9(expr, 0x20);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "0x1");
    }

    // Folded bytes equality should drive concrete branch selection.
    {
        std::vector<uint8_t> expr;
        appendImplicit9(expr, 0x10);
        appendImplicit9(expr, 0x10);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_eq));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
        appendU16(expr, 4); // jump to true arm
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit1)); // false arm
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
        appendU16(expr, 1); // skip true arm
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit2)); // true arm

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "0x2");
    }

    std::cout << "SymbolicExpressionEvaluator bytes comparison tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorImplicitBytesDoNotBleed() {
    std::cout << "Testing SymbolicExpressionEvaluator implicit bytes do not bleed..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // implicit_value bytes should not be reused after a new top-of-stack push.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 1);
        expr.push_back(0x12);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1u));
        expr.push_back(0x34);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 1);

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 1);
        assert(r.pieces[0].kind == SymPiece::Kind::MEMORY);
        assert(r.pieces[0].location);
        assert(r.pieces[0].location->toString() == "0x34");
        assert(r.pieces[0].implicit_bytes.empty());
    }

    // const_type bytes should also stop applying once top-of-stack changes.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const_type));
        appendULEB(expr, 0);
        expr.push_back(2);
        expr.push_back(0x34);
        expr.push_back(0x12);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 8);

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 1);
        assert(r.pieces[0].kind == SymPiece::Kind::REGISTER);
        assert(r.pieces[0].location);
        assert(r.pieces[0].location->toString() == "0x0");
        assert(r.pieces[0].implicit_bytes.empty());
    }

    std::cout << "SymbolicExpressionEvaluator implicit bytes bleed tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorImplicitBytesPerStackEntryOps() {
    std::cout << "Testing SymbolicExpressionEvaluator implicit bytes per-stack ops..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // DUP should duplicate implicit-byte metadata for the duplicated stack entry.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 1);
        expr.push_back(0xab);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_dup));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 1);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 1);

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 2);
        assert(r.pieces[0].kind == SymPiece::Kind::IMPLICIT);
        assert(r.pieces[1].kind == SymPiece::Kind::IMPLICIT);
        assert(r.pieces[0].implicit_bytes.size() == 1 && r.pieces[0].implicit_bytes[0] == 0xab);
        assert(r.pieces[1].implicit_bytes.size() == 1 && r.pieces[1].implicit_bytes[0] == 0xab);
    }

    // SWAP should swap implicit-byte metadata alongside stack values.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 1);
        expr.push_back(0x11);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 1);
        expr.push_back(0x22);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_swap));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 1);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 1);

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 2);
        assert(r.pieces[0].kind == SymPiece::Kind::IMPLICIT);
        assert(r.pieces[1].kind == SymPiece::Kind::IMPLICIT);
        assert(r.pieces[0].implicit_bytes.size() == 1 && r.pieces[0].implicit_bytes[0] == 0x11);
        assert(r.pieces[1].implicit_bytes.size() == 1 && r.pieces[1].implicit_bytes[0] == 0x22);
    }

    // OVER should duplicate second-from-top with its implicit bytes.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 1);
        expr.push_back(0x11);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 1);
        expr.push_back(0x22);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_over));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 1);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 1);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 1);

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 3);
        assert(r.pieces[0].implicit_bytes.size() == 1 && r.pieces[0].implicit_bytes[0] == 0x11);
        assert(r.pieces[1].implicit_bytes.size() == 1 && r.pieces[1].implicit_bytes[0] == 0x22);
        assert(r.pieces[2].implicit_bytes.size() == 1 && r.pieces[2].implicit_bytes[0] == 0x11);
    }

    // PICK should duplicate the chosen entry with its implicit bytes.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 1);
        expr.push_back(0x11);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 1);
        expr.push_back(0x22);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 1);
        expr.push_back(0x33);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_pick));
        expr.push_back(2); // duplicate bottom value (0x11)
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 1);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 1);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 1);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 1);

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 4);
        assert(r.pieces[0].implicit_bytes.size() == 1 && r.pieces[0].implicit_bytes[0] == 0x11);
        assert(r.pieces[1].implicit_bytes.size() == 1 && r.pieces[1].implicit_bytes[0] == 0x33);
        assert(r.pieces[2].implicit_bytes.size() == 1 && r.pieces[2].implicit_bytes[0] == 0x22);
        assert(r.pieces[3].implicit_bytes.size() == 1 && r.pieces[3].implicit_bytes[0] == 0x11);
    }

    // ROT should rotate value+metadata in lockstep.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 1);
        expr.push_back(0x11);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 1);
        expr.push_back(0x22);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 1);
        expr.push_back(0x33);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_rot));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 1);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 1);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 1);

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 3);
        assert(r.pieces[0].implicit_bytes.size() == 1 && r.pieces[0].implicit_bytes[0] == 0x11);
        assert(r.pieces[1].implicit_bytes.size() == 1 && r.pieces[1].implicit_bytes[0] == 0x33);
        assert(r.pieces[2].implicit_bytes.size() == 1 && r.pieces[2].implicit_bytes[0] == 0x22);
    }

    std::cout << "SymbolicExpressionEvaluator implicit bytes per-stack ops tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorStackKindsPerEntryOps() {
    std::cout << "Testing SymbolicExpressionEvaluator stack kinds per-stack ops..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // OVER should duplicate REGISTER kind when source is a register location.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg1));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 1);
        expr.push_back(0x22);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_over));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 8);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 1);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 8);

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 3);
        assert(r.pieces[0].kind == SymPiece::Kind::REGISTER);
        assert(r.pieces[0].location && r.pieces[0].location->toString() == "0x1");
        assert(r.pieces[1].kind == SymPiece::Kind::IMPLICIT);
        assert(r.pieces[1].implicit_bytes.size() == 1 && r.pieces[1].implicit_bytes[0] == 0x22);
        assert(r.pieces[2].kind == SymPiece::Kind::REGISTER);
        assert(r.pieces[2].location && r.pieces[2].location->toString() == "0x1");
    }

    // PICK should duplicate chosen REGISTER kind.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg2)); // bottom
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 1);
        expr.push_back(0x33);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg4)); // top
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_pick));
        expr.push_back(2); // duplicate bottom reg2
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 8);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 8);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 1);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 8);

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 4);
        assert(r.pieces[0].kind == SymPiece::Kind::REGISTER);
        assert(r.pieces[0].location && r.pieces[0].location->toString() == "0x2");
        assert(r.pieces[1].kind == SymPiece::Kind::REGISTER);
        assert(r.pieces[1].location && r.pieces[1].location->toString() == "0x4");
        assert(r.pieces[2].kind == SymPiece::Kind::IMPLICIT);
        assert(r.pieces[2].implicit_bytes.size() == 1 && r.pieces[2].implicit_bytes[0] == 0x33);
        assert(r.pieces[3].kind == SymPiece::Kind::REGISTER);
        assert(r.pieces[3].location && r.pieces[3].location->toString() == "0x2");
    }

    // ROT should rotate stack kinds in lockstep with values.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg1));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 1);
        expr.push_back(0x44);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg3));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_rot));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 8);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 8);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece)); appendULEB(expr, 1);

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 3);
        assert(r.pieces[0].kind == SymPiece::Kind::REGISTER);
        assert(r.pieces[0].location && r.pieces[0].location->toString() == "0x1");
        assert(r.pieces[1].kind == SymPiece::Kind::REGISTER);
        assert(r.pieces[1].location && r.pieces[1].location->toString() == "0x3");
        assert(r.pieces[2].kind == SymPiece::Kind::IMPLICIT);
        assert(r.pieces[2].implicit_bytes.size() == 1 && r.pieces[2].implicit_bytes[0] == 0x44);
    }

    // Final result kind should come from top-of-stack kind after swap.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, 1);
        expr.push_back(0x55);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_swap)); // top becomes implicit value

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "0x55");
    }

    std::cout << "SymbolicExpressionEvaluator stack kinds per-stack ops tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorComputationMaterializationAndKinds() {
    std::cout << "Testing SymbolicExpressionEvaluator computation materialization/kinds..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // Arithmetic should materialize register locations to register values.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg1));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1u));
        expr.push_back(8);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));

        std::vector<uint64_t> regs = {0, 0x1000};
        auto r = se.evaluate(expr, ctx, 0, regs);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "0x1008");
    }

    // Branch condition should use register value, not register number.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
        appendU16(expr, 4); // jump to lit2 when cond != 0
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit1));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
        appendU16(expr, 1); // skip over lit2
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit2));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_nop));

        auto r_true = se.evaluate(expr, ctx, 0, {7});
        assert(r_true.expression && r_true.expression->toString() == "0x2");

        auto r_false = se.evaluate(expr, ctx, 0, {0});
        assert(r_false.expression && r_false.expression->toString() == "0x1");
    }

    // plus_uconst over a value should keep VALUE kind, so piece becomes implicit.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg0));
        expr.push_back(0x00); // sleb128(0)
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_deref));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus_uconst));
        appendULEB(expr, 1);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 8);

        auto r = se.evaluate(expr, ctx, 0, {0x1000});
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 1);
        assert(r.pieces[0].kind == SymPiece::Kind::IMPLICIT);
        assert(r.pieces[0].byte_size == 8);
        assert(r.pieces[0].location);
    }

    // Unary arithmetic should also materialize register values.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg1));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_neg));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));

        auto r = se.evaluate(expr, ctx, 0, {0, 3});
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "0xfffffffffffffffd");
    }

    // convert/reinterpret should materialize register values before type operation.
    {
        EvaluationContext tctx = ctx;
        tctx.resolve_base_type = [](uint64_t off) -> std::optional<EvaluationContext::BaseTypeInfo> {
            EvaluationContext::BaseTypeInfo ti;
            if (off == 0x11) {
                ti.byte_size = 1;
                ti.is_integer = true;
                ti.is_signed = true;
                ti.encoding = DW_ATE::DW_ATE_signed;
                return ti;
            }
            if (off == 0x12) {
                ti.byte_size = 1;
                ti.is_integer = true;
                ti.is_signed = false;
                ti.encoding = DW_ATE::DW_ATE_unsigned;
                return ti;
            }
            return std::nullopt;
        };

        std::vector<uint8_t> expr_convert;
        expr_convert.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg1));
        expr_convert.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_convert));
        appendULEB(expr_convert, 0x11);
        auto rc = se.evaluate(expr_convert, tctx, 0, {0, 0xff80});
        assert(rc.type == SymbolicExpressionResult::Type::VALUE);
        assert(rc.expression && rc.expression->toString() == "0xffffffffffffff80");

        std::vector<uint8_t> expr_reinterpret;
        expr_reinterpret.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg1));
        expr_reinterpret.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reinterpret));
        appendULEB(expr_reinterpret, 0x12);
        auto rr = se.evaluate(expr_reinterpret, tctx, 0, {0, 0xff80});
        assert(rr.type == SymbolicExpressionResult::Type::VALUE);
        assert(rr.expression && rr.expression->toString() == "0x80");
    }

    std::cout << "SymbolicExpressionEvaluator computation materialization/kinds tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorImplicitPointer() {
    std::cout << "Testing SymbolicExpressionEvaluator implicit_pointer..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;
    ctx.offset_size = 4;

    // implicit_pointer(die_ref=0x12345678, off=-8)
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_pointer));
    appendU32(expr, 0x12345678);
    // SLEB(-8) = 0x78
    expr.push_back(0x78);

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::VALUE);
    assert(r.expression);
    assert(r.expression->toString() == "0x12345670");

    // Resolver path with section-bias and GNU alias.
    EvaluationContext ctx2 = ctx;
    ctx2.cu_base_offset = (1ULL << 63) | 0x500;
    ctx2.resolve_dwarf_procedure = [](uint64_t off, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
        if (off == ((1ULL << 63) + 0x20)) {
            std::vector<uint8_t> sub;
            sub.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
            appendU64(sub, 0x4000);
            return sub;
        }
        return std::nullopt;
    };

    std::vector<uint8_t> gnu_expr;
    gnu_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_implicit_pointer));
    appendU32(gnu_expr, 0x20);
    gnu_expr.push_back(0x08); // SLEB(+8)
    auto r2 = se.evaluate(gnu_expr, ctx2);
    assert(r2.type == SymbolicExpressionResult::Type::VALUE);
    assert(r2.expression && r2.expression->toString() == "0x4008");

    std::cout << "SymbolicExpressionEvaluator implicit_pointer tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorTypedOpsAndBranches() {
    std::cout << "Testing SymbolicExpressionEvaluator typed ops and branches..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;
    ctx.cu_base_offset = 0;
    ctx.resolve_base_type = [](uint64_t off) -> std::optional<EvaluationContext::BaseTypeInfo> {
        EvaluationContext::BaseTypeInfo ti;
        if (off == 0x10) {
            ti.byte_size = 4;
            ti.is_integer = true;
            ti.is_signed = false;
            ti.encoding = DW_ATE::DW_ATE_unsigned;
            return ti;
        }
        if (off == 0x20) {
            ti.byte_size = 2;
            ti.is_integer = true;
            ti.is_signed = true;
            ti.encoding = DW_ATE::DW_ATE_signed;
            return ti;
        }
        return std::nullopt;
    };

    // regval_type(reg=5, type=0x10) with concrete reg value -> mask4(0x...) => const fold.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_regval_type));
        appendULEB(expr, 5);
        appendULEB(expr, 0x10);
        std::vector<uint64_t> regs(16, 0);
        regs[5] = 0x1122334455667788ULL;
        auto r = se.evaluate(expr, ctx, 0, regs);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "0x55667788");
    }

    // convert(type=0x20) should sign-extend from 2 bytes.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const4u));
        appendU32(expr, 0x0000ff80); // low 16 = 0xff80 (-128 in int16)
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_convert));
        appendULEB(expr, 0x20);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::VALUE || r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "0xffffffffffffff80");
    }

    // bra with concrete true condition: skip over const1u 1 and take const1u 2.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit1)); // cond=true
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
        appendU16(expr, 2); // jump over next const1u operand pair
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1u));
        expr.push_back(1);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1u));
        expr.push_back(2);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "0x2");
    }

    std::cout << "SymbolicExpressionEvaluator typed/branch tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraITE() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra ITE merge..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0) then 2 else 1
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    appendU16(expr, 4); // to true arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit1)); // false arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    appendU16(expr, 1); // skip true arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit2)); // true arm

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
    assert(r.expression);
    assert(r.expression->toString() == "ite((reg5 != 0x0),0x2,0x1)");

    std::cout << "SymbolicExpressionEvaluator symbolic bra ITE tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraDepthLimit() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra depth limit..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // Symbolic condition with self-branch:
    //   reg0; stack_value; bra -5; lit1
    // The taken edge loops to start with symbolic condition.
    std::vector<uint8_t> expr = {
        static_cast<uint8_t>(DwarfOp::DW_OP_reg0),
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        static_cast<uint8_t>(DwarfOp::DW_OP_bra),
        0xfb, 0xff, // -5
        static_cast<uint8_t>(DwarfOp::DW_OP_lit1),
    };

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::INVALID);
    assert(r.error.find("symbolic bra depth limit") != std::string::npos);

    std::cout << "SymbolicExpressionEvaluator symbolic bra depth limit tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraWithStackState() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra with pre-existing stack..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0) then (10 + 2) else (10 + 1)
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit10));  // preserved stack value
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    appendU16(expr, 5);   // to true arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit1));   // false arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    appendU16(expr, 2);   // skip true arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit2));   // true arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus));

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::VALUE);
    assert(r.expression);
    assert(r.expression->toString() == "ite((reg5 != 0x0),0xc,0xb)");

    std::cout << "SymbolicExpressionEvaluator symbolic bra stack-state tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraCompositePieces() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra composite merge..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0):
    //   then  -> piece(reg0,8) + piece(reg1,8)
    //   else  -> piece(reg2,8) + piece(reg3,8)
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    appendU16(expr, 9); // jump to true arm

    // false arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg2));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(expr, 8);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg3));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(expr, 8);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    appendU16(expr, 6); // skip true arm

    // true arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(expr, 8);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg1));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(expr, 8);

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
    assert(r.pieces.size() == 2);
    assert(r.pieces[0].kind == SymPiece::Kind::REGISTER);
    assert(r.pieces[0].byte_size == 8);
    assert(r.pieces[0].location);
    assert(r.pieces[0].location->toString() == "ite((reg5 != 0x0),0x0,0x2)");
    assert(r.pieces[1].kind == SymPiece::Kind::REGISTER);
    assert(r.pieces[1].byte_size == 8);
    assert(r.pieces[1].location);
    assert(r.pieces[1].location->toString() == "ite((reg5 != 0x0),0x1,0x3)");

    std::cout << "SymbolicExpressionEvaluator symbolic bra composite tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraRegisterMismatchIsInvalid() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra register mismatch..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0): then reg0 else reg2
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    appendU16(expr, 4); // jump to true arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg2)); // false arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    appendU16(expr, 1); // skip true arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0)); // true arm

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::INVALID);
    assert(r.error.find("register mismatch") != std::string::npos);

    std::cout << "SymbolicExpressionEvaluator symbolic bra register mismatch tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraAddressValueMerge() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra address/value merge..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0): then value(7) else address(0x1000)
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    appendU16(expr, 12); // jump over false arm to true arm

    // false arm: address
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
    appendU64(expr, 0x1000);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    appendU16(expr, 2); // skip true arm

    // true arm: stack value
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit7));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::VALUE);
    assert(r.expression);
    assert(r.expression->toString() == "ite((reg5 != 0x0),0x7,load(0x1000,8))");

    std::cout << "SymbolicExpressionEvaluator symbolic bra address/value tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraRegisterValueMerge() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra register/value merge..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0): then register-location(reg0) else value(7)
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    appendU16(expr, 5); // jump over false arm to true arm

    // false arm: value
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit7));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    appendU16(expr, 1); // skip true arm

    // true arm: register location
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0));

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::VALUE);
    assert(r.expression);
    assert(r.expression->toString() == "ite((reg5 != 0x0),reg0,0x7)");

    std::cout << "SymbolicExpressionEvaluator symbolic bra register/value tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraRegisterAddressMerge() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra register/address merge..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0): then register-location(reg0) else address(0x1000)
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    appendU16(expr, 12); // jump over false arm to true arm

    // false arm: address
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
    appendU64(expr, 0x1000);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    appendU16(expr, 1); // skip true arm

    // true arm: register location
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0));

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::VALUE);
    assert(r.expression);
    assert(r.expression->toString() == "ite((reg5 != 0x0),reg0,load(0x1000,8))");

    std::cout << "SymbolicExpressionEvaluator symbolic bra register/address tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraRegisterSameMerge() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra same-register merge..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0): then reg0 else reg0
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    appendU16(expr, 4); // jump to true arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0)); // false arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    appendU16(expr, 1); // skip true arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0)); // true arm

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::REGISTER);
    assert(r.expression);
    assert(r.expression->toString() == "0x0");

    std::cout << "SymbolicExpressionEvaluator symbolic bra same-register tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraCompositeKindMismatchMerge() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra composite kind-mismatch merge..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0):
    //   then  -> register piece (reg0, size 8)
    //   else  -> memory piece (addr 0x1000, size 8)
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    appendU16(expr, 14); // jump over false arm to true arm

    // false arm: memory piece
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
    appendU64(expr, 0x1000);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(expr, 8);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    appendU16(expr, 3); // skip true arm

    // true arm: register piece
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(expr, 8);

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
    assert(r.pieces.size() == 1);
    assert(r.pieces[0].kind == SymPiece::Kind::IMPLICIT);
    assert(r.pieces[0].byte_size == 8);
    assert(r.pieces[0].implicit_bytes.empty());
    assert(r.pieces[0].location);
    assert(r.pieces[0].location->toString() == "ite((reg5 != 0x0),reg0,load(0x1000,8))");

    std::cout << "SymbolicExpressionEvaluator symbolic bra composite kind-mismatch tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraCompositeUnavailableMerge() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra composite unavailable-piece merge..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0):
    //   then  -> unavailable piece(8)
    //   else  -> memory piece(8) at 0x1000
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    appendU16(expr, 14); // jump over false arm to true arm

    // false arm: memory piece
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
    appendU64(expr, 0x1000);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(expr, 8);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    appendU16(expr, 2); // skip true arm

    // true arm: unavailable piece
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(expr, 8);

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
    assert(r.pieces.size() == 1);
    assert(r.pieces[0].kind == SymPiece::Kind::IMPLICIT);
    assert(r.pieces[0].byte_size == 8);
    assert(r.pieces[0].location);
    assert(r.pieces[0].location->toString() ==
           "ite((reg5 != 0x0),unknown(unavail_piece8),load(0x1000,8))");

    std::cout << "SymbolicExpressionEvaluator symbolic bra composite unavailable-piece tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraCompositeBitPieceUnavailableMerge() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra bit_piece unavailable merge..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0):
    //   then  -> unavailable bit_piece(3,1)
    //   else  -> memory bit_piece(3,1) at 0x1000
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    appendU16(expr, 15); // jump over false arm to true arm

    // false arm: memory bit_piece
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
    appendU64(expr, 0x1000);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bit_piece));
    appendULEB(expr, 3);
    appendULEB(expr, 1);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    appendU16(expr, 3); // skip true arm

    // true arm: unavailable bit_piece
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bit_piece));
    appendULEB(expr, 3);
    appendULEB(expr, 1);

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
    assert(r.pieces.size() == 1);
    assert(r.pieces[0].kind == SymPiece::Kind::IMPLICIT);
    assert(r.pieces[0].bit_size == 3);
    assert(r.pieces[0].bit_offset == 1);
    assert(r.pieces[0].location);
    assert(r.pieces[0].location->toString() ==
           "ite((reg5 != 0x0),unknown(unavail_bit_piece3),load(0x1000,1))");

    std::cout << "SymbolicExpressionEvaluator symbolic bra bit_piece unavailable tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraCompositeImplicitMerge() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra implicit-piece merge..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0):
    //   then  -> implicit_value(0x22), piece(1)
    //   else  -> implicit_value(0x11), piece(1)
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    appendU16(expr, 8); // jump over false arm to true arm

    // false arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
    appendULEB(expr, 1);
    expr.push_back(0x11);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(expr, 1);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    appendU16(expr, 5); // skip true arm

    // true arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
    appendULEB(expr, 1);
    expr.push_back(0x22);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(expr, 1);

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
    assert(r.pieces.size() == 1);
    assert(r.pieces[0].kind == SymPiece::Kind::IMPLICIT);
    assert(r.pieces[0].byte_size == 1);
    assert(r.pieces[0].implicit_bytes.empty());
    assert(r.pieces[0].location);
    assert(r.pieces[0].location->toString() == "ite((reg5 != 0x0),0x22,0x11)");

    std::cout << "SymbolicExpressionEvaluator symbolic bra implicit-piece tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraCompositeImplicitMergeLargeBytes() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra implicit-piece merge (large bytes)..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    std::vector<uint8_t> false_arm;
    false_arm.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
    appendULEB(false_arm, 9);
    false_arm.push_back(0x10);
    false_arm.push_back(0x11);
    false_arm.push_back(0x12);
    false_arm.push_back(0x13);
    false_arm.push_back(0x14);
    false_arm.push_back(0x15);
    false_arm.push_back(0x16);
    false_arm.push_back(0x17);
    false_arm.push_back(0x18);
    false_arm.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(false_arm, 9);

    std::vector<uint8_t> true_arm;
    true_arm.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
    appendULEB(true_arm, 9);
    true_arm.push_back(0xaa);
    true_arm.push_back(0xbb);
    true_arm.push_back(0xcc);
    true_arm.push_back(0xdd);
    true_arm.push_back(0xee);
    true_arm.push_back(0xff);
    true_arm.push_back(0x01);
    true_arm.push_back(0x02);
    true_arm.push_back(0x03);
    true_arm.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(true_arm, 9);

    // if (reg5 != 0): then true_arm else false_arm
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    size_t bra_rel_off = expr.size();
    appendU16(expr, 0); // patched below

    size_t false_start = expr.size();
    expr.insert(expr.end(), false_arm.begin(), false_arm.end());
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    size_t skip_rel_off = expr.size();
    appendU16(expr, 0); // patched below

    size_t true_start = expr.size();
    expr.insert(expr.end(), true_arm.begin(), true_arm.end());
    size_t end_off = expr.size();

    uint16_t bra_rel = static_cast<uint16_t>(true_start - false_start);
    expr[bra_rel_off] = static_cast<uint8_t>(bra_rel & 0xff);
    expr[bra_rel_off + 1] = static_cast<uint8_t>((bra_rel >> 8) & 0xff);

    uint16_t skip_rel = static_cast<uint16_t>(end_off - true_start);
    expr[skip_rel_off] = static_cast<uint8_t>(skip_rel & 0xff);
    expr[skip_rel_off + 1] = static_cast<uint8_t>((skip_rel >> 8) & 0xff);

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
    assert(r.pieces.size() == 1);
    assert(r.pieces[0].kind == SymPiece::Kind::IMPLICIT);
    assert(r.pieces[0].byte_size == 9);
    assert(r.pieces[0].implicit_bytes.empty());
    assert(r.pieces[0].location);
    assert(r.pieces[0].location->toString() ==
           "ite((reg5 != 0x0),bytes(0xaabbccddeeff010203),bytes(0x101112131415161718))");

    std::cout << "SymbolicExpressionEvaluator symbolic bra implicit-piece large-byte tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraCompositeImplicitNestedMerge() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra implicit-piece nested merge..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0):
    //   if (reg6 != 0): implicit 0x22 else implicit 0x33
    // else:
    //   implicit 0x11
    std::vector<uint8_t> false_outer;
    false_outer.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
    appendULEB(false_outer, 1);
    false_outer.push_back(0x11);
    false_outer.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(false_outer, 1);

    std::vector<uint8_t> false_inner;
    false_inner.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
    appendULEB(false_inner, 1);
    false_inner.push_back(0x33);
    false_inner.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(false_inner, 1);

    std::vector<uint8_t> true_inner;
    true_inner.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
    appendULEB(true_inner, 1);
    true_inner.push_back(0x22);
    true_inner.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(true_inner, 1);

    std::vector<uint8_t> true_outer;
    true_outer.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg6));
    true_outer.push_back(0x00); // SLEB(0)
    true_outer.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    true_outer.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    true_outer.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    size_t inner_bra_rel_off = true_outer.size();
    appendU16(true_outer, 0); // patch
    size_t inner_false_start = true_outer.size();
    true_outer.insert(true_outer.end(), false_inner.begin(), false_inner.end());
    true_outer.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    size_t inner_skip_rel_off = true_outer.size();
    appendU16(true_outer, 0); // patch
    size_t inner_true_start = true_outer.size();
    true_outer.insert(true_outer.end(), true_inner.begin(), true_inner.end());
    size_t inner_end = true_outer.size();

    uint16_t inner_bra_rel = static_cast<uint16_t>(inner_true_start - inner_false_start);
    true_outer[inner_bra_rel_off] = static_cast<uint8_t>(inner_bra_rel & 0xff);
    true_outer[inner_bra_rel_off + 1] = static_cast<uint8_t>((inner_bra_rel >> 8) & 0xff);
    uint16_t inner_skip_rel = static_cast<uint16_t>(inner_end - inner_true_start);
    true_outer[inner_skip_rel_off] = static_cast<uint8_t>(inner_skip_rel & 0xff);
    true_outer[inner_skip_rel_off + 1] = static_cast<uint8_t>((inner_skip_rel >> 8) & 0xff);

    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    size_t outer_bra_rel_off = expr.size();
    appendU16(expr, 0); // patch
    size_t outer_false_start = expr.size();
    expr.insert(expr.end(), false_outer.begin(), false_outer.end());
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    size_t outer_skip_rel_off = expr.size();
    appendU16(expr, 0); // patch
    size_t outer_true_start = expr.size();
    expr.insert(expr.end(), true_outer.begin(), true_outer.end());
    size_t outer_end = expr.size();

    uint16_t outer_bra_rel = static_cast<uint16_t>(outer_true_start - outer_false_start);
    expr[outer_bra_rel_off] = static_cast<uint8_t>(outer_bra_rel & 0xff);
    expr[outer_bra_rel_off + 1] = static_cast<uint8_t>((outer_bra_rel >> 8) & 0xff);
    uint16_t outer_skip_rel = static_cast<uint16_t>(outer_end - outer_true_start);
    expr[outer_skip_rel_off] = static_cast<uint8_t>(outer_skip_rel & 0xff);
    expr[outer_skip_rel_off + 1] = static_cast<uint8_t>((outer_skip_rel >> 8) & 0xff);

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
    assert(r.pieces.size() == 1);
    assert(r.pieces[0].kind == SymPiece::Kind::IMPLICIT);
    assert(r.pieces[0].byte_size == 1);
    assert(r.pieces[0].implicit_bytes.empty());
    assert(r.pieces[0].location);
    assert(r.pieces[0].location->toString() ==
           "ite((reg5 != 0x0),ite((reg6 != 0x0),0x22,0x33),0x11)");

    std::cout << "SymbolicExpressionEvaluator symbolic bra implicit-piece nested tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorXderefAndXderefType() {
    std::cout << "Testing SymbolicExpressionEvaluator xderef ops..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;
    ctx.cu_base_offset = 0;
    ctx.resolve_base_type = [](uint64_t off) -> std::optional<EvaluationContext::BaseTypeInfo> {
        if (off == 0x20) {
            EvaluationContext::BaseTypeInfo ti;
            ti.byte_size = 2;
            ti.is_integer = true;
            ti.is_signed = true;
            ti.encoding = DW_ATE::DW_ATE_signed;
            return ti;
        }
        return std::nullopt;
    };

    // xderef_size: pops addr-space then addr, models load(addr, size).
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1u)); // addr-space
        expr.push_back(7);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));    // addr
        appendU64(expr, 0x3000);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_xderef_size));
        expr.push_back(4);

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "load(0x3000,4)");
    }

    // xderef_type: typed load + sign extension.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1u)); // addr-space
        expr.push_back(1);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));    // addr
        appendU64(expr, 0x3000);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_xderef_type));
        expr.push_back(1);     // load size=1
        appendULEB(expr, 0x20); // type offset -> signed 2-byte type

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "sext2(load(0x3000,1))");
    }

    std::cout << "SymbolicExpressionEvaluator xderef tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorCallOpsAndGnuIndices() {
    std::cout << "Testing SymbolicExpressionEvaluator call ops and GNU indices..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;
    ctx.offset_size = 4;
    ctx.cu_base_offset = 0x1000;

    std::vector<uint64_t> addr_table = {0x4444};
    ctx.debug_addr_table = &addr_table;

    // GNU addr/const index aliases.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_addr_index));
        appendULEB(expr, 0);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "0x4444");
    }
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_const_index));
        appendULEB(expr, 0);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "0x4444");
    }

    // call2: resolver gets CU-relative absolute offset.
    ctx.resolve_dwarf_procedure = [](uint64_t off, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
        if (off == 0x1010) {
            return std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_lit3)};
        }
        if (off == 0x1014) {
            return std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_reg3)};
        }
        if (off == 0x1018) {
            return std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_breg1), 0x00};
        }
        if (off == 0x1020) {
            return std::vector<uint8_t>{
                static_cast<uint8_t>(DwarfOp::DW_OP_lit2),
                static_cast<uint8_t>(DwarfOp::DW_OP_plus),
            };
        }
        if (off == 0x1024) {
            return std::vector<uint8_t>{
                static_cast<uint8_t>(DwarfOp::DW_OP_lit4),
                static_cast<uint8_t>(DwarfOp::DW_OP_plus),
            };
        }
        if (off == 0x101c) {
            // Malformed subexpression (truncated const4u operand).
            return std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_const4u), 0xaa};
        }
        return std::nullopt;
    };
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit1));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call2));
        appendU16(expr, 0x10);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus));
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::VALUE || r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "0x4");
    }
    // call2 executes subexpression in-place over caller stack.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit1));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call2));
        appendU16(expr, 0x20); // subexpr: lit2; plus
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "0x3");
    }
    // call4 executes subexpression in-place over caller stack.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit3));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call4));
        appendU32(expr, 0x24); // subexpr: lit4; plus
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "0x7");
    }
    // call2 should preserve REGISTER kind from subexpression.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call2));
        appendU16(expr, 0x14);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 8);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 1);
        assert(r.pieces[0].kind == SymPiece::Kind::REGISTER);
        assert(r.pieces[0].byte_size == 8);
        assert(r.pieces[0].location && r.pieces[0].location->toString() == "0x3");
    }
    // call4 should preserve ADDRESS kind from subexpression.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call4));
        appendU32(expr, 0x18);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 8);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 1);
        assert(r.pieces[0].kind == SymPiece::Kind::MEMORY);
        assert(r.pieces[0].byte_size == 8);
        assert(r.pieces[0].location && r.pieces[0].location->toString() == "reg1");
    }

    // call_ref: resolver gets section-bias + reference offset.
    {
        EvaluationContext ctx_ref = ctx;
        ctx_ref.cu_base_offset = (1ULL << 63) | 0x500; // DWO-biased CU base
        ctx_ref.resolve_dwarf_procedure = [](uint64_t off, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
            if (off == ((1ULL << 63) + 0x20)) {
                return std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_lit4)};
            }
            return std::nullopt;
        };
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call_ref));
        appendU32(expr, 0x20);
        auto r = se.evaluate(expr, ctx_ref);
        assert(r.type == SymbolicExpressionResult::Type::VALUE || r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "0x4");
    }
    // call_ref also executes subexpression in-place over caller stack.
    {
        EvaluationContext ctx_ref = ctx;
        ctx_ref.resolve_dwarf_procedure = [](uint64_t off, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
            if (off == 0x24) {
                return std::vector<uint8_t>{
                    static_cast<uint8_t>(DwarfOp::DW_OP_lit5),
                    static_cast<uint8_t>(DwarfOp::DW_OP_plus),
                };
            }
            return std::nullopt;
        };
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit2));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call_ref));
        appendU32(expr, 0x24);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
        auto r = se.evaluate(expr, ctx_ref);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "0x7");
    }

    // Malformed call subexpression is fatal (matches concrete evaluator behavior).
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call2));
        appendU16(expr, 0x1c);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::INVALID);
        assert(r.error.find("DW_OP_call2") != std::string::npos);
    }

    // call_ref without resolver is a no-op (matches concrete evaluator).
    {
        EvaluationContext ctx_no_resolver = ctx;
        ctx_no_resolver.resolve_dwarf_procedure = {};
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit9));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call_ref));
        appendU32(expr, 0x20);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
        auto r = se.evaluate(expr, ctx_no_resolver);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression);
        assert(r.expression->toString() == "0x9");
    }

    // call2/call4 without resolver are no-ops as well.
    {
        EvaluationContext ctx_no_resolver = ctx;
        ctx_no_resolver.resolve_dwarf_procedure = {};

        std::vector<uint8_t> expr2;
        expr2.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit6));
        expr2.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call2));
        appendU16(expr2, 0x10);
        expr2.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
        auto r2 = se.evaluate(expr2, ctx_no_resolver);
        assert(r2.type == SymbolicExpressionResult::Type::VALUE);
        assert(r2.expression);
        assert(r2.expression->toString() == "0x6");

        std::vector<uint8_t> expr4;
        expr4.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit7));
        expr4.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call4));
        appendU32(expr4, 0x10);
        expr4.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
        auto r4 = se.evaluate(expr4, ctx_no_resolver);
        assert(r4.type == SymbolicExpressionResult::Type::VALUE);
        assert(r4.expression);
        assert(r4.expression->toString() == "0x7");
    }

    // Resolver miss (no_proc) is also a no-op.
    {
        EvaluationContext ctx_no_proc = ctx;
        ctx_no_proc.resolve_dwarf_procedure = [](uint64_t /*off*/, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
            return std::nullopt;
        };

        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit8));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call2));
        appendU16(expr, 0x44);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
        auto r = se.evaluate(expr, ctx_no_proc);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "0x8");

        std::vector<uint8_t> expr4;
        expr4.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit5));
        expr4.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call4));
        appendU32(expr4, 0x44);
        expr4.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
        auto r4 = se.evaluate(expr4, ctx_no_proc);
        assert(r4.type == SymbolicExpressionResult::Type::VALUE);
        assert(r4.expression && r4.expression->toString() == "0x5");

        std::vector<uint8_t> expr_ref;
        expr_ref.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit4));
        expr_ref.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_call_ref));
        appendU32(expr_ref, 0x44);
        expr_ref.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));
        auto rr = se.evaluate(expr_ref, ctx_no_proc);
        assert(rr.type == SymbolicExpressionResult::Type::VALUE);
        assert(rr.expression && rr.expression->toString() == "0x4");
    }

    std::cout << "SymbolicExpressionEvaluator call/GNU-index tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorGnuTypedAndParameterOps() {
    std::cout << "Testing SymbolicExpressionEvaluator GNU typed/parameter ops..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;
    ctx.offset_size = 4;
    ctx.cu_base_offset = 0;
    ctx.resolve_base_type = [](uint64_t off) -> std::optional<EvaluationContext::BaseTypeInfo> {
        EvaluationContext::BaseTypeInfo ti;
        if (off == 0x31) {
            ti.byte_size = 1;
            ti.is_integer = true;
            ti.is_signed = true;
            ti.encoding = DW_ATE::DW_ATE_signed;
            return ti;
        }
        if (off == 0x41) {
            ti.byte_size = 2;
            ti.is_integer = true;
            ti.is_signed = true;
            ti.encoding = DW_ATE::DW_ATE_signed;
            return ti;
        }
        if (off == 0x42) {
            ti.byte_size = 2;
            ti.is_integer = true;
            ti.is_signed = false;
            ti.encoding = DW_ATE::DW_ATE_unsigned;
            return ti;
        }
        return std::nullopt;
    };

    // const_type with signed 1-byte base type: 0x80 => -128.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const_type));
        appendULEB(expr, 0x31);
        expr.push_back(1);
        expr.push_back(0x80);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "0xffffffffffffff80");
    }

    // GNU_const_type should alias const_type and preserve bytes for DW_OP_piece.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_const_type));
        appendULEB(expr, 0); // no type normalization
        expr.push_back(2);
        expr.push_back(0x34);
        expr.push_back(0x12);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
        appendULEB(expr, 2);

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
        assert(r.pieces.size() == 1);
        assert(r.pieces[0].kind == SymPiece::Kind::IMPLICIT);
        assert(r.pieces[0].byte_size == 2);
        assert(r.pieces[0].implicit_bytes.size() == 2);
        assert(r.pieces[0].implicit_bytes[0] == 0x34);
        assert(r.pieces[0].implicit_bytes[1] == 0x12);
    }

    // const_type larger than u64 should preserve full bytes as a symbolic byte literal.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const_type));
        appendULEB(expr, 0); // no type normalization
        expr.push_back(9);
        expr.push_back(0x10);
        expr.push_back(0x11);
        expr.push_back(0x12);
        expr.push_back(0x13);
        expr.push_back(0x14);
        expr.push_back(0x15);
        expr.push_back(0x16);
        expr.push_back(0x17);
        expr.push_back(0x18);

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "bytes(0x101112131415161718)");
    }

    // const_type(size>8) + signed base type should fold BYTES -> const via sext.
    {
        std::vector<uint8_t> payload = {0x80, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x00};
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const_type));
        appendULEB(expr, 0x41);
        expr.push_back(static_cast<uint8_t>(payload.size()));
        expr.insert(expr.end(), payload.begin(), payload.end());

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression);
        assert(r.expression->kind == SymExpr::Kind::CONST_U64);

        uint64_t raw2 = 0;
        if (DwarfUtils::objectIsLittleEndian()) {
            raw2 = static_cast<uint64_t>(payload[0]) |
                   (static_cast<uint64_t>(payload[1]) << 8);
        } else {
            raw2 = (static_cast<uint64_t>(payload[payload.size() - 2]) << 8) |
                   static_cast<uint64_t>(payload[payload.size() - 1]);
        }
        uint64_t expected = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int16_t>(raw2 & 0xffff)));
        assert(r.expression->const_u64 == expected);
    }

    // implicit_value(size>8) + convert(unsigned 2-byte type) should fold BYTES -> const via mask.
    {
        std::vector<uint8_t> payload = {0x34, 0x12, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value));
        appendULEB(expr, payload.size());
        expr.insert(expr.end(), payload.begin(), payload.end());
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_convert));
        appendULEB(expr, 0x42);

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression);
        assert(r.expression->kind == SymExpr::Kind::CONST_U64);

        uint64_t expected = 0;
        if (DwarfUtils::objectIsLittleEndian()) {
            expected = static_cast<uint64_t>(payload[0]) |
                       (static_cast<uint64_t>(payload[1]) << 8);
        } else {
            expected = (static_cast<uint64_t>(payload[payload.size() - 2]) << 8) |
                       static_cast<uint64_t>(payload[payload.size() - 1]);
        }
        assert(r.expression->const_u64 == expected);
    }

    // GNU_parameter_ref resolves section-relative DIE and yields parameter value.
    {
        EvaluationContext pctx = ctx;
        pctx.cu_base_offset = (1ULL << 63) | 0x100;
        pctx.resolve_dwarf_procedure = [](uint64_t off, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
            if (off == ((1ULL << 63) + 0x55)) {
                return std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_reg3)};
            }
            return std::nullopt;
        };

        std::vector<uint64_t> regs(8, 0);
        regs[3] = 0xabc;

        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_parameter_ref));
        appendU32(expr, 0x55);

        auto r = se.evaluate(expr, pctx, 0, regs);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "0xabc");
    }

    // GNU_parameter_ref fallback without resolver: push absolute referenced DIE offset.
    {
        EvaluationContext pctx = ctx;
        pctx.cu_base_offset = (1ULL << 63) | 0x100;
        pctx.resolve_dwarf_procedure = nullptr;

        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_parameter_ref));
        appendU32(expr, 0x55);

        auto r = se.evaluate(expr, pctx);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "0x8000000000000055");
    }

    // GNU_parameter_ref resolver miss should push zero (concrete-evaluator-compatible fallback).
    {
        EvaluationContext pctx = ctx;
        pctx.cu_base_offset = (1ULL << 63) | 0x100;
        pctx.resolve_dwarf_procedure = [](uint64_t /*off*/, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
            return std::nullopt;
        };

        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_parameter_ref));
        appendU32(expr, 0x55);

        auto r = se.evaluate(expr, pctx);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "0x0");
    }

    // GNU_uninit is informational/no-op.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1u));
        expr.push_back(5);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_uninit));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus_uconst));
        appendULEB(expr, 1);

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "0x6");
    }

    // GNU_encoded_addr: pcrel + udata4 (0x13) should resolve to pc + raw.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr));
        expr.push_back(0x13); // DW_EH_PE_udata4 | DW_EH_PE_pcrel
        appendU32(expr, 0x20);

        auto r = se.evaluate(expr, ctx, 0x1000);
        assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "0x1020");
    }

    std::cout << "SymbolicExpressionEvaluator GNU typed/parameter tests passed!" << std::endl;
}

void testExpressionVerifier() {
    std::cout << "Testing ExpressionVerifier..." << std::endl;

    ExpressionVerifier verifier;
    EvaluationContext ctx;
    ctx.address_size = 8;
    ctx.offset_size = 4;

    // Commutative rewrite should verify as equivalent.
    {
        std::vector<uint8_t> lhs;
        lhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg1));
        lhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1u));
        lhs.push_back(1);
        lhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus));
        lhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));

        std::vector<uint8_t> rhs;
        rhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1u));
        rhs.push_back(1);
        rhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg1));
        rhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus));
        rhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));

        auto r = verifier.verify(lhs, rhs, ctx);
        assert(r.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT);
    }

    // Non-equivalent rewrite should produce a concrete counterexample.
    {
        std::vector<uint8_t> lhs;
        lhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg1));
        lhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1u));
        lhs.push_back(1);
        lhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus));
        lhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));

        std::vector<uint8_t> rhs;
        rhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg1));
        rhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1u));
        rhs.push_back(2);
        rhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus));
        rhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));

        ExpressionVerificationOptions opts;
        opts.differential_trials = 16;
        opts.register_count = 8;
        auto r = verifier.verify(lhs, rhs, ctx, 0, {}, opts);
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
    }

    // Unsupported/invalid symbolic input should return UNKNOWN.
    {
        std::vector<uint8_t> lhs = {0xff};
        std::vector<uint8_t> rhs = {static_cast<uint8_t>(DwarfOp::DW_OP_lit0)};
        auto r = verifier.verify(lhs, rhs, ctx);
        assert(r.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);
    }

    // If differential checks are disabled and symbolic forms differ, verdict is UNKNOWN.
    {
        std::vector<uint8_t> lhs;
        lhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg1));
        lhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1u));
        lhs.push_back(1);
        lhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus));
        lhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));

        std::vector<uint8_t> rhs;
        rhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg1));
        rhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1u));
        rhs.push_back(2);
        rhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus));
        rhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));

        ExpressionVerificationOptions opts;
        opts.run_differential = false;
        auto r = verifier.verify(lhs, rhs, ctx, 0, {}, opts);
        assert(r.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);
    }

    // verifyWithContexts should handle different PCs/contexts for the two sides.
    {
        std::vector<uint8_t> lhs;
        lhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr));
        lhs.push_back(0x13); // pcrel + udata4
        appendU32(lhs, 0x20); // 0x1000 + 0x20 = 0x1020

        std::vector<uint8_t> rhs;
        rhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr));
        rhs.push_back(0x13); // pcrel + udata4
        appendU32(rhs, 0x10); // 0x1010 + 0x10 = 0x1020

        auto r = verifier.verifyWithContexts(
            lhs, ctx, 0x1000, {},
            rhs, ctx, 0x1010, {});
        assert(r.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT);
    }

    // Different per-side contexts should be supported.
    {
        std::vector<uint8_t> lhs = {
            static_cast<uint8_t>(DwarfOp::DW_OP_addrx), 0x00
        };
        std::vector<uint8_t> rhs = {
            static_cast<uint8_t>(DwarfOp::DW_OP_addrx), 0x00
        };

        EvaluationContext lhs_ctx = ctx;
        EvaluationContext rhs_ctx = ctx;
        std::vector<uint64_t> lhs_table = {0x1111};
        std::vector<uint64_t> rhs_table = {0x2222};
        lhs_ctx.debug_addr_table = &lhs_table;
        rhs_ctx.debug_addr_table = &rhs_table;

        auto r = verifier.verifyWithContexts(lhs, lhs_ctx, 0, {}, rhs, rhs_ctx, 0, {});
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
    }

    // DIE-level helper: expression attribute extraction + verification.
    {
        auto lhs_die = std::make_shared<DIE>(DwarfTag::DW_TAG_variable, 0, 0);
        auto rhs_die = std::make_shared<DIE>(DwarfTag::DW_TAG_variable, 0, 0);

        std::vector<uint8_t> lhs_expr;
        lhs_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg1));
        lhs_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1u));
        lhs_expr.push_back(1);
        lhs_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus));
        lhs_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));

        std::vector<uint8_t> rhs_expr;
        rhs_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1u));
        rhs_expr.push_back(1);
        rhs_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg1));
        rhs_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_plus));
        rhs_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));

        lhs_die->addAttribute(
            DwarfAttribute::DW_AT_location,
            std::make_shared<LocationAttributeValue>(LocationAttributeValue::LocationType::EXPRESSION, lhs_expr));
        rhs_die->addAttribute(
            DwarfAttribute::DW_AT_location,
            std::make_shared<LocationAttributeValue>(LocationAttributeValue::LocationType::EXPRESSION, rhs_expr));

        auto r = verifier.verifyDIEAttributeExpressions(lhs_die, ctx, {}, rhs_die, ctx, {});
        assert(r.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT);
    }

    // DIE-level helper: location-list selection by default vs by PC.
    {
        auto lhs_die = std::make_shared<DIE>(DwarfTag::DW_TAG_variable, 0, 0);
        auto rhs_die = std::make_shared<DIE>(DwarfTag::DW_TAG_variable, 0, 0);

        std::vector<LocationAttributeValue::LocationEntry> lhs_entries;
        lhs_entries.emplace_back(0, 0, std::vector<uint8_t>{
            static_cast<uint8_t>(DwarfOp::DW_OP_lit7),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)}, true);
        lhs_entries.emplace_back(10, 20, std::vector<uint8_t>{
            static_cast<uint8_t>(DwarfOp::DW_OP_lit3),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)}, false);

        std::vector<LocationAttributeValue::LocationEntry> rhs_entries;
        rhs_entries.emplace_back(0, 0, std::vector<uint8_t>{
            static_cast<uint8_t>(DwarfOp::DW_OP_lit8),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)}, true);
        rhs_entries.emplace_back(100, 200, std::vector<uint8_t>{
            static_cast<uint8_t>(DwarfOp::DW_OP_lit3),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)}, false);

        lhs_die->addAttribute(DwarfAttribute::DW_AT_location, std::make_shared<LocationAttributeValue>(lhs_entries));
        rhs_die->addAttribute(DwarfAttribute::DW_AT_location, std::make_shared<LocationAttributeValue>(rhs_entries));

        auto r_default = verifier.verifyDIEAttributeExpressions(lhs_die, ctx, {}, rhs_die, ctx, {});
        assert(r_default.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);

        DIEExpressionSelectionOptions lhs_sel;
        lhs_sel.use_pc_for_location_list = true;
        lhs_sel.location_list_pc = 12;
        DIEExpressionSelectionOptions rhs_sel;
        rhs_sel.use_pc_for_location_list = true;
        rhs_sel.location_list_pc = 120;
        auto r_pc = verifier.verifyDIEAttributeExpressions(
            lhs_die, ctx, {}, rhs_die, ctx, {}, lhs_sel, rhs_sel);
        assert(r_pc.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT);
    }

    // DIE-level helper returns UNKNOWN when attribute is missing.
    {
        auto lhs_die = std::make_shared<DIE>(DwarfTag::DW_TAG_variable, 0, 0);
        auto rhs_die = std::make_shared<DIE>(DwarfTag::DW_TAG_variable, 0, 0);
        auto r = verifier.verifyDIEAttributeExpressions(lhs_die, ctx, {}, rhs_die, ctx, {});
        assert(r.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);
    }

    std::cout << "ExpressionVerifier tests passed!" << std::endl;
}

void testCrossBinaryExpressionComparator() {
    std::cout << "Testing CrossBinaryExpressionComparator..." << std::endl;

    auto makeVar = [](const std::string& name, const std::vector<uint8_t>& expr, uint64_t off) {
        auto die = std::make_shared<DIE>(DwarfTag::DW_TAG_variable, off, 0);
        die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>(name));
        die->addAttribute(DwarfAttribute::DW_AT_location,
                          std::make_shared<LocationAttributeValue>(LocationAttributeValue::LocationType::EXPRESSION, expr));
        return die;
    };
    auto makeSubprogramByLinkage = [](const std::string& linkage, const std::vector<uint8_t>& expr, uint64_t off) {
        auto die = std::make_shared<DIE>(DwarfTag::DW_TAG_subprogram, off, 0);
        die->addAttribute(DwarfAttribute::DW_AT_linkage_name, std::make_shared<StringAttributeValue>(linkage));
        die->addAttribute(DwarfAttribute::DW_AT_location,
                          std::make_shared<LocationAttributeValue>(LocationAttributeValue::LocationType::EXPRESSION, expr));
        return die;
    };

    auto lhs_cu = std::make_shared<DIE>(DwarfTag::DW_TAG_compile_unit, 0x100, 0);
    auto rhs_cu = std::make_shared<DIE>(DwarfTag::DW_TAG_compile_unit, 0x200, 0);

    std::vector<uint8_t> x_lhs = {
        static_cast<uint8_t>(DwarfOp::DW_OP_reg1),
        static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 1,
        static_cast<uint8_t>(DwarfOp::DW_OP_plus),
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
    };
    std::vector<uint8_t> x_rhs = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 1,
        static_cast<uint8_t>(DwarfOp::DW_OP_reg1),
        static_cast<uint8_t>(DwarfOp::DW_OP_plus),
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
    };
    std::vector<uint8_t> y_lhs = {
        static_cast<uint8_t>(DwarfOp::DW_OP_reg2),
        static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 1,
        static_cast<uint8_t>(DwarfOp::DW_OP_plus),
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
    };
    std::vector<uint8_t> y_rhs = {
        static_cast<uint8_t>(DwarfOp::DW_OP_reg2),
        static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 2,
        static_cast<uint8_t>(DwarfOp::DW_OP_plus),
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
    };
    std::vector<uint8_t> z_lhs = {
        static_cast<uint8_t>(DwarfOp::DW_OP_reg3),
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
    };

    lhs_cu->addChild(makeVar("x", x_lhs, 0x110));
    lhs_cu->addChild(makeVar("y", y_lhs, 0x120));
    lhs_cu->addChild(makeVar("z", z_lhs, 0x130));
    rhs_cu->addChild(makeVar("x", x_rhs, 0x210));
    rhs_cu->addChild(makeVar("y", y_rhs, 0x220));

    CrossBinaryExpressionComparator cmp;
    CrossBinaryCompareOptions opts;
    opts.tag = DwarfTag::DW_TAG_variable;
    opts.attribute = DwarfAttribute::DW_AT_location;
    opts.include_missing = true;

    auto results = cmp.compareDIEListsByName({lhs_cu}, {rhs_cu}, opts);
    assert(results.size() == 3);

    auto findByName = [&](const std::string& n) -> const NamedExpressionComparison* {
        for (const auto& r : results) {
            if (r.name == n) return &r;
        }
        return nullptr;
    };

    const auto* rx = findByName("x");
    const auto* ry = findByName("y");
    const auto* rz = findByName("z");
    assert(rx && ry && rz);
    assert(rx->verification.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT);
    assert(ry->verification.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
    assert(rz->verification.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);
    assert(rz->lhs_present && !rz->rhs_present);
    auto summary = cmp.summarize(results);
    assert(summary.total == 3);
    assert(summary.equivalent == 1);
    assert(summary.different == 1);
    assert(summary.unknown == 1);
    assert(summary.missing_lhs == 0);
    assert(summary.missing_rhs == 1);

    std::string text_report = cmp.renderTextReport(results);
    assert(text_report.find("summary total=3") != std::string::npos);
    assert(text_report.find("x|DW_TAG_variable|1|1|") != std::string::npos);
    assert(text_report.find("DIFFERENT") != std::string::npos);

    std::string json_report = cmp.renderJsonReport(results);
    assert(json_report.find("\"total\":3") != std::string::npos);
    assert(json_report.find("\"different\":1") != std::string::npos);
    assert(json_report.find("\"name\":\"x\"") != std::string::npos);

    CrossBinaryGateOptions gate_default;
    auto gate_fail = cmp.evaluateGate(results, gate_default);
    assert(!gate_fail.pass);
    assert(gate_fail.reason.find("different") != std::string::npos);

    CrossBinaryGateOptions gate_allow_one_diff;
    gate_allow_one_diff.max_different = 1;
    auto gate_pass = cmp.evaluateGate(results, gate_allow_one_diff);
    assert(gate_pass.pass);

    CrossBinaryGateOptions gate_fail_missing;
    gate_fail_missing.max_different = 1;
    gate_fail_missing.fail_on_missing = true;
    auto gate_missing = cmp.evaluateGate(results, gate_fail_missing);
    assert(!gate_missing.pass);
    assert(gate_missing.reason.find("missing") != std::string::npos);

    DwarfParser lhs_parser("lhs_dummy");
    DwarfParser rhs_parser("rhs_dummy");
    auto single = cmp.compareNamedInParsers(lhs_parser, rhs_parser, "nonexistent", opts);
    // The call above is just API smoke coverage: name is absent in both.
    assert(single.verification.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);

    // linkage_name-aware keying (useful when names are stripped/rewritten but linkage stays stable).
    {
        auto lcu = std::make_shared<DIE>(DwarfTag::DW_TAG_compile_unit, 0x300, 0);
        auto rcu = std::make_shared<DIE>(DwarfTag::DW_TAG_compile_unit, 0x400, 0);
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_reg5),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
        };
        lcu->addChild(makeSubprogramByLinkage("_Z3foov", expr, 0x310));
        rcu->addChild(makeSubprogramByLinkage("_Z3foov", expr, 0x410));

        CrossBinaryCompareOptions by_name = opts;
        by_name.tag = DwarfTag::DW_TAG_subprogram;
        by_name.key_mode = CompareKeyMode::NAME_ONLY;
        auto none = cmp.compareDIEListsByName({lcu}, {rcu}, by_name);
        assert(none.empty());

        CrossBinaryCompareOptions by_linkage = by_name;
        by_linkage.key_mode = CompareKeyMode::LINKAGE_OR_NAME;
        auto linked = cmp.compareDIEListsByName({lcu}, {rcu}, by_linkage);
        assert(linked.size() == 1);
        assert(linked[0].name == "_Z3foov");
        assert(linked[0].verification.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT);

        std::string linked_json = cmp.renderJsonReport(linked);
        assert(linked_json.find("_Z3foov") != std::string::npos);
    }

    // strict attribute presence filter excludes paired names where one side lacks the target attribute.
    {
        auto lcu = std::make_shared<DIE>(DwarfTag::DW_TAG_compile_unit, 0x500, 0);
        auto rcu = std::make_shared<DIE>(DwarfTag::DW_TAG_compile_unit, 0x600, 0);

        auto lhs_only_name = std::make_shared<DIE>(DwarfTag::DW_TAG_variable, 0x510, 0);
        lhs_only_name->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("p"));
        // Intentionally no DW_AT_location on lhs.

        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_reg6),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
        };
        auto rhs_with_loc = std::make_shared<DIE>(DwarfTag::DW_TAG_variable, 0x610, 0);
        rhs_with_loc->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("p"));
        rhs_with_loc->addAttribute(
            DwarfAttribute::DW_AT_location,
            std::make_shared<LocationAttributeValue>(LocationAttributeValue::LocationType::EXPRESSION, expr));

        lcu->addChild(lhs_only_name);
        rcu->addChild(rhs_with_loc);

        CrossBinaryCompareOptions loose = opts;
        loose.include_missing = true;
        loose.require_attribute_on_both = false;
        auto loose_rows = cmp.compareDIEListsByName({lcu}, {rcu}, loose);
        assert(loose_rows.size() == 1);
        assert(loose_rows[0].name == "p");
        assert(loose_rows[0].verification.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);

        CrossBinaryCompareOptions strict_attr = loose;
        strict_attr.require_attribute_on_both = true;
        auto strict_rows = cmp.compareDIEListsByName({lcu}, {rcu}, strict_attr);
        assert(strict_rows.empty());
    }

    std::cout << "CrossBinaryExpressionComparator tests passed!" << std::endl;
}

void testStrpSup() {
    std::cout << "Testing DW_FORM_strp_sup..." << std::endl;

    // debug_info holds the 4-byte offset for the form.
    std::vector<uint8_t> debug_info = {0x04, 0x00, 0x00, 0x00}; // offset=4
    std::vector<uint8_t> empty;
    std::vector<uint8_t> debug_str_sup = {'x', 'y', 'z', 0, 'h', 'i', 0};

    AttributeParser ap(debug_info, empty, /*debug_str=*/empty,
                       /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                       /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                       /*debug_rnglists=*/empty, /*debug_loclists=*/empty,
                       /*debug_str_sup=*/debug_str_sup);
    ap.setIsDwarf64(false);

    uint64_t off = 0;
    auto v = ap.parseAttribute(DwarfForm::DW_FORM_strp_sup, off);
    auto s = std::dynamic_pointer_cast<StringAttributeValue>(v);
    assert(s);
    assert(s->getValue() == "hi");

    std::cout << "DW_FORM_strp_sup tests passed!" << std::endl;
}

static void appendU32(std::vector<uint8_t>& out, uint32_t v);
static void appendU64(std::vector<uint8_t>& out, uint64_t v);

void testRefSupForms() {
    std::cout << "Testing DW_FORM_ref_sup4/ref_sup8..." << std::endl;

    const uint64_t kSupBias = (1ULL << 62);

    // debug_info holds the raw offsets for the forms (section-relative to supplementary .debug_info).
    std::vector<uint8_t> debug_info;
    appendU32(debug_info, 0x10);          // ref_sup4 = 0x10
    appendU64(debug_info, 0x20ULL);       // ref_sup8 = 0x20

    std::vector<uint8_t> empty;
    AttributeParser ap(debug_info, empty, /*debug_str=*/empty,
                       /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                       /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                       /*debug_rnglists=*/empty, /*debug_loclists=*/empty,
                       /*debug_str_sup=*/empty);
    ap.setSupplementaryDebugInfoOffsetBias(kSupBias);

    uint64_t off = 0;
    auto v4 = ap.parseAttribute(DwarfForm::DW_FORM_ref_sup4, off);
    auto r4 = std::dynamic_pointer_cast<ReferenceAttributeValue>(v4);
    assert(r4);
    assert(r4->getOffset() == kSupBias + 0x10);

    auto v8 = ap.parseAttribute(DwarfForm::DW_FORM_ref_sup8, off);
    auto r8 = std::dynamic_pointer_cast<ReferenceAttributeValue>(v8);
    assert(r8);
    assert(r8->getOffset() == kSupBias + 0x20);

    std::cout << "DW_FORM_ref_sup4/ref_sup8 tests passed!" << std::endl;
}

void testDIEParserRefSupIntegration() {
    std::cout << "Testing DIEParser integration for DW_FORM_ref_sup4..." << std::endl;

    const uint64_t kSupBias = (1ULL << 62);

    // Abbrev table:
    // 1: compile_unit, has children
    // 2: variable, no children, has DW_AT_type as DW_FORM_ref_sup4
    // 3: base_type, no children
    std::vector<uint8_t> debug_abbrev;
    debug_abbrev.push_back(0x01);
    debug_abbrev.push_back(0x11); // DW_TAG_compile_unit
    debug_abbrev.push_back(0x01); // has children
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00); // end attrs

    debug_abbrev.push_back(0x02);
    debug_abbrev.push_back(0x34); // DW_TAG_variable
    debug_abbrev.push_back(0x00); // no children
    debug_abbrev.push_back(0x49); // DW_AT_type
    debug_abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_ref_sup4));
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00); // end attrs

    debug_abbrev.push_back(0x03);
    debug_abbrev.push_back(0x24); // DW_TAG_base_type
    debug_abbrev.push_back(0x00); // no children
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00); // end attrs

    debug_abbrev.push_back(0x00); // end table

    // Build supplementary .debug_info (DWARF4): CU -> base_type child.
    std::vector<uint8_t> sup_info;
    appendU32(sup_info, 0);   // placeholder length
    sup_info.push_back(0x04); sup_info.push_back(0x00); // version 4
    appendU32(sup_info, 0);   // abbrev offset
    sup_info.push_back(0x08); // addr_size

    sup_info.push_back(0x01); // CU DIE abbrev 1
    const uint32_t sup_base_type_off = static_cast<uint32_t>(sup_info.size());
    sup_info.push_back(0x03); // base_type abbrev 3
    sup_info.push_back(0x00); // end of children

    uint32_t sup_unit_length = static_cast<uint32_t>(sup_info.size() - 4);
    sup_info[0] = static_cast<uint8_t>(sup_unit_length & 0xff);
    sup_info[1] = static_cast<uint8_t>((sup_unit_length >> 8) & 0xff);
    sup_info[2] = static_cast<uint8_t>((sup_unit_length >> 16) & 0xff);
    sup_info[3] = static_cast<uint8_t>((sup_unit_length >> 24) & 0xff);

    // Build main .debug_info (DWARF4): CU -> variable child referencing supplementary base_type.
    std::vector<uint8_t> main_info;
    appendU32(main_info, 0);   // placeholder length
    main_info.push_back(0x04); main_info.push_back(0x00); // version 4
    appendU32(main_info, 0);   // abbrev offset
    main_info.push_back(0x08); // addr_size

    main_info.push_back(0x01); // CU DIE abbrev 1
    main_info.push_back(0x02); // variable abbrev 2
    appendU32(main_info, sup_base_type_off); // DW_FORM_ref_sup4 (section-relative to sup .debug_info)
    main_info.push_back(0x00); // end of children

    uint32_t main_unit_length = static_cast<uint32_t>(main_info.size() - 4);
    main_info[0] = static_cast<uint8_t>(main_unit_length & 0xff);
    main_info[1] = static_cast<uint8_t>((main_unit_length >> 8) & 0xff);
    main_info[2] = static_cast<uint8_t>((main_unit_length >> 16) & 0xff);
    main_info[3] = static_cast<uint8_t>((main_unit_length >> 24) & 0xff);

    std::vector<uint8_t> empty;
    ELFIO::elfio elf;

    DIEParser sup_parser(elf, sup_info, debug_abbrev, /*debug_str=*/empty,
                         /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                         /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                         /*debug_rnglists=*/empty, /*debug_loclists=*/empty,
                         /*debug_str_sup=*/empty,
                         /*verbose=*/false, /*debug_info_offset_bias=*/kSupBias,
                         /*supplementary_debug_info_offset_bias=*/kSupBias);
    auto sup_cus = sup_parser.parseCompilationUnits();
    assert(sup_cus.size() == 1);
    auto sup_cu = sup_cus[0];
    assert(sup_cu);
    assert(sup_cu->getChildren().size() == 1);
    auto sup_base = sup_cu->getChildren()[0];
    assert(sup_base);
    assert(sup_base->getOffset() == kSupBias + sup_base_type_off);

    DIEParser main_parser(elf, main_info, debug_abbrev, /*debug_str=*/empty,
                          /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                          /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                          /*debug_rnglists=*/empty, /*debug_loclists=*/empty,
                          /*debug_str_sup=*/empty,
                          /*verbose=*/false, /*debug_info_offset_bias=*/0,
                          /*supplementary_debug_info_offset_bias=*/kSupBias);
    auto main_cus = main_parser.parseCompilationUnits();
    assert(main_cus.size() == 1);
    auto cu = main_cus[0];
    assert(cu);
    assert(cu->getChildren().size() == 1);
    auto var = cu->getChildren()[0];
    assert(var);

    auto type_attr = var->getAttribute(DwarfAttribute::DW_AT_type);
    auto type_val = std::dynamic_pointer_cast<TypeAttributeValue>(type_attr);
    assert(type_val);
    assert(type_val->getOffset() == kSupBias + sup_base_type_off);

    std::cout << "DIEParser ref_sup integration tests passed!" << std::endl;
}

static void appendU32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
}

static void appendU16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
}

static void appendU64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xff));
    }
}

void testAttributeParserBoundedStringsAndBlocks() {
    std::cout << "Testing AttributeParser bounded strings/blocks..." << std::endl;

    std::vector<uint8_t> empty;

    // DW_FORM_string without terminating NUL should stop at the CU end.
    {
        std::vector<uint8_t> debug_info = {'a', 'b'};
        AttributeParser ap(debug_info, empty, empty);
        ap.setCUDebugInfoEnd(debug_info.size());

        uint64_t off = 0;
        auto v = ap.parseAttribute(DwarfForm::DW_FORM_string, off);
        auto s = std::dynamic_pointer_cast<StringAttributeValue>(v);
        assert(s);
        assert(s->getValue() == "ab");
        assert(off == debug_info.size());
    }

    // strp/line_strp/strp_sup should use bounded C-string reads too.
    {
        std::vector<uint8_t> debug_info;
        appendU32(debug_info, 0); // DW_FORM_strp -> debug_str[0]
        appendU32(debug_info, 0); // DW_FORM_line_strp -> debug_line_str[0]
        appendU32(debug_info, 0); // DW_FORM_strp_sup -> debug_str_sup[0]
        std::vector<uint8_t> debug_str = {'x', 'y'};       // no NUL
        std::vector<uint8_t> debug_line_str = {'l', 'n'};  // no NUL
        std::vector<uint8_t> debug_str_sup = {'s', 'u', 'p'}; // no NUL

        AttributeParser ap(debug_info, empty, debug_str,
                           /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                           /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/debug_line_str,
                           /*debug_rnglists=*/empty, /*debug_loclists=*/empty,
                           /*debug_str_sup=*/debug_str_sup);
        ap.setIsDwarf64(false);
        ap.setCUDebugInfoEnd(debug_info.size());

        uint64_t off = 0;
        auto s1 = std::dynamic_pointer_cast<StringAttributeValue>(ap.parseAttribute(DwarfForm::DW_FORM_strp, off));
        auto s2 = std::dynamic_pointer_cast<StringAttributeValue>(ap.parseAttribute(DwarfForm::DW_FORM_line_strp, off));
        auto s3 = std::dynamic_pointer_cast<StringAttributeValue>(ap.parseAttribute(DwarfForm::DW_FORM_strp_sup, off));
        assert(s1 && s1->getValue() == "xy");
        assert(s2 && s2->getValue() == "ln");
        assert(s3 && s3->getValue() == "sup");
        assert(off == debug_info.size());
    }

    // Variable-sized block forms should clamp offset to CU end on truncation.
    {
        std::vector<uint8_t> debug_info = {0x05, 0xaa, 0xbb}; // block1 length=5, only 2 payload bytes
        AttributeParser ap(debug_info, empty, empty);
        ap.setCUDebugInfoEnd(debug_info.size());

        uint64_t off = 0;
        auto v = ap.parseAttribute(DwarfForm::DW_FORM_block1, off);
        auto b = std::dynamic_pointer_cast<BlockAttributeValue>(v);
        assert(b);
        assert(b->getData().empty());
        assert(off == debug_info.size());
    }

    std::cout << "AttributeParser bounded strings/blocks tests passed!" << std::endl;
}

void testDIEParserCUBoundsOnUnterminatedFormString() {
    std::cout << "Testing DIEParser CU bounds for unterminated DW_FORM_string..." << std::endl;

    // Abbrev 1: compile_unit with DW_AT_name: DW_FORM_string, no children.
    std::vector<uint8_t> debug_abbrev;
    appendULEB(debug_abbrev, 1);
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfTag::DW_TAG_compile_unit));
    debug_abbrev.push_back(0x00); // no children
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_name));
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_string));
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00); // end attrs
    debug_abbrev.push_back(0x00); // end table

    std::vector<uint8_t> debug_info;

    auto appendCu = [&](const std::vector<uint8_t>& die_payload) {
        size_t start = debug_info.size();
        appendU32(debug_info, 0); // unit_length placeholder
        debug_info.push_back(0x04); debug_info.push_back(0x00); // version 4
        appendU32(debug_info, 0); // abbrev offset
        debug_info.push_back(0x08); // address_size
        debug_info.insert(debug_info.end(), die_payload.begin(), die_payload.end());
        uint32_t len = static_cast<uint32_t>(debug_info.size() - start - 4);
        debug_info[start + 0] = static_cast<uint8_t>(len & 0xff);
        debug_info[start + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_info[start + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_info[start + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    };

    // CU1 has an unterminated DW_FORM_string.
    appendCu({0x01, 'A'});
    // CU2 is fully valid and must still parse.
    appendCu({0x01, 'B', 0x00});

    std::vector<uint8_t> empty;
    ELFIO::elfio elf;
    DIEParser parser(elf, debug_info, debug_abbrev, /*debug_str=*/empty);
    auto cus = parser.parseCompilationUnits();
    assert(cus.size() == 2);
    assert(cus[0] && cus[0]->getName() == "A");
    assert(cus[1] && cus[1]->getName() == "B");

    std::cout << "DIEParser CU-bound string tests passed!" << std::endl;
}

void testDIEParserTruncatedAbbrevImplicitConst() {
    std::cout << "Testing DIEParser truncated abbrev implicit_const handling..." << std::endl;

    // Abbrev 1: compile_unit with DW_FORM_implicit_const, but truncated SLEB payload.
    std::vector<uint8_t> debug_abbrev;
    appendULEB(debug_abbrev, 1);
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfTag::DW_TAG_compile_unit));
    debug_abbrev.push_back(0x00); // no children
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_language));
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_implicit_const));
    debug_abbrev.push_back(0x80); // truncated SLEB (continuation bit set, no next byte)

    // One DWARF4 CU that references abbrev 1.
    std::vector<uint8_t> debug_info;
    appendU32(debug_info, 8);      // unit_length
    debug_info.push_back(0x04);    // version lo
    debug_info.push_back(0x00);    // version hi
    appendU32(debug_info, 0);      // abbrev offset
    debug_info.push_back(0x08);    // address_size
    debug_info.push_back(0x01);    // CU abbrev code

    std::vector<uint8_t> empty;
    ELFIO::elfio elf;
    DIEParser parser(elf, debug_info, debug_abbrev, /*debug_str=*/empty);
    auto cus = parser.parseCompilationUnits();
    assert(cus.empty());

    std::cout << "DIEParser truncated abbrev implicit_const tests passed!" << std::endl;
}

void testDebugSupParser() {
    std::cout << "Testing .debug_sup parser..." << std::endl;

    // Two entries, ensure we honor unit_length boundaries and can parse multiple.
    std::vector<uint8_t> sup;

    auto appendEntry32 = [&](uint8_t is_sup, uint64_t sig, const std::string& path, const std::vector<uint8_t>& extra) {
        size_t start = sup.size();
        appendU32(sup, 0); // placeholder unit_length

        std::vector<uint8_t> payload;
        appendU16(payload, 5); // version
        payload.push_back(is_sup);
        payload.push_back(0); // reserved
        appendU64(payload, sig);
        payload.insert(payload.end(), path.begin(), path.end());
        payload.push_back(0);
        payload.insert(payload.end(), extra.begin(), extra.end());

        uint32_t unit_length = static_cast<uint32_t>(payload.size());
        sup[start + 0] = static_cast<uint8_t>(unit_length & 0xff);
        sup[start + 1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        sup[start + 2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        sup[start + 3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

        sup.insert(sup.end(), payload.begin(), payload.end());
    };

    appendEntry32(/*is_sup=*/0, /*sig=*/0x1111111111111111ULL, "sup1.elf", {'A', 'B'});
    appendEntry32(/*is_sup=*/1, /*sig=*/0x2222222222222222ULL, "sup2.elf", {});

    DebugSupParser p(sup);
    auto entries = p.parse();
    assert(entries.size() == 2);
    assert(entries[0].well_formed);
    assert(entries[0].version == 5);
    assert(entries[0].is_supplementary == 0);
    assert(entries[0].signature == 0x1111111111111111ULL);
    assert(entries[0].path == "sup1.elf");
    assert(entries[1].well_formed);
    assert(entries[1].is_supplementary == 1);
    assert(entries[1].signature == 0x2222222222222222ULL);
    assert(entries[1].path == "sup2.elf");

    // Make sure entry sizes advance correctly (second entry starts immediately after first).
    assert(entries[1].entry_offset == entries[0].entry_offset + entries[0].entry_size);

    // DWARF64 entry.
    std::vector<uint8_t> sup64;
    auto appendEntry64 = [&](uint8_t is_sup, uint64_t sig, const std::vector<uint8_t>& path_bytes) {
        appendU32(sup64, 0xffffffffu);

        // Build payload first so we can write its size as a u64.
        std::vector<uint8_t> payload;
        appendU16(payload, 5); // version
        payload.push_back(is_sup);
        payload.push_back(0); // reserved
        appendU64(payload, sig);
        payload.insert(payload.end(), path_bytes.begin(), path_bytes.end());
        payload.push_back(0);

        appendU64(sup64, static_cast<uint64_t>(payload.size()));
        sup64.insert(sup64.end(), payload.begin(), payload.end());
    };

    // Include a UTF-8 byte sequence in the path (non-ASCII bytes should be accepted).
    std::vector<uint8_t> path_bytes = {'s', 'u', 'p', static_cast<uint8_t>(0xc3), static_cast<uint8_t>(0xa9), '.', 'e', 'l', 'f'};
    appendEntry64(/*is_sup=*/0, /*sig=*/0x3333333333333333ULL, path_bytes);

    DebugSupParser p64(sup64);
    auto e64 = p64.parse();
    assert(e64.size() == 1);
    assert(e64[0].well_formed);
    assert(e64[0].is_dwarf64);
    assert(e64[0].version == 5);
    assert(e64[0].signature == 0x3333333333333333ULL);
    std::string expected_path;
    expected_path.push_back('s');
    expected_path.push_back('u');
    expected_path.push_back('p');
    expected_path.push_back(static_cast<char>(0xc3));
    expected_path.push_back(static_cast<char>(0xa9));
    expected_path.push_back('.');
    expected_path.push_back('e');
    expected_path.push_back('l');
    expected_path.push_back('f');
    assert(e64[0].path == expected_path);

    // Malformed entry: invalid is_supplementary + missing NUL terminator within the entry.
    std::vector<uint8_t> bad;
    appendU32(bad, 0); // placeholder unit_length
    std::vector<uint8_t> bad_payload;
    appendU16(bad_payload, 5); // version
    bad_payload.push_back(2);  // invalid is_supplementary
    bad_payload.push_back(0);  // reserved
    appendU64(bad_payload, 0x4444444444444444ULL);
    bad_payload.insert(bad_payload.end(), {'n', 'o', '_', 'n', 'u', 'l'}); // no terminating 0
    uint32_t bad_len = static_cast<uint32_t>(bad_payload.size());
    bad[0] = static_cast<uint8_t>(bad_len & 0xff);
    bad[1] = static_cast<uint8_t>((bad_len >> 8) & 0xff);
    bad[2] = static_cast<uint8_t>((bad_len >> 16) & 0xff);
    bad[3] = static_cast<uint8_t>((bad_len >> 24) & 0xff);
    bad.insert(bad.end(), bad_payload.begin(), bad_payload.end());

    DebugSupParser pbad(bad);
    auto ebad = pbad.parse();
    assert(ebad.size() == 1);
    assert(!ebad[0].well_formed);
    assert(ebad[0].path.empty());

    // Malformed entry: DWARF64 marker present but truncated 64-bit unit_length.
    std::vector<uint8_t> bad64_len = {
        0xff, 0xff, 0xff, 0xff, // DWARF64 marker
        0x11, 0x22, 0x33, 0x44, // only 4/8 bytes of unit_length
    };
    DebugSupParser pbad64len(bad64_len);
    auto ebad64len = pbad64len.parse();
    assert(ebad64len.size() == 1);
    assert(!ebad64len[0].well_formed);
    assert(ebad64len[0].error_mask != 0);

    // Malformed entry: unit_length extends beyond available bytes.
    std::vector<uint8_t> bad_oversized;
    appendU32(bad_oversized, 0x100); // claims 256-byte payload; section is shorter
    bad_oversized.push_back(0x05);    // partial payload
    bad_oversized.push_back(0x00);
    DebugSupParser pbad_over(bad_oversized);
    auto ebad_over = pbad_over.parse();
    assert(ebad_over.size() == 1);
    assert(!ebad_over[0].well_formed);
    assert(ebad_over[0].error_mask != 0);

    // Mixed entries: malformed first (bad version + reserved), then valid second.
    {
        std::vector<uint8_t> mix;

        auto appendRawEntry32 = [&](uint16_t version,
                                    uint8_t is_sup,
                                    uint8_t reserved,
                                    uint64_t sig,
                                    const std::vector<uint8_t>& path_bytes) {
            size_t start = mix.size();
            appendU32(mix, 0); // placeholder unit_length
            std::vector<uint8_t> payload;
            appendU16(payload, version);
            payload.push_back(is_sup);
            payload.push_back(reserved);
            appendU64(payload, sig);
            payload.insert(payload.end(), path_bytes.begin(), path_bytes.end());
            payload.push_back(0);
            uint32_t unit_length = static_cast<uint32_t>(payload.size());
            mix[start + 0] = static_cast<uint8_t>(unit_length & 0xff);
            mix[start + 1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
            mix[start + 2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
            mix[start + 3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
            mix.insert(mix.end(), payload.begin(), payload.end());
        };

        appendRawEntry32(/*version=*/4, /*is_sup=*/1, /*reserved=*/1,
                         /*sig=*/0xaaaaaaaaaaaaaaaaULL,
                         /*path=*/{'b', 'a', 'd', '.', 's', 'u', 'p'});
        appendRawEntry32(/*version=*/5, /*is_sup=*/0, /*reserved=*/0,
                         /*sig=*/0xbbbbbbbbbbbbbbbbULL,
                         /*path=*/{'o', 'k', '.', 's', 'u', 'p'});

        DebugSupParser pmix(mix);
        auto emix = pmix.parse();
        assert(emix.size() == 2);
        assert(!emix[0].well_formed);
        assert((emix[0].error_mask & (1u << 2)) != 0); // bad version
        assert((emix[0].error_mask & (1u << 4)) != 0); // bad reserved
        assert(emix[1].well_formed);
        assert(emix[1].path == "ok.sup");
    }

    // Bad path control byte should be rejected.
    {
        std::vector<uint8_t> bad_path;
        appendU32(bad_path, 0);
        std::vector<uint8_t> payload;
        appendU16(payload, 5);
        payload.push_back(0);
        payload.push_back(0);
        appendU64(payload, 0xccccccccccccccccULL);
        payload.push_back('o');
        payload.push_back(0x1f); // control byte
        payload.push_back('k');
        payload.push_back(0);
        uint32_t len = static_cast<uint32_t>(payload.size());
        bad_path[0] = static_cast<uint8_t>(len & 0xff);
        bad_path[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        bad_path[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        bad_path[3] = static_cast<uint8_t>((len >> 24) & 0xff);
        bad_path.insert(bad_path.end(), payload.begin(), payload.end());

        DebugSupParser pbad_path(bad_path);
        auto e = pbad_path.parse();
        assert(e.size() == 1);
        assert(!e[0].well_formed);
        assert(e[0].path.empty());
        assert((e[0].error_mask & (1u << 6)) != 0); // bad path byte
    }

    std::cout << ".debug_sup parser tests passed!" << std::endl;
}

void testDebugNamesParser() {
    std::cout << "Testing .debug_names parser..." << std::endl;

    // Minimal .debug_str with one name "foo".
    std::vector<uint8_t> debug_str = {'f', 'o', 'o', 0x00};
    auto djb32 = [](const char* s) -> uint32_t {
        uint32_t h = 5381;
        while (*s) {
            h = ((h << 5) + h) + static_cast<uint8_t>(*s++);
        }
        return h;
    };
    uint32_t foo_hash = djb32("foo");

    // Build a synthetic DWARF v5 .debug_names unit (DWARF32).
    // This test verifies:
    // - entry_offsets[] are interpreted as offsets into the entry pool (relative to entry_pool_base)
    // - DW_IDX_die_offset (CU-relative) is converted to an absolute .debug_info section offset
    std::vector<uint8_t> debug_names;
    auto appendU8 = [&](uint8_t v) { debug_names.push_back(v); };
    auto appendU16 = [&](uint16_t v) {
        debug_names.push_back(static_cast<uint8_t>(v & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    };
    auto appendU32 = [&](uint32_t v) {
        debug_names.push_back(static_cast<uint8_t>(v & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    };

    // unit_length placeholder
    appendU32(0);

    // Header fields
    appendU16(5);      // version
    appendU16(0);      // padding
    appendU32(1);      // comp_unit_count
    appendU32(0);      // local_type_unit_count
    appendU32(0);      // foreign_type_unit_count
    appendU32(1);      // bucket_count
    appendU32(1);      // name_count

    size_t abbrev_size_pos = debug_names.size();
    appendU32(0);      // abbrev_table_size placeholder
    appendU32(0);      // augmentation_string_size

    // CU list
    appendU32(0x100);  // .debug_info CU offset

    // Buckets
    appendU32(1);      // bucket[0] = 1 (1-based index)

    // Hashes (uint32)
    appendU32(foo_hash);

    // Name offsets (into .debug_str)
    appendU32(0);      // "foo"

    // Entry offsets (into entry pool)
    appendU32(2);      // points past the 2-byte padding below

    // Abbrev table:
    // code=1, tag=DW_TAG_variable
    // (DW_IDX_compile_unit, DW_FORM_data1), (DW_IDX_die_offset, DW_FORM_data4), terminator, end-of-table(0)
    std::vector<uint8_t> abbrev;
    abbrev.push_back(0x01); // code
    abbrev.push_back(static_cast<uint8_t>(DwarfTag::DW_TAG_variable)); // tag
    abbrev.push_back(0x01); // DW_IDX_compile_unit
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data1));
    abbrev.push_back(0x03); // DW_IDX_die_offset
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data4));
    abbrev.push_back(0x00); // end attrs
    abbrev.push_back(0x00);
    abbrev.push_back(0x00); // end abbrev table

    // Patch abbrev_table_size
    uint32_t abbrev_size = static_cast<uint32_t>(abbrev.size());
    debug_names[abbrev_size_pos + 0] = static_cast<uint8_t>(abbrev_size & 0xff);
    debug_names[abbrev_size_pos + 1] = static_cast<uint8_t>((abbrev_size >> 8) & 0xff);
    debug_names[abbrev_size_pos + 2] = static_cast<uint8_t>((abbrev_size >> 16) & 0xff);
    debug_names[abbrev_size_pos + 3] = static_cast<uint8_t>((abbrev_size >> 24) & 0xff);

    debug_names.insert(debug_names.end(), abbrev.begin(), abbrev.end());

    // Entry pool: 2 bytes padding + one entry + terminator.
    appendU8(0xaa);
    appendU8(0xbb);
    appendU8(0x01);      // abbrev_code (ULEB128)
    appendU8(0x00);      // cu_index (data1)
    appendU32(0x20);     // die_offset (data4) relative to CU start
    appendU8(0x00);      // end entries for this name

    // Patch unit_length (excludes the initial 4-byte length field)
    uint32_t unit_length = static_cast<uint32_t>(debug_names.size() - 4);
    debug_names[0] = static_cast<uint8_t>(unit_length & 0xff);
    debug_names[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
    debug_names[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
    debug_names[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

    DebugNamesParser parser(debug_names, debug_str);
    assert(parser.parse());

    auto entries = parser.lookupName("foo");
    assert(entries.size() == 1);
    assert(entries[0].tags.size() == 1);
    assert(entries[0].tags[0] == DwarfTag::DW_TAG_variable);
    assert(entries[0].cu_indices.size() == 1);
    assert(entries[0].cu_indices[0] == 0);
    assert(entries[0].die_offsets.size() == 1);
    assert(entries[0].die_offsets[0] == 0x120);

    std::cout << ".debug_names parser tests passed!" << std::endl;
}

void testDebugNamesParserBucketLookup() {
    std::cout << "Testing .debug_names bucket-based lookup..." << std::endl;

    // Minimal .debug_str with one name "foo".
    std::vector<uint8_t> debug_str = {'f', 'o', 'o', 0x00};

    auto djb32 = [](const char* s) -> uint32_t {
        uint32_t h = 5381;
        while (*s) {
            h = ((h << 5) + h) + static_cast<uint8_t>(*s++);
        }
        return h;
    };
    uint32_t foo_hash = djb32("foo");

    std::vector<uint8_t> debug_names;
    auto appendU8 = [&](uint8_t v) { debug_names.push_back(v); };
    auto appendU16 = [&](uint16_t v) {
        debug_names.push_back(static_cast<uint8_t>(v & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    };
    auto appendU32 = [&](uint32_t v) {
        debug_names.push_back(static_cast<uint8_t>(v & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    };

    // unit_length placeholder
    appendU32(0);

    appendU16(5);      // version
    appendU16(0);      // padding
    appendU32(1);      // comp_unit_count
    appendU32(0);      // local_type_unit_count
    appendU32(0);      // foreign_type_unit_count
    appendU32(2);      // bucket_count
    appendU32(1);      // name_count

    size_t abbrev_size_pos = debug_names.size();
    appendU32(0);      // abbrev_table_size placeholder
    appendU32(0);      // augmentation_string_size

    // CU list
    appendU32(0x100);

    // Buckets: only the bucket for "foo" is populated.
    uint32_t buckets[2] = {0, 0};
    buckets[foo_hash % 2] = 1; // 1-based index of the first name in this bucket
    appendU32(buckets[0]);
    appendU32(buckets[1]);

    // Hashes
    appendU32(foo_hash);

    // Name offsets
    appendU32(0); // "foo"

    // Entry offsets
    appendU32(0); // entry pool starts immediately after abbrev table

    // Abbrev table: same as testDebugNamesParser().
    std::vector<uint8_t> abbrev;
    abbrev.push_back(0x01); // code
    abbrev.push_back(static_cast<uint8_t>(DwarfTag::DW_TAG_variable)); // tag
    abbrev.push_back(0x01); // DW_IDX_compile_unit
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data1));
    abbrev.push_back(0x03); // DW_IDX_die_offset
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data4));
    abbrev.push_back(0x00); // end attrs
    abbrev.push_back(0x00);
    abbrev.push_back(0x00); // end abbrev table

    uint32_t abbrev_size = static_cast<uint32_t>(abbrev.size());
    debug_names[abbrev_size_pos + 0] = static_cast<uint8_t>(abbrev_size & 0xff);
    debug_names[abbrev_size_pos + 1] = static_cast<uint8_t>((abbrev_size >> 8) & 0xff);
    debug_names[abbrev_size_pos + 2] = static_cast<uint8_t>((abbrev_size >> 16) & 0xff);
    debug_names[abbrev_size_pos + 3] = static_cast<uint8_t>((abbrev_size >> 24) & 0xff);
    debug_names.insert(debug_names.end(), abbrev.begin(), abbrev.end());

    // Entry pool: one entry + terminator.
    appendU8(0x01);  // abbrev_code
    appendU8(0x00);  // cu_index
    appendU32(0x20); // die_offset relative to CU
    appendU8(0x00);  // end entries

    // Patch unit_length.
    uint32_t unit_length = static_cast<uint32_t>(debug_names.size() - 4);
    debug_names[0] = static_cast<uint8_t>(unit_length & 0xff);
    debug_names[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
    debug_names[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
    debug_names[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

    DebugNamesParser parser(debug_names, debug_str);
    assert(parser.parse());

    auto entries = parser.lookupName("foo");
    assert(entries.size() == 1);
    assert(entries[0].die_offsets.size() == 1);
    assert(entries[0].die_offsets[0] == 0x120);

    auto missing = parser.lookupName("bar");
    assert(missing.empty());

    std::cout << ".debug_names bucket lookup tests passed!" << std::endl;
}

void testDebugNamesParserMalformedInputs() {
    std::cout << "Testing .debug_names malformed input handling..." << std::endl;

    // Truncated DWARF64 unit length (marker present, only 4/8 bytes follow).
    {
        std::vector<uint8_t> bad = {
            0xff, 0xff, 0xff, 0xff,
            0x11, 0x22, 0x33, 0x44,
        };
        DebugNamesParser p(bad, {});
        assert(!p.parse());
    }

    // Truncated abbrev table ULEB128 (code starts with continuation, missing terminator).
    {
        std::vector<uint8_t> debug_names;
        auto appendU16 = [&](uint16_t v) {
            debug_names.push_back(static_cast<uint8_t>(v & 0xff));
            debug_names.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        };
        auto appendU32 = [&](uint32_t v) {
            debug_names.push_back(static_cast<uint8_t>(v & 0xff));
            debug_names.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
            debug_names.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
            debug_names.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
        };

        appendU32(0);      // unit_length placeholder
        appendU16(5);      // version
        appendU16(0);      // padding
        appendU32(0);      // comp_unit_count
        appendU32(0);      // local_type_unit_count
        appendU32(0);      // foreign_type_unit_count
        appendU32(0);      // bucket_count
        appendU32(0);      // name_count
        appendU32(1);      // abbrev_table_size
        appendU32(0);      // augmentation_string_size
        debug_names.push_back(0x80); // truncated ULEB128 in abbrev table

        uint32_t len = static_cast<uint32_t>(debug_names.size() - 4);
        debug_names[0] = static_cast<uint8_t>(len & 0xff);
        debug_names[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_names[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_names[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugNamesParser p(debug_names, {});
        assert(!p.parse());
    }

    // Truncated abbrev_code in entry pool should not crash lookup and should return no entries.
    {
        std::vector<uint8_t> debug_str = {'f', 'o', 'o', 0x00};
        auto djb32 = [](const char* s) -> uint32_t {
            uint32_t h = 5381;
            while (*s) {
                h = ((h << 5) + h) + static_cast<uint8_t>(*s++);
            }
            return h;
        };

        std::vector<uint8_t> debug_names;
        auto appendU8 = [&](uint8_t v) { debug_names.push_back(v); };
        auto appendU16 = [&](uint16_t v) {
            debug_names.push_back(static_cast<uint8_t>(v & 0xff));
            debug_names.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        };
        auto appendU32 = [&](uint32_t v) {
            debug_names.push_back(static_cast<uint8_t>(v & 0xff));
            debug_names.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
            debug_names.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
            debug_names.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
        };

        appendU32(0);      // unit_length placeholder
        appendU16(5);      // version
        appendU16(0);      // padding
        appendU32(1);      // comp_unit_count
        appendU32(0);      // local_type_unit_count
        appendU32(0);      // foreign_type_unit_count
        appendU32(1);      // bucket_count
        appendU32(1);      // name_count
        size_t abbrev_size_pos = debug_names.size();
        appendU32(0);      // abbrev_table_size placeholder
        appendU32(0);      // augmentation_string_size

        appendU32(0x100);  // CU list
        appendU32(1);      // bucket
        appendU32(djb32("foo")); // hash("foo")
        appendU32(0);      // name offset
        appendU32(0);      // entry offset (start of entry pool)

        std::vector<uint8_t> abbrev;
        abbrev.push_back(0x01); // code
        abbrev.push_back(static_cast<uint8_t>(DwarfTag::DW_TAG_variable)); // tag
        abbrev.push_back(0x01); // DW_IDX_compile_unit
        abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data1));
        abbrev.push_back(0x03); // DW_IDX_die_offset
        abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data4));
        abbrev.push_back(0x00); // end attrs
        abbrev.push_back(0x00);
        abbrev.push_back(0x00); // end abbrev table

        uint32_t abbrev_size = static_cast<uint32_t>(abbrev.size());
        debug_names[abbrev_size_pos + 0] = static_cast<uint8_t>(abbrev_size & 0xff);
        debug_names[abbrev_size_pos + 1] = static_cast<uint8_t>((abbrev_size >> 8) & 0xff);
        debug_names[abbrev_size_pos + 2] = static_cast<uint8_t>((abbrev_size >> 16) & 0xff);
        debug_names[abbrev_size_pos + 3] = static_cast<uint8_t>((abbrev_size >> 24) & 0xff);
        debug_names.insert(debug_names.end(), abbrev.begin(), abbrev.end());

        // Entry pool contains truncated ULEB128 abbrev code.
        appendU8(0x80);

        uint32_t unit_length = static_cast<uint32_t>(debug_names.size() - 4);
        debug_names[0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_names[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_names[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_names[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

        DebugNamesParser parser(debug_names, debug_str);
        assert(parser.parse());
        auto entries = parser.lookupName("foo");
        assert(entries.empty());
    }

    std::cout << ".debug_names malformed input tests passed!" << std::endl;
}

static void appendULEB(std::vector<uint8_t>& out, uint64_t v);
static void appendSLEB(std::vector<uint8_t>& out, int64_t v);
static void appendU16LE(std::vector<uint8_t>& out, uint16_t v);
static void appendU32LE(std::vector<uint8_t>& out, uint32_t v);
static void appendU64LE(std::vector<uint8_t>& out, uint64_t v);
static void appendCString(std::vector<uint8_t>& out, const char* s);
static std::string makeTempDir(const std::string& prefix);
static void writeELFWithSections(const std::string& path,
                                 const std::vector<std::pair<std::string, std::vector<uint8_t>>>& sections);

void testDebugMacroParser() {
    std::cout << "Testing .debug_macro parser..." << std::endl;

    // Synthetic DWARF v5 .debug_macro unit (no line offset, 32-bit offsets).
    std::vector<uint8_t> debug_macro;

    auto appendU8 = [&](uint8_t v) { debug_macro.push_back(v); };
    auto appendU16 = [&](uint16_t v) {
        debug_macro.push_back(static_cast<uint8_t>(v & 0xff));
        debug_macro.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    };
    auto appendCString = [&](const char* s) {
        while (*s) appendU8(static_cast<uint8_t>(*s++));
        appendU8(0);
    };

    // unit_length placeholder
    size_t len_pos = debug_macro.size();
    ::appendU32(debug_macro, 0);

    size_t content_start = debug_macro.size();
    appendU16(5);     // version
    appendU8(0x00);   // flags

    appendU8(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define));
    appendU8(10);     // line (ULEB128=10)
    appendCString("FOO 1");

    appendU8(static_cast<uint8_t>(DW_MACRO::DW_MACRO_undef));
    appendU8(11);     // line (ULEB128=11)
    appendCString("FOO");

    appendU8(0x00);   // end of macro list

    // Patch unit_length (bytes following this u32).
    uint32_t unit_length = static_cast<uint32_t>(debug_macro.size() - content_start);
    debug_macro[len_pos + 0] = static_cast<uint8_t>(unit_length & 0xff);
    debug_macro[len_pos + 1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
    debug_macro[len_pos + 2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
    debug_macro[len_pos + 3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

    DebugMacroParser parser(debug_macro);
    auto entries = parser.parseMacroUnit(0);
    assert(entries.size() == 2);

    assert(entries[0].type == DW_MACRO::DW_MACRO_define);
    assert(entries[0].line == 10);
    assert(entries[0].name == "FOO");
    assert(entries[0].value == "1");

    assert(entries[1].type == DW_MACRO::DW_MACRO_undef);
    assert(entries[1].line == 11);
    assert(entries[1].name == "FOO");

    // Ensure unit_length bounds parsing: append a second unit after the first.
    uint64_t unit2_off = debug_macro.size();
    {
        // unit_length placeholder
        size_t lp = debug_macro.size();
        ::appendU32(debug_macro, 0);
        size_t cs2 = debug_macro.size();

        appendU16(5);     // version
        appendU8(0x00);   // flags

        appendU8(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define));
        appendU8(1);      // line
        appendCString("BAR 2");
        appendU8(0x00);   // end

        uint32_t len2 = static_cast<uint32_t>(debug_macro.size() - cs2);
        debug_macro[lp + 0] = static_cast<uint8_t>(len2 & 0xff);
        debug_macro[lp + 1] = static_cast<uint8_t>((len2 >> 8) & 0xff);
        debug_macro[lp + 2] = static_cast<uint8_t>((len2 >> 16) & 0xff);
        debug_macro[lp + 3] = static_cast<uint8_t>((len2 >> 24) & 0xff);
    }

    DebugMacroParser parser2(debug_macro);
    auto e1 = parser2.parseMacroUnit(0);
    auto e2 = parser2.parseMacroUnit(unit2_off);
    assert(e1.size() == 2);
    assert(e2.size() == 1);
    assert(e2[0].name == "BAR");
    assert(e2[0].value == "2");

    // Also test DW_MACRO_define_strx (indexed strings via .debug_str_offsets + DW_AT_str_offsets_base).
    {
        std::vector<uint8_t> debug_str;
        ::appendCString(debug_str, "BAR 2");

        std::vector<uint8_t> debug_str_offsets;
        // index 0 -> offset 0 in .debug_str
        appendU32LE(debug_str_offsets, 0);

        std::vector<uint8_t> debug_macro2;
        // unit_length placeholder
        ::appendU32(debug_macro2, 0);
        size_t cs = debug_macro2.size();
        appendU16LE(debug_macro2, 5);     // version
        debug_macro2.push_back(0x00);     // flags
        debug_macro2.push_back(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define_strx));
        appendULEB(debug_macro2, 1);      // line
        appendULEB(debug_macro2, 0);      // strx index
        debug_macro2.push_back(0x00);     // end
        uint32_t len = static_cast<uint32_t>(debug_macro2.size() - cs);
        debug_macro2[0] = static_cast<uint8_t>(len & 0xff);
        debug_macro2[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_macro2[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_macro2[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        std::vector<uint8_t> empty;
        DebugMacroParser p2(debug_macro2, &debug_str, &empty, &debug_str_offsets, &empty);
        p2.setStrOffsetsBase(0, 4);
        auto e2 = p2.parseMacroUnit(0);
        assert(e2.size() == 1);
        assert(e2[0].name == "BAR");
        assert(e2[0].value == "2");
    }

    // Ensure getStringFromStrx is bounded by the str_offsets contribution end (no bleed into next contribution).
    {
        std::vector<uint8_t> debug_str;
        ::appendCString(debug_str, "ONE 1");
        ::appendCString(debug_str, "TWO 2");

        // Two DWARF5 .debug_str_offsets contributions, each with 1 entry.
        std::vector<uint8_t> debug_str_offsets;
        auto startContrib = [&](uint32_t str_off) {
            size_t lp = debug_str_offsets.size();
            ::appendU32(debug_str_offsets, 0); // length placeholder
            size_t cs = debug_str_offsets.size();
            // header: version=5, padding=0
            debug_str_offsets.push_back(0x05); debug_str_offsets.push_back(0x00);
            debug_str_offsets.push_back(0x00); debug_str_offsets.push_back(0x00);
            ::appendU32(debug_str_offsets, str_off);
            uint32_t len = static_cast<uint32_t>(debug_str_offsets.size() - cs);
            debug_str_offsets[lp + 0] = static_cast<uint8_t>(len & 0xff);
            debug_str_offsets[lp + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
            debug_str_offsets[lp + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
            debug_str_offsets[lp + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
        };
        startContrib(/*str_off=*/0); // entry 0 -> "ONE 1"
        startContrib(/*str_off=*/6); // entry 0 -> "TWO 2"

        // Macro unit uses index=1. With base at first table start, this would land in the second contribution
        // if unbounded; bounded behavior should return "" (name/value empty).
        std::vector<uint8_t> debug_macro3;
        ::appendU32(debug_macro3, 0);
        size_t cs = debug_macro3.size();
        appendU16LE(debug_macro3, 5);
        debug_macro3.push_back(0x00);
        debug_macro3.push_back(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define_strx));
        appendULEB(debug_macro3, 1);
        appendULEB(debug_macro3, 1); // index=1 (out of contrib0)
        debug_macro3.push_back(0x00);
        uint32_t len = static_cast<uint32_t>(debug_macro3.size() - cs);
        debug_macro3[0] = static_cast<uint8_t>(len & 0xff);
        debug_macro3[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_macro3[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_macro3[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        std::vector<uint8_t> empty;
        DebugMacroParser p3(debug_macro3, &debug_str, &empty, &debug_str_offsets, &empty);
        // base points at first table start: first contrib header is 8 bytes (len+ver+pad).
        p3.setStrOffsetsBase(/*str_offsets_base=*/8, 4);
        auto e3 = p3.parseMacroUnit(0);
        assert(e3.size() == 1);
        assert(e3[0].name.empty());
        assert(e3[0].value.empty());
    }

    // Ensure getDefinitions() follows DW_MACRO_import within the same .debug_macro section.
    {
        std::vector<uint8_t> mac;

        auto appendU8m = [&](uint8_t v) { mac.push_back(v); };
        auto appendU16m = [&](uint16_t v) {
            mac.push_back(static_cast<uint8_t>(v & 0xff));
            mac.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        };
        auto appendU32m = [&](uint32_t v) { ::appendU32(mac, v); };
        auto appendCStringM = [&](const char* s) {
            while (*s) appendU8m(static_cast<uint8_t>(*s++));
            appendU8m(0);
        };

        auto startUnit = [&]() -> std::pair<size_t, size_t> {
            size_t lp = mac.size();
            appendU32m(0);
            size_t cs = mac.size();
            appendU16m(5);
            appendU8m(0x00);
            return {lp, cs};
        };
        auto finishUnit = [&](size_t lp, size_t cs) {
            uint32_t len = static_cast<uint32_t>(mac.size() - cs);
            mac[lp + 0] = static_cast<uint8_t>(len & 0xff);
            mac[lp + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
            mac[lp + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
            mac[lp + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
        };

        // Unit 1: define A 1; import unit2; end.
        auto [lp1, cs1] = startUnit();
        appendU8m(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define));
        appendU8m(1);
        appendCStringM("A 1");
        appendU8m(static_cast<uint8_t>(DW_MACRO::DW_MACRO_import));
        // placeholder offset, patched after unit2 emitted
        size_t import_off_pos = mac.size();
        appendU32m(0);
        appendU8m(0x00);
        finishUnit(lp1, cs1);

        uint64_t unit2_off = mac.size();
        // Unit 2: define B 2; end.
        auto [lp2, cs2] = startUnit();
        appendU8m(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define));
        appendU8m(2);
        appendCStringM("B 2");
        appendU8m(0x00);
        finishUnit(lp2, cs2);

        // Patch import offset (DWARF32 offset_size in macro header flags).
        mac[import_off_pos + 0] = static_cast<uint8_t>(unit2_off & 0xff);
        mac[import_off_pos + 1] = static_cast<uint8_t>((unit2_off >> 8) & 0xff);
        mac[import_off_pos + 2] = static_cast<uint8_t>((unit2_off >> 16) & 0xff);
        mac[import_off_pos + 3] = static_cast<uint8_t>((unit2_off >> 24) & 0xff);

        DebugMacroParser p(mac);
        auto defs = p.getDefinitions(0);
        assert(defs.size() == 2);
        assert(defs[0].name == "A");
        assert(defs[1].name == "B");
    }

    // If the macro unit provides an opcode operands table, we should be able to skip unknown
    // opcodes and continue parsing later entries.
    {
        std::vector<uint8_t> mac;
        ::appendU32(mac, 0); // unit_length placeholder
        size_t cs = mac.size();
        appendU16LE(mac, 5);       // version
        mac.push_back(0x04);       // flags: has_opcode_operands_table, 32-bit offsets

        // opcode operands table:
        // opcode_count=2:
        // - opcode=0xee, operand_count=2, forms=[DW_FORM_udata, DW_FORM_string]
        // - opcode=0xef, operand_count=2, forms=[DW_FORM_strx3, DW_FORM_ref_sig8]
        mac.push_back(2);
        mac.push_back(0xee);
        appendULEB(mac, 2);
        appendULEB(mac, static_cast<uint64_t>(DwarfForm::DW_FORM_udata));
        appendULEB(mac, static_cast<uint64_t>(DwarfForm::DW_FORM_string));
        mac.push_back(0xef);
        appendULEB(mac, 2);
        appendULEB(mac, static_cast<uint64_t>(DwarfForm::DW_FORM_strx3));
        appendULEB(mac, static_cast<uint64_t>(DwarfForm::DW_FORM_ref_sig8));

        // Unknown opcode 0xee payload: udata(7), string("IGNORED")
        mac.push_back(0xee);
        appendULEB(mac, 7);
        ::appendCString(mac, "IGNORED");

        // Unknown opcode 0xef payload: strx3 index bytes + ref_sig8.
        mac.push_back(0xef);
        mac.push_back(0x01);
        mac.push_back(0x02);
        mac.push_back(0x03);
        ::appendU64(mac, 0x1122334455667788ULL);

        // Then a normal define that we must still parse.
        mac.push_back(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define));
        appendULEB(mac, 10);
        ::appendCString(mac, "FOO 1");
        mac.push_back(0x00); // end

        uint32_t len = static_cast<uint32_t>(mac.size() - cs);
        mac[0] = static_cast<uint8_t>(len & 0xff);
        mac[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        mac[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        mac[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugMacroParser p(mac);
        auto e = p.parseMacroUnit(0);
        assert(e.size() == 3);
        assert(static_cast<uint8_t>(e[0].type) == 0xee);
        assert(static_cast<uint8_t>(e[1].type) == 0xef);
        assert(e[2].type == DW_MACRO::DW_MACRO_define);
        assert(e[2].name == "FOO");
        assert(e[2].value == "1");
    }

    // Truncated DWARF64 unit header must be rejected.
    {
        std::vector<uint8_t> mac;
        ::appendU32(mac, 0xffffffffu); // DWARF64 marker, but no 64-bit length follows.
        DebugMacroParser p(mac);
        auto e = p.parseMacroUnit(0);
        assert(e.empty());
    }

    // Unterminated in-unit string must not bleed into a following unit.
    {
        std::vector<uint8_t> mac;

        // Unit 1 (malformed): define with unterminated macro string.
        size_t lp1 = mac.size();
        ::appendU32(mac, 0);
        size_t cs1 = mac.size();
        appendU16LE(mac, 5);
        mac.push_back(0x00);
        mac.push_back(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define));
        appendULEB(mac, 1);
        mac.push_back('B');
        mac.push_back('A');
        mac.push_back('D'); // missing terminating NUL
        uint32_t len1 = static_cast<uint32_t>(mac.size() - cs1);
        mac[lp1 + 0] = static_cast<uint8_t>(len1 & 0xff);
        mac[lp1 + 1] = static_cast<uint8_t>((len1 >> 8) & 0xff);
        mac[lp1 + 2] = static_cast<uint8_t>((len1 >> 16) & 0xff);
        mac[lp1 + 3] = static_cast<uint8_t>((len1 >> 24) & 0xff);

        // Unit 2 (valid): must still parse independently.
        uint64_t unit2_off = mac.size();
        size_t lp2 = mac.size();
        ::appendU32(mac, 0);
        size_t cs2 = mac.size();
        appendU16LE(mac, 5);
        mac.push_back(0x00);
        mac.push_back(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define));
        appendULEB(mac, 2);
        ::appendCString(mac, "OK 1");
        mac.push_back(0x00);
        uint32_t len2 = static_cast<uint32_t>(mac.size() - cs2);
        mac[lp2 + 0] = static_cast<uint8_t>(len2 & 0xff);
        mac[lp2 + 1] = static_cast<uint8_t>((len2 >> 8) & 0xff);
        mac[lp2 + 2] = static_cast<uint8_t>((len2 >> 16) & 0xff);
        mac[lp2 + 3] = static_cast<uint8_t>((len2 >> 24) & 0xff);

        DebugMacroParser p(mac);
        auto e1 = p.parseMacroUnit(0);
        auto e2 = p.parseMacroUnit(unit2_off);
        assert(e1.empty());
        assert(e2.size() == 1);
        assert(e2[0].name == "OK");
        assert(e2[0].value == "1");
    }

    // Truncated opcode-operands table must be rejected.
    {
        std::vector<uint8_t> mac;
        ::appendU32(mac, 0);
        size_t cs = mac.size();
        appendU16LE(mac, 5);
        mac.push_back(0x04); // has_opcode_operands_table
        mac.push_back(1);    // opcode_count
        mac.push_back(0xee); // opcode
        mac.push_back(0x80); // truncated ULEB operand_count
        uint32_t len = static_cast<uint32_t>(mac.size() - cs);
        mac[0] = static_cast<uint8_t>(len & 0xff);
        mac[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        mac[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        mac[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugMacroParser p(mac);
        auto e = p.parseMacroUnit(0);
        assert(e.empty());
    }

    // Malformed skip payload for unknown opcode must stop unit parsing.
    {
        std::vector<uint8_t> mac;
        ::appendU32(mac, 0);
        size_t cs = mac.size();
        appendU16LE(mac, 5);
        mac.push_back(0x04); // has opcode operands table
        mac.push_back(1);    // opcode_count
        mac.push_back(0xee);
        appendULEB(mac, 1); // one operand
        appendULEB(mac, static_cast<uint64_t>(DwarfForm::DW_FORM_block1));

        mac.push_back(0xee);
        mac.push_back(250); // claimed block size (too large for remaining unit bytes)

        // A valid define after malformed unknown opcode should not be parsed.
        mac.push_back(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define));
        appendULEB(mac, 3);
        ::appendCString(mac, "LATE 1");
        mac.push_back(0x00);

        uint32_t len = static_cast<uint32_t>(mac.size() - cs);
        mac[0] = static_cast<uint8_t>(len & 0xff);
        mac[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        mac[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        mac[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugMacroParser p(mac);
        auto e = p.parseMacroUnit(0);
        assert(e.empty());
    }

    // Unterminated .debug_str payload referenced by define_strp should return empty name/value.
    {
        std::vector<uint8_t> debug_str = {'B', 'A', 'D'}; // no NUL
        std::vector<uint8_t> empty;
        std::vector<uint8_t> mac;
        ::appendU32(mac, 0);
        size_t cs = mac.size();
        appendU16LE(mac, 5);
        mac.push_back(0x00);
        mac.push_back(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define_strp));
        appendULEB(mac, 1);
        ::appendU32(mac, 0); // strp offset
        mac.push_back(0x00);
        uint32_t len = static_cast<uint32_t>(mac.size() - cs);
        mac[0] = static_cast<uint8_t>(len & 0xff);
        mac[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        mac[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        mac[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugMacroParser p(mac, &debug_str, &empty, &empty, &empty);
        auto e = p.parseMacroUnit(0);
        assert(e.size() == 1);
        assert(e[0].name.empty());
        assert(e[0].value.empty());
    }

    std::cout << ".debug_macro parser tests passed!" << std::endl;
}

void testDwarfParserMacroLookupFallsBackAcrossCUs() {
    std::cout << "Testing DwarfParser macro lookup fallback across CUs..." << std::endl;

    // Abbrev table:
    // 1: compile_unit, no children, DW_AT_macros (sec_offset).
    std::vector<uint8_t> debug_abbrev;
    debug_abbrev.push_back(0x01);
    debug_abbrev.push_back(0x11); // DW_TAG_compile_unit
    debug_abbrev.push_back(0x00); // no children
    debug_abbrev.push_back(0x79); // DW_AT_macros
    debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_sec_offset));
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00);

    // Build .debug_macro with one unit at offset 0 defining FOO 1.
    std::vector<uint8_t> debug_macro;
    ::appendU32(debug_macro, 0);
    size_t mac_cs = debug_macro.size();
    ::appendU16(debug_macro, 5);
    debug_macro.push_back(0x00); // flags
    debug_macro.push_back(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define));
    debug_macro.push_back(0x01); // line
    ::appendCString(debug_macro, "FOO 1");
    debug_macro.push_back(0x00);
    uint32_t mac_len = static_cast<uint32_t>(debug_macro.size() - mac_cs);
    debug_macro[0] = static_cast<uint8_t>(mac_len & 0xff);
    debug_macro[1] = static_cast<uint8_t>((mac_len >> 8) & 0xff);
    debug_macro[2] = static_cast<uint8_t>((mac_len >> 16) & 0xff);
    debug_macro[3] = static_cast<uint8_t>((mac_len >> 24) & 0xff);

    // .debug_info: two DWARF5 compile units.
    std::vector<uint8_t> debug_info;
    auto appendUnit = [&](uint32_t macros_off) {
        size_t start = debug_info.size();
        ::appendU32(debug_info, 0); // unit_length placeholder
        debug_info.push_back(0x05); debug_info.push_back(0x00); // version 5
        debug_info.push_back(0x08); // address_size
        debug_info.push_back(0x00); // unit_type (compile)
        ::appendU32(debug_info, 0); // abbrev_offset
        debug_info.push_back(0x01); // abbrev code
        ::appendU32(debug_info, macros_off);
        uint32_t len = static_cast<uint32_t>(debug_info.size() - start - 4);
        debug_info[start + 0] = static_cast<uint8_t>(len & 0xff);
        debug_info[start + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_info[start + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_info[start + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    };

    appendUnit(/*macros_off=*/0); // CU0: no macros
    appendUnit(/*macros_off=*/0); // CU1: points at debug_macro offset 0

    std::vector<uint8_t> debug_str = {'\0'};
    std::string dir = makeTempDir("dwarf_macro_fb_");
    std::string elf_path = (std::filesystem::path(dir) / "macro_fb.elf").string();
    writeELFWithSections(elf_path, {
        {".debug_info", debug_info},
        {".debug_abbrev", debug_abbrev},
        {".debug_str", debug_str},
        {".debug_macro", debug_macro},
    });

    DwarfParser parser(elf_path);
    assert(parser.load());

    auto defs = parser.lookupMacro("FOO", /*offset=*/0);
    assert(!defs.empty());
    assert(defs[0].name == "FOO");
    assert(defs[0].value == "1");

    std::cout << "DwarfParser macro lookup fallback tests passed!" << std::endl;
}

void testDwarfParserGetFunctionAtUsesRanges() {
    std::cout << "Testing DwarfParser getFunctionAt() with DW_AT_ranges..." << std::endl;

    // .debug_str: "func\0"
    std::vector<uint8_t> debug_str;
    const std::string fn = "func";
    uint32_t fn_off = static_cast<uint32_t>(debug_str.size());
    for (char c : fn) debug_str.push_back(static_cast<uint8_t>(c));
    debug_str.push_back(0);

    // .debug_abbrev:
    // 1) CU: low_pc(addr), children
    // 2) subprogram: name(strp), ranges(sec_offset)
    std::vector<uint8_t> debug_abbrev;
    appendULEB(debug_abbrev, 1);
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfTag::DW_TAG_compile_unit));
    debug_abbrev.push_back(0x01); // children
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_low_pc));
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_addr));
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00);

    appendULEB(debug_abbrev, 2);
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfTag::DW_TAG_subprogram));
    debug_abbrev.push_back(0x00); // no children
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_name));
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_strp));
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_ranges));
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_sec_offset));
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00);

    debug_abbrev.push_back(0x00); // end abbrev table

    // .debug_ranges: one entry [0,0x10) relative to CU low_pc (0x1000), then terminator.
    std::vector<uint8_t> debug_ranges;
    appendU64(debug_ranges, 0x0);
    appendU64(debug_ranges, 0x10);
    appendU64(debug_ranges, 0x0);
    appendU64(debug_ranges, 0x0);

    // .debug_info (DWARF4, 64-bit addresses).
    std::vector<uint8_t> debug_info;
    appendU32(debug_info, 0); // unit_length placeholder
    debug_info.push_back(0x04); debug_info.push_back(0x00); // version 4
    appendU32(debug_info, 0); // abbrev offset
    debug_info.push_back(0x08); // address size

    debug_info.push_back(0x01); // CU abbrev code
    appendU64(debug_info, 0x1000); // CU low_pc (base for ranges)

    debug_info.push_back(0x02); // subprogram abbrev code
    appendU32(debug_info, fn_off); // name strp
    appendU32(debug_info, 0x0);    // ranges sec_offset

    debug_info.push_back(0x00); // end children

    uint32_t unit_len = static_cast<uint32_t>(debug_info.size() - 4);
    debug_info[0] = static_cast<uint8_t>(unit_len & 0xff);
    debug_info[1] = static_cast<uint8_t>((unit_len >> 8) & 0xff);
    debug_info[2] = static_cast<uint8_t>((unit_len >> 16) & 0xff);
    debug_info[3] = static_cast<uint8_t>((unit_len >> 24) & 0xff);

    std::string dir = makeTempDir("dwarf_ranges_func_");
    std::string elf_path = (std::filesystem::path(dir) / "ranges_func.elf").string();
    writeELFWithSections(elf_path, {
        {".debug_info", debug_info},
        {".debug_abbrev", debug_abbrev},
        {".debug_str", debug_str},
        {".debug_ranges", debug_ranges},
    });

    DwarfParser parser(elf_path);
    assert(parser.load());

    auto die = parser.getFunctionAt(0x1008);
    assert(die);
    assert(die->getTag() == DwarfTag::DW_TAG_subprogram);
    assert(die->getName() == fn);

    assert(!parser.getFunctionAt(0x2000));

    auto funcs = parser.getFunctionsInRange(0x1004, 0x1009);
    bool found = false;
    for (const auto& f : funcs) {
        if (f && f->getName() == fn) {
            found = true;
            break;
        }
    }
    assert(found);

    std::cout << "DwarfParser getFunctionAt ranges tests passed!" << std::endl;
}

static void appendULEB(std::vector<uint8_t>& out, uint64_t v) {
    // Minimal ULEB128 encoder (sufficient for our small synthetic values).
    do {
        uint8_t byte = static_cast<uint8_t>(v & 0x7f);
        v >>= 7;
        if (v != 0) byte |= 0x80;
        out.push_back(byte);
    } while (v != 0);
}

static void appendSLEB(std::vector<uint8_t>& out, int64_t v) {
    bool more = true;
    while (more) {
        uint8_t byte = static_cast<uint8_t>(v & 0x7f);
        bool sign = (byte & 0x40) != 0;
        v >>= 7;
        if ((v == 0 && !sign) || (v == -1 && sign)) {
            more = false;
        } else {
            byte |= 0x80;
        }
        out.push_back(byte);
    }
}

static void appendU16LE(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
}

static void appendU32LE(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
}

static void appendU64LE(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xff));
}

static void appendCString(std::vector<uint8_t>& out, const char* s) {
    while (*s) out.push_back(static_cast<uint8_t>(*s++));
    out.push_back(0);
}

void testDebugLineV4ViaStmtList() {
    std::cout << "Testing .debug_line (DWARF4) via DW_AT_stmt_list..." << std::endl;

    // Build a minimal DWARF4 line table unit at offset 0.
    std::vector<uint8_t> debug_line;

    // unit_length placeholder
    appendU32LE(debug_line, 0);

    appendU16LE(debug_line, 4); // version

    size_t header_len_pos = debug_line.size();
    appendU32LE(debug_line, 0); // header_length placeholder

    // Common header fields
    debug_line.push_back(1);               // minimum_instruction_length
    debug_line.push_back(1);               // max_operations_per_instruction (DWARF 4+)
    debug_line.push_back(1);               // default_is_stmt
    debug_line.push_back(static_cast<uint8_t>(-5)); // line_base
    debug_line.push_back(14);              // line_range
    debug_line.push_back(13);              // opcode_base

    // standard_opcode_lengths for opcodes 1..12
    const uint8_t std_lens[12] = {0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1};
    debug_line.insert(debug_line.end(), std_lens, std_lens + 12);

    // include_directories
    appendCString(debug_line, "src");
    debug_line.push_back(0); // end of dirs

    // file_names
    appendCString(debug_line, "main.c"); // filename
    appendULEB(debug_line, 1);           // dir_index (1-based)
    appendULEB(debug_line, 0);           // mtime
    appendULEB(debug_line, 0);           // size
    debug_line.push_back(0);             // end of files (empty filename)

    uint32_t header_length = static_cast<uint32_t>(debug_line.size() - (header_len_pos + 4));
    debug_line[header_len_pos + 0] = static_cast<uint8_t>(header_length & 0xff);
    debug_line[header_len_pos + 1] = static_cast<uint8_t>((header_length >> 8) & 0xff);
    debug_line[header_len_pos + 2] = static_cast<uint8_t>((header_length >> 16) & 0xff);
    debug_line[header_len_pos + 3] = static_cast<uint8_t>((header_length >> 24) & 0xff);

    // Line program opcodes
    // DW_LNE_set_address(0x1000)
    debug_line.push_back(0);
    appendULEB(debug_line, 1 + 8);
    debug_line.push_back(static_cast<uint8_t>(DwarfLineExtOp::DW_LNE_set_address));
    appendU64LE(debug_line, 0x1000);

    // copy row (line 1, file 1)
    debug_line.push_back(static_cast<uint8_t>(DwarfLineOp::DW_LNS_copy));

    // advance_line +1, advance_pc +4, copy
    debug_line.push_back(static_cast<uint8_t>(DwarfLineOp::DW_LNS_advance_line));
    appendSLEB(debug_line, 1);
    debug_line.push_back(static_cast<uint8_t>(DwarfLineOp::DW_LNS_advance_pc));
    appendULEB(debug_line, 4);
    debug_line.push_back(static_cast<uint8_t>(DwarfLineOp::DW_LNS_copy));

    // end_sequence
    debug_line.push_back(0);
    appendULEB(debug_line, 1);
    debug_line.push_back(static_cast<uint8_t>(DwarfLineExtOp::DW_LNE_end_sequence));

    uint32_t unit_length = static_cast<uint32_t>(debug_line.size() - 4);
    debug_line[0] = static_cast<uint8_t>(unit_length & 0xff);
    debug_line[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
    debug_line[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
    debug_line[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

    // Build DW_AT_stmt_list as DW_FORM_sec_offset (points to 0)
    std::vector<uint8_t> debug_info = {0, 0, 0, 0};
    std::vector<uint8_t> empty;
    AttributeParser ap(debug_info, empty, empty, debug_line);
    ap.setAddressSize(8);
    ap.setIsDwarf64(false);
    ap.setDwarfVersion(DwarfVersion::DWARF4);

    uint64_t off = 0;
    auto attr = ap.parseAttribute(DwarfAttribute::DW_AT_stmt_list, DwarfForm::DW_FORM_sec_offset, off);
    auto line_attr = std::dynamic_pointer_cast<LineAttributeValue>(attr);
    assert(line_attr);

    assert(line_attr->getDirectories().size() == 1);
    assert(line_attr->getDirectories()[0] == "src");
    assert(line_attr->getFiles().size() == 1);
    assert(line_attr->getFiles()[0].filename == "main.c");
    assert(line_attr->getFiles()[0].dir_index == 1);

    const auto& rows = line_attr->getLines();
    assert(rows.size() >= 2);
    assert(rows[0].address == 0x1000);
    assert(rows[0].file == 1);
    assert(rows[0].line == 1);
    assert(rows[1].address == 0x1004);
    assert(rows[1].line == 2);

    std::cout << ".debug_line (DWARF4) tests passed!" << std::endl;
}

void testDebugLineV5ViaStmtList() {
    std::cout << "Testing .debug_line (DWARF5) via DW_AT_stmt_list..." << std::endl;

    // .debug_line_str with two strings: "src" and "main.c"
    std::vector<uint8_t> debug_line_str;
    appendCString(debug_line_str, "src");
    uint32_t main_c_off = static_cast<uint32_t>(debug_line_str.size());
    appendCString(debug_line_str, "main.c");

    // Build a minimal DWARF5 line table unit at offset 0 (DWARF32).
    std::vector<uint8_t> debug_line;
    appendU32LE(debug_line, 0);        // unit_length placeholder
    appendU16LE(debug_line, 5);        // version
    debug_line.push_back(8);           // address_size
    debug_line.push_back(0);           // segment_selector_size

    size_t header_len_pos = debug_line.size();
    appendU32LE(debug_line, 0);        // header_length placeholder

    debug_line.push_back(1);           // minimum_instruction_length
    debug_line.push_back(1);           // max_operations_per_instruction
    debug_line.push_back(1);           // default_is_stmt
    debug_line.push_back(static_cast<uint8_t>(-5)); // line_base
    debug_line.push_back(14);          // line_range
    debug_line.push_back(13);          // opcode_base
    const uint8_t std_lens[12] = {0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1};
    debug_line.insert(debug_line.end(), std_lens, std_lens + 12);

    // Directory table:
    // entry_format_count=1: (DW_LNCT_path, DW_FORM_line_strp), directories_count=1, path offset=0
    debug_line.push_back(1);
    appendULEB(debug_line, 1); // DW_LNCT_path
    appendULEB(debug_line, static_cast<uint64_t>(DwarfForm::DW_FORM_line_strp));
    appendULEB(debug_line, 1); // directories_count
    appendU32LE(debug_line, 0); // offset into .debug_line_str ("src")

    // File table:
    // entry_format_count=2: (path,line_strp) (directory_index,udata)
    debug_line.push_back(2);
    appendULEB(debug_line, 1); // DW_LNCT_path
    appendULEB(debug_line, static_cast<uint64_t>(DwarfForm::DW_FORM_line_strp));
    appendULEB(debug_line, 2); // DW_LNCT_directory_index
    appendULEB(debug_line, static_cast<uint64_t>(DwarfForm::DW_FORM_udata));
    appendULEB(debug_line, 1); // files_count
    appendU32LE(debug_line, main_c_off); // filename offset
    appendULEB(debug_line, 1);           // dir_index

    uint32_t header_length = static_cast<uint32_t>(debug_line.size() - (header_len_pos + 4));
    debug_line[header_len_pos + 0] = static_cast<uint8_t>(header_length & 0xff);
    debug_line[header_len_pos + 1] = static_cast<uint8_t>((header_length >> 8) & 0xff);
    debug_line[header_len_pos + 2] = static_cast<uint8_t>((header_length >> 16) & 0xff);
    debug_line[header_len_pos + 3] = static_cast<uint8_t>((header_length >> 24) & 0xff);

    // Line program: set_address(0x2000), copy, end_sequence.
    debug_line.push_back(0);
    appendULEB(debug_line, 1 + 8);
    debug_line.push_back(static_cast<uint8_t>(DwarfLineExtOp::DW_LNE_set_address));
    appendU64LE(debug_line, 0x2000);
    debug_line.push_back(static_cast<uint8_t>(DwarfLineOp::DW_LNS_copy));
    debug_line.push_back(0);
    appendULEB(debug_line, 1);
    debug_line.push_back(static_cast<uint8_t>(DwarfLineExtOp::DW_LNE_end_sequence));

    uint32_t unit_length = static_cast<uint32_t>(debug_line.size() - 4);
    debug_line[0] = static_cast<uint8_t>(unit_length & 0xff);
    debug_line[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
    debug_line[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
    debug_line[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

    std::vector<uint8_t> debug_info = {0, 0, 0, 0};
    std::vector<uint8_t> empty;
    AttributeParser ap(debug_info, empty, empty, debug_line, {}, {}, {}, {}, debug_line_str);
    ap.setAddressSize(8);
    ap.setIsDwarf64(false);
    ap.setDwarfVersion(DwarfVersion::DWARF5);

    uint64_t off = 0;
    auto attr = ap.parseAttribute(DwarfAttribute::DW_AT_stmt_list, DwarfForm::DW_FORM_sec_offset, off);
    auto line_attr = std::dynamic_pointer_cast<LineAttributeValue>(attr);
    assert(line_attr);

    assert(line_attr->getDirectories().size() == 1);
    assert(line_attr->getDirectories()[0] == "src");
    assert(line_attr->getFiles().size() == 1);
    assert(line_attr->getFiles()[0].filename == "main.c");
    assert(line_attr->getFiles()[0].dir_index == 1);

    const auto& rows = line_attr->getLines();
    assert(!rows.empty());
    assert(rows[0].address == 0x2000);
    assert(rows[0].file == 1);
    assert(rows[0].line == 1);

    std::cout << ".debug_line (DWARF5) tests passed!" << std::endl;
}

void testStrxBasePointsToContributionHeader() {
    std::cout << "Testing DW_FORM_strx with base pointing at .debug_str_offsets header..." << std::endl;

    // .debug_str
    std::vector<uint8_t> debug_str = {'h', 'i', 0x00};

    // .debug_str_offsets contribution (DWARF32):
    // unit_length, version=5, padding=0, offsets[0]=0
    std::vector<uint8_t> debug_str_offsets;
    appendU32(debug_str_offsets, 0); // unit_length placeholder
    appendU16(debug_str_offsets, 5);
    appendU16(debug_str_offsets, 0);
    appendU32(debug_str_offsets, 0); // offsets[0]=0 into .debug_str

    uint32_t unit_length = static_cast<uint32_t>(debug_str_offsets.size() - 4);
    debug_str_offsets[0] = static_cast<uint8_t>(unit_length & 0xff);
    debug_str_offsets[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
    debug_str_offsets[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
    debug_str_offsets[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

    // debug_info contains ULEB128 index=0
    std::vector<uint8_t> debug_info = {0x00};
    std::vector<uint8_t> empty;

    AttributeParser ap(debug_info, empty, debug_str,
                       /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                       /*debug_str_offsets=*/debug_str_offsets, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                       /*debug_rnglists=*/empty, /*debug_loclists=*/empty,
                       /*debug_str_sup=*/empty);
    ap.setIsDwarf64(false);
    ap.setAddressSize(8);
    ap.setDwarfVersion(DwarfVersion::DWARF5);

    // Simulate DW_AT_str_offsets_base pointing to the contribution start (header), not the table.
    ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0,
                    /*addr_base=*/0, /*str_offsets_base=*/0,
                    /*base_address=*/0);

    uint64_t off = 0;
    auto v = ap.parseAttribute(DwarfForm::DW_FORM_strx, off);
    auto s = std::dynamic_pointer_cast<StringAttributeValue>(v);
    assert(s);
    assert(s->getValue() == "hi");

    std::cout << "DW_FORM_strx header-base normalization tests passed!" << std::endl;
}

void testStrxContributionBoundsWhenBasePointsToTableStart() {
    std::cout << "Testing DW_FORM_strx contribution bounds when base points at table start..." << std::endl;

    // Two back-to-back .debug_str_offsets contributions (DWARF32).
    // CU's DW_AT_str_offsets_base points at the *table* start of contribution 1.
    //
    // Without per-contribution bounds, an index that runs past contrib1 would read into contrib2's header.
    std::vector<uint8_t> debug_str_offsets;
    std::vector<uint8_t> debug_str;

    // Build .debug_str with two strings and align with offsets we use below.
    // Offsets are into this blob.
    const uint32_t off_hi = static_cast<uint32_t>(debug_str.size());
    debug_str.insert(debug_str.end(), {'h','i','\0'});
    const uint32_t off_bye = static_cast<uint32_t>(debug_str.size());
    debug_str.insert(debug_str.end(), {'b','y','e','\0'});

    // Contribution 1: header + 1 offset entry -> points at "hi"
    size_t contrib1_start = debug_str_offsets.size();
    appendU32(debug_str_offsets, 0); // unit_length placeholder
    appendU16(debug_str_offsets, 5);
    appendU16(debug_str_offsets, 0);
    appendU32(debug_str_offsets, off_hi);
    {
        uint32_t unit_length = static_cast<uint32_t>(debug_str_offsets.size() - contrib1_start - 4);
        debug_str_offsets[contrib1_start + 0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_str_offsets[contrib1_start + 1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_str_offsets[contrib1_start + 2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_str_offsets[contrib1_start + 3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    // Contribution 2: header + 1 offset entry -> points at "bye"
    size_t contrib2_start = debug_str_offsets.size();
    appendU32(debug_str_offsets, 0); // unit_length placeholder
    appendU16(debug_str_offsets, 5);
    appendU16(debug_str_offsets, 0);
    appendU32(debug_str_offsets, off_bye);
    {
        uint32_t unit_length = static_cast<uint32_t>(debug_str_offsets.size() - contrib2_start - 4);
        debug_str_offsets[contrib2_start + 0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_str_offsets[contrib2_start + 1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_str_offsets[contrib2_start + 2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_str_offsets[contrib2_start + 3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    // Table start for contrib1 is 8 bytes after contrib1_start in DWARF32.
    uint64_t contrib1_table_start = static_cast<uint64_t>(contrib1_start + 8);

    std::vector<uint8_t> empty;

    // Index 0 should resolve to "hi".
    {
        std::vector<uint8_t> debug_info = {0x00}; // ULEB128 index=0
        AttributeParser ap(debug_info, empty, debug_str,
                           /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                           /*debug_str_offsets=*/debug_str_offsets, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                           /*debug_rnglists=*/empty, /*debug_loclists=*/empty,
                           /*debug_str_sup=*/empty);
        ap.setIsDwarf64(false);
        ap.setAddressSize(8);
        ap.setDwarfVersion(DwarfVersion::DWARF5);
        ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0,
                        /*addr_base=*/0, /*str_offsets_base=*/contrib1_table_start,
                        /*base_address=*/0);

        uint64_t off = 0;
        auto v = ap.parseAttribute(DwarfForm::DW_FORM_strx, off);
        auto s = std::dynamic_pointer_cast<StringAttributeValue>(v);
        assert(s);
        assert(s->getValue() == "hi");
    }

    // Index 1 is out of bounds for contrib1 and must NOT read contrib2's header/entries.
    // Current fallback returns "<strx:index>" when table read fails.
    {
        std::vector<uint8_t> debug_info = {0x01}; // ULEB128 index=1
        AttributeParser ap(debug_info, empty, debug_str,
                           /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                           /*debug_str_offsets=*/debug_str_offsets, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                           /*debug_rnglists=*/empty, /*debug_loclists=*/empty,
                           /*debug_str_sup=*/empty);
        ap.setIsDwarf64(false);
        ap.setAddressSize(8);
        ap.setDwarfVersion(DwarfVersion::DWARF5);
        ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0,
                        /*addr_base=*/0, /*str_offsets_base=*/contrib1_table_start,
                        /*base_address=*/0);

        uint64_t off = 0;
        auto v = ap.parseAttribute(DwarfForm::DW_FORM_strx, off);
        auto s = std::dynamic_pointer_cast<StringAttributeValue>(v);
        assert(s);
        assert(s->getValue() == "<strx:1>");
    }

    std::cout << "DW_FORM_strx contribution bounds tests passed!" << std::endl;
}

void testAddrxBasePointsToContributionHeader() {
    std::cout << "Testing DW_FORM_addrx with base pointing at .debug_addr header..." << std::endl;

    // .debug_addr contribution (DWARF32):
    // unit_length, version=5, address_size=8, seg=0, addrs[0]=0x1234
    std::vector<uint8_t> debug_addr;
    appendU32(debug_addr, 0); // unit_length placeholder
    appendU16(debug_addr, 5);
    debug_addr.push_back(8);
    debug_addr.push_back(0);
    appendU64(debug_addr, 0x1234);

    uint32_t unit_length = static_cast<uint32_t>(debug_addr.size() - 4);
    debug_addr[0] = static_cast<uint8_t>(unit_length & 0xff);
    debug_addr[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
    debug_addr[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
    debug_addr[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

    // debug_info contains ULEB128 index=0
    std::vector<uint8_t> debug_info = {0x00};
    std::vector<uint8_t> empty;
    std::vector<uint8_t> debug_str;

    AttributeParser ap(debug_info, empty, debug_str,
                       /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                       /*debug_str_offsets=*/empty, /*debug_addr=*/debug_addr, /*debug_line_str=*/empty,
                       /*debug_rnglists=*/empty, /*debug_loclists=*/empty,
                       /*debug_str_sup=*/empty);
    ap.setIsDwarf64(false);
    ap.setAddressSize(8);
    ap.setDwarfVersion(DwarfVersion::DWARF5);

    // Simulate DW_AT_addr_base pointing to contribution start (header).
    ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0,
                    /*addr_base=*/0, /*str_offsets_base=*/0,
                    /*base_address=*/0);

    uint64_t off = 0;
    auto v = ap.parseAttribute(DwarfForm::DW_FORM_addrx, off);
    auto a = std::dynamic_pointer_cast<AddressAttributeValue>(v);
    assert(a);
    assert(a->getAddress() == 0x1234);

    std::cout << "DW_FORM_addrx header-base normalization tests passed!" << std::endl;
}

void testAddrxContributionBoundsWhenBasePointsToTableStart() {
    std::cout << "Testing DW_FORM_addrx contribution bounds when base points at table start..." << std::endl;

    // Two back-to-back .debug_addr contributions (DWARF32).
    // CU's DW_AT_addr_base points at the *table* start of contribution 1.
    //
    // Without per-contribution bounds, an index that runs past contrib1 would read into contrib2's header.
    std::vector<uint8_t> debug_addr;

    // Contribution 1: header + 1 entry (0x1234)
    size_t contrib1_start = debug_addr.size();
    appendU32(debug_addr, 0); // unit_length placeholder
    appendU16(debug_addr, 5);
    debug_addr.push_back(8); // address_size
    debug_addr.push_back(0); // seg selector size
    appendU64(debug_addr, 0x1234);
    {
        uint32_t unit_length = static_cast<uint32_t>(debug_addr.size() - contrib1_start - 4);
        debug_addr[contrib1_start + 0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_addr[contrib1_start + 1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_addr[contrib1_start + 2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_addr[contrib1_start + 3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    // Contribution 2: header + 1 entry (0x5678)
    size_t contrib2_start = debug_addr.size();
    appendU32(debug_addr, 0); // unit_length placeholder
    appendU16(debug_addr, 5);
    debug_addr.push_back(8);
    debug_addr.push_back(0);
    appendU64(debug_addr, 0x5678);
    {
        uint32_t unit_length = static_cast<uint32_t>(debug_addr.size() - contrib2_start - 4);
        debug_addr[contrib2_start + 0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_addr[contrib2_start + 1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_addr[contrib2_start + 2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_addr[contrib2_start + 3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    // Table start for contrib1 is 8 bytes after contrib1_start in DWARF32.
    uint64_t contrib1_table_start = static_cast<uint64_t>(contrib1_start + 8);

    std::vector<uint8_t> empty;
    std::vector<uint8_t> debug_str;

    // Index 0 should resolve to 0x1234.
    {
        std::vector<uint8_t> debug_info = {0x00}; // ULEB128 index=0
        AttributeParser ap(debug_info, empty, debug_str,
                           /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                           /*debug_str_offsets=*/empty, /*debug_addr=*/debug_addr, /*debug_line_str=*/empty,
                           /*debug_rnglists=*/empty, /*debug_loclists=*/empty,
                           /*debug_str_sup=*/empty);
        ap.setIsDwarf64(false);
        ap.setAddressSize(8);
        ap.setDwarfVersion(DwarfVersion::DWARF5);
        ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0,
                        /*addr_base=*/contrib1_table_start, /*str_offsets_base=*/0,
                        /*base_address=*/0);

        uint64_t off = 0;
        auto v = ap.parseAttribute(DwarfForm::DW_FORM_addrx, off);
        auto a = std::dynamic_pointer_cast<AddressAttributeValue>(v);
        assert(a);
        assert(a->getAddress() == 0x1234);
    }

    // Index 1 is out of bounds for contrib1 and must NOT read contrib2's header/entries.
    // The current fallback returns AddressAttributeValue(index) when the table read fails.
    {
        std::vector<uint8_t> debug_info = {0x01}; // ULEB128 index=1
        AttributeParser ap(debug_info, empty, debug_str,
                           /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                           /*debug_str_offsets=*/empty, /*debug_addr=*/debug_addr, /*debug_line_str=*/empty,
                           /*debug_rnglists=*/empty, /*debug_loclists=*/empty,
                           /*debug_str_sup=*/empty);
        ap.setIsDwarf64(false);
        ap.setAddressSize(8);
        ap.setDwarfVersion(DwarfVersion::DWARF5);
        ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0,
                        /*addr_base=*/contrib1_table_start, /*str_offsets_base=*/0,
                        /*base_address=*/0);

        uint64_t off = 0;
        auto v = ap.parseAttribute(DwarfForm::DW_FORM_addrx, off);
        auto a = std::dynamic_pointer_cast<AddressAttributeValue>(v);
        assert(a);
        assert(a->getAddress() == 1);
    }

    std::cout << "DW_FORM_addrx contribution bounds tests passed!" << std::endl;
}

void testRnglistxContributionBoundsWhenBasePointsToTableStart() {
    std::cout << "Testing DW_FORM_rnglistx contribution bounds when base points at table start..." << std::endl;

    // Two back-to-back .debug_rnglists contributions (DWARF32) with 1 offset entry each.
    // CU's DW_AT_rnglists_base points at the *offsets array* start of contribution 1.
    std::vector<uint8_t> debug_rnglists;
    std::vector<uint8_t> empty;

    auto appendRnglistsContribution = [&](uint64_t range_start, uint64_t range_end) -> uint64_t {
        size_t contrib_start = debug_rnglists.size();
        appendU32(debug_rnglists, 0); // unit_length placeholder
        appendU16(debug_rnglists, 5); // version
        debug_rnglists.push_back(8);  // address_size
        debug_rnglists.push_back(0);  // seg selector size
        appendU32(debug_rnglists, 1); // offset_entry_count
        appendU32(debug_rnglists, 4); // offsets[0] = 4 (list starts after this one 4-byte entry)

        debug_rnglists.push_back(static_cast<uint8_t>(DW_RLE::DW_RLE_start_end));
        appendU64(debug_rnglists, range_start);
        appendU64(debug_rnglists, range_end);
        debug_rnglists.push_back(static_cast<uint8_t>(DW_RLE::DW_RLE_end_of_list));

        uint32_t unit_length = static_cast<uint32_t>(debug_rnglists.size() - contrib_start - 4);
        debug_rnglists[contrib_start + 0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_rnglists[contrib_start + 1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_rnglists[contrib_start + 2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_rnglists[contrib_start + 3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

        return static_cast<uint64_t>(contrib_start + 12); // offsets array start for DWARF32
    };

    uint64_t contrib1_offsets_base = appendRnglistsContribution(0x1000, 0x2000);
    (void)appendRnglistsContribution(0x3000, 0x4000);

    // Index 0 should resolve to a range list.
    {
        std::vector<uint8_t> debug_info = {0x00}; // ULEB index=0
        AttributeParser ap(debug_info, empty, /*debug_str=*/empty,
                           /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                           /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                           /*debug_rnglists=*/debug_rnglists, /*debug_loclists=*/empty,
                           /*debug_str_sup=*/empty);
        ap.setIsDwarf64(false);
        ap.setAddressSize(8);
        ap.setDwarfVersion(DwarfVersion::DWARF5);
        ap.setCUContext(/*rnglists_base=*/contrib1_offsets_base, /*loclists_base=*/0,
                        /*addr_base=*/0, /*str_offsets_base=*/0,
                        /*base_address=*/0);

        uint64_t off = 0;
        auto v = ap.parseAttribute(DwarfForm::DW_FORM_rnglistx, off);
        auto r = std::dynamic_pointer_cast<RangeAttributeValue>(v);
        assert(r);
        const auto& ranges = r->getRanges();
        assert(ranges.size() == 1);
        assert(ranges[0].start == 0x1000);
        assert(ranges[0].end == 0x2000);
    }

    // Index 1 is out of bounds (offset_entry_count=1) and must fall back to returning the index.
    {
        std::vector<uint8_t> debug_info = {0x01}; // ULEB index=1
        AttributeParser ap(debug_info, empty, /*debug_str=*/empty,
                           /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                           /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                           /*debug_rnglists=*/debug_rnglists, /*debug_loclists=*/empty,
                           /*debug_str_sup=*/empty);
        ap.setIsDwarf64(false);
        ap.setAddressSize(8);
        ap.setDwarfVersion(DwarfVersion::DWARF5);
        ap.setCUContext(/*rnglists_base=*/contrib1_offsets_base, /*loclists_base=*/0,
                        /*addr_base=*/0, /*str_offsets_base=*/0,
                        /*base_address=*/0);

        uint64_t off = 0;
        auto v = ap.parseAttribute(DwarfForm::DW_FORM_rnglistx, off);
        auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(v);
        assert(u);
        assert(u->getValue() == 1);
    }

    std::cout << "DW_FORM_rnglistx contribution bounds tests passed!" << std::endl;
}

void testLoclistxContributionBoundsWhenBasePointsToTableStart() {
    std::cout << "Testing DW_FORM_loclistx contribution bounds when base points at table start..." << std::endl;

    // Two back-to-back .debug_loclists contributions (DWARF32) with 1 offset entry each.
    // CU's DW_AT_loclists_base points at the *offsets array* start of contribution 1.
    std::vector<uint8_t> debug_loclists;
    std::vector<uint8_t> empty;

    auto appendLoclistsContribution = [&](uint64_t start, uint64_t end) -> uint64_t {
        size_t contrib_start = debug_loclists.size();
        appendU32(debug_loclists, 0); // unit_length placeholder
        appendU16(debug_loclists, 5); // version
        debug_loclists.push_back(8);  // address_size
        debug_loclists.push_back(0);  // seg selector size
        appendU32(debug_loclists, 1); // offset_entry_count
        appendU32(debug_loclists, 4); // offsets[0] = 4

        debug_loclists.push_back(static_cast<uint8_t>(DW_LLE::DW_LLE_start_end));
        appendU64(debug_loclists, start);
        appendU64(debug_loclists, end);
        debug_loclists.push_back(0x01); // expr_len=1
        debug_loclists.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0));
        debug_loclists.push_back(static_cast<uint8_t>(DW_LLE::DW_LLE_end_of_list));

        uint32_t unit_length = static_cast<uint32_t>(debug_loclists.size() - contrib_start - 4);
        debug_loclists[contrib_start + 0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_loclists[contrib_start + 1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_loclists[contrib_start + 2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_loclists[contrib_start + 3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

        return static_cast<uint64_t>(contrib_start + 12); // offsets array start for DWARF32
    };

    uint64_t contrib1_offsets_base = appendLoclistsContribution(0x1000, 0x2000);
    (void)appendLoclistsContribution(0x3000, 0x4000);

    // Index 0 should resolve to a location list.
    {
        std::vector<uint8_t> debug_info = {0x00}; // ULEB index=0
        AttributeParser ap(debug_info, empty, /*debug_str=*/empty,
                           /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                           /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                           /*debug_rnglists=*/empty, /*debug_loclists=*/debug_loclists,
                           /*debug_str_sup=*/empty);
        ap.setIsDwarf64(false);
        ap.setAddressSize(8);
        ap.setDwarfVersion(DwarfVersion::DWARF5);
        ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/contrib1_offsets_base,
                        /*addr_base=*/0, /*str_offsets_base=*/0,
                        /*base_address=*/0);

        uint64_t off = 0;
        auto v = ap.parseAttribute(DwarfForm::DW_FORM_loclistx, off);
        auto l = std::dynamic_pointer_cast<LocationAttributeValue>(v);
        assert(l);
        const auto& entries = l->getEntries();
        assert(entries.size() == 1);
        assert(entries[0].start == 0x1000);
        assert(entries[0].end == 0x2000);
        assert(entries[0].expression.size() == 1);
        assert(entries[0].expression[0] == static_cast<uint8_t>(DwarfOp::DW_OP_reg0));
    }

    // Index 1 is out of bounds (offset_entry_count=1) and must fall back to returning the index.
    {
        std::vector<uint8_t> debug_info = {0x01}; // ULEB index=1
        AttributeParser ap(debug_info, empty, /*debug_str=*/empty,
                           /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                           /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                           /*debug_rnglists=*/empty, /*debug_loclists=*/debug_loclists,
                           /*debug_str_sup=*/empty);
        ap.setIsDwarf64(false);
        ap.setAddressSize(8);
        ap.setDwarfVersion(DwarfVersion::DWARF5);
        ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/contrib1_offsets_base,
                        /*addr_base=*/0, /*str_offsets_base=*/0,
                        /*base_address=*/0);

        uint64_t off = 0;
        auto v = ap.parseAttribute(DwarfForm::DW_FORM_loclistx, off);
        auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(v);
        assert(u);
        assert(u->getValue() == 1);
    }

    std::cout << "DW_FORM_loclistx contribution bounds tests passed!" << std::endl;
}

void testRnglistsParseDoesNotRunPastContributionEnd() {
    std::cout << "Testing .debug_rnglists list parsing is bounded by contribution end..." << std::endl;

    // Contribution 1 has a malformed list (missing DW_RLE_end_of_list).
    // Contribution 2's first byte is crafted so an unbounded parser would treat it as DW_RLE_start_end (0x06),
    // producing a bogus extra range entry by reading into the next contribution.
    std::vector<uint8_t> debug_rnglists;
    std::vector<uint8_t> empty;

    auto finalizeU32Length = [&](size_t contrib_start) {
        uint32_t unit_length = static_cast<uint32_t>(debug_rnglists.size() - contrib_start - 4);
        debug_rnglists[contrib_start + 0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_rnglists[contrib_start + 1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_rnglists[contrib_start + 2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_rnglists[contrib_start + 3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    };

    // Contribution 1 (DWARF32), offset_entry_count=1, offsets[0]=4.
    size_t c1_start = debug_rnglists.size();
    appendU32(debug_rnglists, 0); // unit_length placeholder
    appendU16(debug_rnglists, 5);
    debug_rnglists.push_back(8);
    debug_rnglists.push_back(0);
    appendU32(debug_rnglists, 1);
    appendU32(debug_rnglists, 4);
    // List 0 (malformed: no end_of_list)
    debug_rnglists.push_back(static_cast<uint8_t>(DW_RLE::DW_RLE_start_end));
    appendU64(debug_rnglists, 0x1000);
    appendU64(debug_rnglists, 0x2000);
    finalizeU32Length(c1_start);

    uint64_t c1_offsets_base = static_cast<uint64_t>(c1_start + 12);

    // Contribution 2 (DWARF32), valid but padded so unit_length low byte == 0x06.
    size_t c2_start = debug_rnglists.size();
    appendU32(debug_rnglists, 0); // unit_length placeholder
    appendU16(debug_rnglists, 5);
    debug_rnglists.push_back(8);
    debug_rnglists.push_back(0);
    appendU32(debug_rnglists, 1);
    appendU32(debug_rnglists, 4);
    debug_rnglists.push_back(static_cast<uint8_t>(DW_RLE::DW_RLE_start_end));
    appendU64(debug_rnglists, 0x3000);
    appendU64(debug_rnglists, 0x4000);
    debug_rnglists.push_back(static_cast<uint8_t>(DW_RLE::DW_RLE_end_of_list));
    // Pad until (unit_length & 0xff) == 0x06.
    for (int i = 0; i < 256; ++i) {
        uint32_t ul = static_cast<uint32_t>(debug_rnglists.size() - c2_start - 4);
        if ((ul & 0xffu) == static_cast<uint8_t>(DW_RLE::DW_RLE_start_end)) break;
        debug_rnglists.push_back(0);
    }
    finalizeU32Length(c2_start);

    // Parse via AttributeParser so CU contribution end is computed and passed down to parseRangeList.
    std::vector<uint8_t> debug_info = {0x00}; // ULEB index=0
    AttributeParser ap(debug_info, empty, /*debug_str=*/empty,
                       /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                       /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                       /*debug_rnglists=*/debug_rnglists, /*debug_loclists=*/empty,
                       /*debug_str_sup=*/empty);
    ap.setIsDwarf64(false);
    ap.setAddressSize(8);
    ap.setDwarfVersion(DwarfVersion::DWARF5);
    ap.setCUContext(/*rnglists_base=*/c1_offsets_base, /*loclists_base=*/0,
                    /*addr_base=*/0, /*str_offsets_base=*/0,
                    /*base_address=*/0);

    uint64_t off = 0;
    auto v = ap.parseAttribute(DwarfForm::DW_FORM_rnglistx, off);
    auto r = std::dynamic_pointer_cast<RangeAttributeValue>(v);
    assert(r);
    const auto& ranges = r->getRanges();
    assert(ranges.size() == 1);
    assert(ranges[0].start == 0x1000);
    assert(ranges[0].end == 0x2000);

    std::cout << ".debug_rnglists bounded parse tests passed!" << std::endl;
}

void testRnglistsSegmentSelectorSizeIsSkipped() {
    std::cout << "Testing .debug_rnglists segment_selector_size skipping..." << std::endl;

    // DWARF32 rnglists contribution with address_size=4, segment_selector_size=2.
    // One list: start_end with segment selector bytes preceding each address.
    std::vector<uint8_t> debug_rnglists;
    appendU32(debug_rnglists, 0); // unit_length placeholder
    appendU16(debug_rnglists, 5);
    debug_rnglists.push_back(4); // address_size
    debug_rnglists.push_back(2); // seg selector size
    appendU32(debug_rnglists, 1); // offset_entry_count
    appendU32(debug_rnglists, 4); // offsets[0] = 4

    debug_rnglists.push_back(static_cast<uint8_t>(DW_RLE::DW_RLE_start_end));
    // segment selector (ignored)
    debug_rnglists.push_back(0xAA);
    debug_rnglists.push_back(0xBB);
    appendU32(debug_rnglists, 0x11223344);
    debug_rnglists.push_back(0xCC);
    debug_rnglists.push_back(0xDD);
    appendU32(debug_rnglists, 0x55667788);
    debug_rnglists.push_back(static_cast<uint8_t>(DW_RLE::DW_RLE_end_of_list));

    uint32_t unit_length = static_cast<uint32_t>(debug_rnglists.size() - 4);
    debug_rnglists[0] = static_cast<uint8_t>(unit_length & 0xff);
    debug_rnglists[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
    debug_rnglists[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
    debug_rnglists[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

    std::vector<uint8_t> debug_info = {0x00}; // index=0
    std::vector<uint8_t> empty;
    AttributeParser ap(debug_info, empty, /*debug_str=*/empty,
                       /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                       /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                       /*debug_rnglists=*/debug_rnglists, /*debug_loclists=*/empty,
                       /*debug_str_sup=*/empty);
    ap.setIsDwarf64(false);
    ap.setAddressSize(4);
    ap.setDwarfVersion(DwarfVersion::DWARF5);

    // Base points at contribution start; normalization should move it to offsets array start.
    ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0,
                    /*addr_base=*/0, /*str_offsets_base=*/0,
                    /*base_address=*/0);

    uint64_t off = 0;
    auto v = ap.parseAttribute(DwarfForm::DW_FORM_rnglistx, off);
    auto r = std::dynamic_pointer_cast<RangeAttributeValue>(v);
    assert(r);
    const auto& ranges = r->getRanges();
    assert(ranges.size() == 1);
    assert(ranges[0].start == 0x11223344);
    assert(ranges[0].end == 0x55667788);

    std::cout << ".debug_rnglists segment selector tests passed!" << std::endl;
}

void testRnglistsBaseAddressxDoesNotReadPastDebugAddrContribution() {
    std::cout << "Testing .debug_rnglists base_addressx respects .debug_addr contribution bounds..." << std::endl;

    // .debug_addr: two contributions back-to-back, each with 1 address entry.
    std::vector<uint8_t> debug_addr;
    size_t c1_start = debug_addr.size();
    appendU32(debug_addr, 0);
    appendU16(debug_addr, 5);
    debug_addr.push_back(8);
    debug_addr.push_back(0);
    appendU64(debug_addr, 0x1000);
    {
        uint32_t unit_length = static_cast<uint32_t>(debug_addr.size() - c1_start - 4);
        debug_addr[c1_start + 0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_addr[c1_start + 1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_addr[c1_start + 2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_addr[c1_start + 3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    size_t c2_start = debug_addr.size();
    appendU32(debug_addr, 0);
    appendU16(debug_addr, 5);
    debug_addr.push_back(8);
    debug_addr.push_back(0);
    appendU64(debug_addr, 0x9000);
    {
        uint32_t unit_length = static_cast<uint32_t>(debug_addr.size() - c2_start - 4);
        debug_addr[c2_start + 0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_addr[c2_start + 1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_addr[c2_start + 2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_addr[c2_start + 3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    // Contribution 1 table start is 8 bytes after start for DWARF32.
    uint64_t c1_table = static_cast<uint64_t>(c1_start + 8);

    // .debug_rnglists: one contribution with list that uses base_addressx index=1 (OOB for contrib1),
    // then offset_pair 0..16. If addrx bounds work, base becomes 0 and range is [0,16].
    std::vector<uint8_t> debug_rnglists;
    appendU32(debug_rnglists, 0);
    appendU16(debug_rnglists, 5);
    debug_rnglists.push_back(8);
    debug_rnglists.push_back(0);
    appendU32(debug_rnglists, 1);
    appendU32(debug_rnglists, 4);
    debug_rnglists.push_back(static_cast<uint8_t>(DW_RLE::DW_RLE_base_addressx));
    debug_rnglists.push_back(0x01); // index=1
    debug_rnglists.push_back(static_cast<uint8_t>(DW_RLE::DW_RLE_offset_pair));
    debug_rnglists.push_back(0x00); // start=0
    debug_rnglists.push_back(0x10); // end=16
    debug_rnglists.push_back(static_cast<uint8_t>(DW_RLE::DW_RLE_end_of_list));
    {
        uint32_t unit_length = static_cast<uint32_t>(debug_rnglists.size() - 4);
        debug_rnglists[0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_rnglists[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_rnglists[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_rnglists[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    // Parse via AttributeParser.
    std::vector<uint8_t> debug_info = {0x00}; // rnglistx index 0
    std::vector<uint8_t> empty;
    AttributeParser ap(debug_info, empty, /*debug_str=*/empty,
                       /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                       /*debug_str_offsets=*/empty, /*debug_addr=*/debug_addr, /*debug_line_str=*/empty,
                       /*debug_rnglists=*/debug_rnglists, /*debug_loclists=*/empty,
                       /*debug_str_sup=*/empty);
    ap.setIsDwarf64(false);
    ap.setAddressSize(8);
    ap.setDwarfVersion(DwarfVersion::DWARF5);
    ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0,
                    /*addr_base=*/c1_table, /*str_offsets_base=*/0,
                    /*base_address=*/0);

    uint64_t off = 0;
    auto v = ap.parseAttribute(DwarfForm::DW_FORM_rnglistx, off);
    auto r = std::dynamic_pointer_cast<RangeAttributeValue>(v);
    assert(r);
    const auto& ranges = r->getRanges();
    // The first entry is a base-address entry, the second is the actual range.
    assert(ranges.size() == 2);
    assert(ranges[0].is_base_address);
    assert(ranges[0].start == 0);
    assert(ranges[0].end == 0);
    assert(!ranges[1].is_base_address);
    assert(ranges[1].start == 0);
    assert(ranges[1].end == 16);

    std::cout << ".debug_rnglists base_addressx bounds tests passed!" << std::endl;
}

void testLoclistsParseDoesNotRunPastContributionEnd() {
    std::cout << "Testing .debug_loclists list parsing is bounded by contribution end..." << std::endl;

    // Contribution 1 has a malformed list (missing DW_LLE_end_of_list).
    // Contribution 2's first byte is crafted so an unbounded parser would treat it as DW_LLE_start_end (0x07),
    // producing a bogus extra location entry by reading into the next contribution.
    std::vector<uint8_t> debug_loclists;
    std::vector<uint8_t> empty;

    auto finalizeU32Length = [&](size_t contrib_start) {
        uint32_t unit_length = static_cast<uint32_t>(debug_loclists.size() - contrib_start - 4);
        debug_loclists[contrib_start + 0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_loclists[contrib_start + 1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_loclists[contrib_start + 2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_loclists[contrib_start + 3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    };

    // Contribution 1 (DWARF32), offset_entry_count=1, offsets[0]=4.
    size_t c1_start = debug_loclists.size();
    appendU32(debug_loclists, 0); // unit_length placeholder
    appendU16(debug_loclists, 5);
    debug_loclists.push_back(8);
    debug_loclists.push_back(0);
    appendU32(debug_loclists, 1);
    appendU32(debug_loclists, 4);
    // List 0 (malformed: no end_of_list)
    debug_loclists.push_back(static_cast<uint8_t>(DW_LLE::DW_LLE_start_end));
    appendU64(debug_loclists, 0x1000);
    appendU64(debug_loclists, 0x2000);
    debug_loclists.push_back(0x01); // expr_len=1
    debug_loclists.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0));
    finalizeU32Length(c1_start);

    uint64_t c1_offsets_base = static_cast<uint64_t>(c1_start + 12);

    // Contribution 2 (DWARF32), valid but padded so unit_length low byte == 0x07.
    size_t c2_start = debug_loclists.size();
    appendU32(debug_loclists, 0); // unit_length placeholder
    appendU16(debug_loclists, 5);
    debug_loclists.push_back(8);
    debug_loclists.push_back(0);
    appendU32(debug_loclists, 1);
    appendU32(debug_loclists, 4);
    debug_loclists.push_back(static_cast<uint8_t>(DW_LLE::DW_LLE_start_end));
    appendU64(debug_loclists, 0x3000);
    appendU64(debug_loclists, 0x4000);
    debug_loclists.push_back(0x01);
    debug_loclists.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0));
    debug_loclists.push_back(static_cast<uint8_t>(DW_LLE::DW_LLE_end_of_list));
    for (int i = 0; i < 256; ++i) {
        uint32_t ul = static_cast<uint32_t>(debug_loclists.size() - c2_start - 4);
        if ((ul & 0xffu) == static_cast<uint8_t>(DW_LLE::DW_LLE_start_end)) break;
        debug_loclists.push_back(0);
    }
    finalizeU32Length(c2_start);

    // Parse via AttributeParser so CU contribution end is computed and passed down to parseLocationList.
    std::vector<uint8_t> debug_info = {0x00}; // ULEB index=0
    AttributeParser ap(debug_info, empty, /*debug_str=*/empty,
                       /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                       /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                       /*debug_rnglists=*/empty, /*debug_loclists=*/debug_loclists,
                       /*debug_str_sup=*/empty);
    ap.setIsDwarf64(false);
    ap.setAddressSize(8);
    ap.setDwarfVersion(DwarfVersion::DWARF5);
    ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/c1_offsets_base,
                    /*addr_base=*/0, /*str_offsets_base=*/0,
                    /*base_address=*/0);

    uint64_t off = 0;
    auto v = ap.parseAttribute(DwarfForm::DW_FORM_loclistx, off);
    auto l = std::dynamic_pointer_cast<LocationAttributeValue>(v);
    assert(l);
    const auto& entries = l->getEntries();
    assert(entries.size() == 1);
    assert(entries[0].start == 0x1000);
    assert(entries[0].end == 0x2000);

    std::cout << ".debug_loclists bounded parse tests passed!" << std::endl;
}

void testLoclistsSegmentSelectorSizeIsSkipped() {
    std::cout << "Testing .debug_loclists segment_selector_size skipping..." << std::endl;

    // DWARF32 loclists contribution with address_size=4, segment_selector_size=2.
    // One list: start_end with expression.
    std::vector<uint8_t> debug_loclists;
    appendU32(debug_loclists, 0); // unit_length placeholder
    appendU16(debug_loclists, 5);
    debug_loclists.push_back(4); // address_size
    debug_loclists.push_back(2); // seg selector size
    appendU32(debug_loclists, 1); // offset_entry_count
    appendU32(debug_loclists, 4); // offsets[0] = 4

    debug_loclists.push_back(static_cast<uint8_t>(DW_LLE::DW_LLE_start_end));
    debug_loclists.push_back(0xAA);
    debug_loclists.push_back(0xBB);
    appendU32(debug_loclists, 0x01020304);
    debug_loclists.push_back(0xCC);
    debug_loclists.push_back(0xDD);
    appendU32(debug_loclists, 0x05060708);
    debug_loclists.push_back(0x01); // expr_len=1
    debug_loclists.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0));
    debug_loclists.push_back(static_cast<uint8_t>(DW_LLE::DW_LLE_end_of_list));

    uint32_t unit_length = static_cast<uint32_t>(debug_loclists.size() - 4);
    debug_loclists[0] = static_cast<uint8_t>(unit_length & 0xff);
    debug_loclists[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
    debug_loclists[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
    debug_loclists[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

    std::vector<uint8_t> debug_info = {0x00}; // index=0
    std::vector<uint8_t> empty;
    AttributeParser ap(debug_info, empty, /*debug_str=*/empty,
                       /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                       /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                       /*debug_rnglists=*/empty, /*debug_loclists=*/debug_loclists,
                       /*debug_str_sup=*/empty);
    ap.setIsDwarf64(false);
    ap.setAddressSize(4);
    ap.setDwarfVersion(DwarfVersion::DWARF5);

    ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0,
                    /*addr_base=*/0, /*str_offsets_base=*/0,
                    /*base_address=*/0);

    uint64_t off = 0;
    auto v = ap.parseAttribute(DwarfForm::DW_FORM_loclistx, off);
    auto l = std::dynamic_pointer_cast<LocationAttributeValue>(v);
    assert(l);
    const auto& entries = l->getEntries();
    assert(entries.size() == 1);
    assert(entries[0].start == 0x01020304);
    assert(entries[0].end == 0x05060708);
    assert(entries[0].expression.size() == 1);
    assert(entries[0].expression[0] == static_cast<uint8_t>(DwarfOp::DW_OP_reg0));

    std::cout << ".debug_loclists segment selector tests passed!" << std::endl;
}

void testLoclistsBaseAddressxDoesNotReadPastDebugAddrContribution() {
    std::cout << "Testing .debug_loclists base_addressx respects .debug_addr contribution bounds..." << std::endl;

    // .debug_addr: two contributions back-to-back, each with 1 address entry.
    std::vector<uint8_t> debug_addr;
    size_t c1_start = debug_addr.size();
    appendU32(debug_addr, 0);
    appendU16(debug_addr, 5);
    debug_addr.push_back(8);
    debug_addr.push_back(0);
    appendU64(debug_addr, 0x1000);
    {
        uint32_t unit_length = static_cast<uint32_t>(debug_addr.size() - c1_start - 4);
        debug_addr[c1_start + 0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_addr[c1_start + 1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_addr[c1_start + 2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_addr[c1_start + 3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    size_t c2_start = debug_addr.size();
    appendU32(debug_addr, 0);
    appendU16(debug_addr, 5);
    debug_addr.push_back(8);
    debug_addr.push_back(0);
    appendU64(debug_addr, 0x9000);
    {
        uint32_t unit_length = static_cast<uint32_t>(debug_addr.size() - c2_start - 4);
        debug_addr[c2_start + 0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_addr[c2_start + 1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_addr[c2_start + 2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_addr[c2_start + 3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    uint64_t c1_table = static_cast<uint64_t>(c1_start + 8);

    // .debug_loclists: base_addressx index=1 (OOB), then offset_pair 0..16 with 1-byte expression.
    std::vector<uint8_t> debug_loclists;
    appendU32(debug_loclists, 0);
    appendU16(debug_loclists, 5);
    debug_loclists.push_back(8);
    debug_loclists.push_back(0);
    appendU32(debug_loclists, 1);
    appendU32(debug_loclists, 4);
    debug_loclists.push_back(static_cast<uint8_t>(DW_LLE::DW_LLE_base_addressx));
    debug_loclists.push_back(0x01); // index=1
    debug_loclists.push_back(static_cast<uint8_t>(DW_LLE::DW_LLE_offset_pair));
    debug_loclists.push_back(0x00); // start=0
    debug_loclists.push_back(0x10); // end=16
    debug_loclists.push_back(0x01); // expr_len=1
    debug_loclists.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0));
    debug_loclists.push_back(static_cast<uint8_t>(DW_LLE::DW_LLE_end_of_list));
    {
        uint32_t unit_length = static_cast<uint32_t>(debug_loclists.size() - 4);
        debug_loclists[0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_loclists[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_loclists[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_loclists[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    std::vector<uint8_t> debug_info = {0x00}; // loclistx index 0
    std::vector<uint8_t> empty;
    AttributeParser ap(debug_info, empty, /*debug_str=*/empty,
                       /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                       /*debug_str_offsets=*/empty, /*debug_addr=*/debug_addr, /*debug_line_str=*/empty,
                       /*debug_rnglists=*/empty, /*debug_loclists=*/debug_loclists,
                       /*debug_str_sup=*/empty);
    ap.setIsDwarf64(false);
    ap.setAddressSize(8);
    ap.setDwarfVersion(DwarfVersion::DWARF5);
    ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0,
                    /*addr_base=*/c1_table, /*str_offsets_base=*/0,
                    /*base_address=*/0);

    uint64_t off = 0;
    auto v = ap.parseAttribute(DwarfForm::DW_FORM_loclistx, off);
    auto l = std::dynamic_pointer_cast<LocationAttributeValue>(v);
    assert(l);
    const auto& entries = l->getEntries();
    // The first entry is the base-address entry, the second is the actual range entry.
    assert(entries.size() == 2);
    assert(entries[0].start == 0);
    assert(entries[0].end == 0);
    assert(entries[1].start == 0);
    assert(entries[1].end == 16);

    std::cout << ".debug_loclists base_addressx bounds tests passed!" << std::endl;
}

void testRnglistxBasePointsToContributionHeader() {
    std::cout << "Testing DW_FORM_rnglistx with base pointing at .debug_rnglists header..." << std::endl;

    // Minimal .debug_rnglists contribution (DWARF32):
    // header + 1 offset entry + 1 list (start_end + end_of_list).
    std::vector<uint8_t> debug_rnglists;
    appendU32(debug_rnglists, 0); // unit_length placeholder
    appendU16(debug_rnglists, 5); // version
    debug_rnglists.push_back(8);  // address_size
    debug_rnglists.push_back(0);  // seg selector size
    appendU32(debug_rnglists, 1); // offset_entry_count

    // offsets[0] = 4 (list starts after this one 4-byte entry)
    appendU32(debug_rnglists, 4);

    // list0 at (offsets_base + 4)
    debug_rnglists.push_back(static_cast<uint8_t>(DW_RLE::DW_RLE_start_end));
    appendU64(debug_rnglists, 0x1000);
    appendU64(debug_rnglists, 0x2000);
    debug_rnglists.push_back(static_cast<uint8_t>(DW_RLE::DW_RLE_end_of_list));

    uint32_t unit_length = static_cast<uint32_t>(debug_rnglists.size() - 4);
    debug_rnglists[0] = static_cast<uint8_t>(unit_length & 0xff);
    debug_rnglists[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
    debug_rnglists[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
    debug_rnglists[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

    // debug_info contains ULEB index=0
    std::vector<uint8_t> debug_info = {0x00};
    std::vector<uint8_t> empty;

    AttributeParser ap(debug_info, empty, /*debug_str=*/empty,
                       /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                       /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                       /*debug_rnglists=*/debug_rnglists, /*debug_loclists=*/empty,
                       /*debug_str_sup=*/empty);
    ap.setIsDwarf64(false);
    ap.setAddressSize(8);
    ap.setDwarfVersion(DwarfVersion::DWARF5);

    // Base points to contribution start (header).
    ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0,
                    /*addr_base=*/0, /*str_offsets_base=*/0,
                    /*base_address=*/0);

    uint64_t off = 0;
    auto v = ap.parseAttribute(DwarfForm::DW_FORM_rnglistx, off);
    auto r = std::dynamic_pointer_cast<RangeAttributeValue>(v);
    assert(r);
    const auto& ranges = r->getRanges();
    assert(ranges.size() == 1);
    assert(ranges[0].start == 0x1000);
    assert(ranges[0].end == 0x2000);

    std::cout << "DW_FORM_rnglistx header-base normalization tests passed!" << std::endl;
}

void testLoclistxBasePointsToContributionHeader() {
    std::cout << "Testing DW_FORM_loclistx with base pointing at .debug_loclists header..." << std::endl;

    // Minimal .debug_loclists contribution (DWARF32):
    // header + 1 offset entry + 1 list (start_end + expr + end_of_list).
    std::vector<uint8_t> debug_loclists;
    appendU32(debug_loclists, 0); // unit_length placeholder
    appendU16(debug_loclists, 5); // version
    debug_loclists.push_back(8);  // address_size
    debug_loclists.push_back(0);  // seg selector size
    appendU32(debug_loclists, 1); // offset_entry_count

    // offsets[0] = 4 (list starts after this one 4-byte entry)
    appendU32(debug_loclists, 4);

    // list0 at (offsets_base + 4)
    debug_loclists.push_back(static_cast<uint8_t>(DW_LLE::DW_LLE_start_end));
    appendU64(debug_loclists, 0x3000);
    appendU64(debug_loclists, 0x3010);
    debug_loclists.push_back(1); // expr len (ULEB128)
    debug_loclists.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg0));
    debug_loclists.push_back(static_cast<uint8_t>(DW_LLE::DW_LLE_end_of_list));

    uint32_t unit_length = static_cast<uint32_t>(debug_loclists.size() - 4);
    debug_loclists[0] = static_cast<uint8_t>(unit_length & 0xff);
    debug_loclists[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
    debug_loclists[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
    debug_loclists[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

    // debug_info contains ULEB index=0
    std::vector<uint8_t> debug_info = {0x00};
    std::vector<uint8_t> empty;

    AttributeParser ap(debug_info, empty, /*debug_str=*/empty,
                       /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                       /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                       /*debug_rnglists=*/empty, /*debug_loclists=*/debug_loclists,
                       /*debug_str_sup=*/empty);
    ap.setIsDwarf64(false);
    ap.setAddressSize(8);
    ap.setDwarfVersion(DwarfVersion::DWARF5);

    // Base points to contribution start (header).
    ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0,
                    /*addr_base=*/0, /*str_offsets_base=*/0,
                    /*base_address=*/0);

    uint64_t off = 0;
    auto v = ap.parseAttribute(DwarfForm::DW_FORM_loclistx, off);
    auto loc = std::dynamic_pointer_cast<LocationAttributeValue>(v);
    assert(loc);
    assert(loc->getLocationType() == LocationAttributeValue::LocationType::LIST);
    const auto& entries = loc->getEntries();
    assert(entries.size() == 1);
    assert(entries[0].start == 0x3000);
    assert(entries[0].end == 0x3010);
    assert(entries[0].expression.size() == 1);
    assert(entries[0].expression[0] == static_cast<uint8_t>(DwarfOp::DW_OP_reg0));

    std::cout << "DW_FORM_loclistx header-base normalization tests passed!" << std::endl;
}

void testVariableLocationEvaluatorLoclistAddressSize() {
    std::cout << "Testing VariableLocationEvaluator loclist address_size handling..." << std::endl;

    // Location expression: const4u 0x1234 (interpreted as address).
    std::vector<uint8_t> expr = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        0x34, 0x12, 0x00, 0x00
    };

    auto makeLoclist = [&](uint8_t addr_size, uint64_t start, uint64_t end) -> std::vector<uint8_t> {
        std::vector<uint8_t> out;
        auto appendAddr = [&](uint64_t v) {
            if (addr_size == 4) {
                appendU32(out, static_cast<uint32_t>(v));
            } else {
                appendU64(out, v);
            }
        };
        appendAddr(start);
        appendAddr(end);
        appendU16(out, static_cast<uint16_t>(expr.size()));
        out.insert(out.end(), expr.begin(), expr.end());
        appendAddr(0);
        appendAddr(0);
        return out;
    };

    for (uint8_t addr_size : {static_cast<uint8_t>(4), static_cast<uint8_t>(8)}) {
        VariableLocationEvaluator eval;
        EvaluationContext ctx;
        ctx.address_size = addr_size;
        ctx.entry_registers = std::vector<uint64_t>(64, 0);
        eval.setContext(ctx);

        auto loclist = makeLoclist(addr_size, /*start=*/0x1000, /*end=*/0x2000);
        auto loc = eval.evaluateLocation(loclist, /*pc=*/0x1004, /*is_loclist=*/true);
        assert(loc.type == VariableLocationType::MEMORY);
        assert(loc.address == 0x1234);
    }

    std::cout << "VariableLocationEvaluator loclist tests passed!" << std::endl;
}

void testCFIParserAArch64MinimalUnwind() {
    std::cout << "Testing CFIParser minimal AArch64-style unwind..." << std::endl;

    // Build a minimal .debug_frame section containing:
    // - One CIE (id=0xffffffff) with:
    //   version=4, addr_size=8, code_align=1, data_align=-8, ra_reg=30
    //   initial instructions:
    //     DW_CFA_def_cfa (reg=31, offset=16)  => CFA = SP + 16
    //     DW_CFA_offset  (reg=30, uleb=1)     => X30 saved at CFA - 8
    // - One FDE referencing the CIE, covering [0x1000, 0x1100)
    std::vector<uint8_t> debug_frame;

    auto appendU8 = [&](uint8_t v) { debug_frame.push_back(v); };
    auto appendU32LE = [&](uint32_t v) { appendU32(debug_frame, v); };
    auto appendU64LE = [&](uint64_t v) { appendU64(debug_frame, v); };

    // CIE
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);              // length placeholder
        appendU32LE(0xffffffffU);    // CIE id for .debug_frame
        appendU8(4);                 // version
        appendU8(0);                 // augmentation string ""
        appendU8(8);                 // address_size
        appendU8(0);                 // segment_selector_size
        appendU8(0x01);              // code_alignment_factor = 1 (ULEB128)
        appendU8(0x78);              // data_alignment_factor = -8 (SLEB128)
        appendU8(0x1e);              // return_address_register = 30 (ULEB128)

        // initial instructions
        appendU8(0x0c);              // DW_CFA_def_cfa
        appendU8(0x1f);              // reg = 31 (SP)
        appendU8(0x10);              // offset = 16
        appendU8(static_cast<uint8_t>(0x80 | 30)); // DW_CFA_offset + reg(30)
        // ULEB128 = 129 (0x81 0x01) to exercise multi-byte ULEB parsing:
        // offset = 129 * data_alignment_factor(-8) = -1032
        appendU8(0x81);
        appendU8(0x01);

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    // FDE
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);           // length placeholder
        appendU32LE(0);           // CIE pointer (absolute offset to CIE at 0)
        appendU64LE(0x1000);      // initial_location
        appendU64LE(0x100);       // address_range
        // no instructions

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    CFIParser cfi(debug_frame, /*is_eh_frame=*/false, /*address_size=*/8);
    assert(cfi.parse());

    UnwindInfo ui = cfi.getUnwindInfo(0x1004);
    assert(ui.valid);
    assert(ui.return_address_register == 30);
    assert(ui.cfa.type == CFA_Type::REGISTER_OFFSET);
    assert(ui.cfa.reg_num == 31);
    assert(ui.cfa.offset == 16);
    {
        auto it = ui.registers.find(30);
        assert(it != ui.registers.end());
        assert(it->second.type == CFA_RegRule::OFFSET);
        assert(it->second.offset == -1032);
    }

    std::vector<uint64_t> regs(256, 0);
    regs[31] = 0x2000; // SP

    uint64_t cfa = ui.computeCFA(regs);
    assert(cfa == 0x2010);

    // Saved LR at CFA-1032 = 0x2010 - 0x408 = 0x1c08
    auto read_mem = [&](uint64_t addr) -> uint64_t {
        if (addr == 0x1c08) return 0x123456789abcdef0ULL;
        return 0;
    };

    auto ra = ui.getRegisterValue(30, regs, cfa, read_mem);
    assert(ra.has_value());
    assert(*ra == 0x123456789abcdef0ULL);

    std::cout << "CFIParser minimal unwind tests passed!" << std::endl;
}

void testCFIParserAArch64NegateRAStateStripsPAC() {
    std::cout << "Testing CFIParser AArch64 negate_ra_state PAC stripping..." << std::endl;

    // Minimal .debug_frame:
    // - CIE: def_cfa SP+16, offset LR at CFA-8, and DW_CFA_AARCH64_negate_ra_state
    // - FDE: [0x1000,0x1100)
    // Then verify UnwindInfo strips PAC bits from LR using pauth_cmask (reg 36).
    std::vector<uint8_t> debug_frame;
    auto appendU8 = [&](uint8_t v) { debug_frame.push_back(v); };
    auto appendU32LE = [&](uint32_t v) { appendU32(debug_frame, v); };
    auto appendU64LE = [&](uint64_t v) { appendU64(debug_frame, v); };

    // CIE
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);              // length placeholder
        appendU32LE(0xffffffffU);    // CIE id for .debug_frame
        appendU8(4);                 // version
        appendU8(0);                 // augmentation string ""
        appendU8(8);                 // address_size
        appendU8(0);                 // segment_selector_size
        appendU8(0x01);              // code_alignment_factor = 1 (ULEB128)
        appendU8(0x78);              // data_alignment_factor = -8 (SLEB128)
        appendU8(0x1e);              // return_address_register = 30 (ULEB128)

        appendU8(0x2d);              // DW_CFA_AARCH64_negate_ra_state (toggle => signed)
        appendU8(0x0c);              // DW_CFA_def_cfa
        appendU8(0x1f);              // reg = 31 (SP)
        appendU8(0x10);              // offset = 16
        appendU8(static_cast<uint8_t>(0x80 | 30)); // DW_CFA_offset + reg(30)
        appendU8(0x01);              // ULEB128=1 => CFA-8

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    // FDE
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);           // length placeholder
        appendU32LE(0);           // CIE pointer (absolute offset to CIE at 0)
        appendU64LE(0x1000);      // initial_location
        appendU64LE(0x100);       // address_range
        // no instructions

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    CFIParser cfi(debug_frame, /*is_eh_frame=*/false, /*address_size=*/8);
    assert(cfi.parse());

    UnwindInfo ui = cfi.getUnwindInfo(0x1004);
    assert(ui.valid);
    assert(ui.aarch64_ra_sign_state == 1);

    std::vector<uint64_t> regs(256, 0);
    regs[31] = 0x2000; // SP
    regs[36] = 0xff00000000000000ULL; // pauth_cmask: clear top byte

    uint64_t cfa = ui.computeCFA(regs);
    assert(cfa == 0x2010);

    auto read_mem = [&](uint64_t addr) -> uint64_t {
        if (addr == 0x2008) return 0xab00000000004000ULL; // signed LR with tag/PAC in top byte
        return 0;
    };

    auto ra = ui.getRegisterValue(30, regs, cfa, read_mem);
    assert(ra.has_value());
    assert(*ra == 0x0000000000004000ULL);

    std::cout << "CFIParser AArch64 negate_ra_state tests passed!" << std::endl;
}

void testCFIParserTruncatedInstructionDoesNotCrash() {
    std::cout << "Testing CFIParser truncated instruction robustness..." << std::endl;

    // CIE with a truncated DW_CFA_def_cfa (missing second ULEB128 operand).
    std::vector<uint8_t> debug_frame;

    auto appendU8 = [&](uint8_t v) { debug_frame.push_back(v); };
    auto appendU32LE = [&](uint32_t v) { appendU32(debug_frame, v); };

    // CIE
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);              // length placeholder
        appendU32LE(0xffffffffU);    // CIE id for .debug_frame
        appendU8(4);                 // version
        appendU8(0);                 // augmentation string ""
        appendU8(8);                 // address_size
        appendU8(0);                 // segment_selector_size
        appendU8(0x01);              // code_alignment_factor = 1
        appendU8(0x78);              // data_alignment_factor = -8
        appendU8(0x1e);              // return_address_register = 30

        // initial instructions: DW_CFA_def_cfa, reg=31, but missing offset ULEB.
        appendU8(0x0c);              // DW_CFA_def_cfa
        appendU8(0x1f);              // reg=31 (ULEB)
        // no offset bytes

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    CFIParser cfi(debug_frame, /*is_eh_frame=*/false, /*address_size=*/8);
    // Should not crash / read out of bounds. Parse should still succeed because we have a CIE.
    assert(cfi.parse());
    assert(!cfi.getCIEs().empty());
    // Truncated def_cfa must not partially apply. Initial row stays at default CFA.
    const auto& cie0 = cfi.getCIEs().front();
    assert(cie0->initial_row.cfa.type == CFA_Type::REGISTER_OFFSET);
    assert(cie0->initial_row.cfa.reg_num == 0);
    assert(cie0->initial_row.cfa.offset == 0);

    std::cout << "CFIParser truncated instruction tests passed!" << std::endl;
}

void testCFIParserRejectsMalformedCIEHeader() {
    std::cout << "Testing CFIParser rejects malformed CIE header..." << std::endl;

    // CIE with unterminated augmentation string ("z" without trailing NUL).
    std::vector<uint8_t> debug_frame;
    auto appendU8 = [&](uint8_t v) { debug_frame.push_back(v); };
    auto appendU32LE = [&](uint32_t v) { appendU32(debug_frame, v); };

    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);
        appendU32LE(0xffffffffU); // CIE id for .debug_frame
        appendU8(4);              // version
        appendU8('z');            // malformed: no NUL terminator for augmentation string

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    CFIParser cfi(debug_frame, /*is_eh_frame=*/false, /*address_size=*/8);
    assert(!cfi.parse());
    assert(cfi.getCIEs().empty());

    std::cout << "CFIParser malformed CIE header tests passed!" << std::endl;
}

void testCFIParserTruncatedFDEOperandDoesNotMutateRow() {
    std::cout << "Testing CFIParser truncated FDE operand does not mutate row..." << std::endl;

    // CIE: CFA = SP + 16.
    // FDE: truncated DW_CFA_def_cfa_offset operand (ULEB continuation without terminator).
    // Expected: malformed FDE instruction stream aborts, row at PC start remains CFA offset 16.
    std::vector<uint8_t> debug_frame;
    auto appendU8 = [&](uint8_t v) { debug_frame.push_back(v); };
    auto appendU32LE = [&](uint32_t v) { appendU32(debug_frame, v); };
    auto appendU64LE = [&](uint64_t v) { appendU64(debug_frame, v); };

    // CIE
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);
        appendU32LE(0xffffffffU);
        appendU8(4);    // version
        appendU8(0);    // augmentation
        appendU8(8);    // address_size
        appendU8(0);    // segment_selector_size
        appendU8(0x01); // code_align=1
        appendU8(0x78); // data_align=-8
        appendU8(0x1e); // ra_reg=30
        appendU8(0x0c); // DW_CFA_def_cfa
        appendU8(0x1f); // reg=31 (SP)
        appendU8(0x10); // off=16

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    // FDE
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);
        appendU32LE(0);      // CIE pointer to offset 0
        appendU64LE(0x1000); // initial_location
        appendU64LE(0x20);   // address_range
        appendU8(0x0e);      // DW_CFA_def_cfa_offset
        appendU8(0x80);      // truncated ULEB128

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    CFIParser cfi(debug_frame, /*is_eh_frame=*/false, /*address_size=*/8);
    assert(cfi.parse());

    UnwindInfo ui = cfi.getUnwindInfo(0x1000);
    assert(ui.valid);
    assert(ui.cfa.type == CFA_Type::REGISTER_OFFSET);
    assert(ui.cfa.reg_num == 31);
    assert(ui.cfa.offset == 16);

    std::cout << "CFIParser truncated FDE operand tests passed!" << std::endl;
}

void testCFIParserRejectsMalformedFDEAugmentationLength() {
    std::cout << "Testing CFIParser rejects malformed FDE augmentation length..." << std::endl;

    // .debug_frame with:
    // - CIE augmentation "z" and empty augmentation payload (aug_len=0)
    // - FDE with truncated ULEB128 augmentation length (0x80)
    std::vector<uint8_t> debug_frame;
    auto appendU8 = [&](uint8_t v) { debug_frame.push_back(v); };
    auto appendU32LE = [&](uint32_t v) { appendU32(debug_frame, v); };
    auto appendU64LE = [&](uint64_t v) { appendU64(debug_frame, v); };

    // CIE
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);
        appendU32LE(0xffffffffU);
        appendU8(4);    // version
        appendU8('z');  // augmentation "z"
        appendU8(0);    // NUL terminator
        appendU8(8);    // address_size
        appendU8(0);    // segment_selector_size
        appendU8(0x01); // code_align=1
        appendU8(0x78); // data_align=-8
        appendU8(0x1e); // ra_reg=30
        appendU8(0x00); // aug_len=0
        appendU8(0x0c); // DW_CFA_def_cfa
        appendU8(0x1f); // SP
        appendU8(0x10); // 16

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    // FDE with malformed augmentation length.
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);
        appendU32LE(0);      // CIE pointer to offset 0
        appendU64LE(0x1000); // initial_location
        appendU64LE(0x20);   // address_range
        appendU8(0x80);      // malformed/truncated aug_length ULEB

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    CFIParser cfi(debug_frame, /*is_eh_frame=*/false, /*address_size=*/8);
    assert(cfi.parse());
    assert(cfi.getCIEs().size() == 1);
    assert(cfi.getFDEs().empty()); // malformed FDE must be rejected

    std::cout << "CFIParser malformed FDE augmentation tests passed!" << std::endl;
}

void testCFIParserMIPSAdvanceLoc8DoesNotAbort() {
    std::cout << "Testing CFIParser DW_CFA_MIPS_advance_loc8 support..." << std::endl;

    // CIE: CFA = SP + 16
    // FDE: advance_loc8 1; def_cfa_offset 24; (so for PC=initial, CFA offset is 16; for PC=initial+1, 24)
    std::vector<uint8_t> debug_frame;
    auto appendU8 = [&](uint8_t v) { debug_frame.push_back(v); };
    auto appendU32LE = [&](uint32_t v) { appendU32(debug_frame, v); };
    auto appendU64LE = [&](uint64_t v) { appendU64(debug_frame, v); };

    // CIE
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);
        appendU32LE(0xffffffffU);
        appendU8(4);
        appendU8(0);
        appendU8(8);
        appendU8(0);
        appendU8(0x01); // code_align=1
        appendU8(0x78); // data_align=-8
        appendU8(0x1e); // ra_reg=30

        appendU8(0x0c); // def_cfa
        appendU8(0x1f); // SP
        appendU8(0x10); // 16

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    // FDE
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);
        appendU32LE(0);
        appendU64LE(0x1000);
        appendU64LE(0x100);

        appendU8(0x1d); // DW_CFA_MIPS_advance_loc8
        appendU64LE(1); // delta=1
        appendU8(0x0e); // def_cfa_offset
        appendU8(24);   // uleb=24

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    CFIParser cfi(debug_frame, /*is_eh_frame=*/false, /*address_size=*/8);
    assert(cfi.parse());

    {
        UnwindInfo ui = cfi.getUnwindInfo(0x1000);
        assert(ui.valid);
        assert(ui.cfa.type == CFA_Type::REGISTER_OFFSET);
        assert(ui.cfa.offset == 16);
    }
    {
        UnwindInfo ui = cfi.getUnwindInfo(0x1001);
        assert(ui.valid);
        assert(ui.cfa.type == CFA_Type::REGISTER_OFFSET);
        assert(ui.cfa.offset == 24);
    }

    std::cout << "CFIParser advance_loc8 tests passed!" << std::endl;
}

void testCFIParserDwarf2EscapeIsSkipped() {
    std::cout << "Testing CFIParser DWARF2 DW_CFA_escape skipping..." << std::endl;

    // CIE version=2:
    // initial instructions:
    //   escape(len=2, bytes=[0x0c,0x1f])  (these look like the start of def_cfa, but must be skipped)
    //   def_cfa(reg=31, off=16)
    // FDE: [0x1000,0x1100)
    std::vector<uint8_t> debug_frame;
    auto appendU8 = [&](uint8_t v) { debug_frame.push_back(v); };
    auto appendU32LE = [&](uint32_t v) { appendU32(debug_frame, v); };
    auto appendU64LE = [&](uint64_t v) { appendU64(debug_frame, v); };

    // CIE
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);
        appendU32LE(0xffffffffU);
        appendU8(2);  // version=2
        appendU8(0);  // augmentation string ""
        appendU8(0x01); // code_align=1 (ULEB128)
        appendU8(0x78); // data_align=-8 (SLEB128)
        appendU8(0x1e); // ra_reg=30 (ULEB128)

        appendU8(0x0f); // DW_CFA_escape (DWARF2)
        appendU8(2);    // length=2
        appendU8(0x0c); // bytes to skip (would be DW_CFA_def_cfa if misparsed)
        appendU8(0x1f); // bytes to skip

        appendU8(0x0c); // DW_CFA_def_cfa
        appendU8(0x1f); // SP
        appendU8(0x10); // 16

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    // FDE
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);
        appendU32LE(0);
        appendU64LE(0x1000);
        appendU64LE(0x100);

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    CFIParser cfi(debug_frame, /*is_eh_frame=*/false, /*address_size=*/8);
    assert(cfi.parse());

    UnwindInfo ui = cfi.getUnwindInfo(0x1004);
    assert(ui.valid);
    assert(ui.cfa.type == CFA_Type::REGISTER_OFFSET);
    assert(ui.cfa.reg_num == 31);
    assert(ui.cfa.offset == 16);

    std::cout << "CFIParser DWARF2 escape tests passed!" << std::endl;
}

void testCFIParserCFAExpressionThenDefCFARegisterOffsetSwitchesBack() {
    std::cout << "Testing CFIParser CFA switches from expression back to reg+off..." << std::endl;

    // CIE: initial CFA is an expression (def_cfa_expression).
    // FDE: overrides CFA with def_cfa_register + def_cfa_offset.
    // Correct behavior: UnwindInfo.cfa.type must be REGISTER_OFFSET (not left as EXPRESSION).
    std::vector<uint8_t> debug_frame;
    auto appendU8 = [&](uint8_t v) { debug_frame.push_back(v); };
    auto appendU32LE = [&](uint32_t v) { appendU32(debug_frame, v); };
    auto appendU64LE = [&](uint64_t v) { appendU64(debug_frame, v); };

    // CIE
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);
        appendU32LE(0xffffffffU);
        appendU8(4);  // version
        appendU8(0);  // augmentation ""
        appendU8(8);  // address_size
        appendU8(0);  // segment_selector_size
        appendU8(0x01); // code_align=1
        appendU8(0x78); // data_align=-8
        appendU8(0x1e); // ra_reg=30

        // def_cfa_expression with a trivial expression (lit0). We won't evaluate it; we just
        // want CFA type to become EXPRESSION initially.
        appendU8(0x0f); // DW_CFA_def_cfa_expression
        appendU8(0x01); // expr length = 1 (ULEB128)
        appendU8(0x30); // DW_OP_lit0

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    // FDE
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);
        appendU32LE(0); // CIE pointer
        appendU64LE(0x1000);
        appendU64LE(0x100);

        appendU8(0x0d); // DW_CFA_def_cfa_register
        appendU8(0x1f); // reg=31
        appendU8(0x0e); // DW_CFA_def_cfa_offset
        appendU8(0x10); // off=16

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    CFIParser cfi(debug_frame, /*is_eh_frame=*/false, /*address_size=*/8);
    assert(cfi.parse());
    UnwindInfo ui = cfi.getUnwindInfo(0x1004);
    assert(ui.valid);
    assert(ui.cfa.type == CFA_Type::REGISTER_OFFSET);
    assert(ui.cfa.reg_num == 31);
    assert(ui.cfa.offset == 16);

    std::cout << "CFIParser CFA reg+off switch tests passed!" << std::endl;
}

void testCFIParserUnknownOpcodeAbortsInstructionStream() {
    std::cout << "Testing CFIParser unknown opcode aborts instruction stream..." << std::endl;

    // Build a .debug_frame CIE whose initial instruction stream begins with an unknown opcode.
    // The following bytes are shaped like a valid DW_CFA_def_cfa sequence, which would be
    // (incorrectly) interpreted if the parser continued after the unknown opcode without knowing
    // operand lengths.
    //
    // With correct behavior, the unknown opcode aborts processing of the instruction stream, so
    // the CFA remains at its default (reg=0, off=0).
    std::vector<uint8_t> debug_frame;
    auto appendU8 = [&](uint8_t v) { debug_frame.push_back(v); };
    auto appendU32LE = [&](uint32_t v) { appendU32(debug_frame, v); };
    auto appendU64LE = [&](uint64_t v) { appendU64(debug_frame, v); };

    // CIE
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);              // length placeholder
        appendU32LE(0xffffffffU);    // CIE id for .debug_frame
        appendU8(4);                 // version
        appendU8(0);                 // augmentation string ""
        appendU8(8);                 // address_size
        appendU8(0);                 // segment_selector_size
        appendU8(0x01);              // code_alignment_factor = 1 (ULEB128)
        appendU8(0x78);              // data_alignment_factor = -8 (SLEB128)
        appendU8(0x1e);              // return_address_register = 30 (ULEB128)

        // initial instructions: unknown opcode + bytes that look like DW_CFA_def_cfa(reg=31,off=16)
        appendU8(0x17);              // unknown/unhandled opcode
        appendU8(0x0c);              // DW_CFA_def_cfa (would be misparsed if we continued)
        appendU8(0x1f);              // reg = 31 (SP)
        appendU8(0x10);              // offset = 16

        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    // FDE covering [0x1000, 0x1100)
    {
        size_t len_pos = debug_frame.size();
        appendU32LE(0);
        appendU32LE(0);        // CIE pointer
        appendU64LE(0x1000);
        appendU64LE(0x100);
        uint32_t len = static_cast<uint32_t>(debug_frame.size() - (len_pos + 4));
        debug_frame[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    CFIParser cfi(debug_frame, /*is_eh_frame=*/false, /*address_size=*/8);
    assert(cfi.parse());

    UnwindInfo ui = cfi.getUnwindInfo(0x1004);
    assert(ui.valid);
    // Default CFA (not overwritten by mis-parsed bytes)
    assert(ui.cfa.type == CFA_Type::REGISTER_OFFSET);
    assert(ui.cfa.reg_num == 0);
    assert(ui.cfa.offset == 0);

    std::cout << "CFIParser unknown opcode abort tests passed!" << std::endl;
}

void testUnwindInfoValExpressionMemoryEndianness() {
    std::cout << "Testing UnwindInfo VAL_EXPRESSION memory endianness..." << std::endl;

    bool prev = DwarfUtils::objectIsLittleEndian();
    DwarfUtils::setObjectLittleEndian(false);

    UnwindInfo ui;
    ui.address_size = 4;

    // Expression: addr(0x1000), deref_size(4), stack_value.
    // On big-endian objects, a word read returning 0x12345678 must decode to 0x12345678.
    std::vector<uint8_t> expr = {
        static_cast<uint8_t>(DwarfOp::DW_OP_addr),
        0x00, 0x00, 0x10, 0x00, // 0x1000 big-endian
        static_cast<uint8_t>(DwarfOp::DW_OP_deref_size),
        0x04,
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
    };

    RegisterRule r;
    r.type = CFA_RegRule::VAL_EXPRESSION;
    r.expression = expr;
    ui.registers[0] = r;

    std::vector<uint64_t> regs;
    auto read_mem = [&](uint64_t addr) -> uint64_t {
        if (addr == 0x1000) return 0x12345678ULL;
        return 0;
    };

    auto v = ui.getRegisterValue(0, regs, /*cfa=*/0, read_mem);
    assert(v.has_value());
    assert(*v == 0x12345678ULL);

    DwarfUtils::setObjectLittleEndian(prev);

    std::cout << "UnwindInfo VAL_EXPRESSION memory endianness tests passed!" << std::endl;
}

void testSymbolicCFIVerifier() {
    std::cout << "Testing SymbolicCFIVerifier..." << std::endl;

    auto makeDebugFrame = [](bool use_offset_extended, uint64_t lr_off_uleb) {
        std::vector<uint8_t> sec;
        auto appendU8 = [&](uint8_t v) { sec.push_back(v); };

        // CIE: version=4, addr_size=8, code_align=1, data_align=-8, ra_reg=30
        {
            size_t len_pos = sec.size();
            appendU32(sec, 0);
            appendU32(sec, 0xffffffffU); // CIE id (.debug_frame)
            appendU8(4);                 // version
            appendU8(0);                 // augmentation ""
            appendU8(8);                 // address_size
            appendU8(0);                 // segment_selector_size
            appendU8(0x01);              // code_alignment_factor = 1
            appendU8(0x78);              // data_alignment_factor = -8 (SLEB)
            appendU8(0x1e);              // return_address_register = 30

            // DW_CFA_def_cfa reg31,16
            appendU8(0x0c);
            appendULEB(sec, 31);
            appendULEB(sec, 16);

            uint32_t len = static_cast<uint32_t>(sec.size() - (len_pos + 4));
            sec[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
            sec[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
            sec[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
            sec[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
        }

        // FDE: [0x1000, 0x1100)
        {
            size_t len_pos = sec.size();
            appendU32(sec, 0);
            appendU32(sec, 0);      // CIE pointer to offset 0
            appendU64(sec, 0x1000);
            appendU64(sec, 0x100);

            if (use_offset_extended) {
                appendU8(0x05);      // DW_CFA_offset_extended
                appendULEB(sec, 30); // reg
                appendULEB(sec, lr_off_uleb);
            } else {
                appendU8(static_cast<uint8_t>(0x80 | 30)); // DW_CFA_offset + reg
                appendULEB(sec, lr_off_uleb);
            }

            uint32_t len = static_cast<uint32_t>(sec.size() - (len_pos + 4));
            sec[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
            sec[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
            sec[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
            sec[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
        }

        return sec;
    };

    // Equivalent encodings: DW_CFA_offset vs DW_CFA_offset_extended (same reg+offset rule).
    {
        auto lhs_sec = makeDebugFrame(false, 1);
        auto rhs_sec = makeDebugFrame(true, 1);
        CFIParser lhs(lhs_sec, /*is_eh_frame=*/false, /*address_size=*/8);
        CFIParser rhs(rhs_sec, /*is_eh_frame=*/false, /*address_size=*/8);
        assert(lhs.parse());
        assert(rhs.parse());
        SymbolicCFIVerifier v;
        auto r = v.compareFDEByIndex(lhs, 0, rhs, 0);
        assert(r.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT);
    }

    // Different rule payload: same opcode form, different offset encoding value.
    {
        auto lhs_sec = makeDebugFrame(false, 1); // CFA-8
        auto rhs_sec = makeDebugFrame(true, 2);  // CFA-16
        CFIParser lhs(lhs_sec, /*is_eh_frame=*/false, /*address_size=*/8);
        CFIParser rhs(rhs_sec, /*is_eh_frame=*/false, /*address_size=*/8);
        assert(lhs.parse());
        assert(rhs.parse());
        SymbolicCFIVerifier v;
        auto r = v.compareFDEByIndex(lhs, 0, rhs, 0);
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.has_mismatch_relative_pc);
    }

    // CFA expression equivalence/difference via DW_CFA_def_cfa_expression in CIE.
    {
        auto makeDebugFrameWithCFAExpr = [](int8_t sleb_off) {
            std::vector<uint8_t> sec;
            auto appendU8 = [&](uint8_t v) { sec.push_back(v); };

            // CIE
            {
                size_t len_pos = sec.size();
                appendU32(sec, 0);
                appendU32(sec, 0xffffffffU); // CIE id (.debug_frame)
                appendU8(4);                 // version
                appendU8(0);                 // augmentation ""
                appendU8(8);                 // address_size
                appendU8(0);                 // segment_selector_size
                appendU8(0x01);              // code_alignment_factor = 1
                appendU8(0x78);              // data_alignment_factor = -8 (SLEB)
                appendU8(0x1e);              // return_address_register = 30

                // DW_CFA_def_cfa_expression: block(DW_OP_breg31, sleb_off)
                appendU8(0x0f);
                appendULEB(sec, 2);
                appendU8(static_cast<uint8_t>(DwarfOp::DW_OP_breg31));
                appendU8(static_cast<uint8_t>(sleb_off)); // small SLEB immediate

                uint32_t len = static_cast<uint32_t>(sec.size() - (len_pos + 4));
                sec[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
                sec[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
                sec[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
                sec[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
            }

            // FDE
            {
                size_t len_pos = sec.size();
                appendU32(sec, 0);
                appendU32(sec, 0);
                appendU64(sec, 0x2000);
                appendU64(sec, 0x40);
                uint32_t len = static_cast<uint32_t>(sec.size() - (len_pos + 4));
                sec[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
                sec[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
                sec[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
                sec[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
            }
            return sec;
        };

        auto a = makeDebugFrameWithCFAExpr(/*+16=*/0x10);
        auto b = makeDebugFrameWithCFAExpr(/*+16=*/0x10);
        auto c = makeDebugFrameWithCFAExpr(/*+24=*/0x18);

        CFIParser pa(a, /*is_eh_frame=*/false, /*address_size=*/8);
        CFIParser pb(b, /*is_eh_frame=*/false, /*address_size=*/8);
        CFIParser pc(c, /*is_eh_frame=*/false, /*address_size=*/8);
        assert(pa.parse());
        assert(pb.parse());
        assert(pc.parse());

        SymbolicCFIVerifier v;
        auto eq = v.compareFDEByIndex(pa, 0, pb, 0);
        assert(eq.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT);

        auto diff = v.compareFDEByIndex(pa, 0, pc, 0);
        assert(diff.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
    }

    // Register val_expression equivalence/difference via DW_CFA_val_expression in FDE.
    {
        auto makeDebugFrameWithValExpr = [](uint8_t imm) {
            std::vector<uint8_t> sec;
            auto appendU8 = [&](uint8_t v) { sec.push_back(v); };

            // CIE: simple register CFA.
            {
                size_t len_pos = sec.size();
                appendU32(sec, 0);
                appendU32(sec, 0xffffffffU);
                appendU8(4);
                appendU8(0);
                appendU8(8);
                appendU8(0);
                appendU8(0x01);
                appendU8(0x78);
                appendU8(0x1e);

                appendU8(0x0c); // DW_CFA_def_cfa reg31,16
                appendULEB(sec, 31);
                appendULEB(sec, 16);

                uint32_t len = static_cast<uint32_t>(sec.size() - (len_pos + 4));
                sec[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
                sec[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
                sec[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
                sec[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
            }

            // FDE: DW_CFA_val_expression reg30, block(DW_OP_const1u imm)
            {
                size_t len_pos = sec.size();
                appendU32(sec, 0);
                appendU32(sec, 0);
                appendU64(sec, 0x3000);
                appendU64(sec, 0x40);

                appendU8(0x16); // DW_CFA_val_expression
                appendULEB(sec, 30);
                appendULEB(sec, 2);
                appendU8(static_cast<uint8_t>(DwarfOp::DW_OP_const1u));
                appendU8(imm);

                uint32_t len = static_cast<uint32_t>(sec.size() - (len_pos + 4));
                sec[len_pos + 0] = static_cast<uint8_t>(len & 0xff);
                sec[len_pos + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
                sec[len_pos + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
                sec[len_pos + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
            }
            return sec;
        };

        auto a = makeDebugFrameWithValExpr(0x2a);
        auto b = makeDebugFrameWithValExpr(0x2a);
        auto c = makeDebugFrameWithValExpr(0x2b);
        CFIParser pa(a, /*is_eh_frame=*/false, /*address_size=*/8);
        CFIParser pb(b, /*is_eh_frame=*/false, /*address_size=*/8);
        CFIParser pc(c, /*is_eh_frame=*/false, /*address_size=*/8);
        assert(pa.parse());
        assert(pb.parse());
        assert(pc.parse());

        SymbolicCFIVerifier v;
        auto eq = v.compareFDEByIndex(pa, 0, pb, 0);
        assert(eq.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT);
        auto diff = v.compareFDEByIndex(pa, 0, pc, 0);
        assert(diff.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
    }

    std::cout << "SymbolicCFIVerifier tests passed!" << std::endl;
}

void testDWPIndexParsing() {
    std::cout << "Testing DWP index parsing..." << std::endl;

    // Minimal synthetic .debug_cu_index with section id table.
    // version=6 (future/newer), section_count=4, unit_count=1, slot_count=1
    // section_ids: [LINE(4), INFO(1), ABBREV(3), ADDR(9)] to ensure mapping isn't positional.
    const uint64_t sig = 0x1122334455667788ULL;

    std::vector<uint8_t> idx;
    appendU32(idx, 6);
    appendU32(idx, 4);
    appendU32(idx, 1);
    appendU32(idx, 1);

    appendU32(idx, 4);
    appendU32(idx, 1);
    appendU32(idx, 3);
    appendU32(idx, 9);

    // hash table: signatures
    appendU64(idx, sig);

    // index table: 1-based row index
    appendU32(idx, 1);

    // section offsets (row0): [0x10(line), 0x20(info), 0x30(abbrev), 0x40(addr)]
    appendU32(idx, 0x10);
    appendU32(idx, 0x20);
    appendU32(idx, 0x30);
    appendU32(idx, 0x40);

    // section sizes (row0): [0x100, 0x200, 0x300, 0x400]
    appendU32(idx, 0x100);
    appendU32(idx, 0x200);
    appendU32(idx, 0x300);
    appendU32(idx, 0x400);

    DWPLoader loader;
    assert(loader.parseIndexData(idx, false));

    auto entry_opt = loader.findUnit(sig);
    assert(entry_opt.has_value());
    const auto& e = *entry_opt;

    assert(e.signature == sig);
    assert(e.line_offset == 0x10 && e.line_size == 0x100);
    assert(e.info_offset == 0x20 && e.info_size == 0x200);
    assert(e.abbrev_offset == 0x30 && e.abbrev_size == 0x300);
    assert(e.addr_offset == 0x40 && e.addr_size == 0x400);

    // Version 1 should also parse (layout is commonly compatible).
    {
        std::vector<uint8_t> idx_v1 = idx;
        // Patch version at byte 0.
        idx_v1[0] = 0x01; idx_v1[1] = 0x00; idx_v1[2] = 0x00; idx_v1[3] = 0x00;
        DWPLoader l1;
        assert(l1.parseIndexData(idx_v1, false));
        auto e1 = l1.findUnit(sig);
        assert(e1.has_value());
        assert(e1->info_offset == 0x20 && e1->info_size == 0x200);
    }

    // Version 0 should be rejected.
    {
        std::vector<uint8_t> idx_v0 = idx;
        idx_v0[0] = 0x00; idx_v0[1] = 0x00; idx_v0[2] = 0x00; idx_v0[3] = 0x00;
        DWPLoader l0;
        assert(!l0.parseIndexData(idx_v0, false));
    }

    // Truncated section-id table should be rejected.
    {
        std::vector<uint8_t> idx_trunc = idx;
        idx_trunc.resize(16); // header only, section_count still says 4
        DWPLoader lt;
        assert(!lt.parseIndexData(idx_trunc, false));
    }

    // Failed re-parse should not leave stale entries from an earlier successful parse.
    {
        DWPLoader ls;
        assert(ls.parseIndexData(idx, false));
        assert(ls.findUnit(sig).has_value());

        std::vector<uint8_t> idx_bad = idx;
        idx_bad.resize(16); // malformed
        assert(!ls.parseIndexData(idx_bad, false));
        assert(!ls.findUnit(sig).has_value());
    }

    // Large offsets/sizes should not overflow extractSection arithmetic.
    {
        const uint64_t sig2 = 0x99aabbccddeeff00ULL;
        std::vector<uint8_t> idx_big;
        appendU32(idx_big, 6); // version
        appendU32(idx_big, 1); // section_count
        appendU32(idx_big, 1); // unit_count
        appendU32(idx_big, 1); // slot_count
        appendU32(idx_big, 1); // section id: DW_SECT_INFO
        appendU64(idx_big, sig2); // hash/signature
        appendU32(idx_big, 1);    // index row
        appendU32(idx_big, 0xfffffff0u); // huge info offset
        appendU32(idx_big, 0x30u);       // size triggers 32-bit wrap if unchecked

        DWPLoader lo;
        assert(lo.parseIndexData(idx_big, false));
        auto sec = lo.getSectionsForUnit(sig2);
        assert(sec.has_value());
        assert(sec->debug_info.empty());
    }

    std::cout << "DWP index parsing tests passed!" << std::endl;
}

void testImplicitConstInAbbrev() {
    std::cout << "Testing DW_FORM_implicit_const in abbrev..." << std::endl;

    // Abbrev table: code=1, tag=compile_unit, no children,
    // attribute: DW_AT_language with DW_FORM_implicit_const = 42.
    std::vector<uint8_t> debug_abbrev;
    debug_abbrev.push_back(0x01); // abbrev code
    debug_abbrev.push_back(0x11); // DW_TAG_compile_unit
    debug_abbrev.push_back(0x00); // no children
    debug_abbrev.push_back(0x13); // DW_AT_language
    debug_abbrev.push_back(0x21); // DW_FORM_implicit_const
    debug_abbrev.push_back(0x2a); // SLEB128(42)
    debug_abbrev.push_back(0x00); // end attr list
    debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00); // end abbrev table

    // .debug_info CU: unit_length=8, version=4, abbrev_offset=0, addr_size=8, abbrev_code=1
    std::vector<uint8_t> debug_info;
    appendU32(debug_info, 8);      // unit_length (doesn't include this field)
    debug_info.push_back(0x04);    // version lo
    debug_info.push_back(0x00);    // version hi
    appendU32(debug_info, 0);      // abbrev_offset
    debug_info.push_back(0x08);    // address_size
    debug_info.push_back(0x01);    // abbrev_code for CU DIE

    std::vector<uint8_t> empty;
    ELFIO::elfio elf;
    DIEParser parser(elf, debug_info, debug_abbrev, /*debug_str=*/empty);

    auto cus = parser.parseCompilationUnits();
    assert(cus.size() == 1);
    auto cu = cus[0];
    assert(cu);
    auto lang_attr = cu->getAttribute(DwarfAttribute::DW_AT_language);
    assert(lang_attr);
    auto sval = std::dynamic_pointer_cast<SignedAttributeValue>(lang_attr);
    assert(sval);
    assert(sval->getValue() == 42);

    std::cout << "DW_FORM_implicit_const abbrev tests passed!" << std::endl;
}

void testRefAddrBiasForDWO() {
    std::cout << "Testing DW_FORM_ref_addr biasing for DWO..." << std::endl;

    // Abbrev table:
    // 1: compile_unit, has children
    // 2: variable, no children, has DW_AT_type as DW_FORM_ref_addr
    // 3: base_type, no children
    std::vector<uint8_t> debug_abbrev;
    debug_abbrev.push_back(0x01);
    debug_abbrev.push_back(0x11); // DW_TAG_compile_unit
    debug_abbrev.push_back(0x01); // has children
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00); // end attrs

    debug_abbrev.push_back(0x02);
    debug_abbrev.push_back(0x34); // DW_TAG_variable
    debug_abbrev.push_back(0x00); // no children
    debug_abbrev.push_back(0x49); // DW_AT_type
    debug_abbrev.push_back(0x10); // DW_FORM_ref_addr
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00); // end attrs

    debug_abbrev.push_back(0x03);
    debug_abbrev.push_back(0x24); // DW_TAG_base_type
    debug_abbrev.push_back(0x00); // no children
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00); // end attrs

    debug_abbrev.push_back(0x00); // end table

    // .debug_info:
    // CU header (DWARF4): len, version, abbrev_offset, addr_size
    // CU DIE: abbrev 1
    // child: variable (abbrev 2) with ref_addr pointing at base_type DIE
    // child: base_type (abbrev 3)
    // null child
    std::vector<uint8_t> debug_info;
    appendU32(debug_info, 0);   // placeholder length
    debug_info.push_back(0x04); debug_info.push_back(0x00); // version 4
    appendU32(debug_info, 0);   // abbrev offset
    debug_info.push_back(0x08); // addr_size

    uint64_t cu_header_size = debug_info.size(); // 11 bytes
    (void)cu_header_size;

    debug_info.push_back(0x01); // CU abbrev code

    // variable DIE starts here (offset 12)
    debug_info.push_back(0x02); // variable abbrev code

    // base_type DIE will be at offset:
    // 11(header) +1(CU code) +1(var code)+4(ref_addr) = 17
    appendU32(debug_info, 17); // ref_addr (DWARF4 offset_size=4)

    debug_info.push_back(0x03); // base_type abbrev code (offset 17)
    debug_info.push_back(0x00); // end of children

    // Fix unit_length
    uint32_t unit_length = static_cast<uint32_t>(debug_info.size() - 4);
    debug_info[0] = static_cast<uint8_t>(unit_length & 0xff);
    debug_info[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
    debug_info[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
    debug_info[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

    std::vector<uint8_t> empty;
    ELFIO::elfio elf;

    uint64_t bias = (1ULL << 63) | (1ULL << 48);
    DIEParser parser(elf, debug_info, debug_abbrev, /*debug_str=*/empty,
                     /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                     /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                     /*debug_rnglists=*/empty, /*debug_loclists=*/empty,
                     /*debug_str_sup=*/empty,
                     /*verbose=*/false, /*debug_info_offset_bias=*/bias);

    auto cus = parser.parseCompilationUnits();
    assert(cus.size() == 1);
    auto cu = cus[0];
    assert(cu);
    assert(!cu->getChildren().empty());

    // First child is variable, second child is base_type
    auto var = cu->getChildren()[0];
    auto base = cu->getChildren()[1];
    assert(var && base);

    auto type_attr = var->getAttribute(DwarfAttribute::DW_AT_type);
    auto type_val = std::dynamic_pointer_cast<TypeAttributeValue>(type_attr);
    assert(type_val);
    assert(type_val->getOffset() == bias + 17);
    assert(base->getOffset() == bias + 17);

    std::cout << "DW_FORM_ref_addr bias tests passed!" << std::endl;
}

void testDwarf5SecOffsetLoclistsAndRnglists() {
    std::cout << "Testing DWARF5 sec_offset loclists/rnglists parsing..." << std::endl;

    // Build a minimal .debug_loclists contribution with header and a single list at offset 12.
    std::vector<uint8_t> debug_loclists;
    appendU32(debug_loclists, 0); // placeholder unit_length
    debug_loclists.push_back(0x05); debug_loclists.push_back(0x00); // version 5
    debug_loclists.push_back(0x08); // address_size
    debug_loclists.push_back(0x00); // segment_selector_size
    appendU32(debug_loclists, 0);   // offset_entry_count
    const uint32_t loclist_off = static_cast<uint32_t>(debug_loclists.size()); // 12

    // DW_LLE_start_end
    debug_loclists.push_back(static_cast<uint8_t>(DW_LLE::DW_LLE_start_end));
    appendU64(debug_loclists, 0x1000);
    appendU64(debug_loclists, 0x1100);
    // expr_len = 1, expr = DW_OP_nop
    debug_loclists.push_back(0x01);
    debug_loclists.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_nop));
    // end_of_list
    debug_loclists.push_back(static_cast<uint8_t>(DW_LLE::DW_LLE_end_of_list));

    // Fix unit_length
    uint32_t loc_unit_length = static_cast<uint32_t>(debug_loclists.size() - 4);
    debug_loclists[0] = static_cast<uint8_t>(loc_unit_length & 0xff);
    debug_loclists[1] = static_cast<uint8_t>((loc_unit_length >> 8) & 0xff);
    debug_loclists[2] = static_cast<uint8_t>((loc_unit_length >> 16) & 0xff);
    debug_loclists[3] = static_cast<uint8_t>((loc_unit_length >> 24) & 0xff);

    // Build a minimal .debug_rnglists contribution with header and a single list at offset 12.
    std::vector<uint8_t> debug_rnglists;
    appendU32(debug_rnglists, 0); // placeholder unit_length
    debug_rnglists.push_back(0x05); debug_rnglists.push_back(0x00); // version 5
    debug_rnglists.push_back(0x08); // address_size
    debug_rnglists.push_back(0x00); // segment_selector_size
    appendU32(debug_rnglists, 0);   // offset_entry_count
    const uint32_t rnglist_off = static_cast<uint32_t>(debug_rnglists.size()); // 12

    // DW_RLE_start_end
    debug_rnglists.push_back(static_cast<uint8_t>(DW_RLE::DW_RLE_start_end));
    appendU64(debug_rnglists, 0x2000);
    appendU64(debug_rnglists, 0x2100);
    // end_of_list
    debug_rnglists.push_back(static_cast<uint8_t>(DW_RLE::DW_RLE_end_of_list));

    // Fix unit_length
    uint32_t rng_unit_length = static_cast<uint32_t>(debug_rnglists.size() - 4);
    debug_rnglists[0] = static_cast<uint8_t>(rng_unit_length & 0xff);
    debug_rnglists[1] = static_cast<uint8_t>((rng_unit_length >> 8) & 0xff);
    debug_rnglists[2] = static_cast<uint8_t>((rng_unit_length >> 16) & 0xff);
    debug_rnglists[3] = static_cast<uint8_t>((rng_unit_length >> 24) & 0xff);

    // debug_info bytes: DW_AT_location sec_offset pointer then DW_AT_ranges sec_offset pointer
    std::vector<uint8_t> debug_info;
    appendU32(debug_info, loclist_off);
    appendU32(debug_info, rnglist_off);

    std::vector<uint8_t> empty;
    AttributeParser ap(debug_info, /*debug_abbrev=*/empty, /*debug_str=*/empty,
                       /*debug_line=*/empty,
                       /*debug_ranges=*/empty,
                       /*debug_loc=*/empty,
                       /*debug_str_offsets=*/empty,
                       /*debug_addr=*/empty,
                       /*debug_line_str=*/empty,
                       /*debug_rnglists=*/debug_rnglists,
                       /*debug_loclists=*/debug_loclists);
    ap.setDwarfVersion(DwarfVersion::DWARF5);
    ap.setIsDwarf64(false);
    ap.setAddressSize(8);
    ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0, /*addr_base=*/0, /*str_offsets_base=*/0, /*base_address=*/0);

    uint64_t off = 0;
    auto loc_attr = ap.parseAttribute(DwarfAttribute::DW_AT_location, DwarfForm::DW_FORM_sec_offset, off);
    auto loc_val = std::dynamic_pointer_cast<LocationAttributeValue>(loc_attr);
    assert(loc_val);
    assert(loc_val->getLocationType() == LocationAttributeValue::LocationType::LIST);
    assert(!loc_val->getEntries().empty());
    assert(loc_val->getEntries()[0].start == 0x1000);
    assert(loc_val->getEntries()[0].end == 0x1100);
    assert(loc_val->getEntries()[0].expression.size() == 1);

    auto rng_attr = ap.parseAttribute(DwarfAttribute::DW_AT_ranges, DwarfForm::DW_FORM_sec_offset, off);
    auto rng_val = std::dynamic_pointer_cast<RangeAttributeValue>(rng_attr);
    assert(rng_val);
    assert(!rng_val->getRanges().empty());
    assert(rng_val->getRanges()[0].start == 0x2000);
    assert(rng_val->getRanges()[0].end == 0x2100);

    std::cout << "DWARF5 sec_offset loclists/rnglists tests passed!" << std::endl;
}

void testDwarf4SecOffsetDebugLocAndRanges() {
    std::cout << "Testing DWARF4 sec_offset debug_loc/debug_ranges parsing..." << std::endl;

    // .debug_loc: base selection + one range + end
    std::vector<uint8_t> debug_loc;
    appendU64(debug_loc, 0xffffffffffffffffULL);
    appendU64(debug_loc, 0x1000);
    appendU64(debug_loc, 0x10);
    appendU64(debug_loc, 0x20);
    // expr_len = 1
    debug_loc.push_back(0x01);
    debug_loc.push_back(0x00);
    debug_loc.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_nop));
    appendU64(debug_loc, 0);
    appendU64(debug_loc, 0);

    // .debug_ranges: base selection + one range + end
    std::vector<uint8_t> debug_ranges;
    appendU64(debug_ranges, 0xffffffffffffffffULL);
    appendU64(debug_ranges, 0x2000);
    appendU64(debug_ranges, 0x30);
    appendU64(debug_ranges, 0x40);
    appendU64(debug_ranges, 0);
    appendU64(debug_ranges, 0);

    // .debug_info stream only needs the two sec_offset pointers.
    std::vector<uint8_t> debug_info;
    appendU32(debug_info, 0); // loc list at offset 0
    appendU32(debug_info, 0); // range list at offset 0

    std::vector<uint8_t> empty;
    AttributeParser ap(debug_info, /*debug_abbrev=*/empty, /*debug_str=*/empty,
                       /*debug_line=*/empty,
                       /*debug_ranges=*/debug_ranges,
                       /*debug_loc=*/debug_loc,
                       /*debug_str_offsets=*/empty,
                       /*debug_addr=*/empty,
                       /*debug_line_str=*/empty,
                       /*debug_rnglists=*/empty,
                       /*debug_loclists=*/empty);
    ap.setDwarfVersion(DwarfVersion::DWARF4);
    ap.setIsDwarf64(false);
    ap.setAddressSize(8);
    ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0, /*addr_base=*/0, /*str_offsets_base=*/0, /*base_address=*/0);

    uint64_t off = 0;
    auto loc_attr = ap.parseAttribute(DwarfAttribute::DW_AT_location, DwarfForm::DW_FORM_sec_offset, off);
    auto loc_val = std::dynamic_pointer_cast<LocationAttributeValue>(loc_attr);
    assert(loc_val);
    assert(!loc_val->getEntries().empty());
    assert(loc_val->getEntries()[0].start == 0x1010);
    assert(loc_val->getEntries()[0].end == 0x1020);

    auto rng_attr = ap.parseAttribute(DwarfAttribute::DW_AT_ranges, DwarfForm::DW_FORM_sec_offset, off);
    auto rng_val = std::dynamic_pointer_cast<RangeAttributeValue>(rng_attr);
    assert(rng_val);
    assert(!rng_val->getRanges().empty());
    // First entry can be a base-address selection entry.
    assert(rng_val->getRanges().size() >= 2);
    assert(rng_val->getRanges()[0].is_base_address);
    assert(rng_val->getRanges()[1].start == 0x2030);
    assert(rng_val->getRanges()[1].end == 0x2040);

    std::cout << "DWARF4 sec_offset debug_loc/debug_ranges tests passed!" << std::endl;
}

static void appendULEB128(std::vector<uint8_t>& out, uint64_t v) {
    do {
        uint8_t b = static_cast<uint8_t>(v & 0x7f);
        v >>= 7;
        if (v) b |= 0x80;
        out.push_back(b);
    } while (v);
}

void testDwarf64LoclistxRnglistxOffsetSize() {
    std::cout << "Testing DWARF64 loclistx/rnglistx offset_size..." << std::endl;

    // loclists: offsets array at base=0, offset_size=8, index 1 -> list at 0x20.
    std::vector<uint8_t> debug_loclists(0x20, 0);
    // offsets array entries (8 bytes each): idx0=0, idx1=0x20 (relative)
    // At pos 8: value 0x20.
    debug_loclists[8] = 0x20;

    // List at 0x20: DW_LLE_start_end, start=0x100, end=0x200, expr_len=1, expr=DW_OP_nop, end_of_list.
    debug_loclists.push_back(static_cast<uint8_t>(DW_LLE::DW_LLE_start_end));
    appendU64(debug_loclists, 0x100);
    appendU64(debug_loclists, 0x200);
    appendULEB128(debug_loclists, 1);
    debug_loclists.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_nop));
    debug_loclists.push_back(static_cast<uint8_t>(DW_LLE::DW_LLE_end_of_list));

    // rnglists: offsets array at base=0, offset_size=8, index 1 -> list at 0x20.
    std::vector<uint8_t> debug_rnglists(0x20, 0);
    debug_rnglists[8] = 0x20;
    debug_rnglists.push_back(static_cast<uint8_t>(DW_RLE::DW_RLE_start_end));
    appendU64(debug_rnglists, 0x300);
    appendU64(debug_rnglists, 0x400);
    debug_rnglists.push_back(static_cast<uint8_t>(DW_RLE::DW_RLE_end_of_list));

    // debug_info: ULEB128 index=1 for loclistx, then index=1 for rnglistx
    std::vector<uint8_t> debug_info;
    appendULEB128(debug_info, 1);
    appendULEB128(debug_info, 1);

    std::vector<uint8_t> empty;
    AttributeParser ap(debug_info, /*debug_abbrev=*/empty, /*debug_str=*/empty,
                       /*debug_line=*/empty,
                       /*debug_ranges=*/empty,
                       /*debug_loc=*/empty,
                       /*debug_str_offsets=*/empty,
                       /*debug_addr=*/empty,
                       /*debug_line_str=*/empty,
                       /*debug_rnglists=*/debug_rnglists,
                       /*debug_loclists=*/debug_loclists);
    ap.setDwarfVersion(DwarfVersion::DWARF5);
    ap.setIsDwarf64(true);
    ap.setAddressSize(8);
    ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0, /*addr_base=*/0, /*str_offsets_base=*/0, /*base_address=*/0);

    uint64_t off = 0;
    auto loc = ap.parseAttribute(DwarfAttribute::DW_AT_location, DwarfForm::DW_FORM_loclistx, off);
    auto loc_val = std::dynamic_pointer_cast<LocationAttributeValue>(loc);
    assert(loc_val);
    assert(!loc_val->getEntries().empty());
    assert(loc_val->getEntries()[0].start == 0x100);
    assert(loc_val->getEntries()[0].end == 0x200);

    auto rng = ap.parseAttribute(DwarfAttribute::DW_AT_ranges, DwarfForm::DW_FORM_rnglistx, off);
    auto rng_val = std::dynamic_pointer_cast<RangeAttributeValue>(rng);
    assert(rng_val);
    assert(!rng_val->getRanges().empty());
    assert(rng_val->getRanges()[0].start == 0x300);
    assert(rng_val->getRanges()[0].end == 0x400);

    std::cout << "DWARF64 loclistx/rnglistx offset_size tests passed!" << std::endl;
}

static std::string makeTempDir(const std::string& prefix) {
    namespace fs = std::filesystem;
    fs::path base = fs::temp_directory_path();
    std::random_device rd;
    std::mt19937_64 gen(rd());
    for (int i = 0; i < 50; ++i) {
        uint64_t r = gen();
        fs::path p = base / (prefix + std::to_string(r));
        std::error_code ec;
        if (fs::create_directory(p, ec)) {
            return p.string();
        }
    }
    // Fall back: current directory
    return ".";
}

static void writeELFWithSections(const std::string& path,
                                 const std::vector<std::pair<std::string, std::vector<uint8_t>>>& sections) {
    ELFIO::elfio writer;
    writer.create(ELFIO::ELFCLASS64, ELFIO::ELFDATA2LSB);
    writer.set_type(ELFIO::ET_REL);
    writer.set_machine(ELFIO::EM_X86_64);

    for (const auto& [name, data] : sections) {
        auto* sec = writer.sections.add(name);
        sec->set_type(ELFIO::SHT_PROGBITS);
        sec->set_flags(0);
        sec->set_addr_align(1);
        if (!data.empty()) {
            sec->set_data(reinterpret_cast<const char*>(data.data()), data.size());
        } else {
            static const char dummy = 0;
            sec->set_data(&dummy, 0);
        }
    }

    assert(writer.save(path));
}

void testSplitDwarfIntegrationELFIO() {
    std::cout << "Testing split DWARF integration (ELFIO fixture)..." << std::endl;

    const uint64_t dwo_id = 0xAABBCCDDEEFF0011ULL;
    const std::string dwo_name = "unit.dwo";

    // Main executable .debug_str
    std::vector<uint8_t> main_str;
    uint32_t dwo_name_off = static_cast<uint32_t>(main_str.size());
    for (char c : dwo_name) main_str.push_back(static_cast<uint8_t>(c));
    main_str.push_back(0);

    // Main .debug_abbrev: CU with DW_AT_dwo_name (strp) and DW_AT_dwo_id (data8)
    std::vector<uint8_t> main_abbrev;
    main_abbrev.push_back(0x01); // code
    main_abbrev.push_back(0x11); // DW_TAG_compile_unit
    main_abbrev.push_back(0x00); // no children
    appendULEB128(main_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_dwo_name));
    appendULEB128(main_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_strp));
    appendULEB128(main_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_dwo_id));
    appendULEB128(main_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_data8));
    main_abbrev.push_back(0x00); main_abbrev.push_back(0x00); // end attrs
    main_abbrev.push_back(0x00); // end table

    // Main .debug_info CU with code=1 and the two attributes
    std::vector<uint8_t> main_info;
    appendU32(main_info, 0); // placeholder unit_length
    main_info.push_back(0x04); main_info.push_back(0x00); // version 4
    appendU32(main_info, 0); // abbrev offset
    main_info.push_back(0x08); // addr_size
    main_info.push_back(0x01); // abbrev code
    appendU32(main_info, dwo_name_off); // strp
    appendU64(main_info, dwo_id);       // data8
    uint32_t main_len = static_cast<uint32_t>(main_info.size() - 4);
    main_info[0] = static_cast<uint8_t>(main_len & 0xff);
    main_info[1] = static_cast<uint8_t>((main_len >> 8) & 0xff);
    main_info[2] = static_cast<uint8_t>((main_len >> 16) & 0xff);
    main_info[3] = static_cast<uint8_t>((main_len >> 24) & 0xff);

    // DWO .debug_str.dwo contains "MyInt"
    std::vector<uint8_t> dwo_str;
    const std::string type_name = "MyInt";
    uint32_t type_name_off = static_cast<uint32_t>(dwo_str.size());
    for (char c : type_name) dwo_str.push_back(static_cast<uint8_t>(c));
    dwo_str.push_back(0);

    // DWO .debug_abbrev.dwo: CU has children; base_type with name/byte_size/encoding
    std::vector<uint8_t> dwo_abbrev;
    dwo_abbrev.push_back(0x01); // CU
    dwo_abbrev.push_back(0x11); // DW_TAG_compile_unit
    dwo_abbrev.push_back(0x01); // has children
    dwo_abbrev.push_back(0x00); dwo_abbrev.push_back(0x00);
    dwo_abbrev.push_back(0x02); // base_type
    dwo_abbrev.push_back(0x24); // DW_TAG_base_type
    dwo_abbrev.push_back(0x00); // no children
    appendULEB128(dwo_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_name));
    appendULEB128(dwo_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_strp));
    appendULEB128(dwo_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_byte_size));
    appendULEB128(dwo_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_data1));
    appendULEB128(dwo_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_encoding));
    appendULEB128(dwo_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_data1));
    dwo_abbrev.push_back(0x00); dwo_abbrev.push_back(0x00);
    dwo_abbrev.push_back(0x00);

    // DWO .debug_info.dwo: CU + child base_type + null
    std::vector<uint8_t> dwo_info;
    appendU32(dwo_info, 0); // placeholder unit_length
    dwo_info.push_back(0x04); dwo_info.push_back(0x00); // version 4
    appendU32(dwo_info, 0); // abbrev offset
    dwo_info.push_back(0x08); // addr_size
    dwo_info.push_back(0x01); // CU code
    dwo_info.push_back(0x02); // base_type code
    appendU32(dwo_info, type_name_off); // name strp
    dwo_info.push_back(0x04);           // byte_size
    dwo_info.push_back(0x05);           // encoding (arbitrary)
    dwo_info.push_back(0x00);           // end children
    uint32_t dwo_len = static_cast<uint32_t>(dwo_info.size() - 4);
    dwo_info[0] = static_cast<uint8_t>(dwo_len & 0xff);
    dwo_info[1] = static_cast<uint8_t>((dwo_len >> 8) & 0xff);
    dwo_info[2] = static_cast<uint8_t>((dwo_len >> 16) & 0xff);
    dwo_info[3] = static_cast<uint8_t>((dwo_len >> 24) & 0xff);

    std::string dir = makeTempDir("dwarf_split_");
    std::string main_path = (std::filesystem::path(dir) / "main.elf").string();
    std::string dwo_path = (std::filesystem::path(dir) / dwo_name).string();

    writeELFWithSections(main_path, {
        {".debug_info", main_info},
        {".debug_abbrev", main_abbrev},
        {".debug_str", main_str},
    });

    writeELFWithSections(dwo_path, {
        {".debug_info.dwo", dwo_info},
        {".debug_abbrev.dwo", dwo_abbrev},
        {".debug_str.dwo", dwo_str},
    });

    DwarfParser parser(main_path);
    // Not strictly necessary because integrateSplitDwarf adds exe dir, but keep explicit.
    parser.addDWOSearchPath(dir);
    assert(parser.load());

    auto dies = parser.findDIEsByName(type_name);
    assert(!dies.empty());
    bool found_base_type = false;
    for (const auto& die : dies) {
        if (die && die->getTag() == DwarfTag::DW_TAG_base_type) {
            found_base_type = true;
            break;
        }
    }
    assert(found_base_type);

    std::cout << "Split DWARF integration tests passed!" << std::endl;
}

void testSplitDwarfDWOAddrxUsesDWODebugAddr() {
    std::cout << "Testing split DWARF: DW_OP_addrx uses DWO .debug_addr..." << std::endl;

    const uint64_t dwo_id = 0x1122334455667788ULL;
    const std::string dwo_name = "unit_addrx.dwo";

    // Main executable .debug_str holds the DWO name.
    std::vector<uint8_t> main_str;
    uint32_t dwo_name_off = static_cast<uint32_t>(main_str.size());
    for (char c : dwo_name) main_str.push_back(static_cast<uint8_t>(c));
    main_str.push_back(0);

    // Main .debug_abbrev: CU with DW_AT_dwo_name (strp) and DW_AT_dwo_id (data8)
    std::vector<uint8_t> main_abbrev;
    main_abbrev.push_back(0x01); // code
    main_abbrev.push_back(0x11); // DW_TAG_compile_unit
    main_abbrev.push_back(0x00); // no children
    appendULEB128(main_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_dwo_name));
    appendULEB128(main_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_strp));
    appendULEB128(main_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_dwo_id));
    appendULEB128(main_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_data8));
    main_abbrev.push_back(0x00); main_abbrev.push_back(0x00);
    main_abbrev.push_back(0x00);

    // Main .debug_info CU (DWARF4 is enough for skeleton).
    std::vector<uint8_t> main_info;
    appendU32(main_info, 0); // placeholder unit_length
    main_info.push_back(0x04); main_info.push_back(0x00); // version 4
    appendU32(main_info, 0); // abbrev offset
    main_info.push_back(0x08); // addr_size
    main_info.push_back(0x01); // abbrev code
    appendU32(main_info, dwo_name_off);
    appendU64(main_info, dwo_id);
    uint32_t main_len = static_cast<uint32_t>(main_info.size() - 4);
    main_info[0] = static_cast<uint8_t>(main_len & 0xff);
    main_info[1] = static_cast<uint8_t>((main_len >> 8) & 0xff);
    main_info[2] = static_cast<uint8_t>((main_len >> 16) & 0xff);
    main_info[3] = static_cast<uint8_t>((main_len >> 24) & 0xff);

    // DWO .debug_str.dwo holds the variable name.
    std::vector<uint8_t> dwo_str;
    const std::string var_name = "gVar";
    uint32_t var_name_off = static_cast<uint32_t>(dwo_str.size());
    for (char c : var_name) dwo_str.push_back(static_cast<uint8_t>(c));
    dwo_str.push_back(0);

    // DWO .debug_abbrev.dwo: DWARF5 CU with DW_AT_addr_base; child variable with name + location exprloc.
    std::vector<uint8_t> dwo_abbrev;
    dwo_abbrev.push_back(0x01); // CU
    dwo_abbrev.push_back(0x11); // DW_TAG_compile_unit
    dwo_abbrev.push_back(0x01); // has children
    appendULEB128(dwo_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_addr_base));
    appendULEB128(dwo_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_sec_offset));
    dwo_abbrev.push_back(0x00); dwo_abbrev.push_back(0x00);

    dwo_abbrev.push_back(0x02); // variable
    dwo_abbrev.push_back(0x34); // DW_TAG_variable
    dwo_abbrev.push_back(0x00); // no children
    appendULEB128(dwo_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_name));
    appendULEB128(dwo_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_strp));
    appendULEB128(dwo_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_location));
    appendULEB128(dwo_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_exprloc));
    dwo_abbrev.push_back(0x00); dwo_abbrev.push_back(0x00);
    dwo_abbrev.push_back(0x00);

    // DWO .debug_addr.dwo: one DWARF32 contribution with one entry = 0xCAFEBABECAFED00D.
    std::vector<uint8_t> dwo_debug_addr;
    appendU32(dwo_debug_addr, 0); // unit_length placeholder
    appendU16(dwo_debug_addr, 5);
    dwo_debug_addr.push_back(8);
    dwo_debug_addr.push_back(0);
    appendU64(dwo_debug_addr, 0xCAFEBABECAFED00DULL);
    {
        uint32_t unit_length = static_cast<uint32_t>(dwo_debug_addr.size() - 4);
        dwo_debug_addr[0] = static_cast<uint8_t>(unit_length & 0xff);
        dwo_debug_addr[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        dwo_debug_addr[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        dwo_debug_addr[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    // DWO .debug_info.dwo (DWARF5):
    // unit_header: len, ver=5, unit_type=DW_UT_compile(1), addr_size=8, abbrev_off=0
    // CU DIE: code=1, addr_base(sec_offset)=0 (points at contribution start)
    // child variable DIE: code=2, name(strp), location(exprloc: DW_OP_addrx 0)
    std::vector<uint8_t> dwo_info;
    appendU32(dwo_info, 0); // placeholder unit_length
    appendU16(dwo_info, 5); // version
    dwo_info.push_back(0x01); // DW_UT_compile
    dwo_info.push_back(0x08); // address_size
    appendU32(dwo_info, 0); // abbrev offset

    dwo_info.push_back(0x01); // CU abbrev code
    appendU32(dwo_info, 0);   // addr_base = 0

    dwo_info.push_back(0x02); // variable abbrev code
    appendU32(dwo_info, var_name_off); // name

    // exprloc: ULEB length then bytes (DW_OP_addrx, uleb 0)
    dwo_info.push_back(0x02); // length=2
    dwo_info.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addrx));
    dwo_info.push_back(0x00);

    dwo_info.push_back(0x00); // end children

    {
        uint32_t unit_length = static_cast<uint32_t>(dwo_info.size() - 4);
        dwo_info[0] = static_cast<uint8_t>(unit_length & 0xff);
        dwo_info[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        dwo_info[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        dwo_info[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    std::string dir = makeTempDir("dwarf_split_addrx_");
    std::string main_path = (std::filesystem::path(dir) / "main_addrx.elf").string();
    std::string dwo_path = (std::filesystem::path(dir) / dwo_name).string();

    writeELFWithSections(main_path, {
        {".debug_info", main_info},
        {".debug_abbrev", main_abbrev},
        {".debug_str", main_str},
    });

    writeELFWithSections(dwo_path, {
        {".debug_info.dwo", dwo_info},
        {".debug_abbrev.dwo", dwo_abbrev},
        {".debug_str.dwo", dwo_str},
        {".debug_addr.dwo", dwo_debug_addr},
    });

    DwarfParser parser(main_path);
    parser.addDWOSearchPath(dir);
    assert(parser.load());

    auto dies = parser.findDIEsByName(var_name);
    assert(!dies.empty());
    std::shared_ptr<DIE> var_die;
    for (const auto& die : dies) {
        if (die && die->getTag() == DwarfTag::DW_TAG_variable) {
            var_die = die;
            break;
        }
    }
    assert(var_die);

    auto loc = parser.getVariableLocation(var_die, /*pc=*/0);
    assert(loc.type == VariableLocationType::MEMORY);
    assert(loc.address == 0xCAFEBABECAFED00DULL);

    std::cout << "Split DWARF DWO addrx tests passed!" << std::endl;
}

void testTypedOpsTypedefChainViaDwarfParser() {
    std::cout << "Testing typed ops typedef chain via DwarfParser..." << std::endl;

    // .debug_str: "MyS8\0Alias\0v\0"
    std::vector<uint8_t> debug_str;
    auto addStr = [&](const std::string& s) -> uint32_t {
        uint32_t off = static_cast<uint32_t>(debug_str.size());
        for (char c : s) debug_str.push_back(static_cast<uint8_t>(c));
        debug_str.push_back(0);
        return off;
    };
    uint32_t off_base = addStr("MyS8");
    uint32_t off_alias = addStr("Alias");
    uint32_t off_var = addStr("v");

    // Abbrev:
    // 1: CU, has children, no attrs
    // 2: base_type name(strp) byte_size(data1) encoding(data1)
    // 3: typedef name(strp) type(ref4)
    // 4: variable name(strp) location(exprloc) type(ref4)
    std::vector<uint8_t> debug_abbrev;
    appendULEB128(debug_abbrev, 1);
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfTag::DW_TAG_compile_unit));
    debug_abbrev.push_back(0x01); // children
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00); // end attrs

    appendULEB128(debug_abbrev, 2);
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfTag::DW_TAG_base_type));
    debug_abbrev.push_back(0x00);
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_name));
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_strp));
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_byte_size));
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_data1));
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_encoding));
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_data1));
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00);

    appendULEB128(debug_abbrev, 3);
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfTag::DW_TAG_typedef));
    debug_abbrev.push_back(0x00);
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_name));
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_strp));
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_type));
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_ref4));
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00);

    appendULEB128(debug_abbrev, 4);
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfTag::DW_TAG_variable));
    debug_abbrev.push_back(0x00);
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_name));
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_strp));
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_location));
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_exprloc));
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_type));
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_ref4));
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00);

    debug_abbrev.push_back(0x00); // end abbrev table

    // .debug_info: DWARF4 CU with children
    std::vector<uint8_t> debug_info;
    appendU32(debug_info, 0); // unit_length placeholder
    debug_info.push_back(0x04); debug_info.push_back(0x00); // version 4
    appendU32(debug_info, 0); // abbrev offset
    debug_info.push_back(0x08); // address size

    // CU DIE
    debug_info.push_back(0x01); // abbrev 1

    // base_type DIE at offset 12
    const uint32_t base_off = static_cast<uint32_t>(debug_info.size());
    debug_info.push_back(0x02); // abbrev 2
    appendU32(debug_info, off_base); // name
    debug_info.push_back(0x01); // byte_size = 1
    debug_info.push_back(0x05); // DW_ATE_signed

    // typedef DIE
    const uint32_t typedef_off = static_cast<uint32_t>(debug_info.size());
    debug_info.push_back(0x03); // abbrev 3
    appendU32(debug_info, off_alias); // name
    appendU32(debug_info, base_off); // DW_FORM_ref4 to base_type (CU-relative, CU at 0)

    // variable DIE, location expression uses DW_OP_convert referencing typedef_off (CU-relative)
    debug_info.push_back(0x04); // abbrev 4
    appendU32(debug_info, off_var); // name
    {
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u),
            0xFF,
            static_cast<uint8_t>(DwarfOp::DW_OP_convert),
            static_cast<uint8_t>(typedef_off), // ULEB128 (fits in 1 byte here)
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        };
        appendULEB128(debug_info, expr.size());
        debug_info.insert(debug_info.end(), expr.begin(), expr.end());
    }
    appendU32(debug_info, typedef_off); // DW_AT_type = typedef

    debug_info.push_back(0x00); // end children

    uint32_t unit_len = static_cast<uint32_t>(debug_info.size() - 4);
    debug_info[0] = static_cast<uint8_t>(unit_len & 0xff);
    debug_info[1] = static_cast<uint8_t>((unit_len >> 8) & 0xff);
    debug_info[2] = static_cast<uint8_t>((unit_len >> 16) & 0xff);
    debug_info[3] = static_cast<uint8_t>((unit_len >> 24) & 0xff);

    std::string dir = makeTempDir("dwarf_typed_");
    std::string main_path = (std::filesystem::path(dir) / "typed.elf").string();
    writeELFWithSections(main_path, {
        {".debug_info", debug_info},
        {".debug_abbrev", debug_abbrev},
        {".debug_str", debug_str},
    });

    DwarfParser parser(main_path);
    assert(parser.load());

    auto vars = parser.findDIEsByName("v");
    assert(!vars.empty());
    auto vdie = vars[0];
    assert(vdie);

    auto loc = parser.getVariableLocation(vdie, /*pc=*/0);
    assert(loc.type == VariableLocationType::IMPLICIT);
    assert(loc.implicit_value.size() == 8);
    for (size_t i = 0; i < 8; ++i) {
        assert(loc.implicit_value[i] == 0xFF);
    }

    std::cout << "Typed ops typedef-chain tests passed!" << std::endl;
}

void testCallStackAArch64CFAExpressionUnwind() {
    std::cout << "Testing CallStackBuilder unwind with CFA expression..." << std::endl;

    // Minimal DWARF so DwarfParser::load succeeds.
    std::vector<uint8_t> debug_str = {'x', 0};

    std::vector<uint8_t> debug_abbrev;
    // code=1: compile_unit, no children, no attrs
    debug_abbrev.push_back(0x01);
    debug_abbrev.push_back(0x11); // DW_TAG_compile_unit
    debug_abbrev.push_back(0x00); // no children
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00);

    std::vector<uint8_t> debug_info;
    appendU32(debug_info, 0); // unit_length placeholder
    debug_info.push_back(0x04); debug_info.push_back(0x00); // version 4
    appendU32(debug_info, 0); // abbrev offset
    debug_info.push_back(0x08); // addr_size
    debug_info.push_back(0x01); // CU abbrev code
    uint32_t unit_len = static_cast<uint32_t>(debug_info.size() - 4);
    debug_info[0] = static_cast<uint8_t>(unit_len & 0xff);
    debug_info[1] = static_cast<uint8_t>((unit_len >> 8) & 0xff);
    debug_info[2] = static_cast<uint8_t>((unit_len >> 16) & 0xff);
    debug_info[3] = static_cast<uint8_t>((unit_len >> 24) & 0xff);

    // Build .debug_frame with:
    // CIE (DWARF v4, augmentation="", code_align=1, data_align=-8, ra_reg=30)
    // FDE1 for [0x1000,0x1100): CFA = SP+16 (expression), RA @ CFA-8, SP = CFA
    // FDE2 for [0x1f00,0x2100): same CFA expression, RA @ CFA-8, SP = CFA
    auto appendULEB = [](std::vector<uint8_t>& out, uint64_t v) { appendULEB128(out, v); };
    auto appendSLEBLocal = [](std::vector<uint8_t>& out, int64_t v) {
        // Minimal SLEB128 encoder.
        bool more = true;
        while (more) {
            uint8_t byte = static_cast<uint8_t>(v & 0x7f);
            bool sign = (byte & 0x40) != 0;
            v >>= 7;
            if ((v == 0 && !sign) || (v == -1 && sign)) {
                more = false;
            } else {
                byte |= 0x80;
            }
            out.push_back(byte);
        }
    };

    std::vector<uint8_t> debug_frame;

    auto startEntry32 = [&](uint32_t id) -> size_t {
        size_t start = debug_frame.size();
        appendU32(debug_frame, 0); // length placeholder
        appendU32(debug_frame, id);
        return start;
    };
    auto finishEntry32 = [&](size_t start) {
        uint32_t len = static_cast<uint32_t>(debug_frame.size() - start - 4);
        debug_frame[start + 0] = static_cast<uint8_t>(len & 0xff);
        debug_frame[start + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_frame[start + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_frame[start + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    };

    // CIE at offset 0, id=0xffffffff for .debug_frame.
    size_t cie_start = startEntry32(0xffffffff);
    debug_frame.push_back(0x04); // version 4
    debug_frame.push_back(0x00); // augmentation string NUL
    debug_frame.push_back(0x08); // address_size
    debug_frame.push_back(0x00); // segment_selector_size
    appendULEB(debug_frame, 1);  // code_alignment_factor
    appendSLEBLocal(debug_frame, -8); // data_alignment_factor
    appendULEB(debug_frame, 30); // return_address_register (x30/lr)
    // no initial instructions
    finishEntry32(cie_start);

    auto emitFDE = [&](uint64_t initial_location, uint64_t range, uint64_t ra_value_at_cfa_minus_8) {
        size_t fde_start = startEntry32(0); // placeholder cie_pointer, patched below
        // For .debug_frame, cie_pointer is absolute offset of CIE (0).
        // We already wrote 0 as id/pointer.

        appendU64(debug_frame, initial_location);
        appendU64(debug_frame, range);

        // Instructions:
        // DW_CFA_def_cfa_expression (0x0f), len=2, DW_OP_breg31, sleb(16)
        debug_frame.push_back(0x0f);
        appendULEB(debug_frame, 2);
        debug_frame.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg31));
        debug_frame.push_back(0x10); // SLEB128(16)

        // DW_CFA_offset (high-bit encoding): 0x80 | reg30, uleb offset=1 => -8
        debug_frame.push_back(static_cast<uint8_t>(0x80 | 30));
        appendULEB(debug_frame, 1);

        // DW_CFA_val_offset (0x14): reg31, uleb offset=0 => SP = CFA
        debug_frame.push_back(0x14);
        appendULEB(debug_frame, 31);
        appendULEB(debug_frame, 0);

        finishEntry32(fde_start);

        (void)ra_value_at_cfa_minus_8;
    };

    emitFDE(0x1000, 0x100, /*ra=*/0x2000);
    emitFDE(0x1f00, 0x200, /*ra=*/0x0000);

    std::string dir = makeTempDir("dwarf_cfaexpr_");
    std::string elf_path = (std::filesystem::path(dir) / "cfaexpr.elf").string();
    writeELFWithSections(elf_path, {
        {".debug_info", debug_info},
        {".debug_abbrev", debug_abbrev},
        {".debug_str", debug_str},
        {".debug_frame", debug_frame},
    });

    DwarfParser parser(elf_path);
    assert(parser.load());

    CallStackBuilder b(parser);
    auto cfg = arch::aarch64();
    cfg.max_frames = 8;
    cfg.stop_at_main = false;
    cfg.stop_at_start = false;
    b.setConfig(cfg);

    // Memory: at CFA-8 for frame0 -> RA=0x2000, for frame1 -> RA=0.
    // With SP0=0x1000, CFA0=0x1010 => CFA-8=0x1008.
    // After unwind, SP1=CFA0=0x1010, CFA1=SP1+16=0x1020 => CFA-8=0x1018.
    std::unordered_map<uint64_t, uint64_t> mem;
    mem[0x1008] = 0x2000;
    mem[0x1018] = 0x0000;
    b.setMemoryReader([&](uint64_t addr, size_t size, void* out) -> bool {
        if (size != 8 || !out) return false;
        auto it = mem.find(addr);
        if (it == mem.end()) return false;
        std::memcpy(out, &it->second, 8);
        return true;
    });

    std::vector<uint64_t> regs(256, 0);
    regs[31] = 0x1000; // SP
    regs[32] = 0x1000; // PC
    regs[30] = 0;      // LR (unused, saved version used)

    CallStack stack = b.buildCallStack(/*pc=*/0x1000, regs);
    if (!stack.error.empty() || !stack.complete || stack.frames.size() != 2) {
        std::cerr << "Call stack build failed.\n";
        std::cerr << "complete=" << stack.complete << " depth=" << stack.frames.size()
                  << " error=\"" << stack.error << "\"\n";
        std::cerr << stack.toString() << "\n";
        assert(false);
    }
    assert(stack.frames[0].pc == 0x1000);
    // Next frame pc is RA-adjusted: 0x2000 - 4 = 0x1ffc
    assert(stack.frames[1].pc == 0x1ffc);

    std::cout << "CallStackBuilder CFA expression tests passed!" << std::endl;
}

void testEHFramePCRelativeEncoding() {
    std::cout << "Testing .eh_frame PC-relative pointer decoding..." << std::endl;

    // Build a minimal .eh_frame with one CIE and one FDE using a pcrel encoding for initial_location.
    // CIE augmentation: "zR" with fde_pointer_encoding = DW_EH_PE_pcrel | DW_EH_PE_udata4 (0x13).
    std::vector<uint8_t> eh;

    auto appendU8 = [&](uint8_t v) { eh.push_back(v); };
    auto appendU32 = [&](uint32_t v) { ::appendU32(eh, v); };
    auto appendULEB = [&](uint64_t v) { appendULEB128(eh, v); };
    auto appendSLEB = [&](int64_t v) {
        bool more = true;
        while (more) {
            uint8_t byte = static_cast<uint8_t>(v & 0x7f);
            bool sign = (byte & 0x40) != 0;
            v >>= 7;
            if ((v == 0 && !sign) || (v == -1 && sign)) {
                more = false;
            } else {
                byte |= 0x80;
            }
            eh.push_back(byte);
        }
    };
    auto startEntry = [&](uint32_t id_or_ptr) -> size_t {
        size_t start = eh.size();
        appendU32(0);          // length placeholder
        appendU32(id_or_ptr);  // CIE id (0) or CIE pointer
        return start;
    };
    auto finishEntry = [&](size_t start) {
        uint32_t len = static_cast<uint32_t>(eh.size() - start - 4);
        eh[start + 0] = static_cast<uint8_t>(len & 0xff);
        eh[start + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        eh[start + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        eh[start + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    };

    // CIE at offset 0.
    size_t cie_start = startEntry(0);
    appendU8(3);              // version
    // augmentation string "zR\0"
    appendU8('z'); appendU8('R'); appendU8(0);
    appendULEB(1);            // code_alignment_factor
    appendSLEB(-8);           // data_alignment_factor
    appendULEB(30);           // return_address_register
    appendULEB(1);            // augmentation length
    appendU8(0x13);           // 'R' fde_pointer_encoding = pcrel|udata4
    // no initial instructions
    finishEntry(cie_start);

    // FDE: cie_pointer is a 4-byte offset back to CIE from this field.
    size_t fde_start = startEntry(0);
    // Patch CIE pointer now that we know where it is.
    {
        uint32_t cie_ptr_field_off = static_cast<uint32_t>(fde_start + 4); // start of id field
        uint32_t rel = cie_ptr_field_off - 0; // CIE at 0
        eh[fde_start + 4] = static_cast<uint8_t>(rel & 0xff);
        eh[fde_start + 5] = static_cast<uint8_t>((rel >> 8) & 0xff);
        eh[fde_start + 6] = static_cast<uint8_t>((rel >> 16) & 0xff);
        eh[fde_start + 7] = static_cast<uint8_t>((rel >> 24) & 0xff);
    }

    const uint64_t section_base = 0x100000;
    // initial_location field starts here:
    uint64_t initial_loc_field_off = section_base + eh.size();
    const uint64_t target_pc = 0x110000;
    uint32_t rel = static_cast<uint32_t>(target_pc - initial_loc_field_off);
    appendU32(rel);           // encoded initial_location (pcrel udata4)
    appendU32(0x100);         // address_range (udata4)
    appendULEB(0);            // augmentation length (no LSDA)
    // no instructions
    finishEntry(fde_start);

    CFIParser p(eh, /*is_eh_frame=*/true, /*address_size=*/8);
    p.setSectionBaseAddress(section_base);
    assert(p.parse());

    auto fde = p.findFDE(target_pc);
    assert(fde);
    assert(fde->initial_location == target_pc);
    assert(fde->address_range == 0x100);

    std::cout << ".eh_frame PC-relative decoding tests passed!" << std::endl;
}

void testEHFrameAlignedEncoding() {
    std::cout << "Testing .eh_frame aligned pointer decoding..." << std::endl;

    // Build a minimal .eh_frame where the FDE initial_location uses DW_EH_PE_aligned|absptr (0x50).
    // This ensures decodePointer() aligns the stream offset before reading the value.
    std::vector<uint8_t> eh;

    auto appendU8 = [&](uint8_t v) { eh.push_back(v); };
    auto appendU32 = [&](uint32_t v) { ::appendU32(eh, v); };
    auto appendU64 = [&](uint64_t v) { ::appendU64(eh, v); };
    auto appendULEB = [&](uint64_t v) { appendULEB128(eh, v); };
    auto startEntry = [&](uint32_t id_or_ptr) -> size_t {
        size_t start = eh.size();
        appendU32(0);          // length placeholder
        appendU32(id_or_ptr);  // CIE id (0) or CIE pointer
        return start;
    };
    auto finishEntry = [&](size_t start) {
        uint32_t len = static_cast<uint32_t>(eh.size() - start - 4);
        eh[start + 0] = static_cast<uint8_t>(len & 0xff);
        eh[start + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        eh[start + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        eh[start + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    };

    // CIE at offset 0. Make its total size 28 bytes so the FDE starts at offset 28 (mod 8 == 4),
    // forcing misalignment of the next absptr field.
    size_t cie_start = startEntry(/*id=*/0);
    appendU8(1);         // version
    // augmentation string "zR\0"
    appendU8('z'); appendU8('R'); appendU8(0);
    appendULEB(1);       // code_alignment_factor
    appendU8(0x78);      // data_alignment_factor = -8 (SLEB128)
    appendU8(30);        // return_address_register (AArch64 LR)
    appendULEB(1);       // augmentation length
    appendU8(0x50);      // 'R' fde_pointer_encoding = aligned|absptr
    // Pad with nops until we reach offset 28.
    while (eh.size() < 28) {
        appendU8(0x00);  // DW_CFA_nop
    }
    finishEntry(cie_start);

    // FDE: cie_pointer is a 4-byte offset back to CIE from this field.
    size_t fde_start = startEntry(0);
    {
        uint32_t cie_ptr_field_off = static_cast<uint32_t>(fde_start + 4);
        uint32_t rel = cie_ptr_field_off - 0; // CIE at 0
        eh[fde_start + 4] = static_cast<uint8_t>(rel & 0xff);
        eh[fde_start + 5] = static_cast<uint8_t>((rel >> 8) & 0xff);
        eh[fde_start + 6] = static_cast<uint8_t>((rel >> 16) & 0xff);
        eh[fde_start + 7] = static_cast<uint8_t>((rel >> 24) & 0xff);
    }

    // After length+cie_ptr, offset is fde_start+8 == 36. For DW_EH_PE_aligned, the value
    // begins at the next 8-byte boundary (40), so insert 4 bytes of padding.
    appendU32(0xaaaaaaaa);                // padding
    appendU64(0x0000000000004000ULL);     // initial_location (absptr)
    appendU64(0x0000000000000100ULL);     // address_range (absptr)
    appendULEB(0);                        // augmentation data length (none)
    finishEntry(fde_start);

    CFIParser p(eh, /*is_eh_frame=*/true, /*address_size=*/8);
    assert(p.parse());

    auto fde = p.findFDE(0x4000);
    assert(fde);
    assert(fde->initial_location == 0x4000);
    assert(fde->address_range == 0x100);

    auto miss = p.findFDE(0x4100);
    assert(!miss);

    std::cout << ".eh_frame aligned decoding tests passed!" << std::endl;
}

void testEHFrameSetLocUsesCIEAddressSize() {
    std::cout << "Testing .eh_frame DW_CFA_set_loc uses CIE address_size..." << std::endl;

    // This constructs an .eh_frame where:
    // - The CIE declares address_size=4 (DWARF v4+ CIE fields)
    // - The parser is constructed with address_size=8 (typical for 64-bit objects)
    // - The FDE instruction stream contains:
    //   DW_CFA_set_loc + 4-byte address + DW_CFA_def_cfa_offset + DW_CFA_advance_loc1
    // If DW_CFA_set_loc incorrectly reads 8 bytes, it will swallow the next 4 bytes of CFA opcodes.
    std::vector<uint8_t> eh;

    auto appendU8 = [&](uint8_t v) { eh.push_back(v); };
    auto appendU32 = [&](uint32_t v) { ::appendU32(eh, v); };
    auto appendULEB = [&](uint64_t v) { appendULEB128(eh, v); };
    auto appendSLEB = [&](int64_t v) {
        bool more = true;
        while (more) {
            uint8_t byte = static_cast<uint8_t>(v & 0x7f);
            bool sign = (byte & 0x40) != 0;
            v >>= 7;
            if ((v == 0 && !sign) || (v == -1 && sign)) {
                more = false;
            } else {
                byte |= 0x80;
            }
            eh.push_back(byte);
        }
    };
    auto startEntry = [&](uint32_t id_or_ptr) -> size_t {
        size_t start = eh.size();
        appendU32(0);          // length placeholder
        appendU32(id_or_ptr);  // CIE id (0) or CIE pointer
        return start;
    };
    auto finishEntry = [&](size_t start) {
        uint32_t len = static_cast<uint32_t>(eh.size() - start - 4);
        eh[start + 0] = static_cast<uint8_t>(len & 0xff);
        eh[start + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        eh[start + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        eh[start + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    };

    // CIE at offset 0, version 4 with address_size=4.
    size_t cie_start = startEntry(0);
    appendU8(4);                 // version
    appendU8('z'); appendU8('R'); appendU8(0); // augmentation "zR"
    appendU8(4);                 // address_size
    appendU8(0);                 // segment_selector_size
    appendULEB(1);               // code_alignment_factor
    appendSLEB(-4);              // data_alignment_factor (arbitrary)
    appendULEB(30);              // return_address_register
    appendULEB(1);               // augmentation length
    appendU8(0x03);              // 'R' fde_pointer_encoding = DW_EH_PE_udata4
    finishEntry(cie_start);

    // FDE: cie_pointer is a 4-byte offset back to CIE from this field.
    size_t fde_start = startEntry(0);
    {
        uint32_t cie_ptr_field_off = static_cast<uint32_t>(fde_start + 4);
        uint32_t rel = cie_ptr_field_off - 0; // CIE at 0
        eh[fde_start + 4] = static_cast<uint8_t>(rel & 0xff);
        eh[fde_start + 5] = static_cast<uint8_t>((rel >> 8) & 0xff);
        eh[fde_start + 6] = static_cast<uint8_t>((rel >> 16) & 0xff);
        eh[fde_start + 7] = static_cast<uint8_t>((rel >> 24) & 0xff);
    }

    appendU32(0x1000); // initial_location (udata4)
    appendU32(0x20);   // address_range (udata4)
    appendULEB(0);     // augmentation data length

    // Instructions:
    // set_loc 0x1008 (4 bytes), then def_cfa_offset 0x20, then advance_loc1 1.
    appendU8(0x01);          // DW_CFA_set_loc
    appendU32(0x1008);       // address (should be 4 bytes, from CIE address_size)
    appendU8(0x0e);          // DW_CFA_def_cfa_offset
    appendU8(0x20);          // uleb 0x20
    appendU8(0x02);          // DW_CFA_advance_loc1
    appendU8(0x01);          // delta=1

    finishEntry(fde_start);

    CFIParser p(eh, /*is_eh_frame=*/true, /*address_size=*/8);
    assert(p.parse());

    // At PC 0x1009, we should have applied def_cfa_offset=0x20 after set_loc and advance_loc.
    UnwindInfo ui = p.getUnwindInfo(0x1009);
    assert(ui.valid);
    assert(ui.cfa.type == CFA_Type::REGISTER_OFFSET);
    assert(ui.cfa.offset == 0x20);

    std::cout << ".eh_frame DW_CFA_set_loc address_size tests passed!" << std::endl;
}

void testEHFrameSetLocInvalidCIEAddressSizeAbortsStream() {
    std::cout << "Testing .eh_frame DW_CFA_set_loc invalid CIE address_size aborts stream..." << std::endl;

    // Similar to testEHFrameSetLocUsesCIEAddressSize, but CIE advertises invalid address_size=3.
    // DW_CFA_set_loc should abort instruction processing rather than defaulting to 32-bit decode.
    std::vector<uint8_t> eh;

    auto appendU8 = [&](uint8_t v) { eh.push_back(v); };
    auto appendU32 = [&](uint32_t v) { ::appendU32(eh, v); };
    auto appendULEB = [&](uint64_t v) { appendULEB128(eh, v); };
    auto appendSLEB = [&](int64_t v) {
        bool more = true;
        while (more) {
            uint8_t byte = static_cast<uint8_t>(v & 0x7f);
            bool sign = (byte & 0x40) != 0;
            v >>= 7;
            if ((v == 0 && !sign) || (v == -1 && sign)) {
                more = false;
            } else {
                byte |= 0x80;
            }
            eh.push_back(byte);
        }
    };
    auto startEntry = [&](uint32_t id_or_ptr) -> size_t {
        size_t start = eh.size();
        appendU32(0);
        appendU32(id_or_ptr);
        return start;
    };
    auto finishEntry = [&](size_t start) {
        uint32_t len = static_cast<uint32_t>(eh.size() - start - 4);
        eh[start + 0] = static_cast<uint8_t>(len & 0xff);
        eh[start + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        eh[start + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        eh[start + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    };

    // CIE at offset 0, version 4 with invalid address_size=3.
    size_t cie_start = startEntry(0);
    appendU8(4);                 // version
    appendU8('z'); appendU8('R'); appendU8(0);
    appendU8(3);                 // INVALID address_size
    appendU8(0);                 // segment_selector_size
    appendULEB(1);               // code_alignment_factor
    appendSLEB(-4);              // data_alignment_factor
    appendULEB(30);              // return_address_register
    appendULEB(1);               // augmentation length
    appendU8(0x03);              // fde_pointer_encoding = DW_EH_PE_udata4
    finishEntry(cie_start);

    // FDE
    size_t fde_start = startEntry(0);
    {
        uint32_t cie_ptr_field_off = static_cast<uint32_t>(fde_start + 4);
        uint32_t rel = cie_ptr_field_off - 0;
        eh[fde_start + 4] = static_cast<uint8_t>(rel & 0xff);
        eh[fde_start + 5] = static_cast<uint8_t>((rel >> 8) & 0xff);
        eh[fde_start + 6] = static_cast<uint8_t>((rel >> 16) & 0xff);
        eh[fde_start + 7] = static_cast<uint8_t>((rel >> 24) & 0xff);
    }

    appendU32(0x1000); // initial_location (udata4)
    appendU32(0x20);   // address_range (udata4)
    appendULEB(0);     // augmentation data length

    // set_loc + def_cfa_offset. With invalid address_size, set_loc aborts stream and
    // def_cfa_offset must not be applied.
    appendU8(0x01);    // DW_CFA_set_loc
    appendU32(0x1008); // would-be address
    appendU8(0x0e);    // DW_CFA_def_cfa_offset
    appendU8(0x20);    // uleb 0x20

    finishEntry(fde_start);

    CFIParser p(eh, /*is_eh_frame=*/true, /*address_size=*/8);
    assert(p.parse());

    UnwindInfo ui = p.getUnwindInfo(0x1001);
    assert(ui.valid);
    assert(ui.cfa.type == CFA_Type::REGISTER_OFFSET);
    assert(ui.cfa.offset == 0); // default row value; def_cfa_offset was not consumed

    std::cout << ".eh_frame invalid CIE address_size tests passed!" << std::endl;
}

void testEHFrameTruncatedPersonalityDoesNotBleed() {
    std::cout << "Testing .eh_frame truncated personality augmentation does not bleed..." << std::endl;

    // Build a CIE with augmentation "zP" but truncate the personality pointer bytes.
    // The parser must not read into the next entry to satisfy the missing pointer.
    std::vector<uint8_t> eh;

    auto appendU8 = [&](uint8_t v) { eh.push_back(v); };
    auto appendU32 = [&](uint32_t v) { ::appendU32(eh, v); };
    auto appendU64 = [&](uint64_t v) { ::appendU64(eh, v); };
    auto appendULEB = [&](uint64_t v) { appendULEB128(eh, v); };
    auto appendSLEB = [&](int64_t v) {
        bool more = true;
        while (more) {
            uint8_t byte = static_cast<uint8_t>(v & 0x7f);
            bool sign = (byte & 0x40) != 0;
            v >>= 7;
            if ((v == 0 && !sign) || (v == -1 && sign)) {
                more = false;
            } else {
                byte |= 0x80;
            }
            eh.push_back(byte);
        }
    };
    auto startEntry = [&](uint32_t id_or_ptr) -> size_t {
        size_t start = eh.size();
        appendU32(0);          // length placeholder
        appendU32(id_or_ptr);  // CIE id (0) or CIE pointer
        return start;
    };
    auto finishEntry = [&](size_t start) {
        uint32_t len = static_cast<uint32_t>(eh.size() - start - 4);
        eh[start + 0] = static_cast<uint8_t>(len & 0xff);
        eh[start + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        eh[start + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        eh[start + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    };

    // CIE at offset 0.
    size_t cie_start = startEntry(0);
    appendU8(3); // version
    // augmentation "zP\0"
    appendU8('z'); appendU8('P'); appendU8(0);
    appendULEB(1);      // code_alignment_factor
    appendSLEB(-8);     // data_alignment_factor
    appendULEB(30);     // return_address_register
    appendULEB(1);      // augmentation length: only encoding byte, pointer is missing
    appendU8(0x00);     // personality encoding = DW_EH_PE_absptr (needs 8 bytes, but truncated)
    finishEntry(cie_start);

    // FDE following immediately with some non-zero bytes to detect bleed.
    size_t fde_start = startEntry(0);
    {
        uint32_t cie_ptr_field_off = static_cast<uint32_t>(fde_start + 4);
        uint32_t rel = cie_ptr_field_off - 0; // CIE at 0
        eh[fde_start + 4] = static_cast<uint8_t>(rel & 0xff);
        eh[fde_start + 5] = static_cast<uint8_t>((rel >> 8) & 0xff);
        eh[fde_start + 6] = static_cast<uint8_t>((rel >> 16) & 0xff);
        eh[fde_start + 7] = static_cast<uint8_t>((rel >> 24) & 0xff);
    }

    // If the CIE personality pointer decode incorrectly reads into this entry,
    // it would likely produce a non-zero personality routine.
    appendU64(0x1111111111111111ULL); // initial_location (absptr)
    appendU64(0x100);                 // address_range (absptr)
    appendULEB(0);                    // augmentation length
    finishEntry(fde_start);

    CFIParser p(eh, /*is_eh_frame=*/true, /*address_size=*/8);
    assert(p.parse());
    assert(!p.getCIEs().empty());
    assert(p.getCIEs()[0]->personality_routine == 0);

    auto fde = p.findFDE(0x1111111111111111ULL);
    assert(fde);
    assert(fde->initial_location == 0x1111111111111111ULL);
    assert(fde->address_range == 0x100);

    std::cout << ".eh_frame truncated personality tests passed!" << std::endl;
}

void testEHFrameTruncatedFDEPointerDoesNotReadPadding() {
    std::cout << "Testing .eh_frame truncated FDE pointer does not read into padding..." << std::endl;

    // Create a CIE that sets fde_pointer_encoding to udata8 (0x04), then an FDE whose
    // entry length truncates the initial_location to 4 bytes. Append padding after the FDE.
    // Without bounded decoding, initial_location would read those padding bytes and appear valid.
    std::vector<uint8_t> eh;

    auto appendU8 = [&](uint8_t v) { eh.push_back(v); };
    auto appendU32 = [&](uint32_t v) { ::appendU32(eh, v); };
    auto appendULEB = [&](uint64_t v) { appendULEB128(eh, v); };
    auto appendSLEB = [&](int64_t v) {
        bool more = true;
        while (more) {
            uint8_t byte = static_cast<uint8_t>(v & 0x7f);
            bool sign = (byte & 0x40) != 0;
            v >>= 7;
            if ((v == 0 && !sign) || (v == -1 && sign)) {
                more = false;
            } else {
                byte |= 0x80;
            }
            eh.push_back(byte);
        }
    };
    auto startEntry = [&](uint32_t id_or_ptr) -> size_t {
        size_t start = eh.size();
        appendU32(0);          // length placeholder
        appendU32(id_or_ptr);  // CIE id (0) or CIE pointer
        return start;
    };
    auto finishEntry = [&](size_t start) {
        uint32_t len = static_cast<uint32_t>(eh.size() - start - 4);
        eh[start + 0] = static_cast<uint8_t>(len & 0xff);
        eh[start + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        eh[start + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        eh[start + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    };

    // CIE at offset 0, version 3 with "zR".
    size_t cie_start = startEntry(0);
    appendU8(3);
    appendU8('z'); appendU8('R'); appendU8(0);
    appendULEB(1);
    appendSLEB(-8);
    appendULEB(30);
    appendULEB(1);   // augmentation length
    appendU8(0x04);  // 'R' = udata8
    finishEntry(cie_start);

    // FDE starts here; patch its CIE pointer.
    size_t fde_start = startEntry(0);
    {
        uint32_t cie_ptr_field_off = static_cast<uint32_t>(fde_start + 4);
        uint32_t rel = cie_ptr_field_off - 0;
        eh[fde_start + 4] = static_cast<uint8_t>(rel & 0xff);
        eh[fde_start + 5] = static_cast<uint8_t>((rel >> 8) & 0xff);
        eh[fde_start + 6] = static_cast<uint8_t>((rel >> 16) & 0xff);
        eh[fde_start + 7] = static_cast<uint8_t>((rel >> 24) & 0xff);
    }

    // Truncated initial_location: only 4 bytes (0x1000), encoding expects 8.
    appendU32(0x1000);
    finishEntry(fde_start);

    // Padding after the FDE.
    appendU32(0x00000000);

    CFIParser p(eh, /*is_eh_frame=*/true, /*address_size=*/8);
    assert(p.parse());
    assert(p.getFDEs().empty());

    auto fde = p.findFDE(0x1000);
    assert(!fde);

    std::cout << ".eh_frame truncated FDE pointer tests passed!" << std::endl;
}

static std::vector<uint8_t> makeDebugSupEntry(uint8_t is_supplementary,
                                              uint64_t signature,
                                              const std::string& path) {
    std::vector<uint8_t> out;
    appendU32(out, 0); // placeholder unit_length (DWARF32)

    std::vector<uint8_t> payload;
    appendU16(payload, 5); // version
    payload.push_back(is_supplementary);
    payload.push_back(0); // reserved
    appendU64(payload, signature);
    for (char c : path) payload.push_back(static_cast<uint8_t>(c));
    payload.push_back(0); // NUL

    uint32_t unit_length = static_cast<uint32_t>(payload.size());
    out[0] = static_cast<uint8_t>(unit_length & 0xff);
    out[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
    out[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
    out[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

void testSupplementaryDebugInfoViaDebugSup() {
    std::cout << "Testing supplementary .debug_info via .debug_sup..." << std::endl;

    const uint64_t sig = 0x1122334455667788ULL;

    // Sup .debug_str: "SupType"
    std::vector<uint8_t> sup_str;
    const std::string sup_type = "SupType";
    uint32_t sup_type_off = static_cast<uint32_t>(sup_str.size());
    for (char c : sup_type) sup_str.push_back(static_cast<uint8_t>(c));
    sup_str.push_back(0);

    // Sup .debug_abbrev: CU(children) + base_type(name/byte_size/encoding)
    std::vector<uint8_t> sup_abbrev;
    sup_abbrev.push_back(0x01); // code
    sup_abbrev.push_back(0x11); // DW_TAG_compile_unit
    sup_abbrev.push_back(0x01); // has children
    sup_abbrev.push_back(0x00); sup_abbrev.push_back(0x00);

    sup_abbrev.push_back(0x02); // code
    sup_abbrev.push_back(0x24); // DW_TAG_base_type
    sup_abbrev.push_back(0x00); // no children
    appendULEB128(sup_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_name));
    appendULEB128(sup_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_strp));
    appendULEB128(sup_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_byte_size));
    appendULEB128(sup_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_data1));
    appendULEB128(sup_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_encoding));
    appendULEB128(sup_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_data1));
    sup_abbrev.push_back(0x00); sup_abbrev.push_back(0x00);
    sup_abbrev.push_back(0x00);

    // Sup .debug_info: CU + child base_type at known offset, then null.
    std::vector<uint8_t> sup_info;
    appendU32(sup_info, 0); // placeholder length
    sup_info.push_back(0x04); sup_info.push_back(0x00); // version 4
    appendU32(sup_info, 0); // abbrev offset
    sup_info.push_back(0x08); // addr_size

    sup_info.push_back(0x01); // CU code
    uint32_t sup_base_type_off = static_cast<uint32_t>(sup_info.size());
    sup_info.push_back(0x02); // base_type code
    appendU32(sup_info, sup_type_off); // name strp
    sup_info.push_back(0x04); // byte_size
    sup_info.push_back(0x05); // encoding
    sup_info.push_back(0x00); // end children

    uint32_t sup_len = static_cast<uint32_t>(sup_info.size() - 4);
    sup_info[0] = static_cast<uint8_t>(sup_len & 0xff);
    sup_info[1] = static_cast<uint8_t>((sup_len >> 8) & 0xff);
    sup_info[2] = static_cast<uint8_t>((sup_len >> 16) & 0xff);
    sup_info[3] = static_cast<uint8_t>((sup_len >> 24) & 0xff);

    // Main .debug_str: "var"
    std::vector<uint8_t> main_str;
    const std::string var_name = "var";
    uint32_t var_off = static_cast<uint32_t>(main_str.size());
    for (char c : var_name) main_str.push_back(static_cast<uint8_t>(c));
    main_str.push_back(0);

    // Main .debug_abbrev: CU(children) + variable(name=strp, type=ref_sup4)
    std::vector<uint8_t> main_abbrev;
    main_abbrev.push_back(0x01);
    main_abbrev.push_back(0x11); // CU
    main_abbrev.push_back(0x01); // children
    main_abbrev.push_back(0x00); main_abbrev.push_back(0x00);

    main_abbrev.push_back(0x02);
    main_abbrev.push_back(0x34); // DW_TAG_variable
    main_abbrev.push_back(0x00); // no children
    appendULEB128(main_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_name));
    appendULEB128(main_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_strp));
    appendULEB128(main_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_type));
    appendULEB128(main_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_ref_sup4));
    main_abbrev.push_back(0x00); main_abbrev.push_back(0x00);
    main_abbrev.push_back(0x00);

    // Main .debug_info: CU + variable referencing supplementary base_type + null child.
    std::vector<uint8_t> main_info;
    appendU32(main_info, 0); // placeholder length
    main_info.push_back(0x04); main_info.push_back(0x00); // version 4
    appendU32(main_info, 0); // abbrev offset
    main_info.push_back(0x08); // addr_size

    main_info.push_back(0x01); // CU code
    main_info.push_back(0x02); // variable code
    appendU32(main_info, var_off);           // name strp
    appendU32(main_info, sup_base_type_off); // ref_sup4 to supplementary
    main_info.push_back(0x00); // end children

    uint32_t main_len = static_cast<uint32_t>(main_info.size() - 4);
    main_info[0] = static_cast<uint8_t>(main_len & 0xff);
    main_info[1] = static_cast<uint8_t>((main_len >> 8) & 0xff);
    main_info[2] = static_cast<uint8_t>((main_len >> 16) & 0xff);
    main_info[3] = static_cast<uint8_t>((main_len >> 24) & 0xff);

    std::string dir = makeTempDir("dwarf_sup_");
    std::string main_path = (std::filesystem::path(dir) / "main.elf").string();
    std::string sup_good = (std::filesystem::path(dir) / "good.sup").string();
    std::string sup_bad = (std::filesystem::path(dir) / "bad.sup").string();

    // bad.sup has a self-entry but with mismatching signature; main.elf lists it first.
    auto bad_sup = makeDebugSupEntry(/*is_supplementary=*/1, /*signature=*/0x9999999999999999ULL, "main.elf");
    writeELFWithSections(sup_bad, {
        {".debug_sup", bad_sup},
        {".debug_info", sup_info},
        {".debug_abbrev", sup_abbrev},
        {".debug_str", sup_str},
    });

    // good.sup has matching signature and content.
    auto good_sup = makeDebugSupEntry(/*is_supplementary=*/1, /*signature=*/sig, "main.elf");
    writeELFWithSections(sup_good, {
        {".debug_sup", good_sup},
        {".debug_info", sup_info},
        {".debug_abbrev", sup_abbrev},
        {".debug_str", sup_str},
    });

    // main .debug_sup contains two entries, bad first then good (relative paths).
    std::vector<uint8_t> main_sup;
    auto e1 = makeDebugSupEntry(/*is_supplementary=*/0, /*signature=*/sig, "bad.sup");
    auto e2 = makeDebugSupEntry(/*is_supplementary=*/0, /*signature=*/sig, "good.sup");
    main_sup.insert(main_sup.end(), e1.begin(), e1.end());
    main_sup.insert(main_sup.end(), e2.begin(), e2.end());

    writeELFWithSections(main_path, {
        {".debug_info", main_info},
        {".debug_abbrev", main_abbrev},
        {".debug_str", main_str},
        {".debug_sup", main_sup},
    });

    DwarfParser parser(main_path);
    assert(parser.load());

    // Ensure supplementary type DIE was loaded and can be found by name.
    auto dies = parser.findDIEsByName(sup_type);
    bool found = false;
    for (const auto& die : dies) {
        if (die && die->getTag() == DwarfTag::DW_TAG_base_type) {
            found = true;
            break;
        }
    }
    assert(found);

    // Ensure the variable's DW_AT_type resolves to the supplementary DIE offset namespace.
    auto vars = parser.findDIEsByName(var_name);
    assert(!vars.empty());
    auto vdie = vars[0];
    assert(vdie);
    auto type_attr = vdie->getAttribute(DwarfAttribute::DW_AT_type);
    auto type_val = std::dynamic_pointer_cast<TypeAttributeValue>(type_attr);
    assert(type_val);
    auto type_die = parser.getType(type_val->getOffset());
    assert(type_die);
    assert(type_die->getName() == sup_type);

    std::cout << "Supplementary .debug_sup integration tests passed!" << std::endl;
}

void testTypeSystem() {
    std::cout << "Testing TypeSystem..." << std::endl;
    
    TypeSystem type_system;
    
    // Test primitive type creation
    auto int_type = type_system.createPrimitiveType(PrimitiveType::Kind::INTEGER, 4, "int");
    assert(int_type->getName() == "int");
    assert(int_type->getSize() == 4);
    assert(int_type->isComplete());
    
    // Test pointer type creation
    auto int_ptr_type = type_system.createPointerType(int_type);
    assert(int_ptr_type->getName() == "int*");
    assert(int_ptr_type->getSize() == sizeof(void*));

    // Test tag-based queries
    {
        auto ptr_types = type_system.getTypesByTag(DwarfTag::DW_TAG_pointer_type);
        bool found = false;
        for (const auto& t : ptr_types) {
            if (t == int_ptr_type) {
                found = true;
                break;
            }
        }
        assert(found);
    }
    
    // Test array type creation
    std::vector<uint64_t> dimensions = {10, 20};
    auto int_array_type = type_system.createArrayType(int_type, dimensions);
    assert(int_array_type->getName() == "int[10][20]");
    assert(int_array_type->getSize() == 4 * 10 * 20);
    // Note: getElementCount() method doesn't exist, using dimensions instead
    auto array_type_ptr = std::dynamic_pointer_cast<ArrayType>(int_array_type);
    assert(array_type_ptr->getDimensions().size() == 2);
    
    // Test function type creation
    std::vector<std::shared_ptr<Type>> param_types = {int_type};
    auto func_type = type_system.createFunctionType(int_type, param_types, false);
    assert(func_type->getName() == "int(int)");
    // Note: These methods don't exist on the base Type class
    // We need to cast to FunctionType to access them
    auto func_type_ptr = std::dynamic_pointer_cast<FunctionType>(func_type);
    assert(func_type_ptr->getParameterTypes().size() == 1);
    assert(!func_type_ptr->isVariadic());
    
    // Test composite type creation
    auto struct_type = std::dynamic_pointer_cast<CompositeType>(
        type_system.createCompositeType(CompositeType::Kind::STRUCT, "Point", 8));
    assert(struct_type->getName() == "Point");
    assert(struct_type->getSize() == 8);
    
    struct_type->addMember("x", int_type, 0);
    struct_type->addMember("y", int_type, 4);
    assert(struct_type->getMembers().size() == 2);
    assert(struct_type->getMemberType("x") == int_type);
    assert(struct_type->getMemberOffset("x") == 0);
    assert(struct_type->getMemberOffset("y") == 4);
    
    // Test enum type creation
    auto enum_type = std::dynamic_pointer_cast<EnumType>(
        type_system.createEnumType("Color", int_type));
    assert(enum_type->getName() == "Color");
    assert(enum_type->getSize() == 4);
    
    enum_type->addEnumerator("RED", 0);
    enum_type->addEnumerator("GREEN", 1);
    enum_type->addEnumerator("BLUE", 2);
    assert(enum_type->getEnumerators().size() == 3);
    assert(enum_type->getEnumeratorName(0) == "RED");
    assert(enum_type->getEnumeratorName(1) == "GREEN");
    assert(enum_type->getEnumeratorName(2) == "BLUE");
    
    std::cout << "TypeSystem tests passed!" << std::endl;
}

void testRngListsParser() {
    std::cout << "Testing RngListsParser..." << std::endl;

    // Build a synthetic .debug_rnglists section
    // Header (DWARF 32-bit):
    //   unit_length (4 bytes)
    //   version (2 bytes): 5
    //   address_size (1 byte): 8
    //   segment_selector_size (1 byte): 0
    //   offset_entry_count (4 bytes): 2
    //   offsets[0] (4 bytes): offset to first list (relative to rnglists_base)
    //   offsets[1] (4 bytes): offset to second list (relative to rnglists_base)
    // Then range list entries...
    //
    // Byte layout:
    //   0-3:   unit_length
    //   4-5:   version
    //   6:     address_size
    //   7:     segment_selector_size
    //   8-11:  offset_entry_count
    //   12-15: offset[0] = 8 (list 0 at byte 12 + 8 = 20)
    //   16-19: offset[1] = 26 (0x1a) (list 1 at byte 12 + 26 = 38)
    //   20:    DW_RLE_start_end (list 0)
    //   21-28: start address (8 bytes)
    //   29-36: end address (8 bytes)
    //   37:    DW_RLE_end_of_list
    //   38:    DW_RLE_offset_pair (list 1)
    //   ...

    std::vector<uint8_t> debug_rnglists = {
        // Unit length (4 bytes, excludes itself)
        0x38, 0x00, 0x00, 0x00,
        // Version (2 bytes)
        0x05, 0x00,
        // Address size (1 byte)
        0x08,
        // Segment selector size (1 byte)
        0x00,
        // Offset entry count (4 bytes) - 2 entries
        0x02, 0x00, 0x00, 0x00,
        // Offset table (2 x 4 bytes each)
        // Offsets are relative to rnglists_base (byte 12)
        0x08, 0x00, 0x00, 0x00,  // offset[0] = 8 -> list 0 at byte 20
        0x1a, 0x00, 0x00, 0x00,  // offset[1] = 26 -> list 1 at byte 38

        // List 0 at byte 20 (rnglists_base + 8 = 12 + 8)
        // DW_RLE_start_end (17 bytes total: 1 + 8 + 8)
        static_cast<uint8_t>(DW_RLE::DW_RLE_start_end),
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // start = 0x1000
        0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // end = 0x2000
        // DW_RLE_end_of_list (1 byte)
        static_cast<uint8_t>(DW_RLE::DW_RLE_end_of_list),

        // List 1 at byte 38 (rnglists_base + 26 = 12 + 26)
        // DW_RLE_offset_pair (requires base address)
        static_cast<uint8_t>(DW_RLE::DW_RLE_offset_pair),
        0x00,  // start offset = 0 (ULEB128)
        0x10,  // end offset = 16 (ULEB128)
        // DW_RLE_offset_pair
        static_cast<uint8_t>(DW_RLE::DW_RLE_offset_pair),
        0x20,  // start offset = 32 (ULEB128)
        0x40,  // end offset = 64 (ULEB128)
        // DW_RLE_end_of_list
        static_cast<uint8_t>(DW_RLE::DW_RLE_end_of_list)
    };

    RngListsParser parser(debug_rnglists);

    // Test header parsing
    uint64_t offset = 0;
    auto header = parser.parseHeader(offset);
    assert(header.has_value());
    assert(header->version == 5);
    assert(header->address_size == 8);
    assert(header->segment_selector_size == 0);
    assert(header->offset_entry_count == 2);
    assert(!header->is_dwarf64);

    // Test parsing first range list (DW_RLE_start_end)
    // List 0 is at rnglists_base (12) + offset[0] (8) = 20
    auto ranges = parser.parseRangeList(20, 0, 8);
    assert(ranges.size() == 1);  // One actual range (end_of_list not included)
    assert(ranges[0].type == DW_RLE::DW_RLE_start_end);
    assert(ranges[0].start == 0x1000);
    assert(ranges[0].end == 0x2000);

    // Test parsing second range list (DW_RLE_offset_pair with base address)
    // List 1 is at rnglists_base (12) + offset[1] (26) = 38
    uint64_t base_address = 0x5000;
    auto ranges2 = parser.parseRangeList(38, base_address, 8);
    assert(ranges2.size() == 2);  // Two offset_pair entries
    assert(ranges2[0].type == DW_RLE::DW_RLE_offset_pair);
    assert(ranges2[0].start == 0x5000 + 0);    // base + 0
    assert(ranges2[0].end == 0x5000 + 16);     // base + 16
    assert(ranges2[1].type == DW_RLE::DW_RLE_offset_pair);
    assert(ranges2[1].start == 0x5000 + 32);   // base + 32
    assert(ranges2[1].end == 0x5000 + 64);     // base + 64

    // Test resolveRngListx
    uint64_t resolved0 = parser.resolveRngListx(0, 0, 12, false);  // rnglists_base=12
    assert(resolved0 == 20);  // 12 + 8 = 20

    uint64_t resolved1 = parser.resolveRngListx(1, 0, 12, false);
    assert(resolved1 == 38);  // 12 + 26 = 38

    std::cout << "RngListsParser tests passed!" << std::endl;
}

void testLocListsParser() {
    std::cout << "Testing LocListsParser..." << std::endl;

    // Build a synthetic .debug_loclists section
    std::vector<uint8_t> debug_loclists = {
        // Unit length (4 bytes)
        0x40, 0x00, 0x00, 0x00,
        // Version (2 bytes)
        0x05, 0x00,
        // Address size (1 byte)
        0x08,
        // Segment selector size (1 byte)
        0x00,
        // Offset entry count (4 bytes) - 1 entry
        0x01, 0x00, 0x00, 0x00,
        // Offset table (1 x 4 bytes)
        0x04, 0x00, 0x00, 0x00,  // offset to list 0 = 4

        // List 0 at offset 4 from offsets array (absolute: 12 + 4 = 16)
        // DW_LLE_start_end with expression
        static_cast<uint8_t>(DW_LLE::DW_LLE_start_end),
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // start = 0x1000
        0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // end = 0x2000
        0x05,  // expression length = 5 (ULEB128)
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        0x00, 0x30, 0x00, 0x00,  // constant 0x3000

        // DW_LLE_offset_pair with expression
        static_cast<uint8_t>(DW_LLE::DW_LLE_offset_pair),
        0x00,  // start offset = 0 (ULEB128)
        0x10,  // end offset = 16 (ULEB128)
        0x02,  // expression length = 2 (ULEB128)
        static_cast<uint8_t>(DwarfOp::DW_OP_reg0),  // in register 0
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),

        // DW_LLE_end_of_list
        static_cast<uint8_t>(DW_LLE::DW_LLE_end_of_list)
    };

    LocListsParser parser(debug_loclists);

    // Test header parsing
    uint64_t offset = 0;
    auto header = parser.parseHeader(offset);
    assert(header.has_value());
    assert(header->version == 5);
    assert(header->address_size == 8);
    assert(header->segment_selector_size == 0);
    assert(header->offset_entry_count == 1);
    assert(!header->is_dwarf64);

    // Test parsing location list
    // List is at offset 12 + 4 = 16
    auto locations = parser.parseLocationList(16, 0, 8);
    assert(locations.size() >= 1);

    // First entry should be DW_LLE_start_end
    assert(locations[0].type == DW_LLE::DW_LLE_start_end);
    assert(locations[0].start == 0x1000);
    assert(locations[0].end == 0x2000);
    assert(locations[0].expression.size() == 5);
    assert(locations[0].expression[0] == static_cast<uint8_t>(DwarfOp::DW_OP_const4u));

    // Second entry should be DW_LLE_offset_pair (with base 0)
    if (locations.size() >= 2) {
        assert(locations[1].type == DW_LLE::DW_LLE_offset_pair);
        assert(locations[1].start == 0);
        assert(locations[1].end == 16);
        assert(locations[1].expression.size() == 2);
        assert(locations[1].expression[0] == static_cast<uint8_t>(DwarfOp::DW_OP_reg0));
    }

    // Test resolveLocListx
    uint64_t resolved = parser.resolveLocListx(0, 0, 12, false);  // header_offset=0, loclists_base=12
    assert(resolved == 16);  // 12 + 4 = 16

    std::cout << "LocListsParser tests passed!" << std::endl;
}

void testLocationAttributeValue() {
    std::cout << "Testing LocationAttributeValue..." << std::endl;

    // Test single expression location
    std::vector<uint8_t> expr = {
        static_cast<uint8_t>(DwarfOp::DW_OP_reg0)
    };
    LocationAttributeValue single_loc(LocationAttributeValue::LocationType::EXPRESSION, expr);

    assert(single_loc.getLocationType() == LocationAttributeValue::LocationType::EXPRESSION);
    assert(single_loc.getData().size() == 1);
    assert(single_loc.containsPC(0x1000));  // Single expression covers all PCs
    assert(single_loc.getExpressionForPC(0x1000) == expr);

    // Test location list with multiple entries
    std::vector<LocationAttributeValue::LocationEntry> entries;

    // Entry 1: 0x1000-0x2000, expression = DW_OP_reg0
    std::vector<uint8_t> expr1 = {static_cast<uint8_t>(DwarfOp::DW_OP_reg0)};
    entries.emplace_back(0x1000, 0x2000, expr1, false);

    // Entry 2: 0x2000-0x3000, expression = DW_OP_reg1
    std::vector<uint8_t> expr2 = {static_cast<uint8_t>(DwarfOp::DW_OP_reg1)};
    entries.emplace_back(0x2000, 0x3000, expr2, false);

    // Entry 3: 0x4000-0x5000, expression = DW_OP_fbreg + offset
    std::vector<uint8_t> expr3 = {
        static_cast<uint8_t>(DwarfOp::DW_OP_fbreg),
        0x10  // offset = 16
    };
    entries.emplace_back(0x4000, 0x5000, expr3, false);

    LocationAttributeValue list_loc(entries);

    assert(list_loc.getLocationType() == LocationAttributeValue::LocationType::LIST);
    assert(list_loc.getEntries().size() == 3);

    // Test PC lookups
    assert(list_loc.containsPC(0x1000));   // In first range
    assert(list_loc.containsPC(0x1500));   // In first range
    assert(!list_loc.containsPC(0x0500));  // Before any range
    assert(list_loc.containsPC(0x2000));   // Start of second range
    assert(list_loc.containsPC(0x2500));   // In second range
    assert(!list_loc.containsPC(0x3500));  // Gap between ranges
    assert(list_loc.containsPC(0x4000));   // Start of third range

    // Test expression retrieval
    auto result1 = list_loc.getExpressionForPC(0x1500);
    assert(result1.size() == 1);
    assert(result1[0] == static_cast<uint8_t>(DwarfOp::DW_OP_reg0));

    auto result2 = list_loc.getExpressionForPC(0x2500);
    assert(result2.size() == 1);
    assert(result2[0] == static_cast<uint8_t>(DwarfOp::DW_OP_reg1));

    auto result3 = list_loc.getExpressionForPC(0x4500);
    assert(result3.size() == 2);
    assert(result3[0] == static_cast<uint8_t>(DwarfOp::DW_OP_fbreg));

    // Test no match
    auto no_match = list_loc.getExpressionForPC(0x3500);
    assert(no_match.empty());

    // Test default location
    std::vector<LocationAttributeValue::LocationEntry> entries_with_default;
    entries_with_default.emplace_back(0x1000, 0x2000, expr1, false);
    std::vector<uint8_t> default_expr = {static_cast<uint8_t>(DwarfOp::DW_OP_reg5)};
    entries_with_default.emplace_back(0, 0, default_expr, true);  // Default location

    LocationAttributeValue default_loc(entries_with_default);

    // Default should be returned when no specific range matches
    auto default_result = default_loc.getExpressionForPC(0x5000);
    assert(default_result.size() == 1);
    assert(default_result[0] == static_cast<uint8_t>(DwarfOp::DW_OP_reg5));

    // Specific range should still take precedence
    auto specific_result = default_loc.getExpressionForPC(0x1500);
    assert(specific_result.size() == 1);
    assert(specific_result[0] == static_cast<uint8_t>(DwarfOp::DW_OP_reg0));

    std::cout << "LocationAttributeValue tests passed!" << std::endl;
}

void testAttributeValues() {
    std::cout << "Testing AttributeValues..." << std::endl;
    
    // Test unsigned attribute value
    auto unsigned_attr = std::make_shared<UnsignedAttributeValue>(42);
    assert(unsigned_attr->getType() == AttributeValueType::UNSIGNED);
    assert(unsigned_attr->getValue() == 42);
    assert(unsigned_attr->toString() == "42");
    
    // Test signed attribute value
    auto signed_attr = std::make_shared<SignedAttributeValue>(-42);
    assert(signed_attr->getType() == AttributeValueType::SIGNED);
    assert(signed_attr->getValue() == -42);
    assert(signed_attr->toString() == "-42");
    
    // Test string attribute value
    auto string_attr = std::make_shared<StringAttributeValue>("hello");
    assert(string_attr->getType() == AttributeValueType::STRING);
    assert(string_attr->getValue() == "hello");
    assert(string_attr->toString() == "hello");
    
    // Test reference attribute value
    auto ref_attr = std::make_shared<ReferenceAttributeValue>(0x1234);
    assert(ref_attr->getType() == AttributeValueType::REFERENCE);
    assert(ref_attr->getOffset() == 0x1234);
    assert(ref_attr->toString() == "ref: 0x1234");
    
    // Test flag attribute value
    auto flag_attr = std::make_shared<FlagAttributeValue>(true);
    assert(flag_attr->getType() == AttributeValueType::FLAG);
    assert(flag_attr->getValue() == true);
    assert(flag_attr->toString() == "true");
    
    // Test address attribute value
    auto addr_attr = std::make_shared<AddressAttributeValue>(0x5678);
    assert(addr_attr->getType() == AttributeValueType::ADDRESS);
    assert(addr_attr->getAddress() == 0x5678);
    assert(addr_attr->toString() == "0x5678");
    
    std::cout << "AttributeValues tests passed!" << std::endl;
}

int main() {
    std::cout << "Running DWARF Parser Tests..." << std::endl;
    std::cout << "================================" << std::endl;
    
    try {
	    testDwarfUtils();
	    testExpressionEvaluator();
	    testExpressionEvaluatorUnsupportedOp();
	    testExpressionEvaluatorImplicitPiece();
    testExpressionEvaluatorTypedOpsUseCUBaseOffset();
    testExpressionEvaluatorTypedOpsMaskNonIntegerTypes();
    testExpressionEvaluatorConstTypeProvidesImplicitBytesForPiece();
    testExpressionEvaluatorPieceTruncatesImplicitBytes();
    testExpressionEvaluatorDerefEndianness();
    testExpressionEvaluatorImplicitValueEndianness();
    testExpressionEvaluatorPieceImplicitBytesEndianness();
    testExpressionEvaluatorConstTypeEndianness();
    testExpressionEvaluatorGnuEncodedAddr();
    testExpressionEvaluatorBranchLoopIsGuarded();
    testExpressionEvaluatorTlsAddressOps();
    testExpressionEvaluatorCallRefUsesSectionOffsetNotCUOffset();
    testExpressionEvaluatorGnuParameterRefRespectsOffsetSize64();
    testExpressionEvaluatorSectionRelativeOpsPreserveDWOBias();
	    testExpressionEvaluatorSectionRelativeOpsPreserveSupplementaryBias();
	    testExpressionEvaluatorMixedSectionRelativeOpsUnderDWOBias();
	    testExpressionEvaluatorSectionRelativeOpsIgnoreHighBitsWhenUnbiased();
	    testVariableLocationCompositeBitPieceOffsets();
	    testSymbolicExpressionEvaluatorBasic();
	    testSymbolicExpressionEvaluatorMalformedOperands();
	    testSymbolicExpressionEvaluatorLoad();
	    testSymbolicExpressionEvaluatorPieces();
	    testSymbolicExpressionEvaluatorUnavailablePieces();
	    testSymbolicExpressionEvaluatorStackValuePieces();
	    testSymbolicExpressionEvaluatorAddrxConstx();
	    testSymbolicExpressionEvaluatorEntryValue();
	    testSymbolicExpressionEvaluatorImplicitValueLarge();
	    testSymbolicExpressionEvaluatorBytesComparisons();
	    testSymbolicExpressionEvaluatorImplicitBytesDoNotBleed();
	    testSymbolicExpressionEvaluatorImplicitBytesPerStackEntryOps();
	    testSymbolicExpressionEvaluatorStackKindsPerEntryOps();
	    testSymbolicExpressionEvaluatorComputationMaterializationAndKinds();
	    testSymbolicExpressionEvaluatorImplicitPointer();
	    testSymbolicExpressionEvaluatorTypedOpsAndBranches();
	    testSymbolicExpressionEvaluatorSymbolicBraITE();
	    testSymbolicExpressionEvaluatorSymbolicBraDepthLimit();
	    testSymbolicExpressionEvaluatorSymbolicBraWithStackState();
	    testSymbolicExpressionEvaluatorSymbolicBraCompositePieces();
	    testSymbolicExpressionEvaluatorSymbolicBraRegisterMismatchIsInvalid();
	    testSymbolicExpressionEvaluatorSymbolicBraAddressValueMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraRegisterValueMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraRegisterAddressMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraRegisterSameMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraCompositeKindMismatchMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraCompositeUnavailableMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraCompositeBitPieceUnavailableMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraCompositeImplicitMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraCompositeImplicitMergeLargeBytes();
	    testSymbolicExpressionEvaluatorSymbolicBraCompositeImplicitNestedMerge();
	    testSymbolicExpressionEvaluatorXderefAndXderefType();
	    testSymbolicExpressionEvaluatorCallOpsAndGnuIndices();
	    testSymbolicExpressionEvaluatorGnuTypedAndParameterOps();
	    testExpressionVerifier();
	    testCrossBinaryExpressionComparator();
	    testAttributeParserBoundedStringsAndBlocks();
	    testStrpSup();
	    testRefSupForms();
	    testDIEParserRefSupIntegration();
	    testDIEParserCUBoundsOnUnterminatedFormString();
	    testDIEParserTruncatedAbbrevImplicitConst();
    testDebugSupParser();
    testDebugNamesParser();
    testDebugNamesParserBucketLookup();
    testDebugNamesParserMalformedInputs();
	    testDebugMacroParser();
	    testDwarfParserMacroLookupFallsBackAcrossCUs();
	    testDwarfParserGetFunctionAtUsesRanges();
	    testDebugLineV4ViaStmtList();
    testDebugLineV5ViaStmtList();
    testStrxBasePointsToContributionHeader();
    testStrxContributionBoundsWhenBasePointsToTableStart();
    testAddrxBasePointsToContributionHeader();
    testAddrxContributionBoundsWhenBasePointsToTableStart();
    testRnglistxBasePointsToContributionHeader();
    testRnglistxContributionBoundsWhenBasePointsToTableStart();
    testLoclistxBasePointsToContributionHeader();
    testLoclistxContributionBoundsWhenBasePointsToTableStart();
    testRnglistsParseDoesNotRunPastContributionEnd();
    testLoclistsParseDoesNotRunPastContributionEnd();
    testRnglistsSegmentSelectorSizeIsSkipped();
    testLoclistsSegmentSelectorSizeIsSkipped();
    testRnglistsBaseAddressxDoesNotReadPastDebugAddrContribution();
    testLoclistsBaseAddressxDoesNotReadPastDebugAddrContribution();
    testVariableLocationEvaluatorLoclistAddressSize();
	    testCFIParserAArch64MinimalUnwind();
	    testCFIParserAArch64NegateRAStateStripsPAC();
		    testCFIParserTruncatedInstructionDoesNotCrash();
		    testCFIParserRejectsMalformedCIEHeader();
		    testCFIParserTruncatedFDEOperandDoesNotMutateRow();
		    testCFIParserRejectsMalformedFDEAugmentationLength();
		    testCFIParserMIPSAdvanceLoc8DoesNotAbort();
		    testCFIParserDwarf2EscapeIsSkipped();
		    testCFIParserCFAExpressionThenDefCFARegisterOffsetSwitchesBack();
	    testCFIParserUnknownOpcodeAbortsInstructionStream();
	    testUnwindInfoValExpressionMemoryEndianness();
	    testSymbolicCFIVerifier();
		    testDWPIndexParsing();
    testImplicitConstInAbbrev();
    testRefAddrBiasForDWO();
    testDwarf5SecOffsetLoclistsAndRnglists();
    testDwarf4SecOffsetDebugLocAndRanges();
    testDwarf64LoclistxRnglistxOffsetSize();
    testSplitDwarfIntegrationELFIO();
    testSplitDwarfDWOAddrxUsesDWODebugAddr();
    testTypedOpsTypedefChainViaDwarfParser();
	    testCallStackAArch64CFAExpressionUnwind();
	    testEHFramePCRelativeEncoding();
	    testEHFrameAlignedEncoding();
	    testEHFrameSetLocUsesCIEAddressSize();
	    testEHFrameSetLocInvalidCIEAddressSizeAbortsStream();
	    testEHFrameTruncatedPersonalityDoesNotBleed();
	    testEHFrameTruncatedFDEPointerDoesNotReadPadding();
	    testSupplementaryDebugInfoViaDebugSup();
    testTypeSystem();
        testRngListsParser();
        testLocListsParser();
        testLocationAttributeValue();
        testAttributeValues();
        
        std::cout << "\nAll tests passed!" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed with unknown exception" << std::endl;
        return 1;
    }
}
