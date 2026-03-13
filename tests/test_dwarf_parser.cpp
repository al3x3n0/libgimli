#include "dwarf_parser.hpp"
#include "type_system.hpp"
#include "expression_evaluator.hpp"
#include "symbolic_expression.hpp"
#include "symbolic_verifier.hpp"
#include "smt_verifier.hpp"
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
#include "type_printer.hpp"
#include <fstream>
#include <iostream>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <random>
#include <sstream>
#include <unordered_map>

using namespace dwarf;

static void appendU64(std::vector<uint8_t>& out, uint64_t v);
static void appendU32(std::vector<uint8_t>& out, uint32_t v);
static void appendU16(std::vector<uint8_t>& out, uint16_t v);
static void appendULEB(std::vector<uint8_t>& out, uint64_t v);
static std::vector<uint8_t> loadTestDataBinary(const std::string& filename);

void testDwarfUtils() {
    std::cout << "Testing DwarfUtils..." << std::endl;

    // Test tag conversion
    assert(DwarfUtils::tagToString(DwarfTag::DW_TAG_compile_unit) == "DW_TAG_compile_unit");
    assert(DwarfUtils::tagToString(DwarfTag::DW_TAG_subprogram) == "DW_TAG_subprogram");
    assert(DwarfUtils::tagToString(DwarfTag::DW_TAG_string_type) == "DW_TAG_string_type");
    assert(DwarfUtils::tagToString(DwarfTag::DW_TAG_set_type) == "DW_TAG_set_type");
    assert(DwarfUtils::tagToString(DwarfTag::DW_TAG_file_type) == "DW_TAG_file_type");
    assert(DwarfUtils::tagToString(DwarfTag::DW_TAG_interface_type) == "DW_TAG_interface_type");
    assert(DwarfUtils::tagToString(DwarfTag::DW_TAG_ptr_to_member_type) == "DW_TAG_ptr_to_member_type");
    assert(DwarfUtils::stringToTag("DW_TAG_string_type") == DwarfTag::DW_TAG_string_type);
    assert(DwarfUtils::stringToTag("DW_TAG_set_type") == DwarfTag::DW_TAG_set_type);
    assert(DwarfUtils::stringToTag("DW_TAG_file_type") == DwarfTag::DW_TAG_file_type);
    assert(DwarfUtils::stringToTag("DW_TAG_interface_type") == DwarfTag::DW_TAG_interface_type);
    assert(DwarfUtils::stringToTag("DW_TAG_ptr_to_member_type") == DwarfTag::DW_TAG_ptr_to_member_type);

    // Test attribute conversion
    assert(DwarfUtils::attributeToString(DwarfAttribute::DW_AT_name) == "DW_AT_name");
    assert(DwarfUtils::attributeToString(DwarfAttribute::DW_AT_type) == "DW_AT_type");
    assert(DwarfUtils::stringToAttribute("DW_AT_name") == DwarfAttribute::DW_AT_name);

    // Test form conversion
    assert(DwarfUtils::formToString(DwarfForm::DW_FORM_strp) == "DW_FORM_strp");
    assert(DwarfUtils::stringToForm("DW_FORM_strp") == DwarfForm::DW_FORM_strp);
    assert(DwarfUtils::formToString(DwarfForm::DW_FORM_GNU_strp_alt) == "DW_FORM_GNU_strp_alt");
    assert(DwarfUtils::stringToForm("DW_FORM_GNU_strp_alt") == DwarfForm::DW_FORM_GNU_strp_alt);
    assert(DwarfUtils::formToString(DwarfForm::DW_FORM_GNU_ref_alt) == "DW_FORM_GNU_ref_alt");
    assert(DwarfUtils::stringToForm("DW_FORM_GNU_ref_alt") == DwarfForm::DW_FORM_GNU_ref_alt);
    assert(DwarfUtils::formToString(DwarfForm::DW_FORM_GNU_str_index) == "DW_FORM_GNU_str_index");
    assert(DwarfUtils::stringToForm("DW_FORM_GNU_str_index") == DwarfForm::DW_FORM_GNU_str_index);
    assert(DwarfUtils::formToString(DwarfForm::DW_FORM_GNU_addr_index) == "DW_FORM_GNU_addr_index");
    assert(DwarfUtils::stringToForm("DW_FORM_GNU_addr_index") == DwarfForm::DW_FORM_GNU_addr_index);
    for (int i = 0; i <= 0xff; ++i) {
        auto f = static_cast<DwarfForm>(static_cast<uint8_t>(i));
        std::string name = DwarfUtils::formToString(f);
        if (name.rfind("DW_FORM_unknown_", 0) == 0) continue;
        assert(DwarfUtils::stringToForm(name) == f);
    }

    // Test operation conversion
    assert(DwarfUtils::operationToString(DwarfOp::DW_OP_const1u) == "DW_OP_const1u");
    assert(DwarfUtils::stringToOperation("DW_OP_const1u") == DwarfOp::DW_OP_const1u);
    assert(DwarfUtils::operationToString(DwarfOp::DW_OP_addrx) == "DW_OP_addrx");
    assert(DwarfUtils::stringToOperation("DW_OP_addrx") == DwarfOp::DW_OP_addrx);
    assert(DwarfUtils::operationToString(DwarfOp::DW_OP_constx) == "DW_OP_constx");
    assert(DwarfUtils::stringToOperation("DW_OP_constx") == DwarfOp::DW_OP_constx);
    assert(DwarfUtils::operationToString(DwarfOp::DW_OP_entry_value) == "DW_OP_entry_value");
    assert(DwarfUtils::stringToOperation("DW_OP_entry_value") == DwarfOp::DW_OP_entry_value);
    assert(DwarfUtils::operationToString(DwarfOp::DW_OP_const_type) == "DW_OP_const_type");
    assert(DwarfUtils::stringToOperation("DW_OP_const_type") == DwarfOp::DW_OP_const_type);
    assert(DwarfUtils::operationToString(DwarfOp::DW_OP_regval_type) == "DW_OP_regval_type");
    assert(DwarfUtils::stringToOperation("DW_OP_regval_type") == DwarfOp::DW_OP_regval_type);
    assert(DwarfUtils::operationToString(DwarfOp::DW_OP_deref_type) == "DW_OP_deref_type");
    assert(DwarfUtils::stringToOperation("DW_OP_deref_type") == DwarfOp::DW_OP_deref_type);
    assert(DwarfUtils::operationToString(DwarfOp::DW_OP_xderef_type) == "DW_OP_xderef_type");
    assert(DwarfUtils::stringToOperation("DW_OP_xderef_type") == DwarfOp::DW_OP_xderef_type);
    assert(DwarfUtils::operationToString(DwarfOp::DW_OP_form_tls_address) == "DW_OP_form_tls_address");
    assert(DwarfUtils::stringToOperation("DW_OP_form_tls_address") == DwarfOp::DW_OP_form_tls_address);
    assert(DwarfUtils::operationToString(DwarfOp::DW_OP_WASM_location) == "DW_OP_WASM_location");
    assert(DwarfUtils::stringToOperation("DW_OP_WASM_location") == DwarfOp::DW_OP_WASM_location);
    assert(DwarfUtils::operationToString(DwarfOp::DW_OP_GNU_addr_index) == "DW_OP_GNU_addr_index");
    assert(DwarfUtils::stringToOperation("DW_OP_GNU_addr_index") == DwarfOp::DW_OP_GNU_addr_index);
    assert(DwarfUtils::stringToOperation("DW_OP_dup") == DwarfOp::DW_OP_dup);
    assert(DwarfUtils::stringToOperation("DW_OP_xor") == DwarfOp::DW_OP_xor);
    assert(DwarfUtils::stringToOperation("DW_OP_lit15") == DwarfOp::DW_OP_lit15);
    assert(DwarfUtils::stringToOperation("DW_OP_reg7") == DwarfOp::DW_OP_reg7);
    assert(DwarfUtils::stringToOperation("DW_OP_breg12") == DwarfOp::DW_OP_breg12);
    assert(DwarfUtils::stringToOperation("DW_OP_lit32") == static_cast<DwarfOp>(0));
    for (int i = 0; i <= 0xff; ++i) {
        auto op = static_cast<DwarfOp>(static_cast<uint8_t>(i));
        std::string name = DwarfUtils::operationToString(op);
        if (name.rfind("DW_OP_unknown_", 0) == 0) continue;
        assert(DwarfUtils::stringToOperation(name) == op);
    }

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
    {
        // GNU predecessor of DW_OP_addrx should consume its ULEB operand when tokenizing.
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_addr_index), 0x00, // uleb 0
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x2a
        };
        auto toks = DwarfUtils::expressionToTokens(expr);
        assert(toks.size() == 2);
        assert(toks[0] == "DW_OP_GNU_addr_index");
        assert(toks[1] == "DW_OP_const1u");
    }
    {
        // Unknown opcodes should preserve the raw opcode byte in utility decoding.
        std::vector<uint8_t> expr = {0xff, static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x2a};
        auto toks = DwarfUtils::expressionToTokens(expr);
        assert(toks.size() == 2);
        assert(toks[0] == "DW_OP_unknown_0xff");
        assert(toks[1] == "DW_OP_const1u");
        auto asm_s = DwarfUtils::expressionToAssembly(expr);
        assert(asm_s.find("DW_OP_unknown_0xff") != std::string::npos);
    }
    {
        // implicit_pointer should consume both DIE ref and SLEB displacement.
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_implicit_pointer),
            0x78, 0x56, 0x34, 0x12, // 32-bit ref
            0x7f,                    // SLEB128(-1)
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x2a
        };
        auto toks = DwarfUtils::expressionToTokens(expr);
        assert(toks.size() == 2);
        assert(toks[0] == "DW_OP_implicit_pointer");
        assert(toks[1] == "DW_OP_const1u");
    }
    {
        // GNU parameter_ref carries a fixed-size DIE reference operand.
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_parameter_ref),
            0x78, 0x56, 0x34, 0x12, // 32-bit ref
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x2a
        };
        auto toks = DwarfUtils::expressionToTokens(expr);
        assert(toks.size() == 2);
        assert(toks[0] == "DW_OP_GNU_parameter_ref");
        assert(toks[1] == "DW_OP_const1u");
    }
    {
        // GNU encoded_addr should consume encoding byte + encoded payload.
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr),
            0x02,                   // DW_EH_PE_udata2
            0x34, 0x12,             // encoded value
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x2a
        };
        auto toks = DwarfUtils::expressionToTokens(expr);
        assert(toks.size() == 2);
        assert(toks[0] == "DW_OP_GNU_encoded_addr");
        assert(toks[1] == "DW_OP_const1u");
    }
    {
        // GNU encoded_addr aligned should consume padding up to the next address-size boundary.
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_nop),
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr),
            0x50, // DW_EH_PE_aligned | DW_EH_PE_absptr
            0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x2a
        };
        DwarfUtils::SizeContext szctx;
        szctx.address_size = 8;
        auto toks = DwarfUtils::expressionToTokens(expr, szctx);
        assert(toks.size() == 3);
        assert(toks[0] == "DW_OP_nop");
        assert(toks[1] == "DW_OP_GNU_encoded_addr");
        assert(toks[2] == "DW_OP_const1u");
    }
    {
        // WASM location should consume kind + ULEB operand for known kinds.
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_WASM_location),
            0x00, // local
            0x81, 0x01, // ULEB 129
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x2a
        };
        auto toks = DwarfUtils::expressionToTokens(expr);
        assert(toks.size() == 2);
        assert(toks[0].find("DW_OP_WASM_location(kind=local,index=129)") != std::string::npos);
        assert(toks[1] == "DW_OP_const1u");
    }
    {
        // Truncated const8 should consume all remaining bytes (not fallback to 4).
        std::vector<uint8_t> bytes = {1, 2, 3, 4, 5, 6};
        size_t sz = DwarfUtils::getOperationSize(DwarfOp::DW_OP_const8u,
                                                 bytes.data(),
                                                 0,
                                                 bytes.size());
        assert(sz == 6);
    }
    {
        // Truncated fixed-width ops should consume remaining bytes.
        std::vector<uint8_t> bytes4 = {0xaa, 0xbb};
        size_t sz4 = DwarfUtils::getOperationSize(DwarfOp::DW_OP_const4u,
                                                  bytes4.data(),
                                                  0,
                                                  bytes4.size());
        assert(sz4 == 2);

        std::vector<uint8_t> bytes2 = {0xcc};
        size_t sz2 = DwarfUtils::getOperationSize(DwarfOp::DW_OP_const2u,
                                                  bytes2.data(),
                                                  0,
                                                  bytes2.size());
        assert(sz2 == 1);
    }
    {
        // Utility-mode DW_OP_addr sizing is conservative (4-byte) without CU context.
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_addr),
            0x78, 0x56, 0x34, 0x12, // 4-byte address payload
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x2a
        };
        auto toks = DwarfUtils::expressionToTokens(expr);
        assert(toks.size() == 2);
        assert(toks[0] == "DW_OP_addr");
        assert(toks[1] == "DW_OP_const1u");
    }
    {
        // Context-aware size decoding should honor address/offset width (DWARF64-style).
        DwarfUtils::SizeContext szctx;
        szctx.address_size = 8;
        szctx.offset_size = 8;

        std::vector<uint8_t> call_ref_bytes = {
            0,0,0,0,0,0,0,0, // 8-byte ref
            0xaa
        };
        size_t call_ref_sz = DwarfUtils::getOperationSize(DwarfOp::DW_OP_call_ref,
                                                          call_ref_bytes.data(),
                                                          0,
                                                          call_ref_bytes.size(),
                                                          szctx);
        assert(call_ref_sz == 8);

        std::vector<uint8_t> imp_ptr_bytes = {
            0,0,0,0,0,0,0,0, // 8-byte ref
            0x7f,             // SLEB(-1)
            0xaa
        };
        size_t imp_ptr_sz = DwarfUtils::getOperationSize(DwarfOp::DW_OP_implicit_pointer,
                                                         imp_ptr_bytes.data(),
                                                         0,
                                                         imp_ptr_bytes.size(),
                                                         szctx);
        assert(imp_ptr_sz == 9);
        std::vector<uint8_t> gnu_param_ref_bytes = {
            0,0,0,0,0,0,0,0, // 8-byte ref
            0xaa
        };
        size_t gnu_param_ref_sz = DwarfUtils::getOperationSize(DwarfOp::DW_OP_GNU_parameter_ref,
                                                               gnu_param_ref_bytes.data(),
                                                               0,
                                                               gnu_param_ref_bytes.size(),
                                                               szctx);
        assert(gnu_param_ref_sz == 8);

        std::vector<uint8_t> form_addr_bytes = {
            1,2,3,4,5,6,7,8,9
        };
        size_t form_addr_sz = DwarfUtils::getFormSize(DwarfForm::DW_FORM_addr,
                                                      form_addr_bytes.data(),
                                                      0,
                                                      form_addr_bytes.size(),
                                                      szctx);
        assert(form_addr_sz == 8);
        std::vector<uint8_t> form_sec_off_bytes = {
            1,2,3,4,5,6,7,8,9
        };
        size_t form_sec_off_sz = DwarfUtils::getFormSize(DwarfForm::DW_FORM_sec_offset,
                                                         form_sec_off_bytes.data(),
                                                         0,
                                                         form_sec_off_bytes.size(),
                                                         szctx);
        assert(form_sec_off_sz == 8);
        size_t gnu_strp_alt_sz = DwarfUtils::getFormSize(DwarfForm::DW_FORM_GNU_strp_alt,
                                                         form_sec_off_bytes.data(),
                                                         0,
                                                         form_sec_off_bytes.size(),
                                                         szctx);
        assert(gnu_strp_alt_sz == 8);
        size_t gnu_ref_alt_sz = DwarfUtils::getFormSize(DwarfForm::DW_FORM_GNU_ref_alt,
                                                        form_sec_off_bytes.data(),
                                                        0,
                                                        form_sec_off_bytes.size(),
                                                        szctx);
        assert(gnu_ref_alt_sz == 8);
        std::vector<uint8_t> gnu_idx_bytes = {0x81, 0x01}; // ULEB 129
        size_t gnu_str_idx_sz = DwarfUtils::getFormSize(DwarfForm::DW_FORM_GNU_str_index,
                                                        gnu_idx_bytes.data(),
                                                        0,
                                                        gnu_idx_bytes.size(),
                                                        szctx);
        assert(gnu_str_idx_sz == 2);
        size_t gnu_addr_idx_sz = DwarfUtils::getFormSize(DwarfForm::DW_FORM_GNU_addr_index,
                                                         gnu_idx_bytes.data(),
                                                         0,
                                                         gnu_idx_bytes.size(),
                                                         szctx);
        assert(gnu_addr_idx_sz == 2);
        DwarfUtils::SizeContext refctx = szctx;
        refctx.offset_size = 4;
        refctx.ref_addr_size = 8; // Explicit override for ref_addr-like encodings.
        std::vector<uint8_t> form_ref_addr_bytes = {
            1,2,3,4,5,6,7,8,9
        };
        size_t form_ref_addr_sz = DwarfUtils::getFormSize(DwarfForm::DW_FORM_ref_addr,
                                                          form_ref_addr_bytes.data(),
                                                          0,
                                                          form_ref_addr_bytes.size(),
                                                          refctx);
        assert(form_ref_addr_sz == 8);
        DwarfUtils::SizeContext refctx_dwarf2 = refctx;
        refctx_dwarf2.ref_addr_size = 0;
        refctx_dwarf2.ref_addr_uses_address_size = true; // DWARF2-like behavior
        size_t form_ref_addr_d2_sz = DwarfUtils::getFormSize(DwarfForm::DW_FORM_ref_addr,
                                                             form_ref_addr_bytes.data(),
                                                             0,
                                                             form_ref_addr_bytes.size(),
                                                             refctx_dwarf2);
        assert(form_ref_addr_d2_sz == 8);
        DwarfUtils::SizeContext refctx_offset = refctx;
        refctx_offset.ref_addr_size = 0;
        refctx_offset.address_size = 8;
        refctx_offset.offset_size = 4;
        refctx_offset.ref_addr_uses_address_size = false; // DWARF3+-like behavior
        size_t form_ref_addr_off_sz = DwarfUtils::getFormSize(DwarfForm::DW_FORM_ref_addr,
                                                              form_ref_addr_bytes.data(),
                                                              0,
                                                              form_ref_addr_bytes.size(),
                                                              refctx_offset);
        assert(form_ref_addr_off_sz == 4);
        std::vector<uint8_t> form_indirect_addr = {
            0x01,                   // ULEB(DW_FORM_addr)
            1,2,3,4,5,6,7,8,9
        };
        size_t form_indirect_sz = DwarfUtils::getFormSize(DwarfForm::DW_FORM_indirect,
                                                          form_indirect_addr.data(),
                                                          0,
                                                          form_indirect_addr.size(),
                                                          szctx);
        assert(form_indirect_sz == 9); // 1-byte form code + 8-byte address

        std::vector<uint8_t> expr64 = {
            static_cast<uint8_t>(DwarfOp::DW_OP_call_ref),
            0,0,0,0,0,0,0,0, // 8-byte ref
            static_cast<uint8_t>(DwarfOp::DW_OP_addr),
            1,2,3,4,5,6,7,8, // 8-byte address
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x2a
        };
        auto toks = DwarfUtils::expressionToTokens(expr64, szctx);
        assert(toks.size() == 3);
        assert(toks[0] == "DW_OP_call_ref");
        assert(toks[1] == "DW_OP_addr");
        assert(toks[2] == "DW_OP_const1u");
        auto asm_s = DwarfUtils::expressionToAssembly(expr64, szctx);
        assert(asm_s.find("DW_OP_call_ref") != std::string::npos);
        assert(asm_s.find("DW_OP_addr") != std::string::npos);

        std::vector<uint8_t> expr_gnu_addr64 = {
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr),
            0x00, // DW_EH_PE_absptr
            1,2,3,4,5,6,7,8, // 8-byte payload (ctx.address_size=8)
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x2a
        };
        auto toks_gnu = DwarfUtils::expressionToTokens(expr_gnu_addr64, szctx);
        assert(toks_gnu.size() == 2);
        assert(toks_gnu[0] == "DW_OP_GNU_encoded_addr");
        assert(toks_gnu[1] == "DW_OP_const1u");
    }
    {
        // Utility-mode DW_FORM_addr sizing is conservative (4-byte) without CU context.
        std::vector<uint8_t> bytes = {0x11, 0x22, 0x33, 0x44, 0xaa};
        size_t sz = DwarfUtils::getFormSize(DwarfForm::DW_FORM_addr,
                                            bytes.data(),
                                            0,
                                            bytes.size());
        assert(sz == 4);
    }
    {
        // Truncated fixed-width forms should consume remaining bytes.
        std::vector<uint8_t> bytes8 = {1,2,3,4,5};
        size_t sz8 = DwarfUtils::getFormSize(DwarfForm::DW_FORM_ref8,
                                             bytes8.data(),
                                             0,
                                             bytes8.size());
        assert(sz8 == 5);

        std::vector<uint8_t> bytes3 = {9,8};
        size_t sz3 = DwarfUtils::getFormSize(DwarfForm::DW_FORM_strx3,
                                             bytes3.data(),
                                             0,
                                             bytes3.size());
        assert(sz3 == 2);
    }

    // Test type utilities
    assert(DwarfUtils::isTypeTag(DwarfTag::DW_TAG_base_type));
    assert(DwarfUtils::isTypeTag(DwarfTag::DW_TAG_pointer_type));
    assert(DwarfUtils::isTypeTag(DwarfTag::DW_TAG_string_type));
    assert(DwarfUtils::isTypeTag(DwarfTag::DW_TAG_set_type));
    assert(DwarfUtils::isTypeTag(DwarfTag::DW_TAG_file_type));
    assert(DwarfUtils::isTypeTag(DwarfTag::DW_TAG_interface_type));
    assert(DwarfUtils::isTypeTag(DwarfTag::DW_TAG_ptr_to_member_type));
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

static std::vector<uint8_t> loadTestDataBinary(const std::string& filename) {
    const std::vector<std::string> candidates = {
        std::string("test_data/") + filename,
        std::string("../test_data/") + filename,
    };

    for (const auto& path : candidates) {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs) continue;

        return std::vector<uint8_t>(
            std::istreambuf_iterator<char>(ifs),
            std::istreambuf_iterator<char>());
    }

    assert(false && "fixture file not found");
    return {};
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

    // DW_OP_WASM_location should decode into a synthetic register-location id.
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_WASM_location),
        0x00, // local
        0x2a  // index 42
    };
    result = evaluator.evaluate(expression);
    assert(result.type == ExpressionResult::REGISTER);
    assert(result.value == ((0ULL << 56) | 42ULL));

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

    // Preserve value and register referents, not just address referents.
    imp_ctx.resolve_dwarf_procedure = [](uint64_t die_offset, uint64_t pc) -> std::optional<std::vector<uint8_t>> {
        (void)pc;
        if (die_offset == 0x1234) {
            return std::vector<uint8_t>{
                static_cast<uint8_t>(DwarfOp::DW_OP_addr),
                0x00, 0x20, 0x00, 0x00, // 0x2000
            };
        }
        if (die_offset == 0x1238) {
            return std::vector<uint8_t>{
                static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x20,
                static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
            };
        }
        if (die_offset == 0x123c) {
            return std::vector<uint8_t>{
                static_cast<uint8_t>(DwarfOp::DW_OP_reg3),
            };
        }
        return std::nullopt;
    };

    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_implicit_pointer),
        0x38, 0x12, 0x00, 0x00, // section offset 0x1238
        0x04, // +4
    };
    result = evaluator.evaluate(expression, imp_ctx);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 0x24);

    registers.assign(8, 0);
    registers[3] = 0x40;
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_GNU_implicit_pointer),
        0x3c, 0x12, 0x00, 0x00, // section offset 0x123c
        0x7e, // -2
    };
    result = evaluator.evaluate(expression, imp_ctx, 0, registers);
    assert(result.type == ExpressionResult::ADDRESS);
    assert(result.value == 0x3e);

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
    ctx.diagnostic_cu_offset = 0x123;
    ctx.diagnostic_die_offset = 0x456;
    ctx.diagnostic_attribute = "DW_AT_location";
    std::vector<uint64_t> regs(64, 0);

    // 0xff is not a defined DW_OP in our enum; evaluator should return INVALID (not silently succeed).
    std::vector<uint8_t> expr = {0xff};
    auto r = eval.evaluate(expr, ctx, /*pc=*/0, regs);
    assert(r.type == ExpressionResult::INVALID);
    assert(r.description.find("opcode 0xff") != std::string::npos);
    assert(r.description.find("vendor/extension opcode") != std::string::npos);
    assert(r.description.find("cu=0x123") != std::string::npos);
    assert(r.description.find("die=0x456") != std::string::npos);
    assert(r.description.find("attr=DW_AT_location") != std::string::npos);
    assert(r.unsupported_opcode.has_value() && *r.unsupported_opcode == 0xff);
    assert(r.unsupported_vendor_extension);

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

    // textrel/datarel/funcrel application modes should use the corresponding context bases.
    {
        ExpressionEvaluator ev;
        EvaluationContext ctx;
        ctx.address_size = 8;
        ctx.text_base = 0x4000;
        ctx.data_base = 0x8000;
        ctx.function_base = 0x1200;

        std::vector<uint8_t> textrel = {
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr),
            0x23, // DW_EH_PE_textrel | DW_EH_PE_udata4
            0x10, 0x00, 0x00, 0x00,
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        };
        auto text_r = ev.evaluate(textrel, ctx, /*pc=*/0, /*registers=*/{});
        assert(text_r.type == ExpressionResult::VALUE);
        assert(text_r.value == 0x4010);

        std::vector<uint8_t> datarel = {
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr),
            0x33, // DW_EH_PE_datarel | DW_EH_PE_udata4
            0x20, 0x00, 0x00, 0x00,
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        };
        auto data_r = ev.evaluate(datarel, ctx, /*pc=*/0, /*registers=*/{});
        assert(data_r.type == ExpressionResult::VALUE);
        assert(data_r.value == 0x8020);

        std::vector<uint8_t> funcrel = {
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr),
            0x43, // DW_EH_PE_funcrel | DW_EH_PE_udata4
            0x34, 0x00, 0x00, 0x00,
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        };
        auto func_r = ev.evaluate(funcrel, ctx, /*pc=*/0, /*registers=*/{});
        assert(func_r.type == ExpressionResult::VALUE);
        assert(func_r.value == 0x1234);
    }

    // aligned application mode should align the payload read cursor before decoding the value.
    {
        ExpressionEvaluator ev;
        EvaluationContext ctx;
        ctx.address_size = 8;
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_nop),
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr),
            0x50, // DW_EH_PE_aligned | DW_EH_PE_absptr
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, // padding to next 8-byte boundary
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        };
        auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
        assert(r.type == ExpressionResult::VALUE);
        assert(r.value == 0x1122334455667788ULL);
    }

    // Unknown/unsupported format should fall back to absptr-sized decoding.
    {
        ExpressionEvaluator ev;
        EvaluationContext ctx;
        ctx.address_size = 8;
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr),
            0x05, // unknown format, absolute application
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
        };
        auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
        assert(r.type == ExpressionResult::VALUE);
        assert(r.value == 0x0102030405060708ULL);
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

void testExpressionEvaluatorEntryValue() {
    std::cout << "Testing ExpressionEvaluator DW_OP_entry_value..." << std::endl;

    {
        ExpressionEvaluator ev;
        EvaluationContext ctx;
        ctx.address_size = 8;
        ctx.entry_registers = std::vector<uint64_t>(32, 0);
        ctx.entry_registers[5] = 0xdeadbeefULL;

        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_entry_value));
        appendULEB(expr, 1);
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg5));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));

        auto r = ev.evaluate(expr, ctx, /*pc=*/0, /*registers=*/{});
        assert(r.type == ExpressionResult::VALUE);
        assert(r.value == 0xdeadbeefULL);
    }

    {
        struct EntryValueMemory : public MemoryContext {
            bool readMemory(uint64_t address, size_t size, void* buffer) const override {
                if (address != 0x1000 || size != 8) return false;
                const uint8_t bytes[8] = {0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
                std::memcpy(buffer, bytes, sizeof(bytes));
                return true;
            }
            bool writeMemory(uint64_t address, size_t size, const void* buffer) override {
                (void)address;
                (void)size;
                (void)buffer;
                return false;
            }
        };

        auto mem = std::make_shared<EntryValueMemory>();
        ExpressionEvaluator ev(mem);
        EvaluationContext ctx;
        ctx.address_size = 8;
        ctx.entry_registers = std::vector<uint64_t>(32, 0);
        ctx.entry_registers[3] = 0x1000;

        std::vector<uint8_t> entry_expr;
        entry_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_entry_value));
        appendULEB(entry_expr, 1);
        entry_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg3));
        entry_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_deref));
        entry_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));

        auto entry_r = ev.evaluate(entry_expr, ctx, /*pc=*/0, /*registers=*/{});
        assert(entry_r.type == ExpressionResult::VALUE);
        assert(entry_r.value == 0x1122334455667788ULL);

        std::vector<uint8_t> gnu_expr;
        gnu_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_entry_value));
        appendULEB(gnu_expr, 1);
        gnu_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg3));
        gnu_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_deref));
        gnu_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));

        auto gnu_r = ev.evaluate(gnu_expr, ctx, /*pc=*/0, /*registers=*/{});
        assert(gnu_r.type == ExpressionResult::VALUE);
        assert(gnu_r.value == 0x1122334455667788ULL);
    }

    std::cout << "ExpressionEvaluator DW_OP_entry_value tests passed!" << std::endl;
}

void testExpressionEvaluatorGnuUninit() {
    std::cout << "Testing ExpressionEvaluator DW_OP_GNU_uninit..." << std::endl;

    ExpressionEvaluator ev;
    EvaluationContext ctx;
    std::vector<uint8_t> expr = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x05,
        static_cast<uint8_t>(DwarfOp::DW_OP_GNU_uninit),
        static_cast<uint8_t>(DwarfOp::DW_OP_plus_uconst), 0x01,
        static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
    };

    auto r = ev.evaluate(expr, ctx);
    assert(r.type == ExpressionResult::VALUE);
    assert(r.value == 0x06);
    assert(r.uninitialized);
    assert(r.description.find("uninitialized") != std::string::npos);

    std::cout << "ExpressionEvaluator DW_OP_GNU_uninit tests passed!" << std::endl;
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

    // Bare literals are values, not addresses.
    {
        std::vector<uint8_t> lit_expr;
        lit_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit7));
        auto lit = se.evaluate(lit_expr, ctx);
        assert(lit.type == SymbolicExpressionResult::Type::VALUE);
        assert(lit.expression);
        assert(lit.expression->toString() == "0x7");
    }

    {
        std::vector<uint8_t> const_expr;
        const_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1u));
        const_expr.push_back(0x2a);
        auto c = se.evaluate(const_expr, ctx);
        assert(c.type == SymbolicExpressionResult::Type::VALUE);
        assert(c.expression);
        assert(c.expression->toString() == "0x2a");
    }

    {
        std::vector<uint8_t> const_expr;
        const_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_const1s));
        const_expr.push_back(0xfe);
        auto c = se.evaluate(const_expr, ctx);
        assert(c.type == SymbolicExpressionResult::Type::VALUE);
        assert(c.expression);
        assert(c.expression->toString() == "0xfffffffffffffffe");
    }

    // fbreg(-0x20) => 0x1000 - 0x20 = 0xfe0 (const-folded)
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_fbreg));
    // SLEB(-32) = 0x60
    expr.push_back(0x60);

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
    assert(r.expression);
    assert(r.expression->toString() == "0xfe0");

    {
        std::vector<uint8_t> obj_expr;
        obj_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_push_object_address));
        auto obj = se.evaluate(obj_expr, ctx);
        assert(obj.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(obj.expression);
        assert(obj.expression->toString() == "object_address");
    }

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

void testSymbolicExpressionEvaluatorDiagnosticContextOnUnsupportedOp() {
    std::cout << "Testing SymbolicExpressionEvaluator diagnostic context on unsupported op..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;
    ctx.diagnostic_cu_offset = 0x123;
    ctx.diagnostic_die_offset = 0x456;
    ctx.diagnostic_attribute = "DW_AT_location";

    std::vector<uint8_t> expr = {0xff};
    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::INVALID);
    assert(r.error.find("unsupported op") != std::string::npos);
    assert(r.error.find("opcode 0xff") != std::string::npos);
    assert(r.error.find("vendor/extension opcode") != std::string::npos);
    assert(r.error.find("cu=0x123") != std::string::npos);
    assert(r.error.find("die=0x456") != std::string::npos);
    assert(r.error.find("attr=DW_AT_location") != std::string::npos);
    assert(r.unsupported_opcode.has_value() && *r.unsupported_opcode == 0xff);
    assert(r.unsupported_vendor_extension);

    std::cout << "SymbolicExpressionEvaluator diagnostic context tests passed!" << std::endl;
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
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
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
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
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
        assert(r.pieces[0].kind == SymPiece::Kind::IMPLICIT);
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

    // Resolver path should also preserve value and register referents.
    EvaluationContext ctx3 = ctx;
    ctx3.resolve_dwarf_procedure = [](uint64_t off, uint64_t /*pc*/) -> std::optional<std::vector<uint8_t>> {
        if (off == 0x90) {
            return std::vector<uint8_t>{
                static_cast<uint8_t>(DwarfOp::DW_OP_const1u), 0x20,
                static_cast<uint8_t>(DwarfOp::DW_OP_stack_value),
            };
        }
        if (off == 0xa0) {
            return std::vector<uint8_t>{
                static_cast<uint8_t>(DwarfOp::DW_OP_reg3),
            };
        }
        return std::nullopt;
    };

    std::vector<uint8_t> value_expr;
    value_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_implicit_pointer));
    appendU32(value_expr, 0x90);
    value_expr.push_back(0x04); // SLEB(+4)
    auto r3 = se.evaluate(value_expr, ctx3);
    assert(r3.type == SymbolicExpressionResult::Type::VALUE);
    assert(r3.expression && r3.expression->toString() == "0x24");

    std::vector<uint64_t> regs(8, 0);
    regs[3] = 0x40;
    std::vector<uint8_t> reg_expr;
    reg_expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_implicit_pointer));
    appendU32(reg_expr, 0xa0);
    reg_expr.push_back(0x7e); // SLEB(-2)
    auto r4 = se.evaluate(reg_expr, ctx3, /*pc=*/0, regs);
    assert(r4.type == SymbolicExpressionResult::Type::VALUE);
    assert(r4.expression && r4.expression->toString() == "0x3e");

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
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "0x2");
    }

    // symbolic branch merge should preserve GNU_uninit taint from either arm.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
        expr.push_back(0x00); // SLEB(0)
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
        appendU16(expr, 4); // to true arm
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit1)); // false arm
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
        appendU16(expr, 2); // skip true arm
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_uninit));
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit2)); // true arm

        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "ite((reg5 != 0x0),0x2,0x1)");
        assert(r.uninitialized);
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
    assert(r.type == SymbolicExpressionResult::Type::VALUE);
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
    assert(r.pieces[0].kind == SymPiece::Kind::IMPLICIT);
    assert(r.pieces[0].byte_size == 8);
    assert(r.pieces[0].location);
    assert(r.pieces[0].location->toString() == "ite((reg5 != 0x0),reg0,reg2)");
    assert(r.pieces[1].kind == SymPiece::Kind::IMPLICIT);
    assert(r.pieces[1].byte_size == 8);
    assert(r.pieces[1].location);
    assert(r.pieces[1].location->toString() == "ite((reg5 != 0x0),reg1,reg3)");

    std::cout << "SymbolicExpressionEvaluator symbolic bra composite tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraCompositeRegisterLocationMerge() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra composite register-location merge..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0):
    //   then  -> register piece(reg0,8)
    //   else  -> register piece(reg2,8)
    // Different register locations should normalize to an implicit branch-dependent value.
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    appendU16(expr, 6); // jump over false arm to true arm

    // false arm
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg2));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(expr, 8);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    appendU16(expr, 3); // skip true arm

    // true arm
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
    assert(r.pieces[0].location->toString() == "ite((reg5 != 0x0),reg0,reg2)");

    std::cout << "SymbolicExpressionEvaluator symbolic bra composite register-location tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraRegisterMismatchMerge() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra register mismatch merge..." << std::endl;

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
    assert(r.type == SymbolicExpressionResult::Type::VALUE);
    assert(r.expression);
    assert(r.expression->toString() == "ite((reg5 != 0x0),reg0,reg2)");

    std::cout << "SymbolicExpressionEvaluator symbolic bra register mismatch merge tests passed!" << std::endl;
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

void testSymbolicExpressionEvaluatorSymbolicBraAddressAddressMerge() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra address/address merge..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0): then address(0x2000) else address(0x1000)
    // Different top-level locations should normalize to a branch-dependent loaded value.
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
    appendU16(expr, 9); // skip true arm

    // true arm: address
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
    appendU64(expr, 0x2000);

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::VALUE);
    assert(r.expression);
    assert(r.expression->toString() == "ite((reg5 != 0x0),load(0x2000,8),load(0x1000,8))");

    std::cout << "SymbolicExpressionEvaluator symbolic bra address/address tests passed!" << std::endl;
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

void testSymbolicExpressionEvaluatorSymbolicBraCompositeMemoryLocationMerge() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra composite memory-location merge..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0):
    //   then  -> memory piece(8) at 0x2000
    //   else  -> memory piece(8) at 0x1000
    // Different memory locations should normalize to an implicit branch-dependent value,
    // not a branch-dependent location descriptor.
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    appendU16(expr, 14); // jump over false arm to true arm

    // false arm: memory piece at 0x1000
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
    appendU64(expr, 0x1000);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(expr, 8);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    appendU16(expr, 11); // skip true arm

    // true arm: memory piece at 0x2000
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
    appendU64(expr, 0x2000);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_piece));
    appendULEB(expr, 8);

    auto r = se.evaluate(expr, ctx);
    assert(r.type == SymbolicExpressionResult::Type::COMPOSITE);
    assert(r.pieces.size() == 1);
    assert(r.pieces[0].kind == SymPiece::Kind::IMPLICIT);
    assert(r.pieces[0].byte_size == 8);
    assert(r.pieces[0].implicit_bytes.empty());
    assert(r.pieces[0].location);
    assert(r.pieces[0].location->toString() == "ite((reg5 != 0x0),load(0x2000,8),load(0x1000,8))");

    std::cout << "SymbolicExpressionEvaluator symbolic bra composite memory-location tests passed!" << std::endl;
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
           "ite((reg5 != 0x0),unknown(unavail_bit_piece3),((load(0x1000,1) >> 0x1) & 0x7))");

    std::cout << "SymbolicExpressionEvaluator symbolic bra bit_piece unavailable tests passed!" << std::endl;
}

void testSymbolicExpressionEvaluatorSymbolicBraCompositeBitPieceMemoryLocationMerge() {
    std::cout << "Testing SymbolicExpressionEvaluator symbolic bra bit_piece memory-location merge..." << std::endl;

    SymbolicExpressionEvaluator se;
    EvaluationContext ctx;
    ctx.address_size = 8;

    // if (reg5 != 0):
    //   then  -> memory bit_piece(3,1) at 0x2000
    //   else  -> memory bit_piece(3,1) at 0x1000
    // Different memory locations should normalize to an implicit extracted-bit value.
    std::vector<uint8_t> expr;
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_breg5));
    expr.push_back(0x00); // SLEB(0)
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_ne));
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bra));
    appendU16(expr, 15); // jump over false arm to true arm

    // false arm: memory bit_piece at 0x1000
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
    appendU64(expr, 0x1000);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_bit_piece));
    appendULEB(expr, 3);
    appendULEB(expr, 1);
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_skip));
    appendU16(expr, 12); // skip true arm

    // true arm: memory bit_piece at 0x2000
    expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_addr));
    appendU64(expr, 0x2000);
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
           "ite((reg5 != 0x0),((load(0x2000,1) >> 0x1) & 0x7),((load(0x1000,1) >> 0x1) & 0x7))");

    std::cout << "SymbolicExpressionEvaluator symbolic bra bit_piece memory-location tests passed!" << std::endl;
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
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
        assert(r.expression && r.expression->toString() == "0x4444");
    }
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_WASM_location));
        expr.push_back(0x00); // local
        appendULEB(expr, 42);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::REGISTER);
        assert(r.expression && r.expression->toString() == "0x2a");
    }
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_WASM_location));
        expr.push_back(0x03); // unknown/custom location kind
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::REGISTER);
        assert(r.expression && r.expression->toString() == "0x300000000000000");
    }
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_WASM_location));
        expr.push_back(0x01); // global
        appendULEB(expr, 7);
        auto r = se.evaluate(expr, ctx);
        assert(r.type == SymbolicExpressionResult::Type::REGISTER);
        assert(r.expression && r.expression->toString() == "0x100000000000007");
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
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
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
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
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
        assert(r.type == SymbolicExpressionResult::Type::VALUE);
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

    // GNU_uninit should preserve uninitialized taint.
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
        assert(r.uninitialized);
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

    // GNU_encoded_addr textrel/datarel/funcrel should use the matching bases from context.
    {
        ctx.text_base = 0x4000;
        ctx.data_base = 0x8000;
        ctx.function_base = 0x1200;

        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr));
        expr.push_back(0x23); // DW_EH_PE_udata4 | DW_EH_PE_textrel
        appendU32(expr, 0x10);

        auto r = se.evaluate(expr, ctx, 0x1000);
        assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "0x4010");

        expr.clear();
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr));
        expr.push_back(0x33); // DW_EH_PE_udata4 | DW_EH_PE_datarel
        appendU32(expr, 0x20);

        r = se.evaluate(expr, ctx, 0x1000);
        assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "0x8020");

        expr.clear();
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr));
        expr.push_back(0x43); // DW_EH_PE_udata4 | DW_EH_PE_funcrel
        appendU32(expr, 0x34);

        r = se.evaluate(expr, ctx, 0x1000);
        assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "0x1234");
    }

    // GNU_encoded_addr aligned application should skip padding to the next address-size boundary.
    {
        ctx.address_size = 8;
        std::vector<uint8_t> expr = {
            static_cast<uint8_t>(DwarfOp::DW_OP_nop),
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr),
            0x50, // DW_EH_PE_aligned | DW_EH_PE_absptr
            0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        };

        auto r = se.evaluate(expr, ctx, 0x1000);
        assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "0x1122334455667788");
    }

    // Unknown/unsupported format should follow the concrete evaluator's absptr fallback.
    {
        std::vector<uint8_t> expr;
        expr.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_GNU_encoded_addr));
        expr.push_back(0x05); // unknown format, absolute application
        appendU64(expr, 0x0102030405060708ULL);

        auto r = se.evaluate(expr, ctx, 0x1000);
        assert(r.type == SymbolicExpressionResult::Type::ADDRESS);
        assert(r.expression && r.expression->toString() == "0x102030405060708");
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
        assert(r.verdict ==
#if DWARF_HAS_Z3
               ExpressionVerificationResult::Verdict::EQUIVALENT
#else
               ExpressionVerificationResult::Verdict::UNKNOWN
#endif
        );
#if DWARF_HAS_Z3
        assert(r.verifier_backend == "z3");
        assert(r.solver_result == "unsat");
#else
        assert(r.verifier_backend == "solver-unavailable");
        assert(r.solver_result == "solver_unavailable");
#endif
        assert(r.counterexample_model.empty());
        assert(r.counterexample_witness.empty());
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
#if DWARF_HAS_Z3
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.verifier_backend == "z3");
        assert(r.solver_result == "sat");
#else
        assert(r.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);
        assert(r.verifier_backend == "solver-unavailable");
        assert(r.solver_result == "solver_unavailable");
#endif
    }

    // Unsupported/invalid symbolic input should return UNKNOWN.
    {
        std::vector<uint8_t> lhs = {0xff};
        std::vector<uint8_t> rhs = {static_cast<uint8_t>(DwarfOp::DW_OP_lit0)};
        auto r = verifier.verify(lhs, rhs, ctx);
        assert(r.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);
        assert(r.verifier_backend == "structural");
        assert(r.solver_result == "unsupported_opcode");
        assert(r.reason.find("lhs unsupported opcode 0xff") != std::string::npos);
        assert(r.lhs_unsupported_opcode.has_value() && *r.lhs_unsupported_opcode == 0xff);
        assert(r.lhs_unsupported_vendor_extension);
        assert(!r.rhs_unsupported_opcode.has_value());
    }

    // Differential options are ignored by the SMT backend; the mismatch is still proven.
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
#if DWARF_HAS_Z3
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.verifier_backend == "z3");
        assert(r.solver_result == "sat");
#else
        assert(r.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);
        assert(r.verifier_backend == "solver-unavailable");
        assert(r.solver_result == "solver_unavailable");
#endif
    }

    // Counterexample witness should be populated for model-dependent mismatches.
    {
        std::vector<uint8_t> lhs;
        lhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_reg1));
        lhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));

        std::vector<uint8_t> rhs;
        rhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
        rhs.push_back(static_cast<uint8_t>(DwarfOp::DW_OP_stack_value));

        auto r = verifier.verify(lhs, rhs, ctx);
#if DWARF_HAS_Z3
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.verifier_backend == "z3");
        assert(r.solver_result == "sat");
        assert(!r.counterexample_model.empty());
        assert(!r.counterexample_witness.empty());
#else
        assert(r.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);
        assert(r.verifier_backend == "solver-unavailable");
        assert(r.solver_result == "solver_unavailable");
        assert(r.counterexample_model.empty());
        assert(r.counterexample_witness.empty());
#endif
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
        assert(r.verdict ==
#if DWARF_HAS_Z3
               ExpressionVerificationResult::Verdict::EQUIVALENT
#else
               ExpressionVerificationResult::Verdict::UNKNOWN
#endif
        );
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
        assert(r.verdict ==
#if DWARF_HAS_Z3
               ExpressionVerificationResult::Verdict::DIFFERENT
#else
               ExpressionVerificationResult::Verdict::UNKNOWN
#endif
        );
    }

    // entry_value and GNU_entry_value should materialize entry-time register values through verifier contexts.
    {
        std::vector<uint8_t> lhs = {
            static_cast<uint8_t>(DwarfOp::DW_OP_entry_value),
            0x01,
            static_cast<uint8_t>(DwarfOp::DW_OP_reg5),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
        };
        std::vector<uint8_t> rhs = {
            static_cast<uint8_t>(DwarfOp::DW_OP_lit0),
            static_cast<uint8_t>(DwarfOp::DW_OP_const1u),
            0x2a,
            static_cast<uint8_t>(DwarfOp::DW_OP_plus),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
        };

        EvaluationContext lhs_ctx = ctx;
        lhs_ctx.entry_registers = std::vector<uint64_t>(16, 0);
        lhs_ctx.entry_registers[5] = 42;

        auto r = verifier.verifyWithContexts(lhs, lhs_ctx, 0, {}, rhs, ctx, 0, {});
        assert(r.verdict ==
#if DWARF_HAS_Z3
               ExpressionVerificationResult::Verdict::EQUIVALENT
#else
               ExpressionVerificationResult::Verdict::UNKNOWN
#endif
        );
    }

    {
        std::vector<uint8_t> lhs = {
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_entry_value),
            0x01,
            static_cast<uint8_t>(DwarfOp::DW_OP_reg5),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
        };
        std::vector<uint8_t> rhs = {
            static_cast<uint8_t>(DwarfOp::DW_OP_lit7),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
        };

        EvaluationContext lhs_ctx = ctx;
        lhs_ctx.entry_registers = std::vector<uint64_t>(16, 0);
        lhs_ctx.entry_registers[5] = 7;

        auto r = verifier.verifyWithContexts(lhs, lhs_ctx, 0, {}, rhs, ctx, 0, {});
        assert(r.verdict ==
#if DWARF_HAS_Z3
               ExpressionVerificationResult::Verdict::EQUIVALENT
#else
               ExpressionVerificationResult::Verdict::UNKNOWN
#endif
        );
    }

    // Per-side entry contexts should still distinguish mismatched entry_value materializations.
    {
        std::vector<uint8_t> lhs = {
            static_cast<uint8_t>(DwarfOp::DW_OP_entry_value),
            0x01,
            static_cast<uint8_t>(DwarfOp::DW_OP_reg5),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
        };
        std::vector<uint8_t> rhs = lhs;

        EvaluationContext lhs_ctx = ctx;
        EvaluationContext rhs_ctx = ctx;
        lhs_ctx.entry_registers = std::vector<uint64_t>(16, 0);
        rhs_ctx.entry_registers = std::vector<uint64_t>(16, 0);
        lhs_ctx.entry_registers[5] = 1;
        rhs_ctx.entry_registers[5] = 2;

        auto r = verifier.verifyWithContexts(lhs, lhs_ctx, 0, {}, rhs, rhs_ctx, 0, {});
#if DWARF_HAS_Z3
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.verifier_backend == "z3");
        assert(r.solver_result == "sat");
#else
        assert(r.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);
        assert(r.verifier_backend == "solver-unavailable");
        assert(r.solver_result == "solver_unavailable");
#endif
    }

    // Wide implicit byte values should remain solver-visible through the public verifier.
    {
        std::vector<uint8_t> lhs = {
            static_cast<uint8_t>(DwarfOp::DW_OP_implicit_value),
            0x09,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03,
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
        };
        std::vector<uint8_t> rhs = {
            static_cast<uint8_t>(DwarfOp::DW_OP_lit0),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
        };

        auto r = verifier.verify(lhs, rhs, ctx);
#if DWARF_HAS_Z3
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.verifier_backend == "z3");
        assert(r.solver_result == "sat");
        assert(!r.counterexample_model.empty());
        assert(!r.counterexample_witness.empty());
#else
        assert(r.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);
        assert(r.verifier_backend == "solver-unavailable");
        assert(r.solver_result == "solver_unavailable");
#endif
    }

    // Uninitialized taint should participate in equivalence, not just the value term.
    {
        std::vector<uint8_t> lhs = {
            static_cast<uint8_t>(DwarfOp::DW_OP_lit1),
            static_cast<uint8_t>(DwarfOp::DW_OP_GNU_uninit),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
        };
        std::vector<uint8_t> rhs = {
            static_cast<uint8_t>(DwarfOp::DW_OP_lit1),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
        };

        auto r = verifier.verify(lhs, rhs, ctx);
#if DWARF_HAS_Z3
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.verifier_backend == "z3");
        assert(r.solver_result == "precheck_uninitialized_mismatch");
#else
        assert(r.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);
        assert(r.verifier_backend == "solver-unavailable");
        assert(r.solver_result == "solver_unavailable");
#endif
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
        assert(r.verdict ==
#if DWARF_HAS_Z3
               ExpressionVerificationResult::Verdict::EQUIVALENT
#else
               ExpressionVerificationResult::Verdict::UNKNOWN
#endif
        );
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
        assert(r_default.verdict ==
#if DWARF_HAS_Z3
               ExpressionVerificationResult::Verdict::DIFFERENT
#else
               ExpressionVerificationResult::Verdict::UNKNOWN
#endif
        );

        DIEExpressionSelectionOptions lhs_sel;
        lhs_sel.use_pc_for_location_list = true;
        lhs_sel.location_list_pc = 12;
        DIEExpressionSelectionOptions rhs_sel;
        rhs_sel.use_pc_for_location_list = true;
        rhs_sel.location_list_pc = 120;
        auto r_pc = verifier.verifyDIEAttributeExpressions(
            lhs_die, ctx, {}, rhs_die, ctx, {}, lhs_sel, rhs_sel);
        assert(r_pc.verdict ==
#if DWARF_HAS_Z3
               ExpressionVerificationResult::Verdict::EQUIVALENT
#else
               ExpressionVerificationResult::Verdict::UNKNOWN
#endif
        );
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

void testSMTExpressionVerifierBehavior() {
    std::cout << "Testing SMTExpressionVerifier behavior..." << std::endl;

    SMTExpressionVerifier smt;

#if !DWARF_HAS_Z3
    assert(!SMTExpressionVerifier::isAvailable());
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::VALUE;
        lhs.expression = SymExpr::makeConst(1);

        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::VALUE;
        rhs.expression = SymExpr::makeConst(1);

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);
        assert(r.solver_result == "solver_unavailable");
        assert(r.reason.find("without Z3 support") != std::string::npos);
    }

    std::cout << "SMTExpressionVerifier behavior tests passed!" << std::endl;
    return;
#else
    assert(SMTExpressionVerifier::isAvailable());
#endif

    // Unknown symbolic leaves are modeled as opaque values rather than encoder failures.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::VALUE;
        lhs.expression = SymExpr::makeUnknown("opaque_test_node");

        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::VALUE;
        rhs.expression = SymExpr::makeUnknown("opaque_test_node");

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT);
        assert(r.solver_result == "unsat" || r.solver_result == "precheck_structural_equal");
    }

    // Distinct unknown symbolic leaves should remain solver-visible and produce a witness.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::VALUE;
        lhs.expression = SymExpr::makeUnknown("opaque_lhs");

        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::VALUE;
        rhs.expression = SymExpr::makeUnknown("opaque_rhs");

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.solver_result == "sat");
        assert(!r.model.empty());
        assert(!r.witness.empty());
    }

    // Missing symbolic expression should not call solver and should return precheck bucket.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::VALUE;

        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::VALUE;
        rhs.expression = SymExpr::makeConst(1);

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);
        assert(r.solver_result == "precheck_missing_expression");
    }

    // Type mismatch should return deterministic DIFFERENT precheck.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::ADDRESS;
        lhs.expression = SymExpr::makeConst(1);

        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::VALUE;
        rhs.expression = SymExpr::makeConst(1);

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.solver_result == "precheck_type_mismatch");
    }

    // Uninitialized-taint mismatch should fail fast even when value expressions match.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::VALUE;
        lhs.expression = SymExpr::makeConst(1);
        lhs.uninitialized = true;

        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::VALUE;
        rhs.expression = SymExpr::makeConst(1);

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.solver_result == "precheck_uninitialized_mismatch");
    }

    // Wide byte literals should compare deterministically without falling into SMT encoding_error.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::VALUE;
        lhs.expression = SymExpr::makeBytes({0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18});

        SymbolicExpressionResult rhs = lhs;

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT);
        assert(r.solver_result == "precheck_wide_bytes_equal");
    }

    // Distinct wide byte literals should also compare deterministically.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::VALUE;
        lhs.expression = SymExpr::makeBytes({0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18});

        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::VALUE;
        rhs.expression = SymExpr::makeBytes({0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x19});

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.solver_result == "precheck_wide_bytes_mismatch");
    }

    // Wide byte literals should remain solver-visible against non-byte expressions.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::VALUE;
        lhs.expression = SymExpr::makeBytes({0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18});

        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::VALUE;
        rhs.expression = SymExpr::makeConst(0);

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.solver_result == "sat");
        assert(!r.model.empty());
        assert(!r.witness.empty());
    }

    // Identical unsupported symbolic shapes should short-circuit before SMT encoding.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::VALUE;
        lhs.expression = SymExpr::makeLoad(SymExpr::makeConst(0x1000), 9);

        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::VALUE;
        rhs.expression = SymExpr::makeLoad(SymExpr::makeConst(0x1000), 9);

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT);
        assert(r.solver_result == "precheck_structural_equal");
    }

    // Identical malformed symbolic shapes should also short-circuit deterministically.
    {
        auto bad = std::make_shared<SymExpr>();
        bad->kind = SymExpr::Kind::ADD;
        bad->args = {SymExpr::makeConst(1)}; // malformed binary arity

        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::VALUE;
        lhs.expression = bad;

        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::VALUE;
        rhs.expression = bad;

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT);
        assert(r.solver_result == "precheck_structural_equal");
    }

    // Oversized loads should now remain solver-visible instead of dropping to encoding_error.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::VALUE;
        lhs.expression = SymExpr::makeLoad(SymExpr::makeConst(0x1000), 9);

        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::VALUE;
        rhs.expression = SymExpr::makeConst(0);

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.solver_result == "sat");
        assert(!r.model.empty());
        assert(!r.witness.empty());
    }

    // Composite with metadata-only pieces should short-circuit to equivalent precheck bucket.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::COMPOSITE;
        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::COMPOSITE;

        SymPiece lp;
        lp.kind = SymPiece::Kind::IMPLICIT;
        lp.byte_size = 4;
        lp.implicit_bytes = {0xaa, 0xbb, 0xcc, 0xdd};

        SymPiece rp = lp;
        lhs.pieces.push_back(lp);
        rhs.pieces.push_back(rp);

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict ==
#if DWARF_HAS_Z3
               ExpressionVerificationResult::Verdict::EQUIVALENT
#else
               ExpressionVerificationResult::Verdict::UNKNOWN
#endif
        );
        assert(r.solver_result == "precheck_no_symbolic_piece");
    }

    // Composite wide-byte piece locations should compare deterministically without encoding_error.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::COMPOSITE;
        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::COMPOSITE;

        SymPiece lp;
        lp.kind = SymPiece::Kind::IMPLICIT;
        lp.byte_size = 9;
        lp.location = SymExpr::makeBytes({0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03});

        SymPiece rp = lp;
        lhs.pieces.push_back(lp);
        rhs.pieces.push_back(rp);

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT);
        assert(r.solver_result == "precheck_piece_wide_bytes_equal" ||
               r.solver_result == "precheck_piece_structural_equal");
    }

    // Distinct composite wide-byte piece locations should also compare deterministically.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::COMPOSITE;
        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::COMPOSITE;

        SymPiece lp;
        lp.kind = SymPiece::Kind::IMPLICIT;
        lp.byte_size = 9;
        lp.location = SymExpr::makeBytes({0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03});

        SymPiece rp = lp;
        rp.location = SymExpr::makeBytes({0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18});

        lhs.pieces.push_back(lp);
        rhs.pieces.push_back(rp);

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.solver_result == "precheck_piece_wide_bytes_mismatch");
    }

    // Composite wide-byte pieces should remain solver-visible against non-byte piece expressions.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::COMPOSITE;
        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::COMPOSITE;

        SymPiece lp;
        lp.kind = SymPiece::Kind::IMPLICIT;
        lp.byte_size = 9;
        lp.location = SymExpr::makeBytes({0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03});

        SymPiece rp = lp;
        rp.location = SymExpr::makeConst(0);

        lhs.pieces.push_back(lp);
        rhs.pieces.push_back(rp);

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.solver_result == "sat");
        assert(!r.model.empty());
        assert(!r.witness.empty());
    }

    // Identical unsupported composite piece expressions should also short-circuit before SMT encoding.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::COMPOSITE;
        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::COMPOSITE;

        SymPiece lp;
        lp.kind = SymPiece::Kind::MEMORY;
        lp.byte_size = 9;
        lp.location = SymExpr::makeLoad(SymExpr::makeConst(0x1000), 9);

        SymPiece rp = lp;
        lhs.pieces.push_back(lp);
        rhs.pieces.push_back(rp);

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::EQUIVALENT);
        assert(r.solver_result == "precheck_piece_structural_equal");
    }

    // Oversized composite-piece loads should remain solver-visible against non-load piece expressions.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::COMPOSITE;
        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::COMPOSITE;

        SymPiece lp;
        lp.kind = SymPiece::Kind::MEMORY;
        lp.byte_size = 9;
        lp.location = SymExpr::makeLoad(SymExpr::makeConst(0x1000), 9);

        SymPiece rp = lp;
        rp.location = SymExpr::makeConst(0);

        lhs.pieces.push_back(lp);
        rhs.pieces.push_back(rp);

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.solver_result == "sat");
        assert(!r.model.empty());
        assert(!r.witness.empty());
    }

    // Composite piece metadata mismatch should fail fast with deterministic precheck bucket.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::COMPOSITE;
        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::COMPOSITE;

        SymPiece lp;
        lp.kind = SymPiece::Kind::MEMORY;
        lp.byte_size = 8;
        lp.location = SymExpr::makeVar("reg1");

        SymPiece rp = lp;
        rp.byte_size = 4; // metadata mismatch

        lhs.pieces.push_back(lp);
        rhs.pieces.push_back(rp);

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.solver_result == "precheck_piece_metadata_mismatch");
    }

    // Composite location presence mismatch should also fail before solver invocation.
    {
        SymbolicExpressionResult lhs;
        lhs.type = SymbolicExpressionResult::Type::COMPOSITE;
        SymbolicExpressionResult rhs;
        rhs.type = SymbolicExpressionResult::Type::COMPOSITE;

        SymPiece lp;
        lp.kind = SymPiece::Kind::MEMORY;
        lp.byte_size = 8;
        lp.location = SymExpr::makeVar("reg1");

        SymPiece rp = lp;
        rp.location.reset(); // presence mismatch

        lhs.pieces.push_back(lp);
        rhs.pieces.push_back(rp);

        auto r = smt.verify(lhs, rhs);
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.solver_result == "precheck_piece_location_presence_mismatch");
    }

    std::cout << "SMTExpressionVerifier behavior tests passed!" << std::endl;
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
    assert(rx->verification.verdict ==
#if DWARF_HAS_Z3
           ExpressionVerificationResult::Verdict::EQUIVALENT
#else
           ExpressionVerificationResult::Verdict::UNKNOWN
#endif
    );
    assert(ry->verification.verdict ==
#if DWARF_HAS_Z3
           ExpressionVerificationResult::Verdict::DIFFERENT
#else
           ExpressionVerificationResult::Verdict::UNKNOWN
#endif
    );
    assert(rz->verification.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);
    assert(rz->lhs_present && !rz->rhs_present);
    auto summary = cmp.summarize(results);
    assert(summary.total == 3);
#if DWARF_HAS_Z3
    assert(summary.equivalent == 1);
    assert(summary.different == 1);
#else
    assert(summary.equivalent == 0);
    assert(summary.different == 0);
#endif
    assert(summary.unknown ==
#if DWARF_HAS_Z3
           1
#else
           3
#endif
    );
    assert(summary.missing_lhs == 0);
    assert(summary.missing_rhs == 1);

    std::string text_report = cmp.renderTextReport(results);
    assert(text_report.find("summary total=3") != std::string::npos);
    assert(text_report.find("x|DW_TAG_variable|1|1|") != std::string::npos);
    assert(text_report.find("lhs_unsupported_opcode") != std::string::npos);
    assert(text_report.find("DIFFERENT") != std::string::npos ||
#if DWARF_HAS_Z3
           false
#else
           text_report.find("UNKNOWN") != std::string::npos
#endif
    );

    std::string json_report = cmp.renderJsonReport(results);
    assert(json_report.find("\"total\":3") != std::string::npos);
    assert(json_report.find(
#if DWARF_HAS_Z3
           "\"different\":1"
#else
           "\"different\":0"
#endif
    ) != std::string::npos);
    assert(json_report.find("\"name\":\"x\"") != std::string::npos);
    assert(json_report.find("\"lhs_unsupported_opcode\"") != std::string::npos);

    CrossBinaryGateOptions gate_default;
    auto gate_fail = cmp.evaluateGate(results, gate_default);
#if DWARF_HAS_Z3
    assert(!gate_fail.pass);
    assert(gate_fail.reason.find("different") != std::string::npos);
    assert(gate_fail.trigger == "max_different");
#else
    assert(gate_fail.pass);
    assert(gate_fail.trigger == "none");
#endif
    assert(!gate_fail.signature.empty());

    CrossBinaryGateOptions gate_allow_one_diff;
    gate_allow_one_diff.max_different = 1;
    auto gate_pass = cmp.evaluateGate(results, gate_allow_one_diff);
    assert(gate_pass.pass);
    assert(gate_pass.trigger == "none");

    CrossBinaryGateOptions gate_fail_missing;
    gate_fail_missing.max_different = 1;
    gate_fail_missing.fail_on_missing = true;
    auto gate_missing = cmp.evaluateGate(results, gate_fail_missing);
    assert(!gate_missing.pass);
    assert(gate_missing.reason.find("missing") != std::string::npos);
    assert(gate_missing.trigger == "fail_on_missing");

    // Solver/backend deny-lists are enforced even when count-based limits pass.
    {
        NamedExpressionComparison row;
        row.name = "k";
        row.tag = DwarfTag::DW_TAG_variable;
        row.lhs_present = true;
        row.rhs_present = true;
        row.verification.verdict = ExpressionVerificationResult::Verdict::EQUIVALENT;
        row.verification.solver_result = "unsat";
        row.verification.verifier_backend =
#if DWARF_HAS_Z3
            "z3";
#else
            "solver-unavailable";
#endif

        std::vector<NamedExpressionComparison> rows = {row};

        CrossBinaryGateOptions deny_solver;
        deny_solver.max_different = 0;
        deny_solver.max_unknown = 0;
        deny_solver.fail_on_solver_results.insert("unsat");
        auto gate_solver = cmp.evaluateGate(rows, deny_solver);
        assert(!gate_solver.pass);
        assert(gate_solver.reason.find("disallowed solver_result encountered: unsat") != std::string::npos);
        assert(gate_solver.trigger == "fail_on_solver_result");
        assert(gate_solver.trigger_detail == "unsat");

        CrossBinaryGateOptions deny_backend;
        deny_backend.max_different = 0;
        deny_backend.max_unknown = 0;
        deny_backend.fail_on_verifier_backends.insert(
#if DWARF_HAS_Z3
            "z3"
#else
            "solver-unavailable"
#endif
        );
        auto gate_backend = cmp.evaluateGate(rows, deny_backend);
        assert(!gate_backend.pass);
        assert(gate_backend.reason.find(
#if DWARF_HAS_Z3
            "disallowed verifier_backend encountered: z3"
#else
            "disallowed verifier_backend encountered: solver-unavailable"
#endif
        ) != std::string::npos);
        assert(gate_backend.trigger == "fail_on_verifier_backend");
        assert(gate_backend.trigger_detail ==
#if DWARF_HAS_Z3
               "z3"
#else
               "solver-unavailable"
#endif
        );

        CrossBinaryGateOptions allow_backend;
        allow_backend.max_different = 0;
        allow_backend.max_unknown = 0;
        allow_backend.fail_on_verifier_backends.insert("structural");
        auto gate_backend_ok = cmp.evaluateGate(rows, allow_backend);
        assert(gate_backend_ok.pass);

        // Empty metadata is normalized to "unspecified" for deny-list matching.
        NamedExpressionComparison unspecified = row;
        unspecified.verification.solver_result.clear();
        unspecified.verification.verifier_backend.clear();
        std::vector<NamedExpressionComparison> unspecified_rows = {unspecified};

        CrossBinaryGateOptions deny_solver_unspecified;
        deny_solver_unspecified.max_different = 0;
        deny_solver_unspecified.max_unknown = 0;
        deny_solver_unspecified.fail_on_solver_results.insert("unspecified");
        auto gate_solver_unspecified = cmp.evaluateGate(unspecified_rows, deny_solver_unspecified);
        assert(!gate_solver_unspecified.pass);
        assert(gate_solver_unspecified.reason.find("disallowed solver_result encountered: unspecified") != std::string::npos);
        assert(gate_solver_unspecified.trigger == "fail_on_solver_result");
        assert(gate_solver_unspecified.trigger_detail == "unspecified");

        CrossBinaryGateOptions deny_backend_unspecified;
        deny_backend_unspecified.max_different = 0;
        deny_backend_unspecified.max_unknown = 0;
        deny_backend_unspecified.fail_on_verifier_backends.insert("unspecified");
        auto gate_backend_unspecified = cmp.evaluateGate(unspecified_rows, deny_backend_unspecified);
        assert(!gate_backend_unspecified.pass);
        assert(gate_backend_unspecified.reason.find("disallowed verifier_backend encountered: unspecified") != std::string::npos);
        assert(gate_backend_unspecified.trigger == "fail_on_verifier_backend");
        assert(gate_backend_unspecified.trigger_detail == "unspecified");

        // If both deny-lists match, solver_result takes precedence in gate reason.
        CrossBinaryGateOptions deny_both;
        deny_both.max_different = 0;
        deny_both.max_unknown = 0;
        deny_both.fail_on_solver_results.insert("unsat");
        deny_both.fail_on_verifier_backends.insert(
#if DWARF_HAS_Z3
            "z3"
#else
            "solver-unavailable"
#endif
        );
        auto gate_both = cmp.evaluateGate(rows, deny_both);
        assert(!gate_both.pass);
        assert(gate_both.reason.find("disallowed solver_result encountered: unsat") != std::string::npos);
        assert(gate_both.trigger == "fail_on_solver_result");
        assert(gate_both.trigger_detail == "unsat");
    }

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
        assert(linked[0].verification.verdict ==
#if DWARF_HAS_Z3
               ExpressionVerificationResult::Verdict::EQUIVALENT
#else
               ExpressionVerificationResult::Verdict::UNKNOWN
#endif
        );

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

    // Range-aware compare should honor per-side entry_value contexts and coverage accounting.
    {
        auto lcu = std::make_shared<DIE>(DwarfTag::DW_TAG_compile_unit, 0xb00, 0);
        auto rcu = std::make_shared<DIE>(DwarfTag::DW_TAG_compile_unit, 0xc00, 0);

        auto makeListVar = [](const std::string& name,
                              const std::vector<LocationAttributeValue::LocationEntry>& entries,
                              uint64_t off) {
            auto die = std::make_shared<DIE>(DwarfTag::DW_TAG_variable, off, 0);
            die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>(name));
            die->addAttribute(DwarfAttribute::DW_AT_location,
                              std::make_shared<LocationAttributeValue>(entries));
            return die;
        };

        std::vector<uint8_t> entry_reg5 = {
            static_cast<uint8_t>(DwarfOp::DW_OP_entry_value),
            0x01,
            static_cast<uint8_t>(DwarfOp::DW_OP_reg5),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
        };
        std::vector<uint8_t> lit7 = {
            static_cast<uint8_t>(DwarfOp::DW_OP_lit7),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
        };
        std::vector<uint8_t> lit9 = {
            static_cast<uint8_t>(DwarfOp::DW_OP_lit9),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
        };

        std::vector<LocationAttributeValue::LocationEntry> lhs_entries;
        lhs_entries.emplace_back(0x10, 0x20, entry_reg5, false);
        lhs_entries.emplace_back(0x20, 0x30, lit9, false);

        std::vector<LocationAttributeValue::LocationEntry> rhs_entries;
        rhs_entries.emplace_back(0x10, 0x20, lit7, false);
        rhs_entries.emplace_back(0x20, 0x40, lit9, false);

        lcu->addChild(makeListVar("range_ctx", lhs_entries, 0xb10));
        rcu->addChild(makeListVar("range_ctx", rhs_entries, 0xc10));

        CrossBinaryCompareOptions range_opts;
        range_opts.tag = DwarfTag::DW_TAG_variable;
        range_opts.attribute = DwarfAttribute::DW_AT_location;
        range_opts.enable_range_aware_location_compare = true;
        range_opts.enable_location_semantic_normalization = true;
        range_opts.include_missing = true;
        range_opts.lhs_context.address_size = 8;
        range_opts.rhs_context.address_size = 8;
        range_opts.lhs_context.entry_registers = std::vector<uint64_t>(16, 0);
        range_opts.rhs_context.entry_registers = std::vector<uint64_t>(16, 0);
        range_opts.lhs_context.entry_registers[5] = 7;

        auto range_rows = cmp.compareDIEListsByName({lcu}, {rcu}, range_opts);
        assert(range_rows.size() == 1);
        const auto& row = range_rows.front();
        assert(row.range_aware);
        assert(row.coverage_total == 0x30);
        assert(row.coverage_equivalent == 0x20);
        assert(row.coverage_different == 0);
        assert(row.coverage_unknown == 0);
        assert(row.coverage_uncovered == 0x10);
        assert(row.range_segments.size() == 3);
        assert(row.range_segments[0].start == 0x10 && row.range_segments[0].end == 0x20);
        assert(row.range_segments[0].verdict ==
#if DWARF_HAS_Z3
               ExpressionVerificationResult::Verdict::EQUIVALENT
#else
               ExpressionVerificationResult::Verdict::UNKNOWN
#endif
        );
        assert(row.range_segments[1].start == 0x20 && row.range_segments[1].end == 0x30);
        assert(row.range_segments[1].verdict ==
#if DWARF_HAS_Z3
               ExpressionVerificationResult::Verdict::EQUIVALENT
#else
               ExpressionVerificationResult::Verdict::UNKNOWN
#endif
        );
        assert(row.range_segments[2].start == 0x30 && row.range_segments[2].end == 0x40);
        assert(!row.range_segments[2].lhs_present && row.range_segments[2].rhs_present);
        assert(row.verification.reason.find("range-aware coverage eq=") != std::string::npos);
        assert(row.verification.reason.find("uncovered=16") != std::string::npos);
        assert(row.verification.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);

        auto range_summary = cmp.summarize(range_rows);
        assert(range_summary.total == 1);
        assert(range_summary.coverage_total == 0x30);
        assert(range_summary.coverage_equivalent == 0x20);
        assert(range_summary.coverage_uncovered == 0x10);

        CrossBinaryGateOptions coverage_gate;
        coverage_gate.max_different = std::numeric_limits<size_t>::max();
        coverage_gate.max_unknown = std::numeric_limits<size_t>::max();
        coverage_gate.fail_on_uncovered = true;
        auto range_gate = cmp.evaluateGate(range_rows, coverage_gate);
        assert(!range_gate.pass);
        assert(range_gate.trigger == "fail_on_uncovered");
        assert(range_gate.trigger_detail == "16");
    }

    // Location semantic normalization should merge adjacent equivalent ranges before segmentation.
    {
        auto lcu = std::make_shared<DIE>(DwarfTag::DW_TAG_compile_unit, 0xd00, 0);
        auto rcu = std::make_shared<DIE>(DwarfTag::DW_TAG_compile_unit, 0xe00, 0);

        auto makeListVar = [](const std::string& name,
                              const std::vector<LocationAttributeValue::LocationEntry>& entries,
                              uint64_t off) {
            auto die = std::make_shared<DIE>(DwarfTag::DW_TAG_variable, off, 0);
            die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>(name));
            die->addAttribute(DwarfAttribute::DW_AT_location,
                              std::make_shared<LocationAttributeValue>(entries));
            return die;
        };

        std::vector<uint8_t> lit4 = {
            static_cast<uint8_t>(DwarfOp::DW_OP_lit4),
            static_cast<uint8_t>(DwarfOp::DW_OP_stack_value)
        };

        std::vector<LocationAttributeValue::LocationEntry> lhs_entries;
        lhs_entries.emplace_back(0x10, 0x18, lit4, false);
        lhs_entries.emplace_back(0x18, 0x20, lit4, false);

        std::vector<LocationAttributeValue::LocationEntry> rhs_entries;
        rhs_entries.emplace_back(0x10, 0x20, lit4, false);

        lcu->addChild(makeListVar("range_norm", lhs_entries, 0xd10));
        rcu->addChild(makeListVar("range_norm", rhs_entries, 0xe10));

        CrossBinaryCompareOptions raw_opts;
        raw_opts.tag = DwarfTag::DW_TAG_variable;
        raw_opts.attribute = DwarfAttribute::DW_AT_location;
        raw_opts.enable_range_aware_location_compare = true;
        raw_opts.enable_location_semantic_normalization = false;

        auto raw_rows = cmp.compareDIEListsByName({lcu}, {rcu}, raw_opts);
        assert(raw_rows.size() == 1);
        const auto& raw = raw_rows.front();
        assert(raw.range_aware);
        assert(raw.coverage_total == 0x10);
        assert(raw.coverage_equivalent == 0x10);
        assert(raw.coverage_uncovered == 0);
        assert(raw.range_segments.size() == 2);
        assert(raw.range_segments[0].start == 0x10 && raw.range_segments[0].end == 0x18);
        assert(raw.range_segments[1].start == 0x18 && raw.range_segments[1].end == 0x20);

        CrossBinaryCompareOptions norm_opts = raw_opts;
        norm_opts.enable_location_semantic_normalization = true;

        auto norm_rows = cmp.compareDIEListsByName({lcu}, {rcu}, norm_opts);
        assert(norm_rows.size() == 1);
        const auto& norm = norm_rows.front();
        assert(norm.range_aware);
        assert(norm.coverage_total == 0x10);
        assert(norm.coverage_equivalent == 0x10);
        assert(norm.coverage_uncovered == 0);
        assert(norm.range_segments.size() == 1);
        assert(norm.range_segments[0].start == 0x10 && norm.range_segments[0].end == 0x20);
        assert(norm.verification.verdict ==
#if DWARF_HAS_Z3
               ExpressionVerificationResult::Verdict::EQUIVALENT
#else
               ExpressionVerificationResult::Verdict::UNKNOWN
#endif
        );
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

void testGnuAltForms() {
    std::cout << "Testing DW_FORM_GNU_strp_alt/DW_FORM_GNU_ref_alt..." << std::endl;

    const uint64_t kSupBias = (1ULL << 62);

    // debug_info holds: gnu_strp_alt offset + gnu_ref_alt offset.
    std::vector<uint8_t> debug_info;
    appendU32(debug_info, 4);     // GNU_strp_alt -> "hi"
    appendU32(debug_info, 0x30);  // GNU_ref_alt -> supplementary DIE offset

    std::vector<uint8_t> empty;
    std::vector<uint8_t> debug_str_sup = {'x', 'y', 'z', 0, 'h', 'i', 0};

    AttributeParser ap(debug_info, empty, /*debug_str=*/empty,
                       /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                       /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                       /*debug_rnglists=*/empty, /*debug_loclists=*/empty,
                       /*debug_str_sup=*/debug_str_sup);
    ap.setIsDwarf64(false);
    ap.setSupplementaryDebugInfoOffsetBias(kSupBias);

    uint64_t off = 0;
    auto s = std::dynamic_pointer_cast<StringAttributeValue>(
        ap.parseAttribute(DwarfForm::DW_FORM_GNU_strp_alt, off));
    assert(s);
    assert(s->getValue() == "hi");

    auto r = std::dynamic_pointer_cast<ReferenceAttributeValue>(
        ap.parseAttribute(DwarfForm::DW_FORM_GNU_ref_alt, off));
    assert(r);
    assert(r->getOffset() == kSupBias + 0x30);

    std::cout << "DW_FORM_GNU_strp_alt/DW_FORM_GNU_ref_alt tests passed!" << std::endl;
}

void testGnuIndexForms() {
    std::cout << "Testing DW_FORM_GNU_str_index/DW_FORM_GNU_addr_index..." << std::endl;

    std::vector<uint8_t> debug_info = {0x00, 0x00}; // two ULEB128 zeros
    std::vector<uint8_t> empty;
    std::vector<uint8_t> debug_str = {'h', 'i', 0};
    std::vector<uint8_t> debug_str_offsets;
    appendU32(debug_str_offsets, 0); // index 0 -> debug_str offset 0
    std::vector<uint8_t> debug_addr;
    appendU64(debug_addr, 0x1122334455667788ULL); // index 0

    AttributeParser ap(debug_info, empty, debug_str,
                       /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                       /*debug_str_offsets=*/debug_str_offsets, /*debug_addr=*/debug_addr, /*debug_line_str=*/empty,
                       /*debug_rnglists=*/empty, /*debug_loclists=*/empty,
                       /*debug_str_sup=*/empty);
    ap.setIsDwarf64(false);
    ap.setAddressSize(8);
    ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0,
                    /*addr_base=*/0, /*str_offsets_base=*/0, /*base_address=*/0);

    uint64_t off = 0;
    auto s = std::dynamic_pointer_cast<StringAttributeValue>(
        ap.parseAttribute(DwarfForm::DW_FORM_GNU_str_index, off));
    assert(s);
    assert(s->getValue() == "hi");

    auto a = std::dynamic_pointer_cast<AddressAttributeValue>(
        ap.parseAttribute(DwarfForm::DW_FORM_GNU_addr_index, off));
    assert(a);
    assert(a->getAddress() == 0x1122334455667788ULL);

    std::cout << "DW_FORM_GNU_str_index/DW_FORM_GNU_addr_index tests passed!" << std::endl;
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

void testDIEParserUnknownVendorFormSkip() {
    std::cout << "Testing DIEParser skip for unknown vendor form..." << std::endl;

    auto runCase = [](uint64_t vendor_form,
                      const std::vector<uint8_t>& payload,
                      const std::string& expected_name) {
        // Abbrev table:
        // 1: compile_unit, no children, attributes:
        //    - DW_AT_type with unknown vendor form
        //    - DW_AT_name with DW_FORM_strp
        std::vector<uint8_t> debug_abbrev;
        appendULEB(debug_abbrev, 1);      // abbrev code
        appendULEB(debug_abbrev, 0x11);   // DW_TAG_compile_unit
        debug_abbrev.push_back(0x00);     // no children
        appendULEB(debug_abbrev, 0x49);   // DW_AT_type
        appendULEB(debug_abbrev, vendor_form);
        appendULEB(debug_abbrev, 0x03);   // DW_AT_name
        appendULEB(debug_abbrev, 0x0e);   // DW_FORM_strp
        debug_abbrev.push_back(0x00);     // end attr list
        debug_abbrev.push_back(0x00);
        debug_abbrev.push_back(0x00);     // end abbrev table

        // Build .debug_info (DWARF4): CU DIE with unknown vendor payload then strp.
        std::vector<uint8_t> debug_info;
        appendU32(debug_info, 0);         // unit_length placeholder
        debug_info.push_back(0x04);       // version 4
        debug_info.push_back(0x00);
        appendU32(debug_info, 0);         // abbrev offset
        debug_info.push_back(0x08);       // address size
        appendULEB(debug_info, 1);        // CU DIE abbrev code 1
        debug_info.insert(debug_info.end(), payload.begin(), payload.end());
        appendU32(debug_info, 0);         // DW_FORM_strp -> debug_str[0]

        uint32_t unit_length = static_cast<uint32_t>(debug_info.size() - 4);
        debug_info[0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_info[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_info[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_info[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

        std::vector<uint8_t> debug_str(expected_name.begin(), expected_name.end());
        debug_str.push_back(0);
        std::vector<uint8_t> empty;
        ELFIO::elfio elf;

        DIEParser parser(elf, debug_info, debug_abbrev, debug_str,
                         /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                         /*debug_str_offsets=*/empty, /*debug_addr=*/empty, /*debug_line_str=*/empty,
                         /*debug_rnglists=*/empty, /*debug_loclists=*/empty,
                         /*debug_str_sup=*/empty);
        auto cus = parser.parseCompilationUnits();
        assert(cus.size() == 1);
        assert(cus[0]);
        // Unknown vendor form should be skipped so the following DW_AT_name still parses.
        if (cus[0]->getName() != expected_name) {
            std::cerr << "vendor form 0x" << std::hex << vendor_form << std::dec
                      << " expected name='" << expected_name
                      << "' actual='" << cus[0]->getName() << "'" << std::endl;
            assert(false);
        }
        // Unknown vendor form is unsupported and should not produce a DW_AT_type attribute.
        assert(!cus[0]->hasAttribute(DwarfAttribute::DW_AT_type));
    };

    // Unknown vendor form with offset-sized payload family (legacy fallback path).
    runCase(/*vendor_form=*/0x1f22,
            /*payload=*/std::vector<uint8_t>{0x44, 0x33, 0x22, 0x11},
            /*expected_name=*/"ok");

    // Unknown vendor form with block1-style payload family (new heuristic path).
    // 0x1f0a mirrors low-byte DW_FORM_block1 operand encoding.
    runCase(/*vendor_form=*/0x1f0a,
            /*payload=*/std::vector<uint8_t>{0x03, 0xaa, 0xbb, 0xcc},
            /*expected_name=*/"blk");

    // Unknown vendor form with indirect-style payload family.
    // 0x1f16 mirrors low-byte DW_FORM_indirect operand encoding:
    //   nested form = DW_FORM_data1 (0x0b), payload = 0x7a.
    runCase(/*vendor_form=*/0x1f16,
            /*payload=*/std::vector<uint8_t>{0x0b, 0x7a},
            /*expected_name=*/"ind");

    // Unknown vendor form with nested indirect vendor-style payload family.
    // 0x1f16 mirrors DW_FORM_indirect, whose nested form is itself vendor-shaped
    // and mirrors DW_FORM_block1 (0x0a): [uleb 0x1f0a][len=3][aa bb cc].
    std::vector<uint8_t> nested_vendor_indirect;
    appendULEB(nested_vendor_indirect, 0x1f0a);
    nested_vendor_indirect.push_back(0x03);
    nested_vendor_indirect.push_back(0xaa);
    nested_vendor_indirect.push_back(0xbb);
    nested_vendor_indirect.push_back(0xcc);
    runCase(/*vendor_form=*/0x1f16,
            /*payload=*/nested_vendor_indirect,
            /*expected_name=*/"vind");

    // Unknown vendor form with supplementary-reference-style payload family.
    // 0x1f24 mirrors low-byte DW_FORM_ref_sup8 (8-byte payload).
    runCase(/*vendor_form=*/0x1f24,
            /*payload=*/std::vector<uint8_t>{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11},
            /*expected_name=*/"sup8");

    std::cout << "DIEParser unknown vendor form skip tests passed!" << std::endl;
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
    assert(entries[0].die_offsets[0] != 0);

    std::cout << ".debug_names parser tests passed!" << std::endl;
}

void testDebugNamesParserTypeUnitIndexResolvesDIEOffsets() {
    std::cout << "Testing .debug_names DW_IDX_type_unit DIE offset resolution..." << std::endl;

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
    auto appendU64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) debug_names.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xff));
    };

    appendU32(0);  // unit_length placeholder
    appendU16(5);  // version
    appendU16(0);  // padding
    appendU32(1);  // comp_unit_count
    appendU32(1);  // local_type_unit_count
    appendU32(1);  // foreign_type_unit_count
    appendU32(1);  // bucket_count
    appendU32(1);  // name_count

    size_t abbrev_size_pos = debug_names.size();
    appendU32(0);  // abbrev_table_size placeholder
    appendU32(0);  // augmentation_string_size

    // CU list + TU list + foreign TU signatures.
    appendU32(0x100);  // cu_offsets[0]
    appendU32(0x500);  // tu_offsets[0]
    appendU64(0xDEADBEEFCAFEBABEULL); // foreign type signature (ignored)

    // Buckets/hashes/name_offsets/entry_offsets.
    appendU32(1);        // bucket[0]
    appendU32(foo_hash); // hash[0]
    appendU32(0);        // name_offsets[0] -> "foo"
    appendU32(0);        // entry_offsets[0] -> start of entry pool

    // Abbrev table:
    // code=1, tag=DW_TAG_variable
    // (DW_IDX_type_unit, DW_FORM_data1), (DW_IDX_die_offset, DW_FORM_data4), terminator, end-of-table(0)
    std::vector<uint8_t> abbrev;
    abbrev.push_back(0x01);
    abbrev.push_back(static_cast<uint8_t>(DwarfTag::DW_TAG_variable));
    abbrev.push_back(0x02); // DW_IDX_type_unit
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data1));
    abbrev.push_back(0x03); // DW_IDX_die_offset
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data4));
    abbrev.push_back(0x00);
    abbrev.push_back(0x00);
    abbrev.push_back(0x00);

    uint32_t abbrev_size = static_cast<uint32_t>(abbrev.size());
    debug_names[abbrev_size_pos + 0] = static_cast<uint8_t>(abbrev_size & 0xff);
    debug_names[abbrev_size_pos + 1] = static_cast<uint8_t>((abbrev_size >> 8) & 0xff);
    debug_names[abbrev_size_pos + 2] = static_cast<uint8_t>((abbrev_size >> 16) & 0xff);
    debug_names[abbrev_size_pos + 3] = static_cast<uint8_t>((abbrev_size >> 24) & 0xff);
    debug_names.insert(debug_names.end(), abbrev.begin(), abbrev.end());

    // Entry pool: abbrev_code=1, tu_index=0, die_offset=0x20, end marker.
    appendU8(0x01);
    appendU8(0x00);
    appendU32(0x20);
    appendU8(0x00);

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
    assert(entries[0].die_offsets[0] == 0x520);

    std::cout << ".debug_names DW_IDX_type_unit tests passed!" << std::endl;
}

void testDebugNamesParserMultipleUnitsLookup() {
    std::cout << "Testing .debug_names multi-unit lookup..." << std::endl;

    std::vector<uint8_t> debug_str = {'f','o','o',0,'b','a','r',0};
    auto djb32 = [](const char* s) -> uint32_t {
        uint32_t h = 5381;
        while (*s) {
            h = ((h << 5) + h) + static_cast<uint8_t>(*s++);
        }
        return h;
    };

    auto buildUnit = [&](uint32_t cu_off, uint32_t str_off, const char* name, uint32_t die_rel) -> std::vector<uint8_t> {
        std::vector<uint8_t> u;
        auto appendU8 = [&](uint8_t v) { u.push_back(v); };
        auto appendU16 = [&](uint16_t v) {
            u.push_back(static_cast<uint8_t>(v & 0xff));
            u.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        };
        auto appendU32 = [&](uint32_t v) {
            u.push_back(static_cast<uint8_t>(v & 0xff));
            u.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
            u.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
            u.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
        };

        appendU32(0);  // unit_length placeholder
        appendU16(5);  // version
        appendU16(0);  // padding
        appendU32(1);  // comp_unit_count
        appendU32(0);  // local_type_unit_count
        appendU32(0);  // foreign_type_unit_count
        appendU32(1);  // bucket_count
        appendU32(1);  // name_count

        size_t abbrev_size_pos = u.size();
        appendU32(0);  // abbrev_table_size placeholder
        appendU32(0);  // augmentation_string_size

        appendU32(cu_off); // CU list
        appendU32(1);      // bucket[0]
        appendU32(djb32(name));
        appendU32(str_off);
        appendU32(0);      // entry_offsets[0]

        std::vector<uint8_t> abbrev;
        abbrev.push_back(0x01);
        abbrev.push_back(static_cast<uint8_t>(DwarfTag::DW_TAG_variable));
        abbrev.push_back(0x01); // DW_IDX_compile_unit
        abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data1));
        abbrev.push_back(0x03); // DW_IDX_die_offset
        abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data4));
        abbrev.push_back(0x00);
        abbrev.push_back(0x00);
        abbrev.push_back(0x00);

        uint32_t abbrev_size = static_cast<uint32_t>(abbrev.size());
        u[abbrev_size_pos + 0] = static_cast<uint8_t>(abbrev_size & 0xff);
        u[abbrev_size_pos + 1] = static_cast<uint8_t>((abbrev_size >> 8) & 0xff);
        u[abbrev_size_pos + 2] = static_cast<uint8_t>((abbrev_size >> 16) & 0xff);
        u[abbrev_size_pos + 3] = static_cast<uint8_t>((abbrev_size >> 24) & 0xff);
        u.insert(u.end(), abbrev.begin(), abbrev.end());

        // Entry pool.
        appendU8(0x01);
        appendU8(0x00);
        appendU32(die_rel);
        appendU8(0x00);

        uint32_t unit_length = static_cast<uint32_t>(u.size() - 4);
        u[0] = static_cast<uint8_t>(unit_length & 0xff);
        u[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        u[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        u[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
        return u;
    };

    std::vector<uint8_t> debug_names;
    auto u1 = buildUnit(/*cu_off=*/0x100, /*str_off=*/0, "foo", /*die_rel=*/0x20);
    auto u2 = buildUnit(/*cu_off=*/0x200, /*str_off=*/4, "bar", /*die_rel=*/0x30);
    debug_names.insert(debug_names.end(), u1.begin(), u1.end());
    debug_names.insert(debug_names.end(), u2.begin(), u2.end());

    DebugNamesParser parser(debug_names, debug_str);
    assert(parser.parse());
    auto foo = parser.lookupName("foo");
    auto bar = parser.lookupName("bar");
    assert(foo.size() == 1 && foo[0].die_offsets.size() == 1 && foo[0].die_offsets[0] == 0x120);
    assert(bar.size() == 1 && bar[0].die_offsets.size() == 1 && bar[0].die_offsets[0] == 0x230);

    std::cout << ".debug_names multi-unit lookup tests passed!" << std::endl;
}

void testDebugNamesParserRealWorldMultiUnitFixture() {
    std::cout << "Testing .debug_names real-world multi-unit fixture..." << std::endl;

    auto debug_names = loadTestDataBinary("debug_names_real_world.bin");
    auto debug_str = loadTestDataBinary("debug_names_real_world.str");

    DebugNamesParser parser(debug_names, debug_str);
    assert(parser.parse());

    const auto& headers = parser.getUnitHeaders();
    assert(headers.size() == 2);
    assert(headers[0].version == 5);
    assert(headers[1].version == 5);
    assert(headers[0].comp_unit_count == 1);
    assert(headers[1].comp_unit_count == 1);
    assert(headers[0].bucket_count == 1);
    assert(headers[1].bucket_count == 1);
    assert(headers[0].abbrev_table_size > 0);
    assert(headers[1].abbrev_table_size > 0);

    auto foo = parser.lookupName("foo");
    auto bar = parser.lookupName("bar");
    auto missing = parser.lookupName("does-not-exist");

    assert(foo.size() == 1);
    assert(bar.size() == 1);
    assert(foo[0].die_offsets.size() == 1);
    assert(bar[0].die_offsets.size() == 1);
    assert(foo[0].die_offsets[0] != bar[0].die_offsets[0]);
    assert(missing.empty());

    std::cout << ".debug_names real-world fixture tests passed!" << std::endl;
}

void testDebugNamesParserRealWorldMixedFixture() {
    std::cout << "Testing .debug_names real-world mixed fixture..." << std::endl;

    auto debug_names = loadTestDataBinary("debug_names_real_world_mixed.bin");
    auto debug_str = loadTestDataBinary("debug_names_real_world_mixed.str");

    DebugNamesParser parser(debug_names, debug_str);
    assert(parser.parse());

    const auto& headers = parser.getUnitHeaders();
    assert(headers.size() == 2);

    assert(headers[0].version == 5);
    assert(headers[0].comp_unit_count == 1);
    assert(headers[0].local_type_unit_count == 1);
    assert(headers[0].foreign_type_unit_count == 1);
    assert(headers[0].name_count == 2);
    assert(headers[0].augmentation_vendor_id == "GDB");
    assert(headers[0].augmentation_payload_size == 7);
    assert(headers[0].augmentation_payload.size() == 7);
    assert(headers[0].augmentation_payload[0] == 0x03);
    assert(headers[0].augmentation_payload[1] == 0x00);
    assert(headers[0].augmentation_payload[2] == 0x00);
    assert(headers[0].augmentation_payload[3] == 0x00);
    assert(headers[0].augmentation_payload[4] == 0xaa);
    assert(headers[0].augmentation_payload[5] == 0xbb);
    assert(headers[0].augmentation_payload[6] == 0xcc);

    assert(headers[1].version == 5);
    assert(headers[1].comp_unit_count == 1);
    assert(headers[1].local_type_unit_count == 0);
    assert(headers[1].foreign_type_unit_count == 1);
    assert(headers[1].name_count == 1);
    assert(headers[1].augmentation_string_size == 0);

    auto foo = parser.lookupName("foo");
    auto bar = parser.lookupName("bar");
    auto baz = parser.lookupName("baz");

    assert(foo.size() == 1);
    assert(bar.size() == 1);
    assert(baz.size() == 1);
    assert(foo[0].die_offsets.size() == 1);
    assert(bar[0].die_offsets.size() == 1);
    assert(baz[0].die_offsets.size() == 1);
    assert(foo[0].die_offsets[0] == 0x120);
    assert(bar[0].die_offsets[0] == 0x530);
    assert(baz[0].die_offsets[0] == 0x240);

    std::cout << ".debug_names real-world mixed fixture tests passed!" << std::endl;
}

void testDebugNamesParserNonEmptyAugmentationStringAccepted() {
    std::cout << "Testing .debug_names non-empty augmentation string acceptance..." << std::endl;

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

    appendU32(0); // unit_length placeholder
    appendU16(5); // version
    appendU16(0); // padding
    appendU32(0); // comp_unit_count
    appendU32(0); // local_type_unit_count
    appendU32(0); // foreign_type_unit_count
    appendU32(0); // bucket_count
    appendU32(0); // name_count
    appendU32(0); // abbrev_table_size
    appendU32(4); // augmentation_string_size
    debug_names.push_back('G');
    debug_names.push_back('D');
    debug_names.push_back('B');
    debug_names.push_back(0);

    uint32_t unit_length = static_cast<uint32_t>(debug_names.size() - 4);
    debug_names[0] = static_cast<uint8_t>(unit_length & 0xff);
    debug_names[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
    debug_names[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
    debug_names[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

    DebugNamesParser parser(debug_names, {});
    assert(parser.parse());

    std::cout << ".debug_names augmentation string tests passed!" << std::endl;
}

void testDebugNamesParserAugmentationPayloadSkipsBytes() {
    std::cout << "Testing .debug_names augmentation payload skipping..." << std::endl;

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

    appendU32(0);  // unit_length placeholder
    appendU16(5);  // version
    appendU16(0);  // padding
    appendU32(1);  // comp_unit_count
    appendU32(0);  // local_type_unit_count
    appendU32(0);  // foreign_type_unit_count
    appendU32(1);  // bucket_count
    appendU32(1);  // name_count

    size_t abbrev_size_pos = debug_names.size();
    appendU32(0);  // abbrev_table_size placeholder
    appendU32(4);  // augmentation_string_size
    appendU8('G');
    appendU8('D');
    appendU8('B');
    appendU8(0);

    // Augmentation payload (producer-specific). This is what we need to skip/recover from.
    appendU8(0xaa);
    appendU8(0xbb);
    appendU8(0xcc);

    // CU list
    appendU32(0x100);

    // Buckets
    appendU32(1);

    // Hashes
    appendU32(foo_hash);

    // Name offsets
    appendU32(0);

    // Entry offsets: entry pool starts after abbrev table, so 0 is valid.
    appendU32(0);

    // Abbrev table: same shape as testDebugNamesParser.
    std::vector<uint8_t> abbrev;
    abbrev.push_back(0x01); // code
    abbrev.push_back(static_cast<uint8_t>(DwarfTag::DW_TAG_variable)); // tag
    abbrev.push_back(0x01); // DW_IDX_compile_unit
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data1));
    abbrev.push_back(0x03); // DW_IDX_die_offset
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data4));
    abbrev.push_back(0x00);
    abbrev.push_back(0x00);
    abbrev.push_back(0x00);

    uint32_t abbrev_size = static_cast<uint32_t>(abbrev.size());
    debug_names[abbrev_size_pos + 0] = static_cast<uint8_t>(abbrev_size & 0xff);
    debug_names[abbrev_size_pos + 1] = static_cast<uint8_t>((abbrev_size >> 8) & 0xff);
    debug_names[abbrev_size_pos + 2] = static_cast<uint8_t>((abbrev_size >> 16) & 0xff);
    debug_names[abbrev_size_pos + 3] = static_cast<uint8_t>((abbrev_size >> 24) & 0xff);

    debug_names.insert(debug_names.end(), abbrev.begin(), abbrev.end());

    // Entry pool: abbrev_code=1, cu_index=0, die_offset=0x20, end marker.
    appendU8(0x01);
    appendU8(0x00);
    appendU32(0x20);
    appendU8(0x00);

    uint32_t unit_length = static_cast<uint32_t>(debug_names.size() - 4);
    debug_names[0] = static_cast<uint8_t>(unit_length & 0xff);
    debug_names[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
    debug_names[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
    debug_names[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

    DebugNamesParser parser(debug_names, debug_str);
    assert(parser.parse());
    assert(parser.getHeader().augmentation_vendor_id == "GDB");
    assert(parser.getHeader().augmentation_payload_size == 3);
    assert(parser.getHeader().augmentation_payload.size() == 3);
    assert(parser.getHeader().augmentation_payload[0] == 0xaa);
    assert(parser.getHeader().augmentation_payload[1] == 0xbb);
    assert(parser.getHeader().augmentation_payload[2] == 0xcc);
    auto entries = parser.lookupName("foo");
    assert(entries.size() == 1);
    assert(entries[0].die_offsets.size() == 1);
    assert(entries[0].die_offsets[0] == 0x120);

    std::cout << ".debug_names augmentation payload skipping tests passed!" << std::endl;
}

void testDebugNamesParserAugmentationPayloadLengthPrefixedSkipsBytes() {
    std::cout << "Testing .debug_names length-prefixed augmentation payload skipping..." << std::endl;

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

    appendU32(0);  // unit_length placeholder
    appendU16(5);  // version
    appendU16(0);  // padding
    appendU32(1);  // comp_unit_count
    appendU32(0);  // local_type_unit_count
    appendU32(0);  // foreign_type_unit_count
    appendU32(1);  // bucket_count
    appendU32(1);  // name_count

    size_t abbrev_size_pos = debug_names.size();
    appendU32(0);  // abbrev_table_size placeholder
    appendU32(4);  // augmentation_string_size
    appendU8('G'); appendU8('D'); appendU8('B'); appendU8(0);

    // Length-prefixed vendor augmentation payload: u32 length=3, then 3 bytes.
    appendU32(3);
    appendU8(0xaa);
    appendU8(0xbb);
    appendU8(0xcc);

    // CU list
    appendU32(0x100);
    // Buckets
    appendU32(1);
    // Hashes
    appendU32(foo_hash);
    // Name offsets
    appendU32(0);
    // Entry offsets
    appendU32(0);

    std::vector<uint8_t> abbrev;
    abbrev.push_back(0x01); // code
    abbrev.push_back(static_cast<uint8_t>(DwarfTag::DW_TAG_variable)); // tag
    abbrev.push_back(0x01); // DW_IDX_compile_unit
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data1));
    abbrev.push_back(0x03); // DW_IDX_die_offset
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data4));
    abbrev.push_back(0x00);
    abbrev.push_back(0x00);
    abbrev.push_back(0x00);

    uint32_t abbrev_size = static_cast<uint32_t>(abbrev.size());
    debug_names[abbrev_size_pos + 0] = static_cast<uint8_t>(abbrev_size & 0xff);
    debug_names[abbrev_size_pos + 1] = static_cast<uint8_t>((abbrev_size >> 8) & 0xff);
    debug_names[abbrev_size_pos + 2] = static_cast<uint8_t>((abbrev_size >> 16) & 0xff);
    debug_names[abbrev_size_pos + 3] = static_cast<uint8_t>((abbrev_size >> 24) & 0xff);
    debug_names.insert(debug_names.end(), abbrev.begin(), abbrev.end());

    // Entry pool.
    appendU8(0x01);
    appendU8(0x00);
    appendU32(0x20);
    appendU8(0x00);

    uint32_t unit_length = static_cast<uint32_t>(debug_names.size() - 4);
    debug_names[0] = static_cast<uint8_t>(unit_length & 0xff);
    debug_names[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
    debug_names[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
    debug_names[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);

    DebugNamesParser parser(debug_names, debug_str);
    assert(parser.parse());
    assert(parser.getHeader().augmentation_vendor_id == "GDB");
    // Payload includes the length prefix bytes as well.
    assert(parser.getHeader().augmentation_payload_size == 7);
    assert(parser.getHeader().augmentation_payload.size() == 7);
    assert(parser.getHeader().augmentation_payload[4] == 0xaa);
    assert(parser.getHeader().augmentation_payload[5] == 0xbb);
    assert(parser.getHeader().augmentation_payload[6] == 0xcc);

    auto entries = parser.lookupName("foo");
    assert(entries.size() == 1);
    assert(entries[0].die_offsets.size() == 1);
    assert(entries[0].die_offsets[0] == 0x120);

    std::cout << ".debug_names length-prefixed augmentation payload skipping tests passed!" << std::endl;
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
    assert(entries[0].die_offsets[0] != 0);

    auto missing = parser.lookupName("bar");
    assert(missing.empty());

    std::cout << ".debug_names bucket lookup tests passed!" << std::endl;
}

void testDebugNamesParserDwarf64UnknownRefSup4Skip() {
    std::cout << "Testing .debug_names DWARF64 unknown DW_FORM_ref_sup4 skip..." << std::endl;

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
    auto appendU64 = [&](uint64_t v) {
        debug_names.push_back(static_cast<uint8_t>(v & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 32) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 40) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 48) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 56) & 0xff));
    };

    appendU32(0xffffffff); // DWARF64 marker
    size_t unit_len_pos = debug_names.size();
    appendU64(0); // unit_length placeholder

    appendU16(5); // version
    appendU16(0); // padding
    appendU32(1); // comp_unit_count
    appendU32(0); // local_type_unit_count
    appendU32(0); // foreign_type_unit_count
    appendU32(1); // bucket_count
    appendU32(1); // name_count
    size_t abbrev_size_pos = debug_names.size();
    appendU32(0); // abbrev_table_size placeholder
    appendU32(0); // augmentation_string_size

    // CU list / buckets / hashes / name offsets / entry offsets.
    appendU64(0x100);          // CU[0]
    appendU32(1);              // bucket[0] starts at 1 (1-based)
    appendU32(djb32("foo"));   // hash[0]
    appendU64(0);              // name_offsets[0] -> debug_str[0]
    appendU64(0);              // entry_offsets[0] -> entry pool base

    std::vector<uint8_t> abbrev;
    // code=1, tag=variable
    abbrev.push_back(0x01);
    abbrev.push_back(static_cast<uint8_t>(DwarfTag::DW_TAG_variable));
    // Known attrs needed by lookup.
    abbrev.push_back(0x01); // DW_IDX_compile_unit
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data1));
    abbrev.push_back(0x03); // DW_IDX_die_offset
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data4));
    // Unknown attr that must be skipped correctly.
    appendULEB(abbrev, 0x7000); // unknown DW_IDX value
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_ref_sup4));
    // End-of-attr list + end-of-abbrev table.
    abbrev.push_back(0x00);
    abbrev.push_back(0x00);
    abbrev.push_back(0x00);

    uint32_t abbrev_size = static_cast<uint32_t>(abbrev.size());
    debug_names[abbrev_size_pos + 0] = static_cast<uint8_t>(abbrev_size & 0xff);
    debug_names[abbrev_size_pos + 1] = static_cast<uint8_t>((abbrev_size >> 8) & 0xff);
    debug_names[abbrev_size_pos + 2] = static_cast<uint8_t>((abbrev_size >> 16) & 0xff);
    debug_names[abbrev_size_pos + 3] = static_cast<uint8_t>((abbrev_size >> 24) & 0xff);
    debug_names.insert(debug_names.end(), abbrev.begin(), abbrev.end());

    // Entry pool: abbrev_code=1, cu_index=0, die_offset=0x20, unknown ref_sup4 payload, end marker.
    appendU8(0x01);
    appendU8(0x00);
    appendU32(0x20);
    appendU32(0xAABBCCDD);
    appendU8(0x00);

    uint64_t unit_length = static_cast<uint64_t>(debug_names.size() - (unit_len_pos + 8));
    for (size_t i = 0; i < 8; ++i) {
        debug_names[unit_len_pos + i] = static_cast<uint8_t>((unit_length >> (8 * i)) & 0xff);
    }

    DebugNamesParser parser(debug_names, debug_str);
    assert(parser.parse());

    auto entries = parser.lookupName("foo");
    assert(entries.size() == 1);
    assert(entries[0].die_offsets.size() == 1);
    assert(entries[0].die_offsets[0] == 0x120); // CU base (0x100) + die_offset (0x20)

    std::cout << ".debug_names DWARF64 ref_sup4 skip tests passed!" << std::endl;
}

void testDebugNamesParserUnknownStrx3Skip() {
    std::cout << "Testing .debug_names unknown DW_FORM_strx3 skip..." << std::endl;

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

    appendU32(0x100);        // CU list
    appendU32(1);            // bucket
    appendU32(djb32("foo")); // hash("foo")
    appendU32(0);            // name offset
    appendU32(0);            // entry offset

    std::vector<uint8_t> abbrev;
    abbrev.push_back(0x01); // code
    abbrev.push_back(static_cast<uint8_t>(DwarfTag::DW_TAG_variable)); // tag
    abbrev.push_back(0x01); // DW_IDX_compile_unit
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data1));
    abbrev.push_back(0x03); // DW_IDX_die_offset
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data4));
    appendULEB(abbrev, 0x7001); // unknown DW_IDX value
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_strx3));
    abbrev.push_back(0x00); // end attrs
    abbrev.push_back(0x00);
    abbrev.push_back(0x00); // end abbrev table

    uint32_t abbrev_size = static_cast<uint32_t>(abbrev.size());
    debug_names[abbrev_size_pos + 0] = static_cast<uint8_t>(abbrev_size & 0xff);
    debug_names[abbrev_size_pos + 1] = static_cast<uint8_t>((abbrev_size >> 8) & 0xff);
    debug_names[abbrev_size_pos + 2] = static_cast<uint8_t>((abbrev_size >> 16) & 0xff);
    debug_names[abbrev_size_pos + 3] = static_cast<uint8_t>((abbrev_size >> 24) & 0xff);
    debug_names.insert(debug_names.end(), abbrev.begin(), abbrev.end());

    // Entry pool: abbrev_code=1, cu_index=0, die_offset=0x20, unknown strx3 payload, end marker.
    appendU8(0x01);
    appendU8(0x00);
    appendU32(0x20);
    appendU8(0x11);
    appendU8(0x22);
    appendU8(0x33);
    appendU8(0x00);

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

    std::cout << ".debug_names unknown strx3 skip tests passed!" << std::endl;
}

void testDebugNamesParserDwarf32UnknownRefSup8Skip() {
    std::cout << "Testing .debug_names DWARF32 unknown DW_FORM_ref_sup8 skip..." << std::endl;

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
    auto appendU64 = [&](uint64_t v) {
        debug_names.push_back(static_cast<uint8_t>(v & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 32) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 40) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 48) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 56) & 0xff));
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

    appendU32(0x100);        // CU list
    appendU32(1);            // bucket
    appendU32(djb32("foo")); // hash("foo")
    appendU32(0);            // name offset
    appendU32(0);            // entry offset

    std::vector<uint8_t> abbrev;
    abbrev.push_back(0x01); // code
    abbrev.push_back(static_cast<uint8_t>(DwarfTag::DW_TAG_variable)); // tag
    abbrev.push_back(0x01); // DW_IDX_compile_unit
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data1));
    abbrev.push_back(0x03); // DW_IDX_die_offset
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data4));
    appendULEB(abbrev, 0x7002); // unknown DW_IDX value
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_ref_sup8));
    abbrev.push_back(0x00); // end attrs
    abbrev.push_back(0x00);
    abbrev.push_back(0x00); // end abbrev table

    uint32_t abbrev_size = static_cast<uint32_t>(abbrev.size());
    debug_names[abbrev_size_pos + 0] = static_cast<uint8_t>(abbrev_size & 0xff);
    debug_names[abbrev_size_pos + 1] = static_cast<uint8_t>((abbrev_size >> 8) & 0xff);
    debug_names[abbrev_size_pos + 2] = static_cast<uint8_t>((abbrev_size >> 16) & 0xff);
    debug_names[abbrev_size_pos + 3] = static_cast<uint8_t>((abbrev_size >> 24) & 0xff);
    debug_names.insert(debug_names.end(), abbrev.begin(), abbrev.end());

    // Entry pool: abbrev_code=1, cu_index=0, die_offset=0x20, unknown ref_sup8 payload, end marker.
    appendU8(0x01);
    appendU8(0x00);
    appendU32(0x20);
    appendU64(0x1122334455667788ULL);
    appendU8(0x00);

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

    std::cout << ".debug_names DWARF32 ref_sup8 skip tests passed!" << std::endl;
}

void testDebugNamesParserDwarf64UnknownAddrSkip() {
    std::cout << "Testing .debug_names DWARF64 unknown DW_FORM_addr skip..." << std::endl;

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
    auto appendU64 = [&](uint64_t v) {
        debug_names.push_back(static_cast<uint8_t>(v & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 32) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 40) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 48) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 56) & 0xff));
    };

    appendU32(0xffffffff); // DWARF64 marker
    size_t unit_len_pos = debug_names.size();
    appendU64(0); // unit_length placeholder

    appendU16(5); // version
    appendU16(0); // padding
    appendU32(1); // comp_unit_count
    appendU32(0); // local_type_unit_count
    appendU32(0); // foreign_type_unit_count
    appendU32(1); // bucket_count
    appendU32(1); // name_count
    size_t abbrev_size_pos = debug_names.size();
    appendU32(0); // abbrev_table_size placeholder
    appendU32(0); // augmentation_string_size

    appendU64(0x100);          // CU[0]
    appendU32(1);              // bucket[0] starts at 1 (1-based)
    appendU32(djb32("foo"));   // hash[0]
    appendU64(0);              // name_offsets[0] -> debug_str[0]
    appendU64(0);              // entry_offsets[0] -> entry pool base

    std::vector<uint8_t> abbrev;
    abbrev.push_back(0x01); // code
    abbrev.push_back(static_cast<uint8_t>(DwarfTag::DW_TAG_variable)); // tag
    abbrev.push_back(0x01); // DW_IDX_compile_unit
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data1));
    abbrev.push_back(0x03); // DW_IDX_die_offset
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data4));
    appendULEB(abbrev, 0x7003); // unknown DW_IDX value
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_addr));
    abbrev.push_back(0x00); // end attrs
    abbrev.push_back(0x00);
    abbrev.push_back(0x00); // end abbrev table

    uint32_t abbrev_size = static_cast<uint32_t>(abbrev.size());
    debug_names[abbrev_size_pos + 0] = static_cast<uint8_t>(abbrev_size & 0xff);
    debug_names[abbrev_size_pos + 1] = static_cast<uint8_t>((abbrev_size >> 8) & 0xff);
    debug_names[abbrev_size_pos + 2] = static_cast<uint8_t>((abbrev_size >> 16) & 0xff);
    debug_names[abbrev_size_pos + 3] = static_cast<uint8_t>((abbrev_size >> 24) & 0xff);
    debug_names.insert(debug_names.end(), abbrev.begin(), abbrev.end());

    // Entry pool: abbrev_code=1, cu_index=0, die_offset=0x20, unknown addr payload, end marker.
    appendU8(0x01);
    appendU8(0x00);
    appendU32(0x20);
    appendU64(0x8899aabbccddeeffULL);
    appendU8(0x00);

    uint64_t unit_length = static_cast<uint64_t>(debug_names.size() - (unit_len_pos + 8));
    for (size_t i = 0; i < 8; ++i) {
        debug_names[unit_len_pos + i] = static_cast<uint8_t>((unit_length >> (8 * i)) & 0xff);
    }

    DebugNamesParser parser(debug_names, debug_str);
    assert(parser.parse());

    auto entries = parser.lookupName("foo");
    assert(entries.size() == 1);
    assert(entries[0].die_offsets.size() == 1);
    assert(entries[0].die_offsets[0] != 0);

    std::cout << ".debug_names DWARF64 addr skip tests passed!" << std::endl;
}

void testDebugNamesParserDwarf32UnknownAddrSkip() {
    std::cout << "Testing .debug_names DWARF32 unknown DW_FORM_addr skip..." << std::endl;

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

    appendU32(0x100);        // CU list
    appendU32(1);            // bucket
    appendU32(djb32("foo")); // hash("foo")
    appendU32(0);            // name offset
    appendU32(0);            // entry offset

    std::vector<uint8_t> abbrev;
    abbrev.push_back(0x01); // code
    abbrev.push_back(static_cast<uint8_t>(DwarfTag::DW_TAG_variable)); // tag
    abbrev.push_back(0x01); // DW_IDX_compile_unit
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data1));
    abbrev.push_back(0x03); // DW_IDX_die_offset
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data4));
    appendULEB(abbrev, 0x7004); // unknown DW_IDX value
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_addr));
    abbrev.push_back(0x00); // end attrs
    abbrev.push_back(0x00);
    abbrev.push_back(0x00); // end abbrev table

    uint32_t abbrev_size = static_cast<uint32_t>(abbrev.size());
    debug_names[abbrev_size_pos + 0] = static_cast<uint8_t>(abbrev_size & 0xff);
    debug_names[abbrev_size_pos + 1] = static_cast<uint8_t>((abbrev_size >> 8) & 0xff);
    debug_names[abbrev_size_pos + 2] = static_cast<uint8_t>((abbrev_size >> 16) & 0xff);
    debug_names[abbrev_size_pos + 3] = static_cast<uint8_t>((abbrev_size >> 24) & 0xff);
    debug_names.insert(debug_names.end(), abbrev.begin(), abbrev.end());

    // Entry pool: abbrev_code=1, cu_index=0, die_offset=0x20, unknown addr payload, end marker.
    appendU8(0x01);
    appendU8(0x00);
    appendU32(0x20);
    appendU32(0x12345678);
    appendU8(0x00);

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

    std::cout << ".debug_names DWARF32 addr skip tests passed!" << std::endl;
}

void testDebugNamesParserDwarf64DieOffsetAsAddr() {
    std::cout << "Testing .debug_names DWARF64 DW_IDX_die_offset as DW_FORM_addr..." << std::endl;

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
    auto appendU64 = [&](uint64_t v) {
        debug_names.push_back(static_cast<uint8_t>(v & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 32) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 40) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 48) & 0xff));
        debug_names.push_back(static_cast<uint8_t>((v >> 56) & 0xff));
    };

    appendU32(0xffffffff); // DWARF64 marker
    size_t unit_len_pos = debug_names.size();
    appendU64(0); // unit_length placeholder

    appendU16(5); // version
    appendU16(0); // padding
    appendU32(1); // comp_unit_count
    appendU32(0); // local_type_unit_count
    appendU32(0); // foreign_type_unit_count
    appendU32(1); // bucket_count
    appendU32(1); // name_count
    size_t abbrev_size_pos = debug_names.size();
    appendU32(0); // abbrev_table_size placeholder
    appendU32(0); // augmentation_string_size

    appendU64(0x100);          // CU[0]
    appendU32(1);              // bucket[0]
    appendU32(djb32("foo"));   // hash[0]
    appendU64(0);              // name_offsets[0]
    appendU64(0);              // entry_offsets[0]

    std::vector<uint8_t> abbrev;
    abbrev.push_back(0x01); // code
    abbrev.push_back(static_cast<uint8_t>(DwarfTag::DW_TAG_variable)); // tag
    abbrev.push_back(0x01); // DW_IDX_compile_unit
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data1));
    abbrev.push_back(0x03); // DW_IDX_die_offset
    abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_addr)); // should decode as 8-byte value
    abbrev.push_back(0x00); // end attrs
    abbrev.push_back(0x00);
    abbrev.push_back(0x00); // end abbrev table

    uint32_t abbrev_size = static_cast<uint32_t>(abbrev.size());
    debug_names[abbrev_size_pos + 0] = static_cast<uint8_t>(abbrev_size & 0xff);
    debug_names[abbrev_size_pos + 1] = static_cast<uint8_t>((abbrev_size >> 8) & 0xff);
    debug_names[abbrev_size_pos + 2] = static_cast<uint8_t>((abbrev_size >> 16) & 0xff);
    debug_names[abbrev_size_pos + 3] = static_cast<uint8_t>((abbrev_size >> 24) & 0xff);
    debug_names.insert(debug_names.end(), abbrev.begin(), abbrev.end());

    // Entry pool: abbrev_code=1, cu_index=0, die_offset=0x20 (8-byte addr), end marker.
    appendU8(0x01);
    appendU8(0x00);
    appendU64(0x20);
    appendU8(0x00);

    uint64_t unit_length = static_cast<uint64_t>(debug_names.size() - (unit_len_pos + 8));
    for (size_t i = 0; i < 8; ++i) {
        debug_names[unit_len_pos + i] = static_cast<uint8_t>((unit_length >> (8 * i)) & 0xff);
    }

    DebugNamesParser parser(debug_names, debug_str);
    assert(parser.parse());
    auto entries = parser.lookupName("foo");
    assert(entries.size() == 1);
    assert(entries[0].die_offsets.size() == 1);
    assert(entries[0].die_offsets[0] == 0x120);

    std::cout << ".debug_names DW_FORM_addr DIE offset tests passed!" << std::endl;
}

void testDebugNamesParserMalformedInputs() {
    std::cout << "Testing .debug_names malformed input handling..." << std::endl;

    // Non-empty name table requires at least one bucket.
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
        appendU32(0);      // bucket_count (invalid with name_count>0)
        appendU32(1);      // name_count
        appendU32(0);      // abbrev_table_size
        appendU32(0);      // augmentation_string_size

        uint32_t len = static_cast<uint32_t>(debug_names.size() - 4);
        debug_names[0] = static_cast<uint8_t>(len & 0xff);
        debug_names[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_names[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_names[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugNamesParser p(debug_names, {});
        assert(!p.parse());
    }

    // Hash table entries must be non-decreasing for bucketed lookup.
    {
        std::vector<uint8_t> debug_str = {'a', 0x00, 'b', 0x00};

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
        appendU32(1);      // comp_unit_count
        appendU32(0);      // local_type_unit_count
        appendU32(0);      // foreign_type_unit_count
        appendU32(1);      // bucket_count
        appendU32(2);      // name_count
        appendU32(0);      // abbrev_table_size
        appendU32(0);      // augmentation_string_size
        appendU32(0x100);  // CU list[0]
        appendU32(1);      // bucket[0]
        appendU32(100);    // hashes[0]
        appendU32(99);     // hashes[1] INVALID decreasing order
        appendU32(0);      // name offset[0]
        appendU32(2);      // name offset[1]
        appendU32(0);      // entry offset[0]
        appendU32(0);      // entry offset[1]

        uint32_t len = static_cast<uint32_t>(debug_names.size() - 4);
        debug_names[0] = static_cast<uint8_t>(len & 0xff);
        debug_names[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_names[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_names[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugNamesParser p(debug_names, debug_str);
        assert(!p.parse());
    }

    // Entry offsets must stay within the entry pool.
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
        appendU32(0);      // abbrev_table_size (no abbrev table bytes)
        appendU32(0);      // augmentation_string_size
        appendU32(0x100);  // CU list[0]
        appendU32(1);      // bucket[0]
        appendU32(djb32("foo")); // hash[0]
        appendU32(0);      // name offset[0]
        appendU32(1);      // INVALID entry offset (entry pool is empty)

        uint32_t len = static_cast<uint32_t>(debug_names.size() - 4);
        debug_names[0] = static_cast<uint8_t>(len & 0xff);
        debug_names[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_names[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_names[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugNamesParser p(debug_names, debug_str);
        assert(!p.parse());
    }

    // Duplicate abbrev code entries in one abbrev table must be rejected.
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
        size_t abbrev_size_pos = debug_names.size();
        appendU32(0);      // abbrev_table_size placeholder
        appendU32(0);      // augmentation_string_size

        std::vector<uint8_t> abbrev;
        // Abbrev #1: code=1, tag=variable, no attrs.
        abbrev.push_back(0x01);
        abbrev.push_back(static_cast<uint8_t>(DwarfTag::DW_TAG_variable));
        abbrev.push_back(0x00);
        abbrev.push_back(0x00);
        // Abbrev #2: duplicate code=1, tag=subprogram, no attrs.
        abbrev.push_back(0x01);
        abbrev.push_back(static_cast<uint8_t>(DwarfTag::DW_TAG_subprogram));
        abbrev.push_back(0x00);
        abbrev.push_back(0x00);
        // End-of-table marker.
        abbrev.push_back(0x00);

        uint32_t abbrev_size = static_cast<uint32_t>(abbrev.size());
        // patch abbrev_table_size
        debug_names[abbrev_size_pos + 0] = static_cast<uint8_t>(abbrev_size & 0xff);
        debug_names[abbrev_size_pos + 1] = static_cast<uint8_t>((abbrev_size >> 8) & 0xff);
        debug_names[abbrev_size_pos + 2] = static_cast<uint8_t>((abbrev_size >> 16) & 0xff);
        debug_names[abbrev_size_pos + 3] = static_cast<uint8_t>((abbrev_size >> 24) & 0xff);
        debug_names.insert(debug_names.end(), abbrev.begin(), abbrev.end());

        uint32_t len = static_cast<uint32_t>(debug_names.size() - 4);
        debug_names[0] = static_cast<uint8_t>(len & 0xff);
        debug_names[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_names[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_names[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugNamesParser p(debug_names, {});
        assert(!p.parse());
    }

    // Name strings referenced from .debug_str are treated leniently; missing NUL terminators
    // should not prevent parsing the rest of the unit.
    {
        std::vector<uint8_t> debug_str = {'f', 'o', 'o'}; // no trailing NUL
        auto djb32 = [](const char* s) -> uint32_t {
            uint32_t h = 5381;
            while (*s) {
                h = ((h << 5) + h) + static_cast<uint8_t>(*s++);
            }
            return h;
        };

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
        appendU32(1);      // comp_unit_count
        appendU32(0);      // local_type_unit_count
        appendU32(0);      // foreign_type_unit_count
        appendU32(1);      // bucket_count
        appendU32(1);      // name_count
        appendU32(0);      // abbrev_table_size
        appendU32(0);      // augmentation_string_size
        appendU32(0x100);  // CU list[0]
        appendU32(1);      // bucket[0]
        appendU32(djb32("foo")); // hash[0]
        appendU32(0);      // name offset[0] -> unterminated "foo"
        appendU32(0);      // entry offset[0]

        uint32_t len = static_cast<uint32_t>(debug_names.size() - 4);
        debug_names[0] = static_cast<uint8_t>(len & 0xff);
        debug_names[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_names[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_names[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugNamesParser p(debug_names, debug_str);
        assert(p.parse());
    }

    // Name offsets must point inside .debug_str.
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
        appendU32(0);      // abbrev_table_size
        appendU32(0);      // augmentation_string_size
        appendU32(0x100);  // CU list[0]
        appendU32(1);      // bucket[0]
        appendU32(djb32("foo")); // hash[0]
        appendU32(99);     // INVALID name offset (outside debug_str)
        appendU32(0);      // entry offset[0]

        uint32_t len = static_cast<uint32_t>(debug_names.size() - 4);
        debug_names[0] = static_cast<uint8_t>(len & 0xff);
        debug_names[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_names[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_names[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugNamesParser p(debug_names, debug_str);
        assert(!p.parse());
    }

    // Bucket entries are 1-based and must not exceed name_count.
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
        appendU32(0);      // abbrev_table_size
        appendU32(0);      // augmentation_string_size
        appendU32(0x100);  // CU list[0]
        appendU32(2);      // INVALID bucket value (> name_count)
        appendU32(djb32("foo")); // hash[0]
        appendU32(0);      // name offset[0]
        appendU32(0);      // entry offset[0]

        uint32_t len = static_cast<uint32_t>(debug_names.size() - 4);
        debug_names[0] = static_cast<uint8_t>(len & 0xff);
        debug_names[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_names[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_names[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugNamesParser p(debug_names, debug_str);
        assert(!p.parse());
    }

    // Non-empty augmentation strings are treated leniently; missing NUL terminators should not
    // prevent parsing the rest of the unit.
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
        appendU32(0);      // abbrev_table_size
        appendU32(3);      // augmentation_string_size
        debug_names.push_back('a');
        debug_names.push_back('b');
        debug_names.push_back('c'); // missing trailing NUL

        uint32_t len = static_cast<uint32_t>(debug_names.size() - 4);
        debug_names[0] = static_cast<uint8_t>(len & 0xff);
        debug_names[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_names[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_names[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugNamesParser p(debug_names, {});
        assert(p.parse());
    }

    // Non-zero reserved padding in the unit header must be rejected.
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
        appendU16(1);      // invalid non-zero padding
        appendU32(0);      // comp_unit_count
        appendU32(0);      // local_type_unit_count
        appendU32(0);      // foreign_type_unit_count
        appendU32(0);      // bucket_count
        appendU32(0);      // name_count
        appendU32(0);      // abbrev_table_size
        appendU32(0);      // augmentation_string_size

        uint32_t len = static_cast<uint32_t>(debug_names.size() - 4);
        debug_names[0] = static_cast<uint8_t>(len & 0xff);
        debug_names[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_names[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_names[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugNamesParser p(debug_names, {});
        assert(!p.parse());
    }

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

    // Unterminated DW_FORM_string in entry pool must not be treated as a valid skipped attribute.
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
        appendU32(0);      // entry offset

        std::vector<uint8_t> abbrev;
        abbrev.push_back(0x01); // code
        abbrev.push_back(static_cast<uint8_t>(DwarfTag::DW_TAG_variable)); // tag
        abbrev.push_back(0x01); // DW_IDX_compile_unit
        abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data1));
        abbrev.push_back(0x03); // DW_IDX_die_offset
        abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_data4));
        abbrev.push_back(0x7f); // unknown index, should be skipped
        abbrev.push_back(static_cast<uint8_t>(DwarfForm::DW_FORM_string));
        abbrev.push_back(0x00); // end attrs
        abbrev.push_back(0x00);
        abbrev.push_back(0x00); // end abbrev table

        uint32_t abbrev_size = static_cast<uint32_t>(abbrev.size());
        debug_names[abbrev_size_pos + 0] = static_cast<uint8_t>(abbrev_size & 0xff);
        debug_names[abbrev_size_pos + 1] = static_cast<uint8_t>((abbrev_size >> 8) & 0xff);
        debug_names[abbrev_size_pos + 2] = static_cast<uint8_t>((abbrev_size >> 16) & 0xff);
        debug_names[abbrev_size_pos + 3] = static_cast<uint8_t>((abbrev_size >> 24) & 0xff);
        debug_names.insert(debug_names.end(), abbrev.begin(), abbrev.end());

        // Entry pool: abbrev_code=1, cu_index=0, die_offset=0x20, then unterminated string bytes.
        appendU8(0x01);
        appendU8(0x00);
        appendU32(0x20);
        appendU8('x');
        appendU8('y');
        appendU8('z');

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

    // Cyclic DW_MACRO_import chains must terminate (visited-set guard).
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

        uint64_t unit1_off = mac.size();
        auto [lp1, cs1] = startUnit();
        appendU8m(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define));
        appendU8m(1);
        appendCStringM("A 1");
        appendU8m(static_cast<uint8_t>(DW_MACRO::DW_MACRO_import));
        size_t u1_import_pos = mac.size();
        appendU32m(0); // patch later -> unit2
        appendU8m(0x00);
        finishUnit(lp1, cs1);

        uint64_t unit2_off = mac.size();
        auto [lp2, cs2] = startUnit();
        appendU8m(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define));
        appendU8m(2);
        appendCStringM("B 2");
        appendU8m(static_cast<uint8_t>(DW_MACRO::DW_MACRO_import));
        size_t u2_import_pos = mac.size();
        appendU32m(0); // patch later -> unit1 (cycle)
        appendU8m(0x00);
        finishUnit(lp2, cs2);

        // Patch imports to create cycle.
        mac[u1_import_pos + 0] = static_cast<uint8_t>(unit2_off & 0xff);
        mac[u1_import_pos + 1] = static_cast<uint8_t>((unit2_off >> 8) & 0xff);
        mac[u1_import_pos + 2] = static_cast<uint8_t>((unit2_off >> 16) & 0xff);
        mac[u1_import_pos + 3] = static_cast<uint8_t>((unit2_off >> 24) & 0xff);
        mac[u2_import_pos + 0] = static_cast<uint8_t>(unit1_off & 0xff);
        mac[u2_import_pos + 1] = static_cast<uint8_t>((unit1_off >> 8) & 0xff);
        mac[u2_import_pos + 2] = static_cast<uint8_t>((unit1_off >> 16) & 0xff);
        mac[u2_import_pos + 3] = static_cast<uint8_t>((unit1_off >> 24) & 0xff);

        DebugMacroParser p(mac);
        auto defs = p.getDefinitions(unit1_off);
        assert(defs.size() == 2);
        assert(defs[0].name == "A");
        assert(defs[1].name == "B");
    }

    // Ensure getDefinitions()/getUndefinitions() include *_sup opcodes.
    {
        std::vector<uint8_t> debug_str_sup;
        ::appendCString(debug_str_sup, "SUPDEF 9"); // offset 0
        uint32_t sup_undef_off = static_cast<uint32_t>(debug_str_sup.size());
        ::appendCString(debug_str_sup, "SUPDEF");

        std::vector<uint8_t> mac;
        ::appendU32(mac, 0); // unit_length placeholder
        size_t cs = mac.size();
        appendU16LE(mac, 5);     // version
        mac.push_back(0x00);     // flags: 32-bit offsets

        mac.push_back(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define_sup));
        appendULEB(mac, 42);     // line
        ::appendU32(mac, 0);     // sup str offset for "SUPDEF 9"

        mac.push_back(static_cast<uint8_t>(DW_MACRO::DW_MACRO_undef_sup));
        appendULEB(mac, 43);     // line
        ::appendU32(mac, sup_undef_off); // sup str offset for "SUPDEF"

        mac.push_back(0x00); // end

        uint32_t len = static_cast<uint32_t>(mac.size() - cs);
        mac[0] = static_cast<uint8_t>(len & 0xff);
        mac[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        mac[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        mac[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        std::vector<uint8_t> empty;
        DebugMacroParser p(mac, &empty, &debug_str_sup, &empty, &empty);

        auto entries = p.parseMacroUnit(0);
        assert(entries.size() == 2);
        assert(entries[0].type == DW_MACRO::DW_MACRO_define_sup);
        assert(entries[0].line == 42);
        assert(entries[0].name == "SUPDEF");
        assert(entries[0].value == "9");
        assert(entries[1].type == DW_MACRO::DW_MACRO_undef_sup);
        assert(entries[1].line == 43);
        assert(entries[1].name == "SUPDEF");

        auto defs = p.getDefinitions(0);
        assert(defs.size() == 1);
        assert(defs[0].line == 42);
        assert(defs[0].name == "SUPDEF");
        assert(defs[0].value == "9");

        auto undefs = p.getUndefinitions(0);
        assert(undefs.size() == 1);
        assert(undefs[0].line == 43);
        assert(undefs[0].name == "SUPDEF");

        auto lookup = p.lookupMacro("SUPDEF", 0);
        assert(lookup.size() == 1);
        assert(lookup[0].line == 42);
        assert(lookup[0].name == "SUPDEF");
        assert(lookup[0].value == "9");
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

    // Unknown opcode payload with DW_FORM_addr should be skippable as well.
    {
        std::vector<uint8_t> mac;
        ::appendU32(mac, 0); // unit_length placeholder
        size_t cs = mac.size();
        appendU16LE(mac, 5);       // version
        mac.push_back(0x05);       // flags: has_opcode_operands_table + 64-bit offsets

        // opcode operands table:
        // opcode_count=1:
        // - opcode=0xee, operand_count=1, forms=[DW_FORM_addr]
        mac.push_back(1);
        mac.push_back(0xee);
        appendULEB(mac, 1);
        appendULEB(mac, static_cast<uint64_t>(DwarfForm::DW_FORM_addr));

        // Unknown opcode 0xee payload: 8-byte address.
        mac.push_back(0xee);
        ::appendU64(mac, 0x123456789abcdef0ULL);

        // Then a normal define that must still parse.
        mac.push_back(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define));
        appendULEB(mac, 1);
        ::appendCString(mac, "ADDR_OK 1");
        mac.push_back(0x00); // end

        uint32_t len = static_cast<uint32_t>(mac.size() - cs);
        mac[0] = static_cast<uint8_t>(len & 0xff);
        mac[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        mac[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        mac[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugMacroParser p(mac);
        auto e = p.parseMacroUnit(0);
        assert(e.size() == 2);
        assert(static_cast<uint8_t>(e[0].type) == 0xee);
        assert(e[1].type == DW_MACRO::DW_MACRO_define);
        assert(e[1].name == "ADDR_OK");
        assert(e[1].value == "1");
    }

    // Unknown opcode payload with DW_FORM_ref_addr should be skippable as well.
    {
        std::vector<uint8_t> mac;
        ::appendU32(mac, 0); // unit_length placeholder
        size_t cs = mac.size();
        appendU16LE(mac, 5);       // version
        mac.push_back(0x05);       // flags: has 64-bit offsets + opcode operands table

        // opcode operands table:
        // opcode_count=1:
        // - opcode=0xed, operand_count=1, forms=[DW_FORM_ref_addr]
        mac.push_back(1);
        mac.push_back(0xed);
        appendULEB(mac, 1);
        appendULEB(mac, static_cast<uint64_t>(DwarfForm::DW_FORM_ref_addr));

        // Unknown opcode 0xed payload: 8-byte ref_addr (offset_size=8 due to flags).
        mac.push_back(0xed);
        ::appendU64(mac, 0x0102030405060708ULL);

        // Then a normal define that must still parse.
        mac.push_back(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define));
        appendULEB(mac, 2);
        ::appendCString(mac, "REF_OK 1");
        mac.push_back(0x00); // end

        uint32_t len = static_cast<uint32_t>(mac.size() - cs);
        mac[0] = static_cast<uint8_t>(len & 0xff);
        mac[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        mac[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        mac[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugMacroParser p(mac);
        auto e = p.parseMacroUnit(0);
        assert(e.size() == 2);
        assert(static_cast<uint8_t>(e[0].type) == 0xed);
        assert(e[1].type == DW_MACRO::DW_MACRO_define);
        assert(e[1].name == "REF_OK");
        assert(e[1].value == "1");
    }

    // Same as above, but with 32-bit offsets in the macro unit header.
    {
        std::vector<uint8_t> mac;
        ::appendU32(mac, 0); // unit_length placeholder
        size_t cs = mac.size();
        appendU16LE(mac, 5);       // version
        mac.push_back(0x04);       // flags: has opcode operands table, 32-bit offsets

        // opcode operands table:
        // opcode_count=1:
        // - opcode=0xec, operand_count=1, forms=[DW_FORM_ref_addr]
        mac.push_back(1);
        mac.push_back(0xec);
        appendULEB(mac, 1);
        appendULEB(mac, static_cast<uint64_t>(DwarfForm::DW_FORM_ref_addr));

        // Unknown opcode 0xec payload: 4-byte ref_addr (offset_size=4 due to flags).
        mac.push_back(0xec);
        ::appendU32(mac, 0x89abcdefu);

        // Then a normal define that must still parse.
        mac.push_back(static_cast<uint8_t>(DW_MACRO::DW_MACRO_define));
        appendULEB(mac, 3);
        ::appendCString(mac, "REF32_OK 1");
        mac.push_back(0x00); // end

        uint32_t len = static_cast<uint32_t>(mac.size() - cs);
        mac[0] = static_cast<uint8_t>(len & 0xff);
        mac[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        mac[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        mac[3] = static_cast<uint8_t>((len >> 24) & 0xff);

        DebugMacroParser p(mac);
        auto e = p.parseMacroUnit(0);
        assert(e.size() == 2);
        assert(static_cast<uint8_t>(e[0].type) == 0xec);
        assert(e[1].type == DW_MACRO::DW_MACRO_define);
        assert(e[1].name == "REF32_OK");
        assert(e[1].value == "1");
    }

    // Truncated DWARF64 unit header must be rejected.
    {
        std::vector<uint8_t> mac;
        ::appendU32(mac, 0xffffffffu); // DWARF64 marker, but no 64-bit length follows.
        DebugMacroParser p(mac);
        auto e = p.parseMacroUnit(0);
        assert(e.empty());
    }

    // Reserved header flag bits must be rejected.
    {
        std::vector<uint8_t> mac;
        ::appendU32(mac, 0); // unit_length placeholder
        size_t cs = mac.size();
        appendU16LE(mac, 5); // version
        mac.push_back(0x80); // invalid reserved bit set
        mac.push_back(0x00); // end of list
        uint32_t len = static_cast<uint32_t>(mac.size() - cs);
        mac[0] = static_cast<uint8_t>(len & 0xff);
        mac[1] = static_cast<uint8_t>((len >> 8) & 0xff);
        mac[2] = static_cast<uint8_t>((len >> 16) & 0xff);
        mac[3] = static_cast<uint8_t>((len >> 24) & 0xff);

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
        debug_info.push_back(0x01); // unit_type (compile)
        debug_info.push_back(0x08); // address_size
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

void testDwarfParserExposesDebugNamesUnitHeaders() {
    std::cout << "Testing DwarfParser exposes .debug_names unit headers..." << std::endl;

    DwarfParser unloaded("does-not-exist.elf");
    assert(unloaded.getDebugNamesUnitHeaders().empty());
    assert(unloaded.getPrimaryDebugNamesHeader() == nullptr);

    auto debug_names = loadTestDataBinary("debug_names_real_world.bin");
    auto debug_str = loadTestDataBinary("debug_names_real_world.str");

    std::vector<uint8_t> debug_abbrev = {
        0x01, 0x11, 0x00, 0x00, 0x00, 0x00
    };

    std::vector<uint8_t> debug_info;
    appendU32(debug_info, 0); // unit_length placeholder
    appendU16(debug_info, 5); // version
    debug_info.push_back(0x01); // DW_UT_compile
    debug_info.push_back(0x08); // address_size
    appendU32(debug_info, 0);   // abbrev offset
    debug_info.push_back(0x01); // CU abbrev code
    {
        uint32_t unit_length = static_cast<uint32_t>(debug_info.size() - 4);
        debug_info[0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_info[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_info[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_info[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    std::string dir = makeTempDir("dwarf_names_headers_");
    std::string elf_path = (std::filesystem::path(dir) / "names_headers.elf").string();
    writeELFWithSections(elf_path, {
        {".debug_info", debug_info},
        {".debug_abbrev", debug_abbrev},
        {".debug_str", debug_str},
        {".debug_names", debug_names},
    });

    DwarfParser parser(elf_path);
    assert(parser.load());
    assert(parser.hasAcceleratedLookup());

    const auto& headers = parser.getDebugNamesUnitHeaders();
    assert(headers.size() == 2);
    assert(headers[0].version == 5);
    assert(headers[1].version == 5);
    assert(headers[0].name_count == 1);
    assert(headers[1].name_count == 1);

    const DebugNamesHeader* primary = parser.getPrimaryDebugNamesHeader();
    assert(primary != nullptr);
    assert(primary->version == 5);
    assert(primary->name_count == 1);

    std::cout << "DwarfParser .debug_names unit header tests passed!" << std::endl;
}

void testDwarf5SkeletonUnitHeaderSkipsDWOId() {
    std::cout << "Testing DWARF5 skeleton unit header dwo_id skipping..." << std::endl;

    // Minimal abbrev: code=1, compile_unit, no children, no attributes.
    std::vector<uint8_t> debug_abbrev;
    appendULEB(debug_abbrev, 1);
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfTag::DW_TAG_compile_unit));
    debug_abbrev.push_back(0x00); // no children
    debug_abbrev.push_back(0x00); // attr=0
    debug_abbrev.push_back(0x00); // form=0
    debug_abbrev.push_back(0x00); // end abbrev table

    // .debug_info: DWARF5 DW_UT_skeleton with dwo_id in header, then DIE abbrev code=1.
    std::vector<uint8_t> debug_info;
    size_t start = debug_info.size();
    appendU32(debug_info, 0); // unit_length placeholder
    appendU16LE(debug_info, 5); // version
    debug_info.push_back(static_cast<uint8_t>(DwarfUnitType::DW_UT_skeleton));
    debug_info.push_back(0x08); // address_size
    appendU32(debug_info, 0);   // abbrev offset
    appendU64(debug_info, 0x1122334455667788ULL); // dwo_id (header extra)
    debug_info.push_back(0x01); // CU abbrev code
    {
        uint32_t len = static_cast<uint32_t>(debug_info.size() - start - 4);
        debug_info[start + 0] = static_cast<uint8_t>(len & 0xff);
        debug_info[start + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_info[start + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_info[start + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    std::vector<uint8_t> debug_str = {'\0'};
    std::string dir = makeTempDir("dwarf5_ut_skel_");
    std::string elf_path = (std::filesystem::path(dir) / "ut_skel.elf").string();
    writeELFWithSections(elf_path, {
        {".debug_info", debug_info},
        {".debug_abbrev", debug_abbrev},
        {".debug_str", debug_str},
    });

    DwarfParser parser(elf_path);
    assert(parser.load());
    auto cus = parser.getCompilationUnits();
    assert(cus.size() == 1);
    assert(cus[0]);
    assert(cus[0]->getTag() == DwarfTag::DW_TAG_compile_unit);

    std::cout << "DWARF5 skeleton unit header skipping tests passed!" << std::endl;
}

void testDwarf5SplitCompileUnitHeaderSkipsDWOId() {
    std::cout << "Testing DWARF5 split-compile unit header dwo_id skipping..." << std::endl;

    // Abbrev: CU has DW_AT_dwo_id (data8), no children.
    std::vector<uint8_t> debug_abbrev;
    debug_abbrev.push_back(0x01); // abbrev code
    debug_abbrev.push_back(0x11); // DW_TAG_compile_unit
    debug_abbrev.push_back(0x00); // no children
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_dwo_id));
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_data8));
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00);

    std::vector<uint8_t> debug_info;
    size_t start = debug_info.size();
    appendU32(debug_info, 0); // unit_length placeholder
    appendU16LE(debug_info, 5); // version
    debug_info.push_back(static_cast<uint8_t>(DwarfUnitType::DW_UT_split_compile));
    debug_info.push_back(0x08); // address_size
    appendU32(debug_info, 0);   // abbrev offset
    appendU64(debug_info, 0xAABBCCDDEEFF0011ULL); // dwo_id (header extra)
    debug_info.push_back(0x01); // CU abbrev code
    appendU64(debug_info, 0xAABBCCDDEEFF0011ULL); // DW_AT_dwo_id attribute
    {
        uint32_t len = static_cast<uint32_t>(debug_info.size() - start - 4);
        debug_info[start + 0] = static_cast<uint8_t>(len & 0xff);
        debug_info[start + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_info[start + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_info[start + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    std::vector<uint8_t> debug_str = {'\0'};
    std::string dir = makeTempDir("dwarf5_ut_splitc_");
    std::string elf_path = (std::filesystem::path(dir) / "ut_splitc.elf").string();
    writeELFWithSections(elf_path, {
        {".debug_info", debug_info},
        {".debug_abbrev", debug_abbrev},
        {".debug_str", debug_str},
    });

    DwarfParser parser(elf_path);
    assert(parser.load());
    auto cus = parser.getCompilationUnits();
    assert(cus.size() == 1);
    auto v = cus[0]->getAttribute(DwarfAttribute::DW_AT_dwo_id);
    auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(v);
    assert(u && u->getValue() == 0xAABBCCDDEEFF0011ULL);

    std::cout << "DWARF5 split-compile unit header skipping tests passed!" << std::endl;
}

void testDwarf5TypeUnitHeaderSkipsSignatureAndTypeOffset() {
    std::cout << "Testing DWARF5 type unit header signature/type_offset skipping..." << std::endl;

    // Minimal abbrev: code=1, compile_unit, no children, no attributes.
    std::vector<uint8_t> debug_abbrev;
    appendULEB(debug_abbrev, 1);
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfTag::DW_TAG_compile_unit));
    debug_abbrev.push_back(0x00); // no children
    debug_abbrev.push_back(0x00); // attr=0
    debug_abbrev.push_back(0x00); // form=0
    debug_abbrev.push_back(0x00); // end abbrev table

    std::vector<uint8_t> debug_info;
    size_t start = debug_info.size();
    appendU32(debug_info, 0); // unit_length placeholder
    appendU16LE(debug_info, 5); // version
    debug_info.push_back(static_cast<uint8_t>(DwarfUnitType::DW_UT_type));
    debug_info.push_back(0x08); // address_size
    appendU32(debug_info, 0);   // abbrev offset
    appendU64(debug_info, 0xDEADBEEFCAFEBABEULL); // type_signature (header extra)
    appendU32(debug_info, 0x10); // type_offset (header extra, DWARF32)
    debug_info.push_back(0x01);  // CU abbrev code
    {
        uint32_t len = static_cast<uint32_t>(debug_info.size() - start - 4);
        debug_info[start + 0] = static_cast<uint8_t>(len & 0xff);
        debug_info[start + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_info[start + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_info[start + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    std::vector<uint8_t> debug_str = {'\0'};
    std::string dir = makeTempDir("dwarf5_ut_type_");
    std::string elf_path = (std::filesystem::path(dir) / "ut_type.elf").string();
    writeELFWithSections(elf_path, {
        {".debug_info", debug_info},
        {".debug_abbrev", debug_abbrev},
        {".debug_str", debug_str},
    });

    DwarfParser parser(elf_path);
    assert(parser.load());
    auto cus = parser.getCompilationUnits();
    assert(cus.size() == 1);
    assert(cus[0]);
    assert(cus[0]->getTag() == DwarfTag::DW_TAG_compile_unit);

    std::cout << "DWARF5 type unit header skipping tests passed!" << std::endl;
}

void testDwarf5PartialUnitSetsCUContextForAddrx() {
    std::cout << "Testing DWARF5 DW_UT_partial sets CU context for DW_FORM_addrx*..." << std::endl;

    // .debug_addr: DWARF32 contribution with one address entry.
    std::vector<uint8_t> debug_addr;
    appendU32(debug_addr, 0); // unit_length placeholder
    appendU16LE(debug_addr, 5);
    debug_addr.push_back(8); // address_size
    debug_addr.push_back(0); // segment_selector_size
    appendU64(debug_addr, 0xCAFEBABECAFED00DULL); // entry[0]
    {
        uint32_t unit_length = static_cast<uint32_t>(debug_addr.size() - 4);
        debug_addr[0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_addr[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_addr[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_addr[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    // .debug_abbrev:
    // 1) partial_unit, children, DW_AT_addr_base(sec_offset)
    // 2) variable, no children, DW_AT_low_pc(addrx1)
    std::vector<uint8_t> debug_abbrev;
    appendULEB(debug_abbrev, 1);
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfTag::DW_TAG_partial_unit));
    debug_abbrev.push_back(0x01); // children
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_addr_base));
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_sec_offset));
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00);

    appendULEB(debug_abbrev, 2);
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfTag::DW_TAG_variable));
    debug_abbrev.push_back(0x00); // no children
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_low_pc));
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_addrx1));
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00);

    debug_abbrev.push_back(0x00); // end abbrev table

    // .debug_info: DWARF5 partial unit with addr_base=0 (points at contribution start).
    std::vector<uint8_t> debug_info;
    size_t start = debug_info.size();
    appendU32(debug_info, 0); // unit_length placeholder
    appendU16LE(debug_info, 5); // version
    debug_info.push_back(static_cast<uint8_t>(DwarfUnitType::DW_UT_partial));
    debug_info.push_back(0x08); // address_size
    appendU32(debug_info, 0);   // abbrev offset
    debug_info.push_back(0x01); // root DIE abbrev code
    appendU32(debug_info, 0);   // DW_AT_addr_base = 0 (header start)
    debug_info.push_back(0x02); // child var abbrev code
    debug_info.push_back(0x00); // addrx1 index 0 (should resolve to entry[0])
    debug_info.push_back(0x00); // end children
    {
        uint32_t len = static_cast<uint32_t>(debug_info.size() - start - 4);
        debug_info[start + 0] = static_cast<uint8_t>(len & 0xff);
        debug_info[start + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_info[start + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_info[start + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    std::vector<uint8_t> debug_str = {'\0'};
    std::string dir = makeTempDir("dwarf5_ut_partial_addrx_");
    std::string elf_path = (std::filesystem::path(dir) / "ut_partial_addrx.elf").string();
    writeELFWithSections(elf_path, {
        {".debug_info", debug_info},
        {".debug_abbrev", debug_abbrev},
        {".debug_str", debug_str},
        {".debug_addr", debug_addr},
    });

    DwarfParser parser(elf_path);
    assert(parser.load());
    auto cus = parser.getCompilationUnits();
    assert(cus.size() == 1);
    assert(cus[0]);
    assert(cus[0]->getTag() == DwarfTag::DW_TAG_partial_unit);
    assert(cus[0]->getChildren().size() == 1);
    auto var = cus[0]->getChildren()[0];
    auto low_pc = var->getAttribute(DwarfAttribute::DW_AT_low_pc);
    auto addr = std::dynamic_pointer_cast<AddressAttributeValue>(low_pc);
    assert(addr && addr->getAddress() == 0xCAFEBABECAFED00DULL);

    std::cout << "DWARF5 DW_UT_partial addrx context tests passed!" << std::endl;
}

void testDwarf5SplitTypeUnitSetsCUContextForAddrx() {
    std::cout << "Testing DWARF5 DW_UT_split_type sets CU context for DW_FORM_addrx*..." << std::endl;

    // .debug_addr: DWARF32 contribution with one address entry.
    std::vector<uint8_t> debug_addr;
    appendU32(debug_addr, 0); // unit_length placeholder
    appendU16LE(debug_addr, 5);
    debug_addr.push_back(8); // address_size
    debug_addr.push_back(0); // segment_selector_size
    appendU64(debug_addr, 0x0123456789ABCDEFULL); // entry[0]
    {
        uint32_t unit_length = static_cast<uint32_t>(debug_addr.size() - 4);
        debug_addr[0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_addr[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_addr[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_addr[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    // .debug_abbrev:
    // 1) type_unit, children, DW_AT_addr_base(sec_offset)
    // 2) variable, no children, DW_AT_low_pc(addrx1)
    std::vector<uint8_t> debug_abbrev;
    appendULEB(debug_abbrev, 1);
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfTag::DW_TAG_type_unit));
    debug_abbrev.push_back(0x01); // children
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_addr_base));
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_sec_offset));
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00);

    appendULEB(debug_abbrev, 2);
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfTag::DW_TAG_variable));
    debug_abbrev.push_back(0x00); // no children
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_low_pc));
    appendULEB(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_addrx1));
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00);

    debug_abbrev.push_back(0x00); // end abbrev table

    // .debug_info: DWARF5 split-type unit with header extras then DIEs.
    std::vector<uint8_t> debug_info;
    size_t start = debug_info.size();
    appendU32(debug_info, 0); // unit_length placeholder
    appendU16LE(debug_info, 5); // version
    debug_info.push_back(static_cast<uint8_t>(DwarfUnitType::DW_UT_split_type));
    debug_info.push_back(0x08); // address_size
    appendU32(debug_info, 0);   // abbrev offset
    appendU64(debug_info, 0xDEADBEEFCAFEBABEULL); // type_signature (header extra)
    appendU32(debug_info, 0x10); // type_offset (header extra)
    debug_info.push_back(0x01); // root DIE abbrev code
    appendU32(debug_info, 0);   // DW_AT_addr_base = 0 (header start)
    debug_info.push_back(0x02); // child var abbrev code
    debug_info.push_back(0x00); // addrx1 index 0 (should resolve to entry[0])
    debug_info.push_back(0x00); // end children
    {
        uint32_t len = static_cast<uint32_t>(debug_info.size() - start - 4);
        debug_info[start + 0] = static_cast<uint8_t>(len & 0xff);
        debug_info[start + 1] = static_cast<uint8_t>((len >> 8) & 0xff);
        debug_info[start + 2] = static_cast<uint8_t>((len >> 16) & 0xff);
        debug_info[start + 3] = static_cast<uint8_t>((len >> 24) & 0xff);
    }

    std::vector<uint8_t> debug_str = {'\0'};
    std::string dir = makeTempDir("dwarf5_ut_splitt_addrx_");
    std::string elf_path = (std::filesystem::path(dir) / "ut_splitt_addrx.elf").string();
    writeELFWithSections(elf_path, {
        {".debug_info", debug_info},
        {".debug_abbrev", debug_abbrev},
        {".debug_str", debug_str},
        {".debug_addr", debug_addr},
    });

    DwarfParser parser(elf_path);
    assert(parser.load());
    auto cus = parser.getCompilationUnits();
    assert(cus.size() == 1);
    assert(cus[0]);
    assert(cus[0]->getTag() == DwarfTag::DW_TAG_type_unit);
    assert(cus[0]->getChildren().size() == 1);
    auto var = cus[0]->getChildren()[0];
    auto low_pc = var->getAttribute(DwarfAttribute::DW_AT_low_pc);
    auto addr = std::dynamic_pointer_cast<AddressAttributeValue>(low_pc);
    assert(addr && addr->getAddress() == 0x0123456789ABCDEFULL);

    std::cout << "DWARF5 DW_UT_split_type addrx context tests passed!" << std::endl;
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

void testV5IndexedFormsInHelperParsers() {
    std::cout << "Testing DWARF5 indexed forms in helper parser paths..." << std::endl;

    std::vector<uint8_t> debug_str = {
        'a','l','p','h','a','\0',
        'b','e','t','a','\0',
        'g','a','m','m','a','\0',
        'd','e','l','t','a','\0',
        'e','p','s','i','l','o','n','\0'
    };
    std::vector<uint8_t> debug_line_str = {'l','i','n','e','c','o','n','s','t','\0'};

    std::vector<uint8_t> debug_str_offsets;
    appendU32(debug_str_offsets, 0); // unit_length placeholder
    appendU16(debug_str_offsets, 5);
    appendU16(debug_str_offsets, 0);
    appendU32(debug_str_offsets, 0); // "alpha"
    appendU32(debug_str_offsets, 6); // "beta"
    appendU32(debug_str_offsets, 11); // "gamma"
    appendU32(debug_str_offsets, 17); // "delta"
    appendU32(debug_str_offsets, 23); // "epsilon"
    {
        uint32_t unit_length = static_cast<uint32_t>(debug_str_offsets.size() - 4);
        debug_str_offsets[0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_str_offsets[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_str_offsets[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_str_offsets[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    std::vector<uint8_t> debug_addr;
    appendU32(debug_addr, 0); // unit_length placeholder
    appendU16(debug_addr, 5);
    debug_addr.push_back(8);
    debug_addr.push_back(0);
    appendU64(debug_addr, 0x1111);
    appendU64(debug_addr, 0x2222);
    appendU64(debug_addr, 0x3333);
    appendU64(debug_addr, 0x4444);
    appendU64(debug_addr, 0x5555);
    {
        uint32_t unit_length = static_cast<uint32_t>(debug_addr.size() - 4);
        debug_addr[0] = static_cast<uint8_t>(unit_length & 0xff);
        debug_addr[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        debug_addr[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        debug_addr[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    // Bytes consumed in this order:
    // addrx1=1, addrx2=2, addrx3=3, addrx4=4
    // strx1=1, strx2=2, strx3=3, strx4=4
    // const(strx1)=0, const(strx3)=2, const(strx4)=3, const(line_strp)=0.
    std::vector<uint8_t> debug_info = {
        0x01,
        0x02, 0x00,
        0x03, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x01,
        0x02, 0x00,
        0x03, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x00,
        0x02, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    std::vector<uint8_t> empty;

    AttributeParser ap(debug_info, empty, debug_str,
                       /*debug_line=*/empty, /*debug_ranges=*/empty, /*debug_loc=*/empty,
                       /*debug_str_offsets=*/debug_str_offsets, /*debug_addr=*/debug_addr, /*debug_line_str=*/debug_line_str,
                       /*debug_rnglists=*/empty, /*debug_loclists=*/empty,
                       /*debug_str_sup=*/empty);
    ap.setIsDwarf64(false);
    ap.setAddressSize(8);
    ap.setDwarfVersion(DwarfVersion::DWARF5);
    ap.setCUContext(/*rnglists_base=*/0, /*loclists_base=*/0,
                    /*addr_base=*/0, /*str_offsets_base=*/0,
                    /*base_address=*/0);

    uint64_t off = 0;

    auto addr1 = std::dynamic_pointer_cast<AddressAttributeValue>(
        ap.parseAddressAttribute(DwarfForm::DW_FORM_addrx1, off));
    assert(addr1);
    assert(addr1->getAddress() == 0x2222);

    auto addr = std::dynamic_pointer_cast<AddressAttributeValue>(
        ap.parseAddressAttribute(DwarfForm::DW_FORM_addrx2, off));
    assert(addr);
    assert(addr->getAddress() == 0x3333);

    auto addr3 = std::dynamic_pointer_cast<AddressAttributeValue>(
        ap.parseAddressAttribute(DwarfForm::DW_FORM_addrx3, off));
    assert(addr3);
    assert(addr3->getAddress() == 0x4444);

    auto addr4 = std::dynamic_pointer_cast<AddressAttributeValue>(
        ap.parseAddressAttribute(DwarfForm::DW_FORM_addrx4, off));
    assert(addr4);
    assert(addr4->getAddress() == 0x5555);

    auto str1 = std::dynamic_pointer_cast<StringAttributeValue>(
        ap.parseStringAttribute(DwarfForm::DW_FORM_strx1, off));
    assert(str1);
    assert(str1->getValue() == "beta");

    auto str = std::dynamic_pointer_cast<StringAttributeValue>(
        ap.parseStringAttribute(DwarfForm::DW_FORM_strx2, off));
    assert(str);
    assert(str->getValue() == "gamma");

    auto str3 = std::dynamic_pointer_cast<StringAttributeValue>(
        ap.parseStringAttribute(DwarfForm::DW_FORM_strx3, off));
    assert(str3);
    assert(str3->getValue() == "delta");

    auto str4 = std::dynamic_pointer_cast<StringAttributeValue>(
        ap.parseStringAttribute(DwarfForm::DW_FORM_strx4, off));
    assert(str4);
    assert(str4->getValue() == "epsilon");

    auto cstrx1 = std::dynamic_pointer_cast<StringAttributeValue>(
        ap.parseConstValueAttribute(DwarfAttribute::DW_AT_const_value, DwarfForm::DW_FORM_strx1, off));
    assert(cstrx1);
    assert(cstrx1->getValue() == "alpha");

    auto cstrx3 = std::dynamic_pointer_cast<StringAttributeValue>(
        ap.parseConstValueAttribute(DwarfAttribute::DW_AT_const_value, DwarfForm::DW_FORM_strx3, off));
    assert(cstrx3);
    assert(cstrx3->getValue() == "gamma");

    auto cstrx4 = std::dynamic_pointer_cast<StringAttributeValue>(
        ap.parseConstValueAttribute(DwarfAttribute::DW_AT_const_value, DwarfForm::DW_FORM_strx4, off));
    assert(cstrx4);
    assert(cstrx4->getValue() == "delta");

    auto cline = std::dynamic_pointer_cast<StringAttributeValue>(
        ap.parseConstValueAttribute(DwarfAttribute::DW_AT_const_value, DwarfForm::DW_FORM_line_strp, off));
    assert(cline);
    assert(cline->getValue() == "lineconst");

    std::cout << "DWARF5 indexed helper parser tests passed!" << std::endl;
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
#if DWARF_HAS_Z3
        assert(r.verifier_backend == "structural+z3");
#else
        assert(r.verifier_backend == "structural+solver-unavailable");
#endif
        assert(r.solver_result == "equivalent");
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
        assert(r.verifier_backend == "structural");
        assert(r.solver_result == "precheck_register_offset_mismatch");
        assert(r.counterexample_model.empty());
        assert(r.counterexample_witness.empty());
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
        assert(eq.verdict ==
#if DWARF_HAS_Z3
               ExpressionVerificationResult::Verdict::EQUIVALENT
#else
               ExpressionVerificationResult::Verdict::UNKNOWN
#endif
        );
#if DWARF_HAS_Z3
        assert(eq.verifier_backend == "structural+z3");
#else
        assert(eq.verifier_backend == "solver-unavailable");
#endif
#if DWARF_HAS_Z3
        assert(eq.solver_result == "equivalent");
#else
        assert(eq.solver_result == "solver_unavailable");
#endif

        auto diff = v.compareFDEByIndex(pa, 0, pc, 0);
#if DWARF_HAS_Z3
        assert(diff.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(diff.verifier_backend == "z3");
        assert(diff.solver_result == "sat");
#else
        assert(diff.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);
        assert(diff.verifier_backend == "solver-unavailable");
        assert(diff.solver_result == "solver_unavailable");
#endif
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
        assert(eq.verdict ==
#if DWARF_HAS_Z3
               ExpressionVerificationResult::Verdict::EQUIVALENT
#else
               ExpressionVerificationResult::Verdict::UNKNOWN
#endif
        );
#if DWARF_HAS_Z3
        assert(eq.verifier_backend == "structural+z3");
#else
        assert(eq.verifier_backend == "solver-unavailable");
#endif
#if DWARF_HAS_Z3
        assert(eq.solver_result == "equivalent");
#else
        assert(eq.solver_result == "solver_unavailable");
#endif
        auto diff = v.compareFDEByIndex(pa, 0, pc, 0);
#if DWARF_HAS_Z3
        assert(diff.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(diff.verifier_backend == "z3");
        assert(diff.solver_result == "sat");
#else
        assert(diff.verdict == ExpressionVerificationResult::Verdict::UNKNOWN);
        assert(diff.verifier_backend == "solver-unavailable");
        assert(diff.solver_result == "solver_unavailable");
#endif
    }

    // AArch64-relevant structural checks: return-address register mismatch.
    {
        UnwindInfo lhs;
        lhs.valid = true;
        lhs.cfa.type = CFA_Type::REGISTER_OFFSET;
        lhs.cfa.reg_num = 31;
        lhs.cfa.offset = 16;
        lhs.return_address_register = 30;

        UnwindInfo rhs = lhs;
        rhs.return_address_register = 29;

        SymbolicCFIVerifier v;
        auto r = v.compareUnwindInfo(lhs, rhs, /*lhs_pc=*/0x1000, /*rhs_pc=*/0x1000);
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.verifier_backend == "structural");
        assert(r.solver_result == "precheck_ra_register_mismatch");
    }

    // AArch64 PAC state mismatch should be detected before symbolic expression checks.
    {
        UnwindInfo lhs;
        lhs.valid = true;
        lhs.cfa.type = CFA_Type::REGISTER_OFFSET;
        lhs.cfa.reg_num = 31;
        lhs.cfa.offset = 16;
        lhs.return_address_register = 30;
        lhs.aarch64_ra_sign_state = 0;

        UnwindInfo rhs = lhs;
        rhs.aarch64_ra_sign_state = 1;

        SymbolicCFIVerifier v;
        auto r = v.compareUnwindInfo(lhs, rhs, /*lhs_pc=*/0x2000, /*rhs_pc=*/0x2000);
        assert(r.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(r.verifier_backend == "structural");
        assert(r.solver_result == "precheck_aarch64_ra_sign_state_mismatch");
    }

    // Missing register rules can be treated as UNDEFINED (default) or as hard mismatch.
    {
        UnwindInfo lhs;
        lhs.valid = true;
        lhs.cfa.type = CFA_Type::REGISTER_OFFSET;
        lhs.cfa.reg_num = 31;
        lhs.cfa.offset = 16;
        lhs.return_address_register = 30;
        RegisterRule r;
        r.type = CFA_RegRule::REGISTER;
        r.reg_num = 29;
        lhs.registers[5] = r;

        UnwindInfo rhs = lhs;
        rhs.registers.erase(5);

        SymbolicCFIVerifier v;

        SymbolicCFICompareOptions strict_missing;
        strict_missing.treat_missing_register_rule_as_undefined = false;
        auto miss = v.compareUnwindInfo(lhs, rhs, /*lhs_pc=*/0x3000, /*rhs_pc=*/0x3000, strict_missing);
        assert(miss.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(miss.verifier_backend == "structural");
        assert(miss.solver_result == "precheck_register_rule_missing");

        SymbolicCFICompareOptions coerce_missing;
        coerce_missing.treat_missing_register_rule_as_undefined = true;
        auto coerced = v.compareUnwindInfo(lhs, rhs, /*lhs_pc=*/0x3000, /*rhs_pc=*/0x3000, coerce_missing);
        assert(coerced.verdict == ExpressionVerificationResult::Verdict::DIFFERENT);
        assert(coerced.verifier_backend == "structural");
        assert(coerced.solver_result == "precheck_register_rule_type_mismatch");
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
    assert(loader.hasCUIndexSection());
    assert(loader.isCUIndexValid());
    assert(!loader.hasTUIndexSection());
    assert(!loader.isTUIndexValid());
    assert(loader.getCUIndexedUnitCount() == 1);

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
        assert(l0.hasCUIndexSection());
        assert(!l0.isCUIndexValid());
        assert(l0.getCUIndexedUnitCount() == 0);
    }

    // Truncated section-id table should be rejected.
    {
        std::vector<uint8_t> idx_trunc = idx;
        idx_trunc.resize(16); // header only, section_count still says 4
        DWPLoader lt;
        assert(!lt.parseIndexData(idx_trunc, false));
        assert(lt.hasCUIndexSection());
        assert(!lt.isCUIndexValid());
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
        assert(ls.hasCUIndexSection());
        assert(!ls.isCUIndexValid());
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

    // TU index parsing state is tracked separately.
    {
        DWPLoader tu;
        assert(tu.parseIndexData(idx, true));
        assert(!tu.hasCUIndexSection());
        assert(!tu.isCUIndexValid());
        assert(tu.hasTUIndexSection());
        assert(tu.isTUIndexValid());
        assert(tu.getTUIndexedUnitCount() == 1);
        assert(tu.findUnit(sig).has_value());
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

void testImplicitConstParserPathAndSignedValue() {
    std::cout << "Testing DW_FORM_implicit_const parser path and signed values..." << std::endl;

    // Abbrev table: code=1, tag=compile_unit, no children,
    // attribute: DW_AT_language with DW_FORM_implicit_const = -7 (SLEB128 0x79).
    std::vector<uint8_t> debug_abbrev;
    debug_abbrev.push_back(0x01); // abbrev code
    debug_abbrev.push_back(0x11); // DW_TAG_compile_unit
    debug_abbrev.push_back(0x00); // no children
    debug_abbrev.push_back(0x13); // DW_AT_language
    debug_abbrev.push_back(0x21); // DW_FORM_implicit_const
    debug_abbrev.push_back(0x79); // SLEB128(-7)
    debug_abbrev.push_back(0x00); // end attr list
    debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00); // end abbrev table

    // .debug_info CU: unit_length=8, version=4, abbrev_offset=0, addr_size=8, abbrev_code=1
    std::vector<uint8_t> debug_info;
    appendU32(debug_info, 8);
    debug_info.push_back(0x04);
    debug_info.push_back(0x00);
    appendU32(debug_info, 0);
    debug_info.push_back(0x08);
    debug_info.push_back(0x01);

    std::vector<uint8_t> empty;
    ELFIO::elfio elf;
    DIEParser parser(elf, debug_info, debug_abbrev, /*debug_str=*/empty);

    auto cus = parser.parseCompilationUnits();
    assert(cus.size() == 1);
    auto lang_attr = cus[0]->getAttribute(DwarfAttribute::DW_AT_language);
    assert(lang_attr);
    auto sval = std::dynamic_pointer_cast<SignedAttributeValue>(lang_attr);
    assert(sval);
    assert(sval->getValue() == -7);

    // Direct AttributeParser path should also produce signed values and consume no bytes.
    std::vector<uint8_t> payload = {0xaa, 0xbb};
    AttributeParser ap(payload, empty, empty);
    ap.setImplicitConstValue(-13);
    uint64_t off = 1;
    auto direct = ap.parseAttribute(DwarfForm::DW_FORM_implicit_const, off);
    auto direct_s = std::dynamic_pointer_cast<SignedAttributeValue>(direct);
    assert(direct_s);
    assert(direct_s->getValue() == -13);
    assert(off == 1);

    std::cout << "DW_FORM_implicit_const parser path tests passed!" << std::endl;
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

static bool tryBuildRealSplitDwarfFixture(const std::string& dir,
                                          std::string& out_obj_path,
                                          std::string& out_dwo_path) {
    namespace fs = std::filesystem;

    const fs::path source_path = fs::path(dir) / "real_split_fixture.c";
    out_obj_path = (fs::path(dir) / "real_split_fixture.o").string();
    out_dwo_path = (fs::path(dir) / "real_split_fixture.dwo").string();

    {
        std::ofstream src(source_path);
        src
            << "typedef const int split_answer_t;\n"
            << "static int split_global = 7;\n"
            << "split_answer_t split_answer(int x) {\n"
            << "    int local = x + split_global;\n"
            << "    return local;\n"
            << "}\n";
    }

    const std::vector<std::string> commands = {
        "cd \"" + dir + "\" && clang -target x86_64-unknown-linux-gnu -c -g -gsplit-dwarf -O0 \"" +
            source_path.filename().string() + "\" -o \"" + fs::path(out_obj_path).filename().string() + "\"",
        "cd \"" + dir + "\" && clang -c -g -gsplit-dwarf -O0 \"" +
            source_path.filename().string() + "\" -o \"" + fs::path(out_obj_path).filename().string() + "\"",
        "cd \"" + dir + "\" && gcc -c -g -gsplit-dwarf -O0 \"" +
            source_path.filename().string() + "\" -o \"" + fs::path(out_obj_path).filename().string() + "\""
    };

    for (const auto& command : commands) {
        std::error_code ec;
        fs::remove(out_obj_path, ec);
        fs::remove(out_dwo_path, ec);
        int rc = std::system(command.c_str());
        if (rc == 0 && fs::exists(out_obj_path) && fs::exists(out_dwo_path)) {
            return true;
        }
    }

    return false;
}

static uint64_t fnv1a64String(const std::string& s) {
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) {
        h ^= static_cast<uint64_t>(c);
        h *= 1099511628211ULL;
    }
    return h;
}

static std::unordered_map<std::string, std::vector<uint8_t>> loadELFSectionsByName(const std::string& path) {
    std::unordered_map<std::string, std::vector<uint8_t>> sections;

    ELFIO::elfio reader;
    if (!reader.load(path)) {
        return sections;
    }

    for (const auto& section : reader.sections) {
        const char* data = section->get_data();
        size_t size = section->get_size();
        if (!data || size == 0) {
            continue;
        }
        sections.emplace(section->get_name(), std::vector<uint8_t>(data, data + size));
    }

    return sections;
}

static bool buildSyntheticDWPFromRealFixture(const std::string& obj_path,
                                             const std::string& dwo_path,
                                             const std::string& dwp_path) {
    DwarfParser parser(obj_path);
    if (!parser.load()) {
        return false;
    }

    const auto& cus = parser.getCompilationUnits();
    if (cus.empty() || !cus[0]) {
        return false;
    }

    auto dwo_name_attr = std::dynamic_pointer_cast<StringAttributeValue>(
        cus[0]->getAttribute(DwarfAttribute::DW_AT_dwo_name));
    auto comp_dir_attr = std::dynamic_pointer_cast<StringAttributeValue>(
        cus[0]->getAttribute(DwarfAttribute::DW_AT_comp_dir));
    if (!dwo_name_attr || !comp_dir_attr) {
        return false;
    }

    std::string id_material = comp_dir_attr->getValue();
    id_material.push_back('\0');
    id_material += dwo_name_attr->getValue();
    const uint64_t dwo_id = fnv1a64String(id_material);

    auto dwo_sections = loadELFSectionsByName(dwo_path);
    const auto info_it = dwo_sections.find(".debug_info.dwo");
    const auto abbrev_it = dwo_sections.find(".debug_abbrev.dwo");
    const auto str_offsets_it = dwo_sections.find(".debug_str_offsets.dwo");
    const auto str_it = dwo_sections.find(".debug_str.dwo");
    if (info_it == dwo_sections.end() ||
        abbrev_it == dwo_sections.end() ||
        str_offsets_it == dwo_sections.end() ||
        str_it == dwo_sections.end()) {
        return false;
    }

    std::vector<uint8_t> cu_index;
    appendU32(cu_index, 6); // version
    appendU32(cu_index, 3); // section_count
    appendU32(cu_index, 1); // unit_count
    appendU32(cu_index, 1); // slot_count
    appendU32(cu_index, 1); // DW_SECT_INFO
    appendU32(cu_index, 3); // DW_SECT_ABBREV
    appendU32(cu_index, 6); // DW_SECT_STR_OFFSETS
    appendU64(cu_index, dwo_id); // signature
    appendU32(cu_index, 1);      // row index
    appendU32(cu_index, 0); // info offset
    appendU32(cu_index, 0); // abbrev offset
    appendU32(cu_index, 0); // str_offsets offset
    appendU32(cu_index, static_cast<uint32_t>(info_it->second.size()));
    appendU32(cu_index, static_cast<uint32_t>(abbrev_it->second.size()));
    appendU32(cu_index, static_cast<uint32_t>(str_offsets_it->second.size()));

    std::vector<std::pair<std::string, std::vector<uint8_t>>> dwp_sections = {
        {".debug_info.dwo", info_it->second},
        {".debug_abbrev.dwo", abbrev_it->second},
        {".debug_str_offsets.dwo", str_offsets_it->second},
        {".debug_str.dwo", str_it->second},
        {".debug_cu_index", cu_index},
    };

    auto line_str_it = dwo_sections.find(".debug_line_str.dwo");
    if (line_str_it != dwo_sections.end()) {
        dwp_sections.push_back({".debug_line_str.dwo", line_str_it->second});
    }

    writeELFWithSections(dwp_path, dwp_sections);
    return true;
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

void testSplitDwarfRealCompilerFixture() {
    std::cout << "Testing split DWARF integration (real compiler fixture)..." << std::endl;

    std::string dir = makeTempDir("dwarf_split_real_");
    std::string obj_path;
    std::string dwo_path;
    bool built = tryBuildRealSplitDwarfFixture(dir, obj_path, dwo_path);
    if (!built) {
        std::cout << "Skipping real compiler split DWARF fixture test: no suitable compiler output\n";
        return;
    }

    DwarfParser parser(obj_path);
    parser.addDWOSearchPath(dir);
    assert(parser.load());

    const auto& stats = parser.getSplitDwarfStats();
    assert(stats.dwo_hits >= 1);
    assert(stats.dwp_hits == 0);

    auto funcs = parser.findDIEsByName("split_answer");
    bool found_func = false;
    for (const auto& die : funcs) {
        if (die && die->getTag() == DwarfTag::DW_TAG_subprogram) {
            found_func = true;
            break;
        }
    }
    assert(found_func);

    auto vars = parser.findDIEsByName("split_global");
    bool found_var = false;
    for (const auto& die : vars) {
        if (die && die->getTag() == DwarfTag::DW_TAG_variable) {
            found_var = true;
            break;
        }
    }
    assert(found_var);

    auto typedefs = parser.findDIEsByName("split_answer_t");
    bool found_typedef = false;
    for (const auto& die : typedefs) {
        if (die && die->getTag() == DwarfTag::DW_TAG_typedef) {
            found_typedef = true;
            break;
        }
    }
    assert(found_typedef);

    std::cout << "Real compiler split DWARF fixture tests passed!" << std::endl;
}

void testSplitDwarfRealCompilerDWPFixture() {
    std::cout << "Testing split DWARF DWP integration (real compiler payload)..." << std::endl;

    std::string dir = makeTempDir("dwarf_split_real_dwp_");
    std::string obj_path;
    std::string dwo_path;
    bool built = tryBuildRealSplitDwarfFixture(dir, obj_path, dwo_path);
    if (!built) {
        std::cout << "Skipping real compiler DWP fixture test: no suitable compiler output\n";
        return;
    }

    std::string dwp_path = (std::filesystem::path(dir) / "real_split_fixture.dwp").string();
    bool packaged = buildSyntheticDWPFromRealFixture(obj_path, dwo_path, dwp_path);
    if (!packaged) {
        std::cout << "Skipping real compiler DWP fixture test: could not package real DWO payload\n";
        return;
    }

    std::filesystem::rename(dwo_path, dwo_path + ".hidden");

    DwarfParser parser(obj_path);
    assert(parser.loadDWPFile(dwp_path));
    assert(parser.load());

    const auto& stats = parser.getSplitDwarfStats();
    assert(stats.dwp_hits >= 1);
    assert(stats.dwo_hits == 0);

    auto funcs = parser.findDIEsByName("split_answer");
    bool found_func = false;
    for (const auto& die : funcs) {
        if (die && die->getTag() == DwarfTag::DW_TAG_subprogram) {
            found_func = true;
            break;
        }
    }
    assert(found_func);

    auto vars = parser.findDIEsByName("split_global");
    bool found_var = false;
    for (const auto& die : vars) {
        if (die && die->getTag() == DwarfTag::DW_TAG_variable) {
            found_var = true;
            break;
        }
    }
    assert(found_var);

    std::cout << "Real compiler DWP fixture tests passed!" << std::endl;
}

void testDwarfParserDWPStateTransitions() {
    std::cout << "Testing DwarfParser DWP state transitions..." << std::endl;

    auto buildPayloadAbbrev = []() -> std::vector<uint8_t> {
        std::vector<uint8_t> a;
        a.push_back(0x01); // CU
        a.push_back(0x11); // DW_TAG_compile_unit
        a.push_back(0x00); // no children
        a.push_back(0x00); a.push_back(0x00);
        a.push_back(0x00); // end table
        return a;
    };

    auto buildPayloadInfo = []() -> std::vector<uint8_t> {
        std::vector<uint8_t> i;
        appendU32(i, 0); // placeholder unit_length
        i.push_back(0x04); i.push_back(0x00); // version 4
        appendU32(i, 0); // abbrev offset
        i.push_back(0x08); // addr_size
        i.push_back(0x01); // CU code
        uint32_t unit_length = static_cast<uint32_t>(i.size() - 4);
        i[0] = static_cast<uint8_t>(unit_length & 0xff);
        i[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        i[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        i[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
        return i;
    };

    auto buildValidCUIndex = [](uint64_t sig, uint32_t info_size, uint32_t abbrev_size) -> std::vector<uint8_t> {
        std::vector<uint8_t> idx;
        appendU32(idx, 6); // version
        appendU32(idx, 2); // section_count
        appendU32(idx, 1); // unit_count
        appendU32(idx, 1); // slot_count
        appendU32(idx, 1); // DW_SECT_INFO
        appendU32(idx, 3); // DW_SECT_ABBREV
        appendU64(idx, sig);
        appendU32(idx, 1); // row index
        appendU32(idx, 0); // info off
        appendU32(idx, 0); // abbrev off
        appendU32(idx, info_size);
        appendU32(idx, abbrev_size);
        return idx;
    };

    auto buildMalformedCUIndex = []() -> std::vector<uint8_t> {
        std::vector<uint8_t> idx;
        appendU32(idx, 6); // version
        appendU32(idx, 2); // section_count
        appendU32(idx, 1); // unit_count
        appendU32(idx, 1); // slot_count
        // Missing section ids/tables.
        return idx;
    };

    std::string dir = makeTempDir("dwarf_parser_dwp_state_");
    std::string bad_path = (std::filesystem::path(dir) / "state_bad.dwp").string();
    std::string good_path = (std::filesystem::path(dir) / "state_good.dwp").string();
    std::string tu_path = (std::filesystem::path(dir) / "state_tu_only.dwp").string();

    std::vector<uint8_t> info = buildPayloadInfo();
    std::vector<uint8_t> abbrev = buildPayloadAbbrev();
    std::vector<uint8_t> str = {'x', 0};
    const uint64_t sig = 0x1122334455667788ULL;

    writeELFWithSections(bad_path, {
        {".debug_info.dwo", info},
        {".debug_abbrev.dwo", abbrev},
        {".debug_str.dwo", str},
        {".debug_cu_index", buildMalformedCUIndex()},
    });

    writeELFWithSections(good_path, {
        {".debug_info.dwo", info},
        {".debug_abbrev.dwo", abbrev},
        {".debug_str.dwo", str},
        {".debug_cu_index", buildValidCUIndex(sig, static_cast<uint32_t>(info.size()), static_cast<uint32_t>(abbrev.size()))},
    });

    writeELFWithSections(tu_path, {
        {".debug_info.dwo", info},
        {".debug_abbrev.dwo", abbrev},
        {".debug_str.dwo", str},
        {".debug_tu_index", buildValidCUIndex(sig, static_cast<uint32_t>(info.size()), static_cast<uint32_t>(abbrev.size()))},
    });

    DwarfParser parser("unused_main_path.elf");

    // Before loading DWP.
    assert(!parser.hasLoadedDWP());
    assert(parser.getLoadedDWPPath().empty());
    assert(!parser.hasDWPIndexSection());
    assert(!parser.isDWPIndexValid());
    assert(parser.getDWPIndexedUnitCount() == 0);

    // After malformed index.
    assert(parser.loadDWPFile(bad_path));
    assert(parser.hasLoadedDWP());
    assert(parser.getLoadedDWPPath() == bad_path);
    assert(parser.hasDWPIndexSection());
    assert(!parser.isDWPIndexValid());
    assert(parser.getDWPIndexedUnitCount() == 0);

    // After valid index.
    assert(parser.loadDWPFile(good_path));
    assert(parser.hasLoadedDWP());
    assert(parser.getLoadedDWPPath() == good_path);
    assert(parser.hasDWPIndexSection());
    assert(parser.isDWPIndexValid());
    assert(parser.getDWPIndexedUnitCount() == 1);
    assert(!parser.hasDWPTUIndexSection());
    assert(!parser.isDWPTUIndexValid());
    assert(parser.getDWPTUIndexedUnitCount() == 0);

    // After TU-only valid index.
    assert(parser.loadDWPFile(tu_path));
    assert(parser.hasLoadedDWP());
    assert(parser.getLoadedDWPPath() == tu_path);
    assert(!parser.hasDWPIndexSection());
    assert(!parser.isDWPIndexValid());
    assert(parser.getDWPIndexedUnitCount() == 0);
    assert(parser.hasDWPTUIndexSection());
    assert(parser.isDWPTUIndexValid());
    assert(parser.getDWPTUIndexedUnitCount() == 1);

    std::cout << "DwarfParser DWP state transition tests passed!" << std::endl;
}

void testSplitDwarfPrefersDWPOverDWO() {
    std::cout << "Testing split DWARF preference: .dwp over .dwo..." << std::endl;

    const uint64_t dwo_id = 0x1020304050607080ULL;
    const std::string dwo_name = "prefer_unit.dwo";
    const std::string dwp_name = "prefer_unit.dwp";

    // Main executable .debug_str holds the DWO filename.
    std::vector<uint8_t> main_str;
    uint32_t dwo_name_off = static_cast<uint32_t>(main_str.size());
    for (char c : dwo_name) main_str.push_back(static_cast<uint8_t>(c));
    main_str.push_back(0);

    // Main .debug_abbrev: skeleton CU with dwo_name + dwo_id.
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

    std::vector<uint8_t> main_info;
    appendU32(main_info, 0); // placeholder unit_length
    main_info.push_back(0x04); main_info.push_back(0x00); // version 4
    appendU32(main_info, 0); // abbrev offset
    main_info.push_back(0x08); // addr_size
    main_info.push_back(0x01); // abbrev code
    appendU32(main_info, dwo_name_off);
    appendU64(main_info, dwo_id);
    {
        uint32_t unit_length = static_cast<uint32_t>(main_info.size() - 4);
        main_info[0] = static_cast<uint8_t>(unit_length & 0xff);
        main_info[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        main_info[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        main_info[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    // Shared abbrev for DWO/DWP payload: CU with one variable child(name=strp).
    std::vector<uint8_t> payload_abbrev;
    payload_abbrev.push_back(0x01); // CU
    payload_abbrev.push_back(0x11); // DW_TAG_compile_unit
    payload_abbrev.push_back(0x01); // has children
    payload_abbrev.push_back(0x00); payload_abbrev.push_back(0x00);
    payload_abbrev.push_back(0x02); // variable
    payload_abbrev.push_back(0x34); // DW_TAG_variable
    payload_abbrev.push_back(0x00); // no children
    appendULEB128(payload_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_name));
    appendULEB128(payload_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_strp));
    payload_abbrev.push_back(0x00); payload_abbrev.push_back(0x00);
    payload_abbrev.push_back(0x00);

    auto makePayloadInfo = []() -> std::vector<uint8_t> {
        std::vector<uint8_t> info;
        appendU32(info, 0); // placeholder unit_length
        info.push_back(0x04); info.push_back(0x00); // version 4
        appendU32(info, 0); // abbrev offset
        info.push_back(0x08); // addr_size
        info.push_back(0x01); // CU code
        info.push_back(0x02); // variable code
        appendU32(info, 0);   // name strp offset
        info.push_back(0x00); // end children
        uint32_t unit_length = static_cast<uint32_t>(info.size() - 4);
        info[0] = static_cast<uint8_t>(unit_length & 0xff);
        info[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        info[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        info[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
        return info;
    };

    const std::string name_from_dwo = "FromDWO";
    const std::string name_from_dwp = "FromDWP";

    std::vector<uint8_t> dwo_str;
    for (char c : name_from_dwo) dwo_str.push_back(static_cast<uint8_t>(c));
    dwo_str.push_back(0);

    std::vector<uint8_t> dwp_str;
    for (char c : name_from_dwp) dwp_str.push_back(static_cast<uint8_t>(c));
    dwp_str.push_back(0);

    std::vector<uint8_t> payload_info = makePayloadInfo();

    // Build .debug_cu_index for one unit with INFO and ABBREV columns.
    std::vector<uint8_t> cu_index;
    appendU32(cu_index, 6); // version
    appendU32(cu_index, 2); // section_count
    appendU32(cu_index, 1); // unit_count
    appendU32(cu_index, 1); // slot_count
    appendU32(cu_index, 1); // DW_SECT_INFO
    appendU32(cu_index, 3); // DW_SECT_ABBREV
    appendU64(cu_index, dwo_id); // hash/signature
    appendU32(cu_index, 1);      // row index (1-based)
    appendU32(cu_index, 0);      // info offset
    appendU32(cu_index, 0);      // abbrev offset
    appendU32(cu_index, static_cast<uint32_t>(payload_info.size()));   // info size
    appendU32(cu_index, static_cast<uint32_t>(payload_abbrev.size())); // abbrev size

    std::string dir = makeTempDir("dwarf_split_prefer_dwp_");
    std::string main_path = (std::filesystem::path(dir) / "main_prefer.elf").string();
    std::string dwo_path = (std::filesystem::path(dir) / dwo_name).string();
    std::string dwp_path = (std::filesystem::path(dir) / dwp_name).string();

    writeELFWithSections(main_path, {
        {".debug_info", main_info},
        {".debug_abbrev", main_abbrev},
        {".debug_str", main_str},
    });

    writeELFWithSections(dwo_path, {
        {".debug_info.dwo", payload_info},
        {".debug_abbrev.dwo", payload_abbrev},
        {".debug_str.dwo", dwo_str},
    });

    writeELFWithSections(dwp_path, {
        {".debug_info.dwo", payload_info},
        {".debug_abbrev.dwo", payload_abbrev},
        {".debug_str.dwo", dwp_str},
        {".debug_cu_index", cu_index},
    });

    DwarfParser parser(main_path);
    parser.addDWOSearchPath(dir);
    assert(parser.loadDWPFile(dwp_path));
    assert(parser.load());

    // Must resolve from DWP payload and not fall back to DWO payload.
    auto dwp_hits = parser.findDIEsByName(name_from_dwp);
    assert(!dwp_hits.empty());
    bool found_dwp_var = false;
    for (const auto& die : dwp_hits) {
        if (die && die->getTag() == DwarfTag::DW_TAG_variable) {
            found_dwp_var = true;
            break;
        }
    }
    assert(found_dwp_var);

    auto dwo_hits = parser.findDIEsByName(name_from_dwo);
    assert(dwo_hits.empty());

    std::cout << "Split DWARF DWP preference tests passed!" << std::endl;
}

void testSplitDwarfFallsBackToDWOWhenDWPDoesNotContainUnit() {
    std::cout << "Testing split DWARF fallback: .dwo when .dwp has no matching unit..." << std::endl;

    const uint64_t dwo_id = 0x8877665544332211ULL;
    const uint64_t other_sig = 0x1111222233334444ULL;
    const std::string dwo_name = "fallback_unit.dwo";
    const std::string dwp_name = "fallback_unit.dwp";
    const std::string var_name = "FromDWOOnly";

    // Main executable .debug_str holds the DWO filename.
    std::vector<uint8_t> main_str;
    uint32_t dwo_name_off = static_cast<uint32_t>(main_str.size());
    for (char c : dwo_name) main_str.push_back(static_cast<uint8_t>(c));
    main_str.push_back(0);

    // Main skeleton CU abbrev: dwo_name + dwo_id.
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

    std::vector<uint8_t> main_info;
    appendU32(main_info, 0); // placeholder unit_length
    main_info.push_back(0x04); main_info.push_back(0x00); // version 4
    appendU32(main_info, 0); // abbrev offset
    main_info.push_back(0x08); // addr_size
    main_info.push_back(0x01); // abbrev code
    appendU32(main_info, dwo_name_off);
    appendU64(main_info, dwo_id);
    {
        uint32_t unit_length = static_cast<uint32_t>(main_info.size() - 4);
        main_info[0] = static_cast<uint8_t>(unit_length & 0xff);
        main_info[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        main_info[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        main_info[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    // Shared payload abbrev: CU with one variable child(name=strp).
    std::vector<uint8_t> payload_abbrev;
    payload_abbrev.push_back(0x01); // CU
    payload_abbrev.push_back(0x11); // DW_TAG_compile_unit
    payload_abbrev.push_back(0x01); // has children
    payload_abbrev.push_back(0x00); payload_abbrev.push_back(0x00);
    payload_abbrev.push_back(0x02); // variable
    payload_abbrev.push_back(0x34); // DW_TAG_variable
    payload_abbrev.push_back(0x00); // no children
    appendULEB128(payload_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_name));
    appendULEB128(payload_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_strp));
    payload_abbrev.push_back(0x00); payload_abbrev.push_back(0x00);
    payload_abbrev.push_back(0x00);

    std::vector<uint8_t> payload_info;
    appendU32(payload_info, 0); // placeholder unit_length
    payload_info.push_back(0x04); payload_info.push_back(0x00); // version 4
    appendU32(payload_info, 0); // abbrev offset
    payload_info.push_back(0x08); // addr_size
    payload_info.push_back(0x01); // CU code
    payload_info.push_back(0x02); // variable code
    appendU32(payload_info, 0);   // name strp offset
    payload_info.push_back(0x00); // end children
    {
        uint32_t unit_length = static_cast<uint32_t>(payload_info.size() - 4);
        payload_info[0] = static_cast<uint8_t>(unit_length & 0xff);
        payload_info[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        payload_info[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        payload_info[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    std::vector<uint8_t> dwo_str;
    for (char c : var_name) dwo_str.push_back(static_cast<uint8_t>(c));
    dwo_str.push_back(0);

    // .debug_cu_index points to a different signature than skeleton dwo_id.
    std::vector<uint8_t> cu_index;
    appendU32(cu_index, 6); // version
    appendU32(cu_index, 2); // section_count
    appendU32(cu_index, 1); // unit_count
    appendU32(cu_index, 1); // slot_count
    appendU32(cu_index, 1); // DW_SECT_INFO
    appendU32(cu_index, 3); // DW_SECT_ABBREV
    appendU64(cu_index, other_sig); // hash/signature (non-matching)
    appendU32(cu_index, 1); // row index
    appendU32(cu_index, 0); // info offset
    appendU32(cu_index, 0); // abbrev offset
    appendU32(cu_index, static_cast<uint32_t>(payload_info.size()));   // info size
    appendU32(cu_index, static_cast<uint32_t>(payload_abbrev.size())); // abbrev size

    std::string dir = makeTempDir("dwarf_split_fallback_dwo_");
    std::string main_path = (std::filesystem::path(dir) / "main_fallback.elf").string();
    std::string dwo_path = (std::filesystem::path(dir) / dwo_name).string();
    std::string dwp_path = (std::filesystem::path(dir) / dwp_name).string();

    writeELFWithSections(main_path, {
        {".debug_info", main_info},
        {".debug_abbrev", main_abbrev},
        {".debug_str", main_str},
    });

    writeELFWithSections(dwo_path, {
        {".debug_info.dwo", payload_info},
        {".debug_abbrev.dwo", payload_abbrev},
        {".debug_str.dwo", dwo_str},
    });

    writeELFWithSections(dwp_path, {
        {".debug_info.dwo", payload_info},
        {".debug_abbrev.dwo", payload_abbrev},
        {".debug_str.dwo", dwo_str},
        {".debug_cu_index", cu_index},
    });

    DwarfParser parser(main_path);
    parser.addDWOSearchPath(dir);
    parser.setVerbose(true);
    assert(parser.loadDWPFile(dwp_path));
    std::ostringstream err;
    auto* old_cerr = std::cerr.rdbuf(err.rdbuf());
    assert(parser.load());
    std::cerr.rdbuf(old_cerr);
    assert(err.str().find("fallback reason=signature_not_found") != std::string::npos);

    auto hits = parser.findDIEsByName(var_name);
    assert(!hits.empty());
    bool found_variable = false;
    for (const auto& die : hits) {
        if (die && die->getTag() == DwarfTag::DW_TAG_variable) {
            found_variable = true;
            break;
        }
    }
    assert(found_variable);
    const auto& stats = parser.getSplitDwarfStats();
    assert(stats.dwo_fallback_hits == 1);
    assert(stats.fallback_sig_miss == 1);
    assert(stats.fallback_invalid_index == 0);
    assert(stats.fallback_no_index == 0);

    std::cout << "Split DWARF DWO fallback tests passed!" << std::endl;
}

void testSplitDwarfFallsBackToDWOWhenDWPIndexMalformed() {
    std::cout << "Testing split DWARF fallback: .dwo when .dwp index is malformed..." << std::endl;

    const uint64_t dwo_id = 0xDEADBEEF00112233ULL;
    const std::string dwo_name = "fallback_bad_index.dwo";
    const std::string dwp_name = "fallback_bad_index.dwp";
    const std::string var_name = "FromDWOAfterBadIndex";

    std::vector<uint8_t> main_str;
    uint32_t dwo_name_off = static_cast<uint32_t>(main_str.size());
    for (char c : dwo_name) main_str.push_back(static_cast<uint8_t>(c));
    main_str.push_back(0);

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

    std::vector<uint8_t> main_info;
    appendU32(main_info, 0); // placeholder unit_length
    main_info.push_back(0x04); main_info.push_back(0x00); // version 4
    appendU32(main_info, 0); // abbrev offset
    main_info.push_back(0x08); // addr_size
    main_info.push_back(0x01); // abbrev code
    appendU32(main_info, dwo_name_off);
    appendU64(main_info, dwo_id);
    {
        uint32_t unit_length = static_cast<uint32_t>(main_info.size() - 4);
        main_info[0] = static_cast<uint8_t>(unit_length & 0xff);
        main_info[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        main_info[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        main_info[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    // Minimal DWO payload with one variable named var_name.
    std::vector<uint8_t> payload_abbrev;
    payload_abbrev.push_back(0x01); // CU
    payload_abbrev.push_back(0x11); // DW_TAG_compile_unit
    payload_abbrev.push_back(0x01); // has children
    payload_abbrev.push_back(0x00); payload_abbrev.push_back(0x00);
    payload_abbrev.push_back(0x02); // variable
    payload_abbrev.push_back(0x34); // DW_TAG_variable
    payload_abbrev.push_back(0x00); // no children
    appendULEB128(payload_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_name));
    appendULEB128(payload_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_strp));
    payload_abbrev.push_back(0x00); payload_abbrev.push_back(0x00);
    payload_abbrev.push_back(0x00);

    std::vector<uint8_t> payload_info;
    appendU32(payload_info, 0); // placeholder unit_length
    payload_info.push_back(0x04); payload_info.push_back(0x00); // version 4
    appendU32(payload_info, 0); // abbrev offset
    payload_info.push_back(0x08); // addr_size
    payload_info.push_back(0x01); // CU code
    payload_info.push_back(0x02); // variable code
    appendU32(payload_info, 0);   // name strp offset
    payload_info.push_back(0x00); // end children
    {
        uint32_t unit_length = static_cast<uint32_t>(payload_info.size() - 4);
        payload_info[0] = static_cast<uint8_t>(unit_length & 0xff);
        payload_info[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        payload_info[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        payload_info[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    std::vector<uint8_t> dwo_str;
    for (char c : var_name) dwo_str.push_back(static_cast<uint8_t>(c));
    dwo_str.push_back(0);

    // Intentionally malformed/truncated .debug_cu_index.
    std::vector<uint8_t> bad_cu_index;
    appendU32(bad_cu_index, 6); // version
    appendU32(bad_cu_index, 2); // section_count
    appendU32(bad_cu_index, 1); // unit_count
    appendU32(bad_cu_index, 1); // slot_count
    // Missing section IDs / tables on purpose.

    std::string dir = makeTempDir("dwarf_split_bad_dwp_index_");
    std::string main_path = (std::filesystem::path(dir) / "main_bad_dwp_index.elf").string();
    std::string dwo_path = (std::filesystem::path(dir) / dwo_name).string();
    std::string dwp_path = (std::filesystem::path(dir) / dwp_name).string();

    writeELFWithSections(main_path, {
        {".debug_info", main_info},
        {".debug_abbrev", main_abbrev},
        {".debug_str", main_str},
    });

    writeELFWithSections(dwo_path, {
        {".debug_info.dwo", payload_info},
        {".debug_abbrev.dwo", payload_abbrev},
        {".debug_str.dwo", dwo_str},
    });

    writeELFWithSections(dwp_path, {
        {".debug_info.dwo", payload_info},
        {".debug_abbrev.dwo", payload_abbrev},
        {".debug_str.dwo", dwo_str},
        {".debug_cu_index", bad_cu_index},
    });

    DwarfParser parser(main_path);
    parser.addDWOSearchPath(dir);
    parser.setVerbose(true);
    assert(parser.loadDWPFile(dwp_path)); // DWP loads, but index has no usable rows.
    std::ostringstream err;
    auto* old_cerr = std::cerr.rdbuf(err.rdbuf());
    assert(parser.load());
    std::cerr.rdbuf(old_cerr);
    assert(err.str().find("fallback reason=invalid_cu_index") != std::string::npos);

    auto hits = parser.findDIEsByName(var_name);
    assert(!hits.empty());
    bool found_variable = false;
    for (const auto& die : hits) {
        if (die && die->getTag() == DwarfTag::DW_TAG_variable) {
            found_variable = true;
            break;
        }
    }
    assert(found_variable);
    const auto& stats = parser.getSplitDwarfStats();
    assert(stats.dwo_fallback_hits == 1);
    assert(stats.fallback_invalid_index == 1);
    assert(stats.fallback_sig_miss == 0);
    assert(stats.fallback_no_index == 0);

    std::cout << "Split DWARF malformed-index fallback tests passed!" << std::endl;
}

void testSplitDwarfFallsBackToDWOWhenDWPHasNoCUIndex() {
    std::cout << "Testing split DWARF fallback: .dwo when .dwp has no CU index..." << std::endl;

    const uint64_t dwo_id = 0xCAFED00D11223344ULL;
    const std::string dwo_name = "fallback_no_index.dwo";
    const std::string dwp_name = "fallback_no_index.dwp";
    const std::string var_name = "FromDWONoIndex";

    std::vector<uint8_t> main_str;
    uint32_t dwo_name_off = static_cast<uint32_t>(main_str.size());
    for (char c : dwo_name) main_str.push_back(static_cast<uint8_t>(c));
    main_str.push_back(0);

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

    std::vector<uint8_t> main_info;
    appendU32(main_info, 0); // placeholder unit_length
    main_info.push_back(0x04); main_info.push_back(0x00); // version 4
    appendU32(main_info, 0); // abbrev offset
    main_info.push_back(0x08); // addr_size
    main_info.push_back(0x01); // abbrev code
    appendU32(main_info, dwo_name_off);
    appendU64(main_info, dwo_id);
    {
        uint32_t unit_length = static_cast<uint32_t>(main_info.size() - 4);
        main_info[0] = static_cast<uint8_t>(unit_length & 0xff);
        main_info[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        main_info[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        main_info[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    std::vector<uint8_t> payload_abbrev;
    payload_abbrev.push_back(0x01); // CU
    payload_abbrev.push_back(0x11); // DW_TAG_compile_unit
    payload_abbrev.push_back(0x01); // has children
    payload_abbrev.push_back(0x00); payload_abbrev.push_back(0x00);
    payload_abbrev.push_back(0x02); // variable
    payload_abbrev.push_back(0x34); // DW_TAG_variable
    payload_abbrev.push_back(0x00); // no children
    appendULEB128(payload_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_name));
    appendULEB128(payload_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_strp));
    payload_abbrev.push_back(0x00); payload_abbrev.push_back(0x00);
    payload_abbrev.push_back(0x00);

    std::vector<uint8_t> payload_info;
    appendU32(payload_info, 0); // placeholder unit_length
    payload_info.push_back(0x04); payload_info.push_back(0x00); // version 4
    appendU32(payload_info, 0); // abbrev offset
    payload_info.push_back(0x08); // addr_size
    payload_info.push_back(0x01); // CU code
    payload_info.push_back(0x02); // variable code
    appendU32(payload_info, 0);   // name strp offset
    payload_info.push_back(0x00); // end children
    {
        uint32_t unit_length = static_cast<uint32_t>(payload_info.size() - 4);
        payload_info[0] = static_cast<uint8_t>(unit_length & 0xff);
        payload_info[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        payload_info[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        payload_info[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    std::vector<uint8_t> dwo_str;
    for (char c : var_name) dwo_str.push_back(static_cast<uint8_t>(c));
    dwo_str.push_back(0);

    std::string dir = makeTempDir("dwarf_split_no_cu_index_");
    std::string main_path = (std::filesystem::path(dir) / "main_no_cu_index.elf").string();
    std::string dwo_path = (std::filesystem::path(dir) / dwo_name).string();
    std::string dwp_path = (std::filesystem::path(dir) / dwp_name).string();

    writeELFWithSections(main_path, {
        {".debug_info", main_info},
        {".debug_abbrev", main_abbrev},
        {".debug_str", main_str},
    });

    writeELFWithSections(dwo_path, {
        {".debug_info.dwo", payload_info},
        {".debug_abbrev.dwo", payload_abbrev},
        {".debug_str.dwo", dwo_str},
    });

    // DWP has DWO payload sections but no .debug_cu_index.
    writeELFWithSections(dwp_path, {
        {".debug_info.dwo", payload_info},
        {".debug_abbrev.dwo", payload_abbrev},
        {".debug_str.dwo", dwo_str},
    });

    DwarfParser parser(main_path);
    parser.addDWOSearchPath(dir);
    parser.setVerbose(true);
    assert(parser.loadDWPFile(dwp_path));
    std::ostringstream err;
    auto* old_cerr = std::cerr.rdbuf(err.rdbuf());
    assert(parser.load());
    std::cerr.rdbuf(old_cerr);
    assert(err.str().find("fallback reason=no_cu_index") != std::string::npos);

    auto hits = parser.findDIEsByName(var_name);
    assert(!hits.empty());
    bool found_variable = false;
    for (const auto& die : hits) {
        if (die && die->getTag() == DwarfTag::DW_TAG_variable) {
            found_variable = true;
            break;
        }
    }
    assert(found_variable);

    const auto& stats = parser.getSplitDwarfStats();
    assert(stats.dwo_fallback_hits == 1);
    assert(stats.fallback_no_index == 1);
    assert(stats.fallback_invalid_index == 0);
    assert(stats.fallback_sig_miss == 0);

    std::cout << "Split DWARF no-index fallback tests passed!" << std::endl;
}

void testSplitDwarfUsesTUIndexWhenCUIndexAbsent() {
    std::cout << "Testing split DWARF: TU index lookup when CU index absent..." << std::endl;

    const uint64_t dwo_id = 0x1234567890ABCDEFULL;
    const std::string dwo_name = "tu_index_only.dwo";
    const std::string dwp_name = "tu_index_only.dwp";
    const std::string var_name = "FromTUIndex";

    std::vector<uint8_t> main_str;
    uint32_t dwo_name_off = static_cast<uint32_t>(main_str.size());
    for (char c : dwo_name) main_str.push_back(static_cast<uint8_t>(c));
    main_str.push_back(0);

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

    std::vector<uint8_t> main_info;
    appendU32(main_info, 0); // placeholder unit_length
    main_info.push_back(0x04); main_info.push_back(0x00); // version 4
    appendU32(main_info, 0); // abbrev offset
    main_info.push_back(0x08); // addr_size
    main_info.push_back(0x01); // abbrev code
    appendU32(main_info, dwo_name_off);
    appendU64(main_info, dwo_id);
    {
        uint32_t unit_length = static_cast<uint32_t>(main_info.size() - 4);
        main_info[0] = static_cast<uint8_t>(unit_length & 0xff);
        main_info[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        main_info[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        main_info[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    std::vector<uint8_t> payload_abbrev;
    payload_abbrev.push_back(0x01); // CU
    payload_abbrev.push_back(0x11); // DW_TAG_compile_unit
    payload_abbrev.push_back(0x01); // has children
    payload_abbrev.push_back(0x00); payload_abbrev.push_back(0x00);
    payload_abbrev.push_back(0x02); // variable
    payload_abbrev.push_back(0x34); // DW_TAG_variable
    payload_abbrev.push_back(0x00); // no children
    appendULEB128(payload_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_name));
    appendULEB128(payload_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_strp));
    payload_abbrev.push_back(0x00); payload_abbrev.push_back(0x00);
    payload_abbrev.push_back(0x00);

    std::vector<uint8_t> payload_info;
    appendU32(payload_info, 0); // placeholder unit_length
    payload_info.push_back(0x04); payload_info.push_back(0x00); // version 4
    appendU32(payload_info, 0); // abbrev offset
    payload_info.push_back(0x08); // addr_size
    payload_info.push_back(0x01); // CU code
    payload_info.push_back(0x02); // variable code
    appendU32(payload_info, 0);   // name strp offset
    payload_info.push_back(0x00); // end children
    {
        uint32_t unit_length = static_cast<uint32_t>(payload_info.size() - 4);
        payload_info[0] = static_cast<uint8_t>(unit_length & 0xff);
        payload_info[1] = static_cast<uint8_t>((unit_length >> 8) & 0xff);
        payload_info[2] = static_cast<uint8_t>((unit_length >> 16) & 0xff);
        payload_info[3] = static_cast<uint8_t>((unit_length >> 24) & 0xff);
    }

    std::vector<uint8_t> dwp_str;
    for (char c : var_name) dwp_str.push_back(static_cast<uint8_t>(c));
    dwp_str.push_back(0);

    // TU index only (no CU index section).
    std::vector<uint8_t> tu_index;
    appendU32(tu_index, 6); // version
    appendU32(tu_index, 2); // section_count
    appendU32(tu_index, 1); // unit_count
    appendU32(tu_index, 1); // slot_count
    appendU32(tu_index, 1); // DW_SECT_INFO
    appendU32(tu_index, 3); // DW_SECT_ABBREV
    appendU64(tu_index, dwo_id); // signature
    appendU32(tu_index, 1); // row index
    appendU32(tu_index, 0); // info offset
    appendU32(tu_index, 0); // abbrev offset
    appendU32(tu_index, static_cast<uint32_t>(payload_info.size()));   // info size
    appendU32(tu_index, static_cast<uint32_t>(payload_abbrev.size())); // abbrev size

    std::string dir = makeTempDir("dwarf_split_tu_index_");
    std::string main_path = (std::filesystem::path(dir) / "main_tu_index.elf").string();
    std::string dwp_path = (std::filesystem::path(dir) / dwp_name).string();

    writeELFWithSections(main_path, {
        {".debug_info", main_info},
        {".debug_abbrev", main_abbrev},
        {".debug_str", main_str},
    });

    writeELFWithSections(dwp_path, {
        {".debug_info.dwo", payload_info},
        {".debug_abbrev.dwo", payload_abbrev},
        {".debug_str.dwo", dwp_str},
        {".debug_tu_index", tu_index},
    });

    DwarfParser parser(main_path);
    parser.setVerbose(true);
    assert(parser.loadDWPFile(dwp_path));
    assert(parser.load());

    auto hits = parser.findDIEsByName(var_name);
    assert(!hits.empty());
    bool found_variable = false;
    for (const auto& die : hits) {
        if (die && die->getTag() == DwarfTag::DW_TAG_variable) {
            found_variable = true;
            break;
        }
    }
    assert(found_variable);

    const auto& stats = parser.getSplitDwarfStats();
    assert(stats.dwp_hits == 1);
    assert(stats.dwo_hits == 0);
    assert(stats.dwo_fallback_hits == 0);
    assert(stats.fallback_no_index == 0);
    assert(stats.fallback_invalid_index == 0);
    assert(stats.fallback_sig_miss == 0);

    std::cout << "Split DWARF TU-index lookup tests passed!" << std::endl;
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

void testVariableLocationDiagnosticContextViaDwarfParser() {
    std::cout << "Testing parser-provided variable location diagnostic context..." << std::endl;

    // .debug_str: "bad\0"
    std::vector<uint8_t> debug_str;
    uint32_t off_bad = 0;
    for (char c : std::string("bad")) debug_str.push_back(static_cast<uint8_t>(c));
    debug_str.push_back(0);

    // Abbrev:
    // 1: CU (children)
    // 2: variable with name(strp) + location(exprloc)
    std::vector<uint8_t> debug_abbrev;
    appendULEB128(debug_abbrev, 1);
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfTag::DW_TAG_compile_unit));
    debug_abbrev.push_back(0x01); // children
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00);

    appendULEB128(debug_abbrev, 2);
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfTag::DW_TAG_variable));
    debug_abbrev.push_back(0x00); // no children
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_name));
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_strp));
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfAttribute::DW_AT_location));
    appendULEB128(debug_abbrev, static_cast<uint64_t>(DwarfForm::DW_FORM_exprloc));
    debug_abbrev.push_back(0x00); debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00); // end abbrev table

    // .debug_info with one variable that has invalid location opcode 0xff.
    std::vector<uint8_t> debug_info;
    appendU32(debug_info, 0); // unit_length placeholder
    debug_info.push_back(0x04); debug_info.push_back(0x00); // version 4
    appendU32(debug_info, 0); // abbrev offset
    debug_info.push_back(0x08); // addr size

    debug_info.push_back(0x01); // CU
    debug_info.push_back(0x02); // variable
    appendU32(debug_info, off_bad); // name
    appendULEB128(debug_info, 1);   // exprloc length
    debug_info.push_back(0xff);     // unsupported op
    debug_info.push_back(0x00);     // end children

    uint32_t unit_len = static_cast<uint32_t>(debug_info.size() - 4);
    debug_info[0] = static_cast<uint8_t>(unit_len & 0xff);
    debug_info[1] = static_cast<uint8_t>((unit_len >> 8) & 0xff);
    debug_info[2] = static_cast<uint8_t>((unit_len >> 16) & 0xff);
    debug_info[3] = static_cast<uint8_t>((unit_len >> 24) & 0xff);

    std::string dir = makeTempDir("dwarf_loc_diag_ctx_");
    std::string path = (std::filesystem::path(dir) / "loc_diag.elf").string();
    writeELFWithSections(path, {
        {".debug_info", debug_info},
        {".debug_abbrev", debug_abbrev},
        {".debug_str", debug_str},
    });

    DwarfParser parser(path);
    assert(parser.load());

    auto vars = parser.findDIEsByName("bad");
    assert(!vars.empty());
    auto loc = parser.getVariableLocation(vars[0], /*pc=*/0);
    assert(loc.type == VariableLocationType::INVALID);
    assert(loc.description.find("attr=DW_AT_location") != std::string::npos);
    assert(loc.description.find("die=0x") != std::string::npos);
    assert(loc.description.find("cu=0x") != std::string::npos);

    // Subsequent raw evaluation should not inherit previous DIE/CU diagnostics.
    auto raw = parser.evaluateLocation(std::vector<uint8_t>{0xff}, /*pc=*/0, /*is_loclist=*/false);
    assert(raw.type == VariableLocationType::INVALID);
    assert(raw.description.find("attr=DW_AT_location") == std::string::npos);
    assert(raw.description.find("die=0x") == std::string::npos);
    assert(raw.description.find("cu=0x") == std::string::npos);

    std::cout << "Parser variable location diagnostic context tests passed!" << std::endl;
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

    auto be_int_type = std::dynamic_pointer_cast<PrimitiveType>(
        type_system.createPrimitiveType(PrimitiveType::Kind::INTEGER, 4, "be_int", 1));
    assert(be_int_type);
    assert(be_int_type->getEndianity() == 1);
    assert(be_int_type->getDescription().find("[endianity=1]") != std::string::npos);

    auto addr_class_int_type = std::dynamic_pointer_cast<PrimitiveType>(
        type_system.createPrimitiveType(PrimitiveType::Kind::INTEGER, 4, "seg_int", 0, 7));
    assert(addr_class_int_type);
    assert(addr_class_int_type->getAddressClass() == 7);
    assert(addr_class_int_type->getDescription().find("[address_class=7]") != std::string::npos);
    
    // Test pointer type creation
    auto int_ptr_type = type_system.createPointerType(int_type);
    assert(int_ptr_type->getName() == "int*");
    assert(int_ptr_type->getSize() == sizeof(void*));

    auto visible_typedef = std::dynamic_pointer_cast<ModifiedType>(
        type_system.createModifiedType(ModifiedTypeKind::TYPEDEF, int_type, int_type->getSize(), "VisibleInt", 1));
    assert(visible_typedef);
    assert(visible_typedef->getVisibility() == 1);
    assert(visible_typedef->getDescription().find("[visibility=1]") != std::string::npos);

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
    assert(array_type_ptr->getByteStride() == 0);
    assert(array_type_ptr->getBitStride() == 0);

    std::vector<ArrayBound> strided_bounds = {{1, 4}};
    auto strided_array_type = type_system.createArrayType(int_type, strided_bounds, 1, 2, 16, 128);
    auto strided_array_type_ptr = std::dynamic_pointer_cast<ArrayType>(strided_array_type);
    assert(strided_array_type_ptr->getName() == "int[1..4]");
    assert(strided_array_type_ptr->getRank() == 1);
    assert(strided_array_type_ptr->getVisibility() == 2);
    assert(strided_array_type_ptr->getByteStride() == 16);
    assert(strided_array_type_ptr->getBitStride() == 128);
    assert(strided_array_type_ptr->getDescription().find("[byte_stride=16]") != std::string::npos);
    assert(strided_array_type_ptr->getDescription().find("[bit_stride=128]") != std::string::npos);

    auto bounded_string_type = std::dynamic_pointer_cast<StringType>(
        type_system.createStringType("CountedString", int_type, 16, 4, 1));
    assert(bounded_string_type->getLength() == 4);
    assert(bounded_string_type->getVisibility() == 1);
    assert(bounded_string_type->getDescription().find("[length=4]") != std::string::npos);

    std::vector<ArrayBound> file_bounds = {{1, 4}};
    auto bounded_file_type = std::dynamic_pointer_cast<FileType>(
        type_system.createFileType("", int_type, 64, file_bounds, 1, 2));
    assert(bounded_file_type->getElementCount() == 4);
    assert(bounded_file_type->getBounds().size() == 1);
    assert(bounded_file_type->getBounds()[0].lower_bound == 1);
    assert(bounded_file_type->getBounds()[0].count == 4);
    assert(bounded_file_type->getRank() == 1);
    assert(bounded_file_type->getVisibility() == 2);
    assert(bounded_file_type->getName() == "file<int>[1..4]");
    
    // Test function type creation
    std::vector<std::shared_ptr<Type>> param_types = {int_type};
    auto func_type = type_system.createFunctionType(int_type, param_types, false, false, 0, false);
    assert(func_type->getName() == "int(int)");
    // Note: These methods don't exist on the base Type class
    // We need to cast to FunctionType to access them
    auto func_type_ptr = std::dynamic_pointer_cast<FunctionType>(func_type);
    assert(func_type_ptr->getParameterTypes().size() == 1);
    assert(!func_type_ptr->isVariadic());
    assert(!func_type_ptr->isPrototyped());
    assert(func_type_ptr->getCallingConvention() == 0);
    assert(!func_type_ptr->isDeclaration());

    std::vector<FunctionParameter> named_params = {{"value", int_type, true, true}};
    auto named_func_type =
        type_system.createFunctionType(int_type, named_params, true, true, 2, true, true, true, true, true, true, true, 2);
    auto named_func_type_ptr = std::dynamic_pointer_cast<FunctionType>(named_func_type);
    assert(named_func_type_ptr->getParameters().size() == 1);
    assert(named_func_type_ptr->getParameters()[0].name == "value");
    assert(named_func_type_ptr->getParameters()[0].type == int_type);
    assert(named_func_type_ptr->getParameters()[0].is_object_pointer);
    assert(named_func_type_ptr->getParameters()[0].is_artificial);
    assert(named_func_type_ptr->isVariadic());
    assert(named_func_type_ptr->isPrototyped());
    assert(named_func_type_ptr->getCallingConvention() == 2);
    assert(named_func_type_ptr->isDeclaration());
    assert(named_func_type_ptr->isExplicit());
    assert(named_func_type_ptr->isElemental());
    assert(named_func_type_ptr->isPure());
    assert(named_func_type_ptr->isRecursive());
    assert(named_func_type_ptr->isMainSubprogram());
    assert(named_func_type_ptr->isConstExpr());
    assert(named_func_type_ptr->getVisibility() == 2);
    assert(named_func_type_ptr->getDescription().find("[prototyped]") != std::string::npos);
    assert(named_func_type_ptr->getDescription().find("[calling_convention=2]") != std::string::npos);
    assert(named_func_type_ptr->getDescription().find("[declaration]") != std::string::npos);
    assert(named_func_type_ptr->getDescription().find("[explicit]") != std::string::npos);
    assert(named_func_type_ptr->getDescription().find("[elemental]") != std::string::npos);
    assert(named_func_type_ptr->getDescription().find("[pure]") != std::string::npos);
    assert(named_func_type_ptr->getDescription().find("[recursive]") != std::string::npos);
    assert(named_func_type_ptr->getDescription().find("[main_subprogram]") != std::string::npos);
    assert(named_func_type_ptr->getDescription().find("[const_expr]") != std::string::npos);
    assert(named_func_type_ptr->getDescription().find("[visibility=2]") != std::string::npos);
    
    // Test composite type creation
    auto struct_type = std::dynamic_pointer_cast<CompositeType>(
        type_system.createCompositeType(CompositeType::Kind::STRUCT, "Point", 8, 2));
    assert(struct_type->getName() == "Point");
    assert(struct_type->getSize() == 8);
    assert(struct_type->getVisibility() == 2);
    assert(struct_type->getDescription().find("[visibility=2]") != std::string::npos);
    
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
    assert(!enum_type->isScoped());
    
    enum_type->addEnumerator("RED", 0);
    enum_type->addEnumerator("GREEN", 1);
    enum_type->addEnumerator("BLUE", 2);
    enum_type->addEnumerator("NEGATIVE", -1);
    assert(enum_type->getEnumerators().size() == 4);
    assert(enum_type->getEnumeratorName(0) == "RED");
    assert(enum_type->getEnumeratorName(1) == "GREEN");
    assert(enum_type->getEnumeratorName(2) == "BLUE");
    assert(enum_type->getEnumeratorName(-1) == "NEGATIVE");

    auto scoped_enum_type = std::dynamic_pointer_cast<EnumType>(
        type_system.createEnumType("ScopedColor", int_type, true, 1));
    assert(scoped_enum_type->isScoped());
    assert(scoped_enum_type->getVisibility() == 1);
    assert(scoped_enum_type->getDescription().find("enum class ScopedColor") == 0);
    assert(scoped_enum_type->getDescription().find("[visibility=1]") != std::string::npos);

    // Test DIE-driven type resolution preserves wrappers and richer metadata.
    {
        std::map<uint64_t, std::shared_ptr<DIE>> dies;
        auto add_die = [&](DwarfTag tag, uint64_t offset) {
            auto die = std::make_shared<DIE>(tag, offset, 0);
            dies[offset] = die;
            return die;
        };
        auto lookup = [&](uint64_t offset) -> std::shared_ptr<DIE> {
            auto it = dies.find(offset);
            return (it != dies.end()) ? it->second : nullptr;
        };

        TypeSystem resolving_system(8, lookup);

        auto int_die = add_die(DwarfTag::DW_TAG_base_type, 0x10);
        int_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("int"));
        int_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(4));
        int_die->addAttribute(DwarfAttribute::DW_AT_encoding, std::make_shared<UnsignedAttributeValue>(4));

        auto be_int_die = add_die(DwarfTag::DW_TAG_base_type, 0x11);
        be_int_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("be_int"));
        be_int_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(4));
        be_int_die->addAttribute(DwarfAttribute::DW_AT_encoding, std::make_shared<UnsignedAttributeValue>(4));
        be_int_die->addAttribute(DwarfAttribute::DW_AT_endianity, std::make_shared<UnsignedAttributeValue>(1));

        auto seg_int_die = add_die(DwarfTag::DW_TAG_base_type, 0x12);
        seg_int_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("seg_int"));
        seg_int_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(4));
        seg_int_die->addAttribute(DwarfAttribute::DW_AT_encoding, std::make_shared<UnsignedAttributeValue>(4));
        seg_int_die->addAttribute(DwarfAttribute::DW_AT_address_class, std::make_shared<UnsignedAttributeValue>(7));

        auto unspecified_die = add_die(DwarfTag::DW_TAG_unspecified_type, 0x15);
        unspecified_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("decltype(auto)"));

        auto string_die = add_die(DwarfTag::DW_TAG_string_type, 0x18);
        string_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("utf8_string"));
        string_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x10));
        string_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(16));
        string_die->addAttribute(DwarfAttribute::DW_AT_string_length, std::make_shared<UnsignedAttributeValue>(4));
        string_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(1));

        auto expr_string_die = add_die(DwarfTag::DW_TAG_string_type, 0x18a);
        expr_string_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("expr_string"));
        expr_string_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x10));
        expr_string_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(16));
        expr_string_die->addAttribute(
            DwarfAttribute::DW_AT_string_length,
            std::make_shared<LocationAttributeValue>(
                LocationAttributeValue::LocationType::EXPRESSION,
                std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_plus_uconst), 0x06}));

        auto set_die = add_die(DwarfTag::DW_TAG_set_type, 0x19);
        set_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("IntSet"));
        set_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x10));
        set_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(32));
        set_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(2));

        auto file_die = add_die(DwarfTag::DW_TAG_file_type, 0x1a);
        file_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("IntFile"));
        file_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x10));
        file_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(64));
        file_die->addAttribute(DwarfAttribute::DW_AT_rank, std::make_shared<UnsignedAttributeValue>(1));
        file_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(2));
        auto file_count = add_die(DwarfTag::DW_TAG_subrange_type, 0x1b);
        file_count->addAttribute(DwarfAttribute::DW_AT_count, std::make_shared<UnsignedAttributeValue>(4));
        file_die->addChild(file_count);

        auto anonymous_file_die = add_die(DwarfTag::DW_TAG_file_type, 0x1c);
        anonymous_file_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x10));
        anonymous_file_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(64));
        anonymous_file_die->addAttribute(DwarfAttribute::DW_AT_rank, std::make_shared<UnsignedAttributeValue>(1));
        anonymous_file_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(2));
        auto anonymous_file_count = add_die(DwarfTag::DW_TAG_subrange_type, 0x1d);
        anonymous_file_count->addAttribute(DwarfAttribute::DW_AT_lower_bound, std::make_shared<SignedAttributeValue>(1));
        anonymous_file_count->addAttribute(DwarfAttribute::DW_AT_upper_bound, std::make_shared<UnsignedAttributeValue>(4));
        anonymous_file_die->addChild(anonymous_file_count);

        auto const_die = add_die(DwarfTag::DW_TAG_const_type, 0x20);
        const_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x10));

        auto typedef_die = add_die(DwarfTag::DW_TAG_typedef, 0x30);
        typedef_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("MyInt"));
        typedef_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x20));
        typedef_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(1));

        auto ref_die = add_die(DwarfTag::DW_TAG_reference_type, 0x40);
        ref_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x30));

        auto rref_die = add_die(DwarfTag::DW_TAG_rvalue_reference_type, 0x45);
        rref_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x30));

        auto atomic_die = add_die(DwarfTag::DW_TAG_atomic_type, 0x46);
        atomic_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x30));

        auto member_ptr_die = add_die(DwarfTag::DW_TAG_ptr_to_member_type, 0x47);
        member_ptr_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x30));
        member_ptr_die->addAttribute(DwarfAttribute::DW_AT_containing_type, std::make_shared<TypeAttributeValue>(0x60));

        auto enum_die = add_die(DwarfTag::DW_TAG_enumeration_type, 0x48);
        enum_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("SignedEnum"));
        enum_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x10));
        enum_die->addAttribute(DwarfAttribute::DW_AT_enum_class, std::make_shared<FlagAttributeValue>(true));
        enum_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(1));
        auto negative_enum_die = add_die(DwarfTag::DW_TAG_enumerator, 0x49);
        negative_enum_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("NEGATIVE"));
        negative_enum_die->addAttribute(DwarfAttribute::DW_AT_const_value, std::make_shared<SignedAttributeValue>(-7));
        enum_die->addChild(negative_enum_die);
        auto expr_enum_die = add_die(DwarfTag::DW_TAG_enumerator, 0x4a);
        expr_enum_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("POSITIVE"));
        expr_enum_die->addAttribute(
            DwarfAttribute::DW_AT_const_value,
            std::make_shared<LocationAttributeValue>(
                LocationAttributeValue::LocationType::EXPRESSION,
                std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_plus_uconst), 0x05}));
        enum_die->addChild(expr_enum_die);

        auto elem_die = add_die(DwarfTag::DW_TAG_array_type, 0x50);
        elem_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x10));
        elem_die->addAttribute(DwarfAttribute::DW_AT_byte_stride, std::make_shared<UnsignedAttributeValue>(16));
        elem_die->addAttribute(DwarfAttribute::DW_AT_bit_stride, std::make_shared<UnsignedAttributeValue>(128));
        elem_die->addAttribute(DwarfAttribute::DW_AT_rank, std::make_shared<UnsignedAttributeValue>(1));
        elem_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(2));
        auto subrange = add_die(DwarfTag::DW_TAG_subrange_type, 0x51);
        subrange->addAttribute(DwarfAttribute::DW_AT_lower_bound, std::make_shared<SignedAttributeValue>(-2));
        subrange->addAttribute(DwarfAttribute::DW_AT_upper_bound, std::make_shared<SignedAttributeValue>(2));
        elem_die->addChild(subrange);

        auto expr_stride_array_die = add_die(DwarfTag::DW_TAG_array_type, 0x52);
        expr_stride_array_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x10));
        expr_stride_array_die->addAttribute(
            DwarfAttribute::DW_AT_byte_stride,
            std::make_shared<LocationAttributeValue>(
                LocationAttributeValue::LocationType::EXPRESSION,
                std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_plus_uconst), 0x18}));
        expr_stride_array_die->addAttribute(
            DwarfAttribute::DW_AT_bit_stride,
            std::make_shared<LocationAttributeValue>(
                LocationAttributeValue::LocationType::EXPRESSION,
                std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_constu), 0x40}));
        auto expr_stride_subrange = add_die(DwarfTag::DW_TAG_subrange_type, 0x53);
        expr_stride_subrange->addAttribute(DwarfAttribute::DW_AT_count, std::make_shared<UnsignedAttributeValue>(3));
        expr_stride_array_die->addChild(expr_stride_subrange);

        auto expr_bound_array_die = add_die(DwarfTag::DW_TAG_array_type, 0x54);
        expr_bound_array_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x10));
        auto expr_bound_subrange = add_die(DwarfTag::DW_TAG_subrange_type, 0x55);
        expr_bound_subrange->addAttribute(
            DwarfAttribute::DW_AT_lower_bound,
            std::make_shared<LocationAttributeValue>(
                LocationAttributeValue::LocationType::EXPRESSION,
                std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_consts), 0x7f}));
        expr_bound_subrange->addAttribute(
            DwarfAttribute::DW_AT_upper_bound,
            std::make_shared<LocationAttributeValue>(
                LocationAttributeValue::LocationType::EXPRESSION,
                std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_constu), 0x03}));
        expr_bound_array_die->addChild(expr_bound_subrange);

        auto base_struct_die = add_die(DwarfTag::DW_TAG_structure_type, 0x60);
        base_struct_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("Base"));
        base_struct_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(4));

        auto interface_die = add_die(DwarfTag::DW_TAG_interface_type, 0x68);
        interface_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("Runnable"));
        interface_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(8));
        interface_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(1));

        auto struct_die = add_die(DwarfTag::DW_TAG_structure_type, 0x70);
        struct_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("Widget"));
        struct_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(16));
        struct_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(2));

        auto member_die = add_die(DwarfTag::DW_TAG_member, 0x71);
        member_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("flags"));
        member_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x10));
        member_die->addAttribute(DwarfAttribute::DW_AT_data_member_location, std::make_shared<UnsignedAttributeValue>(8));
        member_die->addAttribute(DwarfAttribute::DW_AT_bit_size, std::make_shared<UnsignedAttributeValue>(3));
        member_die->addAttribute(DwarfAttribute::DW_AT_data_bit_offset, std::make_shared<UnsignedAttributeValue>(1));
        member_die->addAttribute(DwarfAttribute::DW_AT_accessibility, std::make_shared<UnsignedAttributeValue>(1));
        struct_die->addChild(member_die);

        auto signed_member_die = add_die(DwarfTag::DW_TAG_member, 0x73);
        signed_member_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("tail"));
        signed_member_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x10));
        signed_member_die->addAttribute(DwarfAttribute::DW_AT_data_member_location, std::make_shared<SignedAttributeValue>(-4));
        struct_die->addChild(signed_member_die);

        auto expr_member_die = add_die(DwarfTag::DW_TAG_member, 0x74);
        expr_member_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("payload"));
        expr_member_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x10));
        expr_member_die->addAttribute(
            DwarfAttribute::DW_AT_data_member_location,
            std::make_shared<LocationAttributeValue>(
                LocationAttributeValue::LocationType::EXPRESSION,
                std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_plus_uconst), 0x0c}));
        expr_member_die->addAttribute(DwarfAttribute::DW_AT_mutable, std::make_shared<FlagAttributeValue>(true));
        struct_die->addChild(expr_member_die);

        auto legacy_bitfield_die = add_die(DwarfTag::DW_TAG_member, 0x76);
        legacy_bitfield_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("legacy_bits"));
        legacy_bitfield_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x10));
        legacy_bitfield_die->addAttribute(DwarfAttribute::DW_AT_data_member_location, std::make_shared<UnsignedAttributeValue>(4));
        legacy_bitfield_die->addAttribute(DwarfAttribute::DW_AT_bit_size, std::make_shared<UnsignedAttributeValue>(5));
        legacy_bitfield_die->addAttribute(DwarfAttribute::DW_AT_bit_offset, std::make_shared<UnsignedAttributeValue>(9));
        struct_die->addChild(legacy_bitfield_die);

        auto expr_inherit_die = add_die(DwarfTag::DW_TAG_inheritance, 0x75);
        expr_inherit_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x60));
        expr_inherit_die->addAttribute(
            DwarfAttribute::DW_AT_data_member_location,
            std::make_shared<LocationAttributeValue>(
                LocationAttributeValue::LocationType::EXPRESSION,
                std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_consts), 0x78}));
        expr_inherit_die->addAttribute(DwarfAttribute::DW_AT_accessibility, std::make_shared<UnsignedAttributeValue>(1));
        struct_die->addChild(expr_inherit_die);

        auto inherit_die = add_die(DwarfTag::DW_TAG_inheritance, 0x72);
        inherit_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x60));
        inherit_die->addAttribute(DwarfAttribute::DW_AT_data_member_location, std::make_shared<SignedAttributeValue>(-16));
        inherit_die->addAttribute(DwarfAttribute::DW_AT_virtuality, std::make_shared<UnsignedAttributeValue>(1));
        inherit_die->addAttribute(DwarfAttribute::DW_AT_accessibility, std::make_shared<UnsignedAttributeValue>(2));
        struct_die->addChild(inherit_die);

        auto func_die = add_die(DwarfTag::DW_TAG_subroutine_type, 0x80);
        func_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x10));
        func_die->addAttribute(DwarfAttribute::DW_AT_prototyped, std::make_shared<FlagAttributeValue>(true));
        func_die->addAttribute(DwarfAttribute::DW_AT_calling_convention, std::make_shared<UnsignedAttributeValue>(5));
        func_die->addAttribute(DwarfAttribute::DW_AT_declaration, std::make_shared<FlagAttributeValue>(true));
        func_die->addAttribute(DwarfAttribute::DW_AT_explicit, std::make_shared<FlagAttributeValue>(true));
        func_die->addAttribute(DwarfAttribute::DW_AT_elemental, std::make_shared<FlagAttributeValue>(true));
        func_die->addAttribute(DwarfAttribute::DW_AT_pure, std::make_shared<FlagAttributeValue>(true));
        func_die->addAttribute(DwarfAttribute::DW_AT_recursive, std::make_shared<FlagAttributeValue>(true));
        func_die->addAttribute(DwarfAttribute::DW_AT_main_subprogram, std::make_shared<FlagAttributeValue>(true));
        func_die->addAttribute(DwarfAttribute::DW_AT_const_expr, std::make_shared<FlagAttributeValue>(true));
        func_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(2));
        auto param_die = add_die(DwarfTag::DW_TAG_formal_parameter, 0x81);
        param_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("value"));
        param_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x30));
        param_die->addAttribute(DwarfAttribute::DW_AT_object_pointer, std::make_shared<FlagAttributeValue>(true));
        param_die->addAttribute(DwarfAttribute::DW_AT_artificial, std::make_shared<FlagAttributeValue>(true));
        func_die->addChild(param_die);
        auto variadic_die = add_die(DwarfTag::DW_TAG_unspecified_parameters, 0x82);
        func_die->addChild(variadic_die);

        auto flag_variadic_func_die = add_die(DwarfTag::DW_TAG_subroutine_type, 0x83);
        flag_variadic_func_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x10));
        auto fixed_param_die = add_die(DwarfTag::DW_TAG_formal_parameter, 0x84);
        fixed_param_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("prefix"));
        fixed_param_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x30));
        flag_variadic_func_die->addChild(fixed_param_die);
        auto variable_param_die = add_die(DwarfTag::DW_TAG_formal_parameter, 0x85);
        variable_param_die->addAttribute(DwarfAttribute::DW_AT_variable_parameter, std::make_shared<FlagAttributeValue>(true));
        flag_variadic_func_die->addChild(variable_param_die);

        auto resolved_typedef = std::dynamic_pointer_cast<ModifiedType>(resolving_system.resolveType(typedef_die));
        assert(resolved_typedef);
        assert(resolved_typedef->getKind() == ModifiedTypeKind::TYPEDEF);
        assert(resolved_typedef->getName() == "MyInt");
        assert(resolved_typedef->getVisibility() == 1);
        assert(resolved_typedef->getUnderlyingType());
        assert(resolved_typedef->getUnderlyingType()->getName() == "const int");

        auto resolved_unspecified = std::dynamic_pointer_cast<PrimitiveType>(resolving_system.resolveType(unspecified_die));
        assert(resolved_unspecified);
        assert(resolved_unspecified->getKind() == PrimitiveType::Kind::VOID);
        assert(resolved_unspecified->getName() == "decltype(auto)");
        assert(resolved_unspecified->getSize() == 0);

        auto resolved_be_int = std::dynamic_pointer_cast<PrimitiveType>(resolving_system.resolveType(be_int_die));
        assert(resolved_be_int);
        assert(resolved_be_int->getName() == "be_int");
        assert(resolved_be_int->getEndianity() == 1);
        assert(resolved_be_int->getDescription().find("[endianity=1]") != std::string::npos);

        auto resolved_seg_int = std::dynamic_pointer_cast<PrimitiveType>(resolving_system.resolveType(seg_int_die));
        assert(resolved_seg_int);
        assert(resolved_seg_int->getName() == "seg_int");
        assert(resolved_seg_int->getAddressClass() == 7);
        assert(resolved_seg_int->getDescription().find("[address_class=7]") != std::string::npos);

        auto resolved_string = std::dynamic_pointer_cast<StringType>(resolving_system.resolveType(string_die));
        assert(resolved_string);
        assert(resolved_string->getName() == "utf8_string");
        assert(resolved_string->getSize() == 16);
        assert(resolved_string->getLength() == 4);
        assert(resolved_string->getVisibility() == 1);
        assert(resolved_string->getCharacterType());
        assert(resolved_string->getCharacterType()->getName() == "int");

        auto resolved_expr_string = std::dynamic_pointer_cast<StringType>(resolving_system.resolveType(expr_string_die));
        assert(resolved_expr_string);
        assert(resolved_expr_string->getName() == "expr_string");
        assert(resolved_expr_string->getLength() == 6);

        auto resolved_set = std::dynamic_pointer_cast<SetType>(resolving_system.resolveType(set_die));
        assert(resolved_set);
        assert(resolved_set->getName() == "IntSet");
        assert(resolved_set->getSize() == 32);
        assert(resolved_set->getVisibility() == 2);
        assert(resolved_set->getElementType());
        assert(resolved_set->getElementType()->getName() == "int");

        auto resolved_file = std::dynamic_pointer_cast<FileType>(resolving_system.resolveType(file_die));
        assert(resolved_file);
        assert(resolved_file->getName() == "IntFile");
        assert(resolved_file->getSize() == 64);
        assert(resolved_file->getElementCount() == 4);
        assert(resolved_file->getBounds().size() == 1);
        assert(resolved_file->getBounds()[0].lower_bound == 0);
        assert(resolved_file->getBounds()[0].count == 4);
        assert(resolved_file->getRank() == 1);
        assert(resolved_file->getVisibility() == 2);
        assert(resolved_file->getElementType());
        assert(resolved_file->getElementType()->getName() == "int");

        auto resolved_anonymous_file = std::dynamic_pointer_cast<FileType>(resolving_system.resolveType(anonymous_file_die));
        assert(resolved_anonymous_file);
        assert(resolved_anonymous_file->getName() == "file<int>[1..4]");
        assert(resolved_anonymous_file->getElementCount() == 4);
        assert(resolved_anonymous_file->getBounds().size() == 1);
        assert(resolved_anonymous_file->getBounds()[0].lower_bound == 1);
        assert(resolved_anonymous_file->getBounds()[0].count == 4);
        assert(resolved_anonymous_file->getRank() == 1);
        assert(resolved_anonymous_file->getVisibility() == 2);

        auto resolved_ref = std::dynamic_pointer_cast<ModifiedType>(resolving_system.resolveType(ref_die));
        assert(resolved_ref);
        assert(resolved_ref->getKind() == ModifiedTypeKind::REFERENCE);
        assert(resolved_ref->getSize() == 8);
        assert(resolved_ref->getName() == "MyInt&");

        auto resolved_rref = std::dynamic_pointer_cast<ModifiedType>(resolving_system.resolveType(rref_die));
        assert(resolved_rref);
        assert(resolved_rref->getKind() == ModifiedTypeKind::RVALUE_REFERENCE);
        assert(resolved_rref->getSize() == 8);
        assert(resolved_rref->getName() == "MyInt&&");

        auto resolved_atomic = std::dynamic_pointer_cast<ModifiedType>(resolving_system.resolveType(atomic_die));
        assert(resolved_atomic);
        assert(resolved_atomic->getKind() == ModifiedTypeKind::ATOMIC);
        assert(resolved_atomic->getSize() == 4);
        assert(resolved_atomic->getName() == "_Atomic(MyInt)");

        auto resolved_member_ptr = std::dynamic_pointer_cast<MemberPointerType>(resolving_system.resolveType(member_ptr_die));
        assert(resolved_member_ptr);
        assert(resolved_member_ptr->getSize() == 8);
        assert(resolved_member_ptr->getMemberType()->getName() == "MyInt");
        assert(resolved_member_ptr->getContainingType()->getName() == "Base");
        assert(resolved_member_ptr->getName() == "MyInt Base::*");

        auto resolved_enum = std::dynamic_pointer_cast<EnumType>(resolving_system.resolveType(enum_die));
        assert(resolved_enum);
        assert(resolved_enum->getName() == "SignedEnum");
        assert(resolved_enum->isScoped());
        assert(resolved_enum->getVisibility() == 1);
        assert(resolved_enum->getEnumerators().size() == 2);
        assert(resolved_enum->getEnumerators()[0].value == -7);
        assert(resolved_enum->getEnumeratorName(-7) == "NEGATIVE");
        assert(resolved_enum->getEnumerators()[1].value == 5);
        assert(resolved_enum->getEnumeratorName(5) == "POSITIVE");

        auto resolved_array = std::dynamic_pointer_cast<ArrayType>(resolving_system.resolveType(elem_die));
        assert(resolved_array);
        assert(resolved_array->getName() == "int[-2..2]");
        assert(resolved_array->getDimensions().size() == 1);
        assert(resolved_array->getDimensions()[0] == 5);
        assert(resolved_array->getBounds().size() == 1);
        assert(resolved_array->getBounds()[0].lower_bound == -2);
        assert(resolved_array->getBounds()[0].count == 5);
        assert(resolved_array->getRank() == 1);
        assert(resolved_array->getVisibility() == 2);
        assert(resolved_array->getByteStride() == 16);
        assert(resolved_array->getBitStride() == 128);

        auto resolved_expr_stride_array = std::dynamic_pointer_cast<ArrayType>(resolving_system.resolveType(expr_stride_array_die));
        assert(resolved_expr_stride_array);
        assert(resolved_expr_stride_array->getDimensions().size() == 1);
        assert(resolved_expr_stride_array->getDimensions()[0] == 3);
        assert(resolved_expr_stride_array->getByteStride() == 24);
        assert(resolved_expr_stride_array->getBitStride() == 64);

        auto resolved_expr_bound_array = std::dynamic_pointer_cast<ArrayType>(resolving_system.resolveType(expr_bound_array_die));
        assert(resolved_expr_bound_array);
        assert(resolved_expr_bound_array->getDimensions().size() == 1);
        assert(resolved_expr_bound_array->getDimensions()[0] == 5);
        assert(resolved_expr_bound_array->getBounds().size() == 1);
        assert(resolved_expr_bound_array->getBounds()[0].lower_bound == -1);
        assert(resolved_expr_bound_array->getBounds()[0].count == 5);

        auto resolved_interface = std::dynamic_pointer_cast<CompositeType>(resolving_system.resolveType(interface_die));
        assert(resolved_interface);
        assert(resolved_interface->getKind() == CompositeType::Kind::INTERFACE);
        assert(resolved_interface->getName() == "Runnable");
        assert(resolved_interface->getVisibility() == 1);

        auto resolved_struct = std::dynamic_pointer_cast<CompositeType>(resolving_system.resolveType(struct_die));
        assert(resolved_struct);
        assert(resolved_struct->getVisibility() == 2);
        assert(resolved_struct->getMembers().size() == 4);
        assert(resolved_struct->getMembers()[0].bit_size == 3);
        assert(resolved_struct->getMembers()[0].bit_offset == 1);
        assert(resolved_struct->getMembers()[0].is_public);
        assert(resolved_struct->getMembers()[1].name == "tail");
        assert(static_cast<int64_t>(resolved_struct->getMembers()[1].offset) == -4);
        assert(resolved_struct->getMembers()[2].name == "payload");
        assert(resolved_struct->getMembers()[2].offset == 12);
        assert(resolved_struct->getMembers()[2].is_mutable);
        assert(resolved_struct->getMembers()[3].name == "legacy_bits");
        assert(resolved_struct->getMembers()[3].bit_size == 5);
        assert(resolved_struct->getMembers()[3].bit_offset == 9);
        assert(resolved_struct->getBaseClasses().size() == 2);
        assert(resolved_struct->getBaseClasses()[0].is_public);
        assert(!resolved_struct->getBaseClasses()[0].is_virtual);
        assert(static_cast<int64_t>(resolved_struct->getBaseClasses()[0].offset) == -8);
        assert(resolved_struct->getBaseClasses()[1].is_virtual);
        assert(resolved_struct->getBaseClasses()[1].is_protected);
        assert(static_cast<int64_t>(resolved_struct->getBaseClasses()[1].offset) == -16);

        auto resolved_func = std::dynamic_pointer_cast<FunctionType>(resolving_system.resolveType(func_die));
        assert(resolved_func);
        assert(resolved_func->isVariadic());
        assert(resolved_func->isPrototyped());
        assert(resolved_func->getCallingConvention() == 5);
        assert(resolved_func->isDeclaration());
        assert(resolved_func->isExplicit());
        assert(resolved_func->isElemental());
        assert(resolved_func->isPure());
        assert(resolved_func->isRecursive());
        assert(resolved_func->isMainSubprogram());
        assert(resolved_func->isConstExpr());
        assert(resolved_func->getVisibility() == 2);
        assert(resolved_func->getParameterTypes().size() == 1);
        assert(resolved_func->getParameterTypes()[0]->getName() == "MyInt");
        assert(resolved_func->getParameters().size() == 1);
        assert(resolved_func->getParameters()[0].name == "value");
        assert(resolved_func->getParameters()[0].type->getName() == "MyInt");
        assert(resolved_func->getParameters()[0].is_object_pointer);
        assert(resolved_func->getParameters()[0].is_artificial);

        auto resolved_flag_variadic_func = std::dynamic_pointer_cast<FunctionType>(
            resolving_system.resolveType(flag_variadic_func_die));
        assert(resolved_flag_variadic_func);
        assert(resolved_flag_variadic_func->isVariadic());
        assert(!resolved_flag_variadic_func->isPrototyped());
        assert(resolved_flag_variadic_func->getCallingConvention() == 0);
        assert(!resolved_flag_variadic_func->isDeclaration());
        assert(resolved_flag_variadic_func->getParameters().size() == 1);
        assert(resolved_flag_variadic_func->getParameters()[0].name == "prefix");
        assert(!resolved_flag_variadic_func->getParameters()[0].is_object_pointer);
        assert(!resolved_flag_variadic_func->getParameters()[0].is_artificial);
    }
    
    std::cout << "TypeSystem tests passed!" << std::endl;
}

void testTypePrinter() {
    std::cout << "Testing TypePrinter..." << std::endl;

    std::map<uint64_t, std::shared_ptr<DIE>> dies;
    auto add_die = [&](DwarfTag tag, uint64_t offset) {
        auto die = std::make_shared<DIE>(tag, offset, 0);
        dies[offset] = die;
        return die;
    };
    auto lookup = [&](uint64_t offset) -> std::shared_ptr<DIE> {
        auto it = dies.find(offset);
        return (it != dies.end()) ? it->second : nullptr;
    };

    auto int_die = add_die(DwarfTag::DW_TAG_base_type, 0x100);
    int_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("int"));
    int_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(4));
    int_die->addAttribute(DwarfAttribute::DW_AT_encoding, std::make_shared<UnsignedAttributeValue>(4));

    auto be_int_die = add_die(DwarfTag::DW_TAG_base_type, 0x101);
    be_int_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("be_int"));
    be_int_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(4));
    be_int_die->addAttribute(DwarfAttribute::DW_AT_encoding, std::make_shared<UnsignedAttributeValue>(4));
    be_int_die->addAttribute(DwarfAttribute::DW_AT_endianity, std::make_shared<UnsignedAttributeValue>(1));

    auto seg_int_die = add_die(DwarfTag::DW_TAG_base_type, 0x102);
    seg_int_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("seg_int"));
    seg_int_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(4));
    seg_int_die->addAttribute(DwarfAttribute::DW_AT_encoding, std::make_shared<UnsignedAttributeValue>(4));
    seg_int_die->addAttribute(DwarfAttribute::DW_AT_address_class, std::make_shared<UnsignedAttributeValue>(7));

    auto unspecified_die = add_die(DwarfTag::DW_TAG_unspecified_type, 0x105);
    unspecified_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("decltype(auto)"));

    auto string_die = add_die(DwarfTag::DW_TAG_string_type, 0x108);
    string_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("utf8_string"));
    string_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<TypeAttributeValue>(0x100));
    string_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(16));
    string_die->addAttribute(DwarfAttribute::DW_AT_string_length, std::make_shared<UnsignedAttributeValue>(4));
    string_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(1));

    auto expr_string_die = add_die(DwarfTag::DW_TAG_string_type, 0x1085);
    expr_string_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("CountedExprString"));
    expr_string_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x100));
    expr_string_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(16));
    expr_string_die->addAttribute(
        DwarfAttribute::DW_AT_string_length,
        std::make_shared<LocationAttributeValue>(
            LocationAttributeValue::LocationType::EXPRESSION,
            std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_plus_uconst), 0x06}));

    auto set_die = add_die(DwarfTag::DW_TAG_set_type, 0x109);
    set_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("IntSet"));
    set_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<TypeAttributeValue>(0x100));
    set_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(32));
    set_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(2));

    auto file_die = add_die(DwarfTag::DW_TAG_file_type, 0x10a);
    file_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("IntFile"));
    file_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x100));
    file_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(64));
    file_die->addAttribute(DwarfAttribute::DW_AT_rank, std::make_shared<UnsignedAttributeValue>(1));
    file_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(2));
    auto anonymous_file_die = add_die(DwarfTag::DW_TAG_file_type, 0x10a5);
    anonymous_file_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x100));
    anonymous_file_die->addAttribute(DwarfAttribute::DW_AT_rank, std::make_shared<UnsignedAttributeValue>(1));
    anonymous_file_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(2));
    auto anonymous_file_subrange_die = add_die(DwarfTag::DW_TAG_subrange_type, 0x10a6);
    anonymous_file_subrange_die->addAttribute(DwarfAttribute::DW_AT_lower_bound, std::make_shared<SignedAttributeValue>(1));
    anonymous_file_subrange_die->addAttribute(DwarfAttribute::DW_AT_upper_bound, std::make_shared<SignedAttributeValue>(4));
    anonymous_file_die->addChild(anonymous_file_subrange_die);

    auto const_die = add_die(DwarfTag::DW_TAG_const_type, 0x110);
    const_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x100));

    auto ptr_die = add_die(DwarfTag::DW_TAG_pointer_type, 0x120);
    ptr_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x110));

    auto typedef_die = add_die(DwarfTag::DW_TAG_typedef, 0x130);
    typedef_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("Alias"));
    typedef_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x120));
    typedef_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(1));

    auto rref_die = add_die(DwarfTag::DW_TAG_rvalue_reference_type, 0x140);
    rref_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x130));

    auto atomic_die = add_die(DwarfTag::DW_TAG_atomic_type, 0x145);
    atomic_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x130));

    auto class_die = add_die(DwarfTag::DW_TAG_class_type, 0x146);
    class_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("Widget"));
    class_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(2));

    auto interface_die = add_die(DwarfTag::DW_TAG_interface_type, 0x1465);
    interface_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("Runnable"));
    interface_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(1));

    auto member_ptr_die = add_die(DwarfTag::DW_TAG_ptr_to_member_type, 0x147);
    member_ptr_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<TypeAttributeValue>(0x130));
    member_ptr_die->addAttribute(DwarfAttribute::DW_AT_containing_type, std::make_shared<TypeAttributeValue>(0x146));

    auto enum_die = add_die(DwarfTag::DW_TAG_enumeration_type, 0x1475);
    enum_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("ScopedColor"));
    enum_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<TypeAttributeValue>(0x100));
    enum_die->addAttribute(DwarfAttribute::DW_AT_enum_class, std::make_shared<FlagAttributeValue>(true));
    enum_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(1));
    auto negative_enum_value_die = add_die(DwarfTag::DW_TAG_enumerator, 0x1476);
    negative_enum_value_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("NEGATIVE"));
    negative_enum_value_die->addAttribute(DwarfAttribute::DW_AT_const_value, std::make_shared<SignedAttributeValue>(-7));
    enum_die->addChild(negative_enum_value_die);
    auto expr_enum_value_die = add_die(DwarfTag::DW_TAG_enumerator, 0x1477);
    expr_enum_value_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("POSITIVE"));
    expr_enum_value_die->addAttribute(
        DwarfAttribute::DW_AT_const_value,
        std::make_shared<LocationAttributeValue>(
            LocationAttributeValue::LocationType::EXPRESSION,
            std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_plus_uconst), 0x05}));
    enum_die->addChild(expr_enum_value_die);

    auto func_die = add_die(DwarfTag::DW_TAG_subroutine_type, 0x148);
    func_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<TypeAttributeValue>(0x100));
    func_die->addAttribute(DwarfAttribute::DW_AT_prototyped, std::make_shared<FlagAttributeValue>(true));
    func_die->addAttribute(DwarfAttribute::DW_AT_calling_convention, std::make_shared<UnsignedAttributeValue>(5));
    func_die->addAttribute(DwarfAttribute::DW_AT_declaration, std::make_shared<FlagAttributeValue>(true));
    func_die->addAttribute(DwarfAttribute::DW_AT_explicit, std::make_shared<FlagAttributeValue>(true));
    func_die->addAttribute(DwarfAttribute::DW_AT_elemental, std::make_shared<FlagAttributeValue>(true));
    func_die->addAttribute(DwarfAttribute::DW_AT_pure, std::make_shared<FlagAttributeValue>(true));
    func_die->addAttribute(DwarfAttribute::DW_AT_recursive, std::make_shared<FlagAttributeValue>(true));
    func_die->addAttribute(DwarfAttribute::DW_AT_main_subprogram, std::make_shared<FlagAttributeValue>(true));
    func_die->addAttribute(DwarfAttribute::DW_AT_const_expr, std::make_shared<FlagAttributeValue>(true));
    func_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(2));
    auto param_die = add_die(DwarfTag::DW_TAG_formal_parameter, 0x149);
    param_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("self"));
    param_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<TypeAttributeValue>(0x130));
    param_die->addAttribute(DwarfAttribute::DW_AT_object_pointer, std::make_shared<FlagAttributeValue>(true));
    param_die->addAttribute(DwarfAttribute::DW_AT_artificial, std::make_shared<FlagAttributeValue>(true));
    func_die->addChild(param_die);
    func_die->addChild(add_die(DwarfTag::DW_TAG_unspecified_parameters, 0x14a));

    auto flag_variadic_func_die = add_die(DwarfTag::DW_TAG_subroutine_type, 0x14b);
    flag_variadic_func_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<TypeAttributeValue>(0x100));
    auto fixed_param_die = add_die(DwarfTag::DW_TAG_formal_parameter, 0x14c);
    fixed_param_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("prefix"));
    fixed_param_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<TypeAttributeValue>(0x130));
    flag_variadic_func_die->addChild(fixed_param_die);
    auto variable_param_die = add_die(DwarfTag::DW_TAG_formal_parameter, 0x14d);
    variable_param_die->addAttribute(DwarfAttribute::DW_AT_variable_parameter, std::make_shared<FlagAttributeValue>(true));
    flag_variadic_func_die->addChild(variable_param_die);

    auto struct_die = add_die(DwarfTag::DW_TAG_structure_type, 0x150);
    struct_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("Widget"));
    struct_die->addAttribute(DwarfAttribute::DW_AT_byte_size, std::make_shared<UnsignedAttributeValue>(16));
    struct_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(2));
    auto member_die = add_die(DwarfTag::DW_TAG_member, 0x151);
    member_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("value"));
    member_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<TypeAttributeValue>(0x130));
    member_die->addAttribute(DwarfAttribute::DW_AT_data_member_location, std::make_shared<UnsignedAttributeValue>(8));
    member_die->addAttribute(DwarfAttribute::DW_AT_bit_size, std::make_shared<UnsignedAttributeValue>(3));
    member_die->addAttribute(DwarfAttribute::DW_AT_data_bit_offset, std::make_shared<UnsignedAttributeValue>(1));
    member_die->addAttribute(DwarfAttribute::DW_AT_accessibility, std::make_shared<UnsignedAttributeValue>(1));
    struct_die->addChild(member_die);
    auto signed_member_die = add_die(DwarfTag::DW_TAG_member, 0x1515);
    signed_member_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("tail"));
    signed_member_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<TypeAttributeValue>(0x130));
    signed_member_die->addAttribute(DwarfAttribute::DW_AT_data_member_location, std::make_shared<SignedAttributeValue>(-4));
    signed_member_die->addAttribute(DwarfAttribute::DW_AT_accessibility, std::make_shared<UnsignedAttributeValue>(2));
    struct_die->addChild(signed_member_die);
    auto expr_member_die = add_die(DwarfTag::DW_TAG_member, 0x1516);
    expr_member_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("payload"));
    expr_member_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<TypeAttributeValue>(0x130));
    expr_member_die->addAttribute(
        DwarfAttribute::DW_AT_data_member_location,
        std::make_shared<LocationAttributeValue>(
            LocationAttributeValue::LocationType::EXPRESSION,
            std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_plus_uconst), 0x0c}));
    expr_member_die->addAttribute(DwarfAttribute::DW_AT_accessibility, std::make_shared<UnsignedAttributeValue>(3));
    expr_member_die->addAttribute(DwarfAttribute::DW_AT_external, std::make_shared<FlagAttributeValue>(true));
    expr_member_die->addAttribute(DwarfAttribute::DW_AT_mutable, std::make_shared<FlagAttributeValue>(true));
    struct_die->addChild(expr_member_die);
    auto legacy_bitfield_die = add_die(DwarfTag::DW_TAG_member, 0x15165);
    legacy_bitfield_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("legacy_bits"));
    legacy_bitfield_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<TypeAttributeValue>(0x130));
    legacy_bitfield_die->addAttribute(DwarfAttribute::DW_AT_data_member_location, std::make_shared<UnsignedAttributeValue>(4));
    legacy_bitfield_die->addAttribute(DwarfAttribute::DW_AT_bit_size, std::make_shared<UnsignedAttributeValue>(5));
    legacy_bitfield_die->addAttribute(DwarfAttribute::DW_AT_bit_offset, std::make_shared<UnsignedAttributeValue>(9));
    struct_die->addChild(legacy_bitfield_die);
    auto expr_inherit_die = add_die(DwarfTag::DW_TAG_inheritance, 0x1517);
    expr_inherit_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<TypeAttributeValue>(0x146));
    expr_inherit_die->addAttribute(
        DwarfAttribute::DW_AT_data_member_location,
        std::make_shared<LocationAttributeValue>(
            LocationAttributeValue::LocationType::EXPRESSION,
            std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_consts), 0x78}));
    expr_inherit_die->addAttribute(DwarfAttribute::DW_AT_accessibility, std::make_shared<UnsignedAttributeValue>(1));
    struct_die->addChild(expr_inherit_die);
    auto inherit_die = add_die(DwarfTag::DW_TAG_inheritance, 0x1518);
    inherit_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<TypeAttributeValue>(0x146));
    inherit_die->addAttribute(DwarfAttribute::DW_AT_data_member_location, std::make_shared<SignedAttributeValue>(-16));
    inherit_die->addAttribute(DwarfAttribute::DW_AT_virtuality, std::make_shared<UnsignedAttributeValue>(1));
    inherit_die->addAttribute(DwarfAttribute::DW_AT_accessibility, std::make_shared<UnsignedAttributeValue>(2));
    struct_die->addChild(inherit_die);

    auto interface_decl_die = add_die(DwarfTag::DW_TAG_interface_type, 0x152);
    interface_decl_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("Runnable"));
    interface_decl_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(1));
    auto iface_member_die = add_die(DwarfTag::DW_TAG_member, 0x153);
    iface_member_die->addAttribute(DwarfAttribute::DW_AT_name, std::make_shared<StringAttributeValue>("state"));
    iface_member_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<TypeAttributeValue>(0x130));
    interface_decl_die->addChild(iface_member_die);

    auto array_die = add_die(DwarfTag::DW_TAG_array_type, 0x154);
    array_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x100));
    array_die->addAttribute(DwarfAttribute::DW_AT_byte_stride, std::make_shared<UnsignedAttributeValue>(16));
    array_die->addAttribute(DwarfAttribute::DW_AT_bit_stride, std::make_shared<UnsignedAttributeValue>(128));
    array_die->addAttribute(DwarfAttribute::DW_AT_rank, std::make_shared<UnsignedAttributeValue>(1));
    array_die->addAttribute(DwarfAttribute::DW_AT_visibility, std::make_shared<UnsignedAttributeValue>(2));
    auto array_subrange_die = add_die(DwarfTag::DW_TAG_subrange_type, 0x155);
    array_subrange_die->addAttribute(DwarfAttribute::DW_AT_lower_bound, std::make_shared<SignedAttributeValue>(-2));
    array_subrange_die->addAttribute(DwarfAttribute::DW_AT_upper_bound, std::make_shared<SignedAttributeValue>(2));
    array_die->addChild(array_subrange_die);

    auto expr_stride_array_die = add_die(DwarfTag::DW_TAG_array_type, 0x156);
    expr_stride_array_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x100));
    expr_stride_array_die->addAttribute(
        DwarfAttribute::DW_AT_byte_stride,
        std::make_shared<LocationAttributeValue>(
            LocationAttributeValue::LocationType::EXPRESSION,
            std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_plus_uconst), 0x18}));
    expr_stride_array_die->addAttribute(
        DwarfAttribute::DW_AT_bit_stride,
        std::make_shared<LocationAttributeValue>(
            LocationAttributeValue::LocationType::EXPRESSION,
            std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_constu), 0x40}));
    auto expr_stride_array_subrange_die = add_die(DwarfTag::DW_TAG_subrange_type, 0x157);
    expr_stride_array_subrange_die->addAttribute(DwarfAttribute::DW_AT_count, std::make_shared<UnsignedAttributeValue>(3));
    expr_stride_array_die->addChild(expr_stride_array_subrange_die);

    auto expr_bound_array_die = add_die(DwarfTag::DW_TAG_array_type, 0x158);
    expr_bound_array_die->addAttribute(DwarfAttribute::DW_AT_type, std::make_shared<ReferenceAttributeValue>(0x100));
    auto expr_bound_array_subrange_die = add_die(DwarfTag::DW_TAG_subrange_type, 0x159);
    expr_bound_array_subrange_die->addAttribute(
        DwarfAttribute::DW_AT_lower_bound,
        std::make_shared<LocationAttributeValue>(
            LocationAttributeValue::LocationType::EXPRESSION,
            std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_consts), 0x7f}));
    expr_bound_array_subrange_die->addAttribute(
        DwarfAttribute::DW_AT_upper_bound,
        std::make_shared<LocationAttributeValue>(
            LocationAttributeValue::LocationType::EXPRESSION,
            std::vector<uint8_t>{static_cast<uint8_t>(DwarfOp::DW_OP_constu), 0x03}));
    expr_bound_array_die->addChild(expr_bound_array_subrange_die);

    TypePrinterConfig cfg;
    cfg.pointer_size_bytes = 8;
    cfg.show_offsets = true;
    TypePrinter printer(lookup, cfg);

    assert(printer.formatType(const_die) == "const int");
    assert(printer.formatType(be_int_die) == "be_int [endianity=1]");
    assert(printer.formatType(seg_int_die) == "seg_int [address_class=7]");
    assert(printer.formatType(ptr_die) == "const int*");
    assert(printer.formatType(typedef_die) == "Alias [visibility=1]");
    assert(printer.formatType(unspecified_die) == "decltype(auto)");
    assert(printer.formatType(string_die) == "utf8_string [length=4] [visibility=1]");
    assert(printer.formatType(expr_string_die) == "CountedExprString [length=6]");
    assert(printer.formatType(set_die) == "IntSet [visibility=2]");
    assert(printer.formatType(file_die) == "IntFile [rank=1] [visibility=2]");
    assert(printer.formatType(anonymous_file_die) == "file<int>[1..4] [rank=1] [visibility=2]");
    assert(printer.formatType(rref_die) == "Alias [visibility=1]&&");
    assert(printer.formatType(atomic_die) == "_Atomic(Alias [visibility=1])");
    assert(printer.formatType(interface_die) == "interface Runnable [visibility=1]");
    assert(printer.formatType(member_ptr_die) == "Alias [visibility=1] Widget::*");
    assert(printer.formatType(enum_die) == "enum class ScopedColor : int [visibility=1]");
    std::string enum_text = printer.formatEnum(enum_die, true);
    assert(enum_text.find("NEGATIVE = -7") != std::string::npos);
    assert(enum_text.find("POSITIVE = 5") != std::string::npos);
    assert(printer.formatType(array_die) == "int[-2..2] [byte_stride=16] [bit_stride=128] [rank=1] [visibility=2]");
    assert(printer.formatType(expr_stride_array_die) == "int[3] [byte_stride=24] [bit_stride=64]");
    assert(printer.formatType(expr_bound_array_die) == "int[-1..3]");
    assert(printer.formatTypedef(typedef_die) == "typedef const int* Alias [visibility=1]");
    assert(printer.formatType(func_die) ==
           "int (*)(/* object_pointer, artificial */ Alias [visibility=1] self, ...) [prototyped] [calling_convention=5] [declaration] [explicit] [elemental] [pure] [recursive] [main_subprogram] [const_expr] [visibility=2]");
    assert(printer.formatType(flag_variadic_func_die) == "int (*)(Alias [visibility=1] prefix, ...)");
    assert(printer.formatFunction(func_die) ==
           "int <anonymous>(/* object_pointer, artificial */ Alias [visibility=1] self, ...) [prototyped] [calling_convention=5] [declaration] [explicit] [elemental] [pure] [recursive] [main_subprogram] [const_expr] [visibility=2]");
    assert(printer.formatFunction(flag_variadic_func_die) == "int <anonymous>(Alias [visibility=1] prefix, ...)");

    std::string struct_text = printer.formatStructure(struct_die, true);
    assert(struct_text.find("struct Widget [visibility=2]") != std::string::npos);
    assert(struct_text.find("value : 3") != std::string::npos);
    assert(struct_text.find("offset: 8") != std::string::npos);
    assert(struct_text.find("bit_offset: 1") != std::string::npos);
    assert(struct_text.find("tail") != std::string::npos);
    assert(struct_text.find("offset: -4") != std::string::npos);
    assert(struct_text.find("payload") != std::string::npos);
    assert(struct_text.find("private static mutable Alias [visibility=1] payload") != std::string::npos);
    assert(struct_text.find("offset: 12") != std::string::npos);
    assert(struct_text.find("legacy_bits : 5") != std::string::npos);
    assert(struct_text.find("bit_offset: 9") != std::string::npos);
    assert(struct_text.find("inherits from: public Widget [visibility=2] /* offset: -8 */") != std::string::npos);
    assert(struct_text.find("inherits from: protected virtual Widget [visibility=2] /* offset: -16 */") != std::string::npos);

    std::string interface_text = printer.formatStructure(interface_decl_die, true);
    assert(interface_text.find("interface Runnable [visibility=1]") != std::string::npos);
    assert(interface_text.find("Alias [visibility=1] state") != std::string::npos);

    std::cout << "TypePrinter tests passed!" << std::endl;
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
    testExpressionEvaluatorEntryValue();
    testExpressionEvaluatorGnuUninit();
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
	    testSymbolicExpressionEvaluatorDiagnosticContextOnUnsupportedOp();
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
	    testSymbolicExpressionEvaluatorSymbolicBraCompositeRegisterLocationMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraRegisterMismatchMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraAddressValueMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraAddressAddressMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraRegisterValueMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraRegisterAddressMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraRegisterSameMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraCompositeKindMismatchMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraCompositeUnavailableMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraCompositeMemoryLocationMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraCompositeBitPieceUnavailableMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraCompositeBitPieceMemoryLocationMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraCompositeImplicitMerge();
	    testSymbolicExpressionEvaluatorSymbolicBraCompositeImplicitMergeLargeBytes();
	    testSymbolicExpressionEvaluatorSymbolicBraCompositeImplicitNestedMerge();
	    testSymbolicExpressionEvaluatorXderefAndXderefType();
	    testSymbolicExpressionEvaluatorCallOpsAndGnuIndices();
	    testSymbolicExpressionEvaluatorGnuTypedAndParameterOps();
	    testExpressionVerifier();
	    testSMTExpressionVerifierBehavior();
	    testCrossBinaryExpressionComparator();
	    testAttributeParserBoundedStringsAndBlocks();
	    testStrpSup();
	    testGnuAltForms();
    testGnuIndexForms();
	    testRefSupForms();
	    testDIEParserRefSupIntegration();
    testDIEParserUnknownVendorFormSkip();
    testDIEParserCUBoundsOnUnterminatedFormString();
    testDIEParserTruncatedAbbrevImplicitConst();
    testDebugSupParser();
    testDwarfParserExposesDebugNamesUnitHeaders();
    testDebugNamesParser();
    testDebugNamesParserTypeUnitIndexResolvesDIEOffsets();
    testDebugNamesParserMultipleUnitsLookup();
    testDebugNamesParserRealWorldMultiUnitFixture();
    testDebugNamesParserRealWorldMixedFixture();
    testDebugNamesParserNonEmptyAugmentationStringAccepted();
    testDebugNamesParserAugmentationPayloadSkipsBytes();
    testDebugNamesParserAugmentationPayloadLengthPrefixedSkipsBytes();
    testDebugNamesParserBucketLookup();
    testDebugNamesParserDwarf64UnknownRefSup4Skip();
    testDebugNamesParserUnknownStrx3Skip();
    testDebugNamesParserDwarf32UnknownRefSup8Skip();
    testDebugNamesParserDwarf64UnknownAddrSkip();
    testDebugNamesParserDwarf32UnknownAddrSkip();
    testDebugNamesParserDwarf64DieOffsetAsAddr();
    testDebugNamesParserMalformedInputs();
	    testDebugMacroParser();
	    testDwarfParserMacroLookupFallsBackAcrossCUs();
        testDwarf5SkeletonUnitHeaderSkipsDWOId();
        testDwarf5SplitCompileUnitHeaderSkipsDWOId();
        testDwarf5TypeUnitHeaderSkipsSignatureAndTypeOffset();
        testDwarf5PartialUnitSetsCUContextForAddrx();
        testDwarf5SplitTypeUnitSetsCUContextForAddrx();
	    testDwarfParserGetFunctionAtUsesRanges();
	    testDebugLineV4ViaStmtList();
    testDebugLineV5ViaStmtList();
    testStrxBasePointsToContributionHeader();
    testStrxContributionBoundsWhenBasePointsToTableStart();
    testAddrxBasePointsToContributionHeader();
    testAddrxContributionBoundsWhenBasePointsToTableStart();
    testV5IndexedFormsInHelperParsers();
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
    testImplicitConstParserPathAndSignedValue();
    testRefAddrBiasForDWO();
    testDwarf5SecOffsetLoclistsAndRnglists();
    testDwarf4SecOffsetDebugLocAndRanges();
    testDwarf64LoclistxRnglistxOffsetSize();
    testSplitDwarfIntegrationELFIO();
    testSplitDwarfRealCompilerFixture();
    testSplitDwarfRealCompilerDWPFixture();
    testDwarfParserDWPStateTransitions();
    testSplitDwarfPrefersDWPOverDWO();
    testSplitDwarfFallsBackToDWOWhenDWPDoesNotContainUnit();
    testSplitDwarfFallsBackToDWOWhenDWPIndexMalformed();
    testSplitDwarfFallsBackToDWOWhenDWPHasNoCUIndex();
    testSplitDwarfUsesTUIndexWhenCUIndexAbsent();
    testSplitDwarfDWOAddrxUsesDWODebugAddr();
    testTypedOpsTypedefChainViaDwarfParser();
    testVariableLocationDiagnosticContextViaDwarfParser();
    testCallStackAArch64CFAExpressionUnwind();
	    testEHFramePCRelativeEncoding();
	    testEHFrameAlignedEncoding();
	    testEHFrameSetLocUsesCIEAddressSize();
	    testEHFrameSetLocInvalidCIEAddressSizeAbortsStream();
	    testEHFrameTruncatedPersonalityDoesNotBleed();
	    testEHFrameTruncatedFDEPointerDoesNotReadPadding();
	    testSupplementaryDebugInfoViaDebugSup();
    testTypeSystem();
    testTypePrinter();
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
