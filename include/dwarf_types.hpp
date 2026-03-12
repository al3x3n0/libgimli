#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <map>
#include <optional>
#include <sstream>

namespace dwarf {

// DWARF version
enum class DwarfVersion : uint8_t {
    DWARF2 = 2,
    DWARF3 = 3,
    DWARF4 = 4,
    DWARF5 = 5
};

// DWARF 5 Unit Types (DW_UT_*)
enum class DwarfUnitType : uint8_t {
    DW_UT_compile = 0x01,
    DW_UT_type = 0x02,
    DW_UT_partial = 0x03,
    DW_UT_skeleton = 0x04,
    DW_UT_split_compile = 0x05,
    DW_UT_split_type = 0x06
};

// DWARF address size
enum class AddressSize : uint8_t {
    ADDR_32 = 4,
    ADDR_64 = 8
};

// DWARF tag values (simplified set)
enum class DwarfTag : uint16_t {
    DW_TAG_compile_unit = 0x11,
    DW_TAG_partial_unit = 0x3c,          // DWARF 5
    DW_TAG_type_unit = 0x41,             // DWARF 5
    DW_TAG_skeleton_unit = 0x4a,         // DWARF 5
    DW_TAG_split_compile_unit = 0x1b,    // DWARF 5
    DW_TAG_split_type_unit = 0x43,       // DWARF 5
    DW_TAG_subprogram = 0x2e,
    DW_TAG_variable = 0x34,
    DW_TAG_formal_parameter = 0x05,
    DW_TAG_base_type = 0x24,
    DW_TAG_unspecified_type = 0x3b,
    DW_TAG_string_type = 0x12,
    DW_TAG_set_type = 0x20,
    DW_TAG_file_type = 0x29,
    DW_TAG_pointer_type = 0x0f,
    DW_TAG_ptr_to_member_type = 0x1f,
    DW_TAG_array_type = 0x01,
    DW_TAG_structure_type = 0x13,
    DW_TAG_union_type = 0x17,
    DW_TAG_enumeration_type = 0x04,
    DW_TAG_typedef = 0x16,
    DW_TAG_const_type = 0x26,
    DW_TAG_volatile_type = 0x27,
    DW_TAG_restrict_type = 0x28,
    DW_TAG_reference_type = 0x10,
    DW_TAG_rvalue_reference_type = 0x42,
    DW_TAG_atomic_type = 0x47,
    DW_TAG_subrange_type = 0x21,
    DW_TAG_class_type = 0x02,
    DW_TAG_interface_type = 0x38,
    DW_TAG_subroutine_type = 0x15,
    DW_TAG_enumerator = 0x4a,
    DW_TAG_member = 0x0d,
    DW_TAG_inheritance = 0x1c,
    DW_TAG_inlined_subroutine = 0x1d,
    DW_TAG_lexical_block = 0x0b,
    DW_TAG_unspecified_parameters = 0x0c
};

// DWARF attribute form values
enum class DwarfForm : uint16_t {
    DW_FORM_addr = 0x01,
    DW_FORM_block2 = 0x03,
    DW_FORM_block4 = 0x04,
    DW_FORM_data2 = 0x05,
    DW_FORM_data4 = 0x06,
    DW_FORM_data8 = 0x07,
    DW_FORM_string = 0x08,
    DW_FORM_block = 0x09,
    DW_FORM_block1 = 0x0a,
    DW_FORM_data1 = 0x0b,
    DW_FORM_flag = 0x0c,
    DW_FORM_sdata = 0x0d,
    DW_FORM_strp = 0x0e,
    DW_FORM_udata = 0x0f,
    DW_FORM_ref_addr = 0x10,
    DW_FORM_ref1 = 0x11,
    DW_FORM_ref2 = 0x12,
    DW_FORM_ref4 = 0x13,
    DW_FORM_ref8 = 0x14,
    DW_FORM_ref_udata = 0x15,
    DW_FORM_indirect = 0x16,
    DW_FORM_sec_offset = 0x17,
    DW_FORM_exprloc = 0x18,
    DW_FORM_flag_present = 0x19,
    DW_FORM_ref_sig8 = 0x20,
    DW_FORM_strx = 0x1a,
    DW_FORM_addrx = 0x1b,
    DW_FORM_ref_sup4 = 0x1c,
    DW_FORM_strp_sup = 0x1d,
    DW_FORM_data16 = 0x1e,
    DW_FORM_line_strp = 0x1f,
    DW_FORM_implicit_const = 0x21,
    DW_FORM_loclistx = 0x22,           // DWARF 5
    DW_FORM_rnglistx = 0x23,           // DWARF 5
    DW_FORM_ref_sup8 = 0x24,           // DWARF 5
    DW_FORM_strx1 = 0x25,              // DWARF 5
    DW_FORM_strx2 = 0x26,              // DWARF 5
    DW_FORM_strx3 = 0x27,              // DWARF 5
    DW_FORM_strx4 = 0x28,              // DWARF 5
    DW_FORM_addrx1 = 0x29,             // DWARF 5
    DW_FORM_addrx2 = 0x2a,             // DWARF 5
    DW_FORM_addrx3 = 0x2b,             // DWARF 5
    DW_FORM_addrx4 = 0x2c,             // DWARF 5

    // GNU split-DWARF predecessor forms for alternate debug object references.
    DW_FORM_GNU_addr_index = 0x1f01,
    DW_FORM_GNU_str_index = 0x1f02,
    DW_FORM_GNU_ref_alt = 0x1f20,
    DW_FORM_GNU_strp_alt = 0x1f21
};

// DWARF attribute names
enum class DwarfAttribute : uint16_t {
    DW_AT_sibling = 0x01,
    DW_AT_location = 0x02,
    DW_AT_name = 0x03,
    DW_AT_ordering = 0x09,
    DW_AT_byte_size = 0x0b,
    DW_AT_bit_offset = 0x0c,
    DW_AT_bit_size = 0x0d,
    DW_AT_stmt_list = 0x10,
    DW_AT_low_pc = 0x11,
    DW_AT_high_pc = 0x12,
    DW_AT_language = 0x13,
    DW_AT_discr = 0x15,
    DW_AT_discr_value = 0x16,
    DW_AT_visibility = 0x17,
    DW_AT_import = 0x18,
    DW_AT_string_length = 0x19,
    DW_AT_common_reference = 0x1a,
    DW_AT_comp_dir = 0x1b,
    DW_AT_const_value = 0x1c,
    DW_AT_containing_type = 0x1d,
    DW_AT_default_value = 0x1e,
    DW_AT_inline = 0x20,
    DW_AT_is_optional = 0x21,
    DW_AT_lower_bound = 0x22,
    DW_AT_producer = 0x25,
    DW_AT_prototyped = 0x27,
    DW_AT_return_addr = 0x2a,
    DW_AT_start_scope = 0x2c,
    DW_AT_bit_stride = 0x2e,
    DW_AT_upper_bound = 0x2f,
    DW_AT_abstract_origin = 0x31,
    DW_AT_accessibility = 0x32,
    DW_AT_address_class = 0x33,
    DW_AT_artificial = 0x34,
    DW_AT_base_types = 0x35,
    DW_AT_calling_convention = 0x36,
    DW_AT_count = 0x37,
    DW_AT_data_member_location = 0x38,
    DW_AT_decl_column = 0x39,
    DW_AT_decl_file = 0x3a,
    DW_AT_decl_line = 0x3b,
    DW_AT_declaration = 0x3c,
    DW_AT_discr_list = 0x3d,
    DW_AT_encoding = 0x3e,
    DW_AT_external = 0x3f,
    DW_AT_frame_base = 0x40,
    DW_AT_friend = 0x41,
    DW_AT_identifier_case = 0x42,
    DW_AT_macro_info = 0x43,
    DW_AT_namelist_item = 0x44,
    // Note: DW_AT_volatile is not a standard DWARF attribute - volatile types use DW_TAG_volatile_type
    // This is kept for compatibility but should not appear in actual DWARF data
    DW_AT_volatile = 0x2100,  // Using a value in the reserved vendor range to avoid conflicts
    DW_AT_priority = 0x45,
    DW_AT_segment = 0x46,
    DW_AT_specification = 0x47,
    DW_AT_static_link = 0x48,
    DW_AT_type = 0x49,
    DW_AT_use_location = 0x4a,
    DW_AT_variable_parameter = 0x4c,
    DW_AT_virtuality = 0x4d,
    DW_AT_vtable_elem_location = 0x4e,
    DW_AT_allocated = 0x4f,
    DW_AT_associated = 0x50,
    DW_AT_data_location = 0x51,
    DW_AT_byte_stride = 0x52,
    DW_AT_entry_pc = 0x53,
    DW_AT_use_UTF8 = 0x54,
    DW_AT_extension = 0x55,
    DW_AT_ranges = 0x56,
    DW_AT_trampoline = 0x57,
    DW_AT_call_column = 0x58,
    DW_AT_call_file = 0x59,
    DW_AT_call_line = 0x5a,
    DW_AT_description = 0x5b,
    DW_AT_binary_scale = 0x5c,
    DW_AT_decimal_scale = 0x5d,
    DW_AT_small = 0x5e,
    DW_AT_decimal_sign = 0x5f,
    DW_AT_digit_count = 0x60,
    DW_AT_picture_string = 0x61,
    DW_AT_mutable = 0x62,
    DW_AT_threads_scaled = 0x63,
    DW_AT_explicit = 0x64,
    DW_AT_object_pointer = 0x65,
    DW_AT_endianity = 0x66,
    DW_AT_elemental = 0x67,
    DW_AT_pure = 0x68,
    DW_AT_recursive = 0x69,
    DW_AT_signature = 0x6a,
    DW_AT_main_subprogram = 0x6b,
    DW_AT_data_bit_offset = 0x6c,
    DW_AT_const_expr = 0x6d,
    DW_AT_enum_class = 0x6e,
    DW_AT_linkage_name = 0x6f,
    DW_AT_string_length_bit_size = 0x70,   // DWARF 5
    DW_AT_string_length_byte_size = 0x71,  // DWARF 5
    DW_AT_rank = 0x72,                     // DWARF 5
    DW_AT_str_offsets_base = 0x72,         // DWARF 5
    DW_AT_addr_base = 0x73,                // DWARF 5
    DW_AT_rnglists_base = 0x74,            // DWARF 5
    DW_AT_dwo_id = 0x75,                   // DWARF 5
    DW_AT_dwo_name = 0x76,                 // DWARF 5
    DW_AT_reference = 0x77,                // DWARF 5
    DW_AT_rvalue_reference = 0x78,         // DWARF 5
    DW_AT_macros = 0x79,                   // DWARF 5
    DW_AT_call_all_calls = 0x7a,           // DWARF 5
    DW_AT_call_all_source_calls = 0x7b,    // DWARF 5
    DW_AT_call_all_tail_calls = 0x7c,      // DWARF 5
    DW_AT_call_return_pc = 0x7d,           // DWARF 5
    DW_AT_call_value = 0x7e,               // DWARF 5
    DW_AT_call_origin = 0x7f,              // DWARF 5
    DW_AT_call_parameter = 0x80,           // DWARF 5
    DW_AT_loclists_base = 0x8c,            // DWARF 5

    // GNU split DWARF extensions (vendor)
    DW_AT_GNU_dwo_name = 0x2130,
    DW_AT_GNU_dwo_id = 0x2131
};

// DWARF operation codes for location expressions
enum class DwarfOp : uint8_t {
    DW_OP_addr = 0x03,
    DW_OP_deref = 0x06,
    DW_OP_const1u = 0x08,
    DW_OP_const1s = 0x09,
    DW_OP_const2u = 0x0a,
    DW_OP_const2s = 0x0b,
    DW_OP_const4u = 0x0c,
    DW_OP_const4s = 0x0d,
    DW_OP_const8u = 0x0e,
    DW_OP_const8s = 0x0f,
    DW_OP_constu = 0x10,
    DW_OP_consts = 0x11,
    DW_OP_dup = 0x12,
    DW_OP_drop = 0x13,
    DW_OP_over = 0x14,
    DW_OP_pick = 0x15,
    DW_OP_swap = 0x16,
    DW_OP_rot = 0x17,
    DW_OP_xderef = 0x18,
    DW_OP_abs = 0x19,
    DW_OP_and = 0x1a,
    DW_OP_div = 0x1b,
    DW_OP_minus = 0x1c,
    DW_OP_mod = 0x1d,
    DW_OP_mul = 0x1e,
    DW_OP_neg = 0x1f,
    DW_OP_not = 0x20,
    DW_OP_or = 0x21,
    DW_OP_plus = 0x22,
    DW_OP_plus_uconst = 0x23,
    DW_OP_shl = 0x24,
    DW_OP_shr = 0x25,
    DW_OP_shra = 0x26,
    DW_OP_xor = 0x27,
    DW_OP_bra = 0x28,
    DW_OP_eq = 0x29,
    DW_OP_ge = 0x2a,
    DW_OP_gt = 0x2b,
    DW_OP_le = 0x2c,
    DW_OP_lt = 0x2d,
    DW_OP_ne = 0x2e,
    DW_OP_skip = 0x2f,
    DW_OP_lit0 = 0x30,
    DW_OP_lit1 = 0x31,
    DW_OP_lit2 = 0x32,
    DW_OP_lit3 = 0x33,
    DW_OP_lit4 = 0x34,
    DW_OP_lit5 = 0x35,
    DW_OP_lit6 = 0x36,
    DW_OP_lit7 = 0x37,
    DW_OP_lit8 = 0x38,
    DW_OP_lit9 = 0x39,
    DW_OP_lit10 = 0x3a,
    DW_OP_lit11 = 0x3b,
    DW_OP_lit12 = 0x3c,
    DW_OP_lit13 = 0x3d,
    DW_OP_lit14 = 0x3e,
    DW_OP_lit15 = 0x3f,
    DW_OP_lit16 = 0x40,
    DW_OP_lit17 = 0x41,
    DW_OP_lit18 = 0x42,
    DW_OP_lit19 = 0x43,
    DW_OP_lit20 = 0x44,
    DW_OP_lit21 = 0x45,
    DW_OP_lit22 = 0x46,
    DW_OP_lit23 = 0x47,
    DW_OP_lit24 = 0x48,
    DW_OP_lit25 = 0x49,
    DW_OP_lit26 = 0x4a,
    DW_OP_lit27 = 0x4b,
    DW_OP_lit28 = 0x4c,
    DW_OP_lit29 = 0x4d,
    DW_OP_lit30 = 0x4e,
    DW_OP_lit31 = 0x4f,
    DW_OP_reg0 = 0x50,
    DW_OP_reg1 = 0x51,
    DW_OP_reg2 = 0x52,
    DW_OP_reg3 = 0x53,
    DW_OP_reg4 = 0x54,
    DW_OP_reg5 = 0x55,
    DW_OP_reg6 = 0x56,
    DW_OP_reg7 = 0x57,
    DW_OP_reg8 = 0x58,
    DW_OP_reg9 = 0x59,
    DW_OP_reg10 = 0x5a,
    DW_OP_reg11 = 0x5b,
    DW_OP_reg12 = 0x5c,
    DW_OP_reg13 = 0x5d,
    DW_OP_reg14 = 0x5e,
    DW_OP_reg15 = 0x5f,
    DW_OP_reg16 = 0x60,
    DW_OP_reg17 = 0x61,
    DW_OP_reg18 = 0x62,
    DW_OP_reg19 = 0x63,
    DW_OP_reg20 = 0x64,
    DW_OP_reg21 = 0x65,
    DW_OP_reg22 = 0x66,
    DW_OP_reg23 = 0x67,
    DW_OP_reg24 = 0x68,
    DW_OP_reg25 = 0x69,
    DW_OP_reg26 = 0x6a,
    DW_OP_reg27 = 0x6b,
    DW_OP_reg28 = 0x6c,
    DW_OP_reg29 = 0x6d,
    DW_OP_reg30 = 0x6e,
    DW_OP_reg31 = 0x6f,
    DW_OP_breg0 = 0x70,
    DW_OP_breg1 = 0x71,
    DW_OP_breg2 = 0x72,
    DW_OP_breg3 = 0x73,
    DW_OP_breg4 = 0x74,
    DW_OP_breg5 = 0x75,
    DW_OP_breg6 = 0x76,
    DW_OP_breg7 = 0x77,
    DW_OP_breg8 = 0x78,
    DW_OP_breg9 = 0x79,
    DW_OP_breg10 = 0x7a,
    DW_OP_breg11 = 0x7b,
    DW_OP_breg12 = 0x7c,
    DW_OP_breg13 = 0x7d,
    DW_OP_breg14 = 0x7e,
    DW_OP_breg15 = 0x7f,
    DW_OP_breg16 = 0x80,
    DW_OP_breg17 = 0x81,
    DW_OP_breg18 = 0x82,
    DW_OP_breg19 = 0x83,
    DW_OP_breg20 = 0x84,
    DW_OP_breg21 = 0x85,
    DW_OP_breg22 = 0x86,
    DW_OP_breg23 = 0x87,
    DW_OP_breg24 = 0x88,
    DW_OP_breg25 = 0x89,
    DW_OP_breg26 = 0x8a,
    DW_OP_breg27 = 0x8b,
    DW_OP_breg28 = 0x8c,
    DW_OP_breg29 = 0x8d,
    DW_OP_breg30 = 0x8e,
    DW_OP_breg31 = 0x8f,
    DW_OP_regx = 0x90,
    DW_OP_fbreg = 0x91,
    DW_OP_bregx = 0x92,
    DW_OP_piece = 0x93,
    DW_OP_deref_size = 0x94,
    DW_OP_xderef_size = 0x95,
    DW_OP_nop = 0x96,
    DW_OP_push_object_address = 0x97,
    DW_OP_call2 = 0x98,
    DW_OP_call4 = 0x99,
    DW_OP_call_ref = 0x9a,
    DW_OP_form_tls_address = 0x9b,
    DW_OP_call_frame_cfa = 0x9c,
    DW_OP_bit_piece = 0x9d,
    DW_OP_implicit_value = 0x9e,
    DW_OP_stack_value = 0x9f,
    DW_OP_implicit_pointer = 0xa0,
    DW_OP_addrx = 0xa1,
    DW_OP_constx = 0xa2,
    DW_OP_entry_value = 0xa3,
    DW_OP_const_type = 0xa4,
    DW_OP_regval_type = 0xa5,
    DW_OP_deref_type = 0xa6,
    DW_OP_xderef_type = 0xa7,
    DW_OP_convert = 0xa8,
    DW_OP_reinterpret = 0xa9,

    // GNU Extensions (commonly used in real binaries)
    DW_OP_GNU_push_tls_address = 0xe0,
    DW_OP_WASM_location = 0xed,
    DW_OP_GNU_uninit = 0xf0,
    DW_OP_GNU_encoded_addr = 0xf1,
    DW_OP_GNU_implicit_pointer = 0xf2,
    DW_OP_GNU_entry_value = 0xf3,
    DW_OP_GNU_const_type = 0xf4,
    DW_OP_GNU_regval_type = 0xf5,
    DW_OP_GNU_deref_type = 0xf6,
    DW_OP_GNU_convert = 0xf7,
    DW_OP_GNU_reinterpret = 0xf8,
    DW_OP_GNU_parameter_ref = 0xfa,
    DW_OP_GNU_addr_index = 0xfb,
    DW_OP_GNU_const_index = 0xfc
};

// DWARF Line Number Standard Opcodes
enum class DwarfLineOp : uint8_t {
    DW_LNS_copy = 1,
    DW_LNS_advance_pc = 2,
    DW_LNS_advance_line = 3,
    DW_LNS_set_file = 4,
    DW_LNS_set_column = 5,
    DW_LNS_negate_stmt = 6,
    DW_LNS_set_basic_block = 7,
    DW_LNS_const_add_pc = 8,
    DW_LNS_fixed_advance_pc = 9,
    DW_LNS_set_prologue_end = 10,      // DWARF 3+
    DW_LNS_set_epilogue_begin = 11,    // DWARF 3+
    DW_LNS_set_isa = 12                // DWARF 3+
};

// DWARF Line Number Extended Opcodes
enum class DwarfLineExtOp : uint8_t {
    DW_LNE_end_sequence = 1,
    DW_LNE_set_address = 2,
    DW_LNE_define_file = 3,
    DW_LNE_set_discriminator = 4       // DWARF 4+
};

// DWARF 5 Range List Entry Types (DW_RLE_*)
enum class DW_RLE : uint8_t {
    DW_RLE_end_of_list = 0x00,
    DW_RLE_base_addressx = 0x01,
    DW_RLE_startx_endx = 0x02,
    DW_RLE_startx_length = 0x03,
    DW_RLE_offset_pair = 0x04,
    DW_RLE_base_address = 0x05,
    DW_RLE_start_end = 0x06,
    DW_RLE_start_length = 0x07
};

// DWARF 5 Location List Entry Types (DW_LLE_*)
enum class DW_LLE : uint8_t {
    DW_LLE_end_of_list = 0x00,
    DW_LLE_base_addressx = 0x01,
    DW_LLE_startx_endx = 0x02,
    DW_LLE_startx_length = 0x03,
    DW_LLE_offset_pair = 0x04,
    DW_LLE_default_location = 0x05,
    DW_LLE_base_address = 0x06,
    DW_LLE_start_end = 0x07,
    DW_LLE_start_length = 0x08
};

// DWARF 5 rnglists/loclists unit header
struct RngListsHeader {
    uint64_t unit_length;
    uint16_t version;
    uint8_t address_size;
    uint8_t segment_selector_size;
    uint32_t offset_entry_count;
    bool is_dwarf64;
    uint64_t header_size;
};

struct LocListsHeader {
    uint64_t unit_length;
    uint16_t version;
    uint8_t address_size;
    uint8_t segment_selector_size;
    uint32_t offset_entry_count;
    bool is_dwarf64;
    uint64_t header_size;
};

// Parsed range list entry
struct RngListEntry {
    DW_RLE type;
    uint64_t start;
    uint64_t end;
    bool is_base_address;
};

// Parsed location list entry
struct LocListEntry {
    DW_LLE type;
    uint64_t start;
    uint64_t end;
    std::vector<uint8_t> expression;
    bool is_default;
};

// DWARF Base Type Encodings (DW_ATE_*)
enum class DW_ATE : uint8_t {
    DW_ATE_address = 0x01,
    DW_ATE_boolean = 0x02,
    DW_ATE_complex_float = 0x03,
    DW_ATE_float = 0x04,
    DW_ATE_signed = 0x05,
    DW_ATE_signed_char = 0x06,
    DW_ATE_unsigned = 0x07,
    DW_ATE_unsigned_char = 0x08,
    DW_ATE_imaginary_float = 0x09,   // DWARF 3+
    DW_ATE_packed_decimal = 0x0a,    // DWARF 3+
    DW_ATE_numeric_string = 0x0b,    // DWARF 3+
    DW_ATE_edited = 0x0c,            // DWARF 3+
    DW_ATE_signed_fixed = 0x0d,      // DWARF 3+
    DW_ATE_unsigned_fixed = 0x0e,    // DWARF 3+
    DW_ATE_decimal_float = 0x0f,     // DWARF 3+
    DW_ATE_UTF = 0x10,               // DWARF 4+
    DW_ATE_UCS = 0x11,               // DWARF 5
    DW_ATE_ASCII = 0x12              // DWARF 5
};

// CFI (Call Frame Information) opcodes
enum class DW_CFA : uint8_t {
    // Row creation instructions
    DW_CFA_set_loc = 0x01,
    DW_CFA_advance_loc1 = 0x02,
    DW_CFA_advance_loc2 = 0x03,
    DW_CFA_advance_loc4 = 0x04,
    DW_CFA_advance_loc = 0x40,      // High 2 bits = 01, low 6 bits = delta

    // CFA definition instructions
    DW_CFA_def_cfa = 0x0c,
    DW_CFA_def_cfa_sf = 0x12,
    DW_CFA_def_cfa_register = 0x0d,
    DW_CFA_def_cfa_offset = 0x0e,
    DW_CFA_def_cfa_offset_sf = 0x13,
    DW_CFA_def_cfa_expression = 0x0f,

    // Register rule instructions
    DW_CFA_undefined = 0x07,
    DW_CFA_same_value = 0x08,
    DW_CFA_offset = 0x80,           // High 2 bits = 10, low 6 bits = register
    DW_CFA_offset_extended = 0x05,
    DW_CFA_offset_extended_sf = 0x11,
    DW_CFA_val_offset = 0x14,
    DW_CFA_val_offset_sf = 0x15,
    DW_CFA_register = 0x09,
    DW_CFA_expression = 0x10,
    DW_CFA_val_expression = 0x16,
    DW_CFA_restore = 0xc0,          // High 2 bits = 11, low 6 bits = register
    DW_CFA_restore_extended = 0x06,

    // Row state instructions
    DW_CFA_remember_state = 0x0a,
    DW_CFA_restore_state = 0x0b,

    // Padding and extensions
    DW_CFA_nop = 0x00,
    DW_CFA_MIPS_advance_loc8 = 0x1d,
    DW_CFA_GNU_args_size = 0x2e,
    DW_CFA_GNU_negative_offset_extended = 0x2f
};

// Register rule types for CFI
enum class CFA_RegRule {
    UNDEFINED,      // Register has no recoverable value
    SAME_VALUE,     // Register is unchanged from previous frame
    OFFSET,         // Register saved at CFA + offset
    VAL_OFFSET,     // Register value is CFA + offset
    REGISTER,       // Register saved in another register
    EXPRESSION,     // Register location computed by expression
    VAL_EXPRESSION, // Register value computed by expression
    ARCHITECTURAL   // Register has architecturally defined rule
};

// CFA definition types
enum class CFA_Type {
    REGISTER_OFFSET,  // CFA = register + offset
    EXPRESSION        // CFA computed by expression
};

// Forward declarations
class DIE;
class AttributeValue;
class TypeSystem;

// Attribute value types
enum class AttributeValueType {
    UNSIGNED,
    SIGNED,
    STRING,
    REFERENCE,
    BLOCK,
    FLAG,
    ADDRESS,
    EXPRESSION
};

// Base class for attribute values
class AttributeValue {
public:
    virtual ~AttributeValue() = default;
    virtual AttributeValueType getType() const = 0;
    virtual std::string toString() const = 0;
};

// Specific attribute value types
class UnsignedAttributeValue : public AttributeValue {
public:
    explicit UnsignedAttributeValue(uint64_t value) : value_(value) {}
    AttributeValueType getType() const override { return AttributeValueType::UNSIGNED; }
    std::string toString() const override { return std::to_string(value_); }
    uint64_t getValue() const { return value_; }
private:
    uint64_t value_;
};

class SignedAttributeValue : public AttributeValue {
public:
    explicit SignedAttributeValue(int64_t value) : value_(value) {}
    AttributeValueType getType() const override { return AttributeValueType::SIGNED; }
    std::string toString() const override { return std::to_string(value_); }
    int64_t getValue() const { return value_; }
private:
    int64_t value_;
};

class StringAttributeValue : public AttributeValue {
public:
    explicit StringAttributeValue(const std::string& value) : value_(value) {}
    AttributeValueType getType() const override { return AttributeValueType::STRING; }
    std::string toString() const override { return value_; }
    const std::string& getValue() const { return value_; }
private:
    std::string value_;
};

class ReferenceAttributeValue : public AttributeValue {
public:
    explicit ReferenceAttributeValue(uint64_t offset) : offset_(offset) {}
    AttributeValueType getType() const override { return AttributeValueType::REFERENCE; }
    std::string toString() const override { 
        std::ostringstream oss;
        oss << "ref: 0x" << std::hex << offset_;
        return oss.str();
    }
    uint64_t getOffset() const { return offset_; }
private:
    uint64_t offset_;
};

class BlockAttributeValue : public AttributeValue {
public:
    explicit BlockAttributeValue(const std::vector<uint8_t>& data) : data_(data) {}
    AttributeValueType getType() const override { return AttributeValueType::BLOCK; }
    std::string toString() const override;
    const std::vector<uint8_t>& getData() const { return data_; }
private:
    std::vector<uint8_t> data_;
};

class FlagAttributeValue : public AttributeValue {
public:
    explicit FlagAttributeValue(bool value) : value_(value) {}
    AttributeValueType getType() const override { return AttributeValueType::FLAG; }
    std::string toString() const override { return value_ ? "true" : "false"; }
    bool getValue() const { return value_; }
private:
    bool value_;
};

class AddressAttributeValue : public AttributeValue {
public:
    explicit AddressAttributeValue(uint64_t address) : address_(address) {}
    AttributeValueType getType() const override { return AttributeValueType::ADDRESS; }
    std::string toString() const override { 
        std::ostringstream oss;
        oss << "0x" << std::hex << address_;
        return oss.str();
    }
    uint64_t getAddress() const { return address_; }
private:
    uint64_t address_;
};

class ExpressionAttributeValue : public AttributeValue {
public:
    explicit ExpressionAttributeValue(const std::vector<uint8_t>& expression) : expression_(expression) {}
    AttributeValueType getType() const override { return AttributeValueType::EXPRESSION; }
    std::string toString() const override;
    const std::vector<uint8_t>& getExpression() const { return expression_; }
private:
    std::vector<uint8_t> expression_;
};

} // namespace dwarf
