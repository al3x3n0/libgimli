#include "dwarf_utils.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <cstring>

namespace dwarf {

std::string DwarfUtils::last_error_ = "";
bool DwarfUtils::object_little_endian_ = true;

void DwarfUtils::setObjectLittleEndian(bool little) {
    object_little_endian_ = little;
}

bool DwarfUtils::objectIsLittleEndian() {
    return object_little_endian_;
}

bool DwarfUtils::isLittleEndian() {
    return object_little_endian_;
}

// Tag name conversion
std::string DwarfUtils::tagToString(DwarfTag tag) {
    switch (tag) {
        case DwarfTag::DW_TAG_imported_declaration: return "DW_TAG_imported_declaration";
        case DwarfTag::DW_TAG_label: return "DW_TAG_label";
        case DwarfTag::DW_TAG_compile_unit: return "DW_TAG_compile_unit";
        case DwarfTag::DW_TAG_partial_unit: return "DW_TAG_partial_unit";
        case DwarfTag::DW_TAG_type_unit: return "DW_TAG_type_unit";
        case DwarfTag::DW_TAG_skeleton_unit: return "DW_TAG_skeleton_unit";
        case DwarfTag::DW_TAG_split_compile_unit: return "DW_TAG_split_compile_unit";
        case DwarfTag::DW_TAG_split_type_unit: return "DW_TAG_split_type_unit";
        case DwarfTag::DW_TAG_subprogram: return "DW_TAG_subprogram";
        case DwarfTag::DW_TAG_variable: return "DW_TAG_variable";
        case DwarfTag::DW_TAG_formal_parameter: return "DW_TAG_formal_parameter";
        case DwarfTag::DW_TAG_base_type: return "DW_TAG_base_type";
        case DwarfTag::DW_TAG_unspecified_type: return "DW_TAG_unspecified_type";
        case DwarfTag::DW_TAG_string_type: return "DW_TAG_string_type";
        case DwarfTag::DW_TAG_set_type: return "DW_TAG_set_type";
        case DwarfTag::DW_TAG_file_type: return "DW_TAG_file_type";
        case DwarfTag::DW_TAG_pointer_type: return "DW_TAG_pointer_type";
        case DwarfTag::DW_TAG_ptr_to_member_type: return "DW_TAG_ptr_to_member_type";
        case DwarfTag::DW_TAG_array_type: return "DW_TAG_array_type";
        case DwarfTag::DW_TAG_structure_type: return "DW_TAG_structure_type";
        case DwarfTag::DW_TAG_union_type: return "DW_TAG_union_type";
        case DwarfTag::DW_TAG_enumeration_type: return "DW_TAG_enumeration_type";
        case DwarfTag::DW_TAG_typedef: return "DW_TAG_typedef";
        case DwarfTag::DW_TAG_const_type: return "DW_TAG_const_type";
        case DwarfTag::DW_TAG_volatile_type: return "DW_TAG_volatile_type";
        case DwarfTag::DW_TAG_restrict_type: return "DW_TAG_restrict_type";
        case DwarfTag::DW_TAG_reference_type: return "DW_TAG_reference_type";
        case DwarfTag::DW_TAG_rvalue_reference_type: return "DW_TAG_rvalue_reference_type";
        case DwarfTag::DW_TAG_atomic_type: return "DW_TAG_atomic_type";
        case DwarfTag::DW_TAG_subrange_type: return "DW_TAG_subrange_type";
        case DwarfTag::DW_TAG_class_type: return "DW_TAG_class_type";
        case DwarfTag::DW_TAG_interface_type: return "DW_TAG_interface_type";
        case DwarfTag::DW_TAG_module: return "DW_TAG_module";
        case DwarfTag::DW_TAG_namespace: return "DW_TAG_namespace";
        case DwarfTag::DW_TAG_imported_unit: return "DW_TAG_imported_unit";
        case DwarfTag::DW_TAG_subroutine_type: return "DW_TAG_subroutine_type";
        case DwarfTag::DW_TAG_enumerator: return "DW_TAG_enumerator";
        case DwarfTag::DW_TAG_member: return "DW_TAG_member";
        case DwarfTag::DW_TAG_inheritance: return "DW_TAG_inheritance";
        case DwarfTag::DW_TAG_inlined_subroutine: return "DW_TAG_inlined_subroutine";
        case DwarfTag::DW_TAG_lexical_block: return "DW_TAG_lexical_block";
        case DwarfTag::DW_TAG_unspecified_parameters: return "DW_TAG_unspecified_parameters";
        default: return "DW_TAG_unknown_" + std::to_string(static_cast<int>(tag));
    }
}

DwarfTag DwarfUtils::stringToTag(const std::string& str) {
    if (str == "DW_TAG_imported_declaration") return DwarfTag::DW_TAG_imported_declaration;
    if (str == "DW_TAG_label") return DwarfTag::DW_TAG_label;
    if (str == "DW_TAG_compile_unit") return DwarfTag::DW_TAG_compile_unit;
    if (str == "DW_TAG_partial_unit") return DwarfTag::DW_TAG_partial_unit;
    if (str == "DW_TAG_type_unit") return DwarfTag::DW_TAG_type_unit;
    if (str == "DW_TAG_skeleton_unit") return DwarfTag::DW_TAG_skeleton_unit;
    if (str == "DW_TAG_split_compile_unit") return DwarfTag::DW_TAG_split_compile_unit;
    if (str == "DW_TAG_split_type_unit") return DwarfTag::DW_TAG_split_type_unit;
    if (str == "DW_TAG_subprogram") return DwarfTag::DW_TAG_subprogram;
    if (str == "DW_TAG_variable") return DwarfTag::DW_TAG_variable;
    if (str == "DW_TAG_formal_parameter") return DwarfTag::DW_TAG_formal_parameter;
    if (str == "DW_TAG_base_type") return DwarfTag::DW_TAG_base_type;
    if (str == "DW_TAG_unspecified_type") return DwarfTag::DW_TAG_unspecified_type;
    if (str == "DW_TAG_string_type") return DwarfTag::DW_TAG_string_type;
    if (str == "DW_TAG_set_type") return DwarfTag::DW_TAG_set_type;
    if (str == "DW_TAG_file_type") return DwarfTag::DW_TAG_file_type;
    if (str == "DW_TAG_pointer_type") return DwarfTag::DW_TAG_pointer_type;
    if (str == "DW_TAG_ptr_to_member_type") return DwarfTag::DW_TAG_ptr_to_member_type;
    if (str == "DW_TAG_array_type") return DwarfTag::DW_TAG_array_type;
    if (str == "DW_TAG_structure_type") return DwarfTag::DW_TAG_structure_type;
    if (str == "DW_TAG_union_type") return DwarfTag::DW_TAG_union_type;
    if (str == "DW_TAG_enumeration_type") return DwarfTag::DW_TAG_enumeration_type;
    if (str == "DW_TAG_typedef") return DwarfTag::DW_TAG_typedef;
    if (str == "DW_TAG_const_type") return DwarfTag::DW_TAG_const_type;
    if (str == "DW_TAG_volatile_type") return DwarfTag::DW_TAG_volatile_type;
    if (str == "DW_TAG_restrict_type") return DwarfTag::DW_TAG_restrict_type;
    if (str == "DW_TAG_reference_type") return DwarfTag::DW_TAG_reference_type;
    if (str == "DW_TAG_rvalue_reference_type") return DwarfTag::DW_TAG_rvalue_reference_type;
    if (str == "DW_TAG_atomic_type") return DwarfTag::DW_TAG_atomic_type;
    if (str == "DW_TAG_subrange_type") return DwarfTag::DW_TAG_subrange_type;
    if (str == "DW_TAG_class_type") return DwarfTag::DW_TAG_class_type;
    if (str == "DW_TAG_interface_type") return DwarfTag::DW_TAG_interface_type;
    if (str == "DW_TAG_module") return DwarfTag::DW_TAG_module;
    if (str == "DW_TAG_namespace") return DwarfTag::DW_TAG_namespace;
    if (str == "DW_TAG_imported_unit") return DwarfTag::DW_TAG_imported_unit;
    if (str == "DW_TAG_subroutine_type") return DwarfTag::DW_TAG_subroutine_type;
    if (str == "DW_TAG_enumerator") return DwarfTag::DW_TAG_enumerator;
    if (str == "DW_TAG_member") return DwarfTag::DW_TAG_member;
    if (str == "DW_TAG_inheritance") return DwarfTag::DW_TAG_inheritance;
    if (str == "DW_TAG_inlined_subroutine") return DwarfTag::DW_TAG_inlined_subroutine;
    if (str == "DW_TAG_lexical_block") return DwarfTag::DW_TAG_lexical_block;
    if (str == "DW_TAG_unspecified_parameters") return DwarfTag::DW_TAG_unspecified_parameters;
    return static_cast<DwarfTag>(0);
}

// Attribute name conversion
DwarfAttribute DwarfUtils::stringToAttribute(const std::string& str) {
    if (str == "DW_AT_sibling") return DwarfAttribute::DW_AT_sibling;
    if (str == "DW_AT_location") return DwarfAttribute::DW_AT_location;
    if (str == "DW_AT_name") return DwarfAttribute::DW_AT_name;
    if (str == "DW_AT_ordering") return DwarfAttribute::DW_AT_ordering;
    if (str == "DW_AT_byte_size") return DwarfAttribute::DW_AT_byte_size;
    if (str == "DW_AT_bit_offset") return DwarfAttribute::DW_AT_bit_offset;
    if (str == "DW_AT_bit_size") return DwarfAttribute::DW_AT_bit_size;
    if (str == "DW_AT_stmt_list") return DwarfAttribute::DW_AT_stmt_list;
    if (str == "DW_AT_type") return DwarfAttribute::DW_AT_type;
    if (str == "DW_AT_low_pc") return DwarfAttribute::DW_AT_low_pc;
    if (str == "DW_AT_high_pc") return DwarfAttribute::DW_AT_high_pc;
    if (str == "DW_AT_language") return DwarfAttribute::DW_AT_language;
    if (str == "DW_AT_discr") return DwarfAttribute::DW_AT_discr;
    if (str == "DW_AT_discr_value") return DwarfAttribute::DW_AT_discr_value;
    if (str == "DW_AT_visibility") return DwarfAttribute::DW_AT_visibility;
    if (str == "DW_AT_import") return DwarfAttribute::DW_AT_import;
    if (str == "DW_AT_string_length") return DwarfAttribute::DW_AT_string_length;
    if (str == "DW_AT_common_reference") return DwarfAttribute::DW_AT_common_reference;
    if (str == "DW_AT_comp_dir") return DwarfAttribute::DW_AT_comp_dir;
    if (str == "DW_AT_const_value") return DwarfAttribute::DW_AT_const_value;
    if (str == "DW_AT_containing_type") return DwarfAttribute::DW_AT_containing_type;
    if (str == "DW_AT_default_value") return DwarfAttribute::DW_AT_default_value;
    if (str == "DW_AT_inline") return DwarfAttribute::DW_AT_inline;
    if (str == "DW_AT_is_optional") return DwarfAttribute::DW_AT_is_optional;
    if (str == "DW_AT_lower_bound") return DwarfAttribute::DW_AT_lower_bound;
    if (str == "DW_AT_producer") return DwarfAttribute::DW_AT_producer;
    if (str == "DW_AT_prototyped") return DwarfAttribute::DW_AT_prototyped;
    if (str == "DW_AT_return_addr") return DwarfAttribute::DW_AT_return_addr;
    if (str == "DW_AT_start_scope") return DwarfAttribute::DW_AT_start_scope;
    if (str == "DW_AT_bit_stride") return DwarfAttribute::DW_AT_bit_stride;
    if (str == "DW_AT_upper_bound") return DwarfAttribute::DW_AT_upper_bound;
    if (str == "DW_AT_abstract_origin") return DwarfAttribute::DW_AT_abstract_origin;
    if (str == "DW_AT_accessibility") return DwarfAttribute::DW_AT_accessibility;
    if (str == "DW_AT_address_class") return DwarfAttribute::DW_AT_address_class;
    if (str == "DW_AT_artificial") return DwarfAttribute::DW_AT_artificial;
    if (str == "DW_AT_base_types") return DwarfAttribute::DW_AT_base_types;
    if (str == "DW_AT_calling_convention") return DwarfAttribute::DW_AT_calling_convention;
    if (str == "DW_AT_count") return DwarfAttribute::DW_AT_count;
    if (str == "DW_AT_data_member_location") return DwarfAttribute::DW_AT_data_member_location;
    if (str == "DW_AT_encoding") return DwarfAttribute::DW_AT_encoding;
    if (str == "DW_AT_decl_file") return DwarfAttribute::DW_AT_decl_file;
    if (str == "DW_AT_decl_line") return DwarfAttribute::DW_AT_decl_line;
    if (str == "DW_AT_decl_column") return DwarfAttribute::DW_AT_decl_column;
    if (str == "DW_AT_declaration") return DwarfAttribute::DW_AT_declaration;
    if (str == "DW_AT_discr_list") return DwarfAttribute::DW_AT_discr_list;
    if (str == "DW_AT_external") return DwarfAttribute::DW_AT_external;
    if (str == "DW_AT_frame_base") return DwarfAttribute::DW_AT_frame_base;
    if (str == "DW_AT_friend") return DwarfAttribute::DW_AT_friend;
    if (str == "DW_AT_identifier_case") return DwarfAttribute::DW_AT_identifier_case;
    if (str == "DW_AT_macro_info") return DwarfAttribute::DW_AT_macro_info;
    if (str == "DW_AT_namelist_item") return DwarfAttribute::DW_AT_namelist_item;
    if (str == "DW_AT_priority") return DwarfAttribute::DW_AT_priority;
    if (str == "DW_AT_segment") return DwarfAttribute::DW_AT_segment;
    if (str == "DW_AT_specification") return DwarfAttribute::DW_AT_specification;
    if (str == "DW_AT_static_link") return DwarfAttribute::DW_AT_static_link;
    if (str == "DW_AT_use_location") return DwarfAttribute::DW_AT_use_location;
    if (str == "DW_AT_variable_parameter") return DwarfAttribute::DW_AT_variable_parameter;
    if (str == "DW_AT_virtuality") return DwarfAttribute::DW_AT_virtuality;
    if (str == "DW_AT_vtable_elem_location") return DwarfAttribute::DW_AT_vtable_elem_location;
    if (str == "DW_AT_allocated") return DwarfAttribute::DW_AT_allocated;
    if (str == "DW_AT_associated") return DwarfAttribute::DW_AT_associated;
    if (str == "DW_AT_data_location") return DwarfAttribute::DW_AT_data_location;
    if (str == "DW_AT_byte_stride") return DwarfAttribute::DW_AT_byte_stride;
    if (str == "DW_AT_entry_pc") return DwarfAttribute::DW_AT_entry_pc;
    if (str == "DW_AT_use_UTF8") return DwarfAttribute::DW_AT_use_UTF8;
    if (str == "DW_AT_extension") return DwarfAttribute::DW_AT_extension;
    if (str == "DW_AT_ranges") return DwarfAttribute::DW_AT_ranges;
    if (str == "DW_AT_trampoline") return DwarfAttribute::DW_AT_trampoline;
    if (str == "DW_AT_call_column") return DwarfAttribute::DW_AT_call_column;
    if (str == "DW_AT_call_file") return DwarfAttribute::DW_AT_call_file;
    if (str == "DW_AT_call_line") return DwarfAttribute::DW_AT_call_line;
    if (str == "DW_AT_description") return DwarfAttribute::DW_AT_description;
    if (str == "DW_AT_binary_scale") return DwarfAttribute::DW_AT_binary_scale;
    if (str == "DW_AT_decimal_scale") return DwarfAttribute::DW_AT_decimal_scale;
    if (str == "DW_AT_small") return DwarfAttribute::DW_AT_small;
    if (str == "DW_AT_decimal_sign") return DwarfAttribute::DW_AT_decimal_sign;
    if (str == "DW_AT_digit_count") return DwarfAttribute::DW_AT_digit_count;
    if (str == "DW_AT_picture_string") return DwarfAttribute::DW_AT_picture_string;
    if (str == "DW_AT_mutable") return DwarfAttribute::DW_AT_mutable;
    if (str == "DW_AT_threads_scaled") return DwarfAttribute::DW_AT_threads_scaled;
    if (str == "DW_AT_explicit") return DwarfAttribute::DW_AT_explicit;
    if (str == "DW_AT_object_pointer") return DwarfAttribute::DW_AT_object_pointer;
    if (str == "DW_AT_endianity") return DwarfAttribute::DW_AT_endianity;
    if (str == "DW_AT_elemental") return DwarfAttribute::DW_AT_elemental;
    if (str == "DW_AT_pure") return DwarfAttribute::DW_AT_pure;
    if (str == "DW_AT_recursive") return DwarfAttribute::DW_AT_recursive;
    if (str == "DW_AT_signature") return DwarfAttribute::DW_AT_signature;
    if (str == "DW_AT_main_subprogram") return DwarfAttribute::DW_AT_main_subprogram;
    if (str == "DW_AT_data_bit_offset") return DwarfAttribute::DW_AT_data_bit_offset;
    if (str == "DW_AT_const_expr") return DwarfAttribute::DW_AT_const_expr;
    if (str == "DW_AT_enum_class") return DwarfAttribute::DW_AT_enum_class;
    if (str == "DW_AT_linkage_name") return DwarfAttribute::DW_AT_linkage_name;
    if (str == "DW_AT_addr_base") return DwarfAttribute::DW_AT_addr_base;
    if (str == "DW_AT_rnglists_base") return DwarfAttribute::DW_AT_rnglists_base;
    if (str == "DW_AT_loclists_base") return DwarfAttribute::DW_AT_loclists_base;
    if (str == "DW_AT_str_offsets_base") return DwarfAttribute::DW_AT_str_offsets_base;
    if (str == "DW_AT_reference") return DwarfAttribute::DW_AT_reference;
    if (str == "DW_AT_rvalue_reference") return DwarfAttribute::DW_AT_rvalue_reference;
    if (str == "DW_AT_macros") return DwarfAttribute::DW_AT_macros;
    if (str == "DW_AT_call_all_calls") return DwarfAttribute::DW_AT_call_all_calls;
    if (str == "DW_AT_call_all_source_calls") return DwarfAttribute::DW_AT_call_all_source_calls;
    if (str == "DW_AT_call_all_tail_calls") return DwarfAttribute::DW_AT_call_all_tail_calls;
    if (str == "DW_AT_call_return_pc") return DwarfAttribute::DW_AT_call_return_pc;
    if (str == "DW_AT_call_value") return DwarfAttribute::DW_AT_call_value;
    if (str == "DW_AT_call_origin") return DwarfAttribute::DW_AT_call_origin;
    if (str == "DW_AT_call_parameter") return DwarfAttribute::DW_AT_call_parameter;
    if (str == "DW_AT_dwo_name") return DwarfAttribute::DW_AT_dwo_name;
    if (str == "DW_AT_dwo_id") return DwarfAttribute::DW_AT_dwo_id;
    if (str == "DW_AT_GNU_dwo_name") return DwarfAttribute::DW_AT_GNU_dwo_name;
    if (str == "DW_AT_GNU_dwo_id") return DwarfAttribute::DW_AT_GNU_dwo_id;
    if (str == "DW_AT_volatile") return DwarfAttribute::DW_AT_volatile;
    return static_cast<DwarfAttribute>(0);
}

// Form name conversion
std::string DwarfUtils::formToString(DwarfForm form) {
    switch (form) {
        case DwarfForm::DW_FORM_addr: return "DW_FORM_addr";
        case DwarfForm::DW_FORM_block2: return "DW_FORM_block2";
        case DwarfForm::DW_FORM_block4: return "DW_FORM_block4";
        case DwarfForm::DW_FORM_data2: return "DW_FORM_data2";
        case DwarfForm::DW_FORM_data4: return "DW_FORM_data4";
        case DwarfForm::DW_FORM_data8: return "DW_FORM_data8";
        case DwarfForm::DW_FORM_string: return "DW_FORM_string";
        case DwarfForm::DW_FORM_block: return "DW_FORM_block";
        case DwarfForm::DW_FORM_block1: return "DW_FORM_block1";
        case DwarfForm::DW_FORM_data1: return "DW_FORM_data1";
        case DwarfForm::DW_FORM_flag: return "DW_FORM_flag";
        case DwarfForm::DW_FORM_sdata: return "DW_FORM_sdata";
        case DwarfForm::DW_FORM_strp: return "DW_FORM_strp";
        case DwarfForm::DW_FORM_udata: return "DW_FORM_udata";
        case DwarfForm::DW_FORM_ref_addr: return "DW_FORM_ref_addr";
        case DwarfForm::DW_FORM_ref1: return "DW_FORM_ref1";
        case DwarfForm::DW_FORM_ref2: return "DW_FORM_ref2";
        case DwarfForm::DW_FORM_ref4: return "DW_FORM_ref4";
        case DwarfForm::DW_FORM_ref8: return "DW_FORM_ref8";
        case DwarfForm::DW_FORM_ref_udata: return "DW_FORM_ref_udata";
        case DwarfForm::DW_FORM_indirect: return "DW_FORM_indirect";
        case DwarfForm::DW_FORM_sec_offset: return "DW_FORM_sec_offset";
        case DwarfForm::DW_FORM_exprloc: return "DW_FORM_exprloc";
        case DwarfForm::DW_FORM_flag_present: return "DW_FORM_flag_present";
        case DwarfForm::DW_FORM_strx: return "DW_FORM_strx";
        case DwarfForm::DW_FORM_addrx: return "DW_FORM_addrx";
        case DwarfForm::DW_FORM_ref_sup4: return "DW_FORM_ref_sup4";
        case DwarfForm::DW_FORM_strp_sup: return "DW_FORM_strp_sup";
        case DwarfForm::DW_FORM_data16: return "DW_FORM_data16";
        case DwarfForm::DW_FORM_line_strp: return "DW_FORM_line_strp";
        case DwarfForm::DW_FORM_ref_sig8: return "DW_FORM_ref_sig8";
        case DwarfForm::DW_FORM_implicit_const: return "DW_FORM_implicit_const";
        case DwarfForm::DW_FORM_loclistx: return "DW_FORM_loclistx";
        case DwarfForm::DW_FORM_rnglistx: return "DW_FORM_rnglistx";
        case DwarfForm::DW_FORM_ref_sup8: return "DW_FORM_ref_sup8";
        case DwarfForm::DW_FORM_strx1: return "DW_FORM_strx1";
        case DwarfForm::DW_FORM_strx2: return "DW_FORM_strx2";
        case DwarfForm::DW_FORM_strx3: return "DW_FORM_strx3";
        case DwarfForm::DW_FORM_strx4: return "DW_FORM_strx4";
        case DwarfForm::DW_FORM_addrx1: return "DW_FORM_addrx1";
        case DwarfForm::DW_FORM_addrx2: return "DW_FORM_addrx2";
        case DwarfForm::DW_FORM_addrx3: return "DW_FORM_addrx3";
        case DwarfForm::DW_FORM_addrx4: return "DW_FORM_addrx4";
        case DwarfForm::DW_FORM_GNU_addr_index: return "DW_FORM_GNU_addr_index";
        case DwarfForm::DW_FORM_GNU_str_index: return "DW_FORM_GNU_str_index";
        case DwarfForm::DW_FORM_GNU_ref_alt: return "DW_FORM_GNU_ref_alt";
        case DwarfForm::DW_FORM_GNU_strp_alt: return "DW_FORM_GNU_strp_alt";
        default:
            return "DW_FORM_unknown_" + std::to_string(static_cast<int>(form));
    }
}

DwarfForm DwarfUtils::stringToForm(const std::string& str) {
    if (str == "DW_FORM_addr") return DwarfForm::DW_FORM_addr;
    if (str == "DW_FORM_block2") return DwarfForm::DW_FORM_block2;
    if (str == "DW_FORM_block4") return DwarfForm::DW_FORM_block4;
    if (str == "DW_FORM_data2") return DwarfForm::DW_FORM_data2;
    if (str == "DW_FORM_data4") return DwarfForm::DW_FORM_data4;
    if (str == "DW_FORM_data8") return DwarfForm::DW_FORM_data8;
    if (str == "DW_FORM_string") return DwarfForm::DW_FORM_string;
    if (str == "DW_FORM_block") return DwarfForm::DW_FORM_block;
    if (str == "DW_FORM_block1") return DwarfForm::DW_FORM_block1;
    if (str == "DW_FORM_data1") return DwarfForm::DW_FORM_data1;
    if (str == "DW_FORM_flag") return DwarfForm::DW_FORM_flag;
    if (str == "DW_FORM_sdata") return DwarfForm::DW_FORM_sdata;
    if (str == "DW_FORM_strp") return DwarfForm::DW_FORM_strp;
    if (str == "DW_FORM_udata") return DwarfForm::DW_FORM_udata;
    if (str == "DW_FORM_ref_addr") return DwarfForm::DW_FORM_ref_addr;
    if (str == "DW_FORM_ref1") return DwarfForm::DW_FORM_ref1;
    if (str == "DW_FORM_ref2") return DwarfForm::DW_FORM_ref2;
    if (str == "DW_FORM_ref4") return DwarfForm::DW_FORM_ref4;
    if (str == "DW_FORM_ref8") return DwarfForm::DW_FORM_ref8;
    if (str == "DW_FORM_ref_udata") return DwarfForm::DW_FORM_ref_udata;
    if (str == "DW_FORM_indirect") return DwarfForm::DW_FORM_indirect;
    if (str == "DW_FORM_sec_offset") return DwarfForm::DW_FORM_sec_offset;
    if (str == "DW_FORM_exprloc") return DwarfForm::DW_FORM_exprloc;
    if (str == "DW_FORM_flag_present") return DwarfForm::DW_FORM_flag_present;
    if (str == "DW_FORM_strx") return DwarfForm::DW_FORM_strx;
    if (str == "DW_FORM_addrx") return DwarfForm::DW_FORM_addrx;
    if (str == "DW_FORM_ref_sup4") return DwarfForm::DW_FORM_ref_sup4;
    if (str == "DW_FORM_strp_sup") return DwarfForm::DW_FORM_strp_sup;
    if (str == "DW_FORM_data16") return DwarfForm::DW_FORM_data16;
    if (str == "DW_FORM_line_strp") return DwarfForm::DW_FORM_line_strp;
    if (str == "DW_FORM_ref_sig8") return DwarfForm::DW_FORM_ref_sig8;
    if (str == "DW_FORM_implicit_const") return DwarfForm::DW_FORM_implicit_const;
    if (str == "DW_FORM_loclistx") return DwarfForm::DW_FORM_loclistx;
    if (str == "DW_FORM_rnglistx") return DwarfForm::DW_FORM_rnglistx;
    if (str == "DW_FORM_ref_sup8") return DwarfForm::DW_FORM_ref_sup8;
    if (str == "DW_FORM_strx1") return DwarfForm::DW_FORM_strx1;
    if (str == "DW_FORM_strx2") return DwarfForm::DW_FORM_strx2;
    if (str == "DW_FORM_strx3") return DwarfForm::DW_FORM_strx3;
    if (str == "DW_FORM_strx4") return DwarfForm::DW_FORM_strx4;
    if (str == "DW_FORM_addrx1") return DwarfForm::DW_FORM_addrx1;
    if (str == "DW_FORM_addrx2") return DwarfForm::DW_FORM_addrx2;
    if (str == "DW_FORM_addrx3") return DwarfForm::DW_FORM_addrx3;
    if (str == "DW_FORM_addrx4") return DwarfForm::DW_FORM_addrx4;
    if (str == "DW_FORM_GNU_addr_index") return DwarfForm::DW_FORM_GNU_addr_index;
    if (str == "DW_FORM_GNU_str_index") return DwarfForm::DW_FORM_GNU_str_index;
    if (str == "DW_FORM_GNU_ref_alt") return DwarfForm::DW_FORM_GNU_ref_alt;
    if (str == "DW_FORM_GNU_strp_alt") return DwarfForm::DW_FORM_GNU_strp_alt;
    return static_cast<DwarfForm>(0);
}

// Operation name conversion
DwarfOp DwarfUtils::stringToOperation(const std::string& str) {
    if (str == "DW_OP_addr") return DwarfOp::DW_OP_addr;
    if (str == "DW_OP_deref") return DwarfOp::DW_OP_deref;
    if (str == "DW_OP_const1u") return DwarfOp::DW_OP_const1u;
    if (str == "DW_OP_const1s") return DwarfOp::DW_OP_const1s;
    if (str == "DW_OP_const2u") return DwarfOp::DW_OP_const2u;
    if (str == "DW_OP_const2s") return DwarfOp::DW_OP_const2s;
    if (str == "DW_OP_const4u") return DwarfOp::DW_OP_const4u;
    if (str == "DW_OP_const4s") return DwarfOp::DW_OP_const4s;
    if (str == "DW_OP_const8u") return DwarfOp::DW_OP_const8u;
    if (str == "DW_OP_const8s") return DwarfOp::DW_OP_const8s;
    if (str == "DW_OP_constu") return DwarfOp::DW_OP_constu;
    if (str == "DW_OP_consts") return DwarfOp::DW_OP_consts;
    if (str == "DW_OP_dup") return DwarfOp::DW_OP_dup;
    if (str == "DW_OP_drop") return DwarfOp::DW_OP_drop;
    if (str == "DW_OP_over") return DwarfOp::DW_OP_over;
    if (str == "DW_OP_pick") return DwarfOp::DW_OP_pick;
    if (str == "DW_OP_swap") return DwarfOp::DW_OP_swap;
    if (str == "DW_OP_rot") return DwarfOp::DW_OP_rot;
    if (str == "DW_OP_xderef") return DwarfOp::DW_OP_xderef;
    if (str == "DW_OP_abs") return DwarfOp::DW_OP_abs;
    if (str == "DW_OP_and") return DwarfOp::DW_OP_and;
    if (str == "DW_OP_div") return DwarfOp::DW_OP_div;
    if (str == "DW_OP_minus") return DwarfOp::DW_OP_minus;
    if (str == "DW_OP_mod") return DwarfOp::DW_OP_mod;
    if (str == "DW_OP_mul") return DwarfOp::DW_OP_mul;
    if (str == "DW_OP_neg") return DwarfOp::DW_OP_neg;
    if (str == "DW_OP_not") return DwarfOp::DW_OP_not;
    if (str == "DW_OP_or") return DwarfOp::DW_OP_or;
    if (str == "DW_OP_plus") return DwarfOp::DW_OP_plus;
    if (str == "DW_OP_plus_uconst") return DwarfOp::DW_OP_plus_uconst;
    if (str == "DW_OP_shl") return DwarfOp::DW_OP_shl;
    if (str == "DW_OP_shr") return DwarfOp::DW_OP_shr;
    if (str == "DW_OP_shra") return DwarfOp::DW_OP_shra;
    if (str == "DW_OP_xor") return DwarfOp::DW_OP_xor;
    if (str == "DW_OP_bra") return DwarfOp::DW_OP_bra;
    if (str == "DW_OP_eq") return DwarfOp::DW_OP_eq;
    if (str == "DW_OP_ge") return DwarfOp::DW_OP_ge;
    if (str == "DW_OP_gt") return DwarfOp::DW_OP_gt;
    if (str == "DW_OP_le") return DwarfOp::DW_OP_le;
    if (str == "DW_OP_lt") return DwarfOp::DW_OP_lt;
    if (str == "DW_OP_ne") return DwarfOp::DW_OP_ne;
    if (str == "DW_OP_skip") return DwarfOp::DW_OP_skip;
    if (str == "DW_OP_regx") return DwarfOp::DW_OP_regx;
    if (str == "DW_OP_bregx") return DwarfOp::DW_OP_bregx;
    if (str == "DW_OP_fbreg") return DwarfOp::DW_OP_fbreg;
    if (str == "DW_OP_piece") return DwarfOp::DW_OP_piece;
    if (str == "DW_OP_deref_size") return DwarfOp::DW_OP_deref_size;
    if (str == "DW_OP_xderef_size") return DwarfOp::DW_OP_xderef_size;
    if (str == "DW_OP_nop") return DwarfOp::DW_OP_nop;
    if (str == "DW_OP_push_object_address") return DwarfOp::DW_OP_push_object_address;
    if (str == "DW_OP_bit_piece") return DwarfOp::DW_OP_bit_piece;
    if (str == "DW_OP_implicit_value") return DwarfOp::DW_OP_implicit_value;
    if (str == "DW_OP_stack_value") return DwarfOp::DW_OP_stack_value;
    if (str == "DW_OP_implicit_pointer") return DwarfOp::DW_OP_implicit_pointer;
    if (str == "DW_OP_call2") return DwarfOp::DW_OP_call2;
    if (str == "DW_OP_call4") return DwarfOp::DW_OP_call4;
    if (str == "DW_OP_call_ref") return DwarfOp::DW_OP_call_ref;
    if (str == "DW_OP_form_tls_address") return DwarfOp::DW_OP_form_tls_address;
    if (str == "DW_OP_call_frame_cfa") return DwarfOp::DW_OP_call_frame_cfa;
    if (str == "DW_OP_addrx") return DwarfOp::DW_OP_addrx;
    if (str == "DW_OP_constx") return DwarfOp::DW_OP_constx;
    if (str == "DW_OP_entry_value") return DwarfOp::DW_OP_entry_value;
    if (str == "DW_OP_const_type") return DwarfOp::DW_OP_const_type;
    if (str == "DW_OP_regval_type") return DwarfOp::DW_OP_regval_type;
    if (str == "DW_OP_deref_type") return DwarfOp::DW_OP_deref_type;
    if (str == "DW_OP_xderef_type") return DwarfOp::DW_OP_xderef_type;
    if (str == "DW_OP_convert") return DwarfOp::DW_OP_convert;
    if (str == "DW_OP_reinterpret") return DwarfOp::DW_OP_reinterpret;
    if (str == "DW_OP_GNU_push_tls_address") return DwarfOp::DW_OP_GNU_push_tls_address;
    if (str == "DW_OP_WASM_location") return DwarfOp::DW_OP_WASM_location;
    if (str == "DW_OP_GNU_uninit") return DwarfOp::DW_OP_GNU_uninit;
    if (str == "DW_OP_GNU_encoded_addr") return DwarfOp::DW_OP_GNU_encoded_addr;
    if (str == "DW_OP_GNU_implicit_pointer") return DwarfOp::DW_OP_GNU_implicit_pointer;
    if (str == "DW_OP_GNU_entry_value") return DwarfOp::DW_OP_GNU_entry_value;
    if (str == "DW_OP_GNU_const_type") return DwarfOp::DW_OP_GNU_const_type;
    if (str == "DW_OP_GNU_regval_type") return DwarfOp::DW_OP_GNU_regval_type;
    if (str == "DW_OP_GNU_deref_type") return DwarfOp::DW_OP_GNU_deref_type;
    if (str == "DW_OP_GNU_convert") return DwarfOp::DW_OP_GNU_convert;
    if (str == "DW_OP_GNU_reinterpret") return DwarfOp::DW_OP_GNU_reinterpret;
    if (str == "DW_OP_GNU_parameter_ref") return DwarfOp::DW_OP_GNU_parameter_ref;
    if (str == "DW_OP_GNU_addr_index") return DwarfOp::DW_OP_GNU_addr_index;
    if (str == "DW_OP_GNU_const_index") return DwarfOp::DW_OP_GNU_const_index;

    auto parseIndexed = [&](const char* prefix, uint8_t base, uint8_t max) -> DwarfOp {
        const std::string p(prefix);
        if (str.rfind(p, 0) != 0) return static_cast<DwarfOp>(0);
        const std::string tail = str.substr(p.size());
        if (tail.empty()) return static_cast<DwarfOp>(0);
        try {
            size_t consumed = 0;
            const unsigned long n = std::stoul(tail, &consumed, 10);
            if (consumed != tail.size() || n > max) return static_cast<DwarfOp>(0);
            return static_cast<DwarfOp>(base + static_cast<uint8_t>(n));
        } catch (...) {
            return static_cast<DwarfOp>(0);
        }
    };

    if (auto op = parseIndexed("DW_OP_lit", static_cast<uint8_t>(DwarfOp::DW_OP_lit0), 31);
        op != static_cast<DwarfOp>(0)) {
        return op;
    }
    if (auto op = parseIndexed("DW_OP_reg", static_cast<uint8_t>(DwarfOp::DW_OP_reg0), 31);
        op != static_cast<DwarfOp>(0)) {
        return op;
    }
    if (auto op = parseIndexed("DW_OP_breg", static_cast<uint8_t>(DwarfOp::DW_OP_breg0), 31);
        op != static_cast<DwarfOp>(0)) {
        return op;
    }

    return static_cast<DwarfOp>(0);
}

const std::vector<DwarfOp>& DwarfUtils::knownGnuExtensionOperations() {
    static const std::vector<DwarfOp> kKnownGnuOps = {
        DwarfOp::DW_OP_GNU_push_tls_address,
        DwarfOp::DW_OP_GNU_uninit,
        DwarfOp::DW_OP_GNU_encoded_addr,
        DwarfOp::DW_OP_GNU_implicit_pointer,
        DwarfOp::DW_OP_GNU_entry_value,
        DwarfOp::DW_OP_GNU_const_type,
        DwarfOp::DW_OP_GNU_regval_type,
        DwarfOp::DW_OP_GNU_deref_type,
        DwarfOp::DW_OP_GNU_convert,
        DwarfOp::DW_OP_GNU_reinterpret,
        DwarfOp::DW_OP_GNU_parameter_ref,
        DwarfOp::DW_OP_GNU_addr_index,
        DwarfOp::DW_OP_GNU_const_index,
    };
    return kKnownGnuOps;
}

bool DwarfUtils::isKnownGnuExtensionOperation(DwarfOp op) {
    const auto& known = knownGnuExtensionOperations();
    return std::find(known.begin(), known.end(), op) != known.end();
}

// Endianness handling
uint16_t DwarfUtils::swapBytes(uint16_t value) {
    return static_cast<uint16_t>((value >> 8) | (value << 8));
}

uint32_t DwarfUtils::swapBytes(uint32_t value) {
    return ((value & 0x000000ffU) << 24) |
           ((value & 0x0000ff00U) << 8) |
           ((value & 0x00ff0000U) >> 8) |
           ((value & 0xff000000U) >> 24);
}

uint64_t DwarfUtils::swapBytes(uint64_t value) {
    return ((value & 0x00000000000000ffULL) << 56) |
           ((value & 0x000000000000ff00ULL) << 40) |
           ((value & 0x0000000000ff0000ULL) << 24) |
           ((value & 0x00000000ff000000ULL) << 8) |
           ((value & 0x000000ff00000000ULL) >> 8) |
           ((value & 0x0000ff0000000000ULL) >> 24) |
           ((value & 0x00ff000000000000ULL) >> 40) |
           ((value & 0xff00000000000000ULL) >> 56);
}

// Data reading utilities
uint64_t DwarfUtils::readULEB128(const uint8_t* data, uint64_t& offset, size_t max_offset) {
    uint64_t result = 0;
    int shift = 0;
    
    while (offset < max_offset) {
        uint8_t byte = data[offset++];
        result |= (byte & 0x7F) << shift;
        
        if ((byte & 0x80) == 0) {
            break;
        }
        
        shift += 7;
    }
    
    return result;
}

int64_t DwarfUtils::readSLEB128(const uint8_t* data, uint64_t& offset, size_t max_offset) {
    uint64_t result = 0;
    int shift = 0;
    uint8_t byte = 0;

    while (offset < max_offset) {
        byte = data[offset++];
        result |= static_cast<uint64_t>(byte & 0x7F) << shift;
        shift += 7;

        if ((byte & 0x80) == 0) {
            break;
        }
    }

    // Sign extend using the current shift (total bits consumed).
    if (shift < 64 && (byte & 0x40)) {
        result |= ~0ULL << shift;
    }

    return static_cast<int64_t>(result);
}

uint8_t DwarfUtils::readU8(const uint8_t* data, uint64_t& offset, size_t max_offset) {
    if (offset >= max_offset) return 0;
    return data[offset++];
}

uint16_t DwarfUtils::readU16(const uint8_t* data, uint64_t& offset, size_t max_offset) {
    if (offset + 1 >= max_offset) return 0;
    uint16_t result;
    if (isLittleEndian()) {
        result = static_cast<uint16_t>(data[offset]) |
                 (static_cast<uint16_t>(data[offset + 1]) << 8);
    } else {
        result = (static_cast<uint16_t>(data[offset]) << 8) |
                 static_cast<uint16_t>(data[offset + 1]);
    }
    offset += 2;
    return result;
}

uint32_t DwarfUtils::readU32(const uint8_t* data, uint64_t& offset, size_t max_offset) {
    if (offset + 3 >= max_offset) return 0;
    uint32_t result;
    if (isLittleEndian()) {
        result = static_cast<uint32_t>(data[offset]) |
                 (static_cast<uint32_t>(data[offset + 1]) << 8) |
                 (static_cast<uint32_t>(data[offset + 2]) << 16) |
                 (static_cast<uint32_t>(data[offset + 3]) << 24);
    } else {
        result = (static_cast<uint32_t>(data[offset]) << 24) |
                 (static_cast<uint32_t>(data[offset + 1]) << 16) |
                 (static_cast<uint32_t>(data[offset + 2]) << 8) |
                 static_cast<uint32_t>(data[offset + 3]);
    }
    offset += 4;
    return result;
}

uint64_t DwarfUtils::readU64(const uint8_t* data, uint64_t& offset, size_t max_offset) {
    if (offset + 7 >= max_offset) return 0;
    uint64_t result = 0;
    if (isLittleEndian()) {
        result = static_cast<uint64_t>(data[offset]) |
                 (static_cast<uint64_t>(data[offset + 1]) << 8) |
                 (static_cast<uint64_t>(data[offset + 2]) << 16) |
                 (static_cast<uint64_t>(data[offset + 3]) << 24) |
                 (static_cast<uint64_t>(data[offset + 4]) << 32) |
                 (static_cast<uint64_t>(data[offset + 5]) << 40) |
                 (static_cast<uint64_t>(data[offset + 6]) << 48) |
                 (static_cast<uint64_t>(data[offset + 7]) << 56);
    } else {
        for (int i = 0; i < 8; ++i) {
            result = (result << 8) | static_cast<uint64_t>(data[offset + i]);
        }
    }
    offset += 8;
    return result;
}

// String utilities
std::string DwarfUtils::formatAddress(uint64_t address, bool hex) {
    if (hex) {
        std::stringstream ss;
        ss << "0x" << std::hex << std::uppercase << address;
        return ss.str();
    }
    return std::to_string(address);
}

std::string DwarfUtils::formatOffset(uint64_t offset, bool hex) {
    return formatAddress(offset, hex);
}

std::string DwarfUtils::formatSize(uint64_t size, bool hex) {
    return formatAddress(size, hex);
}

// Validation utilities
bool DwarfUtils::isValidTag(DwarfTag tag) {
    return tag != static_cast<DwarfTag>(0);
}

bool DwarfUtils::isValidAttribute(DwarfAttribute attr) {
    return attr != static_cast<DwarfAttribute>(0);
}

bool DwarfUtils::isValidForm(DwarfForm form) {
    return form != static_cast<DwarfForm>(0);
}

bool DwarfUtils::isValidOperation(DwarfOp op) {
    return op != static_cast<DwarfOp>(0);
}

// Type utilities
bool DwarfUtils::isTypeTag(DwarfTag tag) {
    switch (tag) {
        case DwarfTag::DW_TAG_base_type:
        case DwarfTag::DW_TAG_unspecified_type:
        case DwarfTag::DW_TAG_string_type:
        case DwarfTag::DW_TAG_set_type:
        case DwarfTag::DW_TAG_file_type:
        case DwarfTag::DW_TAG_pointer_type:
        case DwarfTag::DW_TAG_ptr_to_member_type:
        case DwarfTag::DW_TAG_array_type:
        case DwarfTag::DW_TAG_structure_type:
        case DwarfTag::DW_TAG_union_type:
        case DwarfTag::DW_TAG_enumeration_type:
        case DwarfTag::DW_TAG_typedef:
        case DwarfTag::DW_TAG_const_type:
        case DwarfTag::DW_TAG_volatile_type:
        case DwarfTag::DW_TAG_restrict_type:
        case DwarfTag::DW_TAG_reference_type:
        case DwarfTag::DW_TAG_rvalue_reference_type:
        case DwarfTag::DW_TAG_atomic_type:
        case DwarfTag::DW_TAG_subrange_type:
        case DwarfTag::DW_TAG_class_type:
        case DwarfTag::DW_TAG_interface_type:
        case DwarfTag::DW_TAG_subroutine_type:
            return true;
        default:
            return false;
    }
}

bool DwarfUtils::isSubprogramTag(DwarfTag tag) {
    return tag == DwarfTag::DW_TAG_subprogram;
}

bool DwarfUtils::isVariableTag(DwarfTag tag) {
    return tag == DwarfTag::DW_TAG_variable || tag == DwarfTag::DW_TAG_formal_parameter;
}

bool DwarfUtils::isScopeTag(DwarfTag tag) {
    switch (tag) {
        case DwarfTag::DW_TAG_compile_unit:
        case DwarfTag::DW_TAG_subprogram:
        case DwarfTag::DW_TAG_lexical_block:
        case DwarfTag::DW_TAG_inlined_subroutine:
            return true;
        default:
            return false;
    }
}

// File utilities
bool DwarfUtils::fileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

std::string DwarfUtils::getFileExtension(const std::string& filename) {
    size_t pos = filename.find_last_of('.');
    if (pos == std::string::npos) return "";
    return filename.substr(pos + 1);
}

// Size utilities
size_t DwarfUtils::getFormSize(DwarfForm form, const uint8_t* data, size_t offset, size_t max_offset) {
    return getFormSize(form, data, offset, max_offset, SizeContext{});
}

size_t DwarfUtils::getFormSize(DwarfForm form,
                               const uint8_t* data,
                               size_t offset,
                               size_t max_offset,
                               const SizeContext& ctx) {
    if (!data || offset >= max_offset) return 0;
    auto avail = [&](size_t n) -> bool { return offset + n <= max_offset; };

    switch (form) {
        case DwarfForm::DW_FORM_flag_present:
        case DwarfForm::DW_FORM_implicit_const:
            return 0;

        case DwarfForm::DW_FORM_data1:
        case DwarfForm::DW_FORM_flag:
        case DwarfForm::DW_FORM_ref1:
        case DwarfForm::DW_FORM_strx1:
        case DwarfForm::DW_FORM_addrx1:
            return (max_offset - offset >= 1) ? 1 : (max_offset - offset);

        case DwarfForm::DW_FORM_data2:
        case DwarfForm::DW_FORM_ref2:
        case DwarfForm::DW_FORM_strx2:
        case DwarfForm::DW_FORM_addrx2:
            return (max_offset - offset >= 2) ? 2 : (max_offset - offset);

        case DwarfForm::DW_FORM_data4:
        case DwarfForm::DW_FORM_ref4:
        case DwarfForm::DW_FORM_ref_sup4:
        case DwarfForm::DW_FORM_strx4:
        case DwarfForm::DW_FORM_addrx4:
            return (max_offset - offset >= 4) ? 4 : (max_offset - offset);

        case DwarfForm::DW_FORM_data8:
        case DwarfForm::DW_FORM_ref8:
        case DwarfForm::DW_FORM_ref_sig8:
        case DwarfForm::DW_FORM_ref_sup8:
            return (max_offset - offset >= 8) ? 8 : (max_offset - offset);

        case DwarfForm::DW_FORM_data16:
            return (max_offset - offset >= 16) ? 16 : (max_offset - offset);

        case DwarfForm::DW_FORM_string: {
            size_t i = offset;
            while (i < max_offset && data[i] != 0) ++i;
            if (i >= max_offset) return max_offset - offset;
            return (i - offset) + 1;
        }

        case DwarfForm::DW_FORM_block1: {
            if (!avail(1)) return 0;
            uint8_t len = data[offset];
            return 1 + std::min<size_t>(len, max_offset - (offset + 1));
        }

        case DwarfForm::DW_FORM_block2: {
            if (!avail(2)) return 0;
            uint64_t tmp = offset;
            uint16_t len = readU16(data, tmp, max_offset);
            return 2 + std::min<size_t>(len, max_offset - (offset + 2));
        }

        case DwarfForm::DW_FORM_block4: {
            if (!avail(4)) return 0;
            uint64_t tmp = offset;
            uint32_t len = readU32(data, tmp, max_offset);
            return 4 + std::min<size_t>(len, max_offset - (offset + 4));
        }

        case DwarfForm::DW_FORM_block:
        case DwarfForm::DW_FORM_exprloc: {
            uint64_t tmp = offset;
            uint64_t len = readULEB128(data, tmp, max_offset);
            size_t leb = static_cast<size_t>(tmp - offset);
            size_t payload = static_cast<size_t>(std::min<uint64_t>(len, (max_offset > tmp) ? (max_offset - tmp) : 0));
            return leb + payload;
        }

        case DwarfForm::DW_FORM_udata:
        case DwarfForm::DW_FORM_sdata:
        case DwarfForm::DW_FORM_ref_udata:
        case DwarfForm::DW_FORM_strx:
        case DwarfForm::DW_FORM_GNU_str_index:
        case DwarfForm::DW_FORM_addrx:
        case DwarfForm::DW_FORM_GNU_addr_index:
        case DwarfForm::DW_FORM_loclistx:
        case DwarfForm::DW_FORM_rnglistx: {
            uint64_t tmp = offset;
            (void)readULEB128(data, tmp, max_offset);
            return static_cast<size_t>(tmp - offset);
        }

        case DwarfForm::DW_FORM_indirect: {
            // Indirect form: uleb form code followed by that form.
            uint64_t tmp = offset;
            uint64_t f = readULEB128(data, tmp, max_offset);
            size_t head = static_cast<size_t>(tmp - offset);
            size_t tail = getFormSize(static_cast<DwarfForm>(f),
                                      data,
                                      static_cast<size_t>(tmp),
                                      max_offset,
                                      ctx);
            return head + tail;
        }

        // Forms whose size depends on DWARF32/64 or address size. Without CU context,
        // choose conservative defaults (DWARF32 / 4-byte address/offset) when ambiguous.
        case DwarfForm::DW_FORM_addr: {
            const size_t n = (ctx.address_size == 8) ? 8 : 4;
            return (max_offset - offset >= n) ? n : (max_offset - offset);
        }
        case DwarfForm::DW_FORM_strp:
        case DwarfForm::DW_FORM_line_strp:
        case DwarfForm::DW_FORM_sec_offset:
        case DwarfForm::DW_FORM_strp_sup:
        case DwarfForm::DW_FORM_GNU_strp_alt:
        case DwarfForm::DW_FORM_GNU_ref_alt: {
            const size_t n = (ctx.offset_size == 8) ? 8 : 4;
            return (max_offset - offset >= n) ? n : (max_offset - offset);
        }
        case DwarfForm::DW_FORM_ref_addr: {
            const uint8_t ref_size = (ctx.ref_addr_size == 0)
                ? (ctx.ref_addr_uses_address_size ? ctx.address_size : ctx.offset_size)
                : ctx.ref_addr_size;
            const size_t n = (ref_size == 8) ? 8 : 4;
            return (max_offset - offset >= n) ? n : (max_offset - offset);
        }

        case DwarfForm::DW_FORM_strx3:
        case DwarfForm::DW_FORM_addrx3:
            return (max_offset - offset >= 3) ? 3 : (max_offset - offset);

        default:
            return 0;
    }
}

static size_t lebSize(const uint8_t* data, size_t offset, size_t max_offset) {
    size_t i = offset;
    while (i < max_offset) {
        uint8_t b = data[i++];
        if ((b & 0x80) == 0) break;
    }
    return (i >= offset) ? (i - offset) : 0;
}

size_t DwarfUtils::getOperationSize(DwarfOp op, const uint8_t* data, size_t offset, size_t max_offset) {
    return getOperationSize(op, data, offset, max_offset, SizeContext{});
}

size_t DwarfUtils::getOperationSize(DwarfOp op,
                                    const uint8_t* data,
                                    size_t offset,
                                    size_t max_offset,
                                    const SizeContext& ctx) {
    if (!data || offset >= max_offset) return 0;

    // offset points to the first byte *after* the opcode in most callers.
    // This utility expects offset to be the start of operands (same convention).
    switch (op) {
        case DwarfOp::DW_OP_addr:
            {
                const size_t n = (ctx.address_size == 8) ? 8 : 4;
                return (max_offset - offset >= n) ? n : (max_offset - offset);
            }
        case DwarfOp::DW_OP_const1u:
        case DwarfOp::DW_OP_const1s:
        case DwarfOp::DW_OP_deref_size:
        case DwarfOp::DW_OP_xderef_size:
            return 1;
        case DwarfOp::DW_OP_const2u:
        case DwarfOp::DW_OP_const2s:
        case DwarfOp::DW_OP_bra:
        case DwarfOp::DW_OP_skip:
        case DwarfOp::DW_OP_call2:
            return (max_offset - offset >= 2) ? 2 : (max_offset - offset);
        case DwarfOp::DW_OP_const4u:
        case DwarfOp::DW_OP_const4s:
        case DwarfOp::DW_OP_call4:
            return (max_offset - offset >= 4) ? 4 : (max_offset - offset);
        case DwarfOp::DW_OP_const8u:
        case DwarfOp::DW_OP_const8s:
            // Fixed-width 8-byte immediates; on truncation consume remaining bytes.
            return (max_offset - offset >= 8) ? 8 : (max_offset - offset);

        case DwarfOp::DW_OP_constu:
        case DwarfOp::DW_OP_consts:
        case DwarfOp::DW_OP_regx:
        case DwarfOp::DW_OP_fbreg:
        case DwarfOp::DW_OP_piece:
        case DwarfOp::DW_OP_plus_uconst:
        case DwarfOp::DW_OP_addrx:
        case DwarfOp::DW_OP_constx:
        case DwarfOp::DW_OP_GNU_addr_index:
        case DwarfOp::DW_OP_GNU_const_index:
        case DwarfOp::DW_OP_convert:
        case DwarfOp::DW_OP_reinterpret:
        case DwarfOp::DW_OP_GNU_convert:
        case DwarfOp::DW_OP_GNU_reinterpret:
            return lebSize(data, offset, max_offset);

        case DwarfOp::DW_OP_bregx: {
            size_t a = lebSize(data, offset, max_offset);
            size_t b = lebSize(data, offset + a, max_offset);
            return a + b;
        }

        case DwarfOp::DW_OP_entry_value:
        case DwarfOp::DW_OP_GNU_entry_value: {
            size_t a = lebSize(data, offset, max_offset);
            uint64_t tmp = offset;
            uint64_t n = readULEB128(data, tmp, max_offset);
            size_t payload = static_cast<size_t>(std::min<uint64_t>(n, (max_offset > tmp) ? (max_offset - tmp) : 0));
            return a + payload;
        }

        case DwarfOp::DW_OP_implicit_value: {
            size_t a = lebSize(data, offset, max_offset);
            uint64_t tmp = offset;
            uint64_t n = readULEB128(data, tmp, max_offset);
            size_t payload = static_cast<size_t>(std::min<uint64_t>(n, (max_offset > tmp) ? (max_offset - tmp) : 0));
            return a + payload;
        }

        case DwarfOp::DW_OP_WASM_location: {
            // WebAssembly extension opcode:
            //   u8 wasm_location_type followed by optional ULEB index for local/global/stack.
            size_t remaining = (max_offset > offset) ? (max_offset - offset) : 0;
            if (remaining == 0) return 0;
            uint8_t kind = data[offset];
            size_t size = 1; // location type byte
            if (kind <= 0x02) {
                size += lebSize(data, offset + 1, max_offset);
            }
            return std::min(size, remaining);
        }

        case DwarfOp::DW_OP_bit_piece: {
            size_t a = lebSize(data, offset, max_offset);
            size_t b = lebSize(data, offset + a, max_offset);
            return a + b;
        }

        case DwarfOp::DW_OP_const_type:
        case DwarfOp::DW_OP_deref_type:
        case DwarfOp::DW_OP_xderef_type:
        case DwarfOp::DW_OP_regval_type:
        case DwarfOp::DW_OP_GNU_const_type:
        case DwarfOp::DW_OP_GNU_deref_type:
        case DwarfOp::DW_OP_GNU_regval_type: {
            // Typed ops: uleb type/ref + other operands.
            // Best-effort sizes based on spec encodings.
            if (op == DwarfOp::DW_OP_regval_type || op == DwarfOp::DW_OP_GNU_regval_type) {
                size_t a = lebSize(data, offset, max_offset);        // reg
                size_t b = lebSize(data, offset + a, max_offset);    // type
                return a + b;
            }
            if (op == DwarfOp::DW_OP_const_type || op == DwarfOp::DW_OP_GNU_const_type) {
                size_t a = lebSize(data, offset, max_offset);        // type
                if (offset + a >= max_offset) return a;
                uint8_t sz = data[offset + a];                       // 1-byte size
                size_t payload = std::min<size_t>(sz, (max_offset > (offset + a + 1)) ? (max_offset - (offset + a + 1)) : 0);
                return a + 1 + payload;
            }
            // deref_type / xderef_type and GNU_deref_type: 1-byte size + uleb type
            if (max_offset - offset < 1) return 0;
            size_t b = lebSize(data, offset + 1, max_offset);
            return 1 + b;
        }

        case DwarfOp::DW_OP_implicit_pointer:
        case DwarfOp::DW_OP_GNU_implicit_pointer: {
            // Ref-sized DIE offset, followed by SLEB128 displacement.
            size_t remaining = (max_offset > offset) ? (max_offset - offset) : 0;
            const size_t ref_size = (ctx.offset_size == 8) ? 8 : 4;
            if (remaining < ref_size) return remaining;
            size_t sleb = lebSize(data, offset + ref_size, max_offset);
            return ref_size + sleb;
        }

        case DwarfOp::DW_OP_GNU_encoded_addr: {
            // 1-byte encoding selector, then encoded payload.
            if (offset >= max_offset) return 0;
            const uint8_t encoding = data[offset];
            const uint8_t format = static_cast<uint8_t>(encoding & 0x0f);
            const uint8_t application = static_cast<uint8_t>(encoding & 0x70);
            const size_t value_off = offset + 1;
            size_t aligned_value_off = value_off;
            if (application == 0x50) {
                const size_t align = (ctx.address_size == 8) ? 8u : 4u;
                const size_t rem = value_off % align;
                if (rem != 0) aligned_value_off += (align - rem);
            }
            const size_t pad = aligned_value_off - value_off;
            size_t payload = 0;
            switch (format) {
                case 0x00: // DW_EH_PE_absptr
                    payload = (max_offset > aligned_value_off)
                        ? std::min<size_t>((ctx.address_size == 8) ? 8 : 4, max_offset - aligned_value_off)
                        : 0;
                    break;
                case 0x01: // DW_EH_PE_uleb128
                case 0x09: // DW_EH_PE_sleb128
                    payload = lebSize(data, aligned_value_off, max_offset);
                    break;
                case 0x02: // DW_EH_PE_udata2
                case 0x0a: // DW_EH_PE_sdata2
                    payload = (max_offset - aligned_value_off >= 2) ? 2 : (max_offset - aligned_value_off);
                    break;
                case 0x03: // DW_EH_PE_udata4
                case 0x0b: // DW_EH_PE_sdata4
                    payload = (max_offset - aligned_value_off >= 4) ? 4 : (max_offset - aligned_value_off);
                    break;
                case 0x04: // DW_EH_PE_udata8
                case 0x0c: // DW_EH_PE_sdata8
                    payload = (max_offset - aligned_value_off >= 8) ? 8 : (max_offset - aligned_value_off);
                    break;
                default:
                    // Unknown/unsupported encoding: conservative best-effort.
                    payload = (max_offset > aligned_value_off)
                        ? std::min<size_t>((ctx.address_size == 8) ? 8 : 4, max_offset - aligned_value_off)
                        : 0;
                    break;
            }
            return 1 + pad + payload;
        }

        case DwarfOp::DW_OP_call_ref:
            {
                const size_t n = (ctx.offset_size == 8) ? 8 : 4;
                return (max_offset - offset >= n) ? n : (max_offset - offset);
            }
        case DwarfOp::DW_OP_GNU_parameter_ref:
            {
                const size_t n = (ctx.offset_size == 8) ? 8 : 4;
                return (max_offset - offset >= n) ? n : (max_offset - offset);
            }

        // Most ops have no operands.
        default:
            return 0;
    }
}

// Debug utilities
std::string DwarfUtils::hexDump(const uint8_t* data, size_t size, size_t offset) {
    if (!data || offset >= size) return "";
    std::ostringstream oss;
    const size_t end = size;
    for (size_t i = offset; i < end; i += 16) {
        oss << std::hex << std::setw(8) << std::setfill('0') << i << ": ";
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < end) {
                oss << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(data[i + j]) << " ";
            } else {
                oss << "   ";
            }
        }
        oss << " ";
        for (size_t j = 0; j < 16 && i + j < end; ++j) {
            unsigned char c = data[i + j];
            oss << ((c >= 0x20 && c <= 0x7e) ? static_cast<char>(c) : '.');
        }
        if (i + 16 < end) oss << "\n";
    }
    return oss.str();
}

std::string DwarfUtils::hexDump(const std::vector<uint8_t>& data, size_t offset) {
    return hexDump(data.data(), data.size(), offset);
}

void DwarfUtils::printHexDump(const uint8_t* data, size_t size, size_t offset) {
    std::cout << hexDump(data, size, offset) << std::endl;
}

void DwarfUtils::printHexDump(const std::vector<uint8_t>& data, size_t offset) {
    std::cout << hexDump(data, offset) << std::endl;
}

// Expression utilities
std::vector<std::string> DwarfUtils::expressionToTokens(const std::vector<uint8_t>& expression) {
    return expressionToTokens(expression, SizeContext{});
}

std::optional<DwarfUtils::PreservedAttributePayload> DwarfUtils::decodePreservedPayloadAttribute(
    DwarfAttribute attr, const std::shared_ptr<AttributeValue>& value) {
    return decodePreservedPayloadAttribute(attr, value, SizeContext{});
}

std::optional<DwarfUtils::PreservedAttributePayload> DwarfUtils::decodePreservedPayloadAttribute(
    DwarfAttribute attr, const std::shared_ptr<AttributeValue>& value, const SizeContext& ctx) {
    switch (attr) {
        case DwarfAttribute::DW_AT_call_value:
        case DwarfAttribute::DW_AT_call_parameter:
        case DwarfAttribute::DW_AT_discr_list:
            break;
        default:
            return std::nullopt;
    }

    if (!value) {
        return std::nullopt;
    }

    if (auto expr = std::dynamic_pointer_cast<ExpressionAttributeValue>(value)) {
        PreservedAttributePayload payload;
        payload.kind = PreservedAttributePayload::Kind::EXPRESSION;
        payload.bytes = expr->getExpression();
        payload.tokens = expressionToTokens(payload.bytes, ctx);
        return payload;
    }

    if (auto block = std::dynamic_pointer_cast<BlockAttributeValue>(value)) {
        PreservedAttributePayload payload;
        payload.kind = PreservedAttributePayload::Kind::BLOCK;
        payload.bytes = block->getData();
        payload.tokens = expressionToTokens(payload.bytes, ctx);
        return payload;
    }

    return std::nullopt;
}

std::optional<DwarfUtils::DecodedPayloadSemantics> DwarfUtils::decodeCallSitePayloadAttribute(
    DwarfAttribute attr, const std::shared_ptr<AttributeValue>& value) {
    return decodeCallSitePayloadAttribute(attr, value, SizeContext{});
}

std::optional<DwarfUtils::DecodedPayloadSemantics> DwarfUtils::decodeCallSitePayloadAttribute(
    DwarfAttribute attr, const std::shared_ptr<AttributeValue>& value, const SizeContext& ctx) {
    switch (attr) {
        case DwarfAttribute::DW_AT_call_value:
        case DwarfAttribute::DW_AT_call_parameter:
            break;
        default:
            return std::nullopt;
    }

    auto payload = decodePreservedPayloadAttribute(attr, value, ctx);
    if (!payload) {
        return std::nullopt;
    }

    DecodedPayloadSemantics decoded;
    decoded.attribute = attr;
    decoded.payload_kind = payload->kind;
    decoded.bytes = payload->bytes;
    decoded.tokens = payload->tokens;
    decoded.assembly = expressionToAssembly(decoded.bytes, ctx);
    return decoded;
}

std::optional<DwarfUtils::DecodedPayloadSemantics> DwarfUtils::decodeDiscriminantPayloadAttribute(
    DwarfAttribute attr, const std::shared_ptr<AttributeValue>& value) {
    return decodeDiscriminantPayloadAttribute(attr, value, SizeContext{});
}

std::optional<DwarfUtils::DecodedPayloadSemantics> DwarfUtils::decodeDiscriminantPayloadAttribute(
    DwarfAttribute attr, const std::shared_ptr<AttributeValue>& value, const SizeContext& ctx) {
    if (attr != DwarfAttribute::DW_AT_discr_list) {
        return std::nullopt;
    }

    auto payload = decodePreservedPayloadAttribute(attr, value, ctx);
    if (!payload) {
        return std::nullopt;
    }

    DecodedPayloadSemantics decoded;
    decoded.attribute = attr;
    decoded.payload_kind = payload->kind;
    decoded.bytes = payload->bytes;
    decoded.tokens = payload->tokens;
    decoded.assembly = expressionToAssembly(decoded.bytes, ctx);
    return decoded;
}

std::vector<std::string> DwarfUtils::expressionToTokens(const std::vector<uint8_t>& expression,
                                                        const SizeContext& ctx) {
    std::vector<std::string> out;
    size_t off = 0;
    while (off < expression.size()) {
        DwarfOp op = static_cast<DwarfOp>(expression[off++]);
        std::string tok = operationToString(op);
        size_t opsz = getOperationSize(op, expression.data(), off, expression.size(), ctx);

        if (op == DwarfOp::DW_OP_WASM_location && opsz > 0) {
            size_t operand_off = off;
            uint8_t kind = expression[operand_off];
            const char* kind_name = "unknown";
            switch (kind) {
                case 0x00: kind_name = "local"; break;
                case 0x01: kind_name = "global"; break;
                case 0x02: kind_name = "stack"; break;
                default: break;
            }

            std::ostringstream ss;
            ss << tok << "(kind=" << kind_name;

            if (kind <= 0x02 && opsz > 1) {
                uint64_t tmp = static_cast<uint64_t>(operand_off + 1);
                uint64_t end = static_cast<uint64_t>(std::min(expression.size(), operand_off + opsz));
                uint64_t idx = readULEB128(expression.data(), tmp, end);
                ss << ",index=" << idx;
            }
            ss << ")";
            tok = ss.str();
        }

        out.push_back(tok);
        off = std::min(expression.size(), off + opsz);
    }
    return out;
}

std::string DwarfUtils::expressionToAssembly(const std::vector<uint8_t>& expression) {
    return expressionToAssembly(expression, SizeContext{});
}

std::string DwarfUtils::expressionToAssembly(const std::vector<uint8_t>& expression,
                                             const SizeContext& ctx) {
    std::ostringstream oss;
    auto toks = expressionToTokens(expression, ctx);
    for (size_t i = 0; i < toks.size(); ++i) {
        if (i) oss << " ";
        oss << toks[i];
    }
    return oss.str();
}

bool DwarfUtils::isElfFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return false;
    
    char magic[4];
    file.read(magic, 4);
    return magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F';
}

bool DwarfUtils::isDwarfFile(const std::string& filename) {
    return isElfFile(filename); // For now, assume ELF files with DWARF
}

// Error handling
std::string DwarfUtils::getLastError() {
    return last_error_;
}


void DwarfUtils::setLastError(const std::string& error) {
    last_error_ = error;
}

void DwarfUtils::clearLastError() {
    last_error_.clear();
}


std::string DwarfUtils::attributeToString(DwarfAttribute attr) {
    switch (attr) {
        case DwarfAttribute::DW_AT_sibling: return "DW_AT_sibling";
        case DwarfAttribute::DW_AT_location: return "DW_AT_location";
        case DwarfAttribute::DW_AT_name: return "DW_AT_name";
        case DwarfAttribute::DW_AT_ordering: return "DW_AT_ordering";
        case DwarfAttribute::DW_AT_byte_size: return "DW_AT_byte_size";
        case DwarfAttribute::DW_AT_bit_offset: return "DW_AT_bit_offset";
        case DwarfAttribute::DW_AT_bit_size: return "DW_AT_bit_size";
        case DwarfAttribute::DW_AT_stmt_list: return "DW_AT_stmt_list";
        case DwarfAttribute::DW_AT_type: return "DW_AT_type";
        case DwarfAttribute::DW_AT_low_pc: return "DW_AT_low_pc";
        case DwarfAttribute::DW_AT_high_pc: return "DW_AT_high_pc";
        case DwarfAttribute::DW_AT_language: return "DW_AT_language";
        case DwarfAttribute::DW_AT_discr: return "DW_AT_discr";
        case DwarfAttribute::DW_AT_discr_value: return "DW_AT_discr_value";
        case DwarfAttribute::DW_AT_visibility: return "DW_AT_visibility";
        case DwarfAttribute::DW_AT_import: return "DW_AT_import";
        case DwarfAttribute::DW_AT_string_length: return "DW_AT_string_length";
        case DwarfAttribute::DW_AT_common_reference: return "DW_AT_common_reference";
        case DwarfAttribute::DW_AT_comp_dir: return "DW_AT_comp_dir";
        case DwarfAttribute::DW_AT_const_value: return "DW_AT_const_value";
        case DwarfAttribute::DW_AT_containing_type: return "DW_AT_containing_type";
        case DwarfAttribute::DW_AT_default_value: return "DW_AT_default_value";
        case DwarfAttribute::DW_AT_inline: return "DW_AT_inline";
        case DwarfAttribute::DW_AT_is_optional: return "DW_AT_is_optional";
        case DwarfAttribute::DW_AT_lower_bound: return "DW_AT_lower_bound";
        case DwarfAttribute::DW_AT_producer: return "DW_AT_producer";
        case DwarfAttribute::DW_AT_prototyped: return "DW_AT_prototyped";
        case DwarfAttribute::DW_AT_return_addr: return "DW_AT_return_addr";
        case DwarfAttribute::DW_AT_start_scope: return "DW_AT_start_scope";
        case DwarfAttribute::DW_AT_bit_stride: return "DW_AT_bit_stride";
        case DwarfAttribute::DW_AT_upper_bound: return "DW_AT_upper_bound";
        case DwarfAttribute::DW_AT_abstract_origin: return "DW_AT_abstract_origin";
        case DwarfAttribute::DW_AT_accessibility: return "DW_AT_accessibility";
        case DwarfAttribute::DW_AT_address_class: return "DW_AT_address_class";
        case DwarfAttribute::DW_AT_artificial: return "DW_AT_artificial";
        case DwarfAttribute::DW_AT_base_types: return "DW_AT_base_types";
        case DwarfAttribute::DW_AT_calling_convention: return "DW_AT_calling_convention";
        case DwarfAttribute::DW_AT_count: return "DW_AT_count";
        case DwarfAttribute::DW_AT_data_member_location: return "DW_AT_data_member_location";
        case DwarfAttribute::DW_AT_encoding: return "DW_AT_encoding";
        case DwarfAttribute::DW_AT_decl_file: return "DW_AT_decl_file";
        case DwarfAttribute::DW_AT_decl_line: return "DW_AT_decl_line";
        case DwarfAttribute::DW_AT_decl_column: return "DW_AT_decl_column";
        case DwarfAttribute::DW_AT_declaration: return "DW_AT_declaration";
        case DwarfAttribute::DW_AT_discr_list: return "DW_AT_discr_list";
        case DwarfAttribute::DW_AT_external: return "DW_AT_external";
        case DwarfAttribute::DW_AT_frame_base: return "DW_AT_frame_base";
        case DwarfAttribute::DW_AT_friend: return "DW_AT_friend";
        case DwarfAttribute::DW_AT_identifier_case: return "DW_AT_identifier_case";
        case DwarfAttribute::DW_AT_macro_info: return "DW_AT_macro_info";
        case DwarfAttribute::DW_AT_namelist_item: return "DW_AT_namelist_item";
        case DwarfAttribute::DW_AT_priority: return "DW_AT_priority";
        case DwarfAttribute::DW_AT_segment: return "DW_AT_segment";
        case DwarfAttribute::DW_AT_specification: return "DW_AT_specification";
        case DwarfAttribute::DW_AT_static_link: return "DW_AT_static_link";
        case DwarfAttribute::DW_AT_use_location: return "DW_AT_use_location";
        case DwarfAttribute::DW_AT_variable_parameter: return "DW_AT_variable_parameter";
        case DwarfAttribute::DW_AT_virtuality: return "DW_AT_virtuality";
        case DwarfAttribute::DW_AT_vtable_elem_location: return "DW_AT_vtable_elem_location";
        case DwarfAttribute::DW_AT_allocated: return "DW_AT_allocated";
        case DwarfAttribute::DW_AT_associated: return "DW_AT_associated";
        case DwarfAttribute::DW_AT_data_location: return "DW_AT_data_location";
        case DwarfAttribute::DW_AT_byte_stride: return "DW_AT_byte_stride";
        case DwarfAttribute::DW_AT_entry_pc: return "DW_AT_entry_pc";
        case DwarfAttribute::DW_AT_use_UTF8: return "DW_AT_use_UTF8";
        case DwarfAttribute::DW_AT_extension: return "DW_AT_extension";
        case DwarfAttribute::DW_AT_ranges: return "DW_AT_ranges";
        case DwarfAttribute::DW_AT_trampoline: return "DW_AT_trampoline";
        case DwarfAttribute::DW_AT_call_column: return "DW_AT_call_column";
        case DwarfAttribute::DW_AT_call_file: return "DW_AT_call_file";
        case DwarfAttribute::DW_AT_call_line: return "DW_AT_call_line";
        case DwarfAttribute::DW_AT_description: return "DW_AT_description";
        case DwarfAttribute::DW_AT_binary_scale: return "DW_AT_binary_scale";
        case DwarfAttribute::DW_AT_decimal_scale: return "DW_AT_decimal_scale";
        case DwarfAttribute::DW_AT_small: return "DW_AT_small";
        case DwarfAttribute::DW_AT_decimal_sign: return "DW_AT_decimal_sign";
        case DwarfAttribute::DW_AT_digit_count: return "DW_AT_digit_count";
        case DwarfAttribute::DW_AT_picture_string: return "DW_AT_picture_string";
        case DwarfAttribute::DW_AT_mutable: return "DW_AT_mutable";
        case DwarfAttribute::DW_AT_threads_scaled: return "DW_AT_threads_scaled";
        case DwarfAttribute::DW_AT_explicit: return "DW_AT_explicit";
        case DwarfAttribute::DW_AT_object_pointer: return "DW_AT_object_pointer";
        case DwarfAttribute::DW_AT_endianity: return "DW_AT_endianity";
        case DwarfAttribute::DW_AT_elemental: return "DW_AT_elemental";
        case DwarfAttribute::DW_AT_pure: return "DW_AT_pure";
        case DwarfAttribute::DW_AT_recursive: return "DW_AT_recursive";
        case DwarfAttribute::DW_AT_signature: return "DW_AT_signature";
        case DwarfAttribute::DW_AT_main_subprogram: return "DW_AT_main_subprogram";
        case DwarfAttribute::DW_AT_data_bit_offset: return "DW_AT_data_bit_offset";
        case DwarfAttribute::DW_AT_const_expr: return "DW_AT_const_expr";
        case DwarfAttribute::DW_AT_enum_class: return "DW_AT_enum_class";
        case DwarfAttribute::DW_AT_linkage_name: return "DW_AT_linkage_name";
        case DwarfAttribute::DW_AT_addr_base: return "DW_AT_addr_base";
        case DwarfAttribute::DW_AT_rnglists_base: return "DW_AT_rnglists_base";
        case DwarfAttribute::DW_AT_loclists_base: return "DW_AT_loclists_base";
        case DwarfAttribute::DW_AT_str_offsets_base: return "DW_AT_str_offsets_base";
        case DwarfAttribute::DW_AT_reference: return "DW_AT_reference";
        case DwarfAttribute::DW_AT_rvalue_reference: return "DW_AT_rvalue_reference";
        case DwarfAttribute::DW_AT_macros: return "DW_AT_macros";
        case DwarfAttribute::DW_AT_call_all_calls: return "DW_AT_call_all_calls";
        case DwarfAttribute::DW_AT_call_all_source_calls: return "DW_AT_call_all_source_calls";
        case DwarfAttribute::DW_AT_call_all_tail_calls: return "DW_AT_call_all_tail_calls";
        case DwarfAttribute::DW_AT_call_return_pc: return "DW_AT_call_return_pc";
        case DwarfAttribute::DW_AT_call_value: return "DW_AT_call_value";
        case DwarfAttribute::DW_AT_call_origin: return "DW_AT_call_origin";
        case DwarfAttribute::DW_AT_call_parameter: return "DW_AT_call_parameter";
        case DwarfAttribute::DW_AT_dwo_name: return "DW_AT_dwo_name";
        case DwarfAttribute::DW_AT_dwo_id: return "DW_AT_dwo_id";
        case DwarfAttribute::DW_AT_GNU_dwo_name: return "DW_AT_GNU_dwo_name";
        case DwarfAttribute::DW_AT_GNU_dwo_id: return "DW_AT_GNU_dwo_id";
        case DwarfAttribute::DW_AT_volatile: return "DW_AT_volatile";
        default: return "DW_AT_unknown_" + std::to_string(static_cast<int>(attr));
    }
}

std::string DwarfUtils::operationToString(DwarfOp op) {
    switch (op) {
        case DwarfOp::DW_OP_addr: return "DW_OP_addr";
        case DwarfOp::DW_OP_deref: return "DW_OP_deref";
        case DwarfOp::DW_OP_const1u: return "DW_OP_const1u";
        case DwarfOp::DW_OP_const1s: return "DW_OP_const1s";
        case DwarfOp::DW_OP_const2u: return "DW_OP_const2u";
        case DwarfOp::DW_OP_const2s: return "DW_OP_const2s";
        case DwarfOp::DW_OP_const4u: return "DW_OP_const4u";
        case DwarfOp::DW_OP_const4s: return "DW_OP_const4s";
        case DwarfOp::DW_OP_const8u: return "DW_OP_const8u";
        case DwarfOp::DW_OP_const8s: return "DW_OP_const8s";
        case DwarfOp::DW_OP_constu: return "DW_OP_constu";
        case DwarfOp::DW_OP_consts: return "DW_OP_consts";
        case DwarfOp::DW_OP_dup: return "DW_OP_dup";
        case DwarfOp::DW_OP_drop: return "DW_OP_drop";
        case DwarfOp::DW_OP_over: return "DW_OP_over";
        case DwarfOp::DW_OP_pick: return "DW_OP_pick";
        case DwarfOp::DW_OP_swap: return "DW_OP_swap";
        case DwarfOp::DW_OP_rot: return "DW_OP_rot";
        case DwarfOp::DW_OP_xderef: return "DW_OP_xderef";
        case DwarfOp::DW_OP_abs: return "DW_OP_abs";
        case DwarfOp::DW_OP_and: return "DW_OP_and";
        case DwarfOp::DW_OP_div: return "DW_OP_div";
        case DwarfOp::DW_OP_minus: return "DW_OP_minus";
        case DwarfOp::DW_OP_mod: return "DW_OP_mod";
        case DwarfOp::DW_OP_mul: return "DW_OP_mul";
        case DwarfOp::DW_OP_neg: return "DW_OP_neg";
        case DwarfOp::DW_OP_not: return "DW_OP_not";
        case DwarfOp::DW_OP_or: return "DW_OP_or";
        case DwarfOp::DW_OP_plus: return "DW_OP_plus";
        case DwarfOp::DW_OP_plus_uconst: return "DW_OP_plus_uconst";
        case DwarfOp::DW_OP_shl: return "DW_OP_shl";
        case DwarfOp::DW_OP_shr: return "DW_OP_shr";
        case DwarfOp::DW_OP_shra: return "DW_OP_shra";
        case DwarfOp::DW_OP_xor: return "DW_OP_xor";
        case DwarfOp::DW_OP_bra: return "DW_OP_bra";
        case DwarfOp::DW_OP_eq: return "DW_OP_eq";
        case DwarfOp::DW_OP_ge: return "DW_OP_ge";
        case DwarfOp::DW_OP_gt: return "DW_OP_gt";
        case DwarfOp::DW_OP_le: return "DW_OP_le";
        case DwarfOp::DW_OP_lt: return "DW_OP_lt";
        case DwarfOp::DW_OP_ne: return "DW_OP_ne";
        case DwarfOp::DW_OP_skip: return "DW_OP_skip";
        case DwarfOp::DW_OP_lit0: return "DW_OP_lit0";
        case DwarfOp::DW_OP_lit1: return "DW_OP_lit1";
        case DwarfOp::DW_OP_lit2: return "DW_OP_lit2";
        case DwarfOp::DW_OP_lit3: return "DW_OP_lit3";
        case DwarfOp::DW_OP_lit4: return "DW_OP_lit4";
        case DwarfOp::DW_OP_lit5: return "DW_OP_lit5";
        case DwarfOp::DW_OP_lit6: return "DW_OP_lit6";
        case DwarfOp::DW_OP_lit7: return "DW_OP_lit7";
        case DwarfOp::DW_OP_lit8: return "DW_OP_lit8";
        case DwarfOp::DW_OP_lit9: return "DW_OP_lit9";
        case DwarfOp::DW_OP_lit10: return "DW_OP_lit10";
        case DwarfOp::DW_OP_lit11: return "DW_OP_lit11";
        case DwarfOp::DW_OP_lit12: return "DW_OP_lit12";
        case DwarfOp::DW_OP_lit13: return "DW_OP_lit13";
        case DwarfOp::DW_OP_lit14: return "DW_OP_lit14";
        case DwarfOp::DW_OP_lit15: return "DW_OP_lit15";
        case DwarfOp::DW_OP_lit16: return "DW_OP_lit16";
        case DwarfOp::DW_OP_lit17: return "DW_OP_lit17";
        case DwarfOp::DW_OP_lit18: return "DW_OP_lit18";
        case DwarfOp::DW_OP_lit19: return "DW_OP_lit19";
        case DwarfOp::DW_OP_lit20: return "DW_OP_lit20";
        case DwarfOp::DW_OP_lit21: return "DW_OP_lit21";
        case DwarfOp::DW_OP_lit22: return "DW_OP_lit22";
        case DwarfOp::DW_OP_lit23: return "DW_OP_lit23";
        case DwarfOp::DW_OP_lit24: return "DW_OP_lit24";
        case DwarfOp::DW_OP_lit25: return "DW_OP_lit25";
        case DwarfOp::DW_OP_lit26: return "DW_OP_lit26";
        case DwarfOp::DW_OP_lit27: return "DW_OP_lit27";
        case DwarfOp::DW_OP_lit28: return "DW_OP_lit28";
        case DwarfOp::DW_OP_lit29: return "DW_OP_lit29";
        case DwarfOp::DW_OP_lit30: return "DW_OP_lit30";
        case DwarfOp::DW_OP_lit31: return "DW_OP_lit31";
        case DwarfOp::DW_OP_reg0: return "DW_OP_reg0";
        case DwarfOp::DW_OP_reg1: return "DW_OP_reg1";
        case DwarfOp::DW_OP_reg2: return "DW_OP_reg2";
        case DwarfOp::DW_OP_reg3: return "DW_OP_reg3";
        case DwarfOp::DW_OP_reg4: return "DW_OP_reg4";
        case DwarfOp::DW_OP_reg5: return "DW_OP_reg5";
        case DwarfOp::DW_OP_reg6: return "DW_OP_reg6";
        case DwarfOp::DW_OP_reg7: return "DW_OP_reg7";
        case DwarfOp::DW_OP_reg8: return "DW_OP_reg8";
        case DwarfOp::DW_OP_reg9: return "DW_OP_reg9";
        case DwarfOp::DW_OP_reg10: return "DW_OP_reg10";
        case DwarfOp::DW_OP_reg11: return "DW_OP_reg11";
        case DwarfOp::DW_OP_reg12: return "DW_OP_reg12";
        case DwarfOp::DW_OP_reg13: return "DW_OP_reg13";
        case DwarfOp::DW_OP_reg14: return "DW_OP_reg14";
        case DwarfOp::DW_OP_reg15: return "DW_OP_reg15";
        case DwarfOp::DW_OP_reg16: return "DW_OP_reg16";
        case DwarfOp::DW_OP_reg17: return "DW_OP_reg17";
        case DwarfOp::DW_OP_reg18: return "DW_OP_reg18";
        case DwarfOp::DW_OP_reg19: return "DW_OP_reg19";
        case DwarfOp::DW_OP_reg20: return "DW_OP_reg20";
        case DwarfOp::DW_OP_reg21: return "DW_OP_reg21";
        case DwarfOp::DW_OP_reg22: return "DW_OP_reg22";
        case DwarfOp::DW_OP_reg23: return "DW_OP_reg23";
        case DwarfOp::DW_OP_reg24: return "DW_OP_reg24";
        case DwarfOp::DW_OP_reg25: return "DW_OP_reg25";
        case DwarfOp::DW_OP_reg26: return "DW_OP_reg26";
        case DwarfOp::DW_OP_reg27: return "DW_OP_reg27";
        case DwarfOp::DW_OP_reg28: return "DW_OP_reg28";
        case DwarfOp::DW_OP_reg29: return "DW_OP_reg29";
        case DwarfOp::DW_OP_reg30: return "DW_OP_reg30";
        case DwarfOp::DW_OP_reg31: return "DW_OP_reg31";
        case DwarfOp::DW_OP_breg0: return "DW_OP_breg0";
        case DwarfOp::DW_OP_breg1: return "DW_OP_breg1";
        case DwarfOp::DW_OP_breg2: return "DW_OP_breg2";
        case DwarfOp::DW_OP_breg3: return "DW_OP_breg3";
        case DwarfOp::DW_OP_breg4: return "DW_OP_breg4";
        case DwarfOp::DW_OP_breg5: return "DW_OP_breg5";
        case DwarfOp::DW_OP_breg6: return "DW_OP_breg6";
        case DwarfOp::DW_OP_breg7: return "DW_OP_breg7";
        case DwarfOp::DW_OP_breg8: return "DW_OP_breg8";
        case DwarfOp::DW_OP_breg9: return "DW_OP_breg9";
        case DwarfOp::DW_OP_breg10: return "DW_OP_breg10";
        case DwarfOp::DW_OP_breg11: return "DW_OP_breg11";
        case DwarfOp::DW_OP_breg12: return "DW_OP_breg12";
        case DwarfOp::DW_OP_breg13: return "DW_OP_breg13";
        case DwarfOp::DW_OP_breg14: return "DW_OP_breg14";
        case DwarfOp::DW_OP_breg15: return "DW_OP_breg15";
        case DwarfOp::DW_OP_breg16: return "DW_OP_breg16";
        case DwarfOp::DW_OP_breg17: return "DW_OP_breg17";
        case DwarfOp::DW_OP_breg18: return "DW_OP_breg18";
        case DwarfOp::DW_OP_breg19: return "DW_OP_breg19";
        case DwarfOp::DW_OP_breg20: return "DW_OP_breg20";
        case DwarfOp::DW_OP_breg21: return "DW_OP_breg21";
        case DwarfOp::DW_OP_breg22: return "DW_OP_breg22";
        case DwarfOp::DW_OP_breg23: return "DW_OP_breg23";
        case DwarfOp::DW_OP_breg24: return "DW_OP_breg24";
        case DwarfOp::DW_OP_breg25: return "DW_OP_breg25";
        case DwarfOp::DW_OP_breg26: return "DW_OP_breg26";
        case DwarfOp::DW_OP_breg27: return "DW_OP_breg27";
        case DwarfOp::DW_OP_breg28: return "DW_OP_breg28";
        case DwarfOp::DW_OP_breg29: return "DW_OP_breg29";
        case DwarfOp::DW_OP_breg30: return "DW_OP_breg30";
        case DwarfOp::DW_OP_breg31: return "DW_OP_breg31";
        case DwarfOp::DW_OP_regx: return "DW_OP_regx";
        case DwarfOp::DW_OP_fbreg: return "DW_OP_fbreg";
        case DwarfOp::DW_OP_bregx: return "DW_OP_bregx";
        case DwarfOp::DW_OP_piece: return "DW_OP_piece";
        case DwarfOp::DW_OP_deref_size: return "DW_OP_deref_size";
        case DwarfOp::DW_OP_xderef_size: return "DW_OP_xderef_size";
        case DwarfOp::DW_OP_nop: return "DW_OP_nop";
        case DwarfOp::DW_OP_push_object_address: return "DW_OP_push_object_address";
        case DwarfOp::DW_OP_call2: return "DW_OP_call2";
        case DwarfOp::DW_OP_call4: return "DW_OP_call4";
        case DwarfOp::DW_OP_call_ref: return "DW_OP_call_ref";
        case DwarfOp::DW_OP_form_tls_address: return "DW_OP_form_tls_address";
        case DwarfOp::DW_OP_call_frame_cfa: return "DW_OP_call_frame_cfa";
        case DwarfOp::DW_OP_bit_piece: return "DW_OP_bit_piece";
        case DwarfOp::DW_OP_implicit_value: return "DW_OP_implicit_value";
        case DwarfOp::DW_OP_stack_value: return "DW_OP_stack_value";
        case DwarfOp::DW_OP_implicit_pointer: return "DW_OP_implicit_pointer";
        case DwarfOp::DW_OP_addrx: return "DW_OP_addrx";
        case DwarfOp::DW_OP_constx: return "DW_OP_constx";
        case DwarfOp::DW_OP_entry_value: return "DW_OP_entry_value";
        case DwarfOp::DW_OP_const_type: return "DW_OP_const_type";
        case DwarfOp::DW_OP_regval_type: return "DW_OP_regval_type";
        case DwarfOp::DW_OP_deref_type: return "DW_OP_deref_type";
        case DwarfOp::DW_OP_xderef_type: return "DW_OP_xderef_type";
        case DwarfOp::DW_OP_convert: return "DW_OP_convert";
        case DwarfOp::DW_OP_reinterpret: return "DW_OP_reinterpret";
        case DwarfOp::DW_OP_GNU_push_tls_address: return "DW_OP_GNU_push_tls_address";
        case DwarfOp::DW_OP_WASM_location: return "DW_OP_WASM_location";
        case DwarfOp::DW_OP_GNU_uninit: return "DW_OP_GNU_uninit";
        case DwarfOp::DW_OP_GNU_encoded_addr: return "DW_OP_GNU_encoded_addr";
        case DwarfOp::DW_OP_GNU_implicit_pointer: return "DW_OP_GNU_implicit_pointer";
        case DwarfOp::DW_OP_GNU_entry_value: return "DW_OP_GNU_entry_value";
        case DwarfOp::DW_OP_GNU_const_type: return "DW_OP_GNU_const_type";
        case DwarfOp::DW_OP_GNU_regval_type: return "DW_OP_GNU_regval_type";
        case DwarfOp::DW_OP_GNU_deref_type: return "DW_OP_GNU_deref_type";
        case DwarfOp::DW_OP_GNU_convert: return "DW_OP_GNU_convert";
        case DwarfOp::DW_OP_GNU_reinterpret: return "DW_OP_GNU_reinterpret";
        case DwarfOp::DW_OP_GNU_parameter_ref: return "DW_OP_GNU_parameter_ref";
        case DwarfOp::DW_OP_GNU_addr_index: return "DW_OP_GNU_addr_index";
        case DwarfOp::DW_OP_GNU_const_index: return "DW_OP_GNU_const_index";
        default: {
            std::ostringstream oss;
            oss << "DW_OP_unknown_0x"
                << std::hex << std::nouppercase << static_cast<unsigned>(static_cast<uint8_t>(op));
            return oss.str();
        }
    }
}

// Range query helpers

bool DwarfUtils::isAddressInRanges(uint64_t address, const std::vector<AddressRange>& ranges) {
    for (const auto& range : ranges) {
        if (range.contains(address)) {
            return true;
        }
    }
    return false;
}

std::vector<DwarfUtils::AddressRange> DwarfUtils::getRangesContainingAddress(
    uint64_t address, const std::vector<AddressRange>& ranges) {
    std::vector<AddressRange> result;
    for (const auto& range : ranges) {
        if (range.contains(address)) {
            result.push_back(range);
        }
    }
    return result;
}

std::vector<DwarfUtils::AddressRange> DwarfUtils::mergeOverlappingRanges(
    const std::vector<AddressRange>& ranges) {
    if (ranges.empty()) {
        return {};
    }

    // Filter out base address entries and sort by start address
    std::vector<AddressRange> sorted;
    for (const auto& range : ranges) {
        if (!range.is_base_address) {
            sorted.push_back(range);
        }
    }

    if (sorted.empty()) {
        return {};
    }

    std::sort(sorted.begin(), sorted.end());

    std::vector<AddressRange> result;
    result.push_back(sorted[0]);

    for (size_t i = 1; i < sorted.size(); ++i) {
        AddressRange& last = result.back();
        const AddressRange& current = sorted[i];

        if (current.start <= last.end) {
            // Overlapping or adjacent, merge them
            last.end = std::max(last.end, current.end);
        } else {
            // No overlap, add as new range
            result.push_back(current);
        }
    }

    return result;
}

uint64_t DwarfUtils::getTotalRangeSize(const std::vector<AddressRange>& ranges) {
    auto merged = mergeOverlappingRanges(ranges);
    uint64_t total = 0;
    for (const auto& range : merged) {
        total += (range.end - range.start);
    }
    return total;
}

bool DwarfUtils::isContinuousRange(const std::vector<AddressRange>& ranges) {
    auto merged = mergeOverlappingRanges(ranges);
    return merged.size() <= 1;
}

DwarfUtils::AddressRange DwarfUtils::getBoundingRange(const std::vector<AddressRange>& ranges) {
    if (ranges.empty()) {
        return AddressRange(0, 0, false);
    }

    uint64_t min_start = UINT64_MAX;
    uint64_t max_end = 0;

    for (const auto& range : ranges) {
        if (!range.is_base_address) {
            min_start = std::min(min_start, range.start);
            max_end = std::max(max_end, range.end);
        }
    }

    if (min_start == UINT64_MAX) {
        return AddressRange(0, 0, false);
    }

    return AddressRange(min_start, max_end, false);
}

} // namespace dwarf
