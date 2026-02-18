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
        case DwarfTag::DW_TAG_compile_unit: return "DW_TAG_compile_unit";
        case DwarfTag::DW_TAG_subprogram: return "DW_TAG_subprogram";
        case DwarfTag::DW_TAG_variable: return "DW_TAG_variable";
        case DwarfTag::DW_TAG_formal_parameter: return "DW_TAG_formal_parameter";
        case DwarfTag::DW_TAG_base_type: return "DW_TAG_base_type";
        case DwarfTag::DW_TAG_pointer_type: return "DW_TAG_pointer_type";
        case DwarfTag::DW_TAG_array_type: return "DW_TAG_array_type";
        case DwarfTag::DW_TAG_structure_type: return "DW_TAG_structure_type";
        case DwarfTag::DW_TAG_union_type: return "DW_TAG_union_type";
        case DwarfTag::DW_TAG_enumeration_type: return "DW_TAG_enumeration_type";
        case DwarfTag::DW_TAG_typedef: return "DW_TAG_typedef";
        case DwarfTag::DW_TAG_const_type: return "DW_TAG_const_type";
        case DwarfTag::DW_TAG_volatile_type: return "DW_TAG_volatile_type";
        case DwarfTag::DW_TAG_restrict_type: return "DW_TAG_restrict_type";
        case DwarfTag::DW_TAG_subrange_type: return "DW_TAG_subrange_type";
        case DwarfTag::DW_TAG_member: return "DW_TAG_member";
        case DwarfTag::DW_TAG_inheritance: return "DW_TAG_inheritance";
        case DwarfTag::DW_TAG_inlined_subroutine: return "DW_TAG_inlined_subroutine";
        case DwarfTag::DW_TAG_lexical_block: return "DW_TAG_lexical_block";
        case DwarfTag::DW_TAG_unspecified_parameters: return "DW_TAG_unspecified_parameters";
        default: return "DW_TAG_unknown_" + std::to_string(static_cast<int>(tag));
    }
}

DwarfTag DwarfUtils::stringToTag(const std::string& str) {
    if (str == "DW_TAG_compile_unit") return DwarfTag::DW_TAG_compile_unit;
    if (str == "DW_TAG_subprogram") return DwarfTag::DW_TAG_subprogram;
    if (str == "DW_TAG_variable") return DwarfTag::DW_TAG_variable;
    if (str == "DW_TAG_formal_parameter") return DwarfTag::DW_TAG_formal_parameter;
    if (str == "DW_TAG_base_type") return DwarfTag::DW_TAG_base_type;
    if (str == "DW_TAG_pointer_type") return DwarfTag::DW_TAG_pointer_type;
    if (str == "DW_TAG_array_type") return DwarfTag::DW_TAG_array_type;
    if (str == "DW_TAG_structure_type") return DwarfTag::DW_TAG_structure_type;
    if (str == "DW_TAG_union_type") return DwarfTag::DW_TAG_union_type;
    if (str == "DW_TAG_enumeration_type") return DwarfTag::DW_TAG_enumeration_type;
    if (str == "DW_TAG_typedef") return DwarfTag::DW_TAG_typedef;
    if (str == "DW_TAG_const_type") return DwarfTag::DW_TAG_const_type;
    if (str == "DW_TAG_volatile_type") return DwarfTag::DW_TAG_volatile_type;
    if (str == "DW_TAG_restrict_type") return DwarfTag::DW_TAG_restrict_type;
    if (str == "DW_TAG_subrange_type") return DwarfTag::DW_TAG_subrange_type;
    if (str == "DW_TAG_member") return DwarfTag::DW_TAG_member;
    if (str == "DW_TAG_inheritance") return DwarfTag::DW_TAG_inheritance;
    if (str == "DW_TAG_inlined_subroutine") return DwarfTag::DW_TAG_inlined_subroutine;
    if (str == "DW_TAG_lexical_block") return DwarfTag::DW_TAG_lexical_block;
    if (str == "DW_TAG_unspecified_parameters") return DwarfTag::DW_TAG_unspecified_parameters;
    return static_cast<DwarfTag>(0);
}

// Attribute name conversion
DwarfAttribute DwarfUtils::stringToAttribute(const std::string& str) {
    if (str == "DW_AT_name") return DwarfAttribute::DW_AT_name;
    if (str == "DW_AT_type") return DwarfAttribute::DW_AT_type;
    if (str == "DW_AT_low_pc") return DwarfAttribute::DW_AT_low_pc;
    if (str == "DW_AT_high_pc") return DwarfAttribute::DW_AT_high_pc;
    if (str == "DW_AT_location") return DwarfAttribute::DW_AT_location;
    if (str == "DW_AT_byte_size") return DwarfAttribute::DW_AT_byte_size;
    if (str == "DW_AT_encoding") return DwarfAttribute::DW_AT_encoding;
    if (str == "DW_AT_decl_file") return DwarfAttribute::DW_AT_decl_file;
    if (str == "DW_AT_decl_line") return DwarfAttribute::DW_AT_decl_line;
    if (str == "DW_AT_decl_column") return DwarfAttribute::DW_AT_decl_column;
    if (str == "DW_AT_stmt_list") return DwarfAttribute::DW_AT_stmt_list;
    if (str == "DW_AT_comp_dir") return DwarfAttribute::DW_AT_comp_dir;
    if (str == "DW_AT_ranges") return DwarfAttribute::DW_AT_ranges;
    if (str == "DW_AT_addr_base") return DwarfAttribute::DW_AT_addr_base;
    if (str == "DW_AT_rnglists_base") return DwarfAttribute::DW_AT_rnglists_base;
    if (str == "DW_AT_loclists_base") return DwarfAttribute::DW_AT_loclists_base;
    if (str == "DW_AT_str_offsets_base") return DwarfAttribute::DW_AT_str_offsets_base;
    if (str == "DW_AT_dwo_name") return DwarfAttribute::DW_AT_dwo_name;
    if (str == "DW_AT_dwo_id") return DwarfAttribute::DW_AT_dwo_id;
    if (str == "DW_AT_GNU_dwo_name") return DwarfAttribute::DW_AT_GNU_dwo_name;
    if (str == "DW_AT_GNU_dwo_id") return DwarfAttribute::DW_AT_GNU_dwo_id;
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
    if (str == "DW_OP_plus") return DwarfOp::DW_OP_plus;
    if (str == "DW_OP_plus_uconst") return DwarfOp::DW_OP_plus_uconst;
    if (str == "DW_OP_bra") return DwarfOp::DW_OP_bra;
    if (str == "DW_OP_skip") return DwarfOp::DW_OP_skip;
    if (str == "DW_OP_regx") return DwarfOp::DW_OP_regx;
    if (str == "DW_OP_bregx") return DwarfOp::DW_OP_bregx;
    if (str == "DW_OP_fbreg") return DwarfOp::DW_OP_fbreg;
    if (str == "DW_OP_piece") return DwarfOp::DW_OP_piece;
    if (str == "DW_OP_bit_piece") return DwarfOp::DW_OP_bit_piece;
    if (str == "DW_OP_implicit_value") return DwarfOp::DW_OP_implicit_value;
    if (str == "DW_OP_stack_value") return DwarfOp::DW_OP_stack_value;
    if (str == "DW_OP_call2") return DwarfOp::DW_OP_call2;
    if (str == "DW_OP_call4") return DwarfOp::DW_OP_call4;
    if (str == "DW_OP_call_ref") return DwarfOp::DW_OP_call_ref;
    if (str == "DW_OP_entry_value") return DwarfOp::DW_OP_entry_value;
    if (str == "DW_OP_convert") return DwarfOp::DW_OP_convert;
    if (str == "DW_OP_reinterpret") return DwarfOp::DW_OP_reinterpret;
    return static_cast<DwarfOp>(0);
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
        case DwarfTag::DW_TAG_pointer_type:
        case DwarfTag::DW_TAG_array_type:
        case DwarfTag::DW_TAG_structure_type:
        case DwarfTag::DW_TAG_union_type:
        case DwarfTag::DW_TAG_enumeration_type:
        case DwarfTag::DW_TAG_typedef:
        case DwarfTag::DW_TAG_const_type:
        case DwarfTag::DW_TAG_volatile_type:
        case DwarfTag::DW_TAG_restrict_type:
        case DwarfTag::DW_TAG_subrange_type:
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
            return 1;

        case DwarfForm::DW_FORM_data2:
        case DwarfForm::DW_FORM_ref2:
        case DwarfForm::DW_FORM_strx2:
        case DwarfForm::DW_FORM_addrx2:
            return 2;

        case DwarfForm::DW_FORM_data4:
        case DwarfForm::DW_FORM_ref4:
        case DwarfForm::DW_FORM_ref_sup4:
        case DwarfForm::DW_FORM_strx4:
        case DwarfForm::DW_FORM_addrx4:
            return 4;

        case DwarfForm::DW_FORM_data8:
        case DwarfForm::DW_FORM_ref8:
        case DwarfForm::DW_FORM_ref_sig8:
        case DwarfForm::DW_FORM_ref_sup8:
            return 8;

        case DwarfForm::DW_FORM_data16:
            return 16;

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
        case DwarfForm::DW_FORM_addrx:
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
            size_t tail = getFormSize(static_cast<DwarfForm>(f), data, static_cast<size_t>(tmp), max_offset);
            return head + tail;
        }

        // Forms whose size depends on DWARF32/64 or address size. Without CU context,
        // choose conservative defaults (DWARF32 / 4-byte offsets) when ambiguous.
        case DwarfForm::DW_FORM_addr:
            return (max_offset - offset >= 8) ? 8 : 4;
        case DwarfForm::DW_FORM_strp:
        case DwarfForm::DW_FORM_line_strp:
        case DwarfForm::DW_FORM_sec_offset:
        case DwarfForm::DW_FORM_strp_sup:
        case DwarfForm::DW_FORM_ref_addr:
            return (max_offset - offset >= 4) ? 4 : (max_offset - offset);

        case DwarfForm::DW_FORM_strx3:
        case DwarfForm::DW_FORM_addrx3:
            return 3;

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
    if (!data || offset >= max_offset) return 0;

    // offset points to the first byte *after* the opcode in most callers.
    // This utility expects offset to be the start of operands (same convention).
    switch (op) {
        case DwarfOp::DW_OP_addr:
            return (max_offset - offset >= 8) ? 8 : 4;
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
            return 2;
        case DwarfOp::DW_OP_const4u:
        case DwarfOp::DW_OP_const4s:
        case DwarfOp::DW_OP_call4:
        case DwarfOp::DW_OP_GNU_parameter_ref:
            return 4;
        case DwarfOp::DW_OP_const8u:
        case DwarfOp::DW_OP_const8s:
        case DwarfOp::DW_OP_GNU_implicit_pointer:
        case DwarfOp::DW_OP_implicit_pointer:
            // DIE offset size is target-dependent; best-effort use 4 if available.
            return (max_offset - offset >= 8) ? 8 : 4;

        case DwarfOp::DW_OP_constu:
        case DwarfOp::DW_OP_consts:
        case DwarfOp::DW_OP_regx:
        case DwarfOp::DW_OP_fbreg:
        case DwarfOp::DW_OP_piece:
        case DwarfOp::DW_OP_addrx:
        case DwarfOp::DW_OP_constx:
        case DwarfOp::DW_OP_convert:
        case DwarfOp::DW_OP_reinterpret:
            return lebSize(data, offset, max_offset);

        case DwarfOp::DW_OP_bregx: {
            size_t a = lebSize(data, offset, max_offset);
            size_t b = lebSize(data, offset + a, max_offset);
            return a + b;
        }

        case DwarfOp::DW_OP_entry_value: {
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

        case DwarfOp::DW_OP_bit_piece: {
            size_t a = lebSize(data, offset, max_offset);
            size_t b = lebSize(data, offset + a, max_offset);
            return a + b;
        }

        case DwarfOp::DW_OP_const_type:
        case DwarfOp::DW_OP_deref_type:
        case DwarfOp::DW_OP_xderef_type:
        case DwarfOp::DW_OP_regval_type: {
            // Typed ops: uleb type/ref + other operands.
            // Best-effort sizes based on spec encodings.
            if (op == DwarfOp::DW_OP_regval_type) {
                size_t a = lebSize(data, offset, max_offset);        // reg
                size_t b = lebSize(data, offset + a, max_offset);    // type
                return a + b;
            }
            if (op == DwarfOp::DW_OP_const_type) {
                size_t a = lebSize(data, offset, max_offset);        // type
                if (offset + a >= max_offset) return a;
                uint8_t sz = data[offset + a];                       // 1-byte size
                size_t payload = std::min<size_t>(sz, (max_offset > (offset + a + 1)) ? (max_offset - (offset + a + 1)) : 0);
                return a + 1 + payload;
            }
            // deref_type / xderef_type: 1-byte size + uleb type
            if (max_offset - offset < 1) return 0;
            size_t b = lebSize(data, offset + 1, max_offset);
            return 1 + b;
        }

        case DwarfOp::DW_OP_call_ref:
            return (max_offset - offset >= 4) ? 4 : (max_offset - offset);

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
    std::vector<std::string> out;
    size_t off = 0;
    while (off < expression.size()) {
        DwarfOp op = static_cast<DwarfOp>(expression[off++]);
        out.push_back(operationToString(op));
        size_t opsz = getOperationSize(op, expression.data(), off, expression.size());
        off = std::min(expression.size(), off + opsz);
    }
    return out;
}

std::string DwarfUtils::expressionToAssembly(const std::vector<uint8_t>& expression) {
    std::ostringstream oss;
    auto toks = expressionToTokens(expression);
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
        case DwarfAttribute::DW_AT_name: return "DW_AT_name";
        case DwarfAttribute::DW_AT_type: return "DW_AT_type";
        case DwarfAttribute::DW_AT_low_pc: return "DW_AT_low_pc";
        case DwarfAttribute::DW_AT_high_pc: return "DW_AT_high_pc";
        case DwarfAttribute::DW_AT_location: return "DW_AT_location";
        case DwarfAttribute::DW_AT_byte_size: return "DW_AT_byte_size";
        case DwarfAttribute::DW_AT_encoding: return "DW_AT_encoding";
        case DwarfAttribute::DW_AT_decl_file: return "DW_AT_decl_file";
        case DwarfAttribute::DW_AT_decl_line: return "DW_AT_decl_line";
        case DwarfAttribute::DW_AT_decl_column: return "DW_AT_decl_column";
        case DwarfAttribute::DW_AT_stmt_list: return "DW_AT_stmt_list";
        case DwarfAttribute::DW_AT_comp_dir: return "DW_AT_comp_dir";
        case DwarfAttribute::DW_AT_ranges: return "DW_AT_ranges";
        case DwarfAttribute::DW_AT_addr_base: return "DW_AT_addr_base";
        case DwarfAttribute::DW_AT_rnglists_base: return "DW_AT_rnglists_base";
        case DwarfAttribute::DW_AT_loclists_base: return "DW_AT_loclists_base";
        case DwarfAttribute::DW_AT_str_offsets_base: return "DW_AT_str_offsets_base";
        case DwarfAttribute::DW_AT_dwo_name: return "DW_AT_dwo_name";
        case DwarfAttribute::DW_AT_dwo_id: return "DW_AT_dwo_id";
        case DwarfAttribute::DW_AT_GNU_dwo_name: return "DW_AT_GNU_dwo_name";
        case DwarfAttribute::DW_AT_GNU_dwo_id: return "DW_AT_GNU_dwo_id";
        default: return "DW_AT_unknown";
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
        default: return "DW_OP_unknown";
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
