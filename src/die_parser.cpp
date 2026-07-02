#include "die_parser.hpp"
#include "attribute_parser.hpp"
#include "dwarf_utils.hpp"
#include <iostream>

#define DEBUG_OUT(x) do { \
    if (verbose_) { \
        std::ostringstream dwarf_debug_stream__; \
        dwarf_debug_stream__ << x; \
        DwarfUtils::printDebugMessage(std::cerr, dwarf_debug_stream__.str()); \
    } \
} while (false)
#include <sstream>
#include <algorithm>
#include <cstring>

namespace dwarf {

DIE::DIE(DwarfTag tag, uint64_t offset, uint64_t size)
    : tag_(tag), offset_(offset), size_(size) {
}

bool DIE::hasAttribute(DwarfAttribute attr) const {
    return attributes_.find(attr) != attributes_.end();
}

std::shared_ptr<AttributeValue> DIE::getAttribute(DwarfAttribute attr) const {
    auto it = attributes_.find(attr);
    return (it != attributes_.end()) ? it->second : nullptr;
}

void DIE::addAttribute(DwarfAttribute attr, std::shared_ptr<AttributeValue> value) {
    attributes_[attr] = value;
}

void DIE::addChild(std::shared_ptr<DIE> child) {
    children_.push_back(child);
}

std::string DIE::getTagName() const {
    return DwarfUtils::tagToString(tag_);
}

std::string DIE::getName() const {
    auto name_attr = getAttribute(DwarfAttribute::DW_AT_name);
    if (name_attr && name_attr->getType() == AttributeValueType::STRING) {
        return std::static_pointer_cast<StringAttributeValue>(name_attr)->getValue();
    }
    return "";
}

std::string DIE::toString(int indent) const {
    std::stringstream ss;
    std::string indent_str(indent * 2, ' ');
    
    ss << indent_str << "<" << getTagName() << ">";
    if (!getName().empty()) {
        ss << " " << getName();
    }
    ss << " (offset: 0x" << std::hex << offset_ << ", size: " << std::dec << size_ << ")";
    
    if (!attributes_.empty()) {
        ss << "\n" << indent_str << "  Attributes:";
        for (const auto& attr : attributes_) {
            ss << "\n" << indent_str << "    " 
               << DwarfUtils::attributeToString(attr.first) << " = " 
               << attr.second->toString();
        }
    }
    
    if (!children_.empty()) {
        ss << "\n" << indent_str << "  Children:";
        for (const auto& child : children_) {
            ss << "\n" << child->toString(indent + 2);
        }
    }
    
    return ss.str();
}

std::shared_ptr<DIE> DIE::getType() const {
    auto type_attr = getAttribute(DwarfAttribute::DW_AT_type);
    if (type_attr && type_attr->getType() == AttributeValueType::REFERENCE) {
        auto ref_attr = std::static_pointer_cast<ReferenceAttributeValue>(type_attr);
        // Note: This would need to be resolved by the parent parser
        return nullptr;
    }
    return nullptr;
}

uint64_t DIE::getByteSize() const {
    auto size_attr = getAttribute(DwarfAttribute::DW_AT_byte_size);
    if (size_attr && size_attr->getType() == AttributeValueType::UNSIGNED) {
        return std::static_pointer_cast<UnsignedAttributeValue>(size_attr)->getValue();
    }
    return 0;
}

bool DIE::isType() const {
    switch (tag_) {
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
        case DwarfTag::DW_TAG_class_type:
        case DwarfTag::DW_TAG_interface_type:
        case DwarfTag::DW_TAG_enumeration_type:
        case DwarfTag::DW_TAG_typedef:
        case DwarfTag::DW_TAG_const_type:
        case DwarfTag::DW_TAG_volatile_type:
        case DwarfTag::DW_TAG_restrict_type:
        case DwarfTag::DW_TAG_reference_type:
        case DwarfTag::DW_TAG_rvalue_reference_type:
        case DwarfTag::DW_TAG_atomic_type:
        case DwarfTag::DW_TAG_subrange_type:
        case DwarfTag::DW_TAG_subroutine_type:
            return true;
        default:
            return false;
    }
}

DIEParser::DIEParser(const ELFIO::elfio& elf, const std::vector<uint8_t>& debug_info,
                     const std::vector<uint8_t>& debug_abbrev, const std::vector<uint8_t>& debug_str,
                     const std::vector<uint8_t>& debug_line,
                     const std::vector<uint8_t>& debug_ranges,
                     const std::vector<uint8_t>& debug_loc,
                     const std::vector<uint8_t>& debug_str_offsets,
                     const std::vector<uint8_t>& debug_addr,
                     const std::vector<uint8_t>& debug_line_str,
                     const std::vector<uint8_t>& debug_rnglists,
                     const std::vector<uint8_t>& debug_loclists,
                     const std::vector<uint8_t>& debug_str_sup,
                     bool verbose,
                     uint64_t debug_info_offset_bias,
                     uint64_t supplementary_debug_info_offset_bias)
    : elf_(elf)
    , debug_info_(debug_info)
    , debug_abbrev_(debug_abbrev)
    , debug_str_(debug_str)
    , verbose_(verbose)
    , debug_info_offset_bias_(debug_info_offset_bias) {
    // Create attribute parser
    attribute_parser_ = std::make_shared<dwarf::AttributeParser>(debug_info_, debug_abbrev_, debug_str_,
                                                                 debug_line,
                                                                 debug_ranges,
                                                                 debug_loc,
                                                                 debug_str_offsets,
                                                                 debug_addr,
                                                                 debug_line_str,
                                                                 debug_rnglists,
                                                                 debug_loclists,
                                                                 debug_str_sup);
    attribute_parser_->setDebugInfoOffsetBias(debug_info_offset_bias_);
    attribute_parser_->setSupplementaryDebugInfoOffsetBias(supplementary_debug_info_offset_bias);
}

uint64_t DIEParser::getUnsupportedVendorFormSkipCount() const {
    if (!attribute_parser_) return 0;
    return attribute_parser_->getUnsupportedVendorFormSkipCount();
}

std::vector<std::pair<uint16_t, uint64_t>> DIEParser::getUnsupportedVendorFormSkipSamples() const {
    std::vector<std::pair<uint16_t, uint64_t>> out;
    if (!attribute_parser_) return out;
    const auto& samples = attribute_parser_->getUnsupportedVendorFormSkipSamples();
    out.reserve(samples.size());
    for (const auto& s : samples) {
        out.emplace_back(s.form, s.offset);
    }
    return out;
}

std::vector<std::pair<uint16_t, uint64_t>> DIEParser::getUnsupportedVendorFormSkipHistogram() const {
    std::vector<std::pair<uint16_t, uint64_t>> out;
    if (!attribute_parser_) return out;
    const auto& hist = attribute_parser_->getUnsupportedVendorFormSkipHistogram();
    out.reserve(hist.size());
    for (const auto& kv : hist) {
        out.emplace_back(kv.first, kv.second);
    }
    return out;
}

std::vector<std::pair<std::string, uint64_t>> DIEParser::getUnsupportedVendorFormSkipSeverityBuckets() const {
    std::vector<std::pair<std::string, uint64_t>> out;
    if (!attribute_parser_) return out;
    const auto& hist = attribute_parser_->getUnsupportedVendorFormSkipSeverityBuckets();
    out.reserve(hist.size());
    for (const auto& kv : hist) {
        out.emplace_back(kv.first, kv.second);
    }
    return out;
}

std::vector<std::shared_ptr<DIE>> DIEParser::parseCompilationUnits() {
    std::vector<std::shared_ptr<DIE>> compilation_units;
    vendor_form_skip_details_.clear();
    uint64_t offset = 0;
    
    DEBUG_OUT("Starting to parse compilation units, debug_info size: " << debug_info_.size());
    
    while (offset < debug_info_.size()) {
        // Need at least the initial length.
        if (offset + 4 > debug_info_.size()) break;

        uint64_t start_offset = offset;
        uint64_t biased_start_offset = debug_info_offset_bias_ + start_offset;

        clearDecodeError();
        uint32_t initial_length = readU32(offset);
        if (hasDecodeError()) break;
        DEBUG_OUT("Raw length value: 0x" << std::hex << initial_length << std::dec);
        if (initial_length == 0) break;

        bool is_dwarf64 = (initial_length == 0xffffffff);
        uint8_t offset_size = is_dwarf64 ? 8 : 4;
        if (is_dwarf64 && offset + 8 > debug_info_.size()) break;
        uint64_t unit_length = is_dwarf64 ? readU64(offset) : initial_length;
        if (hasDecodeError()) break;
        uint64_t header_size = is_dwarf64 ? 12 : 4;
        if (unit_length > (debug_info_.size() - start_offset - header_size)) break;
        uint64_t unit_end = start_offset + header_size + unit_length;

        DEBUG_OUT("Found compilation unit at offset " << biased_start_offset
                  << ", length: " << unit_length
                  << ", dwarf64: " << (is_dwarf64 ? "yes" : "no"));

        if (offset + 2 > unit_end) {
            offset = unit_end;
            continue;
        }

        uint16_t version = readU16(offset);
        if (hasDecodeError()) {
            offset = unit_end;
            continue;
        }
        DEBUG_OUT("DWARF version: " << version);
        
        uint64_t abbrev_offset;
        uint8_t address_size;
        uint8_t unit_type_raw = 0;
        uint64_t unit_type_signature = 0;
        uint64_t unit_type_offset = 0;
        bool has_type_unit_signature = false;
        
        if (version >= 5) {
            // DWARF 5 format: version, unit_type, address_size, abbrev_offset
            uint64_t need = 2 + (is_dwarf64 ? 8 : 4);
            if (offset + need > unit_end) {
                offset = unit_end;
                continue;
            }
            unit_type_raw = readU8(offset);
            DEBUG_OUT("DWARF 5 unit type: " << (int)unit_type_raw);
            address_size = readU8(offset);
            DEBUG_OUT("Address size: " << (int)address_size);

            abbrev_offset = is_dwarf64 ? readU64(offset) : readU32(offset);
            DEBUG_OUT("Abbrev offset: 0x" << std::hex << abbrev_offset << std::dec);

            // DWARF 5 unit headers have extra fields based on unit_type.
            // See DWARF v5 section 7.5.1.1 (Unit header).
            const auto unit_type = static_cast<DwarfUnitType>(unit_type_raw);
            if (unit_type == DwarfUnitType::DW_UT_type || unit_type == DwarfUnitType::DW_UT_split_type) {
                // type_signature (8 bytes) + type_offset (offset_size bytes)
                uint64_t need_extra = 8 + (is_dwarf64 ? 8 : 4);
                if (offset + need_extra > unit_end) {
                    offset = unit_end;
                    continue;
                }
                unit_type_signature = readU64(offset);
                unit_type_offset = is_dwarf64 ? readU64(offset) : readU32(offset);
                has_type_unit_signature = true;
            } else if (unit_type == DwarfUnitType::DW_UT_skeleton || unit_type == DwarfUnitType::DW_UT_split_compile) {
                // dwo_id (8 bytes)
                if (offset + 8 > unit_end) {
                    offset = unit_end;
                    continue;
                }
                (void)readU64(offset);
            }
        } else {
            // DWARF 2-4 format: version, abbrev_offset, address_size
            uint64_t need = (is_dwarf64 ? 8 : 4) + 1;
            if (offset + need > unit_end) {
                offset = unit_end;
                continue;
            }
            abbrev_offset = is_dwarf64 ? readU64(offset) : readU32(offset);
            DEBUG_OUT("Abbrev offset: 0x" << std::hex << abbrev_offset << std::dec);
            address_size = readU8(offset);
            DEBUG_OUT("Address size: " << (int)address_size);
        }
        if (hasDecodeError()) {
            offset = unit_end;
            continue;
        }
        
        // Set CU context for attribute parsing (for CU-relative references)
        attribute_parser_->setCUOffset(biased_start_offset);
        attribute_parser_->setCUDebugInfoEnd(unit_end);
        attribute_parser_->setAddressSize(address_size);
        attribute_parser_->setDwarfVersion(static_cast<DwarfVersion>(version));
        attribute_parser_->setIsDwarf64(is_dwarf64);

        // Parse the compilation unit DIE
        auto cu_die = parseDIE(offset, debug_abbrev_, abbrev_offset, /*cu_base_offset=*/biased_start_offset, offset_size, unit_end);
        if (cu_die) {
            if (has_type_unit_signature) {
                cu_die->addAttribute(DwarfAttribute::DW_AT_signature,
                                     std::make_shared<UnsignedAttributeValue>(unit_type_signature));
                cu_die->addAttribute(DwarfAttribute::DW_AT_type,
                                     std::make_shared<TypeAttributeValue>(biased_start_offset + unit_type_offset,
                                                                          "<type-unit>"));
            }
            compilation_units.push_back(cu_die);
            DEBUG_OUT("Successfully parsed compilation unit DIE");
        } else {
            DEBUG_OUT("Failed to parse compilation unit DIE");
        }
        
        // Move to next compilation unit regardless of CU DIE parse result.
        offset = unit_end;
    }
    
    DEBUG_OUT("Parsed " << compilation_units.size() << " compilation units");
    return compilation_units;
}

std::shared_ptr<DIE> DIEParser::parseDIE(uint64_t& offset,
                                         const std::vector<uint8_t>& abbrev_data,
                                         uint64_t abbrev_offset,
                                         uint64_t cu_base_offset,
                                         uint8_t offset_size,
                                         uint64_t cu_end) {
    (void)abbrev_data;
    uint64_t info_end = std::min<uint64_t>(cu_end, debug_info_.size());
    if (offset >= info_end) return nullptr;

    uint64_t start_offset = offset;
    uint64_t biased_start_offset = debug_info_offset_bias_ + start_offset;
    clearDecodeError();
    uint64_t abbrev_code = readULEB128(offset);
    if (hasDecodeError()) {
        return nullptr;
    }
    DEBUG_OUT("parseDIE at offset " << start_offset << ", abbrev_code: " << abbrev_code);
    
    if (abbrev_code == 0) {
        DEBUG_OUT("Null DIE found");
        return nullptr; // Null DIE
    }
    
    // Parse abbreviation entry (cached; pointer into the parser-lifetime cache)
    const AbbreviationEntry* abbrev_entry_ptr = lookupAbbreviationEntry(abbrev_code, abbrev_offset);
    if (abbrev_entry_ptr == nullptr) {
        DEBUG_OUT("Failed to find abbreviation entry for code " << abbrev_code);
        return nullptr;
    }
    const AbbreviationEntry& abbrev_entry = *abbrev_entry_ptr;

    DEBUG_OUT("Found abbreviation entry, tag: " << static_cast<int>(abbrev_entry.tag));

    // Create DIE
    auto die = std::make_shared<DIE>(abbrev_entry.tag, biased_start_offset, 0);
    die->setCUBaseOffset(cu_base_offset);
    die->setOffsetSize(offset_size);
    
    // Parse attributes using attribute-aware parsing
    const auto isUnitDIE = [](DwarfTag tag) -> bool {
        switch (tag) {
            case DwarfTag::DW_TAG_compile_unit:
            case DwarfTag::DW_TAG_partial_unit:
            case DwarfTag::DW_TAG_type_unit:
            case DwarfTag::DW_TAG_skeleton_unit:
            case DwarfTag::DW_TAG_split_compile_unit:
            case DwarfTag::DW_TAG_split_type_unit:
                return true;
            default:
                return false;
        }
    };
    const bool is_unit_die = isUnitDIE(die->getTag());
    uint64_t rnglists_base = 0;
    uint64_t loclists_base = 0;
    uint64_t addr_base = 0;
    uint64_t str_offsets_base = 0;
    uint64_t base_address = 0;
    for (const auto& attr_spec : abbrev_entry.attributes) {
        const uint64_t attr_payload_offset = offset;
        const uint64_t before_skip_count = attribute_parser_
            ? attribute_parser_->getUnsupportedVendorFormSkipCount()
            : 0;
        const size_t before_sample_count = attribute_parser_
            ? attribute_parser_->getUnsupportedVendorFormSkipSamples().size()
            : 0;
        std::shared_ptr<AttributeValue> attr_value;
        if (attr_spec.form == DwarfForm::DW_FORM_implicit_const) {
            // Implicit const values live in the abbrev stream; no bytes consumed from .debug_info.
            attribute_parser_->setImplicitConstValue(attr_spec.implicit_const);
            attr_value = attribute_parser_->parseAttribute(attr_spec.attr, attr_spec.form, offset);
            attribute_parser_->setImplicitConstValue(std::nullopt);
        } else {
            attr_value = attribute_parser_->parseAttribute(attr_spec.attr, attr_spec.form, offset);
        }

        if (attribute_parser_ &&
            attribute_parser_->getUnsupportedVendorFormSkipCount() > before_skip_count) {
            VendorFormSkipDetail d{};
            d.form = static_cast<uint16_t>(attr_spec.form);
            d.payload_offset = attr_payload_offset;
            d.cu_offset = cu_base_offset;
            d.die_offset = die->getOffset();
            d.attr = attr_spec.attr;
            d.is_unit_die = is_unit_die;
            const auto& samples = attribute_parser_->getUnsupportedVendorFormSkipSamples();
            if (samples.size() > before_sample_count) {
                d.payload_offset = samples.back().offset;
                d.form = samples.back().form;
                d.severity = samples.back().severity;
            }
            if (vendor_form_skip_details_.size() < 128) {
                vendor_form_skip_details_.push_back(d);
            }
        }

        if (attr_value) {
            die->addAttribute(attr_spec.attr, attr_value);
        }

        // For the CU DIE itself, update context as soon as we learn base attributes so
        // subsequent attributes in the CU can resolve indexed forms.
        if (is_unit_die && attribute_parser_ && attr_value) {
            switch (attr_spec.attr) {
                case DwarfAttribute::DW_AT_rnglists_base: {
                    auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(attr_value);
                    if (u) rnglists_base = u->getValue();
                    break;
                }
                case DwarfAttribute::DW_AT_loclists_base: {
                    auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(attr_value);
                    if (u) loclists_base = u->getValue();
                    break;
                }
                case DwarfAttribute::DW_AT_addr_base: {
                    auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(attr_value);
                    if (u) addr_base = u->getValue();
                    break;
                }
                case DwarfAttribute::DW_AT_str_offsets_base: {
                    auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(attr_value);
                    if (u) str_offsets_base = u->getValue();
                    break;
                }
                case DwarfAttribute::DW_AT_low_pc: {
                    auto a = std::dynamic_pointer_cast<AddressAttributeValue>(attr_value);
                    if (a) base_address = a->getAddress();
                    else {
                        auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(attr_value);
                        if (u) base_address = u->getValue();
                    }
                    break;
                }
                default:
                    break;
            }

            attribute_parser_->setCUContext(rnglists_base, loclists_base, addr_base, str_offsets_base, base_address);
        }
    }

    // Ensure CU context is set before parsing children even if base attributes were absent.
    if (is_unit_die && attribute_parser_) {
        attribute_parser_->setCUContext(rnglists_base, loclists_base, addr_base, str_offsets_base, base_address);
    }
    
    // Parse children if present
    if (abbrev_entry.has_children) {
        uint64_t child_count = 0;
        while (offset < info_end && child_count < 1000) { // Safety limit
            uint64_t child_start_offset = offset;
            auto child = parseDIE(offset, abbrev_data, abbrev_offset, cu_base_offset, offset_size, info_end);
            if (!child) {
                DEBUG_OUT("No more children at offset " << child_start_offset);
                break;
            }
            die->addChild(child);
            child_count++;
            
            // Safety check: if offset didn't advance, break to prevent infinite loop
            if (offset <= child_start_offset) {
                DEBUG_OUT("Offset didn't advance, breaking child parsing loop");
                break;
            }
        }
        if (child_count >= 1000) {
            DEBUG_OUT("Reached child parsing limit, stopping");
        }
    }
    
    // Update size
    die->setSize(offset - start_offset);
    
    return die;
}

std::string DIEParser::getString(uint64_t offset) const {
    if (offset >= debug_str_.size()) return "";

    const uint8_t* start = debug_str_.data() + offset;
    size_t remaining = debug_str_.size() - static_cast<size_t>(offset);
    const void* term = std::memchr(start, 0, remaining);
    if (term == nullptr) {
        return std::string(reinterpret_cast<const char*>(start), remaining);
    }
    size_t n = static_cast<const uint8_t*>(term) - start;
    return std::string(reinterpret_cast<const char*>(start), n);
}

std::vector<uint8_t> DIEParser::getAbbrevData(uint64_t offset) const {
    if (offset >= debug_abbrev_.size()) return {};
    
    std::vector<uint8_t> data;
    size_t pos = offset;
    
    while (pos < debug_abbrev_.size()) {
        data.push_back(debug_abbrev_[pos++]);
    }
    
    return data;
}

bool DIEParser::isValidOffset(uint64_t offset) const {
    return offset < debug_info_.size();
}

uint64_t DIEParser::readULEB128(uint64_t& offset) const {
    if (offset >= debug_info_.size()) {
        decode_error_ = true;
        return 0;
    }

    uint64_t result = 0;
    unsigned shift = 0;
    while (offset < debug_info_.size()) {
        uint8_t byte = debug_info_[offset++];
        uint64_t bits = static_cast<uint64_t>(byte & 0x7f);
        if (shift >= 64 && bits != 0) {
            decode_error_ = true;
            return 0;
        }
        result |= (bits << shift);
        if ((byte & 0x80) == 0) {
            return result;
        }
        shift += 7;
        if (shift >= 64) {
            decode_error_ = true;
            return 0;
        }
    }

    decode_error_ = true;
    return 0;
}

uint64_t DIEParser::readULEB128FromAbbrev(uint64_t& offset) const {
    if (offset >= debug_abbrev_.size()) {
        decode_error_ = true;
        return 0;
    }

    uint64_t result = 0;
    unsigned shift = 0;
    while (offset < debug_abbrev_.size()) {
        uint8_t byte = debug_abbrev_[offset++];
        uint64_t bits = static_cast<uint64_t>(byte & 0x7f);
        if (shift >= 64 && bits != 0) {
            decode_error_ = true;
            return 0;
        }
        result |= (bits << shift);
        if ((byte & 0x80) == 0) {
            return result;
        }
        shift += 7;
        if (shift >= 64) {
            decode_error_ = true;
            return 0;
        }
    }

    decode_error_ = true;
    return 0;
}

int64_t DIEParser::readSLEB128FromAbbrev(uint64_t& offset) const {
    if (offset >= debug_abbrev_.size()) {
        decode_error_ = true;
        return 0;
    }

    uint64_t result = 0;
    unsigned shift = 0;
    uint8_t byte = 0;
    while (offset < debug_abbrev_.size()) {
        byte = debug_abbrev_[offset++];
        uint64_t bits = static_cast<uint64_t>(byte & 0x7f);
        if (shift >= 64 && bits != 0) {
            decode_error_ = true;
            return 0;
        }
        result |= (bits << shift);
        shift += 7;
        if ((byte & 0x80) == 0) {
            if (shift < 64 && (byte & 0x40)) {
                result |= (~0ULL << shift);
            }
            return static_cast<int64_t>(result);
        }
        if (shift >= 64) {
            decode_error_ = true;
            return 0;
        }
    }

    decode_error_ = true;
    return 0;
}

int64_t DIEParser::readSLEB128(uint64_t& offset) const {
    if (offset >= debug_info_.size()) {
        decode_error_ = true;
        return 0;
    }

    uint64_t result = 0;
    unsigned shift = 0;
    uint8_t byte = 0;
    while (offset < debug_info_.size()) {
        byte = debug_info_[offset++];
        uint64_t bits = static_cast<uint64_t>(byte & 0x7f);
        if (shift >= 64 && bits != 0) {
            decode_error_ = true;
            return 0;
        }
        result |= (bits << shift);
        shift += 7;
        if ((byte & 0x80) == 0) {
            if (shift < 64 && (byte & 0x40)) {
                result |= (~0ULL << shift);
            }
            return static_cast<int64_t>(result);
        }
        if (shift >= 64) {
            decode_error_ = true;
            return 0;
        }
    }

    decode_error_ = true;
    return 0;
}

uint8_t DIEParser::readU8(uint64_t& offset) const {
    if (offset + 1 > debug_info_.size()) {
        decode_error_ = true;
        return 0;
    }
    return DwarfUtils::readU8(debug_info_.data(), offset, debug_info_.size());
}

uint8_t DIEParser::readU8FromAbbrev(uint64_t& offset) const {
    if (offset + 1 > debug_abbrev_.size()) {
        decode_error_ = true;
        return 0;
    }
    return DwarfUtils::readU8(debug_abbrev_.data(), offset, debug_abbrev_.size());
}

uint16_t DIEParser::readU16(uint64_t& offset) const {
    if (offset + 2 > debug_info_.size()) {
        decode_error_ = true;
        return 0;
    }
    return DwarfUtils::readU16(debug_info_.data(), offset, debug_info_.size());
}

uint32_t DIEParser::readU32(uint64_t& offset) const {
    if (offset + 4 > debug_info_.size()) {
        decode_error_ = true;
        return 0;
    }
    return DwarfUtils::readU32(debug_info_.data(), offset, debug_info_.size());
}

uint64_t DIEParser::readU64(uint64_t& offset) const {
    if (offset + 8 > debug_info_.size()) {
        decode_error_ = true;
        return 0;
    }
    return DwarfUtils::readU64(debug_info_.data(), offset, debug_info_.size());
}

std::map<uint64_t, DIEParser::AbbreviationEntry> DIEParser::parseAbbreviationTable() {
    std::map<uint64_t, AbbreviationEntry> abbrev_table;
    uint64_t offset = 0;
    
    while (offset < debug_abbrev_.size()) {
        uint64_t before = offset;
        auto entry = parseAbbreviationEntry(offset);
        if (entry.code != 0) {
            abbrev_table[entry.code] = entry;
        }
        if (offset <= before) break;
    }
    
    return abbrev_table;
}

DIEParser::AbbreviationEntry DIEParser::parseAbbreviationEntry(uint64_t& offset) const {
    AbbreviationEntry entry;
    clearDecodeError();
    
    if (offset >= debug_abbrev_.size()) {
        entry.code = 0;
        return entry;
    }
    
    entry.code = readULEB128FromAbbrev(offset);
    if (hasDecodeError()) {
        entry.code = 0;
        offset = debug_abbrev_.size();
        return entry;
    }
    
    if (entry.code == 0) {
        return entry; // End of abbreviation table
    }
    
    entry.tag = static_cast<DwarfTag>(readULEB128FromAbbrev(offset));
    entry.has_children = readU8FromAbbrev(offset) != 0;
    if (hasDecodeError()) {
        entry.code = 0;
        offset = debug_abbrev_.size();
        return entry;
    }
    
    // Parse attributes
    while (offset < debug_abbrev_.size()) {
        uint64_t before = offset;
        uint64_t attr_name = readULEB128FromAbbrev(offset);
        uint64_t attr_form = readULEB128FromAbbrev(offset);
        if (hasDecodeError()) {
            entry.code = 0;
            offset = debug_abbrev_.size();
            return entry;
        }
        
        if (attr_name == 0 && attr_form == 0) {
            break; // End of attribute list
        }

        AbbreviationAttrSpec spec;
        spec.attr = static_cast<DwarfAttribute>(attr_name);
        spec.form = static_cast<DwarfForm>(attr_form);
        if (spec.form == DwarfForm::DW_FORM_implicit_const) {
            // DW_FORM_implicit_const has an extra SLEB128 in the abbrev stream.
            spec.implicit_const = readSLEB128FromAbbrev(offset);
            spec.has_implicit_const = true;
            if (hasDecodeError()) {
                entry.code = 0;
                offset = debug_abbrev_.size();
                return entry;
            }
        }
        entry.attributes.push_back(spec);
        if (offset <= before) {
            entry.code = 0;
            offset = debug_abbrev_.size();
            return entry;
        }
    }
    
    return entry;
}

const std::map<uint64_t, DIEParser::AbbreviationEntry>&
DIEParser::abbreviationTableAt(uint64_t abbrev_offset) const {
    auto cached = abbrev_table_cache_.find(abbrev_offset);
    if (cached != abbrev_table_cache_.end()) {
        return cached->second;
    }

    // Parse this CU's abbreviation table once (from abbrev_offset to the
    // terminating null entry) and cache it. Subsequent DIE lookups are O(log n)
    // map lookups instead of a full re-scan + re-parse of the raw bytes.
    std::map<uint64_t, AbbreviationEntry> table;
    uint64_t offset = abbrev_offset;
    while (offset < debug_abbrev_.size()) {
        uint64_t before = offset;
        AbbreviationEntry entry = parseAbbreviationEntry(offset);
        if (entry.code == 0) {
            break; // End of this table
        }
        table.emplace(entry.code, std::move(entry));
        if (offset <= before) {
            break;
        }
    }

    auto inserted = abbrev_table_cache_.emplace(abbrev_offset, std::move(table));
    return inserted.first->second;
}

const DIEParser::AbbreviationEntry*
DIEParser::lookupAbbreviationEntry(uint64_t code, uint64_t abbrev_offset) const {
    const auto& table = abbreviationTableAt(abbrev_offset);
    auto it = table.find(code);
    if (it == table.end()) {
        DEBUG_OUT("Abbreviation code " << code << " not found");
        return nullptr;
    }
    return &it->second;
}

void DIEParser::clearDecodeError() const {
    decode_error_ = false;
}

bool DIEParser::hasDecodeError() const {
    return decode_error_;
}

} // namespace dwarf
