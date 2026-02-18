#include "variable_inspector.hpp"
#include "attribute_parser.hpp"
#include "dwarf_utils.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <algorithm>

namespace dwarf {

// InspectorMemoryReader default implementations
std::optional<std::string> InspectorMemoryReader::readString(uint64_t address, size_t max_len) const {
    std::string result;
    result.reserve(max_len);

    for (size_t i = 0; i < max_len; ++i) {
        char c;
        if (!read(address + i, &c, 1)) {
            return std::nullopt;
        }
        if (c == '\0') {
            break;
        }
        result.push_back(c);
    }

    return result;
}

std::optional<uint64_t> InspectorMemoryReader::readPointer(uint64_t address, uint8_t ptr_size) const {
    if (ptr_size == 4) {
        uint32_t val;
        if (read(address, &val, 4)) {
            return val;
        }
    } else if (ptr_size == 8) {
        uint64_t val;
        if (read(address, &val, 8)) {
            return val;
        }
    }
    return std::nullopt;
}

// VariableValue formatting
std::string VariableValue::toString(int indent) const {
    std::string prefix(indent * 2, ' ');
    std::ostringstream oss;

    if (!is_valid) {
        oss << prefix << "<" << error_message << ">";
        return oss.str();
    }

    if (is_struct && !members.empty()) {
        oss << prefix << type_name << " {\n";
        for (const auto& member : members) {
            oss << prefix << "  ." << member.name << " = ";
            if (member.value) {
                if (member.value->is_struct || member.value->is_array) {
                    oss << "\n" << member.value->toString(indent + 2);
                } else {
                    oss << member.value->toShortString();
                }
            } else {
                oss << "<unavailable>";
            }
            oss << "\n";
        }
        oss << prefix << "}";
    } else if (is_array && !elements.empty()) {
        oss << prefix << type_name << " [" << array_length << "] = {\n";
        for (size_t i = 0; i < elements.size(); ++i) {
            oss << prefix << "  [" << i << "] = ";
            if (elements[i]) {
                oss << elements[i]->toShortString();
            } else {
                oss << "<unavailable>";
            }
            oss << "\n";
        }
        if (elements.size() < array_length) {
            oss << prefix << "  ...\n";
        }
        oss << prefix << "}";
    } else {
        oss << prefix << toShortString();
    }

    return oss.str();
}

std::string VariableValue::toShortString() const {
    if (!is_valid) {
        return "<" + error_message + ">";
    }

    std::ostringstream oss;

    if (is_enum && !enum_name.empty()) {
        oss << enum_name;
        if (std::holds_alternative<int64_t>(value)) {
            oss << " (" << std::get<int64_t>(value) << ")";
        }
        return oss.str();
    }

    if (is_pointer) {
        if (pointer_address == 0) {
            oss << "nullptr";
        } else {
            oss << "0x" << std::hex << pointer_address;
            if (pointed_value && pointed_value->is_valid) {
                // For char*, show string
                if (type_name.find("char") != std::string::npos &&
                    std::holds_alternative<std::string>(pointed_value->value)) {
                    oss << " \"" << std::get<std::string>(pointed_value->value) << "\"";
                } else {
                    oss << " -> " << pointed_value->toShortString();
                }
            }
        }
        return oss.str();
    }

    if (std::holds_alternative<bool>(value)) {
        oss << (std::get<bool>(value) ? "true" : "false");
    } else if (std::holds_alternative<int64_t>(value)) {
        oss << std::get<int64_t>(value);
    } else if (std::holds_alternative<uint64_t>(value)) {
        oss << std::get<uint64_t>(value);
    } else if (std::holds_alternative<double>(value)) {
        oss << std::get<double>(value);
    } else if (std::holds_alternative<std::string>(value)) {
        oss << "\"" << std::get<std::string>(value) << "\"";
    } else {
        // Show raw bytes
        oss << "{ ";
        for (size_t i = 0; i < std::min(raw_data.size(), size_t(8)); ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(raw_data[i]) << " ";
        }
        if (raw_data.size() > 8) {
            oss << "...";
        }
        oss << "}";
    }

    return oss.str();
}

// StubMemoryReader implementation
bool StubMemoryReader::read(uint64_t address, void* buffer, size_t size) const {
    for (const auto& [region_addr, data] : regions_) {
        if (address >= region_addr && address + size <= region_addr + data.size()) {
            std::memcpy(buffer, data.data() + (address - region_addr), size);
            return true;
        }
    }
    return false;
}

void StubMemoryReader::addRegion(uint64_t address, const std::vector<uint8_t>& data) {
    regions_[address] = data;
}

void StubMemoryReader::addValue(uint64_t address, uint64_t value, size_t size) {
    std::vector<uint8_t> data(size);
    std::memcpy(data.data(), &value, size);
    regions_[address] = data;
}

void StubMemoryReader::addString(uint64_t address, const std::string& str) {
    std::vector<uint8_t> data(str.begin(), str.end());
    data.push_back(0);  // null terminator
    regions_[address] = data;
}

// StubRegisterReader implementation
std::optional<uint64_t> StubRegisterReader::readRegister(uint32_t reg_num) const {
    // AArch64 DWARF register conventions:
    // 29 = FP(x29), 31 = SP, 32 = PC.
    // Keep these available even if the caller only set PC/SP/FP via helpers.
    if (reg_num == 32) return pc_;
    if (reg_num == 31) return sp_;
    if (reg_num == 29) return fp_;

    auto it = registers_.find(reg_num);
    if (it != registers_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<uint64_t> StubRegisterReader::getAllRegisters() const {
    // Keep plenty of headroom for AArch64 DWARF register numbers (SIMD/SVE live well above GPRs).
    std::vector<uint64_t> result(256, 0);
    for (const auto& [num, val] : registers_) {
        if (num < result.size()) {
            result[num] = val;
        }
    }

    // Mirror commonly-used architectural registers into their DWARF numbers.
    if (31 < result.size()) result[31] = sp_;
    if (32 < result.size()) result[32] = pc_;
    if (29 < result.size()) result[29] = fp_;

    return result;
}

void StubRegisterReader::setRegister(uint32_t reg_num, uint64_t value) {
    registers_[reg_num] = value;
}

// VariableInspector implementation
VariableInspector::VariableInspector(DwarfParser& parser,
                                     const InspectorMemoryReader& memory,
                                     const InspectorRegisterReader& registers,
                                     InspectorConfig config)
    : parser_(parser)
    , memory_(memory)
    , registers_(registers)
    , config_(config) {

    // Initialize type printer
    auto die_lookup = [this](uint64_t offset) -> std::shared_ptr<DIE> {
        return parser_.findDIEByOffset(offset);
    };
    TypePrinterConfig tp_cfg;
    tp_cfg.pointer_size_bytes = (parser_.getAddressSize() == AddressSize::ADDR_64) ? 8 : 4;
    type_printer_ = std::make_unique<TypePrinter>(die_lookup, tp_cfg);
}

std::vector<VariableInfo> VariableInspector::getVariablesInScope(uint64_t pc) const {
    std::vector<VariableInfo> result;

    // Find the function containing this PC
    auto func = getFunctionAt(pc);
    if (func) {
        collectVariablesFromDIE(func, pc, result, true);
    }

    // Also collect globals
    for (const auto& cu : parser_.getCompilationUnits()) {
        for (const auto& child : cu->getChildren()) {
            if (child->getTag() == DwarfTag::DW_TAG_variable) {
                // Global variable
                auto info = createVariableInfo(child, pc);
                info.is_global = true;
                result.push_back(info);
            }
        }
    }

    return result;
}

std::vector<VariableInfo> VariableInspector::getLocals(uint64_t pc) const {
    std::vector<VariableInfo> result;

    auto func = getFunctionAt(pc);
    if (func) {
        collectVariablesFromDIE(func, pc, result, true);
    }

    // Filter to only locals (including parameters)
    result.erase(
        std::remove_if(result.begin(), result.end(),
            [](const VariableInfo& v) { return v.is_global; }),
        result.end());

    return result;
}

std::vector<VariableInfo> VariableInspector::getParameters(uint64_t pc) const {
    std::vector<VariableInfo> result;

    auto func = getFunctionAt(pc);
    if (!func) return result;

    for (const auto& child : func->getChildren()) {
        if (child->getTag() == DwarfTag::DW_TAG_formal_parameter) {
            auto info = createVariableInfo(child, pc);
            info.is_parameter = true;
            result.push_back(info);
        }
    }

    return result;
}

std::vector<VariableInfo> VariableInspector::getGlobals(uint64_t pc) const {
    std::vector<VariableInfo> result;

    for (const auto& cu : parser_.getCompilationUnits()) {
        for (const auto& child : cu->getChildren()) {
            if (child->getTag() == DwarfTag::DW_TAG_variable) {
                auto info = createVariableInfo(child, pc);
                info.is_global = true;
                result.push_back(info);
            }
        }
    }

    return result;
}

std::optional<VariableInfo> VariableInspector::findVariable(const std::string& name, uint64_t pc) const {
    auto vars = getVariablesInScope(pc);

    for (const auto& var : vars) {
        if (var.name == name) {
            return var;
        }
    }

    return std::nullopt;
}

void VariableInspector::collectVariablesFromDIE(const std::shared_ptr<DIE>& die,
                                                  uint64_t pc,
                                                  std::vector<VariableInfo>& vars,
                                                  bool in_scope) const {
    if (!die) return;

    // Check if this DIE defines scope boundaries
    bool die_in_scope = in_scope;
    if (die->getTag() == DwarfTag::DW_TAG_lexical_block ||
        die->getTag() == DwarfTag::DW_TAG_inlined_subroutine) {
        die_in_scope = isInScope(die, pc);
    }

    // Collect variables and parameters
    for (const auto& child : die->getChildren()) {
        DwarfTag tag = child->getTag();

        if (tag == DwarfTag::DW_TAG_variable) {
            if (die_in_scope) {
                auto info = createVariableInfo(child, pc);
                info.is_local = true;
                if (!info.is_artificial || config_.include_artificial) {
                    vars.push_back(info);
                }
            }
        } else if (tag == DwarfTag::DW_TAG_formal_parameter) {
            auto info = createVariableInfo(child, pc);
            info.is_parameter = true;
            if (!info.is_artificial || config_.include_artificial) {
                vars.push_back(info);
            }
        } else if (tag == DwarfTag::DW_TAG_lexical_block ||
                   tag == DwarfTag::DW_TAG_inlined_subroutine) {
            // Recurse into nested scopes
            collectVariablesFromDIE(child, pc, vars, die_in_scope);
        }
    }
}

bool VariableInspector::isInScope(const std::shared_ptr<DIE>& die, uint64_t pc) const {
    if (!die) return false;

    // Check low_pc/high_pc
    auto low_pc_attr = die->getAttribute(DwarfAttribute::DW_AT_low_pc);
    auto high_pc_attr = die->getAttribute(DwarfAttribute::DW_AT_high_pc);

    if (low_pc_attr && high_pc_attr) {
        uint64_t low_pc = 0, high_pc = 0;

        auto addr = std::dynamic_pointer_cast<AddressAttributeValue>(low_pc_attr);
        auto uint_val = std::dynamic_pointer_cast<UnsignedAttributeValue>(low_pc_attr);
        if (addr) low_pc = addr->getAddress();
        else if (uint_val) low_pc = uint_val->getValue();

        addr = std::dynamic_pointer_cast<AddressAttributeValue>(high_pc_attr);
        uint_val = std::dynamic_pointer_cast<UnsignedAttributeValue>(high_pc_attr);
        if (addr) high_pc = addr->getAddress();
        else if (uint_val) high_pc = low_pc + uint_val->getValue();  // offset form

        return isInRange(low_pc, high_pc, pc);
    }

    // Check DW_AT_ranges for non-contiguous code ranges
    auto ranges_attr = die->getAttribute(DwarfAttribute::DW_AT_ranges);
    if (ranges_attr) {
        auto ranges = std::dynamic_pointer_cast<RangeAttributeValue>(ranges_attr);
        if (ranges) {
            std::vector<DwarfUtils::AddressRange> conv;
            conv.reserve(ranges->getRanges().size());
            for (const auto& r : ranges->getRanges()) {
                conv.emplace_back(r.start, r.end, r.is_base_address);
            }
            return DwarfUtils::isAddressInRanges(pc, conv);
        }
    }

    return true;  // Assume in scope if no range info
}

bool VariableInspector::isInRange(uint64_t low_pc, uint64_t high_pc, uint64_t pc) const {
    return pc >= low_pc && pc < high_pc;
}

VariableInfo VariableInspector::createVariableInfo(const std::shared_ptr<DIE>& var_die, uint64_t pc) const {
    VariableInfo info;
    info.name = var_die->getName();
    info.die = var_die;

    // Get type
    auto type_attr = var_die->getAttribute(DwarfAttribute::DW_AT_type);
    if (type_attr) {
        uint64_t type_offset = 0;
        auto ref = std::dynamic_pointer_cast<ReferenceAttributeValue>(type_attr);
        auto type_val = std::dynamic_pointer_cast<TypeAttributeValue>(type_attr);
        if (ref) type_offset = ref->getOffset();
        else if (type_val) type_offset = type_val->getOffset();

        if (type_offset != 0) {
            info.type_die = parser_.findDIEByOffset(type_offset);
            if (info.type_die) {
                info.type_string = type_printer_->formatType(info.type_die);
                info.byte_size = type_printer_->getTypeSize(info.type_die);
            }
        }
    }

    // Check if artificial
    auto artificial_attr = var_die->getAttribute(DwarfAttribute::DW_AT_artificial);
    if (artificial_attr) {
        auto flag = std::dynamic_pointer_cast<FlagAttributeValue>(artificial_attr);
        info.is_artificial = flag && flag->getValue();
    }

    // Get declaration location
    auto decl_file_attr = var_die->getAttribute(DwarfAttribute::DW_AT_decl_file);
    auto decl_line_attr = var_die->getAttribute(DwarfAttribute::DW_AT_decl_line);
    if (decl_file_attr) {
        auto uint_val = std::dynamic_pointer_cast<UnsignedAttributeValue>(decl_file_attr);
        if (uint_val) {
            uint64_t file_index = uint_val->getValue();
            info.decl_file = "file#" + std::to_string(file_index);

            // Best-effort resolve file index via the CU's line table (DW_AT_stmt_list).
            // This uses the fact that CU-relative file indices refer to the CU's line program file table.
            auto cus = parser_.getCompilationUnits();
            std::shared_ptr<DIE> best_cu;
            uint64_t best_off = 0;
            uint64_t die_off = var_die->getOffset();
            for (const auto& cu : cus) {
                if (!cu) continue;
                uint64_t cu_off = cu->getOffset();
                if (cu_off <= die_off && cu_off >= best_off) {
                    best_off = cu_off;
                    best_cu = cu;
                }
            }

            if (best_cu) {
                auto stmt_list_attr = best_cu->getAttribute(DwarfAttribute::DW_AT_stmt_list);
                auto line_attr = std::dynamic_pointer_cast<LineAttributeValue>(stmt_list_attr);
                if (line_attr && file_index > 0) {
                    const auto& files = line_attr->getFiles();
                    const auto& dirs = line_attr->getDirectories();
                    if (file_index <= files.size()) {
                        const auto& fe = files[file_index - 1];

                        std::string dir;
                        if (fe.dir_index == 0) {
                            auto comp_dir_attr = best_cu->getAttribute(DwarfAttribute::DW_AT_comp_dir);
                            auto comp_dir = std::dynamic_pointer_cast<StringAttributeValue>(comp_dir_attr);
                            if (comp_dir) dir = comp_dir->getValue();
                        } else if (fe.dir_index <= dirs.size()) {
                            dir = dirs[fe.dir_index - 1];
                        }

                        if (!dir.empty() && dir.back() != '/') dir.push_back('/');
                        info.decl_file = dir + fe.filename;
                    }
                }
            }
        }
    }
    if (decl_line_attr) {
        auto uint_val = std::dynamic_pointer_cast<UnsignedAttributeValue>(decl_line_attr);
        if (uint_val) {
            info.decl_line = static_cast<uint32_t>(uint_val->getValue());
        }
    }

    // Evaluate location and value
    info.location = evaluateLocation(var_die, pc);
    if (info.location.valid() && info.type_die) {
        info.value = readValue(info.location, info.type_die, 0);
    }

    return info;
}

VariableLocation VariableInspector::evaluateLocation(const std::shared_ptr<DIE>& var_die, uint64_t pc) const {
    if (!var_die) return VariableLocation();

    // Prepare evaluation context and delegate to DwarfParser, which understands
    // LocationAttributeValue (expressions + lists) produced by AttributeParser.
    EvaluationContext ctx;
    ctx.entry_registers = registers_.getAllRegisters();

    // Best-effort frame base: prefer FP, fall back to SP.
    if (auto fp = registers_.getFP()) {
        ctx.frame_base = *fp;
    } else {
        ctx.frame_base = registers_.getSP();
    }

    // Best-effort CFA from CFI rules if available.
    UnwindInfo ui = parser_.getUnwindInfo(pc);
    if (ui.valid) {
        ctx.cfa = ui.computeCFA(
            ctx.entry_registers,
            [this](uint64_t addr) -> uint64_t {
                uint64_t v = 0;
                if (!memory_.read(addr, &v, sizeof(v))) return 0;
                return v;
            });
    }

    parser_.setVariableEvaluationContext(ctx);
    parser_.setMemoryReader([this](uint64_t addr, size_t size, void* buf) -> bool {
        return memory_.read(addr, buf, size);
    });

    return parser_.getVariableLocation(var_die, pc);
}

std::shared_ptr<VariableValue> VariableInspector::readValue(const VariableLocation& location,
                                                             const std::shared_ptr<DIE>& type_die,
                                                             int depth) const {
    if (!type_die) {
        auto val = std::make_shared<VariableValue>();
        val->error_message = "unknown type";
        return val;
    }

    if (depth > static_cast<int>(config_.max_pointer_depth)) {
        auto val = std::make_shared<VariableValue>();
        val->error_message = "max depth exceeded";
        return val;
    }

    // Get the base type (skip typedefs, const, volatile)
    auto base_type = getBaseType(type_die);
    if (!base_type) {
        auto val = std::make_shared<VariableValue>();
        val->error_message = "cannot resolve type";
        return val;
    }

    DwarfTag tag = base_type->getTag();

    switch (tag) {
        case DwarfTag::DW_TAG_base_type:
            return readPrimitiveValue(location, base_type);

        case DwarfTag::DW_TAG_pointer_type:
            return readPointerValue(location, base_type, depth);

        case DwarfTag::DW_TAG_array_type:
            return readArrayValue(location, base_type, depth);

        case DwarfTag::DW_TAG_structure_type:
        case DwarfTag::DW_TAG_class_type:
        case DwarfTag::DW_TAG_union_type:
            return readStructValue(location, base_type, depth);

        case DwarfTag::DW_TAG_enumeration_type:
            return readEnumValue(location, base_type);

        case DwarfTag::DW_TAG_reference_type:
            // References are like pointers
            return readPointerValue(location, base_type, depth);

        default: {
            auto val = std::make_shared<VariableValue>();
            val->type_name = type_printer_->formatType(type_die);
            val->byte_size = type_printer_->getTypeSize(type_die);

            // Try to read raw bytes
            auto raw = readRawBytes(location, val->byte_size);
            if (raw) {
                val->raw_data = *raw;
                val->is_valid = true;
            } else {
                val->error_message = "cannot read value";
            }
            return val;
        }
    }
}

std::shared_ptr<VariableValue> VariableInspector::readPrimitiveValue(
    const VariableLocation& location,
    const std::shared_ptr<DIE>& type_die) const {

    auto val = std::make_shared<VariableValue>();
    val->type_name = type_printer_->formatType(type_die);
    val->byte_size = type_printer_->getTypeSize(type_die);

    auto raw = readRawBytes(location, val->byte_size);
    if (!raw) {
        val->error_message = "cannot read value";
        return val;
    }
    val->raw_data = *raw;

    // Get encoding
    auto enc_attr = type_die->getAttribute(DwarfAttribute::DW_AT_encoding);
    uint8_t encoding = 0;
    if (enc_attr) {
        auto uint_val = std::dynamic_pointer_cast<UnsignedAttributeValue>(enc_attr);
        if (uint_val) encoding = static_cast<uint8_t>(uint_val->getValue());
    }

    // Interpret based on encoding and size
    DW_ATE ate = static_cast<DW_ATE>(encoding);

    switch (ate) {
        case DW_ATE::DW_ATE_boolean:
            val->value = (raw->at(0) != 0);
            break;

        case DW_ATE::DW_ATE_signed:
        case DW_ATE::DW_ATE_signed_char:
            switch (val->byte_size) {
                case 1: val->value = static_cast<int64_t>(*reinterpret_cast<int8_t*>(raw->data())); break;
                case 2: val->value = static_cast<int64_t>(*reinterpret_cast<int16_t*>(raw->data())); break;
                case 4: val->value = static_cast<int64_t>(*reinterpret_cast<int32_t*>(raw->data())); break;
                case 8: val->value = *reinterpret_cast<int64_t*>(raw->data()); break;
            }
            break;

        case DW_ATE::DW_ATE_unsigned:
        case DW_ATE::DW_ATE_unsigned_char:
            switch (val->byte_size) {
                case 1: val->value = static_cast<uint64_t>(raw->at(0)); break;
                case 2: val->value = static_cast<uint64_t>(*reinterpret_cast<uint16_t*>(raw->data())); break;
                case 4: val->value = static_cast<uint64_t>(*reinterpret_cast<uint32_t*>(raw->data())); break;
                case 8: val->value = *reinterpret_cast<uint64_t*>(raw->data()); break;
            }
            break;

        case DW_ATE::DW_ATE_float:
            switch (val->byte_size) {
                case 4: val->value = static_cast<double>(*reinterpret_cast<float*>(raw->data())); break;
                case 8: val->value = *reinterpret_cast<double*>(raw->data()); break;
            }
            break;

        default:
            // Store as unsigned
            if (val->byte_size <= 8) {
                uint64_t v = 0;
                std::memcpy(&v, raw->data(), val->byte_size);
                val->value = v;
            }
            break;
    }

    val->is_valid = true;
    return val;
}

std::shared_ptr<VariableValue> VariableInspector::readPointerValue(
    const VariableLocation& location,
    const std::shared_ptr<DIE>& type_die,
    int depth) const {

    auto val = std::make_shared<VariableValue>();
    val->type_name = type_printer_->formatType(type_die);
    val->byte_size = (parser_.getAddressSize() == AddressSize::ADDR_64) ? 8 : 4;
    val->is_pointer = true;

    auto raw = readRawBytes(location, val->byte_size);
    if (!raw) {
        val->error_message = "cannot read pointer";
        return val;
    }
    val->raw_data = *raw;

    uint64_t ptr_val = 0;
    if (val->byte_size == 4) {
        uint32_t tmp = 0;
        std::memcpy(&tmp, raw->data(), 4);
        ptr_val = tmp;
    } else {
        std::memcpy(&ptr_val, raw->data(), 8);
    }
    val->pointer_address = ptr_val;
    val->value = ptr_val;
    val->is_valid = true;

    // Try to dereference
    if (config_.resolve_pointers && ptr_val != 0 && depth < static_cast<int>(config_.max_pointer_depth)) {
        // Get pointed-to type
        auto pointed_type_attr = type_die->getAttribute(DwarfAttribute::DW_AT_type);
        if (pointed_type_attr) {
            uint64_t pointed_offset = 0;
            auto ref = std::dynamic_pointer_cast<ReferenceAttributeValue>(pointed_type_attr);
            auto type_val = std::dynamic_pointer_cast<TypeAttributeValue>(pointed_type_attr);
            if (ref) pointed_offset = ref->getOffset();
            else if (type_val) pointed_offset = type_val->getOffset();

            if (pointed_offset != 0) {
                auto pointed_type = parser_.findDIEByOffset(pointed_offset);
                if (pointed_type) {
                    // Check if it's a char* - try to read as string
                    auto base_pointed = getBaseType(pointed_type);
                    if (base_pointed && base_pointed->getTag() == DwarfTag::DW_TAG_base_type) {
                        std::string name = base_pointed->getName();
                        if (name == "char" || name == "signed char" || name == "unsigned char") {
                            auto str = memory_.readString(ptr_val, config_.max_string_length);
                            if (str) {
                                val->pointed_value = std::make_shared<VariableValue>();
                                val->pointed_value->value = *str;
                                val->pointed_value->is_valid = true;
                                return val;
                            }
                        }
                    }

                    // Read as normal value
                    VariableLocation deref_loc;
                    deref_loc.type = VariableLocationType::MEMORY;
                    deref_loc.address = ptr_val;
                    val->pointed_value = readValue(deref_loc, pointed_type, depth + 1);
                }
            }
        }
    }

    return val;
}

std::shared_ptr<VariableValue> VariableInspector::readArrayValue(
    const VariableLocation& location,
    const std::shared_ptr<DIE>& type_die,
    int depth) const {

    auto val = std::make_shared<VariableValue>();
    val->type_name = type_printer_->formatType(type_die);
    val->is_array = true;

    // Get element type
    auto elem_type_attr = type_die->getAttribute(DwarfAttribute::DW_AT_type);
    std::shared_ptr<DIE> elem_type;
    if (elem_type_attr) {
        uint64_t offset = 0;
        auto ref = std::dynamic_pointer_cast<ReferenceAttributeValue>(elem_type_attr);
        auto type_val = std::dynamic_pointer_cast<TypeAttributeValue>(elem_type_attr);
        if (ref) offset = ref->getOffset();
        else if (type_val) offset = type_val->getOffset();
        if (offset != 0) elem_type = parser_.findDIEByOffset(offset);
    }

    if (!elem_type) {
        val->error_message = "unknown element type";
        return val;
    }

    uint64_t elem_size = type_printer_->getTypeSize(elem_type);

    // Get array dimensions
    uint64_t array_len = 0;
    for (const auto& child : type_die->getChildren()) {
        if (child->getTag() == DwarfTag::DW_TAG_subrange_type) {
            auto upper = child->getAttribute(DwarfAttribute::DW_AT_upper_bound);
            auto count = child->getAttribute(DwarfAttribute::DW_AT_count);

            if (upper) {
                auto uint_val = std::dynamic_pointer_cast<UnsignedAttributeValue>(upper);
                if (uint_val) array_len = uint_val->getValue() + 1;
            } else if (count) {
                auto uint_val = std::dynamic_pointer_cast<UnsignedAttributeValue>(count);
                if (uint_val) array_len = uint_val->getValue();
            }
            break;
        }
    }

    val->array_length = array_len;
    val->byte_size = array_len * elem_size;

    // Read elements (up to max)
    size_t num_to_read = std::min(static_cast<size_t>(array_len),
                                   static_cast<size_t>(config_.max_array_elements));

    for (size_t i = 0; i < num_to_read; ++i) {
        VariableLocation elem_loc = location;
        if (location.type == VariableLocationType::MEMORY) {
            elem_loc.address = location.address + i * elem_size;
        } else {
            // Can't handle array in registers
            break;
        }

        val->elements.push_back(readValue(elem_loc, elem_type, depth + 1));
    }

    val->is_valid = true;
    return val;
}

std::shared_ptr<VariableValue> VariableInspector::readStructValue(
    const VariableLocation& location,
    const std::shared_ptr<DIE>& type_die,
    int depth) const {

    auto val = std::make_shared<VariableValue>();
    val->type_name = type_printer_->formatType(type_die);
    val->byte_size = type_printer_->getTypeSize(type_die);
    val->is_struct = true;

    if (depth > static_cast<int>(config_.max_struct_depth)) {
        val->error_message = "max struct depth";
        return val;
    }

    // Read members
    for (const auto& child : type_die->getChildren()) {
        if (child->getTag() != DwarfTag::DW_TAG_member) continue;

        std::string member_name = child->getName();

        // Get member offset
        uint64_t member_offset = 0;
        auto loc_attr = child->getAttribute(DwarfAttribute::DW_AT_data_member_location);
        if (loc_attr) {
            auto uint_val = std::dynamic_pointer_cast<UnsignedAttributeValue>(loc_attr);
            if (uint_val) member_offset = uint_val->getValue();
        }

        // Get member type
        auto member_type_attr = child->getAttribute(DwarfAttribute::DW_AT_type);
        if (!member_type_attr) continue;

        uint64_t type_offset = 0;
        auto ref = std::dynamic_pointer_cast<ReferenceAttributeValue>(member_type_attr);
        auto type_val = std::dynamic_pointer_cast<TypeAttributeValue>(member_type_attr);
        if (ref) type_offset = ref->getOffset();
        else if (type_val) type_offset = type_val->getOffset();
        if (type_offset == 0) continue;

        auto member_type = parser_.findDIEByOffset(type_offset);
        if (!member_type) continue;

        // Create location for member
        VariableLocation member_loc = location;
        if (location.type == VariableLocationType::MEMORY) {
            member_loc.address = location.address + member_offset;
        } else {
            // Can't handle struct members in registers easily
            continue;
        }

        VariableValue::MemberValue mv;
        mv.name = member_name;
        mv.offset = member_offset;
        mv.value = readValue(member_loc, member_type, depth + 1);

        val->members.push_back(mv);
    }

    val->is_valid = true;
    return val;
}

std::shared_ptr<VariableValue> VariableInspector::readEnumValue(
    const VariableLocation& location,
    const std::shared_ptr<DIE>& type_die) const {

    auto val = std::make_shared<VariableValue>();
    val->type_name = type_printer_->formatType(type_die);
    val->byte_size = type_printer_->getTypeSize(type_die);
    val->is_enum = true;

    auto raw = readRawBytes(location, val->byte_size);
    if (!raw) {
        val->error_message = "cannot read enum";
        return val;
    }
    val->raw_data = *raw;

    int64_t enum_val = 0;
    if (val->byte_size <= 8) {
        std::memcpy(&enum_val, raw->data(), val->byte_size);
    }
    val->value = enum_val;

    // Find the enumerator name
    for (const auto& child : type_die->getChildren()) {
        if (child->getTag() == DwarfTag::DW_TAG_enumerator) {
            auto const_val = child->getAttribute(DwarfAttribute::DW_AT_const_value);
            if (const_val) {
                int64_t ev = 0;
                auto uint_attr = std::dynamic_pointer_cast<UnsignedAttributeValue>(const_val);
                auto int_attr = std::dynamic_pointer_cast<SignedAttributeValue>(const_val);
                if (uint_attr) ev = static_cast<int64_t>(uint_attr->getValue());
                else if (int_attr) ev = int_attr->getValue();

                if (ev == enum_val) {
                    val->enum_name = child->getName();
                    break;
                }
            }
        }
    }

    val->is_valid = true;
    return val;
}

std::shared_ptr<DIE> VariableInspector::getBaseType(const std::shared_ptr<DIE>& type_die) const {
    if (!type_die) return nullptr;

    DwarfTag tag = type_die->getTag();

    // Skip modifiers
    if (tag == DwarfTag::DW_TAG_typedef ||
        tag == DwarfTag::DW_TAG_const_type ||
        tag == DwarfTag::DW_TAG_volatile_type ||
        tag == DwarfTag::DW_TAG_restrict_type) {

        auto type_attr = type_die->getAttribute(DwarfAttribute::DW_AT_type);
        if (type_attr) {
            uint64_t offset = 0;
            auto ref = std::dynamic_pointer_cast<ReferenceAttributeValue>(type_attr);
            auto type_val = std::dynamic_pointer_cast<TypeAttributeValue>(type_attr);
            if (ref) offset = ref->getOffset();
            else if (type_val) offset = type_val->getOffset();

            if (offset != 0) {
                auto underlying = parser_.findDIEByOffset(offset);
                return getBaseType(underlying);
            }
        }
    }

    return type_die;
}

std::optional<std::vector<uint8_t>> VariableInspector::readRawBytes(
    const VariableLocation& location,
    size_t size) const {

    std::vector<uint8_t> data(size);

    switch (location.type) {
        case VariableLocationType::MEMORY:
            if (memory_.read(location.address, data.data(), size)) {
                return data;
            }
            break;

        case VariableLocationType::REGISTER: {
            auto reg_val = registers_.readRegister(static_cast<uint32_t>(location.reg_num));
            if (reg_val && size <= sizeof(uint64_t)) {
                std::memcpy(data.data(), &(*reg_val), size);
                return data;
            }
            break;
        }

        case VariableLocationType::IMPLICIT:
            if (location.implicit_value.size() >= size) {
                data.assign(location.implicit_value.begin(),
                            location.implicit_value.begin() + size);
                return data;
            }
            break;

        default:
            break;
    }

    return std::nullopt;
}

std::shared_ptr<VariableValue> VariableInspector::inspectVariable(
    const std::shared_ptr<DIE>& var_die,
    uint64_t pc,
    int depth) const {

    auto location = evaluateLocation(var_die, pc);
    if (!location.valid()) {
        auto val = std::make_shared<VariableValue>();
        val->error_message = VariableLocationEvaluator::formatLocation(location);
        return val;
    }

    auto type_attr = var_die->getAttribute(DwarfAttribute::DW_AT_type);
    if (!type_attr) {
        auto val = std::make_shared<VariableValue>();
        val->error_message = "no type information";
        return val;
    }

    uint64_t type_offset = 0;
    auto ref = std::dynamic_pointer_cast<ReferenceAttributeValue>(type_attr);
    auto type_val = std::dynamic_pointer_cast<TypeAttributeValue>(type_attr);
    if (ref) type_offset = ref->getOffset();
    else if (type_val) type_offset = type_val->getOffset();

    auto type_die = parser_.findDIEByOffset(type_offset);
    return readValue(location, type_die, depth);
}

std::shared_ptr<DIE> VariableInspector::getFunctionAt(uint64_t pc) const {
    return parser_.getFunctionAt(pc);
}

std::shared_ptr<DIE> VariableInspector::getLexicalBlockAt(uint64_t pc) const {
    auto func = getFunctionAt(pc);
    if (!func) return nullptr;

    // Find innermost lexical block
    std::shared_ptr<DIE> innermost = nullptr;
    uint64_t smallest_range = UINT64_MAX;

    std::function<void(const std::shared_ptr<DIE>&)> search = [&](const std::shared_ptr<DIE>& die) {
        if (die->getTag() == DwarfTag::DW_TAG_lexical_block) {
            if (isInScope(die, pc)) {
                auto low_pc_attr = die->getAttribute(DwarfAttribute::DW_AT_low_pc);
                auto high_pc_attr = die->getAttribute(DwarfAttribute::DW_AT_high_pc);

                if (low_pc_attr && high_pc_attr) {
                    uint64_t low = 0, high = 0;
                    // ... extract values ...
                    uint64_t range = high - low;
                    if (range < smallest_range) {
                        smallest_range = range;
                        innermost = die;
                    }
                }
            }
        }

        for (const auto& child : die->getChildren()) {
            search(child);
        }
    };

    search(func);
    return innermost;
}

void VariableInspector::printVariables(uint64_t pc, bool verbose) const {
    auto vars = getVariablesInScope(pc);

    std::cout << "Variables in scope at 0x" << std::hex << pc << std::dec << ":\n";
    std::cout << std::string(50, '-') << "\n";

    for (const auto& var : vars) {
        printVariable(var, verbose);
    }
}

void VariableInspector::printVariable(const VariableInfo& var, bool verbose) const {
    std::cout << "  ";

    // Prefix
    if (var.is_parameter) std::cout << "[param] ";
    else if (var.is_local) std::cout << "[local] ";
    else if (var.is_global) std::cout << "[global] ";

    // Type and name
    std::cout << var.type_string << " " << var.name;

    // Location
    if (verbose && var.location.valid()) {
        std::cout << " @ " << VariableLocationEvaluator::formatLocation(var.location);
    }

    // Value
    if (var.value) {
        std::cout << " = " << var.value->toShortString();
    } else {
        std::cout << " = <" << VariableLocationEvaluator::formatLocation(var.location) << ">";
    }

    std::cout << "\n";

    // Detailed value for structs/arrays
    if (verbose && var.value && (var.value->is_struct || var.value->is_array)) {
        std::cout << var.value->toString(2) << "\n";
    }
}

} // namespace dwarf
