#include "type_printer.hpp"
#include "attribute_parser.hpp"
#include "demangler.hpp"
#include "dwarf_utils.hpp"

#include <optional>
#include <sstream>
#include <iomanip>

namespace dwarf {
namespace {

std::optional<int64_t> decodeConstantOffsetExpression(const std::vector<uint8_t>& expr) {
    if (expr.empty()) {
        return std::nullopt;
    }

    uint64_t offset = 0;
    const auto* data = expr.data();
    const size_t size = expr.size();
    DwarfOp op = static_cast<DwarfOp>(data[offset++]);

    switch (op) {
        case DwarfOp::DW_OP_plus_uconst:
        case DwarfOp::DW_OP_constu:
            return static_cast<int64_t>(DwarfUtils::readULEB128(data, offset, size));
        case DwarfOp::DW_OP_consts:
            return DwarfUtils::readSLEB128(data, offset, size);
        default:
            break;
    }

    const uint8_t raw = static_cast<uint8_t>(op);
    if (raw >= static_cast<uint8_t>(DwarfOp::DW_OP_lit0) &&
        raw <= static_cast<uint8_t>(DwarfOp::DW_OP_lit31)) {
        return static_cast<int64_t>(raw - static_cast<uint8_t>(DwarfOp::DW_OP_lit0));
    }

    return std::nullopt;
}

std::optional<int64_t> decodeConstantOffsetAttribute(const std::shared_ptr<AttributeValue>& attr) {
    if (!attr) {
        return std::nullopt;
    }

    if (auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(attr)) {
        return static_cast<int64_t>(u->getValue());
    }
    if (auto s = std::dynamic_pointer_cast<SignedAttributeValue>(attr)) {
        return s->getValue();
    }
    if (auto block = std::dynamic_pointer_cast<BlockAttributeValue>(attr)) {
        return decodeConstantOffsetExpression(block->getData());
    }
    if (auto expr = std::dynamic_pointer_cast<ExpressionAttributeValue>(attr)) {
        return decodeConstantOffsetExpression(expr->getExpression());
    }
    if (auto loc = std::dynamic_pointer_cast<LocationAttributeValue>(attr)) {
        if (loc->getLocationType() == LocationAttributeValue::LocationType::EXPRESSION) {
            return decodeConstantOffsetExpression(loc->getData());
        }
    }

    return std::nullopt;
}

std::string formatFormalParameterPrefix(const std::shared_ptr<DIE>& param_die) {
    if (!param_die) {
        return "";
    }

    bool is_object_pointer = false;
    auto object_pointer_attr = param_die->getAttribute(DwarfAttribute::DW_AT_object_pointer);
    if (auto flag = std::dynamic_pointer_cast<FlagAttributeValue>(object_pointer_attr)) {
        is_object_pointer = flag->getValue();
    }

    bool is_artificial = false;
    auto artificial_attr = param_die->getAttribute(DwarfAttribute::DW_AT_artificial);
    if (auto flag = std::dynamic_pointer_cast<FlagAttributeValue>(artificial_attr)) {
        is_artificial = flag->getValue();
    }

    if (!is_object_pointer && !is_artificial) {
        return "";
    }

    std::string prefix = "/* ";
    if (is_object_pointer) {
        prefix += "object_pointer";
    }
    if (is_object_pointer && is_artificial) {
        prefix += ", ";
    }
    if (is_artificial) {
        prefix += "artificial";
    }
    prefix += " */ ";
    return prefix;
}

} // namespace

// RecursionGuard implementation
TypePrinter::RecursionGuard::RecursionGuard(const TypePrinter* printer, uint64_t offset)
    : printer_(printer), offset_(offset), valid_(true) {
    if (printer_->recursion_depth_ >= printer_->config_.max_recursion_depth) {
        valid_ = false;
        return;
    }
    if (printer_->visited_.count(offset)) {
        valid_ = false;
        return;
    }
    printer_->recursion_depth_++;
    printer_->visited_[offset] = true;
}

TypePrinter::RecursionGuard::~RecursionGuard() {
    if (valid_) {
        printer_->recursion_depth_--;
        printer_->visited_.erase(offset_);
    }
}

TypePrinter::TypePrinter(DIELookup die_lookup, TypePrinterConfig config)
    : die_lookup_(std::move(die_lookup)), config_(config) {}

std::string TypePrinter::formatType(const std::shared_ptr<DIE>& type_die) const {
    if (!type_die) {
        return "void";
    }
    return formatTypeInternal(type_die, "");
}

std::string TypePrinter::formatTypeRef(uint64_t type_offset) const {
    auto die = die_lookup_(type_offset);
    return formatType(die);
}

std::string TypePrinter::formatVariable(const std::shared_ptr<DIE>& var_die) const {
    if (!var_die) {
        return "";
    }

    std::string name = var_die->getName();
    if (name.empty()) {
        name = "<anonymous>";
    }

    // Get the type
    auto type_attr = var_die->getAttribute(DwarfAttribute::DW_AT_type);
    if (!type_attr) {
        return "void " + name;
    }

    // Try ReferenceAttributeValue first
    auto ref = std::dynamic_pointer_cast<ReferenceAttributeValue>(type_attr);
    if (ref) {
        auto type_die = die_lookup_(ref->getOffset());
        return formatTypeInternal(type_die, name);
    }

    // Try TypeAttributeValue
    auto type_val = std::dynamic_pointer_cast<TypeAttributeValue>(type_attr);
    if (type_val) {
        auto type_die = die_lookup_(type_val->getOffset());
        return formatTypeInternal(type_die, name);
    }

    return "void " + name;
}

// Helper function to get type offset from type attribute
static uint64_t getTypeOffset(const std::shared_ptr<AttributeValue>& type_attr) {
    if (!type_attr) return 0;

    auto ref = std::dynamic_pointer_cast<ReferenceAttributeValue>(type_attr);
    if (ref) return ref->getOffset();

    auto type_val = std::dynamic_pointer_cast<TypeAttributeValue>(type_attr);
    if (type_val) return type_val->getOffset();

    return 0;
}

std::string TypePrinter::formatFunction(const std::shared_ptr<DIE>& func_die) const {
    if (!func_die) {
        return "";
    }

    std::string result;

    // Get return type
    auto type_attr = func_die->getAttribute(DwarfAttribute::DW_AT_type);
    uint64_t type_offset = getTypeOffset(type_attr);
    if (type_offset != 0) {
        auto type_die = die_lookup_(type_offset);
        result = formatType(type_die);
    } else {
        result = "void";
    }

    result += " ";

    // Get function name
    std::string name = func_die->getName();
    // Try linkage name for mangled names
    auto linkage_attr = func_die->getAttribute(DwarfAttribute::DW_AT_linkage_name);
    if (linkage_attr) {
        auto str = std::dynamic_pointer_cast<StringAttributeValue>(linkage_attr);
        if (str) {
            name = Demangler::demangle(str->getValue());
        }
    }
    if (name.empty()) {
        name = "<anonymous>";
    }
    result += name;

    // Collect parameters
    result += "(";
    bool first = true;
    bool has_unspecified_params = false;

    for (const auto& child : func_die->getChildren()) {
        if (child->getTag() == DwarfTag::DW_TAG_formal_parameter) {
            if (!first) {
                result += ", ";
            }
            first = false;

            std::string param_name = child->getName();
            result += formatFormalParameterPrefix(child);
            auto param_type_attr = child->getAttribute(DwarfAttribute::DW_AT_type);
            uint64_t param_type_offset = getTypeOffset(param_type_attr);
            if (param_type_offset != 0) {
                auto param_type = die_lookup_(param_type_offset);
                if (config_.show_function_params && !param_name.empty()) {
                    result += formatTypeInternal(param_type, param_name);
                } else {
                    result += formatType(param_type);
                }
            } else {
                result += "void";
            }
        } else if (child->getTag() == DwarfTag::DW_TAG_unspecified_parameters) {
            has_unspecified_params = true;
        }
    }

    if (has_unspecified_params) {
        if (!first) {
            result += ", ";
        }
        result += "...";
    }

    result += ")";
    return result;
}

std::string TypePrinter::formatStructure(const std::shared_ptr<DIE>& type_die,
                                         bool include_members) const {
    if (!type_die) {
        return "";
    }

    std::string result;
    DwarfTag tag = type_die->getTag();

    if (tag == DwarfTag::DW_TAG_structure_type) {
        result = "struct ";
    } else if (tag == DwarfTag::DW_TAG_union_type) {
        result = "union ";
    } else if (tag == DwarfTag::DW_TAG_class_type) {
        result = "class ";
    } else if (tag == DwarfTag::DW_TAG_interface_type) {
        result = "interface ";
    } else {
        return "";
    }

    std::string name = type_die->getName();
    if (!name.empty()) {
        result += name;
    }

    if (!include_members) {
        return result;
    }

    result += " {\n";

    for (const auto& child : type_die->getChildren()) {
        if (child->getTag() == DwarfTag::DW_TAG_member) {
            result += config_.indent;

            auto access_attr = child->getAttribute(DwarfAttribute::DW_AT_accessibility);
            if (auto access = std::dynamic_pointer_cast<UnsignedAttributeValue>(access_attr)) {
                switch (access->getValue()) {
                    case 1: result += "public "; break;
                    case 2: result += "protected "; break;
                    case 3: result += "private "; break;
                    default: break;
                }
            }

            auto external_attr = child->getAttribute(DwarfAttribute::DW_AT_external);
            if (auto external = std::dynamic_pointer_cast<FlagAttributeValue>(external_attr)) {
                if (external->getValue()) {
                    result += "static ";
                }
            }

            // Get member type
            auto member_type_attr = child->getAttribute(DwarfAttribute::DW_AT_type);
            std::string member_decl;
            if (member_type_attr) {
                auto ref = std::dynamic_pointer_cast<ReferenceAttributeValue>(member_type_attr);
                if (ref) {
                    auto member_type = die_lookup_(ref->getOffset());
                    std::string member_name = child->getName();
                    if (member_name.empty()) {
                        member_name = "<anonymous>";
                    }
                    member_decl = formatTypeInternal(member_type, member_name);
                }
            }
            if (member_decl.empty()) {
                member_decl = "void " + child->getName();
            }
            result += member_decl;

            // Show offset if configured
            if (config_.show_offsets) {
                if (auto offset = decodeConstantOffsetAttribute(
                        child->getAttribute(DwarfAttribute::DW_AT_data_member_location))) {
                    std::ostringstream oss;
                    oss << " /* offset: " << *offset << " */";
                    result += oss.str();
                }
            }

            result += ";\n";
        } else if (child->getTag() == DwarfTag::DW_TAG_inheritance) {
            // Handle inheritance (base classes)
            auto base_type_attr = child->getAttribute(DwarfAttribute::DW_AT_type);
            if (base_type_attr) {
                auto ref = std::dynamic_pointer_cast<ReferenceAttributeValue>(base_type_attr);
                if (ref) {
                    result += config_.indent + "/* inherits from: ";
                    auto base_type = die_lookup_(ref->getOffset());

                    auto access_attr = child->getAttribute(DwarfAttribute::DW_AT_accessibility);
                    if (auto access = std::dynamic_pointer_cast<UnsignedAttributeValue>(access_attr)) {
                        switch (access->getValue()) {
                            case 1: result += "public "; break;
                            case 2: result += "protected "; break;
                            case 3: result += "private "; break;
                            default: break;
                        }
                    }

                    auto virtuality_attr = child->getAttribute(DwarfAttribute::DW_AT_virtuality);
                    if (auto virtuality = std::dynamic_pointer_cast<UnsignedAttributeValue>(virtuality_attr)) {
                        if (virtuality->getValue() != 0) {
                            result += "virtual ";
                        }
                    }

                    result += formatType(base_type);

                    if (config_.show_offsets) {
                        if (auto offset = decodeConstantOffsetAttribute(
                                child->getAttribute(DwarfAttribute::DW_AT_data_member_location))) {
                            std::ostringstream oss;
                            oss << " /* offset: " << *offset << " */";
                            result += oss.str();
                        }
                    }

                    result += " */\n";
                }
            }
        }
    }

    result += "}";

    if (config_.show_byte_sizes) {
        uint64_t size = getTypeSize(type_die);
        if (size > 0) {
            std::ostringstream oss;
            oss << " /* " << size << " bytes */";
            result += oss.str();
        }
    }

    return result;
}

std::string TypePrinter::formatEnum(const std::shared_ptr<DIE>& enum_die,
                                    bool include_values) const {
    if (!enum_die || enum_die->getTag() != DwarfTag::DW_TAG_enumeration_type) {
        return "";
    }

    std::string result = "enum ";

    // Check if it's a scoped enum (C++11 enum class)
    auto enum_class_attr = enum_die->getAttribute(DwarfAttribute::DW_AT_enum_class);
    if (enum_class_attr) {
        auto flag = std::dynamic_pointer_cast<FlagAttributeValue>(enum_class_attr);
        if (flag && flag->getValue()) {
            result = "enum class ";
        }
    }

    std::string name = enum_die->getName();
    if (!name.empty()) {
        result += name;
    }

    // Underlying type
    auto type_attr = enum_die->getAttribute(DwarfAttribute::DW_AT_type);
    if (type_attr) {
        auto ref = std::dynamic_pointer_cast<ReferenceAttributeValue>(type_attr);
        if (ref) {
            auto underlying_type = die_lookup_(ref->getOffset());
            result += " : " + formatType(underlying_type);
        }
    }

    if (!include_values) {
        return result;
    }

    result += " {\n";

    for (const auto& child : enum_die->getChildren()) {
        if (child->getTag() == DwarfTag::DW_TAG_enumerator) {
            result += config_.indent;
            std::string enum_name = child->getName();
            if (enum_name.empty()) {
                enum_name = "<anonymous>";
            }
            result += enum_name;

            auto const_value = child->getAttribute(DwarfAttribute::DW_AT_const_value);
            if (const_value) {
                auto uint_val = std::dynamic_pointer_cast<UnsignedAttributeValue>(const_value);
                auto int_val = std::dynamic_pointer_cast<SignedAttributeValue>(const_value);
                if (uint_val) {
                    result += " = " + std::to_string(uint_val->getValue());
                } else if (int_val) {
                    result += " = " + std::to_string(int_val->getValue());
                }
            }
            result += ",\n";
        }
    }

    result += "}";
    return result;
}

std::string TypePrinter::formatTypedef(const std::shared_ptr<DIE>& typedef_die) const {
    if (!typedef_die || typedef_die->getTag() != DwarfTag::DW_TAG_typedef) {
        return "";
    }

    std::string alias_name = typedef_die->getName();
    if (alias_name.empty()) {
        alias_name = "<anonymous>";
    }

    auto type_attr = typedef_die->getAttribute(DwarfAttribute::DW_AT_type);
    if (!type_attr) {
        return "typedef void " + alias_name;
    }

    auto ref = std::dynamic_pointer_cast<ReferenceAttributeValue>(type_attr);
    if (!ref) {
        return "typedef void " + alias_name;
    }

    auto underlying_type = die_lookup_(ref->getOffset());
    std::string underlying = formatType(underlying_type);

    return "typedef " + underlying + " " + alias_name;
}

uint64_t TypePrinter::getTypeSize(const std::shared_ptr<DIE>& type_die) const {
    if (!type_die) {
        return 0;
    }

    auto size_attr = type_die->getAttribute(DwarfAttribute::DW_AT_byte_size);
    if (size_attr) {
        auto uint_val = std::dynamic_pointer_cast<UnsignedAttributeValue>(size_attr);
        if (uint_val) {
            return uint_val->getValue();
        }
    }

    // For pointer/reference types, size is address size (typically 8 on 64-bit)
    DwarfTag tag = type_die->getTag();
    if (tag == DwarfTag::DW_TAG_pointer_type ||
        tag == DwarfTag::DW_TAG_reference_type) {
        return config_.pointer_size_bytes;
    }

    // For typedefs, get size of underlying type
    if (tag == DwarfTag::DW_TAG_typedef ||
        tag == DwarfTag::DW_TAG_const_type ||
        tag == DwarfTag::DW_TAG_volatile_type) {
        auto ref_type = getReferencedType(type_die);
        return getTypeSize(ref_type);
    }

    return 0;
}

bool TypePrinter::isPointerType(const std::shared_ptr<DIE>& type_die) const {
    if (!type_die) return false;
    return type_die->getTag() == DwarfTag::DW_TAG_pointer_type;
}

bool TypePrinter::isArrayType(const std::shared_ptr<DIE>& type_die) const {
    if (!type_die) return false;
    return type_die->getTag() == DwarfTag::DW_TAG_array_type;
}

bool TypePrinter::isFunctionType(const std::shared_ptr<DIE>& type_die) const {
    if (!type_die) return false;
    return type_die->getTag() == DwarfTag::DW_TAG_subroutine_type;
}

std::string TypePrinter::formatTypeInternal(const std::shared_ptr<DIE>& type_die,
                                            const std::string& var_name) const {
    if (!type_die) {
        if (var_name.empty()) {
            return "void";
        }
        return "void " + var_name;
    }

    RecursionGuard guard(this, type_die->getOffset());
    if (!guard.isValid()) {
        std::string result = "<recursive type>";
        if (!var_name.empty()) {
            result += " " + var_name;
        }
        return result;
    }

    DwarfTag tag = type_die->getTag();

    switch (tag) {
        case DwarfTag::DW_TAG_base_type:
            if (var_name.empty()) {
                return formatBaseType(type_die);
            }
            return formatBaseType(type_die) + " " + var_name;

        case DwarfTag::DW_TAG_unspecified_type: {
            std::string name = type_die->getName();
            if (name.empty()) {
                name = "void";
            }
            return var_name.empty() ? name : name + " " + var_name;
        }

        case DwarfTag::DW_TAG_string_type:
            return formatStringType(type_die, var_name);

        case DwarfTag::DW_TAG_set_type:
            return formatSetType(type_die, var_name);

        case DwarfTag::DW_TAG_file_type:
            return formatFileType(type_die, var_name);

        case DwarfTag::DW_TAG_pointer_type:
            return formatPointerType(type_die, var_name);

        case DwarfTag::DW_TAG_ptr_to_member_type:
            return formatPtrToMemberType(type_die, var_name);

        case DwarfTag::DW_TAG_reference_type:
            return formatReferenceType(type_die, var_name);

        case DwarfTag::DW_TAG_rvalue_reference_type: {
            auto referee = getReferencedType(type_die);
            std::string referee_str = formatType(referee);
            if (var_name.empty()) {
                return referee_str + "&&";
            }
            return referee_str + " &&" + var_name;
        }

        case DwarfTag::DW_TAG_atomic_type: {
            auto value_type = getReferencedType(type_die);
            std::string value_str = formatType(value_type);
            if (var_name.empty()) {
                return "_Atomic(" + value_str + ")";
            }
            return "_Atomic(" + value_str + ") " + var_name;
        }

        case DwarfTag::DW_TAG_array_type:
            return formatArrayType(type_die, var_name);

        case DwarfTag::DW_TAG_const_type:
            return formatConstType(type_die, var_name);

        case DwarfTag::DW_TAG_volatile_type:
            return formatVolatileType(type_die, var_name);

        case DwarfTag::DW_TAG_restrict_type:
            return formatRestrictType(type_die, var_name);

        case DwarfTag::DW_TAG_typedef:
            if (config_.expand_typedefs) {
                auto ref_type = getReferencedType(type_die);
                return formatTypeInternal(ref_type, var_name);
            }
            return formatTypedefType(type_die) + (var_name.empty() ? "" : " " + var_name);

        case DwarfTag::DW_TAG_structure_type:
            return formatStructType(type_die) + (var_name.empty() ? "" : " " + var_name);

        case DwarfTag::DW_TAG_union_type:
            return formatUnionType(type_die) + (var_name.empty() ? "" : " " + var_name);

        case DwarfTag::DW_TAG_class_type:
            return formatClassType(type_die) + (var_name.empty() ? "" : " " + var_name);

        case DwarfTag::DW_TAG_interface_type:
            return formatInterfaceType(type_die) + (var_name.empty() ? "" : " " + var_name);

        case DwarfTag::DW_TAG_enumeration_type:
            return formatEnumType(type_die) + (var_name.empty() ? "" : " " + var_name);

        case DwarfTag::DW_TAG_subroutine_type:
            return formatSubroutineType(type_die, var_name);

        default:
            break;
    }

    // Unknown type
    std::string result = "<unknown type>";
    if (!var_name.empty()) {
        result += " " + var_name;
    }
    return result;
}

std::string TypePrinter::formatBaseType(const std::shared_ptr<DIE>& die) const {
    std::string name = die->getName();
    if (!name.empty()) {
        return name;
    }

    // Synthesize name from encoding and size
    auto enc_attr = die->getAttribute(DwarfAttribute::DW_AT_encoding);
    auto size_attr = die->getAttribute(DwarfAttribute::DW_AT_byte_size);

    uint8_t encoding = 0;
    uint64_t byte_size = 0;

    if (enc_attr) {
        auto uint_val = std::dynamic_pointer_cast<UnsignedAttributeValue>(enc_attr);
        if (uint_val) {
            encoding = static_cast<uint8_t>(uint_val->getValue());
        }
    }

    if (size_attr) {
        auto uint_val = std::dynamic_pointer_cast<UnsignedAttributeValue>(size_attr);
        if (uint_val) {
            byte_size = uint_val->getValue();
        }
    }

    return getBaseTypeName(encoding, byte_size);
}

std::string TypePrinter::formatPointerType(const std::shared_ptr<DIE>& die,
                                           const std::string& var_name) const {
    auto pointee = getReferencedType(die);

    // Check if pointing to a function type
    if (pointee && pointee->getTag() == DwarfTag::DW_TAG_subroutine_type) {
        return formatSubroutineType(pointee, "*" + var_name);
    }

    // Check if pointing to an array
    if (pointee && pointee->getTag() == DwarfTag::DW_TAG_array_type) {
        std::string base = formatType(pointee);
        if (var_name.empty()) {
            return base + "*";
        }
        return base + " *" + var_name;
    }

    std::string pointee_str = formatType(pointee);
    if (var_name.empty()) {
        return pointee_str + "*";
    }
    return pointee_str + " *" + var_name;
}

std::string TypePrinter::formatReferenceType(const std::shared_ptr<DIE>& die,
                                              const std::string& var_name) const {
    auto referee = getReferencedType(die);
    std::string referee_str = formatType(referee);

    if (var_name.empty()) {
        return referee_str + "&";
    }
    return referee_str + " &" + var_name;
}

std::string TypePrinter::formatStringType(const std::shared_ptr<DIE>& die,
                                          const std::string& var_name) const {
    std::string name = die->getName();
    if (name.empty()) {
        auto char_type = getReferencedType(die);
        if (char_type) {
            std::string char_str = formatType(char_type);
            uint64_t size = getTypeSize(die);
            std::stringstream ss;
            ss << char_str << "[";
            if (size != 0) {
                ss << size;
            }
            ss << "]";
            name = ss.str();
        } else {
            name = "string";
        }
    }

    if (auto length = decodeConstantOffsetAttribute(
            die->getAttribute(DwarfAttribute::DW_AT_string_length))) {
        if (*length >= 0) {
            name += " [length=" + std::to_string(*length) + "]";
        }
    }

    return var_name.empty() ? name : name + " " + var_name;
}

std::string TypePrinter::formatSetType(const std::shared_ptr<DIE>& die,
                                       const std::string& var_name) const {
    std::string name = die->getName();
    if (name.empty()) {
        auto element_type = getReferencedType(die);
        if (element_type) {
            name = "set<" + formatType(element_type) + ">";
        } else {
            name = "set";
        }
    }
    return var_name.empty() ? name : name + " " + var_name;
}

std::string TypePrinter::formatFileType(const std::shared_ptr<DIE>& die,
                                        const std::string& var_name) const {
    std::string name = die->getName();
    if (name.empty()) {
        auto element_type = getReferencedType(die);
        name = "file";
        if (element_type) {
            name += "<" + formatType(element_type) + ">";
        }
        auto bounds = getArrayBounds(die);
        if (!bounds.empty()) {
            std::stringstream ss;
            ss << name;
            if (bounds[0].lower_bound == 0) {
                ss << "[" << bounds[0].count << "]";
            } else {
                int64_t upper = bounds[0].lower_bound + static_cast<int64_t>(bounds[0].count) - 1;
                ss << "[" << bounds[0].lower_bound << ".." << upper << "]";
            }
            name = ss.str();
        }
    }
    return var_name.empty() ? name : name + " " + var_name;
}

std::string TypePrinter::formatArrayType(const std::shared_ptr<DIE>& die,
                                         const std::string& var_name) const {
    auto element_type = getReferencedType(die);
    std::string element_str = formatType(element_type);

    auto bounds = getArrayBounds(die);
    std::string suffix = formatArraySuffix(bounds);

    std::string result;
    if (var_name.empty()) {
        result = element_str + suffix;
    } else {
        result = element_str + " " + var_name + suffix;
    }

    if (auto byte_stride = decodeConstantOffsetAttribute(
            die->getAttribute(DwarfAttribute::DW_AT_byte_stride))) {
        if (*byte_stride >= 0) {
            result += " [byte_stride=" + std::to_string(*byte_stride) + "]";
        }
    }

    if (auto bit_stride = decodeConstantOffsetAttribute(
            die->getAttribute(DwarfAttribute::DW_AT_bit_stride))) {
        if (*bit_stride >= 0) {
            result += " [bit_stride=" + std::to_string(*bit_stride) + "]";
        }
    }

    return result;
}

std::string TypePrinter::formatConstType(const std::shared_ptr<DIE>& die,
                                         const std::string& var_name) const {
    auto underlying = getReferencedType(die);

    if (!underlying) {
        if (var_name.empty()) {
            return "const void";
        }
        return "const void " + var_name;
    }

    // For pointers: int *const vs const int*
    if (underlying->getTag() == DwarfTag::DW_TAG_pointer_type) {
        auto pointee = getReferencedType(underlying);
        std::string pointee_str = formatType(pointee);
        if (var_name.empty()) {
            return pointee_str + " *const";
        }
        return pointee_str + " *const " + var_name;
    }

    std::string underlying_str = formatType(underlying);
    if (var_name.empty()) {
        return "const " + underlying_str;
    }
    return "const " + underlying_str + " " + var_name;
}

std::string TypePrinter::formatVolatileType(const std::shared_ptr<DIE>& die,
                                             const std::string& var_name) const {
    auto underlying = getReferencedType(die);
    std::string underlying_str = formatType(underlying);

    if (var_name.empty()) {
        return "volatile " + underlying_str;
    }
    return "volatile " + underlying_str + " " + var_name;
}

std::string TypePrinter::formatRestrictType(const std::shared_ptr<DIE>& die,
                                             const std::string& var_name) const {
    auto underlying = getReferencedType(die);
    std::string underlying_str = formatType(underlying);

    if (var_name.empty()) {
        return underlying_str + " restrict";
    }
    return underlying_str + " restrict " + var_name;
}

std::string TypePrinter::formatTypedefType(const std::shared_ptr<DIE>& die) const {
    std::string name = die->getName();
    if (name.empty()) {
        // Fall back to underlying type
        auto underlying = getReferencedType(die);
        return formatType(underlying);
    }
    return name;
}

std::string TypePrinter::formatStructType(const std::shared_ptr<DIE>& die) const {
    std::string name = die->getName();
    if (name.empty()) {
        return "struct <anonymous>";
    }
    return "struct " + name;
}

std::string TypePrinter::formatUnionType(const std::shared_ptr<DIE>& die) const {
    std::string name = die->getName();
    if (name.empty()) {
        return "union <anonymous>";
    }
    return "union " + name;
}

std::string TypePrinter::formatClassType(const std::shared_ptr<DIE>& die) const {
    std::string name = die->getName();
    if (name.empty()) {
        return "class <anonymous>";
    }
    // For classes, just use the name without "class" prefix (C++ style)
    return name;
}

std::string TypePrinter::formatInterfaceType(const std::shared_ptr<DIE>& die) const {
    std::string name = die->getName();
    if (name.empty()) {
        return "interface <anonymous>";
    }
    return "interface " + name;
}

std::string TypePrinter::formatEnumType(const std::shared_ptr<DIE>& die) const {
    if (!die || die->getTag() != DwarfTag::DW_TAG_enumeration_type) {
        return "enum <anonymous>";
    }

    bool is_scoped = false;
    auto enum_class_attr = die->getAttribute(DwarfAttribute::DW_AT_enum_class);
    if (enum_class_attr) {
        auto flag = std::dynamic_pointer_cast<FlagAttributeValue>(enum_class_attr);
        if (flag && flag->getValue()) {
            is_scoped = true;
        }
    }

    std::string name = die->getName();
    if (name.empty()) {
        return is_scoped ? "enum class <anonymous>" : "enum <anonymous>";
    }
    return (is_scoped ? "enum class " : "enum ") + name;
}

std::string TypePrinter::formatSubroutineType(const std::shared_ptr<DIE>& die,
                                               const std::string& var_name) const {
    // Return type
    auto return_type = getReferencedType(die);
    std::string return_str = formatType(return_type);

    // Parameters
    std::string params = "(";
    bool first = true;
    bool has_varargs = false;

    for (const auto& child : die->getChildren()) {
        if (child->getTag() == DwarfTag::DW_TAG_formal_parameter) {
            auto variable_parameter_attr = child->getAttribute(DwarfAttribute::DW_AT_variable_parameter);
            if (variable_parameter_attr) {
                auto flag = std::dynamic_pointer_cast<FlagAttributeValue>(variable_parameter_attr);
                if (flag && flag->getValue()) {
                    has_varargs = true;
                    continue;
                }
            }

            if (!first) {
                params += ", ";
            }
            first = false;

            params += formatFormalParameterPrefix(child);
            auto param_type_attr = child->getAttribute(DwarfAttribute::DW_AT_type);
            if (param_type_attr) {
                auto ref = std::dynamic_pointer_cast<ReferenceAttributeValue>(param_type_attr);
                if (ref) {
                    auto param_type = die_lookup_(ref->getOffset());
                    params += formatType(param_type);
                } else {
                    params += "void";
                }
            } else {
                params += "void";
            }
        } else if (child->getTag() == DwarfTag::DW_TAG_unspecified_parameters) {
            has_varargs = true;
        }
    }

    if (has_varargs) {
        if (!first) {
            params += ", ";
        }
        params += "...";
    }

    params += ")";

    // Function pointer: return_type (*name)(params)
    if (var_name.empty()) {
        return return_str + " (*)" + params;
    }
    return return_str + " (*" + var_name + ")" + params;
}

std::string TypePrinter::formatPtrToMemberType(const std::shared_ptr<DIE>& die,
                                                const std::string& var_name) const {
    // DW_AT_type is the type of the member
    // DW_AT_containing_type is the class type
    auto member_type = getReferencedType(die);

    auto containing_attr = die->getAttribute(DwarfAttribute::DW_AT_containing_type);
    std::string class_name = "";
    if (containing_attr) {
        auto ref = std::dynamic_pointer_cast<ReferenceAttributeValue>(containing_attr);
        if (ref) {
            auto class_die = die_lookup_(ref->getOffset());
            class_name = class_die ? class_die->getName() : "";
        }
    }

    std::string member_str = formatType(member_type);

    if (class_name.empty()) {
        class_name = "<unknown>";
    }

    if (var_name.empty()) {
        return member_str + " " + class_name + "::*";
    }
    return member_str + " " + class_name + "::*" + var_name;
}

std::shared_ptr<DIE> TypePrinter::getReferencedType(const std::shared_ptr<DIE>& die) const {
    if (!die) {
        return nullptr;
    }

    auto type_attr = die->getAttribute(DwarfAttribute::DW_AT_type);
    uint64_t offset = getTypeOffset(type_attr);
    if (offset == 0) {
        return nullptr;
    }

    return die_lookup_(offset);
}

std::string TypePrinter::getTypeName(const std::shared_ptr<DIE>& die) const {
    if (!die) {
        return "";
    }
    return die->getName();
}

std::string TypePrinter::getBaseTypeName(uint8_t encoding, uint64_t byte_size) const {
    DW_ATE enc = static_cast<DW_ATE>(encoding);

    if (config_.use_fixed_width_ints) {
        switch (enc) {
            case DW_ATE::DW_ATE_signed:
                switch (byte_size) {
                    case 1: return "int8_t";
                    case 2: return "int16_t";
                    case 4: return "int32_t";
                    case 8: return "int64_t";
                    default: break;
                }
                break;
            case DW_ATE::DW_ATE_unsigned:
                switch (byte_size) {
                    case 1: return "uint8_t";
                    case 2: return "uint16_t";
                    case 4: return "uint32_t";
                    case 8: return "uint64_t";
                    default: break;
                }
                break;
            default:
                break;
        }
    }

    switch (enc) {
        case DW_ATE::DW_ATE_boolean:
            return "bool";
        case DW_ATE::DW_ATE_signed:
            switch (byte_size) {
                case 1: return "signed char";
                case 2: return "short";
                case 4: return "int";
                case 8: return "long long";
                default: return "int";
            }
        case DW_ATE::DW_ATE_unsigned:
            switch (byte_size) {
                case 1: return "unsigned char";
                case 2: return "unsigned short";
                case 4: return "unsigned int";
                case 8: return "unsigned long long";
                default: return "unsigned int";
            }
        case DW_ATE::DW_ATE_signed_char:
            return "signed char";
        case DW_ATE::DW_ATE_unsigned_char:
            return "unsigned char";
        case DW_ATE::DW_ATE_float:
            switch (byte_size) {
                case 4: return "float";
                case 8: return "double";
                case 16: return "long double";
                default: return "double";
            }
        case DW_ATE::DW_ATE_complex_float:
            switch (byte_size) {
                case 8: return "float _Complex";
                case 16: return "double _Complex";
                default: return "_Complex";
            }
        case DW_ATE::DW_ATE_imaginary_float:
            return "_Imaginary";
        case DW_ATE::DW_ATE_address:
            return "void*";
        case DW_ATE::DW_ATE_UTF:
            switch (byte_size) {
                case 1: return "char8_t";
                case 2: return "char16_t";
                case 4: return "char32_t";
                default: return "char";
            }
        default:
            return "int";
    }
}

std::vector<TypePrinter::PrintedArrayBound> TypePrinter::getArrayBounds(const std::shared_ptr<DIE>& die) const {
    std::vector<PrintedArrayBound> bounds;

    for (const auto& child : die->getChildren()) {
        if (child->getTag() == DwarfTag::DW_TAG_subrange_type) {
            int64_t lower = 0;
            auto lower_attr = child->getAttribute(DwarfAttribute::DW_AT_lower_bound);
            if (auto uint_val = std::dynamic_pointer_cast<UnsignedAttributeValue>(lower_attr)) {
                lower = static_cast<int64_t>(uint_val->getValue());
            } else if (auto int_val = std::dynamic_pointer_cast<SignedAttributeValue>(lower_attr)) {
                lower = int_val->getValue();
            }

            // Try upper_bound first (0 to upper_bound inclusive = upper_bound+1 elements)
            auto upper_attr = child->getAttribute(DwarfAttribute::DW_AT_upper_bound);
            if (upper_attr) {
                auto uint_val = std::dynamic_pointer_cast<UnsignedAttributeValue>(upper_attr);
                auto int_val = std::dynamic_pointer_cast<SignedAttributeValue>(upper_attr);
                if (uint_val) {
                    int64_t upper = static_cast<int64_t>(uint_val->getValue());
                    bounds.push_back({lower, upper >= lower ? static_cast<uint64_t>(upper - lower + 1) : 0});
                } else if (int_val) {
                    int64_t upper = int_val->getValue();
                    bounds.push_back({lower, upper >= lower ? static_cast<uint64_t>(upper - lower + 1) : 0});
                }
                continue;
            }

            // Try count
            auto count_attr = child->getAttribute(DwarfAttribute::DW_AT_count);
            if (count_attr) {
                auto uint_val = std::dynamic_pointer_cast<UnsignedAttributeValue>(count_attr);
                if (uint_val) {
                    bounds.push_back({lower, uint_val->getValue()});
                }
                continue;
            }

            // Unknown size (VLA)
            bounds.push_back({lower, 0});
        }
    }

    return bounds;
}

std::string TypePrinter::formatArraySuffix(const std::vector<PrintedArrayBound>& bounds) const {
    std::string suffix;
    for (const auto& bound : bounds) {
        if (bound.count == 0) {
            suffix += "[]";
            continue;
        }

        if (bound.lower_bound == 0) {
            suffix += "[" + std::to_string(bound.count) + "]";
            continue;
        }

        int64_t upper = bound.lower_bound + static_cast<int64_t>(bound.count) - 1;
        suffix += "[" + std::to_string(bound.lower_bound) + ".." + std::to_string(upper) + "]";
    }
    return suffix;
}

} // namespace dwarf
