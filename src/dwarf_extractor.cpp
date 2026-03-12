#include "dwarf_extractor.hpp"
#include "dwarf_utils.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>

namespace dwarf {

DwarfExtractor::DwarfExtractor(std::shared_ptr<DwarfParser> parser)
    : parser_(parser), verbose_(false) {
    database_ = std::make_shared<DwarfDatabase>();
    uint8_t ptr_size = (parser_ && parser_->getAddressSize() == AddressSize::ADDR_32) ? 4 : 8;
    auto die_lookup = [this](uint64_t offset) -> std::shared_ptr<DIE> {
        return parser_ ? parser_->findDIEByOffset(offset) : nullptr;
    };
    type_system_ = std::make_shared<TypeSystem>(ptr_size, die_lookup);
}

std::shared_ptr<DwarfDatabase> DwarfExtractor::extract() {
    debugOutput("Starting DWARF data extraction...");
    
    // Extract all types of debug information
    extractCompilationUnits();
    extractFunctions();
    extractVariables();
    extractTypes();
    
    debugOutput("DWARF data extraction completed");
    return database_;
}

void DwarfExtractor::extractCompilationUnits() {
    debugOutput("Extracting compilation units...");
    
    const auto& compilation_units = parser_->getCompilationUnits();
    for (const auto& cu_die : compilation_units) {
        auto cu_info = extractCompilationUnit(cu_die);
        if (cu_info) {
            database_->addCompilationUnit(cu_info);
            debugOutput("Extracted compilation unit: " + cu_info->getName());
        }
    }
}

void DwarfExtractor::extractFunctions() {
    debugOutput("Extracting functions...");
    
    auto function_dies = parser_->findDIEsByTag(DwarfTag::DW_TAG_subprogram);
    for (const auto& die : function_dies) {
        auto func_info = extractFunction(die);
        if (func_info) {
            database_->addFunction(func_info);
            debugOutput("Extracted function: " + func_info->getName());
        }
    }
}

void DwarfExtractor::extractVariables() {
    debugOutput("Extracting variables...");
    
    auto variable_dies = parser_->findDIEsByTag(DwarfTag::DW_TAG_variable);
    for (const auto& die : variable_dies) {
        auto var_info = extractVariable(die);
        if (var_info) {
            database_->addVariable(var_info);
            debugOutput("Extracted variable: " + var_info->getName());
        }
    }
}

void DwarfExtractor::extractTypes() {
    debugOutput("Extracting types...");
    
    // Extract various type tags
    std::vector<DwarfTag> type_tags = {
        DwarfTag::DW_TAG_base_type,
        DwarfTag::DW_TAG_structure_type,
        DwarfTag::DW_TAG_union_type,
        DwarfTag::DW_TAG_class_type,
        DwarfTag::DW_TAG_interface_type,
        DwarfTag::DW_TAG_array_type,
        DwarfTag::DW_TAG_string_type,
        DwarfTag::DW_TAG_set_type,
        DwarfTag::DW_TAG_file_type,
        DwarfTag::DW_TAG_pointer_type,
        DwarfTag::DW_TAG_ptr_to_member_type,
        DwarfTag::DW_TAG_reference_type,
        DwarfTag::DW_TAG_rvalue_reference_type,
        DwarfTag::DW_TAG_atomic_type,
        DwarfTag::DW_TAG_enumeration_type,
        DwarfTag::DW_TAG_subroutine_type,
        DwarfTag::DW_TAG_unspecified_type,
        DwarfTag::DW_TAG_typedef
    };
    
    for (const auto& tag : type_tags) {
        auto type_dies = parser_->findDIEsByTag(tag);
        for (const auto& die : type_dies) {
            auto type_info = extractType(die);
            if (type_info) {
                database_->addType(type_info);
                debugOutput("Extracted type: " + type_info->getName());
            }
        }
    }
}

std::shared_ptr<FunctionInfo> DwarfExtractor::extractFunction(std::shared_ptr<DIE> die) {
    if (!die) return nullptr;
    
    std::string name = extractName(die);
    if (name.empty()) return nullptr;
    
    uint64_t low_pc = extractLowPC(die);
    uint64_t high_pc = extractHighPC(die);
    uint64_t size = extractSize(die);
    
    auto func_info = std::make_shared<FunctionInfo>(die, name, low_pc, high_pc, size);
    
    // Extract function properties
    func_info->setStatic(isStatic(die));
    func_info->setInline(isInline(die));
    func_info->setVirtual(isVirtual(die));
    
    // Extract return type
    std::string return_type = extractTypeName(die);
    if (!return_type.empty()) {
        func_info->setReturnType(return_type);
    }
    
    // Extract frame base
    std::string frame_base = extractFrameBase(die);
    if (!frame_base.empty()) {
        func_info->setFrameBase(frame_base);
    }
    
    // Extract parameters
    auto parameters = extractParameters(die);
    for (const auto& param : parameters) {
        func_info->addParameter(param);
    }
    
    return func_info;
}

std::shared_ptr<VariableInfo> DwarfExtractor::extractVariable(std::shared_ptr<DIE> die) {
    if (!die) return nullptr;
    
    std::string name = extractName(die);
    if (name.empty()) return nullptr;
    
    std::string type = extractTypeName(die);
    uint64_t location = extractLocation(die);
    
    auto var_info = std::make_shared<VariableInfo>(die, name, type, location);
    
    // Extract variable properties
    var_info->setGlobal(isGlobal(die));
    var_info->setStatic(isStatic(die));
    var_info->setConst(isConst(die));
    var_info->setVolatile(isVolatile(die));
    
    // Extract location description
    std::string location_desc = extractLocationDescription(die);
    if (!location_desc.empty()) {
        var_info->setLocationDescription(location_desc);
    }
    
    return var_info;
}

std::shared_ptr<TypeInfo> DwarfExtractor::extractType(std::shared_ptr<DIE> die) {
    if (!die) return nullptr;
    
    std::string name = extractName(die);
    DwarfTag tag = die->getTag();
    uint64_t size = extractSize(die);
    
    auto type_info = std::make_shared<TypeInfo>(die, name, tag, size);
    
    // Extract type properties
    type_info->setPrimitive(isPrimitive(die));
    type_info->setComposite(isComposite(die));
    type_info->setArray(isArray(die));
    type_info->setPointer(isPointer(die));
    type_info->setReference(isReference(die));
    
    // Extract type name
    std::string type_name = extractTypeName(die);
    if (!type_name.empty()) {
        type_info->setTypeName(type_name);
    }
    
    // Extract members for composite types
    if (isComposite(die)) {
        auto members = extractMembers(die);
        for (const auto& member : members) {
            type_info->addMember(member);
        }
    }
    
    // Extract enumerators for enum types
    if (tag == DwarfTag::DW_TAG_enumeration_type) {
        auto enumerators = extractEnumerators(die);
        for (const auto& enumerator : enumerators) {
            type_info->addEnumerator(enumerator);
        }
    }
    
    return type_info;
}

std::shared_ptr<CompilationUnitInfo> DwarfExtractor::extractCompilationUnit(std::shared_ptr<DIE> die) {
    if (!die) return nullptr;
    
    std::string name = extractName(die);
    if (name.empty()) {
        name = "unnamed_cu_" + std::to_string(die->getOffset());
    }
    
    std::string language = extractLanguage(die);
    std::string producer = extractProducer(die);
    
    auto cu_info = std::make_shared<CompilationUnitInfo>(die, name, language, producer);
    
    return cu_info;
}

// Attribute extraction helpers
std::string DwarfExtractor::extractName(std::shared_ptr<DIE> die) {
    return getAttributeString(die, DwarfAttribute::DW_AT_name);
}

std::string DwarfExtractor::extractTypeName(std::shared_ptr<DIE> die) {
    return getAttributeString(die, DwarfAttribute::DW_AT_type);
}

uint64_t DwarfExtractor::extractLowPC(std::shared_ptr<DIE> die) {
    return getAttributeUInt(die, DwarfAttribute::DW_AT_low_pc);
}

uint64_t DwarfExtractor::extractHighPC(std::shared_ptr<DIE> die) {
    return getAttributeUInt(die, DwarfAttribute::DW_AT_high_pc);
}

uint64_t DwarfExtractor::extractSize(std::shared_ptr<DIE> die) {
    return getAttributeUInt(die, DwarfAttribute::DW_AT_byte_size);
}

uint64_t DwarfExtractor::extractLocation(std::shared_ptr<DIE> die) {
    return getAttributeUInt(die, DwarfAttribute::DW_AT_location);
}

std::string DwarfExtractor::extractLocationDescription(std::shared_ptr<DIE> die) {
    auto location_attr = die->getAttribute(DwarfAttribute::DW_AT_location);
    if (location_attr) {
        return location_attr->toString();
    }
    return "";
}

std::string DwarfExtractor::extractFrameBase(std::shared_ptr<DIE> die) {
    auto frame_base_attr = die->getAttribute(DwarfAttribute::DW_AT_frame_base);
    if (frame_base_attr) {
        return frame_base_attr->toString();
    }
    return "";
}

std::string DwarfExtractor::extractLanguage(std::shared_ptr<DIE> die) {
    return getAttributeString(die, DwarfAttribute::DW_AT_language);
}

std::string DwarfExtractor::extractProducer(std::shared_ptr<DIE> die) {
    return getAttributeString(die, DwarfAttribute::DW_AT_producer);
}

// Property extraction helpers
bool DwarfExtractor::isStatic(std::shared_ptr<DIE> die) {
    return hasAttribute(die, DwarfAttribute::DW_AT_external) && 
           !hasAttribute(die, DwarfAttribute::DW_AT_declaration);
}

bool DwarfExtractor::isInline(std::shared_ptr<DIE> die) {
    return hasAttribute(die, DwarfAttribute::DW_AT_inline);
}

bool DwarfExtractor::isVirtual(std::shared_ptr<DIE> die) {
    return hasAttribute(die, DwarfAttribute::DW_AT_virtuality);
}

bool DwarfExtractor::isGlobal(std::shared_ptr<DIE> die) {
    return hasAttribute(die, DwarfAttribute::DW_AT_external);
}

bool DwarfExtractor::isConst(std::shared_ptr<DIE> die) {
    return hasAttribute(die, DwarfAttribute::DW_AT_const_value);
}

bool DwarfExtractor::isVolatile(std::shared_ptr<DIE> die) {
    return hasAttribute(die, DwarfAttribute::DW_AT_volatile);
}

bool DwarfExtractor::isPrimitive(std::shared_ptr<DIE> die) {
    return die->getTag() == DwarfTag::DW_TAG_base_type;
}

bool DwarfExtractor::isComposite(std::shared_ptr<DIE> die) {
    DwarfTag tag = die->getTag();
    return tag == DwarfTag::DW_TAG_structure_type || 
           tag == DwarfTag::DW_TAG_union_type || 
           tag == DwarfTag::DW_TAG_class_type;
}

bool DwarfExtractor::isArray(std::shared_ptr<DIE> die) {
    return die->getTag() == DwarfTag::DW_TAG_array_type;
}

bool DwarfExtractor::isPointer(std::shared_ptr<DIE> die) {
    return die->getTag() == DwarfTag::DW_TAG_pointer_type;
}

bool DwarfExtractor::isReference(std::shared_ptr<DIE> die) {
    return die->getTag() == DwarfTag::DW_TAG_reference_type;
}

// Parameter and member extraction
std::vector<std::string> DwarfExtractor::extractParameters(std::shared_ptr<DIE> die) {
    std::vector<std::string> parameters;
    
    for (const auto& child : die->getChildren()) {
        if (child->getTag() == DwarfTag::DW_TAG_formal_parameter) {
            std::string param_name = extractName(child);
            if (!param_name.empty()) {
                parameters.push_back(param_name);
            }
        }
    }
    
    return parameters;
}

std::vector<std::string> DwarfExtractor::extractMembers(std::shared_ptr<DIE> die) {
    std::vector<std::string> members;
    
    for (const auto& child : die->getChildren()) {
        if (child->getTag() == DwarfTag::DW_TAG_member) {
            std::string member_name = extractName(child);
            if (!member_name.empty()) {
                members.push_back(member_name);
            }
        }
    }
    
    return members;
}

std::vector<std::string> DwarfExtractor::extractEnumerators(std::shared_ptr<DIE> die) {
    std::vector<std::string> enumerators;
    
    for (const auto& child : die->getChildren()) {
        if (child->getTag() == DwarfTag::DW_TAG_enumerator) {
            std::string enumerator_name = extractName(child);
            if (!enumerator_name.empty()) {
                enumerators.push_back(enumerator_name);
            }
        }
    }
    
    return enumerators;
}

// Utility methods
std::string DwarfExtractor::getAttributeString(std::shared_ptr<DIE> die, DwarfAttribute attr) {
    auto attr_value = die->getAttribute(attr);
    if (attr_value) {
        return attr_value->toString();
    }
    return "";
}

uint64_t DwarfExtractor::getAttributeUInt(std::shared_ptr<DIE> die, DwarfAttribute attr) {
    auto attr_value = die->getAttribute(attr);
    if (attr_value) {
        if (auto int_value = std::dynamic_pointer_cast<UnsignedAttributeValue>(attr_value)) {
            return int_value->getValue();
        }
    }
    return 0;
}

bool DwarfExtractor::hasAttribute(std::shared_ptr<DIE> die, DwarfAttribute attr) {
    return die->hasAttribute(attr);
}

std::string DwarfExtractor::getTagName(DwarfTag tag) {
    return DwarfUtils::tagToString(tag);
}

std::string DwarfExtractor::formatAddress(uint64_t address) {
    std::ostringstream oss;
    oss << "0x" << std::hex << address << std::dec;
    return oss.str();
}

std::string DwarfExtractor::formatLocation(uint64_t location) {
    std::ostringstream oss;
    oss << "0x" << std::hex << location << std::dec;
    return oss.str();
}

void DwarfExtractor::debugOutput(const std::string& message) const {
    if (verbose_) {
        std::cerr << "Debug: " << message << std::endl;
    }
}

} // namespace dwarf
