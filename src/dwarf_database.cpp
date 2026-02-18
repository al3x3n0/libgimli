#include "dwarf_database.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <regex>

namespace dwarf {

// FunctionInfo implementation
FunctionInfo::FunctionInfo(std::shared_ptr<DIE> die, const std::string& name, 
                           uint64_t low_pc, uint64_t high_pc, uint64_t size)
    : die_(die), name_(name), low_pc_(low_pc), high_pc_(high_pc), size_(size),
      is_static_(false), is_inline_(false), is_virtual_(false) {
}

std::string FunctionInfo::getSignature() const {
    std::ostringstream oss;
    oss << return_type_ << " " << name_ << "(";
    for (size_t i = 0; i < parameters_.size(); ++i) {
        if (i > 0) oss << ", ";
        oss << parameters_[i];
    }
    oss << ")";
    return oss.str();
}

std::string FunctionInfo::getDescription() const {
    std::ostringstream oss;
    oss << "Function: " << name_;
    if (!return_type_.empty()) {
        oss << " -> " << return_type_;
    }
    if (low_pc_ != 0) {
        oss << " [0x" << std::hex << low_pc_ << "-0x" << (low_pc_ + high_pc_) << std::dec << "]";
    }
    if (is_static_) oss << " [static]";
    if (is_inline_) oss << " [inline]";
    if (is_virtual_) oss << " [virtual]";
    return oss.str();
}

// VariableInfo implementation
VariableInfo::VariableInfo(std::shared_ptr<DIE> die, const std::string& name, 
                           const std::string& type, uint64_t location)
    : die_(die), name_(name), type_(type), location_(location),
      is_global_(false), is_static_(false), is_const_(false), is_volatile_(false) {
}

std::string VariableInfo::getDescription() const {
    std::ostringstream oss;
    oss << "Variable: " << name_;
    if (!type_.empty()) {
        oss << " : " << type_;
    }
    if (location_ != 0) {
        oss << " [0x" << std::hex << location_ << std::dec << "]";
    }
    if (is_global_) oss << " [global]";
    if (is_static_) oss << " [static]";
    if (is_const_) oss << " [const]";
    if (is_volatile_) oss << " [volatile]";
    return oss.str();
}

// TypeInfo implementation
TypeInfo::TypeInfo(std::shared_ptr<DIE> die, const std::string& name, 
                   DwarfTag tag, uint64_t size)
    : die_(die), name_(name), tag_(tag), size_(size),
      is_primitive_(false), is_composite_(false), is_array_(false), 
      is_pointer_(false), is_reference_(false) {
}

std::string TypeInfo::getDescription() const {
    std::ostringstream oss;
    oss << "Type: " << name_;
    if (!type_name_.empty()) {
        oss << " (" << type_name_ << ")";
    }
    if (size_ > 0) {
        oss << " [" << size_ << " bytes]";
    }
    if (is_primitive_) oss << " [primitive]";
    if (is_composite_) oss << " [composite]";
    if (is_array_) oss << " [array]";
    if (is_pointer_) oss << " [pointer]";
    if (is_reference_) oss << " [reference]";
    return oss.str();
}

// CompilationUnitInfo implementation
CompilationUnitInfo::CompilationUnitInfo(std::shared_ptr<DIE> die, const std::string& name, 
                                         const std::string& language, const std::string& producer)
    : die_(die), name_(name), language_(language), producer_(producer) {
}

std::string CompilationUnitInfo::getDescription() const {
    std::ostringstream oss;
    oss << "Compilation Unit: " << name_;
    if (!language_.empty()) {
        oss << " [" << language_ << "]";
    }
    if (!producer_.empty()) {
        oss << " (" << producer_ << ")";
    }
    oss << " - " << functions_.size() << " functions, " 
        << variables_.size() << " variables, " << types_.size() << " types";
    return oss.str();
}

// DwarfDatabase implementation
DwarfDatabase::DwarfDatabase() {
}

void DwarfDatabase::addCompilationUnit(std::shared_ptr<CompilationUnitInfo> cu) {
    compilation_units_.push_back(cu);
}

void DwarfDatabase::addFunction(std::shared_ptr<FunctionInfo> func) {
    functions_.push_back(func);
    function_name_index_[toLower(func->getName())].push_back(func);
}

void DwarfDatabase::addVariable(std::shared_ptr<VariableInfo> var) {
    variables_.push_back(var);
    variable_name_index_[toLower(var->getName())].push_back(var);
}

void DwarfDatabase::addType(std::shared_ptr<TypeInfo> type) {
    types_.push_back(type);
    type_name_index_[toLower(type->getName())].push_back(type);
    type_tag_index_[type->getTypeTag()].push_back(type);
}

std::vector<std::shared_ptr<FunctionInfo>> DwarfDatabase::findFunctions(const std::string& name) const {
    auto it = function_name_index_.find(toLower(name));
    return (it != function_name_index_.end()) ? it->second : std::vector<std::shared_ptr<FunctionInfo>>();
}

std::vector<std::shared_ptr<FunctionInfo>> DwarfDatabase::findFunctionsByPattern(const std::string& pattern) const {
    std::vector<std::shared_ptr<FunctionInfo>> result;
    for (const auto& func : functions_) {
        if (matchesPattern(func->getName(), pattern)) {
            result.push_back(func);
        }
    }
    return result;
}

std::vector<std::shared_ptr<VariableInfo>> DwarfDatabase::findVariables(const std::string& name) const {
    auto it = variable_name_index_.find(toLower(name));
    return (it != variable_name_index_.end()) ? it->second : std::vector<std::shared_ptr<VariableInfo>>();
}

std::vector<std::shared_ptr<TypeInfo>> DwarfDatabase::findTypes(const std::string& name) const {
    auto it = type_name_index_.find(toLower(name));
    return (it != type_name_index_.end()) ? it->second : std::vector<std::shared_ptr<TypeInfo>>();
}

std::vector<std::shared_ptr<TypeInfo>> DwarfDatabase::findTypesByTag(DwarfTag tag) const {
    auto it = type_tag_index_.find(tag);
    return (it != type_tag_index_.end()) ? it->second : std::vector<std::shared_ptr<TypeInfo>>();
}

std::vector<std::shared_ptr<FunctionInfo>> DwarfDatabase::getStaticFunctions() const {
    return filter<FunctionInfo>([](const std::shared_ptr<FunctionInfo>& func) {
        return func->isStatic();
    });
}

std::vector<std::shared_ptr<FunctionInfo>> DwarfDatabase::getInlineFunctions() const {
    return filter<FunctionInfo>([](const std::shared_ptr<FunctionInfo>& func) {
        return func->isInline();
    });
}

std::vector<std::shared_ptr<FunctionInfo>> DwarfDatabase::getVirtualFunctions() const {
    return filter<FunctionInfo>([](const std::shared_ptr<FunctionInfo>& func) {
        return func->isVirtual();
    });
}

std::vector<std::shared_ptr<VariableInfo>> DwarfDatabase::getGlobalVariables() const {
    return filter<VariableInfo>([](const std::shared_ptr<VariableInfo>& var) {
        return var->isGlobal();
    });
}

std::vector<std::shared_ptr<VariableInfo>> DwarfDatabase::getStaticVariables() const {
    return filter<VariableInfo>([](const std::shared_ptr<VariableInfo>& var) {
        return var->isStatic();
    });
}

std::vector<std::shared_ptr<TypeInfo>> DwarfDatabase::getPrimitiveTypes() const {
    return filter<TypeInfo>([](const std::shared_ptr<TypeInfo>& type) {
        return type->isPrimitive();
    });
}

std::vector<std::shared_ptr<TypeInfo>> DwarfDatabase::getCompositeTypes() const {
    return filter<TypeInfo>([](const std::shared_ptr<TypeInfo>& type) {
        return type->isComposite();
    });
}

std::vector<std::shared_ptr<TypeInfo>> DwarfDatabase::getArrayTypes() const {
    return filter<TypeInfo>([](const std::shared_ptr<TypeInfo>& type) {
        return type->isArray();
    });
}

std::vector<std::shared_ptr<TypeInfo>> DwarfDatabase::getPointerTypes() const {
    return filter<TypeInfo>([](const std::shared_ptr<TypeInfo>& type) {
        return type->isPointer();
    });
}


void DwarfDatabase::clear() {
    compilation_units_.clear();
    functions_.clear();
    variables_.clear();
    types_.clear();
    function_name_index_.clear();
    variable_name_index_.clear();
    type_name_index_.clear();
    type_tag_index_.clear();
}

std::string DwarfDatabase::getSummary() const {
    std::ostringstream oss;
    oss << "DWARF Database Summary:\n";
    oss << "  Compilation Units: " << compilation_units_.size() << "\n";
    oss << "  Functions: " << functions_.size() << "\n";
    oss << "  Variables: " << variables_.size() << "\n";
    oss << "  Types: " << types_.size() << "\n";
    return oss.str();
}

void DwarfDatabase::printStatistics() const {
    std::cout << getSummary() << std::endl;
    
    // Function statistics
    auto static_funcs = getStaticFunctions();
    auto inline_funcs = getInlineFunctions();
    auto virtual_funcs = getVirtualFunctions();
    
    std::cout << "\nFunction Statistics:\n";
    std::cout << "  Static: " << static_funcs.size() << "\n";
    std::cout << "  Inline: " << inline_funcs.size() << "\n";
    std::cout << "  Virtual: " << virtual_funcs.size() << "\n";
    
    // Variable statistics
    auto global_vars = getGlobalVariables();
    auto static_vars = getStaticVariables();
    
    std::cout << "\nVariable Statistics:\n";
    std::cout << "  Global: " << global_vars.size() << "\n";
    std::cout << "  Static: " << static_vars.size() << "\n";
    
    // Type statistics
    auto primitive_types = getPrimitiveTypes();
    auto composite_types = getCompositeTypes();
    auto array_types = getArrayTypes();
    auto pointer_types = getPointerTypes();
    
    std::cout << "\nType Statistics:\n";
    std::cout << "  Primitive: " << primitive_types.size() << "\n";
    std::cout << "  Composite: " << composite_types.size() << "\n";
    std::cout << "  Array: " << array_types.size() << "\n";
    std::cout << "  Pointer: " << pointer_types.size() << "\n";
}

void DwarfDatabase::updateIndexes() {
    function_name_index_.clear();
    variable_name_index_.clear();
    type_name_index_.clear();
    type_tag_index_.clear();
    
    for (const auto& func : functions_) {
        function_name_index_[toLower(func->getName())].push_back(func);
    }
    
    for (const auto& var : variables_) {
        variable_name_index_[toLower(var->getName())].push_back(var);
    }
    
    for (const auto& type : types_) {
        type_name_index_[toLower(type->getName())].push_back(type);
        type_tag_index_[type->getTypeTag()].push_back(type);
    }
}

std::string DwarfDatabase::toLower(const std::string& str) const {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

bool DwarfDatabase::matchesPattern(const std::string& text, const std::string& pattern) const {
    try {
        std::regex regex_pattern(pattern, std::regex_constants::icase);
        return std::regex_search(text, regex_pattern);
    } catch (const std::regex_error&) {
        // If regex fails, fall back to simple substring search
        return text.find(pattern) != std::string::npos;
    }
}

} // namespace dwarf
