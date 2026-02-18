#pragma once

#include "dwarf_types.hpp"
#include "die_parser.hpp"
#include <memory>
#include <vector>
#include <map>
#include <set>
#include <string>
#include <functional>
#include <unordered_map>

namespace dwarf {

// Forward declarations
class DwarfDatabase;
class FunctionInfo;
class VariableInfo;
class TypeInfo;
class CompilationUnitInfo;

// Base class for all debug information entries
class DebugInfoEntry {
public:
    virtual ~DebugInfoEntry() = default;
    virtual DwarfTag getTag() const = 0;
    virtual uint64_t getOffset() const = 0;
    virtual const std::string& getName() const = 0;
    virtual std::shared_ptr<DIE> getDIE() const = 0;
};

// Function information
class FunctionInfo : public DebugInfoEntry {
public:
    FunctionInfo(std::shared_ptr<DIE> die, const std::string& name, 
                 uint64_t low_pc, uint64_t high_pc, uint64_t size);
    
    DwarfTag getTag() const override { return DwarfTag::DW_TAG_subprogram; }
    uint64_t getOffset() const override { return die_->getOffset(); }
    const std::string& getName() const override { return name_; }
    std::shared_ptr<DIE> getDIE() const override { return die_; }
    
    // Function-specific properties
    uint64_t getLowPC() const { return low_pc_; }
    uint64_t getHighPC() const { return high_pc_; }
    uint64_t getSize() const { return size_; }
    const std::vector<std::string>& getParameters() const { return parameters_; }
    const std::string& getReturnType() const { return return_type_; }
    const std::string& getFrameBase() const { return frame_base_; }
    bool isStatic() const { return is_static_; }
    bool isInline() const { return is_inline_; }
    bool isVirtual() const { return is_virtual_; }
    
    // Setters
    void addParameter(const std::string& param) { parameters_.push_back(param); }
    void setReturnType(const std::string& type) { return_type_ = type; }
    void setFrameBase(const std::string& frame_base) { frame_base_ = frame_base; }
    void setStatic(bool is_static) { is_static_ = is_static; }
    void setInline(bool is_inline) { is_inline_ = is_inline; }
    void setVirtual(bool is_virtual) { is_virtual_ = is_virtual; }
    
    // Utility methods
    std::string getSignature() const;
    std::string getDescription() const;

private:
    std::shared_ptr<DIE> die_;
    std::string name_;
    uint64_t low_pc_;
    uint64_t high_pc_;
    uint64_t size_;
    std::vector<std::string> parameters_;
    std::string return_type_;
    std::string frame_base_;
    bool is_static_;
    bool is_inline_;
    bool is_virtual_;
};

// Variable information
class VariableInfo : public DebugInfoEntry {
public:
    VariableInfo(std::shared_ptr<DIE> die, const std::string& name, 
                 const std::string& type, uint64_t location);
    
    DwarfTag getTag() const override { return DwarfTag::DW_TAG_variable; }
    uint64_t getOffset() const override { return die_->getOffset(); }
    const std::string& getName() const override { return name_; }
    std::shared_ptr<DIE> getDIE() const override { return die_; }
    
    // Variable-specific properties
    const std::string& getType() const { return type_; }
    uint64_t getLocation() const { return location_; }
    const std::string& getLocationDescription() const { return location_description_; }
    bool isGlobal() const { return is_global_; }
    bool isStatic() const { return is_static_; }
    bool isConst() const { return is_const_; }
    bool isVolatile() const { return is_volatile_; }
    const std::string& getScope() const { return scope_; }
    
    // Setters
    void setType(const std::string& type) { type_ = type; }
    void setLocation(uint64_t location) { location_ = location; }
    void setLocationDescription(const std::string& desc) { location_description_ = desc; }
    void setGlobal(bool is_global) { is_global_ = is_global; }
    void setStatic(bool is_static) { is_static_ = is_static; }
    void setConst(bool is_const) { is_const_ = is_const; }
    void setVolatile(bool is_volatile) { is_volatile_ = is_volatile; }
    void setScope(const std::string& scope) { scope_ = scope; }
    
    // Utility methods
    std::string getDescription() const;

private:
    std::shared_ptr<DIE> die_;
    std::string name_;
    std::string type_;
    uint64_t location_;
    std::string location_description_;
    bool is_global_;
    bool is_static_;
    bool is_const_;
    bool is_volatile_;
    std::string scope_;
};

// Type information
class TypeInfo : public DebugInfoEntry {
public:
    TypeInfo(std::shared_ptr<DIE> die, const std::string& name, 
             DwarfTag tag, uint64_t size);
    
    DwarfTag getTag() const override { return tag_; }
    uint64_t getOffset() const override { return die_->getOffset(); }
    const std::string& getName() const override { return name_; }
    std::shared_ptr<DIE> getDIE() const override { return die_; }
    
    // Type-specific properties
    DwarfTag getTypeTag() const { return tag_; }
    uint64_t getSize() const { return size_; }
    const std::string& getTypeName() const { return type_name_; }
    bool isPrimitive() const { return is_primitive_; }
    bool isComposite() const { return is_composite_; }
    bool isArray() const { return is_array_; }
    bool isPointer() const { return is_pointer_; }
    bool isReference() const { return is_reference_; }
    const std::vector<std::string>& getMembers() const { return members_; }
    const std::vector<std::string>& getEnumerators() const { return enumerators_; }
    const std::string& getBaseType() const { return base_type_; }
    
    // Setters
    void setTypeName(const std::string& type_name) { type_name_ = type_name; }
    void setPrimitive(bool is_primitive) { is_primitive_ = is_primitive; }
    void setComposite(bool is_composite) { is_composite_ = is_composite; }
    void setArray(bool is_array) { is_array_ = is_array; }
    void setPointer(bool is_pointer) { is_pointer_ = is_pointer; }
    void setReference(bool is_reference) { is_reference_ = is_reference; }
    void addMember(const std::string& member) { members_.push_back(member); }
    void addEnumerator(const std::string& enumerator) { enumerators_.push_back(enumerator); }
    void setBaseType(const std::string& base_type) { base_type_ = base_type; }
    
    // Utility methods
    std::string getDescription() const;

private:
    std::shared_ptr<DIE> die_;
    std::string name_;
    DwarfTag tag_;
    uint64_t size_;
    std::string type_name_;
    bool is_primitive_;
    bool is_composite_;
    bool is_array_;
    bool is_pointer_;
    bool is_reference_;
    std::vector<std::string> members_;
    std::vector<std::string> enumerators_;
    std::string base_type_;
};

// Compilation unit information
class CompilationUnitInfo {
public:
    CompilationUnitInfo(std::shared_ptr<DIE> die, const std::string& name, 
                        const std::string& language, const std::string& producer);
    
    // Properties
    std::shared_ptr<DIE> getDIE() const { return die_; }
    const std::string& getName() const { return name_; }
    const std::string& getLanguage() const { return language_; }
    const std::string& getProducer() const { return producer_; }
    uint64_t getOffset() const { return die_->getOffset(); }
    uint64_t getSize() const { return die_->getSize(); }
    
    // Statistics
    size_t getFunctionCount() const { return functions_.size(); }
    size_t getVariableCount() const { return variables_.size(); }
    size_t getTypeCount() const { return types_.size(); }
    
    // Access to contained data
    const std::vector<std::shared_ptr<FunctionInfo>>& getFunctions() const { return functions_; }
    const std::vector<std::shared_ptr<VariableInfo>>& getVariables() const { return variables_; }
    const std::vector<std::shared_ptr<TypeInfo>>& getTypes() const { return types_; }
    
    // Add data
    void addFunction(std::shared_ptr<FunctionInfo> func) { functions_.push_back(func); }
    void addVariable(std::shared_ptr<VariableInfo> var) { variables_.push_back(var); }
    void addType(std::shared_ptr<TypeInfo> type) { types_.push_back(type); }
    
    // Utility methods
    std::string getDescription() const;

private:
    std::shared_ptr<DIE> die_;
    std::string name_;
    std::string language_;
    std::string producer_;
    std::vector<std::shared_ptr<FunctionInfo>> functions_;
    std::vector<std::shared_ptr<VariableInfo>> variables_;
    std::vector<std::shared_ptr<TypeInfo>> types_;
};

// Main database class for storing and querying DWARF data
class DwarfDatabase {
public:
    DwarfDatabase();
    ~DwarfDatabase() = default;
    
    // Data population
    void addCompilationUnit(std::shared_ptr<CompilationUnitInfo> cu);
    void addFunction(std::shared_ptr<FunctionInfo> func);
    void addVariable(std::shared_ptr<VariableInfo> var);
    void addType(std::shared_ptr<TypeInfo> type);
    
    // Query functions
    std::vector<std::shared_ptr<FunctionInfo>> findFunctions(const std::string& name) const;
    std::vector<std::shared_ptr<FunctionInfo>> findFunctionsByPattern(const std::string& pattern) const;
    std::vector<std::shared_ptr<VariableInfo>> findVariables(const std::string& name) const;
    std::vector<std::shared_ptr<TypeInfo>> findTypes(const std::string& name) const;
    std::vector<std::shared_ptr<TypeInfo>> findTypesByTag(DwarfTag tag) const;
    
    // Iteration functions
    const std::vector<std::shared_ptr<CompilationUnitInfo>>& getCompilationUnits() const { return compilation_units_; }
    const std::vector<std::shared_ptr<FunctionInfo>>& getFunctions() const { return functions_; }
    const std::vector<std::shared_ptr<VariableInfo>>& getVariables() const { return variables_; }
    const std::vector<std::shared_ptr<TypeInfo>>& getTypes() const { return types_; }
    
    // Filtering functions
    std::vector<std::shared_ptr<FunctionInfo>> getStaticFunctions() const;
    std::vector<std::shared_ptr<FunctionInfo>> getInlineFunctions() const;
    std::vector<std::shared_ptr<FunctionInfo>> getVirtualFunctions() const;
    std::vector<std::shared_ptr<VariableInfo>> getGlobalVariables() const;
    std::vector<std::shared_ptr<VariableInfo>> getStaticVariables() const;
    std::vector<std::shared_ptr<TypeInfo>> getPrimitiveTypes() const;
    std::vector<std::shared_ptr<TypeInfo>> getCompositeTypes() const;
    std::vector<std::shared_ptr<TypeInfo>> getArrayTypes() const;
    std::vector<std::shared_ptr<TypeInfo>> getPointerTypes() const;
    
    // Statistics
    size_t getTotalFunctionCount() const { return functions_.size(); }
    size_t getTotalVariableCount() const { return variables_.size(); }
    size_t getTotalTypeCount() const { return types_.size(); }
    size_t getTotalCompilationUnitCount() const { return compilation_units_.size(); }
    
    // Search and filter with predicates
    template<typename T>
    std::vector<std::shared_ptr<T>> filter(const std::function<bool(const std::shared_ptr<T>&)>& predicate) const {
        std::vector<std::shared_ptr<T>> result;
        (void)predicate;
        // This will be specialized for each type
        return result;
    }
    
    // Clear all data
    void clear();
    
    // Utility methods
    std::string getSummary() const;
    void printStatistics() const;

private:
    std::vector<std::shared_ptr<CompilationUnitInfo>> compilation_units_;
    std::vector<std::shared_ptr<FunctionInfo>> functions_;
    std::vector<std::shared_ptr<VariableInfo>> variables_;
    std::vector<std::shared_ptr<TypeInfo>> types_;
    
    // Indexes for fast lookup
    std::unordered_map<std::string, std::vector<std::shared_ptr<FunctionInfo>>> function_name_index_;
    std::unordered_map<std::string, std::vector<std::shared_ptr<VariableInfo>>> variable_name_index_;
    std::unordered_map<std::string, std::vector<std::shared_ptr<TypeInfo>>> type_name_index_;
    std::unordered_map<DwarfTag, std::vector<std::shared_ptr<TypeInfo>>> type_tag_index_;
    
    // Helper methods
    void updateIndexes();
    std::string toLower(const std::string& str) const;
    bool matchesPattern(const std::string& text, const std::string& pattern) const;
};

} // namespace dwarf

// Template specializations
namespace dwarf {

// Template specialization for FunctionInfo
template<>
inline std::vector<std::shared_ptr<FunctionInfo>> DwarfDatabase::filter<FunctionInfo>(const std::function<bool(const std::shared_ptr<FunctionInfo>&)>& predicate) const {
    std::vector<std::shared_ptr<FunctionInfo>> result;
    for (const auto& func : functions_) {
        if (predicate(func)) {
            result.push_back(func);
        }
    }
    return result;
}

// Template specialization for VariableInfo
template<>
inline std::vector<std::shared_ptr<VariableInfo>> DwarfDatabase::filter<VariableInfo>(const std::function<bool(const std::shared_ptr<VariableInfo>&)>& predicate) const {
    std::vector<std::shared_ptr<VariableInfo>> result;
    for (const auto& var : variables_) {
        if (predicate(var)) {
            result.push_back(var);
        }
    }
    return result;
}

// Template specialization for TypeInfo
template<>
inline std::vector<std::shared_ptr<TypeInfo>> DwarfDatabase::filter<TypeInfo>(const std::function<bool(const std::shared_ptr<TypeInfo>&)>& predicate) const {
    std::vector<std::shared_ptr<TypeInfo>> result;
    for (const auto& type : types_) {
        if (predicate(type)) {
            result.push_back(type);
        }
    }
    return result;
}

} // namespace dwarf
