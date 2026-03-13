#pragma once

#include "dwarf_types.hpp"
#include <memory>
#include <vector>
#include <map>
#include <string>
#include <functional>

namespace dwarf {

// Forward declarations
class DIE;

// Forward declaration for Type
class Type;

// Member and BaseClass structures
struct Member {
    std::string name;
    std::shared_ptr<Type> type;
    uint64_t offset;
    uint64_t bit_size;
    uint64_t bit_offset;
    bool is_static;
    bool is_mutable;
    bool is_public;
    bool is_protected;
    bool is_private;
};

struct BaseClass {
    std::shared_ptr<Type> type;
    uint64_t offset;
    bool is_virtual;
    bool is_public;
    bool is_protected;
    bool is_private;
};

struct ArrayBound {
    int64_t lower_bound;
    uint64_t count;
};

struct FunctionParameter {
    std::string name;
    std::shared_ptr<Type> type;
    bool is_object_pointer = false;
    bool is_artificial = false;
};

enum class ModifiedTypeKind {
    TYPEDEF,
    CONST,
    VOLATILE,
    RESTRICT,
    REFERENCE,
    RVALUE_REFERENCE,
    ATOMIC
};

// Forward declaration
class TypeSystem;

// Base type representation
class Type : public std::enable_shared_from_this<Type> {
public:
    virtual ~Type() = default;
    virtual std::string getName() const = 0;
    virtual uint64_t getSize() const = 0;
    virtual std::string getDescription() const = 0;
    virtual bool isComplete() const = 0;
    virtual std::shared_ptr<Type> resolve() = 0;

    DwarfTag getDwarfTag() const { return dwarf_tag_; }
    void setDwarfTag(DwarfTag tag) { dwarf_tag_ = tag; }

protected:
    DwarfTag dwarf_tag_ = static_cast<DwarfTag>(0);
};

// Primitive types
class PrimitiveType : public Type {
public:
    enum class Kind {
        VOID,
        BOOLEAN,
        INTEGER,
        FLOAT,
        COMPLEX,
        POINTER
    };
    
    PrimitiveType(Kind kind, uint64_t size, const std::string& name = "");
    std::string getName() const override;
    uint64_t getSize() const override;
    std::string getDescription() const override;
    bool isComplete() const override;
    std::shared_ptr<Type> resolve() override;
    Kind getKind() const { return kind_; }
    
private:
    Kind kind_;
    uint64_t size_;
    std::string name_;
};

class ModifiedType : public Type {
public:
    ModifiedType(ModifiedTypeKind kind,
                 std::shared_ptr<Type> underlying_type,
                 uint64_t size = 0,
                 const std::string& name = "");
    std::string getName() const override;
    uint64_t getSize() const override;
    std::string getDescription() const override;
    bool isComplete() const override;
    std::shared_ptr<Type> resolve() override;

    ModifiedTypeKind getKind() const { return kind_; }
    std::shared_ptr<Type> getUnderlyingType() const { return underlying_type_; }
    const std::string& getAliasName() const { return name_; }

private:
    ModifiedTypeKind kind_;
    std::shared_ptr<Type> underlying_type_;
    uint64_t size_;
    std::string name_;
};

// Composite types
class CompositeType : public Type {
public:
    enum class Kind {
        STRUCT,
        UNION,
        CLASS,
        INTERFACE
    };
    
    CompositeType(Kind kind, const std::string& name, uint64_t size = 0);
    std::string getName() const override;
    uint64_t getSize() const override;
    std::string getDescription() const override;
    bool isComplete() const override;
    std::shared_ptr<Type> resolve() override;
    Kind getKind() const { return kind_; }
    
    // Member management
    void addMember(const std::string& name, std::shared_ptr<Type> type, uint64_t offset = 0);
    void addMember(const Member& member);
    const std::vector<dwarf::Member>& getMembers() const { return members_; }
    std::shared_ptr<Type> getMemberType(const std::string& name) const;
    uint64_t getMemberOffset(const std::string& name) const;
    
    // Inheritance
    void addBaseClass(std::shared_ptr<CompositeType> base, uint64_t offset = 0);
    void addBaseClass(const BaseClass& base);
    const std::vector<dwarf::BaseClass>& getBaseClasses() const { return base_classes_; }
    
private:
    Kind kind_;
    std::string name_;
    uint64_t size_;
    
    std::vector<dwarf::Member> members_;
    std::vector<dwarf::BaseClass> base_classes_;
};

// Array types
class ArrayType : public Type {
public:
    ArrayType(std::shared_ptr<Type> element_type, const std::vector<uint64_t>& dimensions);
    ArrayType(std::shared_ptr<Type> element_type,
              const std::vector<ArrayBound>& bounds,
              uint64_t rank = 0,
              uint64_t byte_stride = 0,
              uint64_t bit_stride = 0);
    std::string getName() const override;
    uint64_t getSize() const override;
    std::string getDescription() const override;
    bool isComplete() const override;
    std::shared_ptr<Type> resolve() override;
    
    std::shared_ptr<Type> getElementType() const { return element_type_; }
    const std::vector<uint64_t>& getDimensions() const { return dimensions_; }
    const std::vector<ArrayBound>& getBounds() const { return bounds_; }
    uint64_t getRank() const { return rank_; }
    uint64_t getByteStride() const { return byte_stride_; }
    uint64_t getBitStride() const { return bit_stride_; }
    uint64_t getElementCount() const;
    
private:
    std::shared_ptr<Type> element_type_;
    std::vector<uint64_t> dimensions_;
    std::vector<ArrayBound> bounds_;
    uint64_t rank_;
    uint64_t byte_stride_;
    uint64_t bit_stride_;
};

class StringType : public Type {
public:
    StringType(const std::string& name,
               std::shared_ptr<Type> character_type,
               uint64_t size,
               uint64_t length = 0);
    std::string getName() const override;
    uint64_t getSize() const override;
    std::string getDescription() const override;
    bool isComplete() const override;
    std::shared_ptr<Type> resolve() override;

    std::shared_ptr<Type> getCharacterType() const { return character_type_; }
    uint64_t getLength() const { return length_; }

private:
    std::string name_;
    std::shared_ptr<Type> character_type_;
    uint64_t size_;
    uint64_t length_;
};

class SetType : public Type {
public:
    SetType(const std::string& name,
            std::shared_ptr<Type> element_type,
            uint64_t size);
    std::string getName() const override;
    uint64_t getSize() const override;
    std::string getDescription() const override;
    bool isComplete() const override;
    std::shared_ptr<Type> resolve() override;

    std::shared_ptr<Type> getElementType() const { return element_type_; }

private:
    std::string name_;
    std::shared_ptr<Type> element_type_;
    uint64_t size_;
};

class FileType : public Type {
public:
    FileType(const std::string& name,
             std::shared_ptr<Type> element_type,
             uint64_t size,
             uint64_t element_count = 0,
             uint64_t rank = 0);
    FileType(const std::string& name,
             std::shared_ptr<Type> element_type,
             uint64_t size,
             const std::vector<ArrayBound>& bounds,
             uint64_t rank = 0);
    std::string getName() const override;
    uint64_t getSize() const override;
    std::string getDescription() const override;
    bool isComplete() const override;
    std::shared_ptr<Type> resolve() override;

    std::shared_ptr<Type> getElementType() const { return element_type_; }
    uint64_t getElementCount() const;
    const std::vector<ArrayBound>& getBounds() const { return bounds_; }
    uint64_t getRank() const { return rank_; }

private:
    std::string name_;
    std::shared_ptr<Type> element_type_;
    uint64_t size_;
    std::vector<ArrayBound> bounds_;
    uint64_t rank_;
};

// Function types
class FunctionType : public Type {
public:
    FunctionType(std::shared_ptr<Type> return_type, 
                 const std::vector<std::shared_ptr<Type>>& parameter_types,
                 bool is_variadic = false,
                 bool is_prototyped = false,
                 uint64_t calling_convention = 0,
                 bool is_declaration = false,
                 bool is_explicit = false,
                 bool is_elemental = false,
                 bool is_pure = false,
                 bool is_recursive = false,
                 bool is_main_subprogram = false,
                 bool is_const_expr = false);
    FunctionType(std::shared_ptr<Type> return_type,
                 const std::vector<FunctionParameter>& parameters,
                 bool is_variadic = false,
                 bool is_prototyped = false,
                 uint64_t calling_convention = 0,
                 bool is_declaration = false,
                 bool is_explicit = false,
                 bool is_elemental = false,
                 bool is_pure = false,
                 bool is_recursive = false,
                 bool is_main_subprogram = false,
                 bool is_const_expr = false);
    std::string getName() const override;
    uint64_t getSize() const override;
    std::string getDescription() const override;
    bool isComplete() const override;
    std::shared_ptr<Type> resolve() override;
    
    std::shared_ptr<Type> getReturnType() const { return return_type_; }
    const std::vector<std::shared_ptr<Type>>& getParameterTypes() const { return parameter_types_; }
    const std::vector<FunctionParameter>& getParameters() const { return parameters_; }
    bool isVariadic() const { return is_variadic_; }
    bool isPrototyped() const { return is_prototyped_; }
    uint64_t getCallingConvention() const { return calling_convention_; }
    bool isDeclaration() const { return is_declaration_; }
    bool isExplicit() const { return is_explicit_; }
    bool isElemental() const { return is_elemental_; }
    bool isPure() const { return is_pure_; }
    bool isRecursive() const { return is_recursive_; }
    bool isMainSubprogram() const { return is_main_subprogram_; }
    bool isConstExpr() const { return is_const_expr_; }
    
private:
    std::shared_ptr<Type> return_type_;
    std::vector<std::shared_ptr<Type>> parameter_types_;
    std::vector<FunctionParameter> parameters_;
    bool is_variadic_;
    bool is_prototyped_;
    uint64_t calling_convention_;
    bool is_declaration_;
    bool is_explicit_;
    bool is_elemental_;
    bool is_pure_;
    bool is_recursive_;
    bool is_main_subprogram_;
    bool is_const_expr_;
};

class MemberPointerType : public Type {
public:
    MemberPointerType(std::shared_ptr<Type> member_type,
                      std::shared_ptr<Type> containing_type,
                      uint64_t size);
    std::string getName() const override;
    uint64_t getSize() const override;
    std::string getDescription() const override;
    bool isComplete() const override;
    std::shared_ptr<Type> resolve() override;

    std::shared_ptr<Type> getMemberType() const { return member_type_; }
    std::shared_ptr<Type> getContainingType() const { return containing_type_; }

private:
    std::shared_ptr<Type> member_type_;
    std::shared_ptr<Type> containing_type_;
    uint64_t size_;
};

// Enum types
class EnumType : public Type {
public:
    struct Enumerator {
        std::string name;
        int64_t value;
    };
    
    EnumType(const std::string& name, std::shared_ptr<Type> underlying_type, bool is_scoped = false);
    std::string getName() const override;
    uint64_t getSize() const override;
    std::string getDescription() const override;
    bool isComplete() const override;
    std::shared_ptr<Type> resolve() override;
    
    void addEnumerator(const std::string& name, int64_t value);
    const std::vector<Enumerator>& getEnumerators() const { return enumerators_; }
    std::shared_ptr<Type> getUnderlyingType() const { return underlying_type_; }
    bool isScoped() const { return is_scoped_; }
    std::string getEnumeratorName(int64_t value) const;
    
private:
    std::string name_;
    std::shared_ptr<Type> underlying_type_;
    bool is_scoped_;
    std::vector<Enumerator> enumerators_;
};

// Type system for managing types
class TypeSystem {
public:
    using DIELookup = std::function<std::shared_ptr<DIE>(uint64_t)>;

    explicit TypeSystem(uint8_t pointer_size_bytes = sizeof(void*), DIELookup die_lookup = {});
    
    // Type creation
    std::shared_ptr<Type> createPrimitiveType(PrimitiveType::Kind kind, uint64_t size, 
                                              const std::string& name = "");
    std::shared_ptr<Type> createPointerType(std::shared_ptr<Type> pointee_type);
    std::shared_ptr<Type> createReferenceType(std::shared_ptr<Type> referee_type);
    std::shared_ptr<Type> createRvalueReferenceType(std::shared_ptr<Type> referee_type);
    std::shared_ptr<Type> createAtomicType(std::shared_ptr<Type> value_type);
    std::shared_ptr<Type> createMemberPointerType(std::shared_ptr<Type> member_type,
                                                  std::shared_ptr<Type> containing_type);
    std::shared_ptr<Type> createStringType(const std::string& name,
                                           std::shared_ptr<Type> character_type,
                                           uint64_t size,
                                           uint64_t length = 0);
    std::shared_ptr<Type> createSetType(const std::string& name,
                                        std::shared_ptr<Type> element_type,
                                        uint64_t size);
    std::shared_ptr<Type> createFileType(const std::string& name,
                                         std::shared_ptr<Type> element_type,
                                         uint64_t size,
                                         uint64_t element_count = 0,
                                         uint64_t rank = 0);
    std::shared_ptr<Type> createFileType(const std::string& name,
                                         std::shared_ptr<Type> element_type,
                                         uint64_t size,
                                         const std::vector<ArrayBound>& bounds,
                                         uint64_t rank = 0);
    std::shared_ptr<Type> createArrayType(std::shared_ptr<Type> element_type, 
                                          const std::vector<uint64_t>& dimensions);
    std::shared_ptr<Type> createArrayType(std::shared_ptr<Type> element_type,
                                          const std::vector<ArrayBound>& bounds,
                                          uint64_t rank = 0,
                                          uint64_t byte_stride = 0,
                                          uint64_t bit_stride = 0);
    std::shared_ptr<Type> createFunctionType(std::shared_ptr<Type> return_type,
                                             const std::vector<std::shared_ptr<Type>>& parameter_types,
                                             bool is_variadic = false,
                                             bool is_prototyped = false,
                                             uint64_t calling_convention = 0,
                                             bool is_declaration = false,
                                             bool is_explicit = false,
                                             bool is_elemental = false,
                                             bool is_pure = false,
                                             bool is_recursive = false,
                                             bool is_main_subprogram = false,
                                             bool is_const_expr = false);
    std::shared_ptr<Type> createFunctionType(std::shared_ptr<Type> return_type,
                                             const std::vector<FunctionParameter>& parameters,
                                             bool is_variadic = false,
                                             bool is_prototyped = false,
                                             uint64_t calling_convention = 0,
                                             bool is_declaration = false,
                                             bool is_explicit = false,
                                             bool is_elemental = false,
                                             bool is_pure = false,
                                             bool is_recursive = false,
                                             bool is_main_subprogram = false,
                                             bool is_const_expr = false);
    std::shared_ptr<Type> createModifiedType(ModifiedTypeKind kind,
                                             std::shared_ptr<Type> underlying_type,
                                             uint64_t size = 0,
                                             const std::string& name = "");
    std::shared_ptr<Type> createCompositeType(CompositeType::Kind kind, const std::string& name,
                                              uint64_t size = 0);
    std::shared_ptr<Type> createEnumType(const std::string& name, 
                                         std::shared_ptr<Type> underlying_type,
                                         bool is_scoped = false);
    
    // Type resolution
    std::shared_ptr<Type> resolveType(std::shared_ptr<DIE> die);
    std::shared_ptr<Type> getType(uint64_t offset);
    void cacheType(uint64_t offset, std::shared_ptr<Type> type);
    
    // Type queries
    std::vector<std::shared_ptr<Type>> getAllTypes() const;
    std::vector<std::shared_ptr<Type>> getTypesByTag(DwarfTag tag) const;
    std::shared_ptr<Type> findTypeByName(const std::string& name) const;
    
    // Debugging
    void printTypes() const;
    void printType(std::shared_ptr<Type> type, int indent = 0) const;
    
private:
    std::map<uint64_t, std::shared_ptr<Type>> type_cache_;
    std::vector<std::shared_ptr<Type>> all_types_;
    uint8_t pointer_size_bytes_ = sizeof(void*);
    DIELookup die_lookup_;
    
    // Type resolution helpers
    std::shared_ptr<Type> resolvePrimitiveType(std::shared_ptr<DIE> die);
    std::shared_ptr<Type> resolvePointerType(std::shared_ptr<DIE> die);
    std::shared_ptr<Type> resolveMemberPointerType(std::shared_ptr<DIE> die);
    std::shared_ptr<Type> resolveStringType(std::shared_ptr<DIE> die);
    std::shared_ptr<Type> resolveSetType(std::shared_ptr<DIE> die);
    std::shared_ptr<Type> resolveFileType(std::shared_ptr<DIE> die);
    std::shared_ptr<Type> resolveArrayType(std::shared_ptr<DIE> die);
    std::shared_ptr<Type> resolveCompositeType(std::shared_ptr<DIE> die);
    std::shared_ptr<Type> resolveEnumType(std::shared_ptr<DIE> die);
    std::shared_ptr<Type> resolveFunctionType(std::shared_ptr<DIE> die);
    std::shared_ptr<Type> resolveTypedefType(std::shared_ptr<DIE> die);
    std::shared_ptr<Type> resolveModifiedType(std::shared_ptr<DIE> die, ModifiedTypeKind kind);

    // Attribute helpers
    std::string getTypeName(std::shared_ptr<DIE> die) const;
    uint64_t getTypeSize(std::shared_ptr<DIE> die) const;
    std::shared_ptr<DIE> getTypeReference(std::shared_ptr<DIE> die) const;
    uint64_t getSubrangeCount(std::shared_ptr<DIE> die) const;
    int64_t getSubrangeLowerBound(std::shared_ptr<DIE> die) const;
};

} // namespace dwarf
