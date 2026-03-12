#include "type_system.hpp"
#include "attribute_parser.hpp"
#include "die_parser.hpp"
#include "dwarf_utils.hpp"
#include <iostream>
#include <sstream>

namespace dwarf {

// PrimitiveType implementation
PrimitiveType::PrimitiveType(Kind kind, uint64_t size, const std::string& name)
    : kind_(kind), size_(size), name_(name) {
}

std::string PrimitiveType::getName() const {
    if (!name_.empty()) return name_;
    
    switch (kind_) {
        case Kind::VOID: return "void";
        case Kind::BOOLEAN: return "bool";
        case Kind::INTEGER: return "int";
        case Kind::FLOAT: return "float";
        case Kind::COMPLEX: return "complex";
        case Kind::POINTER: return "pointer";
        default: return "unknown";
    }
}

uint64_t PrimitiveType::getSize() const {
    return size_;
}

std::string PrimitiveType::getDescription() const {
    std::stringstream ss;
    ss << getName() << " (" << size_ << " bytes)";
    return ss.str();
}

bool PrimitiveType::isComplete() const {
    return true;
}

std::shared_ptr<Type> PrimitiveType::resolve() {
    return std::static_pointer_cast<Type>(shared_from_this());
}

// ModifiedType implementation
ModifiedType::ModifiedType(ModifiedTypeKind kind,
                           std::shared_ptr<Type> underlying_type,
                           uint64_t size,
                           const std::string& name)
    : kind_(kind), underlying_type_(std::move(underlying_type)), size_(size), name_(name) {
}

std::string ModifiedType::getName() const {
    const std::string underlying_name = underlying_type_ ? underlying_type_->getName() : "void";
    switch (kind_) {
        case ModifiedTypeKind::TYPEDEF:
            return name_.empty() ? underlying_name : name_;
        case ModifiedTypeKind::CONST:
            return "const " + underlying_name;
        case ModifiedTypeKind::VOLATILE:
            return "volatile " + underlying_name;
        case ModifiedTypeKind::RESTRICT:
            return underlying_name + " restrict";
        case ModifiedTypeKind::REFERENCE:
            return underlying_name + "&";
        case ModifiedTypeKind::RVALUE_REFERENCE:
            return underlying_name + "&&";
        case ModifiedTypeKind::ATOMIC:
            return "_Atomic(" + underlying_name + ")";
    }
    return underlying_name;
}

uint64_t ModifiedType::getSize() const {
    if (size_ != 0) return size_;
    return underlying_type_ ? underlying_type_->getSize() : 0;
}

std::string ModifiedType::getDescription() const {
    std::stringstream ss;
    ss << getName();
    uint64_t size = getSize();
    if (size != 0) ss << " (" << size << " bytes)";
    return ss.str();
}

bool ModifiedType::isComplete() const {
    return underlying_type_ ? underlying_type_->isComplete() : false;
}

std::shared_ptr<Type> ModifiedType::resolve() {
    if (!underlying_type_) return nullptr;
    return underlying_type_->resolve();
}

// CompositeType implementation
CompositeType::CompositeType(Kind kind, const std::string& name, uint64_t size)
    : kind_(kind), name_(name), size_(size) {
}

std::string CompositeType::getName() const {
    return name_;
}

uint64_t CompositeType::getSize() const {
    return size_;
}

std::string CompositeType::getDescription() const {
    std::stringstream ss;
    ss << getName() << " (" << size_ << " bytes)";
    if (!members_.empty()) {
        ss << " with " << members_.size() << " members";
    }
    return ss.str();
}

bool CompositeType::isComplete() const {
    return size_ > 0;
}

std::shared_ptr<Type> CompositeType::resolve() {
    return std::static_pointer_cast<Type>(shared_from_this());
}

void CompositeType::addMember(const std::string& name, std::shared_ptr<Type> type, uint64_t offset) {
    members_.push_back({name, type, offset, 0, 0, false, false, false, false});
}

void CompositeType::addMember(const Member& member) {
    members_.push_back(member);
}

std::shared_ptr<Type> CompositeType::getMemberType(const std::string& name) const {
    for (const auto& member : members_) {
        if (member.name == name) {
            return member.type;
        }
    }
    return nullptr;
}

uint64_t CompositeType::getMemberOffset(const std::string& name) const {
    for (const auto& member : members_) {
        if (member.name == name) {
            return member.offset;
        }
    }
    return 0;
}

void CompositeType::addBaseClass(std::shared_ptr<CompositeType> base, uint64_t offset) {
    base_classes_.push_back({base, offset, false, false, false, false});
}

void CompositeType::addBaseClass(const BaseClass& base) {
    base_classes_.push_back(base);
}

// ArrayType implementation
ArrayType::ArrayType(std::shared_ptr<Type> element_type, const std::vector<uint64_t>& dimensions)
    : element_type_(std::move(element_type)), dimensions_(dimensions) {
    bounds_.reserve(dimensions_.size());
    for (uint64_t dim : dimensions_) {
        bounds_.push_back({0, dim});
    }
}

ArrayType::ArrayType(std::shared_ptr<Type> element_type, const std::vector<ArrayBound>& bounds)
    : element_type_(std::move(element_type)), bounds_(bounds) {
    dimensions_.reserve(bounds_.size());
    for (const auto& bound : bounds_) {
        dimensions_.push_back(bound.count);
    }
}

std::string ArrayType::getName() const {
    std::stringstream ss;
    ss << element_type_->getName();
    for (uint64_t dim : dimensions_) {
        ss << "[" << dim << "]";
    }
    return ss.str();
}

uint64_t ArrayType::getSize() const {
    uint64_t total_size = element_type_->getSize();
    for (uint64_t dim : dimensions_) {
        total_size *= dim;
    }
    return total_size;
}

std::string ArrayType::getDescription() const {
    std::stringstream ss;
    ss << getName() << " (" << getSize() << " bytes)";
    return ss.str();
}

bool ArrayType::isComplete() const {
    return element_type_->isComplete();
}

std::shared_ptr<Type> ArrayType::resolve() {
    return std::static_pointer_cast<Type>(shared_from_this());
}

uint64_t ArrayType::getElementCount() const {
    uint64_t count = 1;
    for (uint64_t dim : dimensions_) {
        count *= dim;
    }
    return count;
}

// StringType implementation
StringType::StringType(const std::string& name,
                       std::shared_ptr<Type> character_type,
                       uint64_t size)
    : name_(name), character_type_(std::move(character_type)), size_(size) {
}

std::string StringType::getName() const {
    if (!name_.empty()) {
        return name_;
    }
    if (character_type_) {
        std::stringstream ss;
        ss << character_type_->getName() << "[";
        if (size_ != 0) {
            ss << size_;
        }
        ss << "]";
        return ss.str();
    }
    return "string";
}

uint64_t StringType::getSize() const {
    return size_;
}

std::string StringType::getDescription() const {
    std::stringstream ss;
    ss << getName();
    if (size_ != 0) {
        ss << " (" << size_ << " bytes)";
    }
    return ss.str();
}

bool StringType::isComplete() const {
    return true;
}

std::shared_ptr<Type> StringType::resolve() {
    return std::static_pointer_cast<Type>(shared_from_this());
}

// SetType implementation
SetType::SetType(const std::string& name,
                 std::shared_ptr<Type> element_type,
                 uint64_t size)
    : name_(name), element_type_(std::move(element_type)), size_(size) {
}

std::string SetType::getName() const {
    if (!name_.empty()) {
        return name_;
    }
    if (element_type_) {
        return "set<" + element_type_->getName() + ">";
    }
    return "set";
}

uint64_t SetType::getSize() const {
    return size_;
}

std::string SetType::getDescription() const {
    std::stringstream ss;
    ss << getName();
    if (size_ != 0) {
        ss << " (" << size_ << " bytes)";
    }
    return ss.str();
}

bool SetType::isComplete() const {
    return true;
}

std::shared_ptr<Type> SetType::resolve() {
    return std::static_pointer_cast<Type>(shared_from_this());
}

// FileType implementation
FileType::FileType(const std::string& name,
                   std::shared_ptr<Type> element_type,
                   uint64_t size,
                   uint64_t element_count)
    : name_(name),
      element_type_(std::move(element_type)),
      size_(size),
      element_count_(element_count) {
}

std::string FileType::getName() const {
    if (!name_.empty()) {
        return name_;
    }
    std::string base = "file";
    if (element_type_) {
        base += "<" + element_type_->getName() + ">";
    }
    if (element_count_ != 0) {
        std::stringstream ss;
        ss << base << "[" << element_count_ << "]";
        return ss.str();
    }
    return base;
}

uint64_t FileType::getSize() const {
    return size_;
}

std::string FileType::getDescription() const {
    std::stringstream ss;
    ss << getName();
    if (size_ != 0) {
        ss << " (" << size_ << " bytes)";
    }
    return ss.str();
}

bool FileType::isComplete() const {
    return true;
}

std::shared_ptr<Type> FileType::resolve() {
    return std::static_pointer_cast<Type>(shared_from_this());
}

// FunctionType implementation
FunctionType::FunctionType(std::shared_ptr<Type> return_type, 
                           const std::vector<std::shared_ptr<Type>>& parameter_types,
                           bool is_variadic)
    : return_type_(std::move(return_type)), parameter_types_(parameter_types), is_variadic_(is_variadic) {
    parameters_.reserve(parameter_types_.size());
    for (const auto& parameter_type : parameter_types_) {
        parameters_.push_back({"", parameter_type});
    }
}

FunctionType::FunctionType(std::shared_ptr<Type> return_type,
                           const std::vector<FunctionParameter>& parameters,
                           bool is_variadic)
    : return_type_(std::move(return_type)), parameters_(parameters), is_variadic_(is_variadic) {
    parameter_types_.reserve(parameters_.size());
    for (const auto& parameter : parameters_) {
        parameter_types_.push_back(parameter.type);
    }
}

std::string FunctionType::getName() const {
    std::stringstream ss;
    ss << return_type_->getName() << "(";
    for (size_t i = 0; i < parameter_types_.size(); ++i) {
        if (i > 0) ss << ", ";
        ss << parameter_types_[i]->getName();
    }
    if (is_variadic_) {
        if (!parameter_types_.empty()) ss << ", ";
        ss << "...";
    }
    ss << ")";
    return ss.str();
}

uint64_t FunctionType::getSize() const {
    return 0; // Functions don't have a size
}

std::string FunctionType::getDescription() const {
    return getName();
}

bool FunctionType::isComplete() const {
    return return_type_->isComplete();
}

std::shared_ptr<Type> FunctionType::resolve() {
    return std::static_pointer_cast<Type>(shared_from_this());
}

// MemberPointerType implementation
MemberPointerType::MemberPointerType(std::shared_ptr<Type> member_type,
                                     std::shared_ptr<Type> containing_type,
                                     uint64_t size)
    : member_type_(std::move(member_type)),
      containing_type_(std::move(containing_type)),
      size_(size) {
}

std::string MemberPointerType::getName() const {
    const std::string member_name = member_type_ ? member_type_->getName() : "void";
    const std::string containing_name = containing_type_ ? containing_type_->getName() : "<unknown>";
    return member_name + " " + containing_name + "::*";
}

uint64_t MemberPointerType::getSize() const {
    return size_;
}

std::string MemberPointerType::getDescription() const {
    std::stringstream ss;
    ss << getName();
    if (size_ != 0) {
        ss << " (" << size_ << " bytes)";
    }
    return ss.str();
}

bool MemberPointerType::isComplete() const {
    return member_type_ && containing_type_ &&
           member_type_->isComplete() && containing_type_->isComplete();
}

std::shared_ptr<Type> MemberPointerType::resolve() {
    return std::static_pointer_cast<Type>(shared_from_this());
}

// EnumType implementation
EnumType::EnumType(const std::string& name, std::shared_ptr<Type> underlying_type, bool is_scoped)
    : name_(name), underlying_type_(underlying_type), is_scoped_(is_scoped) {
}

std::string EnumType::getName() const {
    return name_;
}

uint64_t EnumType::getSize() const {
    return underlying_type_ ? underlying_type_->getSize() : 0;
}

std::string EnumType::getDescription() const {
    std::stringstream ss;
    if (is_scoped_) {
        ss << "enum class ";
    }
    ss << name_ << " (" << getSize() << " bytes)";
    if (!enumerators_.empty()) {
        ss << " with " << enumerators_.size() << " values";
    }
    return ss.str();
}

bool EnumType::isComplete() const {
    return underlying_type_ && underlying_type_->isComplete();
}

std::shared_ptr<Type> EnumType::resolve() {
    return std::static_pointer_cast<Type>(shared_from_this());
}

void EnumType::addEnumerator(const std::string& name, int64_t value) {
    enumerators_.push_back({name, value});
}

std::string EnumType::getEnumeratorName(int64_t value) const {
    for (const auto& enumerator : enumerators_) {
        if (enumerator.value == value) {
            return enumerator.name;
        }
    }
    return "";
}

// TypeSystem implementation
TypeSystem::TypeSystem(uint8_t pointer_size_bytes, DIELookup die_lookup)
    : pointer_size_bytes_(pointer_size_bytes)
    , die_lookup_(std::move(die_lookup)) {}

std::shared_ptr<Type> TypeSystem::createPrimitiveType(PrimitiveType::Kind kind, uint64_t size, 
                                                      const std::string& name) {
    auto type = std::make_shared<PrimitiveType>(kind, size, name);
    type->setDwarfTag(DwarfTag::DW_TAG_base_type);
    all_types_.push_back(type);
    return type;
}

std::shared_ptr<Type> TypeSystem::createPointerType(std::shared_ptr<Type> pointee_type) {
    auto type = std::make_shared<PrimitiveType>(PrimitiveType::Kind::POINTER, 
                                                pointer_size_bytes_, 
                                                pointee_type->getName() + "*");
    type->setDwarfTag(DwarfTag::DW_TAG_pointer_type);
    all_types_.push_back(type);
    return type;
}

std::shared_ptr<Type> TypeSystem::createReferenceType(std::shared_ptr<Type> referee_type) {
    auto type = std::make_shared<ModifiedType>(ModifiedTypeKind::REFERENCE,
                                               std::move(referee_type),
                                               pointer_size_bytes_);
    type->setDwarfTag(DwarfTag::DW_TAG_reference_type);
    all_types_.push_back(type);
    return type;
}

std::shared_ptr<Type> TypeSystem::createRvalueReferenceType(std::shared_ptr<Type> referee_type) {
    auto type = std::make_shared<ModifiedType>(ModifiedTypeKind::RVALUE_REFERENCE,
                                               std::move(referee_type),
                                               pointer_size_bytes_);
    type->setDwarfTag(DwarfTag::DW_TAG_rvalue_reference_type);
    all_types_.push_back(type);
    return type;
}

std::shared_ptr<Type> TypeSystem::createAtomicType(std::shared_ptr<Type> value_type) {
    auto type = std::make_shared<ModifiedType>(ModifiedTypeKind::ATOMIC,
                                               std::move(value_type));
    type->setDwarfTag(DwarfTag::DW_TAG_atomic_type);
    all_types_.push_back(type);
    return type;
}

std::shared_ptr<Type> TypeSystem::createMemberPointerType(std::shared_ptr<Type> member_type,
                                                          std::shared_ptr<Type> containing_type) {
    auto type = std::make_shared<MemberPointerType>(std::move(member_type),
                                                    std::move(containing_type),
                                                    pointer_size_bytes_);
    type->setDwarfTag(DwarfTag::DW_TAG_ptr_to_member_type);
    all_types_.push_back(type);
    return type;
}

std::shared_ptr<Type> TypeSystem::createStringType(const std::string& name,
                                                   std::shared_ptr<Type> character_type,
                                                   uint64_t size) {
    auto type = std::make_shared<StringType>(name, std::move(character_type), size);
    type->setDwarfTag(DwarfTag::DW_TAG_string_type);
    all_types_.push_back(type);
    return type;
}

std::shared_ptr<Type> TypeSystem::createSetType(const std::string& name,
                                                std::shared_ptr<Type> element_type,
                                                uint64_t size) {
    auto type = std::make_shared<SetType>(name, std::move(element_type), size);
    type->setDwarfTag(DwarfTag::DW_TAG_set_type);
    all_types_.push_back(type);
    return type;
}

std::shared_ptr<Type> TypeSystem::createFileType(const std::string& name,
                                                 std::shared_ptr<Type> element_type,
                                                 uint64_t size,
                                                 uint64_t element_count) {
    auto type = std::make_shared<FileType>(name, std::move(element_type), size, element_count);
    type->setDwarfTag(DwarfTag::DW_TAG_file_type);
    all_types_.push_back(type);
    return type;
}

std::shared_ptr<Type> TypeSystem::createArrayType(std::shared_ptr<Type> element_type, 
                                                  const std::vector<uint64_t>& dimensions) {
    auto type = std::make_shared<ArrayType>(element_type, dimensions);
    type->setDwarfTag(DwarfTag::DW_TAG_array_type);
    all_types_.push_back(type);
    return type;
}

std::shared_ptr<Type> TypeSystem::createArrayType(std::shared_ptr<Type> element_type,
                                                  const std::vector<ArrayBound>& bounds) {
    auto type = std::make_shared<ArrayType>(std::move(element_type), bounds);
    type->setDwarfTag(DwarfTag::DW_TAG_array_type);
    all_types_.push_back(type);
    return type;
}

std::shared_ptr<Type> TypeSystem::createFunctionType(std::shared_ptr<Type> return_type,
                                                     const std::vector<std::shared_ptr<Type>>& parameter_types,
                                                     bool is_variadic) {
    auto type = std::make_shared<FunctionType>(return_type, parameter_types, is_variadic);
    type->setDwarfTag(DwarfTag::DW_TAG_subroutine_type);
    all_types_.push_back(type);
    return type;
}

std::shared_ptr<Type> TypeSystem::createFunctionType(std::shared_ptr<Type> return_type,
                                                     const std::vector<FunctionParameter>& parameters,
                                                     bool is_variadic) {
    auto type = std::make_shared<FunctionType>(std::move(return_type), parameters, is_variadic);
    type->setDwarfTag(DwarfTag::DW_TAG_subroutine_type);
    all_types_.push_back(type);
    return type;
}

std::shared_ptr<Type> TypeSystem::createModifiedType(ModifiedTypeKind kind,
                                                     std::shared_ptr<Type> underlying_type,
                                                     uint64_t size,
                                                     const std::string& name) {
    auto type = std::make_shared<ModifiedType>(kind, std::move(underlying_type), size, name);
    switch (kind) {
        case ModifiedTypeKind::TYPEDEF:
            type->setDwarfTag(DwarfTag::DW_TAG_typedef);
            break;
        case ModifiedTypeKind::CONST:
            type->setDwarfTag(DwarfTag::DW_TAG_const_type);
            break;
        case ModifiedTypeKind::VOLATILE:
            type->setDwarfTag(DwarfTag::DW_TAG_volatile_type);
            break;
        case ModifiedTypeKind::RESTRICT:
            type->setDwarfTag(DwarfTag::DW_TAG_restrict_type);
            break;
        case ModifiedTypeKind::REFERENCE:
            type->setDwarfTag(DwarfTag::DW_TAG_reference_type);
            break;
        case ModifiedTypeKind::RVALUE_REFERENCE:
            type->setDwarfTag(DwarfTag::DW_TAG_rvalue_reference_type);
            break;
        case ModifiedTypeKind::ATOMIC:
            type->setDwarfTag(DwarfTag::DW_TAG_atomic_type);
            break;
    }
    all_types_.push_back(type);
    return type;
}

std::shared_ptr<Type> TypeSystem::createCompositeType(CompositeType::Kind kind, const std::string& name,
                                                      uint64_t size) {
    auto type = std::make_shared<CompositeType>(kind, name, size);
    switch (kind) {
        case CompositeType::Kind::STRUCT:
            type->setDwarfTag(DwarfTag::DW_TAG_structure_type);
            break;
        case CompositeType::Kind::UNION:
            type->setDwarfTag(DwarfTag::DW_TAG_union_type);
            break;
        case CompositeType::Kind::CLASS:
            type->setDwarfTag(DwarfTag::DW_TAG_class_type);
            break;
        case CompositeType::Kind::INTERFACE:
            type->setDwarfTag(DwarfTag::DW_TAG_interface_type);
            break;
    }
    all_types_.push_back(type);
    return type;
}

std::shared_ptr<Type> TypeSystem::createEnumType(const std::string& name, 
                                                 std::shared_ptr<Type> underlying_type,
                                                 bool is_scoped) {
    auto type = std::make_shared<EnumType>(name, underlying_type, is_scoped);
    type->setDwarfTag(DwarfTag::DW_TAG_enumeration_type);
    all_types_.push_back(type);
    return type;
}

std::shared_ptr<Type> TypeSystem::resolveType(std::shared_ptr<DIE> die) {
    if (!die) return nullptr;
    
    uint64_t offset = die->getOffset();
    auto cached = type_cache_.find(offset);
    if (cached != type_cache_.end()) {
        return cached->second;
    }
    
    std::shared_ptr<Type> type;
    
    switch (die->getTag()) {
        case DwarfTag::DW_TAG_base_type:
            type = resolvePrimitiveType(die);
            break;
        case DwarfTag::DW_TAG_unspecified_type:
            type = createPrimitiveType(PrimitiveType::Kind::VOID, getTypeSize(die), getTypeName(die));
            break;
        case DwarfTag::DW_TAG_string_type:
            type = resolveStringType(die);
            break;
        case DwarfTag::DW_TAG_set_type:
            type = resolveSetType(die);
            break;
        case DwarfTag::DW_TAG_file_type:
            type = resolveFileType(die);
            break;
        case DwarfTag::DW_TAG_pointer_type:
            type = resolvePointerType(die);
            break;
        case DwarfTag::DW_TAG_ptr_to_member_type:
            type = resolveMemberPointerType(die);
            break;
        case DwarfTag::DW_TAG_reference_type:
            type = resolveModifiedType(die, ModifiedTypeKind::REFERENCE);
            break;
        case DwarfTag::DW_TAG_rvalue_reference_type:
            type = resolveModifiedType(die, ModifiedTypeKind::RVALUE_REFERENCE);
            break;
        case DwarfTag::DW_TAG_atomic_type:
            type = resolveModifiedType(die, ModifiedTypeKind::ATOMIC);
            break;
        case DwarfTag::DW_TAG_array_type:
            type = resolveArrayType(die);
            break;
        case DwarfTag::DW_TAG_structure_type:
        case DwarfTag::DW_TAG_union_type:
        case DwarfTag::DW_TAG_class_type:
        case DwarfTag::DW_TAG_interface_type:
            type = resolveCompositeType(die);
            break;
        case DwarfTag::DW_TAG_enumeration_type:
            type = resolveEnumType(die);
            break;
        case DwarfTag::DW_TAG_subroutine_type:
            type = resolveFunctionType(die);
            break;
        case DwarfTag::DW_TAG_typedef:
            type = resolveTypedefType(die);
            break;
        case DwarfTag::DW_TAG_const_type:
            type = resolveModifiedType(die, ModifiedTypeKind::CONST);
            break;
        case DwarfTag::DW_TAG_volatile_type:
            type = resolveModifiedType(die, ModifiedTypeKind::VOLATILE);
            break;
        case DwarfTag::DW_TAG_restrict_type:
            type = resolveModifiedType(die, ModifiedTypeKind::RESTRICT);
            break;
        default:
            return nullptr;
    }
    
    if (type) {
        type->setDwarfTag(die->getTag());
        type_cache_[offset] = type;
    }
    
    return type;
}

std::shared_ptr<Type> TypeSystem::getType(uint64_t offset) {
    auto it = type_cache_.find(offset);
    return (it != type_cache_.end()) ? it->second : nullptr;
}

void TypeSystem::cacheType(uint64_t offset, std::shared_ptr<Type> type) {
    type_cache_[offset] = type;
}

std::vector<std::shared_ptr<Type>> TypeSystem::getAllTypes() const {
    return all_types_;
}

std::vector<std::shared_ptr<Type>> TypeSystem::getTypesByTag(DwarfTag tag) const {
    std::vector<std::shared_ptr<Type>> result;
    for (const auto& type : all_types_) {
        if (type && type->getDwarfTag() == tag) {
            result.push_back(type);
        }
    }
    return result;
}

std::shared_ptr<Type> TypeSystem::findTypeByName(const std::string& name) const {
    for (const auto& type : all_types_) {
        if (type->getName() == name) {
            return type;
        }
    }
    return nullptr;
}

void TypeSystem::printTypes() const {
    std::cout << "Types:" << std::endl;
    for (const auto& type : all_types_) {
        printType(type, 1);
    }
}

void TypeSystem::printType(std::shared_ptr<Type> type, int indent) const {
    if (!type) return;
    
    std::string indent_str(indent * 2, ' ');
    std::cout << indent_str << type->getDescription() << std::endl;
}

// Type resolution helpers
std::shared_ptr<Type> TypeSystem::resolvePrimitiveType(std::shared_ptr<DIE> die) {
    std::string name = getTypeName(die);
    uint64_t size = getTypeSize(die);
    
    // Determine the primitive type kind based on encoding
    auto encoding_attr = die->getAttribute(DwarfAttribute::DW_AT_encoding);
    PrimitiveType::Kind kind = PrimitiveType::Kind::INTEGER;
    
    if (encoding_attr && encoding_attr->getType() == AttributeValueType::UNSIGNED) {
        uint64_t encoding = std::static_pointer_cast<UnsignedAttributeValue>(encoding_attr)->getValue();
        switch (encoding) {
            case 1: // DW_ATE_address
                kind = PrimitiveType::Kind::POINTER;
                break;
            case 2: // DW_ATE_boolean
                kind = PrimitiveType::Kind::BOOLEAN;
                break;
            case 3: // DW_ATE_float
                kind = PrimitiveType::Kind::FLOAT;
                break;
            case 4: // DW_ATE_signed
            case 5: // DW_ATE_signed_char
                kind = PrimitiveType::Kind::INTEGER;
                break;
            case 6: // DW_ATE_unsigned
            case 7: // DW_ATE_unsigned_char
                kind = PrimitiveType::Kind::INTEGER;
                break;
            default:
                kind = PrimitiveType::Kind::INTEGER;
                break;
        }
    }
    
    return createPrimitiveType(kind, size, name);
}

std::shared_ptr<Type> TypeSystem::resolvePointerType(std::shared_ptr<DIE> die) {
    std::string name = getTypeName(die);
    uint64_t size = getTypeSize(die);
    
    auto pointee_type = getTypeReference(die);
    std::shared_ptr<Type> resolved_pointee = pointee_type ? resolveType(pointee_type) : nullptr;
    
    if (resolved_pointee) {
        return createPointerType(resolved_pointee);
    } else {
        return createPrimitiveType(PrimitiveType::Kind::POINTER, size, name);
    }
}

std::shared_ptr<Type> TypeSystem::resolveMemberPointerType(std::shared_ptr<DIE> die) {
    auto member_die = getTypeReference(die);
    std::shared_ptr<Type> resolved_member = member_die ? resolveType(member_die) : nullptr;

    std::shared_ptr<Type> resolved_containing;
    auto containing_attr = die->getAttribute(DwarfAttribute::DW_AT_containing_type);
    if (containing_attr && containing_attr->getType() == AttributeValueType::REFERENCE) {
        auto ref = std::static_pointer_cast<ReferenceAttributeValue>(containing_attr);
        if (die_lookup_) {
            resolved_containing = resolveType(die_lookup_(ref->getOffset()));
        }
    }

    return createMemberPointerType(resolved_member, resolved_containing);
}

std::shared_ptr<Type> TypeSystem::resolveStringType(std::shared_ptr<DIE> die) {
    auto char_die = getTypeReference(die);
    std::shared_ptr<Type> resolved_char = char_die ? resolveType(char_die) : nullptr;
    return createStringType(getTypeName(die), resolved_char, getTypeSize(die));
}

std::shared_ptr<Type> TypeSystem::resolveSetType(std::shared_ptr<DIE> die) {
    auto element_die = getTypeReference(die);
    std::shared_ptr<Type> resolved_element = element_die ? resolveType(element_die) : nullptr;
    return createSetType(getTypeName(die), resolved_element, getTypeSize(die));
}

std::shared_ptr<Type> TypeSystem::resolveFileType(std::shared_ptr<DIE> die) {
    auto element_die = getTypeReference(die);
    std::shared_ptr<Type> resolved_element = element_die ? resolveType(element_die) : nullptr;

    uint64_t element_count = 0;
    for (const auto& child : die->getChildren()) {
        if (child->getTag() == DwarfTag::DW_TAG_subrange_type) {
            element_count = getSubrangeCount(child);
            break;
        }
    }

    return createFileType(getTypeName(die), resolved_element, getTypeSize(die), element_count);
}

std::shared_ptr<Type> TypeSystem::resolveArrayType(std::shared_ptr<DIE> die) {
    uint64_t size = getTypeSize(die);

    auto element_type = getTypeReference(die);
    std::shared_ptr<Type> resolved_element = element_type ? resolveType(element_type) : nullptr;

    if (resolved_element) {
        std::vector<ArrayBound> bounds;

        for (const auto& child : die->getChildren()) {
            if (child->getTag() == DwarfTag::DW_TAG_subrange_type) {
                bounds.push_back({getSubrangeLowerBound(child), getSubrangeCount(child)});
            }
        }

        if (bounds.empty()) {
            if (size != 0 && resolved_element->getSize() != 0) {
                bounds.push_back({0, size / resolved_element->getSize()});
            } else {
                bounds.push_back({0, 1});
            }
        }

        return createArrayType(resolved_element, bounds);
    } else {
        return createPrimitiveType(PrimitiveType::Kind::INTEGER, size, getTypeName(die));
    }
}

std::shared_ptr<Type> TypeSystem::resolveCompositeType(std::shared_ptr<DIE> die) {
    std::string name = getTypeName(die);
    uint64_t size = getTypeSize(die);
    
    CompositeType::Kind kind = CompositeType::Kind::STRUCT;
    if (die->getTag() == DwarfTag::DW_TAG_union_type) {
        kind = CompositeType::Kind::UNION;
    } else if (die->getTag() == DwarfTag::DW_TAG_class_type) {
        kind = CompositeType::Kind::CLASS;
    } else if (die->getTag() == DwarfTag::DW_TAG_interface_type) {
        kind = CompositeType::Kind::INTERFACE;
    }
    
    auto composite_type = std::make_shared<CompositeType>(kind, name, size);
    all_types_.push_back(composite_type);
    
    // Parse members
    for (const auto& child : die->getChildren()) {
        if (child->getTag() == DwarfTag::DW_TAG_member) {
            std::string member_name = child->getName();
            auto member_type = getTypeReference(child);
            std::shared_ptr<Type> resolved_member_type = member_type ? resolveType(member_type) : nullptr;
            
            if (resolved_member_type) {
                Member member{member_name, resolved_member_type, 0, 0, 0, false, false, false, false};
                auto offset_attr = child->getAttribute(DwarfAttribute::DW_AT_data_member_location);
                if (offset_attr && offset_attr->getType() == AttributeValueType::UNSIGNED) {
                    member.offset = std::static_pointer_cast<UnsignedAttributeValue>(offset_attr)->getValue();
                }

                auto bit_size_attr = child->getAttribute(DwarfAttribute::DW_AT_bit_size);
                if (bit_size_attr && bit_size_attr->getType() == AttributeValueType::UNSIGNED) {
                    member.bit_size = std::static_pointer_cast<UnsignedAttributeValue>(bit_size_attr)->getValue();
                }

                auto bit_offset_attr = child->getAttribute(DwarfAttribute::DW_AT_data_bit_offset);
                if (bit_offset_attr && bit_offset_attr->getType() == AttributeValueType::UNSIGNED) {
                    member.bit_offset = std::static_pointer_cast<UnsignedAttributeValue>(bit_offset_attr)->getValue();
                }

                auto external_attr = child->getAttribute(DwarfAttribute::DW_AT_external);
                if (external_attr && external_attr->getType() == AttributeValueType::FLAG) {
                    member.is_static = std::static_pointer_cast<FlagAttributeValue>(external_attr)->getValue();
                }

                auto access_attr = child->getAttribute(DwarfAttribute::DW_AT_accessibility);
                if (access_attr && access_attr->getType() == AttributeValueType::UNSIGNED) {
                    switch (std::static_pointer_cast<UnsignedAttributeValue>(access_attr)->getValue()) {
                        case 1: member.is_public = true; break;
                        case 2: member.is_protected = true; break;
                        case 3: member.is_private = true; break;
                        default: break;
                    }
                }

                composite_type->addMember(member);
            }
        } else if (child->getTag() == DwarfTag::DW_TAG_inheritance) {
            auto base_type_die = getTypeReference(child);
            auto base_type = base_type_die ? resolveType(base_type_die) : nullptr;
            auto base_composite = std::dynamic_pointer_cast<CompositeType>(base_type);
            if (base_composite) {
                BaseClass base{base_composite, 0, false, false, false, false};
                auto offset_attr = child->getAttribute(DwarfAttribute::DW_AT_data_member_location);
                if (offset_attr && offset_attr->getType() == AttributeValueType::UNSIGNED) {
                    base.offset = std::static_pointer_cast<UnsignedAttributeValue>(offset_attr)->getValue();
                }
                auto virtuality_attr = child->getAttribute(DwarfAttribute::DW_AT_virtuality);
                if (virtuality_attr && virtuality_attr->getType() == AttributeValueType::UNSIGNED) {
                    base.is_virtual = std::static_pointer_cast<UnsignedAttributeValue>(virtuality_attr)->getValue() != 0;
                }
                auto access_attr = child->getAttribute(DwarfAttribute::DW_AT_accessibility);
                if (access_attr && access_attr->getType() == AttributeValueType::UNSIGNED) {
                    switch (std::static_pointer_cast<UnsignedAttributeValue>(access_attr)->getValue()) {
                        case 1: base.is_public = true; break;
                        case 2: base.is_protected = true; break;
                        case 3: base.is_private = true; break;
                        default: break;
                    }
                }
                composite_type->addBaseClass(base);
            }
        }
    }
    
    return composite_type;
}

std::shared_ptr<Type> TypeSystem::resolveEnumType(std::shared_ptr<DIE> die) {
    std::string name = getTypeName(die);
    uint64_t size = getTypeSize(die);
    
    auto underlying_type = getTypeReference(die);
    std::shared_ptr<Type> resolved_underlying = underlying_type ? resolveType(underlying_type) : nullptr;
    
    if (!resolved_underlying) {
        resolved_underlying = createPrimitiveType(PrimitiveType::Kind::INTEGER, size, "int");
    }
    
    bool is_scoped = false;
    auto enum_class_attr = die->getAttribute(DwarfAttribute::DW_AT_enum_class);
    if (enum_class_attr && enum_class_attr->getType() == AttributeValueType::FLAG) {
        is_scoped = std::static_pointer_cast<FlagAttributeValue>(enum_class_attr)->getValue();
    }

    auto enum_type = std::dynamic_pointer_cast<EnumType>(
        createEnumType(name, resolved_underlying, is_scoped));
    
    // Parse enumerators
    for (const auto& child : die->getChildren()) {
        if (child->getTag() == DwarfTag::DW_TAG_enumerator) {
            std::string enumerator_name = child->getName();
            auto const_attr = child->getAttribute(DwarfAttribute::DW_AT_const_value);
            if (const_attr) {
                if (const_attr->getType() == AttributeValueType::UNSIGNED) {
                    int64_t value = std::static_pointer_cast<UnsignedAttributeValue>(const_attr)->getValue();
                    enum_type->addEnumerator(enumerator_name, value);
                } else if (const_attr->getType() == AttributeValueType::SIGNED) {
                    int64_t value = std::static_pointer_cast<SignedAttributeValue>(const_attr)->getValue();
                    enum_type->addEnumerator(enumerator_name, value);
                }
            }
        }
    }
    
    return enum_type;
}

std::shared_ptr<Type> TypeSystem::resolveFunctionType(std::shared_ptr<DIE> die) {
    std::string name = getTypeName(die);
    
    auto return_type = getTypeReference(die);
    std::shared_ptr<Type> resolved_return = return_type ? resolveType(return_type) : nullptr;
    
    if (!resolved_return) {
        resolved_return = createPrimitiveType(PrimitiveType::Kind::VOID, 0, "void");
    }
    
    std::vector<FunctionParameter> parameters;
    bool is_variadic = false;

    for (const auto& child : die->getChildren()) {
        if (child->getTag() == DwarfTag::DW_TAG_formal_parameter) {
            auto param_type = getTypeReference(child);
            std::shared_ptr<Type> resolved_param = param_type ? resolveType(param_type) : nullptr;
            if (resolved_param) {
                parameters.push_back({child->getName(), resolved_param});
            }
        } else if (child->getTag() == DwarfTag::DW_TAG_unspecified_parameters) {
            is_variadic = true;
        }
    }

    return createFunctionType(resolved_return, parameters, is_variadic);
}

std::shared_ptr<Type> TypeSystem::resolveTypedefType(std::shared_ptr<DIE> die) {
    std::string name = getTypeName(die);

    auto underlying_type = getTypeReference(die);
    std::shared_ptr<Type> resolved_underlying = underlying_type ? resolveType(underlying_type) : nullptr;

    if (resolved_underlying) {
        return createModifiedType(ModifiedTypeKind::TYPEDEF, resolved_underlying, resolved_underlying->getSize(), name);
    } else {
        return createModifiedType(ModifiedTypeKind::TYPEDEF, nullptr, 0, name);
    }
}

std::shared_ptr<Type> TypeSystem::resolveModifiedType(std::shared_ptr<DIE> die, ModifiedTypeKind kind) {
    auto underlying_die = getTypeReference(die);
    std::shared_ptr<Type> resolved_underlying = underlying_die ? resolveType(underlying_die) : nullptr;
    const uint64_t size = (kind == ModifiedTypeKind::REFERENCE ||
                           kind == ModifiedTypeKind::RVALUE_REFERENCE)
                              ? pointer_size_bytes_
                              : getTypeSize(die);
    return createModifiedType(kind, resolved_underlying, size, getTypeName(die));
}

// Attribute helpers
std::string TypeSystem::getTypeName(std::shared_ptr<DIE> die) const {
    auto name_attr = die->getAttribute(DwarfAttribute::DW_AT_name);
    if (name_attr && name_attr->getType() == AttributeValueType::STRING) {
        return std::static_pointer_cast<StringAttributeValue>(name_attr)->getValue();
    }
    return "";
}

uint64_t TypeSystem::getTypeSize(std::shared_ptr<DIE> die) const {
    auto size_attr = die->getAttribute(DwarfAttribute::DW_AT_byte_size);
    if (size_attr && size_attr->getType() == AttributeValueType::UNSIGNED) {
        return std::static_pointer_cast<UnsignedAttributeValue>(size_attr)->getValue();
    }
    return 0;
}

std::shared_ptr<DIE> TypeSystem::getTypeReference(std::shared_ptr<DIE> die) const {
    auto type_attr = die->getAttribute(DwarfAttribute::DW_AT_type);
    if (!type_attr) return nullptr;

    uint64_t offset = 0;
    if (auto ref = std::dynamic_pointer_cast<ReferenceAttributeValue>(type_attr)) {
        offset = ref->getOffset();
    } else if (auto tv = std::dynamic_pointer_cast<TypeAttributeValue>(type_attr)) {
        offset = tv->getOffset();
    }

    if (offset == 0) return nullptr;
    if (!die_lookup_) return nullptr;
    return die_lookup_(offset);
}

uint64_t TypeSystem::getSubrangeCount(std::shared_ptr<DIE> die) const {
    if (!die) return 1;

    auto count_attr = die->getAttribute(DwarfAttribute::DW_AT_count);
    if (count_attr && count_attr->getType() == AttributeValueType::UNSIGNED) {
        return std::static_pointer_cast<UnsignedAttributeValue>(count_attr)->getValue();
    }

    int64_t lower = 0;
    auto lower_attr = die->getAttribute(DwarfAttribute::DW_AT_lower_bound);
    if (auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(lower_attr)) {
        lower = static_cast<int64_t>(u->getValue());
    } else if (auto s = std::dynamic_pointer_cast<SignedAttributeValue>(lower_attr)) {
        lower = s->getValue();
    }

    auto upper_attr = die->getAttribute(DwarfAttribute::DW_AT_upper_bound);
    if (auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(upper_attr)) {
        int64_t upper = static_cast<int64_t>(u->getValue());
        return upper >= lower ? static_cast<uint64_t>(upper - lower + 1) : 1;
    }
    if (auto s = std::dynamic_pointer_cast<SignedAttributeValue>(upper_attr)) {
        int64_t upper = s->getValue();
        return upper >= lower ? static_cast<uint64_t>(upper - lower + 1) : 1;
    }

    return 1;
}

int64_t TypeSystem::getSubrangeLowerBound(std::shared_ptr<DIE> die) const {
    if (!die) return 0;

    auto lower_attr = die->getAttribute(DwarfAttribute::DW_AT_lower_bound);
    if (auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(lower_attr)) {
        return static_cast<int64_t>(u->getValue());
    }
    if (auto s = std::dynamic_pointer_cast<SignedAttributeValue>(lower_attr)) {
        return s->getValue();
    }

    return 0;
}

} // namespace dwarf
