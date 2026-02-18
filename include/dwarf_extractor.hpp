#pragma once

#include "dwarf_database.hpp"
#include "dwarf_parser.hpp"
#include "type_system.hpp"
#include <memory>

namespace dwarf {

class DwarfExtractor {
public:
    explicit DwarfExtractor(std::shared_ptr<DwarfParser> parser);
    ~DwarfExtractor() = default;
    
    // Main extraction method
    std::shared_ptr<DwarfDatabase> extract();
    
    // Individual extraction methods
    void extractCompilationUnits();
    void extractFunctions();
    void extractVariables();
    void extractTypes();
    
    // Access to the database
    std::shared_ptr<DwarfDatabase> getDatabase() const { return database_; }
    
    // Configuration
    void setVerbose(bool verbose) { verbose_ = verbose; }
    bool isVerbose() const { return verbose_; }

private:
    std::shared_ptr<DwarfParser> parser_;
    std::shared_ptr<DwarfDatabase> database_;
    std::shared_ptr<TypeSystem> type_system_;
    bool verbose_;
    
    // Helper methods for extraction
    std::shared_ptr<FunctionInfo> extractFunction(std::shared_ptr<DIE> die);
    std::shared_ptr<VariableInfo> extractVariable(std::shared_ptr<DIE> die);
    std::shared_ptr<TypeInfo> extractType(std::shared_ptr<DIE> die);
    std::shared_ptr<CompilationUnitInfo> extractCompilationUnit(std::shared_ptr<DIE> die);
    
    // Attribute extraction helpers
    std::string extractName(std::shared_ptr<DIE> die);
    std::string extractTypeName(std::shared_ptr<DIE> die);
    uint64_t extractLowPC(std::shared_ptr<DIE> die);
    uint64_t extractHighPC(std::shared_ptr<DIE> die);
    uint64_t extractSize(std::shared_ptr<DIE> die);
    uint64_t extractLocation(std::shared_ptr<DIE> die);
    std::string extractLocationDescription(std::shared_ptr<DIE> die);
    std::string extractFrameBase(std::shared_ptr<DIE> die);
    std::string extractLanguage(std::shared_ptr<DIE> die);
    std::string extractProducer(std::shared_ptr<DIE> die);
    
    // Property extraction helpers
    bool isStatic(std::shared_ptr<DIE> die);
    bool isInline(std::shared_ptr<DIE> die);
    bool isVirtual(std::shared_ptr<DIE> die);
    bool isGlobal(std::shared_ptr<DIE> die);
    bool isConst(std::shared_ptr<DIE> die);
    bool isVolatile(std::shared_ptr<DIE> die);
    bool isPrimitive(std::shared_ptr<DIE> die);
    bool isComposite(std::shared_ptr<DIE> die);
    bool isArray(std::shared_ptr<DIE> die);
    bool isPointer(std::shared_ptr<DIE> die);
    bool isReference(std::shared_ptr<DIE> die);
    
    // Parameter and member extraction
    std::vector<std::string> extractParameters(std::shared_ptr<DIE> die);
    std::vector<std::string> extractMembers(std::shared_ptr<DIE> die);
    std::vector<std::string> extractEnumerators(std::shared_ptr<DIE> die);
    
    // Utility methods
    std::string getAttributeString(std::shared_ptr<DIE> die, DwarfAttribute attr);
    uint64_t getAttributeUInt(std::shared_ptr<DIE> die, DwarfAttribute attr);
    bool hasAttribute(std::shared_ptr<DIE> die, DwarfAttribute attr);
    std::string getTagName(DwarfTag tag);
    std::string formatAddress(uint64_t address);
    std::string formatLocation(uint64_t location);
    
    // Debug output
    void debugOutput(const std::string& message) const;
};

} // namespace dwarf
