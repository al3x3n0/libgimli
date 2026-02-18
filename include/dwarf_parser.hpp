#pragma once

#include "dwarf_types.hpp"
#include "die_parser.hpp"
#include "debug_names_parser.hpp"
#include "debug_macro_parser.hpp"
#include "cfi_parser.hpp"
#include "source_location.hpp"
#include "variable_location.hpp"
#include "split_dwarf.hpp"
#include <elfio/elfio.hpp>
#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <map>
#include <unordered_map>

namespace dwarf {

class DwarfParser {
public:
    explicit DwarfParser(const std::string& filename);
    ~DwarfParser() = default;
    
    // Main interface
    bool load();
    bool isValid() const { return is_valid_; }
    
    // Debug options
    void setVerbose(bool verbose) { verbose_ = verbose; }
    bool isVerbose() const { return verbose_; }

    // ELF access
    const ELFIO::elfio& getELF() const { return *elf_; }
    
    // DWARF information access
    const std::vector<std::shared_ptr<DIE>>& getCompilationUnits() const { return compilation_units_; }
    std::vector<std::shared_ptr<DIE>> findDIEsByTag(DwarfTag tag) const;
    std::vector<std::shared_ptr<DIE>> findDIEsByName(const std::string& name) const;
    std::shared_ptr<DIE> findDIEByOffset(uint64_t offset) const;
    
    // Type system access
    std::shared_ptr<DIE> getType(uint64_t type_offset) const;
    std::string getTypeName(std::shared_ptr<DIE> type_die) const;
    uint64_t getTypeSize(std::shared_ptr<DIE> type_die) const;
    
    // Symbol information
    std::vector<std::shared_ptr<DIE>> getFunctions() const;
    std::vector<std::shared_ptr<DIE>> getVariables() const;
    std::vector<std::shared_ptr<DIE>> getTypes() const;

    // Function lookup by address
    std::shared_ptr<DIE> getFunctionAt(uint64_t address) const;
    std::shared_ptr<DIE> getInlinedFunctionAt(uint64_t address) const;
    std::vector<std::shared_ptr<DIE>> getFunctionsInRange(uint64_t start, uint64_t end) const;

    // Accelerated name lookup (uses .debug_names if available)
    std::vector<std::shared_ptr<DIE>> findDIEsByNameFast(const std::string& name) const;
    bool hasAcceleratedLookup() const { return names_parser_ != nullptr; }

    // Macro information access
    std::vector<MacroDefinition> getMacroDefinitions(uint64_t offset = 0) const;
    std::vector<MacroDefinition> lookupMacro(const std::string& name, uint64_t offset = 0) const;
    std::vector<MacroDefinition> getMacroDefinitionsForCU(const std::shared_ptr<DIE>& cu) const;
    std::vector<MacroDefinition> lookupMacroForCU(const std::shared_ptr<DIE>& cu, const std::string& name) const;
    bool hasMacroInfo() const { return macro_parser_ != nullptr; }

    // CFI (Call Frame Information) / Stack Unwinding
    UnwindInfo getUnwindInfo(uint64_t pc) const;
    bool hasCFI() const { return cfi_parser_ != nullptr; }

    // Unwind a single frame given register values and memory reader
    // Returns the unwound register values and the return address
    struct UnwindResult {
        bool success = false;
        uint64_t return_address = 0;
        std::vector<uint64_t> registers;
    };
    UnwindResult unwindFrame(uint64_t pc,
                            const std::vector<uint64_t>& registers,
                            const std::function<uint64_t(uint64_t)>& read_memory) const;

    // Source location lookup (address <-> line)
    std::optional<SourceLocation> getSourceLocation(uint64_t address) const;
    std::vector<SourceLocation> getAllSourceLocations(uint64_t address) const;
    std::vector<uint64_t> getAddressesForLine(const std::string& file, uint32_t line) const;
    std::optional<AddressRange> getAddressRangeForLine(const std::string& file, uint32_t line) const;
    std::vector<SourceLocation> getLinesInFile(const std::string& file) const;
    std::vector<std::string> getAllSourceFiles() const;
    bool hasSourceLocationInfo() const { return source_resolver_ != nullptr; }

    // Variable location evaluation
    VariableLocation getVariableLocation(const std::shared_ptr<DIE>& variable, uint64_t pc) const;
    VariableLocation evaluateLocation(const std::vector<uint8_t>& location_data,
                                      uint64_t pc, bool is_loclist = false) const;
    void setVariableEvaluationContext(const EvaluationContext& context);
    void setMemoryReader(std::function<bool(uint64_t, size_t, void*)> reader);

    // Split DWARF support
    void addDWOSearchPath(const std::string& path);
    void setDWOSearchPaths(const std::vector<std::string>& paths);
    bool loadDWOFile(const std::string& path);
    bool loadDWPFile(const std::string& path);
    bool hasSplitDwarf() const { return split_loader_ != nullptr || dwp_loader_ != nullptr; }

    // Debug information
    void printDebugInfo() const;
    void printCompilationUnits() const;
    void printTypes() const;
    void printFunctions() const;
    void printVariables() const;
    
    // File information
    const std::string& getFilename() const { return filename_; }
    DwarfVersion getVersion() const { return version_; }
    AddressSize getAddressSize() const { return address_size_; }
    
private:
    std::string filename_;
    std::unique_ptr<ELFIO::elfio> elf_;
    std::unique_ptr<ELFIO::elfio> sup_elf_;
    std::unique_ptr<DIEParser> die_parser_;
    std::unique_ptr<DIEParser> sup_die_parser_;
    
    // DWARF sections
    std::vector<uint8_t> debug_info_;
    std::vector<uint8_t> debug_abbrev_;
    std::vector<uint8_t> debug_str_;
    std::vector<uint8_t> debug_line_;
    std::vector<uint8_t> debug_ranges_;
    std::vector<uint8_t> debug_loc_;

    // DWARF 5 sections
    std::vector<uint8_t> debug_str_offsets_;
    std::vector<uint8_t> debug_addr_;
    std::vector<uint8_t> debug_line_str_;
    std::vector<uint8_t> debug_rnglists_;
    std::vector<uint8_t> debug_loclists_;
    std::vector<uint8_t> debug_sup_;
    std::vector<uint8_t> debug_str_sup_;
    std::vector<uint8_t> debug_names_;
    std::vector<uint8_t> debug_macro_;

    // Supplementary file sections (DWARF5 .debug_sup)
    std::vector<uint8_t> sup_debug_info_;
    std::vector<uint8_t> sup_debug_abbrev_;
    std::vector<uint8_t> sup_debug_str_;
    std::vector<uint8_t> sup_debug_line_;
    std::vector<uint8_t> sup_debug_str_offsets_;
    std::vector<uint8_t> sup_debug_addr_;
    std::vector<uint8_t> sup_debug_line_str_;
    std::vector<uint8_t> sup_debug_rnglists_;
    std::vector<uint8_t> sup_debug_loclists_;

    // CFI sections
    std::vector<uint8_t> debug_frame_;
    std::vector<uint8_t> eh_frame_;

    // DWARF 5 parsers
    std::unique_ptr<DebugNamesParser> names_parser_;
    std::unique_ptr<DebugMacroParser> macro_parser_;

    // CFI parser
    std::unique_ptr<CFIParser> cfi_parser_;

    // Source location resolver
    std::unique_ptr<SourceLocationResolver> source_resolver_;

    // Variable location evaluator
    std::unique_ptr<VariableLocationEvaluator> var_evaluator_;

    // Split DWARF support
    std::unique_ptr<SplitDwarfLoader> split_loader_;
    std::unique_ptr<DWPLoader> dwp_loader_;
    std::map<uint64_t, uint16_t> dwo_slot_by_id_;
    std::unordered_map<uint16_t, uint64_t> dwo_id_by_slot_;
    uint16_t next_dwo_slot_ = 1;
    // Cached DWO section payloads needed at query time (notably for DWPs where slices are temporary).
    std::unordered_map<uint64_t, std::vector<uint8_t>> dwo_debug_addr_by_id_;
    mutable std::unordered_map<uint64_t, std::vector<uint64_t>> debug_addr_table_cache_;

    // Parsed data
    std::vector<std::shared_ptr<DIE>> compilation_units_;
    std::vector<std::shared_ptr<DIE>> supplementary_units_;
    std::map<uint64_t, std::shared_ptr<DIE>> die_cache_;
    
    // DWARF version info
    DwarfVersion version_;
    AddressSize address_size_;
    bool is_valid_;
    bool verbose_;
    uint64_t supplementary_debug_info_offset_bias_ = 0;
    
    // Internal methods
    bool loadELFFile();
    bool loadDWARFSections();
    bool parseCompilationUnits();
    void integrateSupplementary();
    void integrateSplitDwarf();
    uint64_t getOrAssignDWOBias(uint64_t dwo_id);
    const std::vector<uint64_t>* getDebugAddrTable(uint64_t addr_base, uint8_t address_size) const;
    const std::vector<uint64_t>* getDebugAddrTableForSection(const std::vector<uint8_t>& debug_addr_section,
                                                             uint64_t addr_base,
                                                             uint8_t address_size) const;
    void cacheDIE(std::shared_ptr<DIE> die);
    
    // Section loading helpers
    bool loadSection(const std::string& section_name, std::vector<uint8_t>& data);
    std::vector<uint8_t> getSectionData(const ELFIO::section* section) const;

    // Initialize source location resolver from line tables
    void initializeSourceResolver();
};

} // namespace dwarf
