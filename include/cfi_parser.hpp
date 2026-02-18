#pragma once

#include "dwarf_types.hpp"
#include <vector>
#include <map>
#include <stack>
#include <cstdint>
#include <optional>
#include <memory>
#include <functional>

namespace dwarf {

// Register rule for unwinding
struct RegisterRule {
    CFA_RegRule type = CFA_RegRule::UNDEFINED;
    int64_t offset = 0;                     // For OFFSET, VAL_OFFSET
    uint64_t reg_num = 0;                   // For REGISTER
    std::vector<uint8_t> expression;        // For EXPRESSION, VAL_EXPRESSION
};

// CFA (Canonical Frame Address) definition
struct CFADefinition {
    CFA_Type type = CFA_Type::REGISTER_OFFSET;
    uint64_t reg_num = 0;                   // Register number for REGISTER_OFFSET
    int64_t offset = 0;                     // Offset for REGISTER_OFFSET
    std::vector<uint8_t> expression;        // For EXPRESSION type
};

// A single row in the virtual unwind table
struct UnwindRow {
    uint64_t location = 0;                  // PC address for this row
    CFADefinition cfa;                       // CFA definition
    std::map<uint64_t, RegisterRule> registers;  // Register rules indexed by register number
    // AArch64 extension: DW_CFA_AARCH64_negate_ra_state toggles this flag. When non-zero,
    // the return address value may be signed (PAC) and need masking before use.
    uint8_t aarch64_ra_sign_state = 0;
};

// Common Information Entry (CIE)
struct CIE {
    uint64_t offset;                        // Offset in section
    uint64_t length;                        // Length of CIE
    uint64_t cie_id;                        // CIE ID (0 for .debug_frame, 0 for .eh_frame)
    uint8_t version;                        // CIE version
    std::string augmentation;               // Augmentation string
    uint8_t address_size;                   // Address size (DWARF 4+)
    uint8_t segment_selector_size;          // Segment selector size (DWARF 4+)
    uint64_t code_alignment_factor;         // Code alignment factor (ULEB128)
    int64_t data_alignment_factor;          // Data alignment factor (SLEB128)
    uint64_t return_address_register;       // Return address register
    std::vector<uint8_t> initial_instructions;  // Initial instructions

    // Augmentation data (for .eh_frame)
    bool has_augmentation_data = false;
    uint8_t fde_pointer_encoding = 0;       // 'R' augmentation
    uint8_t lsda_pointer_encoding = 0;      // 'L' augmentation
    uint64_t personality_routine = 0;       // 'P' augmentation
    uint8_t personality_encoding = 0;
    bool signal_frame = false;              // 'S' augmentation

    // Computed initial row from CIE instructions
    UnwindRow initial_row;
};

// Frame Description Entry (FDE)
struct FDE {
    uint64_t offset;                        // Offset in section
    uint64_t length;                        // Length of FDE
    uint64_t cie_pointer;                   // Pointer to CIE
    uint64_t initial_location;              // Starting address
    uint64_t address_range;                 // Size of code region
    std::vector<uint8_t> instructions;      // FDE instructions

    // Augmentation data (for .eh_frame)
    uint64_t lsda_pointer = 0;              // LSDA pointer if present

    // Pointer to associated CIE
    std::shared_ptr<CIE> cie;
};

// Unwind information for a specific PC
struct UnwindInfo {
    bool valid = false;
    uint64_t pc = 0;
    uint8_t address_size = 8;
    CFADefinition cfa;
    std::map<uint64_t, RegisterRule> registers;
    uint64_t return_address_register = 0;
    uint8_t aarch64_ra_sign_state = 0; // See UnwindRow::aarch64_ra_sign_state

    // Get CFA value given register values
    // Returns CFA address, or 0 if cannot be computed
    uint64_t computeCFA(const std::vector<uint64_t>& reg_values) const;
    uint64_t computeCFA(const std::vector<uint64_t>& reg_values,
                        const std::function<uint64_t(uint64_t)>& read_memory) const;

    // Get previous value of a register given current register values and memory
    // Returns the value, or nullopt if cannot be recovered
    std::optional<uint64_t> getRegisterValue(uint64_t reg_num,
                                              const std::vector<uint64_t>& reg_values,
                                              uint64_t cfa,
                                              const std::function<uint64_t(uint64_t)>& read_memory) const;
};

// Parser for .debug_frame and .eh_frame sections
class CFIParser {
public:
    CFIParser(const std::vector<uint8_t>& section_data,
              bool is_eh_frame = false,
              uint8_t address_size = 8);

    // Parse the entire section
    bool parse();

    // Find FDE containing the given PC
    std::shared_ptr<FDE> findFDE(uint64_t pc) const;

    // Get unwind information for a specific PC
    UnwindInfo getUnwindInfo(uint64_t pc) const;

    // Get all CIEs
    const std::vector<std::shared_ptr<CIE>>& getCIEs() const { return cies_; }

    // Get all FDEs
    const std::vector<std::shared_ptr<FDE>>& getFDEs() const { return fdes_; }

    // Check if section is empty
    bool empty() const { return section_data_.empty(); }
    size_t size() const { return section_data_.size(); }

    // Set base address for eh_frame (needed for relative addressing)
    void setSectionBaseAddress(uint64_t base) { section_base_ = base; }

private:
    const std::vector<uint8_t>& section_data_;
    bool is_eh_frame_;
    uint8_t address_size_;
    uint64_t section_base_ = 0;

    std::vector<std::shared_ptr<CIE>> cies_;
    std::vector<std::shared_ptr<FDE>> fdes_;
    std::map<uint64_t, std::shared_ptr<CIE>> cie_map_;  // offset -> CIE

    // Parsing methods
    bool parseCIE(uint64_t offset, uint64_t length, bool is_64bit);
    bool parseFDE(uint64_t offset, uint64_t length, uint64_t cie_pointer, bool is_64bit);

    // Execute CFI instructions to build unwind table
    void executeInstructions(const std::vector<uint8_t>& instructions,
                            UnwindRow& row,
                            const CIE& cie,
                            uint64_t pc_begin,
                            uint64_t pc_end,
                            std::vector<UnwindRow>& table) const;

    // Execute a single CFI instruction
    uint64_t executeInstruction(uint64_t offset,
                                const std::vector<uint8_t>& instructions,
                                UnwindRow& row,
                                const CIE& cie,
                                std::stack<UnwindRow>& state_stack) const;

    // Decode pointer based on encoding (for .eh_frame)
    uint64_t decodePointer(uint64_t& offset, uint8_t encoding, uint64_t pc_rel_base) const;
    uint64_t decodePointerBounded(uint64_t& offset,
                                  uint64_t end,
                                  uint8_t encoding,
                                  uint64_t pc_rel_base) const;

    // Reading helpers
    uint8_t readU8(uint64_t& offset) const;
    uint16_t readU16(uint64_t& offset) const;
    uint32_t readU32(uint64_t& offset) const;
    uint64_t readU64(uint64_t& offset) const;
    uint64_t readAddress(uint64_t& offset) const;
    uint64_t readULEB128(uint64_t& offset) const;
    int64_t readSLEB128(uint64_t& offset) const;
    std::vector<uint8_t> readBlock(uint64_t& offset, uint64_t size) const;
};

} // namespace dwarf
