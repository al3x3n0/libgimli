#pragma once

#include "dwarf_types.hpp"
#include "expression_evaluator.hpp"
#include "loclists_parser.hpp"
#include <vector>
#include <string>
#include <optional>
#include <functional>
#include <cstdint>

namespace dwarf {

// Variable location type
enum class VariableLocationType {
    INVALID,        // Location cannot be determined
    REGISTER,       // Value is in a register
    MEMORY,         // Value is at a memory address
    IMPLICIT,       // Value is implicit (constant or computed)
    COMPOSITE,      // Value is split across multiple locations
    OPTIMIZED_OUT   // Variable was optimized out
};

// Single piece of a variable's location
struct LocationPiece {
    VariableLocationType type = VariableLocationType::INVALID;
    uint64_t location = 0;      // Register number or memory address
    uint64_t size_bits = 0;     // Size in bits
    uint64_t offset_bits = 0;   // Bit offset within the piece
    std::vector<uint8_t> value; // For IMPLICIT type
};

// Complete variable location at a specific PC
struct VariableLocation {
    VariableLocationType type = VariableLocationType::INVALID;
    std::vector<LocationPiece> pieces;
    uint64_t address = 0;       // For simple MEMORY locations
    uint64_t reg_num = 0;       // For simple REGISTER locations
    std::vector<uint8_t> implicit_value;  // For simple IMPLICIT locations
    std::string description;    // Human-readable description

    bool valid() const { return type != VariableLocationType::INVALID; }
    bool isOptimizedOut() const { return type == VariableLocationType::OPTIMIZED_OUT; }
};

// Location list entry with address range
struct LocationListEntry {
    uint64_t start_address;
    uint64_t end_address;
    std::vector<uint8_t> expression;
    bool is_default = false;
};

// Variable location evaluator
class VariableLocationEvaluator {
public:
    VariableLocationEvaluator();

    // Set evaluation context (registers, frame info, etc.)
    void setContext(const EvaluationContext& context);

    // Set memory reader for dereferencing
    void setMemoryReader(std::function<bool(uint64_t, size_t, void*)> reader);

    // Evaluate a simple location expression (DW_AT_location with exprloc form)
    VariableLocation evaluateExpression(const std::vector<uint8_t>& expression,
                                        uint64_t pc = 0);

    // Evaluate a location list at a specific PC
    VariableLocation evaluateLocationList(const std::vector<LocationListEntry>& entries,
                                          uint64_t pc);

    // Evaluate a DWARF 5 location list
    VariableLocation evaluateLocList(const std::vector<LocListEntry>& entries,
                                     uint64_t pc);

    // Parse and evaluate location from raw bytes (determines if expression or list)
    VariableLocation evaluateLocation(const std::vector<uint8_t>& location_data,
                                      uint64_t pc,
                                      bool is_loclist = false);

    // Read variable value from its location
    std::optional<std::vector<uint8_t>> readValue(const VariableLocation& location,
                                                   size_t size);

    // Format location as human-readable string
    static std::string formatLocation(const VariableLocation& location);

    // Get current context
    const EvaluationContext& getContext() const { return context_; }

private:
    EvaluationContext context_;
    std::shared_ptr<MemoryContext> memory_context_;
    std::unique_ptr<ExpressionEvaluator> evaluator_;
    std::function<bool(uint64_t, size_t, void*)> memory_reader_;

    // Convert expression result to variable location
    VariableLocation resultToLocation(const ExpressionResult& result);

    // Find matching entry for PC in location list
    const LocationListEntry* findEntry(const std::vector<LocationListEntry>& entries,
                                       uint64_t pc) const;
};

// Memory context implementation that uses a callback
class CallbackMemoryContext : public MemoryContext {
public:
    CallbackMemoryContext(std::function<bool(uint64_t, size_t, void*)> reader)
        : reader_(reader) {}

    bool readMemory(uint64_t address, size_t size, void* buffer) const override {
        if (reader_) {
            return reader_(address, size, buffer);
        }
        return false;
    }

    bool writeMemory(uint64_t address, size_t size, const void* buffer) override {
        (void)address; (void)size; (void)buffer;
        return false; // Writing not supported
    }

private:
    std::function<bool(uint64_t, size_t, void*)> reader_;
};

} // namespace dwarf
