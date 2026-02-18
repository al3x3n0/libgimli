#pragma once

#include "dwarf_parser.hpp"
#include "expression_evaluator.hpp"
#include "type_printer.hpp"
#include "variable_location.hpp"
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include <variant>
#include <map>

namespace dwarf {

// Forward declarations
class DwarfParser;

// Memory reader interface for reading target memory
class InspectorMemoryReader {
public:
    virtual ~InspectorMemoryReader() = default;

    // Read bytes from memory at the given address
    virtual bool read(uint64_t address, void* buffer, size_t size) const = 0;

    // Read a single value
    template<typename T>
    std::optional<T> readValue(uint64_t address) const {
        T value;
        if (read(address, &value, sizeof(T))) {
            return value;
        }
        return std::nullopt;
    }

    // Read a null-terminated string (with max length)
    virtual std::optional<std::string> readString(uint64_t address, size_t max_len = 256) const;

    // Read a pointer-sized value
    virtual std::optional<uint64_t> readPointer(uint64_t address, uint8_t ptr_size = 8) const;
};

// Register reader interface for reading CPU registers
class InspectorRegisterReader {
public:
    virtual ~InspectorRegisterReader() = default;

    // Read a register by DWARF register number
    virtual std::optional<uint64_t> readRegister(uint32_t reg_num) const = 0;

    // Get all register values (indexed by DWARF register number)
    virtual std::vector<uint64_t> getAllRegisters() const = 0;

    // Get the program counter
    virtual uint64_t getPC() const = 0;

    // Get the stack pointer
    virtual uint64_t getSP() const = 0;

    // Get the frame pointer (if available)
    virtual std::optional<uint64_t> getFP() const = 0;
};

// Represents a variable's value
struct VariableValue {
    // The raw bytes of the value
    std::vector<uint8_t> raw_data;

    // Interpreted value (based on type)
    std::variant<
        std::monostate,     // Unknown/unavailable
        bool,               // Boolean
        int64_t,            // Signed integer
        uint64_t,           // Unsigned integer
        double,             // Floating point
        std::string         // String (for char*)
    > value;

    // Type information
    std::string type_name;
    uint64_t byte_size = 0;
    bool is_pointer = false;
    bool is_reference = false;
    bool is_array = false;
    bool is_struct = false;
    bool is_enum = false;

    // For pointers - address and dereferenced value (if readable)
    uint64_t pointer_address = 0;
    std::shared_ptr<VariableValue> pointed_value;

    // For structs/classes - member values
    struct MemberValue {
        std::string name;
        uint64_t offset;
        std::shared_ptr<VariableValue> value;
    };
    std::vector<MemberValue> members;

    // For arrays - element values (first N elements)
    std::vector<std::shared_ptr<VariableValue>> elements;
    uint64_t array_length = 0;

    // For enums - the enumerator name
    std::string enum_name;

    // Status
    bool is_valid = false;
    std::string error_message;

    // Format as string
    std::string toString(int indent = 0) const;
    std::string toShortString() const;
};

// Information about a variable in scope
struct VariableInfo {
    std::string name;
    std::shared_ptr<DIE> die;           // The variable's DIE
    std::shared_ptr<DIE> type_die;      // The variable's type DIE

    // Scope information
    bool is_parameter = false;          // Function parameter
    bool is_local = false;              // Local variable
    bool is_global = false;             // Global/static variable
    bool is_artificial = false;         // Compiler-generated (e.g., "this")

    // Source location
    std::string decl_file;
    uint32_t decl_line = 0;

    // Type information (from TypePrinter)
    std::string type_string;
    uint64_t byte_size = 0;

    // Location and value (evaluated at specific PC)
    VariableLocation location;
    std::shared_ptr<VariableValue> value;
};

// Configuration for variable inspection
struct InspectorConfig {
    bool resolve_pointers = true;       // Dereference pointers
    uint32_t max_pointer_depth = 3;     // Max pointer chain depth
    uint32_t max_string_length = 256;   // Max chars for strings
    uint32_t max_array_elements = 16;   // Max array elements to show
    uint32_t max_struct_depth = 3;      // Max nested struct depth
    bool show_addresses = true;         // Show memory addresses
    bool show_raw_bytes = false;        // Show raw byte values
    bool include_artificial = false;    // Include compiler-generated vars
};

// Main variable inspector class
class VariableInspector {
public:
    VariableInspector(DwarfParser& parser,
                      const InspectorMemoryReader& memory,
                      const InspectorRegisterReader& registers,
                      InspectorConfig config = {});

    // Get all variables in scope at the given PC
    std::vector<VariableInfo> getVariablesInScope(uint64_t pc) const;

    // Get only local variables (including parameters)
    std::vector<VariableInfo> getLocals(uint64_t pc) const;

    // Get only function parameters
    std::vector<VariableInfo> getParameters(uint64_t pc) const;

    // Get global variables visible at this PC
    std::vector<VariableInfo> getGlobals(uint64_t pc) const;

    // Find a specific variable by name at the given PC
    std::optional<VariableInfo> findVariable(const std::string& name, uint64_t pc) const;

    // Evaluate a variable's location at the given PC
    VariableLocation evaluateLocation(const std::shared_ptr<DIE>& var_die, uint64_t pc) const;

    // Read a variable's value given its location and type
    std::shared_ptr<VariableValue> readValue(const VariableLocation& location,
                                              const std::shared_ptr<DIE>& type_die,
                                              int depth = 0) const;

    // Evaluate and read a variable's value
    std::shared_ptr<VariableValue> inspectVariable(const std::shared_ptr<DIE>& var_die,
                                                    uint64_t pc,
                                                    int depth = 0) const;

    // Print all variables in scope
    void printVariables(uint64_t pc, bool verbose = false) const;

    // Print a single variable
    void printVariable(const VariableInfo& var, bool verbose = false) const;

    // Get the function containing this PC
    std::shared_ptr<DIE> getFunctionAt(uint64_t pc) const;

    // Get the lexical block containing this PC
    std::shared_ptr<DIE> getLexicalBlockAt(uint64_t pc) const;

    // Update configuration
    void setConfig(const InspectorConfig& config) { config_ = config; }
    const InspectorConfig& getConfig() const { return config_; }

private:
    DwarfParser& parser_;
    const InspectorMemoryReader& memory_;
    const InspectorRegisterReader& registers_;
    InspectorConfig config_;

    // Type printer for formatting
    mutable std::unique_ptr<TypePrinter> type_printer_;

    // Expression evaluator
    mutable ExpressionEvaluator expr_evaluator_;

    // Internal helpers
    void collectVariablesFromDIE(const std::shared_ptr<DIE>& die,
                                  uint64_t pc,
                                  std::vector<VariableInfo>& vars,
                                  bool in_scope) const;

    bool isInScope(const std::shared_ptr<DIE>& die, uint64_t pc) const;
    bool isInRange(uint64_t low_pc, uint64_t high_pc, uint64_t pc) const;

    VariableInfo createVariableInfo(const std::shared_ptr<DIE>& var_die, uint64_t pc) const;

    std::shared_ptr<VariableValue> readPrimitiveValue(const VariableLocation& location,
                                                       const std::shared_ptr<DIE>& type_die) const;
    std::shared_ptr<VariableValue> readPointerValue(const VariableLocation& location,
                                                     const std::shared_ptr<DIE>& type_die,
                                                     int depth) const;
    std::shared_ptr<VariableValue> readArrayValue(const VariableLocation& location,
                                                   const std::shared_ptr<DIE>& type_die,
                                                   int depth) const;
    std::shared_ptr<VariableValue> readStructValue(const VariableLocation& location,
                                                    const std::shared_ptr<DIE>& type_die,
                                                    int depth) const;
    std::shared_ptr<VariableValue> readEnumValue(const VariableLocation& location,
                                                  const std::shared_ptr<DIE>& type_die) const;

    // Get underlying type (skip typedefs, const, etc.)
    std::shared_ptr<DIE> getBaseType(const std::shared_ptr<DIE>& type_die) const;

    // Read raw bytes from location
    std::optional<std::vector<uint8_t>> readRawBytes(const VariableLocation& location,
                                                      size_t size) const;
};

// Stub implementations for testing without real target
class StubMemoryReader : public InspectorMemoryReader {
public:
    bool read(uint64_t address, void* buffer, size_t size) const override;

    // Add fake memory regions for testing
    void addRegion(uint64_t address, const std::vector<uint8_t>& data);
    void addValue(uint64_t address, uint64_t value, size_t size = 8);
    void addString(uint64_t address, const std::string& str);

private:
    mutable std::map<uint64_t, std::vector<uint8_t>> regions_;
};

class StubRegisterReader : public InspectorRegisterReader {
public:
    std::optional<uint64_t> readRegister(uint32_t reg_num) const override;
    std::vector<uint64_t> getAllRegisters() const override;
    uint64_t getPC() const override { return pc_; }
    uint64_t getSP() const override { return sp_; }
    std::optional<uint64_t> getFP() const override { return fp_; }

    // Set register values
    void setRegister(uint32_t reg_num, uint64_t value);
    void setPC(uint64_t pc) { pc_ = pc; }
    void setSP(uint64_t sp) { sp_ = sp; }
    void setFP(uint64_t fp) { fp_ = fp; }

private:
    std::map<uint32_t, uint64_t> registers_;
    uint64_t pc_ = 0;
    uint64_t sp_ = 0;
    uint64_t fp_ = 0;
};

} // namespace dwarf
