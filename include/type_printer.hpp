#pragma once

#include "die_parser.hpp"
#include "dwarf_types.hpp"
#include <string>
#include <memory>
#include <map>
#include <vector>
#include <functional>

namespace dwarf {

/**
 * Configuration for type printing
 */
struct TypePrinterConfig {
    bool show_byte_sizes = false;           // Show byte sizes like "int (4 bytes)"
    bool show_offsets = false;              // Show member offsets in structs
    bool expand_typedefs = false;           // Expand typedefs to their underlying types
    bool qualified_names = true;            // Use fully qualified names (with namespaces)
    bool show_const_volatile = true;        // Show const/volatile qualifiers
    bool show_templates = true;             // Show template parameters
    bool show_function_params = true;       // Show function parameter types
    bool use_fixed_width_ints = false;      // Use uint32_t instead of unsigned int
    uint8_t pointer_size_bytes = 8;         // Size of pointers/references in bytes (target-dependent)
    int max_recursion_depth = 10;           // Max depth for nested type expansion
    std::string indent = "    ";            // Indentation string for struct members
};

/**
 * Type pretty printer
 *
 * Formats DWARF type DIEs as C/C++ type declarations.
 * Handles:
 * - Basic types (int, float, etc.)
 * - Pointers and references
 * - Arrays (fixed and variable length)
 * - Structures, unions, classes
 * - Enumerations
 * - Typedefs
 * - Function types and pointers
 * - Const/volatile qualifiers
 * - Template types (via name parsing)
 */
class TypePrinter {
public:
    using DIELookup = std::function<std::shared_ptr<DIE>(uint64_t)>;

    /**
     * Create a type printer
     * @param die_lookup Function to resolve DIE references by offset
     * @param config Configuration options
     */
    TypePrinter(DIELookup die_lookup, TypePrinterConfig config = {});

    /**
     * Format a type DIE as a C/C++ type string
     * @param type_die The type DIE to format
     * @return The formatted type string (e.g., "const int*")
     */
    std::string formatType(const std::shared_ptr<DIE>& type_die) const;

    /**
     * Format a type reference (DW_AT_type attribute value)
     * @param type_offset The offset of the type DIE
     * @return The formatted type string
     */
    std::string formatTypeRef(uint64_t type_offset) const;

    /**
     * Format a variable declaration
     * @param var_die The variable DIE
     * @return The formatted declaration (e.g., "int* ptr")
     */
    std::string formatVariable(const std::shared_ptr<DIE>& var_die) const;

    /**
     * Format a function declaration
     * @param func_die The function DIE
     * @return The formatted declaration (e.g., "int foo(char* str, int n)")
     */
    std::string formatFunction(const std::shared_ptr<DIE>& func_die) const;

    /**
     * Format a struct/class/union definition
     * @param type_die The struct/class/union DIE
     * @param include_members Whether to include member definitions
     * @return The formatted definition
     */
    std::string formatStructure(const std::shared_ptr<DIE>& type_die,
                                bool include_members = true) const;

    /**
     * Format an enumeration definition
     * @param enum_die The enum DIE
     * @param include_values Whether to include enumerator values
     * @return The formatted definition
     */
    std::string formatEnum(const std::shared_ptr<DIE>& enum_die,
                          bool include_values = true) const;

    /**
     * Format a typedef
     * @param typedef_die The typedef DIE
     * @return The formatted typedef (e.g., "typedef unsigned int uint32_t")
     */
    std::string formatTypedef(const std::shared_ptr<DIE>& typedef_die) const;

    /**
     * Get the size of a type in bytes
     * @param type_die The type DIE
     * @return The size in bytes, or 0 if unknown
     */
    uint64_t getTypeSize(const std::shared_ptr<DIE>& type_die) const;

    /**
     * Check if a type is a pointer type
     */
    bool isPointerType(const std::shared_ptr<DIE>& type_die) const;

    /**
     * Check if a type is an array type
     */
    bool isArrayType(const std::shared_ptr<DIE>& type_die) const;

    /**
     * Check if a type is a function type
     */
    bool isFunctionType(const std::shared_ptr<DIE>& type_die) const;

    /**
     * Update configuration
     */
    void setConfig(const TypePrinterConfig& config) { config_ = config; }
    const TypePrinterConfig& getConfig() const { return config_; }

private:
    DIELookup die_lookup_;
    TypePrinterConfig config_;
    mutable int recursion_depth_ = 0;
    mutable std::map<uint64_t, bool> visited_; // For cycle detection

    // Core type formatting
    std::string formatTypeInternal(const std::shared_ptr<DIE>& type_die,
                                   const std::string& var_name = "") const;

    // Specific type formatters
    std::string formatBaseType(const std::shared_ptr<DIE>& die) const;
    std::string formatPointerType(const std::shared_ptr<DIE>& die,
                                  const std::string& var_name) const;
    std::string formatReferenceType(const std::shared_ptr<DIE>& die,
                                    const std::string& var_name) const;
    std::string formatArrayType(const std::shared_ptr<DIE>& die,
                               const std::string& var_name) const;
    std::string formatConstType(const std::shared_ptr<DIE>& die,
                               const std::string& var_name) const;
    std::string formatVolatileType(const std::shared_ptr<DIE>& die,
                                   const std::string& var_name) const;
    std::string formatRestrictType(const std::shared_ptr<DIE>& die,
                                   const std::string& var_name) const;
    std::string formatTypedefType(const std::shared_ptr<DIE>& die) const;
    std::string formatStructType(const std::shared_ptr<DIE>& die) const;
    std::string formatUnionType(const std::shared_ptr<DIE>& die) const;
    std::string formatClassType(const std::shared_ptr<DIE>& die) const;
    std::string formatInterfaceType(const std::shared_ptr<DIE>& die) const;
    std::string formatEnumType(const std::shared_ptr<DIE>& die) const;
    std::string formatSubroutineType(const std::shared_ptr<DIE>& die,
                                     const std::string& var_name) const;
    std::string formatPtrToMemberType(const std::shared_ptr<DIE>& die,
                                      const std::string& var_name) const;

    // Helper methods
    std::shared_ptr<DIE> getReferencedType(const std::shared_ptr<DIE>& die) const;
    std::string getTypeName(const std::shared_ptr<DIE>& die) const;
    std::string getBaseTypeName(uint8_t encoding, uint64_t byte_size) const;
    std::vector<uint64_t> getArrayDimensions(const std::shared_ptr<DIE>& die) const;
    std::string formatArraySuffix(const std::vector<uint64_t>& dimensions) const;

    // Recursion guard
    class RecursionGuard {
    public:
        RecursionGuard(const TypePrinter* printer, uint64_t offset);
        ~RecursionGuard();
        bool isValid() const { return valid_; }
    private:
        const TypePrinter* printer_;
        uint64_t offset_;
        bool valid_;
    };
    friend class RecursionGuard;
};

} // namespace dwarf
