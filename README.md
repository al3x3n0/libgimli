# DWARF/DIE Parser and Evaluator

A comprehensive C++ library for parsing and evaluating DWARF debug information from ELF files using the ELFIO library.

## Features

- **Complete DWARF Parser**: Parse DWARF debug information from ELF files
- **DIE (Debug Information Entry) Support**: Full support for all DWARF DIE types
- **Type System**: Comprehensive type system for representing DWARF types
- **Expression Evaluator**: Evaluate DWARF location expressions and operations
- **Attribute Parser**: Parse and evaluate DWARF attributes
- **Modern C++**: Uses C++17 features and modern design patterns
- **Cross-platform**: Works on Linux, macOS, and Windows

## Dependencies

- **ELFIO**: Header-only ELF file I/O library (included as submodule)
- **CMake**: Build system (version 3.16 or later)
- **C++17 Compiler**: GCC 7+, Clang 5+, or MSVC 2017+

## Building

```bash
# Clone the repository
git clone <repository-url>
cd dwarf

# Initialize submodules
git submodule update --init --recursive

# Create build directory
mkdir build
cd build

# Configure and build
cmake ..
make -j$(nproc)

# Run tests
./dwarf_tests

# Run example
./dwarf_example <path-to-elf-file>
```

## Usage

### Basic Usage

```cpp
#include "dwarf_parser.hpp"

// Create parser and load ELF file
dwarf::DwarfParser parser("program.elf");
if (!parser.load()) {
    std::cerr << "Failed to load DWARF information" << std::endl;
    return 1;
}

// Get compilation units
auto compilation_units = parser.getCompilationUnits();

// Get functions
auto functions = parser.getFunctions();
for (const auto& func : functions) {
    std::cout << "Function: " << func->getName() << std::endl;
}

// Get types
auto types = parser.getTypes();
for (const auto& type : types) {
    std::cout << "Type: " << type->getName() << std::endl;
}
```

### Type System

```cpp
#include "type_system.hpp"

dwarf::TypeSystem type_system;

// Create primitive types
auto int_type = type_system.createPrimitiveType(
    dwarf::PrimitiveType::Kind::INTEGER, 4, "int");

// Create pointer types
auto int_ptr_type = type_system.createPointerType(int_type);

// Create array types
std::vector<uint64_t> dimensions = {10, 20};
auto array_type = type_system.createArrayType(int_type, dimensions);

// Create composite types
auto struct_type = std::dynamic_pointer_cast<dwarf::CompositeType>(
    type_system.createCompositeType(
        dwarf::CompositeType::Kind::STRUCT, "Point", 8));
struct_type->addMember("x", int_type, 0);
struct_type->addMember("y", int_type, 4);
```

### Expression Evaluation

```cpp
#include "expression_evaluator.hpp"

dwarf::ExpressionEvaluator evaluator;

// Evaluate a simple expression
std::vector<uint8_t> expression = {
    static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_const4u),
    42, 0, 0, 0  // 42 in little-endian
};

auto result = evaluator.evaluate(expression);
std::cout << "Result: " << result.description << std::endl;
```

## Architecture

### Core Components

1. **DwarfParser**: Main parser class that loads and manages DWARF information
2. **DIEParser**: Parses individual Debug Information Entries
3. **TypeSystem**: Manages type information and type resolution
4. **ExpressionEvaluator**: Evaluates DWARF location expressions
5. **DwarfUtils**: Utility functions for DWARF operations

### Data Structures

- **DIE**: Represents a Debug Information Entry with attributes and children
- **AttributeValue**: Base class for DWARF attribute values
- **Type**: Base class for type representations
- **ExpressionResult**: Result of expression evaluation

## Supported DWARF Features

### DIE Tags
- Compilation units
- Subprograms (functions)
- Variables and parameters
- Base types, pointer types, array types
- Structure types, union types, class types
- Enumeration types
- Typedefs
- Lexical blocks and scopes

### Attribute Forms
- Address forms (DW_FORM_addr)
- Data forms (DW_FORM_data1, DW_FORM_data2, etc.)
- String forms (DW_FORM_string, DW_FORM_strp)
- Reference forms (DW_FORM_ref1, DW_FORM_ref2, etc.)
- Block forms (DW_FORM_block, DW_FORM_block1, etc.)
- Expression forms (DW_FORM_exprloc)

### Expression Operations
- Arithmetic operations (add, subtract, multiply, divide)
- Bitwise operations (and, or, xor, shift)
- Comparison operations (equal, greater, less, etc.)
- Stack operations (dup, drop, swap, etc.)
- Memory operations (deref, xderef)
- Register operations (reg, breg, regx, etc.)
- Control flow operations (bra, skip)

## Example Programs

### Command Line Tool

The example program provides a command-line interface for exploring DWARF information:

```bash
# Show all information
./dwarf_example program.elf --all

# Show only types
./dwarf_example program.elf --types

# Show only functions
./dwarf_example program.elf --functions

# Show only variables
./dwarf_example program.elf --variables
```

### Test Suite

The test suite validates core functionality:

```bash
./dwarf_tests
```

## API Reference

### DwarfParser

```cpp
class DwarfParser {
public:
    explicit DwarfParser(const std::string& filename);
    bool load();
    bool isValid() const;
    
    // Information access
    const std::vector<std::shared_ptr<DIE>>& getCompilationUnits() const;
    std::vector<std::shared_ptr<DIE>> findDIEsByTag(DwarfTag tag) const;
    std::vector<std::shared_ptr<DIE>> findDIEsByName(const std::string& name) const;
    std::shared_ptr<DIE> findDIEByOffset(uint64_t offset) const;
    
    // Symbol information
    std::vector<std::shared_ptr<DIE>> getFunctions() const;
    std::vector<std::shared_ptr<DIE>> getVariables() const;
    std::vector<std::shared_ptr<DIE>> getTypes() const;
    
    // Debug output
    void printDebugInfo() const;
    void printCompilationUnits() const;
    void printTypes() const;
    void printFunctions() const;
    void printVariables() const;
};
```

### TypeSystem

```cpp
class TypeSystem {
public:
    // Type creation
    std::shared_ptr<Type> createPrimitiveType(PrimitiveType::Kind kind, uint64_t size, const std::string& name = "");
    std::shared_ptr<Type> createPointerType(std::shared_ptr<Type> pointee_type);
    std::shared_ptr<Type> createArrayType(std::shared_ptr<Type> element_type, const std::vector<uint64_t>& dimensions);
    std::shared_ptr<Type> createFunctionType(std::shared_ptr<Type> return_type, const std::vector<std::shared_ptr<Type>>& parameter_types, bool is_variadic = false);
    std::shared_ptr<Type> createCompositeType(CompositeType::Kind kind, const std::string& name, uint64_t size = 0);
    std::shared_ptr<Type> createEnumType(const std::string& name, std::shared_ptr<Type> underlying_type);
    
    // Type resolution
    std::shared_ptr<Type> resolveType(std::shared_ptr<DIE> die);
    std::shared_ptr<Type> getType(uint64_t offset);
    void cacheType(uint64_t offset, std::shared_ptr<Type> type);
    
    // Type queries
    std::vector<std::shared_ptr<Type>> getAllTypes() const;
    std::vector<std::shared_ptr<Type>> getTypesByTag(DwarfTag tag) const;
    std::shared_ptr<Type> findTypeByName(const std::string& name) const;
};
```

### ExpressionEvaluator

```cpp
class ExpressionEvaluator {
public:
    ExpressionEvaluator();
    
    // Main evaluation
    ExpressionResult evaluate(const std::vector<uint8_t>& expression, uint64_t pc = 0, const std::vector<uint64_t>& registers = {});
    
    // Stack operations
    void push(uint64_t value);
    uint64_t pop();
    uint64_t top() const;
    bool empty() const;
    size_t size() const;
    
    // Debugging
    void printStack() const;
    std::string expressionToString(const std::vector<uint8_t>& expression) const;
};
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## Acknowledgments

- ELFIO library for ELF file I/O
- DWARF Debugging Information Format specification
- The C++ community for modern C++ best practices
