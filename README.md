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
- **Z3**: Optional. Enables solver-backed semantic verification for `compare-expr` and parts of `compare-cfi`

## Building

```bash
# Configure and build (default: Z3 enabled when available)
cmake -S . -B build
cmake --build build -j

# Run tests
ctest --test-dir build --output-on-failure

# Run example
./build/dwarf_example <path-to-elf-file>
```

Optional solver-free build:

```bash
# Build parser/query/CLI support without Z3
cmake -S . -B build-noz3 -DDWARF_ENABLE_Z3=OFF
cmake --build build-noz3 -j
ctest --test-dir build-noz3 --output-on-failure
```

Behavior by build mode:
- With Z3 enabled, semantic compare can prove equivalence/counterexamples and emits solver-backed buckets such as `unsat`, `sat`, `z3`, and `structural+z3`.
- With Z3 disabled, the same APIs and CLI subcommands remain available.
- In no-Z3 builds, `compare-expr` returns `solver_result=solver_unavailable` and `verifier_backend=solver-unavailable` for solver-dependent rows.
- In no-Z3 builds, `compare-cfi` still reports deterministic structural matches, with backends such as `structural+solver-unavailable`.

### Installed CMake Package

The install step exports a CMake package with a namespaced target:

```bash
cmake -S . -B build
cmake --build build -j
cmake --install build --prefix /tmp/dwarf-install
```

Consumer example:

```cmake
find_package(DwarfParser CONFIG REQUIRED)
add_executable(app main.cpp)
target_link_libraries(app PRIVATE Dwarf::dwarf_parser)
```

If the installed package was built with Z3 enabled, `find_package(DwarfParser)` will also resolve the Z3 dependency automatically.

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

`dwarf_dump` provides section dumps plus semantic comparison subcommands:

```bash
# Dump .debug_info
./build/dwarf_dump -i program.elf

# Dump everything
./build/dwarf_dump -A program.elf

# Compare location expressions (strict gate: fail on any difference)
./build/dwarf_dump compare-expr before.elf after.elf \
  --strict --max-different=0 --format=text

# Compare location expressions with JSON report output
./build/dwarf_dump compare-expr before.elf after.elf \
  --format=json --schema-version=1 --output=compare-expr.json

# Optional: relocation/index sanity checks + normalized range-aware location compare
./build/dwarf_dump compare-expr before.elf after.elf \
  --reloc-check --normalize-loc --range-aware \
  --min-equivalent-coverage=0.99 --max-different-coverage=0.00 \
  --fail-on-uncovered

# Compare unwind/CFI across all FDEs (strict gate)
./build/dwarf_dump compare-cfi before.elf after.elf \
  --all-fdes --strict --max-different=0

# Compare unwind/CFI while tolerating unknown/missing rows
./build/dwarf_dump compare-cfi before.elf after.elf \
  --all-fdes --allow-unknown --allow-missing --max-different=0

# C++ API example for semantic compare (expr + CFI)
./build/dwarf_semantic_compare_example before.elf after.elf
```

`dwarf_semantic_compare_example` demonstrates:
- `CrossBinaryExpressionComparator` for variable-location semantic equivalence
- solver-aware gate evaluation (`trigger`, `trigger_detail`, `signature`)
- `SymbolicCFIVerifier::compareFDEByIndex` for unwind/CFI equivalence metadata

### CI Gate Examples

Use `dwarf_dump` exit codes directly in CI jobs to enforce regression gates:

```bash
# Expression equivalence gate
./build/dwarf_dump compare-expr old.elf new.elf \
  --strict --max-different=0 --format=json --output=expr-report.json

# CFI equivalence gate over all functions/FDEs
./build/dwarf_dump compare-cfi old.elf new.elf \
  --all-fdes --strict --max-different=0 --format=json --output=cfi-report.json

# Optional policy: fail only on confirmed differences
./build/dwarf_dump compare-cfi old.elf new.elf \
  --all-fdes --allow-unknown --allow-missing --max-different=0
```

### Solver-Backed Semantic Policies

`compare-expr` and `compare-cfi` support solver-specific gates and summaries:

```bash
# Fail gate if any row is produced by a disallowed solver outcome/backend
./build/dwarf_dump compare-expr old.elf new.elf \
  --fail-on-solver-result=unknown \
  --fail-on-verifier-backend=z3

# Emit only solver/backend bucket summaries (no per-row report)
./build/dwarf_dump compare-cfi old.elf new.elf \
  --all-fdes --emit-solver-summary-only --format=json --schema-version=1
```

Useful options:
- `--solver-timeout-ms=<N>`
- `--fail-on-solver-result=<K>` (repeatable)
- `--fail-on-verifier-backend=<K>` (repeatable)
- `--emit-solver-summary-only`
- If both `fail-on` policies match a row, `solver_result` policy triggers first.

No-Z3 behavior:
- `compare-expr` still runs, but solver-dependent rows report `solver_result=solver_unavailable` and `verifier_backend=solver-unavailable`.
- `compare-cfi` still runs and can report structural equivalence, typically with `solver_result=equivalent` and `verifier_backend=structural+solver-unavailable`.
- This means gate policies remain usable in solver-free builds, but they evaluate against fallback buckets instead of Z3-backed ones.

JSON rows include solver metadata:
- `solver_result`
- `verifier_backend`
- `counterexample_model`
- `counterexample_witness`

JSON summaries include bucket counts:
- `solver_result_counts`
- `verifier_backend_counts`

### Test Suite

The test suite validates core functionality:

```bash
./dwarf_tests
```

### Semantic Compare API Cookbook

For a complete runnable API sample, see:
- `examples/semantic_compare_example.cpp`

Minimal C++ patterns:

```cpp
#include "dwarf_parser.hpp"
#include "expression_compare.hpp"
#include "cfi_symbolic.hpp"

using namespace dwarf;
```

1. Load two binaries and run variable location-expression semantic compare:

```cpp
DwarfParser lhs("before.elf");
DwarfParser rhs("after.elf");
if (!lhs.load() || !rhs.load() || !lhs.isValid() || !rhs.isValid()) {
    // handle load error
}

CrossBinaryExpressionComparator cmp;
CrossBinaryCompareOptions opts;
opts.tag = DwarfTag::DW_TAG_variable;
opts.attribute = DwarfAttribute::DW_AT_location;
opts.include_missing = true;
opts.verification_options.solver_timeout_ms = 200;

auto rows = cmp.compareParsersByName(lhs, rhs, opts);
auto summary = cmp.summarize(rows);
```

2. Apply solver-aware gate policy from library API:

```cpp
CrossBinaryGateOptions gate_opts;
gate_opts.max_different = 0;
gate_opts.fail_on_solver_results.insert("unknown");
gate_opts.fail_on_verifier_backends.insert("unspecified");

auto gate = cmp.evaluateGate(rows, gate_opts);
// gate.pass, gate.reason, gate.trigger, gate.trigger_detail, gate.signature
```

3. Render report payloads:

```cpp
std::string report_text = cmp.renderTextReport(rows, /*max_rows=*/50);
std::string report_json = cmp.renderJsonReport(rows, /*max_rows=*/50);
```

4. Compare unwind/CFI semantics for a specific FDE pair:

```cpp
if (lhs.hasCFI() && rhs.hasCFI() &&
    !lhs.getCFIParser().getFDEs().empty() &&
    !rhs.getCFIParser().getFDEs().empty()) {
    SymbolicCFIVerifier cfi_verifier;
    SymbolicCFICompareOptions cfi_opts;
    cfi_opts.expression_options.solver_timeout_ms = 200;

    auto cfi = cfi_verifier.compareFDEByIndex(
        lhs.getCFIParser(), 0,
        rhs.getCFIParser(), 0,
        cfi_opts);
    // cfi.verdict, cfi.verifier_backend, cfi.solver_result, cfi.reason
}
```

Common interpretation hints:
- `solver_result=unsat` usually means proof of equivalence.
- `solver_result=sat` means a semantic counterexample exists.
- `solver_result` values starting with `precheck_` are deterministic structural checks before SMT solving.
- `solver_result=solver_unavailable` means the library was built without Z3, so no SMT proof was attempted.
- `counterexample_model` / `counterexample_witness` are most useful for `sat` mismatches.

### Semantic Compare Contract

Compatibility guidance for semantic compare outputs/APIs:

- CLI JSON contract is versioned with `--schema-version`.
- For `schema_version=1`, these gate fields are part of the public contract:
  - `gate.pass`
  - `gate.reason`
  - `gate.trigger`
  - `gate.trigger_detail`
  - `gate.signature`
- For expression rows, solver metadata contract includes:
  - `verifier_backend`
  - `solver_result`
  - `counterexample_model`
  - `counterexample_witness`
- For CFI rows, solver metadata contract includes the same four fields above.

Stability policy:
- New fields may be added in minor releases without breaking existing fields.
- Existing field names/meanings for the current schema version are not changed without introducing a new schema version.
- `precheck_*` solver buckets are intended to be machine-consumable and deterministic for structural failures.
- `solver_unavailable`, `solver-unavailable`, and `structural+solver-unavailable` are part of the supported contract for solver-free builds.
- If multiple fail-on policies match, `solver_result` policy takes precedence over `verifier_backend`.

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
