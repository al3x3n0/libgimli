cmake_minimum_required(VERSION 3.16)
project(DwarfParser VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CTest)

# Find required packages
find_package(PkgConfig REQUIRED)

# Include directories
include_directories(include)
include_directories(third_party/elfio)

# Add ELFIO library (header-only)
add_subdirectory(third_party/elfio)

# Source files
set(SOURCES
    src/dwarf_parser.cpp
    src/die_parser.cpp
    src/attribute_parser.cpp
    src/expression_evaluator.cpp
    src/symbolic_expression.cpp
    src/symbolic_verifier.cpp
    src/expression_compare.cpp
    src/type_system.cpp
    src/dwarf_utils.cpp
    src/dwarf_database.cpp
    src/dwarf_extractor.cpp
    src/rnglists_parser.cpp
    src/loclists_parser.cpp
    src/debug_sup_parser.cpp
    src/debug_names_parser.cpp
    src/debug_macro_parser.cpp
    src/cfi_parser.cpp
    src/source_location.cpp
    src/variable_location.cpp
    src/split_dwarf.cpp
    src/call_stack.cpp
    src/demangler.cpp
    src/type_printer.cpp
    src/symbol_table.cpp
    src/variable_inspector.cpp
)

# Header files
set(HEADERS
    include/dwarf_parser.hpp
    include/die_parser.hpp
    include/attribute_parser.hpp
    include/expression_evaluator.hpp
    include/symbolic_expression.hpp
    include/symbolic_verifier.hpp
    include/expression_compare.hpp
    include/type_system.hpp
    include/dwarf_utils.hpp
    include/dwarf_types.hpp
    include/dwarf_database.hpp
    include/dwarf_extractor.hpp
    include/rnglists_parser.hpp
    include/loclists_parser.hpp
    include/debug_sup_parser.hpp
    include/debug_names_parser.hpp
    include/debug_macro_parser.hpp
    include/cfi_parser.hpp
    include/source_location.hpp
    include/variable_location.hpp
    include/split_dwarf.hpp
    include/call_stack.hpp
    include/demangler.hpp
    include/type_printer.hpp
    include/symbol_table.hpp
    include/variable_inspector.hpp
)

# Create the main library
add_library(dwarf_parser ${SOURCES} ${HEADERS})
target_link_libraries(dwarf_parser elfio)

# Create example executables
add_executable(dwarf_example examples/main.cpp)
target_link_libraries(dwarf_example dwarf_parser)

add_executable(dwarf_database_example examples/database_example.cpp)
target_link_libraries(dwarf_database_example dwarf_parser)

# Create test executable
add_executable(dwarf_tests tests/test_dwarf_parser.cpp)
target_link_libraries(dwarf_tests dwarf_parser)

# Create CLI regression tests for dwarf_dump
add_executable(dwarf_dump_cli_tests tests/test_dwarf_dump_cli.cpp)
target_link_libraries(dwarf_dump_cli_tests dwarf_parser)

# Create dwarf_dump tool
add_executable(dwarf_dump tools/dwarf_dump.cpp)
target_link_libraries(dwarf_dump dwarf_parser)

# Compiler flags
target_compile_options(dwarf_parser PRIVATE -Wall -Wextra -O2)
target_compile_options(dwarf_example PRIVATE -Wall -Wextra -O2)
target_compile_options(dwarf_database_example PRIVATE -Wall -Wextra -O2)
target_compile_options(dwarf_tests PRIVATE -Wall -Wextra -O2)
target_compile_options(dwarf_dump_cli_tests PRIVATE -Wall -Wextra -O2)
target_compile_options(dwarf_dump PRIVATE -Wall -Wextra -O2)

add_test(NAME dwarf_tests COMMAND dwarf_tests)
add_test(NAME dwarf_dump_cli_tests COMMAND dwarf_dump_cli_tests)

# Installation
install(TARGETS dwarf_parser dwarf_example dwarf_database_example dwarf_dump
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/ DESTINATION include)
