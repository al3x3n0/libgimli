cmake_minimum_required(VERSION 3.16)
project(DwarfParser VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CTest)
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

option(DWARF_ENABLE_Z3 "Enable Z3-backed symbolic verification support" ON)

set(DWARF_HAVE_Z3 OFF)
if(DWARF_ENABLE_Z3)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(Z3 REQUIRED IMPORTED_TARGET z3)
    set(DWARF_HAVE_Z3 ON)
endif()

# Add ELFIO library (header-only)
add_subdirectory(third_party/ELFIO)

# Source files
set(SOURCES
    src/dwarf_parser.cpp
    src/die_parser.cpp
    src/attribute_parser.cpp
    src/expression_evaluator.cpp
    src/symbolic_expression.cpp
    src/symbolic_verifier.cpp
    src/smt_verifier.cpp
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
    src/legacy_dwarf_parser.cpp
    src/cfi_parser.cpp
    src/cfi_symbolic.cpp
    src/dwarf_compare.cpp
    src/source_location.cpp
    src/variable_location.cpp
    src/split_dwarf.cpp
    src/call_stack.cpp
    src/cfg_reconstruction.cpp
    src/demangler.cpp
    src/type_printer.cpp
    src/symbol_table.cpp
    src/bolt_remap.cpp
    src/variable_inspector.cpp
    src/dwarf_support_matrix.cpp
)

# Header files
set(HEADERS
    include/dwarf_parser.hpp
    include/die_parser.hpp
    include/attribute_parser.hpp
    include/expression_evaluator.hpp
    include/symbolic_expression.hpp
    include/symbolic_verifier.hpp
    include/smt_verifier.hpp
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
    include/legacy_dwarf_parser.hpp
    include/cfi_parser.hpp
    include/cfi_symbolic.hpp
    include/dwarf_compare.hpp
    include/source_location.hpp
    include/variable_location.hpp
    include/split_dwarf.hpp
    include/call_stack.hpp
    include/cfg_reconstruction.hpp
    include/demangler.hpp
    include/type_printer.hpp
    include/symbol_table.hpp
    include/bolt_remap.hpp
    include/variable_inspector.hpp
    include/dwarf_support_matrix.hpp
)

# Create the main library
add_library(dwarf_parser ${SOURCES} ${HEADERS})
add_library(Dwarf::dwarf_parser ALIAS dwarf_parser)
target_include_directories(dwarf_parser
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party/ELFIO>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_features(dwarf_parser PUBLIC cxx_std_17)
target_link_libraries(dwarf_parser PUBLIC elfio)
if(DWARF_HAVE_Z3)
    target_link_libraries(dwarf_parser PUBLIC PkgConfig::Z3)
endif()
target_compile_definitions(dwarf_parser PUBLIC DWARF_HAS_Z3=$<BOOL:${DWARF_HAVE_Z3}>)
set_target_properties(dwarf_parser PROPERTIES
    EXPORT_NAME dwarf_parser
)

# Create example executables
add_executable(dwarf_example examples/main.cpp)
target_link_libraries(dwarf_example dwarf_parser)

add_executable(dwarf_database_example examples/database_example.cpp)
target_link_libraries(dwarf_database_example dwarf_parser)

add_executable(dwarf_semantic_compare_example examples/semantic_compare_example.cpp)
target_link_libraries(dwarf_semantic_compare_example dwarf_parser)

# Create test executable
add_executable(dwarf_tests tests/test_dwarf_parser.cpp)
target_link_libraries(dwarf_tests dwarf_parser)

# Create CLI regression tests for dwarf_dump
add_executable(dwarf_dump_cli_tests tests/test_dwarf_dump_cli.cpp)
target_link_libraries(dwarf_dump_cli_tests dwarf_parser)

# Create dwarf_dump tool
add_executable(dwarf_dump tools/dwarf_dump.cpp)
target_link_libraries(dwarf_dump dwarf_parser)

# Create BOLT mapping detector tool
add_executable(bolt_map_detect tools/bolt_map_detect.cpp)
target_link_libraries(bolt_map_detect dwarf_parser)

# Create CLI regression tests for bolt_map_detect
add_executable(bolt_map_detect_cli_tests tests/test_bolt_map_detect_cli.cpp)
target_link_libraries(bolt_map_detect_cli_tests elfio)

# Compiler flags
target_compile_options(dwarf_parser PRIVATE -Wall -Wextra -O2)
target_compile_options(dwarf_example PRIVATE -Wall -Wextra -O2)
target_compile_options(dwarf_database_example PRIVATE -Wall -Wextra -O2)
target_compile_options(dwarf_semantic_compare_example PRIVATE -Wall -Wextra -O2)
target_compile_options(dwarf_tests PRIVATE -Wall -Wextra -O2)
target_compile_options(dwarf_dump_cli_tests PRIVATE -Wall -Wextra -O2)
target_compile_options(dwarf_dump PRIVATE -Wall -Wextra -O2)
target_compile_options(bolt_map_detect PRIVATE -Wall -Wextra -O2)
target_compile_options(bolt_map_detect_cli_tests PRIVATE -Wall -Wextra -O2)

add_test(NAME dwarf_tests COMMAND dwarf_tests)
add_test(NAME dwarf_dump_cli_tests COMMAND dwarf_dump_cli_tests)
add_test(NAME bolt_map_detect_cli_tests COMMAND bolt_map_detect_cli_tests)
add_test(
    NAME dwarf_package_consumer_smoke
    COMMAND ${CMAKE_COMMAND} -P "${CMAKE_CURRENT_BINARY_DIR}/RunPackageConsumerTest.cmake"
)

set(DWARF_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/DwarfParser" CACHE STRING
    "CMake package config install directory")

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/DwarfParserConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/DwarfParserConfig.cmake"
    INSTALL_DESTINATION "${DWARF_INSTALL_CMAKEDIR}"
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/DwarfParserConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion
)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/RunPackageConsumerTest.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/RunPackageConsumerTest.cmake"
    @ONLY
)

# Installation
install(TARGETS dwarf_parser elfio dwarf_example dwarf_database_example dwarf_semantic_compare_example dwarf_dump bolt_map_detect
    EXPORT DwarfParserTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY third_party/ELFIO/elfio/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/elfio)

install(EXPORT DwarfParserTargets
    FILE DwarfParserTargets.cmake
    NAMESPACE Dwarf::
    DESTINATION "${DWARF_INSTALL_CMAKEDIR}"
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/DwarfParserConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/DwarfParserConfigVersion.cmake"
    DESTINATION "${DWARF_INSTALL_CMAKEDIR}"
)
