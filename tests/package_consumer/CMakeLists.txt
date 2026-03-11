cmake_minimum_required(VERSION 3.16)
project(DwarfPackageConsumer LANGUAGES CXX)

find_package(DwarfParser CONFIG REQUIRED)

add_executable(dwarf_package_consumer main.cpp)
target_link_libraries(dwarf_package_consumer PRIVATE Dwarf::dwarf_parser)
