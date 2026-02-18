#include "dwarf_parser.hpp"
#include "dwarf_utils.hpp"
#include "type_system.hpp"
#include "expression_evaluator.hpp"
#include "demangler.hpp"
#include "type_printer.hpp"
#include "symbol_table.hpp"
#include "variable_inspector.hpp"
#include <iostream>
#include <iomanip>

using namespace dwarf;

void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " <elf_file> [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --info          Print general DWARF information" << std::endl;
    std::cout << "  --types         Print all types" << std::endl;
    std::cout << "  --functions     Print all functions" << std::endl;
    std::cout << "  --variables     Print all variables" << std::endl;
    std::cout << "  --cu            Print compilation units" << std::endl;
    std::cout << "  --all           Print all information (default)" << std::endl;
    std::cout << "  --verbose       Enable verbose debug output" << std::endl;
    std::cout << "  --help          Show this help message" << std::endl;
}

void printDIEInfo(std::shared_ptr<dwarf::DIE> die, int indent = 0) {
    if (!die) return;
    
    std::string indent_str(indent * 2, ' ');
    std::cout << indent_str << "DIE: " << die->getTagName();
    if (!die->getName().empty()) {
        std::cout << " \"" << die->getName() << "\"";
    }
    std::cout << " (offset: 0x" << std::hex << die->getOffset() << std::dec << ")";
    
    if (die->isType()) {
        std::cout << " [TYPE]";
    }
    
    std::cout << std::endl;
    
    // Print attributes
    for (const auto& attr : die->getAttributes()) {
        std::cout << indent_str << "  " << "attr" 
                  << " = " << attr.second->toString() << std::endl;
    }
    
    // Print children
    for (const auto& child : die->getChildren()) {
        printDIEInfo(child, indent + 1);
    }
}

void demonstrateSymbolTable(const ELFIO::elfio& elf, DwarfParser& parser) {
    std::cout << "\n=== Symbol Table Demo ===" << std::endl;

    SymbolTableConfig config;
    config.demangle_names = true;
    config.link_dwarf = true;

    SymbolTable symtab(elf, config);
    if (!symtab.load()) {
        std::cout << "No symbols found in ELF file.\n";
        return;
    }

    // Link with DWARF
    symtab.linkWithDwarf(parser);

    // Print statistics
    auto stats = symtab.getStats();
    std::cout << "Symbol Statistics:\n";
    std::cout << "  Total symbols: " << stats.total_symbols << "\n";
    std::cout << "  Functions:     " << stats.functions << "\n";
    std::cout << "  Objects:       " << stats.objects << "\n";
    std::cout << "  Global:        " << stats.global_symbols << "\n";
    std::cout << "  With DWARF:    " << stats.dwarf_linked << "\n";

    // Show some functions
    auto functions = symtab.getFunctions();
    if (!functions.empty()) {
        std::cout << "\nFunctions (first 5):\n";
        int count = 0;
        for (const auto& func : functions) {
            if (count >= 5) break;
            if (!func->is_defined) continue;

            std::cout << "  0x" << std::hex << func->address << std::dec
                      << " (" << func->size << " bytes) "
                      << func->demangled_name;
            if (func->has_dwarf_info) {
                std::cout << " [DWARF]";
            }
            std::cout << "\n";
            count++;
        }
    }

    // Demonstrate address lookup
    if (!functions.empty()) {
        auto func = functions.front();
        if (func->is_defined && func->address != 0) {
            uint64_t test_addr = func->address + 10;
            std::cout << "\nAddress lookup for 0x" << std::hex << test_addr << std::dec << ":\n";

            auto match = symtab.findByAddress(test_addr);
            if (match) {
                std::cout << "  Found: " << match->symbol->demangled_name
                          << " + 0x" << std::hex << match->offset << std::dec << "\n";
            }

            // Try full address resolution
            AddressResolver resolver(symtab, parser);
            auto resolved = resolver.resolve(test_addr);
            std::cout << "  Full resolution: " << resolved.toShortString() << "\n";
        }
    }
}

void demonstrateDemangler() {
    std::cout << "\n=== Name Demangler Demo ===" << std::endl;

    std::vector<std::string> mangled_names = {
        "_ZN3foo3barEi",                          // foo::bar(int)
        "_Z7factoryi",                             // factorial(int)
        "_ZNSt6vectorIiSaIiEE9push_backEOi",       // std::vector<int>::push_back(int&&)
        "_ZN5MyClass10myFunctionEPcRKi",          // MyClass::myFunction(char*, int const&)
        "main",                                    // Not mangled
        "_ZSt4cout"                                // std::cout
    };

    std::cout << "Demangling examples:\n";
    for (const auto& name : mangled_names) {
        std::string demangled = Demangler::demangle(name);
        std::cout << "  " << std::setw(40) << std::left << name
                  << " -> " << demangled << std::endl;

        if (Demangler::isMangled(name) && name != demangled) {
            std::cout << "    Base name: " << Demangler::extractBaseName(demangled) << std::endl;
        }
    }
}

void demonstrateTypePrinter(DwarfParser& parser) {
    std::cout << "\n=== Type Printer Demo ===" << std::endl;

    auto types = parser.getTypes();
    if (types.empty()) {
        std::cout << "No types found in DWARF info.\n";
        return;
    }

    // Create DIE lookup function
    auto die_lookup = [&parser](uint64_t offset) -> std::shared_ptr<dwarf::DIE> {
        return parser.findDIEByOffset(offset);
    };

    TypePrinterConfig config;
    config.show_byte_sizes = true;
    TypePrinter printer(die_lookup, config);

    std::cout << "Formatted types from DWARF:\n";
    int count = 0;
    for (const auto& type_die : types) {
        if (count >= 8) {  // Show first 8 types
            std::cout << "  ... and " << (types.size() - count) << " more types\n";
            break;
        }

        std::string formatted = printer.formatType(type_die);
        std::cout << "  " << formatted;

        uint64_t size = printer.getTypeSize(type_die);
        if (size > 0 && config.show_byte_sizes) {
            std::cout << " (" << size << " bytes)";
        }
        std::cout << std::endl;
        count++;
    }

    // Show a few formatted variables
    auto variables = parser.getVariables();
    if (!variables.empty()) {
        std::cout << "\nFormatted variable declarations:\n";
        count = 0;
        for (const auto& var : variables) {
            if (count >= 5) break;
            std::string decl = printer.formatVariable(var);
            std::cout << "  " << decl << ";\n";
            count++;
        }
    }

    // Show formatted function declarations
    auto functions = parser.getFunctions();
    if (!functions.empty()) {
        std::cout << "\nFormatted function declarations:\n";
        count = 0;
        for (const auto& func : functions) {
            if (count >= 3) break;
            std::string decl = printer.formatFunction(func);
            std::cout << "  " << decl << ";\n";
            count++;
        }
    }
}

void demonstrateExpressionEvaluator() {
    std::cout << "\n=== Expression Evaluator Demo ===" << std::endl;
    
    ExpressionEvaluator evaluator;
    
    // Test simple expression: push constant 42
    std::vector<uint8_t> expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        42, 0, 0, 0  // 42 in little-endian
    };
    
    std::cout << "Expression: " << evaluator.expressionToString(expression) << std::endl;
    auto result = evaluator.evaluate(expression);
    std::cout << "Result: " << result.description << std::endl;
    
    // Test addition: 10 + 32
    expression = {
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        10, 0, 0, 0,
        static_cast<uint8_t>(DwarfOp::DW_OP_const4u),
        32, 0, 0, 0,
        static_cast<uint8_t>(DwarfOp::DW_OP_plus)
    };
    
    std::cout << "Expression: " << evaluator.expressionToString(expression) << std::endl;
    result = evaluator.evaluate(expression);
    std::cout << "Result: " << result.description << std::endl;
}

void demonstrateTypeSystem() {
    std::cout << "\n=== Type System Demo ===" << std::endl;
    
    TypeSystem type_system;
    
    // Create some primitive types
    auto int_type = type_system.createPrimitiveType(PrimitiveType::Kind::INTEGER, 4, "int");
    auto float_type = type_system.createPrimitiveType(PrimitiveType::Kind::FLOAT, 4, "float");
    auto bool_type = type_system.createPrimitiveType(PrimitiveType::Kind::BOOLEAN, 1, "bool");
    
    std::cout << "Created types:" << std::endl;
    std::cout << "  " << int_type->getDescription() << std::endl;
    std::cout << "  " << float_type->getDescription() << std::endl;
    std::cout << "  " << bool_type->getDescription() << std::endl;
    
    // Create pointer type
    auto int_ptr_type = type_system.createPointerType(int_type);
    std::cout << "  " << int_ptr_type->getDescription() << std::endl;
    
    // Create array type
    std::vector<uint64_t> dimensions = {10, 20};
    auto int_array_type = type_system.createArrayType(int_type, dimensions);
    std::cout << "  " << int_array_type->getDescription() << std::endl;
    
    // Create function type
    std::vector<std::shared_ptr<Type>> param_types = {int_type, float_type};
    auto func_type = type_system.createFunctionType(int_type, param_types, false);
    std::cout << "  " << func_type->getDescription() << std::endl;
    
    // Create composite type
    auto struct_type = std::dynamic_pointer_cast<CompositeType>(
        type_system.createCompositeType(CompositeType::Kind::STRUCT, "Point", 8));
    struct_type->addMember("x", int_type, 0);
    struct_type->addMember("y", int_type, 4);
    std::cout << "  " << struct_type->getDescription() << std::endl;
    
    // Create enum type
    auto enum_type = std::dynamic_pointer_cast<EnumType>(
        type_system.createEnumType("Color", int_type));
    enum_type->addEnumerator("RED", 0);
    enum_type->addEnumerator("GREEN", 1);
    enum_type->addEnumerator("BLUE", 2);
    std::cout << "  " << enum_type->getDescription() << std::endl;
}

void demonstrateVariableInspector(DwarfParser& parser) {
    std::cout << "\n=== Variable Inspector Demo ===" << std::endl;

    // Create stub memory and register readers for demonstration
    StubMemoryReader memory;
    StubRegisterReader registers;

    // Set up some fake register values
    registers.setPC(0x1000);
    registers.setSP(0x7fff0000);
    registers.setFP(0x7fff0100);
    for (uint32_t i = 0; i < 16; i++) {
        registers.setRegister(i, 0x100 + i * 8);
    }

    // Set up some fake memory regions
    memory.addValue(0x7fff0100, 42, 4);       // An int value
    memory.addValue(0x7fff0108, 0x400000, 8); // A pointer
    memory.addString(0x400000, "Hello, World!");

    // Create inspector with configuration
    InspectorConfig config;
    config.resolve_pointers = true;
    config.max_pointer_depth = 2;
    config.max_array_elements = 8;
    config.include_artificial = false;

    VariableInspector inspector(parser, memory, registers, config);

    // Get functions and try to find variables in first function
    auto functions = parser.getFunctions();
    if (!functions.empty()) {
        std::cout << "\nSearching for variables in functions...\n";

        for (size_t i = 0; i < std::min(functions.size(), size_t(3)); i++) {
            auto func = functions[i];
            std::string func_name = func->getName();

            // Get low_pc for the function
            auto low_pc_attr = func->getAttribute(DwarfAttribute::DW_AT_low_pc);
            if (!low_pc_attr) continue;

            uint64_t low_pc = 0;
            auto addr = std::dynamic_pointer_cast<AddressAttributeValue>(low_pc_attr);
            auto uint_val = std::dynamic_pointer_cast<UnsignedAttributeValue>(low_pc_attr);
            if (addr) low_pc = addr->getAddress();
            else if (uint_val) low_pc = uint_val->getValue();

            if (low_pc == 0) continue;

            std::cout << "\nFunction: " << func_name << " (PC: 0x" << std::hex << low_pc << std::dec << ")\n";

            // Get parameters
            auto params = inspector.getParameters(low_pc);
            if (!params.empty()) {
                std::cout << "  Parameters:\n";
                for (const auto& param : params) {
                    std::cout << "    " << param.type_string << " " << param.name;
                    std::cout << " @ " << VariableLocationEvaluator::formatLocation(param.location);
                    std::cout << "\n";
                }
            }

            // Get locals
            auto locals = inspector.getLocals(low_pc);
            if (!locals.empty()) {
                std::cout << "  Local variables:\n";
                for (const auto& local : locals) {
                    if (local.is_parameter) continue; // Already showed parameters
                    std::cout << "    " << local.type_string << " " << local.name;
                    std::cout << " @ " << VariableLocationEvaluator::formatLocation(local.location);
                    std::cout << "\n";
                }
            }
        }
    } else {
        std::cout << "No functions found in DWARF info.\n";
    }

    // Show global variables
    auto globals = inspector.getGlobals(0);
    if (!globals.empty()) {
        std::cout << "\nGlobal variables (first 5):\n";
        for (size_t i = 0; i < std::min(globals.size(), size_t(5)); i++) {
            const auto& var = globals[i];
            std::cout << "  " << var.type_string << " " << var.name;
            std::cout << " @ " << VariableLocationEvaluator::formatLocation(var.location);
            std::cout << "\n";
        }
    }

    std::cout << "\nVariable Inspector demo complete.\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    
    // Check for help option first
    if (std::string(argv[1]) == "--help") {
        printUsage(argv[0]);
        return 0;
    }
    
    std::string filename = argv[1];
    bool show_info = false;
    bool show_types = false;
    bool show_functions = false;
    bool show_variables = false;
    bool show_cu = false;
    bool show_all = true;
    bool verbose = false;
    
    // Parse command line arguments
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--info") {
            show_info = true;
            show_all = false;
        } else if (arg == "--types") {
            show_types = true;
            show_all = false;
        } else if (arg == "--functions") {
            show_functions = true;
            show_all = false;
        } else if (arg == "--variables") {
            show_variables = true;
            show_all = false;
        } else if (arg == "--cu") {
            show_cu = true;
            show_all = false;
        } else if (arg == "--all") {
            show_all = true;
        } else if (arg == "--verbose") {
            verbose = true;
        } else if (arg == "--help") {
            printUsage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }
    
    // Create and load DWARF parser
    DwarfParser parser(filename);
    parser.setVerbose(verbose);
    
    std::cout << "Loading DWARF information from: " << filename << std::endl;
    
    if (!parser.load()) {
        std::cerr << "Failed to load DWARF information: " << dwarf::DwarfUtils::getLastError() << std::endl;
        return 1;
    }
    
    if (!parser.isValid()) {
        std::cerr << "Invalid DWARF information" << std::endl;
        return 1;
    }
    
    std::cout << "Successfully loaded DWARF information!" << std::endl;
    
    // Show requested information
    if (show_all || show_info) {
        parser.printDebugInfo();
    }
    
    if (show_all || show_cu) {
        parser.printCompilationUnits();
    }
    
    if (show_all || show_types) {
        parser.printTypes();
    }
    
    if (show_all || show_functions) {
        parser.printFunctions();
    }
    
    if (show_all || show_variables) {
        parser.printVariables();
    }
    
    // Demonstrate additional features
    if (show_all) {
        demonstrateSymbolTable(parser.getELF(), parser);
        demonstrateDemangler();
        demonstrateTypePrinter(parser);
        demonstrateExpressionEvaluator();
        demonstrateTypeSystem();
        demonstrateVariableInspector(parser);
    }
    
    // Show some statistics
    auto functions = parser.getFunctions();
    auto variables = parser.getVariables();
    auto types = parser.getTypes();
    
    std::cout << "\n=== Statistics ===" << std::endl;
    std::cout << "Functions found: " << functions.size() << std::endl;
    std::cout << "Variables found: " << variables.size() << std::endl;
    std::cout << "Types found: " << types.size() << std::endl;
    
    // Show some example function details
    if (!functions.empty()) {
        std::cout << "\n=== Example Function Details ===" << std::endl;
        for (size_t i = 0; i < std::min(functions.size(), size_t(3)); ++i) {
            auto func = functions[i];
            std::cout << "Function " << i + 1 << ": " << func->getName() << std::endl;
            
            // Show function attributes
            auto low_pc = func->getAttribute(DwarfAttribute::DW_AT_low_pc);
            auto high_pc = func->getAttribute(DwarfAttribute::DW_AT_high_pc);
            auto frame_base = func->getAttribute(DwarfAttribute::DW_AT_frame_base);
            
            if (low_pc) {
                std::cout << "  Low PC: " << low_pc->toString() << std::endl;
            }
            if (high_pc) {
                std::cout << "  High PC: " << high_pc->toString() << std::endl;
            }
            if (frame_base) {
                std::cout << "  Frame Base: " << frame_base->toString() << std::endl;
            }
            
            // Show parameters
            std::cout << "  Parameters:" << std::endl;
            for (const auto& child : func->getChildren()) {
                if (child->getTag() == DwarfTag::DW_TAG_formal_parameter) {
                    std::cout << "    " << child->getName() << std::endl;
                }
            }
            std::cout << std::endl;
        }
    }
    
    return 0;
}
