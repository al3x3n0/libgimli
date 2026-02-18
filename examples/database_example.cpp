#include "dwarf_database.hpp"
#include "dwarf_extractor.hpp"
#include "dwarf_parser.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>

void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " <elf_file> [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --functions     Show functions" << std::endl;
    std::cout << "  --variables     Show variables" << std::endl;
    std::cout << "  --types         Show types" << std::endl;
    std::cout << "  --cu            Show compilation units" << std::endl;
    std::cout << "  --search <name> Search for specific name" << std::endl;
    std::cout << "  --filter <type> Filter by type (static, inline, virtual, global, etc.)" << std::endl;
    std::cout << "  --stats         Show statistics" << std::endl;
    std::cout << "  --verbose       Enable verbose output" << std::endl;
    std::cout << "  --all           Show all information (default)" << std::endl;
    std::cout << "  --help          Show this help message" << std::endl;
}

void printFunction(const std::shared_ptr<dwarf::FunctionInfo>& func) {
    std::cout << "  " << func->getDescription() << std::endl;
    if (!func->getParameters().empty()) {
        std::cout << "    Parameters: ";
        for (size_t i = 0; i < func->getParameters().size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << func->getParameters()[i];
        }
        std::cout << std::endl;
    }
    if (!func->getReturnType().empty()) {
        std::cout << "    Return Type: " << func->getReturnType() << std::endl;
    }
    if (!func->getFrameBase().empty()) {
        std::cout << "    Frame Base: " << func->getFrameBase() << std::endl;
    }
}

void printVariable(const std::shared_ptr<dwarf::VariableInfo>& var) {
    std::cout << "  " << var->getDescription() << std::endl;
    if (!var->getType().empty()) {
        std::cout << "    Type: " << var->getType() << std::endl;
    }
    if (!var->getLocationDescription().empty()) {
        std::cout << "    Location: " << var->getLocationDescription() << std::endl;
    }
    if (!var->getScope().empty()) {
        std::cout << "    Scope: " << var->getScope() << std::endl;
    }
}

void printType(const std::shared_ptr<dwarf::TypeInfo>& type) {
    std::cout << "  " << type->getDescription() << std::endl;
    if (!type->getMembers().empty()) {
        std::cout << "    Members: ";
        for (size_t i = 0; i < type->getMembers().size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << type->getMembers()[i];
        }
        std::cout << std::endl;
    }
    if (!type->getEnumerators().empty()) {
        std::cout << "    Enumerators: ";
        for (size_t i = 0; i < type->getEnumerators().size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << type->getEnumerators()[i];
        }
        std::cout << std::endl;
    }
}

void printCompilationUnit(const std::shared_ptr<dwarf::CompilationUnitInfo>& cu) {
    std::cout << "  " << cu->getDescription() << std::endl;
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
    bool show_functions = false;
    bool show_variables = false;
    bool show_types = false;
    bool show_cu = false;
    bool show_stats = false;
    bool show_all = true;
    bool verbose = false;
    std::string search_name;
    std::string filter_type;
    
    // Parse command line arguments
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--functions") {
            show_functions = true;
            show_all = false;
        } else if (arg == "--variables") {
            show_variables = true;
            show_all = false;
        } else if (arg == "--types") {
            show_types = true;
            show_all = false;
        } else if (arg == "--cu") {
            show_cu = true;
            show_all = false;
        } else if (arg == "--stats") {
            show_stats = true;
            show_all = false;
        } else if (arg == "--search" && i + 1 < argc) {
            search_name = argv[++i];
            show_all = false;
        } else if (arg == "--filter" && i + 1 < argc) {
            filter_type = argv[++i];
            show_all = false;
        } else if (arg == "--verbose") {
            verbose = true;
        } else if (arg == "--all") {
            show_all = true;
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
    auto parser = std::make_shared<dwarf::DwarfParser>(filename);
    parser->setVerbose(verbose);
    
    std::cout << "Loading DWARF information from: " << filename << std::endl;
    
    if (!parser->load()) {
        std::cerr << "Failed to load DWARF information" << std::endl;
        return 1;
    }
    
    // Create extractor and extract data
    auto extractor = std::make_shared<dwarf::DwarfExtractor>(parser);
    extractor->setVerbose(verbose);
    
    std::cout << "Extracting debug data..." << std::endl;
    auto database = extractor->extract();
    
    std::cout << "Successfully loaded DWARF information!" << std::endl;
    std::cout << database->getSummary() << std::endl;
    
    // Handle search
    if (!search_name.empty()) {
        std::cout << "\n=== Search Results for '" << search_name << "' ===" << std::endl;
        
        auto functions = database->findFunctions(search_name);
        auto variables = database->findVariables(search_name);
        auto types = database->findTypes(search_name);
        
        if (!functions.empty()) {
            std::cout << "\nFunctions:" << std::endl;
            for (const auto& func : functions) {
                printFunction(func);
            }
        }
        
        if (!variables.empty()) {
            std::cout << "\nVariables:" << std::endl;
            for (const auto& var : variables) {
                printVariable(var);
            }
        }
        
        if (!types.empty()) {
            std::cout << "\nTypes:" << std::endl;
            for (const auto& type : types) {
                printType(type);
            }
        }
        
        if (functions.empty() && variables.empty() && types.empty()) {
            std::cout << "No results found for '" << search_name << "'" << std::endl;
        }
        
        return 0;
    }
    
    // Handle filter
    if (!filter_type.empty()) {
        std::cout << "\n=== Filtered Results for '" << filter_type << "' ===" << std::endl;
        
        if (filter_type == "static") {
            auto static_funcs = database->getStaticFunctions();
            auto static_vars = database->getStaticVariables();
            
            if (!static_funcs.empty()) {
                std::cout << "\nStatic Functions:" << std::endl;
                for (const auto& func : static_funcs) {
                    printFunction(func);
                }
            }
            
            if (!static_vars.empty()) {
                std::cout << "\nStatic Variables:" << std::endl;
                for (const auto& var : static_vars) {
                    printVariable(var);
                }
            }
        } else if (filter_type == "inline") {
            auto inline_funcs = database->getInlineFunctions();
            if (!inline_funcs.empty()) {
                std::cout << "\nInline Functions:" << std::endl;
                for (const auto& func : inline_funcs) {
                    printFunction(func);
                }
            }
        } else if (filter_type == "virtual") {
            auto virtual_funcs = database->getVirtualFunctions();
            if (!virtual_funcs.empty()) {
                std::cout << "\nVirtual Functions:" << std::endl;
                for (const auto& func : virtual_funcs) {
                    printFunction(func);
                }
            }
        } else if (filter_type == "global") {
            auto global_vars = database->getGlobalVariables();
            if (!global_vars.empty()) {
                std::cout << "\nGlobal Variables:" << std::endl;
                for (const auto& var : global_vars) {
                    printVariable(var);
                }
            }
        } else if (filter_type == "primitive") {
            auto primitive_types = database->getPrimitiveTypes();
            if (!primitive_types.empty()) {
                std::cout << "\nPrimitive Types:" << std::endl;
                for (const auto& type : primitive_types) {
                    printType(type);
                }
            }
        } else if (filter_type == "composite") {
            auto composite_types = database->getCompositeTypes();
            if (!composite_types.empty()) {
                std::cout << "\nComposite Types:" << std::endl;
                for (const auto& type : composite_types) {
                    printType(type);
                }
            }
        } else {
            std::cerr << "Unknown filter type: " << filter_type << std::endl;
            std::cerr << "Available filters: static, inline, virtual, global, primitive, composite" << std::endl;
            return 1;
        }
        
        return 0;
    }
    
    // Show statistics
    if (show_stats) {
        database->printStatistics();
        return 0;
    }
    
    // Show all or specific sections
    if (show_all || show_functions) {
        std::cout << "\n=== Functions ===" << std::endl;
        const auto& functions = database->getFunctions();
        for (const auto& func : functions) {
            printFunction(func);
        }
    }
    
    if (show_all || show_variables) {
        std::cout << "\n=== Variables ===" << std::endl;
        const auto& variables = database->getVariables();
        for (const auto& var : variables) {
            printVariable(var);
        }
    }
    
    if (show_all || show_types) {
        std::cout << "\n=== Types ===" << std::endl;
        const auto& types = database->getTypes();
        for (const auto& type : types) {
            printType(type);
        }
    }
    
    if (show_all || show_cu) {
        std::cout << "\n=== Compilation Units ===" << std::endl;
        const auto& compilation_units = database->getCompilationUnits();
        for (const auto& cu : compilation_units) {
            printCompilationUnit(cu);
        }
    }
    
    return 0;
}
