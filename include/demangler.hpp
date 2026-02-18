#pragma once

#include <string>
#include <optional>

namespace dwarf {

/**
 * C++ name demangler
 *
 * Demangles C++ symbol names using the Itanium C++ ABI demangling
 * function (__cxa_demangle) or platform equivalents.
 */
class Demangler {
public:
    /**
     * Demangle a C++ mangled name
     * @param mangled_name The mangled symbol name (e.g., "_Z3fooi")
     * @return The demangled name if successful, or the original name if not mangled
     */
    static std::string demangle(const std::string& mangled_name);

    /**
     * Try to demangle a C++ mangled name
     * @param mangled_name The mangled symbol name
     * @return The demangled name if successful, std::nullopt otherwise
     */
    static std::optional<std::string> tryDemangle(const std::string& mangled_name);

    /**
     * Check if a name appears to be mangled
     * @param name The symbol name to check
     * @return true if the name looks like a mangled C++ name
     */
    static bool isMangled(const std::string& name);

    /**
     * Extract just the function/method name without namespace/class qualifiers
     * @param demangled_name A demangled name like "namespace::Class::method(int)"
     * @return Just the method name like "method"
     */
    static std::string extractBaseName(const std::string& demangled_name);

    /**
     * Extract the full qualified name without parameters
     * @param demangled_name A demangled name like "namespace::Class::method(int)"
     * @return The qualified name like "namespace::Class::method"
     */
    static std::string extractQualifiedName(const std::string& demangled_name);

    /**
     * Extract parameter types from a demangled function name
     * @param demangled_name A demangled name like "void foo(int, char*)"
     * @return Parameter string like "int, char*"
     */
    static std::string extractParameters(const std::string& demangled_name);

    /**
     * Extract return type from a demangled function name
     * @param demangled_name A demangled name like "void foo(int)"
     * @return Return type like "void", or empty if not present
     */
    static std::string extractReturnType(const std::string& demangled_name);
};

} // namespace dwarf
