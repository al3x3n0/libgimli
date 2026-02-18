#include "demangler.hpp"

#include <cstdlib>
#include <cstring>
#include <memory>

// Use __cxa_demangle on platforms that support it (GCC, Clang)
#if defined(__GNUC__) || defined(__clang__)
#include <cxxabi.h>
#define HAS_CXA_DEMANGLE 1
#endif

namespace dwarf {

std::string Demangler::demangle(const std::string& mangled_name) {
    auto result = tryDemangle(mangled_name);
    return result.value_or(mangled_name);
}

std::optional<std::string> Demangler::tryDemangle(const std::string& mangled_name) {
    if (mangled_name.empty()) {
        return std::nullopt;
    }

#ifdef HAS_CXA_DEMANGLE
    int status = 0;
    // __cxa_demangle allocates memory that we need to free
    char* demangled = abi::__cxa_demangle(mangled_name.c_str(), nullptr, nullptr, &status);

    if (status == 0 && demangled != nullptr) {
        std::string result(demangled);
        std::free(demangled);
        return result;
    }

    // status meanings:
    // -1: memory allocation failure
    // -2: mangled_name is not a valid mangled name
    // -3: invalid arguments
    if (demangled) {
        std::free(demangled);
    }
    return std::nullopt;
#else
    // Fallback: no demangling available
    // Just check if it looks mangled and return nullopt
    if (isMangled(mangled_name)) {
        return std::nullopt;
    }
    return mangled_name;
#endif
}

bool Demangler::isMangled(const std::string& name) {
    if (name.empty()) {
        return false;
    }

    // Itanium C++ ABI mangled names start with "_Z"
    if (name.length() >= 2 && name[0] == '_' && name[1] == 'Z') {
        return true;
    }

    // Some systems use "__Z" prefix
    if (name.length() >= 3 && name[0] == '_' && name[1] == '_' && name[2] == 'Z') {
        return true;
    }

    // MSVC mangled names start with "?" (but we may not handle these)
    if (name[0] == '?') {
        return true;
    }

    // Block-invoked symbols (Objective-C / Swift blocks)
    if (name.find("___block_invoke") != std::string::npos) {
        return true;
    }

    return false;
}

std::string Demangler::extractBaseName(const std::string& demangled_name) {
    if (demangled_name.empty()) {
        return demangled_name;
    }

    // Find the opening parenthesis (start of parameters)
    size_t paren_pos = demangled_name.find('(');
    std::string name_part = (paren_pos != std::string::npos)
        ? demangled_name.substr(0, paren_pos)
        : demangled_name;

    // Handle template parameters - find matching angle brackets
    // "std::vector<int>::push_back" -> we want "push_back"
    size_t last_colon = std::string::npos;
    int angle_depth = 0;

    for (size_t i = name_part.length(); i > 0; --i) {
        char c = name_part[i - 1];
        if (c == '>') {
            angle_depth++;
        } else if (c == '<') {
            angle_depth--;
        } else if (c == ':' && angle_depth == 0) {
            if (i >= 2 && name_part[i - 2] == ':') {
                last_colon = i;
                break;
            }
        }
    }

    if (last_colon != std::string::npos) {
        return name_part.substr(last_colon);
    }

    // Check for return type prefix (e.g., "void foo")
    // Find the last space that's not in templates
    size_t last_space = std::string::npos;
    angle_depth = 0;
    for (size_t i = 0; i < name_part.length(); ++i) {
        char c = name_part[i];
        if (c == '<') {
            angle_depth++;
        } else if (c == '>') {
            angle_depth--;
        } else if (c == ' ' && angle_depth == 0) {
            last_space = i;
        }
    }

    if (last_space != std::string::npos) {
        return name_part.substr(last_space + 1);
    }

    return name_part;
}

std::string Demangler::extractQualifiedName(const std::string& demangled_name) {
    if (demangled_name.empty()) {
        return demangled_name;
    }

    // Find the opening parenthesis (start of parameters)
    size_t paren_pos = demangled_name.find('(');
    std::string name_part = (paren_pos != std::string::npos)
        ? demangled_name.substr(0, paren_pos)
        : demangled_name;

    // Remove leading return type if present
    // Look for a space that's not inside angle brackets
    int angle_depth = 0;
    size_t name_start = 0;

    for (size_t i = 0; i < name_part.length(); ++i) {
        char c = name_part[i];
        if (c == '<') {
            angle_depth++;
        } else if (c == '>') {
            angle_depth--;
        } else if (c == ' ' && angle_depth == 0) {
            // Check if what follows looks like a name (not a modifier)
            if (i + 1 < name_part.length()) {
                char next = name_part[i + 1];
                if (next != '*' && next != '&' && next != '[') {
                    // This might be the end of return type
                    name_start = i + 1;
                }
            }
        }
    }

    return name_part.substr(name_start);
}

std::string Demangler::extractParameters(const std::string& demangled_name) {
    if (demangled_name.empty()) {
        return "";
    }

    // Find the opening parenthesis
    size_t open_paren = demangled_name.find('(');
    if (open_paren == std::string::npos) {
        return "";
    }

    // Find matching closing parenthesis
    int paren_depth = 0;
    size_t close_paren = std::string::npos;

    for (size_t i = open_paren; i < demangled_name.length(); ++i) {
        if (demangled_name[i] == '(') {
            paren_depth++;
        } else if (demangled_name[i] == ')') {
            paren_depth--;
            if (paren_depth == 0) {
                close_paren = i;
                break;
            }
        }
    }

    if (close_paren != std::string::npos && close_paren > open_paren + 1) {
        return demangled_name.substr(open_paren + 1, close_paren - open_paren - 1);
    }

    return "";
}

std::string Demangler::extractReturnType(const std::string& demangled_name) {
    if (demangled_name.empty()) {
        return "";
    }

    // Find the opening parenthesis (start of parameters)
    size_t paren_pos = demangled_name.find('(');
    if (paren_pos == std::string::npos || paren_pos == 0) {
        return "";
    }

    std::string name_part = demangled_name.substr(0, paren_pos);

    // Look for the last space that's not inside angle brackets
    // Everything before that space is the return type
    int angle_depth = 0;
    size_t last_space = std::string::npos;

    for (size_t i = 0; i < name_part.length(); ++i) {
        char c = name_part[i];
        if (c == '<') {
            angle_depth++;
        } else if (c == '>') {
            angle_depth--;
        } else if (c == ' ' && angle_depth == 0) {
            last_space = i;
        }
    }

    if (last_space != std::string::npos && last_space > 0) {
        std::string potential_return = name_part.substr(0, last_space);

        // Verify it's not a namespace/class prefix by checking for ::
        if (potential_return.find("::") == std::string::npos) {
            return potential_return;
        }
    }

    return "";
}

} // namespace dwarf
