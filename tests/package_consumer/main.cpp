#include <dwarf_parser.hpp>

int main() {
    dwarf::DwarfParser parser("");
    return parser.isValid() ? 1 : 0;
}
