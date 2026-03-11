#pragma once

#include <string>
#include <vector>

namespace dwarf {

struct SupportMatrixRow {
    std::string area;
    std::string feature;
    std::string status;
    std::string notes;
};

// Canonical support rows used by CLI/runtime support reporting.
const std::vector<SupportMatrixRow>& getSupportMatrixRows();

} // namespace dwarf

