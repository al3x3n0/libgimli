#include <cassert>
#include "dwarf_types.hpp"
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <sys/wait.h>
#include <vector>
#include <filesystem>
#include <elfio/elfio.hpp>

namespace fs = std::filesystem;

namespace {

#if DWARF_HAS_Z3
const char* kExprSolverBackend = "z3";
const char* kExprPrimarySolverResult = "unsat";
const char* kCFIStructuralBackend = "structural+z3";
#else
const char* kExprSolverBackend = "solver-unavailable";
const char* kExprPrimarySolverResult = "solver_unavailable";
const char* kCFIStructuralBackend = "structural+solver-unavailable";
#endif

std::string firstExisting(const std::vector<std::string>& candidates) {
    for (const auto& p : candidates) {
        if (fs::exists(p)) return p;
    }
    return {};
}

int exitCodeFromSystem(int rc) {
    if (rc == -1) return -1;
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

std::string readFile(const std::string& path) {
    std::ifstream ifs(path);
    return std::string((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());
}

std::vector<uint8_t> readBinaryFile(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(ifs)),
                                std::istreambuf_iterator<char>());
}

void appendU16LE(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
}

void appendU32LE(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
}

void appendU64LE(std::vector<uint8_t>& out, uint64_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 32) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 40) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 48) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 56) & 0xff));
}

void appendULEB128(std::vector<uint8_t>& out, uint64_t v) {
    do {
        uint8_t byte = static_cast<uint8_t>(v & 0x7f);
        v >>= 7;
        if (v != 0) byte |= 0x80;
        out.push_back(byte);
    } while (v != 0);
}

void writeELFWithSections(const std::string& path,
                          const std::vector<std::pair<std::string, std::vector<uint8_t>>>& sections) {
    ELFIO::elfio writer;
    writer.create(ELFIO::ELFCLASS64, ELFIO::ELFDATA2LSB);
    writer.set_type(ELFIO::ET_REL);
    writer.set_machine(ELFIO::EM_X86_64);

    for (const auto& [name, data] : sections) {
        auto* sec = writer.sections.add(name);
        sec->set_type(ELFIO::SHT_PROGBITS);
        sec->set_flags(0);
        sec->set_addr_align(1);
        if (!data.empty()) {
            sec->set_data(reinterpret_cast<const char*>(data.data()), data.size());
        } else {
            static const char dummy = 0;
            sec->set_data(&dummy, 0);
        }
    }

    assert(writer.save(path));
}

int runAndCapture(const std::string& cmd, const std::string& out_path, std::string& out_text) {
    std::string full = cmd + " > " + out_path + " 2>&1";
    int rc = std::system(full.c_str());
    out_text = readFile(out_path);
    return exitCodeFromSystem(rc);
}

std::string findDWPTool() {
    // Optional real-package coverage auto-activates when one of these tools exists.
    const std::vector<std::string> commands = {
        "command -v dwp >/dev/null 2>&1 && printf dwp",
        "command -v llvm-dwp >/dev/null 2>&1 && printf llvm-dwp",
    };

    for (const auto& probe : commands) {
        fs::path tmp = fs::path("/tmp") / ("dwp_cli_probe_" + std::to_string(std::rand()) + ".txt");
        std::string cmd = "/bin/zsh -lc '" + probe + "' > \"" + tmp.string() + "\" 2>/dev/null";
        int rc = std::system(cmd.c_str());
        if (rc != 0) {
            std::error_code ec;
            fs::remove(tmp, ec);
            continue;
        }
        std::ifstream ifs(tmp);
        std::string tool;
        std::getline(ifs, tool);
        std::error_code ec;
        fs::remove(tmp, ec);
        if (!tool.empty()) {
            return tool;
        }
    }

    return {};
}

bool tryBuildRealSplitDwarfFixture(const std::string& dir,
                                   std::string& out_obj_path,
                                   std::string& out_dwo_path) {
    const fs::path source_path = fs::path(dir) / "real_cli_split_fixture.c";
    out_obj_path = (fs::path(dir) / "real_cli_split_fixture.o").string();
    out_dwo_path = (fs::path(dir) / "real_cli_split_fixture.dwo").string();

    {
        std::ofstream src(source_path);
        src
            << "typedef const int split_answer_t;\n"
            << "static int split_global = 7;\n"
            << "split_answer_t split_answer(int x) {\n"
            << "    int local = x + split_global;\n"
            << "    return local;\n"
            << "}\n";
    }

    const std::vector<std::string> commands = {
        "cd \"" + dir + "\" && clang -target x86_64-unknown-linux-gnu -c -g -gsplit-dwarf -O0 \"" +
            source_path.filename().string() + "\" -o \"" + fs::path(out_obj_path).filename().string() + "\"",
        "cd \"" + dir + "\" && clang -c -g -gsplit-dwarf -O0 \"" +
            source_path.filename().string() + "\" -o \"" + fs::path(out_obj_path).filename().string() + "\"",
        "cd \"" + dir + "\" && gcc -c -g -gsplit-dwarf -O0 \"" +
            source_path.filename().string() + "\" -o \"" + fs::path(out_obj_path).filename().string() + "\""
    };

    for (const auto& command : commands) {
        std::error_code ec;
        fs::remove(out_obj_path, ec);
        fs::remove(out_dwo_path, ec);
        int rc = std::system(command.c_str());
        if (rc == 0 && fs::exists(out_obj_path) && fs::exists(out_dwo_path)) {
            return true;
        }
    }

    return false;
}

bool buildRealDWPFromTool(const std::string& dir,
                          const std::string& obj_path,
                          const std::string& dwp_path) {
    const std::string tool = findDWPTool();
    if (tool.empty()) {
        return false;
    }

    std::string command =
        "cd \"" + dir + "\" && " + tool + " \"" +
        fs::path(obj_path).filename().string() + "\" -o \"" +
        fs::path(dwp_path).filename().string() + "\"";
    std::error_code ec;
    fs::remove(dwp_path, ec);
    int rc = std::system(command.c_str());
    return rc == 0 && fs::exists(dwp_path) && fs::file_size(dwp_path, ec) > 0;
}

std::string extractFirstObjectFromArrayKey(const std::string& json, const std::string& key) {
    const std::string array_key = "\"" + key + "\":";
    size_t p = json.find(array_key);
    if (p == std::string::npos) return {};
    p = json.find('[', p + array_key.size());
    if (p == std::string::npos) return {};
    ++p;
    while (p < json.size() && (json[p] == ' ' || json[p] == '\n' || json[p] == '\r' || json[p] == '\t')) ++p;
    if (p >= json.size() || json[p] != '{') return {};

    const size_t start = p;
    int depth = 0;
    bool in_str = false;
    bool esc = false;
    for (; p < json.size(); ++p) {
        char c = json[p];
        if (in_str) {
            if (esc) {
                esc = false;
            } else if (c == '\\') {
                esc = true;
            } else if (c == '"') {
                in_str = false;
            }
            continue;
        }
        if (c == '"') {
            in_str = true;
            continue;
        }
        if (c == '{') ++depth;
        if (c == '}') {
            --depth;
            if (depth == 0) return json.substr(start, p - start + 1);
        }
    }
    return {};
}

std::vector<std::string> extractObjectsFromArrayKey(const std::string& json, const std::string& key) {
    std::vector<std::string> out;
    const std::string array_key = "\"" + key + "\":";
    size_t p = json.find(array_key);
    if (p == std::string::npos) return out;
    p = json.find('[', p + array_key.size());
    if (p == std::string::npos) return out;
    ++p;

    bool in_str = false;
    bool esc = false;
    int depth = 0;
    size_t obj_start = std::string::npos;
    for (; p < json.size(); ++p) {
        char c = json[p];
        if (in_str) {
            if (esc) {
                esc = false;
            } else if (c == '\\') {
                esc = true;
            } else if (c == '"') {
                in_str = false;
            }
            continue;
        }
        if (c == '"') {
            in_str = true;
            continue;
        }
        if (c == ']') {
            if (depth == 0) break;
        }
        if (c == '{') {
            if (depth == 0) obj_start = p;
            ++depth;
            continue;
        }
        if (c == '}') {
            --depth;
            if (depth == 0 && obj_start != std::string::npos) {
                out.push_back(json.substr(obj_start, p - obj_start + 1));
                obj_start = std::string::npos;
            }
            continue;
        }
    }
    return out;
}

std::string extractObjectForKey(const std::string& json, const std::string& key) {
    const std::string obj_key = "\"" + key + "\":";
    size_t p = json.find(obj_key);
    if (p == std::string::npos) return {};
    p = json.find('{', p + obj_key.size());
    if (p == std::string::npos) return {};

    const size_t start = p;
    int depth = 0;
    bool in_str = false;
    bool esc = false;
    for (; p < json.size(); ++p) {
        char c = json[p];
        if (in_str) {
            if (esc) {
                esc = false;
            } else if (c == '\\') {
                esc = true;
            } else if (c == '"') {
                in_str = false;
            }
            continue;
        }
        if (c == '"') {
            in_str = true;
            continue;
        }
        if (c == '{') ++depth;
        if (c == '}') {
            --depth;
            if (depth == 0) return json.substr(start, p - start + 1);
        }
    }
    return {};
}

std::string extractStringFieldFromObject(const std::string& obj_json, const std::string& key) {
    const std::string key_pat = "\"" + key + "\":\"";
    size_t p = obj_json.find(key_pat);
    if (p == std::string::npos) return {};
    p += key_pat.size();
    std::string out;
    bool esc = false;
    for (; p < obj_json.size(); ++p) {
        char c = obj_json[p];
        if (esc) {
            out.push_back(c);
            esc = false;
            continue;
        }
        if (c == '\\') {
            esc = true;
            continue;
        }
        if (c == '"') {
            return out;
        }
        out.push_back(c);
    }
    return {};
}

uint64_t extractUIntFieldFromObject(const std::string& obj_json, const std::string& key, bool* ok = nullptr) {
    const std::string key_pat = "\"" + key + "\":";
    size_t p = obj_json.find(key_pat);
    if (p == std::string::npos) {
        if (ok) *ok = false;
        return 0;
    }
    p += key_pat.size();
    while (p < obj_json.size() &&
           (obj_json[p] == ' ' || obj_json[p] == '\n' || obj_json[p] == '\r' || obj_json[p] == '\t')) {
        ++p;
    }
    size_t end = p;
    while (end < obj_json.size() && obj_json[end] >= '0' && obj_json[end] <= '9') ++end;
    if (end == p) {
        if (ok) *ok = false;
        return 0;
    }
    if (ok) *ok = true;
    return static_cast<uint64_t>(std::strtoull(obj_json.substr(p, end - p).c_str(), nullptr, 10));
}

bool extractBoolFieldFromObject(const std::string& obj_json, const std::string& key, bool* ok = nullptr) {
    const std::string key_pat = "\"" + key + "\":";
    size_t p = obj_json.find(key_pat);
    if (p == std::string::npos) {
        if (ok) *ok = false;
        return false;
    }
    p += key_pat.size();
    while (p < obj_json.size() &&
           (obj_json[p] == ' ' || obj_json[p] == '\n' || obj_json[p] == '\r' || obj_json[p] == '\t')) {
        ++p;
    }
    if (p + 4 <= obj_json.size() && obj_json.compare(p, 4, "true") == 0) {
        if (ok) *ok = true;
        return true;
    }
    if (p + 5 <= obj_json.size() && obj_json.compare(p, 5, "false") == 0) {
        if (ok) *ok = true;
        return false;
    }
    if (ok) *ok = false;
    return false;
}

std::string extractValueForTextKey(const std::string& text, const std::string& key) {
    const std::string pat = key + "=";
    size_t p = text.find(pat);
    if (p == std::string::npos) return {};
    p += pat.size();
    size_t eol = text.find('\n', p);
    return text.substr(p, (eol == std::string::npos) ? std::string::npos : (eol - p));
}

bool objectArrayContainsStringField(const std::vector<std::string>& objects,
                                    const std::string& key,
                                    const std::string& value) {
    for (const auto& obj : objects) {
        if (extractStringFieldFromObject(obj, key) == value) return true;
    }
    return false;
}

bool objectArrayContainsUIntField(const std::vector<std::string>& objects,
                                  const std::string& key,
                                  uint64_t value) {
    for (const auto& obj : objects) {
        bool ok = false;
        if (extractUIntFieldFromObject(obj, key, &ok) == value && ok) return true;
    }
    return false;
}

std::string makeInvalidLocationOpcodeELF(const std::string& stem) {
    std::vector<uint8_t> debug_str;
    const uint32_t off_bad = 0;
    for (char c : std::string("bad")) debug_str.push_back(static_cast<uint8_t>(c));
    debug_str.push_back(0);

    std::vector<uint8_t> debug_abbrev;
    appendULEB128(debug_abbrev, 1);
    appendULEB128(debug_abbrev, 0x11); // DW_TAG_compile_unit
    debug_abbrev.push_back(0x01); // children
    debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00);

    appendULEB128(debug_abbrev, 2);
    appendULEB128(debug_abbrev, 0x34); // DW_TAG_variable
    debug_abbrev.push_back(0x00); // no children
    appendULEB128(debug_abbrev, 0x03); // DW_AT_name
    appendULEB128(debug_abbrev, 0x0e); // DW_FORM_strp
    appendULEB128(debug_abbrev, 0x02); // DW_AT_location
    appendULEB128(debug_abbrev, 0x18); // DW_FORM_exprloc
    debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00); // end abbrev table

    std::vector<uint8_t> debug_info;
    appendU32LE(debug_info, 0); // unit_length placeholder
    appendU16LE(debug_info, 4); // version
    appendU32LE(debug_info, 0); // abbrev offset
    debug_info.push_back(0x08); // addr size

    debug_info.push_back(0x01); // CU
    debug_info.push_back(0x02); // variable
    appendU32LE(debug_info, off_bad);
    appendULEB128(debug_info, 1); // exprloc length
    debug_info.push_back(0xff);   // unsupported op
    debug_info.push_back(0x00);   // end children

    const uint32_t unit_len = static_cast<uint32_t>(debug_info.size() - 4);
    debug_info[0] = static_cast<uint8_t>(unit_len & 0xff);
    debug_info[1] = static_cast<uint8_t>((unit_len >> 8) & 0xff);
    debug_info[2] = static_cast<uint8_t>((unit_len >> 16) & 0xff);
    debug_info[3] = static_cast<uint8_t>((unit_len >> 24) & 0xff);

    fs::path dir = fs::temp_directory_path() / fs::path(stem);
    fs::create_directories(dir);
    std::string path = (dir / "invalid_loc.elf").string();
    writeELFWithSections(path, {
        {".debug_info", debug_info},
        {".debug_abbrev", debug_abbrev},
        {".debug_str", debug_str},
    });
    return path;
}

std::string makeVariableLocationELF(
    const std::string& stem,
    const std::vector<std::pair<std::string, std::vector<uint8_t>>>& vars) {
    std::vector<uint8_t> debug_str;
    std::vector<uint32_t> name_offsets;
    name_offsets.reserve(vars.size());
    for (const auto& var : vars) {
        name_offsets.push_back(static_cast<uint32_t>(debug_str.size()));
        for (char c : var.first) debug_str.push_back(static_cast<uint8_t>(c));
        debug_str.push_back(0);
    }

    std::vector<uint8_t> debug_abbrev;
    appendULEB128(debug_abbrev, 1);
    appendULEB128(debug_abbrev, 0x11); // DW_TAG_compile_unit
    debug_abbrev.push_back(0x01); // children
    debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00);

    appendULEB128(debug_abbrev, 2);
    appendULEB128(debug_abbrev, 0x34); // DW_TAG_variable
    debug_abbrev.push_back(0x00); // no children
    appendULEB128(debug_abbrev, 0x03); // DW_AT_name
    appendULEB128(debug_abbrev, 0x0e); // DW_FORM_strp
    appendULEB128(debug_abbrev, 0x02); // DW_AT_location
    appendULEB128(debug_abbrev, 0x18); // DW_FORM_exprloc
    debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00); // end abbrev table

    std::vector<uint8_t> debug_info;
    appendU32LE(debug_info, 0); // unit_length placeholder
    appendU16LE(debug_info, 4); // version
    appendU32LE(debug_info, 0); // abbrev offset
    debug_info.push_back(0x08); // addr size

    debug_info.push_back(0x01); // CU
    for (size_t i = 0; i < vars.size(); ++i) {
        debug_info.push_back(0x02); // variable
        appendU32LE(debug_info, name_offsets[i]);
        appendULEB128(debug_info, static_cast<uint64_t>(vars[i].second.size()));
        debug_info.insert(debug_info.end(), vars[i].second.begin(), vars[i].second.end());
    }
    debug_info.push_back(0x00); // end children

    const uint32_t unit_len = static_cast<uint32_t>(debug_info.size() - 4);
    debug_info[0] = static_cast<uint8_t>(unit_len & 0xff);
    debug_info[1] = static_cast<uint8_t>((unit_len >> 8) & 0xff);
    debug_info[2] = static_cast<uint8_t>((unit_len >> 16) & 0xff);
    debug_info[3] = static_cast<uint8_t>((unit_len >> 24) & 0xff);

    fs::path dir = fs::temp_directory_path() / fs::path(stem);
    fs::create_directories(dir);
    std::string path = (dir / "single_var.elf").string();
    writeELFWithSections(path, {
        {".debug_info", debug_info},
        {".debug_abbrev", debug_abbrev},
        {".debug_str", debug_str},
    });
    return path;
}

std::string makeSingleVariableLocationELF(const std::string& stem,
                                          const std::string& var_name,
                                          const std::vector<uint8_t>& expr) {
    return makeVariableLocationELF(stem, {{var_name, expr}});
}

std::string makeSemanticPayloadELF(const std::string& stem) {
    std::vector<uint8_t> debug_str;
    const uint32_t off_name = 0;
    for (char c : std::string("payload")) debug_str.push_back(static_cast<uint8_t>(c));
    debug_str.push_back(0);

    std::vector<uint8_t> debug_abbrev;
    appendULEB128(debug_abbrev, 1);
    appendULEB128(debug_abbrev, 0x11); // DW_TAG_compile_unit
    debug_abbrev.push_back(0x01);      // children
    debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00);

    appendULEB128(debug_abbrev, 2);
    appendULEB128(debug_abbrev, 0x34); // DW_TAG_variable
    debug_abbrev.push_back(0x00);      // no children
    appendULEB128(debug_abbrev, 0x03); // DW_AT_name
    appendULEB128(debug_abbrev, 0x0e); // DW_FORM_strp
    appendULEB128(debug_abbrev, 0x7e); // DW_AT_call_value
    appendULEB128(debug_abbrev, 0x18); // DW_FORM_exprloc
    appendULEB128(debug_abbrev, 0x80); // DW_AT_call_parameter
    appendULEB128(debug_abbrev, 0x0a); // DW_FORM_block1
    appendULEB128(debug_abbrev, 0x3d); // DW_AT_discr_list
    appendULEB128(debug_abbrev, 0x18); // DW_FORM_exprloc
    debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00);

    std::vector<uint8_t> debug_info;
    appendU32LE(debug_info, 0); // unit_length placeholder
    appendU16LE(debug_info, 4); // version
    appendU32LE(debug_info, 0); // abbrev offset
    debug_info.push_back(0x08); // addr size

    debug_info.push_back(0x01); // CU
    debug_info.push_back(0x02); // variable
    appendU32LE(debug_info, off_name);
    appendULEB128(debug_info, 2); // call_value exprloc length
    debug_info.push_back(static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_plus_uconst));
    debug_info.push_back(0x04);
    debug_info.push_back(2); // call_parameter block1 length
    debug_info.push_back(static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_constu));
    debug_info.push_back(0x05);
    appendULEB128(debug_info, 2); // discr_list exprloc length
    debug_info.push_back(static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_lit1));
    debug_info.push_back(static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_lit2));
    debug_info.push_back(0x00); // end children

    const uint32_t unit_len = static_cast<uint32_t>(debug_info.size() - 4);
    debug_info[0] = static_cast<uint8_t>(unit_len & 0xff);
    debug_info[1] = static_cast<uint8_t>((unit_len >> 8) & 0xff);
    debug_info[2] = static_cast<uint8_t>((unit_len >> 16) & 0xff);
    debug_info[3] = static_cast<uint8_t>((unit_len >> 24) & 0xff);

    fs::path dir = fs::temp_directory_path() / fs::path(stem);
    fs::create_directories(dir);
    std::string path = (dir / "semantic_payload.elf").string();
    writeELFWithSections(path, {
        {".debug_info", debug_info},
        {".debug_abbrev", debug_abbrev},
        {".debug_str", debug_str},
    });
    return path;
}

std::string makeSingleVariableLoclistELF(
    const std::string& stem,
    const std::string& var_name,
    const std::vector<std::tuple<uint64_t, uint64_t, std::vector<uint8_t>>>& segments) {
    std::vector<uint8_t> debug_str;
    const uint32_t off_name = 0;
    for (char c : var_name) debug_str.push_back(static_cast<uint8_t>(c));
    debug_str.push_back(0);

    std::vector<uint8_t> debug_loclists;
    appendU32LE(debug_loclists, 0);   // unit_length placeholder
    appendU16LE(debug_loclists, 5);   // version
    debug_loclists.push_back(0x08);   // address_size
    debug_loclists.push_back(0x00);   // segment_selector_size
    appendU32LE(debug_loclists, 0);   // offset_entry_count
    const uint32_t loclist_off = static_cast<uint32_t>(debug_loclists.size());

    for (const auto& [start, end, expr] : segments) {
        debug_loclists.push_back(0x07); // DW_LLE_start_end
        appendU64LE(debug_loclists, start);
        appendU64LE(debug_loclists, end);
        appendULEB128(debug_loclists, static_cast<uint64_t>(expr.size()));
        debug_loclists.insert(debug_loclists.end(), expr.begin(), expr.end());
    }
    debug_loclists.push_back(0x00); // DW_LLE_end_of_list

    const uint32_t loclists_unit_len = static_cast<uint32_t>(debug_loclists.size() - 4);
    debug_loclists[0] = static_cast<uint8_t>(loclists_unit_len & 0xff);
    debug_loclists[1] = static_cast<uint8_t>((loclists_unit_len >> 8) & 0xff);
    debug_loclists[2] = static_cast<uint8_t>((loclists_unit_len >> 16) & 0xff);
    debug_loclists[3] = static_cast<uint8_t>((loclists_unit_len >> 24) & 0xff);

    std::vector<uint8_t> debug_abbrev;
    appendULEB128(debug_abbrev, 1);
    appendULEB128(debug_abbrev, 0x11); // DW_TAG_compile_unit
    debug_abbrev.push_back(0x01);      // children
    appendULEB128(debug_abbrev, 0x8c); // DW_AT_loclists_base
    appendULEB128(debug_abbrev, 0x17); // DW_FORM_sec_offset
    debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00);

    appendULEB128(debug_abbrev, 2);
    appendULEB128(debug_abbrev, 0x34); // DW_TAG_variable
    debug_abbrev.push_back(0x00);      // no children
    appendULEB128(debug_abbrev, 0x03); // DW_AT_name
    appendULEB128(debug_abbrev, 0x0e); // DW_FORM_strp
    appendULEB128(debug_abbrev, 0x02); // DW_AT_location
    appendULEB128(debug_abbrev, 0x17); // DW_FORM_sec_offset
    debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00);
    debug_abbrev.push_back(0x00);

    std::vector<uint8_t> debug_info;
    appendU32LE(debug_info, 0); // unit_length placeholder
    appendU16LE(debug_info, 5); // version
    debug_info.push_back(0x01); // DW_UT_compile
    debug_info.push_back(0x08); // addr size
    appendU32LE(debug_info, 0); // abbrev offset

    debug_info.push_back(0x01); // CU
    appendU32LE(debug_info, 0); // DW_AT_loclists_base = contribution header start

    debug_info.push_back(0x02); // variable
    appendU32LE(debug_info, off_name);
    appendU32LE(debug_info, loclist_off); // DW_AT_location sec_offset into .debug_loclists
    debug_info.push_back(0x00); // end children

    const uint32_t unit_len = static_cast<uint32_t>(debug_info.size() - 4);
    debug_info[0] = static_cast<uint8_t>(unit_len & 0xff);
    debug_info[1] = static_cast<uint8_t>((unit_len >> 8) & 0xff);
    debug_info[2] = static_cast<uint8_t>((unit_len >> 16) & 0xff);
    debug_info[3] = static_cast<uint8_t>((unit_len >> 24) & 0xff);

    fs::path dir = fs::temp_directory_path() / fs::path(stem);
    fs::create_directories(dir);
    std::string path = (dir / "single_var_loclist.elf").string();
    writeELFWithSections(path, {
        {".debug_info", debug_info},
        {".debug_abbrev", debug_abbrev},
        {".debug_str", debug_str},
        {".debug_loclists", debug_loclists},
    });
    return path;
}

struct VendorTelemetryExpectations {
    uint64_t skips = 0;
    std::vector<uint64_t> forms;
    std::vector<std::string> severities;
    std::vector<std::string> buckets;
    std::vector<std::pair<uint64_t, uint64_t>> histogram_entries;
    std::vector<std::pair<std::string, uint64_t>> severity_entries;
    std::vector<std::pair<std::string, uint64_t>> bucket_entries;
};

VendorTelemetryExpectations makeVendorTelemetryExpectations(
    uint64_t skips,
    std::vector<uint64_t> forms,
    std::vector<std::string> severities,
    std::vector<std::string> buckets,
    std::vector<std::pair<uint64_t, uint64_t>> histogram_entries,
    std::vector<std::pair<std::string, uint64_t>> severity_entries,
    std::vector<std::pair<std::string, uint64_t>> bucket_entries) {
    VendorTelemetryExpectations out;
    out.skips = skips;
    out.forms = std::move(forms);
    out.severities = std::move(severities);
    out.buckets = std::move(buckets);
    out.histogram_entries = std::move(histogram_entries);
    out.severity_entries = std::move(severity_entries);
    out.bucket_entries = std::move(bucket_entries);
    return out;
}

void assertVendorTelemetryText(const std::string& out_text,
                               const VendorTelemetryExpectations& expected) {
    assert(extractValueForTextKey(out_text, "vendor_form_skips") == std::to_string(expected.skips));
    std::string text_examples = extractValueForTextKey(out_text, "vendor_form_skip_examples");
    for (uint64_t form : expected.forms) {
        std::ostringstream needle;
        needle << "form=0x" << std::hex << form;
        assert(text_examples.find(needle.str()) != std::string::npos);
    }

    std::string histogram = extractValueForTextKey(out_text, "vendor_form_skip_histogram");
    for (const auto& [form, count] : expected.histogram_entries) {
        std::ostringstream needle;
        needle << "0x" << std::hex << form << std::dec << ":" << count;
        assert(histogram.find(needle.str()) != std::string::npos);
    }

    std::string offset_buckets = extractValueForTextKey(out_text, "vendor_form_skip_offset_buckets");
    for (const auto& [bucket, count] : expected.bucket_entries) {
        assert(offset_buckets.find(bucket + ":" + std::to_string(count)) != std::string::npos);
    }

    std::string severity_buckets = extractValueForTextKey(out_text, "vendor_form_skip_severity_buckets");
    for (const auto& [severity, count] : expected.severity_entries) {
        assert(severity_buckets.find(severity + ":" + std::to_string(count)) != std::string::npos);
    }
}

void assertVendorTelemetryJsonV2(const std::string& out_json_v2,
                                 const VendorTelemetryExpectations& expected) {
    assert(out_json_v2.find("\"schema_version\":2") != std::string::npos);
    auto examples = extractObjectsFromArrayKey(out_json_v2, "vendor_form_skip_examples_structured");
    auto hist = extractObjectsFromArrayKey(out_json_v2, "vendor_form_skip_histogram_structured");
    auto buckets = extractObjectsFromArrayKey(out_json_v2, "vendor_form_skip_offset_buckets_structured");
    auto sev = extractObjectsFromArrayKey(out_json_v2, "vendor_form_skip_severity_buckets_structured");
    assert(!examples.empty());
    assert(!hist.empty());
    assert(!buckets.empty());
    assert(!sev.empty());

    for (uint64_t form : expected.forms) {
        assert(objectArrayContainsUIntField(examples, "form", form));
    }
    for (const auto& severity : expected.severities) {
        assert(objectArrayContainsStringField(examples, "severity", severity));
    }
    for (const auto& bucket : expected.buckets) {
        assert(objectArrayContainsStringField(buckets, "bucket", bucket));
    }
    for (const auto& [form, count] : expected.histogram_entries) {
        assert(objectArrayContainsUIntField(hist, "form", form));
        assert(objectArrayContainsUIntField(hist, "count", count));
    }
    for (const auto& [severity, count] : expected.severity_entries) {
        assert(objectArrayContainsStringField(sev, "severity", severity));
        assert(objectArrayContainsUIntField(sev, "count", count));
    }
    for (const auto& [bucket, count] : expected.bucket_entries) {
        assert(objectArrayContainsStringField(buckets, "bucket", bucket));
        assert(objectArrayContainsUIntField(buckets, "count", count));
    }
}

} // namespace

int main() {
    std::cout << "Running dwarf_dump CLI tests..." << std::endl;

#if DWARF_HAS_Z3
    const std::string dwarf_dump = firstExisting({"./build/dwarf_dump", "./dwarf_dump"});
#else
    const std::string dwarf_dump = firstExisting({"./build-noz3/dwarf_dump", "./build/dwarf_dump", "./dwarf_dump"});
#endif
    const std::string test_elf = firstExisting({"./test_elf", "../test_elf"});
    assert(!dwarf_dump.empty());
    assert(!test_elf.empty());

    auto writeSplitFallbackFixture = [](const std::string& prefix,
                                        bool include_cu_index,
                                        bool malformed_cu_index,
                                        bool signature_miss,
                                        std::string& main_path,
                                        std::string& dwp_path) {
        const uint64_t dwo_id = 0xA1B2C3D4E5F60718ULL;
        const uint64_t other_sig = 0x0F1E2D3C4B5A6978ULL;
        const std::string dwo_name = prefix + ".dwo";
        const std::string var_name = "FromDWO";

        fs::path dir = fs::path("/tmp") / ("dwarf_cli_" + prefix + "_" + std::to_string(std::rand()));
        std::error_code ec;
        fs::create_directories(dir, ec);
        assert(fs::exists(dir));

        std::vector<uint8_t> main_str;
        uint32_t dwo_name_off = static_cast<uint32_t>(main_str.size());
        for (char c : dwo_name) main_str.push_back(static_cast<uint8_t>(c));
        main_str.push_back(0);

        std::vector<uint8_t> main_abbrev;
        main_abbrev.push_back(0x01); // code
        main_abbrev.push_back(0x11); // DW_TAG_compile_unit
        main_abbrev.push_back(0x00); // no children
        appendULEB128(main_abbrev, static_cast<uint64_t>(dwarf::DwarfAttribute::DW_AT_dwo_name));
        appendULEB128(main_abbrev, static_cast<uint64_t>(dwarf::DwarfForm::DW_FORM_strp));
        appendULEB128(main_abbrev, static_cast<uint64_t>(dwarf::DwarfAttribute::DW_AT_dwo_id));
        appendULEB128(main_abbrev, static_cast<uint64_t>(dwarf::DwarfForm::DW_FORM_data8));
        main_abbrev.push_back(0x00); main_abbrev.push_back(0x00);
        main_abbrev.push_back(0x00);

        std::vector<uint8_t> main_info;
        appendU32LE(main_info, 0);    // placeholder unit_length
        appendU16LE(main_info, 4);    // version
        appendU32LE(main_info, 0);    // abbrev offset
        main_info.push_back(0x08); // addr_size
        main_info.push_back(0x01); // abbrev code
        appendU32LE(main_info, dwo_name_off);
        appendU64LE(main_info, dwo_id);
        uint32_t main_len = static_cast<uint32_t>(main_info.size() - 4);
        main_info[0] = static_cast<uint8_t>(main_len & 0xff);
        main_info[1] = static_cast<uint8_t>((main_len >> 8) & 0xff);
        main_info[2] = static_cast<uint8_t>((main_len >> 16) & 0xff);
        main_info[3] = static_cast<uint8_t>((main_len >> 24) & 0xff);

        std::vector<uint8_t> payload_abbrev;
        payload_abbrev.push_back(0x01); // CU
        payload_abbrev.push_back(0x11); // DW_TAG_compile_unit
        payload_abbrev.push_back(0x01); // has children
        payload_abbrev.push_back(0x00); payload_abbrev.push_back(0x00);
        payload_abbrev.push_back(0x02); // variable
        payload_abbrev.push_back(0x34); // DW_TAG_variable
        payload_abbrev.push_back(0x00); // no children
        appendULEB128(payload_abbrev, static_cast<uint64_t>(dwarf::DwarfAttribute::DW_AT_name));
        appendULEB128(payload_abbrev, static_cast<uint64_t>(dwarf::DwarfForm::DW_FORM_strp));
        payload_abbrev.push_back(0x00); payload_abbrev.push_back(0x00);
        payload_abbrev.push_back(0x00);

        std::vector<uint8_t> payload_info;
        appendU32LE(payload_info, 0);    // placeholder unit_length
        appendU16LE(payload_info, 4);    // version
        appendU32LE(payload_info, 0);    // abbrev offset
        payload_info.push_back(0x08); // addr_size
        payload_info.push_back(0x01); // CU code
        payload_info.push_back(0x02); // var code
        appendU32LE(payload_info, 0); // name strp offset
        payload_info.push_back(0x00); // end children
        uint32_t payload_len = static_cast<uint32_t>(payload_info.size() - 4);
        payload_info[0] = static_cast<uint8_t>(payload_len & 0xff);
        payload_info[1] = static_cast<uint8_t>((payload_len >> 8) & 0xff);
        payload_info[2] = static_cast<uint8_t>((payload_len >> 16) & 0xff);
        payload_info[3] = static_cast<uint8_t>((payload_len >> 24) & 0xff);

        std::vector<uint8_t> dwo_str;
        for (char c : var_name) dwo_str.push_back(static_cast<uint8_t>(c));
        dwo_str.push_back(0);

        std::vector<uint8_t> cu_index;
        if (!include_cu_index) {
            // Intentionally omit CU index section.
        } else if (malformed_cu_index) {
            appendU32LE(cu_index, 6); // version
            appendU32LE(cu_index, 2); // section_count
            appendU32LE(cu_index, 1); // unit_count
            appendU32LE(cu_index, 1); // slot_count
        } else {
            appendU32LE(cu_index, 6); // version
            appendU32LE(cu_index, 2); // section_count
            appendU32LE(cu_index, 1); // unit_count
            appendU32LE(cu_index, 1); // slot_count
            appendU32LE(cu_index, 1); // DW_SECT_INFO
            appendU32LE(cu_index, 3); // DW_SECT_ABBREV
            appendU64LE(cu_index, signature_miss ? other_sig : dwo_id); // signature
            appendU32LE(cu_index, 1); // row index
            appendU32LE(cu_index, 0); // info offset
            appendU32LE(cu_index, 0); // abbrev offset
            appendU32LE(cu_index, static_cast<uint32_t>(payload_info.size()));
            appendU32LE(cu_index, static_cast<uint32_t>(payload_abbrev.size()));
        }

        main_path = (dir / (prefix + "_main.elf")).string();
        std::string dwo_path = (dir / dwo_name).string();
        dwp_path = (dir / (prefix + ".dwp")).string();

        writeELFWithSections(main_path, {
            {".debug_info", main_info},
            {".debug_abbrev", main_abbrev},
            {".debug_str", main_str},
        });
        writeELFWithSections(dwo_path, {
            {".debug_info.dwo", payload_info},
            {".debug_abbrev.dwo", payload_abbrev},
            {".debug_str.dwo", dwo_str},
        });
        std::vector<std::pair<std::string, std::vector<uint8_t>>> dwp_sections = {
            {".debug_info.dwo", payload_info},
            {".debug_abbrev.dwo", payload_abbrev},
            {".debug_str.dwo", dwo_str},
        };
        if (include_cu_index) {
            dwp_sections.push_back({".debug_cu_index", cu_index});
        }
        writeELFWithSections(dwp_path, dwp_sections);
    };

    auto writeSplitTUOnlyFixture = [](const std::string& prefix,
                                      std::string& main_path,
                                      std::string& dwp_path) {
        const uint64_t dwo_id = 0x55AA33CC77DD11EEULL;
        const std::string dwo_name = prefix + ".dwo";

        fs::path dir = fs::path("/tmp") / ("dwarf_cli_tu_" + prefix + "_" + std::to_string(std::rand()));
        std::error_code ec;
        fs::create_directories(dir, ec);
        assert(fs::exists(dir));

        std::vector<uint8_t> main_str;
        uint32_t dwo_name_off = static_cast<uint32_t>(main_str.size());
        for (char c : dwo_name) main_str.push_back(static_cast<uint8_t>(c));
        main_str.push_back(0);

        std::vector<uint8_t> main_abbrev;
        main_abbrev.push_back(0x01); // code
        main_abbrev.push_back(0x11); // DW_TAG_compile_unit
        main_abbrev.push_back(0x00); // no children
        main_abbrev.push_back(0x76); // DW_AT_dwo_name
        main_abbrev.push_back(0x0e); // DW_FORM_strp
        main_abbrev.push_back(0x75); // DW_AT_dwo_id
        main_abbrev.push_back(0x07); // DW_FORM_data8
        main_abbrev.push_back(0x00); main_abbrev.push_back(0x00);
        main_abbrev.push_back(0x00);

        std::vector<uint8_t> main_info;
        appendU32LE(main_info, 0); // placeholder unit_length
        appendU16LE(main_info, 4); // version
        appendU32LE(main_info, 0); // abbrev offset
        main_info.push_back(0x08); // addr_size
        main_info.push_back(0x01); // abbrev code
        appendU32LE(main_info, dwo_name_off);
        appendU64LE(main_info, dwo_id);
        uint32_t main_len = static_cast<uint32_t>(main_info.size() - 4);
        main_info[0] = static_cast<uint8_t>(main_len & 0xff);
        main_info[1] = static_cast<uint8_t>((main_len >> 8) & 0xff);
        main_info[2] = static_cast<uint8_t>((main_len >> 16) & 0xff);
        main_info[3] = static_cast<uint8_t>((main_len >> 24) & 0xff);

        std::vector<uint8_t> payload_abbrev;
        payload_abbrev.push_back(0x01); // CU
        payload_abbrev.push_back(0x11); // DW_TAG_compile_unit
        payload_abbrev.push_back(0x01); // has children
        payload_abbrev.push_back(0x00); payload_abbrev.push_back(0x00);
        payload_abbrev.push_back(0x02); // variable
        payload_abbrev.push_back(0x34); // DW_TAG_variable
        payload_abbrev.push_back(0x00); // no children
        payload_abbrev.push_back(0x03); // DW_AT_name
        payload_abbrev.push_back(0x0e); // DW_FORM_strp
        payload_abbrev.push_back(0x00); payload_abbrev.push_back(0x00);
        payload_abbrev.push_back(0x00);

        std::vector<uint8_t> payload_info;
        appendU32LE(payload_info, 0); // placeholder unit_length
        appendU16LE(payload_info, 4); // version
        appendU32LE(payload_info, 0); // abbrev offset
        payload_info.push_back(0x08); // addr_size
        payload_info.push_back(0x01); // CU code
        payload_info.push_back(0x02); // var code
        appendU32LE(payload_info, 0); // name strp offset
        payload_info.push_back(0x00); // end children
        uint32_t payload_len = static_cast<uint32_t>(payload_info.size() - 4);
        payload_info[0] = static_cast<uint8_t>(payload_len & 0xff);
        payload_info[1] = static_cast<uint8_t>((payload_len >> 8) & 0xff);
        payload_info[2] = static_cast<uint8_t>((payload_len >> 16) & 0xff);
        payload_info[3] = static_cast<uint8_t>((payload_len >> 24) & 0xff);

        std::vector<uint8_t> dwp_str = {'y', 0};

        std::vector<uint8_t> tu_index;
        appendU32LE(tu_index, 6); // version
        appendU32LE(tu_index, 2); // section_count
        appendU32LE(tu_index, 1); // unit_count
        appendU32LE(tu_index, 1); // slot_count
        appendU32LE(tu_index, 1); // DW_SECT_INFO
        appendU32LE(tu_index, 3); // DW_SECT_ABBREV
        appendU64LE(tu_index, dwo_id); // signature
        appendU32LE(tu_index, 1); // row index
        appendU32LE(tu_index, 0); // info offset
        appendU32LE(tu_index, 0); // abbrev offset
        appendU32LE(tu_index, static_cast<uint32_t>(payload_info.size()));
        appendU32LE(tu_index, static_cast<uint32_t>(payload_abbrev.size()));

        main_path = (dir / (prefix + "_main.elf")).string();
        dwp_path = (dir / (prefix + ".dwp")).string();

        writeELFWithSections(main_path, {
            {".debug_info", main_info},
            {".debug_abbrev", main_abbrev},
            {".debug_str", main_str},
        });
        writeELFWithSections(dwp_path, {
            {".debug_info.dwo", payload_info},
            {".debug_abbrev.dwo", payload_abbrev},
            {".debug_str.dwo", dwp_str},
            {".debug_tu_index", tu_index},
        });
    };

    auto writeSplitUnknownSectionFixture = [](const std::string& prefix,
                                              bool tu_index,
                                              uint32_t unknown_id,
                                              std::string& main_path,
                                              std::string& dwp_path) {
        const uint64_t dwo_id = tu_index ? 0x66778899AABBCCDDULL : 0x1122446688AACCEEULL;
        const std::string dwo_name = prefix + ".dwo";

        fs::path dir = fs::path("/tmp") / ("dwarf_cli_unknown_dwp_" + prefix + "_" + std::to_string(std::rand()));
        std::error_code ec;
        fs::create_directories(dir, ec);
        assert(fs::exists(dir));

        std::vector<uint8_t> main_str;
        uint32_t dwo_name_off = static_cast<uint32_t>(main_str.size());
        for (char c : dwo_name) main_str.push_back(static_cast<uint8_t>(c));
        main_str.push_back(0);

        std::vector<uint8_t> main_abbrev;
        main_abbrev.push_back(0x01);
        main_abbrev.push_back(0x11);
        main_abbrev.push_back(0x00);
        main_abbrev.push_back(0x76);
        main_abbrev.push_back(0x0e);
        main_abbrev.push_back(0x75);
        main_abbrev.push_back(0x07);
        main_abbrev.push_back(0x00); main_abbrev.push_back(0x00);
        main_abbrev.push_back(0x00);

        std::vector<uint8_t> main_info;
        appendU32LE(main_info, 0);
        appendU16LE(main_info, 4);
        appendU32LE(main_info, 0);
        main_info.push_back(0x08);
        main_info.push_back(0x01);
        appendU32LE(main_info, dwo_name_off);
        appendU64LE(main_info, dwo_id);
        uint32_t main_len = static_cast<uint32_t>(main_info.size() - 4);
        main_info[0] = static_cast<uint8_t>(main_len & 0xff);
        main_info[1] = static_cast<uint8_t>((main_len >> 8) & 0xff);
        main_info[2] = static_cast<uint8_t>((main_len >> 16) & 0xff);
        main_info[3] = static_cast<uint8_t>((main_len >> 24) & 0xff);

        std::vector<uint8_t> payload_abbrev;
        payload_abbrev.push_back(0x01);
        payload_abbrev.push_back(0x11);
        payload_abbrev.push_back(0x01);
        payload_abbrev.push_back(0x00); payload_abbrev.push_back(0x00);
        payload_abbrev.push_back(0x02);
        payload_abbrev.push_back(0x34);
        payload_abbrev.push_back(0x00);
        payload_abbrev.push_back(0x03);
        payload_abbrev.push_back(0x0e);
        payload_abbrev.push_back(0x00); payload_abbrev.push_back(0x00);
        payload_abbrev.push_back(0x00);

        std::vector<uint8_t> payload_info;
        appendU32LE(payload_info, 0);
        appendU16LE(payload_info, 4);
        appendU32LE(payload_info, 0);
        payload_info.push_back(0x08);
        payload_info.push_back(0x01);
        payload_info.push_back(0x02);
        appendU32LE(payload_info, 0);
        payload_info.push_back(0x00);
        uint32_t payload_len = static_cast<uint32_t>(payload_info.size() - 4);
        payload_info[0] = static_cast<uint8_t>(payload_len & 0xff);
        payload_info[1] = static_cast<uint8_t>((payload_len >> 8) & 0xff);
        payload_info[2] = static_cast<uint8_t>((payload_len >> 16) & 0xff);
        payload_info[3] = static_cast<uint8_t>((payload_len >> 24) & 0xff);

        std::vector<uint8_t> index;
        appendU32LE(index, 6);
        appendU32LE(index, 3);
        appendU32LE(index, 1);
        appendU32LE(index, 1);
        appendU32LE(index, 1);
        appendU32LE(index, unknown_id);
        appendU32LE(index, 3);
        appendU64LE(index, dwo_id);
        appendU32LE(index, 1);
        appendU32LE(index, 0);
        appendU32LE(index, 0x40);
        appendU32LE(index, 0);
        appendU32LE(index, static_cast<uint32_t>(payload_info.size()));
        appendU32LE(index, 0x10);
        appendU32LE(index, static_cast<uint32_t>(payload_abbrev.size()));

        main_path = (dir / (prefix + "_main.elf")).string();
        dwp_path = (dir / (prefix + ".dwp")).string();

        writeELFWithSections(main_path, {
            {".debug_info", main_info},
            {".debug_abbrev", main_abbrev},
            {".debug_str", main_str},
        });
        writeELFWithSections(dwp_path, {
            {".debug_info.dwo", payload_info},
            {".debug_abbrev.dwo", payload_abbrev},
            {".debug_str.dwo", {'z', 0}},
            {tu_index ? ".debug_tu_index" : ".debug_cu_index", index},
        });
    };

    {
        std::string out;
        int code = runAndCapture(dwarf_dump + " compare-expr --help", "/tmp/dwarf_cli_help.txt", out);
        assert(code == 0);
        assert(out.find("--strict-attr-present") != std::string::npos);
        assert(out.find("--no-differential") != std::string::npos);
        assert(out.find("--schema-version") != std::string::npos);
        assert(out.find("--reloc-check") != std::string::npos);
        assert(out.find("--normalize-loc") != std::string::npos);
        assert(out.find("--normalization-policy=<off|symbolic-canonical>") != std::string::npos);
        assert(out.find("Apply semantic normalization before compare") != std::string::npos);
        assert(out.find("--range-aware") != std::string::npos);
        assert(out.find("--vendor-op-profile=<P>") != std::string::npos);
        assert(out.find("--gate-profile=<P>") != std::string::npos);
        assert(out.find("--verify-profile=<P>") != std::string::npos);
        assert(out.find("--verify-features=<LIST>") != std::string::npos);
        assert(out.find("--emit-profile-only") != std::string::npos);
        assert(out.find("--emit-solver-summary-only") != std::string::npos);
        assert(out.find("--solver-timeout-ms=<N>") != std::string::npos);
        assert(out.find("--fail-on-solver-result=<K>") != std::string::npos);
        assert(out.find("--fail-on-verifier-backend=<K>") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(dwarf_dump + " compare-cfi --help", "/tmp/dwarf_cli_cfi_help.txt", out);
        assert(code == 0);
        assert(out.find("--lhs-fde-index") != std::string::npos);
        assert(out.find("--allow-range-mismatch") != std::string::npos);
        assert(out.find("--sort=") != std::string::npos);
        assert(out.find("--show-equivalent") != std::string::npos);
        assert(out.find("--only-different") != std::string::npos);
        assert(out.find("--only-unknown") != std::string::npos);
        assert(out.find("--gate-profile=<P>") != std::string::npos);
        assert(out.find("--emit-profile-only") != std::string::npos);
        assert(out.find("--emit-solver-summary-only") != std::string::npos);
        assert(out.find("--emit-gate-signature-only") != std::string::npos);
        assert(out.find("--solver-timeout-ms=<N>") != std::string::npos);
        assert(out.find("--fail-on-solver-result=<K>") != std::string::npos);
        assert(out.find("--fail-on-verifier-backend=<K>") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(dwarf_dump + " verify-reloc --help", "/tmp/dwarf_cli_reloc_help.txt", out);
        assert(code == 0);
        assert(out.find("--format=<text|json>") != std::string::npos);
        assert(out.find("--max-errors") != std::string::npos);
        assert(out.find("--explain-gate") != std::string::npos);
        assert(out.find("--normalize-loc") != std::string::npos);
        assert(out.find("--normalization-policy=<off|symbolic-canonical>") != std::string::npos);
        assert(out.find("--verify-profile=<P>") != std::string::npos);
        assert(out.find("--verify-features=<LIST>") != std::string::npos);
        assert(out.find("--emit-profile-only") != std::string::npos);
        assert(out.find("--emit-gate-signature-only") != std::string::npos);
        assert(out.find("--report-only") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(dwarf_dump + " triage-vendor-ops --help", "/tmp/dwarf_cli_triage_help.txt", out);
        assert(code == 0);
        assert(out.find("--format=<text|json>") != std::string::npos);
        assert(out.find("--schema-version=<N>") != std::string::npos);
        assert(out.find("selection_status=no_safe_family_selected") != std::string::npos);
        assert(out.find("two independent samples") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(dwarf_dump + " --help", "/tmp/dwarf_cli_main_help.txt", out);
        assert(code == 0);
        assert(out.find("--show-support") != std::string::npos);
        assert(out.find("triage-vendor-ops") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(dwarf_dump + " --show-support", "/tmp/dwarf_cli_support_only.txt", out);
        assert(code == 0);
        assert(out.find("DWARF v5 Support Matrix") != std::string::npos);
        assert(out.find("DW_FORM_implicit_const") != std::string::npos);
        assert(out.find("split-dwarf") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(dwarf_dump + " --show-support " + test_elf, "/tmp/dwarf_cli_support_with_file.txt", out);
        assert(code == 0);
        assert(out.find("Runtime (loaded file)") != std::string::npos);
        assert(out.find("has_split_dwarf=") != std::string::npos);
        assert(out.find("has_loaded_dwp=") != std::string::npos);
        assert(out.find("dwp_path=") != std::string::npos);
        assert(out.find("has_dwp_cu_index=") != std::string::npos);
        assert(out.find("dwp_cu_index_valid=") != std::string::npos);
        assert(out.find("dwp_cu_index_units=") != std::string::npos);
        assert(out.find("has_dwp_tu_index=") != std::string::npos);
        assert(out.find("dwp_tu_index_valid=") != std::string::npos);
        assert(out.find("dwp_tu_index_units=") != std::string::npos);
        assert(out.find("dwp_hits=") != std::string::npos);
        assert(out.find("dwo_hits=") != std::string::npos);
        assert(out.find("dwo_fallback_hits=") != std::string::npos);
        assert(out.find("fallback_no_index=") != std::string::npos);
        assert(out.find("fallback_invalid_index=") != std::string::npos);
        assert(out.find("fallback_sig_miss=") != std::string::npos);
        assert(out.find("has_debug_names=") != std::string::npos);
        assert(out.find("vendor_form_skips=") != std::string::npos);
        assert(out.find("vendor_form_skip_examples=") != std::string::npos);
        assert(out.find("vendor_form_skip_histogram=") != std::string::npos);
        assert(out.find("vendor_form_skip_offset_buckets=") != std::string::npos);
        assert(out.find("vendor_form_skip_severity_buckets=") != std::string::npos);
        assert(out.find("expression_site_count=") != std::string::npos);
        assert(out.find("expression_op_count=") != std::string::npos);
        assert(out.find("unknown_expression_opcode_sites=") != std::string::npos);
        assert(out.find("unknown_vendor_expression_opcode_sites=") != std::string::npos);
        assert(out.find("unknown_expression_opcode_histogram=") != std::string::npos);
        assert(out.find("unknown_expression_opcode_attributes=") != std::string::npos);
    }

    {
        std::string invalid_expr_elf = makeInvalidLocationOpcodeELF("dwarf_cli_support_invalid_expr");

        std::string out_text;
        int code_text = runAndCapture(dwarf_dump + " --show-support " + invalid_expr_elf,
                                      "/tmp/dwarf_cli_support_invalid_expr.txt", out_text);
        assert(code_text == 0);
        assert(extractValueForTextKey(out_text, "unknown_expression_opcode_sites") == "1");
        assert(extractValueForTextKey(out_text, "unknown_vendor_expression_opcode_sites") == "1");
        assert(extractValueForTextKey(out_text, "unknown_expression_opcode_histogram") == "0xff:1");
        assert(extractValueForTextKey(out_text, "unknown_expression_opcode_attributes") == "DW_AT_location:1");

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " --show-support --format=json --schema-version=2 " + invalid_expr_elf,
            "/tmp/dwarf_cli_support_invalid_expr_json_v2.txt", out_json);
        assert(code_json == 0);
        std::string runtime_obj = extractObjectForKey(out_json, "runtime");
        assert(!runtime_obj.empty());
        bool ok = false;
        assert(extractUIntFieldFromObject(runtime_obj, "unknown_expression_opcode_sites", &ok) == 1 && ok);
        assert(extractUIntFieldFromObject(runtime_obj, "unknown_vendor_expression_opcode_sites", &ok) == 1 && ok);
        assert(extractStringFieldFromObject(runtime_obj, "unknown_expression_opcode_histogram") == "0xff:1");
        assert(extractStringFieldFromObject(runtime_obj, "unknown_expression_opcode_attributes") ==
               "DW_AT_location:1");
        auto unknown_ops = extractObjectsFromArrayKey(out_json, "unknown_expression_opcode_histogram_structured");
        auto unknown_attrs = extractObjectsFromArrayKey(out_json, "unknown_expression_opcode_attributes_structured");
        assert(objectArrayContainsUIntField(unknown_ops, "opcode", 255));
        assert(objectArrayContainsUIntField(unknown_ops, "count", 1));
        assert(objectArrayContainsStringField(unknown_attrs, "attribute", "DW_AT_location"));
    }

    {
        // Fixture with an unknown vendor form in .debug_info so parser recovery telemetry is non-zero.
        fs::path dir = fs::path("/tmp") / ("dwarf_cli_vendor_form_" + std::to_string(std::rand()));
        std::error_code ec;
        fs::create_directories(dir, ec);
        assert(fs::exists(dir));

        std::vector<uint8_t> debug_abbrev = {
            0x01,       // abbrev code
            0x11,       // DW_TAG_compile_unit
            0x00,       // no children
            0x49,       // DW_AT_type
            0xb0, 0x3e, // unknown vendor form 0x1f30 (ULEB128)
            0x49,       // DW_AT_type (repeated to force duplicate skip exemplar candidates)
            0xb0, 0x3e, // unknown vendor form 0x1f30 (ULEB128)
            0x03,       // DW_AT_name
            0x0e,       // DW_FORM_strp
            0x00, 0x00, // end attr specs
            0x00        // end abbrev table
        };

        std::vector<uint8_t> debug_info;
        appendU32LE(debug_info, 0); // unit_length placeholder
        appendU16LE(debug_info, 4); // version
        appendU32LE(debug_info, 0); // abbrev offset
        debug_info.push_back(0x08); // address size
        debug_info.push_back(0x01); // abbrev code
        appendU32LE(debug_info, 0x11223344); // unknown vendor form payload #1
        appendU32LE(debug_info, 0x55667788); // unknown vendor form payload #2
        appendU32LE(debug_info, 0); // DW_FORM_strp -> debug_str[0]
        uint32_t unit_len = static_cast<uint32_t>(debug_info.size() - 4);
        debug_info[0] = static_cast<uint8_t>(unit_len & 0xff);
        debug_info[1] = static_cast<uint8_t>((unit_len >> 8) & 0xff);
        debug_info[2] = static_cast<uint8_t>((unit_len >> 16) & 0xff);
        debug_info[3] = static_cast<uint8_t>((unit_len >> 24) & 0xff);

        std::vector<uint8_t> debug_str = {'o', 'k', 0};

        std::string vendor_elf = (dir / "vendor_form.elf").string();
        writeELFWithSections(vendor_elf, {
            {".debug_info", debug_info},
            {".debug_abbrev", debug_abbrev},
            {".debug_str", debug_str},
        });

        std::string out_text;
        int code_text = runAndCapture(dwarf_dump + " --show-support " + vendor_elf,
                                      "/tmp/dwarf_cli_support_vendor_form.txt", out_text);
        assert(code_text == 0);
        assertVendorTelemetryText(out_text, makeVendorTelemetryExpectations(
            2, {0x1f30}, {"fallback_offset_sized"}, {"unit_die_payload"},
            {{0x1f30, 2}}, {{"fallback_offset_sized", 2}}, {{"unit_die_payload", 2}}));
        // Dedup: repeated form+attr should still emit a single exemplar string.
        std::string text_examples = extractValueForTextKey(out_text, "vendor_form_skip_examples");
        assert(text_examples.find("die=0x") != std::string::npos);
        assert(text_examples.find("attr=DW_AT_type") != std::string::npos);
        assert(text_examples.find(';') == std::string::npos);

        std::string out_json;
        int code_json = runAndCapture(dwarf_dump + " --show-support --format=json " + vendor_elf,
                                      "/tmp/dwarf_cli_support_vendor_form_json.txt", out_json);
        assert(code_json == 0);
        {
            std::string runtime_obj = extractObjectForKey(out_json, "runtime");
            assert(!runtime_obj.empty());
            bool ok = false;
            assert(extractUIntFieldFromObject(runtime_obj, "vendor_form_skips", &ok) == 2 && ok);
            std::string examples = extractStringFieldFromObject(runtime_obj, "vendor_form_skip_examples");
            assert(!examples.empty());
            assert(examples.find("form=0x1f30") != std::string::npos);
            assert(examples.find("die=0x") != std::string::npos);
            assert(examples.find("attr=DW_AT_type") != std::string::npos);
            assert(examples.find(';') == std::string::npos);
            assert(extractStringFieldFromObject(runtime_obj, "vendor_form_skip_histogram") == "0x1f30:2");
            assert(extractStringFieldFromObject(runtime_obj, "vendor_form_skip_offset_buckets") ==
                   "unit_die_payload:2");
            assert(extractStringFieldFromObject(runtime_obj, "vendor_form_skip_severity_buckets") ==
                   "fallback_offset_sized:2");
        }

        std::string out_json_v2;
        int code_json_v2 = runAndCapture(
            dwarf_dump + " --show-support --format=json --schema-version=2 " + vendor_elf,
            "/tmp/dwarf_cli_support_vendor_form_json_v2.txt", out_json_v2);
        assert(code_json_v2 == 0);
        assertVendorTelemetryJsonV2(out_json_v2, makeVendorTelemetryExpectations(
            2, {0x1f30}, {"fallback_offset_sized"}, {"unit_die_payload"},
            {{0x1f30, 2}}, {{"fallback_offset_sized", 2}}, {{"unit_die_payload", 2}}));
        auto v2_examples = extractObjectsFromArrayKey(out_json_v2, "vendor_form_skip_examples_structured");
        assert(objectArrayContainsStringField(v2_examples, "attr", "DW_AT_type"));
    }

    {
        // Fixture with a known-shape vendor form (0x1f0e mirrors DW_FORM_strp).
        fs::path dir = fs::path("/tmp") / ("dwarf_cli_vendor_form_known_" + std::to_string(std::rand()));
        std::error_code ec;
        fs::create_directories(dir, ec);
        assert(fs::exists(dir));

        std::vector<uint8_t> debug_abbrev = {
            0x01,       // abbrev code
            0x11,       // DW_TAG_compile_unit
            0x00,       // no children
            0x49,       // DW_AT_type
            0x8e, 0x3e, // unknown vendor form 0x1f0e (ULEB128)
            0x03,       // DW_AT_name
            0x0e,       // DW_FORM_strp
            0x00, 0x00, // end attr specs
            0x00        // end abbrev table
        };

        std::vector<uint8_t> debug_info;
        appendU32LE(debug_info, 0); // unit_length placeholder
        appendU16LE(debug_info, 4); // version
        appendU32LE(debug_info, 0); // abbrev offset
        debug_info.push_back(0x08); // address size
        debug_info.push_back(0x01); // abbrev code
        appendU32LE(debug_info, 0x11223344); // mirrored strp-sized payload
        appendU32LE(debug_info, 0); // DW_FORM_strp -> debug_str[0]
        uint32_t unit_len = static_cast<uint32_t>(debug_info.size() - 4);
        debug_info[0] = static_cast<uint8_t>(unit_len & 0xff);
        debug_info[1] = static_cast<uint8_t>((unit_len >> 8) & 0xff);
        debug_info[2] = static_cast<uint8_t>((unit_len >> 16) & 0xff);
        debug_info[3] = static_cast<uint8_t>((unit_len >> 24) & 0xff);

        std::vector<uint8_t> debug_str = {'s', 't', 'r', 'p', 0};

        std::string vendor_elf = (dir / "vendor_form_known.elf").string();
        writeELFWithSections(vendor_elf, {
            {".debug_info", debug_info},
            {".debug_abbrev", debug_abbrev},
            {".debug_str", debug_str},
        });

        std::string out_text;
        int code_text = runAndCapture(dwarf_dump + " --show-support " + vendor_elf,
                                      "/tmp/dwarf_cli_support_vendor_form_known.txt", out_text);
        assert(code_text == 0);
        assertVendorTelemetryText(out_text, makeVendorTelemetryExpectations(
            1, {0x1f0e}, {"known_shape"}, {"unit_die_payload"},
            {{0x1f0e, 1}}, {{"known_shape", 1}}, {{"unit_die_payload", 1}}));

        std::string out_json_v2;
        int code_json_v2 = runAndCapture(
            dwarf_dump + " --show-support --format=json --schema-version=2 " + vendor_elf,
            "/tmp/dwarf_cli_support_vendor_form_known_json_v2.txt", out_json_v2);
        assert(code_json_v2 == 0);
        assertVendorTelemetryJsonV2(out_json_v2, makeVendorTelemetryExpectations(
            1, {0x1f0e}, {"known_shape"}, {"unit_die_payload"},
            {{0x1f0e, 1}}, {{"known_shape", 1}}, {{"unit_die_payload", 1}}));
    }

    {
        // Fixture with a known-shape non-0x1fxx vendor form (0x7f0e mirrors DW_FORM_strp).
        fs::path dir = fs::path("/tmp") / ("dwarf_cli_vendor_form_non1f_known_" + std::to_string(std::rand()));
        std::error_code ec;
        fs::create_directories(dir, ec);
        assert(fs::exists(dir));

        std::vector<uint8_t> debug_abbrev;
        appendULEB128(debug_abbrev, 0x01);
        appendULEB128(debug_abbrev, 0x11);
        debug_abbrev.push_back(0x00);
        appendULEB128(debug_abbrev, 0x49);
        appendULEB128(debug_abbrev, 0x7f0e);
        appendULEB128(debug_abbrev, 0x03);
        appendULEB128(debug_abbrev, 0x0e);
        debug_abbrev.push_back(0x00);
        debug_abbrev.push_back(0x00);
        debug_abbrev.push_back(0x00);

        std::vector<uint8_t> debug_info;
        appendU32LE(debug_info, 0);
        appendU16LE(debug_info, 4);
        appendU32LE(debug_info, 0);
        debug_info.push_back(0x08);
        debug_info.push_back(0x01);
        appendU32LE(debug_info, 0x11223344);
        appendU32LE(debug_info, 0);
        uint32_t unit_len = static_cast<uint32_t>(debug_info.size() - 4);
        debug_info[0] = static_cast<uint8_t>(unit_len & 0xff);
        debug_info[1] = static_cast<uint8_t>((unit_len >> 8) & 0xff);
        debug_info[2] = static_cast<uint8_t>((unit_len >> 16) & 0xff);
        debug_info[3] = static_cast<uint8_t>((unit_len >> 24) & 0xff);

        std::vector<uint8_t> debug_str = {'n', '1', 'f', 0};

        std::string vendor_elf = (dir / "vendor_form_non1f_known.elf").string();
        writeELFWithSections(vendor_elf, {
            {".debug_info", debug_info},
            {".debug_abbrev", debug_abbrev},
            {".debug_str", debug_str},
        });

        std::string out_text;
        int code_text = runAndCapture(dwarf_dump + " --show-support " + vendor_elf,
                                      "/tmp/dwarf_cli_support_vendor_form_non1f_known.txt", out_text);
        assert(code_text == 0);
        assertVendorTelemetryText(out_text, makeVendorTelemetryExpectations(
            1, {0x7f0e}, {"known_shape"}, {"unit_die_payload"},
            {{0x7f0e, 1}}, {{"known_shape", 1}}, {{"unit_die_payload", 1}}));

        std::string out_json_v2;
        int code_json_v2 = runAndCapture(
            dwarf_dump + " --show-support --format=json --schema-version=2 " + vendor_elf,
            "/tmp/dwarf_cli_support_vendor_form_non1f_known_json_v2.txt", out_json_v2);
        assert(code_json_v2 == 0);
        assertVendorTelemetryJsonV2(out_json_v2, makeVendorTelemetryExpectations(
            1, {0x7f0e}, {"known_shape"}, {"unit_die_payload"},
            {{0x7f0e, 1}}, {{"known_shape", 1}}, {{"unit_die_payload", 1}}));
    }

    {
        // Fixture mixing known-shape and fallback-offset-sized vendor-form recovery in one file.
        fs::path dir = fs::path("/tmp") / ("dwarf_cli_vendor_form_mixed_" + std::to_string(std::rand()));
        std::error_code ec;
        fs::create_directories(dir, ec);
        assert(fs::exists(dir));

        std::vector<uint8_t> debug_abbrev = {
            0x01,       // abbrev code
            0x11,       // DW_TAG_compile_unit
            0x00,       // no children
            0x49,       // DW_AT_type
            0x8e, 0x3e, // unknown vendor form 0x1f0e (known-shape strp)
            0x49,       // DW_AT_type
            0xb0, 0x3e, // unknown vendor form 0x1f30 (fallback offset-sized)
            0x03,       // DW_AT_name
            0x0e,       // DW_FORM_strp
            0x00, 0x00, // end attr specs
            0x00        // end abbrev table
        };

        std::vector<uint8_t> debug_info;
        appendU32LE(debug_info, 0); // unit_length placeholder
        appendU16LE(debug_info, 4); // version
        appendU32LE(debug_info, 0); // abbrev offset
        debug_info.push_back(0x08); // address size
        debug_info.push_back(0x01); // abbrev code
        appendU32LE(debug_info, 0x11223344); // known-shape mirrored strp payload
        appendU32LE(debug_info, 0x11223344); // fallback offset-sized payload
        appendU32LE(debug_info, 0); // DW_FORM_strp -> debug_str[0]
        uint32_t unit_len = static_cast<uint32_t>(debug_info.size() - 4);
        debug_info[0] = static_cast<uint8_t>(unit_len & 0xff);
        debug_info[1] = static_cast<uint8_t>((unit_len >> 8) & 0xff);
        debug_info[2] = static_cast<uint8_t>((unit_len >> 16) & 0xff);
        debug_info[3] = static_cast<uint8_t>((unit_len >> 24) & 0xff);

        std::vector<uint8_t> debug_str = {'m', 'i', 'x', 0};

        std::string vendor_elf = (dir / "vendor_form_mixed.elf").string();
        writeELFWithSections(vendor_elf, {
            {".debug_info", debug_info},
            {".debug_abbrev", debug_abbrev},
            {".debug_str", debug_str},
        });

        std::string out_text;
        int code_text = runAndCapture(dwarf_dump + " --show-support " + vendor_elf,
                                      "/tmp/dwarf_cli_support_vendor_form_mixed.txt", out_text);
        assert(code_text == 0);
        assertVendorTelemetryText(out_text, makeVendorTelemetryExpectations(
            2, {0x1f0e, 0x1f30}, {"known_shape", "fallback_offset_sized"}, {"unit_die_payload"},
            {{0x1f0e, 1}, {0x1f30, 1}},
            {{"known_shape", 1}, {"fallback_offset_sized", 1}},
            {{"unit_die_payload", 2}}));
        {
            std::string line = extractValueForTextKey(out_text, "vendor_form_skip_examples");
            assert(line.find("severity=known_shape") != std::string::npos);
            assert(line.find("severity=fallback_offset_sized") != std::string::npos);
            assert(line.find(';') != std::string::npos);
        }

        std::string out_json_v2;
        int code_json_v2 = runAndCapture(
            dwarf_dump + " --show-support --format=json --schema-version=2 " + vendor_elf,
            "/tmp/dwarf_cli_support_vendor_form_mixed_json_v2.txt", out_json_v2);
        assert(code_json_v2 == 0);
        assertVendorTelemetryJsonV2(out_json_v2, makeVendorTelemetryExpectations(
            2, {0x1f0e, 0x1f30}, {"known_shape", "fallback_offset_sized"}, {"unit_die_payload"},
            {{0x1f0e, 1}, {0x1f30, 1}},
            {{"known_shape", 1}, {"fallback_offset_sized", 1}},
            {{"unit_die_payload", 2}}));
    }

    {
        // Fixture with nested vendor-indirect recovery hitting newly covered known-shape families.
        fs::path dir = fs::path("/tmp") / ("dwarf_cli_vendor_form_nested_known_" + std::to_string(std::rand()));
        std::error_code ec;
        fs::create_directories(dir, ec);
        assert(fs::exists(dir));

        std::vector<uint8_t> debug_abbrev = {
            0x01,       // abbrev code
            0x11,       // DW_TAG_compile_unit
            0x00,       // no children
            0x49,       // DW_AT_type
            0x96, 0x3e, // unknown vendor form 0x1f16 (mirrored indirect)
            0x03,       // DW_AT_name
            0x0e,       // DW_FORM_strp
            0x00, 0x00, // end attr specs
            0x00        // end abbrev table
        };

        std::vector<uint8_t> debug_info;
        appendU32LE(debug_info, 0); // unit_length placeholder
        appendU16LE(debug_info, 4); // version
        appendU32LE(debug_info, 0); // abbrev offset
        debug_info.push_back(0x08); // address size
        debug_info.push_back(0x01); // abbrev code
        debug_info.push_back(0xa0); // ULEB 0x1f20 low byte mirror via vendor-indirect
        debug_info.push_back(0x3e);
        appendU64LE(debug_info, 0x1122334455667788ULL); // mirrored ref_sig8-sized payload
        appendU32LE(debug_info, 0); // DW_FORM_strp -> debug_str[0]
        uint32_t unit_len = static_cast<uint32_t>(debug_info.size() - 4);
        debug_info[0] = static_cast<uint8_t>(unit_len & 0xff);
        debug_info[1] = static_cast<uint8_t>((unit_len >> 8) & 0xff);
        debug_info[2] = static_cast<uint8_t>((unit_len >> 16) & 0xff);
        debug_info[3] = static_cast<uint8_t>((unit_len >> 24) & 0xff);

        std::vector<uint8_t> debug_str = {'n', 'e', 's', 't', 0};

        std::string vendor_elf = (dir / "vendor_form_nested_known.elf").string();
        writeELFWithSections(vendor_elf, {
            {".debug_info", debug_info},
            {".debug_abbrev", debug_abbrev},
            {".debug_str", debug_str},
        });

        std::string out_text;
        int code_text = runAndCapture(dwarf_dump + " --show-support " + vendor_elf,
                                      "/tmp/dwarf_cli_support_vendor_form_nested_known.txt", out_text);
        assert(code_text == 0);
        assertVendorTelemetryText(out_text, makeVendorTelemetryExpectations(
            1, {0x1f16}, {"known_shape"}, {"unit_die_payload"},
            {{0x1f16, 1}}, {{"known_shape", 1}}, {{"unit_die_payload", 1}}));

        std::string out_json_v2;
        int code_json_v2 = runAndCapture(
            dwarf_dump + " --show-support --format=json --schema-version=2 " + vendor_elf,
            "/tmp/dwarf_cli_support_vendor_form_nested_known_json_v2.txt", out_json_v2);
        assert(code_json_v2 == 0);
        assertVendorTelemetryJsonV2(out_json_v2, makeVendorTelemetryExpectations(
            1, {0x1f16}, {"known_shape"}, {"unit_die_payload"},
            {{0x1f16, 1}}, {{"known_shape", 1}}, {{"unit_die_payload", 1}}));
    }

    {
        // Fixture with nested non-0x1fxx vendor-indirect recovery hitting known-shape family.
        fs::path dir = fs::path("/tmp") / ("dwarf_cli_vendor_form_nested_non1f_known_" + std::to_string(std::rand()));
        std::error_code ec;
        fs::create_directories(dir, ec);
        assert(fs::exists(dir));

        std::vector<uint8_t> debug_abbrev;
        appendULEB128(debug_abbrev, 0x01);
        appendULEB128(debug_abbrev, 0x11);
        debug_abbrev.push_back(0x00);
        appendULEB128(debug_abbrev, 0x49);
        appendULEB128(debug_abbrev, 0x7f16);
        appendULEB128(debug_abbrev, 0x03);
        appendULEB128(debug_abbrev, 0x0e);
        debug_abbrev.push_back(0x00);
        debug_abbrev.push_back(0x00);
        debug_abbrev.push_back(0x00);

        std::vector<uint8_t> debug_info;
        appendU32LE(debug_info, 0);
        appendU16LE(debug_info, 4);
        appendU32LE(debug_info, 0);
        debug_info.push_back(0x08);
        debug_info.push_back(0x01);
        appendULEB128(debug_info, 0x7f20);
        appendU64LE(debug_info, 0x1122334455667788ULL);
        appendU32LE(debug_info, 0);
        uint32_t unit_len = static_cast<uint32_t>(debug_info.size() - 4);
        debug_info[0] = static_cast<uint8_t>(unit_len & 0xff);
        debug_info[1] = static_cast<uint8_t>((unit_len >> 8) & 0xff);
        debug_info[2] = static_cast<uint8_t>((unit_len >> 16) & 0xff);
        debug_info[3] = static_cast<uint8_t>((unit_len >> 24) & 0xff);

        std::vector<uint8_t> debug_str = {'x', 'n', 'e', 's', 't', 0};

        std::string vendor_elf = (dir / "vendor_form_nested_non1f_known.elf").string();
        writeELFWithSections(vendor_elf, {
            {".debug_info", debug_info},
            {".debug_abbrev", debug_abbrev},
            {".debug_str", debug_str},
        });

        std::string out_text;
        int code_text = runAndCapture(dwarf_dump + " --show-support " + vendor_elf,
                                      "/tmp/dwarf_cli_support_vendor_form_nested_non1f_known.txt", out_text);
        assert(code_text == 0);
        assertVendorTelemetryText(out_text, makeVendorTelemetryExpectations(
            1, {0x7f16}, {"known_shape"}, {"unit_die_payload"},
            {{0x7f16, 1}}, {{"known_shape", 1}}, {{"unit_die_payload", 1}}));

        std::string out_json_v2;
        int code_json_v2 = runAndCapture(
            dwarf_dump + " --show-support --format=json --schema-version=2 " + vendor_elf,
            "/tmp/dwarf_cli_support_vendor_form_nested_non1f_known_json_v2.txt", out_json_v2);
        assert(code_json_v2 == 0);
        assertVendorTelemetryJsonV2(out_json_v2, makeVendorTelemetryExpectations(
            1, {0x7f16}, {"known_shape"}, {"unit_die_payload"},
            {{0x7f16, 1}}, {{"known_shape", 1}}, {{"unit_die_payload", 1}}));
    }

    {
        std::string out;
        int code = runAndCapture(dwarf_dump + " --show-support --format=json", "/tmp/dwarf_cli_support_only_json.txt", out);
        assert(code == 0);
        assert(out.find("\"kind\":\"dwarf_support\"") != std::string::npos);
        assert(out.find("\"schema_version\":1") != std::string::npos);
        assert(out.find("\"rows\":[") != std::string::npos);
        assert(out.find("\"DW_FORM_implicit_const\"") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " --show-support --format=json --schema-version=2",
            "/tmp/dwarf_cli_support_only_json_v2.txt", out);
        assert(code == 0);
        assert(out.find("\"schema_version\":2") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(dwarf_dump + " --show-support --format=json " + test_elf, "/tmp/dwarf_cli_support_with_file_json.txt", out);
        assert(code == 0);
        assert(out.find("\"runtime\":{") != std::string::npos);
        assert(out.find("\"has_split_dwarf\":") != std::string::npos);
        assert(out.find("\"has_loaded_dwp\":") != std::string::npos);
        assert(out.find("\"dwp_path\":") != std::string::npos);
        assert(out.find("\"has_dwp_cu_index\":") != std::string::npos);
        assert(out.find("\"dwp_cu_index_valid\":") != std::string::npos);
        assert(out.find("\"dwp_cu_index_units\":") != std::string::npos);
        assert(out.find("\"has_dwp_tu_index\":") != std::string::npos);
        assert(out.find("\"dwp_tu_index_valid\":") != std::string::npos);
        assert(out.find("\"dwp_tu_index_units\":") != std::string::npos);
        assert(out.find("\"dwp_hits\":") != std::string::npos);
        assert(out.find("\"dwo_hits\":") != std::string::npos);
        assert(out.find("\"dwo_fallback_hits\":") != std::string::npos);
        assert(out.find("\"fallback_no_index\":") != std::string::npos);
        assert(out.find("\"fallback_invalid_index\":") != std::string::npos);
        assert(out.find("\"fallback_sig_miss\":") != std::string::npos);
        assert(out.find("\"has_debug_names\":") != std::string::npos);
        assert(out.find("\"vendor_form_skips\":") != std::string::npos);
        assert(out.find("\"vendor_form_skip_examples\":") != std::string::npos);
        assert(out.find("\"vendor_form_skip_histogram\":") != std::string::npos);
        assert(out.find("\"vendor_form_skip_offset_buckets\":") != std::string::npos);
        assert(out.find("\"vendor_form_skip_severity_buckets\":") != std::string::npos);
    }

    {
        std::string main_path, dwp_path;
        writeSplitFallbackFixture("sig_miss",
                                  /*include_cu_index=*/true,
                                  /*malformed_cu_index=*/false,
                                  /*signature_miss=*/true,
                                  main_path, dwp_path);
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " --show-support -v --dwp=" + dwp_path + " " + main_path,
            "/tmp/dwarf_cli_support_sig_miss_verbose.txt", out);
        assert(code == 0);
        assert(out.find("fallback reason=signature_not_found") != std::string::npos);
        assert(out.find("dwo_fallback_hits=1") != std::string::npos);
        assert(out.find("fallback_sig_miss=1") != std::string::npos);
    }

    {
        std::string main_path, dwp_path;
        writeSplitFallbackFixture("bad_index",
                                  /*include_cu_index=*/true,
                                  /*malformed_cu_index=*/true,
                                  /*signature_miss=*/false,
                                  main_path, dwp_path);
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " --show-support -v --dwp=" + dwp_path + " " + main_path,
            "/tmp/dwarf_cli_support_bad_index_verbose.txt", out);
        assert(code == 0);
        assert(out.find("fallback reason=invalid_cu_index") != std::string::npos);
        assert(out.find("dwo_fallback_hits=1") != std::string::npos);
        assert(out.find("fallback_invalid_index=1") != std::string::npos);
    }

    {
        std::string main_path, dwp_path;
        writeSplitFallbackFixture("no_index",
                                  /*include_cu_index=*/false,
                                  /*malformed_cu_index=*/false,
                                  /*signature_miss=*/false,
                                  main_path, dwp_path);
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " --show-support -v --dwp=" + dwp_path + " " + main_path,
            "/tmp/dwarf_cli_support_no_index_verbose.txt", out);
        assert(code == 0);
        assert(out.find("fallback reason=no_cu_index") != std::string::npos);
        assert(out.find("dwo_fallback_hits=1") != std::string::npos);
        assert(out.find("fallback_no_index=1") != std::string::npos);
    }

    {
        std::string main_path, dwp_path;
        writeSplitFallbackFixture("summary_dwp",
                                  /*include_cu_index=*/true,
                                  /*malformed_cu_index=*/false,
                                  /*signature_miss=*/true,
                                  main_path, dwp_path);
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " --summary --dwp=" + dwp_path + " " + main_path,
            "/tmp/dwarf_cli_summary_with_dwp.txt", out);
        assert(code == 0);
        assert(out.find("Has loaded DWP: yes") != std::string::npos);
        assert(out.find("DWP path: " + dwp_path) != std::string::npos);
        assert(out.find("Has DWP CU index: yes") != std::string::npos);
        assert(out.find("DWP CU index valid: yes") != std::string::npos);
        assert(out.find("DWP indexed units: 1") != std::string::npos);
        assert(out.find("Has DWP TU index: no") != std::string::npos);
        assert(out.find("DWP TU index valid: no") != std::string::npos);
        assert(out.find("DWP TU indexed units: 0") != std::string::npos);
    }

    {
        std::string main_path, dwp_path;
        writeSplitTUOnlyFixture("tu_only", main_path, dwp_path);
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " --show-support --dwp=" + dwp_path + " " + main_path,
            "/tmp/dwarf_cli_support_tu_only.txt", out);
        assert(code == 0);
        assert(out.find("has_dwp_cu_index=no") != std::string::npos);
        assert(out.find("dwp_path=" + dwp_path) != std::string::npos);
        assert(out.find("has_dwp_tu_index=yes") != std::string::npos);
        assert(out.find("dwp_tu_index_valid=yes") != std::string::npos);
        assert(out.find("dwp_tu_index_units=1") != std::string::npos);
        assert(out.find("dwp_hits=1") != std::string::npos);
        assert(out.find("dwo_fallback_hits=0") != std::string::npos);
    }

    {
        std::string main_path, dwp_path;
        writeSplitTUOnlyFixture("tu_only_json", main_path, dwp_path);
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " --show-support --format=json --dwp=" + dwp_path + " " + main_path,
            "/tmp/dwarf_cli_support_tu_only_json.txt", out);
        assert(code == 0);
        assert(out.find("\"has_dwp_cu_index\":false") != std::string::npos);
        assert(out.find("\"dwp_path\":\"" + dwp_path + "\"") != std::string::npos);
        assert(out.find("\"has_dwp_tu_index\":true") != std::string::npos);
        assert(out.find("\"dwp_tu_index_valid\":true") != std::string::npos);
        assert(out.find("\"dwp_tu_index_units\":1") != std::string::npos);
        assert(out.find("\"dwp_hits\":1") != std::string::npos);
        assert(out.find("\"dwo_fallback_hits\":0") != std::string::npos);
    }

    {
        std::string main_path, dwp_path;
        writeSplitTUOnlyFixture("tu_summary", main_path, dwp_path);
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " --summary --dwp=" + dwp_path + " " + main_path,
            "/tmp/dwarf_cli_summary_tu_only.txt", out);
        assert(code == 0);
        assert(out.find("Has DWP CU index: no") != std::string::npos);
        assert(out.find("Has DWP TU index: yes") != std::string::npos);
        assert(out.find("DWP TU index valid: yes") != std::string::npos);
        assert(out.find("DWP TU indexed units: 1") != std::string::npos);
    }

    {
        std::string main_path, dwp_path;
        writeSplitUnknownSectionFixture("unknown_cu_verbose", /*tu_index=*/false, 0x44, main_path, dwp_path);
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " --show-support -v --dwp=" + dwp_path + " " + main_path,
            "/tmp/dwarf_cli_support_unknown_cu_verbose.txt", out);
        assert(code == 0);
        assert(out.find("unknown DWP section ids\tsupported") != std::string::npos);
        assert(out.find("unknown_dwp_cu_section_ids=0x44") != std::string::npos);
        assert(out.find("unknown_dwp_tu_section_ids=") == std::string::npos);
    }

    {
        std::string main_path, dwp_path;
        writeSplitUnknownSectionFixture("unknown_tu_json", /*tu_index=*/true, 0x55, main_path, dwp_path);
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " --show-support --format=json --schema-version=2 --dwp=" + dwp_path + " " + main_path,
            "/tmp/dwarf_cli_support_unknown_tu_json.txt", out);
        assert(code == 0);
        assert(out.find("\"feature\":\"unknown DWP section ids\",\"status\":\"supported\"") != std::string::npos);
        assert(out.find("\"unknown_dwp_tu_section_ids\":[85]") != std::string::npos);
        assert(out.find("\"unknown_dwp_cu_section_ids\":") == std::string::npos);
    }

    {
        const std::string tool = findDWPTool();
        if (tool.empty()) {
            std::cout << "Skipping real tool-produced DWP CLI fixture test: no dwp/llvm-dwp available"
                      << " (test auto-activates when either tool is installed)\n";
        } else {
            fs::path dir = fs::path("/tmp") / ("dwarf_cli_real_dwp_" + std::to_string(std::rand()));
            std::error_code ec;
            fs::create_directories(dir, ec);
            assert(fs::exists(dir));

            std::string obj_path;
            std::string dwo_path;
            bool built = tryBuildRealSplitDwarfFixture(dir.string(), obj_path, dwo_path);
            if (!built) {
                std::cout << "Skipping real tool-produced DWP CLI fixture test: no suitable compiler output\n";
            } else {
                std::string dwp_path = (dir / "real_cli_fixture.dwp").string();
                bool packaged = buildRealDWPFromTool(dir.string(), obj_path, dwp_path);
                if (!packaged) {
                    std::cout << "Skipping real tool-produced DWP CLI fixture test: "
                              << tool << " did not produce a usable package\n";
                } else {
                    std::error_code rename_ec;
                    fs::rename(dwo_path, dwo_path + ".hidden", rename_ec);
                    assert(!rename_ec);

                    std::string out;
                    int code = runAndCapture(
                        dwarf_dump + " --show-support --dwp=" + dwp_path + " " + obj_path,
                        "/tmp/dwarf_cli_real_tool_dwp_support.txt", out);
                    assert(code == 0);
                    assert(out.find("has_loaded_dwp=yes") != std::string::npos);
                    assert(out.find("dwp_path=" + dwp_path) != std::string::npos);
                    assert(out.find("dwp_hits=") != std::string::npos);
                }
            }
        }
    }

    {
        std::string out;
        int code = runAndCapture(dwarf_dump + " --format=json " + test_elf, "/tmp/dwarf_cli_bad_main_format_scope.txt", out);
        assert(code == 1);
        assert(out.find("--format is only supported with --show-support") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " --schema-version=2 " + test_elf,
            "/tmp/dwarf_cli_bad_main_schema_scope.txt", out);
        assert(code == 1);
        assert(out.find("--schema-version is only supported with --show-support") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " --show-support --schema-version=2 " + test_elf,
            "/tmp/dwarf_cli_bad_main_schema_requires_json.txt", out);
        assert(code == 1);
        assert(out.find("--schema-version requires --format=json") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " --show-support --format=json --schema-version=9 " + test_elf,
            "/tmp/dwarf_cli_bad_main_schema_unsupported.txt", out);
        assert(code == 1);
        assert(out.find("unsupported --schema-version 9") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --register-count=0 --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_bad_regcount.txt", out);
        assert(code == 1);
        assert(out.find("invalid --register-count") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " --die-offset=bad " + test_elf,
            "/tmp/dwarf_cli_bad_die_offset.txt", out);
        assert(code == 1);
        assert(out.find("invalid --die-offset") != std::string::npos);
    }

    {
        std::string out;
        const std::string names_bin = firstExisting({"./test_data/debug_names_real_world.bin",
                                                     "../test_data/debug_names_real_world.bin"});
        const std::string names_str = firstExisting({"./test_data/debug_names_real_world.str",
                                                     "../test_data/debug_names_real_world.str"});
        assert(!names_bin.empty());
        assert(!names_str.empty());

        const auto debug_names = readBinaryFile(names_bin);
        const auto debug_str = readBinaryFile(names_str);
        assert(!debug_names.empty());
        assert(!debug_str.empty());

        std::vector<uint8_t> debug_abbrev = {
            0x01, 0x11, 0x00, 0x00, 0x00, 0x00
        };

        std::vector<uint8_t> debug_info;
        appendU32LE(debug_info, 0); // unit_length placeholder
        appendU16LE(debug_info, 5); // version
        debug_info.push_back(0x01); // DW_UT_compile
        debug_info.push_back(0x08); // address_size
        appendU32LE(debug_info, 0); // abbrev offset
        debug_info.push_back(0x01); // abbrev code
        const uint32_t unit_len = static_cast<uint32_t>(debug_info.size() - 4);
        debug_info[0] = static_cast<uint8_t>(unit_len & 0xff);
        debug_info[1] = static_cast<uint8_t>((unit_len >> 8) & 0xff);
        debug_info[2] = static_cast<uint8_t>((unit_len >> 16) & 0xff);
        debug_info[3] = static_cast<uint8_t>((unit_len >> 24) & 0xff);

        std::string names_elf = (fs::temp_directory_path() / "dwarf_cli_debug_names_fixture.elf").string();
        writeELFWithSections(names_elf, {
            {".debug_info", debug_info},
            {".debug_abbrev", debug_abbrev},
            {".debug_str", debug_str},
            {".debug_names", debug_names},
        });

        int code = runAndCapture(
            dwarf_dump + " -n " + names_elf,
            "/tmp/dwarf_cli_debug_names.txt", out);
        assert(code == 0);
        assert(out.find(".debug_names contents:") != std::string::npos);
        assert(out.find("Unit count: 2") != std::string::npos);
        assert(out.find("Unit 0:") != std::string::npos);
        assert(out.find("Unit 1:") != std::string::npos);
        assert(out.find("version: 5") != std::string::npos);
        assert(out.find("comp_units: 1") != std::string::npos);
        assert(out.find("names: 1") != std::string::npos);
    }

    {
        std::string out;
        const std::string names_bin = firstExisting({"./test_data/debug_names_real_world_mixed.bin",
                                                     "../test_data/debug_names_real_world_mixed.bin"});
        const std::string names_str = firstExisting({"./test_data/debug_names_real_world_mixed.str",
                                                     "../test_data/debug_names_real_world_mixed.str"});
        assert(!names_bin.empty());
        assert(!names_str.empty());

        const auto debug_names = readBinaryFile(names_bin);
        const auto debug_str = readBinaryFile(names_str);
        assert(!debug_names.empty());
        assert(!debug_str.empty());

        std::vector<uint8_t> debug_abbrev = {
            0x01, 0x11, 0x00, 0x00, 0x00, 0x00
        };

        std::vector<uint8_t> debug_info;
        appendU32LE(debug_info, 0); // unit_length placeholder
        appendU16LE(debug_info, 5); // version
        debug_info.push_back(0x01); // DW_UT_compile
        debug_info.push_back(0x08); // address_size
        appendU32LE(debug_info, 0); // abbrev offset
        debug_info.push_back(0x01); // abbrev code
        const uint32_t unit_len = static_cast<uint32_t>(debug_info.size() - 4);
        debug_info[0] = static_cast<uint8_t>(unit_len & 0xff);
        debug_info[1] = static_cast<uint8_t>((unit_len >> 8) & 0xff);
        debug_info[2] = static_cast<uint8_t>((unit_len >> 16) & 0xff);
        debug_info[3] = static_cast<uint8_t>((unit_len >> 24) & 0xff);

        std::string names_elf = (fs::temp_directory_path() / "dwarf_cli_debug_names_mixed_fixture.elf").string();
        writeELFWithSections(names_elf, {
            {".debug_info", debug_info},
            {".debug_abbrev", debug_abbrev},
            {".debug_str", debug_str},
            {".debug_names", debug_names},
        });

        int code = runAndCapture(
            dwarf_dump + " -n " + names_elf,
            "/tmp/dwarf_cli_debug_names_mixed.txt", out);
        assert(code == 0);
        assert(out.find(".debug_names contents:") != std::string::npos);
        assert(out.find("Unit count: 2") != std::string::npos);
        assert(out.find("local_type_units: 1") != std::string::npos);
        assert(out.find("foreign_type_units: 1") != std::string::npos);
        assert(out.find("augmentation_vendor: GDB") != std::string::npos);
        assert(out.find("augmentation_payload_size: 7") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --no-differential --differential-trials=0 --register-count=16 --seed=0x1234 "
                "--cfa=0x1000 --frame-base=0x2000 --tls-base=0x3000 --object-address=0x4000 "
                "--address-size=8 --offset-size=4 --reg=0:0x55 "
                "--allow-unknown --allow-missing --max-rows=1",
            "/tmp/dwarf_cli_ok.txt", out);
        assert(code == 0);
        assert(out.find("summary total=") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --range-aware --normalize-loc --reloc-check "
                "--min-equivalent-coverage=0.0 --max-different-coverage=1.0 "
                "--allow-unknown --allow-missing --max-rows=1",
            "/tmp/dwarf_cli_range_aware_ok.txt", out);
        assert(code == 0);
        assert(out.find("summary total=") != std::string::npos);
    }

    {
        std::vector<uint8_t> lit4 = {0x34, 0x9f}; // DW_OP_lit4; DW_OP_stack_value
        std::vector<std::tuple<uint64_t, uint64_t, std::vector<uint8_t>>> lhs_segments = {
            {0x10, 0x18, lit4},
            {0x18, 0x20, lit4},
        };
        std::vector<std::tuple<uint64_t, uint64_t, std::vector<uint8_t>>> rhs_segments = {
            {0x10, 0x20, lit4},
            {0x20, 0x30, lit4},
        };

        std::string lhs_loc_elf = makeSingleVariableLoclistELF("dwarf_cli_range_loc_lhs", "range_norm", lhs_segments);
        std::string rhs_loc_elf = makeSingleVariableLoclistELF("dwarf_cli_range_loc_rhs", "range_norm", rhs_segments);

        std::string out_text;
        int code_text = runAndCapture(
            dwarf_dump + " compare-expr " + lhs_loc_elf + " " + rhs_loc_elf +
                " --name=range_norm --range-aware --normalize-loc --allow-unknown --allow-missing --report-only",
            "/tmp/dwarf_cli_range_aware_loclists_text.txt", out_text);
        assert(code_text == 0);
        assert(out_text.find("normalization_note") != std::string::npos);
        assert(out_text.find("normalization_groups=") != std::string::npos);
        assert(out_text.find("coverage_total=32") != std::string::npos);
#if DWARF_HAS_Z3
        assert(out_text.find("coverage_eq=16") != std::string::npos);
        assert(out_text.find("coverage_unknown=0") != std::string::npos);
        assert(out_text.find("coverage_uncovered=16") != std::string::npos);
        assert(out_text.find("|32|16|0|0|0|16|0|") != std::string::npos);
#else
        assert(out_text.find("coverage_eq=0") != std::string::npos);
        assert(out_text.find("coverage_unknown=16") != std::string::npos);
        assert(out_text.find("coverage_uncovered=16") != std::string::npos);
        assert(out_text.find("|32|0|0|16|0|16|0|") != std::string::npos);
#endif

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + lhs_loc_elf + " " + rhs_loc_elf +
                " --name=range_norm --range-aware --normalize-loc --allow-unknown --allow-missing --report-only --format=json --schema-version=1",
            "/tmp/dwarf_cli_range_aware_loclists_json.txt", out_json);
        assert(code_json == 0);
        std::string row_json = extractFirstObjectFromArrayKey(out_json, "comparisons");
        assert(!row_json.empty());
        assert(row_json.find("\"range_aware\":true") != std::string::npos);
        assert(row_json.find("\"coverage_total\":32") != std::string::npos);
#if DWARF_HAS_Z3
        assert(row_json.find("\"coverage_equivalent\":16") != std::string::npos);
        assert(row_json.find("\"coverage_unknown\":0") != std::string::npos);
        assert(row_json.find("\"coverage_uncovered\":16") != std::string::npos);
#else
        assert(row_json.find("\"coverage_equivalent\":0") != std::string::npos);
        assert(row_json.find("\"coverage_unknown\":16") != std::string::npos);
        assert(row_json.find("\"coverage_uncovered\":16") != std::string::npos);
#endif
        assert(row_json.find("\"range_segments\"") != std::string::npos);
        assert(row_json.find("\"normalization_note\"") != std::string::npos);
        assert(row_json.find("\"start\":16") != std::string::npos);
        assert(row_json.find("\"end\":32") != std::string::npos);
        std::string range_report_json = extractObjectForKey(out_json, "report");
        std::string range_summary_json = extractObjectForKey(range_report_json, "summary");
        assert(!range_summary_json.empty());
        assert(range_summary_json.find("\"normalization_groups\"") != std::string::npos);
        auto norm_segments = extractObjectsFromArrayKey(row_json, "range_segments");
        assert(norm_segments.size() == 2);
        assert(norm_segments[0].find("\"start\":16") != std::string::npos);
        assert(norm_segments[0].find("\"end\":32") != std::string::npos);
        assert(norm_segments[0].find("\"normalization_note\":\"normalization eliminated the mismatch\"") != std::string::npos);
#if DWARF_HAS_Z3
        assert(norm_segments[0].find("\"verdict\":\"EQUIVALENT\"") != std::string::npos);
#else
        assert(norm_segments[0].find("\"verdict\":\"UNKNOWN\"") != std::string::npos);
#endif
        assert(norm_segments[1].find("\"start\":32") != std::string::npos);
        assert(norm_segments[1].find("\"end\":48") != std::string::npos);
        assert(norm_segments[1].find("\"lhs_present\":false") != std::string::npos);

        std::string out_json_raw;
        int code_json_raw = runAndCapture(
            dwarf_dump + " compare-expr " + lhs_loc_elf + " " + rhs_loc_elf +
                " --name=range_norm --range-aware --normalization-policy=off --allow-unknown --allow-missing --report-only --format=json --schema-version=1",
            "/tmp/dwarf_cli_range_aware_loclists_json_raw.txt", out_json_raw);
        assert(code_json_raw == 0);
        std::string row_json_raw = extractFirstObjectFromArrayKey(out_json_raw, "comparisons");
        assert(!row_json_raw.empty());
        auto raw_segments = extractObjectsFromArrayKey(row_json_raw, "range_segments");
        assert(raw_segments.size() == 3);
        assert(raw_segments[0].find("\"start\":16") != std::string::npos);
        assert(raw_segments[0].find("\"end\":24") != std::string::npos);
        assert(raw_segments[1].find("\"start\":24") != std::string::npos);
        assert(raw_segments[1].find("\"end\":32") != std::string::npos);
        assert(raw_segments[2].find("\"start\":32") != std::string::npos);
        assert(raw_segments[2].find("\"end\":48") != std::string::npos);

        std::string gate_text;
        int gate_code = runAndCapture(
            dwarf_dump + " compare-expr " + lhs_loc_elf + " " + rhs_loc_elf +
                " --name=range_norm --range-aware --normalize-loc --allow-unknown --allow-missing"
                " --max-different=100000 --max-unknown=100000 --fail-on-uncovered",
            "/tmp/dwarf_cli_range_aware_loclists_gate_text.txt", gate_text);
        assert(gate_code == 2);
        assert(gate_text.find("uncovered range-aware segments are disallowed") != std::string::npos);

        std::string gate_json;
        int gate_json_code = runAndCapture(
            dwarf_dump + " compare-expr " + lhs_loc_elf + " " + rhs_loc_elf +
                " --name=range_norm --range-aware --normalize-loc --allow-unknown --allow-missing"
                " --max-different=100000 --max-unknown=100000 --fail-on-uncovered --format=json --schema-version=1",
            "/tmp/dwarf_cli_range_aware_loclists_gate_json.txt", gate_json);
        assert(gate_json_code == 2);
        assert(gate_json.find("\"trigger\":\"fail_on_uncovered\"") != std::string::npos);
        assert(gate_json.find("\"trigger_detail\":\"16\"") != std::string::npos);

        std::string eq_gate_text;
        int eq_gate_code = runAndCapture(
            dwarf_dump + " compare-expr " + lhs_loc_elf + " " + rhs_loc_elf +
                " --name=range_norm --range-aware --normalize-loc --allow-unknown --allow-missing"
                " --max-different=100000 --max-unknown=100000 --min-equivalent-coverage=0.6",
            "/tmp/dwarf_cli_range_aware_loclists_eq_gate_text.txt", eq_gate_text);
        assert(eq_gate_code == 2);
        assert(eq_gate_text.find("equivalent coverage ratio below minimum") != std::string::npos);

        std::string eq_gate_json;
        int eq_gate_json_code = runAndCapture(
            dwarf_dump + " compare-expr " + lhs_loc_elf + " " + rhs_loc_elf +
                " --name=range_norm --range-aware --normalize-loc --allow-unknown --allow-missing"
                " --max-different=100000 --max-unknown=100000 --min-equivalent-coverage=0.6 --format=json --schema-version=1",
            "/tmp/dwarf_cli_range_aware_loclists_eq_gate_json.txt", eq_gate_json);
        assert(eq_gate_json_code == 2);
        assert(eq_gate_json.find("\"trigger\":\"min_equivalent_coverage\"") != std::string::npos);
#if DWARF_HAS_Z3
        assert(eq_gate_json.find("\"trigger_detail\":\"0.500000/0.600000\"") != std::string::npos);
#else
        assert(eq_gate_json.find("\"trigger_detail\":\"0.000000/0.600000\"") != std::string::npos);
#endif
    }

    {
        std::vector<uint8_t> lit4 = {0x34, 0x9f}; // DW_OP_lit4; DW_OP_stack_value
        std::vector<uint8_t> lit5 = {0x35, 0x9f}; // DW_OP_lit5; DW_OP_stack_value
        std::vector<std::tuple<uint64_t, uint64_t, std::vector<uint8_t>>> lhs_segments = {
            {0x10, 0x20, lit4},
            {0x20, 0x30, lit4},
        };
        std::vector<std::tuple<uint64_t, uint64_t, std::vector<uint8_t>>> rhs_segments = {
            {0x10, 0x20, lit5},
            {0x20, 0x30, lit4},
        };

        std::string lhs_loc_elf = makeSingleVariableLoclistELF("dwarf_cli_range_diff_lhs", "range_diff", lhs_segments);
        std::string rhs_loc_elf = makeSingleVariableLoclistELF("dwarf_cli_range_diff_rhs", "range_diff", rhs_segments);

        std::string diff_text;
        int diff_code = runAndCapture(
            dwarf_dump + " compare-expr " + lhs_loc_elf + " " + rhs_loc_elf +
                " --name=range_diff --range-aware --normalize-loc --allow-unknown --allow-missing --report-only",
            "/tmp/dwarf_cli_range_aware_diff_text.txt", diff_text);
        assert(diff_code == 0);
        assert(diff_text.find("coverage_total=32") != std::string::npos);
#if DWARF_HAS_Z3
        assert(diff_text.find("coverage_eq=16") != std::string::npos);
        assert(diff_text.find("coverage_diff=16") != std::string::npos);
#else
        assert(diff_text.find("coverage_eq=0") != std::string::npos);
        assert(diff_text.find("coverage_diff=0") != std::string::npos);
        assert(diff_text.find("coverage_unknown=32") != std::string::npos);
#endif

        std::string diff_gate_json;
        int diff_gate_code = runAndCapture(
            dwarf_dump + " compare-expr " + lhs_loc_elf + " " + rhs_loc_elf +
                " --name=range_diff --range-aware --normalize-loc --allow-unknown --allow-missing"
                " --max-unknown=100000 --max-different=100000 --max-different-coverage=0.4 --format=json --schema-version=1",
            "/tmp/dwarf_cli_range_aware_diff_gate_json.txt", diff_gate_json);
#if DWARF_HAS_Z3
        assert(diff_gate_code == 2);
        assert(diff_gate_json.find("\"trigger\":\"max_different_coverage\"") != std::string::npos);
        assert(diff_gate_json.find("\"trigger_detail\":\"0.500000/0.400000\"") != std::string::npos);
#else
        assert(diff_gate_code == 0);
        assert(diff_gate_json.find("\"pass\":true") != std::string::npos);
        assert(diff_gate_json.find("\"trigger\":\"none\"") != std::string::npos);
#endif
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --min-equivalent-coverage=1.5",
            "/tmp/dwarf_cli_bad_ratio.txt", out);
        assert(code == 1);
        assert(out.find("invalid --min-equivalent-coverage") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --summary-only",
            "/tmp/dwarf_cli_verify_reloc_summary.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("summary total=") != std::string::npos);
        assert(out.find("errors=") != std::string::npos);
        assert(out.find("warnings=") != std::string::npos);
        assert(out.find("section_debug_str_offsets=") != std::string::npos);
        assert(out.find("section_debug_loclists=") != std::string::npos);
        assert(out.find("section_debug_rnglists=") != std::string::npos);
        assert(out.find("code_counts=") != std::string::npos);
        assert(out.find("top_codes=") != std::string::npos);
        assert(out.find("sort_issues=") != std::string::npos);
        assert(out.find("sort_top_codes=") != std::string::npos);
        assert(out.find("verify_profile=") != std::string::npos);
        assert(out.find("gate_profile=") != std::string::npos);
        assert(out.find("explain_gate_mode=") != std::string::npos);
        assert(out.find("min_count=") != std::string::npos);
        assert(out.find("max_total=") != std::string::npos);
        assert(out.find("max_per_code=") != std::string::npos);
        assert(out.find("max_per_section=") != std::string::npos);
        assert(out.find("fail_on_codes=") != std::string::npos);
        assert(out.find("fail_on_sections=") != std::string::npos);
        assert(out.find("only_codes=") != std::string::npos);
        assert(out.find("only_sections=") != std::string::npos);
        assert(out.find("only_severities=") != std::string::npos);
        assert(out.find("verify_features=") != std::string::npos);
        assert(out.find("normalization_policy=") != std::string::npos);
        assert(out.find("gate_trigger=") != std::string::npos);
        assert(out.find("gate_trigger_detail=") != std::string::npos);
        assert(out.find("gate_signature=") != std::string::npos);
        assert(out.find("gate_observed=") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --summary-only --explain-gate",
            "/tmp/dwarf_cli_verify_reloc_explain_gate_text.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("explain_gate_mode=always") != std::string::npos);
        assert(out.find("gate_explanation=") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --format=json --summary-only",
            "/tmp/dwarf_cli_verify_reloc_json.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("\"summary\"") != std::string::npos);
        assert(out.find("\"section_counts\"") != std::string::npos);
        assert(out.find("\"code_counts\"") != std::string::npos);
        assert(out.find("\"top_codes\"") != std::string::npos);
        assert(out.find("\"sort_issues\"") != std::string::npos);
        assert(out.find("\"sort_top_codes\"") != std::string::npos);
        assert(out.find("\"verify_profile\"") != std::string::npos);
        assert(out.find("\"gate_profile\"") != std::string::npos);
        assert(out.find("\"explain_gate_mode\"") != std::string::npos);
        assert(out.find("\"min_count\"") != std::string::npos);
        assert(out.find("\"max_total\"") != std::string::npos);
        assert(out.find("\"max_per_code\"") != std::string::npos);
        assert(out.find("\"max_per_section\"") != std::string::npos);
        assert(out.find("\"fail_on_codes\"") != std::string::npos);
        assert(out.find("\"fail_on_sections\"") != std::string::npos);
        assert(out.find("\"only_codes\"") != std::string::npos);
        assert(out.find("\"only_sections\"") != std::string::npos);
        assert(out.find("\"only_severities\"") != std::string::npos);
        assert(out.find("\"verify_features\"") != std::string::npos);
        assert(out.find("\"normalization_policy\"") != std::string::npos);
        assert(out.find("\"gate\"") != std::string::npos);
        assert(out.find("\"trigger\"") != std::string::npos);
        assert(out.find("\"trigger_detail\"") != std::string::npos);
        assert(out.find("\"signature\"") != std::string::npos);
        assert(out.find("\"observed\"") != std::string::npos);
        assert(out.find("\"thresholds\"") != std::string::npos);
        assert(out.find("\"issues\"") == std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --summary-only --emit-gate-signature-only",
            "/tmp/dwarf_cli_verify_reloc_sig_only_text.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("gate_signature=") != std::string::npos);
        assert(out.find("summary total=") == std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --summary-only --emit-profile-only",
            "/tmp/dwarf_cli_verify_reloc_profile_only_text.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("verify_profile=") != std::string::npos);
        assert(out.find("verify_features=") != std::string::npos);
        assert(out.find("normalization_policy=") != std::string::npos);
        assert(out.find("gate_trigger=") != std::string::npos);
        assert(out.find("gate_signature=") != std::string::npos);
        assert(out.find("summary total=") == std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --format=json --summary-only --emit-gate-signature-only",
            "/tmp/dwarf_cli_verify_reloc_sig_only_json.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("\"gate\"") != std::string::npos);
        assert(out.find("\"signature\"") != std::string::npos);
        assert(out.find("\"summary\"") == std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --format=json --summary-only --emit-profile-only",
            "/tmp/dwarf_cli_verify_reloc_profile_only_json.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("\"profile\"") != std::string::npos);
        assert(out.find("\"verify_profile\"") != std::string::npos);
        assert(out.find("\"verify_features\"") != std::string::npos);
        assert(out.find("\"normalization_policy\"") != std::string::npos);
        assert(out.find("\"gate\"") != std::string::npos);
        assert(out.find("\"trigger\"") != std::string::npos);
        assert(out.find("\"thresholds\"") != std::string::npos);
        assert(out.find("\"gate_signature\"") != std::string::npos);
        assert(out.find("\"summary\"") == std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --verify-features=none",
            "/tmp/dwarf_cli_verify_reloc_features_none.txt", out);
        assert(code == 0);
        assert(out.find("verify_features=none") != std::string::npos);
        assert(out.find("normalization_policy=off") != std::string::npos);
        assert(out.find("summary total=0") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --verify-profile=off",
            "/tmp/dwarf_cli_verify_reloc_profile_off.txt", out);
        assert(code == 0);
        assert(out.find("verify_features=none") != std::string::npos);
        assert(out.find("normalization_policy=off") != std::string::npos);
        assert(out.find("summary total=0") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --verify-profile=strict",
            "/tmp/dwarf_cli_verify_reloc_profile_strict.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("gate_profile=strict") != std::string::npos);
        assert(out.find("verify_features=section-reloc,loc-normalize,range-aware") != std::string::npos);
        assert(out.find("normalization_policy=symbolic_canonical") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --verify-features=none,section-reloc",
            "/tmp/dwarf_cli_verify_reloc_features_section_only.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("verify_features=section-reloc") != std::string::npos);
        assert(out.find("normalization_policy=off") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --normalize-loc",
            "/tmp/dwarf_cli_verify_reloc_normalize_loc.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("normalization_policy=symbolic_canonical") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --normalization-policy=off",
            "/tmp/dwarf_cli_verify_reloc_normalization_policy_off.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("normalization_policy=off") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --format=json --summary-only --explain-gate",
            "/tmp/dwarf_cli_verify_reloc_explain_gate_json.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("\"explain_gate_mode\":\"always\"") != std::string::npos);
        assert(out.find("\"explanation\"") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --summary-only --explain-gate=off",
            "/tmp/dwarf_cli_verify_reloc_explain_gate_off.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("explain_gate_mode=off") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --only-code=UNRESOLVED_INDEXED_STRING",
            "/tmp/dwarf_cli_verify_reloc_only_code.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("only_codes=UNRESOLVED_INDEXED_STRING") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --only-section=.debug_loclists",
            "/tmp/dwarf_cli_verify_reloc_only_section.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("only_sections=.debug_loclists") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --only-severity=error",
            "/tmp/dwarf_cli_verify_reloc_only_severity.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("only_severities=error") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --top-codes=1",
            "/tmp/dwarf_cli_verify_reloc_top_codes.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("top_codes=") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --sort-issues=code",
            "/tmp/dwarf_cli_verify_reloc_sort_issues.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("sort_issues=code") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --sort-top-codes=code",
            "/tmp/dwarf_cli_verify_reloc_sort_top_codes.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("sort_top_codes=code") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --min-count=2",
            "/tmp/dwarf_cli_verify_reloc_min_count.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("min_count=2") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --max-total=123",
            "/tmp/dwarf_cli_verify_reloc_max_total.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("max_total=123") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --gate-profile=balanced",
            "/tmp/dwarf_cli_verify_reloc_gate_profile.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("gate_profile=balanced") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --gate-profile=strict",
            "/tmp/dwarf_cli_verify_reloc_gate_profile_strict.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("gate_profile=strict") != std::string::npos);
        assert(out.find("explain_gate_mode=on-fail") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --max-per-code=UNRESOLVED_INDEXED_STRING:3",
            "/tmp/dwarf_cli_verify_reloc_max_per_code.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("max_per_code=UNRESOLVED_INDEXED_STRING:3") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --max-per-section=.debug_loclists:5",
            "/tmp/dwarf_cli_verify_reloc_max_per_section.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("max_per_section=.debug_loclists:5") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --fail-on-code=UNRESOLVED_INDEXED_STRING",
            "/tmp/dwarf_cli_verify_reloc_fail_on_code.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("fail_on_codes=UNRESOLVED_INDEXED_STRING") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf +
                " --summary-only --fail-on-section=.debug_loclists",
            "/tmp/dwarf_cli_verify_reloc_fail_on_section.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("fail_on_sections=.debug_loclists") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --only-code=",
            "/tmp/dwarf_cli_verify_reloc_bad_only_code.txt", out);
        assert(code == 1);
        assert(out.find("invalid --only-code") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --only-section=bad",
            "/tmp/dwarf_cli_verify_reloc_bad_only_section.txt", out);
        assert(code == 1);
        assert(out.find("invalid --only-section") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --only-severity=bad",
            "/tmp/dwarf_cli_verify_reloc_bad_only_severity.txt", out);
        assert(code == 1);
        assert(out.find("invalid --only-severity") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --verify-features=bad",
            "/tmp/dwarf_cli_verify_reloc_bad_verify_features.txt", out);
        assert(code == 1);
        assert(out.find("invalid --verify-features") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --verify-profile=bad",
            "/tmp/dwarf_cli_verify_reloc_bad_verify_profile.txt", out);
        assert(code == 1);
        assert(out.find("invalid --verify-profile") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --top-codes=bad",
            "/tmp/dwarf_cli_verify_reloc_bad_top_codes.txt", out);
        assert(code == 1);
        assert(out.find("invalid --top-codes") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --sort-issues=bad",
            "/tmp/dwarf_cli_verify_reloc_bad_sort_issues.txt", out);
        assert(code == 1);
        assert(out.find("invalid --sort-issues") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --sort-top-codes=bad",
            "/tmp/dwarf_cli_verify_reloc_bad_sort_top_codes.txt", out);
        assert(code == 1);
        assert(out.find("invalid --sort-top-codes") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --min-count=bad",
            "/tmp/dwarf_cli_verify_reloc_bad_min_count.txt", out);
        assert(code == 1);
        assert(out.find("invalid --min-count") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --max-total=bad",
            "/tmp/dwarf_cli_verify_reloc_bad_max_total.txt", out);
        assert(code == 1);
        assert(out.find("invalid --max-total") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --gate-profile=bad",
            "/tmp/dwarf_cli_verify_reloc_bad_gate_profile.txt", out);
        assert(code == 1);
        assert(out.find("invalid --gate-profile") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --explain-gate=bad",
            "/tmp/dwarf_cli_verify_reloc_bad_explain_gate.txt", out);
        assert(code == 1);
        assert(out.find("invalid --explain-gate") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --max-per-code=bad",
            "/tmp/dwarf_cli_verify_reloc_bad_max_per_code.txt", out);
        assert(code == 1);
        assert(out.find("invalid --max-per-code") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --max-per-section=bad",
            "/tmp/dwarf_cli_verify_reloc_bad_max_per_section.txt", out);
        assert(code == 1);
        assert(out.find("invalid --max-per-section") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --fail-on-code=",
            "/tmp/dwarf_cli_verify_reloc_bad_fail_on_code.txt", out);
        assert(code == 1);
        assert(out.find("invalid --fail-on-code") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " verify-reloc " + test_elf + " --fail-on-section=bad",
            "/tmp/dwarf_cli_verify_reloc_bad_fail_on_section.txt", out);
        assert(code == 1);
        assert(out.find("invalid --fail-on-section") != std::string::npos);
    }

    {
        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --format=json --schema-version=1 --allow-unknown --allow-missing --max-rows=1",
            "/tmp/dwarf_expr_schema1.json", out_json);
        assert(code_json == 0);
        assert(out_json.find("\"schema_version\":1") != std::string::npos);
        assert(out_json.find("\"options\"") != std::string::npos);
        assert(out_json.find("\"report\"") != std::string::npos);
        assert(out_json.find("\"gate\"") != std::string::npos);
        assert(out_json.find("\"trigger\"") != std::string::npos);
        assert(out_json.find("\"signature\"") != std::string::npos);
        assert(out_json.find("\"solver_result_counts\"") != std::string::npos);
        assert(out_json.find("\"verifier_backend_counts\"") != std::string::npos);
        assert(out_json.find("\"unknown_reason_counts\"") != std::string::npos);
        assert(out_json.find("\"unknown_lhs_attribute_kind_counts\"") != std::string::npos);
        assert(out_json.find("\"verifier_backend\"") != std::string::npos);
        assert(out_json.find("\"solver_result\"") != std::string::npos);
        assert(out_json.find("\"counterexample_model\"") != std::string::npos);
        assert(out_json.find("\"counterexample_witness\"") != std::string::npos);
        std::string out_bad_schema;
        int code_bad_schema = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --format=json --schema-version=9 --allow-unknown --allow-missing",
            "/tmp/dwarf_expr_bad_schema.txt", out_bad_schema);
        assert(code_bad_schema == 1);
        assert(out_bad_schema.find("unsupported --schema-version") != std::string::npos);
    }

    {
        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name=_IO_stdin_used --allow-unknown --allow-missing --format=json --schema-version=1",
            "/tmp/dwarf_expr_row_contract_name.json", out_json);
        assert(code_json == 0 || code_json == 2);
        std::string row_json = extractFirstObjectFromArrayKey(out_json, "comparisons");
        assert(!row_json.empty());
        assert(row_json.find("\"verifier_backend\"") != std::string::npos);
        assert(row_json.find("\"solver_result\"") != std::string::npos);
        assert(row_json.find("\"counterexample_model\"") != std::string::npos);
        assert(row_json.find("\"counterexample_witness\"") != std::string::npos);
    }

    {
        std::vector<uint8_t> lhs_expr = {
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_reg1),
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_const1u), 1,
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_plus),
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_stack_value)
        };
        std::vector<uint8_t> rhs_expr = {
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_const1u), 1,
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_reg1),
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_plus),
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_stack_value)
        };

        std::string lhs_elf = makeSingleVariableLocationELF("dwarf_cli_norm_lhs", "norm", lhs_expr);
        std::string rhs_elf = makeSingleVariableLocationELF("dwarf_cli_norm_rhs", "norm", rhs_expr);

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + lhs_elf + " " + rhs_elf +
                " --name=norm --normalize-loc --allow-unknown --allow-missing --format=json --schema-version=1",
            "/tmp/dwarf_cli_normalize_loc_json.txt", out_json);
        assert(code_json == 0);
        std::string row_json = extractFirstObjectFromArrayKey(out_json, "comparisons");
        assert(!row_json.empty());
        assert(row_json.find("\"normalization_applied\":true") != std::string::npos);
        assert(row_json.find("\"normalization_equal\":true") != std::string::npos);
        assert(row_json.find("\"normalization_status\":\"attempted\"") != std::string::npos);
        assert(row_json.find("\"normalization_reason\":\"symbolic canonical comparison\"") != std::string::npos);
        assert(row_json.find("\"normalization_note\":\"normalization eliminated the mismatch\"") != std::string::npos);
        assert(row_json.find("\"lhs_normalization_changed\":") != std::string::npos);
        assert(row_json.find("\"rhs_normalization_changed\":") != std::string::npos);
        assert(row_json.find("\"normalization_kind\":\"symbolic_canonical\"") != std::string::npos);
        assert(row_json.find("\"lhs_normalization_rule_class\"") != std::string::npos);
        assert(row_json.find("\"rhs_normalization_rule_class\"") != std::string::npos);
        assert(row_json.find("\"lhs_raw_summary\":") != std::string::npos);
        assert(row_json.find("\"rhs_raw_summary\":") != std::string::npos);
        assert(row_json.find("\"lhs_summary\"") != std::string::npos);
        assert(row_json.find("\"rhs_summary\"") != std::string::npos);
        assert(row_json.find("\"lhs_normalized_summary\"") != std::string::npos);
        assert(row_json.find("\"rhs_normalized_summary\"") != std::string::npos);
        assert(row_json.find("\"solver_result\":\"normalized_equal\"") != std::string::npos);
        assert(row_json.find("\"verdict\":\"EQUIVALENT\"") != std::string::npos);
        assert(out_json.find("\"normalized_equal\":1") != std::string::npos);
        assert(out_json.find("\"normalization_attempted\":1") != std::string::npos);
        assert(out_json.find("\"normalization_changed\":") != std::string::npos);
        assert(out_json.find("\"normalization_kind_counts\"") != std::string::npos);
    }

    {
        std::vector<uint8_t> lhs_expr = {
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_reg1),
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_const1u), 0,
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_or),
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_stack_value)
        };
        std::vector<uint8_t> rhs_expr = {
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_reg1),
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_stack_value)
        };

        std::string lhs_elf = makeSingleVariableLocationELF("dwarf_cli_rewrite_lhs", "rewrite", lhs_expr);
        std::string rhs_elf = makeSingleVariableLocationELF("dwarf_cli_rewrite_rhs", "rewrite", rhs_expr);

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + lhs_elf + " " + rhs_elf +
                " --name=rewrite --normalization-policy=symbolic-canonical --allow-unknown --allow-missing --format=json --schema-version=1",
            "/tmp/dwarf_cli_rewrite_json.txt", out_json);
        assert(code_json == 0);
        std::string row_json = extractFirstObjectFromArrayKey(out_json, "comparisons");
        assert(!row_json.empty());
        assert(row_json.find("\"verdict\":\"EQUIVALENT\"") != std::string::npos);
        assert(row_json.find("\"solver_result\":\"normalized_equal\"") != std::string::npos);
        assert(row_json.find("\"normalization_note\":\"normalization eliminated the mismatch\"") != std::string::npos);
        assert(row_json.find("\"lhs_normalization_rule_class\":\"or_identity\"") != std::string::npos);
        assert(row_json.find("\"rhs_normalization_rule_class\":\"\"") != std::string::npos);
    }

    {
        std::vector<uint8_t> lhs_expr = {
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_reg1),
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_const1u), 1,
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_plus),
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_stack_value)
        };
        std::vector<uint8_t> rhs_expr = {
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_const1u), 1,
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_reg1),
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_plus),
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_stack_value)
        };
        std::string lhs_elf = makeSingleVariableLocationELF("dwarf_cli_norm_policy_lhs", "norm", lhs_expr);
        std::string rhs_elf = makeSingleVariableLocationELF("dwarf_cli_norm_policy_rhs", "norm", rhs_expr);
        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + lhs_elf + " " + rhs_elf +
                " --name=norm --normalization-policy=symbolic-canonical --allow-unknown --allow-missing --format=json --schema-version=1",
            "/tmp/dwarf_cli_normalization_policy_json.txt", out_json);
        assert(code_json == 0);
        std::string row_json = extractFirstObjectFromArrayKey(out_json, "comparisons");
        assert(!row_json.empty());
        assert(out_json.find("\"normalization_policy\":\"symbolic_canonical\"") != std::string::npos);
        assert(row_json.find("\"normalization_status\":\"attempted\"") != std::string::npos);
        assert(row_json.find("\"normalization_note\":\"normalization eliminated the mismatch\"") != std::string::npos);
        assert(row_json.find("\"lhs_raw_summary\":") != std::string::npos);
        assert(row_json.find("\"rhs_raw_summary\":") != std::string::npos);
    }

    {
        std::vector<uint8_t> or_identity_alpha = {
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_reg1),
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_const1u), 0,
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_or),
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_stack_value)
        };
        std::vector<uint8_t> or_identity_beta = {
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_reg2),
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_const1u), 0,
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_or),
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_stack_value)
        };
        std::string grouped_elf = makeVariableLocationELF(
            "dwarf_cli_norm_group",
            {
                {"alpha", or_identity_alpha},
                {"beta", or_identity_beta},
            });

        std::string out_text;
        int code_text = runAndCapture(
            dwarf_dump + " compare-expr " + grouped_elf + " " + grouped_elf +
                " --summary-only --normalization-policy=symbolic-canonical --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_norm_group_text.txt", out_text);
        assert(code_text == 0);
        assert(out_text.find("normalization_groups=") != std::string::npos);
        assert(out_text.find("rows_attempted=2") != std::string::npos);
        assert(out_text.find("rows_equal=2") != std::string::npos);
        assert(out_text.find("rows_lhs_rule_class_counts=or_identity:2") != std::string::npos);
        assert(out_text.find("rows_rhs_rule_class_counts=or_identity:2") != std::string::npos);

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + grouped_elf + " " + grouped_elf +
                " --summary-only --format=json --schema-version=1 --normalization-policy=symbolic-canonical --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_norm_group_json.txt", out_json);
        assert(code_json == 0);
        std::string report_json = extractObjectForKey(out_json, "report");
        std::string summary_json = extractObjectForKey(report_json, "summary");
        assert(!summary_json.empty());
        assert(summary_json.find("\"normalization_groups\"") != std::string::npos);
        assert(summary_json.find("\"rows\":{\"attempted\":2,\"equal\":2,\"changed\":2") != std::string::npos);
        assert(summary_json.find("\"lhs_rule_class_counts\":{\"or_identity\":2}") != std::string::npos);
        assert(summary_json.find("\"rhs_rule_class_counts\":{\"or_identity\":2}") != std::string::npos);
        assert(summary_json.find("\"segments\":{\"attempted\":0") != std::string::npos);
    }

    {
        std::string invalid_expr_elf = makeInvalidLocationOpcodeELF("dwarf_cli_invalid_expr_compare");

        std::string out_text;
        int code_text = runAndCapture(
            dwarf_dump + " compare-expr " + invalid_expr_elf + " " + invalid_expr_elf +
                " --name=bad --allow-unknown --allow-missing",
            "/tmp/dwarf_expr_unsupported_opcode_text.txt", out_text);
        assert(code_text == 0);
        assert(out_text.find("lhs_attribute_kind") != std::string::npos);
        assert(out_text.find("rhs_attribute_detail") != std::string::npos);
        assert(out_text.find("lhs_unsupported_opcode") != std::string::npos);
        assert(out_text.find("rhs_unsupported_opcode") != std::string::npos);
        assert(out_text.find("lhs_unsupported_vendor_extension") != std::string::npos);
        assert(out_text.find("rhs_unsupported_vendor_extension") != std::string::npos);
        assert(out_text.find("reason_class") != std::string::npos);
        assert(out_text.find("isolation_kind") != std::string::npos);
        assert(out_text.find("unsupported_opcode_counts=") != std::string::npos);
        assert(out_text.find("location_expression") != std::string::npos);
        assert(out_text.find("attr=DW_AT_location") != std::string::npos);
        assert(out_text.find("|255|255|1|1|") != std::string::npos);

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + invalid_expr_elf + " " + invalid_expr_elf +
                " --name=bad --allow-unknown --allow-missing --format=json --schema-version=1",
            "/tmp/dwarf_expr_unsupported_opcode_json.txt", out_json);
        assert(code_json == 0);
        std::string row_json = extractFirstObjectFromArrayKey(out_json, "comparisons");
        assert(!row_json.empty());
        assert(row_json.find("\"lhs_unsupported_opcode\":255") != std::string::npos);
        assert(row_json.find("\"rhs_unsupported_opcode\":255") != std::string::npos);
        assert(row_json.find("\"lhs_unsupported_vendor_extension\":true") != std::string::npos);
        assert(row_json.find("\"rhs_unsupported_vendor_extension\":true") != std::string::npos);
        assert(row_json.find("\"verdict\":\"UNKNOWN\"") != std::string::npos);
        assert(row_json.find("\"solver_result\":\"unsupported_opcode\"") != std::string::npos);
        assert(row_json.find("\"reason_class\":\"unsupported_isolated\"") != std::string::npos);
        assert(row_json.find("\"isolation_kind\":\"unsupported_opcode\"") != std::string::npos);
        assert(row_json.find("\"lhs_attribute_kind\":\"location_expression\"") != std::string::npos);
        assert(row_json.find("\"rhs_attribute_kind\":\"location_expression\"") != std::string::npos);
        assert(row_json.find("\"lhs_attribute_detail\":\"attr=DW_AT_location") != std::string::npos);
        assert(row_json.find("\"rhs_attribute_detail\":\"attr=DW_AT_location") != std::string::npos);
        assert(out_json.find("\"unknown_reason_class_counts\"") != std::string::npos);
        assert(out_json.find("\"unsupported_opcode_counts\"") != std::string::npos);
        assert(out_json.find("\"unsupported_rows\":1") != std::string::npos);
        assert(out_json.find("\"unsupported_isolated_rows\":1") != std::string::npos);
    }

    {
        std::vector<uint8_t> vendor_expr = {0xf9, 0x09, 0xfd, 0x05, static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_stack_value)};
        std::vector<uint8_t> standard_expr = {
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_constu), 0x09,
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_plus_uconst), 0x05,
            static_cast<uint8_t>(dwarf::DwarfOp::DW_OP_stack_value)
        };
        std::string lhs_elf = makeSingleVariableLocationELF("dwarf_cli_vendor_profile_lhs", "vendor_norm", vendor_expr);
        std::string rhs_elf = makeSingleVariableLocationELF("dwarf_cli_vendor_profile_rhs", "vendor_norm", standard_expr);

        std::string out_without_profile;
        int code_without_profile = runAndCapture(
            dwarf_dump + " compare-expr " + lhs_elf + " " + rhs_elf +
                " --name=vendor_norm --allow-unknown --allow-missing --report-only --format=json --schema-version=1",
            "/tmp/dwarf_cli_vendor_profile_off.json", out_without_profile);
        assert(code_without_profile == 0);
        std::string row_without_profile = extractFirstObjectFromArrayKey(out_without_profile, "comparisons");
        assert(!row_without_profile.empty());
        assert(row_without_profile.find("\"verdict\":\"UNKNOWN\"") != std::string::npos);
        assert(row_without_profile.find("\"lhs_unsupported_opcode\":249") != std::string::npos);
        assert(row_without_profile.find("\"reason_class\":\"unsupported_isolated\"") != std::string::npos);

        std::string out_with_profile;
        int code_with_profile = runAndCapture(
            dwarf_dump + " compare-expr " + lhs_elf + " " + rhs_elf +
                " --name=vendor_norm --vendor-op-profile=synthetic-v1 --allow-unknown --allow-missing --report-only --format=json --schema-version=1",
            "/tmp/dwarf_cli_vendor_profile_on.json", out_with_profile);
        assert(code_with_profile == 0);
        std::string row_with_profile = extractFirstObjectFromArrayKey(out_with_profile, "comparisons");
        assert(!row_with_profile.empty());
        assert(row_with_profile.find("\"lhs_unsupported_opcode\":null") != std::string::npos);
        assert(row_with_profile.find("\"rhs_unsupported_opcode\":null") != std::string::npos);
        assert(row_with_profile.find("\"reason_class\":\"\"") != std::string::npos ||
               row_with_profile.find("\"reason_class\":null") == std::string::npos);
        assert(row_with_profile.find("\"verdict\":\"EQUIVALENT\"") != std::string::npos ||
               row_with_profile.find("\"verdict\":\"UNKNOWN\"") != std::string::npos);
        assert(out_with_profile.find("\"vendor_op_profile\":\"synthetic-v1\"") != std::string::npos);
    }

    {
        std::vector<uint8_t> vendor_expr = {0xef};
        std::string lhs_elf = makeSingleVariableLocationELF("dwarf_cli_vendor_triage_a", "vendor_triage", vendor_expr);
        std::string rhs_elf = makeSingleVariableLocationELF("dwarf_cli_vendor_triage_b", "vendor_triage", vendor_expr);

        std::string out_text;
        int code_text = runAndCapture(
            dwarf_dump + " triage-vendor-ops " + lhs_elf + " " + rhs_elf,
            "/tmp/dwarf_cli_vendor_triage_text.txt", out_text);
        assert(code_text == 0);
        assert(out_text.find("kind=vendor_expression_triage") != std::string::npos);
        assert(out_text.find("selection_status=no_safe_family_selected") != std::string::npos);
        assert(out_text.find("selection_reason=no_profiled_semantics_mapping") != std::string::npos);
        assert(out_text.find("opcode=0xef") != std::string::npos);
        assert(out_text.find("independent_sample_count=2") != std::string::npos);
        assert(out_text.find("standalone_expression_sites=2") != std::string::npos);
        assert(out_text.find("top_patterns=0xef:2") != std::string::npos);

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " triage-vendor-ops " + lhs_elf + " " + rhs_elf + " --format=json --schema-version=1",
            "/tmp/dwarf_cli_vendor_triage.json", out_json);
        assert(code_json == 0);
        assert(out_json.find("\"kind\":\"vendor_expression_triage\"") != std::string::npos);
        assert(out_json.find("\"selection_status\":\"no_safe_family_selected\"") != std::string::npos);
        assert(out_json.find("\"selection_reason\":\"no_profiled_semantics_mapping\"") != std::string::npos);
        auto ranked = extractObjectsFromArrayKey(out_json, "ranked_vendor_opcodes");
        assert(ranked.size() == 1);
        bool ok = false;
        assert(extractUIntFieldFromObject(ranked.front(), "opcode", &ok) == 0xef && ok);
        assert(extractUIntFieldFromObject(ranked.front(), "independent_sample_count", &ok) == 2 && ok);
        assert(extractUIntFieldFromObject(ranked.front(), "standalone_expression_sites", &ok) == 2 && ok);
        assert(extractStringFieldFromObject(ranked.front(), "selection_blocker") ==
               "no_profiled_semantics_mapping");
        auto attrs = extractObjectsFromArrayKey(ranked.front(), "attribute_histogram");
        assert(!attrs.empty());
        assert(extractStringFieldFromObject(attrs.front(), "name") == "DW_AT_location");
        assert(extractUIntFieldFromObject(attrs.front(), "count", &ok) == 2 && ok);
        auto patterns = extractObjectsFromArrayKey(ranked.front(), "pattern_histogram");
        assert(!patterns.empty());
        assert(extractStringFieldFromObject(patterns.front(), "name") == "0xef");
        assert(extractUIntFieldFromObject(patterns.front(), "count", &ok) == 2 && ok);
    }

    {
        std::vector<uint8_t> bad = {0xff};
        std::vector<uint8_t> lit4 = {0x34, 0x9f}; // DW_OP_lit4; DW_OP_stack_value
        std::vector<std::tuple<uint64_t, uint64_t, std::vector<uint8_t>>> lhs_segments = {
            {0x10, 0x20, bad},
            {0x20, 0x30, lit4},
        };
        std::vector<std::tuple<uint64_t, uint64_t, std::vector<uint8_t>>> rhs_segments = lhs_segments;

        std::string lhs_loc_elf = makeSingleVariableLoclistELF("dwarf_cli_range_bad_lhs", "range_bad", lhs_segments);
        std::string rhs_loc_elf = makeSingleVariableLoclistELF("dwarf_cli_range_bad_rhs", "range_bad", rhs_segments);

        std::string out_text;
        int code_text = runAndCapture(
            dwarf_dump + " compare-expr " + lhs_loc_elf + " " + rhs_loc_elf +
                " --name=range_bad --range-aware --allow-unknown --allow-missing --report-only",
            "/tmp/dwarf_cli_range_bad_text.txt", out_text);
        assert(code_text == 0);
        assert(out_text.find("coverage_unsupported=16") != std::string::npos);
        assert(out_text.find("unsupported_rows=1") != std::string::npos);
        assert(out_text.find("unsupported_segments=1") != std::string::npos);

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + lhs_loc_elf + " " + rhs_loc_elf +
                " --name=range_bad --range-aware --allow-unknown --allow-missing --report-only --format=json --schema-version=1",
            "/tmp/dwarf_cli_range_bad_json.txt", out_json);
        assert(code_json == 0);
        std::string row_json = extractFirstObjectFromArrayKey(out_json, "comparisons");
        assert(!row_json.empty());
        assert(row_json.find("\"coverage_unsupported\":16") != std::string::npos);
        assert(row_json.find("\"unsupported_segments\":1") != std::string::npos);
        assert(row_json.find("\"reason_class\":\"unsupported_isolated\"") != std::string::npos);
        assert(row_json.find("\"isolation_kind\":\"unsupported_opcode\"") != std::string::npos);
        auto segments = extractObjectsFromArrayKey(row_json, "range_segments");
        assert(segments.size() == 2);
        assert(segments[0].find("\"reason_class\":\"unsupported_isolated\"") != std::string::npos);
        assert(segments[0].find("\"isolation_kind\":\"unsupported_opcode\"") != std::string::npos);
        assert(segments[0].find("\"solver_result\":\"unsupported_opcode\"") != std::string::npos);
        assert(segments[0].find("\"diagnosis_origin\":\"range_segment\"") != std::string::npos);
        assert(segments[0].find("\"lhs_unsupported_opcode\":255") != std::string::npos);
        assert(segments[0].find("\"rhs_unsupported_opcode\":255") != std::string::npos);
        assert(out_json.find("\"coverage_unsupported\":16") != std::string::npos);
        assert(out_json.find("\"unsupported_rows\":1") != std::string::npos);
        assert(out_json.find("\"unsupported_isolated_rows\":1") != std::string::npos);
        assert(out_json.find("\"unsupported_segments\":1") != std::string::npos);
    }

    {
        std::vector<uint8_t> wide_expr = {
            0x9e, // DW_OP_implicit_value
            0x09,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03,
            0x9f  // DW_OP_stack_value
        };
        std::vector<uint8_t> zero_expr = {
            0x30, // DW_OP_lit0
            0x9f  // DW_OP_stack_value
        };

        std::string wide_expr_elf = makeSingleVariableLocationELF("dwarf_cli_wide_expr_lhs", "wide", wide_expr);
        std::string zero_expr_elf = makeSingleVariableLocationELF("dwarf_cli_wide_expr_rhs", "wide", zero_expr);

        std::string out_text;
        int code_text = runAndCapture(
            dwarf_dump + " compare-expr " + wide_expr_elf + " " + zero_expr_elf +
                " --name=wide --allow-unknown --allow-missing --report-only",
            "/tmp/dwarf_expr_wide_bytes_text.txt", out_text);
        assert(code_text == 0);
#if DWARF_HAS_Z3
        assert(out_text.find("|DIFFERENT|") != std::string::npos);
        assert(out_text.find("|z3|sat|") != std::string::npos
               || out_text.find("|solver-unavailable|solver_unavailable|") != std::string::npos);
#else
        assert(out_text.find("|UNKNOWN|") != std::string::npos);
        assert(out_text.find("|solver-unavailable|solver_unavailable|") != std::string::npos);
#endif

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + wide_expr_elf + " " + zero_expr_elf +
                " --name=wide --allow-unknown --allow-missing --report-only --format=json --schema-version=1",
            "/tmp/dwarf_expr_wide_bytes_json.txt", out_json);
        assert(code_json == 0);
        std::string row_json = extractFirstObjectFromArrayKey(out_json, "comparisons");
        assert(!row_json.empty());
#if DWARF_HAS_Z3
        assert(row_json.find("\"verdict\":\"DIFFERENT\"") != std::string::npos);
        assert(row_json.find("\"solver_result\":\"sat\"") != std::string::npos);
        assert(row_json.find("\"counterexample_witness\":\"") != std::string::npos);
#else
        assert(row_json.find("\"verdict\":\"UNKNOWN\"") != std::string::npos);
        assert(row_json.find("\"solver_result\":\"solver_unavailable\"") != std::string::npos);
#endif
    }

    {
        std::vector<uint8_t> wide_load_expr = {
            0x03, // DW_OP_addr
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1000
            0x94, // DW_OP_deref_size
            0x09, // size = 9
            0x9f  // DW_OP_stack_value
        };
        std::vector<uint8_t> zero_expr = {
            0x30, // DW_OP_lit0
            0x9f  // DW_OP_stack_value
        };

        std::string wide_load_elf = makeSingleVariableLocationELF("dwarf_cli_wide_load_lhs", "wide_load", wide_load_expr);
        std::string zero_expr_elf = makeSingleVariableLocationELF("dwarf_cli_wide_load_rhs", "wide_load", zero_expr);

        std::string out_text;
        int code_text = runAndCapture(
            dwarf_dump + " compare-expr " + wide_load_elf + " " + zero_expr_elf +
                " --name=wide_load --allow-unknown --allow-missing --report-only",
            "/tmp/dwarf_expr_wide_load_text.txt", out_text);
        assert(code_text == 0);
#if DWARF_HAS_Z3
        assert(out_text.find("|DIFFERENT|") != std::string::npos);
        assert(out_text.find("|z3|sat|") != std::string::npos
               || out_text.find("|solver-unavailable|solver_unavailable|") != std::string::npos);
#else
        assert(out_text.find("|UNKNOWN|") != std::string::npos);
        assert(out_text.find("|solver-unavailable|solver_unavailable|") != std::string::npos);
#endif

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + wide_load_elf + " " + zero_expr_elf +
                " --name=wide_load --allow-unknown --allow-missing --report-only --format=json --schema-version=1",
            "/tmp/dwarf_expr_wide_load_json.txt", out_json);
        assert(code_json == 0);
        std::string row_json = extractFirstObjectFromArrayKey(out_json, "comparisons");
        assert(!row_json.empty());
#if DWARF_HAS_Z3
        assert(row_json.find("\"verdict\":\"DIFFERENT\"") != std::string::npos);
        assert(row_json.find("\"solver_result\":\"sat\"") != std::string::npos);
        assert(row_json.find("\"counterexample_witness\":\"") != std::string::npos);
#else
        assert(row_json.find("\"verdict\":\"UNKNOWN\"") != std::string::npos);
        assert(row_json.find("\"solver_result\":\"solver_unavailable\"") != std::string::npos);
#endif
    }

    {
        std::vector<uint8_t> wide_expr = {
            0x9e, // DW_OP_implicit_value
            0x09,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03,
            0x9f  // DW_OP_stack_value
        };
        std::vector<uint8_t> zero_expr = {
            0x30, // DW_OP_lit0
            0x9f  // DW_OP_stack_value
        };

        std::string wide_expr_elf = makeSingleVariableLocationELF("dwarf_cli_wide_expr_gate_lhs", "wide_gate", wide_expr);
        std::string zero_expr_elf = makeSingleVariableLocationELF("dwarf_cli_wide_expr_gate_rhs", "wide_gate", zero_expr);

        std::string out_text;
        int code_text = runAndCapture(
            dwarf_dump + " compare-expr " + wide_expr_elf + " " + zero_expr_elf +
                " --name=wide_gate --allow-unknown --allow-missing --max-different=100000"
                " --fail-on-solver-result=sat",
            "/tmp/dwarf_expr_wide_bytes_fail_on_sat.txt", out_text);
#if DWARF_HAS_Z3
        assert(code_text == 2);
        assert(out_text.find("disallowed solver_result encountered: sat") != std::string::npos);
#else
        assert(code_text == 0);
        assert(out_text.find("solver_result=solver_unavailable") != std::string::npos ||
               out_text.find("solver_unavailable") != std::string::npos);
#endif

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + wide_expr_elf + " " + zero_expr_elf +
                " --name=wide_gate --allow-unknown --allow-missing --max-different=100000"
                " --fail-on-solver-result=sat --format=json --schema-version=1",
            "/tmp/dwarf_expr_wide_bytes_fail_on_sat.json", out_json);
#if DWARF_HAS_Z3
        assert(code_json == 2);
        assert(out_json.find("\"trigger\":\"fail_on_solver_result\"") != std::string::npos);
        assert(out_json.find("\"signature\":\"pass=0;trigger=fail_on_solver_result;detail=sat\"") != std::string::npos);
#else
        assert(code_json == 0);
        assert(out_json.find("\"solver_result\":\"solver_unavailable\"") != std::string::npos);
#endif
    }

    {
        std::vector<uint8_t> wide_load_expr = {
            0x03, // DW_OP_addr
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1000
            0x94, // DW_OP_deref_size
            0x09, // size = 9
            0x9f  // DW_OP_stack_value
        };
        std::vector<uint8_t> zero_expr = {
            0x30, // DW_OP_lit0
            0x9f  // DW_OP_stack_value
        };

        std::string wide_load_elf = makeSingleVariableLocationELF("dwarf_cli_wide_load_gate_lhs", "wide_load_gate", wide_load_expr);
        std::string zero_expr_elf = makeSingleVariableLocationELF("dwarf_cli_wide_load_gate_rhs", "wide_load_gate", zero_expr);

        std::string out_text;
        int code_text = runAndCapture(
            dwarf_dump + " compare-expr " + wide_load_elf + " " + zero_expr_elf +
                " --name=wide_load_gate --allow-unknown --allow-missing --max-different=100000"
                " --fail-on-solver-result=sat",
            "/tmp/dwarf_expr_wide_load_fail_on_sat.txt", out_text);
#if DWARF_HAS_Z3
        assert(code_text == 2);
        assert(out_text.find("disallowed solver_result encountered: sat") != std::string::npos);
#else
        assert(code_text == 0);
        assert(out_text.find("solver_result=solver_unavailable") != std::string::npos ||
               out_text.find("solver_unavailable") != std::string::npos);
#endif

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + wide_load_elf + " " + zero_expr_elf +
                " --name=wide_load_gate --allow-unknown --allow-missing --max-different=100000"
                " --fail-on-solver-result=sat --format=json --schema-version=1",
            "/tmp/dwarf_expr_wide_load_fail_on_sat.json", out_json);
#if DWARF_HAS_Z3
        assert(code_json == 2);
        assert(out_json.find("\"trigger\":\"fail_on_solver_result\"") != std::string::npos);
        assert(out_json.find("\"signature\":\"pass=0;trigger=fail_on_solver_result;detail=sat\"") != std::string::npos);
#else
        assert(code_json == 0);
        assert(out_json.find("\"solver_result\":\"solver_unavailable\"") != std::string::npos);
#endif
    }

    {
        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --summary-only --format=json --schema-version=1 --verify-features=all --solver-timeout-ms=123 --allow-unknown --allow-missing",
            "/tmp/dwarf_expr_verify_features_all.json", out_json);
        assert(code_json == 0);
        assert(out_json.find("\"verify_features\":[\"section-reloc\",\"loc-normalize\",\"range-aware\"]") != std::string::npos);
        assert(out_json.find("\"normalization_policy\":\"symbolic_canonical\"") != std::string::npos);
        assert(out_json.find("\"solver_timeout_ms\":123") != std::string::npos);
        assert(out_json.find("\"verify_profile\":\"custom\"") != std::string::npos);
        assert(out_json.find("\"gate_profile\":\"custom\"") != std::string::npos);
        assert(out_json.find("\"reloc_check\":true") != std::string::npos);
        assert(out_json.find("\"normalize_loc\":true") != std::string::npos);
        assert(out_json.find("\"range_aware\":true") != std::string::npos);
    }

    {
        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --summary-only --format=json --schema-version=1 --verify-profile=off --allow-unknown --allow-missing",
            "/tmp/dwarf_expr_verify_profile_off.json", out_json);
        assert(code_json == 0);
        assert(out_json.find("\"verify_features\":[]") != std::string::npos);
        assert(out_json.find("\"normalization_policy\":\"off\"") != std::string::npos);
        assert(out_json.find("\"reloc_check\":false") != std::string::npos);
        assert(out_json.find("\"normalize_loc\":false") != std::string::npos);
        assert(out_json.find("\"range_aware\":false") != std::string::npos);
        assert(out_json.find("\"verify_profile\":\"off\"") != std::string::npos);
        assert(out_json.find("\"gate_profile\":\"custom\"") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --emit-profile-only --solver-timeout-ms=456 --allow-unknown --allow-missing",
            "/tmp/dwarf_expr_emit_profile_only_text.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("verify_profile=") != std::string::npos);
        assert(out.find("verify_features=") != std::string::npos);
        assert(out.find("normalization_policy=symbolic_canonical") != std::string::npos);
        assert(out.find("solver_timeout_ms=456") != std::string::npos);
        assert(out.find("gate_profile=") != std::string::npos);
        assert(out.find("gate_pass=") != std::string::npos);
        assert(out.find("gate_trigger=") != std::string::npos);
        assert(out.find("solver_result_counts=") != std::string::npos);
        assert(out.find("verifier_backend_counts=") != std::string::npos);
        assert(out.find("gate_signature=") != std::string::npos);
        assert(out.find("summary total=") == std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --emit-solver-summary-only --allow-unknown --allow-missing",
            "/tmp/dwarf_expr_emit_solver_summary_only_text.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("solver_summary total=") != std::string::npos);
        assert(out.find("solver_result_counts=") != std::string::npos);
        assert(out.find("verifier_backend_counts=") != std::string::npos);
        assert(out.find("name|tag|") == std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --emit-profile-only --format=json --schema-version=1 --solver-timeout-ms=789 --allow-unknown --allow-missing",
            "/tmp/dwarf_expr_emit_profile_only_json.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("\"profile\"") != std::string::npos);
        assert(out.find("\"verify_profile\"") != std::string::npos);
        assert(out.find("\"normalization_policy\"") != std::string::npos);
        assert(out.find("\"verify_features\"") != std::string::npos);
        assert(out.find("\"solver_timeout_ms\":789") != std::string::npos);
        assert(out.find("\"gate_profile\"") != std::string::npos);
        assert(out.find("\"fail_on_solver_results\"") != std::string::npos);
        assert(out.find("\"fail_on_verifier_backends\"") != std::string::npos);
        assert(out.find("\"solver_result_counts\"") != std::string::npos);
        assert(out.find("\"verifier_backend_counts\"") != std::string::npos);
        assert(out.find("\"gate\"") != std::string::npos);
        assert(out.find("\"trigger\"") != std::string::npos);
        assert(out.find("\"signature\"") != std::string::npos);
        assert(out.find("\"report\"") == std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --emit-solver-summary-only --format=json --schema-version=1 --allow-unknown --allow-missing",
            "/tmp/dwarf_expr_emit_solver_summary_only_json.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("\"schema_version\":1") != std::string::npos);
        assert(out.find("\"solver_summary\"") != std::string::npos);
        assert(out.find("\"solver_result_counts\"") != std::string::npos);
        assert(out.find("\"verifier_backend_counts\"") != std::string::npos);
        assert(out.find("\"profile\"") == std::string::npos);
        assert(out.find("\"report\"") == std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --emit-profile-only --emit-solver-summary-only --allow-unknown --allow-missing",
            "/tmp/dwarf_expr_bad_emit_combo.txt", out);
        assert(code == 1);
        assert(out.find("cannot combine --emit-profile-only with --emit-solver-summary-only") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --verify-profile=strict --name=__definitely_missing_symbol_name__",
            "/tmp/dwarf_expr_verify_profile_strict.txt", out);
        assert(code == 2);
        assert(out.find("gate FAILED") != std::string::npos);
    }

    {
        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --summary-only --format=json --schema-version=1 --gate-profile=strict",
            "/tmp/dwarf_expr_gate_profile_strict.json", out_json);
        assert(code_json == 0 || code_json == 2);
        assert(out_json.find("\"gate_profile\":\"strict\"") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name=_IO_stdin_used --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_name_ok.txt", out);
        assert(code == 0);
        assert(out.find("summary total=1") != std::string::npos);
        assert(out.find("_IO_stdin_used") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name=__definitely_missing_symbol_name__ --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_name_missing.txt", out);
        assert(code == 0);
        assert(out.find("summary total=1") != std::string::npos);
        assert(out.find("both DIEs missing") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name=_IO_stdin_used --name=__definitely_missing_symbol_name__ --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_name_multi.txt", out);
        assert(code == 0);
        assert(out.find("summary total=2") != std::string::npos);
        assert(out.find("_IO_stdin_used") != std::string::npos);
        assert(out.find("__definitely_missing_symbol_name__") != std::string::npos);
    }

    {
        std::string out_bad;
        int code_bad = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --fail-on-solver-result=",
            "/tmp/dwarf_cli_expr_bad_fail_on_solver_result.txt", out_bad);
        assert(code_bad == 1);
        assert(out_bad.find("invalid --fail-on-solver-result") != std::string::npos);
    }

    {
        std::string out_bad;
        int code_bad = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --fail-on-verifier-backend=",
            "/tmp/dwarf_cli_expr_bad_fail_on_verifier_backend.txt", out_bad);
        assert(code_bad == 1);
        assert(out_bad.find("invalid --fail-on-verifier-backend") != std::string::npos);
    }

    {
        std::string out_bad;
        int code_bad = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --solver-timeout-ms=not_a_number",
            "/tmp/dwarf_cli_expr_bad_solver_timeout_nonnumeric.txt", out_bad);
        assert(code_bad == 1);
        assert(out_bad.find("invalid --solver-timeout-ms value") != std::string::npos);
    }

    {
        std::string out_bad;
        int code_bad = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --solver-timeout-ms=4294967296",
            "/tmp/dwarf_cli_expr_bad_solver_timeout_overflow.txt", out_bad);
        assert(code_bad == 1);
        assert(out_bad.find("invalid --solver-timeout-ms value") != std::string::npos);
    }

    {
        std::string out_fail;
        int code_fail = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name=_IO_stdin_used --normalization-policy=off --fail-on-solver-result=" + std::string(kExprPrimarySolverResult) +
                " --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_expr_fail_on_solver_unsat.txt", out_fail);
        assert(code_fail == 2);
        assert(out_fail.find("gate FAILED") != std::string::npos);
        assert(out_fail.find("disallowed solver_result encountered: " + std::string(kExprPrimarySolverResult)) != std::string::npos);
    }

    {
        std::string out_fail_json;
        int code_fail_json = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name=_IO_stdin_used --normalization-policy=off --fail-on-solver-result=" + std::string(kExprPrimarySolverResult) +
                " --allow-unknown --allow-missing --format=json --schema-version=1",
            "/tmp/dwarf_cli_expr_fail_on_solver_unsat.json", out_fail_json);
        assert(code_fail_json == 2);
        std::string gate_obj = extractObjectForKey(out_fail_json, "gate");
        assert(!gate_obj.empty());
        bool ok_pass = false;
        bool pass = extractBoolFieldFromObject(gate_obj, "pass", &ok_pass);
        assert(ok_pass && !pass);
        assert(extractStringFieldFromObject(gate_obj, "trigger") == "fail_on_solver_result");
        assert(extractStringFieldFromObject(gate_obj, "trigger_detail") == kExprPrimarySolverResult);
        assert(extractStringFieldFromObject(gate_obj, "signature") ==
               "pass=0;trigger=fail_on_solver_result;detail=" + std::string(kExprPrimarySolverResult));
    }

    {
        std::string out_fail;
        int code_fail = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name=_IO_stdin_used --normalization-policy=off --fail-on-verifier-backend=" + std::string(kExprSolverBackend) +
                " --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_expr_fail_on_verifier_backend_z3.txt", out_fail);
        assert(code_fail == 2);
        assert(out_fail.find("gate FAILED") != std::string::npos);
        assert(out_fail.find("disallowed verifier_backend encountered: " + std::string(kExprSolverBackend)) != std::string::npos);
    }

    {
        std::string out_fail_json;
        int code_fail_json = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name=_IO_stdin_used --normalization-policy=off --fail-on-verifier-backend=" + std::string(kExprSolverBackend) +
                " --allow-unknown --allow-missing --format=json --schema-version=1",
            "/tmp/dwarf_cli_expr_fail_on_verifier_backend_z3.json", out_fail_json);
        assert(code_fail_json == 2);
        std::string gate_obj = extractObjectForKey(out_fail_json, "gate");
        assert(!gate_obj.empty());
        bool ok_pass = false;
        bool pass = extractBoolFieldFromObject(gate_obj, "pass", &ok_pass);
        assert(ok_pass && !pass);
        assert(extractStringFieldFromObject(gate_obj, "trigger") == "fail_on_verifier_backend");
        assert(extractStringFieldFromObject(gate_obj, "trigger_detail") == kExprSolverBackend);
        assert(extractStringFieldFromObject(gate_obj, "signature") ==
               "pass=0;trigger=fail_on_verifier_backend;detail=" + std::string(kExprSolverBackend));
    }

    {
        std::string out_fail;
        int code_fail = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name=__definitely_missing_symbol_name__ --allow-unknown --allow-missing --fail-on-solver-result=unspecified",
            "/tmp/dwarf_cli_expr_fail_on_solver_unspecified.txt", out_fail);
        assert(code_fail == 2);
        assert(out_fail.find("gate FAILED") != std::string::npos);
        assert(out_fail.find("disallowed solver_result encountered: unspecified") != std::string::npos);
    }

    {
        std::string out_fail_json;
        int code_fail_json = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name=__definitely_missing_symbol_name__ --allow-unknown --allow-missing --fail-on-solver-result=unspecified --format=json --schema-version=1",
            "/tmp/dwarf_cli_expr_fail_on_solver_unspecified.json", out_fail_json);
        assert(code_fail_json == 2);
        assert(out_fail_json.find("\"trigger\":\"fail_on_solver_result\"") != std::string::npos);
        assert(out_fail_json.find("\"trigger_detail\":\"unspecified\"") != std::string::npos);
    }

    {
        std::string out_fail;
        int code_fail = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name=__definitely_missing_symbol_name__ --allow-unknown --allow-missing --fail-on-verifier-backend=unspecified",
            "/tmp/dwarf_cli_expr_fail_on_backend_unspecified.txt", out_fail);
        assert(code_fail == 2);
        assert(out_fail.find("gate FAILED") != std::string::npos);
        assert(out_fail.find("disallowed verifier_backend encountered: unspecified") != std::string::npos);
    }

    {
        std::string out_fail_json;
        int code_fail_json = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name=__definitely_missing_symbol_name__ --allow-unknown --allow-missing --fail-on-verifier-backend=unspecified --format=json --schema-version=1",
            "/tmp/dwarf_cli_expr_fail_on_backend_unspecified.json", out_fail_json);
        assert(code_fail_json == 2);
        assert(out_fail_json.find("\"trigger\":\"fail_on_verifier_backend\"") != std::string::npos);
        assert(out_fail_json.find("\"trigger_detail\":\"unspecified\"") != std::string::npos);
    }

    {
        std::string out_fail_json;
        int code_fail_json = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name=_IO_stdin_used --normalization-policy=off --fail-on-solver-result=" + std::string(kExprPrimarySolverResult) +
                " --fail-on-verifier-backend=" + std::string(kExprSolverBackend) +
                " --allow-unknown --allow-missing --format=json --schema-version=1",
            "/tmp/dwarf_cli_expr_fail_on_both_solver_and_backend.json", out_fail_json);
        assert(code_fail_json == 2);
        assert(out_fail_json.find("\"trigger\":\"fail_on_solver_result\"") != std::string::npos);
        assert(out_fail_json.find("\"trigger_detail\":\"" + std::string(kExprPrimarySolverResult) + "\"") != std::string::npos);
        assert(out_fail_json.find("\"signature\":\"pass=0;trigger=fail_on_solver_result;detail=" +
                                  std::string(kExprPrimarySolverResult) + "\"") != std::string::npos);
    }

    {
        std::string out_fail;
        int code_fail = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name=_IO_stdin_used --normalization-policy=off --fail-on-solver-result=" + std::string(kExprPrimarySolverResult) +
                " --fail-on-verifier-backend=" + std::string(kExprSolverBackend) +
                " --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_expr_fail_on_both_solver_and_backend.txt", out_fail);
        assert(code_fail == 2);
        assert(out_fail.find("disallowed solver_result encountered: " + std::string(kExprPrimarySolverResult)) != std::string::npos);
        assert(out_fail.find("disallowed verifier_backend encountered: " + std::string(kExprSolverBackend)) == std::string::npos);
    }

    {
        std::string out_gate;
        int code_gate = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf + " --max-unknown=0",
            "/tmp/dwarf_cli_gate_fail.txt", out_gate);
        assert(code_gate == 2);
        assert(out_gate.find("gate FAILED") != std::string::npos);

        std::string out_report_only;
        int code_report_only = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf + " --max-unknown=0 --report-only",
            "/tmp/dwarf_cli_report_only.txt", out_report_only);
        assert(code_report_only == 0);
        assert(out_report_only.find("summary total=") != std::string::npos);
    }

    {
        const std::string list_path = "/tmp/dwarf_cli_name_list.txt";
        {
            std::ofstream ofs(list_path);
            ofs << "# comment line\n";
            ofs << "_IO_stdin_used\n";
            ofs << "  __definitely_missing_symbol_name__  \n";
        }

        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name-file=" + list_path + " --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_name_file_ok.txt", out);
        assert(code == 0);
        assert(out.find("summary total=2") != std::string::npos);
        assert(out.find("_IO_stdin_used") != std::string::npos);
        assert(out.find("__definitely_missing_symbol_name__") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name-file=/tmp/__dwarf_cli_missing_name_file__.txt",
            "/tmp/dwarf_cli_name_file_bad.txt", out);
        assert(code == 1);
        assert(out.find("cannot open name file") != std::string::npos);
    }

    {
        const std::string out_path = "/tmp/dwarf_cli_report_out.txt";
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --allow-unknown --allow-missing --max-rows=1 --output=" + out_path,
            "/tmp/dwarf_cli_output_stdout.txt", out);
        assert(code == 0);
        std::string report = readFile(out_path);
        assert(report.find("summary total=") != std::string::npos);
        assert(report.find("name|tag|") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --allow-unknown --allow-missing --output=/tmp/__dwarf_no_dir__/report.txt",
            "/tmp/dwarf_cli_output_bad.txt", out);
        assert(code == 1);
        assert(out.find("cannot open output file") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --only-verdict=unknown --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_filter_unknown.txt", out);
        assert(code == 0);
        assert(out.find("summary total=") != std::string::npos);
        assert(out.find("UNKNOWN") != std::string::npos);
        assert(out.find("EQUIVALENT") == std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --sort=verdict --allow-unknown --allow-missing --max-rows=3",
            "/tmp/dwarf_cli_sort_verdict.txt", out);
        assert(code == 0);
        assert(out.find("summary total=") != std::string::npos);
    }

    {
        std::string out_bad_verdict;
        int code_bad_verdict = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf + " --only-verdict=bad",
            "/tmp/dwarf_cli_bad_verdict_filter.txt", out_bad_verdict);
        assert(code_bad_verdict == 1);
        assert(out_bad_verdict.find("invalid --only-verdict") != std::string::npos);

        std::string out_bad_sort;
        int code_bad_sort = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf + " --sort=bad",
            "/tmp/dwarf_cli_bad_sort.txt", out_bad_sort);
        assert(code_bad_sort == 1);
        assert(out_bad_sort.find("invalid --sort") != std::string::npos);

        std::string out_bad_features;
        int code_bad_features = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf + " --verify-features=bad",
            "/tmp/dwarf_cli_bad_verify_features.txt", out_bad_features);
        assert(code_bad_features == 1);
        assert(out_bad_features.find("invalid --verify-features") != std::string::npos);

        std::string out_bad_profile;
        int code_bad_profile = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf + " --verify-profile=bad",
            "/tmp/dwarf_cli_bad_verify_profile.txt", out_bad_profile);
        assert(code_bad_profile == 1);
        assert(out_bad_profile.find("invalid --verify-profile") != std::string::npos);

        std::string out_bad_gate_profile;
        int code_bad_gate_profile = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf + " --gate-profile=bad",
            "/tmp/dwarf_cli_bad_gate_profile_expr.txt", out_bad_gate_profile);
        assert(code_bad_gate_profile == 1);
        assert(out_bad_gate_profile.find("invalid --gate-profile") != std::string::npos);
    }

    {
        std::string out_text;
        int code_text = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --summary-only --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_summary_only_text.txt", out_text);
        assert(code_text == 0);
        assert(out_text.find("summary total=") != std::string::npos);
        assert(out_text.find("name|tag|") == std::string::npos);

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --summary-only --format=json --schema-version=1 --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_summary_only_json.txt", out_json);
        assert(code_json == 0);
        assert(out_json.find("\"schema_version\":1") != std::string::npos);
        assert(out_json.find("\"report\"") != std::string::npos);
        assert(out_json.find("\"summary\"") != std::string::npos);
        assert(out_json.find("\"gate\"") != std::string::npos);
        assert(out_json.find("\"verify_profile\"") != std::string::npos);
        assert(out_json.find("\"gate_profile\"") != std::string::npos);
        assert(out_json.find("\"fail_on_solver_results\"") != std::string::npos);
        assert(out_json.find("\"fail_on_verifier_backends\"") != std::string::npos);
        assert(out_json.find("\"solver_result_counts\"") != std::string::npos);
        assert(out_json.find("\"verifier_backend_counts\"") != std::string::npos);
        assert(out_json.find("\"trigger\"") != std::string::npos);
        assert(out_json.find("\"signature\"") != std::string::npos);
        assert(out_json.find("\"comparisons\"") == std::string::npos);
    }

    {
        std::string out_prefix;
        int code_prefix = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name-prefix=_IO_ --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_name_prefix.txt", out_prefix);
        assert(code_prefix == 0);
        assert(out_prefix.find("_IO_stdin_used") != std::string::npos);

        std::string out_contains;
        int code_contains = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --name-contains=stdin --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_name_contains.txt", out_contains);
        assert(code_contains == 0);
        assert(out_contains.find("_IO_stdin_used") != std::string::npos);
    }

    {
        std::string out_bad_prefix;
        int code_bad_prefix = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf + " --name-prefix=",
            "/tmp/dwarf_cli_bad_name_prefix.txt", out_bad_prefix);
        assert(code_bad_prefix == 1);
        assert(out_bad_prefix.find("invalid --name-prefix") != std::string::npos);

        std::string out_bad_contains;
        int code_bad_contains = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf + " --name-contains=",
            "/tmp/dwarf_cli_bad_name_contains.txt", out_bad_contains);
        assert(code_bad_contains == 1);
        assert(out_bad_contains.find("invalid --name-contains") != std::string::npos);
    }

    {
        std::string out_ok;
        int code_ok = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --lhs-fde-index=0 --rhs-fde-index=0",
            "/tmp/dwarf_cli_compare_cfi_ok.txt", out_ok);
        assert(code_ok == 0);
        assert(out_ok.find("mode=fde") != std::string::npos);
        assert(out_ok.find("|EQUIVALENT|") != std::string::npos);
    }

    {
        std::string out_all;
        int code_all = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --sort=lhs-pc --max-rows=2",
            "/tmp/dwarf_cli_compare_cfi_all_fdes.txt", out_all);
        assert(code_all == 0);
        assert(out_all.find("mode=all-fdes") != std::string::npos);
        assert(out_all.find("pair_by=index") != std::string::npos);
        assert(out_all.find("sort=lhs-pc") != std::string::npos);
        assert(out_all.find("different=0") != std::string::npos);
        assert(out_all.find("|EQUIVALENT|") == std::string::npos);
    }

    {
        std::string out_show_eq;
        int code_show_eq = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --show-equivalent --max-rows=1",
            "/tmp/dwarf_cli_compare_cfi_show_equivalent.txt", out_show_eq);
        assert(code_show_eq == 0);
        assert(out_show_eq.find("|EQUIVALENT|") != std::string::npos);
    }

    {
        std::string out_only_diff;
        int code_only_diff = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --show-equivalent --only-different --max-rows=1",
            "/tmp/dwarf_cli_compare_cfi_only_different.txt", out_only_diff);
        assert(code_only_diff == 0);
        assert(out_only_diff.find("|EQUIVALENT|") == std::string::npos);
        assert(out_only_diff.find("|DIFFERENT|") == std::string::npos);

        std::string out_only_unknown;
        int code_only_unknown = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --show-equivalent --only-unknown --max-rows=1",
            "/tmp/dwarf_cli_compare_cfi_only_unknown.txt", out_only_unknown);
        assert(code_only_unknown == 0);
        assert(out_only_unknown.find("|EQUIVALENT|") == std::string::npos);
        assert(out_only_unknown.find("|UNKNOWN|") == std::string::npos);
    }

    {
        std::string out_pair;
        int code_pair = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --pair-by=start-pc --max-rows=1",
            "/tmp/dwarf_cli_compare_cfi_pair_startpc.txt", out_pair);
        assert(code_pair == 0);
        assert(out_pair.find("pair_by=start-pc") != std::string::npos);
    }

    {
        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --max-rows=1 --format=json --schema-version=1",
            "/tmp/dwarf_cli_compare_cfi_all_json.txt", out_json);
        assert(code_json == 0);
        assert(out_json.find("\"schema_version\":1") != std::string::npos);
        assert(out_json.find("\"mode\":\"all-fdes\"") != std::string::npos);
        assert(out_json.find("\"options\"") != std::string::npos);
        assert(out_json.find("\"sort\":\"lhs-index\"") != std::string::npos);
        assert(out_json.find("\"show_equivalent\":false") != std::string::npos);
        assert(out_json.find("\"gate_profile\"") != std::string::npos);
        assert(out_json.find("\"fail_on_solver_results\"") != std::string::npos);
        assert(out_json.find("\"summary\"") != std::string::npos);
        assert(out_json.find("\"solver_result_counts\"") != std::string::npos);
        assert(out_json.find("\"verifier_backend_counts\"") != std::string::npos);
        assert(out_json.find("\"rows\"") != std::string::npos);
        assert(out_json.find("\"gate\"") != std::string::npos);
        assert(out_json.find("\"trigger\"") != std::string::npos);
        assert(out_json.find("\"signature\"") != std::string::npos);
    }

    {
        std::string out_json_show;
        int code_json_show = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --show-equivalent --max-rows=1 --format=json --schema-version=1",
            "/tmp/dwarf_cli_compare_cfi_all_json_show.txt", out_json_show);
        assert(code_json_show == 0);
        assert(out_json_show.find("\"show_equivalent\":true") != std::string::npos);
        assert(out_json_show.find("\"lhs_initial_location\"") != std::string::npos);
        assert(out_json_show.find("\"rhs_address_range\"") != std::string::npos);
        assert(out_json_show.find("\"lhs_function_name\"") != std::string::npos);
        assert(out_json_show.find("\"rhs_function_name\"") != std::string::npos);
        assert(out_json_show.find("\"verifier_backend\"") != std::string::npos);
        assert(out_json_show.find("\"solver_result\"") != std::string::npos);
        assert(out_json_show.find("\"counterexample_witness\"") != std::string::npos);
        std::string row_json = extractFirstObjectFromArrayKey(out_json_show, "rows");
        assert(!row_json.empty());
        assert(row_json.find("\"verifier_backend\"") != std::string::npos);
        assert(row_json.find("\"solver_result\"") != std::string::npos);
        assert(row_json.find("\"counterexample_model\"") != std::string::npos);
        assert(row_json.find("\"counterexample_witness\"") != std::string::npos);
    }

    {
        std::string out_json_only_diff;
        int code_json_only_diff = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --show-equivalent --only-different --format=json --schema-version=1",
            "/tmp/dwarf_cli_compare_cfi_only_diff_json.txt", out_json_only_diff);
        assert(code_json_only_diff == 0);
        assert(out_json_only_diff.find("\"only_different\":true") != std::string::npos);
        assert(out_json_only_diff.find("\"only_unknown\":false") != std::string::npos);
        assert(out_json_only_diff.find("\"rows\":[]") != std::string::npos);
    }

    {
        std::string out_text;
        int code_text = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --summary-only",
            "/tmp/dwarf_cli_compare_cfi_summary_only_text.txt", out_text);
        assert(code_text == 0);
        assert(out_text.find("mode=all-fdes") != std::string::npos);
        assert(out_text.find("gate_profile=") != std::string::npos);
        assert(out_text.find("gate_trigger=") != std::string::npos);
        assert(out_text.find("gate_signature=") != std::string::npos);
        assert(out_text.find("solver_result_counts=") != std::string::npos);
        assert(out_text.find("verifier_backend_counts=") != std::string::npos);
        assert(out_text.find("lhs_index|rhs_index|") == std::string::npos);

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --summary-only --format=json --schema-version=1",
            "/tmp/dwarf_cli_compare_cfi_summary_only_json.txt", out_json);
        assert(code_json == 0);
        assert(out_json.find("\"summary\"") != std::string::npos);
        assert(out_json.find("\"fail_on_solver_results\"") != std::string::npos);
        assert(out_json.find("\"solver_result_counts\"") != std::string::npos);
        assert(out_json.find("\"verifier_backend_counts\"") != std::string::npos);
        assert(out_json.find("\"trigger\"") != std::string::npos);
        assert(out_json.find("\"signature\"") != std::string::npos);
        assert(out_json.find("\"rows\"") == std::string::npos);
    }

    {
        std::string out_text;
        int code_text = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --emit-gate-signature-only",
            "/tmp/dwarf_cli_compare_cfi_sig_only_text.txt", out_text);
        assert(code_text == 0 || code_text == 2);
        assert(out_text.find("gate_signature=") != std::string::npos);
        assert(out_text.find("mode=all-fdes") == std::string::npos);

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --emit-gate-signature-only --format=json --schema-version=1",
            "/tmp/dwarf_cli_compare_cfi_sig_only_json.txt", out_json);
        assert(code_json == 0 || code_json == 2);
        assert(out_json.find("\"gate\"") != std::string::npos);
        assert(out_json.find("\"signature\"") != std::string::npos);
        assert(out_json.find("\"summary\"") == std::string::npos);
    }

    {
        std::string out_text;
        int code_text = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --emit-profile-only --solver-timeout-ms=222",
            "/tmp/dwarf_cli_compare_cfi_profile_only_text.txt", out_text);
        assert(code_text == 0 || code_text == 2);
        assert(out_text.find("gate_profile=") != std::string::npos);
        assert(out_text.find("solver_timeout_ms=222") != std::string::npos);
        assert(out_text.find("thresholds=") != std::string::npos);
        assert(out_text.find("fail_on_solver_results:") != std::string::npos);
        assert(out_text.find("solver_result_counts:") != std::string::npos);
        assert(out_text.find("verifier_backend_counts:") != std::string::npos);
        assert(out_text.find("gate_trigger=") != std::string::npos);
        assert(out_text.find("gate_signature=") != std::string::npos);
        assert(out_text.find("mode=all-fdes") == std::string::npos);

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --emit-profile-only --format=json --schema-version=1 --solver-timeout-ms=333",
            "/tmp/dwarf_cli_compare_cfi_profile_only_json.txt", out_json);
        assert(code_json == 0 || code_json == 2);
        assert(out_json.find("\"profile\"") != std::string::npos);
        assert(out_json.find("\"gate\"") != std::string::npos);
        assert(out_json.find("\"profile\":\"") != std::string::npos);
        assert(out_json.find("\"solver_timeout_ms\":333") != std::string::npos);
        assert(out_json.find("\"fail_on_solver_results\"") != std::string::npos);
        assert(out_json.find("\"solver_result_counts\"") != std::string::npos);
        assert(out_json.find("\"verifier_backend_counts\"") != std::string::npos);
        assert(out_json.find("\"trigger\"") != std::string::npos);
        assert(out_json.find("\"signature\"") != std::string::npos);
        assert(out_json.find("\"summary\"") == std::string::npos);
    }

    {
        std::string out_text;
        int code_text = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --emit-solver-summary-only",
            "/tmp/dwarf_cli_compare_cfi_solver_summary_only_text.txt", out_text);
        assert(code_text == 0 || code_text == 2);
        assert(out_text.find("solver_summary total=") != std::string::npos);
        assert(out_text.find("solver_result_counts=") != std::string::npos);
        assert(out_text.find("verifier_backend_counts=") != std::string::npos);
        assert(out_text.find("gate_profile=") == std::string::npos);
    }

    {
        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --emit-solver-summary-only --format=json --schema-version=1",
            "/tmp/dwarf_cli_compare_cfi_solver_summary_only_json.txt", out_json);
        assert(code_json == 0 || code_json == 2);
        assert(out_json.find("\"schema_version\":1") != std::string::npos);
        assert(out_json.find("\"solver_summary\"") != std::string::npos);
        assert(out_json.find("\"solver_result_counts\"") != std::string::npos);
        assert(out_json.find("\"verifier_backend_counts\"") != std::string::npos);
        assert(out_json.find("\"profile\"") == std::string::npos);
        assert(out_json.find("\"summary\"") == std::string::npos);
    }

    {
        std::string out_bad;
        int code_bad = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --emit-profile-only --emit-solver-summary-only",
            "/tmp/dwarf_cli_compare_cfi_bad_emit_combo1.txt", out_bad);
        assert(code_bad == 1);
        assert(out_bad.find("emit-only modes are mutually exclusive") != std::string::npos);
    }

    {
        std::string out_bad;
        int code_bad = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --emit-solver-summary-only --emit-gate-signature-only",
            "/tmp/dwarf_cli_compare_cfi_bad_emit_combo2.txt", out_bad);
        assert(code_bad == 1);
        assert(out_bad.find("emit-only modes are mutually exclusive") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --gate-profile=strict --summary-only",
            "/tmp/dwarf_cli_compare_cfi_gate_profile_strict.txt", out);
        assert(code == 0 || code == 2);
        assert(out.find("gate_profile=strict") != std::string::npos);
    }

    {
        std::string out_bad;
        int code_bad = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --fail-on-solver-result=",
            "/tmp/dwarf_cli_cfi_bad_fail_on_solver_result.txt", out_bad);
        assert(code_bad == 1);
        assert(out_bad.find("invalid --fail-on-solver-result") != std::string::npos);
    }

    {
        std::string out_bad;
        int code_bad = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --fail-on-verifier-backend=",
            "/tmp/dwarf_cli_cfi_bad_fail_on_verifier_backend.txt", out_bad);
        assert(code_bad == 1);
        assert(out_bad.find("invalid --fail-on-verifier-backend") != std::string::npos);
    }

    {
        std::string out_bad;
        int code_bad = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --solver-timeout-ms=not_a_number",
            "/tmp/dwarf_cli_cfi_bad_solver_timeout_nonnumeric.txt", out_bad);
        assert(code_bad == 1);
        assert(out_bad.find("invalid --solver-timeout-ms value") != std::string::npos);
    }

    {
        std::string out_bad;
        int code_bad = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --solver-timeout-ms=4294967296",
            "/tmp/dwarf_cli_cfi_bad_solver_timeout_overflow.txt", out_bad);
        assert(code_bad == 1);
        assert(out_bad.find("invalid --solver-timeout-ms value") != std::string::npos);
    }

    {
        std::string out_fail;
        int code_fail = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --lhs-fde-index=0 --rhs-fde-index=0 --fail-on-solver-result=equivalent",
            "/tmp/dwarf_cli_cfi_fail_on_solver_equivalent.txt", out_fail);
        assert(code_fail == 2);
        assert(out_fail.find("gate FAILED") != std::string::npos);
        assert(out_fail.find("disallowed by fail-on-solver-result") != std::string::npos);
        assert(out_fail.find("gate_trigger=fail_on_solver_result") != std::string::npos);
    }

    {
        std::string out_fail_json;
        int code_fail_json = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --lhs-fde-index=0 --rhs-fde-index=0 --fail-on-solver-result=equivalent --format=json --schema-version=1",
            "/tmp/dwarf_cli_cfi_fail_on_solver_equivalent.json", out_fail_json);
        assert(code_fail_json == 2);
        std::string gate_obj = extractObjectForKey(out_fail_json, "gate");
        assert(!gate_obj.empty());
        bool ok_pass = false;
        bool pass = extractBoolFieldFromObject(gate_obj, "pass", &ok_pass);
        assert(ok_pass && !pass);
        assert(extractStringFieldFromObject(gate_obj, "trigger") == "fail_on_solver_result");
        assert(extractStringFieldFromObject(gate_obj, "trigger_detail") == "equivalent");
        assert(extractStringFieldFromObject(gate_obj, "signature") == "pass=0;trigger=fail_on_solver_result;detail=equivalent");
    }

    {
        std::string out_fail;
        int code_fail = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --lhs-fde-index=0 --rhs-fde-index=0 --fail-on-verifier-backend=" + std::string(kCFIStructuralBackend),
            "/tmp/dwarf_cli_cfi_fail_on_verifier_backend_structural_z3.txt", out_fail);
        assert(code_fail == 2);
        assert(out_fail.find("gate FAILED") != std::string::npos);
        assert(out_fail.find("disallowed by fail-on-verifier-backend") != std::string::npos);
        assert(out_fail.find("gate_trigger=fail_on_verifier_backend") != std::string::npos);
    }

    {
        std::string out_fail_json;
        int code_fail_json = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --lhs-fde-index=0 --rhs-fde-index=0 --fail-on-verifier-backend=" + std::string(kCFIStructuralBackend) +
                " --format=json --schema-version=1",
            "/tmp/dwarf_cli_cfi_fail_on_verifier_backend_structural_z3.json", out_fail_json);
        assert(code_fail_json == 2);
        std::string gate_obj = extractObjectForKey(out_fail_json, "gate");
        assert(!gate_obj.empty());
        bool ok_pass = false;
        bool pass = extractBoolFieldFromObject(gate_obj, "pass", &ok_pass);
        assert(ok_pass && !pass);
        assert(extractStringFieldFromObject(gate_obj, "trigger") == "fail_on_verifier_backend");
        assert(extractStringFieldFromObject(gate_obj, "trigger_detail") == kCFIStructuralBackend);
        assert(extractStringFieldFromObject(gate_obj, "signature") ==
               "pass=0;trigger=fail_on_verifier_backend;detail=" + std::string(kCFIStructuralBackend));
    }

    {
        std::string out_fail_json;
        int code_fail_json = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --lhs-fde-index=0 --rhs-fde-index=0 --fail-on-solver-result=equivalent" +
                std::string(" --fail-on-verifier-backend=") + kCFIStructuralBackend +
                " --format=json --schema-version=1",
            "/tmp/dwarf_cli_cfi_fail_on_both_solver_and_backend.json", out_fail_json);
        assert(code_fail_json == 2);
        assert(out_fail_json.find("\"trigger\":\"fail_on_solver_result\"") != std::string::npos);
        assert(out_fail_json.find("\"trigger_detail\":\"equivalent\"") != std::string::npos);
        assert(out_fail_json.find("\"signature\":\"pass=0;trigger=fail_on_solver_result;detail=equivalent\"") != std::string::npos);
    }

    {
        std::string out_fail;
        int code_fail = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --lhs-fde-index=0 --rhs-fde-index=0 --fail-on-solver-result=equivalent" +
                std::string(" --fail-on-verifier-backend=") + kCFIStructuralBackend,
            "/tmp/dwarf_cli_cfi_fail_on_both_solver_and_backend.txt", out_fail);
        assert(code_fail == 2);
        assert(out_fail.find("gate_trigger=fail_on_solver_result") != std::string::npos);
        assert(out_fail.find("solver_result=equivalent disallowed by fail-on-solver-result") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --gate-profile=bad",
            "/tmp/dwarf_cli_compare_cfi_bad_gate_profile.txt", out);
        assert(code == 1);
        assert(out.find("invalid --gate-profile") != std::string::npos);
    }

    {
        std::string out_bad_schema;
        int code_bad_schema = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --format=json --schema-version=2",
            "/tmp/dwarf_cli_compare_cfi_bad_schema.txt", out_bad_schema);
        assert(code_bad_schema == 1);
        assert(out_bad_schema.find("unsupported --schema-version") != std::string::npos);
    }

    {
        const std::string big_elf = firstExisting({"./simple_test_elf", "../simple_test_elf"});
        assert(!big_elf.empty());

        std::string out_text;
        int code_text = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + big_elf +
                " --all-fdes --max-rows=1",
            "/tmp/dwarf_cli_compare_cfi_range_mismatch_text.txt", out_text);
        assert(code_text == 2);
        assert(out_text.find("precheck_fde_range_mismatch") != std::string::npos);
        assert(out_text.find("|DIFFERENT|structural|precheck_fde_range_mismatch|") != std::string::npos);

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + big_elf +
                " --all-fdes --max-rows=1 --format=json --schema-version=1",
            "/tmp/dwarf_cli_compare_cfi_range_mismatch_json.txt", out_json);
        assert(code_json == 2);
        assert(out_json.find("\"solver_result_counts\"") != std::string::npos);
        assert(out_json.find("\"precheck_fde_range_mismatch\"") != std::string::npos);
        assert(out_json.find("\"verifier_backend\":\"structural\"") != std::string::npos);
        assert(out_json.find("\"solver_result\":\"precheck_fde_range_mismatch\"") != std::string::npos);

        std::string out_missing;
        int code_missing = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + big_elf +
                " --all-fdes --max-rows=1 --fail-on-missing",
            "/tmp/dwarf_cli_compare_cfi_missing_fail.txt", out_missing);
        assert(code_missing == 2);
        assert(out_missing.find("gate FAILED") != std::string::npos);
        assert(out_missing.find("missing_lhs=") != std::string::npos);
    }

    {
        const std::string big_elf = firstExisting({"./simple_test_elf", "../simple_test_elf"});
        assert(!big_elf.empty());

        std::string out_strict;
        int code_strict = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + big_elf +
                " --all-fdes --strict --max-rows=1",
            "/tmp/dwarf_cli_compare_cfi_strict.txt", out_strict);
        assert(code_strict == 2);
        assert(out_strict.find("gate FAILED") != std::string::npos);

        std::string out_relaxed;
        int code_relaxed = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + big_elf +
                " --all-fdes --strict --allow-unknown --allow-missing --max-different=100000 --max-rows=1",
            "/tmp/dwarf_cli_compare_cfi_relaxed.txt", out_relaxed);
        assert(code_relaxed == 0);
        assert(out_relaxed.find("mode=all-fdes") != std::string::npos);

        std::string out_fail_solver;
        int code_fail_solver = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + big_elf +
                " --all-fdes --allow-unknown --allow-missing --max-different=100000 --max-rows=1 "
                "--fail-on-solver-result=precheck_fde_range_mismatch",
            "/tmp/dwarf_cli_compare_cfi_fail_on_precheck_solver.txt", out_fail_solver);
        assert(code_fail_solver == 2);
        assert(out_fail_solver.find("gate_trigger=fail_on_solver_result") != std::string::npos);
        assert(out_fail_solver.find("precheck_fde_range_mismatch") != std::string::npos);

        std::string out_fail_solver_json;
        int code_fail_solver_json = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + big_elf +
                " --all-fdes --allow-unknown --allow-missing --max-different=100000 --max-rows=1 "
                "--fail-on-solver-result=precheck_fde_range_mismatch --format=json --schema-version=1",
            "/tmp/dwarf_cli_compare_cfi_fail_on_precheck_solver.json", out_fail_solver_json);
        assert(code_fail_solver_json == 2);
        assert(out_fail_solver_json.find("\"trigger\":\"fail_on_solver_result\"") != std::string::npos);
        assert(out_fail_solver_json.find("\"trigger_detail\":\"precheck_fde_range_mismatch\"") != std::string::npos);
        assert(out_fail_solver_json.find("\"signature\":\"pass=0;trigger=fail_on_solver_result;detail=precheck_fde_range_mismatch\"") != std::string::npos);

        std::string out_fail_backend;
        int code_fail_backend = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + big_elf +
                " --all-fdes --allow-unknown --allow-missing --max-different=100000 --max-rows=1 "
                "--fail-on-verifier-backend=structural",
            "/tmp/dwarf_cli_compare_cfi_fail_on_structural_backend.txt", out_fail_backend);
        assert(code_fail_backend == 2);
        assert(out_fail_backend.find("gate_trigger=fail_on_verifier_backend") != std::string::npos);
        assert(out_fail_backend.find("verifier_backend=structural") != std::string::npos);

        std::string out_fail_backend_json;
        int code_fail_backend_json = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + big_elf +
                " --all-fdes --allow-unknown --allow-missing --max-different=100000 --max-rows=1 "
                "--fail-on-verifier-backend=structural --format=json --schema-version=1",
            "/tmp/dwarf_cli_compare_cfi_fail_on_structural_backend.json", out_fail_backend_json);
        assert(code_fail_backend_json == 2);
        assert(out_fail_backend_json.find("\"trigger\":\"fail_on_verifier_backend\"") != std::string::npos);
        assert(out_fail_backend_json.find("\"trigger_detail\":\"structural\"") != std::string::npos);
        assert(out_fail_backend_json.find("\"signature\":\"pass=0;trigger=fail_on_verifier_backend;detail=structural\"") != std::string::npos);
    }

    {
        std::string out_ok;
        int code_ok = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --lhs-fde-index=0 --rhs-fde-index=0 "
                "--cfa=0x1000 --frame-base=0x2000 --tls-base=0x3000 --object-address=0x4000 "
                "--address-size=8 --offset-size=4 --reg=1:0x55 "
                "--differential-trials=4 --register-count=16 --seed=0x1234 --no-differential",
            "/tmp/dwarf_cli_compare_cfi_ctx_ok.txt", out_ok);
        assert(code_ok == 0);
        assert(out_ok.find("|EQUIVALENT|") != std::string::npos);
    }

    {
        std::string out_func;
        int code_func = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf + " --func=main",
            "/tmp/dwarf_cli_compare_cfi_func.txt", out_func);
        assert(code_func == 0);
        assert(out_func.find("mode=func") != std::string::npos);
        assert(out_func.find("|EQUIVALENT|") != std::string::npos);
    }

    {
        std::string out_fail;
        int code_fail = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --lhs-fde-index=999 --rhs-fde-index=999 --max-unknown=0",
            "/tmp/dwarf_cli_compare_cfi_fail.txt", out_fail);
        assert(code_fail == 2);
        assert(out_fail.find("gate FAILED") != std::string::npos);
    }

    {
        std::string out_report_only;
        int code_report_only = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --lhs-fde-index=999 --rhs-fde-index=999 --max-unknown=0 --report-only",
            "/tmp/dwarf_cli_compare_cfi_report_only.txt", out_report_only);
        assert(code_report_only == 0);
        assert(out_report_only.find("gate_pass=0") != std::string::npos);
    }

    {
        std::string out_bad;
        int code_bad = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --lhs-fde-index=0 --rhs-fde-index=0 --register-count=0",
            "/tmp/dwarf_cli_compare_cfi_bad_regcount.txt", out_bad);
        assert(code_bad == 1);
        assert(out_bad.find("invalid --register-count") != std::string::npos);
    }

    {
        const std::string out_path = "/tmp/dwarf_cli_compare_cfi_out.txt";
        std::string out_stdout;
        int code_out = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --max-rows=1 --output=" + out_path,
            "/tmp/dwarf_cli_compare_cfi_out_stdout.txt", out_stdout);
        assert(code_out == 0);
        std::string file_text = readFile(out_path);
        assert(file_text.find("mode=all-fdes") != std::string::npos);
        assert(file_text.find("lhs_index|rhs_index|") != std::string::npos);

        std::string out_bad_path;
        int code_bad_path = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --output=/tmp/__dwarf_no_dir__/cfi.txt",
            "/tmp/dwarf_cli_compare_cfi_bad_output.txt", out_bad_path);
        assert(code_bad_path == 1);
        assert(out_bad_path.find("cannot open output file") != std::string::npos);
    }

    {
        std::string out_bad_mix;
        int code_bad_mix = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --func=main --lhs-pc=0x1000 --rhs-pc=0x1000",
            "/tmp/dwarf_cli_compare_cfi_bad_mix.txt", out_bad_mix);
        assert(code_bad_mix == 1);
        assert(out_bad_mix.find("do not mix --*-pc with --*-func") != std::string::npos);
    }

    {
        std::string out_bad_mix2;
        int code_bad_mix2 = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --lhs-pc=0x1000 --rhs-pc=0x1000",
            "/tmp/dwarf_cli_compare_cfi_bad_mix2.txt", out_bad_mix2);
        assert(code_bad_mix2 == 1);
        assert(out_bad_mix2.find("--all-fdes cannot be combined") != std::string::npos);
    }

    {
        const std::string semantic_elf = makeSemanticPayloadELF("dwarf_cli_semantic_payload");

        std::string out_text;
        int code_text = runAndCapture(
            dwarf_dump + " --debug-info " + semantic_elf,
            "/tmp/dwarf_cli_semantic_payload.txt", out_text);
        assert(code_text == 0);
        assert(out_text.find("DW_AT_call_value\texpr[2]: 23 04  ; semantic=DW_OP_plus_uconst") !=
               std::string::npos);
        assert(out_text.find("DW_AT_call_parameter\tblock[2]: 10 05  ; semantic=DW_OP_constu") !=
               std::string::npos);
        assert(out_text.find("DW_AT_discr_list\texpr[2]: 31 32  ; semantic=DW_OP_lit1 DW_OP_lit2") !=
               std::string::npos);

        std::string out_verbose;
        int code_verbose = runAndCapture(
            dwarf_dump + " --debug-info --verbose " + semantic_elf,
            "/tmp/dwarf_cli_semantic_payload_verbose.txt", out_verbose);
        assert(code_verbose == 0);
        assert(out_verbose.find("tokens=[DW_OP_plus_uconst] ; bytes=0x2304") != std::string::npos);
        assert(out_verbose.find("tokens=[DW_OP_constu] ; bytes=0x1005") != std::string::npos);
        assert(out_verbose.find("tokens=[DW_OP_lit1, DW_OP_lit2] ; bytes=0x3132") != std::string::npos);
        assert(out_verbose.find("DW_AT_name\tpayload ; semantic=") == std::string::npos);
    }

    {
        std::string out_bad_pair_scope;
        int code_bad_pair_scope = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf + " --pair-by=range",
            "/tmp/dwarf_cli_compare_cfi_bad_pair_scope.txt", out_bad_pair_scope);
        assert(code_bad_pair_scope == 1);
        assert(out_bad_pair_scope.find("--pair-by is only valid with --all-fdes") != std::string::npos);

        std::string out_bad_pair_value;
        int code_bad_pair_value = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf + " --all-fdes --pair-by=bad",
            "/tmp/dwarf_cli_compare_cfi_bad_pair_value.txt", out_bad_pair_value);
        assert(code_bad_pair_value == 1);
        assert(out_bad_pair_value.find("invalid --pair-by") != std::string::npos);
    }

    {
        std::string out_bad_sort;
        int code_bad_sort = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf + " --sort=bad",
            "/tmp/dwarf_cli_compare_cfi_bad_sort.txt", out_bad_sort);
        assert(code_bad_sort == 1);
        assert(out_bad_sort.find("invalid --sort value") != std::string::npos);
    }

    {
        std::string out_bad_combo;
        int code_bad_combo = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --only-different --only-unknown",
            "/tmp/dwarf_cli_compare_cfi_bad_only_combo.txt", out_bad_combo);
        assert(code_bad_combo == 1);
        assert(out_bad_combo.find("mutually exclusive") != std::string::npos);
    }

    {
        const std::string summary_file =
            firstExisting({"./test_data/vendor_expression_triage_summary.json",
                          "../test_data/vendor_expression_triage_summary.json"});
        assert(!summary_file.empty());
        const std::string summary = readFile(summary_file);
        assert(summary.find("\"selection_status\":\"no_safe_family_selected\"") != std::string::npos);
        assert(summary.find("\"selection_reason\":\"no_vendor_opcodes_observed\"") != std::string::npos);
        assert(summary.find("\"scope\":\"checked-in-repository-fixtures\"") != std::string::npos);
    }

    std::cout << "dwarf_dump CLI tests passed!" << std::endl;
    return 0;
}
