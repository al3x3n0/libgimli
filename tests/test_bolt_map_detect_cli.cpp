#include <cassert>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/wait.h>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

namespace {

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

int runAndCapture(const std::string& cmd, const std::string& out_path, std::string& out_text) {
    std::string full = cmd + " > " + out_path + " 2>&1";
    int rc = std::system(full.c_str());
    out_text = readFile(out_path);
    return exitCodeFromSystem(rc);
}

} // namespace

int main() {
    std::cout << "Running bolt_map_detect CLI tests..." << std::endl;

    const std::string bolt_map_detect = firstExisting({"./build/bolt_map_detect", "./bolt_map_detect"});
    const std::string test_elf = firstExisting({"./test_elf", "./test_data/test_dwarf4", "../test_elf"});
    assert(!bolt_map_detect.empty());
    assert(!test_elf.empty());

    {
        std::string out;
        int code = runAndCapture(bolt_map_detect + " --help", "/tmp/bolt_map_detect_help.txt", out);
        assert(code == 0);
        assert(out.find("--require-bolt") != std::string::npos);
        assert(out.find("--show-unmapped") != std::string::npos);
        assert(out.find("--mapping-level=<function|block>") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(bolt_map_detect + " " + test_elf, "/tmp/bolt_map_detect_non_bolt.txt", out);
        assert(code == 0);
        assert(out.find("bolt_detected=false") != std::string::npos);
        assert(out.find("mappings=0") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            bolt_map_detect + " --mapping-level=block " + test_elf,
            "/tmp/bolt_map_detect_block_non_bolt.txt",
            out);
        assert(code == 0);
        assert(out.find("mapping_level=block") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            bolt_map_detect + " --emit-dfg-json " + test_elf,
            "/tmp/bolt_map_detect_emit_dfg_bad_format.txt",
            out);
        assert(code == 1);
        assert(out.find("--emit-dfg-json requires --format=json") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            bolt_map_detect + " --format=json --dfg-summary-only " + test_elf,
            "/tmp/bolt_map_detect_dfg_summary_requires_emit.txt",
            out);
        assert(code == 1);
        assert(out.find("--dfg-summary-only requires --emit-dfg-json") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            bolt_map_detect + " --emit-analysis-json " + test_elf,
            "/tmp/bolt_map_detect_analysis_requires_json.txt",
            out);
        assert(code == 1);
        assert(out.find("--emit-analysis-json requires --format=json") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            bolt_map_detect + " --max-indirect-call-increase-total=0 " + test_elf,
            "/tmp/bolt_map_detect_gate_requires_block.txt",
            out);
        assert(code == 1);
        assert(out.find("analysis gates require --mapping-level=block") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            bolt_map_detect + " --format=json --mapping-level=block --emit-dfg-json " + test_elf,
            "/tmp/bolt_map_detect_emit_dfg_json.txt",
            out);
        assert(code == 0);
        assert(out.find("\"dfg\"") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            bolt_map_detect + " --format=json --mapping-level=block --emit-dfg-json --dfg-summary-only " + test_elf,
            "/tmp/bolt_map_detect_emit_dfg_summary_json.txt",
            out);
        assert(code == 0);
        assert(out.find("\"dfg\"") != std::string::npos);
        assert(out.find("\"instruction_address\"") == std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            bolt_map_detect + " --format=json --mapping-level=block --emit-analysis-json " + test_elf,
            "/tmp/bolt_map_detect_emit_analysis_json.txt",
            out);
        assert(code == 0);
        assert(out.find("\"analysis\"") != std::string::npos);
        assert(out.find("\"analysis_summary\"") != std::string::npos);
        assert(out.find("\"analysis_gate\"") != std::string::npos);
        assert(out.find("\"resolution_rate_old\"") != std::string::npos);
        assert(out.find("\"avg_best_confidence_new\"") != std::string::npos);
        assert(out.find("\"max_indirect_call_increase\"") != std::string::npos);
        assert(out.find("\"worst_resolution_drop\"") != std::string::npos);
        assert(out.find("\"delta_indirect_calls\"") != std::string::npos ||
               out.find("\"analysis\":[]") != std::string::npos);
        assert(out.find("\"delta_resolution_rate\"") != std::string::npos ||
               out.find("\"analysis\":[]") != std::string::npos);
        assert(out.find("\"candidate_target_symbols\"") != std::string::npos ||
               out.find("\"analysis\":[]") != std::string::npos);
        assert(out.find("\"candidate_target_symbol_scores\"") != std::string::npos ||
               out.find("\"analysis\":[]") != std::string::npos);
        assert(out.find("\"reason\"") != std::string::npos ||
               out.find("\"analysis\":[]") != std::string::npos);
        const bool has_fp_keys = out.find("\"old_fp\"") != std::string::npos &&
                                 out.find("\"new_fp\"") != std::string::npos;
        const bool empty_analysis = out.find("\"analysis\":[]") != std::string::npos;
        assert(has_fp_keys || empty_analysis);
    }

    {
        std::string out;
        int code = runAndCapture(
            bolt_map_detect +
                " --format=json --mapping-level=block --emit-analysis-json "
                "--max-indirect-call-increase-total=-1 " + test_elf,
            "/tmp/bolt_map_detect_gate_fail.txt",
            out);
        assert(code == 2);
        assert(out.find("analysis gate failed") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(
            bolt_map_detect + " --require-bolt " + test_elf,
            "/tmp/bolt_map_detect_require_bolt.txt",
            out);
        assert(code == 2);
        assert(out.find("does not look BOLT-optimized") != std::string::npos);
    }

    std::cout << "bolt_map_detect CLI tests passed!" << std::endl;
    return 0;
}
