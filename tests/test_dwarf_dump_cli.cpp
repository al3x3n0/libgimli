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
    std::cout << "Running dwarf_dump CLI tests..." << std::endl;

    const std::string dwarf_dump = firstExisting({"./build/dwarf_dump", "./dwarf_dump"});
    const std::string test_elf = firstExisting({"./test_elf", "../test_elf"});
    assert(!dwarf_dump.empty());
    assert(!test_elf.empty());

    {
        std::string out;
        int code = runAndCapture(dwarf_dump + " compare-expr --help", "/tmp/dwarf_cli_help.txt", out);
        assert(code == 0);
        assert(out.find("--strict-attr-present") != std::string::npos);
        assert(out.find("--no-differential") != std::string::npos);
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
                " --summary-only --format=json --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_summary_only_json.txt", out_json);
        assert(code_json == 0);
        assert(out_json.find("\"summary\"") != std::string::npos);
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

    std::cout << "dwarf_dump CLI tests passed!" << std::endl;
    return 0;
}
