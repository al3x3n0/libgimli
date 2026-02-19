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
        assert(out.find("--schema-version") != std::string::npos);
    }

    {
        std::string out;
        int code = runAndCapture(dwarf_dump + " compare-cfi --help", "/tmp/dwarf_cli_cfi_help.txt", out);
        assert(code == 0);
        assert(out.find("--lhs-fde-index") != std::string::npos);
        assert(out.find("--allow-range-mismatch") != std::string::npos);
        assert(out.find("--sort=<lhs-index|rhs-index|lhs-pc|rhs-pc|verdict>") != std::string::npos);
        assert(out.find("--show-equivalent") != std::string::npos);
        assert(out.find("--only-different") != std::string::npos);
        assert(out.find("--only-unknown") != std::string::npos);
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

        std::string out_bad_schema;
        int code_bad_schema = runAndCapture(
            dwarf_dump + " compare-expr " + test_elf + " " + test_elf +
                " --format=json --schema-version=9 --allow-unknown --allow-missing",
            "/tmp/dwarf_expr_bad_schema.txt", out_bad_schema);
        assert(code_bad_schema == 1);
        assert(out_bad_schema.find("unsupported --schema-version") != std::string::npos);
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
                " --summary-only --format=json --schema-version=1 --allow-unknown --allow-missing",
            "/tmp/dwarf_cli_summary_only_json.txt", out_json);
        assert(code_json == 0);
        assert(out_json.find("\"schema_version\":1") != std::string::npos);
        assert(out_json.find("\"report\"") != std::string::npos);
        assert(out_json.find("\"summary\"") != std::string::npos);
        assert(out_json.find("\"gate\"") != std::string::npos);
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
        assert(out_json.find("\"summary\"") != std::string::npos);
        assert(out_json.find("\"rows\"") != std::string::npos);
        assert(out_json.find("\"gate\"") != std::string::npos);
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
        assert(out_text.find("lhs_index|rhs_index|") == std::string::npos);

        std::string out_json;
        int code_json = runAndCapture(
            dwarf_dump + " compare-cfi " + test_elf + " " + test_elf +
                " --all-fdes --summary-only --format=json --schema-version=1",
            "/tmp/dwarf_cli_compare_cfi_summary_only_json.txt", out_json);
        assert(code_json == 0);
        assert(out_json.find("\"summary\"") != std::string::npos);
        assert(out_json.find("\"rows\"") == std::string::npos);
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

    std::cout << "dwarf_dump CLI tests passed!" << std::endl;
    return 0;
}
