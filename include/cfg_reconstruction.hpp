#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace ELFIO {
class elfio;
}

namespace dwarf {

enum class CFGArchitecture : uint8_t {
    UNKNOWN = 0,
    AARCH64 = 1
};

struct CFGReconstructionOptions {
    bool include_fallthrough_edges = true;
    bool normalize_pc_relative_immediates = true;
    // Absolute-address byte ranges [start, end) to mask out before hashing.
    std::vector<std::pair<uint64_t, uint64_t>> relocation_ranges;
};

struct BasicBlock {
    uint64_t start = 0;
    uint64_t end = 0;
    uint64_t hash = 0;
    std::vector<uint64_t> successors;

    uint64_t size() const { return end > start ? (end - start) : 0; }
};

struct ControlFlowGraph {
    uint64_t function_start = 0;
    uint64_t function_end = 0;
    CFGArchitecture architecture = CFGArchitecture::UNKNOWN;
    std::vector<BasicBlock> blocks;

    bool empty() const { return blocks.empty(); }
};

struct CFGBlockMapping {
    uint64_t old_block = 0;
    uint64_t new_block = 0;
    uint64_t old_size = 0;
    uint64_t new_size = 0;
    uint64_t block_hash = 0;
};

struct DFGNode {
    uint64_t instruction_address = 0;
    uint64_t block_start = 0;
    std::vector<uint16_t> defs;
    std::vector<uint16_t> uses;
};

struct DFGEdge {
    size_t from_node = 0;
    size_t to_node = 0;
    uint16_t reg = 0;
    bool cross_block = false;
};

struct DataFlowGraph {
    std::vector<DFGNode> nodes;
    std::vector<DFGEdge> edges;
};

struct FunctionPointerCallsite {
    uint64_t instruction_address = 0;
    uint16_t pointer_reg = 0;
    std::vector<uint64_t> reaching_def_instructions;
    std::vector<uint64_t> candidate_target_addresses;
};

struct FunctionPointerAnalysisResult {
    size_t indirect_calls = 0;
    std::vector<FunctionPointerCallsite> callsites;
};

class CFGReconstructor {
public:
    // Reconstruct a CFG for one function blob. `function_bytes` must correspond to
    // [function_start, function_start + function_size).
    static bool reconstruct(const std::vector<uint8_t>& function_bytes,
                            uint64_t function_start,
                            uint64_t function_size,
                            CFGArchitecture architecture,
                            ControlFlowGraph& out_cfg,
                            const CFGReconstructionOptions& options = {});

    // Best-effort architecture name parsing (e.g. "aarch64", "arm64").
    static CFGArchitecture parseArchitecture(const std::string& name);

    // Collect relocation-affected absolute byte ranges by target section name.
    static std::map<std::string, std::vector<std::pair<uint64_t, uint64_t>>>
    collectRelocationRangesBySection(const ELFIO::elfio& elf);
};

class CFGMatcher {
public:
    // Match blocks between two CFGs using:
    // 1) unique normalized block hashes
    // 2) predecessor/successor-hash context disambiguation for repeated hashes
    static std::vector<CFGBlockMapping> matchBlocks(const ControlFlowGraph& old_cfg,
                                                    const ControlFlowGraph& new_cfg);
};

class DFGBuilder {
public:
    // Build an AArch64 register-level DFG for one function using CFG structure.
    // The decoder is conservative and intentionally partial; unknown instructions
    // produce no def/use records.
    static bool buildAArch64RegisterDFG(const std::vector<uint8_t>& function_bytes,
                                        uint64_t function_start,
                                        uint64_t function_size,
                                        const ControlFlowGraph& cfg,
                                        DataFlowGraph& out_dfg);
};

class FunctionPointerAnalyzer {
public:
    // Analyze AArch64 indirect callsites (BLR reg) and infer candidate target
    // addresses from reaching definitions carried by the DFG.
    static bool analyzeAArch64(const std::vector<uint8_t>& function_bytes,
                               uint64_t function_start,
                               uint64_t function_size,
                               const DataFlowGraph& dfg,
                               FunctionPointerAnalysisResult& out_result);
};

} // namespace dwarf
