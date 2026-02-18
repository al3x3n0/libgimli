#pragma once

#include "dwarf_types.hpp"
#include "cfi_parser.hpp"
#include "source_location.hpp"
#include <vector>
#include <string>
#include <functional>
#include <memory>
#include <optional>
#include <cstdint>

namespace dwarf {

// Forward declarations
class DwarfParser;
class DIE;

// Represents a single stack frame
struct StackFrame {
    uint64_t pc = 0;                    // Program counter for this frame
    uint64_t sp = 0;                    // Stack pointer
    uint64_t fp = 0;                    // Frame pointer (if available)
    uint64_t return_address = 0;        // Return address to caller

    // Function information
    std::string function_name;          // Demangled function name
    std::string linkage_name;           // Mangled/linkage name
    uint64_t function_start = 0;        // Function start address
    uint64_t function_end = 0;          // Function end address

    // Source location
    std::string source_file;            // Source file path
    uint32_t line = 0;                  // Line number
    uint32_t column = 0;                // Column number

    // Inlining information
    bool is_inlined = false;            // Is this an inlined frame?
    std::string inlined_at_file;        // File where inlined
    uint32_t inlined_at_line = 0;       // Line where inlined

    // DIE reference
    uint64_t die_offset = 0;            // Offset of function DIE

    // Register state (architecture-dependent)
    std::vector<uint64_t> registers;

    // Validation
    bool valid() const { return pc != 0; }
    bool has_source_info() const { return !source_file.empty() && line > 0; }
    bool has_function_info() const { return !function_name.empty(); }

    // Format as string
    std::string toString() const;
    std::string toShortString() const;  // Just "function at file:line"
};

// Inlined call site information
struct InlinedCallSite {
    std::string function_name;
    std::string source_file;
    uint32_t line = 0;
    uint32_t column = 0;
    uint64_t low_pc = 0;
    uint64_t high_pc = 0;
};

// Complete call stack
struct CallStack {
    std::vector<StackFrame> frames;
    bool complete = false;              // Did we reach the bottom?
    std::string error;                  // Error message if unwinding failed

    size_t depth() const { return frames.size(); }
    bool empty() const { return frames.empty(); }

    // Format entire stack
    std::string toString() const;

    // Get frame at index (0 = innermost/current)
    const StackFrame* getFrame(size_t index) const {
        return index < frames.size() ? &frames[index] : nullptr;
    }
};

// Memory reader callback type
using MemoryReader = std::function<bool(uint64_t address, size_t size, void* buffer)>;

// Register reader callback type (returns register value by number)
using RegisterReader = std::function<std::optional<uint64_t>(uint64_t reg_num)>;

// Call stack builder configuration
struct CallStackConfig {
    uint32_t max_frames = 256;          // Maximum frames to unwind
    bool include_inlined = true;        // Include inlined function frames
    bool resolve_symbols = true;        // Look up function names
    bool resolve_source = true;         // Look up source locations
    bool stop_at_main = true;           // Stop when reaching main()
    bool stop_at_start = true;          // Stop when reaching _start

    // Architecture-specific register numbers
    uint64_t pc_register = 0;           // Program counter register
    uint64_t sp_register = 0;           // Stack pointer register
    uint64_t fp_register = 0;           // Frame pointer register
    uint64_t ra_register = 0;           // Return address register
    uint8_t address_size = 8;           // Address size in bytes
    uint8_t return_address_adjust = 0;  // PC = RA - adjust (best-effort call-site PC)
};

// Predefined configurations for common architectures
namespace arch {
    // x86-64 (AMD64)
    inline CallStackConfig x86_64() {
        CallStackConfig cfg;
        cfg.pc_register = 16;   // RIP
        cfg.sp_register = 7;    // RSP
        cfg.fp_register = 6;    // RBP
        cfg.ra_register = 16;   // Return address in RIP after ret
        cfg.address_size = 8;
        cfg.return_address_adjust = 1;  // RA points after call; subtract 1 to stay in call insn
        return cfg;
    }

    // AArch64 (ARM64)
    inline CallStackConfig aarch64() {
        CallStackConfig cfg;
        cfg.pc_register = 32;   // PC
        cfg.sp_register = 31;   // SP
        cfg.fp_register = 29;   // X29/FP
        cfg.ra_register = 30;   // X30/LR
        cfg.address_size = 8;
        cfg.return_address_adjust = 4;  // AArch64 instructions are 4 bytes
        return cfg;
    }

    // ARM 32-bit
    inline CallStackConfig arm32() {
        CallStackConfig cfg;
        cfg.pc_register = 15;   // PC
        cfg.sp_register = 13;   // SP
        cfg.fp_register = 11;   // FP
        cfg.ra_register = 14;   // LR
        cfg.address_size = 4;
        cfg.return_address_adjust = 4;  // Best-effort (ARM state)
        return cfg;
    }

    // x86 32-bit
    inline CallStackConfig x86_32() {
        CallStackConfig cfg;
        cfg.pc_register = 8;    // EIP
        cfg.sp_register = 4;    // ESP
        cfg.fp_register = 5;    // EBP
        cfg.ra_register = 8;    // Return address via stack
        cfg.address_size = 4;
        cfg.return_address_adjust = 1;
        return cfg;
    }
}

// Call stack builder - combines CFI unwinding with symbol/source resolution
class CallStackBuilder {
public:
    explicit CallStackBuilder(const DwarfParser& parser);

    // Set configuration
    void setConfig(const CallStackConfig& config) { config_ = config; }
    const CallStackConfig& getConfig() const { return config_; }

    // Set memory reader for stack unwinding
    void setMemoryReader(MemoryReader reader) { memory_reader_ = reader; }

    // Set register reader for initial state
    void setRegisterReader(RegisterReader reader) { register_reader_ = reader; }

    // Build call stack starting from given PC and registers
    CallStack buildCallStack(uint64_t pc, const std::vector<uint64_t>& registers);

    // Build call stack using register reader callback
    CallStack buildCallStack(uint64_t pc);

    // Build a single frame (no unwinding)
    StackFrame buildFrame(uint64_t pc, const std::vector<uint64_t>& registers);

    // Get inlined call sites at a given PC
    std::vector<InlinedCallSite> getInlinedCallSites(uint64_t pc) const;

    // Find function containing address
    std::shared_ptr<DIE> findFunctionAtAddress(uint64_t pc) const;

    // Resolve source location for address
    std::optional<SourceLocation> resolveSourceLocation(uint64_t pc) const;

private:
    const DwarfParser& parser_;
    CallStackConfig config_;
    MemoryReader memory_reader_;
    RegisterReader register_reader_;

    // Internal helpers
    bool unwindFrame(StackFrame& frame, std::vector<uint64_t>& registers);
    void populateFunctionInfo(StackFrame& frame, uint64_t pc);
    void populateSourceInfo(StackFrame& frame, uint64_t pc);
    void populateInlinedFrames(std::vector<StackFrame>& frames, uint64_t pc,
                               const std::vector<uint64_t>& registers);
    bool shouldStopUnwinding(const StackFrame& frame) const;

    // Read memory helper
    bool readMemory(uint64_t address, size_t size, void* buffer) const;
    uint64_t readAddress(uint64_t address) const;
};

} // namespace dwarf
