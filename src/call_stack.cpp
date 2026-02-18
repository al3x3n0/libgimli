#include "call_stack.hpp"
#include "dwarf_parser.hpp"
#include "attribute_parser.hpp"
#include "dwarf_utils.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace dwarf {

// Helper to extract low_pc from DIE
static uint64_t getDIELowPC(const std::shared_ptr<DIE>& die) {
    if (!die) return 0;
    auto attr = die->getAttribute(DwarfAttribute::DW_AT_low_pc);
    if (!attr) return 0;
    auto addr_attr = std::dynamic_pointer_cast<AddressAttributeValue>(attr);
    if (addr_attr) return addr_attr->getAddress();
    auto uint_attr = std::dynamic_pointer_cast<UnsignedAttributeValue>(attr);
    if (uint_attr) return uint_attr->getValue();
    return 0;
}

// Helper to extract high_pc from DIE (may be relative or absolute)
static uint64_t getDIEHighPC(const std::shared_ptr<DIE>& die, uint64_t low_pc = 0) {
    if (!die) return 0;
    auto attr = die->getAttribute(DwarfAttribute::DW_AT_high_pc);
    if (!attr) return 0;
    auto addr_attr = std::dynamic_pointer_cast<AddressAttributeValue>(attr);
    if (addr_attr) return addr_attr->getAddress();
    auto uint_attr = std::dynamic_pointer_cast<UnsignedAttributeValue>(attr);
    if (uint_attr) {
        uint64_t val = uint_attr->getValue();
        // If value is smaller than low_pc, it's a size (relative)
        if (val < low_pc && low_pc > 0) {
            return low_pc + val;
        }
        return val;
    }
    return 0;
}

// StackFrame implementation

std::string StackFrame::toString() const {
    std::ostringstream oss;

    oss << "#" << std::setw(2) << std::setfill(' ') << 0;  // Frame number set externally
    oss << "  0x" << std::hex << std::setw(16) << std::setfill('0') << pc;

    if (is_inlined) {
        oss << " [inlined]";
    }

    if (!function_name.empty()) {
        oss << " in " << function_name;
        if (function_start != 0) {
            oss << "+0x" << std::hex << (pc - function_start);
        }
    } else {
        oss << " in ??";
    }

    if (!source_file.empty()) {
        oss << " at " << source_file;
        if (line > 0) {
            oss << ":" << std::dec << line;
            if (column > 0) {
                oss << ":" << column;
            }
        }
    }

    if (is_inlined && !inlined_at_file.empty()) {
        oss << " (inlined at " << inlined_at_file;
        if (inlined_at_line > 0) {
            oss << ":" << std::dec << inlined_at_line;
        }
        oss << ")";
    }

    return oss.str();
}

std::string StackFrame::toShortString() const {
    std::ostringstream oss;

    if (!function_name.empty()) {
        oss << function_name;
    } else {
        oss << "0x" << std::hex << pc;
    }

    if (!source_file.empty() && line > 0) {
        // Extract just filename
        std::string filename = source_file;
        size_t pos = source_file.find_last_of('/');
        if (pos != std::string::npos) {
            filename = source_file.substr(pos + 1);
        }
        oss << " at " << filename << ":" << std::dec << line;
    }

    return oss.str();
}

// CallStack implementation

std::string CallStack::toString() const {
    std::ostringstream oss;

    if (frames.empty()) {
        oss << "(empty call stack)";
        if (!error.empty()) {
            oss << "\nError: " << error;
        }
        return oss.str();
    }

    for (size_t i = 0; i < frames.size(); ++i) {
        if (i > 0) oss << "\n";

        oss << "#" << std::setw(2) << std::setfill(' ') << i;
        oss << "  0x" << std::hex << std::setw(16) << std::setfill('0') << frames[i].pc;

        if (frames[i].is_inlined) {
            oss << " [inlined]";
        }

        if (!frames[i].function_name.empty()) {
            oss << " in " << frames[i].function_name;
            if (frames[i].function_start != 0 && frames[i].pc >= frames[i].function_start) {
                oss << "+0x" << std::hex << (frames[i].pc - frames[i].function_start);
            }
        } else {
            oss << " in ??";
        }

        if (!frames[i].source_file.empty()) {
            oss << " at " << frames[i].source_file;
            if (frames[i].line > 0) {
                oss << ":" << std::dec << frames[i].line;
            }
        }
    }

    if (!complete) {
        oss << "\n... (truncated)";
    }

    if (!error.empty()) {
        oss << "\nError: " << error;
    }

    return oss.str();
}

// CallStackBuilder implementation

CallStackBuilder::CallStackBuilder(const DwarfParser& parser)
    : parser_(parser), config_(arch::aarch64()) {
    // Default to aarch64 since that's what we've been testing with
}

CallStack CallStackBuilder::buildCallStack(uint64_t pc, const std::vector<uint64_t>& registers) {
    CallStack stack;
    std::vector<uint64_t> current_regs = registers;

    for (uint32_t frame_num = 0; frame_num < config_.max_frames; ++frame_num) {
        // Build current frame
        StackFrame frame = buildFrame(pc, current_regs);

        if (!frame.valid()) {
            stack.error = "Invalid frame at depth " + std::to_string(frame_num);
            break;
        }

        // Add inlined frames if configured
        if (config_.include_inlined && frame_num == 0) {
            populateInlinedFrames(stack.frames, pc, current_regs);
        }

        stack.frames.push_back(frame);

        // Check if we should stop
        if (shouldStopUnwinding(frame)) {
            stack.complete = true;
            break;
        }

        // Try to unwind to next frame
        if (!unwindFrame(frame, current_regs)) {
            stack.error = "Failed to unwind at depth " + std::to_string(frame_num);
            break;
        }

        // Get next PC from return address
        pc = frame.return_address;
        if (pc == 0) {
            stack.complete = true;
            break;
        }

        // Adjust PC to point to call site (return address - instruction size)
        // This is architecture-dependent.
        if (pc > config_.return_address_adjust) {
            pc -= config_.return_address_adjust;
        }
    }

    if (stack.frames.size() >= config_.max_frames) {
        stack.error = "Maximum frame depth reached";
    }

    return stack;
}

CallStack CallStackBuilder::buildCallStack(uint64_t pc) {
    // Build initial register state from register reader
    // Keep headroom: AArch64 DWARF register numbers can exceed GPRs (SIMD, etc.).
    std::vector<uint64_t> registers(256, 0);

    if (register_reader_) {
        for (uint64_t i = 0; i < registers.size(); ++i) {
            auto val = register_reader_(i);
            if (val) {
                registers[i] = *val;
            }
        }
    }

    return buildCallStack(pc, registers);
}

StackFrame CallStackBuilder::buildFrame(uint64_t pc, const std::vector<uint64_t>& registers) {
    StackFrame frame;
    frame.pc = pc;
    frame.registers = registers;

    // Get SP and FP from registers
    if (config_.sp_register < registers.size()) {
        frame.sp = registers[config_.sp_register];
    }
    if (config_.fp_register < registers.size()) {
        frame.fp = registers[config_.fp_register];
    }

    // Populate function info
    if (config_.resolve_symbols) {
        populateFunctionInfo(frame, pc);
    }

    // Populate source info
    if (config_.resolve_source) {
        populateSourceInfo(frame, pc);
    }

    return frame;
}

std::vector<InlinedCallSite> CallStackBuilder::getInlinedCallSites(uint64_t pc) const {
    std::vector<InlinedCallSite> sites;

    // Find function containing this PC
    auto func_die = findFunctionAtAddress(pc);
    if (!func_die) {
        return sites;
    }

    // Look for inlined subroutines within this function
    std::function<void(const std::shared_ptr<DIE>&)> findInlined;
    findInlined = [&](const std::shared_ptr<DIE>& die) {
        if (die->getTag() == DwarfTag::DW_TAG_inlined_subroutine) {
            // Check if PC is within this inlined range
            uint64_t low_pc = getDIELowPC(die);
            uint64_t high_pc = getDIEHighPC(die, low_pc);

            if (pc >= low_pc && pc < high_pc) {
                InlinedCallSite site;
                site.low_pc = low_pc;
                site.high_pc = high_pc;

                // Get function name from DW_AT_abstract_origin
                auto origin_attr = die->getAttribute(DwarfAttribute::DW_AT_abstract_origin);
                if (origin_attr) {
                    auto ref_attr = std::dynamic_pointer_cast<ReferenceAttributeValue>(origin_attr);
                    if (ref_attr) {
                        auto origin_die = parser_.findDIEByOffset(ref_attr->getOffset());
                        if (origin_die) {
                            site.function_name = origin_die->getName();
                        }
                    }
                }

                // Get call site info
                auto call_file_attr = die->getAttribute(DwarfAttribute::DW_AT_call_file);
                auto call_line_attr = die->getAttribute(DwarfAttribute::DW_AT_call_line);
                auto call_col_attr = die->getAttribute(DwarfAttribute::DW_AT_call_column);

                if (call_line_attr) {
                    auto unsigned_attr = std::dynamic_pointer_cast<UnsignedAttributeValue>(call_line_attr);
                    if (unsigned_attr) {
                        site.line = static_cast<uint32_t>(unsigned_attr->getValue());
                    }
                }
                if (call_col_attr) {
                    auto unsigned_attr = std::dynamic_pointer_cast<UnsignedAttributeValue>(call_col_attr);
                    if (unsigned_attr) {
                        site.column = static_cast<uint32_t>(unsigned_attr->getValue());
                    }
                }

                sites.push_back(site);
            }
        }

        // Recurse into children
        for (const auto& child : die->getChildren()) {
            findInlined(child);
        }
    };

    findInlined(func_die);
    return sites;
}

std::shared_ptr<DIE> CallStackBuilder::findFunctionAtAddress(uint64_t pc) const {
    auto functions = parser_.getFunctions();

    for (const auto& func : functions) {
        uint64_t low_pc = getDIELowPC(func);
        uint64_t high_pc = getDIEHighPC(func, low_pc);

        if (low_pc != 0 && pc >= low_pc && pc < high_pc) {
            return func;
        }

        // Check ranges attribute for non-contiguous functions
        auto ranges_attr = func->getAttribute(DwarfAttribute::DW_AT_ranges);
        if (ranges_attr) {
            auto range_attr = std::dynamic_pointer_cast<RangeAttributeValue>(ranges_attr);
            if (range_attr) {
                for (const auto& range : range_attr->getRanges()) {
                    if (!range.is_base_address && pc >= range.start && pc < range.end) {
                        return func;
                    }
                }
            }
        }
    }

    return nullptr;
}

std::optional<SourceLocation> CallStackBuilder::resolveSourceLocation(uint64_t pc) const {
    return parser_.getSourceLocation(pc);
}

bool CallStackBuilder::unwindFrame(StackFrame& frame, std::vector<uint64_t>& registers) {
    // Get unwind info from CFI
    UnwindInfo info = parser_.getUnwindInfo(frame.pc);
    if (!info.valid) {
        return false;
    }

    // Create memory reader wrapper
    auto mem_reader = [this](uint64_t addr) -> uint64_t {
        return this->readAddress(addr);
    };

    // Compute CFA (may require memory if CFA is an expression).
    uint64_t cfa = info.computeCFA(registers, mem_reader);
    if (cfa == 0) {
        return false;
    }

    // Unwind registers
    std::vector<uint64_t> new_registers = registers;

    for (const auto& [reg_num, rule] : info.registers) {
        auto value = info.getRegisterValue(reg_num, registers, cfa, mem_reader);
        if (value && reg_num < new_registers.size()) {
            new_registers[reg_num] = *value;
        }
    }

    // Get return address
    auto ra = info.getRegisterValue(info.return_address_register, registers, cfa, mem_reader);
    if (ra) {
        frame.return_address = *ra;
    } else {
        return false;
    }

    registers = new_registers;
    return true;
}

void CallStackBuilder::populateFunctionInfo(StackFrame& frame, uint64_t pc) {
    auto func_die = findFunctionAtAddress(pc);
    if (!func_die) {
        return;
    }

    frame.function_name = func_die->getName();
    frame.die_offset = func_die->getOffset();

    // Get linkage name if available
    auto linkage_attr = func_die->getAttribute(DwarfAttribute::DW_AT_linkage_name);
    if (linkage_attr) {
        auto str_attr = std::dynamic_pointer_cast<StringAttributeValue>(linkage_attr);
        if (str_attr) {
            frame.linkage_name = str_attr->getValue();
        }
    }

    // Get function bounds
    frame.function_start = getDIELowPC(func_die);
    frame.function_end = getDIEHighPC(func_die, frame.function_start);
}

void CallStackBuilder::populateSourceInfo(StackFrame& frame, uint64_t pc) {
    auto loc = parser_.getSourceLocation(pc);
    if (loc) {
        frame.source_file = loc->file;
        frame.line = loc->line;
        frame.column = loc->column;
    }
}

void CallStackBuilder::populateInlinedFrames(std::vector<StackFrame>& frames, uint64_t pc,
                                              const std::vector<uint64_t>& registers) {
    auto sites = getInlinedCallSites(pc);

    // Sort by nesting level (innermost first)
    // For now, just add them in order found
    for (const auto& site : sites) {
        StackFrame frame;
        frame.pc = pc;
        frame.registers = registers;
        frame.is_inlined = true;
        frame.function_name = site.function_name;
        frame.function_start = site.low_pc;
        frame.function_end = site.high_pc;
        frame.inlined_at_file = site.source_file;
        frame.inlined_at_line = site.line;

        // Get source info for the inlined code
        populateSourceInfo(frame, pc);

        frames.push_back(frame);
    }
}

bool CallStackBuilder::shouldStopUnwinding(const StackFrame& frame) const {
    if (config_.stop_at_main && frame.function_name == "main") {
        return true;
    }
    if (config_.stop_at_start &&
        (frame.function_name == "_start" || frame.function_name == "__libc_start_main")) {
        return true;
    }
    return false;
}

bool CallStackBuilder::readMemory(uint64_t address, size_t size, void* buffer) const {
    if (memory_reader_) {
        return memory_reader_(address, size, buffer);
    }
    return false;
}

uint64_t CallStackBuilder::readAddress(uint64_t address) const {
    size_t size = config_.address_size;

    std::vector<uint8_t> buf(size, 0);
    if (readMemory(address, size, buf.data())) {
        const bool little = DwarfUtils::objectIsLittleEndian();
        uint64_t v = 0;
        if (little) {
            for (size_t i = 0; i < size && i < 8; ++i) {
                v |= (static_cast<uint64_t>(buf[i]) << (i * 8));
            }
            return v;
        }
        for (size_t i = 0; i < size && i < 8; ++i) {
            v = (v << 8) | static_cast<uint64_t>(buf[i]);
        }
        return v;
    }
    return 0;
}

} // namespace dwarf
