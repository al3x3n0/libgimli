#include "cfg_reconstruction.hpp"

#include <elfio/elfio.hpp>
#include <elfio/elfio_relocation.hpp>

#include <algorithm>
#include <map>
#include <set>
#include <tuple>

namespace dwarf {

namespace {

uint32_t readU32LE(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

int64_t signExtend(uint64_t x, unsigned bits) {
    const uint64_t m = 1ULL << (bits - 1U);
    return static_cast<int64_t>((x ^ m) - m);
}

uint64_t fnv1a64(const uint8_t* data, size_t size) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < size; ++i) {
        h ^= static_cast<uint64_t>(data[i]);
        h *= 1099511628211ULL;
    }
    return h;
}

bool isAArch64CondBranch(uint32_t insn) {
    return (insn & 0xFF000010U) == 0x54000000U;
}

bool isAArch64UncondBranch(uint32_t insn) {
    return (insn & 0xFC000000U) == 0x14000000U;
}

bool isAArch64CallImm(uint32_t insn) {
    return (insn & 0xFC000000U) == 0x94000000U;
}

bool isAArch64CBZ(uint32_t insn) {
    return (insn & 0x7F000000U) == 0x34000000U;
}

bool isAArch64TBZ(uint32_t insn) {
    return (insn & 0x7F000000U) == 0x36000000U;
}

bool isAArch64RET(uint32_t insn) {
    return (insn & 0xFFFFFC1FU) == 0xD65F0000U;
}

bool branchTargetAArch64(uint64_t pc, uint32_t insn, uint64_t& target) {
    if (isAArch64UncondBranch(insn)) {
        const uint64_t imm26 = static_cast<uint64_t>(insn & 0x03FFFFFFU);
        const int64_t disp = signExtend(imm26, 26) << 2;
        target = static_cast<uint64_t>(static_cast<int64_t>(pc) + disp);
        return true;
    }
    if (isAArch64CondBranch(insn)) {
        const uint64_t imm19 = static_cast<uint64_t>((insn >> 5) & 0x7FFFFU);
        const int64_t disp = signExtend(imm19, 19) << 2;
        target = static_cast<uint64_t>(static_cast<int64_t>(pc) + disp);
        return true;
    }
    if (isAArch64CBZ(insn)) {
        const uint64_t imm19 = static_cast<uint64_t>((insn >> 5) & 0x7FFFFU);
        const int64_t disp = signExtend(imm19, 19) << 2;
        target = static_cast<uint64_t>(static_cast<int64_t>(pc) + disp);
        return true;
    }
    if (isAArch64TBZ(insn)) {
        const uint64_t imm14 = static_cast<uint64_t>((insn >> 5) & 0x3FFFU);
        const int64_t disp = signExtend(imm14, 14) << 2;
        target = static_cast<uint64_t>(static_cast<int64_t>(pc) + disp);
        return true;
    }
    return false;
}

uint32_t normalizeInsnAArch64(uint32_t insn, const CFGReconstructionOptions& options) {
    if (!options.normalize_pc_relative_immediates) return insn;
    if (isAArch64UncondBranch(insn) || isAArch64CallImm(insn)) {
        return insn & 0xFC000000U;
    }
    if (isAArch64CondBranch(insn)) {
        return insn & 0xFF00001FU;
    }
    if (isAArch64CBZ(insn)) {
        return insn & 0xFF00001FU;
    }
    if (isAArch64TBZ(insn)) {
        return insn & 0xFFF8001FU;
    }
    // ADR
    if ((insn & 0x9F000000U) == 0x10000000U) {
        return insn & 0x9F00001FU;
    }
    // ADRP
    if ((insn & 0x9F000000U) == 0x90000000U) {
        return insn & 0x9F00001FU;
    }
    // LDR literal (integer/simd classes)
    if ((insn & 0x3B000000U) == 0x18000000U) {
        return insn & 0xFF00001FU;
    }
    return insn;
}

uint64_t normalizedBlockHash(const std::vector<uint8_t>& bytes,
                             size_t offset,
                             size_t size,
                             uint64_t block_start,
                             CFGArchitecture arch,
                             const CFGReconstructionOptions& options) {
    std::vector<uint8_t> normalized(size);
    for (size_t i = 0; i < size; ++i) normalized[i] = bytes[offset + i];

    if (arch == CFGArchitecture::AARCH64 && size >= 4) {
        const size_t full_insns = (size / 4) * 4;
        for (size_t i = 0; i < full_insns; i += 4) {
            uint32_t insn = readU32LE(normalized.data() + i);
            const uint32_t masked = normalizeInsnAArch64(insn, options);
            normalized[i + 0] = static_cast<uint8_t>(masked & 0xFFU);
            normalized[i + 1] = static_cast<uint8_t>((masked >> 8) & 0xFFU);
            normalized[i + 2] = static_cast<uint8_t>((masked >> 16) & 0xFFU);
            normalized[i + 3] = static_cast<uint8_t>((masked >> 24) & 0xFFU);
        }
    }

    if (!options.relocation_ranges.empty()) {
        for (size_t i = 0; i < size; ++i) {
            const uint64_t addr = block_start + static_cast<uint64_t>(i);
            for (const auto& range : options.relocation_ranges) {
                if (addr >= range.first && addr < range.second) {
                    normalized[i] = 0;
                    break;
                }
            }
        }
    }

    return fnv1a64(normalized.data(), normalized.size());
}

bool reconstructAArch64(const std::vector<uint8_t>& function_bytes,
                        uint64_t function_start,
                        uint64_t function_size,
                        const CFGReconstructionOptions& options,
                        ControlFlowGraph& out_cfg) {
    out_cfg = {};
    out_cfg.architecture = CFGArchitecture::AARCH64;
    out_cfg.function_start = function_start;
    out_cfg.function_end = function_start + function_size;

    if (function_size == 0 || function_bytes.empty()) return true;
    if (function_bytes.size() < function_size) return false;

    const uint64_t end = function_start + function_size;
    std::set<uint64_t> leaders;
    leaders.insert(function_start);

    for (size_t off = 0; off + 4 <= function_size; off += 4) {
        const uint64_t pc = function_start + static_cast<uint64_t>(off);
        const uint32_t insn = readU32LE(function_bytes.data() + off);
        uint64_t target = 0;
        if (branchTargetAArch64(pc, insn, target)) {
            if (target >= function_start && target < end) leaders.insert(target);
            if (!isAArch64UncondBranch(insn) && options.include_fallthrough_edges) {
                const uint64_t next = pc + 4;
                if (next < end) leaders.insert(next);
            }
        } else if (isAArch64RET(insn)) {
            const uint64_t next = pc + 4;
            if (next < end) leaders.insert(next);
        }
    }

    std::vector<uint64_t> starts(leaders.begin(), leaders.end());
    std::sort(starts.begin(), starts.end());
    out_cfg.blocks.reserve(starts.size());
    std::map<uint64_t, size_t> block_index_by_start;
    for (size_t i = 0; i < starts.size(); ++i) {
        const uint64_t start = starts[i];
        const uint64_t block_end = (i + 1 < starts.size()) ? starts[i + 1] : end;
        if (block_end <= start) continue;

        const size_t rel = static_cast<size_t>(start - function_start);
        const size_t block_size = static_cast<size_t>(block_end - start);
        if (rel + block_size > function_bytes.size()) continue;

        BasicBlock bb;
        bb.start = start;
        bb.end = block_end;
        bb.hash = normalizedBlockHash(function_bytes, rel, block_size, start, CFGArchitecture::AARCH64, options);
        block_index_by_start[bb.start] = out_cfg.blocks.size();
        out_cfg.blocks.push_back(std::move(bb));
    }

    for (size_t i = 0; i < out_cfg.blocks.size(); ++i) {
        BasicBlock& bb = out_cfg.blocks[i];
        const size_t rel = static_cast<size_t>(bb.start - function_start);
        const size_t block_size = static_cast<size_t>(bb.end - bb.start);
        if (block_size < 4 || rel + block_size > function_bytes.size()) {
            continue;
        }
        const uint32_t term = readU32LE(function_bytes.data() + rel + block_size - 4);
        uint64_t target = 0;
        if (branchTargetAArch64(bb.end - 4, term, target)) {
            auto it = block_index_by_start.find(target);
            if (it != block_index_by_start.end()) bb.successors.push_back(target);
            if (!isAArch64UncondBranch(term) && options.include_fallthrough_edges && i + 1 < out_cfg.blocks.size()) {
                bb.successors.push_back(out_cfg.blocks[i + 1].start);
            }
            continue;
        }
        if (isAArch64RET(term)) continue;
        if (options.include_fallthrough_edges && i + 1 < out_cfg.blocks.size()) {
            bb.successors.push_back(out_cfg.blocks[i + 1].start);
        }
    }

    return true;
}

std::string joinHashesSorted(std::vector<uint64_t> v) {
    std::sort(v.begin(), v.end());
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i != 0) out.push_back(',');
        out += std::to_string(v[i]);
    }
    return out;
}

using AddressRange = std::pair<uint64_t, uint64_t>;

std::vector<AddressRange> mergeRanges(std::vector<AddressRange> ranges) {
    if (ranges.empty()) return {};
    std::sort(ranges.begin(), ranges.end(), [](const AddressRange& a, const AddressRange& b) {
        if (a.first != b.first) return a.first < b.first;
        return a.second < b.second;
    });
    std::vector<AddressRange> merged;
    merged.reserve(ranges.size());
    merged.push_back(ranges.front());
    for (size_t i = 1; i < ranges.size(); ++i) {
        AddressRange& back = merged.back();
        if (ranges[i].first <= back.second) {
            if (ranges[i].second > back.second) back.second = ranges[i].second;
        } else {
            merged.push_back(ranges[i]);
        }
    }
    return merged;
}

uint64_t relocationMaskWidth(ELFIO::Elf_Half machine, unsigned reloc_type) {
    if (machine == ELFIO::EM_AARCH64) {
        constexpr unsigned R_AARCH64_ABS16 = 259;
        constexpr unsigned R_AARCH64_ABS32 = 258;
        constexpr unsigned R_AARCH64_ABS64 = 257;
        constexpr unsigned R_AARCH64_PREL16 = 262;
        constexpr unsigned R_AARCH64_PREL32 = 261;
        constexpr unsigned R_AARCH64_PREL64 = 260;
        switch (reloc_type) {
            case R_AARCH64_ABS64:
            case R_AARCH64_PREL64:
                return 8;
            case R_AARCH64_ABS16:
            case R_AARCH64_PREL16:
                return 2;
            case R_AARCH64_ABS32:
            case R_AARCH64_PREL32:
                return 4;
            default:
                return 4;
        }
    }
    return 4;
}

std::map<uint64_t, uint64_t> buildHashByStart(const ControlFlowGraph& cfg) {
    std::map<uint64_t, uint64_t> out;
    for (const auto& b : cfg.blocks) out[b.start] = b.hash;
    return out;
}

std::map<uint64_t, std::vector<uint64_t>> buildPredecessorHashes(
    const ControlFlowGraph& cfg,
    const std::map<uint64_t, uint64_t>& hash_by_start) {
    std::map<uint64_t, std::vector<uint64_t>> pred_hashes;
    for (const auto& b : cfg.blocks) {
        for (uint64_t succ : b.successors) {
            if (hash_by_start.find(succ) == hash_by_start.end()) continue;
            pred_hashes[succ].push_back(b.hash);
        }
    }
    return pred_hashes;
}

std::string blockContextKey(const BasicBlock& b,
                            const std::map<uint64_t, std::vector<uint64_t>>& pred_hashes,
                            const std::map<uint64_t, uint64_t>& hash_by_start) {
    std::vector<uint64_t> succ_hashes;
    succ_hashes.reserve(b.successors.size());
    for (uint64_t succ : b.successors) {
        auto it = hash_by_start.find(succ);
        if (it != hash_by_start.end()) succ_hashes.push_back(it->second);
    }
    auto pit = pred_hashes.find(b.start);
    std::vector<uint64_t> preds = (pit == pred_hashes.end()) ? std::vector<uint64_t>{} : pit->second;

    return "sz=" + std::to_string(b.size()) +
           "|pred=" + joinHashesSorted(preds) +
           "|succ=" + joinHashesSorted(succ_hashes);
}

void addUniqueReg(std::vector<uint16_t>& regs, uint16_t reg) {
    if (std::find(regs.begin(), regs.end(), reg) == regs.end()) regs.push_back(reg);
}

void decodeAArch64RegDefUse(uint32_t insn, std::vector<uint16_t>& defs, std::vector<uint16_t>& uses) {
    const uint16_t rd = static_cast<uint16_t>(insn & 0x1FU);
    const uint16_t rn = static_cast<uint16_t>((insn >> 5) & 0x1FU);
    const uint16_t rm = static_cast<uint16_t>((insn >> 16) & 0x1FU);

    // BR/BLR/RET (register branches)
    if ((insn & 0xFFFFFC1FU) == 0xD61F0000U) { // BR Xn
        addUniqueReg(uses, rn);
        return;
    }
    if ((insn & 0xFFFFFC1FU) == 0xD63F0000U) { // BLR Xn
        addUniqueReg(uses, rn);
        addUniqueReg(defs, 30);
        return;
    }
    if ((insn & 0xFFFFFC1FU) == 0xD65F0000U) { // RET Xn
        addUniqueReg(uses, rn);
        return;
    }

    if (isAArch64CallImm(insn)) { // BL imm26
        addUniqueReg(defs, 30);
        return;
    }
    if (isAArch64UncondBranch(insn) || isAArch64CondBranch(insn)) return;
    if (isAArch64CBZ(insn) || ((insn & 0x7F000000U) == 0x35000000U)) { // CBNZ
        addUniqueReg(uses, rd);
        return;
    }
    if (isAArch64TBZ(insn) || ((insn & 0x7F000000U) == 0x37000000U)) { // TBNZ
        addUniqueReg(uses, rd);
        return;
    }

    // ADR/ADRP
    if ((insn & 0x9F000000U) == 0x10000000U || (insn & 0x9F000000U) == 0x90000000U) {
        addUniqueReg(defs, rd);
        return;
    }

    // LDR literal
    if ((insn & 0x3B000000U) == 0x18000000U) {
        addUniqueReg(defs, rd);
        return;
    }

    // ADD/SUB (immediate), 32/64-bit and flag/non-flag forms.
    const uint32_t op_imm = insn & 0x1F000000U;
    if (op_imm == 0x11000000U || op_imm == 0x31000000U ||
        op_imm == 0x51000000U || op_imm == 0x71000000U ||
        op_imm == 0x91000000U || op_imm == 0xB1000000U ||
        op_imm == 0xD1000000U || op_imm == 0xF1000000U) {
        addUniqueReg(defs, rd);
        addUniqueReg(uses, rn);
        return;
    }

    // Move wide immediates (MOVN/MOVZ/MOVK), 32/64-bit.
    const uint32_t wide = insn & 0x7F800000U;
    if (wide == 0x12800000U || wide == 0x52800000U || wide == 0x72800000U ||
        wide == 0x92800000U || wide == 0xD2800000U || wide == 0xF2800000U) {
        addUniqueReg(defs, rd);
        if (wide == 0x72800000U || wide == 0xF2800000U) addUniqueReg(uses, rd); // MOVK reads old value
        return;
    }

    // Common load/store unsigned immediate form: base in Rn, Rt is def/use by load/store bit.
    if ((insn & 0x3B000000U) == 0x39000000U) {
        const bool is_load = (insn & 0x00400000U) != 0;
        addUniqueReg(uses, rn);
        if (is_load) {
            addUniqueReg(defs, rd);
        } else {
            addUniqueReg(uses, rd);
        }
        return;
    }

    // Generic data-processing register fallback (conservative heuristic).
    if ((insn & 0x1A000000U) == 0x0A000000U) {
        addUniqueReg(defs, rd);
        addUniqueReg(uses, rn);
        addUniqueReg(uses, rm);
        return;
    }
}

bool decodeAArch64ADROrADRP(uint32_t insn, uint64_t pc, uint64_t& out_target) {
    const uint64_t immlo = static_cast<uint64_t>((insn >> 29) & 0x3U);
    const uint64_t immhi = static_cast<uint64_t>((insn >> 5) & 0x7FFFFU);
    const uint64_t imm21 = (immhi << 2) | immlo;
    if ((insn & 0x9F000000U) == 0x10000000U) { // ADR
        const int64_t disp = signExtend(imm21, 21);
        out_target = static_cast<uint64_t>(static_cast<int64_t>(pc) + disp);
        return true;
    }
    if ((insn & 0x9F000000U) == 0x90000000U) { // ADRP
        const int64_t disp_pages = signExtend(imm21, 21) << 12;
        const uint64_t page = pc & ~0xFFFULL;
        out_target = static_cast<uint64_t>(static_cast<int64_t>(page) + disp_pages);
        return true;
    }
    return false;
}

bool isAArch64BLR(uint32_t insn, uint16_t& reg) {
    if ((insn & 0xFFFFFC1FU) != 0xD63F0000U) return false;
    reg = static_cast<uint16_t>((insn >> 5) & 0x1FU);
    return true;
}

size_t findBlockStartForAddress(const ControlFlowGraph& cfg, uint64_t address, uint64_t& out_start) {
    for (size_t i = 0; i < cfg.blocks.size(); ++i) {
        const auto& b = cfg.blocks[i];
        if (address >= b.start && address < b.end) {
            out_start = b.start;
            return i;
        }
    }
    out_start = 0;
    return static_cast<size_t>(-1);
}

template <typename T>
bool mapEquals(const std::map<uint16_t, std::set<T>>& a, const std::map<uint16_t, std::set<T>>& b) {
    if (a.size() != b.size()) return false;
    auto ia = a.begin();
    auto ib = b.begin();
    while (ia != a.end()) {
        if (ia->first != ib->first || ia->second != ib->second) return false;
        ++ia;
        ++ib;
    }
    return true;
}

} // namespace

CFGArchitecture CFGReconstructor::parseArchitecture(const std::string& name) {
    std::string lowered = name;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) {
        if (c >= 'A' && c <= 'Z') return static_cast<char>(c - 'A' + 'a');
        return static_cast<char>(c);
    });
    if (lowered == "aarch64" || lowered == "arm64") return CFGArchitecture::AARCH64;
    return CFGArchitecture::UNKNOWN;
}

bool CFGReconstructor::reconstruct(const std::vector<uint8_t>& function_bytes,
                                   uint64_t function_start,
                                   uint64_t function_size,
                                   CFGArchitecture architecture,
                                   ControlFlowGraph& out_cfg,
                                   const CFGReconstructionOptions& options) {
    if (function_size > function_bytes.size()) return false;
    if (architecture == CFGArchitecture::AARCH64) {
        return reconstructAArch64(function_bytes, function_start, function_size, options, out_cfg);
    }
    out_cfg = {};
    out_cfg.architecture = architecture;
    out_cfg.function_start = function_start;
    out_cfg.function_end = function_start + function_size;
    return false;
}

std::map<std::string, std::vector<std::pair<uint64_t, uint64_t>>>
CFGReconstructor::collectRelocationRangesBySection(const ELFIO::elfio& elf) {
    std::map<std::string, std::vector<std::pair<uint64_t, uint64_t>>> out;
    for (const auto& section : elf.sections) {
        const auto type = section->get_type();
        if (type != ELFIO::SHT_REL && type != ELFIO::SHT_RELA) continue;

        const ELFIO::Elf_Word target_index = section->get_info();
        if (target_index >= elf.sections.size()) continue;
        const ELFIO::section* target = elf.sections[target_index];
        if (!target) continue;

        const uint64_t target_size = target->get_size();
        const uint64_t target_addr = target->get_address();
        if (target_size == 0) continue;

        ELFIO::relocation_section_accessor relocs(elf, const_cast<ELFIO::section*>(section.get()));
        const auto count = relocs.get_entries_num();
        auto& ranges = out[target->get_name()];
        for (ELFIO::Elf_Xword i = 0; i < count; ++i) {
            ELFIO::Elf64_Addr offset = 0;
            ELFIO::Elf_Word symbol = 0;
            unsigned reloc_type = 0;
            ELFIO::Elf_Sxword addend = 0;
            if (!relocs.get_entry(i, offset, symbol, reloc_type, addend)) continue;
            (void)symbol;
            (void)addend;
            if (offset >= target_size) continue;
            const uint64_t width = relocationMaskWidth(elf.get_machine(), reloc_type);
            const uint64_t end_off = std::min<uint64_t>(target_size, static_cast<uint64_t>(offset) + width);
            const uint64_t start = target_addr + static_cast<uint64_t>(offset);
            const uint64_t end = target_addr + end_off;
            if (end > start) ranges.push_back({start, end});
        }
    }
    for (auto& kv : out) {
        kv.second = mergeRanges(std::move(kv.second));
    }
    return out;
}

std::vector<CFGBlockMapping> CFGMatcher::matchBlocks(const ControlFlowGraph& old_cfg,
                                                     const ControlFlowGraph& new_cfg) {
    std::vector<CFGBlockMapping> out;
    std::map<uint64_t, std::vector<BasicBlock>> old_by_hash;
    std::map<uint64_t, std::vector<BasicBlock>> new_by_hash;
    for (const auto& b : old_cfg.blocks) old_by_hash[b.hash].push_back(b);
    for (const auto& b : new_cfg.blocks) new_by_hash[b.hash].push_back(b);

    const auto old_hash_by_start = buildHashByStart(old_cfg);
    const auto new_hash_by_start = buildHashByStart(new_cfg);
    const auto old_pred_hashes = buildPredecessorHashes(old_cfg, old_hash_by_start);
    const auto new_pred_hashes = buildPredecessorHashes(new_cfg, new_hash_by_start);

    for (const auto& kv : old_by_hash) {
        const auto itn = new_by_hash.find(kv.first);
        if (itn == new_by_hash.end()) continue;

        if (kv.second.size() == 1 && itn->second.size() == 1) {
            const BasicBlock& ob = kv.second.front();
            const BasicBlock& nb = itn->second.front();
            out.push_back(CFGBlockMapping{
                ob.start,
                nb.start,
                ob.end - ob.start,
                nb.end - nb.start,
                kv.first
            });
            continue;
        }

        std::map<std::string, std::vector<BasicBlock>> old_by_ctx;
        std::map<std::string, std::vector<BasicBlock>> new_by_ctx;
        for (const auto& ob : kv.second) {
            old_by_ctx[blockContextKey(ob, old_pred_hashes, old_hash_by_start)].push_back(ob);
        }
        for (const auto& nb : itn->second) {
            new_by_ctx[blockContextKey(nb, new_pred_hashes, new_hash_by_start)].push_back(nb);
        }

        for (const auto& ctx : old_by_ctx) {
            const auto new_ctx_it = new_by_ctx.find(ctx.first);
            if (new_ctx_it == new_by_ctx.end()) continue;
            if (ctx.second.size() != 1 || new_ctx_it->second.size() != 1) continue;
            const BasicBlock& ob = ctx.second.front();
            const BasicBlock& nb = new_ctx_it->second.front();
            out.push_back(CFGBlockMapping{
                ob.start,
                nb.start,
                ob.end - ob.start,
                nb.end - nb.start,
                kv.first
            });
        }
    }

    std::sort(out.begin(), out.end(), [](const CFGBlockMapping& a, const CFGBlockMapping& b) {
        if (a.old_block != b.old_block) return a.old_block < b.old_block;
        return a.new_block < b.new_block;
    });
    return out;
}

bool DFGBuilder::buildAArch64RegisterDFG(const std::vector<uint8_t>& function_bytes,
                                         uint64_t function_start,
                                         uint64_t function_size,
                                         const ControlFlowGraph& cfg,
                                         DataFlowGraph& out_dfg) {
    out_dfg = {};
    if (cfg.architecture != CFGArchitecture::AARCH64) return false;
    if (function_size > function_bytes.size()) return false;

    std::vector<std::vector<size_t>> block_nodes(cfg.blocks.size());
    std::map<uint64_t, size_t> block_index_by_start;
    for (size_t i = 0; i < cfg.blocks.size(); ++i) block_index_by_start[cfg.blocks[i].start] = i;

    for (size_t off = 0; off + 4 <= function_size; off += 4) {
        const uint64_t addr = function_start + static_cast<uint64_t>(off);
        uint64_t block_start = 0;
        const size_t block_index = findBlockStartForAddress(cfg, addr, block_start);
        if (block_index == static_cast<size_t>(-1)) continue;

        const uint32_t insn = readU32LE(function_bytes.data() + off);
        DFGNode node;
        node.instruction_address = addr;
        node.block_start = block_start;
        decodeAArch64RegDefUse(insn, node.defs, node.uses);
        if (node.defs.empty() && node.uses.empty()) continue;

        const size_t node_index = out_dfg.nodes.size();
        out_dfg.nodes.push_back(std::move(node));
        block_nodes[block_index].push_back(node_index);
    }

    std::vector<std::vector<size_t>> preds(cfg.blocks.size());
    for (size_t i = 0; i < cfg.blocks.size(); ++i) {
        for (uint64_t succ : cfg.blocks[i].successors) {
            auto it = block_index_by_start.find(succ);
            if (it != block_index_by_start.end()) preds[it->second].push_back(i);
        }
    }

    std::vector<std::map<uint16_t, size_t>> block_gen(cfg.blocks.size());
    for (size_t bi = 0; bi < cfg.blocks.size(); ++bi) {
        for (size_t node_idx : block_nodes[bi]) {
            for (uint16_t reg : out_dfg.nodes[node_idx].defs) block_gen[bi][reg] = node_idx;
        }
    }

    using DefSetMap = std::map<uint16_t, std::set<size_t>>;
    std::vector<DefSetMap> in(cfg.blocks.size());
    std::vector<DefSetMap> out(cfg.blocks.size());
    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t bi = 0; bi < cfg.blocks.size(); ++bi) {
            DefSetMap new_in;
            for (size_t p : preds[bi]) {
                for (const auto& kv : out[p]) {
                    auto& s = new_in[kv.first];
                    s.insert(kv.second.begin(), kv.second.end());
                }
            }

            DefSetMap new_out = new_in;
            for (const auto& kv : block_gen[bi]) {
                new_out[kv.first].clear();
                new_out[kv.first].insert(kv.second);
            }

            if (!mapEquals(in[bi], new_in) || !mapEquals(out[bi], new_out)) {
                in[bi] = std::move(new_in);
                out[bi] = std::move(new_out);
                changed = true;
            }
        }
    }

    std::set<std::tuple<size_t, size_t, uint16_t>> edge_seen;
    for (size_t bi = 0; bi < cfg.blocks.size(); ++bi) {
        DefSetMap current = in[bi];
        for (size_t node_idx : block_nodes[bi]) {
            const auto& node = out_dfg.nodes[node_idx];
            for (uint16_t reg : node.uses) {
                auto it = current.find(reg);
                if (it == current.end()) continue;
                for (size_t from_idx : it->second) {
                    if (!edge_seen.insert(std::make_tuple(from_idx, node_idx, reg)).second) continue;
                    out_dfg.edges.push_back(DFGEdge{
                        from_idx,
                        node_idx,
                        reg,
                        out_dfg.nodes[from_idx].block_start != node.block_start
                    });
                }
            }
            for (uint16_t reg : node.defs) {
                current[reg].clear();
                current[reg].insert(node_idx);
            }
        }
    }

    std::sort(out_dfg.edges.begin(), out_dfg.edges.end(), [](const DFGEdge& a, const DFGEdge& b) {
        if (a.from_node != b.from_node) return a.from_node < b.from_node;
        if (a.to_node != b.to_node) return a.to_node < b.to_node;
        return a.reg < b.reg;
    });
    return true;
}

bool FunctionPointerAnalyzer::analyzeAArch64(const std::vector<uint8_t>& function_bytes,
                                             uint64_t function_start,
                                             uint64_t function_size,
                                             const DataFlowGraph& dfg,
                                             FunctionPointerAnalysisResult& out_result) {
    out_result = {};
    if (function_size > function_bytes.size()) return false;

    std::map<uint64_t, size_t> node_by_addr;
    for (size_t i = 0; i < dfg.nodes.size(); ++i) {
        node_by_addr[dfg.nodes[i].instruction_address] = i;
    }

    std::vector<std::vector<size_t>> incoming(dfg.nodes.size());
    for (size_t ei = 0; ei < dfg.edges.size(); ++ei) {
        const auto& e = dfg.edges[ei];
        if (e.to_node < incoming.size()) incoming[e.to_node].push_back(ei);
    }

    for (size_t off = 0; off + 4 <= function_size; off += 4) {
        const uint64_t addr = function_start + static_cast<uint64_t>(off);
        const uint32_t insn = readU32LE(function_bytes.data() + off);
        uint16_t call_reg = 0;
        if (!isAArch64BLR(insn, call_reg)) continue;

        FunctionPointerCallsite cs;
        cs.instruction_address = addr;
        cs.pointer_reg = call_reg;
        ++out_result.indirect_calls;

        auto node_it = node_by_addr.find(addr);
        if (node_it != node_by_addr.end()) {
            const size_t to_idx = node_it->second;
            std::set<size_t> def_nodes;
            for (size_t edge_idx : incoming[to_idx]) {
                const auto& e = dfg.edges[edge_idx];
                if (e.reg == call_reg) def_nodes.insert(e.from_node);
            }
            for (size_t from_idx : def_nodes) {
                if (from_idx >= dfg.nodes.size()) continue;
                const uint64_t def_addr = dfg.nodes[from_idx].instruction_address;
                cs.reaching_def_instructions.push_back(def_addr);
                if (def_addr < function_start) continue;
                const uint64_t rel = def_addr - function_start;
                if (rel + 4 > function_bytes.size()) continue;
                const uint32_t def_insn = readU32LE(function_bytes.data() + static_cast<size_t>(rel));
                uint64_t cand = 0;
                if (decodeAArch64ADROrADRP(def_insn, def_addr, cand)) {
                    cs.candidate_target_addresses.push_back(cand);
                }
            }
        }

        std::sort(cs.reaching_def_instructions.begin(), cs.reaching_def_instructions.end());
        cs.reaching_def_instructions.erase(
            std::unique(cs.reaching_def_instructions.begin(), cs.reaching_def_instructions.end()),
            cs.reaching_def_instructions.end());
        std::sort(cs.candidate_target_addresses.begin(), cs.candidate_target_addresses.end());
        cs.candidate_target_addresses.erase(
            std::unique(cs.candidate_target_addresses.begin(), cs.candidate_target_addresses.end()),
            cs.candidate_target_addresses.end());
        out_result.callsites.push_back(std::move(cs));
    }

    std::sort(out_result.callsites.begin(), out_result.callsites.end(),
              [](const FunctionPointerCallsite& a, const FunctionPointerCallsite& b) {
                  return a.instruction_address < b.instruction_address;
              });
    return true;
}

} // namespace dwarf
