#include "dwarf_parser.hpp"
#include "dwarf_utils.hpp"
#include "attribute_parser.hpp"
#include "debug_sup_parser.hpp"
#include "legacy_dwarf_parser.hpp"
#include <elfio/elfio_relocation.hpp>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <unordered_set>
#include <cstdint>
#include <sstream>

namespace dwarf {

static std::string pathDirname(const std::string& path);

static ELFIO::Elf_Half findSectionIndex(const ELFIO::elfio& elf, const ELFIO::section* target) {
    ELFIO::Elf_Half idx = 0;
    for (const auto& sec : elf.sections) {
        if (sec.get() == target) {
            return idx;
        }
        ++idx;
    }
    return static_cast<ELFIO::Elf_Half>(elf.sections.size());
}

static bool writeRelocatedValue(std::vector<uint8_t>& data,
                                uint64_t offset,
                                uint64_t value,
                                size_t width,
                                bool little_endian) {
    if (offset + width > data.size()) return false;
    if (little_endian) {
        for (size_t i = 0; i < width; ++i) {
            data[offset + i] = static_cast<uint8_t>((value >> (i * 8)) & 0xff);
        }
        return true;
    }
    for (size_t i = 0; i < width; ++i) {
        size_t shift = (width - 1 - i) * 8;
        data[offset + i] = static_cast<uint8_t>((value >> shift) & 0xff);
    }
    return true;
}

static void applyRelocationsToSection(const ELFIO::elfio& elf,
                                      const ELFIO::section* target,
                                      std::vector<uint8_t>& data) {
    if (!target || data.empty()) return;
    if (elf.get_type() != ELFIO::ET_REL) return;

    const ELFIO::Elf_Half target_index = findSectionIndex(elf, target);
    if (target_index >= elf.sections.size()) return;

    const bool little_endian = (elf.get_encoding() == ELFIO::ELFDATA2LSB);
    for (const auto& rel_sec_ptr : elf.sections) {
        const auto* rel_sec = rel_sec_ptr.get();
        if (!rel_sec) continue;
        const auto rel_type = rel_sec->get_type();
        if (rel_type != ELFIO::SHT_REL && rel_type != ELFIO::SHT_RELA) continue;
        if (rel_sec->get_info() != target_index) continue;
        if (rel_sec->get_link() >= elf.sections.size()) continue;

        auto* mutable_rel_sec = const_cast<ELFIO::section*>(rel_sec);
        auto* mutable_sym_sec = const_cast<ELFIO::section*>(elf.sections[rel_sec->get_link()]);
        ELFIO::relocation_section_accessor relocs(elf, mutable_rel_sec);
        ELFIO::symbol_section_accessor syms(elf, mutable_sym_sec);

        const auto count = relocs.get_entries_num();
        for (unsigned i = 0; i < count; ++i) {
            ELFIO::Elf64_Addr offset = 0;
            ELFIO::Elf_Word symbol = 0;
            unsigned reloc_kind = 0;
            ELFIO::Elf_Sxword addend = 0;
            if (!relocs.get_entry(i, offset, symbol, reloc_kind, addend)) continue;

            size_t width = 0;
            switch (reloc_kind) {
                case 10: // R_X86_64_32
                case 11: // R_X86_64_32S
                    width = 4;
                    break;
                case 1: // R_X86_64_64
                    width = 8;
                    break;
                default:
                    continue;
            }

            std::string name;
            ELFIO::Elf64_Addr value = 0;
            ELFIO::Elf_Xword size = 0;
            unsigned char bind = 0;
            unsigned char sym_type = 0;
            ELFIO::Elf_Half section_index = 0;
            unsigned char other = 0;
            if (!syms.get_symbol(symbol, name, value, size, bind, sym_type, section_index, other)) {
                continue;
            }

            uint64_t relocated = static_cast<uint64_t>(value) + static_cast<uint64_t>(addend);
            writeRelocatedValue(data, static_cast<uint64_t>(offset), relocated, width, little_endian);
        }
    }
}

static void appendVendorFormSkipSamples(DwarfParser::SupportTelemetry& telemetry,
                                        const std::vector<DIEParser::VendorFormSkipDetail>& samples) {
    constexpr size_t kMaxExamples = 8;
    for (const auto& s : samples) {
        std::string bucket = "child_die_payload";
        if (s.payload_offset < s.die_offset) {
            bucket = "before_die";
        } else if (s.is_unit_die) {
            bucket = "unit_die_payload";
        }
        telemetry.vendor_form_skip_offset_buckets[bucket] += 1;

        const std::string key = [&]() {
            std::ostringstream ks;
            ks << "form=0x" << std::hex << s.form << std::dec
               << ",attr=" << DwarfUtils::attributeToString(s.attr);
            return ks.str();
        }();
        if (std::find(telemetry.vendor_form_skip_example_keys.begin(),
                      telemetry.vendor_form_skip_example_keys.end(),
                      key) != telemetry.vendor_form_skip_example_keys.end()) {
            continue;
        }
        if (telemetry.vendor_form_skip_examples.size() >= kMaxExamples) break;
        std::ostringstream os;
        os << "form=0x" << std::hex << s.form
           << ",off=0x" << s.payload_offset
           << ",cu=0x" << s.cu_offset
           << ",die=0x" << s.die_offset
           << std::dec
           << ",attr=" << DwarfUtils::attributeToString(s.attr)
           << ",severity=" << (s.severity.empty() ? "unspecified" : s.severity);
        telemetry.vendor_form_skip_example_keys.push_back(key);
        telemetry.vendor_form_skip_examples.push_back(os.str());
        telemetry.vendor_form_skip_examples_structured.push_back(
            DwarfParser::SupportTelemetry::VendorFormSkipExample{
                s.form, s.payload_offset, s.cu_offset, s.die_offset, s.attr,
                s.severity.empty() ? "unspecified" : s.severity});
    }
}

static void mergeVendorFormSkipHistogram(DwarfParser::SupportTelemetry& telemetry,
                                         const std::vector<std::pair<uint16_t, uint64_t>>& hist) {
    for (const auto& kv : hist) {
        telemetry.vendor_form_skip_histogram[kv.first] += kv.second;
    }
}

static void mergeVendorFormSkipSeverityBuckets(DwarfParser::SupportTelemetry& telemetry,
                                               const std::vector<std::pair<std::string, uint64_t>>& hist) {
    for (const auto& kv : hist) {
        telemetry.vendor_form_skip_severity_buckets[kv.first] += kv.second;
    }
}

DwarfParser::DwarfParser(const std::string& filename)
    : filename_(filename), version_(DwarfVersion::DWARF4), address_size_(AddressSize::ADDR_64), is_valid_(false), verbose_(false) {
    elf_ = std::make_unique<ELFIO::elfio>();
}

bool DwarfParser::load() {
    support_telemetry_ = SupportTelemetry{};
    type_signature_die_offset_cache_.clear();
    if (!loadELFFile()) {
        return false;
    }
    
    if (!loadDWARFSections()) {
        return false;
    }

    const bool has_full_debug_info =
        !debug_info_.empty() && !debug_abbrev_.empty() && !debug_str_.empty();
    const bool has_partial_debug_info =
        !debug_info_.empty() || !debug_abbrev_.empty() || !debug_str_.empty();

    if (has_full_debug_info) {
        if (!parseCompilationUnits()) {
            return false;
        }
    } else if (has_partial_debug_info) {
        DwarfUtils::setLastError("Incomplete DWARF unit sections");
        return false;
    } else if (!hasCFI()) {
        DwarfUtils::setLastError("No DWARF debug info or CFI sections available");
        return false;
    }

    // If this file references supplementary debug info via .debug_sup, parse and cache those DIEs
    // so DW_FORM_ref_sup* references can be resolved through findDIEByOffset().
    integrateSupplementary();

    // If this is a split DWARF skeleton, try to load and parse .dwo units so
    // queries (functions/variables/types/lines) can see full debug info.
    integrateSplitDwarf();

    // Resolve standard DW_FORM_ref_sig8 references after all unit sources are loaded.
    resolveTypeSignatureReferences();

    // Initialize source location resolver
    initializeSourceResolver();

    // Initialize variable location evaluator
    var_evaluator_ = std::make_unique<VariableLocationEvaluator>();

    is_valid_ = true;
    return true;
}

bool DwarfParser::loadELFFile() {
    if (!elf_->load(filename_)) {
        DwarfUtils::setLastError("Failed to load ELF file: " + filename_);
        return false;
    }
    
    // Verify it's a valid ELF file
    if (elf_->get_class() != ELFIO::ELFCLASS32 && elf_->get_class() != ELFIO::ELFCLASS64) {
        DwarfUtils::setLastError("Invalid ELF class");
        return false;
    }

    // DWARF data follows the object file's endianness.
    DwarfUtils::setObjectLittleEndian(elf_->get_encoding() == ELFIO::ELFDATA2LSB);

    // Set address size based on ELF class (used by CFI parsing and as a default).
    address_size_ = (elf_->get_class() == ELFIO::ELFCLASS32) ? AddressSize::ADDR_32 : AddressSize::ADDR_64;
    
    return true;
}

bool DwarfParser::loadDWARFSections() {
    // Load CU-oriented DWARF sections on a best-effort basis so CFI-only objects remain usable.
    loadSection(constants::DEBUG_INFO_SECTION, debug_info_);
    loadSection(constants::DEBUG_ABBREV_SECTION, debug_abbrev_);
    loadSection(constants::DEBUG_STR_SECTION, debug_str_);
    
    // Load optional sections
    loadSection(constants::DEBUG_LINE_SECTION, debug_line_);
    loadSection(constants::DEBUG_RANGES_SECTION, debug_ranges_);
    loadSection(constants::DEBUG_LOC_SECTION, debug_loc_);

    // Load DWARF 5 optional sections
    loadSection(constants::DEBUG_STR_OFFSETS_SECTION, debug_str_offsets_);
    loadSection(constants::DEBUG_ADDR_SECTION, debug_addr_);
    loadSection(constants::DEBUG_LINE_STR_SECTION, debug_line_str_);
    loadSection(constants::DEBUG_RNGLISTS_SECTION, debug_rnglists_);
    loadSection(constants::DEBUG_LOCLISTS_SECTION, debug_loclists_);
    loadSection(constants::DEBUG_STR_SUP_SECTION, debug_str_sup_);
    loadSection(constants::DEBUG_SUP_SECTION, debug_sup_);
    loadSection(constants::DEBUG_NAMES_SECTION, debug_names_);
    loadSection(constants::DEBUG_MACRO_SECTION, debug_macro_);
    loadSection(constants::DEBUG_ARANGES_SECTION, debug_aranges_);
    loadSection(constants::DEBUG_PUBNAMES_SECTION, debug_pubnames_);
    loadSection(constants::DEBUG_PUBTYPES_SECTION, debug_pubtypes_);
    loadSection(constants::DEBUG_MACINFO_SECTION, debug_macinfo_);

    // If we have a supplementary file reference, attempt to load it.
    // This enables DW_FORM_strp_sup and DW_FORM_ref_sup* resolution.
    if (!debug_sup_.empty()) {
        DebugSupParser sup_parser(debug_sup_);
        const auto entries = sup_parser.parse();

        // Prefer entries where this file is NOT itself supplementary (is_supplementary==0),
        // which is the typical case for a main executable referencing a supplementary file.
        std::vector<DebugSupEntry> candidates;
        candidates.reserve(entries.size());
        for (const auto& e : entries) {
            if (!e.well_formed) continue;
            if (e.version != 5) continue;
            if (e.reserved != 0) continue;
            if (e.path.empty()) continue;
            if (e.is_supplementary == 0) {
                candidates.push_back(e);
            }
        }
        if (candidates.empty()) {
            // Fall back to any well-formed entry with a path.
            for (const auto& e : entries) {
                if (!e.well_formed) continue;
                if (e.version != 5) continue;
                if (e.reserved != 0) continue;
                if (e.path.empty()) continue;
                candidates.push_back(e);
            }
        }

        for (const auto& e : candidates) {
            std::string candidate = e.path;
            if (!candidate.empty() && candidate[0] != '/') {
                candidate = pathDirname(filename_) + "/" + candidate;
            }

            auto tmp_elf = std::make_unique<ELFIO::elfio>();
            if (!tmp_elf->load(candidate)) continue;
            // Supplementary files should match the main object's endianness/class.
            // If they don't, treat as non-matching to avoid parsing garbage.
            if (tmp_elf->get_encoding() != elf_->get_encoding()) continue;
            if (tmp_elf->get_class() != elf_->get_class()) continue;

            // Best-effort signature verification: if the supplementary file also contains a
            // .debug_sup entry that marks itself as supplementary, require the signature to match.
            bool signature_ok = true;
            if (auto* sup_sec = tmp_elf->sections[constants::DEBUG_SUP_SECTION]) {
                auto sup_bytes = getSectionData(sup_sec);
                if (!sup_bytes.empty()) {
                    DebugSupParser p2(sup_bytes);
                    auto sup_entries = p2.parse();
                    bool saw_self = false;
                    bool saw_match = false;
                    for (const auto& se : sup_entries) {
                        if (se.version != 5) continue;
                        if (se.reserved != 0) continue;
                        if (se.is_supplementary != 1) continue;
                        saw_self = true;
                        if (se.signature == e.signature) {
                            saw_match = true;
                            break;
                        }
                    }
                    if (saw_self && !saw_match) {
                        signature_ok = false;
                    }
                }
            }
            if (!signature_ok) continue;

            // Cache the ELF handle so section pointers remain valid if needed later.
            sup_elf_ = std::move(tmp_elf);

            // Load supplementary sections (best-effort).
            auto loadSupSection = [&](const std::string& name, std::vector<uint8_t>& out) {
                ELFIO::section* s = sup_elf_->sections[name];
                if (!s) return;
                out = getSectionData(s);
            };

            loadSupSection(constants::DEBUG_INFO_SECTION, sup_debug_info_);
            loadSupSection(constants::DEBUG_ABBREV_SECTION, sup_debug_abbrev_);
            loadSupSection(constants::DEBUG_STR_SECTION, sup_debug_str_);
            loadSupSection(constants::DEBUG_LINE_SECTION, sup_debug_line_);
            loadSupSection(constants::DEBUG_STR_OFFSETS_SECTION, sup_debug_str_offsets_);
            loadSupSection(constants::DEBUG_ADDR_SECTION, sup_debug_addr_);
            loadSupSection(constants::DEBUG_LINE_STR_SECTION, sup_debug_line_str_);
            loadSupSection(constants::DEBUG_RNGLISTS_SECTION, sup_debug_rnglists_);
            loadSupSection(constants::DEBUG_LOCLISTS_SECTION, sup_debug_loclists_);

            // If the main file didn't have an explicit .debug_str_sup, use the supplementary's .debug_str.
            if (debug_str_sup_.empty() && !sup_debug_str_.empty()) {
                debug_str_sup_ = sup_debug_str_;
            }

            // Assign a stable bias for supplementary DIE offsets so they won't collide with main or DWO DIEs.
            if (!sup_debug_info_.empty()) {
                supplementary_debug_info_offset_bias_ = (1ULL << 62);
            }

            break;
        }
    }

    // Load CFI sections
    loadSection(constants::DEBUG_FRAME_SECTION, debug_frame_);
    loadSection(constants::EH_FRAME_SECTION, eh_frame_);

    // Initialize DWARF 5 parsers if sections are available
    if (!debug_names_.empty()) {
        names_parser_ = std::make_unique<DebugNamesParser>(debug_names_, debug_str_);
        names_parser_->parse();
    }
    if (!debug_macro_.empty()) {
        macro_parser_ = std::make_unique<DebugMacroParser>(debug_macro_,
                                                           &debug_str_,
                                                           &debug_str_sup_,
                                                           &debug_str_offsets_,
                                                           &debug_line_);
    }
    if (!debug_macinfo_.empty()) {
        macinfo_parser_ = std::make_unique<DebugMacinfoParser>(debug_macinfo_);
    }
    if (!debug_aranges_.empty()) {
        DebugArangesParser aranges_parser(debug_aranges_);
        aranges_ = aranges_parser.parse();
    }
    if (!debug_pubnames_.empty()) {
        DebugPubTableParser pubnames_parser(debug_pubnames_);
        pubnames_ = pubnames_parser.parse();
    }
    if (!debug_pubtypes_.empty()) {
        DebugPubTableParser pubtypes_parser(debug_pubtypes_);
        pubtypes_ = pubtypes_parser.parse();
    }

    // Initialize CFI parser (prefer .eh_frame, fallback to .debug_frame)
    uint8_t addr_size = (address_size_ == AddressSize::ADDR_64) ? 8 : 4;
    if (!eh_frame_.empty()) {
        cfi_parser_ = std::make_unique<CFIParser>(eh_frame_, true, addr_size);
        if (auto* sec = elf_->sections[constants::EH_FRAME_SECTION]) {
            cfi_parser_->setSectionBaseAddress(sec->get_address());
        }
        cfi_parser_->parse();
    } else if (!debug_frame_.empty()) {
        cfi_parser_ = std::make_unique<CFIParser>(debug_frame_, false, addr_size);
        cfi_parser_->parse();
    }

    return true;
}

bool DwarfParser::loadSection(const std::string& section_name, std::vector<uint8_t>& data) {
    ELFIO::section* section = elf_->sections[section_name];
    if (!section) {
        if (verbose_) {
            DwarfUtils::printDebugMessage(std::cerr, "Section " + section_name + " not found");
        }
        return false;
    }
    
    data = getSectionData(section);
    if (verbose_) {
        DwarfUtils::printDebugMessage(
            std::cerr,
            "Section " + section_name + " loaded, size: " + std::to_string(data.size()));
    }
    return !data.empty();
}

std::vector<uint8_t> DwarfParser::getSectionData(const ELFIO::section* section) const {
    if (!section) {
        return {};
    }
    
    const char* data = section->get_data();
    size_t size = section->get_size();

    std::vector<uint8_t> out(data, data + size);
    applyRelocationsToSection(*elf_, section, out);
    return out;
}

bool DwarfParser::parseCompilationUnits() {
    if (debug_info_.empty() || debug_abbrev_.empty() || debug_str_.empty()) {
        return false;
    }
    
    // Create DIE parser with all sections
    die_parser_ = std::make_unique<DIEParser>(*elf_, debug_info_, debug_abbrev_, debug_str_,
                                               debug_line_, debug_ranges_, debug_loc_,
                                               debug_str_offsets_, debug_addr_,
                                               debug_line_str_, debug_rnglists_, debug_loclists_,
                                               debug_str_sup_,
                                               verbose_, /*debug_info_offset_bias=*/0,
                                               /*supplementary_debug_info_offset_bias=*/supplementary_debug_info_offset_bias_);
    
    // Parse compilation units
    compilation_units_ = die_parser_->parseCompilationUnits();
    support_telemetry_.vendor_form_skips += die_parser_->getUnsupportedVendorFormSkipCount();
    appendVendorFormSkipSamples(support_telemetry_, die_parser_->getUnsupportedVendorFormSkipDetails());
    mergeVendorFormSkipHistogram(support_telemetry_, die_parser_->getUnsupportedVendorFormSkipHistogram());
    mergeVendorFormSkipSeverityBuckets(support_telemetry_, die_parser_->getUnsupportedVendorFormSkipSeverityBuckets());
    
    // Cache all DIEs
    type_signature_die_offset_cache_.clear();
    for (const auto& cu : compilation_units_) {
        cacheDIE(cu);
    }
    
    return !compilation_units_.empty();
}

void DwarfParser::integrateSupplementary() {
    if (supplementary_debug_info_offset_bias_ == 0) return;
    if (sup_debug_info_.empty() || sup_debug_abbrev_.empty()) return;
    if (!sup_elf_) return;

    // Parse supplementary DIEs with their own bias, then cache them.
    const std::vector<uint8_t> empty_ranges;
    const std::vector<uint8_t> empty_loc;
    const std::vector<uint8_t>& sup_str = sup_debug_str_.empty() ? debug_str_ : sup_debug_str_;

    sup_die_parser_ = std::make_unique<DIEParser>(
        *sup_elf_,
        sup_debug_info_,
        sup_debug_abbrev_,
        sup_str,
        /*debug_line=*/sup_debug_line_,
        /*debug_ranges=*/empty_ranges,
        /*debug_loc=*/empty_loc,
        /*debug_str_offsets=*/sup_debug_str_offsets_,
        /*debug_addr=*/sup_debug_addr_,
        /*debug_line_str=*/sup_debug_line_str_,
        /*debug_rnglists=*/sup_debug_rnglists_,
        /*debug_loclists=*/sup_debug_loclists_,
        /*debug_str_sup=*/debug_str_sup_,
        verbose_,
        /*debug_info_offset_bias=*/supplementary_debug_info_offset_bias_,
        /*supplementary_debug_info_offset_bias=*/supplementary_debug_info_offset_bias_);

    supplementary_units_ = sup_die_parser_->parseCompilationUnits();
    support_telemetry_.vendor_form_skips += sup_die_parser_->getUnsupportedVendorFormSkipCount();
    appendVendorFormSkipSamples(support_telemetry_, sup_die_parser_->getUnsupportedVendorFormSkipDetails());
    mergeVendorFormSkipHistogram(support_telemetry_, sup_die_parser_->getUnsupportedVendorFormSkipHistogram());
    mergeVendorFormSkipSeverityBuckets(support_telemetry_, sup_die_parser_->getUnsupportedVendorFormSkipSeverityBuckets());
    for (const auto& cu : supplementary_units_) {
        cacheDIE(cu);
    }
}

static uint64_t fnv1a64(const std::string& s) {
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) {
        h ^= static_cast<uint64_t>(c);
        h *= 1099511628211ULL;
    }
    return h;
}

static std::string pathDirname(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) return ".";
    if (pos == 0) return "/";
    return path.substr(0, pos);
}

uint64_t DwarfParser::getOrAssignDWOBias(uint64_t dwo_id) {
    auto it = dwo_slot_by_id_.find(dwo_id);
    if (it != dwo_slot_by_id_.end()) {
        uint16_t slot = it->second;
        dwo_id_by_slot_[slot] = dwo_id;
        return (1ULL << 63) | (static_cast<uint64_t>(slot) << 48);
    }

    // Keep 0 reserved so we can use it to signal "no bias".
    if (next_dwo_slot_ == 0) next_dwo_slot_ = 1;

    // 15-bit slot stored in bits [62:48]. This gives us 32767 distinct DWOs.
    if (next_dwo_slot_ >= 0x8000) {
        if (verbose_) {
            std::cerr << "Debug: Too many DWOs to assign unique offset biases" << std::endl;
        }
        return 0;
    }

    uint16_t slot = next_dwo_slot_++;
    dwo_slot_by_id_[dwo_id] = slot;
    dwo_id_by_slot_[slot] = dwo_id;
    return (1ULL << 63) | (static_cast<uint64_t>(slot) << 48);
}

const std::vector<uint64_t>* DwarfParser::getDebugAddrTable(uint64_t addr_base, uint8_t address_size) const {
    return getDebugAddrTableForSection(debug_addr_, addr_base, address_size);
}

static uint64_t hashCombine64(uint64_t h, uint64_t v) {
    // Similar to boost::hash_combine.
    return h ^ (v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2));
}

const std::vector<uint64_t>* DwarfParser::getDebugAddrTableForSection(const std::vector<uint8_t>& debug_addr_section,
                                                                      uint64_t addr_base,
                                                                      uint8_t address_size) const {
    if (debug_addr_section.empty()) return nullptr;
    if (address_size != 4 && address_size != 8) return nullptr;
    if (addr_base >= debug_addr_section.size()) return nullptr;

    // Best-effort normalize addr_base and bound the table to its contribution.
    // DW_AT_addr_base is supposed to point to the table start, but some producers point to the contribution start.
    uint64_t table_start = addr_base;
    uint64_t table_end = debug_addr_section.size();
    uint8_t seg_size = 0;
    uint8_t entry_stride = address_size;

    struct DebugAddrContribution {
        uint64_t table_start = 0;
        uint64_t unit_end = 0;
        uint8_t seg_size = 0;
        uint8_t entry_stride = 0;
        bool ok = false;
    };

    auto tryParseContributionAt = [&](uint64_t contribution_start) -> DebugAddrContribution {
        DebugAddrContribution out;
        if (contribution_start >= debug_addr_section.size()) return out;

        uint64_t off = contribution_start;
        uint32_t initial_length = DwarfUtils::readU32(debug_addr_section.data(), off, debug_addr_section.size());
        bool is64 = (initial_length == 0xffffffff);
        uint64_t unit_length = is64 ? DwarfUtils::readU64(debug_addr_section.data(), off, debug_addr_section.size())
                                    : initial_length;
        uint64_t length_field_size = is64 ? 12 : 4;
        uint64_t unit_end = contribution_start + length_field_size + unit_length;
        if (unit_end > debug_addr_section.size() || unit_end < off) return out;

        uint16_t version = DwarfUtils::readU16(debug_addr_section.data(), off, unit_end);
        uint8_t addr_sz = DwarfUtils::readU8(debug_addr_section.data(), off, unit_end);
        uint8_t seg_sz = DwarfUtils::readU8(debug_addr_section.data(), off, unit_end);
        if (version != 5) return out;
        if (addr_sz != address_size) return out;

        uint8_t stride = static_cast<uint8_t>(seg_sz + addr_sz);
        if (stride == 0) return out;

        out.table_start = off;
        out.unit_end = unit_end;
        out.seg_size = seg_sz;
        out.entry_stride = stride;
        out.ok = true;
        return out;
    };

    // Case 1: base points at contribution header.
    auto c = tryParseContributionAt(addr_base);
    if (c.ok) {
        table_start = c.table_start;
        table_end = c.unit_end;
        seg_size = c.seg_size;
        entry_stride = c.entry_stride;
    } else {
        // Case 2: base points at table start; try to locate header just before it.
        if (addr_base >= 8) {
            auto c32 = tryParseContributionAt(addr_base - 8);
            if (c32.ok && c32.table_start == addr_base) {
                table_start = addr_base;
                table_end = c32.unit_end;
                seg_size = c32.seg_size;
                entry_stride = c32.entry_stride;
            }
        }
        if (table_start == addr_base && table_end == debug_addr_section.size() && addr_base >= 16) {
            auto c64 = tryParseContributionAt(addr_base - 16);
            if (c64.ok && c64.table_start == addr_base) {
                table_start = addr_base;
                table_end = c64.unit_end;
                seg_size = c64.seg_size;
                entry_stride = c64.entry_stride;
            }
        }
    }

    addr_base = table_start;

    // Cache key includes the section identity to support DWO/supplementary tables.
    uint64_t key = 0;
    key = hashCombine64(key, reinterpret_cast<uint64_t>(debug_addr_section.data()));
    key = hashCombine64(key, static_cast<uint64_t>(debug_addr_section.size()));
    key = hashCombine64(key, addr_base);
    key = hashCombine64(key, static_cast<uint64_t>(address_size));
    key = hashCombine64(key, static_cast<uint64_t>(seg_size));
    auto it = debug_addr_table_cache_.find(key);
    if (it != debug_addr_table_cache_.end()) {
        return &it->second;
    }

    std::vector<uint64_t> table;
    table.reserve(256);

    uint64_t off = addr_base;
    // Hard cap to avoid runaway allocations on malformed input.
    const size_t kMaxEntries = 1u << 20;
    while (off + static_cast<uint64_t>(seg_size) + address_size <= table_end && table.size() < kMaxEntries) {
        uint64_t v = 0;
        if (address_size == 8) {
            uint64_t tmp = off + seg_size;
            v = DwarfUtils::readU64(debug_addr_section.data(), tmp, debug_addr_section.size());
        } else {
            uint64_t tmp = off + seg_size;
            v = DwarfUtils::readU32(debug_addr_section.data(), tmp, debug_addr_section.size());
        }
        table.push_back(v);
        off += entry_stride;
    }

    auto [ins_it, _] = debug_addr_table_cache_.emplace(key, std::move(table));
    return &ins_it->second;
}

void DwarfParser::integrateSplitDwarf() {
    split_stats_ = SplitDwarfStats{};

    // Scan existing compilation units for DW_AT_dwo_name. If present, attempt to load
    // the corresponding .dwo file and parse its .debug_* sections.
    if (compilation_units_.empty()) return;

    std::unordered_set<uint64_t> processed_dwo_ids;
    size_t initial_cu_count = compilation_units_.size();

    // If we have any skeleton units, ensure we have a loader and a reasonable default search path.
    const std::string exe_dir = pathDirname(filename_);

    auto parseDWOSections = [this](uint64_t dwo_id, const SplitDwarfLoader::DWOSections& sections) {
        if (sections.debug_info.empty() || sections.debug_abbrev.empty()) {
            return;
        }

        uint64_t bias = getOrAssignDWOBias(dwo_id);
        if (bias == 0) return;

        // Ensure raw DWO offsets fit in our bias scheme (48-bit region).
        if (sections.debug_info.size() >= (1ULL << 48)) {
            if (verbose_) {
                std::cerr << "Debug: DWO .debug_info.dwo too large for biased offsets" << std::endl;
            }
            return;
        }

        const std::vector<uint8_t>& dwo_str = sections.debug_str.empty() ? debug_str_ : sections.debug_str;
        const std::vector<uint8_t>& dwo_addr = sections.debug_addr.empty() ? debug_addr_ : sections.debug_addr;
        const std::vector<uint8_t>& dwo_line_str = sections.debug_line_str.empty() ? debug_line_str_ : sections.debug_line_str;
        const std::vector<uint8_t> empty_ranges;
        const std::vector<uint8_t> empty_loc;

        DIEParser dwo_parser(
            *elf_,
            sections.debug_info,
            sections.debug_abbrev,
            dwo_str,
            sections.debug_line,
            /*debug_ranges=*/empty_ranges,
            /*debug_loc=*/empty_loc,
            sections.debug_str_offsets,
            /*debug_addr=*/dwo_addr,
            /*debug_line_str=*/dwo_line_str,
            sections.debug_rnglists,
            sections.debug_loclists,
            /*debug_str_sup=*/debug_str_sup_,
            verbose_,
            bias,
            /*supplementary_debug_info_offset_bias=*/supplementary_debug_info_offset_bias_);

        // Cache DWO .debug_addr payload for later expression evaluation.
        // This is required for DWPs (where getSectionsForUnit() returns temporary slices).
        if (!sections.debug_addr.empty()) {
            dwo_debug_addr_by_id_[dwo_id] = sections.debug_addr;
        }

        auto dwo_cus = dwo_parser.parseCompilationUnits();
        support_telemetry_.vendor_form_skips += dwo_parser.getUnsupportedVendorFormSkipCount();
        appendVendorFormSkipSamples(support_telemetry_, dwo_parser.getUnsupportedVendorFormSkipDetails());
        mergeVendorFormSkipHistogram(support_telemetry_, dwo_parser.getUnsupportedVendorFormSkipHistogram());
        mergeVendorFormSkipSeverityBuckets(support_telemetry_, dwo_parser.getUnsupportedVendorFormSkipSeverityBuckets());
        for (const auto& dwo_cu : dwo_cus) {
            compilation_units_.push_back(dwo_cu);
            cacheDIE(dwo_cu);
        }
    };

    for (size_t i = 0; i < initial_cu_count; ++i) {
        const auto& cu = compilation_units_[i];
        if (!cu) continue;

        auto dwo_name_attr = cu->getAttribute(DwarfAttribute::DW_AT_dwo_name);
        if (!dwo_name_attr) {
            dwo_name_attr = cu->getAttribute(DwarfAttribute::DW_AT_GNU_dwo_name);
        }
        auto dwo_name_val = std::dynamic_pointer_cast<StringAttributeValue>(dwo_name_attr);
        if (!dwo_name_val) continue;

        std::string dwo_name = dwo_name_val->getValue();
        if (dwo_name.empty()) continue;

        // Compilation directory (used for path resolution and stable ID hashing).
        std::string comp_dir;
        auto comp_dir_attr = cu->getAttribute(DwarfAttribute::DW_AT_comp_dir);
        auto comp_dir_val = std::dynamic_pointer_cast<StringAttributeValue>(comp_dir_attr);
        if (comp_dir_val) comp_dir = comp_dir_val->getValue();

        uint64_t dwo_id = 0;
        auto dwo_id_attr = cu->getAttribute(DwarfAttribute::DW_AT_dwo_id);
        if (!dwo_id_attr) dwo_id_attr = cu->getAttribute(DwarfAttribute::DW_AT_GNU_dwo_id);
        if (dwo_id_attr) {
            if (auto u = std::dynamic_pointer_cast<UnsignedAttributeValue>(dwo_id_attr)) {
                dwo_id = u->getValue();
            } else if (auto b = std::dynamic_pointer_cast<BlockAttributeValue>(dwo_id_attr)) {
                const auto& data = b->getData();
                if (data.size() >= 8) {
                    uint64_t v = 0;
                    for (int j = 0; j < 8; ++j) v |= static_cast<uint64_t>(data[j]) << (j * 8);
                    dwo_id = v;
                }
            }
        }

        if (dwo_id == 0) {
            std::string id_material = comp_dir;
            id_material.push_back('\0');
            id_material += dwo_name;
            dwo_id = fnv1a64(id_material);
        }

        if (processed_dwo_ids.count(dwo_id)) continue;
        processed_dwo_ids.insert(dwo_id);

        // Prefer .dwp if present and the unit signature matches.
        if (dwp_loader_ && dwp_loader_->isLoaded()) {
            auto dwp_sections = dwp_loader_->getSectionsForUnit(dwo_id);
            if (dwp_sections) {
                ++split_stats_.dwp_hits;
                if (verbose_) {
                    std::cerr << "Debug: split-dwarf source=dwp dwo_id=0x"
                              << std::hex << dwo_id << std::dec << std::endl;
                }
                parseDWOSections(dwo_id, *dwp_sections);
                continue;
            } else if (verbose_) {
                ++split_stats_.dwo_fallback_hits;
                std::cerr << "Debug: split-dwarf source=dwo fallback reason=";
                if (!dwp_loader_->hasCUIndexSection()) {
                    ++split_stats_.fallback_no_index;
                    std::cerr << "no_cu_index";
                } else if (!dwp_loader_->isCUIndexValid()) {
                    ++split_stats_.fallback_invalid_index;
                    std::cerr << "invalid_cu_index";
                } else {
                    ++split_stats_.fallback_sig_miss;
                    std::cerr << "signature_not_found";
                }
                std::cerr << " dwo_id=0x" << std::hex << dwo_id << std::dec << std::endl;
            } else {
                ++split_stats_.dwo_fallback_hits;
                if (!dwp_loader_->hasCUIndexSection()) {
                    ++split_stats_.fallback_no_index;
                } else if (!dwp_loader_->isCUIndexValid()) {
                    ++split_stats_.fallback_invalid_index;
                } else {
                    ++split_stats_.fallback_sig_miss;
                }
            }
        }

        if (!split_loader_) {
            split_loader_ = std::make_unique<SplitDwarfLoader>();
            split_loader_->addSearchPath(exe_dir);
        }

        SkeletonUnit skel{};
        skel.offset = cu->getOffset();
        skel.dwo_id = dwo_id;
        skel.dwo_name = dwo_name;
        skel.comp_dir = comp_dir;
        split_loader_->addSkeletonUnit(skel);

        if (!split_loader_->loadDWO(skel)) {
            if (verbose_) {
                std::cerr << "Debug: Failed to load DWO for " << dwo_name << std::endl;
            }
            continue;
        }

        auto sections_opt = split_loader_->getDWOSections(dwo_id);
        if (!sections_opt) continue;
        ++split_stats_.dwo_hits;
        if (verbose_) {
            std::cerr << "Debug: split-dwarf source=dwo dwo_id=0x"
                      << std::hex << dwo_id << std::dec << std::endl;
        }
        parseDWOSections(dwo_id, *sections_opt);
    }
}

void DwarfParser::cacheDIE(std::shared_ptr<DIE> die) {
    if (!die) return;
    
    die_cache_[die->getOffset()] = die;
    indexTypeUnitSignature(die);
    
    // Cache children recursively
    for (const auto& child : die->getChildren()) {
        cacheDIE(child);
    }
}

void DwarfParser::indexTypeUnitSignature(std::shared_ptr<DIE> die) {
    if (!die) return;
    auto sig_attr = std::dynamic_pointer_cast<UnsignedAttributeValue>(
        die->getAttribute(DwarfAttribute::DW_AT_signature));
    if (!sig_attr) return;

    uint64_t resolved_offset = die->getOffset();
    if (auto type_attr = std::dynamic_pointer_cast<TypeAttributeValue>(
            die->getAttribute(DwarfAttribute::DW_AT_type))) {
        if (!type_attr->isSignatureReference() && type_attr->getOffset() != 0) {
            resolved_offset = type_attr->getOffset();
        }
    }
    type_signature_die_offset_cache_[sig_attr->getValue()] = resolved_offset;
}

void DwarfParser::resolveTypeSignatureReferences() {
    for (const auto& cu : compilation_units_) {
        resolveTypeSignatureReferences(cu);
    }
    for (const auto& cu : supplementary_units_) {
        resolveTypeSignatureReferences(cu);
    }
}

void DwarfParser::resolveTypeSignatureReferences(std::shared_ptr<DIE> die) {
    if (!die) return;

    std::vector<std::pair<DwarfAttribute, std::shared_ptr<TypeAttributeValue>>> replacements;
    for (const auto& attr_kv : die->getAttributes()) {
        auto type_attr = std::dynamic_pointer_cast<TypeAttributeValue>(attr_kv.second);
        if (!type_attr || !type_attr->isSignatureReference()) continue;
        auto it = type_signature_die_offset_cache_.find(type_attr->getOffset());
        if (it == type_signature_die_offset_cache_.end()) continue;
        replacements.emplace_back(attr_kv.first,
                                  std::make_shared<TypeAttributeValue>(it->second, type_attr->getName()));
    }

    for (const auto& replacement : replacements) {
        die->addAttribute(replacement.first, replacement.second);
    }

    for (const auto& child : die->getChildren()) {
        resolveTypeSignatureReferences(child);
    }
}

std::vector<std::shared_ptr<DIE>> DwarfParser::findDIEsByTag(DwarfTag tag) const {
    std::vector<std::shared_ptr<DIE>> result;
    
    for (const auto& pair : die_cache_) {
        if (pair.second->getTag() == tag) {
            result.push_back(pair.second);
        }
    }
    
    return result;
}

std::vector<std::shared_ptr<DIE>> DwarfParser::findDIEsByName(const std::string& name) const {
    std::vector<std::shared_ptr<DIE>> result;

    for (const auto& pair : die_cache_) {
        if (pair.second->getName() == name) {
            result.push_back(pair.second);
        }
    }

    return result;
}

std::vector<std::shared_ptr<DIE>> DwarfParser::findDIEsByNameFast(const std::string& name) const {
    std::vector<std::shared_ptr<DIE>> result;

    // Use accelerated lookup if available
    if (names_parser_) {
        auto offsets = names_parser_->lookupDIEOffsets(name);
        for (uint64_t offset : offsets) {
            auto die = findDIEByOffset(offset);
            if (die) {
                result.push_back(die);
            }
        }
        return result;
    }

    // Fall back to linear search
    return findDIEsByName(name);
}

const std::vector<DebugNamesHeader>& DwarfParser::getDebugNamesUnitHeaders() const {
    static const std::vector<DebugNamesHeader> kEmptyHeaders;
    if (!names_parser_) return kEmptyHeaders;
    return names_parser_->getUnitHeaders();
}

const DebugNamesHeader* DwarfParser::getPrimaryDebugNamesHeader() const {
    if (!names_parser_) return nullptr;
    const auto& headers = names_parser_->getUnitHeaders();
    if (headers.empty()) return nullptr;
    return &headers[0];
}

std::vector<MacroDefinition> DwarfParser::getMacroDefinitions(uint64_t offset) const {
    if (offset == 0) {
        for (const auto& cu : compilation_units_) {
            auto defs = getMacroDefinitionsForCU(cu);
            if (!defs.empty()) return defs;
        }
    }
    if (macro_parser_) {
        auto defs = macro_parser_->getDefinitions(offset);
        if (!defs.empty()) return defs;
    }
    if (macinfo_parser_) {
        return macinfo_parser_->getDefinitions(offset);
    }
    return {};
}

std::vector<MacroDefinition> DwarfParser::lookupMacro(const std::string& name, uint64_t offset) const {
    if (offset == 0) {
        for (const auto& cu : compilation_units_) {
            auto defs = lookupMacroForCU(cu, name);
            if (!defs.empty()) return defs;
        }
    }
    if (macro_parser_) {
        auto defs = macro_parser_->lookupMacro(name, offset);
        if (!defs.empty()) return defs;
    }
    if (macinfo_parser_) {
        return macinfo_parser_->lookupMacro(name, offset);
    }
    return {};
}

std::vector<MacroDefinition> DwarfParser::getMacroDefinitionsForCU(const std::shared_ptr<DIE>& cu) const {
    if (!cu) return {};

    auto modernOffset = [&](const std::shared_ptr<DIE>& die) -> std::pair<bool, uint64_t> {
        if (!die) return {false, 0};
        if (auto a = std::dynamic_pointer_cast<UnsignedAttributeValue>(die->getAttribute(DwarfAttribute::DW_AT_macros))) {
            return {true, a->getValue()};
        }
        return {false, 0};
    };
    auto legacyOffset = [&](const std::shared_ptr<DIE>& die) -> std::pair<bool, uint64_t> {
        if (!die) return {false, 0};
        if (auto a = std::dynamic_pointer_cast<UnsignedAttributeValue>(die->getAttribute(DwarfAttribute::DW_AT_macro_info))) {
            return {true, a->getValue()};
        }
        return {false, 0};
    };

    if (macro_parser_) {
        auto [has_macro_attr, macro_offset] = modernOffset(cu);
        if (has_macro_attr) {
            uint64_t str_offsets_base = 0;
            if (auto b = std::dynamic_pointer_cast<UnsignedAttributeValue>(cu->getAttribute(DwarfAttribute::DW_AT_str_offsets_base))) {
                str_offsets_base = b->getValue();
            }
            macro_parser_->setStrOffsetsBase(str_offsets_base, cu->getOffsetSize());
            auto defs = macro_parser_->getDefinitions(macro_offset);
            if (!defs.empty()) return defs;

            for (const auto& other : compilation_units_) {
                if (!other || other == cu) continue;
                auto [has_other_macro_attr, mo] = modernOffset(other);
                if (!has_other_macro_attr) continue;
                uint64_t sb = 0;
                if (auto b2 = std::dynamic_pointer_cast<UnsignedAttributeValue>(other->getAttribute(DwarfAttribute::DW_AT_str_offsets_base))) {
                    sb = b2->getValue();
                }
                macro_parser_->setStrOffsetsBase(sb, other->getOffsetSize());
                auto d2 = macro_parser_->getDefinitions(mo);
                if (!d2.empty()) return d2;
            }
            return defs;
        }
    }

    if (macinfo_parser_) {
        auto [has_legacy_attr, macro_offset] = legacyOffset(cu);
        if (has_legacy_attr) {
            auto defs = macinfo_parser_->getDefinitions(macro_offset);
            if (!defs.empty()) return defs;
            for (const auto& other : compilation_units_) {
                if (!other || other == cu) continue;
                auto [has_other_legacy_attr, mo] = legacyOffset(other);
                if (!has_other_legacy_attr) continue;
                auto d2 = macinfo_parser_->getDefinitions(mo);
                if (!d2.empty()) return d2;
            }
            return defs;
        }
    }

    return {};
}

std::vector<MacroDefinition> DwarfParser::lookupMacroForCU(const std::shared_ptr<DIE>& cu, const std::string& name) const {
    if (!cu) return {};

    auto modernOffset = [&](const std::shared_ptr<DIE>& die) -> std::pair<bool, uint64_t> {
        if (!die) return {false, 0};
        if (auto a = std::dynamic_pointer_cast<UnsignedAttributeValue>(die->getAttribute(DwarfAttribute::DW_AT_macros))) {
            return {true, a->getValue()};
        }
        return {false, 0};
    };
    auto legacyOffset = [&](const std::shared_ptr<DIE>& die) -> std::pair<bool, uint64_t> {
        if (!die) return {false, 0};
        if (auto a = std::dynamic_pointer_cast<UnsignedAttributeValue>(die->getAttribute(DwarfAttribute::DW_AT_macro_info))) {
            return {true, a->getValue()};
        }
        return {false, 0};
    };

    if (macro_parser_) {
        auto [has_macro_attr, macro_offset] = modernOffset(cu);
        if (has_macro_attr) {
            uint64_t str_offsets_base = 0;
            if (auto b = std::dynamic_pointer_cast<UnsignedAttributeValue>(cu->getAttribute(DwarfAttribute::DW_AT_str_offsets_base))) {
                str_offsets_base = b->getValue();
            }
            macro_parser_->setStrOffsetsBase(str_offsets_base, cu->getOffsetSize());
            auto defs = macro_parser_->lookupMacro(name, macro_offset);
            if (!defs.empty()) return defs;
            for (const auto& other : compilation_units_) {
                if (!other || other == cu) continue;
                auto [has_other_macro_attr, mo] = modernOffset(other);
                if (!has_other_macro_attr) continue;
                uint64_t sb = 0;
                if (auto b2 = std::dynamic_pointer_cast<UnsignedAttributeValue>(other->getAttribute(DwarfAttribute::DW_AT_str_offsets_base))) {
                    sb = b2->getValue();
                }
                macro_parser_->setStrOffsetsBase(sb, other->getOffsetSize());
                auto d2 = macro_parser_->lookupMacro(name, mo);
                if (!d2.empty()) return d2;
            }
            return defs;
        }
    }

    if (macinfo_parser_) {
        auto [has_legacy_attr, macro_offset] = legacyOffset(cu);
        if (has_legacy_attr) {
            auto defs = macinfo_parser_->lookupMacro(name, macro_offset);
            if (!defs.empty()) return defs;
            for (const auto& other : compilation_units_) {
                if (!other || other == cu) continue;
                auto [has_other_legacy_attr, mo] = legacyOffset(other);
                if (!has_other_legacy_attr) continue;
                auto d2 = macinfo_parser_->lookupMacro(name, mo);
                if (!d2.empty()) return d2;
            }
            return defs;
        }
    }

    return {};
}

std::shared_ptr<DIE> DwarfParser::findDIEByOffset(uint64_t offset) const {
    auto it = die_cache_.find(offset);
    return (it != die_cache_.end()) ? it->second : nullptr;
}

std::shared_ptr<DIE> DwarfParser::getType(uint64_t type_offset) const {
    return findDIEByOffset(type_offset);
}

std::string DwarfParser::getTypeName(std::shared_ptr<DIE> type_die) const {
    if (!type_die) return "";
    return type_die->getName();
}

uint64_t DwarfParser::getTypeSize(std::shared_ptr<DIE> type_die) const {
    if (!type_die) return 0;
    return type_die->getByteSize();
}

std::vector<std::shared_ptr<DIE>> DwarfParser::getFunctions() const {
    return findDIEsByTag(DwarfTag::DW_TAG_subprogram);
}

std::vector<std::shared_ptr<DIE>> DwarfParser::getVariables() const {
    std::vector<std::shared_ptr<DIE>> result;
    auto variables = findDIEsByTag(DwarfTag::DW_TAG_variable);
    auto parameters = findDIEsByTag(DwarfTag::DW_TAG_formal_parameter);
    
    result.insert(result.end(), variables.begin(), variables.end());
    result.insert(result.end(), parameters.begin(), parameters.end());
    
    return result;
}

std::vector<std::shared_ptr<DIE>> DwarfParser::getTypes() const {
    std::vector<std::shared_ptr<DIE>> result;

    for (const auto& pair : die_cache_) {
        if (pair.second->isType()) {
            result.push_back(pair.second);
        }
    }

    return result;
}

// Helper to get low_pc from a DIE
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

// Helper to get high_pc from a DIE
static uint64_t getDIEHighPC(const std::shared_ptr<DIE>& die, uint64_t low_pc) {
    if (!die) return 0;
    auto attr = die->getAttribute(DwarfAttribute::DW_AT_high_pc);
    if (!attr) return 0;
    auto addr_attr = std::dynamic_pointer_cast<AddressAttributeValue>(attr);
    if (addr_attr) return addr_attr->getAddress();
    // high_pc can be an offset from low_pc
    auto uint_attr = std::dynamic_pointer_cast<UnsignedAttributeValue>(attr);
    if (uint_attr) return low_pc + uint_attr->getValue();
    return 0;
}

std::shared_ptr<DIE> DwarfParser::getFunctionAt(uint64_t address) const {
    std::shared_ptr<DIE> best_match = nullptr;
    uint64_t smallest_range = UINT64_MAX;

    for (const auto& pair : die_cache_) {
        auto die = pair.second;
        if (die->getTag() != DwarfTag::DW_TAG_subprogram) {
            continue;
        }

        uint64_t low_pc = getDIELowPC(die);
        uint64_t high_pc = (low_pc != 0) ? getDIEHighPC(die, low_pc) : 0;

        // Check [low_pc, high_pc) if present.
        if (low_pc != 0 && high_pc != 0 && address >= low_pc && address < high_pc) {
            uint64_t range = high_pc - low_pc;
            if (range < smallest_range) {
                smallest_range = range;
                best_match = die;
            }
            continue;
        }

        // Fall back to DW_AT_ranges (non-contiguous functions).
        auto ranges_attr = die->getAttribute(DwarfAttribute::DW_AT_ranges);
        if (!ranges_attr) continue;
        auto range_attr = std::dynamic_pointer_cast<RangeAttributeValue>(ranges_attr);
        if (!range_attr) continue;

        for (const auto& r : range_attr->getRanges()) {
            if (r.is_base_address) continue;
            if (address >= r.start && address < r.end) {
                uint64_t range = r.end - r.start;
                if (range < smallest_range) {
                    smallest_range = range;
                    best_match = die;
                }
                break;
            }
        }
    }

    return best_match;
}

std::shared_ptr<DIE> DwarfParser::getInlinedFunctionAt(uint64_t address) const {
    std::shared_ptr<DIE> best_match = nullptr;
    uint64_t smallest_range = UINT64_MAX;

    for (const auto& pair : die_cache_) {
        auto die = pair.second;
        if (die->getTag() != DwarfTag::DW_TAG_inlined_subroutine) {
            continue;
        }

        uint64_t low_pc = getDIELowPC(die);
        uint64_t high_pc = (low_pc != 0) ? getDIEHighPC(die, low_pc) : 0;

        if (low_pc != 0 && high_pc != 0 && address >= low_pc && address < high_pc) {
            uint64_t range = high_pc - low_pc;
            if (range < smallest_range) {
                smallest_range = range;
                best_match = die;
            }
            continue;
        }

        auto ranges_attr = die->getAttribute(DwarfAttribute::DW_AT_ranges);
        if (!ranges_attr) continue;
        auto range_attr = std::dynamic_pointer_cast<RangeAttributeValue>(ranges_attr);
        if (!range_attr) continue;

        for (const auto& r : range_attr->getRanges()) {
            if (r.is_base_address) continue;
            if (address >= r.start && address < r.end) {
                uint64_t range = r.end - r.start;
                if (range < smallest_range) {
                    smallest_range = range;
                    best_match = die;
                }
                break;
            }
        }
    }

    return best_match;
}

std::vector<std::shared_ptr<DIE>> DwarfParser::getFunctionsInRange(uint64_t start, uint64_t end) const {
    std::vector<std::shared_ptr<DIE>> result;

    for (const auto& pair : die_cache_) {
        auto die = pair.second;
        if (die->getTag() != DwarfTag::DW_TAG_subprogram) {
            continue;
        }

        uint64_t low_pc = getDIELowPC(die);
        uint64_t high_pc = (low_pc != 0) ? getDIEHighPC(die, low_pc) : 0;

        if (low_pc != 0 && high_pc != 0) {
            if (low_pc < end && high_pc > start) {
                result.push_back(die);
            }
            continue;
        }

        auto ranges_attr = die->getAttribute(DwarfAttribute::DW_AT_ranges);
        auto range_attr = std::dynamic_pointer_cast<RangeAttributeValue>(ranges_attr);
        if (!range_attr) continue;

        for (const auto& r : range_attr->getRanges()) {
            if (r.is_base_address) continue;
            if (r.start < end && r.end > start) {
                result.push_back(die);
                break;
            }
        }
    }

    return result;
}

void DwarfParser::printDebugInfo() const {
    std::cout << "DWARF Debug Information for: " << filename_ << std::endl;
    std::cout << "Version: " << static_cast<int>(version_) << std::endl;
    std::cout << "Address Size: " << static_cast<int>(address_size_) << " bytes" << std::endl;
    std::cout << "Compilation Units: " << compilation_units_.size() << std::endl;
    std::cout << "Total DIEs: " << die_cache_.size() << std::endl;
    std::cout << std::endl;
}

void DwarfParser::printCompilationUnits() const {
    std::cout << "Compilation Units:" << std::endl;
    for (size_t i = 0; i < compilation_units_.size(); ++i) {
        std::cout << "  [" << i << "] " << compilation_units_[i]->toString(1) << std::endl;
    }
    std::cout << std::endl;
}

void DwarfParser::printTypes() const {
    std::cout << "Types:" << std::endl;
    auto types = getTypes();
    for (const auto& type : types) {
        std::cout << "  " << type->toString(1) << std::endl;
    }
    std::cout << std::endl;
}

void DwarfParser::printFunctions() const {
    std::cout << "Functions:" << std::endl;
    auto functions = getFunctions();
    for (const auto& func : functions) {
        std::cout << "  " << func->toString(1) << std::endl;
    }
    std::cout << std::endl;
}

void DwarfParser::printVariables() const {
    std::cout << "Variables:" << std::endl;
    auto variables = getVariables();
    for (const auto& var : variables) {
        std::cout << "  " << var->toString(1) << std::endl;
    }
    std::cout << std::endl;
}

UnwindInfo DwarfParser::getUnwindInfo(uint64_t pc) const {
    if (cfi_parser_) {
        return cfi_parser_->getUnwindInfo(pc);
    }
    return UnwindInfo();
}

DwarfParser::UnwindResult DwarfParser::unwindFrame(
    uint64_t pc,
    const std::vector<uint64_t>& registers,
    const std::function<uint64_t(uint64_t)>& read_memory) const {

    UnwindResult result;

    if (!cfi_parser_) {
        return result;
    }

    UnwindInfo info = cfi_parser_->getUnwindInfo(pc);
    if (!info.valid) {
        return result;
    }

    // Compute CFA
    uint64_t cfa = info.computeCFA(registers, read_memory);
    if (cfa == 0) {
        return result;
    }

    // Initialize result registers as copies
    result.registers = registers;

    // Unwind each register that has a rule
    for (const auto& [reg_num, rule] : info.registers) {
        auto value = info.getRegisterValue(reg_num, registers, cfa, read_memory);
        if (value && reg_num < result.registers.size()) {
            result.registers[reg_num] = *value;
        }
    }

    // Get return address
    auto ra = info.getRegisterValue(info.return_address_register, registers, cfa, read_memory);
    if (ra) {
        result.return_address = *ra;
        result.success = true;
    }

    return result;
}

// Source location methods

std::optional<SourceLocation> DwarfParser::getSourceLocation(uint64_t address) const {
    if (source_resolver_) {
        return source_resolver_->getSourceLocation(address);
    }
    return std::nullopt;
}

std::vector<SourceLocation> DwarfParser::getAllSourceLocations(uint64_t address) const {
    if (source_resolver_) {
        return source_resolver_->getAllSourceLocations(address);
    }
    return {};
}

std::vector<uint64_t> DwarfParser::getAddressesForLine(const std::string& file, uint32_t line) const {
    if (source_resolver_) {
        return source_resolver_->getAddressesForLine(file, line);
    }
    return {};
}

std::optional<AddressRange> DwarfParser::getAddressRangeForLine(const std::string& file, uint32_t line) const {
    if (source_resolver_) {
        return source_resolver_->getAddressRangeForLine(file, line);
    }
    return std::nullopt;
}

std::vector<SourceLocation> DwarfParser::getLinesInFile(const std::string& file) const {
    if (source_resolver_) {
        return source_resolver_->getLinesInFile(file);
    }
    return {};
}

std::vector<std::string> DwarfParser::getAllSourceFiles() const {
    if (source_resolver_) {
        return source_resolver_->getAllFiles();
    }
    return {};
}

void DwarfParser::initializeSourceResolver() {
    if (debug_line_.empty()) {
        return;
    }

    source_resolver_ = std::make_unique<SourceLocationResolver>();

    // Parse line tables for each compilation unit
    for (const auto& cu : compilation_units_) {
        // Get the stmt_list attribute which points to the line table
        auto stmt_list_attr = cu->getAttribute(DwarfAttribute::DW_AT_stmt_list);
        if (!stmt_list_attr) {
            continue;
        }

        auto line_attr = std::dynamic_pointer_cast<LineAttributeValue>(stmt_list_attr);
        if (!line_attr) {
            continue;
        }

        // Get compilation directory
        std::string comp_dir;
        auto comp_dir_attr = cu->getAttribute(DwarfAttribute::DW_AT_comp_dir);
        if (comp_dir_attr) {
            auto str_attr = std::dynamic_pointer_cast<StringAttributeValue>(comp_dir_attr);
            if (str_attr) {
                comp_dir = str_attr->getValue();
            }
        }

        // Build directories list
        std::vector<std::string> directories = line_attr->getDirectories();

        // Add line table entries
        source_resolver_->addLineTable(
            line_attr->getLines(),
            directories,
            line_attr->getFiles(),
            comp_dir
        );
    }
}

// Variable location methods

VariableLocation DwarfParser::getVariableLocation(const std::shared_ptr<DIE>& variable, uint64_t pc) const {
    if (!variable || !var_evaluator_) {
        return VariableLocation();
    }

    // Keep evaluator context call-local so diagnostics and CU-specific address data
    // do not leak into unrelated future evaluations.
    EvaluationContext prev_ctx = var_evaluator_->getContext();
    struct ContextRestoreGuard {
        VariableLocationEvaluator* evaluator;
        EvaluationContext previous;
        ~ContextRestoreGuard() {
            if (evaluator) evaluator->setContext(previous);
        }
    } restore{var_evaluator_.get(), prev_ctx};

    // Augment the existing evaluation context with CU-specific address-base info
    // so expression ops like DW_OP_addrx/DW_OP_constx can resolve.
    {
        EvaluationContext ctx = prev_ctx;
        ctx.address_size = (address_size_ == AddressSize::ADDR_64) ? 8 : 4;
        ctx.offset_size = 4; // Default; we'll refine from containing CU if possible.
        ctx.cu_base_offset = 0;

        // Find containing CU by offset (best-effort).
        std::shared_ptr<DIE> best_cu;
        uint64_t best_off = 0;
        uint64_t die_off = variable->getOffset();
        for (const auto& cu : compilation_units_) {
            if (!cu) continue;
            uint64_t cu_off = cu->getOffset();
            if (cu_off <= die_off && cu_off >= best_off) {
                best_off = cu_off;
                best_cu = cu;
            }
        }

        if (best_cu) {
            ctx.offset_size = best_cu->getOffsetSize();
            ctx.cu_base_offset = best_cu->getCUBaseOffset();
            ctx.diagnostic_cu_offset = best_cu->getOffset();

            auto addr_base_attr = best_cu->getAttribute(DwarfAttribute::DW_AT_addr_base);
            auto addr_base_u = std::dynamic_pointer_cast<UnsignedAttributeValue>(addr_base_attr);
            if (addr_base_u) {
                ctx.addr_base = addr_base_u->getValue();
                const std::vector<uint8_t>* dbg_addr = &debug_addr_;
                uint64_t cu_off = best_cu->getOffset();

                // DWO units use a biased offset with bit 63 set.
                if (cu_off & (1ULL << 63)) {
                    uint16_t slot = static_cast<uint16_t>((cu_off >> 48) & 0x7fffU);
                    auto it_id = dwo_id_by_slot_.find(slot);
                    if (it_id != dwo_id_by_slot_.end()) {
                        auto it_sec = dwo_debug_addr_by_id_.find(it_id->second);
                        if (it_sec != dwo_debug_addr_by_id_.end() && !it_sec->second.empty()) {
                            dbg_addr = &it_sec->second;
                        }
                    }
                } else if (cu_off & (1ULL << 62)) {
                    // Supplementary units use bit 62 bias.
                    if (!sup_debug_addr_.empty()) {
                        dbg_addr = &sup_debug_addr_;
                    }
                }

                ctx.debug_addr_table = getDebugAddrTableForSection(*dbg_addr, ctx.addr_base, ctx.address_size);
            }
        }

        // Attach concrete DIE/attribute context for evaluator diagnostics.
        ctx.diagnostic_die_offset = variable->getOffset();
        ctx.diagnostic_attribute = "DW_AT_location";

        // Allow ExpressionEvaluator to resolve DW_OP_call* and typed ops.
        ctx.resolve_dwarf_procedure = [this](uint64_t die_offset, uint64_t pc) -> std::optional<std::vector<uint8_t>> {
            auto die = findDIEByOffset(die_offset);
            if (!die) return std::nullopt;
            auto loc_attr = die->getAttribute(DwarfAttribute::DW_AT_location);
            if (!loc_attr) return std::nullopt;

            if (auto expr_attr = std::dynamic_pointer_cast<ExpressionAttributeValue>(loc_attr)) {
                return expr_attr->getExpression();
            }
            if (auto block_attr = std::dynamic_pointer_cast<BlockAttributeValue>(loc_attr)) {
                return block_attr->getData();
            }
            if (auto loc_type_attr = std::dynamic_pointer_cast<LocationAttributeValue>(loc_attr)) {
                if (loc_type_attr->getLocationType() == LocationAttributeValue::LocationType::EXPRESSION) {
                    return loc_type_attr->getData();
                }
                if (loc_type_attr->getLocationType() == LocationAttributeValue::LocationType::LIST) {
                    auto e = loc_type_attr->getExpressionForPC(pc);
                    if (!e.empty()) return e;
                }
            }
            return std::nullopt;
        };

        ctx.resolve_base_type = [this](uint64_t type_die_offset) -> std::optional<EvaluationContext::BaseTypeInfo> {
            // Typed ops reference a base type, but in practice producers may hand us typedefs,
            // qualifiers, etc. Follow DW_AT_type chains best-effort.
            uint64_t cur = type_die_offset;
            for (int depth = 0; depth < 16; ++depth) {
                auto die = findDIEByOffset(cur);
                if (!die) return std::nullopt;

                if (die->getTag() == DwarfTag::DW_TAG_base_type) {
                    EvaluationContext::BaseTypeInfo info;

                    auto size_attr = die->getAttribute(DwarfAttribute::DW_AT_byte_size);
                    if (auto sz = std::dynamic_pointer_cast<UnsignedAttributeValue>(size_attr)) {
                        info.byte_size = sz->getValue();
                    }

                    auto enc_attr = die->getAttribute(DwarfAttribute::DW_AT_encoding);
                    auto enc = std::dynamic_pointer_cast<UnsignedAttributeValue>(enc_attr);
                    if (enc) {
                        DW_ATE ate = static_cast<DW_ATE>(static_cast<uint8_t>(enc->getValue() & 0xff));
                        info.encoding = ate;
                        switch (ate) {
                            case DW_ATE::DW_ATE_signed:
                            case DW_ATE::DW_ATE_signed_char:
                            case DW_ATE::DW_ATE_signed_fixed:
                                info.is_integer = true;
                                info.is_signed = true;
                                break;
                            case DW_ATE::DW_ATE_unsigned:
                            case DW_ATE::DW_ATE_unsigned_char:
                            case DW_ATE::DW_ATE_unsigned_fixed:
                            case DW_ATE::DW_ATE_boolean:
                            case DW_ATE::DW_ATE_address:
                                info.is_integer = true;
                                info.is_signed = false;
                                break;
                            case DW_ATE::DW_ATE_float:
                            case DW_ATE::DW_ATE_complex_float:
                            case DW_ATE::DW_ATE_imaginary_float:
                            case DW_ATE::DW_ATE_decimal_float:
                                info.is_integer = false;
                                info.is_signed = false;
                                break;
                            default:
                                info.is_integer = false;
                                info.is_signed = false;
                                break;
                        }
                    }

                    return info;
                }

                auto t = die->getAttribute(DwarfAttribute::DW_AT_type);
                if (auto tv = std::dynamic_pointer_cast<TypeAttributeValue>(t)) {
                    cur = tv->getOffset();
                    continue;
                }
                if (auto rv = std::dynamic_pointer_cast<ReferenceAttributeValue>(t)) {
                    cur = rv->getOffset();
                    continue;
                }

                return std::nullopt;
            }
            return std::nullopt;
        };

        var_evaluator_->setContext(ctx);
    }

    // Get the DW_AT_location attribute
    auto loc_attr = variable->getAttribute(DwarfAttribute::DW_AT_location);
    if (!loc_attr) {
        VariableLocation loc;
        loc.type = VariableLocationType::OPTIMIZED_OUT;
        loc.description = "no location attribute";
        return loc;
    }

    // Handle expression form
    auto expr_attr = std::dynamic_pointer_cast<ExpressionAttributeValue>(loc_attr);
    if (expr_attr) {
        return var_evaluator_->evaluateExpression(expr_attr->getExpression(), pc);
    }

    // Handle LocationAttributeValue (which can be expression or list)
    auto loc_type_attr = std::dynamic_pointer_cast<LocationAttributeValue>(loc_attr);
    if (loc_type_attr) {
        if (loc_type_attr->getLocationType() == LocationAttributeValue::LocationType::EXPRESSION) {
            return var_evaluator_->evaluateExpression(loc_type_attr->getData(), pc);
        }
        if (loc_type_attr->getLocationType() == LocationAttributeValue::LocationType::LIST) {
            auto expr = loc_type_attr->getExpressionForPC(pc);
            if (expr.empty()) {
                VariableLocation loc;
                loc.type = VariableLocationType::OPTIMIZED_OUT;
                loc.description = "not available at this PC";
                return loc;
            }
            return var_evaluator_->evaluateExpression(expr, pc);
        }
    }

    // Handle block form (raw expression bytes)
    auto block_attr = std::dynamic_pointer_cast<BlockAttributeValue>(loc_attr);
    if (block_attr) {
        return var_evaluator_->evaluateExpression(block_attr->getData(), pc);
    }

    VariableLocation loc;
    loc.type = VariableLocationType::INVALID;
    loc.description = "unknown location form";
    return loc;
}

VariableLocation DwarfParser::evaluateLocation(const std::vector<uint8_t>& location_data,
                                               uint64_t pc, bool is_loclist) const {
    if (!var_evaluator_) {
        // Create a temporary evaluator
        VariableLocationEvaluator temp_eval;
        return temp_eval.evaluateLocation(location_data, pc, is_loclist);
    }
    return var_evaluator_->evaluateLocation(location_data, pc, is_loclist);
}

void DwarfParser::setVariableEvaluationContext(const EvaluationContext& context) {
    if (!var_evaluator_) {
        var_evaluator_ = std::make_unique<VariableLocationEvaluator>();
    }
    var_evaluator_->setContext(context);
}

void DwarfParser::setMemoryReader(std::function<bool(uint64_t, size_t, void*)> reader) {
    if (!var_evaluator_) {
        var_evaluator_ = std::make_unique<VariableLocationEvaluator>();
    }
    var_evaluator_->setMemoryReader(reader);
}

// Split DWARF methods

void DwarfParser::addDWOSearchPath(const std::string& path) {
    if (!split_loader_) {
        split_loader_ = std::make_unique<SplitDwarfLoader>();
    }
    split_loader_->addSearchPath(path);
}

void DwarfParser::setDWOSearchPaths(const std::vector<std::string>& paths) {
    if (!split_loader_) {
        split_loader_ = std::make_unique<SplitDwarfLoader>();
    }
    split_loader_->setSearchPaths(paths);
}

bool DwarfParser::loadDWOFile(const std::string& path) {
    if (!split_loader_) {
        split_loader_ = std::make_unique<SplitDwarfLoader>();
    }
    return split_loader_->loadDWOFile(path);
}

bool DwarfParser::loadDWPFile(const std::string& path) {
    if (!dwp_loader_) {
        dwp_loader_ = std::make_unique<DWPLoader>();
    }
    return dwp_loader_->load(path);
}

} // namespace dwarf
