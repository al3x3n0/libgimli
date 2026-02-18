#include "variable_location.hpp"
#include "dwarf_utils.hpp"
#include <sstream>
#include <iomanip>

namespace dwarf {

VariableLocationEvaluator::VariableLocationEvaluator() {
    memory_context_ = std::make_shared<DefaultMemoryContext>();
    evaluator_ = std::make_unique<ExpressionEvaluator>(memory_context_);
}

void VariableLocationEvaluator::setContext(const EvaluationContext& context) {
    context_ = context;
    evaluator_->setContext(context);
}

void VariableLocationEvaluator::setMemoryReader(
    std::function<bool(uint64_t, size_t, void*)> reader) {
    memory_reader_ = reader;
    memory_context_ = std::make_shared<CallbackMemoryContext>(reader);
    evaluator_->setMemoryContext(memory_context_);
}

VariableLocation VariableLocationEvaluator::evaluateExpression(
    const std::vector<uint8_t>& expression, uint64_t pc) {

    if (expression.empty()) {
        VariableLocation loc;
        loc.type = VariableLocationType::OPTIMIZED_OUT;
        loc.description = "optimized out (empty expression)";
        return loc;
    }

    std::vector<uint64_t> registers;
    // Use entry_registers from context if available
    registers = context_.entry_registers;

    ExpressionResult result = evaluator_->evaluate(expression, context_, pc, registers);
    return resultToLocation(result);
}

VariableLocation VariableLocationEvaluator::evaluateLocationList(
    const std::vector<LocationListEntry>& entries, uint64_t pc) {

    const LocationListEntry* entry = findEntry(entries, pc);

    if (!entry) {
        VariableLocation loc;
        loc.type = VariableLocationType::OPTIMIZED_OUT;
        loc.description = "not available at this PC";
        return loc;
    }

    return evaluateExpression(entry->expression, pc);
}

VariableLocation VariableLocationEvaluator::evaluateLocList(
    const std::vector<LocListEntry>& entries, uint64_t pc) {

    // Find matching entry
    const LocListEntry* best_entry = nullptr;
    const LocListEntry* default_entry = nullptr;

    for (const auto& entry : entries) {
        if (entry.type == DW_LLE::DW_LLE_end_of_list) {
            break;
        }

        if (entry.is_default) {
            default_entry = &entry;
            continue;
        }

        // Check if PC is within range
        if (pc >= entry.start && pc < entry.end) {
            best_entry = &entry;
            break;
        }
    }

    if (!best_entry) {
        best_entry = default_entry;
    }

    if (!best_entry || best_entry->expression.empty()) {
        VariableLocation loc;
        loc.type = VariableLocationType::OPTIMIZED_OUT;
        loc.description = "not available at this PC";
        return loc;
    }

    return evaluateExpression(best_entry->expression, pc);
}

VariableLocation VariableLocationEvaluator::evaluateLocation(
    const std::vector<uint8_t>& location_data, uint64_t pc, bool is_loclist) {

    if (location_data.empty()) {
        VariableLocation loc;
        loc.type = VariableLocationType::OPTIMIZED_OUT;
        loc.description = "optimized out";
        return loc;
    }

    if (is_loclist) {
        // Parse as DWARF 4 location list
        std::vector<LocationListEntry> entries;
        uint64_t offset = 0;
        uint64_t base_address = context_.cfa; // Best-effort fallback base

        uint8_t addr_size = context_.address_size ? context_.address_size : 8;
        uint64_t max_addr = (addr_size == 4) ? 0xffffffffULL : UINT64_MAX;

        auto readAddr = [&](uint64_t& off) -> uint64_t {
            if (addr_size == 4) {
                return DwarfUtils::readU32(location_data.data(), off, location_data.size());
            }
            return DwarfUtils::readU64(location_data.data(), off, location_data.size());
        };

        while (offset + (2 * addr_size) + 2 <= location_data.size()) {
            uint64_t start = readAddr(offset);
            uint64_t end = readAddr(offset);

            // End of list
            if (start == 0 && end == 0) {
                break;
            }

            // Base address selection
            if (start == max_addr) {
                base_address = end;
                continue;
            }

            // Read expression length and data
            uint16_t expr_len = DwarfUtils::readU16(location_data.data(), offset, location_data.size());

            if (offset + expr_len > location_data.size()) break;

            LocationListEntry entry;
            entry.start_address = base_address + start;
            entry.end_address = base_address + end;
            entry.expression = std::vector<uint8_t>(
                location_data.begin() + offset,
                location_data.begin() + offset + expr_len);
            offset += expr_len;

            entries.push_back(entry);
        }

        return evaluateLocationList(entries, pc);
    }

    // Treat as simple expression
    return evaluateExpression(location_data, pc);
}

std::optional<std::vector<uint8_t>> VariableLocationEvaluator::readValue(
    const VariableLocation& location, size_t size) {

    if (!location.valid()) {
        return std::nullopt;
    }

    std::vector<uint8_t> value(size);

    switch (location.type) {
        case VariableLocationType::MEMORY:
            if (memory_reader_) {
                if (memory_reader_(location.address, size, value.data())) {
                    return value;
                }
            }
            return std::nullopt;

        case VariableLocationType::REGISTER:
            // Would need register access
            return std::nullopt;

        case VariableLocationType::IMPLICIT:
            if (location.implicit_value.size() >= size) {
                return std::vector<uint8_t>(
                    location.implicit_value.begin(),
                    location.implicit_value.begin() + size);
            }
            return location.implicit_value;

        case VariableLocationType::COMPOSITE: {
            // Read each piece and combine into a packed bitstream (LSB-first for little-endian objects).
            std::vector<uint8_t> result(size, 0);

            const bool little = DwarfUtils::objectIsLittleEndian();
            auto getBit = [&](const std::vector<uint8_t>& buf, size_t bit_index) -> uint8_t {
                size_t byte = bit_index / 8;
                size_t bit = bit_index % 8;
                if (byte >= buf.size()) return 0;
                if (little) {
                    return static_cast<uint8_t>((buf[byte] >> bit) & 0x1);
                }
                // Big-endian: bit 0 is the MSB within a byte.
                return static_cast<uint8_t>((buf[byte] >> (7 - bit)) & 0x1);
            };
            auto setBit = [&](std::vector<uint8_t>& buf, size_t bit_index, uint8_t v) {
                size_t byte = bit_index / 8;
                size_t bit = bit_index % 8;
                if (byte >= buf.size()) return;
                if (little) {
                    uint8_t mask = static_cast<uint8_t>(1u << bit);
                    buf[byte] = static_cast<uint8_t>((buf[byte] & ~mask) | ((v ? 1u : 0u) << bit));
                } else {
                    uint8_t mask = static_cast<uint8_t>(1u << (7 - bit));
                    buf[byte] = static_cast<uint8_t>((buf[byte] & ~mask) | ((v ? 1u : 0u) << (7 - bit)));
                }
            };

            size_t dst_bit_cursor = 0;
            const size_t dst_bits = size * 8;

            for (const auto& piece : location.pieces) {
                if (dst_bit_cursor >= dst_bits) break;

                size_t nbits = static_cast<size_t>(piece.size_bits);
                if (nbits == 0) continue;
                if (dst_bit_cursor + nbits > dst_bits) {
                    nbits = dst_bits - dst_bit_cursor;
                }

                std::vector<uint8_t> src;
                size_t src_bit_base = static_cast<size_t>(piece.offset_bits);

                if (piece.type == VariableLocationType::MEMORY) {
                    if (!memory_reader_) {
                        dst_bit_cursor += nbits;
                        continue;
                    }
                    const size_t need_bits = src_bit_base + nbits;
                    const size_t need_bytes = (need_bits + 7) / 8;
                    src.resize(need_bytes, 0);
                    if (!memory_reader_(piece.location, need_bytes, src.data())) {
                        dst_bit_cursor += nbits;
                        continue;
                    }
                } else if (piece.type == VariableLocationType::IMPLICIT) {
                    src = piece.value;
                } else {
                    // REGISTER / OPTIMIZED_OUT / INVALID: we can't materialize bytes here.
                    dst_bit_cursor += nbits;
                    continue;
                }

                for (size_t i = 0; i < nbits; ++i) {
                    uint8_t b = getBit(src, src_bit_base + i);
                    setBit(result, dst_bit_cursor + i, b);
                }
                dst_bit_cursor += nbits;
            }
            return result;
        }

        default:
            return std::nullopt;
    }
}

std::string VariableLocationEvaluator::formatLocation(const VariableLocation& location) {
    std::ostringstream oss;

    switch (location.type) {
        case VariableLocationType::INVALID:
            oss << "<invalid>";
            break;

        case VariableLocationType::REGISTER:
            oss << "register " << location.reg_num;
            break;

        case VariableLocationType::MEMORY:
            oss << "memory 0x" << std::hex << location.address;
            break;

        case VariableLocationType::IMPLICIT:
            oss << "implicit value: ";
            for (size_t i = 0; i < location.implicit_value.size() && i < 8; ++i) {
                oss << std::hex << std::setfill('0') << std::setw(2)
                    << static_cast<int>(location.implicit_value[i]);
            }
            if (location.implicit_value.size() > 8) {
                oss << "...";
            }
            break;

        case VariableLocationType::COMPOSITE:
            oss << "composite [";
            for (size_t i = 0; i < location.pieces.size(); ++i) {
                if (i > 0) oss << ", ";
                const auto& piece = location.pieces[i];
                switch (piece.type) {
                    case VariableLocationType::REGISTER:
                        oss << "reg" << piece.location;
                        break;
                    case VariableLocationType::MEMORY:
                        oss << "mem@0x" << std::hex << piece.location;
                        break;
                    default:
                        oss << "?";
                }
                oss << ":" << std::dec << piece.size_bits << "bits";
            }
            oss << "]";
            break;

        case VariableLocationType::OPTIMIZED_OUT:
            oss << "<optimized out>";
            break;
    }

    if (!location.description.empty()) {
        oss << " (" << location.description << ")";
    }

    return oss.str();
}

VariableLocation VariableLocationEvaluator::resultToLocation(const ExpressionResult& result) {
    VariableLocation loc;

    switch (result.type) {
        case ExpressionResult::ADDRESS:
            loc.type = VariableLocationType::MEMORY;
            loc.address = result.value;
            loc.description = result.description;
            break;

        case ExpressionResult::REGISTER:
            loc.type = VariableLocationType::REGISTER;
            loc.reg_num = result.value;
            loc.description = result.description;
            break;

        case ExpressionResult::VALUE:
            loc.type = VariableLocationType::IMPLICIT;
            // Store value as bytes
            loc.implicit_value.resize(8);
            for (int i = 0; i < 8; ++i) {
                loc.implicit_value[i] = (result.value >> (i * 8)) & 0xff;
            }
            loc.description = result.description;
            break;

        case ExpressionResult::COMPOSITE:
            loc.type = VariableLocationType::COMPOSITE;
            for (const auto& piece : result.pieces) {
                LocationPiece lp;
                switch (piece.kind) {
                    case PieceDescriptor::MEMORY:
                        lp.type = VariableLocationType::MEMORY;
                        lp.location = piece.location;
                        break;
                    case PieceDescriptor::REGISTER:
                        lp.type = VariableLocationType::REGISTER;
                        lp.location = piece.location;
                        break;
                    case PieceDescriptor::IMPLICIT:
                        lp.type = VariableLocationType::IMPLICIT;
                        lp.value = piece.implicit_value;
                        break;
                    case PieceDescriptor::EMPTY:
                        lp.type = VariableLocationType::OPTIMIZED_OUT;
                        break;
                }
                lp.size_bits = piece.bit_size;
                lp.offset_bits = piece.bit_offset;
                loc.pieces.push_back(lp);
            }
            loc.description = result.description;
            break;

        case ExpressionResult::INVALID:
        default:
            loc.type = VariableLocationType::INVALID;
            loc.description = result.description;
            break;
    }

    return loc;
}

const LocationListEntry* VariableLocationEvaluator::findEntry(
    const std::vector<LocationListEntry>& entries, uint64_t pc) const {

    const LocationListEntry* default_entry = nullptr;

    for (const auto& entry : entries) {
        if (entry.is_default) {
            default_entry = &entry;
            continue;
        }

        if (pc >= entry.start_address && pc < entry.end_address) {
            return &entry;
        }
    }

    return default_entry;
}

} // namespace dwarf
