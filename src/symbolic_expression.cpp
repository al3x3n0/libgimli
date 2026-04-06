#include "symbolic_expression.hpp"
#include "dwarf_utils.hpp"
#include <cassert>
#include <limits>
#include <sstream>

namespace dwarf {

namespace {
thread_local bool g_decode_error = false;
thread_local std::string g_decode_error_message;

void clearDecodeError() {
    g_decode_error = false;
    g_decode_error_message.clear();
}

struct DecodeStateScope {
    bool prev_error = false;
    std::string prev_message;

    DecodeStateScope() : prev_error(g_decode_error), prev_message(g_decode_error_message) {
        clearDecodeError();
    }

    ~DecodeStateScope() {
        g_decode_error = prev_error;
        g_decode_error_message = std::move(prev_message);
    }
};

void setDecodeError(const char* msg) {
    if (!g_decode_error) {
        g_decode_error = true;
        g_decode_error_message = msg ? msg : "decode error";
    }
}

bool hasDecodeError() {
    return g_decode_error;
}

std::string unsupportedOpMessage(uint8_t opcode, uint64_t offset) {
    std::ostringstream oss;
    oss << "unsupported op "
        << DwarfUtils::operationToString(static_cast<DwarfOp>(opcode))
        << " (opcode 0x" << std::hex << static_cast<unsigned>(opcode) << std::dec << ")";
    if (opcode >= 0xe0) {
        oss << " [vendor/extension opcode]";
    }
    oss << " at " << offset;
    return oss.str();
}

const char* vendorProfileOpcodeName(VendorExpressionProfile profile, uint8_t opcode) {
    if (profile == VendorExpressionProfile::SYNTHETIC_V1) {
        switch (opcode) {
            case 0xf9: return "DW_OP_vendor_synthetic_constu";
            case 0xfd: return "DW_OP_vendor_synthetic_plus_uconst";
            case 0xfe: return "DW_OP_vendor_synthetic_deref_size";
            default: break;
        }
    }
    return nullptr;
}

const std::string& decodeErrorMessage() {
    return g_decode_error_message;
}
} // namespace

static uint64_t dwarfSectionOffsetBias(uint64_t cu_base_offset) {
    constexpr uint64_t kLow48Mask = (1ULL << 48) - 1;
    constexpr uint64_t kBiasBits = (1ULL << 63) | (1ULL << 62);
    if ((cu_base_offset & kBiasBits) == 0) return 0;
    return cu_base_offset & ~kLow48Mask;
}

static uint64_t alignOffsetUp(uint64_t off, uint64_t align) {
    if (align <= 1) return off;
    uint64_t rem = off % align;
    return rem == 0 ? off : (off + (align - rem));
}

static bool isConst(const SymExprPtr& e) {
    return e && e->kind == SymExpr::Kind::CONST_U64;
}

static bool isImmediateLike(const SymExprPtr& e) {
    if (!e) return false;
    return e->kind == SymExpr::Kind::CONST_U64 || e->kind == SymExpr::Kind::BYTES;
}

static std::optional<uint64_t> asConst(const SymExprPtr& e) {
    if (!isConst(e)) return std::nullopt;
    return e->const_u64;
}

static const std::vector<uint8_t>* asBytes(const SymExprPtr& e) {
    if (!e || e->kind != SymExpr::Kind::BYTES) return nullptr;
    return &e->raw_bytes;
}

SymExprPtr SymExpr::makeConst(uint64_t v) {
    auto e = std::make_shared<SymExpr>();
    e->kind = Kind::CONST_U64;
    e->const_u64 = v;
    return e;
}

SymExprPtr SymExpr::makeBytes(std::vector<uint8_t> bytes) {
    auto e = std::make_shared<SymExpr>();
    e->kind = Kind::BYTES;
    e->raw_bytes = std::move(bytes);
    return e;
}

SymExprPtr SymExpr::makeVar(std::string n) {
    auto e = std::make_shared<SymExpr>();
    e->kind = Kind::VAR;
    e->name = std::move(n);
    return e;
}

SymExprPtr SymExpr::makeUnknown(std::string why) {
    auto e = std::make_shared<SymExpr>();
    e->kind = Kind::UNKNOWN;
    e->name = std::move(why);
    return e;
}

SymExprPtr SymExpr::makeUnary(Kind k, SymExprPtr a) {
    if (k == Kind::NEG) {
        if (auto c = asConst(a)) {
            return makeConst(static_cast<uint64_t>(-static_cast<int64_t>(*c)));
        }
    }
    if (k == Kind::NOT) {
        if (auto c = asConst(a)) {
            return makeConst(~(*c));
        }
    }
    if (k == Kind::ABS) {
        if (auto c = asConst(a)) {
            int64_t v = static_cast<int64_t>(*c);
            if (v < 0) v = -v;
            return makeConst(static_cast<uint64_t>(v));
        }
    }

    auto e = std::make_shared<SymExpr>();
    e->kind = k;
    e->args = {std::move(a)};
    return e;
}

static SymExprPtr foldBinary(SymExpr::Kind k, SymExprPtr a, SymExprPtr b) {
    auto ba = asBytes(a);
    auto bb = asBytes(b);
    if (ba && bb) {
        if (k == SymExpr::Kind::EQ) return SymExpr::makeConst((*ba == *bb) ? 1 : 0);
        if (k == SymExpr::Kind::NE) return SymExpr::makeConst((*ba != *bb) ? 1 : 0);
    }

    auto ca = asConst(a);
    auto cb = asConst(b);
    if (!ca || !cb) return nullptr;

    uint64_t x = *ca;
    uint64_t y = *cb;
    switch (k) {
        case SymExpr::Kind::ADD: return SymExpr::makeConst(x + y);
        case SymExpr::Kind::SUB: return SymExpr::makeConst(x - y);
        case SymExpr::Kind::MUL: return SymExpr::makeConst(x * y);
        case SymExpr::Kind::DIV: return (y == 0) ? SymExpr::makeUnknown("div0") : SymExpr::makeConst(x / y);
        case SymExpr::Kind::MOD: return (y == 0) ? SymExpr::makeUnknown("mod0") : SymExpr::makeConst(x % y);
        case SymExpr::Kind::AND: return SymExpr::makeConst(x & y);
        case SymExpr::Kind::OR: return SymExpr::makeConst(x | y);
        case SymExpr::Kind::XOR: return SymExpr::makeConst(x ^ y);
        case SymExpr::Kind::SHL: return SymExpr::makeConst(x << (y & 63));
        case SymExpr::Kind::SHR: return SymExpr::makeConst(x >> (y & 63));
        case SymExpr::Kind::SHRA: {
            int64_t sx = static_cast<int64_t>(x);
            int64_t r = sx >> (y & 63);
            return SymExpr::makeConst(static_cast<uint64_t>(r));
        }
        case SymExpr::Kind::EQ: return SymExpr::makeConst(x == y ? 1 : 0);
        case SymExpr::Kind::NE: return SymExpr::makeConst(x != y ? 1 : 0);
        case SymExpr::Kind::LT: return SymExpr::makeConst(static_cast<int64_t>(x) < static_cast<int64_t>(y) ? 1 : 0);
        case SymExpr::Kind::LE: return SymExpr::makeConst(static_cast<int64_t>(x) <= static_cast<int64_t>(y) ? 1 : 0);
        case SymExpr::Kind::GT: return SymExpr::makeConst(static_cast<int64_t>(x) > static_cast<int64_t>(y) ? 1 : 0);
        case SymExpr::Kind::GE: return SymExpr::makeConst(static_cast<int64_t>(x) >= static_cast<int64_t>(y) ? 1 : 0);
        default:
            return nullptr;
    }
}

SymExprPtr SymExpr::makeBinary(Kind k, SymExprPtr a, SymExprPtr b) {
    if (auto folded = foldBinary(k, a, b)) {
        return folded;
    }

    if ((k == Kind::EQ || k == Kind::NE) && a && b && a->toString() == b->toString()) {
        return makeConst(k == Kind::EQ ? 1 : 0);
    }

    // Simple identities.
    if (k == Kind::ADD) {
        if (auto cb = asConst(b); cb && *cb == 0) return a;
        if (auto ca = asConst(a); ca && *ca == 0) return b;
    }
    if (k == Kind::SUB) {
        if (auto cb = asConst(b); cb && *cb == 0) return a;
    }
    if (k == Kind::MUL) {
        if (auto cb = asConst(b); cb && *cb == 1) return a;
        if (auto ca = asConst(a); ca && *ca == 1) return b;
        if (auto cb = asConst(b); cb && *cb == 0) return makeConst(0);
        if (auto ca = asConst(a); ca && *ca == 0) return makeConst(0);
    }

    auto e = std::make_shared<SymExpr>();
    e->kind = k;
    e->args = {std::move(a), std::move(b)};
    return e;
}

SymExprPtr SymExpr::makeITE(SymExprPtr cond, SymExprPtr t, SymExprPtr f) {
    if (auto cc = asConst(cond)) {
        return (*cc != 0) ? t : f;
    }
    if (t && f && t->toString() == f->toString()) {
        return t;
    }
    auto e = std::make_shared<SymExpr>();
    e->kind = Kind::ITE;
    e->args = {std::move(cond), std::move(t), std::move(f)};
    return e;
}

SymExprPtr SymExpr::makeLoad(SymExprPtr addr, uint64_t size_bytes) {
    auto e = std::make_shared<SymExpr>();
    e->kind = Kind::LOAD;
    e->aux_bytes = size_bytes;
    e->args = {std::move(addr)};
    return e;
}

static uint64_t maskToBytesU64(uint64_t v, uint64_t byte_size) {
    if (byte_size == 0) return v;
    if (byte_size >= 8) return v;
    uint64_t bits = byte_size * 8;
    return v & ((1ULL << bits) - 1ULL);
}

static uint64_t signExtendBytesU64(uint64_t v, uint64_t byte_size) {
    if (byte_size == 0) return v;
    if (byte_size >= 8) return v;
    v = maskToBytesU64(v, byte_size);
    uint64_t shift = 64 - (byte_size * 8);
    return static_cast<uint64_t>(static_cast<int64_t>(v << shift) >> shift);
}

static uint64_t decodeLowBytesU64(const std::vector<uint8_t>& bytes, uint64_t byte_size) {
    if (byte_size == 0 || bytes.empty()) return 0;
    if (byte_size > 8) return 0;

    bool le = DwarfUtils::objectIsLittleEndian();
    size_t n = static_cast<size_t>(byte_size);
    if (n > bytes.size()) n = bytes.size();

    uint64_t v = 0;
    if (le) {
        for (size_t i = 0; i < n; ++i) {
            v |= static_cast<uint64_t>(bytes[i]) << (i * 8);
        }
    } else {
        size_t start = bytes.size() - n;
        for (size_t i = 0; i < n; ++i) {
            v = (v << 8) | static_cast<uint64_t>(bytes[start + i]);
        }
    }
    return v;
}

SymExprPtr SymExpr::makeMask(SymExprPtr v, uint64_t size_bytes) {
    if (auto c = asConst(v)) {
        return makeConst(maskToBytesU64(*c, size_bytes));
    }
    if (auto b = asBytes(v); b && size_bytes <= 8) {
        return makeConst(maskToBytesU64(decodeLowBytesU64(*b, size_bytes), size_bytes));
    }
    auto e = std::make_shared<SymExpr>();
    e->kind = Kind::MASK;
    e->aux_bytes = size_bytes;
    e->args = {std::move(v)};
    return e;
}

SymExprPtr SymExpr::makeSExt(SymExprPtr v, uint64_t size_bytes) {
    if (auto c = asConst(v)) {
        return makeConst(signExtendBytesU64(*c, size_bytes));
    }
    if (auto b = asBytes(v); b && size_bytes <= 8) {
        return makeConst(signExtendBytesU64(decodeLowBytesU64(*b, size_bytes), size_bytes));
    }
    auto e = std::make_shared<SymExpr>();
    e->kind = Kind::SEXT;
    e->aux_bytes = size_bytes;
    e->args = {std::move(v)};
    return e;
}

std::string SymExpr::toString() const {
    auto child = [](const SymExprPtr& expr) -> std::string {
        return expr ? expr->toString() : "null_expr";
    };
    auto bin = [&](const char* op) -> std::string {
        if (args.size() != 2) {
            std::ostringstream ss;
            ss << "malformed_bin(" << op << ",argc=" << args.size() << ")";
            return ss.str();
        }
        return "(" + child(args[0]) + " " + op + " " + child(args[1]) + ")";
    };
    auto un = [&](const char* op) -> std::string {
        if (args.size() != 1) {
            std::ostringstream ss;
            ss << "malformed_un(" << op << ",argc=" << args.size() << ")";
            return ss.str();
        }
        return std::string(op) + "(" + child(args[0]) + ")";
    };

    switch (kind) {
        case Kind::CONST_U64: {
            std::ostringstream ss;
            ss << "0x" << std::hex << const_u64;
            return ss.str();
        }
        case Kind::BYTES: {
            std::ostringstream ss;
            ss << "bytes(0x";
            ss << std::hex;
            for (uint8_t b : raw_bytes) {
                if (b < 0x10) ss << '0';
                ss << static_cast<unsigned int>(b);
            }
            ss << ")";
            return ss.str();
        }
        case Kind::VAR:
            return name;
        case Kind::ADD: return bin("+");
        case Kind::SUB: return bin("-");
        case Kind::MUL: return bin("*");
        case Kind::DIV: return bin("/");
        case Kind::MOD: return bin("%");
        case Kind::AND: return bin("&");
        case Kind::OR: return bin("|");
        case Kind::XOR: return bin("^");
        case Kind::SHL: return bin("<<");
        case Kind::SHR: return bin(">>");
        case Kind::SHRA: return bin(">>a");
        case Kind::NEG: return un("neg");
        case Kind::NOT: return un("not");
        case Kind::ABS: return un("abs");
        case Kind::EQ: return bin("==");
        case Kind::NE: return bin("!=");
        case Kind::LT: return bin("<");
        case Kind::LE: return bin("<=");
        case Kind::GT: return bin(">");
        case Kind::GE: return bin(">=");
        case Kind::ITE: {
            if (args.size() != 3) {
                std::ostringstream ss;
                ss << "malformed_ite(argc=" << args.size() << ")";
                return ss.str();
            }
            return "ite(" + child(args[0]) + "," + child(args[1]) + "," + child(args[2]) + ")";
        }
        case Kind::LOAD: {
            if (args.size() != 1) {
                std::ostringstream ss;
                ss << "malformed_load(argc=" << args.size() << ",bytes=" << std::dec << aux_bytes << ")";
                return ss.str();
            }
            std::ostringstream ss;
            ss << "load(" << child(args[0]) << "," << std::dec << aux_bytes << ")";
            return ss.str();
        }
        case Kind::MASK: {
            if (args.size() != 1) {
                std::ostringstream ss;
                ss << "malformed_mask(argc=" << args.size() << ",bytes=" << std::dec << aux_bytes << ")";
                return ss.str();
            }
            std::ostringstream ss;
            ss << "mask" << std::dec << aux_bytes << "(" << child(args[0]) << ")";
            return ss.str();
        }
        case Kind::SEXT: {
            if (args.size() != 1) {
                std::ostringstream ss;
                ss << "malformed_sext(argc=" << args.size() << ",bytes=" << std::dec << aux_bytes << ")";
                return ss.str();
            }
            std::ostringstream ss;
            ss << "sext" << std::dec << aux_bytes << "(" << child(args[0]) << ")";
            return ss.str();
        }
        case Kind::UNKNOWN:
            return "unknown(" + name + ")";
    }
    std::ostringstream ss;
    ss << "malformed_kind(" << static_cast<int>(kind) << ")";
    return ss.str();
}

SymExprPtr SymbolicExpressionEvaluator::pop() {
    if (stack_.empty()) return SymExpr::makeUnknown("empty_stack");
    auto v = stack_.back();
    stack_.pop_back();
    if (!stack_kinds_.empty()) {
        stack_kinds_.pop_back();
    }
    if (!stack_implicit_bytes_.empty()) {
        stack_implicit_bytes_.pop_back();
    }
    return v;
}

SymExprPtr SymbolicExpressionEvaluator::top() const {
    if (stack_.empty()) return SymExpr::makeUnknown("empty_stack");
    return stack_.back();
}

SymStackValueKind SymbolicExpressionEvaluator::topKind() const {
    if (stack_kinds_.empty()) return SymStackValueKind::ADDRESS;
    return stack_kinds_.back();
}

std::optional<std::vector<uint8_t>> SymbolicExpressionEvaluator::topImplicitBytes() const {
    if (stack_implicit_bytes_.empty()) return std::nullopt;
    return stack_implicit_bytes_.back();
}

void SymbolicExpressionEvaluator::setTopKind(SymStackValueKind kind) {
    if (!stack_kinds_.empty()) {
        stack_kinds_.back() = kind;
    }
}

void SymbolicExpressionEvaluator::push(SymExprPtr v, SymStackValueKind kind) {
    stack_.push_back(std::move(v));
    stack_kinds_.push_back(kind);
    stack_implicit_bytes_.push_back(std::nullopt);
}

void SymbolicExpressionEvaluator::pushWithImplicitBytes(SymExprPtr v, std::vector<uint8_t> bytes,
                                                        SymStackValueKind kind) {
    stack_.push_back(std::move(v));
    stack_kinds_.push_back(kind);
    stack_implicit_bytes_.push_back(std::move(bytes));
}

SymExprPtr SymbolicExpressionEvaluator::regValueExpr(uint64_t regnum) const {
    // If caller provided concrete registers, use them; otherwise keep symbolic.
    if (regnum < regs_.size()) {
        return SymExpr::makeConst(regs_[regnum]);
    }
    return SymExpr::makeVar("reg" + std::to_string(regnum));
}

SymExprPtr SymbolicExpressionEvaluator::materializeForComputation(const SymExprPtr& v,
                                                                  SymStackValueKind kind) const {
    if (kind != SymStackValueKind::REGISTER) return v;
    auto regnum = asConst(v);
    if (!regnum) return SymExpr::makeUnknown("reg?");
    return regValueExpr(*regnum);
}

SymExprPtr SymbolicExpressionEvaluator::frameBaseExpr() const {
    if (ctx_.frame_base != 0) return SymExpr::makeConst(ctx_.frame_base);
    return SymExpr::makeVar("frame_base");
}

SymExprPtr SymbolicExpressionEvaluator::cfaExpr() const {
    if (ctx_.cfa != 0) return SymExpr::makeConst(ctx_.cfa);
    return SymExpr::makeVar("cfa");
}

SymExprPtr SymbolicExpressionEvaluator::tlsBaseExpr() const {
    if (ctx_.tls_base != 0) return SymExpr::makeConst(ctx_.tls_base);
    return SymExpr::makeVar("tls_base");
}

SymExprPtr SymbolicExpressionEvaluator::objectAddrExpr() const {
    if (ctx_.object_address != 0) return SymExpr::makeConst(ctx_.object_address);
    return SymExpr::makeVar("object_address");
}

std::string SymbolicExpressionEvaluator::diagnosticContextSuffix() const {
    return DwarfUtils::formatDiagnosticContext(
        ctx_.diagnostic_cu_offset,
        ctx_.diagnostic_die_offset,
        ctx_.diagnostic_attribute);
}

void SymbolicExpressionEvaluator::appendDiagnosticContext(SymbolicExpressionResult& result) const {
    if (result.type != SymbolicExpressionResult::Type::INVALID) return;
    std::string suffix = diagnosticContextSuffix();
    if (suffix.empty()) return;
    if (result.error.find(suffix) != std::string::npos) return;
    result.error += suffix;
}

static uint64_t readU8(const std::vector<uint8_t>& b, uint64_t& off) {
    if (off >= b.size()) {
        setDecodeError("truncated u8");
        return 0;
    }
    return b[off++];
}

static uint64_t readU16(const std::vector<uint8_t>& b, uint64_t& off) {
    uint64_t avail = (off <= b.size()) ? (b.size() - off) : 0;
    if (avail < 2) {
        setDecodeError("truncated u16");
        off = b.size();
        return 0;
    }
    uint64_t v = static_cast<uint64_t>(b[off]) | (static_cast<uint64_t>(b[off + 1]) << 8);
    off += 2;
    return v;
}

static uint64_t readU32(const std::vector<uint8_t>& b, uint64_t& off) {
    uint64_t avail = (off <= b.size()) ? (b.size() - off) : 0;
    if (avail < 4) {
        setDecodeError("truncated u32");
        off = b.size();
        return 0;
    }
    uint64_t v = static_cast<uint64_t>(b[off]) |
                 (static_cast<uint64_t>(b[off + 1]) << 8) |
                 (static_cast<uint64_t>(b[off + 2]) << 16) |
                 (static_cast<uint64_t>(b[off + 3]) << 24);
    off += 4;
    return v;
}

static uint64_t readU64(const std::vector<uint8_t>& b, uint64_t& off) {
    uint64_t avail = (off <= b.size()) ? (b.size() - off) : 0;
    if (avail < 8) {
        setDecodeError("truncated u64");
        off = b.size();
        return 0;
    }
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(b[off + i]) << (i * 8);
    }
    off += 8;
    return v;
}

static uint64_t readAddressSized(const std::vector<uint8_t>& b, uint64_t& off, uint8_t address_size) {
    if (address_size == 4) return readU32(b, off);
    if (address_size == 8) return readU64(b, off);
    setDecodeError("invalid address_size");
    return 0;
}

static uint64_t readOffsetSized(const std::vector<uint8_t>& b, uint64_t& off, uint8_t offset_size) {
    if (offset_size == 4) return readU32(b, off);
    if (offset_size == 8) return readU64(b, off);
    setDecodeError("invalid offset_size");
    return 0;
}

static uint64_t readULEB(const std::vector<uint8_t>& b, uint64_t& off) {
    if (off >= b.size()) {
        setDecodeError("truncated uleb128");
        return 0;
    }
    uint64_t result = 0;
    uint64_t shift = 0;
    while (true) {
        if (off >= b.size()) {
            setDecodeError("truncated uleb128");
            return result;
        }
        uint8_t byte = b[off++];
        if (shift > 63 || (shift == 63 && (byte & 0x7f) > 1)) {
            setDecodeError("uleb128 overflow");
            return result;
        }
        result |= (static_cast<uint64_t>(byte & 0x7f) << shift);
        if ((byte & 0x80) == 0) break;
        shift += 7;
    }
    return result;
}

static int64_t readSLEB(const std::vector<uint8_t>& b, uint64_t& off) {
    if (off >= b.size()) {
        setDecodeError("truncated sleb128");
        return 0;
    }
    int64_t result = 0;
    int shift = 0;
    uint8_t byte = 0;
    while (true) {
        if (off >= b.size()) {
            setDecodeError("truncated sleb128");
            return result;
        }
        byte = b[off++];
        if (shift > 63 || (shift == 63 && (byte & 0x7f) != 0 && (byte & 0x7f) != 0x7f)) {
            setDecodeError("sleb128 overflow");
            return result;
        }
        result |= (static_cast<int64_t>(byte & 0x7f) << shift);
        shift += 7;
        if ((byte & 0x80) == 0) break;
    }
    if ((shift < 64) && (byte & 0x40)) {
        result |= - (static_cast<int64_t>(1) << shift);
    }
    return result;
}

static std::vector<uint8_t> decodeBytes(const std::vector<uint8_t>& b, uint64_t& off, uint64_t len) {
    std::vector<uint8_t> out;
    uint64_t avail = (off <= b.size()) ? (b.size() - off) : 0;
    if (len > avail) {
        setDecodeError("truncated byte payload");
        len = avail;
    }
    out.insert(out.end(), b.begin() + static_cast<int64_t>(off),
               b.begin() + static_cast<int64_t>(off + len));
    off += len;
    return out;
}

static SymExprPtr decodeAsU64ConstOrUnknown(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return SymExpr::makeConst(0);
    if (bytes.size() > 8) {
        return SymExpr::makeUnknown("bytes>8");
    }
    uint64_t v = 0;
    bool le = DwarfUtils::objectIsLittleEndian();
    if (le) {
        for (size_t i = 0; i < bytes.size(); ++i) v |= static_cast<uint64_t>(bytes[i]) << (i * 8);
    } else {
        for (size_t i = 0; i < bytes.size(); ++i) v = (v << 8) | static_cast<uint64_t>(bytes[i]);
    }
    return SymExpr::makeConst(v);
}

static SymExprPtr decodeAsValueExprPreserveBytes(const std::vector<uint8_t>& bytes) {
    if (bytes.size() <= 8) return decodeAsU64ConstOrUnknown(bytes);
    return SymExpr::makeBytes(bytes);
}

static bool symExprEquivalent(const SymExprPtr& a, const SymExprPtr& b) {
    if (a == b) return true;
    if (!a || !b) return false;
    return a->toString() == b->toString();
}

static SymbolicExpressionResult mergeBranchResults(const SymExprPtr& cond,
                                                   const SymbolicExpressionResult& taken,
                                                   const SymbolicExpressionResult& fallthrough,
                                                   uint8_t address_size,
                                                   const std::vector<uint64_t>& regs) {
    if (taken.type == SymbolicExpressionResult::Type::INVALID) return taken;
    if (fallthrough.type == SymbolicExpressionResult::Type::INVALID) return fallthrough;
    const bool merged_uninitialized = taken.uninitialized || fallthrough.uninitialized;
    auto applyMergedMetadata = [&](SymbolicExpressionResult& merged) {
        if (taken.unsupported_opcode.has_value() &&
            fallthrough.unsupported_opcode.has_value() &&
            *taken.unsupported_opcode == *fallthrough.unsupported_opcode &&
            taken.unsupported_vendor_extension == fallthrough.unsupported_vendor_extension) {
            merged.unsupported_opcode = taken.unsupported_opcode;
            merged.unsupported_vendor_extension = taken.unsupported_vendor_extension;
        }
    };

    if (taken.type != fallthrough.type) {
        auto asValueExpr = [address_size, &regs](const SymbolicExpressionResult& r) -> SymExprPtr {
            if ((r.type == SymbolicExpressionResult::Type::VALUE ||
                 r.type == SymbolicExpressionResult::Type::ADDRESS) &&
                r.expression) {
                if (r.type == SymbolicExpressionResult::Type::VALUE) return r.expression;
                return SymExpr::makeLoad(r.expression, address_size);
            }
            if (r.type == SymbolicExpressionResult::Type::REGISTER && r.expression) {
                auto regnum_opt = asConst(r.expression);
                if (!regnum_opt) return SymExpr::makeUnknown("reg?");
                if (*regnum_opt < regs.size()) return SymExpr::makeConst(regs[*regnum_opt]);
                return SymExpr::makeVar("reg" + std::to_string(*regnum_opt));
            }
            return nullptr;
        };

        auto tv = asValueExpr(taken);
        auto fv = asValueExpr(fallthrough);
        if (tv && fv) {
            SymbolicExpressionResult merged;
            merged.type = SymbolicExpressionResult::Type::VALUE;
            merged.expression = SymExpr::makeITE(cond, tv, fv);
            merged.uninitialized = merged_uninitialized;
            applyMergedMetadata(merged);
            return merged;
        }
        return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "symbolic bra type mismatch"};
    }

    switch (taken.type) {
        case SymbolicExpressionResult::Type::ADDRESS: {
            if (!taken.expression || !fallthrough.expression) {
                return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "symbolic bra missing expression"};
            }
            if (!symExprEquivalent(taken.expression, fallthrough.expression)) {
                SymbolicExpressionResult merged;
                merged.type = SymbolicExpressionResult::Type::VALUE;
                merged.expression = SymExpr::makeITE(
                    cond,
                    SymExpr::makeLoad(taken.expression, address_size),
                    SymExpr::makeLoad(fallthrough.expression, address_size));
                merged.uninitialized = merged_uninitialized;
                applyMergedMetadata(merged);
                return merged;
            }
            SymbolicExpressionResult merged;
            merged.type = SymbolicExpressionResult::Type::ADDRESS;
            merged.expression = taken.expression;
            merged.uninitialized = merged_uninitialized;
            applyMergedMetadata(merged);
            return merged;
        }
        case SymbolicExpressionResult::Type::VALUE: {
            if (!taken.expression || !fallthrough.expression) {
                return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "symbolic bra missing expression"};
            }
            SymbolicExpressionResult merged;
            merged.type = SymbolicExpressionResult::Type::VALUE;
            merged.expression = SymExpr::makeITE(cond, taken.expression, fallthrough.expression);
            merged.uninitialized = merged_uninitialized;
            applyMergedMetadata(merged);
            return merged;
        }
        case SymbolicExpressionResult::Type::REGISTER: {
            if (!taken.expression || !fallthrough.expression) {
                return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "symbolic bra missing register expression"};
            }
            if (!symExprEquivalent(taken.expression, fallthrough.expression)) {
                auto asRegisterValueExpr = [&regs](const SymExprPtr& reg_expr) -> SymExprPtr {
                    auto regnum_opt = asConst(reg_expr);
                    if (!regnum_opt) return SymExpr::makeUnknown("reg?");
                    if (*regnum_opt < regs.size()) return SymExpr::makeConst(regs[*regnum_opt]);
                    return SymExpr::makeVar("reg" + std::to_string(*regnum_opt));
                };
                SymbolicExpressionResult merged;
                merged.type = SymbolicExpressionResult::Type::VALUE;
                merged.expression = SymExpr::makeITE(
                    cond,
                    asRegisterValueExpr(taken.expression),
                    asRegisterValueExpr(fallthrough.expression));
                merged.uninitialized = merged_uninitialized;
                applyMergedMetadata(merged);
                return merged;
            }
            SymbolicExpressionResult merged = taken;
            merged.uninitialized = merged_uninitialized;
            applyMergedMetadata(merged);
            return merged;
        }
        case SymbolicExpressionResult::Type::COMPOSITE: {
            if (taken.pieces.size() != fallthrough.pieces.size()) {
                return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "symbolic bra composite size mismatch"};
            }
            SymbolicExpressionResult merged;
            merged.type = SymbolicExpressionResult::Type::COMPOSITE;
            merged.uninitialized = merged_uninitialized;
            applyMergedMetadata(merged);
            merged.pieces.reserve(taken.pieces.size());

            auto pieceAsValueExpr = [address_size, &regs](const SymPiece& p) -> SymExprPtr {
                switch (p.kind) {
                    case SymPiece::Kind::MEMORY:
                        if (!p.location) return nullptr;
                        {
                            uint64_t load_size = p.byte_size;
                            if (load_size == 0) {
                                if (p.bit_size != 0) {
                                    load_size = (p.bit_offset + p.bit_size + 7) / 8;
                                } else {
                                    load_size = address_size;
                                }
                            }
                            SymExprPtr v = SymExpr::makeLoad(p.location, load_size);
                            if (p.bit_size != 0) {
                                if (p.bit_offset != 0) {
                                    v = SymExpr::makeBinary(SymExpr::Kind::SHR, v,
                                                            SymExpr::makeConst(p.bit_offset));
                                }
                                if (p.bit_size < 64) {
                                    uint64_t mask = (1ULL << p.bit_size) - 1;
                                    v = SymExpr::makeBinary(SymExpr::Kind::AND, v,
                                                            SymExpr::makeConst(mask));
                                }
                            }
                            return v;
                        }
                    case SymPiece::Kind::REGISTER: {
                        if (!p.location) return nullptr;
                        auto regnum_opt = asConst(p.location);
                        if (!regnum_opt) return SymExpr::makeUnknown("reg?");
                        if (*regnum_opt < regs.size()) return SymExpr::makeConst(regs[*regnum_opt]);
                        return SymExpr::makeVar("reg" + std::to_string(*regnum_opt));
                    }
                    case SymPiece::Kind::IMPLICIT:
                        return p.location ? p.location : decodeAsValueExprPreserveBytes(p.implicit_bytes);
                    case SymPiece::Kind::EMPTY: {
                        if (p.bit_size != 0) {
                            return SymExpr::makeUnknown("unavail_bit_piece" + std::to_string(p.bit_size));
                        }
                        return SymExpr::makeUnknown("unavail_piece" + std::to_string(p.byte_size));
                    }
                }
                return nullptr;
            };

            for (size_t i = 0; i < taken.pieces.size(); ++i) {
                const auto& tp = taken.pieces[i];
                const auto& fp = fallthrough.pieces[i];

                if (tp.byte_size != fp.byte_size ||
                    tp.bit_size != fp.bit_size ||
                    tp.bit_offset != fp.bit_offset) {
                    return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "symbolic bra composite shape mismatch"};
                }

                SymPiece mp = tp;
                if (tp.kind == fp.kind) {
                    if (tp.kind == SymPiece::Kind::MEMORY) {
                        if (!tp.location || !fp.location) {
                            return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "symbolic bra composite missing location"};
                        }
                        if (symExprEquivalent(tp.location, fp.location)) {
                            mp.location = tp.location;
                        } else {
                            auto tv = pieceAsValueExpr(tp);
                            auto fv = pieceAsValueExpr(fp);
                            if (!tv || !fv) {
                                return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "symbolic bra composite kind mismatch"};
                            }
                            mp.kind = SymPiece::Kind::IMPLICIT;
                            mp.implicit_bytes.clear();
                            mp.location = SymExpr::makeITE(cond, tv, fv);
                        }
                    } else if (tp.kind == SymPiece::Kind::REGISTER) {
                        if (!tp.location || !fp.location) {
                            return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "symbolic bra composite missing location"};
                        }
                        if (symExprEquivalent(tp.location, fp.location)) {
                            mp.location = tp.location;
                        } else {
                            auto tv = pieceAsValueExpr(tp);
                            auto fv = pieceAsValueExpr(fp);
                            if (!tv || !fv) {
                                return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "symbolic bra composite kind mismatch"};
                            }
                            mp.kind = SymPiece::Kind::IMPLICIT;
                            mp.implicit_bytes.clear();
                            mp.location = SymExpr::makeITE(cond, tv, fv);
                        }
                    } else if (tp.kind == SymPiece::Kind::IMPLICIT) {
                        if (!tp.location && !fp.location && tp.implicit_bytes == fp.implicit_bytes) {
                            mp.implicit_bytes = tp.implicit_bytes;
                            mp.location.reset();
                        } else {
                            // Branch-dependent implicit bytes: lift to a symbolic value term.
                            auto tv = tp.location ? tp.location : decodeAsValueExprPreserveBytes(tp.implicit_bytes);
                            auto fv = fp.location ? fp.location : decodeAsValueExprPreserveBytes(fp.implicit_bytes);
                            if (!tv || !fv) {
                                return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "symbolic bra implicit piece missing value"};
                            }
                            mp.implicit_bytes.clear();
                            mp.location = symExprEquivalent(tv, fv) ? tv : SymExpr::makeITE(cond, tv, fv);
                        }
                    } else {
                        mp.location.reset();
                    }
                } else {
                    // Different piece location kinds: normalize to value semantics.
                    auto tv = pieceAsValueExpr(tp);
                    auto fv = pieceAsValueExpr(fp);
                    if (!tv || !fv) {
                        return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "symbolic bra composite kind mismatch"};
                    }
                    mp.kind = SymPiece::Kind::IMPLICIT;
                    mp.implicit_bytes.clear();
                    mp.location = symExprEquivalent(tv, fv) ? tv : SymExpr::makeITE(cond, tv, fv);
                }
                merged.pieces.push_back(std::move(mp));
            }
            return merged;
        }
        case SymbolicExpressionResult::Type::INVALID:
            return taken;
    }

    return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "symbolic bra unsupported result type"};
}

SymbolicExpressionResult SymbolicExpressionEvaluator::evaluate(const std::vector<uint8_t>& expr,
                                                              const EvaluationContext& ctx,
                                                              uint64_t pc,
                                                              const std::vector<uint64_t>& regs) {
    pc_ = pc;
    ctx_ = ctx;
    regs_ = regs;
    branch_depth_ = 0;

    stack_.clear();
    stack_kinds_.clear();
    stack_implicit_bytes_.clear();
    pieces_.clear();
    uninitialized_taint_ = false;
    setTopKind(SymStackValueKind::ADDRESS);

    auto result = evaluateFromOffset(expr, 0);
    result.uninitialized = result.uninitialized || uninitialized_taint_;
    appendDiagnosticContext(result);
    return result;
}

std::optional<SymbolicExpressionResult> SymbolicExpressionEvaluator::handleVendorProfileOpcode(
    uint8_t opcode,
    const std::vector<uint8_t>& expr,
    uint64_t& off) {
    if (ctx_.vendor_expression_profile != VendorExpressionProfile::SYNTHETIC_V1) {
        return std::nullopt;
    }

    switch (opcode) {
        case 0xf9:
            push(SymExpr::makeConst(readULEB(expr, off)), SymStackValueKind::VALUE);
            return SymbolicExpressionResult{SymbolicExpressionResult::Type::VALUE, nullptr, {}, ""};
        case 0xfd: {
            uint64_t uconst = readULEB(expr, off);
            if (hasDecodeError()) {
                return SymbolicExpressionResult{SymbolicExpressionResult::Type::INVALID,
                                                nullptr, {}, decodeErrorMessage()};
            }
            if (stack_.size() < 1) {
                return SymbolicExpressionResult{SymbolicExpressionResult::Type::INVALID,
                                                nullptr, {}, "stack underflow in vendor synthetic plus_uconst"};
            }
            auto kind = topKind();
            auto raw = pop();
            auto v = materializeForComputation(raw, kind);
            auto result_kind = (kind == SymStackValueKind::ADDRESS)
                                   ? SymStackValueKind::ADDRESS
                                   : SymStackValueKind::VALUE;
            push(SymExpr::makeBinary(SymExpr::Kind::ADD, v, SymExpr::makeConst(uconst)), result_kind);
            return SymbolicExpressionResult{SymbolicExpressionResult::Type::VALUE, nullptr, {}, ""};
        }
        case 0xfe: {
            if (off >= expr.size()) {
                return SymbolicExpressionResult{SymbolicExpressionResult::Type::INVALID,
                                                nullptr, {}, "truncated vendor synthetic deref_size"};
            }
            uint8_t size = static_cast<uint8_t>(readU8(expr, off));
            if (hasDecodeError()) {
                return SymbolicExpressionResult{SymbolicExpressionResult::Type::INVALID,
                                                nullptr, {}, decodeErrorMessage()};
            }
            if (stack_.size() < 1) {
                return SymbolicExpressionResult{SymbolicExpressionResult::Type::INVALID,
                                                nullptr, {}, "stack underflow in vendor synthetic deref_size"};
            }
            auto kind = topKind();
            auto addr = materializeForComputation(pop(), kind);
            push(SymExpr::makeLoad(addr, size), SymStackValueKind::VALUE);
            return SymbolicExpressionResult{SymbolicExpressionResult::Type::VALUE, nullptr, {}, ""};
        }
        default:
            return std::nullopt;
    }
}

SymbolicExpressionResult SymbolicExpressionEvaluator::evaluateFromOffset(const std::vector<uint8_t>& expr,
                                                                         uint64_t start_off) {
    DecodeStateScope decode_scope;
    uint64_t off = start_off;
    size_t steps = 0;
    const size_t max_steps = std::max<size_t>(1024, expr.size() * 16);

    while (off < expr.size()) {
        if (++steps > max_steps) {
            return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "step limit exceeded"};
        }
        uint64_t op_off = off;
        uint8_t opb = static_cast<uint8_t>(readU8(expr, off));
        DwarfOp op = static_cast<DwarfOp>(opb);
        auto stackUnderflow = [&](size_t need) -> SymbolicExpressionResult {
            return {SymbolicExpressionResult::Type::INVALID,
                    nullptr,
                    {},
                    "stack underflow at " + std::to_string(op_off) +
                        " need " + std::to_string(need) +
                        " have " + std::to_string(stack_.size())};
        };
        auto decodeFailure = [&]() -> SymbolicExpressionResult {
            return {SymbolicExpressionResult::Type::INVALID,
                    nullptr,
                    {},
                    decodeErrorMessage() + " at " + std::to_string(op_off)};
        };
        auto requireAddressSize = [&]() -> bool {
            if (ctx_.address_size == 4 || ctx_.address_size == 8) return true;
            return false;
        };
        auto normalizeComputationKind = [](SymStackValueKind kind, const SymExprPtr& expr) -> SymStackValueKind {
            if (kind == SymStackValueKind::REGISTER) return SymStackValueKind::VALUE;
            if (kind == SymStackValueKind::ADDRESS && isImmediateLike(expr)) return SymStackValueKind::VALUE;
            return kind;
        };

        // Literals.
        if (opb >= static_cast<uint8_t>(DwarfOp::DW_OP_lit0) &&
            opb <= static_cast<uint8_t>(DwarfOp::DW_OP_lit31)) {
            push(SymExpr::makeConst(opb - static_cast<uint8_t>(DwarfOp::DW_OP_lit0)),
                 SymStackValueKind::VALUE);
            continue;
        }

        // DW_OP_reg0..31 sets a register location.
        if (opb >= static_cast<uint8_t>(DwarfOp::DW_OP_reg0) &&
            opb <= static_cast<uint8_t>(DwarfOp::DW_OP_reg31)) {
            uint64_t reg = opb - static_cast<uint8_t>(DwarfOp::DW_OP_reg0);
            push(SymExpr::makeConst(reg));
            setTopKind(SymStackValueKind::REGISTER);
            continue;
        }

        // DW_OP_breg0..31: address = reg + sleb.
        if (opb >= static_cast<uint8_t>(DwarfOp::DW_OP_breg0) &&
            opb <= static_cast<uint8_t>(DwarfOp::DW_OP_breg31)) {
            uint64_t reg = opb - static_cast<uint8_t>(DwarfOp::DW_OP_breg0);
            int64_t disp = readSLEB(expr, off);
            if (hasDecodeError()) {
                return {SymbolicExpressionResult::Type::INVALID,
                        nullptr,
                        {},
                        decodeErrorMessage() + " at " + std::to_string(op_off)};
            }
            auto base = regValueExpr(reg);
            auto addr = SymExpr::makeBinary(SymExpr::Kind::ADD, base, SymExpr::makeConst(static_cast<uint64_t>(disp)));
            push(addr);
            setTopKind(SymStackValueKind::ADDRESS);
            continue;
        }

        switch (op) {
            case DwarfOp::DW_OP_skip: {
                int16_t rel = static_cast<int16_t>(readU16(expr, off));
                if (hasDecodeError()) {
                    return {SymbolicExpressionResult::Type::INVALID,
                            nullptr,
                            {},
                            decodeErrorMessage() + " at " + std::to_string(op_off)};
                }
                int64_t base = static_cast<int64_t>(off);
                int64_t next = base + static_cast<int64_t>(rel);
                if (next < 0 || static_cast<uint64_t>(next) > expr.size()) {
                    return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "skip out of range"};
                }
                off = static_cast<uint64_t>(next);
                break;
            }
            case DwarfOp::DW_OP_bra: {
                int16_t rel = static_cast<int16_t>(readU16(expr, off));
                if (hasDecodeError()) {
                    return {SymbolicExpressionResult::Type::INVALID,
                            nullptr,
                            {},
                            decodeErrorMessage() + " at " + std::to_string(op_off)};
                }
                if (stack_.empty()) return stackUnderflow(1);
                auto cond_kind = topKind();
                auto cond = materializeForComputation(pop(), cond_kind);
                auto c = asConst(cond);
                if (!c) {
                    constexpr int kMaxBranchDepth = 16;
                    if (branch_depth_ >= kMaxBranchDepth) {
                        return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "symbolic bra depth limit"};
                    }
                    int64_t base = static_cast<int64_t>(off);
                    int64_t next = base + static_cast<int64_t>(rel);
                    if (next < 0 || static_cast<uint64_t>(next) > expr.size()) {
                        return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "bra out of range"};
                    }
                    SymbolicExpressionEvaluator fall_eval = *this;
                    SymbolicExpressionEvaluator taken_eval = *this;
                    fall_eval.branch_depth_ = branch_depth_ + 1;
                    taken_eval.branch_depth_ = branch_depth_ + 1;
                    auto rf = fall_eval.evaluateFromOffset(expr, off);
                    auto rt = taken_eval.evaluateFromOffset(expr, static_cast<uint64_t>(next));
                    return mergeBranchResults(cond, rt, rf, ctx_.address_size, regs_);
                }
                if (*c != 0) {
                    int64_t base = static_cast<int64_t>(off);
                    int64_t next = base + static_cast<int64_t>(rel);
                    if (next < 0 || static_cast<uint64_t>(next) > expr.size()) {
                        return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "bra out of range"};
                    }
                    off = static_cast<uint64_t>(next);
                }
                break;
            }
            case DwarfOp::DW_OP_addr: {
                uint64_t a = readAddressSized(expr, off, ctx_.address_size);
                push(SymExpr::makeConst(a), SymStackValueKind::ADDRESS);
                break;
            }
            case DwarfOp::DW_OP_const1u: push(SymExpr::makeConst(readU8(expr, off)), SymStackValueKind::VALUE); break;
            case DwarfOp::DW_OP_const2u: push(SymExpr::makeConst(readU16(expr, off)), SymStackValueKind::VALUE); break;
            case DwarfOp::DW_OP_const4u: push(SymExpr::makeConst(readU32(expr, off)), SymStackValueKind::VALUE); break;
            case DwarfOp::DW_OP_const8u: push(SymExpr::makeConst(readU64(expr, off)), SymStackValueKind::VALUE); break;
            case DwarfOp::DW_OP_const1s: push(SymExpr::makeConst(static_cast<uint64_t>(static_cast<int8_t>(readU8(expr, off)))), SymStackValueKind::VALUE); break;
            case DwarfOp::DW_OP_const2s: push(SymExpr::makeConst(static_cast<uint64_t>(static_cast<int16_t>(readU16(expr, off)))), SymStackValueKind::VALUE); break;
            case DwarfOp::DW_OP_const4s: push(SymExpr::makeConst(static_cast<uint64_t>(static_cast<int32_t>(readU32(expr, off)))), SymStackValueKind::VALUE); break;
            case DwarfOp::DW_OP_const8s: push(SymExpr::makeConst(static_cast<uint64_t>(static_cast<int64_t>(readU64(expr, off)))), SymStackValueKind::VALUE); break;
            case DwarfOp::DW_OP_constu: push(SymExpr::makeConst(readULEB(expr, off)), SymStackValueKind::VALUE); break;
            case DwarfOp::DW_OP_consts: push(SymExpr::makeConst(static_cast<uint64_t>(readSLEB(expr, off))), SymStackValueKind::VALUE); break;

            case DwarfOp::DW_OP_dup: {
                if (stack_.empty()) return stackUnderflow(1);
                auto v = top();
                auto b = topImplicitBytes();
                auto k = topKind();
                if (b.has_value()) {
                    pushWithImplicitBytes(v, *b, k);
                } else {
                    push(v, k);
                }
                break;
            }
            case DwarfOp::DW_OP_drop:
                if (stack_.empty()) return stackUnderflow(1);
                (void)pop();
                break;
            case DwarfOp::DW_OP_over: {
                if (stack_.size() < 2) return stackUnderflow(2);
                auto idx = stack_.size() - 2;
                auto kind = (idx < stack_kinds_.size()) ? stack_kinds_[idx] : SymStackValueKind::ADDRESS;
                if (idx < stack_implicit_bytes_.size() && stack_implicit_bytes_[idx].has_value()) {
                    pushWithImplicitBytes(stack_[idx], *stack_implicit_bytes_[idx], kind);
                } else {
                    push(stack_[idx], kind);
                }
                break;
            }
            case DwarfOp::DW_OP_pick: {
                uint64_t idx = readU8(expr, off);
                if (hasDecodeError()) return decodeFailure();
                if (idx >= stack_.size()) {
                    return stackUnderflow(static_cast<size_t>(idx) + 1);
                } else {
                    auto src = stack_.size() - 1 - idx;
                    auto kind = (src < stack_kinds_.size()) ? stack_kinds_[src] : SymStackValueKind::ADDRESS;
                    if (src < stack_implicit_bytes_.size() && stack_implicit_bytes_[src].has_value()) {
                        pushWithImplicitBytes(stack_[src], *stack_implicit_bytes_[src], kind);
                    } else {
                        push(stack_[src], kind);
                    }
                }
                break;
            }
            case DwarfOp::DW_OP_swap: {
                if (stack_.size() < 2) return stackUnderflow(2);
                std::swap(stack_[stack_.size() - 1], stack_[stack_.size() - 2]);
                if (stack_kinds_.size() >= 2) {
                    std::swap(stack_kinds_[stack_kinds_.size() - 1],
                              stack_kinds_[stack_kinds_.size() - 2]);
                }
                if (stack_implicit_bytes_.size() >= 2) {
                    std::swap(stack_implicit_bytes_[stack_implicit_bytes_.size() - 1],
                              stack_implicit_bytes_[stack_implicit_bytes_.size() - 2]);
                }
                break;
            }
            case DwarfOp::DW_OP_rot: {
                if (stack_.size() < 3) return stackUnderflow(3);
                auto a = stack_[stack_.size() - 3];
                auto b = stack_[stack_.size() - 2];
                auto c = stack_[stack_.size() - 1];
                stack_[stack_.size() - 3] = b;
                stack_[stack_.size() - 2] = c;
                stack_[stack_.size() - 1] = a;
                if (stack_kinds_.size() >= 3) {
                    auto ka = stack_kinds_[stack_kinds_.size() - 3];
                    auto kb = stack_kinds_[stack_kinds_.size() - 2];
                    auto kc = stack_kinds_[stack_kinds_.size() - 1];
                    stack_kinds_[stack_kinds_.size() - 3] = kb;
                    stack_kinds_[stack_kinds_.size() - 2] = kc;
                    stack_kinds_[stack_kinds_.size() - 1] = ka;
                }
                if (stack_implicit_bytes_.size() >= 3) {
                    auto ia = stack_implicit_bytes_[stack_implicit_bytes_.size() - 3];
                    auto ib = stack_implicit_bytes_[stack_implicit_bytes_.size() - 2];
                    auto ic = stack_implicit_bytes_[stack_implicit_bytes_.size() - 1];
                    stack_implicit_bytes_[stack_implicit_bytes_.size() - 3] = ib;
                    stack_implicit_bytes_[stack_implicit_bytes_.size() - 2] = ic;
                    stack_implicit_bytes_[stack_implicit_bytes_.size() - 1] = ia;
                }
                break;
            }

            case DwarfOp::DW_OP_abs: {
                if (stack_.size() < 1) return stackUnderflow(1);
                auto k = topKind();
                auto a = materializeForComputation(pop(), k);
                push(SymExpr::makeUnary(SymExpr::Kind::ABS, a), SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_neg: {
                if (stack_.size() < 1) return stackUnderflow(1);
                auto k = topKind();
                auto a = materializeForComputation(pop(), k);
                push(SymExpr::makeUnary(SymExpr::Kind::NEG, a), SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_not: {
                if (stack_.size() < 1) return stackUnderflow(1);
                auto k = topKind();
                auto a = materializeForComputation(pop(), k);
                push(SymExpr::makeUnary(SymExpr::Kind::NOT, a), SymStackValueKind::VALUE);
                break;
            }

            case DwarfOp::DW_OP_plus: {
                if (stack_.size() < 2) return stackUnderflow(2);
                auto kb = topKind();
                auto b_raw = pop();
                auto ka = topKind();
                auto a_raw = pop();
                auto b = materializeForComputation(b_raw, kb);
                auto a = materializeForComputation(a_raw, ka);
                auto nka = normalizeComputationKind(ka, a_raw);
                auto nkb = normalizeComputationKind(kb, b_raw);
                SymStackValueKind rk = SymStackValueKind::VALUE;
                if ((nka == SymStackValueKind::ADDRESS && nkb == SymStackValueKind::VALUE) ||
                    (nka == SymStackValueKind::VALUE && nkb == SymStackValueKind::ADDRESS) ||
                    (nka == SymStackValueKind::ADDRESS && nkb == SymStackValueKind::ADDRESS)) {
                    rk = SymStackValueKind::ADDRESS;
                }
                push(SymExpr::makeBinary(SymExpr::Kind::ADD, a, b), rk);
                break;
            }
            case DwarfOp::DW_OP_minus: {
                if (stack_.size() < 2) return stackUnderflow(2);
                auto kb = topKind();
                auto b_raw = pop();
                auto ka = topKind();
                auto a_raw = pop();
                auto b = materializeForComputation(b_raw, kb);
                auto a = materializeForComputation(a_raw, ka);
                auto nka = normalizeComputationKind(ka, a_raw);
                auto nkb = normalizeComputationKind(kb, b_raw);
                SymStackValueKind rk =
                    (nka == SymStackValueKind::ADDRESS && nkb == SymStackValueKind::VALUE)
                        ? SymStackValueKind::ADDRESS
                        : SymStackValueKind::VALUE;
                push(SymExpr::makeBinary(SymExpr::Kind::SUB, a, b), rk);
                break;
            }
            case DwarfOp::DW_OP_mul: {
                if (stack_.size() < 2) return stackUnderflow(2);
                auto kb = topKind();
                auto b = materializeForComputation(pop(), kb);
                auto ka = topKind();
                auto a = materializeForComputation(pop(), ka);
                push(SymExpr::makeBinary(SymExpr::Kind::MUL, a, b), SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_div: {
                if (stack_.size() < 2) return stackUnderflow(2);
                auto kb = topKind();
                auto b = materializeForComputation(pop(), kb);
                auto ka = topKind();
                auto a = materializeForComputation(pop(), ka);
                push(SymExpr::makeBinary(SymExpr::Kind::DIV, a, b), SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_mod: {
                if (stack_.size() < 2) return stackUnderflow(2);
                auto kb = topKind();
                auto b = materializeForComputation(pop(), kb);
                auto ka = topKind();
                auto a = materializeForComputation(pop(), ka);
                push(SymExpr::makeBinary(SymExpr::Kind::MOD, a, b), SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_and: {
                if (stack_.size() < 2) return stackUnderflow(2);
                auto kb = topKind();
                auto b = materializeForComputation(pop(), kb);
                auto ka = topKind();
                auto a = materializeForComputation(pop(), ka);
                push(SymExpr::makeBinary(SymExpr::Kind::AND, a, b), SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_or: {
                if (stack_.size() < 2) return stackUnderflow(2);
                auto kb = topKind();
                auto b = materializeForComputation(pop(), kb);
                auto ka = topKind();
                auto a = materializeForComputation(pop(), ka);
                push(SymExpr::makeBinary(SymExpr::Kind::OR, a, b), SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_xor: {
                if (stack_.size() < 2) return stackUnderflow(2);
                auto kb = topKind();
                auto b = materializeForComputation(pop(), kb);
                auto ka = topKind();
                auto a = materializeForComputation(pop(), ka);
                push(SymExpr::makeBinary(SymExpr::Kind::XOR, a, b), SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_shl: {
                if (stack_.size() < 2) return stackUnderflow(2);
                auto kb = topKind();
                auto b = materializeForComputation(pop(), kb);
                auto ka = topKind();
                auto a = materializeForComputation(pop(), ka);
                push(SymExpr::makeBinary(SymExpr::Kind::SHL, a, b), SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_shr: {
                if (stack_.size() < 2) return stackUnderflow(2);
                auto kb = topKind();
                auto b = materializeForComputation(pop(), kb);
                auto ka = topKind();
                auto a = materializeForComputation(pop(), ka);
                push(SymExpr::makeBinary(SymExpr::Kind::SHR, a, b), SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_shra: {
                if (stack_.size() < 2) return stackUnderflow(2);
                auto kb = topKind();
                auto b = materializeForComputation(pop(), kb);
                auto ka = topKind();
                auto a = materializeForComputation(pop(), ka);
                push(SymExpr::makeBinary(SymExpr::Kind::SHRA, a, b), SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_plus_uconst: {
                uint64_t u = readULEB(expr, off);
                if (hasDecodeError()) return decodeFailure();
                if (stack_.size() < 1) return stackUnderflow(1);
                auto ka = topKind();
                auto a_raw = pop();
                auto a = materializeForComputation(a_raw, ka);
                auto nka = normalizeComputationKind(ka, a_raw);
                auto rk = (nka == SymStackValueKind::ADDRESS) ? SymStackValueKind::ADDRESS
                                                               : SymStackValueKind::VALUE;
                push(SymExpr::makeBinary(SymExpr::Kind::ADD, a, SymExpr::makeConst(u)), rk);
                break;
            }

            case DwarfOp::DW_OP_eq:
            case DwarfOp::DW_OP_ne:
            case DwarfOp::DW_OP_lt:
            case DwarfOp::DW_OP_le:
            case DwarfOp::DW_OP_gt:
            case DwarfOp::DW_OP_ge: {
                if (stack_.size() < 2) return stackUnderflow(2);
                auto kb = topKind();
                auto b = materializeForComputation(pop(), kb);
                auto ka = topKind();
                auto a = materializeForComputation(pop(), ka);
                SymExpr::Kind k = SymExpr::Kind::UNKNOWN;
                if (op == DwarfOp::DW_OP_eq) k = SymExpr::Kind::EQ;
                if (op == DwarfOp::DW_OP_ne) k = SymExpr::Kind::NE;
                if (op == DwarfOp::DW_OP_lt) k = SymExpr::Kind::LT;
                if (op == DwarfOp::DW_OP_le) k = SymExpr::Kind::LE;
                if (op == DwarfOp::DW_OP_gt) k = SymExpr::Kind::GT;
                if (op == DwarfOp::DW_OP_ge) k = SymExpr::Kind::GE;
                push(SymExpr::makeBinary(k, a, b), SymStackValueKind::VALUE);
                break;
            }

            case DwarfOp::DW_OP_deref: {
                if (stack_.size() < 1) return stackUnderflow(1);
                if (!requireAddressSize()) {
                    return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "invalid address_size"};
                }
                auto k = topKind();
                auto addr = materializeForComputation(pop(), k);
                push(SymExpr::makeLoad(addr, ctx_.address_size));
                setTopKind(SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_deref_size: {
                uint64_t sz = readU8(expr, off);
                if (hasDecodeError()) return decodeFailure();
                if (stack_.size() < 1) return stackUnderflow(1);
                auto k = topKind();
                auto addr = materializeForComputation(pop(), k);
                push(SymExpr::makeLoad(addr, sz));
                setTopKind(SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_xderef: {
                if (stack_.size() < 2) return stackUnderflow(2);
                if (!requireAddressSize()) {
                    return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "invalid address_size"};
                }
                auto k = topKind();
                auto addr = materializeForComputation(pop(), k);
                (void)pop(); // address space id (ignored in symbolic model)
                push(SymExpr::makeLoad(addr, ctx_.address_size));
                setTopKind(SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_xderef_size: {
                uint64_t sz = readU8(expr, off);
                if (hasDecodeError()) return decodeFailure();
                if (stack_.size() < 2) return stackUnderflow(2);
                auto k = topKind();
                auto addr = materializeForComputation(pop(), k);
                (void)pop(); // address space id (ignored in symbolic model)
                push(SymExpr::makeLoad(addr, sz));
                setTopKind(SymStackValueKind::VALUE);
                break;
            }

            case DwarfOp::DW_OP_const_type:
            case DwarfOp::DW_OP_GNU_const_type: {
                uint64_t type_offset = readULEB(expr, off);
                uint64_t abs_type_off = (type_offset == 0) ? 0 : (ctx_.cu_base_offset + type_offset);
                uint64_t sz = readU8(expr, off);
                if (hasDecodeError()) return decodeFailure();
                uint64_t avail = (off <= expr.size()) ? (expr.size() - off) : 0;
                if (sz > avail) {
                    return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "truncated const_type"};
                }
                std::vector<uint8_t> bytes = decodeBytes(expr, off, sz);
                SymExprPtr v = decodeAsValueExprPreserveBytes(bytes);
                if (type_offset != 0 && ctx_.resolve_base_type) {
                    auto ti = ctx_.resolve_base_type(abs_type_off);
                    if (ti && ti->byte_size > 0 && ti->byte_size <= 8) {
                        if (ti->is_integer) {
                            v = ti->is_signed ? SymExpr::makeSExt(v, ti->byte_size)
                                              : SymExpr::makeMask(v, ti->byte_size);
                        } else {
                            v = SymExpr::makeMask(v, ti->byte_size);
                        }
                    }
                }
                pushWithImplicitBytes(v, bytes, SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_regval_type:
            case DwarfOp::DW_OP_GNU_regval_type: {
                uint64_t reg = readULEB(expr, off);
                uint64_t type_offset = readULEB(expr, off);
                if (hasDecodeError()) return decodeFailure();
                uint64_t abs_type_off = (type_offset == 0) ? 0 : (ctx_.cu_base_offset + type_offset);
                auto v = regValueExpr(reg);
                if (type_offset != 0 && ctx_.resolve_base_type) {
                    auto ti = ctx_.resolve_base_type(abs_type_off);
                    if (ti && ti->byte_size > 0 && ti->byte_size <= 8) {
                        if (ti->is_integer) {
                            v = ti->is_signed ? SymExpr::makeSExt(v, ti->byte_size)
                                              : SymExpr::makeMask(v, ti->byte_size);
                        } else {
                            v = SymExpr::makeMask(v, ti->byte_size);
                        }
                    }
                }
                push(v);
                setTopKind(SymStackValueKind::VALUE);
                break;
            }

            case DwarfOp::DW_OP_deref_type:
            case DwarfOp::DW_OP_GNU_deref_type: {
                uint64_t sz = readU8(expr, off);
                uint64_t type_offset = readULEB(expr, off);
                if (hasDecodeError()) return decodeFailure();
                uint64_t abs_type_off = (type_offset == 0) ? 0 : (ctx_.cu_base_offset + type_offset);
                if (stack_.size() < 1) return stackUnderflow(1);
                auto k = topKind();
                auto addr = materializeForComputation(pop(), k);
                SymExprPtr v = SymExpr::makeLoad(addr, sz);
                if (type_offset != 0 && ctx_.resolve_base_type) {
                    auto ti = ctx_.resolve_base_type(abs_type_off);
                    if (ti && ti->byte_size > 0 && ti->byte_size <= 8) {
                        if (ti->is_integer) {
                            v = ti->is_signed ? SymExpr::makeSExt(v, ti->byte_size)
                                              : SymExpr::makeMask(v, ti->byte_size);
                        } else {
                            v = SymExpr::makeMask(v, ti->byte_size);
                        }
                    }
                }
                push(v);
                setTopKind(SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_xderef_type: {
                uint64_t sz = readU8(expr, off);
                uint64_t type_offset = readULEB(expr, off);
                if (hasDecodeError()) return decodeFailure();
                uint64_t abs_type_off = (type_offset == 0) ? 0 : (ctx_.cu_base_offset + type_offset);
                if (stack_.size() < 2) return stackUnderflow(2);
                auto k = topKind();
                auto addr = materializeForComputation(pop(), k);
                (void)pop(); // address space id
                SymExprPtr v = SymExpr::makeLoad(addr, sz);
                if (type_offset != 0 && ctx_.resolve_base_type) {
                    auto ti = ctx_.resolve_base_type(abs_type_off);
                    if (ti && ti->byte_size > 0 && ti->byte_size <= 8) {
                        if (ti->is_integer) {
                            v = ti->is_signed ? SymExpr::makeSExt(v, ti->byte_size)
                                              : SymExpr::makeMask(v, ti->byte_size);
                        } else {
                            v = SymExpr::makeMask(v, ti->byte_size);
                        }
                    }
                }
                push(v);
                setTopKind(SymStackValueKind::VALUE);
                break;
            }

            case DwarfOp::DW_OP_convert:
            case DwarfOp::DW_OP_GNU_convert: {
                uint64_t type_offset = readULEB(expr, off);
                if (hasDecodeError()) return decodeFailure();
                uint64_t abs_type_off = (type_offset == 0) ? 0 : (ctx_.cu_base_offset + type_offset);
                if (stack_.size() < 1) return stackUnderflow(1);
                auto k = topKind();
                auto v = materializeForComputation(pop(), k);
                if (type_offset != 0 && ctx_.resolve_base_type) {
                    auto ti = ctx_.resolve_base_type(abs_type_off);
                    if (ti && ti->byte_size > 0 && ti->byte_size <= 8) {
                        if (ti->is_integer) {
                            v = ti->is_signed ? SymExpr::makeSExt(v, ti->byte_size)
                                              : SymExpr::makeMask(v, ti->byte_size);
                        } else {
                            v = SymExpr::makeMask(v, ti->byte_size);
                        }
                    }
                }
                push(v);
                setTopKind(SymStackValueKind::VALUE);
                break;
            }

            case DwarfOp::DW_OP_reinterpret:
            case DwarfOp::DW_OP_GNU_reinterpret: {
                uint64_t type_offset = readULEB(expr, off);
                if (hasDecodeError()) return decodeFailure();
                uint64_t abs_type_off = (type_offset == 0) ? 0 : (ctx_.cu_base_offset + type_offset);
                if (stack_.size() < 1) return stackUnderflow(1);
                auto k = topKind();
                auto v = materializeForComputation(pop(), k);
                if (type_offset != 0 && ctx_.resolve_base_type) {
                    auto ti = ctx_.resolve_base_type(abs_type_off);
                    if (ti && ti->byte_size > 0 && ti->byte_size <= 8) {
                        v = SymExpr::makeMask(v, ti->byte_size);
                    }
                }
                push(v);
                setTopKind(SymStackValueKind::VALUE);
                break;
            }

            case DwarfOp::DW_OP_implicit_pointer:
            case DwarfOp::DW_OP_GNU_implicit_pointer: {
                // (die_ref, sleb offset) -> pointer based on referenced DIE location plus offset.
                uint64_t die_ref = readOffsetSized(expr, off, ctx_.offset_size);
                int64_t disp = readSLEB(expr, off);
                if (hasDecodeError()) return decodeFailure();
                uint64_t abs_die_ref = dwarfSectionOffsetBias(ctx_.cu_base_offset) + die_ref;

                SymExprPtr base_ptr = SymExpr::makeConst(abs_die_ref);
                if (ctx_.resolve_dwarf_procedure) {
                    auto sub = ctx_.resolve_dwarf_procedure(abs_die_ref, pc_);
                    if (sub) {
                        constexpr int kMaxDepth = 8;
                        if (call_depth_ >= kMaxDepth) {
                            return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "implicit_pointer depth limit"};
                        }
                        SymbolicExpressionEvaluator sub_eval;
                        sub_eval.call_depth_ = call_depth_ + 1;
                        sub_eval.branch_depth_ = branch_depth_;
                        auto sr = sub_eval.evaluate(*sub, ctx_, pc_, regs_);
                        uninitialized_taint_ = uninitialized_taint_ || sr.uninitialized;
                        if ((sr.type == SymbolicExpressionResult::Type::ADDRESS ||
                             sr.type == SymbolicExpressionResult::Type::VALUE) &&
                            sr.expression) {
                            base_ptr = sr.expression;
                        } else if (sr.type == SymbolicExpressionResult::Type::REGISTER &&
                                   sr.expression) {
                            auto regnum_opt = asConst(sr.expression);
                            base_ptr = regnum_opt ? regValueExpr(*regnum_opt)
                                                  : SymExpr::makeUnknown("implicit_pointer(reg?)");
                        } else {
                            base_ptr = SymExpr::makeUnknown("implicit_pointer(unsupported)");
                        }
                    } else {
                        base_ptr = SymExpr::makeUnknown("implicit_pointer(no_proc)");
                    }
                } else {
                    base_ptr = SymExpr::makeUnknown("implicit_pointer(no_resolver)");
                }

                push(SymExpr::makeBinary(SymExpr::Kind::ADD, base_ptr,
                                         SymExpr::makeConst(static_cast<uint64_t>(disp))));
                setTopKind(SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_call2: {
                uint64_t die_offset = readU16(expr, off);
                if (hasDecodeError()) return decodeFailure();
                if (!ctx_.resolve_dwarf_procedure) {
                    break;
                }
                uint64_t abs_off = ctx_.cu_base_offset + die_offset;
                auto sub = ctx_.resolve_dwarf_procedure(abs_off, pc_);
                if (!sub) {
                    break;
                }
                constexpr int kMaxDepth = 8;
                if (call_depth_ >= kMaxDepth) {
                    return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "call depth limit"};
                }
                ++call_depth_;
                bool ok = executeProcedureSubexprInPlace(*sub);
                --call_depth_;
                if (!ok) {
                    return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "DW_OP_call2 subexpression failed"};
                }
                break;
            }
            case DwarfOp::DW_OP_call4: {
                uint64_t die_offset = readU32(expr, off);
                if (hasDecodeError()) return decodeFailure();
                if (!ctx_.resolve_dwarf_procedure) {
                    break;
                }
                uint64_t abs_off = ctx_.cu_base_offset + die_offset;
                auto sub = ctx_.resolve_dwarf_procedure(abs_off, pc_);
                if (!sub) {
                    break;
                }
                constexpr int kMaxDepth = 8;
                if (call_depth_ >= kMaxDepth) {
                    return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "call depth limit"};
                }
                ++call_depth_;
                bool ok = executeProcedureSubexprInPlace(*sub);
                --call_depth_;
                if (!ok) {
                    return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "DW_OP_call4 subexpression failed"};
                }
                break;
            }
            case DwarfOp::DW_OP_call_ref: {
                uint64_t die_offset = readOffsetSized(expr, off, ctx_.offset_size);
                if (hasDecodeError()) return decodeFailure();
                if (!ctx_.resolve_dwarf_procedure) {
                    break;
                }
                uint64_t abs_off = dwarfSectionOffsetBias(ctx_.cu_base_offset) + die_offset;
                auto sub = ctx_.resolve_dwarf_procedure(abs_off, pc_);
                if (!sub) {
                    break;
                }
                constexpr int kMaxDepth = 8;
                if (call_depth_ >= kMaxDepth) {
                    return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "call depth limit"};
                }
                ++call_depth_;
                bool ok = executeProcedureSubexprInPlace(*sub);
                --call_depth_;
                if (!ok) {
                    return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "DW_OP_call_ref subexpression failed"};
                }
                break;
            }

            case DwarfOp::DW_OP_regx: {
                uint64_t reg = readULEB(expr, off);
                if (hasDecodeError()) return decodeFailure();
                push(SymExpr::makeConst(reg));
                setTopKind(SymStackValueKind::REGISTER);
                break;
            }
            case DwarfOp::DW_OP_bregx: {
                uint64_t reg = readULEB(expr, off);
                int64_t disp = readSLEB(expr, off);
                if (hasDecodeError()) return decodeFailure();
                auto addr = SymExpr::makeBinary(SymExpr::Kind::ADD, regValueExpr(reg),
                                                SymExpr::makeConst(static_cast<uint64_t>(disp)));
                push(addr);
                setTopKind(SymStackValueKind::ADDRESS);
                break;
            }
            case DwarfOp::DW_OP_fbreg: {
                int64_t disp = readSLEB(expr, off);
                if (hasDecodeError()) return decodeFailure();
                auto addr = SymExpr::makeBinary(SymExpr::Kind::ADD, frameBaseExpr(),
                                                SymExpr::makeConst(static_cast<uint64_t>(disp)));
                push(addr);
                setTopKind(SymStackValueKind::ADDRESS);
                break;
            }
            case DwarfOp::DW_OP_call_frame_cfa: {
                push(cfaExpr());
                setTopKind(SymStackValueKind::ADDRESS);
                break;
            }
            case DwarfOp::DW_OP_push_object_address: {
                push(objectAddrExpr(), SymStackValueKind::ADDRESS);
                break;
            }
            case DwarfOp::DW_OP_form_tls_address:
            case DwarfOp::DW_OP_GNU_push_tls_address: {
                if (stack_.size() < 1) return stackUnderflow(1);
                auto k = topKind();
                auto a = materializeForComputation(pop(), k);
                push(SymExpr::makeBinary(SymExpr::Kind::ADD, tlsBaseExpr(), a));
                break;
            }
            case DwarfOp::DW_OP_GNU_uninit: {
                uninitialized_taint_ = true;
                break;
            }
            case DwarfOp::DW_OP_GNU_encoded_addr: {
                uint64_t avail = (off <= expr.size()) ? (expr.size() - off) : 0;
                if (avail < 1) {
                    return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "truncated gnu_encoded_addr"};
                }

                uint8_t encoding = static_cast<uint8_t>(readU8(expr, off));
                constexpr uint8_t kFmtMask = 0x0f;
                constexpr uint8_t kAppMask = 0x70;
                constexpr uint8_t kIndMask = 0x80;
                uint8_t fmt = static_cast<uint8_t>(encoding & kFmtMask);

                if ((encoding & kAppMask) == 0x50) {
                    if (!requireAddressSize()) {
                        return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "invalid address_size"};
                    }
                    off = alignOffsetUp(off, ctx_.address_size);
                }

                SymExprPtr raw;
                switch (fmt) {
                    case 0x00: // absptr
                        raw = SymExpr::makeConst(readAddressSized(expr, off, ctx_.address_size));
                        break;
                    case 0x01: // uleb128
                        raw = SymExpr::makeConst(readULEB(expr, off));
                        break;
                    case 0x02: // udata2
                        raw = SymExpr::makeConst(readU16(expr, off));
                        break;
                    case 0x03: // udata4
                        raw = SymExpr::makeConst(readU32(expr, off));
                        break;
                    case 0x04: // udata8
                        raw = SymExpr::makeConst(readU64(expr, off));
                        break;
                    case 0x09: // sleb128
                        raw = SymExpr::makeConst(static_cast<uint64_t>(readSLEB(expr, off)));
                        break;
                    case 0x0a: { // sdata2
                        int16_t v = static_cast<int16_t>(readU16(expr, off));
                        raw = SymExpr::makeConst(static_cast<uint64_t>(static_cast<int64_t>(v)));
                        break;
                    }
                    case 0x0b: { // sdata4
                        int32_t v = static_cast<int32_t>(readU32(expr, off));
                        raw = SymExpr::makeConst(static_cast<uint64_t>(static_cast<int64_t>(v)));
                        break;
                    }
                    case 0x0c: { // sdata8
                        int64_t v = static_cast<int64_t>(readU64(expr, off));
                        raw = SymExpr::makeConst(static_cast<uint64_t>(v));
                        break;
                    }
                    default:
                        return {SymbolicExpressionResult::Type::INVALID, nullptr, {},
                                "DW_OP_GNU_encoded_addr unsupported encoding format"};
                }

                SymExprPtr addr = raw;
                bool is_value = false;
                switch (encoding & kAppMask) {
                    case 0x00: // absolute
                        break;
                    case 0x10: // pcrel
                        addr = SymExpr::makeBinary(SymExpr::Kind::ADD, SymExpr::makeConst(pc_), raw);
                        break;
                    case 0x20: // textrel
                        addr = SymExpr::makeBinary(SymExpr::Kind::ADD, SymExpr::makeConst(ctx_.text_base), raw);
                        break;
                    case 0x30: // datarel
                        addr = SymExpr::makeBinary(SymExpr::Kind::ADD, SymExpr::makeConst(ctx_.data_base), raw);
                        break;
                    case 0x40: // funcrel
                        addr = SymExpr::makeBinary(SymExpr::Kind::ADD, SymExpr::makeConst(ctx_.function_base), raw);
                        break;
                    case 0x50: // aligned
                        break;
                    default:
                        return {SymbolicExpressionResult::Type::INVALID, nullptr, {},
                                "DW_OP_GNU_encoded_addr unsupported application mode"};
                }

                if ((encoding & kIndMask) != 0) {
                    if (!requireAddressSize()) {
                        return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "invalid address_size"};
                    }
                    addr = SymExpr::makeLoad(addr, ctx_.address_size);
                    is_value = true;
                }

                push(addr, is_value ? SymStackValueKind::VALUE : SymStackValueKind::ADDRESS);
                break;
            }
            case DwarfOp::DW_OP_GNU_parameter_ref: {
                uint64_t die_offset = readOffsetSized(expr, off, ctx_.offset_size);
                if (hasDecodeError()) return decodeFailure();
                uint64_t abs_off = dwarfSectionOffsetBias(ctx_.cu_base_offset) + die_offset;

                if (!ctx_.resolve_dwarf_procedure) {
                    push(SymExpr::makeUnknown("gnu_parameter_ref(no_resolver)"));
                    setTopKind(SymStackValueKind::VALUE);
                    break;
                }

                auto sub = ctx_.resolve_dwarf_procedure(abs_off, pc_);
                if (!sub) {
                    push(SymExpr::makeUnknown("gnu_parameter_ref(no_proc)"));
                    setTopKind(SymStackValueKind::VALUE);
                    break;
                }

                constexpr int kMaxDepth = 8;
                if (call_depth_ >= kMaxDepth) {
                    return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "gnu_parameter_ref depth limit"};
                }

                SymbolicExpressionEvaluator sub_eval;
                sub_eval.call_depth_ = call_depth_ + 1;
                sub_eval.branch_depth_ = branch_depth_;
                SymbolicExpressionResult sr = sub_eval.evaluate(*sub, ctx_, pc_, regs_);
                uninitialized_taint_ = uninitialized_taint_ || sr.uninitialized;
                auto materialized = materializeResultAsValue(sr, regs_, "gnu_parameter_ref");
                if (materialized.type == SymbolicExpressionResult::Type::INVALID) {
                    return materialized;
                }
                push(materialized.expression ? materialized.expression
                                             : SymExpr::makeUnknown("gnu_parameter_ref(empty)"));
                setTopKind(SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_WASM_location: {
                if (off >= expr.size()) return decodeFailure();
                uint8_t kind = static_cast<uint8_t>(readU8(expr, off));
                if (hasDecodeError()) return decodeFailure();

                uint64_t index = 0;
                if (kind <= 0x02) {
                    index = readULEB(expr, off);
                    if (hasDecodeError()) return decodeFailure();
                }

                uint64_t encoded = (static_cast<uint64_t>(kind) << 56) |
                                   (index & 0x00ffffffffffffffULL);
                push(SymExpr::makeConst(encoded), SymStackValueKind::REGISTER);
                break;
            }
            case DwarfOp::DW_OP_addrx:
            case DwarfOp::DW_OP_constx:
            case DwarfOp::DW_OP_GNU_addr_index:
            case DwarfOp::DW_OP_GNU_const_index: {
                uint64_t idx = readULEB(expr, off);
                if (hasDecodeError()) return decodeFailure();
                bool is_addr = (op == DwarfOp::DW_OP_addrx || op == DwarfOp::DW_OP_GNU_addr_index);
                if (ctx_.debug_addr_table && idx < ctx_.debug_addr_table->size()) {
                    push(SymExpr::makeConst((*ctx_.debug_addr_table)[idx]));
                } else {
                    std::string n = is_addr ? "addrx(" : "constx(";
                    n += std::to_string(idx);
                    n += ")";
                    push(SymExpr::makeUnknown(n));
                }
                setTopKind(is_addr ? SymStackValueKind::ADDRESS : SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_entry_value:
            case DwarfOp::DW_OP_GNU_entry_value: {
                constexpr int kMaxDepth = 8;
                if (call_depth_ >= kMaxDepth) {
                    return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "entry_value depth limit"};
                }
                uint64_t len = readULEB(expr, off);
                if (hasDecodeError()) return decodeFailure();
                uint64_t avail = (off <= expr.size()) ? (expr.size() - off) : 0;
                if (len > avail) {
                    return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "truncated entry_value"};
                }
                std::vector<uint8_t> sub(expr.begin() + static_cast<int64_t>(off),
                                         expr.begin() + static_cast<int64_t>(off + len));
                off += len;
                ++call_depth_;
                SymbolicExpressionResult sr = evalEntryValueSubexpr(sub);
                --call_depth_;
                if (sr.type == SymbolicExpressionResult::Type::INVALID) {
                    return sr;
                }
                // entry_value pushes a value (not a location).
                push(sr.expression ? sr.expression : SymExpr::makeUnknown("entry_value"));
                setTopKind(SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_stack_value: {
                if (stack_.empty()) return stackUnderflow(1);
                if (topKind() == SymStackValueKind::REGISTER) {
                    auto reg_loc = top();
                    auto regnum_opt = asConst(reg_loc);
                    SymExprPtr v = regnum_opt ? regValueExpr(*regnum_opt)
                                              : SymExpr::makeUnknown("stack_value(reg?)");
                    (void)pop();
                    push(v, SymStackValueKind::VALUE);
                } else {
                    setTopKind(SymStackValueKind::VALUE);
                }
                break;
            }
            case DwarfOp::DW_OP_implicit_value: {
                uint64_t len = readULEB(expr, off);
                if (hasDecodeError()) return decodeFailure();
                std::vector<uint8_t> bytes = decodeBytes(expr, off, len);
                pushWithImplicitBytes(decodeAsValueExprPreserveBytes(bytes), bytes);
                setTopKind(SymStackValueKind::VALUE);
                break;
            }
            case DwarfOp::DW_OP_piece: {
                uint64_t bytes = readULEB(expr, off);
                if (hasDecodeError()) return decodeFailure();
                SymPiece p;
                p.byte_size = bytes;
                if (stack_.empty()) {
                    // DW_OP_piece with no preceding location encodes an unavailable piece.
                    p.kind = SymPiece::Kind::EMPTY;
                } else {
                    auto implicit_bytes = topImplicitBytes();
                    auto kind = topKind();
                    if (implicit_bytes.has_value()) {
                        p.kind = SymPiece::Kind::IMPLICIT;
                        p.implicit_bytes = *implicit_bytes;
                        (void)pop();
                    } else if (kind == SymStackValueKind::REGISTER) {
                        p.kind = SymPiece::Kind::REGISTER;
                        p.location = pop();
                    } else if (kind == SymStackValueKind::VALUE) {
                        p.kind = SymPiece::Kind::IMPLICIT;
                        p.location = pop();
                    } else {
                        p.kind = SymPiece::Kind::MEMORY;
                        p.location = pop();
                    }
                }
                pieces_.push_back(std::move(p));
                break;
            }
            case DwarfOp::DW_OP_bit_piece: {
                uint64_t bit_size = readULEB(expr, off);
                uint64_t bit_off = readULEB(expr, off);
                if (hasDecodeError()) return decodeFailure();
                SymPiece p;
                p.bit_size = bit_size;
                p.bit_offset = bit_off;
                if (stack_.empty()) {
                    // DW_OP_bit_piece with no preceding location encodes an unavailable piece.
                    p.kind = SymPiece::Kind::EMPTY;
                } else {
                    auto implicit_bytes = topImplicitBytes();
                    auto kind = topKind();
                    if (implicit_bytes.has_value()) {
                        p.kind = SymPiece::Kind::IMPLICIT;
                        p.implicit_bytes = *implicit_bytes;
                        (void)pop();
                    } else if (kind == SymStackValueKind::REGISTER) {
                        p.kind = SymPiece::Kind::REGISTER;
                        p.location = pop();
                    } else if (kind == SymStackValueKind::VALUE) {
                        p.kind = SymPiece::Kind::IMPLICIT;
                        p.location = pop();
                    } else {
                        p.kind = SymPiece::Kind::MEMORY;
                        p.location = pop();
                    }
                }
                pieces_.push_back(std::move(p));
                break;
            }

            case DwarfOp::DW_OP_nop:
                break;

            default:
                {
                    if (auto handled = handleVendorProfileOpcode(static_cast<uint8_t>(op), expr, off)) {
                        if (handled->type == SymbolicExpressionResult::Type::INVALID) {
                            handled->uninitialized = handled->uninitialized || uninitialized_taint_;
                            return *handled;
                        }
                        break;
                    }
                    SymbolicExpressionResult r;
                    r.type = SymbolicExpressionResult::Type::INVALID;
                    r.error = unsupportedOpMessage(static_cast<uint8_t>(op), op_off);
                    if (const char* profile_name = vendorProfileOpcodeName(ctx_.vendor_expression_profile,
                                                                           static_cast<uint8_t>(op))) {
                        std::ostringstream oss;
                        oss << "unsupported op " << profile_name
                            << " (opcode 0x" << std::hex << static_cast<unsigned>(static_cast<uint8_t>(op))
                            << std::dec << ") at " << op_off;
                        r.error = oss.str();
                    }
                    r.unsupported_opcode = static_cast<uint8_t>(op);
                    r.unsupported_vendor_extension = static_cast<uint8_t>(op) >= 0xe0;
                    r.uninitialized = uninitialized_taint_;
                    return r;
                }
        }

        if (hasDecodeError()) {
            return {SymbolicExpressionResult::Type::INVALID,
                    nullptr,
                    {},
                    decodeErrorMessage() + " at " + std::to_string(op_off)};
        }
    }

    if (!pieces_.empty()) {
        SymbolicExpressionResult r;
        r.type = SymbolicExpressionResult::Type::COMPOSITE;
        r.pieces = std::move(pieces_);
        r.uninitialized = uninitialized_taint_;
        return r;
    }

    if (stack_.empty()) {
        return {SymbolicExpressionResult::Type::INVALID, nullptr, {}, "empty stack"};
    }

    SymbolicExpressionResult r;
    r.expression = top();
    switch (topKind()) {
        case SymStackValueKind::REGISTER:
            r.type = SymbolicExpressionResult::Type::REGISTER;
            break;
        case SymStackValueKind::VALUE:
            r.type = SymbolicExpressionResult::Type::VALUE;
            break;
        case SymStackValueKind::ADDRESS:
            r.type = SymbolicExpressionResult::Type::ADDRESS;
            break;
    }
    r.uninitialized = uninitialized_taint_;
    return r;
}

SymbolicExpressionResult SymbolicExpressionEvaluator::evalEntryValueSubexpr(const std::vector<uint8_t>& subexpr) {
    // Evaluate the subexpression using entry_registers as the register file when present.
    // This mirrors the intent of DW_OP_entry_value: refer to call-site values.
    SymbolicExpressionEvaluator sub;
    sub.call_depth_ = call_depth_;
    sub.branch_depth_ = branch_depth_;
    EvaluationContext ctx = ctx_;
    std::vector<uint64_t> regs = ctx_.entry_registers.empty() ? regs_ : ctx_.entry_registers;
    auto r = sub.evaluate(subexpr, ctx, pc_, regs);
    return materializeResultAsValue(r, ctx_.entry_registers, "entry_value");
}

SymbolicExpressionResult SymbolicExpressionEvaluator::materializeResultAsValue(
    const SymbolicExpressionResult& result,
    const std::vector<uint64_t>& register_bank,
    const char* op_name) const {
    SymbolicExpressionResult out;
    out.type = SymbolicExpressionResult::Type::VALUE;
    out.uninitialized = result.uninitialized;
    out.unsupported_opcode = result.unsupported_opcode;
    out.unsupported_vendor_extension = result.unsupported_vendor_extension;

    switch (result.type) {
        case SymbolicExpressionResult::Type::VALUE:
            out.expression = result.expression ? result.expression
                                               : SymExpr::makeUnknown(std::string(op_name) + "(empty)");
            return out;
        case SymbolicExpressionResult::Type::REGISTER: {
            if (!result.expression) {
                return {SymbolicExpressionResult::Type::INVALID, nullptr, {},
                        std::string(op_name) + " register missing", result.uninitialized,
                        result.unsupported_opcode, result.unsupported_vendor_extension};
            }
            auto regnum_opt = asConst(result.expression);
            if (!regnum_opt) {
                return {SymbolicExpressionResult::Type::INVALID, nullptr, {},
                        std::string(op_name) + " non-const regnum", result.uninitialized,
                        result.unsupported_opcode, result.unsupported_vendor_extension};
            }
            if (!register_bank.empty() && *regnum_opt < register_bank.size()) {
                out.expression = SymExpr::makeConst(register_bank[*regnum_opt]);
            } else if (std::string(op_name) == "entry_value") {
                out.expression = SymExpr::makeVar("entry_reg" + std::to_string(*regnum_opt));
            } else {
                out.expression = SymExpr::makeVar("reg" + std::to_string(*regnum_opt));
            }
            return out;
        }
        case SymbolicExpressionResult::Type::ADDRESS:
            if (ctx_.address_size != 4 && ctx_.address_size != 8) {
                return {SymbolicExpressionResult::Type::INVALID, nullptr, {},
                        std::string(op_name) + " invalid address_size", result.uninitialized,
                        result.unsupported_opcode, result.unsupported_vendor_extension};
            }
            out.expression = SymExpr::makeLoad(result.expression ? result.expression
                                                                 : SymExpr::makeUnknown(std::string(op_name) + "_addr"),
                                               ctx_.address_size);
            return out;
        default:
            return {SymbolicExpressionResult::Type::INVALID, nullptr, {},
                    std::string(op_name) + " unsupported result", result.uninitialized,
                    result.unsupported_opcode, result.unsupported_vendor_extension};
    }
}

bool SymbolicExpressionEvaluator::executeProcedureSubexprInPlace(const std::vector<uint8_t>& subexpr) {
    SymbolicExpressionEvaluator sub = *this;
    auto r = sub.evaluateFromOffset(subexpr, 0);
    if (r.type == SymbolicExpressionResult::Type::INVALID && r.error != "empty stack") {
        return false;
    }

    stack_ = std::move(sub.stack_);
    stack_kinds_ = std::move(sub.stack_kinds_);
    stack_implicit_bytes_ = std::move(sub.stack_implicit_bytes_);
    if (r.type == SymbolicExpressionResult::Type::COMPOSITE) {
        pieces_ = std::move(r.pieces);
    } else {
        pieces_ = std::move(sub.pieces_);
    }
    uninitialized_taint_ = sub.uninitialized_taint_;
    return true;
}

} // namespace dwarf
