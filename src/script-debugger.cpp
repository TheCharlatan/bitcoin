// script_debugger.cpp
//
// A standalone, interactive, post-mortem Bitcoin Script debugger built on
// libbitcoinkernel's ENABLE_SCRIPT_TRACE hooks.
//
// It runs VerifyScript() once (via btck::ScriptPubkey::Verify), captures
// every BEGIN/STEP/END trace frame the interpreter emits, and then gives
// you a gdb-style command line to walk forward/backward through that
// captured execution. At every stop it renders a boxed dashboard: a
// status header with a progress bar, a windowed script disassembly with
// the current instruction highlighted and upcoming opcodes visible, and
// stack/altstack panels with hex + ASCII previews and the top-of-stack
// item called out. Stepping/playback redraws in place (movie-style)
// rather than scrolling, and the debugger recognizes a handful of common
// consensus-level script templates (P2PKH, P2PK, single-key tapscript
// leaves, bare multisig) so you don't have to eyeball opcode shapes by
// hand.
//
// Byte-type convention used throughout this file:
//   - "Domain A" (scripts/transactions we BUILD and feed INTO the kernel,
//     e.g. via btck::ScriptPubkey / btck::Transaction constructors) uses
//     std::byte, because that's what bitcoinkernel_wrapper.h's
//     constructors require (std::span<const std::byte>).
//   - "Domain B" (data we READ BACK from captured ScriptTraceFrame objects,
//     e.g. stack items, the executed script bytes, opcode values) stays as
//     `unsigned char`, because that's what btck::ScriptTraceFrame actually
//     holds (it mirrors the underlying C struct's unsigned char* fields).
//
// Two ways to feed it a script to debug:
//
//   1) Full-transaction mode: give it a real spending transaction, an
//      input index, and the scriptPubkey/amount being spent.
//   2) Quick mode: give it just a scriptSig (and/or witness items) and a
//      scriptPubkey; the debugger synthesizes a minimal wrapping
//      transaction around them so you don't need a real one. Scripts can
//      be given as hex or as simple mnemonic assembly.
//
// Requirements:
//   - libbitcoinkernel built with -DENABLE_SCRIPT_TRACE=ON
//   - Linux (uses termios directly for interactive line editing, and
//     ioctl(TIOCGWINSZ) to size the dashboard to the terminal)
//   - No dependencies beyond libstdc++ / libc and libbitcoinkernel
//
// Build (adjust paths to your build tree):
//
//   g++ -std=c++23 -O2 -o script_debugger script_debugger.cpp \
//       -I<bitcoin-src>/src \
//       -L<bitcoin-build>/lib -lbitcoinkernel \
//       -Wl,-rpath,<bitcoin-build>/lib
//
// Examples:
//
//   Full-tx mode:
//     ./script_debugger --tx <hex> --index 0 \
//         --scriptpubkey <hex> --amount 100000 --flags all
//
//   Quick mode, hex scripts:
//     ./script_debugger --quick \
//         --scriptsig-hex 51 --scriptpubkey-hex 51 --amount 0 --flags none
//
//   Quick mode, mnemonic assembly, segwit v0:
//     ./script_debugger --quick \
//         --scriptsig-asm "" \
//         --witness-asm "OP_1" \
//         --scriptpubkey-asm "OP_0 <20-byte-hash-hex-here>" \
//         --amount 100000 --flags all
//
// Once inside, type `help`.

#include <kernel/bitcoinkernel_wrapper.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

#include <chrono>
#include <thread>

// =====================================================================
// Hex <-> bytes helpers
//
// Two families:
//   - to_bytes()        -> std::vector<std::byte>          (Domain A)
//   - to_uchar_bytes()  -> std::vector<unsigned char>       (Domain B)
// =====================================================================

namespace hexutil {

int nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw std::invalid_argument(std::string("invalid hex character: ") + c);
}

bool looks_like_hex(const std::string& s)
{
    if (s.empty() || s.size() % 2 != 0) return false;
    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

std::string strip_0x(const std::string& hex_in)
{
    if (hex_in.rfind("0x", 0) == 0 || hex_in.rfind("0X", 0) == 0) return hex_in.substr(2);
    return hex_in;
}

// Domain B: raw unsigned char bytes, used when comparing against or
// printing data that came out of a captured ScriptTraceFrame.
std::vector<unsigned char> to_uchar_bytes(const std::string& hex_in)
{
    std::string hex = strip_0x(hex_in);
    if (hex.size() % 2 != 0) throw std::invalid_argument("hex string must have even length: " + hex_in);
    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i + 1]);
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return out;
}

// Domain A: std::byte, used when building scripts/transactions to feed
// into btck:: constructors (which require std::span<const std::byte>).
std::vector<std::byte> to_bytes(const std::string& hex_in)
{
    std::string hex = strip_0x(hex_in);
    if (hex.size() % 2 != 0) throw std::invalid_argument("hex string must have even length: " + hex_in);
    std::vector<std::byte> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i + 1]);
        out.push_back(static_cast<std::byte>((hi << 4) | lo));
    }
    return out;
}

std::string from_bytes(std::span<const unsigned char> data)
{
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (unsigned char b : data) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0xF]);
    }
    return out;
}

std::string from_bytes(const std::vector<unsigned char>& data)
{
    return from_bytes(std::span<const unsigned char>(data.data(), data.size()));
}

std::string json_escape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out.push_back(c);
            }
        }
    }
    return out;
}

} // namespace hexutil

// =====================================================================
// ANSI color helpers
// =====================================================================

namespace color {

bool g_enabled = true;

std::string wrap(const char* code, const std::string& s)
{
    if (!g_enabled) return s;
    return std::string("\x1b[") + code + "m" + s + "\x1b[0m";
}

std::string bold(const std::string& s)    { return wrap("1", s); }
std::string dim(const std::string& s)     { return wrap("2", s); }
std::string red(const std::string& s)     { return wrap("31", s); }
std::string green(const std::string& s)   { return wrap("32", s); }
std::string yellow(const std::string& s)  { return wrap("33", s); }
std::string blue(const std::string& s)    { return wrap("34", s); }
std::string magenta(const std::string& s) { return wrap("35", s); }
std::string cyan(const std::string& s)    { return wrap("36", s); }

} // namespace color

// =====================================================================
// Opcode name table + simple mnemonic assembler
//
// The opcode->name table below reflects standard, publicly documented
// Bitcoin Script opcode values; it is not copied from any single source
// listing, just the well-known byte assignments.
//
// The assembler (Domain A) produces std::vector<std::byte>, since its
// output is always destined for a btck::ScriptPubkey / btck::Transaction
// construction call.
// =====================================================================

namespace opnames {

const char* name(uint8_t op)
{
    if (op >= 0x01 && op <= 0x4b) return "OP_PUSHBYTES";
    switch (op) {
    case 0x00: return "OP_0";
    case 0x4c: return "OP_PUSHDATA1";
    case 0x4d: return "OP_PUSHDATA2";
    case 0x4e: return "OP_PUSHDATA4";
    case 0x4f: return "OP_1NEGATE";
    case 0x50: return "OP_RESERVED";
    case 0x51: return "OP_1";
    case 0x52: return "OP_2";
    case 0x53: return "OP_3";
    case 0x54: return "OP_4";
    case 0x55: return "OP_5";
    case 0x56: return "OP_6";
    case 0x57: return "OP_7";
    case 0x58: return "OP_8";
    case 0x59: return "OP_9";
    case 0x5a: return "OP_10";
    case 0x5b: return "OP_11";
    case 0x5c: return "OP_12";
    case 0x5d: return "OP_13";
    case 0x5e: return "OP_14";
    case 0x5f: return "OP_15";
    case 0x60: return "OP_16";
    case 0x61: return "OP_NOP";
    case 0x62: return "OP_VER";
    case 0x63: return "OP_IF";
    case 0x64: return "OP_NOTIF";
    case 0x65: return "OP_VERIF";
    case 0x66: return "OP_VERNOTIF";
    case 0x67: return "OP_ELSE";
    case 0x68: return "OP_ENDIF";
    case 0x69: return "OP_VERIFY";
    case 0x6a: return "OP_RETURN";
    case 0x6b: return "OP_TOALTSTACK";
    case 0x6c: return "OP_FROMALTSTACK";
    case 0x6d: return "OP_2DROP";
    case 0x6e: return "OP_2DUP";
    case 0x6f: return "OP_3DUP";
    case 0x70: return "OP_2OVER";
    case 0x71: return "OP_2ROT";
    case 0x72: return "OP_2SWAP";
    case 0x73: return "OP_IFDUP";
    case 0x74: return "OP_DEPTH";
    case 0x75: return "OP_DROP";
    case 0x76: return "OP_DUP";
    case 0x77: return "OP_NIP";
    case 0x78: return "OP_OVER";
    case 0x79: return "OP_PICK";
    case 0x7a: return "OP_ROLL";
    case 0x7b: return "OP_ROT";
    case 0x7c: return "OP_SWAP";
    case 0x7d: return "OP_TUCK";
    case 0x7e: return "OP_CAT";
    case 0x7f: return "OP_SUBSTR";
    case 0x80: return "OP_LEFT";
    case 0x81: return "OP_RIGHT";
    case 0x82: return "OP_SIZE";
    case 0x83: return "OP_INVERT";
    case 0x84: return "OP_AND";
    case 0x85: return "OP_OR";
    case 0x86: return "OP_XOR";
    case 0x87: return "OP_EQUAL";
    case 0x88: return "OP_EQUALVERIFY";
    case 0x89: return "OP_RESERVED1";
    case 0x8a: return "OP_RESERVED2";
    case 0x8b: return "OP_1ADD";
    case 0x8c: return "OP_1SUB";
    case 0x8d: return "OP_2MUL";
    case 0x8e: return "OP_2DIV";
    case 0x8f: return "OP_NEGATE";
    case 0x90: return "OP_ABS";
    case 0x91: return "OP_NOT";
    case 0x92: return "OP_0NOTEQUAL";
    case 0x93: return "OP_ADD";
    case 0x94: return "OP_SUB";
    case 0x95: return "OP_MUL";
    case 0x96: return "OP_DIV";
    case 0x97: return "OP_MOD";
    case 0x98: return "OP_LSHIFT";
    case 0x99: return "OP_RSHIFT";
    case 0x9a: return "OP_BOOLAND";
    case 0x9b: return "OP_BOOLOR";
    case 0x9c: return "OP_NUMEQUAL";
    case 0x9d: return "OP_NUMEQUALVERIFY";
    case 0x9e: return "OP_NUMNOTEQUAL";
    case 0x9f: return "OP_LESSTHAN";
    case 0xa0: return "OP_GREATERTHAN";
    case 0xa1: return "OP_LESSTHANOREQUAL";
    case 0xa2: return "OP_GREATERTHANOREQUAL";
    case 0xa3: return "OP_MIN";
    case 0xa4: return "OP_MAX";
    case 0xa5: return "OP_WITHIN";
    case 0xa6: return "OP_RIPEMD160";
    case 0xa7: return "OP_SHA1";
    case 0xa8: return "OP_SHA256";
    case 0xa9: return "OP_HASH160";
    case 0xaa: return "OP_HASH256";
    case 0xab: return "OP_CODESEPARATOR";
    case 0xac: return "OP_CHECKSIG";
    case 0xad: return "OP_CHECKSIGVERIFY";
    case 0xae: return "OP_CHECKMULTISIG";
    case 0xaf: return "OP_CHECKMULTISIGVERIFY";
    case 0xb0: return "OP_NOP1";
    case 0xb1: return "OP_CHECKLOCKTIMEVERIFY";
    case 0xb2: return "OP_CHECKSEQUENCEVERIFY";
    case 0xb3: return "OP_NOP4";
    case 0xb4: return "OP_NOP5";
    case 0xb5: return "OP_NOP6";
    case 0xb6: return "OP_NOP7";
    case 0xb7: return "OP_NOP8";
    case 0xb8: return "OP_NOP9";
    case 0xb9: return "OP_NOP10";
    case 0xba: return "OP_CHECKSIGADD";
    case 0xff: return "OP_INVALIDOPCODE";
    default:   return "OP_UNKNOWN";
    }
}

// One-line human descriptions for a handful of the most commonly-debugged
// opcodes, used by the 'explain' REPL command. Not exhaustive -- falls
// back to a generic note for anything not covered.
const char* describe(uint8_t op)
{
    switch (op) {
    case 0x00: return "Pushes an empty byte array (false/0) onto the stack.";
    case 0x63: return "Pops top; if truthy, executes the IF-branch, else skips to ELSE/ENDIF.";
    case 0x64: return "Pops top; if falsy, executes the branch (inverse of OP_IF).";
    case 0x67: return "Switches from the IF-branch to the ELSE-branch (or vice versa).";
    case 0x68: return "Closes the nearest OP_IF/OP_NOTIF block.";
    case 0x69: return "Pops top; fails the script immediately if it's falsy.";
    case 0x6a: return "Immediately fails the script (marks output unspendable outside OP_RETURN data carriers).";
    case 0x75: return "Pops and discards the top stack item.";
    case 0x76: return "Duplicates the top stack item.";
    case 0x7c: return "Swaps the top two stack items.";
    case 0x82: return "Pushes the byte-length of the top item (without popping it).";
    case 0x87: return "Pops two items, pushes true if byte-equal.";
    case 0x88: return "OP_EQUAL followed by OP_VERIFY.";
    case 0xa8: return "Pops top, pushes its SHA256 hash.";
    case 0xa9: return "Pops top, pushes RIPEMD160(SHA256(x)) -- the standard P2PKH/P2SH hash.";
    case 0xaa: return "Pops top, pushes SHA256(SHA256(x)).";
    case 0xac: return "Pops pubkey and sig; pushes true/false for signature validity.";
    case 0xad: return "OP_CHECKSIG followed by OP_VERIFY.";
    case 0xae: return "Legacy multisig: pops multiple pubkeys/sigs, verifies m-of-n.";
    case 0xb1: return "Fails unless the top stack item is <= the tx's nLockTime (BIP65).";
    case 0xb2: return "Fails unless the top stack item is <= the input's nSequence (BIP112).";
    case 0xba: return "Taproot multisig building block: pops pubkey, sig, n; verifies and pushes n or n+1 (BIP342).";
    default:
        if (op >= 0x01 && op <= 0x4b) return "Pushes the following N bytes as literal data.";
        if (op >= 0x51 && op <= 0x60) return "Pushes the small integer 1-16 directly.";
        return "No description available -- see the Bitcoin Script opcode reference.";
    }
}

bool is_if_like(uint8_t op)   { return op == 0x63 || op == 0x64; }              // OP_IF, OP_NOTIF
bool is_else(uint8_t op)      { return op == 0x67; }                            // OP_ELSE
bool is_endif(uint8_t op)     { return op == 0x68; }                            // OP_ENDIF
bool is_push_range(uint8_t op){ return op >= 0x01 && op <= 0x4e; }

// Looks up an opcode by mnemonic (case-insensitive, "OP_" prefix optional).
// Returns -1 if not found.
int lookup(std::string tok)
{
    for (auto& c : tok) c = static_cast<char>(::toupper(static_cast<unsigned char>(c)));
    if (tok.rfind("OP_", 0) != 0) tok = "OP_" + tok;
    for (int op = 0; op <= 0xff; ++op) {
        if (tok == name(static_cast<uint8_t>(op))) return op;
    }
    return -1;
}

// Minimal CScriptNum-style encoding of a signed integer into push bytes
// (little-endian, sign-magnitude in the high bit of the last byte). This
// mirrors the well-known, standard Bitcoin Script number encoding.
std::vector<std::byte> encode_scriptnum(int64_t value)
{
    if (value == 0) return {};
    std::vector<std::byte> result;
    const bool negative = value < 0;
    uint64_t absvalue = negative ? static_cast<uint64_t>(-(value + 1)) + 1 : static_cast<uint64_t>(value);
    while (absvalue) {
        result.push_back(static_cast<std::byte>(absvalue & 0xff));
        absvalue >>= 8;
    }
    if ((result.back() & std::byte{0x80}) != std::byte{0}) {
        result.push_back(negative ? std::byte{0x80} : std::byte{0x00});
    } else if (negative) {
        result.back() |= std::byte{0x80};
    }
    return result;
}

void append_push(std::vector<std::byte>& out, std::span<const std::byte> data)
{
    size_t n = data.size();
    if (n == 0) {
        out.push_back(std::byte{0x00}); // OP_0
    } else if (n <= 75) {
        out.push_back(static_cast<std::byte>(n));
        out.insert(out.end(), data.begin(), data.end());
    } else if (n <= 0xff) {
        out.push_back(std::byte{0x4c}); // OP_PUSHDATA1
        out.push_back(static_cast<std::byte>(n));
        out.insert(out.end(), data.begin(), data.end());
    } else if (n <= 0xffff) {
        out.push_back(std::byte{0x4d}); // OP_PUSHDATA2
        out.push_back(static_cast<std::byte>(n & 0xff));
        out.push_back(static_cast<std::byte>((n >> 8) & 0xff));
        out.insert(out.end(), data.begin(), data.end());
    } else {
        out.push_back(std::byte{0x4e}); // OP_PUSHDATA4
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::byte>((n >> (8 * i)) & 0xff));
        out.insert(out.end(), data.begin(), data.end());
    }
}

// A tiny mnemonic assembler. Whitespace-separated tokens. Each token is
// one of:
//   - An opcode mnemonic ("OP_DUP", "DUP", "OP_CHECKSIG", ...)
//   - A decimal integer ("0", "16", "-1", "12345") -> minimally encoded
//     script-number push, using the dedicated small-int opcodes for
//     0..16 and -1.
//   - A hex literal (even-length hex string, optionally "0x"-prefixed,
//     not matching an opcode mnemonic) -> raw data push using the
//     shortest applicable push opcode.
//   - "<...>" is accepted as an alternative bracket form for hex/decimal
//     data pushes (brackets are stripped before re-parsing the interior).
std::vector<std::byte> assemble(const std::string& src)
{
    std::vector<std::byte> out;
    std::istringstream iss(src);
    std::string tok;
    while (iss >> tok) {
        if (tok.size() >= 2 && tok.front() == '<' && tok.back() == '>') {
            tok = tok.substr(1, tok.size() - 2);
        }
        if (tok.empty()) continue;

        int op = lookup(tok);
        if (op >= 0) {
            out.push_back(static_cast<std::byte>(op));
            continue;
        }

        bool numeric = !tok.empty() &&
            (std::isdigit(static_cast<unsigned char>(tok[0])) ||
             (tok[0] == '-' && tok.size() > 1 && std::isdigit(static_cast<unsigned char>(tok[1]))));
        if (numeric) {
            try {
                int64_t v = std::stoll(tok);
                if (v == -1) { out.push_back(std::byte{0x4f}); continue; }         // OP_1NEGATE
                if (v >= 0 && v <= 16) {
                    out.push_back(v == 0 ? std::byte{0x00} : static_cast<std::byte>(0x50 + v));
                    continue;
                }
                auto enc = encode_scriptnum(v);
                append_push(out, enc);
                continue;
            } catch (...) {
                // fall through to hex/error handling below
            }
        }

        if (hexutil::looks_like_hex(tok)) {
            auto bytes = hexutil::to_bytes(tok);
            append_push(out, bytes);
            continue;
        }

        throw std::invalid_argument("cannot assemble token: '" + tok + "'");
    }
    return out;
}

} // namespace opnames

// =====================================================================
// Opcode "category" classification, used purely for color-coding in the
// interactive dashboard (Domain B presentation, not consensus logic).
// =====================================================================

namespace opcategory {

enum class Category { Push, Flow, Stack, Splice, Bitwise, Arithmetic, Crypto, Locktime, Reserved, Disabled, Other };

Category classify(uint8_t op)
{
    if (op <= 0x4e) return Category::Push;                             // OP_0..OP_PUSHDATA4
    if (op == 0x4f) return Category::Push;                              // OP_1NEGATE
    if (op >= 0x51 && op <= 0x60) return Category::Push;                 // OP_1..OP_16
    if (op == 0x50 || op == 0x62 || op == 0x65 || op == 0x66 ||
        op == 0x89 || op == 0x8a) return Category::Reserved;             // OP_RESERVED and friends
    if (op >= 0x63 && op <= 0x69) return Category::Flow;                 // OP_IF..OP_VERIFY
    if (op == 0x6a) return Category::Flow;                               // OP_RETURN
    if (op >= 0x6b && op <= 0x7d) return Category::Stack;                // OP_TOALTSTACK..OP_TUCK
    if (op >= 0x7e && op <= 0x82) return Category::Splice;               // OP_CAT..OP_SIZE
    if (op >= 0x83 && op <= 0x86) return Category::Disabled;             // OP_INVERT/AND/OR/XOR
    if (op == 0x87 || op == 0x88) return Category::Bitwise;              // OP_EQUAL(VERIFY)
    if (op >= 0x8b && op <= 0xa5) return Category::Arithmetic;           // numeric ops
    if (op >= 0xa6 && op <= 0xaa) return Category::Crypto;               // hash functions
    if (op == 0xab) return Category::Flow;                               // OP_CODESEPARATOR
    if (op >= 0xac && op <= 0xaf) return Category::Crypto;               // OP_CHECKSIG family
    if (op == 0xb1 || op == 0xb2) return Category::Locktime;             // CLTV/CSV
    if (op == 0xba) return Category::Crypto;                             // OP_CHECKSIGADD
    return Category::Other;
}

std::string colorize(const std::string& text, uint8_t op)
{
    switch (classify(op)) {
    case Category::Push:       return color::cyan(text);
    case Category::Stack:      return color::blue(text);
    case Category::Splice:     return color::blue(text);
    case Category::Bitwise:    return color::green(text);
    case Category::Arithmetic: return color::green(text);
    case Category::Crypto:     return color::magenta(text);
    case Category::Flow:       return color::yellow(text);
    case Category::Locktime:   return color::red(text);
    case Category::Disabled:   return color::red(text);
    case Category::Reserved:   return color::dim(text);
    case Category::Other:      return text;
    }
    return text;
}

} // namespace opcategory

// =====================================================================
// Raw transaction serialization (Domain A), used by "quick mode" to
// synthesize a minimal wrapping transaction around a bare scriptSig/
// scriptPubkey pair so that VerifyScript can be invoked without needing a
// real on-chain transaction. Standard Bitcoin tx wire format, written
// from scratch, entirely in std::byte since the output feeds directly
// into btck::Transaction's constructor.
// =====================================================================

namespace txbuild {

void put_u8(std::vector<std::byte>& out, uint8_t v) { out.push_back(static_cast<std::byte>(v)); }

void put_le16(std::vector<std::byte>& out, uint16_t v)
{
    out.push_back(static_cast<std::byte>(v & 0xff));
    out.push_back(static_cast<std::byte>((v >> 8) & 0xff));
}

void put_le32(std::vector<std::byte>& out, uint32_t v)
{
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::byte>((v >> (8 * i)) & 0xff));
}

void put_le64(std::vector<std::byte>& out, uint64_t v)
{
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::byte>((v >> (8 * i)) & 0xff));
}

void put_varint(std::vector<std::byte>& out, uint64_t v)
{
    if (v < 0xfd) {
        put_u8(out, static_cast<uint8_t>(v));
    } else if (v <= 0xffff) {
        put_u8(out, 0xfd);
        put_le16(out, static_cast<uint16_t>(v));
    } else if (v <= 0xffffffffULL) {
        put_u8(out, 0xfe);
        put_le32(out, static_cast<uint32_t>(v));
    } else {
        put_u8(out, 0xff);
        put_le64(out, v);
    }
}

void put_bytes(std::vector<std::byte>& out, std::span<const std::byte> data)
{
    out.insert(out.end(), data.begin(), data.end());
}

void put_varbytes(std::vector<std::byte>& out, std::span<const std::byte> data)
{
    put_varint(out, data.size());
    put_bytes(out, data);
}

// Builds a minimal 1-input, 1-output transaction spending a synthetic
// prevout with the given scriptSig, optionally with segwit witness data
// for that single input. The output is a throwaway OP_TRUE script; its
// contents don't affect script verification of the *input* being
// debugged, which is checked against the caller-supplied scriptPubkey
// and amount separately.
std::vector<std::byte> build_quick_tx(std::span<const std::byte> script_sig,
                                       int64_t amount,
                                       const std::vector<std::vector<std::byte>>& witness_items)
{
    std::vector<std::byte> out;
    const bool segwit = !witness_items.empty();

    put_le32(out, 2); // version

    if (segwit) {
        put_u8(out, 0x00); // marker
        put_u8(out, 0x01); // flag
    }

    put_varint(out, 1); // input count
    {
        // Synthetic prevout txid: 32 bytes, not all zero (avoids any
        // accidental special-casing on the null txid), arbitrary content.
        std::array<std::byte, 32> txid{};
        txid[0] = std::byte{0xde};
        txid[1] = std::byte{0xb0};
        txid[31] = std::byte{0x01};
        put_bytes(out, std::span<const std::byte>(txid.data(), txid.size()));
        put_le32(out, 0);              // prevout index
        put_varbytes(out, script_sig); // scriptSig
        put_le32(out, 0xffffffff);     // sequence
    }

    put_varint(out, 1); // output count
    {
        put_le64(out, static_cast<uint64_t>(std::max<int64_t>(amount, 0)));
        const std::byte op_true[] = {std::byte{0x51}};
        put_varbytes(out, std::span<const std::byte>(op_true, 1));
    }

    if (segwit) {
        put_varint(out, witness_items.size());
        for (const auto& item : witness_items) {
            put_varbytes(out, std::span<const std::byte>(item.data(), item.size()));
        }
    }

    put_le32(out, 0); // locktime
    return out;
}

} // namespace txbuild

// =====================================================================
// Control-flow-aware script disassembler (Domain B)
//
// Operates on btck::ScriptTraceFrame::m_script, which the header defines
// as std::vector<unsigned char> (it mirrors the underlying C struct's
// `const unsigned char* script` field), so this stays unsigned char.
// =====================================================================

struct DisasmOp {
    size_t op_index;
    size_t byte_offset;
    uint8_t opcode;
    std::vector<unsigned char> push_data;
    bool truncated = false;
    int depth = 0;     // IF/NOTIF nesting depth *before* this op
    bool is_branch = false;
};

std::vector<DisasmOp> disassemble(const std::vector<unsigned char>& script)
{
    std::vector<DisasmOp> ops;
    size_t i = 0, op_index = 0;
    int depth = 0;

    auto push_truncated = [&](DisasmOp op, size_t from) {
        op.push_data.assign(script.begin() + from, script.end());
        op.truncated = true;
        ops.push_back(std::move(op));
    };

    while (i < script.size()) {
        DisasmOp op;
        op.byte_offset = i;
        op.op_index = op_index++;
        uint8_t opcode = script[i++];
        op.opcode = opcode;

        if (opnames::is_else(opcode) || opnames::is_endif(opcode)) {
            if (depth > 0) depth -= (opnames::is_endif(opcode) ? 1 : 0);
            op.depth = depth;
        } else {
            op.depth = depth;
        }

        if (opcode >= 0x01 && opcode <= 0x4b) {
            size_t n = opcode;
            if (i + n > script.size()) { push_truncated(op, i); break; }
            op.push_data.assign(script.begin() + i, script.begin() + i + n);
            i += n;
        } else if (opcode == 0x4c) {
            if (i >= script.size()) { ops.push_back(op); break; }
            size_t n = script[i]; i += 1;
            if (i + n > script.size()) { push_truncated(op, i); break; }
            op.push_data.assign(script.begin() + i, script.begin() + i + n);
            i += n;
        } else if (opcode == 0x4d) {
            if (i + 2 > script.size()) { ops.push_back(op); break; }
            size_t n = static_cast<size_t>(script[i]) | (static_cast<size_t>(script[i + 1]) << 8);
            i += 2;
            if (i + n > script.size()) { push_truncated(op, i); break; }
            op.push_data.assign(script.begin() + i, script.begin() + i + n);
            i += n;
        } else if (opcode == 0x4e) {
            if (i + 4 > script.size()) { ops.push_back(op); break; }
            size_t n = static_cast<size_t>(script[i]) | (static_cast<size_t>(script[i + 1]) << 8) |
                       (static_cast<size_t>(script[i + 2]) << 16) | (static_cast<size_t>(script[i + 3]) << 24);
            i += 4;
            if (i + n > script.size()) { push_truncated(op, i); break; }
            op.push_data.assign(script.begin() + i, script.begin() + i + n);
            i += n;
        } else if (opnames::is_if_like(opcode)) {
            op.is_branch = true;
            ++depth;
        }

        ops.push_back(std::move(op));
    }
    return ops;
}

// Builds a git-log-style rail prefix for op `pos` within `ops`: a └ on the
// last op of a nesting level, a ├ mid-block, matching the IF/NOTIF/ELSE/
// ENDIF depth already tracked by disassemble(). Purely structural (based
// on script layout), independent of which branch actually executed.
std::string branch_prefix(const std::vector<DisasmOp>& ops, size_t pos)
{
    int depth = ops[pos].depth;
    if (depth <= 0) return std::string(static_cast<size_t>(std::max(0, depth)) * 2, ' ');
    std::string indent(static_cast<size_t>(depth - 1) * 2, ' ');
    bool is_last = (pos + 1 >= ops.size()) || (ops[pos + 1].depth < depth);
    indent += is_last ? "\u2514 " : "\u251c ";
    return indent;
}

std::string format_disasm_op(const std::vector<DisasmOp>& ops, size_t pos, bool current, bool exec_hint, bool use_color)
{
    const DisasmOp& op = ops[pos];
    std::ostringstream oss;
    std::string indent = branch_prefix(ops, pos);

    std::string marker = current ? "-> " : "   ";
    std::string idx_field = "[" + std::to_string(op.op_index) + "]";
    std::string off_field = "off=" + std::to_string(op.byte_offset);

    std::string body;
    if (op.opcode >= 0x01 && op.opcode <= 0x4e) {
        body = "PUSH(" + std::to_string(op.push_data.size()) + "): " + hexutil::from_bytes(op.push_data);
        if (op.truncated) body += "  [TRUNCATED]";
    } else {
        char hexbuf[8];
        std::snprintf(hexbuf, sizeof(hexbuf), "0x%02x", op.opcode);
        body = std::string(opnames::name(op.opcode)) + " (" + hexbuf + ")";
    }

    oss << (use_color && current ? color::green(marker) : marker)
        << std::left << std::setw(8) << idx_field << " "
        << std::setw(10) << off_field << " "
        << indent << body;

    if (current && !exec_hint) {
        oss << (use_color ? color::dim("  [not executed: inactive branch]") : "  [not executed: inactive branch]");
    }
    return oss.str();
}

// Domain B helper: builds a compact hex preview for a push/stack item,
// eliding the middle of long items so it still fits comfortably inside a
// dashboard panel.
std::string hex_preview(const std::vector<unsigned char>& data, size_t max_bytes = 16)
{
    if (data.size() <= max_bytes) return hexutil::from_bytes(data);
    size_t half = max_bytes / 2;
    std::vector<unsigned char> head(data.begin(), data.begin() + static_cast<long>(half));
    std::vector<unsigned char> tail(data.end() - static_cast<long>(half), data.end());
    return hexutil::from_bytes(head) + "..." + hexutil::from_bytes(tail);
}

// Domain B helper: returns a printable-ASCII rendering of a stack/push
// item if (and only if) every byte is printable ASCII and the item is
// short enough to be a plausible text label (e.g. an OP_RETURN payload
// or a redeem-script comment); otherwise an empty string.
std::string ascii_preview(const std::vector<unsigned char>& data, size_t max_len = 32)
{
    if (data.empty() || data.size() > max_len) return "";
    for (unsigned char b : data) {
        if (b < 0x20 || b > 0x7e) return "";
    }
    return std::string(data.begin(), data.end());
}

// Best-effort structural guess at what a stack item "is", purely from its
// length. This is a UX hint, not a consensus claim -- lengths overlap
// (e.g. 32B could be a sighash, an x-only pubkey, or just a hash), so we
// keep the wording hedged with "?" for ambiguous cases.
std::string type_guess(const std::vector<unsigned char>& data)
{
    switch (data.size()) {
    case 20: return "hash160";
    case 32: return "hash256 / x-only pubkey?";
    case 33: return "compressed pubkey";
    case 64: return "schnorr sig (or sig+SIGHASH_DEFAULT)";
    case 65: return "schnorr sig+sighash / uncompressed-adjacent?";
    default:
        if (data.size() >= 70 && data.size() <= 73) return "DER ECDSA sig";
        if (data.empty()) return "false / 0";
        if (data.size() == 1 && data[0] == 0x01) return "true / 1";
        return "";
    }
}

// =====================================================================
// Lightweight, best-effort recognition of well-known consensus-level
// scriptPubkey / tapscript-leaf templates. This is a UX aid for the
// debugger, not a consensus or policy classifier -- it looks only at
// opcode/push shape, and false negatives are expected for anything even
// slightly non-standard. Deliberately scoped to actual Script templates
// only (no application-layer/meta-protocol interpretation of push data).
// =====================================================================

namespace scripttpl {

std::optional<std::string> recognize_common_template(const std::vector<DisasmOp>& ops)
{
    auto op_at = [&](size_t i) -> uint8_t { return i < ops.size() ? ops[i].opcode : 0xFFu; };

    // P2PKH: OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG
    if (ops.size() == 5 && op_at(0) == 0x76 && op_at(1) == 0xa9 &&
        ops[2].opcode >= 0x01 && ops[2].opcode <= 0x4e && ops[2].push_data.size() == 20 &&
        op_at(3) == 0x88 && op_at(4) == 0xac) {
        return "Pay-to-pubkey-hash (P2PKH)";
    }

    // P2PK: <33B or 65B pubkey> OP_CHECKSIG
    if (ops.size() == 2 && ops[0].opcode >= 0x01 && ops[0].opcode <= 0x4e &&
        (ops[0].push_data.size() == 33 || ops[0].push_data.size() == 65) && op_at(1) == 0xac) {
        return "Pay-to-pubkey (P2PK)";
    }

    // Single-key tapscript leaf: <32B x-only pubkey> OP_CHECKSIG
    if (ops.size() == 2 && ops[0].opcode >= 0x01 && ops[0].opcode <= 0x4e &&
        ops[0].push_data.size() == 32 && op_at(1) == 0xac) {
        return "Single-key tapscript leaf (x-only pubkey + OP_CHECKSIG)";
    }

    // Bare m-of-n multisig: OP_m <pubkey>... OP_n OP_CHECKMULTISIG
    if (ops.size() >= 4 && op_at(ops.size() - 1) == 0xae) {
        uint8_t m_op = op_at(0);
        uint8_t n_op = op_at(ops.size() - 2);
        bool m_small = m_op >= 0x51 && m_op <= 0x60;
        bool n_small = n_op >= 0x51 && n_op <= 0x60;
        if (m_small && n_small) {
            int n = n_op - 0x50;
            int m = m_op - 0x50;
            bool all_pubkeys = true;
            for (size_t i = 1; i + 2 < ops.size(); ++i) {
                const auto& o = ops[i];
                if (!(o.opcode >= 0x01 && o.opcode <= 0x4e && (o.push_data.size() == 33 || o.push_data.size() == 65))) {
                    all_pubkeys = false;
                    break;
                }
            }
            if (all_pubkeys && static_cast<int>(ops.size()) - 3 == n) {
                return std::to_string(m) + "-of-" + std::to_string(n) + " bare multisig";
            }
        }
    }

    return std::nullopt;
}

} // namespace scripttpl

// =====================================================================
// Terminal size query, used to size the dashboard boxes to the actual
// window instead of a hardcoded width.
// =====================================================================

namespace termsize {

int columns()
{
    struct winsize ws{};
    if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        return ws.ws_col;
    }
    return 100; // sane fallback when not attached to a real terminal
}

} // namespace termsize

// =====================================================================
// Box-drawing helpers for the interactive dashboard.
//
// visible_width()/truncate_visible()/pad_visible() are ANSI- and
// UTF-8-aware: they treat SGR color escapes as zero-width and treat the
// (3-byte-UTF-8) box-drawing glyphs used here as exactly one terminal
// column each, so panel borders line up correctly whether or not color
// is enabled.
// =====================================================================

namespace ui {

size_t visible_width(const std::string& s)
{
    size_t width = 0;
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == 0x1b && i + 1 < s.size() && s[i + 1] == '[') {
            size_t j = s.find('m', i);
            if (j == std::string::npos) { i = s.size(); break; }
            i = j + 1;
            continue;
        }
        size_t char_len = 1;
        if ((c & 0x80) == 0x00) char_len = 1;
        else if ((c & 0xE0) == 0xC0) char_len = 2;
        else if ((c & 0xF0) == 0xE0) char_len = 3;
        else if ((c & 0xF8) == 0xF0) char_len = 4;
        width += 1;
        i += char_len;
    }
    return width;
}

// Truncates a (possibly ANSI-colored) string to at most `max_width`
// visible columns, preserving any escape sequences encountered before
// the cut point, appending a reset code if color was in use (so
// truncation never bleeds color onto the rest of a line), and reserving
// exactly one column for a trailing ellipsis glyph so the result never
// exceeds max_width visible columns.
std::string truncate_visible(const std::string& s, size_t max_width)
{
    if (max_width == 0) return "";
    if (visible_width(s) <= max_width) return s;

    std::string out;
    size_t width = 0;
    size_t i = 0;
    bool saw_escape = false;
    const size_t target = max_width - 1; // reserve one column for the ellipsis

    while (i < s.size() && width < target) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == 0x1b && i + 1 < s.size() && s[i + 1] == '[') {
            size_t j = s.find('m', i);
            if (j == std::string::npos) break;
            out.append(s, i, j - i + 1);
            saw_escape = true;
            i = j + 1;
            continue;
        }
        size_t char_len = 1;
        if ((c & 0x80) == 0x00) char_len = 1;
        else if ((c & 0xE0) == 0xC0) char_len = 2;
        else if ((c & 0xF0) == 0xE0) char_len = 3;
        else if ((c & 0xF8) == 0xF0) char_len = 4;
        out.append(s, i, std::min(char_len, s.size() - i));
        ++width;
        i += char_len;
    }
    if (saw_escape) out += "\x1b[0m";
    out += "\u2026"; // "…"
    return out;
}

std::string pad_visible(const std::string& s, size_t width)
{
    size_t vw = visible_width(s);
    if (vw >= width) return s;
    return s + std::string(width - vw, ' ');
}

std::string repeat_utf8(const char* glyph, size_t n)
{
    std::string out;
    size_t glyph_len = std::strlen(glyph);
    out.reserve(n * glyph_len);
    for (size_t i = 0; i < n; ++i) out += glyph;
    return out;
}

constexpr const char* GLYPH_H  = "\u2500"; // ─
constexpr const char* GLYPH_V  = "\u2502"; // │
constexpr const char* GLYPH_TL = "\u250c"; // ┌
constexpr const char* GLYPH_TR = "\u2510"; // ┐
constexpr const char* GLYPH_BL = "\u2514"; // └
constexpr const char* GLYPH_BR = "\u2518"; // ┘

// A single-column box renderer. `width` is the TOTAL visual width of the
// box including its left/right border characters.
class Box {
public:
    explicit Box(std::string title, size_t width) : m_title(std::move(title)), m_width(std::max<size_t>(width, 8)) {}

    void add_line(std::string line) { m_lines.push_back(std::move(line)); }

    std::vector<std::string> render() const
    {
        std::vector<std::string> out;
        out.push_back(render_top());
        size_t content_width = m_width >= 4 ? m_width - 4 : 1;
        for (const auto& raw_line : m_lines) {
            std::string line = truncate_visible(raw_line, content_width);
            std::string padded = pad_visible(line, content_width);
            out.push_back(std::string(GLYPH_V) + " " + padded + " " + GLYPH_V);
        }
        out.push_back(render_bottom());
        return out;
    }

private:
    std::string m_title;
    size_t m_width;
    std::vector<std::string> m_lines;

    std::string render_top() const
    {
        std::string title_disp = m_title.empty() ? "" : (" " + m_title + " ");
        size_t title_vw = visible_width(title_disp);
        size_t inner = m_width >= 2 ? m_width - 2 : 0;

        if (title_vw > inner) {
            // No room for the title at all; degrade to a plain border
            // rather than corrupting the box width.
            return std::string(GLYPH_TL) + repeat_utf8(GLYPH_H, inner) + GLYPH_TR;
        }
        size_t remaining = inner - title_vw;
        size_t left = std::min<size_t>(2, remaining);
        size_t right = remaining - left;
        return std::string(GLYPH_TL) + repeat_utf8(GLYPH_H, left) + title_disp + repeat_utf8(GLYPH_H, right) + GLYPH_TR;
    }

    std::string render_bottom() const
    {
        size_t inner = m_width >= 2 ? m_width - 2 : 0;
        return std::string(GLYPH_BL) + repeat_utf8(GLYPH_H, inner) + GLYPH_BR;
    }
};

} // namespace ui

// =====================================================================
// Raw-terminal line editor (arrow keys + history), falls back to plain
// std::getline when stdin is not a TTY.
// =====================================================================

class LineEditor {
public:
    explicit LineEditor(std::string prompt) : m_prompt(std::move(prompt))
    {
        m_is_tty = ::isatty(STDIN_FILENO) && ::isatty(STDOUT_FILENO);
        if (m_is_tty) enable_raw_mode();
    }

    ~LineEditor()
    {
        if (m_is_tty) disable_raw_mode();
    }

    // Returns std::nullopt on EOF (Ctrl-D on an empty line, or stream EOF).
    std::optional<std::string> read_line()
    {
        if (!m_is_tty) return read_line_plain();
        return read_line_raw();
    }

private:
    std::string m_prompt;
    bool m_is_tty = false;
    struct termios m_orig{};
    std::vector<std::string> m_history;

    void enable_raw_mode()
    {
        tcgetattr(STDIN_FILENO, &m_orig);
        struct termios raw = m_orig;
        // Only touch INPUT processing: no local echo (we draw the line
        // ourselves), no canonical/line buffering (so we see each
        // keystroke immediately), no signal generation (Ctrl-C is
        // handled as data, see below), no flow control / special
        // input-byte munging.
        raw.c_lflag &= ~(ECHO | ICANON | ISIG | IEXTEN);
        raw.c_iflag &= ~(IXON | ICRNL | BRKINT | INPCK | ISTRIP);
        // Deliberately leave c_oflag untouched: OPOST (and ONLCR under
        // it) must stay enabled so that '\n' written by anything in this
        // program -- our own prompt redraws, the dashboard, batch
        // output, everything -- still gets translated to '\r\n' by the
        // tty driver. Raw mode only needs to change how *input* is
        // delivered to us; output post-processing should be left at its
        // normal terminal default.
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    }

    void disable_raw_mode()
    {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &m_orig);
    }

    std::optional<std::string> read_line_plain()
    {
        std::cout << m_prompt << std::flush;
        std::string line;
        if (!std::getline(std::cin, line)) return std::nullopt;
        return line;
    }

    static int read_raw_char()
    {
        char c;
        ssize_t n = ::read(STDIN_FILENO, &c, 1);
        if (n <= 0) return -1;
        return static_cast<unsigned char>(c);
    }

    std::optional<std::string> read_line_raw()
    {
        std::string buf;
        size_t cursor = 0;
        int hist_idx = static_cast<int>(m_history.size()); // one past the end = "editing new line"
        std::string saved_new_line;

        auto redraw = [&]() {
            std::cout << "\r\x1b[K" << m_prompt << buf;
            size_t back = buf.size() - cursor;
            if (back > 0) std::cout << "\x1b[" << back << "D";
            std::cout << std::flush;
        };

        std::cout << m_prompt << std::flush;

        while (true) {
            int c = read_raw_char();
            if (c < 0) { // EOF / read error
                if (buf.empty()) { std::cout << "\n"; return std::nullopt; }
                continue;
            }

            if (c == '\r' || c == '\n') {
                std::cout << "\n";
                if (!buf.empty() && (m_history.empty() || m_history.back() != buf)) {
                    m_history.push_back(buf);
                }
                return buf;
            }
            if (c == 3) { // Ctrl-C: cancel current line
                std::cout << "^C\n";
                buf.clear();
                cursor = 0;
                std::cout << m_prompt << std::flush;
                continue;
            }
            if (c == 4) { // Ctrl-D
                if (buf.empty()) { std::cout << "\n"; return std::nullopt; }
                continue;
            }
            if (c == 127 || c == 8) { // Backspace
                if (cursor > 0) {
                    buf.erase(cursor - 1, 1);
                    --cursor;
                    redraw();
                }
                continue;
            }
            if (c == 1) { cursor = 0; redraw(); continue; } // Ctrl-A: home
            if (c == 5) { cursor = buf.size(); redraw(); continue; } // Ctrl-E: end
            if (c == 21) { buf.erase(0, cursor); cursor = 0; redraw(); continue; } // Ctrl-U
            if (c == 11) { buf.erase(cursor); redraw(); continue; } // Ctrl-K

            if (c == 27) { // ESC sequence
                int c1 = read_raw_char();
                if (c1 != '[' && c1 != 'O') continue;
                int c2 = read_raw_char();
                if (c2 == 'A') { // Up
                    if (hist_idx > 0) {
                        if (hist_idx == static_cast<int>(m_history.size())) saved_new_line = buf;
                        --hist_idx;
                        buf = m_history[hist_idx];
                        cursor = buf.size();
                        redraw();
                    }
                } else if (c2 == 'B') { // Down
                    if (hist_idx < static_cast<int>(m_history.size())) {
                        ++hist_idx;
                        buf = (hist_idx == static_cast<int>(m_history.size())) ? saved_new_line : m_history[hist_idx];
                        cursor = buf.size();
                        redraw();
                    }
                } else if (c2 == 'C') { // Right
                    if (cursor < buf.size()) { ++cursor; redraw(); }
                } else if (c2 == 'D') { // Left
                    if (cursor > 0) { --cursor; redraw(); }
                } else if (c2 == 'H') { // Home
                    cursor = 0; redraw();
                } else if (c2 == 'F') { // End
                    cursor = buf.size(); redraw();
                } else if (c2 == '3') { // Delete key: ESC [ 3 ~
                    int c3 = read_raw_char();
                    (void)c3;
                    if (cursor < buf.size()) { buf.erase(cursor, 1); redraw(); }
                }
                continue;
            }

            if (c >= 0x20 && c < 0x7f) {
                buf.insert(buf.begin() + cursor, static_cast<char>(c));
                ++cursor;
                redraw();
            }
        }
    }
};

// =====================================================================
// Trace capture
// =====================================================================

struct Tracer {
    std::vector<btck::ScriptTraceFrame>& frames;

    void ScriptTrace(btck::ScriptTraceFrame frame)
    {
        frames.push_back(std::move(frame));
    }
};

const char* kind_str(btck::ScriptTraceFrameKind k)
{
    switch (k) {
    case btck::ScriptTraceFrameKind::BEGIN: return "BEGIN";
    case btck::ScriptTraceFrameKind::STEP:  return "STEP";
    case btck::ScriptTraceFrameKind::END:   return "END";
    }
    return "?";
}

std::optional<btck::ScriptTraceFrameKind> kind_from_str(std::string s)
{
    for (auto& c : s) c = static_cast<char>(::toupper(static_cast<unsigned char>(c)));
    if (s == "BEGIN") return btck::ScriptTraceFrameKind::BEGIN;
    if (s == "STEP") return btck::ScriptTraceFrameKind::STEP;
    if (s == "END") return btck::ScriptTraceFrameKind::END;
    return std::nullopt;
}

const char* sigversion_str(btck::SigVersion sv)
{
    switch (sv) {
    case btck::SigVersion::BASE:       return "BASE";
    case btck::SigVersion::WITNESS_V0: return "WITNESS_V0";
    case btck::SigVersion::TAPROOT:    return "TAPROOT";
    case btck::SigVersion::TAPSCRIPT:  return "TAPSCRIPT";
    }
    return "?";
}

const char* status_str(btck::ScriptVerifyStatus s)
{
    switch (s) {
    case btck::ScriptVerifyStatus::OK: return "OK";
    case btck::ScriptVerifyStatus::ERROR_INVALID_FLAGS_COMBINATION: return "ERROR_INVALID_FLAGS_COMBINATION";
    case btck::ScriptVerifyStatus::ERROR_SPENT_OUTPUTS_REQUIRED: return "ERROR_SPENT_OUTPUTS_REQUIRED";
    }
    return "?";
}

struct Run {
    size_t begin_idx;
    size_t end_idx; // inclusive
};

std::vector<Run> group_runs(const std::vector<btck::ScriptTraceFrame>& frames)
{
    std::vector<Run> runs;
    std::optional<size_t> cur_begin;
    for (size_t i = 0; i < frames.size(); ++i) {
        if (frames[i].m_kind == btck::ScriptTraceFrameKind::BEGIN) {
            cur_begin = i;
        } else if (frames[i].m_kind == btck::ScriptTraceFrameKind::END && cur_begin) {
            runs.push_back(Run{*cur_begin, i});
            cur_begin.reset();
        }
    }
    return runs;
}

// =====================================================================
// Tiny expression evaluator for conditional breakpoints / watches
//
// Grammar (deliberately small): one or more comparisons joined by &&.
//   expr    := cmp (&& cmp)*
//   cmp     := ident op value
//   op      := '==' | '!=' | '<' | '<=' | '>' | '>='
//   ident   := opcode | op_pos | op_count | stack_depth | altstack_depth
//              | kind | sig_version | exec | script_error
//              | codeseparator_pos
//   value   := decimal integer | 0xHEX | identifier (opcode/kind name)
// =====================================================================

struct FrameView {
    const btck::ScriptTraceFrame& f;
    size_t index;
};

class Condition {
public:
    static std::optional<Condition> parse(const std::string& text)
    {
        Condition c;
        std::string remaining = text;
        size_t pos;
        std::vector<std::string> clauses;
        while ((pos = remaining.find("&&")) != std::string::npos) {
            clauses.push_back(remaining.substr(0, pos));
            remaining = remaining.substr(pos + 2);
        }
        clauses.push_back(remaining);

        for (auto& cl : clauses) {
            auto clause_opt = parse_clause(cl);
            if (!clause_opt) return std::nullopt;
            c.m_clauses.push_back(*clause_opt);
        }
        c.m_text = text;
        return c;
    }

    bool eval(const FrameView& fv) const
    {
        for (const auto& cl : m_clauses) {
            if (!eval_clause(cl, fv)) return false;
        }
        return true;
    }

    const std::string& text() const { return m_text; }

private:
    struct Clause {
        std::string ident;
        std::string op;
        std::string raw_value;
    };

    std::vector<Clause> m_clauses;
    std::string m_text;

    static std::optional<Clause> parse_clause(std::string s)
    {
        auto trim = [](std::string& x) {
            size_t a = x.find_first_not_of(" \t");
            size_t b = x.find_last_not_of(" \t");
            if (a == std::string::npos) { x.clear(); return; }
            x = x.substr(a, b - a + 1);
        };
        trim(s);
        static const std::vector<std::string> ops = {"==", "!=", "<=", ">=", "<", ">"};
        for (const auto& op : ops) {
            auto p = s.find(op);
            if (p != std::string::npos) {
                Clause c;
                c.ident = s.substr(0, p);
                c.op = op;
                c.raw_value = s.substr(p + op.size());
                trim(c.ident);
                trim(c.raw_value);
                if (c.ident.empty() || c.raw_value.empty()) return std::nullopt;
                return c;
            }
        }
        return std::nullopt;
    }

    static int64_t resolve_ident(const std::string& ident, const FrameView& fv, bool& is_string_domain, std::string& string_val)
    {
        is_string_domain = false;
        const auto& f = fv.f;
        if (ident == "opcode") { is_string_domain = true; string_val = opnames::name(f.m_opcode); return f.m_opcode; }
        if (ident == "op_pos") return static_cast<int64_t>(f.m_opcode_pos);
        if (ident == "op_count") return f.m_op_count;
        if (ident == "stack_depth") return static_cast<int64_t>(f.m_stack.size());
        if (ident == "altstack_depth") return static_cast<int64_t>(f.m_altstack.size());
        if (ident == "kind") { is_string_domain = true; string_val = kind_str(f.m_kind); return static_cast<int64_t>(f.m_kind); }
        if (ident == "sig_version") { is_string_domain = true; string_val = sigversion_str(f.m_sig_version); return static_cast<int64_t>(f.m_sig_version); }
        if (ident == "exec") return f.m_exec ? 1 : 0;
        if (ident == "script_error") return f.m_script_error;
        if (ident == "codeseparator_pos") return static_cast<int64_t>(f.m_codeseparator_pos);
        if (ident == "frame") return static_cast<int64_t>(fv.index);
        throw std::invalid_argument("unknown identifier in condition: " + ident);
    }

    static bool eval_clause(const Clause& c, const FrameView& fv)
    {
        bool lhs_is_string = false;
        std::string lhs_str;
        int64_t lhs = resolve_ident(c.ident, fv, lhs_is_string, lhs_str);

        int64_t rhs = 0;
        std::string v = c.raw_value;
        if (v.rfind("0x", 0) == 0 || v.rfind("0X", 0) == 0) {
            rhs = std::stoll(v.substr(2), nullptr, 16);
        } else if (!v.empty() && (std::isdigit(static_cast<unsigned char>(v[0])) || (v[0] == '-' && v.size() > 1))) {
            rhs = std::stoll(v);
        } else if (int op = opnames::lookup(v); op >= 0) {
            rhs = op;
        } else if (auto k = kind_from_str(v); k) {
            rhs = static_cast<int64_t>(*k);
        } else {
            throw std::invalid_argument("cannot parse condition value: " + v);
        }
        (void)lhs_is_string; (void)lhs_str;

        if (c.op == "==") return lhs == rhs;
        if (c.op == "!=") return lhs != rhs;
        if (c.op == "<")  return lhs < rhs;
        if (c.op == "<=") return lhs <= rhs;
        if (c.op == ">")  return lhs > rhs;
        if (c.op == ">=") return lhs >= rhs;
        return false;
    }
};

// =====================================================================
// CLI options
// =====================================================================

struct SpentOutputSpec {
    std::string script_hex;
    int64_t amount;
};

struct Options {
    // Full-tx mode
    bool quick = false;
    std::string tx_hex;
    unsigned int input_index = 0;
    std::vector<SpentOutputSpec> spent_outputs;

    // Common
    std::string scriptpubkey_hex;
    std::string scriptpubkey_asm;
    int64_t amount = 0;
    std::string flags_str = "all";

    // Quick mode extras
    std::string scriptsig_hex;
    std::string scriptsig_asm;
    std::vector<std::string> witness_hex;
    std::vector<std::string> witness_asm;

    // UX
    bool no_color = false;
    bool no_visual = false;
    std::string batch_file;
    bool batch_then_exit = false;
    std::string export_path;
};

void print_usage(const char* argv0)
{
    std::cout <<
        "Usage:\n"
        "  Full-tx mode:\n"
        "    " << argv0 << " --tx <hex> --index <n> --scriptpubkey <hex> --amount <sats>\n"
        "        [--flags <list>] [--spent-output <scriptpubkey_hex>:<amount>]...\n\n"
        "  Quick mode (synthesizes a minimal wrapping transaction):\n"
        "    " << argv0 << " --quick\n"
        "        [--scriptsig-hex <hex> | --scriptsig-asm \"<mnemonics>\"]\n"
        "        (--scriptpubkey-hex <hex> | --scriptpubkey-asm \"<mnemonics>\")\n"
        "        [--witness-hex <hex>]...   [--witness-asm \"<mnemonics>\"]...\n"
        "        --amount <sats> [--flags <list>]\n\n"
        "  Common options:\n"
        "    --flags <list>       Comma-separated: none,p2sh,dersig,nulldummy,cltv,csv,\n"
        "                          witness,taproot,all (default: all)\n"
        "    --no-color            Disable ANSI colors\n"
        "    --no-visual           Disable the automatic boxed dashboard (plain text only)\n"
        "    --batch <file>        Run commands from file before/instead of the REPL\n"
        "    --batch-then-exit     Exit after running --batch instead of entering the REPL\n"
        "    --export <file.json>  Export the captured trace as JSON on startup\n\n"
        "  Mnemonic assembly (for *-asm options) accepts opcode names (DUP, CHECKSIG,\n"
        "  OP_1, ...), decimal integers, and hex literals for data pushes, e.g.:\n"
        "     \"OP_DUP OP_HASH160 89abcdef... OP_EQUALVERIFY OP_CHECKSIG\"\n";
}

btck::ScriptVerificationFlags parse_flags(const std::string& s)
{
    static const std::map<std::string, btck::ScriptVerificationFlags> table = {
        {"none",      btck::ScriptVerificationFlags::NONE},
        {"p2sh",      btck::ScriptVerificationFlags::P2SH},
        {"dersig",    btck::ScriptVerificationFlags::DERSIG},
        {"nulldummy", btck::ScriptVerificationFlags::NULLDUMMY},
        {"cltv",      btck::ScriptVerificationFlags::CHECKLOCKTIMEVERIFY},
        {"csv",       btck::ScriptVerificationFlags::CHECKSEQUENCEVERIFY},
        {"witness",   btck::ScriptVerificationFlags::WITNESS},
        {"taproot",   btck::ScriptVerificationFlags::TAPROOT},
        {"all",       btck::ScriptVerificationFlags::ALL},
    };

    auto flags = btck::ScriptVerificationFlags::NONE;
    std::istringstream iss(s);
    std::string tok;
    while (std::getline(iss, tok, ',')) {
        for (auto& c : tok) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
        auto it = table.find(tok);
        if (it == table.end()) throw std::invalid_argument("unknown flag: " + tok);
        flags |= it->second;
    }
    return flags;
}

Options parse_args(int argc, char** argv)
{
    Options opt;
    bool have_spk = false, have_amount = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) throw std::invalid_argument(std::string("missing value for ") + name);
            return argv[++i];
        };

        if (arg == "--quick") opt.quick = true;
        else if (arg == "--tx") opt.tx_hex = next("--tx");
        else if (arg == "--index") opt.input_index = static_cast<unsigned int>(std::stoul(next("--index")));
        else if (arg == "--scriptpubkey" || arg == "--scriptpubkey-hex") { opt.scriptpubkey_hex = next(arg.c_str()); have_spk = true; }
        else if (arg == "--scriptpubkey-asm") { opt.scriptpubkey_asm = next("--scriptpubkey-asm"); have_spk = true; }
        else if (arg == "--scriptsig-hex") opt.scriptsig_hex = next("--scriptsig-hex");
        else if (arg == "--scriptsig-asm") opt.scriptsig_asm = next("--scriptsig-asm");
        else if (arg == "--witness-hex") opt.witness_hex.push_back(next("--witness-hex"));
        else if (arg == "--witness-asm") opt.witness_asm.push_back(next("--witness-asm"));
        else if (arg == "--amount") { opt.amount = std::stoll(next("--amount")); have_amount = true; }
        else if (arg == "--flags") opt.flags_str = next("--flags");
        else if (arg == "--spent-output") {
            std::string v = next("--spent-output");
            auto pos = v.rfind(':');
            if (pos == std::string::npos) throw std::invalid_argument("--spent-output must be script_hex:amount");
            SpentOutputSpec s;
            s.script_hex = v.substr(0, pos);
            s.amount = std::stoll(v.substr(pos + 1));
            opt.spent_outputs.push_back(std::move(s));
        }
        else if (arg == "--no-color") opt.no_color = true;
        else if (arg == "--no-visual") opt.no_visual = true;
        else if (arg == "--batch") opt.batch_file = next("--batch");
        else if (arg == "--batch-then-exit") opt.batch_then_exit = true;
        else if (arg == "--export") opt.export_path = next("--export");
        else if (arg == "--help" || arg == "-h") { print_usage(argv[0]); std::exit(0); }
        else throw std::invalid_argument("unknown argument: " + arg);
    }

    if (!have_spk) { print_usage(argv[0]); throw std::invalid_argument("a scriptPubkey is required (--scriptpubkey-hex/--scriptpubkey-asm)"); }
    if (!have_amount) { print_usage(argv[0]); throw std::invalid_argument("--amount is required"); }
    if (!opt.quick && opt.tx_hex.empty()) { print_usage(argv[0]); throw std::invalid_argument("full-tx mode requires --tx (or pass --quick)"); }

    return opt;
}

// =====================================================================
// Running the verification and capturing the trace
// =====================================================================

struct RunResult {
    bool success = false;
    btck::ScriptVerifyStatus status = btck::ScriptVerifyStatus::OK;
};

// Domain A: returns std::byte, since the result is destined for a
// btck::ScriptPubkey / btck::Transaction constructor.
std::vector<std::byte> resolve_script(const std::string& hex, const std::string& asm_src, const char* label)
{
    if (!hex.empty() && !asm_src.empty()) {
        throw std::invalid_argument(std::string("specify only one of hex/asm for ") + label);
    }
    if (!hex.empty()) return hexutil::to_bytes(hex);
    if (!asm_src.empty()) return opnames::assemble(asm_src);
    return {};
}

RunResult run_verification(const Options& opt, std::vector<btck::ScriptTraceFrame>& frames)
{
    auto spk_bytes = resolve_script(opt.scriptpubkey_hex, opt.scriptpubkey_asm, "scriptpubkey");
    btck::ScriptPubkey spk{spk_bytes};

    std::vector<std::byte> tx_bytes;

    if (opt.quick) {
        auto scriptsig = resolve_script(opt.scriptsig_hex, opt.scriptsig_asm, "scriptsig");

        std::vector<std::vector<std::byte>> witness_items;
        for (const auto& h : opt.witness_hex) witness_items.push_back(hexutil::to_bytes(h));
        for (const auto& a : opt.witness_asm) witness_items.push_back(opnames::assemble(a));

        tx_bytes = txbuild::build_quick_tx(scriptsig, opt.amount, witness_items);
    } else {
        tx_bytes = hexutil::to_bytes(opt.tx_hex);
    }

    btck::Transaction tx{tx_bytes};
    const size_t n_inputs = tx.CountInputs();

    // Validate the input index ourselves. btck_script_pubkey_verify does
    // `assert(input_index < tx.vin.size())` internally, which is a hard
    // process-terminating assert in a debug/asan build, not a catchable
    // exception -- so we check it here and fail gracefully instead.
    unsigned int input_index = opt.quick ? 0 : opt.input_index;
    if (input_index >= n_inputs) {
        throw std::invalid_argument(
            "--index " + std::to_string(input_index) + " is out of range: this transaction has " +
            std::to_string(n_inputs) + " input(s) (valid indices: 0.." +
            std::to_string(n_inputs == 0 ? 0 : n_inputs - 1) + ")");
    }

    std::vector<btck::TransactionOutput> spent_outputs;

    if (opt.quick) {
        // The single synthesized input spends exactly the scriptPubkey
        // under test, so provide it as the spent-outputs list too (needed
        // for TAPROOT / WITNESS_V1 verification paths).
        spent_outputs.emplace_back(spk, opt.amount);
    } else if (!opt.spent_outputs.empty()) {
        // btck_precomputed_transaction_data_create does
        // `assert(spent_outputs_len == tx.vin.size())` internally -- same
        // hard-abort concern as above, so validate the count ourselves
        // before constructing PrecomputedTransactionData.
        if (opt.spent_outputs.size() != n_inputs) {
            throw std::invalid_argument(
                "this transaction has " + std::to_string(n_inputs) + " input(s), but " +
                std::to_string(opt.spent_outputs.size()) + " --spent-output entrie(s) were given. "
                "libbitcoinkernel's PrecomputedTransactionData requires exactly one spent output "
                "per transaction input, supplied in input order (index 0 first).");
        }
        for (const auto& s : opt.spent_outputs) {
            btck::ScriptPubkey out_spk{hexutil::to_bytes(s.script_hex)};
            spent_outputs.emplace_back(out_spk, s.amount);
        }
    } else if (n_inputs == 1) {
        // Common case: debugging a single-input transaction. The only
        // spent output is exactly the scriptPubkey/amount already
        // supplied for the input under test, so build the precomputed
        // data automatically instead of forcing the user to repeat
        // themselves on the command line.
        std::cout << color::dim(
            "note: no --spent-output given; this transaction has a single input, "
            "so using --scriptpubkey/--amount as the sole spent output.") << "\n";
        spent_outputs.emplace_back(spk, opt.amount);
    }
    // else: multiple inputs and nothing supplied. Leave spent_outputs
    // empty; this is fine unless the verification flags require TAPROOT,
    // in which case we surface a clear hint after Verify() returns below.

    std::optional<btck::PrecomputedTransactionData> txdata;
    if (!spent_outputs.empty()) txdata.emplace(tx, spent_outputs);

    auto flags = parse_flags(opt.flags_str);

    try {
        btck::ScriptTraceSetCallback(std::make_unique<Tracer>(Tracer{frames}));
    } catch (const std::runtime_error& e) {
        std::cerr << "error: " << e.what() << "\n";
        std::cerr << "Rebuild libbitcoinkernel with -DENABLE_SCRIPT_TRACE=ON to use this debugger.\n";
        std::exit(1);
    }

    RunResult result;
    result.success = spk.Verify(
        /*amount=*/opt.amount,
        /*tx_to=*/tx,
        /*precomputed_txdata=*/txdata ? &*txdata : nullptr,
        /*input_index=*/input_index,
        /*flags=*/flags,
        /*status=*/result.status);

    btck::ScriptTraceUnsetCallback();

    if (!result.success && result.status == btck::ScriptVerifyStatus::ERROR_SPENT_OUTPUTS_REQUIRED) {
        std::cout << color::yellow(
            "hint: the active verification flags include TAPROOT, which requires the full set "
            "of spent outputs (one per transaction input, in order) to be supplied via "
            "--spent-output -- even when the script being debugged isn't itself a taproot script. "
            "This transaction has " + std::to_string(n_inputs) + " input(s); pass " +
            std::to_string(n_inputs) + " --spent-output <scriptpubkey_hex>:<amount> entries in "
            "input order, or narrow --flags to exclude taproot (e.g. --flags p2sh,dersig,witness) "
            "if you only need to debug pre-taproot verification.") << "\n";
    }

    return result;
}

// =====================================================================
// Interactive / batch debugger
// =====================================================================

class Debugger {
public:
    Debugger(std::vector<btck::ScriptTraceFrame> frames, RunResult result, bool visual)
        : m_frames(std::move(frames)), m_result(result), m_runs(group_runs(m_frames)), m_visual(visual)
    {
        if (!m_runs.empty()) m_cursor = m_runs.front().begin_idx;
    }

    void run_batch_file(const std::string& path)
    {
        std::ifstream in(path);
        if (!in) { std::cout << "cannot open batch file: " << path << "\n"; return; }
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty() || line[0] == '#') continue;
            std::cout << color::dim("(batch) " + line) << "\n";
            if (!dispatch(line)) break;
        }
    }

    void export_json(const std::string& path) const
    {
        std::ofstream out(path);
        if (!out) { std::cout << "cannot open export file: " << path << "\n"; return; }
        out << "{\n";
        out << "  \"success\": " << (m_result.success ? "true" : "false") << ",\n";
        out << "  \"status\": \"" << status_str(m_result.status) << "\",\n";
        out << "  \"frames\": [\n";
        for (size_t i = 0; i < m_frames.size(); ++i) {
            const auto& f = m_frames[i];
            out << "    {\n";
            out << "      \"index\": " << i << ",\n";
            out << "      \"kind\": \"" << kind_str(f.m_kind) << "\",\n";
            out << "      \"opcode\": " << static_cast<int>(f.m_opcode) << ",\n";
            out << "      \"opcode_name\": \"" << opnames::name(f.m_opcode) << "\",\n";
            out << "      \"op_pos\": " << f.m_opcode_pos << ",\n";
            out << "      \"exec\": " << (f.m_exec ? "true" : "false") << ",\n";
            out << "      \"op_count\": " << f.m_op_count << ",\n";
            out << "      \"sig_version\": \"" << sigversion_str(f.m_sig_version) << "\",\n";
            out << "      \"codeseparator_pos\": " << f.m_codeseparator_pos << ",\n";
            out << "      \"script_error\": " << f.m_script_error << ",\n";
            out << "      \"stack\": [";
            for (size_t j = 0; j < f.m_stack.size(); ++j) {
                out << "\"" << hexutil::from_bytes(f.m_stack[j]) << "\"" << (j + 1 < f.m_stack.size() ? ", " : "");
            }
            out << "],\n";
            out << "      \"altstack\": [";
            for (size_t j = 0; j < f.m_altstack.size(); ++j) {
                out << "\"" << hexutil::from_bytes(f.m_altstack[j]) << "\"" << (j + 1 < f.m_altstack.size() ? ", " : "");
            }
            out << "]\n";
            out << "    }" << (i + 1 < m_frames.size() ? "," : "") << "\n";
        }
        out << "  ]\n";
        out << "}\n";
        std::cout << "exported " << m_frames.size() << " frame(s) to " << path << "\n";
    }

    void repl()
    {
        print_summary();
        std::cout << "Type 'help' for a list of commands.\n";
        LineEditor editor(color::bold("(sdb) "));
        while (true) {
            auto line = editor.read_line();
            if (!line) { std::cout << "\n"; break; }
            if (line->empty()) continue;
            if (!dispatch(*line)) break;
        }
    }

    bool dispatch(const std::string& line)
    {
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        // Commands that render the dashboard themselves (via stop_here()
        // or a direct redraw_frame() call) manage m_last_render_lines on
        // their own. Everything else invalidates our in-place-redraw
        // anchor, since its output isn't accounted for in that line
        // count and must never be silently erased by a later step/play.
        static const std::set<std::string> nav_cmds = {
            "step", "n", "next", "back", "p", "prev", "goto", "g", "select",
            "continue", "c", "reverse-continue", "rc", "play",
            "view", "dash", "dashboard"
        };
        if (nav_cmds.find(cmd) == nav_cmds.end()) {
            m_last_render_lines = 0;
        }

        try {
            if (cmd == "help" || cmd == "h" || cmd == "?") cmd_help();
            else if (cmd == "quit" || cmd == "q" || cmd == "exit") return false;
            else if (cmd == "summary") print_summary();
            else if (cmd == "runs") cmd_runs();
            else if (cmd == "select") cmd_select(iss);
            else if (cmd == "step" || cmd == "n" || cmd == "next") cmd_step(1);
            else if (cmd == "back" || cmd == "p" || cmd == "prev") cmd_step(-1);
            else if (cmd == "goto" || cmd == "g") cmd_goto(iss);
            else if (cmd == "list" || cmd == "l") cmd_list(iss);
            else if (cmd == "info" || cmd == "i") { print_frame(m_cursor); print_watches(); }
            else if (cmd == "stack") print_stack(m_cursor, false);
            else if (cmd == "altstack") print_stack(m_cursor, true);
            else if (cmd == "disasm" || cmd == "d") print_disasm(m_cursor);
            else if (cmd == "view" || cmd == "dash" || cmd == "dashboard") redraw_frame([&]{ render_dashboard(m_cursor); });
            else if (cmd == "viz") cmd_viz(iss);
            else if (cmd == "legend") cmd_legend();
            else if (cmd == "break" || cmd == "b") cmd_break(iss);
            else if (cmd == "unbreak") cmd_unbreak(iss);
            else if (cmd == "breakpoints") cmd_list_breakpoints();
            else if (cmd == "continue" || cmd == "c") cmd_continue(1);
            else if (cmd == "reverse-continue" || cmd == "rc") cmd_continue(-1);
            else if (cmd == "watch") cmd_watch(iss);
            else if (cmd == "unwatch") cmd_unwatch(iss);
            else if (cmd == "watches") print_watches();
            else if (cmd == "find") cmd_find(iss);
            else if (cmd == "diff") cmd_diff(iss);
            else if (cmd == "timeline" || cmd == "sparkline") cmd_timeline();
            else if (cmd == "export") cmd_export(iss);
            else if (cmd == "color") cmd_color(iss);
            else if (cmd == "why") cmd_why();
            else if (cmd == "explain") cmd_explain(iss);
            else if (cmd == "play") cmd_play(iss);
            else if (cmd == "recognize" || cmd == "pattern") cmd_recognize();
            else if (cmd == "redraw") cmd_redraw(iss);
            else std::cout << "unknown command: " << cmd << " (try 'help')\n";
        } catch (const std::exception& e) {
            std::cout << color::red(std::string("error: ") + e.what()) << "\n";
        }
        return true;
    }

private:
    std::vector<btck::ScriptTraceFrame> m_frames;
    RunResult m_result;
    std::vector<Run> m_runs;
    size_t m_cursor = 0;
    bool m_visual = true;

    // In-place ("movie-style") redraw state: how many lines the last
    // dashboard render produced, so the next one can move the cursor up
    // and overwrite it instead of scrolling. See redraw_frame().
    bool m_redraw_inplace = true;
    size_t m_last_render_lines = 0;

    struct Breakpoint {
        bool by_opcode = false;
        uint8_t opcode = 0;
        bool by_index = false;
        uint32_t op_pos = 0;
        std::optional<Condition> cond;
        std::string label;
    };
    std::vector<Breakpoint> m_breakpoints;
    std::vector<size_t> m_watch_slots;

    bool use_color() const { return color::g_enabled; }

    // ---- in-place redraw ----

    // Captures everything render_fn() prints to std::cout, then -- if
    // in-place redraw is enabled and we're on a real terminal -- moves
    // the cursor up over the previous render (m_last_render_lines) and
    // clears to end of screen before printing the new one, so stepping
    // and playback feel like scrubbing a single frame in place rather
    // than scrolling a transcript. Falls back to a plain append when
    // redraw is disabled or stdout isn't a TTY (e.g. piped/logged runs).
    void redraw_frame(const std::function<void()>& render_fn)
    {
        std::ostringstream oss;
        std::streambuf* old_buf = std::cout.rdbuf(oss.rdbuf());
        try {
            render_fn();
        } catch (...) {
            std::cout.rdbuf(old_buf);
            throw;
        }
        std::cout.rdbuf(old_buf);
        std::string text = oss.str();

        bool can_inplace = m_redraw_inplace && ::isatty(STDOUT_FILENO);
        if (can_inplace && m_last_render_lines > 0) {
            std::cout << "\x1b[" << m_last_render_lines << "A" << "\x1b[J";
        }
        std::cout << text << std::flush;
        m_last_render_lines = can_inplace ? static_cast<size_t>(std::count(text.begin(), text.end(), '\n')) : 0;
    }

    // Stops the cursor at the current frame: renders the dashboard (via
    // in-place redraw) if visualization is on, otherwise falls back to
    // plain-text frame info. `note`, if given, is an extra line (e.g. a
    // breakpoint-hit message) shown immediately above the render, bundled
    // into the same redraw so it survives being erased by later steps.
    void stop_here(const std::string& note = "")
    {
        if (m_visual) {
            redraw_frame([&]{
                if (!note.empty()) std::cout << note << "\n";
                render_dashboard(m_cursor);
            });
        } else {
            if (!note.empty()) std::cout << note << "\n";
            print_frame(m_cursor);
            print_watches();
        }
    }

    // ---- summary / info ----

    void print_summary() const
    {
        std::string banner = m_result.success ? "  \u2713 VALID  " : "  \u2717 INVALID  ";
        std::cout << (use_color() ? (m_result.success ? color::green(banner) : color::red(banner)) : banner) << "\n";
        std::cout << color::bold("=== Verification result ===") << "\n";
        std::cout << "  success: " << (m_result.success ? color::green("true") : color::red("false")) << "\n";
        std::cout << "  status:  " << status_str(m_result.status) << "\n";
        std::cout << "  captured frames: " << m_frames.size()
                   << "  (" << m_runs.size() << " script run(s))\n";
        for (size_t i = 0; i < m_runs.size(); ++i) {
            const auto& r = m_runs[i];
            const auto& end_frame = m_frames[r.end_idx];
            std::cout << "    run " << i << ": frames [" << r.begin_idx << ".." << r.end_idx << "]"
                      << "  sigversion=" << sigversion_str(end_frame.m_sig_version)
                      << "  final_script_error=" << end_frame.m_script_error << "\n";
        }
        std::cout << "  visualization: " << (m_visual ? "on" : "off")
                   << "  (toggle: 'viz on|off', one-off: 'view', color key: 'legend')\n";
    }

    size_t run_index_of(size_t frame_idx) const
    {
        for (size_t i = 0; i < m_runs.size(); ++i) {
            if (frame_idx >= m_runs[i].begin_idx && frame_idx <= m_runs[i].end_idx) return i;
        }
        return m_runs.empty() ? 0 : m_runs.size() - 1;
    }

    void print_frame(size_t idx) const
    {
        if (idx >= m_frames.size()) { std::cout << "no such frame\n"; return; }
        const auto& f = m_frames[idx];
        std::string kind_colored = std::string(kind_str(f.m_kind));
        if (use_color()) {
            if (f.m_kind == btck::ScriptTraceFrameKind::BEGIN) kind_colored = color::cyan(kind_colored);
            else if (f.m_kind == btck::ScriptTraceFrameKind::END) kind_colored = color::magenta(kind_colored);
            else kind_colored = color::yellow(kind_colored);
        }
        std::cout << color::bold("Frame #" + std::to_string(idx)) << " [" << kind_colored << "]"
                  << "  run=" << run_index_of(idx)
                  << "  op_pos=" << f.m_opcode_pos
                  << "  opcode=" << opnames::name(f.m_opcode)
                  << "  exec=" << (f.m_exec ? "yes" : "no")
                  << "  op_count=" << f.m_op_count
                  << "  sigversion=" << sigversion_str(f.m_sig_version)
                  << "\n";
        std::cout << "  codeseparator_pos: ";
        if (f.m_codeseparator_pos == 0xFFFFFFFFu) std::cout << "none"; else std::cout << f.m_codeseparator_pos;
        std::cout << "\n";
        if (f.m_tapleaf_hash) {
            std::cout << "  tapleaf_hash: "
                      << hexutil::from_bytes(std::span<const unsigned char>(f.m_tapleaf_hash->data(), 32)) << "\n";
        }
        if (f.m_kind == btck::ScriptTraceFrameKind::END) {
            bool ok = (f.m_script_error == 0);
            std::string errstr = "  script_error: " + std::to_string(f.m_script_error);
            std::cout << (use_color() ? (ok ? color::green(errstr) : color::red(errstr)) : errstr) << "\n";
        }
        std::cout << "  stack depth: " << f.m_stack.size() << "  altstack depth: " << f.m_altstack.size() << "\n";
    }

    static std::optional<int64_t> try_decode_scriptnum(const std::vector<unsigned char>& v)
    {
        if (v.empty()) return 0;
        if (v.size() > 8) return std::nullopt;
        int64_t result = 0;
        for (size_t i = 0; i < v.size(); ++i) result |= static_cast<int64_t>(v[i]) << (8 * i);
        if (v.back() & 0x80) {
            result &= ~(static_cast<int64_t>(0x80) << (8 * (v.size() - 1)));
            result = -result;
        }
        return result;
    }

    void print_stack(size_t idx, bool alt) const
    {
        if (idx >= m_frames.size()) { std::cout << "no such frame\n"; return; }
        const auto& items = alt ? m_frames[idx].m_altstack : m_frames[idx].m_stack;
        std::cout << (alt ? "altstack" : "stack") << " at frame #" << idx
                  << " (top last, " << items.size() << " item(s)):\n";
        if (items.empty()) { std::cout << "  (empty)\n"; return; }
        for (size_t i = 0; i < items.size(); ++i) {
            bool is_top = (i + 1 == items.size());
            std::string line = "  [" + std::to_string(i) + "] " + hexutil::from_bytes(items[i]) +
                                "  (" + std::to_string(items[i].size()) + " bytes)";
            if (auto n = try_decode_scriptnum(items[i])) line += "  = " + std::to_string(*n);
            std::cout << (use_color() && is_top ? color::bold(line) : line) << (is_top ? "  <- top" : "") << "\n";
        }
    }

    void print_disasm(size_t idx) const
    {
        if (idx >= m_frames.size()) { std::cout << "no such frame\n"; return; }
        const auto& f = m_frames[idx];
        auto ops = disassemble(f.m_script);
        std::cout << "script (" << f.m_script.size() << " bytes, " << ops.size() << " op(s)):\n";
        for (size_t pos = 0; pos < ops.size(); ++pos) {
            const auto& op = ops[pos];
            bool current = (op.op_index == f.m_opcode_pos) && f.m_kind == btck::ScriptTraceFrameKind::STEP;
            bool exec_hint = current ? f.m_exec : true;
            std::cout << format_disasm_op(ops, pos, current, exec_hint, use_color()) << "\n";
        }
    }

    // ---- dashboard rendering ----

    void render_status_header(size_t idx) const
    {
        const auto& f = m_frames[idx];
        std::string kind = kind_str(f.m_kind);
        if (use_color()) {
            if (f.m_kind == btck::ScriptTraceFrameKind::BEGIN) kind = color::cyan(kind);
            else if (f.m_kind == btck::ScriptTraceFrameKind::END) kind = (f.m_script_error == 0) ? color::green(kind) : color::red(kind);
            else kind = color::yellow(kind);
        }
        std::cout << color::bold("Frame " + std::to_string(idx)) << "/" << (m_frames.empty() ? 0 : m_frames.size() - 1)
                  << "  [" << kind << "]"
                  << "  run " << run_index_of(idx) << "/" << (m_runs.empty() ? 0 : m_runs.size() - 1)
                  << "  " << opcategory::colorize(opnames::name(f.m_opcode), f.m_opcode)
                  << "  op_pos=" << f.m_opcode_pos
                  << "  op_count=" << f.m_op_count
                  << "  exec=" << (f.m_exec ? color::green("yes") : color::dim("no"))
                  << "  sigver=" << sigversion_str(f.m_sig_version)
                  << "\n";
        if (f.m_codeseparator_pos != 0xFFFFFFFFu) {
            std::cout << "  codeseparator_pos=" << f.m_codeseparator_pos;
            if (f.m_tapleaf_hash) {
                std::cout << "  tapleaf="
                          << hexutil::from_bytes(std::span<const unsigned char>(f.m_tapleaf_hash->data(), 8)) << "...";
            }
            std::cout << "\n";
        }
        if (f.m_kind == btck::ScriptTraceFrameKind::END) {
            bool ok = (f.m_script_error == 0);
            std::string msg = "script_error: " + std::to_string(f.m_script_error) + (ok ? "  (OK)" : "  (FAILED)");
            std::cout << "  " << (use_color() ? (ok ? color::green(msg) : color::red(msg)) : msg) << "\n";
        }
    }

    std::string progress_bar(size_t pos_in_run, size_t run_len, size_t bar_width = 24) const
    {
        if (run_len <= 1) return "[" + std::string(bar_width, '=') + "]";
        size_t filled = static_cast<size_t>(std::llround(
            static_cast<double>(pos_in_run) / static_cast<double>(run_len - 1) * static_cast<double>(bar_width)));
        filled = std::min(filled, bar_width);
        std::string bar = "[";
        bar += std::string(filled, '=');
        if (filled < bar_width) {
            bar += ">";
            bar += std::string(bar_width - filled - 1, ' ');
        }
        bar += "]";
        return bar;
    }

    std::string format_dashboard_op(const std::vector<DisasmOp>& ops, size_t pos, bool current, bool exec_hint) const
    {
        const DisasmOp& op = ops[pos];
        std::string indent = branch_prefix(ops, pos);
        std::string marker = current ? "\u25b6 " : "  ";
        if (use_color() && current) marker = color::green("\u25b6") + " ";

        std::string idx_field = "[" + std::to_string(op.op_index) + "]";

        std::string body;
        if (op.opcode >= 0x01 && op.opcode <= 0x4e) {
            std::string hex = hex_preview(op.push_data);
            std::string ascii = ascii_preview(op.push_data);
            std::string plain = "PUSH(" + std::to_string(op.push_data.size()) + "B): " + hex;
            if (!ascii.empty()) plain += "  '" + ascii + "'";
            if (op.truncated) plain += "  [TRUNCATED]";
            body = use_color() ? color::cyan(plain) : plain;
        } else {
            body = opcategory::colorize(opnames::name(op.opcode), op.opcode);
        }

        std::string line = marker + idx_field + " " + indent + body;
        if (current && !exec_hint) {
            std::string note = " (skipped: inactive branch)";
            line += use_color() ? color::dim(note) : note;
        }
        return line;
    }

    void render_script_box(size_t idx, size_t total_width) const
    {
        const auto& f = m_frames[idx];
        auto ops = disassemble(f.m_script);
        bool is_step = (f.m_kind == btck::ScriptTraceFrameKind::STEP);
        size_t current = f.m_opcode_pos;

        std::string title = std::string("Script (run ") + std::to_string(run_index_of(idx)) + ", " +
                             sigversion_str(f.m_sig_version) + ", " + std::to_string(f.m_script.size()) + " bytes)";
        ui::Box box(title, total_width);

        if (ops.empty()) {
            box.add_line(use_color() ? color::dim("(empty script)") : "(empty script)");
        } else {
            constexpr long context = 4;
            long lo, hi;
            if (is_step) {
                lo = static_cast<long>(current) - context;
                hi = static_cast<long>(current) + context;
            } else if (f.m_kind == btck::ScriptTraceFrameKind::BEGIN) {
                lo = 0;
                hi = 2 * context;
            } else { // END
                hi = static_cast<long>(ops.size()) - 1;
                lo = hi - 2 * context;
            }
            lo = std::max<long>(lo, 0);
            hi = std::min<long>(hi, static_cast<long>(ops.size()) - 1);

            if (lo > 0) {
                std::string msg = "\u22ee " + std::to_string(lo) + " earlier op(s)";
                box.add_line(use_color() ? color::dim(msg) : msg);
            }
            for (long i = lo; i <= hi; ++i) {
                bool is_current = is_step && static_cast<size_t>(i) == current;
                box.add_line(format_dashboard_op(ops, static_cast<size_t>(i), is_current, is_current ? f.m_exec : true));
            }
            if (hi < static_cast<long>(ops.size()) - 1) {
                std::string msg = "\u22ee " + std::to_string(static_cast<long>(ops.size()) - 1 - hi) + " more op(s)";
                box.add_line(use_color() ? color::dim(msg) : msg);
            }
        }

        for (const auto& line : box.render()) std::cout << line << "\n";
    }

    // Returns "+new", "~chg", or "" describing how items[i] at frame idx
    // compares to the same-index item at the previous frame's stack.
    static std::string diff_tag(const std::vector<std::vector<unsigned char>>& prev,
                                 const std::vector<std::vector<unsigned char>>& cur,
                                 size_t i)
    {
        if (i >= prev.size()) return "+new";
        if (i < cur.size() && prev[i] != cur[i]) return "~chg";
        return "";
    }

    // Items present at idx-1 but no longer present at idx (from the top
    // down) -- i.e. what this frame's op just popped/consumed.
    std::vector<std::vector<unsigned char>> popped_since_prev(size_t idx, bool alt) const
    {
        std::vector<std::vector<unsigned char>> out;
        if (idx == 0) return out;
        const auto& prev = alt ? m_frames[idx - 1].m_altstack : m_frames[idx - 1].m_stack;
        const auto& cur  = alt ? m_frames[idx].m_altstack     : m_frames[idx].m_stack;
        if (cur.size() >= prev.size()) return out;
        for (size_t i = cur.size(); i < prev.size(); ++i) out.push_back(prev[i]);
        return out;
    }

    void render_stack_box(size_t idx, bool alt, size_t total_width) const
    {
        const auto& f = m_frames[idx];
        const auto& items = alt ? f.m_altstack : f.m_stack;
        const auto& prev_items = (idx > 0) ? (alt ? m_frames[idx - 1].m_altstack : m_frames[idx - 1].m_stack)
                                            : items; // no diff available at frame 0

        std::string title = std::string(alt ? "Altstack" : "Stack") + " (depth " + std::to_string(items.size()) + ")";
        ui::Box box(title, total_width);

        auto popped = popped_since_prev(idx, alt);
        if (!popped.empty()) {
            std::string line = "\u2193 popped: ";
            for (size_t i = 0; i < popped.size(); ++i) {
                line += hex_preview(popped[i], 12);
                if (i + 1 < popped.size()) line += ", ";
            }
            box.add_line(use_color() ? color::dim(line) : line);
        }

        if (items.empty()) {
            box.add_line(use_color() ? color::dim("(empty)") : "(empty)");
        } else {
            for (size_t rev = 0; rev < items.size(); ++rev) {
                size_t i = items.size() - 1 - rev;
                bool is_top = (i + 1 == items.size());
                const auto& item = items[i];

                std::string hex = hex_preview(item, 20);
                std::string ascii = ascii_preview(item);
                std::string ty = type_guess(item);
                std::string line = "[" + std::to_string(i) + "] " + hex + "  (" + std::to_string(item.size()) + "B)";
                if (auto n = try_decode_scriptnum(item)) line += "  =" + std::to_string(*n);
                if (!ascii.empty()) line += "  '" + ascii + "'";
                if (!ty.empty()) line += "  \u27f6 " + ty;

                std::string tag = (idx > 0) ? diff_tag(prev_items, items, i) : "";
                if (!tag.empty()) {
                    line += "  ";
                    line += use_color()
                        ? (tag == "+new" ? color::green(tag) : color::yellow(tag))
                        : tag;
                }

                bool watched = !alt && std::find(m_watch_slots.begin(), m_watch_slots.end(), i) != m_watch_slots.end();

                if (is_top) {
                    line += "  \u25c4 top";
                    line = use_color() ? color::bold(line) : line;
                } else if (watched) {
                    line = use_color() ? color::yellow(line) : line;
                }
                box.add_line(line);
            }
        }

        for (const auto& line : box.render()) std::cout << line << "\n";
    }

    void render_minimap(size_t idx) const
    {
        if (m_runs.size() <= 1) return; // not interesting for a single run
        static const char* labels[] = {"run0", "run1", "run2", "run3", "run4"};
        for (size_t ri = 0; ri < m_runs.size(); ++ri) {
            const Run& r = m_runs[ri];
            size_t run_len = r.end_idx - r.begin_idx + 1;
            bool is_here = (idx >= r.begin_idx && idx <= r.end_idx);
            size_t pos_in_run = is_here ? idx - r.begin_idx : (idx > r.end_idx ? run_len - 1 : 0);
            bool done = idx > r.end_idx;

            std::string label = ri < 5 ? labels[ri] : ("run" + std::to_string(ri));
            std::string bar = done ? progress_bar(run_len - 1, run_len, 24) : progress_bar(pos_in_run, run_len, 24);
            std::string status = done ? "done" : (is_here ? ("frame " + std::to_string(pos_in_run + 1) + "/" + std::to_string(run_len)) : "pending");
            std::string sv = sigversion_str(m_frames[r.end_idx].m_sig_version);

            std::string line = label + " " + bar + "  " + status + "  " + sv;
            if (is_here) line += "  \u2190 you are here";

            if (use_color()) {
                if (is_here) line = color::bold(line);
                else if (done) line = color::dim(line);
            }
            std::cout << "  " << line << "\n";
        }
        std::cout << "\n";
    }

    // Notes the outcome of a just-executed OP_CHECKSIG-family opcode by
    // comparing this frame's stack to the previous frame's -- these ops
    // pop 2 (or 3, for CHECKSIGADD) args and push a result, so the top of
    // the *current* stack tells you pass/fail without re-running anything.
    void render_checksig_note(size_t idx) const
    {
        if (idx == 0) return;
        const auto& prev = m_frames[idx - 1];
        if (prev.m_kind != btck::ScriptTraceFrameKind::STEP) return;
        bool is_checksig = prev.m_opcode == 0xac || prev.m_opcode == 0xad || prev.m_opcode == 0xba;
        if (!is_checksig || !prev.m_exec) return;

        const auto& f = m_frames[idx];
        if (f.m_stack.empty()) return;
        const auto& top = f.m_stack.back();

        bool truthy = false;
        for (unsigned char b : top) if (b != 0) { truthy = true; break; }
        // CHECKSIGADD pushes an incremented count, not a bool; treat any
        // nonzero as "counted" rather than claiming pass/fail for it.
        std::string verb = (prev.m_opcode == 0xba) ? "count now" : (truthy ? "signature OK" : "signature check FAILED");
        std::string msg = "  " + std::string(opnames::name(prev.m_opcode)) + " result: " + verb;
        std::cout << (use_color() ? (truthy ? color::green(msg) : color::red(msg)) : msg) << "\n";
    }

    // Recognizes common consensus-level script templates for the script
    // at frame idx and prints a one-line banner. Returns whether anything
    // was printed, so callers (the dashboard and the standalone
    // 'recognize' command) can show a "nothing found" fallback.
    bool render_pattern_banner(size_t idx) const
    {
        if (idx >= m_frames.size()) return false;
        const auto& f = m_frames[idx];
        auto ops = disassemble(f.m_script);
        if (ops.empty()) return false;

        if (auto tpl = scripttpl::recognize_common_template(ops)) {
            std::string line = "\u25c6 Recognized template: " + *tpl;
            std::cout << (use_color() ? color::magenta(line) : line) << "\n";
            return true;
        }
        return false;
    }

    void render_dashboard(size_t idx) const
    {
        if (idx >= m_frames.size()) { std::cout << "no such frame\n"; return; }
        size_t width = static_cast<size_t>(std::clamp(termsize::columns(), 60, 112));

        render_minimap(idx);
        render_status_header(idx);
        render_pattern_banner(idx);
        render_checksig_note(idx);

        if (!m_runs.empty()) {
            size_t ri = run_index_of(idx);
            const Run& r = m_runs[ri];
            size_t pos_in_run = idx - r.begin_idx;
            size_t run_len = r.end_idx - r.begin_idx + 1;
            std::cout << "  " << progress_bar(pos_in_run, run_len) << "  frame " << (pos_in_run + 1)
                      << "/" << run_len << " within this run\n";
        }
        std::cout << "\n";

        render_script_box(idx, width);
        std::cout << "\n";
        render_stack_box(idx, /*alt=*/false, width);
        if (!m_frames[idx].m_altstack.empty()) {
            std::cout << "\n";
            render_stack_box(idx, /*alt=*/true, width);
        }

        print_watches();
    }

    void cmd_viz(std::istringstream& iss)
    {
        std::string mode;
        if (!(iss >> mode)) { std::cout << "usage: viz on|off\n"; return; }
        if (mode == "on") m_visual = true;
        else if (mode == "off") m_visual = false;
        else { std::cout << "usage: viz on|off\n"; return; }
        m_last_render_lines = 0; // stale under the new mode either way
        std::cout << "visualization " << (m_visual ? "enabled" : "disabled") << "\n";
    }

    void cmd_redraw(std::istringstream& iss)
    {
        std::string mode;
        if (!(iss >> mode)) { std::cout << "usage: redraw on|off\n"; return; }
        if (mode == "on") m_redraw_inplace = true;
        else if (mode == "off") { m_redraw_inplace = false; m_last_render_lines = 0; }
        else { std::cout << "usage: redraw on|off\n"; return; }
        std::cout << "in-place redraw " << (m_redraw_inplace ? "enabled" : "disabled") << "\n";
    }

    void cmd_legend() const
    {
        if (!use_color()) { std::cout << "(color is off; the legend has no visible effect right now)\n"; return; }
        std::cout << "opcode color legend:\n";
        std::cout << "  " << color::cyan("push / data") << "\n";
        std::cout << "  " << color::yellow("flow control (IF/ELSE/ENDIF/VERIFY/RETURN/CODESEPARATOR)") << "\n";
        std::cout << "  " << color::blue("stack & splice ops (DUP/SWAP/SIZE/...)") << "\n";
        std::cout << "  " << color::green("arithmetic & equality") << "\n";
        std::cout << "  " << color::magenta("crypto (HASH*/CHECKSIG*)") << "\n";
        std::cout << "  " << color::red("locktime (CLTV/CSV) & disabled opcodes") << "\n";
        std::cout << "  " << color::dim("reserved / unassigned") << "\n";
    }

    // ---- navigation ----

    void cmd_runs() const
    {
        for (size_t i = 0; i < m_runs.size(); ++i) {
            const auto& r = m_runs[i];
            std::cout << "run " << i << ": frames [" << r.begin_idx << ".." << r.end_idx << "]"
                      << ", " << (r.end_idx - r.begin_idx + 1) << " frame(s)"
                      << ", sigversion=" << sigversion_str(m_frames[r.end_idx].m_sig_version) << "\n";
        }
        if (m_runs.empty()) std::cout << "(no runs captured)\n";
    }

    void cmd_select(std::istringstream& iss)
    {
        size_t n;
        if (!(iss >> n) || n >= m_runs.size()) {
            m_last_render_lines = 0;
            std::cout << "usage: select <run#>\n";
            return;
        }
        m_cursor = m_runs[n].begin_idx;
        stop_here();
    }

    void cmd_step(int dir)
    {
        if (m_frames.empty()) { m_last_render_lines = 0; std::cout << "no frames\n"; return; }
        if (dir > 0 && m_cursor + 1 < m_frames.size()) ++m_cursor;
        else if (dir < 0 && m_cursor > 0) --m_cursor;
        else {
            m_last_render_lines = 0;
            std::cout << (dir > 0 ? "already at last frame\n" : "already at first frame\n");
            return;
        }
        stop_here();
    }

    static bool key_waiting()
    {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        struct timeval tv{0, 0};
        return ::select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv) > 0;
    }

    // Auto-steps forward frame-by-frame with a short delay, stopping on
    // the next breakpoint hit, end of trace, or Enter (drained but not
    // otherwise interpreted). Each frame reuses stop_here(), so with
    // in-place redraw on this genuinely animates: frame N erases frame
    // N-1 and paints itself in the same screen region instead of
    // scrolling. No-op if stdin isn't a real TTY.
    //
    // Note: the redraw's cursor tracking (key_waiting()/single-byte read)
    // assumes the terminal is already in raw/non-canonical mode.
    // LineEditor only enables raw mode for the duration of its own
    // read_line() call, so between REPL prompts the terminal is back in
    // canonical mode -- meaning you press Enter (not just any key) to
    // interrupt playback. If you want true any-key interrupt, expose
    // LineEditor's raw-mode toggle publicly and wrap this loop with it.
    void cmd_play(std::istringstream& iss)
    {
        int delay_ms = 200;
        iss >> delay_ms;
        delay_ms = std::max(10, delay_ms);

        m_last_render_lines = 0;

        if (!::isatty(STDIN_FILENO)) {
            std::cout << "'play' requires an interactive terminal\n";
            return;
        }
        std::cout << color::dim("playing at " + std::to_string(delay_ms) + "ms/frame -- press Enter to stop") << "\n";

        while (m_cursor + 1 < m_frames.size()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
            ++m_cursor;

            bool hit = false;
            for (const auto& bp : m_breakpoints) {
                if (breakpoint_hits(bp, m_cursor)) { hit = true; break; }
            }

            if (hit) {
                stop_here("\a" + color::yellow("breakpoint hit during play"));
                m_last_render_lines = 0; // leave this frame visible
                return;
            }

            stop_here();

            if (key_waiting()) {
                char discard;
                (void)!::read(STDIN_FILENO, &discard, 1);
                m_last_render_lines = 0;
                std::cout << color::dim("(stopped)") << "\n";
                return;
            }
        }
        m_last_render_lines = 0;
        std::cout << color::dim("(reached end of trace)") << "\n";
    }

    void cmd_goto(std::istringstream& iss)
    {
        size_t n;
        if (!(iss >> n) || n >= m_frames.size()) {
            m_last_render_lines = 0;
            std::cout << "usage: goto <frame#> (0.." << (m_frames.empty() ? 0 : m_frames.size() - 1) << ")\n";
            return;
        }
        m_cursor = n;
        stop_here();
    }

    void cmd_list(std::istringstream& iss)
    {
        size_t window = 5;
        iss >> window;
        size_t lo = (m_cursor >= window) ? m_cursor - window : 0;
        size_t hi = std::min(m_frames.size(), m_cursor + window + 1);
        for (size_t i = lo; i < hi; ++i) {
            std::string prefix = (i == m_cursor) ? "-> " : "   ";
            std::string line = prefix + "#" + std::to_string(i) + " [" + kind_str(m_frames[i].m_kind) + "]" +
                                " op_pos=" + std::to_string(m_frames[i].m_opcode_pos) +
                                " " + opnames::name(m_frames[i].m_opcode);
            std::cout << (use_color() && i == m_cursor ? color::green(line) : line) << "\n";
        }
    }

    // ---- breakpoints ----

    static int resolve_opcode(const std::string& tok)
    {
        int by_name = opnames::lookup(tok);
        if (by_name >= 0) return by_name;
        try {
            size_t consumed = 0;
            int v = std::stoi(tok, &consumed, 16);
            if (consumed == tok.size() && v >= 0 && v <= 0xff) return v;
        } catch (...) {}
        return -1;
    }

    void cmd_break(std::istringstream& iss)
    {
        std::string kind;
        if (!(iss >> kind)) {
            std::cout << "usage: break opcode <name|hex> | break index <op_pos> | break if <expr>\n";
            return;
        }
        Breakpoint bp;
        if (kind == "opcode") {
            std::string tok;
            if (!(iss >> tok)) { std::cout << "usage: break opcode <name|hex>\n"; return; }
            int op = resolve_opcode(tok);
            if (op < 0) { std::cout << "unrecognized opcode: " << tok << "\n"; return; }
            bp.by_opcode = true;
            bp.opcode = static_cast<uint8_t>(op);
            bp.label = std::string("opcode ") + opnames::name(bp.opcode);
        } else if (kind == "index") {
            uint32_t pos;
            if (!(iss >> pos)) { std::cout << "usage: break index <op_pos>\n"; return; }
            bp.by_index = true;
            bp.op_pos = pos;
            bp.label = "index " + std::to_string(pos);
        } else if (kind == "if") {
            std::string rest;
            std::getline(iss, rest);
            size_t a = rest.find_first_not_of(' ');
            if (a == std::string::npos) { std::cout << "usage: break if <expr>\n"; return; }
            rest = rest.substr(a);
            auto cond = Condition::parse(rest);
            if (!cond) { std::cout << "could not parse condition: " << rest << "\n"; return; }
            bp.cond = cond;
            bp.label = "if " + rest;
        } else {
            int op = resolve_opcode(kind);
            if (op < 0) { std::cout << "usage: break opcode|index|if ...\n"; return; }
            bp.by_opcode = true;
            bp.opcode = static_cast<uint8_t>(op);
            bp.label = std::string("opcode ") + opnames::name(bp.opcode);
        }
        m_breakpoints.push_back(bp);
        std::cout << "breakpoint #" << (m_breakpoints.size() - 1) << " set: " << bp.label << "\n";
    }

    void cmd_unbreak(std::istringstream& iss)
    {
        size_t n;
        if (!(iss >> n) || n >= m_breakpoints.size()) { std::cout << "usage: unbreak <breakpoint#>\n"; return; }
        std::cout << "removed breakpoint: " << m_breakpoints[n].label << "\n";
        m_breakpoints.erase(m_breakpoints.begin() + static_cast<long>(n));
    }

    void cmd_list_breakpoints() const
    {
        if (m_breakpoints.empty()) { std::cout << "(no breakpoints)\n"; return; }
        for (size_t i = 0; i < m_breakpoints.size(); ++i) {
            std::cout << "  #" << i << "  " << m_breakpoints[i].label << "\n";
        }
    }

    bool breakpoint_hits(const Breakpoint& bp, size_t frame_idx) const
    {
        const auto& f = m_frames[frame_idx];
        if (bp.by_opcode) {
            return f.m_kind == btck::ScriptTraceFrameKind::STEP && f.m_opcode == bp.opcode;
        }
        if (bp.by_index) {
            return f.m_kind == btck::ScriptTraceFrameKind::STEP && f.m_opcode_pos == bp.op_pos;
        }
        if (bp.cond) {
            return bp.cond->eval(FrameView{f, frame_idx});
        }
        return false;
    }

    void cmd_continue(int dir)
    {
        if (m_breakpoints.empty()) { m_last_render_lines = 0; std::cout << "no breakpoints set; use 'break' first\n"; return; }
        if (m_frames.empty()) { m_last_render_lines = 0; std::cout << "no frames\n"; return; }

        if (dir > 0) {
            for (size_t i = m_cursor + 1; i < m_frames.size(); ++i) {
                for (const auto& bp : m_breakpoints) {
                    if (breakpoint_hits(bp, i)) {
                        m_cursor = i;
                        stop_here("\a" + color::yellow("breakpoint hit: " + bp.label));
                        return;
                    }
                }
            }
            m_cursor = m_frames.size() - 1;
        } else {
            for (size_t i = m_cursor; i-- > 0; ) {
                for (const auto& bp : m_breakpoints) {
                    if (breakpoint_hits(bp, i)) {
                        m_cursor = i;
                        stop_here("\a" + color::yellow("breakpoint hit (reverse): " + bp.label));
                        return;
                    }
                }
                if (i == 0) break;
            }
            m_cursor = 0;
        }
        stop_here(color::dim("reached " + std::string(dir > 0 ? "end" : "start") + " of trace without hitting a breakpoint"));
    }

    // ---- watches ----

    void cmd_watch(std::istringstream& iss)
    {
        size_t slot;
        if (!(iss >> slot)) { std::cout << "usage: watch <stack-slot-index>\n"; return; }
        if (std::find(m_watch_slots.begin(), m_watch_slots.end(), slot) == m_watch_slots.end()) {
            m_watch_slots.push_back(slot);
        }
        std::cout << "watching stack[" << slot << "]\n";
    }

    void cmd_unwatch(std::istringstream& iss)
    {
        size_t slot;
        if (!(iss >> slot)) { std::cout << "usage: unwatch <stack-slot-index>\n"; return; }
        m_watch_slots.erase(std::remove(m_watch_slots.begin(), m_watch_slots.end(), slot), m_watch_slots.end());
    }

    void print_watches() const
    {
        if (m_watch_slots.empty() || m_cursor >= m_frames.size()) return;
        const auto& stack = m_frames[m_cursor].m_stack;
        std::cout << "watches:\n";
        for (size_t slot : m_watch_slots) {
            std::cout << "  stack[" << slot << "] = ";
            if (slot < stack.size()) std::cout << hexutil::from_bytes(stack[slot]);
            else std::cout << "(out of range, depth=" << stack.size() << ")";
            std::cout << "\n";
        }
    }

    // ---- search / diff / timeline / export / color ----

    void cmd_find(std::istringstream& iss)
    {
        std::string hex;
        if (!(iss >> hex)) { std::cout << "usage: find <hex-bytes>\n"; return; }
        std::vector<unsigned char> needle = hexutil::to_uchar_bytes(hex);

        size_t hits = 0;
        for (size_t fi = 0; fi < m_frames.size(); ++fi) {
            for (bool alt : {false, true}) {
                const auto& items = alt ? m_frames[fi].m_altstack : m_frames[fi].m_stack;
                for (size_t si = 0; si < items.size(); ++si) {
                    if (items[si] == needle) {
                        std::cout << "  frame #" << fi << " " << (alt ? "altstack" : "stack") << "[" << si << "]\n";
                        ++hits;
                    }
                }
            }
        }
        std::cout << hits << " match(es)\n";
    }

    void cmd_diff(std::istringstream& iss)
    {
        size_t a, b;
        if (!(iss >> a >> b) || a >= m_frames.size() || b >= m_frames.size()) {
            std::cout << "usage: diff <frame#> <frame#>\n";
            return;
        }
        diff_one("stack", m_frames[a].m_stack, m_frames[b].m_stack, a, b);
        diff_one("altstack", m_frames[a].m_altstack, m_frames[b].m_altstack, a, b);
    }

    void diff_one(const char* label,
                  const std::vector<std::vector<unsigned char>>& sa,
                  const std::vector<std::vector<unsigned char>>& sb,
                  size_t a, size_t b) const
    {
        std::cout << label << ": frame #" << a << " (" << sa.size() << " item(s)) vs frame #" << b
                  << " (" << sb.size() << " item(s))\n";
        size_t n = std::max(sa.size(), sb.size());
        for (size_t i = 0; i < n; ++i) {
            bool has_a = i < sa.size(), has_b = i < sb.size();
            std::string av = has_a ? hexutil::from_bytes(sa[i]) : "(none)";
            std::string bv = has_b ? hexutil::from_bytes(sb[i]) : "(none)";
            if (has_a && has_b && sa[i] == sb[i]) {
                std::cout << "  [" << i << "] " << av << "\n";
            } else {
                std::string line = "  [" + std::to_string(i) + "] " + av + "  ->  " + bv;
                std::cout << (use_color() ? color::yellow(line) : line) << "\n";
            }
        }
    }

    void cmd_timeline() const
    {
        if (m_runs.empty()) { std::cout << "(no runs captured)\n"; return; }
        size_t ri = run_index_of(m_cursor);
        const Run& r = m_runs[ri];
        size_t max_depth = 0;
        for (size_t i = r.begin_idx; i <= r.end_idx; ++i) max_depth = std::max(max_depth, m_frames[i].m_stack.size());
        if (max_depth == 0) max_depth = 1;

        std::cout << "stack-depth timeline for run " << ri
                   << " (frames [" << r.begin_idx << ".." << r.end_idx << "], max depth " << max_depth << "):\n";

        const int rows = static_cast<int>(std::min<size_t>(max_depth, 12));
        for (int row = rows; row >= 0; --row) {
            std::cout << std::setw(3) << (max_depth * row / std::max(1, rows)) << " | ";
            for (size_t i = r.begin_idx; i <= r.end_idx; ++i) {
                size_t depth = m_frames[i].m_stack.size();
                int scaled = static_cast<int>(std::round(static_cast<double>(depth) / max_depth * rows));
                bool mark = (scaled == row);
                bool cursor_here = (i == m_cursor);
                std::string cell = mark ? "*" : " ";
                if (cursor_here && mark) cell = use_color() ? color::green("*") : "*";
                std::cout << cell;
            }
            std::cout << "\n";
        }
        std::cout << "    +" << std::string(r.end_idx - r.begin_idx + 1, '-') << "\n";
        std::cout << "     (" << (r.end_idx - r.begin_idx + 1) << " frames, left=older, right=newer, '*' at cursor is highlighted)\n";
    }

    void cmd_export(std::istringstream& iss)
    {
        std::string path;
        if (!(iss >> path)) { std::cout << "usage: export <file.json>\n"; return; }
        export_json(path);
    }

    // Jumps straight to the frame that explains a failed verification:
    // the STEP immediately preceding the first END with a nonzero
    // script_error (i.e. the last opcode actually blamed for failure).
    void cmd_why()
    {
        if (m_result.success) {
            std::cout << color::green("verification succeeded; nothing to explain") << "\n";
            return;
        }
        for (size_t i = 0; i < m_frames.size(); ++i) {
            const auto& f = m_frames[i];
            if (f.m_kind == btck::ScriptTraceFrameKind::END && f.m_script_error != 0) {
                size_t blame = i;
                for (size_t j = i; j-- > 0; ) {
                    if (m_frames[j].m_kind == btck::ScriptTraceFrameKind::STEP) { blame = j; break; }
                    if (m_frames[j].m_kind == btck::ScriptTraceFrameKind::BEGIN) break;
                }
                std::cout << color::red("Run " + std::to_string(run_index_of(i)) + " ("
                          + sigversion_str(f.m_sig_version) + ") failed: script_error="
                          + std::to_string(f.m_script_error)) << "\n";
                if (blame != i) {
                    std::cout << "  last executed opcode: " << opnames::name(m_frames[blame].m_opcode)
                              << " at op_pos=" << m_frames[blame].m_opcode_pos << "\n";
                }
                std::cout << "  jumping cursor there...\n";
                m_cursor = blame;
                stop_here();
                return;
            }
        }
        std::cout << "verification failed but no END frame with a nonzero script_error was captured "
                     "(check overall status: '" << status_str(m_result.status) << "')\n";
    }

    void cmd_explain(std::istringstream& iss) const
    {
        std::string tok;
        uint8_t op;
        if (iss >> tok) {
            int resolved = resolve_opcode(tok);
            if (resolved < 0) { std::cout << "unrecognized opcode: " << tok << "\n"; return; }
            op = static_cast<uint8_t>(resolved);
        } else {
            if (m_cursor >= m_frames.size()) { std::cout << "usage: explain [opcode]\n"; return; }
            op = m_frames[m_cursor].m_opcode;
        }
        char hexbuf[8];
        std::snprintf(hexbuf, sizeof(hexbuf), "0x%02x", op);
        std::cout << color::bold(std::string(opnames::name(op)) + " (" + hexbuf + ")") << "\n";
        std::cout << "  " << opnames::describe(op) << "\n";
    }

    void cmd_recognize() const
    {
        if (m_cursor >= m_frames.size()) { std::cout << "no such frame\n"; return; }
        if (!render_pattern_banner(m_cursor)) {
            std::cout << "no recognized template for the script at the current frame\n";
        }
    }

    void cmd_color(std::istringstream& iss)
    {
        std::string mode;
        if (!(iss >> mode)) { std::cout << "usage: color on|off\n"; return; }
        if (mode == "on") color::g_enabled = true;
        else if (mode == "off") color::g_enabled = false;
        else std::cout << "usage: color on|off\n";
    }

    void cmd_help() const
    {
        std::cout <<
            "Navigation:\n"
            "  runs                     List captured script runs (BEGIN..END sequences)\n"
            "  select <run#>            Jump cursor to the start of a given run\n"
            "  step | n                 Move cursor forward one frame\n"
            "  back | p                 Move cursor backward one frame\n"
            "  goto <frame#>            Jump cursor to an absolute frame index\n"
            "  list [n]                 Show n frames (default 5) around the cursor\n"
            "  play [ms]                 Auto-step forward, redrawing in place, until a\n"
            "                             breakpoint/end or Enter is pressed (default 200ms/frame)\n"
            "\n"
            "View:\n"
            "  (the boxed dashboard is shown automatically at every stop while 'viz' is on,\n"
            "   and redraws in place -- like a movie -- while 'redraw' is on)\n"
            "  view | dash                Force a one-off dashboard render at the cursor\n"
            "  viz on|off                 Toggle automatic dashboard rendering\n"
            "  redraw on|off              Toggle in-place (movie-style) redraw during step/play\n"
            "  legend                     Show the opcode color key\n"
            "\n"
            "Inspection (plain-text, grep-friendly):\n"
            "  info | i                 Show metadata for the current frame\n"
            "  stack / altstack         Show the (alt)stack at the current frame\n"
            "  disasm | d                Disassemble the whole script (control-flow indented,\n"
            "                             current instruction highlighted)\n"
            "  diff <f1> <f2>           Show stack/altstack differences between two frames\n"
            "  timeline                 ASCII stack-depth plot across the current run\n"
            "  find <hex>               Search all captured stack/altstack items for bytes\n"
            "  recognize | pattern      Identify common consensus-level script templates\n"
            "                            (P2PKH, P2PK, single-key tapscript leaves, bare\n"
            "                            multisig) for the script at the current frame\n"
            "\n"
            "Breakpoints:\n"
            "  break opcode <name|hex>  Break when that opcode is about to execute\n"
            "  break index <op_pos>     Break at a specific opcode position\n"
            "  break if <expr>          Break when a condition holds, e.g.:\n"
            "                             'break if stack_depth > 4'\n"
            "                             'break if opcode == OP_CHECKSIG'\n"
            "                             'break if kind == END && script_error != 0'\n"
            "                           idents: opcode, op_pos, op_count, stack_depth,\n"
            "                           altstack_depth, kind, sig_version, exec,\n"
            "                           script_error, codeseparator_pos, frame\n"
            "  unbreak <#>              Remove breakpoint by its listed number\n"
            "  breakpoints              List active breakpoints\n"
            "  continue | c              Run forward to the next breakpoint\n"
            "  reverse-continue | rc     Run backward to the previous breakpoint\n"
            "\n"
            "Watches:\n"
            "  watch <slot>              Print stack[<slot>] automatically at every stop\n"
            "  unwatch <slot>             Stop watching that slot\n"
            "  watches                    List current watch values\n"
            "\n"
            "Misc:\n"
            "  export <file.json>        Dump the full captured trace as JSON\n"
            "  color on|off               Toggle ANSI colors\n"
            "  summary                    Reprint the overall verification result\n"
            "  why                        Jump to the opcode that caused a failed verification\n"
            "  explain [opcode]           One-line description of an opcode (default: opcode at cursor)\n"
            "  quit | q                   Exit\n";
    }
};

// =====================================================================
// main
// =====================================================================

int main(int argc, char** argv)
{
    try {
        Options opt = parse_args(argc, argv);
        color::g_enabled = !opt.no_color && ::isatty(STDOUT_FILENO);
        bool visual = !opt.no_visual && ::isatty(STDOUT_FILENO);

        std::vector<btck::ScriptTraceFrame> frames;
        RunResult result = run_verification(opt, frames);
        Debugger dbg(std::move(frames), result, visual);

        if (!opt.export_path.empty()) dbg.export_json(opt.export_path);
        if (!opt.batch_file.empty()) dbg.run_batch_file(opt.batch_file);
        if (opt.batch_then_exit) return 0;

        dbg.repl();
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
