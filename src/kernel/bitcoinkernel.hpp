// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BITCOINKERNEL_HPP
#define BITCOIN_KERNEL_BITCOINKERNEL_HPP

#include <consensus/amount.h>
#include <kernel/script_flags.h> // IWYU pragma: keep

#include <cstdint>
#include <memory>
#include <span>

#ifndef BITCOINKERNEL_API
#if defined(_WIN32)
#ifdef BITCOINKERNEL_BUILD
#define BITCOINKERNEL_API __declspec(dllexport)
#else
#define BITCOINKERNEL_API
#endif
#elif defined(__GNUC__) && (__GNUC__ >= 4) && defined(BITCOINKERNEL_BUILD)
#define BITCOINKERNEL_API __attribute__((visibility("default")))
#else
#define BITCOINKERNEL_API
#endif
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251) // Suppress C4251 for STL members (e.g. std::unique_ptr) in exported classes
#endif

namespace kernel_header {

class TransactionOutput;

class BITCOINKERNEL_API Transaction
{
private:
    struct TransactionImpl;
    std::unique_ptr<TransactionImpl> m_impl;

public:
    explicit Transaction(std::span<const unsigned char> raw_transaction) noexcept;
    ~Transaction();

    /** Check whether this Transaction object is valid. */
    explicit operator bool() const noexcept { return bool{m_impl}; }

    friend class ScriptPubkey;
};

class BITCOINKERNEL_API ScriptPubkey
{
private:
    struct ScriptPubkeyImpl;
    std::unique_ptr<ScriptPubkeyImpl> m_impl;

public:
    explicit ScriptPubkey(std::span<const unsigned char> script_pubkey) noexcept;
    ~ScriptPubkey();

    /** Check whether this ScriptPubkey object is valid. */
    explicit operator bool() const noexcept { return bool{m_impl}; }

    int VerifyScript(
        const CAmount amount,
        const Transaction& tx_to,
        std::span<const TransactionOutput> spent_outputs,
        const unsigned int input_index,
        const unsigned int flags) const noexcept;

    friend class TransactionOutput;
};

class BITCOINKERNEL_API TransactionOutput
{
private:
    struct TransactionOutputImpl;
    std::unique_ptr<TransactionOutputImpl> m_impl;

public:
    explicit TransactionOutput(const ScriptPubkey& script_pubkey, int64_t amount) noexcept;
    ~TransactionOutput();

    TransactionOutput(TransactionOutput&& other) noexcept;
    TransactionOutput& operator=(TransactionOutput&& other) noexcept;

    /** Check whether this TransactionOutput object is valid. */
    explicit operator bool() const noexcept { return bool{m_impl}; }

    friend class ScriptPubkey;
};

} // namespace kernel_header

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // BITCOIN_KERNEL_BITCOINKERNEL_HPP
