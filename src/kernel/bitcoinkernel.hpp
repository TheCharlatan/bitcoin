// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BITCOINKERNEL_HPP
#define BITCOIN_KERNEL_BITCOINKERNEL_HPP

#include <consensus/amount.h>
#include <kernel/logging_types.h> // IWYU pragma: keep
#include <kernel/script_flags.h> // IWYU pragma: keep
#include <util/chaintype.h>      // IWYU pragma: keep

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string_view>

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

BITCOINKERNEL_API void AddLogLevelCategory(const BCLog::LogFlags category, const BCLog::Level level);

BITCOINKERNEL_API void EnableLogCategory(const BCLog::LogFlags category);

BITCOINKERNEL_API void DisableLogCategory(const BCLog::LogFlags category);

BITCOINKERNEL_API void DisableLogging();

BITCOINKERNEL_API void SetLogAlwaysPrintCategoryLevel(bool log_always_print_category_level);

BITCOINKERNEL_API void SetLogTimestamps(bool log_timestamps);

BITCOINKERNEL_API void SetLogTimeMicros(bool log_time_micros);

BITCOINKERNEL_API void SetLogThreadnames(bool log_threadnames);

BITCOINKERNEL_API void SetLogSourcelocations(bool log_sourcelocations);

class BITCOINKERNEL_API Logger
{
private:
    struct LoggerImpl;
    std::unique_ptr<LoggerImpl> m_impl;

public:
    explicit Logger(std::function<void(std::string_view)> callback) noexcept;
    ~Logger();

    /** Check whether this Logger object is valid. */
    explicit operator bool() const noexcept { return bool{m_impl}; }
};

class BITCOINKERNEL_API ChainParameters
{
private:
    struct ChainParametersImpl;
    std::unique_ptr<ChainParametersImpl> m_impl;

public:
    explicit ChainParameters(const ChainType chain_type) noexcept;
    ~ChainParameters() noexcept;

    friend class ContextOptions;
};


class BITCOINKERNEL_API ContextOptions
{
private:
    struct ContextOptionsImpl;
    std::unique_ptr<ContextOptionsImpl> m_impl;

public:
    explicit ContextOptions() noexcept;
    ~ContextOptions() noexcept;

    void SetChainParameters(const ChainParameters& chain_parameters) noexcept;

    friend class Context;
};

class BITCOINKERNEL_API Context
{
private:
    struct ContextImpl;
    std::unique_ptr<ContextImpl> m_impl;

public:
    explicit Context(const ContextOptions& opts) noexcept;
    Context() noexcept;
    ~Context() noexcept;

    /** Check whether this Context object is valid. */
    explicit operator bool() const noexcept { return bool{m_impl}; }
};

} // namespace kernel_header

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // BITCOIN_KERNEL_BITCOINKERNEL_HPP
