// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BITCOINKERNEL_HPP
#define BITCOIN_KERNEL_BITCOINKERNEL_HPP

#include <consensus/amount.h>
#include <kernel/logging_types.h>
#include <kernel/script_flags.h>

#include <functional>
#include <memory>
#include <string_view>
#include <span>

namespace kernel_header {

class Transaction;
class ScriptPubkey;
class TransactionOutput;

class Transaction
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

class ScriptPubkey
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

class TransactionOutput
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

void AddLogLevelCategory(const BCLog::LogFlags category, const BCLog::Level level);

void EnableLogCategory(const BCLog::LogFlags category);

void DisableLogCategory(const BCLog::LogFlags category);

void DisableLogging();

void SetLogAlwaysPrintCategoryLevel(bool log_always_print_category_level);

void SetLogTimestamps(bool log_timestamps);

void SetLogTimeMicros(bool log_time_micros);

void SetLogThreadnames(bool log_threadnames);

void SetLogSourcelocations(bool log_sourcelocations);

class Logger
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

} // namespace kernel_header

#endif // BITCOIN_KERNEL_BITCOINKERNEL_HPP
