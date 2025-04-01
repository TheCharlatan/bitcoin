// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BITCOINKERNEL_BUILD

#include <kernel/bitcoinkernel.hpp>

#include <kernel/bitcoinkernel.h>

#include <consensus/amount.h>
#include <kernel/chainparams.h>
#include <kernel/checks.h>
#include <kernel/context.h>
#include <kernel/notifications_interface.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <util/result.h>
#include <util/signalinterrupt.h>
#include <util/translation.h>

#include <cstring>
#include <exception>
#include <functional>
#include <span>
#include <string>
#include <utility>
#include <vector>

// Define G_TRANSLATION_FUN symbol in libbitcoinkernel library so users of the
// library aren't required to export this symbol
extern const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

static const kernel::Context kernel_context_static{};

namespace kernel_header {

BCLog::Level get_bclog_level(const kernel_LogLevel level)
{
    switch (level) {
    case kernel_LogLevel::kernel_LOG_INFO: {
        return BCLog::Level::Info;
    }
    case kernel_LogLevel::kernel_LOG_DEBUG: {
        return BCLog::Level::Debug;
    }
    case kernel_LogLevel::kernel_LOG_TRACE: {
        return BCLog::Level::Trace;
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

BCLog::LogFlags get_bclog_flag(const kernel_LogCategory category)
{
    switch (category) {
    case kernel_LogCategory::kernel_LOG_BENCH: {
        return BCLog::LogFlags::BENCH;
    }
    case kernel_LogCategory::kernel_LOG_BLOCKSTORAGE: {
        return BCLog::LogFlags::BLOCKSTORAGE;
    }
    case kernel_LogCategory::kernel_LOG_COINDB: {
        return BCLog::LogFlags::COINDB;
    }
    case kernel_LogCategory::kernel_LOG_LEVELDB: {
        return BCLog::LogFlags::LEVELDB;
    }
    case kernel_LogCategory::kernel_LOG_MEMPOOL: {
        return BCLog::LogFlags::MEMPOOL;
    }
    case kernel_LogCategory::kernel_LOG_PRUNE: {
        return BCLog::LogFlags::PRUNE;
    }
    case kernel_LogCategory::kernel_LOG_RAND: {
        return BCLog::LogFlags::RAND;
    }
    case kernel_LogCategory::kernel_LOG_REINDEX: {
        return BCLog::LogFlags::REINDEX;
    }
    case kernel_LogCategory::kernel_LOG_VALIDATION: {
        return BCLog::LogFlags::VALIDATION;
    }
    case kernel_LogCategory::kernel_LOG_KERNEL: {
        return BCLog::LogFlags::KERNEL;
    }
    case kernel_LogCategory::kernel_LOG_ALL: {
        return BCLog::LogFlags::ALL;
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

bool is_valid_flag_combination(unsigned int flags)
{
    if (flags & SCRIPT_VERIFY_CLEANSTACK && ~flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) return false;
    if (flags & SCRIPT_VERIFY_WITNESS && ~flags & SCRIPT_VERIFY_P2SH) return false;
    return true;
}

struct ScriptPubkey::ScriptPubkeyImpl {
    CScript m_script_pubkey;

    ScriptPubkeyImpl(std::span<const unsigned char> script_pubkey)
        : m_script_pubkey{script_pubkey.begin(), script_pubkey.end()}
    {
    }
};

ScriptPubkey::ScriptPubkey(std::span<const unsigned char> script_pubkey) noexcept
    : m_impl{std::make_unique<ScriptPubkey::ScriptPubkeyImpl>(script_pubkey)}
{}

ScriptPubkey::~ScriptPubkey() = default;

struct Transaction::TransactionImpl {
    CTransaction m_transaction;
};

Transaction::Transaction(std::span<const unsigned char> raw_transaction) noexcept
{
    try {
        DataStream stream{raw_transaction};
        m_impl = std::make_unique<Transaction::TransactionImpl>(CTransaction{deserialize, TX_WITH_WITNESS, stream});
    } catch (std::exception) {
        m_impl = nullptr;
    }
}

Transaction::~Transaction() = default;

struct TransactionOutput::TransactionOutputImpl {
    CTxOut m_tx_out;

    TransactionOutputImpl(CAmount amount, const ScriptPubkey& script_pubkey)
        : m_tx_out{amount, script_pubkey.m_impl->m_script_pubkey}
    {
    }
};

TransactionOutput::TransactionOutput(const ScriptPubkey& script_pubkey, int64_t amount) noexcept
{
    m_impl = std::make_unique<TransactionOutput::TransactionOutputImpl>(CAmount{amount}, script_pubkey);
}

TransactionOutput::~TransactionOutput() = default;

TransactionOutput::TransactionOutput(TransactionOutput&& other) noexcept = default;
TransactionOutput& TransactionOutput::operator=(TransactionOutput&& other) noexcept = default;


/** Check that all specified flags are part of the libbitcoinkernel interface. */
bool verify_flags(unsigned int flags)
{
    return (flags & ~(kernel_SCRIPT_FLAGS_VERIFY_ALL)) == 0;
}

int ScriptPubkey::VerifyScript(
    const int64_t amount_,
    const Transaction& tx_to,
    std::span<const TransactionOutput> spent_outputs,
    const unsigned int input_index,
    const unsigned int flags,
    kernel_ScriptVerifyStatus& status) const noexcept
{
    const CAmount amount{amount_};

    if (!verify_flags(flags)) {
        status = kernel_SCRIPT_VERIFY_ERROR_INVALID_FLAGS;
        return false;
    }

    if (!is_valid_flag_combination(flags)) {
        status = kernel_SCRIPT_VERIFY_ERROR_INVALID_FLAGS_COMBINATION;
        return false;
    }

    if (flags & kernel_SCRIPT_FLAGS_VERIFY_TAPROOT && spent_outputs.empty()) {
        status = kernel_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_REQUIRED;
        return false;
    }

    const CTransaction& tx = tx_to.m_impl->m_transaction;
    std::vector<CTxOut> spent_outputs_vec;
    if (!spent_outputs.empty()) {
        if (spent_outputs.size() != tx.vin.size()) {
            status = kernel_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_MISMATCH;
            return false;
        }
        spent_outputs_vec.reserve(spent_outputs.size());
        for (const auto& spent_output : spent_outputs) {
            spent_outputs_vec.push_back(spent_output.m_impl->m_tx_out);
        }
    }

    if (input_index >= tx.vin.size()) {
        status = kernel_SCRIPT_VERIFY_ERROR_TX_INPUT_INDEX;
        return false;
    }
    PrecomputedTransactionData txdata{tx};

    if (!spent_outputs_vec.empty() && flags & kernel_SCRIPT_FLAGS_VERIFY_TAPROOT) {
        txdata.Init(tx, std::move(spent_outputs_vec));
    }

    return ::VerifyScript(tx.vin[input_index].scriptSig,
                        m_impl->m_script_pubkey,
                        &tx.vin[input_index].scriptWitness,
                        flags,
                        TransactionSignatureChecker(&tx, input_index, amount, txdata, MissingDataBehavior::FAIL),
                        nullptr);
}

void AddLogLevelCategory(const kernel_LogCategory category, const kernel_LogLevel level)
{
    if (category == kernel_LogCategory::kernel_LOG_ALL) {
        LogInstance().SetLogLevel(get_bclog_level(level));
    }

    LogInstance().AddCategoryLogLevel(get_bclog_flag(category), get_bclog_level(level));
}

void EnableLogCategory(const kernel_LogCategory category)
{
    LogInstance().EnableCategory(get_bclog_flag(category));
}

void DisableLogCategory(const kernel_LogCategory category)
{
    LogInstance().DisableCategory(get_bclog_flag(category));
}

void DisableLogging()
{
    LogInstance().DisableLogging();
}

struct Logger::LoggerImpl {
    std::list<std::function<void(const std::string&)>>::iterator m_connection;

    LoggerImpl(std::function<void(std::string_view)> callback, const kernel_LoggingOptions options)
    {
        LogInstance().m_log_timestamps = options.log_timestamps;
        LogInstance().m_log_time_micros = options.log_time_micros;
        LogInstance().m_log_threadnames = options.log_threadnames;
        LogInstance().m_log_sourcelocations = options.log_sourcelocations;
        LogInstance().m_always_print_category_level = options.always_print_category_levels;

        m_connection = LogInstance().PushBackCallback([callback](const std::string& str) { callback(str); });

        try {
            // Only start logging if we just added the connection.
            if (LogInstance().NumConnections() == 1 && !LogInstance().StartLogging()) {
                LogError("Logger start failed.");
                LogInstance().DeleteCallback(m_connection);
            }
        } catch (std::exception& e) {
            LogError("Logger start failed.");
            LogInstance().DeleteCallback(m_connection);
            throw e;
        }

        LogDebug(BCLog::KERNEL, "Logger connected.");
    }

    ~LoggerImpl()
    {
        LogDebug(BCLog::KERNEL, "Logger disconnected.");
        LogInstance().DeleteCallback(m_connection);

        // We are not buffering if we have a connection, so check that it is not the
        // last available connection.
        if (!LogInstance().Enabled()) {
            LogInstance().DisconnectTestLogger();
        }
    }
};

Logger::Logger(std::function<void(std::string_view)> callback, const kernel_LoggingOptions& logging_options) noexcept
{
    try {
        m_impl = std::make_unique<LoggerImpl>(callback, logging_options);
    } catch (std::exception&) {
        m_impl = nullptr;
    }
}

Logger::~Logger() = default;

struct ContextOptions::ContextOptionsImpl {
};

ContextOptions::ContextOptions() noexcept
{
    m_impl = std::make_unique<ContextOptionsImpl>();
}

ContextOptions::~ContextOptions() noexcept = default;

struct Context::ContextImpl
{
    std::unique_ptr<kernel::Context> m_context;

    std::unique_ptr<kernel::Notifications> m_notifications;

    std::unique_ptr<util::SignalInterrupt> m_interrupt;

    std::unique_ptr<const CChainParams> m_chainparams;

    ContextImpl(const ContextOptions& options, bool& sane)
        : m_context{std::make_unique<kernel::Context>()},
          m_notifications{std::make_unique<kernel::Notifications>()},
          m_interrupt{std::make_unique<util::SignalInterrupt>()},
          m_chainparams{CChainParams::Main()}
    {
        if (!kernel::SanityChecks(*m_context)) {
            LogError("Kernel context sanity check failed.");
            sane = false;
        }
    }
};

Context::Context(const ContextOptions& options) noexcept
{
    bool sane{true};
    m_impl = std::make_unique<ContextImpl>(options, sane);
    if (!sane) m_impl = nullptr;
}

Context::Context() noexcept
{
    bool sane{true};
    ContextOptions options{};
    m_impl = std::make_unique<ContextImpl>(options, sane);
    if (!sane) m_impl = nullptr;
}

Context::~Context() noexcept = default;

} // namespace kernel_header
