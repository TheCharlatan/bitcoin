// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BITCOINKERNEL_BUILD

#include <kernel/bitcoinkernel.h>

#include <consensus/amount.h>
#include <kernel/chainparams.h>
#include <kernel/checks.h>
#include <kernel/context.h>
#include <kernel/notifications_interface.h>
#include <kernel/warning.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <util/result.h>
#include <util/signalinterrupt.h>
#include <util/translation.h>
#include <validation.h>

#include <cassert>
#include <cstddef>
#include <cstring>
#include <exception>
#include <functional>
#include <list>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

class CBlockIndex;

// Define G_TRANSLATION_FUN symbol in libbitcoinkernel library so users of the
// library aren't required to export this symbol
extern const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

static const kernel::Context btck_context_static{};

struct btck_BlockTreeEntry
{
    CBlockIndex* m_block_index;
};

namespace {

/** Check that all specified flags are part of the libbitcoinkernel interface. */
bool verify_flags(unsigned int flags)
{
    return (flags & ~(btck_SCRIPT_FLAGS_VERIFY_ALL)) == 0;
}

bool is_valid_flag_combination(unsigned int flags)
{
    if (flags & SCRIPT_VERIFY_CLEANSTACK && ~flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) return false;
    if (flags & SCRIPT_VERIFY_WITNESS && ~flags & SCRIPT_VERIFY_P2SH) return false;
    return true;
}

BCLog::Level get_bclog_level(const btck_LogLevel level)
{
    switch (level) {
    case btck_LogLevel::btck_LOG_INFO: {
        return BCLog::Level::Info;
    }
    case btck_LogLevel::btck_LOG_DEBUG: {
        return BCLog::Level::Debug;
    }
    case btck_LogLevel::btck_LOG_TRACE: {
        return BCLog::Level::Trace;
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

BCLog::LogFlags get_bclog_flag(const btck_LogCategory category)
{
    switch (category) {
    case btck_LogCategory::btck_LOG_BENCH: {
        return BCLog::LogFlags::BENCH;
    }
    case btck_LogCategory::btck_LOG_BLOCKSTORAGE: {
        return BCLog::LogFlags::BLOCKSTORAGE;
    }
    case btck_LogCategory::btck_LOG_COINDB: {
        return BCLog::LogFlags::COINDB;
    }
    case btck_LogCategory::btck_LOG_LEVELDB: {
        return BCLog::LogFlags::LEVELDB;
    }
    case btck_LogCategory::btck_LOG_MEMPOOL: {
        return BCLog::LogFlags::MEMPOOL;
    }
    case btck_LogCategory::btck_LOG_PRUNE: {
        return BCLog::LogFlags::PRUNE;
    }
    case btck_LogCategory::btck_LOG_RAND: {
        return BCLog::LogFlags::RAND;
    }
    case btck_LogCategory::btck_LOG_REINDEX: {
        return BCLog::LogFlags::REINDEX;
    }
    case btck_LogCategory::btck_LOG_VALIDATION: {
        return BCLog::LogFlags::VALIDATION;
    }
    case btck_LogCategory::btck_LOG_KERNEL: {
        return BCLog::LogFlags::KERNEL;
    }
    case btck_LogCategory::btck_LOG_ALL: {
        return BCLog::LogFlags::ALL;
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

btck_SynchronizationState cast_state(SynchronizationState state)
{
    switch (state) {
    case SynchronizationState::INIT_REINDEX:
        return btck_SynchronizationState::btck_INIT_REINDEX;
    case SynchronizationState::INIT_DOWNLOAD:
        return btck_SynchronizationState::btck_INIT_DOWNLOAD;
    case SynchronizationState::POST_INIT:
        return btck_SynchronizationState::btck_POST_INIT;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

btck_Warning cast_btck_warning(kernel::Warning warning)
{
    switch (warning) {
    case kernel::Warning::UNKNOWN_NEW_RULES_ACTIVATED:
        return btck_Warning::btck_LARGE_WORK_INVALID_CHAIN;
    case kernel::Warning::LARGE_WORK_INVALID_CHAIN:
        return btck_Warning::btck_LARGE_WORK_INVALID_CHAIN;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

class KernelNotifications : public kernel::Notifications
{
private:
    btck_NotificationInterfaceCallbacks m_cbs;

public:
    KernelNotifications(btck_NotificationInterfaceCallbacks cbs)
        : m_cbs{cbs}
    {
    }

    kernel::InterruptResult blockTip(SynchronizationState state, CBlockIndex& index, double verification_progress) override
    {
        if (m_cbs.block_tip) m_cbs.block_tip((void*)m_cbs.user_data, cast_state(state), new btck_BlockTreeEntry{&index}, verification_progress);
        return {};
    }
    void headerTip(SynchronizationState state, int64_t height, int64_t timestamp, bool presync) override
    {
        if (m_cbs.header_tip) m_cbs.header_tip((void*)m_cbs.user_data, cast_state(state), height, timestamp, presync);
    }
    void progress(const bilingual_str& title, int progress_percent, bool resume_possible) override
    {
        if (m_cbs.progress) m_cbs.progress((void*)m_cbs.user_data, title.original.c_str(), title.original.length(), progress_percent, resume_possible);
    }
    void warningSet(kernel::Warning id, const bilingual_str& message) override
    {
        if (m_cbs.warning_set) m_cbs.warning_set((void*)m_cbs.user_data, cast_btck_warning(id), message.original.c_str(), message.original.length());
    }
    void warningUnset(kernel::Warning id) override
    {
        if (m_cbs.warning_unset) m_cbs.warning_unset((void*)m_cbs.user_data, cast_btck_warning(id));
    }
    void flushError(const bilingual_str& message) override
    {
        if (m_cbs.flush_error) m_cbs.flush_error((void*)m_cbs.user_data, message.original.c_str(), message.original.length());
    }
    void fatalError(const bilingual_str& message) override
    {
        if (m_cbs.fatal_error) m_cbs.fatal_error((void*)m_cbs.user_data, message.original.c_str(), message.original.length());
    }
};

struct ContextOptions {
    mutable Mutex m_mutex;
    std::unique_ptr<const CChainParams> m_chainparams GUARDED_BY(m_mutex);
    std::unique_ptr<const KernelNotifications> m_notifications GUARDED_BY(m_mutex);
};

class Context
{
public:
    std::unique_ptr<kernel::Context> m_context;

    std::unique_ptr<KernelNotifications> m_notifications;

    std::unique_ptr<util::SignalInterrupt> m_interrupt;

    std::unique_ptr<const CChainParams> m_chainparams;

    Context(const ContextOptions* options, bool& sane)
        : m_context{std::make_unique<kernel::Context>()},
          m_interrupt{std::make_unique<util::SignalInterrupt>()}
    {
        if (options) {
            LOCK(options->m_mutex);
            if (options->m_chainparams) {
                m_chainparams = std::make_unique<const CChainParams>(*options->m_chainparams);
            }
            if (options->m_notifications) {
                m_notifications = std::make_unique<KernelNotifications>(*options->m_notifications);
            }
        }

        if (!m_chainparams) {
            m_chainparams = CChainParams::Main();
        }
        if (!m_notifications) {
            m_notifications = std::make_unique<KernelNotifications>(btck_NotificationInterfaceCallbacks{
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr});
        }

        if (!kernel::SanityChecks(*m_context)) {
            sane = false;
        }
    }
};

} // namespace

struct btck_Transaction
{
    std::shared_ptr<const CTransaction> m_tx;
};

struct btck_TransactionOutput
{
    const CTxOut* m_txout;
    bool m_owned;
};

struct btck_ScriptPubkey
{
    const CScript* m_script;
    bool m_owned;
};

struct btck_LoggingConnection
{
    std::unique_ptr<std::list<std::function<void(const std::string&)>>::iterator> m_connection;
};

struct btck_ContextOptions
{
    std::unique_ptr<ContextOptions> m_opts;
};

struct btck_Context
{
    std::shared_ptr<Context> m_context;
};

struct btck_ChainParameters
{
    std::unique_ptr<const CChainParams> m_params;
};

btck_Transaction* btck_transaction_create(const unsigned char* raw_transaction, size_t raw_transaction_len)
{
    try {
        DataStream stream{std::span{raw_transaction, raw_transaction_len}};
        auto tx{std::make_shared<CTransaction>(deserialize, TX_WITH_WITNESS, stream)};
        return new btck_Transaction{std::move(tx)};
    } catch (const std::exception&) {
        return nullptr;
    }
}

uint64_t btck_transaction_count_outputs(const btck_Transaction* transaction)
{
    return transaction->m_tx->vout.size();
}

btck_TransactionOutput* btck_transaction_get_output_at(const btck_Transaction* transaction, uint64_t output_index)
{
    assert(output_index < transaction->m_tx->vout.size());
    return new btck_TransactionOutput{&transaction->m_tx->vout[output_index], false};
}

uint64_t btck_transaction_count_inputs(const btck_Transaction* transaction)
{
    return transaction->m_tx->vin.size();
}

btck_Transaction* btck_transaction_copy(const btck_Transaction* transaction)
{
    return new btck_Transaction{transaction->m_tx};
}

void btck_transaction_destroy(btck_Transaction* transaction)
{
    if (!transaction) return;
    delete transaction;
    transaction = nullptr;
}

btck_ScriptPubkey* btck_script_pubkey_create(const unsigned char* script_pubkey, size_t script_pubkey_len)
{
    return new btck_ScriptPubkey{new CScript(script_pubkey, script_pubkey + script_pubkey_len), true};
}

btck_ScriptPubkey* btck_script_pubkey_copy(const btck_ScriptPubkey* script_pubkey)
{
    return new btck_ScriptPubkey{new CScript(*script_pubkey->m_script), true};
}

void btck_script_pubkey_destroy(btck_ScriptPubkey* script_pubkey)
{
    if (!script_pubkey) return;
    if (script_pubkey->m_owned) {
        delete script_pubkey->m_script;
    }
    delete script_pubkey;
    script_pubkey = nullptr;
}

btck_TransactionOutput* btck_transaction_output_create(const btck_ScriptPubkey* script_pubkey, int64_t amount)
{
    const CAmount& value{amount};
    return new btck_TransactionOutput{new CTxOut(value, *script_pubkey->m_script), true};
}

btck_TransactionOutput* btck_transaction_output_copy(const btck_TransactionOutput* output)
{
    return new btck_TransactionOutput{new CTxOut{*output->m_txout}, true};
}

btck_ScriptPubkey* btck_transaction_output_get_script_pubkey(const btck_TransactionOutput* output)
{
    const auto* script_pubkey{&output->m_txout->scriptPubKey};
    return new btck_ScriptPubkey{script_pubkey, false};
}

int64_t btck_transaction_output_get_amount(const btck_TransactionOutput* output)
{
    return output->m_txout->nValue;
}

void btck_transaction_output_destroy(btck_TransactionOutput* output)
{
    if (!output) return;
    if (output->m_owned) {
        delete output->m_txout;
    }
    delete output;
    output = nullptr;
}

bool btck_script_pubkey_verify(const btck_ScriptPubkey* script_pubkey,
                          const int64_t amount_,
                          const btck_Transaction* tx_to,
                          const btck_TransactionOutput** spent_outputs_, size_t spent_outputs_len,
                          const unsigned int input_index,
                          const unsigned int flags,
                          btck_ScriptVerifyStatus* status)
{
    const CAmount amount{amount_};

    if (!verify_flags(flags)) {
        if (status) *status = btck_SCRIPT_VERIFY_ERROR_INVALID_FLAGS;
        return false;
    }

    if (!is_valid_flag_combination(flags)) {
        if (status) *status = btck_SCRIPT_VERIFY_ERROR_INVALID_FLAGS_COMBINATION;
        return false;
    }

    if (flags & btck_SCRIPT_FLAGS_VERIFY_TAPROOT && spent_outputs_ == nullptr) {
        if (status) *status = btck_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_REQUIRED;
        return false;
    }

    const CTransaction& tx{*tx_to->m_tx};
    std::vector<CTxOut> spent_outputs;
    if (spent_outputs_ != nullptr) {
        assert(spent_outputs_len == tx.vin.size());
        spent_outputs.reserve(spent_outputs_len);
        for (size_t i = 0; i < spent_outputs_len; i++) {
            const CTxOut& tx_out{*spent_outputs_[i]->m_txout};
            spent_outputs.push_back(tx_out);
        }
    }

    assert(input_index < tx.vin.size());
    PrecomputedTransactionData txdata{tx};

    if (spent_outputs_ != nullptr && flags & btck_SCRIPT_FLAGS_VERIFY_TAPROOT) {
        txdata.Init(tx, std::move(spent_outputs));
    }

    return VerifyScript(tx.vin[input_index].scriptSig,
                        *script_pubkey->m_script,
                        &tx.vin[input_index].scriptWitness,
                        flags,
                        TransactionSignatureChecker(&tx, input_index, amount, txdata, MissingDataBehavior::FAIL),
                        nullptr);
}

void btck_logging_set_level_category(const btck_LogCategory category, const btck_LogLevel level)
{
    if (category == btck_LogCategory::btck_LOG_ALL) {
        LogInstance().SetLogLevel(get_bclog_level(level));
    }

    LogInstance().AddCategoryLogLevel(get_bclog_flag(category), get_bclog_level(level));
}

void btck_logging_enable_category(const btck_LogCategory category)
{
    LogInstance().EnableCategory(get_bclog_flag(category));
}

void btck_logging_disable_category(const btck_LogCategory category)
{
    LogInstance().DisableCategory(get_bclog_flag(category));
}

void btck_logging_disable()
{
    LogInstance().DisableLogging();
}

btck_LoggingConnection* btck_logging_connection_create(btck_LogCallback callback,
                                                           const void* user_data,
                                                           const btck_LoggingOptions options)
{
    LogInstance().m_log_timestamps = options.log_timestamps;
    LogInstance().m_log_time_micros = options.log_time_micros;
    LogInstance().m_log_threadnames = options.log_threadnames;
    LogInstance().m_log_sourcelocations = options.log_sourcelocations;
    LogInstance().m_always_print_category_level = options.always_print_category_levels;

    auto connection{LogInstance().PushBackCallback([callback, user_data](const std::string& str) { callback((void*)user_data, str.c_str(), str.length()); })};

    try {
        // Only start logging if we just added the connection.
        if (LogInstance().NumConnections() == 1 && !LogInstance().StartLogging()) {
            LogError("Logger start failed.");
            LogInstance().DeleteCallback(connection);
            return nullptr;
        }
    } catch (std::exception&) {
        LogError("Logger start failed.");
        LogInstance().DeleteCallback(connection);
        return nullptr;
    }

    LogDebug(BCLog::KERNEL, "Logger connected.");

    return new btck_LoggingConnection{std::make_unique<std::list<std::function<void(const std::string&)>>::iterator>(connection)};
}

void btck_logging_connection_destroy(btck_LoggingConnection* connection)
{
    if (!connection) {
        return;
    }

    LogDebug(BCLog::KERNEL, "Logger disconnected.");
    LogInstance().DeleteCallback(*connection->m_connection);
    delete connection;

    // Switch back to buffering by calling DisconnectTestLogger if the
    // connection that was just removed was the last one.
    if (!LogInstance().Enabled()) {
        LogInstance().DisconnectTestLogger();
    }
    connection = nullptr;
}

btck_ChainParameters* btck_chain_parameters_create(const btck_ChainType chain_type)
{
    switch (chain_type) {
    case btck_ChainType::btck_CHAIN_TYPE_MAINNET: {
        return new btck_ChainParameters{CChainParams::Main()};
    }
    case btck_ChainType::btck_CHAIN_TYPE_TESTNET: {
        return new btck_ChainParameters{CChainParams::TestNet()};
    }
    case btck_ChainType::btck_CHAIN_TYPE_TESTNET_4: {
        return new btck_ChainParameters{CChainParams::TestNet4()};
    }
    case btck_ChainType::btck_CHAIN_TYPE_SIGNET: {
        return new btck_ChainParameters{CChainParams::SigNet({})};
    }
    case btck_ChainType::btck_CHAIN_TYPE_REGTEST: {
        return new btck_ChainParameters{CChainParams::RegTest({})};
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

void btck_chain_parameters_destroy(btck_ChainParameters* chain_parameters)
{
    if (!chain_parameters) return;
    delete chain_parameters;
    chain_parameters = nullptr;
}

btck_ContextOptions* btck_context_options_create()
{
    return new btck_ContextOptions{std::make_unique<ContextOptions>()};
}

void btck_context_options_set_chainparams(btck_ContextOptions* options, const btck_ChainParameters* chain_parameters)
{
    // Copy the chainparams, so the caller can free it again
    LOCK(options->m_opts->m_mutex);
    options->m_opts->m_chainparams = std::make_unique<const CChainParams>(*chain_parameters->m_params);
}

void btck_context_options_set_notifications(btck_ContextOptions* options, btck_NotificationInterfaceCallbacks notifications)
{
    // The KernelNotifications are copy-initialized, so the caller can free them again.
    LOCK(options->m_opts->m_mutex);
    options->m_opts->m_notifications = std::make_unique<const KernelNotifications>(notifications);
}

void btck_context_options_destroy(btck_ContextOptions* options)
{
    if (!options) return;
    delete options;
    options = nullptr;
}

btck_Context* btck_context_create(const btck_ContextOptions* options)
{
    bool sane{true};
    auto context{std::make_shared<Context>(options->m_opts.get(), sane)};
    if (!sane) {
        LogError("Kernel context sanity check failed.");
        return nullptr;
    }
    return new btck_Context{std::move(context)};
}

void btck_context_destroy(btck_Context* context)
{
    if (!context) return;
    delete context;
    context = nullptr;
}

void btck_block_tree_entry_destroy(btck_BlockTreeEntry* block_tree_entry)
{
    if (!block_tree_entry) return;
    delete block_tree_entry;
    block_tree_entry = nullptr;
}
