// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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
#include <span.h>
#include <tinyformat.h>
#include <util/result.h>
#include <util/signalinterrupt.h>
#include <util/translation.h>
#include <validation.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <list>
#include <memory>
#include <string>
#include <utility>
#include <vector>

class CBlockIndex;

// Define G_TRANSLATION_FUN symbol in libbitcoinkernel library so users of the
// library aren't required to export this symbol
extern const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

static const kernel::Context kernel_context_static{};

namespace {

// These tags are used to guard against void* types pointing to unexpected data
constexpr uint64_t KERNEL_CHAIN_PARAMS_TAG{0};
constexpr uint64_t KERNEL_NOTIFICATIONS_TAG{1};

/** A class that deserializes a single CTransaction one time. */
class TxInputStream
{
private:
    const unsigned char* m_data;
    size_t m_remaining;

public:
    TxInputStream(const unsigned char* txTo, size_t txToLen) : m_data{txTo},
                                                               m_remaining{txToLen}
    {
    }

    void read(Span<std::byte> dst)
    {
        if (dst.size() > m_remaining) {
            throw std::ios_base::failure(std::string(__func__) + ": end of data");
        }

        if (dst.data() == nullptr) {
            throw std::ios_base::failure(std::string(__func__) + ": bad destination buffer");
        }

        if (m_data == nullptr) {
            throw std::ios_base::failure(std::string(__func__) + ": bad source buffer");
        }

        memcpy(dst.data(), m_data, dst.size());
        m_remaining -= dst.size();
        m_data += dst.size();
    }

    template <typename T>
    TxInputStream& operator>>(T&& obj)
    {
        ::Unserialize(*this, obj);
        return *this;
    }
};

/** Check that all specified flags are part of the libbitcoinkernel interface. */
bool verify_flags(unsigned int flags)
{
    return (flags & ~(kernel_SCRIPT_FLAGS_VERIFY_ALL)) == 0;
}

bool is_valid_flag_combination(unsigned int flags)
{
    if (flags & SCRIPT_VERIFY_CLEANSTACK && ~flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) return false;
    if (flags & SCRIPT_VERIFY_WITNESS && ~flags & SCRIPT_VERIFY_P2SH) return false;
    return true;
}

std::string log_level_to_string(const kernel_LogLevel level)
{
    switch (level) {
    case kernel_LogLevel::kernel_LOG_INFO: {
        return "info";
    }
    case kernel_LogLevel::kernel_LOG_DEBUG: {
        return "debug";
    }
    case kernel_LogLevel::kernel_LOG_TRACE: {
        return "trace";
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

std::string log_category_to_string(const kernel_LogCategory category)
{
    switch (category) {
    case kernel_LogCategory::kernel_LOG_BENCH: {
        return "bench";
    }
    case kernel_LogCategory::kernel_LOG_BLOCKSTORAGE: {
        return "blockstorage";
    }
    case kernel_LogCategory::kernel_LOG_COINDB: {
        return "coindb";
    }
    case kernel_LogCategory::kernel_LOG_LEVELDB: {
        return "leveldb";
    }
    case kernel_LogCategory::kernel_LOG_LOCK: {
        return "lock";
    }
    case kernel_LogCategory::kernel_LOG_MEMPOOL: {
        return "mempool";
    }
    case kernel_LogCategory::kernel_LOG_PRUNE: {
        return "prune";
    }
    case kernel_LogCategory::kernel_LOG_RAND: {
        return "rand";
    }
    case kernel_LogCategory::kernel_LOG_REINDEX: {
        return "reindex";
    }
    case kernel_LogCategory::kernel_LOG_VALIDATION: {
        return "validation";
    }
    case kernel_LogCategory::kernel_LOG_KERNEL: {
        return "kernel";
    }
    case kernel_LogCategory::kernel_LOG_ALL: {
        return "all";
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

class KernelChainParams
{
    uint64_t m_tag;

public:
    std::unique_ptr<const CChainParams> m_chainparams;

    KernelChainParams(std::unique_ptr<const CChainParams> chainparams)
        : m_tag{KERNEL_CHAIN_PARAMS_TAG},
          m_chainparams{std::move(chainparams)}
    {
    }

    bool IsValid() const
    {
        return m_tag == KERNEL_CHAIN_PARAMS_TAG;
    }
};

kernel_SynchronizationState cast_state(SynchronizationState state)
{
    switch (state) {
    case SynchronizationState::INIT_REINDEX:
        return kernel_SynchronizationState::kernel_INIT_REINDEX;
    case SynchronizationState::INIT_DOWNLOAD:
        return kernel_SynchronizationState::kernel_INIT_DOWNLOAD;
    case SynchronizationState::POST_INIT:
        return kernel_SynchronizationState::kernel_POST_INIT;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

kernel_Warning cast_kernel_warning(kernel::Warning warning)
{
    switch (warning) {
    case kernel::Warning::UNKNOWN_NEW_RULES_ACTIVATED:
        return kernel_Warning::kernel_LARGE_WORK_INVALID_CHAIN;
    case kernel::Warning::LARGE_WORK_INVALID_CHAIN:
        return kernel_Warning::kernel_LARGE_WORK_INVALID_CHAIN;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

class KernelNotifications : public kernel::Notifications
{
private:
    uint64_t m_tag;
    kernel_NotificationInterfaceCallbacks m_cbs;

public:
    KernelNotifications(kernel_NotificationInterfaceCallbacks cbs)
        : m_tag{KERNEL_NOTIFICATIONS_TAG},
          m_cbs{cbs}
    {
    }

    kernel::InterruptResult blockTip(SynchronizationState state, CBlockIndex& index) override
    {
        if (m_cbs.block_tip) m_cbs.block_tip(m_cbs.user_data, cast_state(state), reinterpret_cast<kernel_BlockIndex*>(&index));
        return {};
    }
    void headerTip(SynchronizationState state, int64_t height, int64_t timestamp, bool presync) override
    {
        if (m_cbs.header_tip) m_cbs.header_tip(m_cbs.user_data, cast_state(state), height, timestamp, presync);
    }
    void warningSet(kernel::Warning id, const bilingual_str& message) override
    {
        if (m_cbs.warning_set) m_cbs.warning_set(m_cbs.user_data, cast_kernel_warning(id), message.original.c_str());
    }
    void warningUnset(kernel::Warning id) override
    {
        if (m_cbs.warning_unset) m_cbs.warning_unset(m_cbs.user_data, cast_kernel_warning(id));
    }
    void flushError(const bilingual_str& message) override
    {
        if (m_cbs.flush_error) m_cbs.flush_error(m_cbs.user_data, message.original.c_str());
    }
    void fatalError(const bilingual_str& message) override
    {
        if (m_cbs.fatal_error) m_cbs.fatal_error(m_cbs.user_data, message.original.c_str());
    }

    bool IsValid() const
    {
        return m_tag == KERNEL_NOTIFICATIONS_TAG;
    }
};

struct ContextOptions {
    std::unique_ptr<const KernelNotifications> m_notifications;
    std::unique_ptr<const CChainParams> m_chainparams;
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
        if (options && options->m_notifications) {
            m_notifications = std::make_unique<KernelNotifications>(*options->m_notifications);
        } else {
            m_notifications = std::make_unique<KernelNotifications>(kernel_NotificationInterfaceCallbacks{
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr});
        }

        if (options && options->m_chainparams) {
            m_chainparams = std::make_unique<const CChainParams>(*options->m_chainparams);
        } else {
            m_chainparams = CChainParams::Main();
        }

        if (!kernel::SanityChecks(*m_context)) {
            sane = false;
        }
    }
};

const ContextOptions* cast_const_context_options(const kernel_ContextOptions* options)
{
    assert(options);
    return reinterpret_cast<const ContextOptions*>(options);
}

ContextOptions* cast_context_options(kernel_ContextOptions* options)
{
    assert(options);
    return reinterpret_cast<ContextOptions*>(options);
}

const KernelChainParams* cast_const_chain_params(const kernel_ChainParameters* chain_params)
{
    assert(chain_params);
    return reinterpret_cast<const KernelChainParams*>(chain_params);
}

const KernelNotifications* cast_const_notifications(const kernel_Notifications* notifications)
{
    assert(notifications);
    return reinterpret_cast<const KernelNotifications*>(notifications);
}

Context* cast_context(kernel_Context* context)
{
    assert(context);
    return reinterpret_cast<Context*>(context);
}

} // namespace

bool kernel_verify_script(const unsigned char* script_pubkey, size_t script_pubkey_len,
                         const int64_t amount_,
                         const unsigned char* tx_to, size_t tx_to_len,
                         const kernel_TransactionOutput* spent_outputs_, size_t spent_outputs_len,
                         const unsigned int input_index,
                         const unsigned int flags,
                         kernel_ScriptVerifyStatus* status)
{
    const CAmount amount{amount_};

    if (!verify_flags(flags)) {
        if (status) *status = kernel_SCRIPT_VERIFY_ERROR_INVALID_FLAGS;
        return false;
    }

    if (!is_valid_flag_combination(flags)) {
        if (status) *status = kernel_SCRIPT_VERIFY_ERROR_INVALID_FLAGS_COMBINATION;
        return false;
    }

    if (flags & kernel_SCRIPT_FLAGS_VERIFY_TAPROOT && spent_outputs_ == nullptr) {
        if (status) *status = kernel_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_REQUIRED;
        return false;
    }

    try {
        TxInputStream stream{tx_to, tx_to_len};
        CTransaction tx{deserialize, TX_WITH_WITNESS, stream};

        std::vector<CTxOut> spent_outputs;
        if (spent_outputs_ != nullptr) {
            if (spent_outputs_len != tx.vin.size()) {
                if (status) *status = kernel_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_MISMATCH;
                return false;
            }
            spent_outputs.reserve(spent_outputs_len);
            for (size_t i = 0; i < spent_outputs_len; i++) {
                CScript spk{CScript(spent_outputs_[i].script_pubkey, spent_outputs_[i].script_pubkey + spent_outputs_[i].script_pubkey_len)};
                const CAmount& value{spent_outputs_[i].value};
                CTxOut tx_out{CTxOut(value, spk)};
                spent_outputs.push_back(tx_out);
            }
        }

        if (input_index >= tx.vin.size()) {
            if (status) *status = kernel_SCRIPT_VERIFY_ERROR_TX_INPUT_INDEX;
            return false;
        }
        if (GetSerializeSize(TX_WITH_WITNESS(tx)) != tx_to_len) {
            if (status) *status = kernel_SCRIPT_VERIFY_ERROR_TX_SIZE_MISMATCH;
            return false;
        }

        PrecomputedTransactionData txdata{tx};

        if (spent_outputs_ != nullptr && flags & kernel_SCRIPT_FLAGS_VERIFY_TAPROOT) {
            txdata.Init(tx, std::move(spent_outputs));
        }

        return VerifyScript(tx.vin[input_index].scriptSig,
                            CScript(script_pubkey,
                                    script_pubkey + script_pubkey_len),
                            &tx.vin[input_index].scriptWitness,
                            flags,
                            TransactionSignatureChecker(&tx, input_index, amount, txdata, MissingDataBehavior::FAIL),
                            nullptr);
    } catch (const std::exception&) {
        if (status) *status = kernel_SCRIPT_VERIFY_ERROR_TX_DESERIALIZE;
        return false;
    }
}

bool kernel_add_log_level_category(const kernel_LogCategory category, const kernel_LogLevel level_)
{
    const auto level{log_level_to_string(level_)};
    if (category == kernel_LogCategory::kernel_LOG_ALL) {
        return LogInstance().SetLogLevel(level);
    }

    return LogInstance().SetCategoryLogLevel(log_category_to_string(category), level);
}

bool kernel_enable_log_category(const kernel_LogCategory category)
{
    return LogInstance().EnableCategory(log_category_to_string(category));
}

bool kernel_disable_log_category(const kernel_LogCategory category)
{
    return LogInstance().DisableCategory(log_category_to_string(category));
}

void kernel_disable_logging()
{
    LogInstance().DisableLogging();
}

kernel_LoggingConnection* kernel_logging_connection_create(kernel_LogCallback callback,
                                                           void* user_data,
                                                           const kernel_LoggingOptions options)
{
    LogInstance().m_log_timestamps = options.log_timestamps;
    LogInstance().m_log_time_micros = options.log_time_micros;
    LogInstance().m_log_threadnames = options.log_threadnames;
    LogInstance().m_log_sourcelocations = options.log_sourcelocations;
    LogInstance().m_always_print_category_level = options.always_print_category_levels;

    auto connection{LogInstance().PushBackCallback([callback, user_data](const std::string& str) { callback(user_data, str.c_str()); })};

    try {
        // Only start logging if we just added the connection.
        if (LogInstance().NumConnections() == 1 && !LogInstance().StartLogging()) {
            LogError("Logger start failed.\n");
            LogInstance().DeleteCallback(connection);
            return nullptr;
        }
    } catch (std::exception& e) {
        LogError("Logger start failed.\n");
        LogInstance().DeleteCallback(connection);
        return nullptr;
    }

    LogDebug(BCLog::KERNEL, "Logger connected.\n");

    auto heap_connection{new std::list<std::function<void(const std::string&)>>::iterator(connection)};
    return reinterpret_cast<kernel_LoggingConnection*>(heap_connection);
}

void kernel_logging_connection_destroy(kernel_LoggingConnection* connection_)
{
    auto connection{reinterpret_cast<std::list<std::function<void(const std::string&)>>::iterator*>(connection_)};
    if (!connection) {
        return;
    }

    LogDebug(BCLog::KERNEL, "Logger disconnected.\n");
    LogInstance().DeleteCallback(*connection);
    delete connection;

    // We are not buffering if we have a connection, so check that it is not the
    // last available connection.
    if (!LogInstance().Enabled()) {
        LogInstance().DisconnectTestLogger();
    }
}

const kernel_ChainParameters* kernel_chain_parameters_create(const kernel_ChainType chain_type)
{
    switch (chain_type) {
    case kernel_ChainType::kernel_CHAIN_TYPE_MAINNET: {
        return reinterpret_cast<const kernel_ChainParameters*>(new KernelChainParams(CChainParams::Main()));
    }
    case kernel_ChainType::kernel_CHAIN_TYPE_TESTNET: {
        return reinterpret_cast<const kernel_ChainParameters*>(new KernelChainParams(CChainParams::TestNet()));
    }
    case kernel_ChainType::kernel_CHAIN_TYPE_SIGNET: {
        return reinterpret_cast<const kernel_ChainParameters*>(new KernelChainParams(CChainParams::SigNet({})));
    }
    case kernel_ChainType::kernel_CHAIN_TYPE_REGTEST: {
        return reinterpret_cast<const kernel_ChainParameters*>(new KernelChainParams(CChainParams::RegTest({})));
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

void kernel_chain_parameters_destroy(const kernel_ChainParameters* chain_parameters)
{
    if (chain_parameters) {
        delete cast_const_chain_params(chain_parameters);
    }
}

kernel_Notifications* kernel_notifications_create(kernel_NotificationInterfaceCallbacks callbacks)
{
    return reinterpret_cast<kernel_Notifications*>(new KernelNotifications{callbacks});
}

void kernel_notifications_destroy(const kernel_Notifications* notifications)
{
    if (notifications) {
        delete cast_const_notifications(notifications);
    }
}

kernel_ContextOptions* kernel_context_options_create()
{
    return reinterpret_cast<kernel_ContextOptions*>(new ContextOptions{});
}

bool kernel_context_options_set(kernel_ContextOptions* options_, const kernel_ContextOptionType n_option, const void* value)
{
    auto options{cast_context_options(options_)};
    switch (n_option) {
    case kernel_ContextOptionType::kernel_CHAIN_PARAMETERS_OPTION: {
        auto chain_params{reinterpret_cast<const KernelChainParams*>(value)};
        if (!chain_params->IsValid()) {
            LogError("Selected kernel notifications context option, but the value is not a valid chain params struct.\n");
            return false;
        }
        // Copy the chainparams, so the caller can free it again
        options->m_chainparams = std::make_unique<const CChainParams>(*chain_params->m_chainparams);
        return true;
    }
    case kernel_ContextOptionType::kernel_NOTIFICATIONS_OPTION: {
        auto notifications{reinterpret_cast<const KernelNotifications*>(value)};
        if (!notifications->IsValid()) {
            LogError("Selected kernel notifications context option, but the value is not a valid kernel notifications struct.\n");
            return false;
        }
        // This copies the data, so the caller can free it again.
        options->m_notifications = std::make_unique<KernelNotifications>(*notifications);
        return true;
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

void kernel_context_options_destroy(kernel_ContextOptions* options)
{
    if (options) {
        delete cast_context_options(options);
    }
}

kernel_Context* kernel_context_create(const kernel_ContextOptions* options_)
{
    auto options{cast_const_context_options(options_)};
    bool sane{true};
    auto context{new Context{options, sane}};
    if (!sane) {
        LogError("Kernel context sanity check failed.\n");
        delete context;
        return nullptr;
    }
    return reinterpret_cast<kernel_Context*>(context);
}

void kernel_context_destroy(kernel_Context* context)
{
    if (context) {
        delete cast_context(context);
    }
}
