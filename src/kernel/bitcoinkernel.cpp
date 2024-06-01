// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>

#include <chain.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <kernel/chainparams.h>
#include <kernel/checks.h>
#include <kernel/context.h>
#include <kernel/notifications_interface.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <node/caches.h>
#include <node/chainstate.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <sync.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/result.h>
#include <util/signalinterrupt.h>
#include <util/task_runner.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

// Define G_TRANSLATION_FUN symbol in libbitcoinkernel library so users of the
// library aren't required to export this symbol
extern const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

static const kernel::Context kernel_context_static{};

namespace {

/** A class that deserializes a single CTransaction one time. */
class TxInputStream
{
public:
    TxInputStream(const unsigned char* txTo, size_t txToLen) : m_data(txTo),
                                                               m_remaining(txToLen)
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

private:
    const unsigned char* m_data;
    size_t m_remaining;
};

void set_error_ok(kernel_Error* error)
{
    if (error) {
        error->code = kernel_ErrorCode::kernel_ERROR_OK;
    }
}

void set_error(kernel_Error* error, kernel_ErrorCode error_code, std::string message)
{
    if (error) {
        error->code = error_code;
        // clamp error message size
        if (message.size() > sizeof(error->message)) {
            message.resize(sizeof(error->message) - 1);
        }
        memcpy(error->message, message.c_str(), message.size() + 1);
    }
}

void set_error_invalid_pointer(kernel_Error* error, std::string message)
{
    set_error(error, kernel_ErrorCode::kernel_ERROR_INVALID_POINTER, message);
}

/** Check that all specified flags are part of the libbitcoinkernel interface. */
static bool verify_flags(unsigned int flags)
{
    return (flags & ~(kernel_SCRIPT_FLAGS_VERIFY_ALL)) == 0;
}

static bool is_valid_flag_combination(unsigned int flags)
{
    if (flags & SCRIPT_VERIFY_CLEANSTACK && ~flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) return false;
    if (flags & SCRIPT_VERIFY_WITNESS && ~flags & SCRIPT_VERIFY_P2SH) return false;
    return true;
}

static int verify_script(const unsigned char* scriptPubKey, size_t scriptPubKeyLen,
                         const CAmount amount,
                         const unsigned char* txTo, size_t txToLen,
                         const kernel_TransactionOutput* spentOutputs, size_t spentOutputsLen,
                         const unsigned int nIn, const unsigned int flags, kernel_Error* error)
{
    if (!verify_flags(flags)) {
        set_error(error, kernel_ERROR_INVALID_FLAGS, "");
        return 0;
    }

    if (!is_valid_flag_combination(flags)) {
        set_error(error, kernel_ERROR_INVALID_FLAGS_COMBINATION, "This combination of flags is not supported.");
        return 0;
    }

    if (flags & kernel_SCRIPT_FLAGS_VERIFY_TAPROOT && spentOutputs == nullptr) {
        set_error(error, kernel_ERROR_SPENT_OUTPUTS_REQUIRED, "");
        return 0;
    }

    try {
        TxInputStream stream{txTo, txToLen};
        CTransaction tx{deserialize, TX_WITH_WITNESS, stream};

        std::vector<CTxOut> spent_outputs;
        if (spentOutputs != nullptr) {
            if (spentOutputsLen != tx.vin.size()) {
                set_error(error, kernel_ERROR_SPENT_OUTPUTS_MISMATCH, "");
                return 0;
            }
            for (size_t i = 0; i < spentOutputsLen; i++) {
                CScript spk{CScript(spentOutputs[i].script_pubkey, spentOutputs[i].script_pubkey + spentOutputs[i].script_pubkey_len)};
                const CAmount& value{spentOutputs[i].value};
                CTxOut tx_out{CTxOut(value, spk)};
                spent_outputs.push_back(tx_out);
            }
        }

        if (nIn >= tx.vin.size()) {
            set_error(error, kernel_ERROR_TX_INDEX, "");
            return 0;
        }
        if (GetSerializeSize(TX_WITH_WITNESS(tx)) != txToLen) {
            set_error(error, kernel_ERROR_TX_SIZE_MISMATCH, "");
            return 0;
        }

        // Regardless of the verification result, the tx did not error.
        set_error_ok(error);

        PrecomputedTransactionData txdata(tx);

        if (spentOutputs != nullptr && flags & kernel_SCRIPT_FLAGS_VERIFY_TAPROOT) {
            txdata.Init(tx, std::move(spent_outputs));
        }

        return VerifyScript(tx.vin[nIn].scriptSig, CScript(scriptPubKey, scriptPubKey + scriptPubKeyLen), &tx.vin[nIn].scriptWitness, flags, TransactionSignatureChecker(&tx, nIn, amount, txdata, MissingDataBehavior::FAIL), nullptr);
    } catch (const std::exception&) {
        set_error(error, kernel_ERROR_TX_DESERIALIZE, ""); // Error deserializing
        return 0;
    }
}

std::string kernel_log_level_to_string(const kernel_LogLevel level)
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
    }
}

std::string kernel_log_category_to_string(const kernel_LogCategory category)
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
    case kernel_LogCategory::kernel_LOG_NONE: {
        return "none";
    }
    case kernel_LogCategory::kernel_LOG_ALL: {
        return "all";
    }
    }
}

kernel_SynchronizationState cast_state(SynchronizationState state)
{
    switch (state) {
    case SynchronizationState::INIT_REINDEX:
        return kernel_SynchronizationState::kernel_INIT_REINDEX;
    case SynchronizationState::INIT_DOWNLOAD:
        return kernel_SynchronizationState::kernel_INIT_DOWNLOAD;
    case SynchronizationState::POST_INIT:
        return kernel_SynchronizationState::kernel_POST_INIT;
    }
    assert(false);
}

class KernelNotifications : public kernel::Notifications
{
private:
    std::unique_ptr<const kernel_NotificationInterfaceCallbacks> m_cbs;

public:
    KernelNotifications(std::unique_ptr<const kernel_NotificationInterfaceCallbacks> kni_cbs)
        : m_cbs{std::move(kni_cbs)} {}

    kernel::InterruptResult blockTip(SynchronizationState state, CBlockIndex& index) override
    {
        if (m_cbs && m_cbs->block_tip) m_cbs->block_tip(m_cbs->user_data, cast_state(state), reinterpret_cast<kernel_BlockIndex*>(&index));
        return {};
    }

    void headerTip(SynchronizationState state, int64_t height, int64_t timestamp, bool presync) override
    {
        if (m_cbs && m_cbs->header_tip) m_cbs->header_tip(m_cbs->user_data, cast_state(state), height, timestamp, presync);
    }

    void warning(const bilingual_str& warning) override
    {
        if (m_cbs && m_cbs->warning) m_cbs->warning(m_cbs->user_data, warning.original.c_str());
    }
    void flushError(const bilingual_str& message) override
    {
        if (m_cbs && m_cbs->flush_error) m_cbs->flush_error(m_cbs->user_data, message.original.c_str());
    }
    void fatalError(const bilingual_str& message) override
    {
        if (m_cbs && m_cbs->fatal_error) m_cbs->fatal_error(m_cbs->user_data, message.original.c_str());
    }
};

class ValidationTaskRunner : public util::TaskRunnerInterface
{
private:
    std::unique_ptr<const kernel_TaskRunnerCallbacks> m_cbs;

public:
    ValidationTaskRunner(std::unique_ptr<const kernel_TaskRunnerCallbacks> tr_cbs) : m_cbs{std::move(tr_cbs)} {}

    void insert(std::function<void()> func) override
    {
        if (m_cbs && m_cbs->insert) {
            // prevent the event from being deleted when it goes out of scope
            // here, it is the caller's responsibility to correctly call
            // kernel_execute_event_and_destroy to process it, preventing a memory leak.
            auto heap_func = new std::function<void()>(func);

            m_cbs->insert(m_cbs->user_data, reinterpret_cast<kernel_ValidationEvent*>(heap_func));
        }
    }

    void flush() override
    {
        if (m_cbs && m_cbs->flush) m_cbs->flush(m_cbs->user_data);
    }

    size_t size() override
    {
        if (m_cbs && m_cbs->size) return m_cbs->size(m_cbs->user_data);
        return 0;
    }
};

struct ContextOptions {
    std::unique_ptr<const kernel_NotificationInterfaceCallbacks> m_kni_cbs;
    std::unique_ptr<const CChainParams> m_chainparams;
    std::unique_ptr<const kernel_TaskRunnerCallbacks> m_tr_cbs;

    void set_option(const kernel_ContextOptionType option, const void* value, kernel_Error* err)
    {
        switch (option) {
        case kernel_ContextOptionType::kernel_NOTIFICATION_INTERFACE_CALLBACKS_OPTION: {
            auto kni_cbs{reinterpret_cast<const kernel_NotificationInterfaceCallbacks*>(value)};
            if (!kni_cbs) {
                set_error_invalid_pointer(err, "Invalid kernel_NotificationInterfaceCallbacks pointer.");
                return;
            }
            // This copies the data, so the caller can free it again.
            m_kni_cbs = std::make_unique<kernel_NotificationInterfaceCallbacks>(*kni_cbs);
            set_error_ok(err);
            return;
        }
        case kernel_ContextOptionType::kernel_CHAIN_PARAMETERS_OPTION: {
            auto chain_params = reinterpret_cast<const CChainParams*>(value);
            if (!chain_params) {
                set_error_invalid_pointer(err, "Invalid kernel_ChainParameters pointer.");
                return;
            }
            m_chainparams = std::make_unique<const CChainParams>(*chain_params);
            set_error_ok(err);
            return;
        }
        case kernel_ContextOptionType::kernel_TASK_RUNNER_CALLBACKS_OPTION: {
            auto tr_cbs{reinterpret_cast<const kernel_TaskRunnerCallbacks*>(value)};
            if (!tr_cbs) {
                set_error_invalid_pointer(err, "Invalid kernel_TaskRunnerCallbacks pointer.");
            }
            m_tr_cbs = std::make_unique<kernel_TaskRunnerCallbacks>(*tr_cbs);
            set_error_ok(err);
            return;
        }
        default: {
            set_error(err, kernel_ErrorCode::kernel_ERROR_UNKNOWN_OPTION, "Unknown context option");
        }
        }
    }
};

class Context
{
public:
    std::unique_ptr<kernel::Context> m_context;

    std::unique_ptr<ValidationSignals> m_signals;

    std::unique_ptr<KernelNotifications> m_notifications;

    std::unique_ptr<util::SignalInterrupt> m_interrupt;

    std::unique_ptr<const CChainParams> m_chainparams;

    Context(kernel_Error* error, const ContextOptions* options)
        : m_context{std::make_unique<kernel::Context>()},
          m_interrupt{std::make_unique<util::SignalInterrupt>()}
    {
        if (options && options->m_kni_cbs) {
            m_notifications = std::make_unique<KernelNotifications>(
                std::make_unique<const kernel_NotificationInterfaceCallbacks>(*options->m_kni_cbs));
        } else {
            m_notifications = std::make_unique<KernelNotifications>(nullptr);
        }

        if (options && options->m_chainparams) {
            m_chainparams = std::make_unique<const CChainParams>(*options->m_chainparams);
        } else {
            m_chainparams = CChainParams::Main();
        }

        if (options && options->m_tr_cbs) {
            m_signals = std::make_unique<ValidationSignals>(std::make_unique<ValidationTaskRunner>(
                std::make_unique<const kernel_TaskRunnerCallbacks>(*options->m_tr_cbs)));
        }

        if (!kernel::SanityChecks(*m_context)) {
            set_error(error, kernel_ErrorCode::kernel_ERROR_INVALID_CONTEXT, "Context sanity check failed.");
        } else {
            set_error_ok(error);
        }
    }
};

class KernelValidationInterface final : public CValidationInterface
{
public:
    const kernel_ValidationInterfaceCallbacks m_cbs;

    explicit KernelValidationInterface(const kernel_ValidationInterfaceCallbacks vi_cbs) : m_cbs{vi_cbs} {}

protected:
    void BlockChecked(const CBlock& block, const BlockValidationState& stateIn) override
    {
        if (m_cbs.block_checked) {
            m_cbs.block_checked(m_cbs.user_data,
                                reinterpret_cast<const kernel_BlockPointer*>(&block),
                                reinterpret_cast<const kernel_BlockValidationState*>(&stateIn));
        }
    }
};

ContextOptions* cast_context_options(kernel_ContextOptions* context_opts, kernel_Error* error)
{
    if (!context_opts) {
        set_error_invalid_pointer(error, "Invalid kernel_ContextOptions pointer.");
    }
    return reinterpret_cast<ContextOptions*>(context_opts);
}

const Context* cast_const_context(const kernel_Context* context, kernel_Error* error)
{
    if (!context) {
        set_error_invalid_pointer(error, "Invalid kernel_Context pointer.");
        return nullptr;
    }
    return reinterpret_cast<const Context*>(context);
}

Context* cast_context(kernel_Context* context, kernel_Error* error)
{
    if (!context) {
        set_error_invalid_pointer(error, "Invalid kernel_Context pointer.");
        return nullptr;
    }
    return reinterpret_cast<Context*>(context);
}

ChainstateManager* cast_chainstate_manager(kernel_ChainstateManager* chainman, kernel_Error* error)
{
    if (!chainman) {
        set_error_invalid_pointer(error, "Invalid kernel_ChainstateManager pointer.");
        return nullptr;
    }
    return reinterpret_cast<ChainstateManager*>(chainman);
}

ChainstateManager::Options* cast_chainman_opts(kernel_ChainstateManagerOptions* chainman_opts, kernel_Error* error)
{
    if (!chainman_opts) {
        set_error_invalid_pointer(error, "Invalid kernel_ChainstateManagerOptions pointer.");
        return nullptr;
    }
    return reinterpret_cast<ChainstateManager::Options*>(chainman_opts);
}

node::BlockManager::Options* cast_blockman_opts(kernel_BlockManagerOptions* blockman_opts, kernel_Error* error)
{
    if (!blockman_opts) {
        set_error_invalid_pointer(error, "Invalid kernel_BlockManagerOptions pointer.");
        return nullptr;
    }
    return reinterpret_cast<node::BlockManager::Options*>(blockman_opts);
}

std::shared_ptr<CBlock>* cast_cblocksharedpointer(kernel_Block* block, kernel_Error* err)
{
    if (!block) {
        set_error_invalid_pointer(err, "Invalid kernel_Block pointer.");
    }
    return reinterpret_cast<std::shared_ptr<CBlock>*>(block);
}

node::ChainstateLoadOptions* cast_chainstate_load_options(kernel_ChainstateLoadOptions* load_opts, kernel_Error* err)
{
    if (!load_opts) {
        set_error_invalid_pointer(err, "Invalid kernel_ChainstateLoadOptions pointer.");
    }
    return reinterpret_cast<node::ChainstateLoadOptions*>(load_opts);
}

const CBlock* cast_cblockpointer(const kernel_BlockPointer* block_pointer, kernel_Error* err)
{
    if (!block_pointer) {
        set_error_invalid_pointer(err, "Invalid kernel_BlockPointer pointer.");
    }
    return reinterpret_cast<const CBlock*>(block_pointer);
}

CBlockIndex* cast_block_index(kernel_BlockIndex* block_index, kernel_Error* err)
{
    if (!block_index) {
        set_error_invalid_pointer(err, "Invalid kernel_BlockIndex pointer.");
        return nullptr;
    }
    return reinterpret_cast<CBlockIndex*>(block_index);
}

std::shared_ptr<KernelValidationInterface>* cast_validation_interface(kernel_ValidationInterface* validation_interface_, kernel_Error* err)
{
    if (!validation_interface_) {
        set_error_invalid_pointer(err, "Invalid kernel_ValidationInterface pointer.");
        return nullptr;
    }
    auto validation_interface = reinterpret_cast<std::shared_ptr<KernelValidationInterface>*>(validation_interface_);
    if (!*validation_interface) {
        set_error_invalid_pointer(err, "Invalid kernel_ValidationInterface pointer.");
        return nullptr;
    }
    return validation_interface;
}

} // namespace

void kernel_add_log_level_category(const kernel_LogCategory category_, const kernel_LogLevel level_)
{
    const auto level{kernel_log_level_to_string(level_)};
    if (category_ == kernel_LogCategory::kernel_LOG_ALL) {
        LogInstance().SetLogLevel(level);
        return;
    }

    LogInstance().SetCategoryLogLevel(kernel_log_category_to_string(category_), level);
}

void kernel_enable_log_category(const kernel_LogCategory category)
{
    LogInstance().EnableCategory(kernel_log_category_to_string(category));
}

void kernel_disable_log_category(const kernel_LogCategory category)
{
    LogInstance().DisableCategory(kernel_log_category_to_string(category));
}

kernel_LoggingConnection* kernel_logging_connection_create(kernel_LogCallback callback,
                                                           void* user_data,
                                                           const kernel_LoggingOptions options,
                                                           kernel_Error* error)
{
    if (!callback) {
        set_error_invalid_pointer(error, "Invalid kernel_LogCallback callback.");
        return nullptr;
    }
    LogInstance().m_log_timestamps = options.log_timestamps;
    LogInstance().m_log_time_micros = options.log_time_micros;
    LogInstance().m_log_threadnames = options.log_threadnames;
    LogInstance().m_log_sourcelocations = options.log_sourcelocations;
    LogInstance().m_always_print_category_level = options.always_print_category_levels;

    auto connection{LogInstance().PushBackCallback([callback, user_data](const std::string& str) { callback(user_data, str.c_str()); })};
    if (!LogInstance().StartLogging()) {
        set_error(error, kernel_ErrorCode::kernel_ERROR_LOGGING_FAILED, "Logger start failed.");
        return nullptr;
    }
    set_error_ok(error);

    auto heap_connection{new std::list<std::function<void(const std::string&)>>::iterator(connection)};
    return reinterpret_cast<kernel_LoggingConnection*>(heap_connection);
}

void kernel_logging_connection_destroy(kernel_LoggingConnection* connection_)
{
    auto connection{reinterpret_cast<std::list<std::function<void(const std::string&)>>::iterator*>(connection_)};
    if (!connection) {
        return;
    }
    LogInstance().DeleteCallback(*connection);
    delete connection;
}

int kernel_verify_script_with_spent_outputs(const unsigned char* script_pubkey, size_t script_pubkey_len,
                                            const int64_t amount,
                                            const unsigned char* tx_to, size_t tx_to_len,
                                            const kernel_TransactionOutput* spent_outputs, size_t spent_outputs_len,
                                            const unsigned int nIn, const unsigned int flags, kernel_Error* error)
{
    const CAmount am{amount};

    if (!script_pubkey) {
        set_error_invalid_pointer(error, "Invalid script_pubkey pointer.");
        return 0;
    }
    if (!tx_to) {
        set_error_invalid_pointer(error, "Invalid tx_to pointer.");
        return 0;
    }

    return ::verify_script(script_pubkey, script_pubkey_len, am, tx_to, tx_to_len, spent_outputs, spent_outputs_len, nIn, flags, error);
}

int kernel_verify_script_with_amount(const unsigned char* script_pubkey, size_t script_pubkey_len,
                                     const int64_t amount,
                                     const unsigned char* tx_to, size_t tx_to_len,
                                     const unsigned int nIn, const unsigned int flags, kernel_Error* error)
{
    if (!script_pubkey) {
        set_error_invalid_pointer(error, "Invalid script_pubkey pointer.");
        return 0;
    }
    if (!tx_to) {
        set_error_invalid_pointer(error, "Invalid tx_to pointer.");
        return 0;
    }

    const CAmount am{amount};
    const kernel_TransactionOutput* spentOutputs{nullptr};
    unsigned int spentOutputsLen = 0;
    return ::verify_script(script_pubkey, script_pubkey_len, am, tx_to, tx_to_len, spentOutputs, spentOutputsLen, nIn, flags, error);
}

int kernel_verify_script(const unsigned char* script_pubkey, size_t script_pubkey_len,
                         const unsigned char* tx_to, size_t tx_to_len,
                         const unsigned int nIn, const unsigned int flags, kernel_Error* error)
{
    if (!script_pubkey) {
        set_error_invalid_pointer(error, "Invalid script_pubkey pointer.");
        return 0;
    }
    if (!tx_to) {
        set_error_invalid_pointer(error, "Invalid tx_to pointer.");
        return 0;
    }

    if (flags & kernel_ScriptFlags::kernel_SCRIPT_FLAGS_VERIFY_WITNESS) {
        set_error(error, kernel_ErrorCode::kernel_ERROR_AMOUNT_REQUIRED, "");
        return 0;
    }

    const CAmount am{0};
    const kernel_TransactionOutput* spentOutputs{nullptr};
    unsigned int spentOutputsLen{0};
    return ::verify_script(script_pubkey, script_pubkey_len, am, tx_to, tx_to_len, spentOutputs, spentOutputsLen, nIn, flags, error);
}

const kernel_ChainParameters* kernel_chain_parameters_create(const kernel_ChainType chain_type)
{
    switch (chain_type) {
    case kernel_ChainType::kernel_CHAIN_TYPE_MAINNET: {
        return reinterpret_cast<const kernel_ChainParameters*>(CChainParams::Main().release());
    }
    case kernel_ChainType::kernel_CHAIN_TYPE_TESTNET: {
        return reinterpret_cast<const kernel_ChainParameters*>(CChainParams::TestNet().release());
    }
    case kernel_ChainType::kernel_CHAIN_TYPE_SIGNET: {
        return reinterpret_cast<const kernel_ChainParameters*>(CChainParams::SigNet({}).release());
    }
    case kernel_ChainType::kernel_CHAIN_TYPE_REGTEST: {
        return reinterpret_cast<const kernel_ChainParameters*>(CChainParams::RegTest({}).release());
    }
    }
    assert(0);
}

void kernel_chain_parameters_destroy(const kernel_ChainParameters* chain_parameters)
{
    delete reinterpret_cast<const CChainParams*>(chain_parameters);
}

kernel_ContextOptions* kernel_context_options_create()
{
    return reinterpret_cast<kernel_ContextOptions*>(new ContextOptions{});
}

void kernel_context_options_set(kernel_ContextOptions* context_opts_, const kernel_ContextOptionType n_option, const void* value, kernel_Error* error)
{
    auto context_options{cast_context_options(context_opts_, error)};
    if (!context_options) {
        return;
    }
    context_options->set_option(n_option, value, error);
}

void kernel_context_options_destroy(kernel_ContextOptions* context_opts_)
{
    delete reinterpret_cast<ContextOptions*>(context_opts_);
}

kernel_Context* kernel_context_create(const kernel_ContextOptions* options, kernel_Error* error)
{
    auto context_options{reinterpret_cast<const ContextOptions*>(options)};
    return reinterpret_cast<kernel_Context*>(new Context{error, context_options});
}

bool kernel_context_interrupt(kernel_Context* context_, kernel_Error* error)
{
    auto context{cast_context(context_, error)};
    if (!context) {
        return false;
    }

    return (*context->m_interrupt)();
}

void kernel_context_destroy(kernel_Context* context_)
{
    delete reinterpret_cast<Context*>(context_);
}

kernel_ValidationInterface* kernel_validation_interface_create(kernel_ValidationInterfaceCallbacks vi_cbs)
{
    return reinterpret_cast<kernel_ValidationInterface*>(new std::shared_ptr<KernelValidationInterface>(new KernelValidationInterface(vi_cbs)));
}

void kernel_validation_interface_register(kernel_Context* context_, kernel_ValidationInterface* validation_interface_, kernel_Error* err)
{
    auto context{cast_context(context_, err)};
    if (!context) {
        return;
    }
    auto validation_interface{cast_validation_interface(validation_interface_, err)};
    if (!validation_interface) {
        return;
    }
    if (!context->m_signals) {
        set_error(err, kernel_ErrorCode::kernel_ERROR_INVALID_CONTEXT, "Cannot register validation interface with context that has no validation signals");
    }
    context->m_signals->RegisterSharedValidationInterface(*validation_interface);
    set_error_ok(err);
}

void kernel_validation_interface_unregister(kernel_Context* context_, kernel_ValidationInterface* validation_interface_, kernel_Error* err)
{
    auto context{cast_context(context_, err)};
    if (!context) {
        return;
    }
    auto validation_interface{cast_validation_interface(validation_interface_, err)};
    if (!validation_interface) {
        return;
    }
    if (!context->m_signals) {
        set_error(err, kernel_ErrorCode::kernel_ERROR_INVALID_CONTEXT, "Cannot de-register validation interface with context that has no validation signals");
    }
    context->m_signals->SyncWithValidationInterfaceQueue();
    context->m_signals->FlushBackgroundCallbacks();
    context->m_signals->UnregisterSharedValidationInterface(*validation_interface);
    set_error_ok(err);
}

void kernel_validation_interface_destroy(kernel_ValidationInterface* validation_interface)
{
    if (!validation_interface) {
        return;
    }
    delete reinterpret_cast<std::shared_ptr<KernelValidationInterface>*>(validation_interface);
}

void kernel_execute_event_and_destroy(kernel_ValidationEvent* event, kernel_Error* error)
{
    std::function<void()>* func = reinterpret_cast<std::function<void()>*>(event);
    if (!func) {
        set_error_invalid_pointer(error, "Invalid kernel_ValidationEvent pointer");
        return;
    }
    try {
        (*func)();
        delete func;
    } catch (const std::exception& e) {
        set_error(error, kernel_ErrorCode::kernel_ERROR_INTERNAL, std::string{e.what()});
        if (func) delete func;
    }
}

kernel_ValidationMode kernel_get_validation_mode_from_block_validation_state(const kernel_BlockValidationState* block_validation_state_)
{
    auto block_validation_state = reinterpret_cast<const BlockValidationState*>(block_validation_state_);
    if (block_validation_state->IsValid()) return kernel_ValidationMode::kernel_VALIDATION_STATE_VALID;
    if (block_validation_state->IsInvalid()) return kernel_ValidationMode::kernel_VALIDATION_STATE_INVALID;
    return kernel_ValidationMode::kernel_VALIDATION_STATE_ERROR;
}

kernel_BlockValidationResult kernel_get_block_validation_result_from_block_validation_state(const kernel_BlockValidationState* block_validation_state_)
{
    auto block_validation_state = reinterpret_cast<const BlockValidationState*>(block_validation_state_);
    switch (block_validation_state->GetResult()) {
    case BlockValidationResult::BLOCK_RESULT_UNSET:
        return kernel_BlockValidationResult::kernel_BLOCK_RESULT_UNSET;
    case BlockValidationResult::BLOCK_CONSENSUS:
        return kernel_BlockValidationResult::kernel_BLOCK_CONSENSUS;
    case BlockValidationResult::BLOCK_RECENT_CONSENSUS_CHANGE:
        return kernel_BlockValidationResult::kernel_BLOCK_RECENT_CONSENSUS_CHANGE;
    case BlockValidationResult::BLOCK_CACHED_INVALID:
        return kernel_BlockValidationResult::kernel_BLOCK_CACHED_INVALID;
    case BlockValidationResult::BLOCK_INVALID_HEADER:
        return kernel_BlockValidationResult::kernel_BLOCK_INVALID_HEADER;
    case BlockValidationResult::BLOCK_MUTATED:
        return kernel_BlockValidationResult::kernel_BLOCK_MUTATED;
    case BlockValidationResult::BLOCK_MISSING_PREV:
        return kernel_BlockValidationResult::kernel_BLOCK_MISSING_PREV;
    case BlockValidationResult::BLOCK_INVALID_PREV:
        return kernel_BlockValidationResult::kernel_BLOCK_INVALID_PREV;
    case BlockValidationResult::BLOCK_TIME_FUTURE:
        return kernel_BlockValidationResult::kernel_BLOCK_TIME_FUTURE;
    case BlockValidationResult::BLOCK_CHECKPOINT:
        return kernel_BlockValidationResult::kernel_BLOCK_CHECKPOINT;
    case BlockValidationResult::BLOCK_HEADER_LOW_WORK:
        return kernel_BlockValidationResult::kernel_BLOCK_HEADER_LOW_WORK;
    }
}

kernel_ChainstateManagerOptions* kernel_chainstate_manager_options_create(const kernel_Context* context_, const char* data_dir, kernel_Error* error)
{
    fs::path abs_data_dir{fs::absolute(fs::PathFromString(data_dir))};
    fs::create_directories(abs_data_dir);
    auto context{cast_const_context(context_, error)};
    if (!context) {
        return nullptr;
    }
    return reinterpret_cast<kernel_ChainstateManagerOptions*>(new ChainstateManager::Options{
        .chainparams = *context->m_chainparams,
        .datadir = abs_data_dir,
        .notifications = *context->m_notifications,
        .signals = context->m_signals.get()});
}

void kernel_chainstate_manager_options_destroy(kernel_ChainstateManagerOptions* chainman_opts_)
{
    delete reinterpret_cast<ChainstateManager::Options*>(chainman_opts_);
}

kernel_BlockManagerOptions* kernel_block_manager_options_create(const kernel_Context* context_, const char* blocks_dir, kernel_Error* error)
{
    fs::path abs_blocks_dir{fs::absolute(fs::PathFromString(blocks_dir))};
    fs::create_directories(abs_blocks_dir);
    auto context{cast_const_context(context_, error)};
    if (!context) {
        return nullptr;
    }
    return reinterpret_cast<kernel_BlockManagerOptions*>(new node::BlockManager::Options{
        .chainparams = *context->m_chainparams,
        .blocks_dir = abs_blocks_dir,
        .notifications = *context->m_notifications});
}

void kernel_block_manager_options_destroy(kernel_BlockManagerOptions* blockman_opts_)
{
    delete reinterpret_cast<node::BlockManager::Options*>(blockman_opts_);
}

kernel_ChainstateManager* kernel_chainstate_manager_create(
    kernel_ChainstateManagerOptions* chainstate_manager_opts,
    kernel_BlockManagerOptions* block_manager_opts,
    const kernel_Context* context_,
    kernel_Error* error)
{
    auto chainman_opts{cast_chainman_opts(chainstate_manager_opts, error)};
    if (!chainman_opts) {
        return nullptr;
    }
    auto blockman_opts{cast_blockman_opts(block_manager_opts, error)};
    if (!blockman_opts) {
        return nullptr;
    }
    auto context{cast_const_context(context_, error)};
    if (!context) {
        return nullptr;
    }

    return reinterpret_cast<kernel_ChainstateManager*>(new ChainstateManager{*context->m_interrupt, *chainman_opts, *blockman_opts});
}

kernel_ChainstateLoadOptions* kernel_chainstate_load_options_create()
{
    return reinterpret_cast<kernel_ChainstateLoadOptions*>(new node::ChainstateLoadOptions);
}

void kernel_chainstate_load_options_set(
    kernel_ChainstateLoadOptions* chainstate_load_opts_,
    kernel_ChainstateLoadOptionType n_option,
    void* value,
    kernel_Error* error)
{
    auto chainstate_load_opts{cast_chainstate_load_options(chainstate_load_opts_, error)};
    if (!chainstate_load_opts) {
        return;
    }
    switch (n_option) {
    case kernel_ChainstateLoadOptionType::kernel_WIPE_BLOCK_TREE_DB_CHAINSTATE_LOAD_OPTION: {
        auto reindex{reinterpret_cast<bool*>(value)};
        chainstate_load_opts->wipe_block_tree_db = *reindex;
        return;
    }
    case kernel_ChainstateLoadOptionType::kernel_WIPE_CHAINSTATE_DB_CHAINSTATE_LOAD_OPTION: {
        auto reindex_chainstate{reinterpret_cast<bool*>(value)};
        chainstate_load_opts->wipe_chainstate_db = *reindex_chainstate;
        return;
    }
    default: {
        set_error(error, kernel_ErrorCode::kernel_ERROR_UNKNOWN_OPTION, "Unknown chainstate load option");
    }
    }
}

void kernel_chainstate_load_options_destroy(kernel_ChainstateLoadOptions* chainstate_load_opts_)
{
    delete reinterpret_cast<node::ChainstateLoadOptions*>(chainstate_load_opts_);
}

void kernel_chainstate_manager_load_chainstate(const kernel_Context* context_,
                                               kernel_ChainstateLoadOptions* chainstate_load_opts_,
                                               kernel_ChainstateManager* chainman_,
                                               kernel_Error* error)
{
    auto context{cast_const_context(context_, error)};
    if (!context) {
        return;
    }

    auto default_load_opts{node::ChainstateLoadOptions{}};
    auto& chainstate_load_opts = default_load_opts;

    if (chainstate_load_opts_) {
        chainstate_load_opts = *reinterpret_cast<node::ChainstateLoadOptions*>(chainstate_load_opts_);
    }

    if (chainstate_load_opts.wipe_block_tree_db && !chainstate_load_opts.wipe_chainstate_db) {
        set_error(error, kernel_ErrorCode::kernel_ERROR_INTERNAL, "Wiping the block tree db without also wiping the chainstate db is currently unsupported.");
    }

    auto chainman{cast_chainstate_manager(chainman_, error)};
    if (!chainman) {
        return;
    }

    node::CacheSizes cache_sizes;
    cache_sizes.block_tree_db = 2 << 20;
    cache_sizes.coins_db = 2 << 22;
    cache_sizes.coins = (450 << 20) - (2 << 20) - (2 << 22);
    auto [status, chainstate_err]{node::LoadChainstate(*chainman, cache_sizes, chainstate_load_opts)};
    if (status != node::ChainstateLoadStatus::SUCCESS) {
        set_error(error, kernel_ErrorCode::kernel_ERROR_INTERNAL, "Failed to load chain state from your data directory. " + chainstate_err.original);
        return;
    }
    std::tie(status, chainstate_err) = node::VerifyLoadedChainstate(*chainman, chainstate_load_opts);
    if (status != node::ChainstateLoadStatus::SUCCESS) {
        set_error(error, kernel_ErrorCode::kernel_ERROR_INTERNAL, "Failed to verify loaded chain state from your datadir. " + chainstate_err.original);
    }

    for (Chainstate* chainstate : WITH_LOCK(::cs_main, return chainman->GetAll())) {
        BlockValidationState state;
        if (!chainstate->ActivateBestChain(state, nullptr)) {
            set_error(error, kernel_ErrorCode::kernel_ERROR_INTERNAL, "Failed to connect best block. " + state.ToString());
        }
    }
}

void kernel_chainstate_manager_destroy(kernel_ChainstateManager* chainman_, const kernel_Context* context_, kernel_Error* error)
{
    auto chainman{cast_chainstate_manager(chainman_, error)};
    if (!chainman) {
        return;
    }
    auto context{cast_const_context(context_, error)};
    if (!context) {
        return;
    }

    if (chainman->m_thread_load.joinable()) chainman->m_thread_load.join();

    // Without this precise shutdown sequence, there will be a lot of nullptr
    // dereferencing and UB.
    {
        LOCK(cs_main);
        for (Chainstate* chainstate : chainman->GetAll()) {
            if (chainstate->CanFlushToDisk()) {
                chainstate->ForceFlushStateToDisk();
                chainstate->ResetCoinsViews();
            }
        }
    }

    delete chainman;
    set_error_ok(error);
    return;
}

void kernel_import_blocks(const kernel_Context* context_,
                          kernel_ChainstateManager* chainman_,
                          const char** block_file_paths,
                          size_t block_file_paths_len,
                          kernel_Error* error)
{
    auto context{cast_const_context(context_, error)};
    if (!context) {
        return;
    }

    auto chainman{cast_chainstate_manager(chainman_, error)};
    if (!chainman) {
        return;
    }
    std::vector<fs::path> import_files;
    import_files.reserve(block_file_paths_len);
    for (uint32_t i = 0; i < block_file_paths_len; i++) {
        if (block_file_paths[i] != nullptr) {
            import_files.emplace_back(block_file_paths[i]);
        }
    }
    node::ImportBlocks(*chainman, import_files);
    chainman->ActiveChainstate().ForceFlushStateToDisk();
}

kernel_Block* kernel_block_from_string(const char* block_hex_string, kernel_Error* error)
{
    std::string raw_block{block_hex_string};
    if (raw_block.empty()) {
        set_error(error, kernel_ErrorCode::kernel_ERROR_INTERNAL, "Empty block string passed in.");
    }

    auto block{new CBlock()};

    if (!DecodeHexBlk(*block, raw_block)) {
        delete block;
        set_error(error, kernel_ERROR_INTERNAL, "Block decode failed.");
        return nullptr;
    }

    return reinterpret_cast<kernel_Block*>(new std::shared_ptr<CBlock>(block));
}

void kernel_byte_array_destroy(kernel_ByteArray* byte_array)
{
    delete[] byte_array->data;
    delete byte_array;
}

kernel_ByteArray* kernel_copy_block_data(kernel_Block* block_, kernel_Error* error)
{
    auto block{cast_cblocksharedpointer(block_, error)};
    if (!block) {
        return nullptr;
    }

    DataStream ss{};
    ss << TX_WITH_WITNESS(**block);

    auto byte_array{new kernel_ByteArray{
        .data = new unsigned char[ss.size()],
        .size = ss.size(),
    }};

    std::memcpy(byte_array->data, ss.data(), byte_array->size);

    return byte_array;
}

kernel_ByteArray* kernel_copy_block_pointer_data(const kernel_BlockPointer* block_, kernel_Error* error)
{
    auto block{cast_cblockpointer(block_, error)};
    if (!block) {
        return nullptr;
    }

    DataStream ss{};
    ss << TX_WITH_WITNESS(*block);

    auto byte_array{new kernel_ByteArray{
        .data = new unsigned char[ss.size()],
        .size = ss.size(),
    }};

    std::memcpy(byte_array->data, ss.data(), byte_array->size);

    return byte_array;
}

void kernel_block_destroy(kernel_Block* block)
{
    delete reinterpret_cast<std::shared_ptr<CBlock>*>(block);
}

kernel_BlockIndex* kernel_get_block_index_from_tip(const kernel_Context* context_, kernel_ChainstateManager* chainman_, kernel_Error* error)
{
    auto context{cast_const_context(context_, error)};
    if (!context) {
        return nullptr;
    }
    auto chainman{cast_chainstate_manager(chainman_, error)};
    if (!chainman) {
        return nullptr;
    }

    return reinterpret_cast<kernel_BlockIndex*>(WITH_LOCK(::cs_main, return chainman->ActiveChain().Tip()));
}

kernel_BlockIndex* kernel_get_previous_block_index(kernel_BlockIndex* block_index_, kernel_Error* error)
{
    CBlockIndex* block_index{cast_block_index(block_index_, error)};
    if (!block_index) {
        return nullptr;
    }

    if (!block_index->pprev) {
        set_error(error, kernel_ErrorCode::kernel_ERROR_OUT_OF_BOUNDS, "Genesis block has no previous.");
    }

    return reinterpret_cast<kernel_BlockIndex*>(block_index->pprev);
}

kernel_Block* kernel_read_block_from_disk(const kernel_Context* context_,
                                          kernel_ChainstateManager* chainman_,
                                          kernel_BlockIndex* block_index_,
                                          kernel_Error* error)
{
    auto context{cast_const_context(context_, error)};
    if (!context) {
        return nullptr;
    }

    auto chainman{cast_chainstate_manager(chainman_, error)};
    if (!chainman) {
        return nullptr;
    }
    CBlockIndex* block_index{cast_block_index(block_index_, error)};
    if (!block_index) {
        return nullptr;
    }

    auto block = new std::shared_ptr<CBlock>(new CBlock{});
    auto res = chainman->m_blockman.ReadBlockFromDisk(**block, *block_index);
    if (!res) {
        set_error(error, kernel_ERROR_INTERNAL, "Failed to read block from disk.");
    }
    return reinterpret_cast<kernel_Block*>(block);
}

void kernel_block_index_destroy(kernel_BlockIndex* block_index)
{
    // This is just a dummy function. The user does not control block index memory.
    return;
}

bool kernel_chainstate_manager_process_block(const kernel_Context* context_, kernel_ChainstateManager* chainman_, kernel_Block* block_, kernel_Error* error)
{
    auto context{cast_const_context(context_, error)};
    if (!context) {
        return false;
    }

    auto chainman{cast_chainstate_manager(chainman_, error)};
    if (!chainman) {
        return false;
    }

    auto blockptr{cast_cblocksharedpointer(block_, error)};
    if (!blockptr) {
        return false;
    }

    set_error_ok(error);

    CBlock& block{**blockptr};

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        set_error(error, kernel_ERROR_INTERNAL, "Block does not start with a coinbase.");
        return false;
    }

    uint256 hash{block.GetHash()};
    {
        LOCK(cs_main);
        const CBlockIndex* pindex{chainman->m_blockman.LookupBlockIndex(hash)};
        if (pindex) {
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
                set_error(error, kernel_ERROR_INTERNAL, "Block is a duplicate.");
                return false;
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                set_error(error, kernel_ERROR_INTERNAL, "Block is an invalid duplicate.");
                return false;
            }
        }
    }

    {
        LOCK(cs_main);
        const CBlockIndex* pindex{chainman->m_blockman.LookupBlockIndex(block.hashPrevBlock)};
        if (pindex) {
            chainman->UpdateUncommittedBlockStructures(block, pindex);
        }
    }

    bool new_block;
    bool accepted{chainman->ProcessNewBlock(*blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&new_block)};

    if (!new_block && accepted) {
        set_error(error, kernel_ERROR_INTERNAL, "Block is a duplicate.");
        return false;
    }
    return accepted;
}
