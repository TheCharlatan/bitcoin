// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>

#include <chain.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <kernel/chainparams.h>
#include <kernel/checks.h>
#include <kernel/context.h>
#include <kernel/notifications_interface.h>
#include <kernel/warning.h>
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
#include <tinyformat.h>
#include <uint256.h>
#include <util/fs.h>
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
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

// By triggering StartLogging first thing we make sure that no logging messages
// are buffered. This is required, because the buffering is currently unbounded.
#ifndef BUFFER_LOGS
struct LogInitializer
{
    LogInitializer() {
        // Start logging before doing anything else to ensure log messages are not buffered.
        LogInstance().StartLogging();
    }
} LOG_INITIALIZER;
#endif // BUFFER_LOGS

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
            spent_outputs.reserve(spentOutputsLen);
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

kernel_Warning cast_kernel_warning(kernel::Warning warning)
{
    switch (warning) {
    case kernel::Warning::UNKNOWN_NEW_RULES_ACTIVATED:
        return kernel_Warning::kernel_LARGE_WORK_INVALID_CHAIN;
    case kernel::Warning::LARGE_WORK_INVALID_CHAIN:
        return kernel_Warning::kernel_LARGE_WORK_INVALID_CHAIN;
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
    void warningSet(kernel::Warning id, const bilingual_str& message) override
    {
        if (m_cbs && m_cbs->warning_set) m_cbs->warning_set(m_cbs->user_data, cast_kernel_warning(id), message.original.c_str());
    }
    void warningUnset(kernel::Warning id) override
    {
        if (m_cbs && m_cbs->warning_unset) m_cbs->warning_unset(m_cbs->user_data, cast_kernel_warning(id));
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

struct ContextOptions {
    std::unique_ptr<const kernel_NotificationInterfaceCallbacks> m_kni_cbs;
    std::unique_ptr<const CChainParams> m_chainparams;
};

class Context
{
public:
    std::unique_ptr<kernel::Context> m_context;

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

        if (!kernel::SanityChecks(*m_context)) {
            set_error(error, kernel_ErrorCode::kernel_ERROR_INVALID_CONTEXT, "Context sanity check failed.");
        } else {
            set_error_ok(error);
        }
    }
};

const ContextOptions* cast_const_context_options(const kernel_ContextOptions* context_opts)
{
    assert(context_opts);
    return reinterpret_cast<const ContextOptions*>(context_opts);
}

ContextOptions* cast_context_options(kernel_ContextOptions* context_opts)
{
    assert(context_opts);
    return reinterpret_cast<ContextOptions*>(context_opts);
}

const CChainParams* cast_const_chain_params(const kernel_ChainParameters* chain_params)
{
    assert(chain_params);
    return reinterpret_cast<const CChainParams*>(chain_params);
}

Context* cast_context(kernel_Context* context)
{
    assert(context);
    return reinterpret_cast<Context*>(context);
}

const Context* cast_const_context(const kernel_Context* context)
{
    assert(context);
    return reinterpret_cast<const Context*>(context);
}

ChainstateManager::Options* cast_chainstate_manager_options(kernel_ChainstateManagerOptions* opts)
{
    assert(opts);
    return reinterpret_cast<ChainstateManager::Options*>(opts);
}

node::BlockManager::Options* cast_block_manager_options(kernel_BlockManagerOptions* opts)
{
    assert(opts);
    return reinterpret_cast<node::BlockManager::Options*>(opts);
}

ChainstateManager* cast_chainstate_manager(kernel_ChainstateManager* chainman)
{
    assert(chainman);
    return reinterpret_cast<ChainstateManager*>(chainman);
}

node::ChainstateLoadOptions* cast_chainstate_load_options(kernel_ChainstateLoadOptions* opts)
{
    assert(opts);
    return reinterpret_cast<node::ChainstateLoadOptions*>(opts);
}

std::shared_ptr<CBlock>* cast_cblocksharedpointer(kernel_Block* block)
{
    assert(block);
    return reinterpret_cast<std::shared_ptr<CBlock>*>(block);
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
    LogInstance().m_log_timestamps = options.log_timestamps;
    LogInstance().m_log_time_micros = options.log_time_micros;
    LogInstance().m_log_threadnames = options.log_threadnames;
    LogInstance().m_log_sourcelocations = options.log_sourcelocations;
    LogInstance().m_always_print_category_level = options.always_print_category_levels;

    auto connection{LogInstance().PushBackCallback([callback, user_data](const std::string& str) { callback(user_data, str.c_str()); })};

// Trigger start logging now if the messages were supposed to be buffered.
#ifdef BUFFER_LOGS
    try {
        // Only start logging if we just added the connection.
        if (LogInstance().NumConnections() == 1 && !LogInstance().StartLogging()) {
            set_error(error, kernel_ErrorCode::kernel_ERROR_LOGGING_FAILED, "Logger start failed.");
            LogInstance().DeleteCallback(connection);
            return nullptr;
        }
        set_error_ok(error);
    } catch(std::exception& e) {
        set_error(error , kernel_ErrorCode::kernel_ERROR_LOGGING_FAILED, strprintf("Logger start failed: %s", e.what()));
        LogInstance().DeleteCallback(connection);
        return nullptr;
    }
#endif // BUFFER_LOGS

    LogPrintf("Logger connected.\n");

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
// This is used to reset the buffering
#ifdef BUFFER_LOGS
    // We are not buffering if we have a connection, so check that it is not the
    // last available connection.
    if (!LogInstance().Enabled()) {
        LogInstance().DisconnectTestLogger();
    }
#endif // BUFFER_LOGS
}

int kernel_verify_script(const unsigned char* script_pubkey, size_t script_pubkey_len,
                                            const int64_t amount,
                                            const unsigned char* tx_to, size_t tx_to_len,
                                            const kernel_TransactionOutput* spent_outputs, size_t spent_outputs_len,
                                            const unsigned int nIn, const unsigned int flags, kernel_Error* error)
{
    const CAmount am{amount};

    return ::verify_script(script_pubkey, script_pubkey_len, am, tx_to, tx_to_len, spent_outputs, spent_outputs_len, nIn, flags, error);
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
    if (chain_parameters) {
        delete cast_const_chain_params(chain_parameters);
    }
}

kernel_ContextOptions* kernel_context_options_create()
{
    return reinterpret_cast<kernel_ContextOptions*>(new ContextOptions{});
}

void kernel_context_options_set(kernel_ContextOptions* context_opts_, const kernel_ContextOptionType n_option, const void* value, kernel_Error* error)
{
    auto context_opts{cast_context_options(context_opts_)};
    switch (n_option) {
    case kernel_ContextOptionType::kernel_CHAIN_PARAMETERS_OPTION: {
        auto chain_params{reinterpret_cast<const CChainParams*>(value)};
        context_opts->m_chainparams = std::make_unique<const CChainParams>(*chain_params);
        return;
    }
    case kernel_ContextOptionType::kernel_NOTIFICATION_INTERFACE_CALLBACKS_OPTION: {
        auto kni_cbs{reinterpret_cast<const kernel_NotificationInterfaceCallbacks*>(value)};
        // This copies the data, so the caller can free it again.
        context_opts->m_kni_cbs = std::make_unique<kernel_NotificationInterfaceCallbacks>(*kni_cbs);
        set_error_ok(error);
        return;
    }
    default: {
        set_error(error, kernel_ErrorCode::kernel_ERROR_UNKNOWN_CONTEXT_OPTION, "Unknown context option");
    }
    }
}

void kernel_context_options_destroy(kernel_ContextOptions* context_opts)
{
    if (context_opts) {
        delete cast_context_options(context_opts);
    }
}

kernel_Context* kernel_context_create(const kernel_ContextOptions* options, kernel_Error* error)
{
    auto context_options{cast_const_context_options(options)};
    return reinterpret_cast<kernel_Context*>(new Context{error, context_options});
}

void kernel_context_destroy(kernel_Context* context)
{
    if (context) {
        delete cast_context(context);
    }
}

kernel_ChainstateManagerOptions* kernel_chainstate_manager_options_create(const kernel_Context* context_, const char* data_dir, kernel_Error* error)
{
    try {
        fs::path abs_data_dir{fs::absolute(fs::PathFromString(data_dir))};
        fs::create_directories(abs_data_dir);
        auto context{cast_const_context(context_)};
        return reinterpret_cast<kernel_ChainstateManagerOptions*>(new ChainstateManager::Options{
            .chainparams = *context->m_chainparams,
            .datadir = abs_data_dir,
            .notifications = *context->m_notifications});
    } catch (const std::exception& e) {
        set_error(error, kernel_ERROR_INTERNAL, strprintf("Failed to create chainstate manager options: %s", e.what()));
        return nullptr;
    }
}

void kernel_chainstate_manager_options_destroy(kernel_ChainstateManagerOptions* chainman_opts)
{
    if (chainman_opts) {
        delete cast_chainstate_manager_options(chainman_opts);
    }
}

kernel_BlockManagerOptions* kernel_block_manager_options_create(const kernel_Context* context_, const char* blocks_dir, kernel_Error* error)
{
    try {
        fs::path abs_blocks_dir{fs::absolute(fs::PathFromString(blocks_dir))};
        fs::create_directories(abs_blocks_dir);
        auto context{cast_const_context(context_)};
        if (!context) {
            return nullptr;
        }
        return reinterpret_cast<kernel_BlockManagerOptions*>(new node::BlockManager::Options{
            .chainparams = *context->m_chainparams,
            .blocks_dir = abs_blocks_dir,
            .notifications = *context->m_notifications});
    } catch (const std::exception& e) {
        set_error(error, kernel_ERROR_INTERNAL, strprintf("Failed to create block manager options: %s", e.what()));
        return nullptr;
    }
}

void kernel_block_manager_options_destroy(kernel_BlockManagerOptions* blockman_opts)
{
    if (blockman_opts) {
        delete cast_block_manager_options(blockman_opts);
    }
}

kernel_ChainstateManager* kernel_chainstate_manager_create(
    kernel_ChainstateManagerOptions* chainstate_manager_opts,
    kernel_BlockManagerOptions* block_manager_opts,
    const kernel_Context* context_,
    kernel_Error* error)
{
    auto chainman_opts{cast_chainstate_manager_options(chainstate_manager_opts)};
    auto blockman_opts{cast_block_manager_options(block_manager_opts)};
    auto context{cast_const_context(context_)};

    try {
        return reinterpret_cast<kernel_ChainstateManager*>(new ChainstateManager{*context->m_interrupt, *chainman_opts, *blockman_opts});
    } catch (const std::exception& e) {
        set_error(error, kernel_ERROR_INTERNAL, strprintf("Failed to create chainstate manager: %s", e.what()));
        return nullptr;
    }
}

kernel_ChainstateLoadOptions* kernel_chainstate_load_options_create()
{
    return reinterpret_cast<kernel_ChainstateLoadOptions*>(new node::ChainstateLoadOptions);
}

void kernel_chainstate_load_options_destroy(kernel_ChainstateLoadOptions* chainstate_load_opts)
{
    if (chainstate_load_opts) {
        delete cast_chainstate_load_options(chainstate_load_opts);
    }
}

void kernel_chainstate_manager_load_chainstate(const kernel_Context* context_,
                                               kernel_ChainstateLoadOptions* chainstate_load_opts_,
                                               kernel_ChainstateManager* chainman_,
                                               kernel_Error* error)
{
    try {
        auto& chainstate_load_opts{*cast_chainstate_load_options(chainstate_load_opts_)};
        auto& chainman{*cast_chainstate_manager(chainman_)};

        node::CacheSizes cache_sizes;
        cache_sizes.block_tree_db = 2 << 20;
        cache_sizes.coins_db = 2 << 22;
        cache_sizes.coins = (450 << 20) - (2 << 20) - (2 << 22);
        auto [status, chainstate_err]{node::LoadChainstate(chainman, cache_sizes, chainstate_load_opts)};
        if (status != node::ChainstateLoadStatus::SUCCESS) {
            set_error(error, kernel_ErrorCode::kernel_ERROR_INTERNAL, "Failed to load chain state from your data directory. " + chainstate_err.original);
            return;
        }
        std::tie(status, chainstate_err) = node::VerifyLoadedChainstate(chainman, chainstate_load_opts);
        if (status != node::ChainstateLoadStatus::SUCCESS) {
            set_error(error, kernel_ErrorCode::kernel_ERROR_INTERNAL, "Failed to verify loaded chain state from your datadir. " + chainstate_err.original);
        }

        for (Chainstate* chainstate : WITH_LOCK(::cs_main, return chainman.GetAll())) {
            BlockValidationState state;
            if (!chainstate->ActivateBestChain(state, nullptr)) {
                set_error(error, kernel_ErrorCode::kernel_ERROR_INTERNAL, "Failed to connect best block. " + state.ToString());
            }
        }
    } catch (const std::exception& e) {
        set_error(error, kernel_ERROR_INTERNAL, strprintf("Failed to load chainstate: %s", e.what()));
    }
}

void kernel_chainstate_manager_destroy(kernel_ChainstateManager* chainman_, const kernel_Context* context_)
{
    if (!chainman_) return;

    auto chainman{cast_chainstate_manager(chainman_)};

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
    return;
}

kernel_Block* kernel_block_create(const unsigned char* raw_block, size_t raw_block_length, kernel_Error* error)
{
    auto block{new CBlock()};

    DataStream stream{Span{raw_block, raw_block_length}};

    try {
        stream >> TX_WITH_WITNESS(*block);
    } catch (const std::exception& e) {
        delete block;
        set_error(error, kernel_ERROR_INTERNAL, "Block decode failed.");
        return nullptr;
    }

    return reinterpret_cast<kernel_Block*>(new std::shared_ptr<CBlock>(block));
}

void kernel_block_destroy(kernel_Block* block)
{
    if (block) {
        delete cast_cblocksharedpointer(block);
    }
}

bool kernel_chainstate_manager_process_block(const kernel_Context* context_, kernel_ChainstateManager* chainman_, kernel_Block* block_, kernel_Error* error)
{
    auto& chainman{*cast_chainstate_manager(chainman_)};

    auto blockptr{cast_cblocksharedpointer(block_)};

    CBlock& block{**blockptr};

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        set_error(error, kernel_ERROR_BLOCK_WITHOUT_COINBASE, "Block does not start with a coinbase.");
        return false;
    }

    uint256 hash{block.GetHash()};
    {
        LOCK(cs_main);
        const CBlockIndex* pindex{chainman.m_blockman.LookupBlockIndex(hash)};
        if (pindex) {
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
                set_error(error, kernel_ERROR_DUPLICATE_BLOCK, "Block is a duplicate.");
                return false;
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                set_error(error, kernel_ERROR_DUPLICATE_BLOCK, "Block is an invalid duplicate.");
                return false;
            }
        }
    }

    {
        LOCK(cs_main);
        const CBlockIndex* pindex{chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock)};
        if (pindex) {
            chainman.UpdateUncommittedBlockStructures(block, pindex);
        }
    }

    bool new_block;
    bool accepted{chainman.ProcessNewBlock(*blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&new_block)};

    if (!new_block && accepted) {
        set_error(error, kernel_ERROR_DUPLICATE_BLOCK, "Block is a duplicate.");
        return false;
    }
    return accepted;
}
