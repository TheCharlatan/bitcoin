#include <kernel/checks.h>
#include <kernel/context.h>

#include <chainparams.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <node/caches.h>
#include <node/chainstate.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/sigcache.h>
#include <undo.h>
#include <util/signalinterrupt.h>
#include <util/task_runner.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <iostream>
#include <memory>
#include <thread>

#include <bitcoinkernel.h>

static LogCallback g_log_callback = nullptr;

void log_info(const char* msg)
{
    if (g_log_callback) {
        g_log_callback(msg);
    } else {
        std::cout << msg << std::endl;
    }
}

void log_error(const char* msg)
{
    if (g_log_callback) {
        g_log_callback(strprintf("Error: %s\n", msg).c_str());
    } else {
        std::cerr << msg << std::endl;
    }
}

const char* fmt_bool(bool b)
{
    return b ? "true" : "false";
}

void set_error_invalid_pointer(kernel_error* err, std::string message)
{
    err->code = kernel_ERR_INVALID_POINTER;
    if (message.size() < 256) {
        strncpy(err->message, message.c_str(), sizeof(err->message) - 1);
    }
}

void set_error_ok(kernel_error* err)
{
    err->code = kernel_ERR_OK;
}

void set_error(kernel_error* err, kernel_error_code code, std::string message)
{
    err->code = code;
    if (message.size() < 256) {
        strncpy(err->message, message.c_str(), sizeof(err->message) - 1);
    }
}

C_SynchronizationState cast_state(SynchronizationState state)
{
    switch (state) {
    case SynchronizationState::INIT_REINDEX:
        return C_SynchronizationState::INIT_REINDEX;
    case SynchronizationState::INIT_DOWNLOAD:
        return C_SynchronizationState::INIT_DOWNLOAD;
    case SynchronizationState::POST_INIT:
        return C_SynchronizationState::POST_INIT;
    }
    assert(false);
}

class KernelNotifications : public kernel::Notifications
{
private:
    std::unique_ptr<KernelNotificationInterfaceCallbacks> m_cbs;

public:
    KernelNotifications(std::unique_ptr<KernelNotificationInterfaceCallbacks> kni_cbs) : m_cbs{std::move(kni_cbs)} {}

    kernel::InterruptResult blockTip(SynchronizationState state, CBlockIndex& index) override
    {
        if (m_cbs && m_cbs->block_tip) m_cbs->block_tip(m_cbs->user_data, cast_state(state), nullptr);
        return {};
    }
    void headerTip(SynchronizationState state, int64_t height, int64_t timestamp, bool presync) override
    {
        if (m_cbs && m_cbs->header_tip) m_cbs->header_tip(m_cbs->user_data, cast_state(state), height, timestamp, presync);
    }
    void progress(const bilingual_str& title, int progress_percent, bool resume_possible) override
    {
        if (m_cbs && m_cbs->progress) m_cbs->progress(m_cbs->user_data, title.original.c_str(), progress_percent, resume_possible);
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

void c_execute_event(C_ValidationEvent* event)
{
    std::function<void()>* func = reinterpret_cast<std::function<void()>*>(event);
    (*func)();
    delete func;
}

class ValidationTaskRunner : public util::TaskRunnerInterface
{
private:
    std::unique_ptr<TaskRunnerCallbacks> m_cbs;

public:
    ValidationTaskRunner(std::unique_ptr<TaskRunnerCallbacks> tr_cbs) : m_cbs{std::move(tr_cbs)} {}

    void insert(std::function<void()> func) override
    {
        if (m_cbs && m_cbs->insert) {
            // prevent the event from being deleted when it goes out of scope
            // here, it is the caller's responsibility to correctly call
            // c_execute_event to process it, preventing a memory leak.
            auto heap_func = new std::function<void()>(func);

            m_cbs->insert(m_cbs->user_data, reinterpret_cast<C_ValidationEvent*>(heap_func));
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
    std::unique_ptr<KernelNotificationInterfaceCallbacks> m_kni_cbs;
    std::unique_ptr<TaskRunnerCallbacks> m_tr_cbs;

    std::unique_ptr<const CChainParams> m_chainparams = CChainParams::SigNet({});

    void set_option(C_ContextOptionType option, void* value, kernel_error* err)
    {
        switch (option) {
        case C_ContextOptionType::KernelNotificationInterfaceCallbacksOption: {
            auto kn_cbs = static_cast<KernelNotificationInterfaceCallbacks*>(value);
            if (!kn_cbs) {
                set_error_invalid_pointer(err, "Invalid KernelNotificationInterfaceCallbacks pointer.");
                return;
            }
            // This copies the data, so the caller can free it again.
            m_kni_cbs = std::make_unique<KernelNotificationInterfaceCallbacks>(*kn_cbs);
            set_error_ok(err);
            return;
        }
        case C_ContextOptionType::TaskRunnerCallbacksOption: {
            auto tr_cbs = static_cast<TaskRunnerCallbacks*>(value);
            if (!tr_cbs) {
                set_error_invalid_pointer(err, "Invalid TaskRunnerCallbacks pointer.");
                return;
            }
            // This copies the data, so the caller can free it again.
            m_tr_cbs = std::make_unique<TaskRunnerCallbacks>(*tr_cbs);
            set_error_ok(err);
            return;
        }
        case C_ContextOptionType::ChainTypeOption: {
            auto chain_type = static_cast<C_Chain*>(value);
            if (!chain_type) {
                set_error_invalid_pointer(err, "Invalid C_Chain pointer.");
                return;
            }
            switch (*chain_type) {
            case C_Chain::kernel_MAINNET:
                m_chainparams = CChainParams::Main();
                return;
            case C_Chain::kernel_TESTNET:
                m_chainparams = CChainParams::TestNet();
                return;
            case C_Chain::kernel_SIGNET:
                m_chainparams = CChainParams::SigNet({});
                return;
            case C_Chain::kernel_REGTEST:
                m_chainparams = CChainParams::RegTest({});
                return;
            default:
                set_error(err, kernel_ERR_UNKNOWN_OPTION, "Unknown chain type option.");
                return;
            };
        }
        default: {
            set_error(err, kernel_ERR_UNKNOWN_OPTION, "Unknown context option");
        }
        }
    }

    bool healthy()
    {
        return true;
    }
};

C_ContextOptions* c_context_opt_create()
{
    return reinterpret_cast<C_ContextOptions*>(new ContextOptions{});
}

static ContextOptions* cast_context_options(C_ContextOptions* context_opts_, kernel_error* err)
{
    if (!context_opts_) {
        set_error_invalid_pointer(err, "Invalid C_ContextOptions pointer.");
        return nullptr;
    }
    return reinterpret_cast<ContextOptions*>(context_opts_);
}

void c_context_set_opt(C_ContextOptions* context_opts_, C_ContextOptionType n_option, void* value, kernel_error* err)
{
    auto context_options = cast_context_options(context_opts_, err);
    if (!context_options) {
        return;
    }
    context_options->set_option(n_option, value, err);
}

class Context
{
public:
    std::unique_ptr<kernel::Context> m_context;

    std::unique_ptr<ValidationSignals> m_signals;

    std::unique_ptr<KernelNotifications> m_notifications;

    std::unique_ptr<util::SignalInterrupt> m_interrupt;

    std::unique_ptr<const CChainParams> m_chainparams;

    Context(kernel_error* err, ContextOptions* options)
        : m_context{std::make_unique<kernel::Context>()},
          m_signals{nullptr},
          m_notifications{std::make_unique<KernelNotifications>(std::move(options->m_kni_cbs))},
          m_interrupt{std::make_unique<util::SignalInterrupt>()},
          m_chainparams{std::move(options->m_chainparams)}
    {
        if (options->m_tr_cbs) {
            m_signals = std::make_unique<ValidationSignals>(std::make_unique<ValidationTaskRunner>(std::move(options->m_tr_cbs)));
        }
        delete options;

        if (!kernel::SanityChecks(*m_context)) {
            set_error(err, kernel_ERR_INVALID_CONTEXT, "Context sanity check failed.");
        } else {
            set_error_ok(err);
        }
    }
};

static Context* cast_context(C_Context* p_context, kernel_error* err)
{
    if (!p_context) {
        set_error_invalid_pointer(err, "Invalid C_Context pointer.");
        return nullptr;
    }
    return reinterpret_cast<Context*>(p_context);
}

void c_context_create(C_ContextOptions* options, C_Context** context, kernel_error* err)
{
    auto context_options = cast_context_options(options, err);
    if (!context_options) {
        return;
    }
    if (*context) {
        set_error_invalid_pointer(err, "Invalid C_Context pointer, must be null.");
        return;
    }
    *context = reinterpret_cast<C_Context*>(new Context{err, context_options});
}

void c_context_destroy(C_Context* context, kernel_error* err)
{
    auto context_wrapper = cast_context(context, err);
    if (!context_wrapper) {
        return;
    }
    if (context_wrapper->m_signals) {
        context_wrapper->m_signals->UnregisterAllValidationInterfaces();
    }
    delete context_wrapper;
    set_error_ok(err);
}

void c_set_logging_callback_and_start_logging(LogCallback callback, kernel_error* err)
{
    g_log_callback = callback;
    LogInstance().m_print_to_file = false;
    LogInstance().m_print_to_console = false;
    LogInstance().m_log_timestamps = false;
    LogInstance().PushBackCallback([](const std::string& str) { g_log_callback(str.c_str()); });
    if (!LogInstance().StartLogging()) {
        set_error(err, kernel_ERR_LOGGING_FAILED, "Logger start failed.");
    } else {
        set_error_ok(err);
        log_info("Logger started.");
    }
}

void c_block_from_str(const char* block_str, C_Block** block_out, kernel_error* err)
{
    std::string raw_block(block_str);
    if (raw_block.empty()) {
        set_error(err, kernel_ERR_INTERNAL, "Empty block string passed in.");
        return;
    }

    auto block = new CBlock();

    if (!DecodeHexBlk(*block, raw_block)) {
        set_error(err, kernel_ERR_INTERNAL, "Block decode failed.");
        return;
    }
    *block_out = reinterpret_cast<C_Block*>(new std::shared_ptr<CBlock>(block));
}

void c_block_destroy(C_Block* block)
{
    delete reinterpret_cast<std::shared_ptr<CBlock>*>(block);
}

static const CTransactionRef* cast_ctransaction_ref(const C_TransactionRef* transaction_ref_, kernel_error* err)
{
    if (!transaction_ref_) {
        set_error_invalid_pointer(err, "Invalid C_TransactionRef pointer.");
        return nullptr;
    }
    auto transaction_ref = reinterpret_cast<const CTransactionRef*>(transaction_ref_);
    if (!*transaction_ref) {
        set_error_invalid_pointer(err, "Invalid C_TransactionRef shared pointer.");
        return nullptr;
    }
    return transaction_ref;
}

void c_transaction_ref_from_str(const char* transaction_str, C_TransactionRef** transaction_out, kernel_error* err)
{
    std::string raw_transaction{transaction_str};
    if (raw_transaction.empty()) {
        set_error(err, kernel_ERR_INTERNAL, "Empty transaction string passed in.");
        return;
    }

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, raw_transaction)) {
        set_error(err, kernel_ERR_INTERNAL, "Transaction decode failed.");
        return;
    }
    CTransactionRef* transaction = new CTransactionRef(std::make_shared<const CTransaction>(CTransaction(std::move(mtx))));
    *transaction_out = reinterpret_cast<C_TransactionRef*>(transaction);
}

void c_transaction_ref_destroy(const C_TransactionRef* transaction_ref_, kernel_error* err)
{
    auto transaction_ref{cast_ctransaction_ref(transaction_ref_, err)};
    if (!transaction_ref) {
        return;
    }
    delete transaction_ref;
}

Consensus::BuriedDeployment c_buried_deployment_to_buried_deployment(const C_BuriedDeployment dep)
{
    switch (dep) {
    case C_BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
        return Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB;
    case C_BuriedDeployment::DEPLOYMENT_CLTV:
        return Consensus::BuriedDeployment::DEPLOYMENT_CLTV;
    case C_BuriedDeployment::DEPLOYMENT_DERSIG:
        return Consensus::BuriedDeployment::DEPLOYMENT_DERSIG;
    case C_BuriedDeployment::DEPLOYMENT_CSV:
        return Consensus::BuriedDeployment::DEPLOYMENT_CSV;
    case C_BuriedDeployment::DEPLOYMENT_SEGWIT:
        return Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT;
    default:
        assert(0);
    }
}

void c_chainstate_manager_create(const char* data_dir, bool reindex, C_Context* context_, C_ChainstateManager** chainman_out, kernel_error* err)
{
    auto context = cast_context(context_, err);
    if (!context) {
        return;
    }

    // SETUP: Argument parsing and handling
    fs::path abs_datadir{fs::absolute(fs::PathFromString(data_dir))};
    fs::create_directories(abs_datadir);

    // SETUP: Chainstate
    const ChainstateManager::Options chainman_opts{
        .chainparams = *context->m_chainparams,
        .datadir = abs_datadir,
        .notifications = *context->m_notifications,
        .signals = context->m_signals.get(),
    };
    const node::BlockManager::Options blockman_opts{
        .chainparams = chainman_opts.chainparams,
        .blocks_dir = abs_datadir / "blocks",
        .notifications = chainman_opts.notifications,
        .reindex = reindex,
    };
    bilingual_str chainman_error;
    ChainstateManager* chainman = new ChainstateManager{*context->m_interrupt, chainman_opts, blockman_opts, chainman_error};
    if (!chainman_error.empty()) {
        set_error(err, kernel_ERR_INTERNAL, chainman_error.original);
        delete chainman;
        return;
    }

    node::CacheSizes cache_sizes;
    cache_sizes.block_tree_db = 2 << 20;
    cache_sizes.coins_db = 2 << 22;
    cache_sizes.coins = (450 << 20) - (2 << 20) - (2 << 22);
    node::ChainstateLoadOptions options;
    options.reindex = reindex;
    auto [status, error] = node::LoadChainstate(*chainman, cache_sizes, options);
    if (status != node::ChainstateLoadStatus::SUCCESS) {
        log_error(strprintf("Failed to load Chain state from your datadir: %s.", error.original).c_str());
        c_chainstate_manager_destroy(reinterpret_cast<C_ChainstateManager*>(chainman), context_, err);
        return;
    } else {
        std::tie(status, error) = node::VerifyLoadedChainstate(*chainman, options);
        if (status != node::ChainstateLoadStatus::SUCCESS) {
            log_error(strprintf("Failed to verify loaded Chain state from your datadir: %s.", error.original).c_str());
            c_chainstate_manager_destroy(reinterpret_cast<C_ChainstateManager*>(chainman), context_, err);
            return;
        }
    }

    for (Chainstate* chainstate : WITH_LOCK(::cs_main, return chainman->GetAll())) {
        BlockValidationState state;
        if (!chainstate->ActivateBestChain(state, nullptr)) {
            log_error(strprintf("Failed to connect best block (%s)", state.ToString()).c_str());
            c_chainstate_manager_destroy(reinterpret_cast<C_ChainstateManager*>(chainman), context_, err);
            return;
        }
    }

    *chainman_out = reinterpret_cast<C_ChainstateManager*>(chainman);
}

static ChainstateManager* cast_chainstate_manager(C_ChainstateManager* chainman_, kernel_error* err)
{
    if (!chainman_) {
        set_error_invalid_pointer(err, "Invalid C_ChainstateManager pointer.");
        return nullptr;
    }
    return reinterpret_cast<ChainstateManager*>(chainman_);
}

bool c_is_loading_blocks(C_ChainstateManager* chainman_, kernel_error* err)
{
    auto chainman = cast_chainstate_manager(chainman_, err);
    if (!chainman) {
        return false;
    }
    return chainman->m_blockman.LoadingBlocks();
}

bool c_is_initial_block_download(C_ChainstateManager* chainman_, kernel_error* err)
{
    auto chainman = cast_chainstate_manager(chainman_, err);
    if (!chainman) {
        return false;
    }
    return chainman->IsInitialBlockDownload();
}

static std::shared_ptr<CBlock>* cast_cblock(C_Block* block_, kernel_error* err)
{
    if (!block_) {
        set_error_invalid_pointer(err, "Invalid C_Block pointer.");
        return nullptr;
    }
    auto block = reinterpret_cast<std::shared_ptr<CBlock>*>(block_);
    if (!*block) {
        set_error_invalid_pointer(err, "Invalid C_Block pointer.");
        return nullptr;
    }
    return block;
}

static const CBlock* cast_cblockpointer(const C_BlockPointer* block_, kernel_error* err)
{
    if (!block_) {
        set_error_invalid_pointer(err, "Invalid C_Block pointer.");
        return nullptr;
    }
    return reinterpret_cast<const CBlock*>(block_);
}

bool c_is_block_mutated(C_BlockPointer* block_, bool check_witness_root, kernel_error* err)
{
    auto block = cast_cblockpointer(block_, err);
    if (!block) {
        return false;
    }
    return IsBlockMutated(*block, check_witness_root);
}

BlockHash c_block_get_hash(C_Block* block_, kernel_error* err)
{
    auto block = cast_cblock(block_, err);
    if (!block) {
        return BlockHash{};
    }
    BlockHash result;
    auto block_hash = (*block)->GetHash();
    std::copy(block_hash.begin(), block_hash.end(), result.hash);
    return result;
}

void c_block_get_header(C_Block* block_, C_BlockHeader** block_header_out, kernel_error* err)
{
    auto block = cast_cblock(block_, err);
    if (!block) {
        return;
    }
    auto header = (*block)->GetBlockHeader();
    *block_header_out = reinterpret_cast<C_BlockHeader*>(new CBlockHeader(std::move(header)));
}

CBlockIndex* cast_block_index(C_BlockIndex* block_index_, kernel_error* err)
{
    if (!block_index_) {
        set_error_invalid_pointer(err, "Invalid C_BlockIndex pointer.");
        return nullptr;
    }
    return reinterpret_cast<CBlockIndex*>(block_index_);
}

C_BlockIndex* c_lookup_block_index(C_ChainstateManager* chainman_, BlockHash* block_hash_, kernel_error* err)
{
    auto chainman = cast_chainstate_manager(chainman_, err);
    if (!chainman) {
        return nullptr;
    }
    auto hash = uint256{Span<const unsigned char>{(*block_hash_).hash, 32}};
    auto block_index = WITH_LOCK(::cs_main, return chainman->m_blockman.LookupBlockIndex(hash));
    if (!block_index) {
        set_error(err, kernel_ERR_INTERNAL, "A block with the given hash is not indexed.");
        return nullptr;
    }
    return reinterpret_cast<C_BlockIndex*>(block_index);
}

bool c_deployment_active_at(C_BlockIndex* prev_block_index_, C_ChainstateManager* chainman_, C_BuriedDeployment deployment, kernel_error* err)
{
    auto prev_block_index = cast_block_index(prev_block_index_, err);
    if (!prev_block_index) {
        return false;
    }
    auto chainman = cast_chainstate_manager(chainman_, err);
    if (!chainman) {
        return false;
    }
    return DeploymentActiveAt(*prev_block_index, *chainman, c_buried_deployment_to_buried_deployment(deployment));
}

bool c_deployment_active_after(C_BlockIndex* block_index_, C_ChainstateManager* chainman_, C_BuriedDeployment deployment, kernel_error* err)
{
    auto block_index = cast_block_index(block_index_, err);
    if (!block_index) {
        return false;
    }
    auto chainman = cast_chainstate_manager(chainman_, err);
    if (!chainman) {
        return false;
    }
    return DeploymentActiveAfter(block_index, *chainman, c_buried_deployment_to_buried_deployment(deployment));
}

void c_block_index_destroy(C_BlockIndex* block_index_, kernel_error* err)
{
    auto block_index_wrapper = cast_block_index(block_index_, err);
    if (!block_index_wrapper) {
        return;
    }
    delete block_index_wrapper;
}

CBlockUndo* cast_cblock_undo(C_BlockUndo* undo_, kernel_error* err)
{
    if (!undo_) {
        set_error_invalid_pointer(err, "Invalid C_BlockUndo pointer.");
        return nullptr;
    }
    return reinterpret_cast<CBlockUndo*>(undo_);
}

CTxUndo* cast_tx_undo(C_TxUndo* undo_, kernel_error* err)
{
    if (!undo_) {
        set_error_invalid_pointer(err, "Invalid C_BlockUndo pointer.");
        return nullptr;
    }
    return reinterpret_cast<CTxUndo*>(undo_);
}

size_t c_number_of_txundo_in_block_undo(C_BlockUndo* undo_, kernel_error* err)
{
    auto undo = cast_cblock_undo(undo_, err);
    if (!undo) {
        return 0;
    }
    return undo->vtxundo.size();
}

C_TxUndo* c_get_tx_undo_by_index(C_BlockUndo* undo_, kernel_error* err, uint64_t index)
{
    auto undo = cast_cblock_undo(undo_, err);
    if (!undo) {
        return nullptr;
    }
    if (index > undo->vtxundo.size()) {
        set_error(err, kernel_ERR_INTERNAL, "Index is out of bounds");
        return nullptr;
    }
    return reinterpret_cast<C_TxUndo*>(&undo->vtxundo[index]);
}

size_t c_number_of_coins_in_tx_undo(C_TxUndo* tx_undo_, kernel_error* err)
{
    auto undo = cast_tx_undo(tx_undo_, err);
    if (!undo) {
        return 0;
    }
    return undo->vprevout.size();
}

C_CoinOpaque* c_get_coin_by_index(C_TxUndo* tx_undo_, kernel_error* err, uint64_t index)
{
    auto tx_undo = cast_tx_undo(tx_undo_, err);
    if (!tx_undo) {
        return nullptr;
    }
    if (index > tx_undo->vprevout.size()) {
        set_error(err, kernel_ERR_INTERNAL, "Index is out of bounds");
        return nullptr;
    }
    return reinterpret_cast<C_CoinOpaque*>(&tx_undo->vprevout[index]);
}

C_TransactionOut* c_get_prevout(C_CoinOpaque* coin_, kernel_error* err)
{
    if (!coin_) {
        set_error_invalid_pointer(err, "Invalid C_CoinOpaque pointer.");
        return nullptr;
    }
    auto coin = reinterpret_cast<Coin*>(coin_);
    return reinterpret_cast<C_TransactionOut*>(&coin->out);
}

void c_block_undo_destroy(C_BlockUndo* undo_, kernel_error* err)
{
    auto undo = cast_cblock_undo(undo_, err);
    if (!undo) {
        return;
    }
    delete undo;
}

void c_block_pointer_destroy(C_BlockPointer* block_, kernel_error* err)
{
    auto block = cast_cblockpointer(block_, err);
    if (!block) {
        return;
    }
    delete block;
}

size_t c_number_of_transactions_in_block(const C_BlockPointer* block_, kernel_error* err)
{
    auto block = cast_cblockpointer(block_, err);
    if (!block) {
        return 0;
    }
    return block->vtx.size();
}

const C_TransactionRef* c_get_transaction_by_index(const C_BlockPointer* block_, kernel_error* err, uint64_t index)
{
    auto block = cast_cblockpointer(block_, err);
    if (!block) {
        return nullptr;
    }
    if (index > block->vtx.size()) {
        set_error(err, kernel_ERR_INTERNAL, "Index is out of bounds.");
        return nullptr;
    }
    return reinterpret_cast<const C_TransactionRef*>(&block->vtx[index]);
}

uint32_t c_transaction_ref_get_locktime(const C_TransactionRef* transaction_ref_, kernel_error* err)
{
    auto transaction_ref = cast_ctransaction_ref(transaction_ref_, err);
    if (!transaction_ref) {
        return 0;
    }
    return (*transaction_ref)->nVersion;
}

bool c_transaction_ref_is_coinbase(const C_TransactionRef* transaction_ref_, kernel_error* err)
{
    auto transaction_ref = cast_ctransaction_ref(transaction_ref_, err);
    if (!transaction_ref) {
        return 0;
    }
    return (*transaction_ref)->IsCoinBase();
}

size_t c_get_transaction_input_size(const C_TransactionRef* transaction_ref_, kernel_error* err)
{
    auto transaction_ref = cast_ctransaction_ref(transaction_ref_, err);
    if (!transaction_ref) {
        return 0;
    }
    return (*transaction_ref)->vin.size();
}

size_t c_get_transaction_output_size(const C_TransactionRef* transaction_ref_, kernel_error* err)
{
    auto transaction_ref = cast_ctransaction_ref(transaction_ref_, err);
    if (!transaction_ref) {
        return 0;
    }
    return (*transaction_ref)->vout.size();
}

const C_TransactionOut* c_get_output_by_index(const C_TransactionRef* transaction_ref_, kernel_error* err, uint64_t index)
{
    auto transaction_ref = cast_ctransaction_ref(transaction_ref_, err);
    if (!transaction_ref) {
        return nullptr;
    }
    if (index > (*transaction_ref)->vout.size()) {
        set_error(err, kernel_ERR_INTERNAL, "Index is out of bounds");
    }
    return reinterpret_cast<const C_TransactionOut*>(&(*transaction_ref)->vout[index]);
}

const C_TransactionIn* c_get_input_by_index(const C_TransactionRef* transaction_ref_, kernel_error* err, uint64_t index)
{
    auto transaction_ref = cast_ctransaction_ref(transaction_ref_, err);
    if (!transaction_ref) {
        return nullptr;
    }
    if (index > (*transaction_ref)->vin.size()) {
        set_error(err, kernel_ERR_INTERNAL, "Index is out of bounds");
    }
    return reinterpret_cast<const C_TransactionIn*>(&(*transaction_ref)->vin[index]);
}

void c_get_prevout_hash(const C_TransactionIn* transaction_in_, ByteArray** txid, kernel_error* err)
{
    if (!transaction_in_) {
        set_error_invalid_pointer(err, "Invalid C_TransactionIn pointer.");
    }
    const CTxIn* input = reinterpret_cast<const CTxIn*>(transaction_in_);

    *txid = new ByteArray{
        .data = reinterpret_cast<const uint8_t*>(input->prevout.hash.data()), // Correct pointer type cast
        .len = input->prevout.hash.size(),
    };
}

uint32_t c_get_prevout_n(const C_TransactionIn* transaction_in_, kernel_error* err)
{
    if (!transaction_in_) {
        set_error_invalid_pointer(err, "Invalid C_TransactionIn pointer.");
    }
    const CTxIn* input = reinterpret_cast<const CTxIn*>(transaction_in_);
    return input->prevout.n;
}

void c_get_script_sig(const C_TransactionIn* transaction_in_, ByteArray** script_sig, kernel_error* err)
{
    if (!transaction_in_) {
        set_error_invalid_pointer(err, "Invalid C_TransactionIn pointer.");
    }
    const CTxIn* input = reinterpret_cast<const CTxIn*>(transaction_in_);

    *script_sig = new ByteArray{
        .data = input->scriptSig.data(),
        .len = input->scriptSig.size(),
    };
}

void c_get_tx_in_witness(const C_TransactionIn* transaction_in_, TxInWitness** tx_in_witness, kernel_error* err)
{
    if (!transaction_in_) {
        set_error_invalid_pointer(err, "Invalid C_TransactionIn pointer.");
    }
    const CTxIn* input = reinterpret_cast<const CTxIn*>(transaction_in_);

    auto& input_witness = input->scriptWitness.stack;

    ByteArray* witness = new ByteArray[input_witness.size()];
    for (size_t i{0}; i < input_witness.size(); ++i) {
        witness[i].data = input_witness[i].data();
        witness[i].len = input_witness[i].size();
    }

    *tx_in_witness = new TxInWitness;

    (*tx_in_witness)->data = witness;
    (*tx_in_witness)->len = input_witness.size();
}

void c_tx_in_witness_destroy(TxInWitness* witness_, kernel_error* err)
{
    if (!witness_) {
        set_error_invalid_pointer(err, "Invalid C_TxInWitness pointer.");
    }
    delete[] witness_;
}

void c_byte_array_destroy(ByteArray* data)
{
    delete data;
}

void c_get_script_pubkey(const C_TransactionOut* output_, ByteArray** script_pubkey, kernel_error* err)
{
    if (!output_) {
        set_error_invalid_pointer(err, "Invalid C_Txout pointer.");
        return;
    }
    const CTxOut* output = reinterpret_cast<const CTxOut*>(output_);

    *script_pubkey = new ByteArray{
        .data = output->scriptPubKey.data(),
        .len = output->scriptPubKey.size(),
    };
}

void c_import_blocks(C_ChainstateManager* chainman_, kernel_error* err)
{
    auto chainman{cast_chainstate_manager(chainman_, err)};
    if (!chainman) {
        return;
    }
    std::vector<fs::path> vImportFiles;
    node::ImportBlocks(*chainman, vImportFiles);
    chainman->ActiveChainstate().ForceFlushStateToDisk();
}

void c_chainstate_manager_flush(C_ChainstateManager* chainman_, kernel_error* err)
{
    auto chainman{cast_chainstate_manager(chainman_, err)};
    if (!chainman) {
        return;
    }
    {
        LOCK(cs_main);
        for (Chainstate* chainstate : chainman->GetAll()) {
            chainstate->ForceFlushStateToDisk();
        }
    }
}

void c_chainstate_coins_cursor_create(C_ChainstateManager* chainman_, C_CoinsViewCursor** cursor_out, kernel_error* err)
{
    auto chainman{cast_chainstate_manager(chainman_, err)};
    if (!chainman) {
        return;
    }
    auto cursor = WITH_LOCK(::cs_main, return chainman->ActiveChainstate().CoinsDB()).Cursor();
    if (!cursor->Valid()) {
        set_error(err, kernel_ERR_INTERNAL, "Cursor is not valid, probably the chainstate is not initialized correctly. Ensure that the chainstate is flushed");
        return;
    }
    set_error_ok(err);
    *cursor_out = reinterpret_cast<C_CoinsViewCursor*>(cursor.release());
}

static CCoinsViewCursor* cast_coins_view_cursor(C_CoinsViewCursor* cursor_, kernel_error* err)
{
    auto cursor = reinterpret_cast<CCoinsViewCursor*>(cursor_);
    if (!cursor) {
        set_error_invalid_pointer(err, "Invalid cursor pointer.");
        return nullptr;
    }
    if (!cursor->Valid()) {
        set_error_invalid_pointer(err, "Cursor is not valid, probably the chainstate is not initialized correctly.");
        return nullptr;
    }
    return cursor;
}

void c_coins_cursor_next(C_CoinsViewCursor* cursor_, kernel_error* err)
{
    auto cursor{cast_coins_view_cursor(cursor_, err)};
    if (!cursor) {
        return;
    }
    set_error_ok(err);
    cursor->Next();
}

C_OutPoint c_coins_cursor_get_key(C_CoinsViewCursor* cursor_, kernel_error* err)
{
    auto cursor{cast_coins_view_cursor(cursor_, err)};
    if (!cursor) {
        return C_OutPoint{};
    }
    COutPoint key;
    cursor->GetKey(key);

    C_OutPoint out_point{
        .hash = {},
        .n = key.n,
    };
    std::memcpy(out_point.hash, key.hash.data(), sizeof(out_point.hash));
    set_error_ok(err);
    return out_point;
}

bool c_coins_cursor_valid(C_CoinsViewCursor* cursor_, kernel_error* err)
{
    auto cursor{cast_coins_view_cursor(cursor_, err)};
    if (!cursor) {
        return false;
    }
    set_error_ok(err);
    return true;
}

void c_coins_cursor_destroy(C_CoinsViewCursor* cursor_, kernel_error* err)
{
    if (!cursor_) {
        return;
    }
    auto cursor = reinterpret_cast<CCoinsViewCursor*>(cursor_);

    delete cursor;
    set_error_ok(err);
}

std::string CScriptToHexString(const CScript& script)
{
    std::ostringstream ss;
    ss << std::hex;
    for (const auto& byte : script) {
        ss << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

C_Coin c_coins_cursor_get_value(C_CoinsViewCursor* cursor_, kernel_error* err)
{
    auto cursor{cast_coins_view_cursor(cursor_, err)};
    if (!cursor) {
        return C_Coin{};
    }

    Coin coin;
    cursor->GetValue(coin);

    std::vector<uint8_t> temp(coin.out.scriptPubKey.begin(), coin.out.scriptPubKey.end());
    return C_Coin{
        .out = C_TxOut{
            .value = coin.out.nValue,
            .script_pubkey = ByteArray{
                .data = coin.out.scriptPubKey.data(),
                .len = coin.out.scriptPubKey.size(),
            },
        },
        .is_coinbase = coin.fCoinBase,
        .confirmation_height = coin.nHeight,
    };
}

C_BlockValidationResult block_validation_result_to_c(const BlockValidationResult& result)
{
    switch (result) {
    case BlockValidationResult::BLOCK_RESULT_UNSET:
        return C_BlockValidationResult::BLOCK_RESULT_UNSET;
    case BlockValidationResult::BLOCK_CONSENSUS:
        return C_BlockValidationResult::BLOCK_CONSENSUS;
    case BlockValidationResult::BLOCK_RECENT_CONSENSUS_CHANGE:
        return C_BlockValidationResult::BLOCK_RECENT_CONSENSUS_CHANGE;
    case BlockValidationResult::BLOCK_CACHED_INVALID:
        return C_BlockValidationResult::BLOCK_CACHED_INVALID;
    case BlockValidationResult::BLOCK_INVALID_HEADER:
        return C_BlockValidationResult::BLOCK_INVALID_HEADER;
    case BlockValidationResult::BLOCK_MUTATED:
        return C_BlockValidationResult::BLOCK_MUTATED;
    case BlockValidationResult::BLOCK_MISSING_PREV:
        return C_BlockValidationResult::BLOCK_MISSING_PREV;
    case BlockValidationResult::BLOCK_INVALID_PREV:
        return C_BlockValidationResult::BLOCK_INVALID_PREV;
    case BlockValidationResult::BLOCK_TIME_FUTURE:
        return C_BlockValidationResult::BLOCK_TIME_FUTURE;
    case BlockValidationResult::BLOCK_CHECKPOINT:
        return C_BlockValidationResult::BLOCK_CHECKPOINT;
    case BlockValidationResult::BLOCK_HEADER_LOW_WORK:
        return C_BlockValidationResult::BLOCK_HEADER_LOW_WORK;
    default:
        assert(0);
    }
}

template <typename T>
inline C_ModeState validation_mode_to_c(const ValidationState<T>& state)
{
    if (state.IsValid()) return C_ModeState::M_VALID;
    if (state.IsInvalid()) return C_ModeState::M_INVALID;
    return C_ModeState::M_ERROR;
}

C_BlockValidationState block_validation_state_to_c(const BlockValidationState& state)
{
    return C_BlockValidationState{
        .mode = validation_mode_to_c(state),
        .result = block_validation_result_to_c(state.GetResult()),
    };
}

class DummyValidationInterface final : public CValidationInterface
{
public:
    ValidationInterfaceCallbacks m_cbs;

    explicit DummyValidationInterface(ValidationInterfaceCallbacks vi_cbs) : m_cbs{vi_cbs} {}

protected:
    void BlockChecked(const CBlock& block, const BlockValidationState& stateIn) override
    {
        // Just casting these to void* is obviously unsafe and should be fixed.
        // It served the purpose of putting the infrastructure in place for now.
        if (m_cbs.block_checked) m_cbs.block_checked(m_cbs.user_data, reinterpret_cast<const C_BlockPointer*>(&block), block_validation_state_to_c(stateIn));

        switch (stateIn.GetResult()) {
        case BlockValidationResult::BLOCK_RESULT_UNSET:
            return;
        case BlockValidationResult::BLOCK_HEADER_LOW_WORK:
            log_error("the block header may be on a too-little-work chain");
            return;
        case BlockValidationResult::BLOCK_CONSENSUS:
            log_error("invalid by consensus rules (excluding any below reasons)");
            return;
        case BlockValidationResult::BLOCK_RECENT_CONSENSUS_CHANGE:
            log_error("Invalid by a change to consensus rules more recent than SegWit.");
            return;
        case BlockValidationResult::BLOCK_CACHED_INVALID:
            log_error("this block was cached as being invalid and we didn't store the reason why");
            return;
        case BlockValidationResult::BLOCK_INVALID_HEADER:
            log_error("invalid proof of work or time too old");
            return;
        case BlockValidationResult::BLOCK_MUTATED:
            log_error("the block's data didn't match the data committed to by the PoW");
            return;
        case BlockValidationResult::BLOCK_MISSING_PREV:
            log_error("We don't have the previous block the checked one is built on");
            return;
        case BlockValidationResult::BLOCK_INVALID_PREV:
            log_error("A block this one builds on is invalid");
            return;
        case BlockValidationResult::BLOCK_TIME_FUTURE:
            log_error("block timestamp was > 2 hours in the future (or our clock is bad)");
            return;
        case BlockValidationResult::BLOCK_CHECKPOINT:
            log_error("the block failed to meet one of our checkpoints");
            return;
        }
        assert(0);
    }
};

void c_validation_interface_create(ValidationInterfaceCallbacks vi_cbs, C_ValidationInterface** validation_interface)
{
    std::shared_ptr<DummyValidationInterface>* heap_validation_interface = new std::shared_ptr<DummyValidationInterface>(new DummyValidationInterface(vi_cbs));
    *validation_interface = reinterpret_cast<C_ValidationInterface*>(heap_validation_interface);
}

std::shared_ptr<DummyValidationInterface>* cast_validation_interface(C_ValidationInterface* validation_interface_, kernel_error* err)
{
    if (!validation_interface_) {
        set_error_invalid_pointer(err, "Invalid C_ValidationInterface pointer.");
        return nullptr;
    }
    auto dummy_validation_interface = reinterpret_cast<std::shared_ptr<DummyValidationInterface>*>(validation_interface_);
    if (!*dummy_validation_interface) {
        set_error_invalid_pointer(err, "Invalid C_ValidationInterface pointer.");
        return nullptr;
    }
    return dummy_validation_interface;
}

void c_validation_interface_destroy(C_ValidationInterface* validation_interface_, kernel_error* err)
{
    auto dummy_validation_interface = cast_validation_interface(validation_interface_, err);
    if (!dummy_validation_interface) {
        return;
    }
    dummy_validation_interface->reset();
    set_error_ok(err);
}

void c_validation_interface_register(C_Context* context_, C_ValidationInterface* validation_interface_, kernel_error* err)
{
    auto context_wrapper = cast_context(context_, err);
    if (!context_wrapper) {
        return;
    }
    auto dummy_validation_interface = cast_validation_interface(validation_interface_, err);
    if (!dummy_validation_interface) {
        return;
    }
    if (!context_wrapper->m_signals) {
        set_error(err, kernel_ERR_INVALID_CONTEXT, "Cannot register validation interface with context that has no validation signals");
    }
    context_wrapper->m_signals->RegisterSharedValidationInterface(*dummy_validation_interface);
    set_error_ok(err);
}

void c_validation_interface_unregister(C_Context* context_, C_ValidationInterface* validation_interface_, kernel_error* err)
{
    auto context_wrapper = cast_context(context_, err);
    if (!context_wrapper) {
        return;
    }
    auto dummy_validation_interface = cast_validation_interface(validation_interface_, err);
    if (!dummy_validation_interface) {
        return;
    }
    if (!context_wrapper->m_signals) {
        set_error(err, kernel_ERR_INVALID_CONTEXT, "Cannot register validation interface with context that has no validation signals");
    }
    context_wrapper->m_signals->UnregisterSharedValidationInterface(*dummy_validation_interface);
    set_error_ok(err);
}

C_BlockIndex* c_get_genesis_block_index(C_ChainstateManager* chainman_, kernel_error* err)
{
    auto chainman{cast_chainstate_manager(chainman_, err)};
    if (!chainman) {
        return nullptr;
    }

    return reinterpret_cast<C_BlockIndex*>(WITH_LOCK(::cs_main, return chainman->ActiveChain().Genesis()));
}

C_BlockIndex* c_get_next_block_index(C_ChainstateManager* chainman_, kernel_error* err, C_BlockIndex* block_index_)
{
    auto chainman{cast_chainstate_manager(chainman_, err)};
    if (!chainman) {
        return nullptr;
    }
    CBlockIndex* block_index{cast_block_index(block_index_, err)};
    if (!block_index) {
        return nullptr;
    }

    block_index = WITH_LOCK(::cs_main, return chainman->ActiveChain().Next(block_index));
    return reinterpret_cast<C_BlockIndex*>(block_index);
}

int c_get_block_height(C_BlockIndex* block_index_, kernel_error* err)
{
    auto block_index{cast_block_index(block_index_, err)};
    if (!block_index) {
        return 0;
    }
    return block_index->nHeight;
}

void c_read_block_data(C_ChainstateManager* chainman_, C_BlockIndex* block_index_, kernel_error* err, C_BlockPointer** block_data, bool read_block, C_BlockUndo** undo_data, bool read_undo)
{
    auto chainman{cast_chainstate_manager(chainman_, err)};
    if (!chainman) {
        return;
    }
    auto block_index{cast_block_index(block_index_, err)};
    if (!block_index) {
        return;
    }

    if (read_block) {
        CBlock* block = new CBlock{};
        auto res = chainman->m_blockman.ReadBlockFromDisk(*block, *block_index);
        if (!res) {
            set_error(err, kernel_ERR_INTERNAL, "Failed to read block from disk.");
            return;
        }
        *block_data = reinterpret_cast<C_BlockPointer*>(block);
    }

    if (read_undo) {
        if (block_index->nHeight < 1) {
            set_error(err, kernel_ERR_INTERNAL, "The genesis block does not have undo data.");
            return;
        }
        CBlockUndo* undo = new CBlockUndo{};
        auto res = chainman->m_blockman.UndoReadFromDisk(*undo, *block_index);
        if (!res) {
            set_error(err, kernel_ERR_INTERNAL, "Failed to read undo data from disk.");
            return;
        }
        *undo_data = reinterpret_cast<C_BlockUndo*>(undo);
    }
}

void c_process_transaction(C_ChainstateManager* chainman_, const C_TransactionRef* transaction_ref_, bool test_accept, C_MempoolAcceptResult** result_out, kernel_error* err)
{
    auto chainman = cast_chainstate_manager(chainman_, err);
    if (!chainman) {
        return;
    }
    auto tx = cast_ctransaction_ref(transaction_ref_, err);
    if (!tx) {
        return;
    }
    auto res = WITH_LOCK(::cs_main, return chainman->ProcessTransaction(*tx, test_accept));
    *result_out = reinterpret_cast<C_MempoolAcceptResult*>(new MempoolAcceptResult(std::move(res)));
}

bool c_chainstate_manager_process_new_block_header(C_ChainstateManager* chainman_, C_BlockHeader* header_, bool min_pow_checked, kernel_error* err)
{
    auto chainman = cast_chainstate_manager(chainman_, err);
    if (!chainman) {
        return false;
    }
    if (!header_) {
        set_error_invalid_pointer(err, "Invalid C_BlockHeader pointer.");
        return false;
    }
    auto header = reinterpret_cast<CBlockHeader*>(header_);
    BlockValidationState state;
    std::vector<CBlockHeader> headers{*header};
    return chainman->ProcessNewBlockHeaders(headers, min_pow_checked, state);
}

bool c_chainstate_manager_validate_block(C_ChainstateManager* chainman_, C_Block* c_block, kernel_error* err)
{
    auto chainman{cast_chainstate_manager(chainman_, err)};
    if (!chainman) {
        return false;
    }

    auto blockptr{cast_cblock(c_block, err)};
    if (!blockptr) {
        return false;
    }

    set_error_ok(err);

    CBlock& block = **blockptr;

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        set_error(err, kernel_ERR_INTERNAL, "Block does not start with a coinbase.");
        return false;
    }

    uint256 hash = block.GetHash();
    {
        LOCK(cs_main);
        const CBlockIndex* pindex = chainman->m_blockman.LookupBlockIndex(hash);
        if (pindex) {
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
                set_error(err, kernel_ERR_INTERNAL, "Block is a duplicate.");
                return false;
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                set_error(err, kernel_ERR_INTERNAL, "Block is an invalid duplicate.");
                return false;
            }
        }
    }

    {
        LOCK(cs_main);
        const CBlockIndex* pindex = chainman->m_blockman.LookupBlockIndex(block.hashPrevBlock);
        if (pindex) {
            chainman->UpdateUncommittedBlockStructures(block, pindex);
        }
    }

    bool new_block;
    bool accepted = chainman->ProcessNewBlock(*blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&new_block);

    if (!new_block && accepted) {
        set_error(err, kernel_ERR_INTERNAL, "Block is a duplicate.");
        return false;
    }
    return accepted;
}

void c_chainstate_manager_destroy(C_ChainstateManager* chainman_, C_Context* context_wrapper_, kernel_error* err)
{
    auto chainman{cast_chainstate_manager(chainman_, err)};
    if (!chainman) {
        return;
    }
    auto context_wrapper = cast_context(context_wrapper_, err);
    if (!context_wrapper) {
        return;
    }

    chainman->ActiveChainstate().ForceFlushStateToDisk();
    // Without this precise shutdown sequence, there will be a lot of nullptr
    // dereferencing and UB.
    if (context_wrapper->m_signals) {
        context_wrapper->m_signals->FlushBackgroundCallbacks();
    }
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

    set_error_ok(err);

    return;
}
