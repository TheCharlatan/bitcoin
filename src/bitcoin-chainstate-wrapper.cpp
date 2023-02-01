#include <kernel/checks.h>
#include <kernel/context.h>
#include <kernel/validation_cache_sizes.h>

#include <chainparams.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <node/caches.h>
#include <node/chainstate.h>
#include <script/sigcache.h>
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

C_SynchronizationState cast_state(SynchronizationState state) {
    switch (state)
    {
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
    KernelNotificationInterfaceCallbacks m_cbs;

public:
    explicit KernelNotifications(
        KernelNotificationInterfaceCallbacks kn_cbs
    ) : m_cbs{kn_cbs} {}

    kernel::InterruptResult blockTip(SynchronizationState state, CBlockIndex& index) override
    {
        log_info("Block tip changed.");
        if (m_cbs.block_tip) m_cbs.block_tip(m_cbs.user_data, cast_state(state), nullptr);
        return {};
    }
    void headerTip(SynchronizationState state, int64_t height, int64_t timestamp, bool presync) override
    {
        log_info(strprintf("Header tip changed: %d, %d, %d", height, timestamp, presync).c_str());
        if (m_cbs.header_tip) m_cbs.header_tip(m_cbs.user_data, cast_state(state), height, timestamp, presync);
    }
    void progress(const bilingual_str& title, int progress_percent, bool resume_possible) override
    {
        log_info(strprintf("Progress: %s, %d, %d\n", title.original, progress_percent, resume_possible).c_str());
        if (m_cbs.progress) m_cbs.progress(m_cbs.user_data, title.original.c_str(), progress_percent, resume_possible);
    }
    void warning(const bilingual_str& warning) override
    {
        log_info(strprintf("Warning: %s", warning.original).c_str());
        if (m_cbs.warning) m_cbs.warning(m_cbs.user_data, warning.original.c_str());
    }
    void flushError(const std::string& debug_message) override
    {
        log_error(strprintf("Error flushing block data to disk: %s", debug_message).c_str());
        if (m_cbs.flush_error) m_cbs.flush_error(m_cbs.user_data, debug_message.c_str());
    }
    void fatalError(const std::string& debug_message, const bilingual_str& user_message) override
    {
        log_error(debug_message.c_str());
        log_error((user_message.empty() ? "A fatal internal error occurred." : user_message.original).c_str());
        if (m_cbs.fatal_error) m_cbs.fatal_error(m_cbs.user_data, debug_message.c_str(), user_message.original.c_str());
    }
};

void c_execute_event(void* event) {
    std::function<void()>* func = static_cast<std::function<void()>*>(event);
    (*func)();
    delete func;
}

class ValidationTaskRunner : public util::TaskRunnerInterface 
{
private:
    TaskRunnerCallbacks m_cbs;

public:
    ValidationTaskRunner(TaskRunnerCallbacks tr_cbs) : m_cbs{tr_cbs} {}

    void insert(std::function<void()> func) override
    {
        // prevent the event from being deleted when it goes out of scope
        // here, it is the caller's responsibility to correctly call
        // c_execute_event to process it, preventing a memory leak.
        auto heap_func = new std::function<void()>(func);

        if (m_cbs.insert) m_cbs.insert(m_cbs.user_data, heap_func);
    }

    void flush() override
    {
        if (m_cbs.flush) m_cbs.flush(m_cbs.user_data);
    }

    size_t size() override
    {
        if (m_cbs.size) return m_cbs.size(m_cbs.user_data);
        return 0;
    }
};

class ContextWrapper
{
public:

    std::unique_ptr<kernel::Context> m_context;

    std::unique_ptr<ValidationSignals> m_signals;

    std::unique_ptr<kernel::Notifications> m_notifications;

    std::unique_ptr<util::SignalInterrupt> m_interrupt;

    std::unique_ptr<const CChainParams> m_chainparams = CChainParams::SigNet({});

    ContextWrapper(
            KernelNotificationInterfaceCallbacks kn_cbs,
            TaskRunnerCallbacks tr_cbs
    ) {
        m_signals = std::make_unique<ValidationSignals>(std::make_unique<ValidationTaskRunner>(tr_cbs));
        m_notifications = std::make_unique<KernelNotifications>(kn_cbs);
        m_context = std::make_unique<kernel::Context>();
        m_interrupt = std::make_unique<util::SignalInterrupt>();

        // As long as we don't have error infrastructure here, this remains an assert.
        assert(kernel::SanityChecks(*m_context));

        // Necessary for CheckInputScripts (eventually called by ProcessNewBlock),
        // which will try the script cache first and fall back to actually
        // performing the check with the signature cache.
        kernel::ValidationCacheSizes validation_cache_sizes{};
        assert(InitSignatureCache(validation_cache_sizes.signature_cache_bytes));
        assert(InitScriptExecutionCache(validation_cache_sizes.script_execution_cache_bytes));
    }

    bool healthy() {
        return true;
    }
};

static ContextWrapper* cast_context_wrapper(void* context_wrapper)
{
    if (!context_wrapper || !(static_cast<ContextWrapper *>(context_wrapper))->healthy() ) {
        log_error("Received invalid context pointer\n");
    }
    return static_cast<ContextWrapper*>(context_wrapper);
}

void* c_context_new(KernelNotificationInterfaceCallbacks kn_cbs, TaskRunnerCallbacks tr_cbs)
{
    return new ContextWrapper(kn_cbs, tr_cbs);
}

void c_context_delete(void* context) {
    auto context_wrapper = cast_context_wrapper(context);
    context_wrapper->m_signals->UnregisterAllValidationInterfaces();
    delete context_wrapper;
}

void c_set_logging_callback_and_start_logging(LogCallback callback) {
    g_log_callback = callback;
    LogInstance().m_print_to_file = false;
    LogInstance().m_print_to_console = false;
    LogInstance().m_log_timestamps = false;
    LogInstance().PushBackCallback([](const std::string& str) { g_log_callback(str.c_str()); });
    if (!LogInstance().StartLogging()) {
        log_error("Logger start failed.\n");
    } else {
        log_info("Logger started.");
    }
}

void* c_chainstate_manager_create(const char* data_dir, void* context_wrapper_) {
    auto context_wrapper = cast_context_wrapper(context_wrapper_);

    // SETUP: Argument parsing and handling
    fs::path abs_datadir{fs::absolute(fs::PathFromString(data_dir))};
    fs::create_directories(abs_datadir);

    // SETUP: Chainstate
    const ChainstateManager::Options chainman_opts{
        .chainparams = *context_wrapper->m_chainparams,
        .datadir = abs_datadir,
        .adjusted_time_callback = NodeClock::now,
        .notifications = *context_wrapper->m_notifications,
        .signals = context_wrapper->m_signals.get(),
    };
    const node::BlockManager::Options blockman_opts{
        .chainparams = chainman_opts.chainparams,
        .blocks_dir = abs_datadir / "blocks",
        .notifications = chainman_opts.notifications,
    };
    ChainstateManager* chainman = new ChainstateManager{*context_wrapper->m_interrupt, chainman_opts, blockman_opts};

    node::CacheSizes cache_sizes;
    cache_sizes.block_tree_db = 2 << 20;
    cache_sizes.coins_db = 2 << 22;
    cache_sizes.coins = (450 << 20) - (2 << 20) - (2 << 22);
    node::ChainstateLoadOptions options;
    auto [status, error] = node::LoadChainstate(*chainman, cache_sizes, options);
    if (status != node::ChainstateLoadStatus::SUCCESS) {
        log_error("Failed to load Chain state from your datadir.");
        c_chainstate_manager_delete(chainman, context_wrapper_);
        return nullptr;
    } else {
        std::tie(status, error) = node::VerifyLoadedChainstate(*chainman, options);
        if (status != node::ChainstateLoadStatus::SUCCESS) {
            log_error("Failed to verify loaded Chain state from your datadir.");
            c_chainstate_manager_delete(chainman, context_wrapper_);
            return nullptr;
        }
    }

    for (Chainstate* chainstate : WITH_LOCK(::cs_main, return chainman->GetAll())) {
        BlockValidationState state;
        if (!chainstate->ActivateBestChain(state, nullptr)) {
            log_error(strprintf("Failed to connect best block (%s)", state.ToString()).c_str());
            c_chainstate_manager_delete(chainman, context_wrapper_);
            return nullptr;
        }
    }

    C_ChainstateInfo info = c_get_chainstate_info(chainman);

    {
        LOCK(chainman->GetMutex());
        auto msg = strprintf(
            "Successfully loaded chainstate:\n\tData Directory: %s\n\tReindexing: %s\n\tSnapshot Active: %s\n\tActive Height: %s\n\tActive IBD: %s",
            info.path,
            fmt_bool(info.reindexing),
            fmt_bool(info.snapshot_active),
            info.active_height,
            fmt_bool(info.active_ibd));
        CBlockIndex* tip = chainman->ActiveTip();
        if (tip) {
            log_info(strprintf("%s\n\tActive Tip: %s", msg, tip->ToString()).c_str());
        } else {
            log_info(msg.c_str());
        }
    }
    return chainman;
}

void* c_chainstate_coins_cursor(void* chainman_) {
    if (!chainman_ || !(static_cast<ChainstateManager *>(chainman_))->healthy() ) {
        log_error("Received invalid chainman pointer");
    }
    ChainstateManager* chainman = static_cast<ChainstateManager*>(chainman_);

    auto cursor = WITH_LOCK(::cs_main, return chainman->ActiveChainstate().CoinsDB()).Cursor();
    return cursor.release();
}

void c_coins_cursor_next(void* cursor_) {
    if (!cursor_ || !(static_cast<CCoinsViewCursor *>(cursor_))->Valid()) {
        log_error("Received invalid cursor pointer");
    }
    CCoinsViewCursor* cursor = static_cast<CCoinsViewCursor*>(cursor_);
    cursor->Next();
}

C_OutPoint c_coins_cursor_get_key(void* cursor_) {
    if (!cursor_ || !(static_cast<CCoinsViewCursor *>(cursor_))->Valid()) {
        log_error("Received invalid cursor pointer");
    }
    CCoinsViewCursor* cursor = static_cast<CCoinsViewCursor*>(cursor_);
    COutPoint key;
    cursor->GetKey(key);

    C_OutPoint out_point{
        .hash = {},
        .n = key.n,
    };
    std::memcpy(out_point.hash, key.hash.data(), sizeof(out_point.hash));
    return out_point;
}

int c_coins_cursor_valid(void* cursor_) {
    if (!cursor_ || !(static_cast<CCoinsViewCursor *>(cursor_))->Valid()) {
        return false;
    }
    return true;
}

void c_coins_cursor_delete(void* cursor_) {
    if (!cursor_) {
        log_error("Received invalid cursor pointer");
    }
    CCoinsViewCursor* cursor = static_cast<CCoinsViewCursor*>(cursor_);
    delete cursor;
}

std::string CScriptToHexString(const CScript& script) {
    std::ostringstream ss;
    ss << std::hex;
    for (const auto& byte : script) {
        ss << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

C_Coin c_coins_cursor_get_value(void* cursor_) {
    if (!cursor_ || !(static_cast<CCoinsViewCursor *>(cursor_))->Valid()) {
        log_error("Received invalid cursor pointer");
    }
    CCoinsViewCursor* cursor = static_cast<CCoinsViewCursor*>(cursor_);
    Coin coin;
    cursor->GetValue(coin);

    std::vector<uint8_t> temp(coin.out.scriptPubKey.begin(), coin.out.scriptPubKey.end());
    C_Coin c_coin{
        .out = C_TxOut{
            .value = coin.out.nValue,
            .script_pubkey = ByteArray {
                .data = coin.out.scriptPubKey.data(),
                .len = coin.out.scriptPubKey.size(),
            },
        },
        .is_coinbase = coin.fCoinBase,
        .confirmation_height = coin.nHeight,
    };
    return c_coin;
}

C_ChainstateInfo c_get_chainstate_info(void* chainman_) {
    if (!chainman_ || !(static_cast<ChainstateManager *>(chainman_))->healthy() ) {
        log_error("Received invalid chainman pointer");
    }

    ChainstateManager* chainman = static_cast<ChainstateManager*>(chainman_);
    C_ChainstateInfo info{
        .path = chainman->m_options.datadir.c_str(),
        .reindexing = node::fReindex.load(),
        .snapshot_active = chainman->IsSnapshotActive(),
        .active_height = WITH_LOCK(::cs_main, return chainman->ActiveHeight()),
        .active_ibd = chainman->IsInitialBlockDownload(),
    };
    return info;
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
        if (m_cbs.block_checked) m_cbs.block_checked(m_cbs.user_data, (void *)&block, (void *)&stateIn);

        log_info(stateIn.ToString().c_str());
        switch (stateIn.GetResult()) {
        case BlockValidationResult::BLOCK_RESULT_UNSET:
            log_info("Block passed ProcessNewBlock");
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

void* c_create_validation_interface(ValidationInterfaceCallbacks vi_cbs)
{
    std::shared_ptr<DummyValidationInterface>* heap_validation_interface
        = new std::shared_ptr<DummyValidationInterface>(new DummyValidationInterface(vi_cbs));
    return heap_validation_interface;
}

void c_destroy_validation_interface(void* dummy_validation_interface_) {
    std::shared_ptr<DummyValidationInterface>* dummy_validation_interface
        = static_cast<std::shared_ptr<DummyValidationInterface>*>(dummy_validation_interface_);
    dummy_validation_interface->reset();
}

void c_register_validation_interface(void* context_, void* dummy_validation_interface_) {
    auto context_wrapper = cast_context_wrapper(context_);
    std::shared_ptr<DummyValidationInterface>* dummy_validation_interface
        = static_cast<std::shared_ptr<DummyValidationInterface>*>(dummy_validation_interface_);
    context_wrapper->m_signals->RegisterSharedValidationInterface(*dummy_validation_interface);
}

void c_unregister_validation_interface(void* context_, void* dummy_validation_interface_) {
    auto context_wrapper = cast_context_wrapper(context_);
    std::shared_ptr<DummyValidationInterface>* dummy_validation_interface
        = static_cast<std::shared_ptr<DummyValidationInterface>*>(dummy_validation_interface_);
    context_wrapper->m_signals->UnregisterSharedValidationInterface(*dummy_validation_interface);
}

int c_chainstate_manager_validate_block(void* chainman_, void* context_, const char* raw_c_block)
{
    if (!chainman_ || !(static_cast<ChainstateManager *>(chainman_))->healthy() ) {
        log_error("Received invalid chainman pointer");
        return -1;
    }
    ChainstateManager* chainman = static_cast<ChainstateManager*>(chainman_);

    // make sure we can get a valid context wrapper before proceeding
    Assert(cast_context_wrapper(context_));

    std::string raw_block(raw_c_block);
    if (raw_block.empty()) {
        log_error("Empty line found");
        return 1;
    }

    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;

    if (!DecodeHexBlk(block, raw_block)) {
        log_error("Block decode failed");
        return 1;
    }

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        log_error("Block does not start with a coinbase");
        return 1;
    }

    uint256 hash = block.GetHash();
    {
        LOCK(cs_main);
        const CBlockIndex* pindex = chainman->m_blockman.LookupBlockIndex(hash);
        if (pindex) {
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
                log_error("duplicate");
                return 1;
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                log_error("duplicate-invalid");
                return 1;
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
    // auto sc = std::make_shared<ValidateBlockValidationInterface>(block.GetHash());
    // context_wrapper->m_signals->RegisterSharedValidationInterface(sc);
    bool accepted = chainman->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&new_block);
    // context_wrapper->m_signals->UnregisterSharedValidationInterface(sc);
    if (!new_block && accepted) {
        log_error("duplicate");
        return 1;
    }
    return 0;
}

int c_chainstate_manager_delete(void* chainman_, void* context_wrapper_) {
    if (!chainman_ || !(static_cast<ChainstateManager *>(chainman_))->healthy() ) {
        log_error("Received invalid chainman pointer");
        return -1;
    }
    ChainstateManager* chainman = static_cast<ChainstateManager*>(chainman_);
    auto context_wrapper = cast_context_wrapper(context_wrapper_);

    chainman->ActiveChainstate().ForceFlushStateToDisk();
    // Without this precise shutdown sequence, there will be a lot of nullptr
    // dereferencing and UB.
    context_wrapper->m_signals->FlushBackgroundCallbacks();
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

    return 0;
}
