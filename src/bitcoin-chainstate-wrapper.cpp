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
#include <scheduler.h>
#include <script/sigcache.h>
#include <util/system.h>
#include <util/thread.h>
#include <validation.h>
#include <validationinterface.h>

#include <cassert>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <iostream>

#include <chrono>
#include <thread>

#include <bitcoinkernel.h>

static LogCallback g_log_callback = nullptr;

void* c_scheduler_new() {
    // SETUP: Scheduling and Background Signals
    CScheduler* scheduler = new CScheduler();
    std::cerr << "created new scheduler\n";
    // Start the lightweight task scheduler thread
    scheduler->m_service_thread = std::thread(util::TraceThread, "scheduler", [&] { scheduler->serviceQueue(); });
    std::cerr << "created task scheduler\n";

    // Gather some entropy once per minute.
    scheduler->scheduleEvery(RandAddPeriodic, std::chrono::minutes{1});
    std::cerr << "scheduler task\n";

    GetMainSignals().RegisterBackgroundSignalScheduler(*scheduler);
    std::cout << "register background\n";
    std::cout << "sleeping for 1ms\n";
    std::this_thread::sleep_for(1ms);
    return scheduler;
}

void c_set_logging_callback_and_start_logging(LogCallback callback) {
    g_log_callback = callback;
    LogInstance().m_print_to_file = false;
    LogInstance().m_print_to_console = false;
    LogInstance().m_log_timestamps = false;
    LogInstance().PushBackCallback([&callback](const std::string& str) { g_log_callback(str.c_str()); });
    if (!LogInstance().StartLogging()) {
        callback("logger start failed");
    } else {
        callback("logger started");
    }
}

void* c_chainstate_manager_create(const char* data_dir, void* scheduler_) {
    // SETUP: Argument parsing and handling
    std::filesystem::path abs_datadir = std::filesystem::absolute(data_dir);
    std::filesystem::create_directories(abs_datadir);
    gArgs.ForceSetArg("-datadir", abs_datadir.string());


    // SETUP: Misc Globals
    SelectParams(CBaseChainParams::MAIN);
    const CChainParams& chainparams = Params();

    kernel::Context kernel_context{};
    // We can't use a goto here, but we can use an assert since none of the
    // things instantiated so far requires running the epilogue to be torn down
    // properly
    assert(!kernel::SanityChecks(kernel_context).has_value());

    // Necessary for CheckInputScripts (eventually called by ProcessNewBlock),
    // which will try the script cache first and fall back to actually
    // performing the check with the signature cache.
    kernel::ValidationCacheSizes validation_cache_sizes{};
    Assert(InitSignatureCache(validation_cache_sizes.signature_cache_bytes));
    Assert(InitScriptExecutionCache(validation_cache_sizes.script_execution_cache_bytes));

    // SETUP: Chainstate
    const ChainstateManager::Options chainman_opts{
        .chainparams = chainparams,
        .datadir = gArgs.GetDataDirNet(),
        .adjusted_time_callback = NodeClock::now,
    };
    ChainstateManager* chainman = new ChainstateManager(chainman_opts, {});

    node::CacheSizes cache_sizes;
    cache_sizes.block_tree_db = 2 << 20;
    cache_sizes.coins_db = 2 << 22;
    cache_sizes.coins = (450 << 20) - (2 << 20) - (2 << 22);
    node::ChainstateLoadOptions options;
    options.check_interrupt = [] { return false; };
    auto [status, error] = node::LoadChainstate(*chainman, cache_sizes, options);
    if (status != node::ChainstateLoadStatus::SUCCESS) {
        std::cerr << "Failed to load Chain state from your datadir." << std::endl;
        c_chainstate_manager_delete(chainman, scheduler_);
        return nullptr;
    } else {
        std::tie(status, error) = node::VerifyLoadedChainstate(*chainman, options);
        if (status != node::ChainstateLoadStatus::SUCCESS) {
            std::cerr << "Failed to verify loaded Chain state from your datadir." << std::endl;
            c_chainstate_manager_delete(chainman, scheduler_);
            return nullptr;
        }
    }

    for (Chainstate* chainstate : WITH_LOCK(::cs_main, return chainman->GetAll())) {
        BlockValidationState state;
        if (!chainstate->ActivateBestChain(state, nullptr)) {
            std::cerr << "Failed to connect best block (" << state.ToString() << ")" << std::endl;
            c_chainstate_manager_delete(chainman, scheduler_);
            return nullptr;
        }
    }

    C_ChainstateInfo info = c_get_chainstate_info(chainman);

    // Main program logic starts here
    std::cout
        << "Hello! I'm going to print out some information about your datadir." << std::endl
        << "\t" << "Path: " << info.path << std::endl;
    {
        LOCK(chainman->GetMutex());
        std::cout
        << "\t" << "Reindexing: " << std::boolalpha << info.reindexing << std::noboolalpha << std::endl
        << "\t" << "Snapshot Active: " << std::boolalpha << info.snapshot_active << std::noboolalpha << std::endl
        << "\t" << "Active Height: " << info.active_height << std::endl
        << "\t" << "Active IBD: " << std::boolalpha << info.active_ibd << std::noboolalpha << std::endl;
        CBlockIndex* tip = chainman->ActiveTip();
        if (tip) {
            std::cout << "\t" << tip->ToString() << std::endl;
        }
    }
    return chainman;
}

void* c_chainstate_coins_cursor(void* chainman_) {
    if (!chainman_ || !(static_cast<ChainstateManager *>(chainman_))->healthy() ) {
        std::cerr << "Received invalid chainman pointer";
    }
    ChainstateManager* chainman = static_cast<ChainstateManager*>(chainman_);

    return chainman->ActiveChainstate().CoinsDB().Cursor().get();
}

void c_coins_cursor_next(void* cursor_) {
    if (!cursor_ || !(static_cast<CCoinsViewCursor *>(cursor_))->Valid()) {
        std::cerr << "Received invvalid cursor pointer";
    }
    CCoinsViewCursor* cursor = static_cast<CCoinsViewCursor*>(cursor_);
    cursor->Next();
}

C_OutPoint c_coins_cursor_get_key(void* cursor_) {
    if (!cursor_ || !(static_cast<CCoinsViewCursor *>(cursor_))->Valid()) {
        std::cerr << "Received invvalid cursor pointer";
    }
    CCoinsViewCursor* cursor = static_cast<CCoinsViewCursor*>(cursor_);
    COutPoint key;
    cursor->GetKey(key);
    C_OutPoint out_point {
        hash: key.hash.ToString().c_str(),
        n: key.n,
    };
    return out_point;
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
        std::cerr << "Received invvalid cursor pointer";
    }
    CCoinsViewCursor* cursor = static_cast<CCoinsViewCursor*>(cursor_);
    Coin coin;
    cursor->GetValue(coin);
    C_Coin c_coin{
        out: C_TxOut {
            value: coin.out.nValue,
            script_pubkey: CScriptToHexString(coin.out.scriptPubKey).c_str(),
        },
        is_coinbase: coin.fCoinBase,
        confirmation_height: coin.nHeight,
    };
    return c_coin;
}

C_ChainstateInfo c_get_chainstate_info(void* chainman_) {
    if (!chainman_ || !(static_cast<ChainstateManager *>(chainman_))->healthy() ) {
        std::cerr << "Received invalid chainman pointer";
    }
    ChainstateManager* chainman = static_cast<ChainstateManager*>(chainman_);
    C_ChainstateInfo info{
        path : gArgs.GetDataDirNet().c_str(),
        reindexing : node::fReindex.load(),
        snapshot_active : chainman->IsSnapshotActive(),
        active_height : chainman->ActiveHeight(),
        active_ibd : chainman->ActiveChainstate().IsInitialBlockDownload(),
    };
    return info;
}

int c_chainstate_manager_validate_block(void* chainman_, const char* raw_c_block) {
    if (!chainman_ || !(static_cast<ChainstateManager *>(chainman_))->healthy() ) {
        std::cerr << "Received invalid chainman pointer";
        return -1;
    }
    ChainstateManager* chainman = static_cast<ChainstateManager*>(chainman_);
    std::string raw_block(raw_c_block);
    if (raw_block.empty()) {
        std::cerr << "Empty line found" << std::endl;
        return 1;
    }

    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;

    if (!DecodeHexBlk(block, raw_block)) {
        std::cerr << "Block decode failed" << std::endl;
        return 1;
    }

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        std::cerr << "Block does not start with a coinbase" << std::endl;
        return 1;
    }

    uint256 hash = block.GetHash();
    {
        LOCK(cs_main);
        const CBlockIndex* pindex = chainman->m_blockman.LookupBlockIndex(hash);
        if (pindex) {
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
                std::cerr << "duplicate" << std::endl;
                return 1;
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                std::cerr << "duplicate-invalid" << std::endl;
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

    // Adapted from rpc/mining.cpp
    class submitblock_StateCatcher final : public CValidationInterface
    {
    public:
        uint256 hash;
        bool found;
        BlockValidationState state;

        explicit submitblock_StateCatcher(const uint256& hashIn) : hash(hashIn), found(false), state() {}

    protected:
        void BlockChecked(const CBlock& block, const BlockValidationState& stateIn) override
        {
            if (block.GetHash() != hash)
                return;
            found = true;
            state = stateIn;
        }
    };

    bool new_block;
    auto sc = std::make_shared<submitblock_StateCatcher>(block.GetHash());
    RegisterSharedValidationInterface(sc);
    bool accepted = chainman->ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&new_block);
    UnregisterSharedValidationInterface(sc);
    if (!new_block && accepted) {
        std::cerr << "duplicate" << std::endl;
        return 1;
    }
    if (!sc->found) {
        std::cerr << "inconclusive" << std::endl;
        return 1;
    }
    std::cout << sc->state.ToString() << std::endl;
    switch (sc->state.GetResult()) {
    case BlockValidationResult::BLOCK_RESULT_UNSET:
        std::cerr << "initial value. Block has not yet been rejected" << std::endl;
        return 1;
    case BlockValidationResult::BLOCK_HEADER_LOW_WORK:
        std::cerr << "the block header may be on a too-little-work chain" << std::endl;
        return 1;
    case BlockValidationResult::BLOCK_CONSENSUS:
        std::cerr << "invalid by consensus rules (excluding any below reasons)" << std::endl;
        return 1;
    case BlockValidationResult::BLOCK_RECENT_CONSENSUS_CHANGE:
        std::cerr << "Invalid by a change to consensus rules more recent than SegWit." << std::endl;
        return 1;
    case BlockValidationResult::BLOCK_CACHED_INVALID:
        std::cerr << "this block was cached as being invalid and we didn't store the reason why" << std::endl;
        return 1;
    case BlockValidationResult::BLOCK_INVALID_HEADER:
        std::cerr << "invalid proof of work or time too old" << std::endl;
        return 1;
    case BlockValidationResult::BLOCK_MUTATED:
        std::cerr << "the block's data didn't match the data committed to by the PoW" << std::endl;
        return 1;
    case BlockValidationResult::BLOCK_MISSING_PREV:
        std::cerr << "We don't have the previous block the checked one is built on" << std::endl;
        return 1;
    case BlockValidationResult::BLOCK_INVALID_PREV:
        std::cerr << "A block this one builds on is invalid" << std::endl;
        return 1;
    case BlockValidationResult::BLOCK_TIME_FUTURE:
        std::cerr << "block timestamp was > 2 hours in the future (or our clock is bad)" << std::endl;
        return 1;
    case BlockValidationResult::BLOCK_CHECKPOINT:
        std::cerr << "the block failed to meet one of our checkpoints" << std::endl;
        return 1;
    }
    return 0;
}

int c_chainstate_manager_delete(void* chainman_, void* scheduler_) {
    if (!chainman_ || !(static_cast<ChainstateManager *>(chainman_))->healthy() ) {
        std::cerr << "Received invalid chainman pointer";
        return -1;
    }
    if (!scheduler_ || !(static_cast<CScheduler *>(scheduler_))->healthy() ) {
        std::cerr << "Received invalid scheduler pointer";
        return -1;
    }
    ChainstateManager* chainman = static_cast<ChainstateManager*>(chainman_);
    CScheduler* scheduler = static_cast<CScheduler*>(scheduler_);
    // Without this precise shutdown sequence, there will be a lot of nullptr
    // dereferencing and UB.
    scheduler->stop();
    if (chainman->m_load_block.joinable()) chainman->m_load_block.join();
    StopScriptCheckWorkerThreads();

    GetMainSignals().FlushBackgroundCallbacks();
    {
        LOCK(cs_main);
        for (Chainstate* chainstate : chainman->GetAll()) {
            if (chainstate->CanFlushToDisk()) {
                chainstate->ForceFlushStateToDisk();
                chainstate->ResetCoinsViews();
            }
        }
    }
    GetMainSignals().UnregisterBackgroundSignalScheduler();
    return 0;
}
