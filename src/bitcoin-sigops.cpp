// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// The bitcoin-chainstate executable serves to surface the dependencies required
// by a program wishing to use Bitcoin Core's consensus engine as it is right
// now.
//
// DEVELOPER NOTE: Since this is a "demo-only", experimental, etc. executable,
//                 it may diverge from Bitcoin Core's coding style.
//
// It is part of the libbitcoinkernel project.

#include "primitives/transaction.h"
#include <kernel/chainparams.h>
#include <kernel/chainstatemanager_opts.h>
#include <kernel/checks.h>
#include <kernel/context.h>
#include <kernel/warning.h>

#include <consensus/validation.h>
#include <core_io.h>
#include <kernel/caches.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <node/chainstate.h>
#include <random.h>
#include <script/sigcache.h>
#include <undo.h>
#include <util/chaintype.h>
#include <util/fs.h>
#include <util/signalinterrupt.h>
#include <util/task_runner.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <cassert>
#include <cstdint>
#include <functional>
#include <iosfwd>
#include <memory>
#include <string>

/**
 * Check the total number of non-witness sigops across the whole transaction, as per BIP54.
 */
static bool CheckSigopsBIP54(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    Assert(!tx.IsCoinBase());

    if (tx.HasWitness()) {
        return true;
    }

    unsigned int sigops{0};
    for (unsigned i{0}; i < tx.vin.size(); ++i) {
        const auto& prev_txo{inputs.AccessCoin(tx.vin[i].prevout).out};

        // Unlike the existing block wide sigop limit, BIP54 counts sigops when they are actually executed.
        // This means sigops in the spent scriptpubkey count toward the limit.
        // `fAccurate` means correctly accounting sigops for CHECKMULTISIGs with 16 pubkeys or less. This
        // method of accounting was introduced by BIP16, and BIP54 reuses it.
        sigops += tx.vin[i].scriptSig.GetSigOpCount(/*fAccurate=*/true);
        sigops += prev_txo.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);

        std::cout << tx.GetHash().ToString() << "," << sigops << std::endl;

        if (sigops > MAX_TX_LEGACY_SIGOPS) {
            return false;
        }
    }
    return true;
}

int main(int argc, char* argv[])
{
    // We do not enable logging for this app, so explicitly disable it.
    // To enable logging instead, replace with:
    //    LogInstance().m_print_to_console = true;
    //    LogInstance().StartLogging();
    LogInstance().DisableLogging();

    // SETUP: Argument parsing and handling
    if (argc != 2) {
        std::cerr
            << "Usage: " << argv[0] << " DATADIR" << std::endl
            << "Display DATADIR information, and process hex-encoded blocks on standard input." << std::endl
            << std::endl
            << "IMPORTANT: THIS EXECUTABLE IS EXPERIMENTAL, FOR TESTING ONLY, AND EXPECTED TO" << std::endl
            << "           BREAK IN FUTURE VERSIONS. DO NOT USE ON YOUR ACTUAL DATADIR." << std::endl;
        return 1;
    }
    fs::path abs_datadir{fs::absolute(argv[1])};
    fs::create_directories(abs_datadir);


    // SETUP: Context
    kernel::Context kernel_context{};
    // We can't use a goto here, but we can use an assert since none of the
    // things instantiated so far requires running the epilogue to be torn down
    // properly
    assert(kernel::SanityChecks(kernel_context));

    class KernelNotifications : public kernel::Notifications
    {
        void fatalError(const bilingual_str& message) override
        {
            std::cerr << "Error: " << message.original << std::endl;
            exit(1);
        }
    };
    auto notifications = std::make_unique<KernelNotifications>();

    kernel::CacheSizes cache_sizes{DEFAULT_KERNEL_CACHE};

    // SETUP: Chainstate
    auto chainparams = CChainParams::SigNet(CChainParams::SigNetOptions{});
    const ChainstateManager::Options chainman_opts{
        .chainparams = *chainparams,
        .datadir = abs_datadir,
        .notifications = *notifications,
        .signals = nullptr,
    };
    const node::BlockManager::Options blockman_opts{
        .chainparams = chainman_opts.chainparams,
        .blocks_dir = abs_datadir / "blocks",
        .notifications = chainman_opts.notifications,
        .block_tree_db_params = DBParams{
            .path = abs_datadir / "blocks" / "index",
            .cache_bytes = cache_sizes.block_tree_db,
        },
    };
    util::SignalInterrupt interrupt;
    ChainstateManager chainman{interrupt, chainman_opts, blockman_opts};

    node::ChainstateLoadOptions options;
    auto [status, error] = node::LoadChainstate(chainman, cache_sizes, options);
    if (status != node::ChainstateLoadStatus::SUCCESS) {
        std::cerr << "Failed to load Chain state from your datadir." << std::endl;
        std::cerr << error.original << std::endl;
        return 1;
    } else {
        std::tie(status, error) = node::VerifyLoadedChainstate(chainman, options);
        if (status != node::ChainstateLoadStatus::SUCCESS) {
            std::cerr << "Failed to verify loaded Chain state from your datadir." << std::endl;
            return 1;
        }
    }

    for (Chainstate* chainstate : WITH_LOCK(::cs_main, return chainman.GetAll())) {
        BlockValidationState state;
        if (!chainstate->ActivateBestChain(state, nullptr)) {
            std::cerr << "Failed to connect best block (" << state.ToString() << ")" << std::endl;
            return 1;
        }
    }

    CBlockIndex* tip = chainman.ActiveTip();
    CBlockIndex* genesis = chainman.ActiveChain().Genesis();
    CBlock block;
    CBlockUndo block_undo;
    while (tip != genesis) {
        chainman.m_blockman.ReadBlock(block, tip->GetBlockPos());
        chainman.m_blockman.ReadBlockUndo(block_undo, *tip);
        for (uint64_t i{1}; i < block.vtx.size(); i++) {
            CCoinsView coins_dummy;
            CCoinsViewCache coins(&coins_dummy);
            for (uint64_t j{0}; j < block.vtx[i]->vin.size(); j++) {
                COutPoint out{block.vtx[i]->vin[j].prevout};
                Coin coin{block_undo.vtxundo[i-1].vprevout[j]};
                coins.EmplaceCoinInternalDANGER(std::move(out), std::move(coin));
            }

            CheckSigopsBIP54(*block.vtx[i], coins);
        }
        tip = tip->pprev;
    }

    // Without this precise shutdown sequence, there will be a lot of nullptr
    // dereferencing and UB.
    {
        LOCK(cs_main);
        for (Chainstate* chainstate : chainman.GetAll()) {
            if (chainstate->CanFlushToDisk()) {
                chainstate->ForceFlushStateToDisk();
                chainstate->ResetCoinsViews();
            }
        }
    }
}
