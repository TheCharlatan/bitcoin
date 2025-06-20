#include <kernel/chainparams.h>
#include <kernel/chainstatemanager_opts.h>
#include <kernel/checks.h>
#include <kernel/context.h>
#include <kernel/warning.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <util/signalinterrupt.h>

#include <iostream>

int main(int argc, char* argv[])
{
    // We do not enable logging for this app, so explicitly disable it.
    // To enable logging instead, replace with:
    //    LogInstance().m_print_to_console = true;
    //    LogInstance().StartLogging();
    LogInstance().DisableLogging();

    const std::string data_dir{"/home/drgrid/bitcoin/test_signet_blocktreestore/signet"};
    fs::path abs_datadir{fs::absolute(data_dir.c_str())};
    if (!fs::exists(abs_datadir)) {
        std::cout << "Data dir is not pointing to an existing directory" << std::endl;
        return 0;
    }
    std::cout << "Using directory: " << fs::PathToString(abs_datadir) << std::endl;


    auto chainparams = CChainParams::SigNet(CChainParams::SigNetOptions{});

    class KernelNotifications : public kernel::Notifications
    {
    public:
        kernel::InterruptResult blockTip(SynchronizationState, CBlockIndex&) override
        {
            return {};
        }
        void headerTip(SynchronizationState, int64_t height, int64_t timestamp, bool presync) override { }
        void progress(const bilingual_str& title, int progress_percent, bool resume_possible) override { }
        void warningSet(kernel::Warning id, const bilingual_str& message) override { }
        void warningUnset(kernel::Warning id) override { }
        void flushError(const bilingual_str& message) override { }
        void fatalError(const bilingual_str& message) override { }
    };
    auto notifications = std::make_unique<KernelNotifications>();

    util::SignalInterrupt interrupt;
    const node::BlockManager::Options blockman_opts{
        .chainparams = *chainparams,
        .blocks_dir = abs_datadir / "blocks",
        .block_tree_dir = abs_datadir / "blocks" / "index",
        .notifications = *notifications,
    };

    node::BlockManager blockman{interrupt, blockman_opts};

    blockman.LoadBlockIndexDB({});

    const CBlockIndex* best = nullptr;
    for (const auto& [hash, block_index] : blockman.m_block_index) {
        if (best == nullptr) best = &block_index;
        if (best->nChainWork < block_index.nChainWork) best = &block_index;
    }

    CBlock block;
    blockman.ReadBlock(block, best->GetBlockPos());
    std::cout << "Best block found: " << block.GetHash().ToString() << std::endl;
}

