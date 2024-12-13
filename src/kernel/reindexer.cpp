// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "kernel/bitcoinkernel.h"
#include <kernel/bitcoinkernel_wrapper.h>

#include <cassert>
#include <filesystem>
#include <iostream>

class TestLog
{
public:
    void LogMessage(const char* message)
    {
        std::cout << "kernel: " << message;
    }
};

class ReindexKernelNotifications : public KernelNotifications<ReindexKernelNotifications>
{
public:
    void FlushErrorHandler(const char* error) override
    {
        std::cout << error << std::endl;
        assert(0);
    }
    void FatalErrorHandler(const char* error) override
    {
        std::cout << error << std::endl;
        assert(0);
    }
};

Context create_context(ReindexKernelNotifications& notifications, kernel_ChainType chain_type)
{
    ContextOptions options{};
    ChainParams params{chain_type};
    options.SetChainParams(params);
    options.SetNotifications(notifications);
    return Context{options};
}

void run_reindex(std::filesystem::path path_root, std::filesystem::path path_blocks, Context& context)
{
    ChainstateManagerOptions chainman_opts{context, path_root};
    assert(chainman_opts);
    chainman_opts.SetWorkerThreads(15);
    BlockManagerOptions blockman_opts{context, path_blocks};
    assert(blockman_opts);
    auto chainman{ChainMan{context, chainman_opts, blockman_opts}};
    assert(chainman);
    ChainstateLoadOptions chainstate_load_opts{};
    chainstate_load_opts.SetWipeChainstateDb(true);
    chainstate_load_opts.SetWipeBlockTreeDb(true);
    assert(chainman.LoadChainstate(chainstate_load_opts));
    chainman.ImportBlocks({});
}

std::optional<kernel_ChainType> string_to_chain_type(const std::string& chainTypeStr) {
    if (chainTypeStr == "mainnet") {
        return kernel_CHAIN_TYPE_MAINNET;
    } else if (chainTypeStr == "testnet") {
        return kernel_CHAIN_TYPE_TESTNET;
    } else if (chainTypeStr == "signet") {
        return kernel_CHAIN_TYPE_SIGNET;
    } else if (chainTypeStr == "regtest") {
        return kernel_CHAIN_TYPE_REGTEST;
    } else {
        return std::nullopt;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Usage: <data_dir> <chain_type>" << std::endl;
        return 1;
    }

    std::string data_dir_raw{argv[1]};
    std::cout << data_dir_raw;
    std::filesystem::path data_dir{data_dir_raw};
    std::string chain_type_raw{argv[2]};

    kernel_LoggingOptions logging_options = {
        .log_timestamps = true,
        .log_time_micros = true,
        .log_threadnames = false,
        .log_sourcelocations = false,
        .always_print_category_levels = true,
    };
    Logger logger{std::make_unique<TestLog>(TestLog{}), logging_options};

    kernel_ChainType chain_type;
    if (auto maybe_chain_type{string_to_chain_type(chain_type_raw)}) {
        chain_type = *maybe_chain_type;
    } else {
        std::cout << "Error: invalid chain type string. Valid values are \"mainnet\", \"testnet\", \"signet\", \"regtest\"" << std::endl;
        return 1;
    }

    ReindexKernelNotifications notifications{};
    auto context = create_context(notifications, chain_type);
    assert(context);
    run_reindex(data_dir, data_dir / "blocks", context);

    std::cout << "Reindex completed";
}

