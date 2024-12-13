// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "kernel/bitcoinkernel.h"
#include <kernel/bitcoinkernel_wrapper.h>

#include <cassert>
#include <filesystem>
#include <iostream>
#include <string>

using namespace btck;

class TestLog
{
public:
    void LogMessage(std::string_view message)
    {
        std::cout << "kernel: " << message;
    }
};

class ReindexKernelNotifications : public KernelNotifications<ReindexKernelNotifications>
{
public:
    void FlushErrorHandler(std::string_view error) override
    {
        std::cout << error << std::endl;
        assert(0);
    }
    void FatalErrorHandler(std::string_view error) override
    {
        std::cout << error << std::endl;
        assert(0);
    }
};

Context create_context(std::shared_ptr<ReindexKernelNotifications> notifications, ChainType chain_type)
{
    ContextOptions options{};
    ChainParams params{chain_type};
    options.SetChainParams(params);
    options.SetNotifications(notifications);
    return Context{options};
}

void run_reindex(std::filesystem::path path_root, std::filesystem::path path_blocks, Context& context)
{
    ChainstateManagerOptions chainman_opts{context, path_root, path_blocks};
    chainman_opts.SetWipeDbs(true, true);
    chainman_opts.SetWorkerThreads(15);
    auto chainman{ChainMan{context, chainman_opts}};
    chainman.ImportBlocks({});
}

std::optional<ChainType> string_to_chain_type(const std::string& chainTypeStr) {
    if (chainTypeStr == "mainnet") {
        return ChainType::MAINNET;
    } else if (chainTypeStr == "testnet") {
        return ChainType::TESTNET;
    } else if (chainTypeStr == "signet") {
        return ChainType::SIGNET;
    } else if (chainTypeStr == "regtest") {
        return ChainType::REGTEST;
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

    btck_LoggingOptions logging_options = {
        .log_timestamps = true,
        .log_time_micros = true,
        .log_threadnames = false,
        .log_sourcelocations = false,
        .always_print_category_levels = true,
    };
    Logger logger{std::make_unique<TestLog>(TestLog{}), logging_options};

    ChainType chain_type;
    if (auto maybe_chain_type{string_to_chain_type(chain_type_raw)}) {
        chain_type = *maybe_chain_type;
    } else {
        std::cout << "Error: invalid chain type string. Valid values are \"mainnet\", \"testnet\", \"signet\", \"regtest\"" << std::endl;
        return 1;
    }

    auto notifications{std::make_shared<ReindexKernelNotifications>()};
    auto context = create_context(notifications, chain_type);
    run_reindex(data_dir, data_dir / "blocks", context);

    std::cout << "Reindex completed";
}

