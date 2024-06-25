// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>
#include <kernel/bitcoinkernel_wrapper.h>

#include <node/blockstorage.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>

void assert_error_ok(kernel_Error& error)
{
    if (error.code != kernel_ErrorCode::kernel_ERROR_OK) {
        std::cout << error.message << " error code: " << error.code << "\n";
        assert(error.code == kernel_ErrorCode::kernel_ERROR_OK);
    }
}

class TestLog
{
public:
    void LogMessage(const char* message)
    {
        std::cout << "kernel: " << message;
    }
};

class LinearizeKernelNotifications : public KernelNotifications<LinearizeKernelNotifications>
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

Context create_context(LinearizeKernelNotifications& notifications, kernel_Error& error, kernel_ChainType chain_type)
{
    ContextOptions options{};
    ChainParams params{chain_type};
    options.SetChainParams(params, error);
    assert_error_ok(error);
    options.SetNotificationCallbacks(notifications, error);
    assert_error_ok(error);
    return Context{options, error};
}

std::unique_ptr<ChainMan> create_chainman(std::filesystem::path path_root,
                                          std::filesystem::path path_blocks,
                                          kernel_Error& error,
                                          bool block_tree_db_in_memory,
                                          bool chainstate_db_in_memory,
                                          std::optional<uint64_t> max_blockfile_size,
                                          Context& context)
{
    ChainstateManagerOptions chainman_opts{context, path_root, error};
    assert_error_ok(error);
    BlockManagerOptions blockman_opts{context, path_blocks, error};
    assert_error_ok(error);
    if (max_blockfile_size.has_value()) {
        blockman_opts.SetMaxBlockfileSize(max_blockfile_size.value(), error);
        assert_error_ok(error);
    }

    auto chainman{std::make_unique<ChainMan>(context, chainman_opts, blockman_opts, error)};
    assert_error_ok(error);

    ChainstateLoadOptions chainstate_load_opts{};
    if (block_tree_db_in_memory) {
        chainstate_load_opts.SetBlockTreeDbInMemory(block_tree_db_in_memory, error);
        assert_error_ok(error);
    }
    if (chainstate_db_in_memory) {
        chainstate_load_opts.SetChainstateDbInMemory(chainstate_db_in_memory, error);
        assert_error_ok(error);
    }

    chainman->LoadChainstate(chainstate_load_opts, error);
    assert_error_ok(error);

    return chainman;
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
    if (argc != 7) {
        std::cout << "Usage: <in_path> <out_path> <chain_type> <start_height> <end_height> <max_file_size>" << std::endl;
        return 1;
    }

    std::string in_path_raw{argv[1]};
    std::string out_path_raw{argv[2]};
    std::string chain_type_raw{argv[3]};
    int start_height{std::stoi(argv[4])};
    int end_height{std::stoi(argv[5])};
    uint64_t max_blockfile_size{std::stoul(argv[6])};

    std::filesystem::path in_path{in_path_raw};

    kernel_ChainType chain_type;
    if (auto maybe_chain_type{string_to_chain_type(chain_type_raw)}) {
        chain_type = *maybe_chain_type;
    } else {
        std::cout << "Error: invalid chain type string. Valid values are \"mainnet\", \"testnet\", \"signet\", \"regtest\"" << std::endl;
        return 1;
    }

    if (max_blockfile_size < 0x8000000) {
        std::cout << "Error: max blockfile size has to be at least: " << 0x8000000 << " (128 MiB)" << std::endl;
        return 1;
    }

    kernel_Error error;
    error.code = kernel_ErrorCode::kernel_ERROR_OK;

    kernel_LoggingOptions logging_options = {
        .log_timestamps = true,
        .log_time_micros = true,
        .log_threadnames = false,
        .log_sourcelocations = false,
        .always_print_category_levels = true,
    };

    Logger<TestLog>::EnableLogCategory(kernel_LogCategory::kernel_LOG_REINDEX);
    Logger logger{std::make_unique<TestLog>(TestLog{}), logging_options, error};

    LinearizeKernelNotifications notifications{};
    auto context = create_context(notifications, error, chain_type);

    auto chainman_in = create_chainman(in_path, in_path / "blocks", error, false, false, std::nullopt, context);

    auto tip_height = chainman_in->GetBlockIndexFromTip().GetInfo()->height;
    if (start_height < 0 || start_height > tip_height) {
        std::cout << "Invalid start height range, needs to be between 0 and the current tip, which is: " << tip_height;
    }
    if (end_height < start_height || end_height < 0) {
        std::cout << "Invalid end height range, needs to be greater than start height and greater than 0.";
    }

    auto block_index = chainman_in->GetBlockIndexFromGenesis();

    std::filesystem::path out_path{out_path_raw};
    auto chainman_out = create_chainman(out_path, out_path, error, true, true, max_blockfile_size, context);

    std::cout << "In path: " << in_path
              << " , out path: " << out_path
              << " , start height: " << start_height
              << " , end height: " << end_height
              << " , max block file size: " << max_blockfile_size 
              << std::endl;

    while (block_index) {
        auto height = block_index.GetInfo()->height;
        if (height > end_height) {
            break;
        }
        auto block = chainman_in->ReadBlock(block_index, error);
        if (height % 100 == 0) std::cout << "Writing block at height: " << height << std::endl;
        chainman_out->WriteBlockToDisk(block, height, error);

        block_index = chainman_in->GetNextBlockIndex(block_index, error);
    }
    return 0;
}
