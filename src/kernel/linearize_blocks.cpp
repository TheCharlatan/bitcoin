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

Context create_context(LinearizeKernelNotifications& notifications, kernel_ChainType chain_type)
{
    ContextOptions options{};
    ChainParams params{chain_type};
    options.SetChainParams(params);
    options.SetNotifications(notifications);
    return Context{options};
}

std::unique_ptr<ChainMan> create_chainman(std::filesystem::path path_root,
                                          std::filesystem::path path_blocks,
                                          bool block_tree_db_in_memory,
                                          bool chainstate_db_in_memory,
                                          Context& context)
{
    ChainstateManagerOptions chainman_opts{context, path_root};
    assert(chainman_opts);
    BlockManagerOptions blockman_opts{context, path_blocks};
    assert(blockman_opts);

    auto chainman{std::make_unique<ChainMan>(context, chainman_opts, blockman_opts)};
    assert(chainman);

    ChainstateLoadOptions chainstate_load_opts{};
    if (block_tree_db_in_memory) {
        chainstate_load_opts.SetBlockTreeDbInMemory(block_tree_db_in_memory);
    }
    if (chainstate_db_in_memory) {
        chainstate_load_opts.SetChainstateDbInMemory(chainstate_db_in_memory);
    }

    assert(chainman->LoadChainstate(chainstate_load_opts));

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
        std::cout << "Usage: <in_path> <out_path> <chain_type> <start_height> <end_height> <single_file>" << std::endl;
        return 1;
    }

    std::string in_path_raw{argv[1]};
    std::string out_path_raw{argv[2]};
    std::string chain_type_raw{argv[3]};
    int start_height{std::stoi(argv[4])};
    int end_height{std::stoi(argv[5])};
    bool single_file{static_cast<bool>(std::stoi(argv[6]))};

    std::filesystem::path in_path{in_path_raw};

    kernel_ChainType chain_type;
    if (auto maybe_chain_type{string_to_chain_type(chain_type_raw)}) {
        chain_type = *maybe_chain_type;
    } else {
        std::cout << "Error: invalid chain type string. Valid values are \"mainnet\", \"testnet\", \"signet\", \"regtest\"" << std::endl;
        return 1;
    }

    kernel_LoggingOptions logging_options = {
        .log_timestamps = true,
        .log_time_micros = true,
        .log_threadnames = false,
        .log_sourcelocations = false,
        .always_print_category_levels = true,
    };

    assert(kernel_enable_log_category(kernel_LogCategory::kernel_LOG_REINDEX));
    Logger logger{std::make_unique<TestLog>(TestLog{}), logging_options};

    LinearizeKernelNotifications notifications{};
    auto context = create_context(notifications, chain_type);
    assert(context);

    auto chainman_in = create_chainman(in_path, in_path / "blocks", false, false, context);

    auto tip_height = chainman_in->GetBlockIndexFromTip().GetHeight();
    if (start_height < 0 || start_height > tip_height) {
        std::cout << "Invalid start height range, needs to be between 0 and the current tip, which is: " << tip_height;
    }
    if (end_height < start_height || end_height < 0) {
        std::cout << "Invalid end height range, needs to be greater than start height and greater than 0.";
    }

    auto block_index = std::make_optional<BlockIndex>(chainman_in->GetBlockIndexFromGenesis());

    std::filesystem::path out_path{out_path_raw};
    auto chainman_out = create_chainman(out_path, out_path, true, true, context);

    std::cout << "In path: " << in_path
              << " , out path: " << out_path
              << " , start height: " << start_height
              << " , end height: " << end_height
              << " , single file: " << single_file
              << std::endl;

    while (block_index) {
        auto height = block_index.value().GetHeight();
        if (height > end_height) {
            break;
        }
        auto block = chainman_in->ReadBlock(*block_index).value();
        if (height % 100 == 0) std::cout << "Writing block at height: " << height << std::endl;
        chainman_out->WriteBlockToDisk(block, height);

        block_index = chainman_in->GetNextBlockIndex(*block_index);
    }

    if (!single_file) return 0;

    // Collect and sort all blk*.dat filenames
    std::vector<std::string> files;
    for (const auto& entry : fs::directory_iterator(out_path)) {
        if (entry.is_regular_file() && entry.path().extension() == ".dat" && entry.path().filename().string().starts_with("blk")) {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());

    std::filesystem::path output_filename = out_path / "blk-merged.dat"; // Output file name

    std::ofstream output_file(output_filename, std::ios::binary);
    if (!output_file.is_open()) {
        std::cerr << "Failed to open output file: " << output_filename << std::endl;
        return 1;
    }

    for (const std::string& filename : files) {
        std::ifstream inputFile(filename, std::ios::binary);
        if (!inputFile.is_open()) {
            std::cerr << "Failed to open input file: " << filename << std::endl;
            continue;
        }
        output_file << inputFile.rdbuf();

        std::cout << "Merged and deleting: " << filename << std::endl;

        inputFile.close();

        if (fs::remove(filename)) {
            std::cout << "Deleted: " << filename << std::endl;
        } else {
            std::cerr << "Failed to delete: " << filename << std::endl;
        }
    }

    output_file.close();

    return 0;
}
