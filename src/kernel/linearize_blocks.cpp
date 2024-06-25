// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>
#include <kernel/bitcoinkernel_wrapper.h>

#include <cassert>
#include <filesystem>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
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

class LinearizeKernelNotifications : public KernelNotifications<LinearizeKernelNotifications>
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

Context create_context(std::shared_ptr<LinearizeKernelNotifications> notifications, ChainType chain_type)
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
    ChainstateManagerOptions chainman_opts{context, path_root, path_blocks};

    if (block_tree_db_in_memory) {
        chainman_opts.SetBlockTreeDbInMemory(block_tree_db_in_memory);
    }
    if (chainstate_db_in_memory) {
        chainman_opts.SetChainstateDbInMemory(chainstate_db_in_memory);
    }

    return std::make_unique<ChainMan>(context, chainman_opts);
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

    ChainType chain_type;
    if (auto maybe_chain_type{string_to_chain_type(chain_type_raw)}) {
        chain_type = *maybe_chain_type;
    } else {
        std::cout << "Error: invalid chain type string. Valid values are \"mainnet\", \"testnet\", \"signet\", \"regtest\"" << std::endl;
        return 1;
    }

    btck_LoggingOptions logging_options = {
        .log_timestamps = true,
        .log_time_micros = true,
        .log_threadnames = false,
        .log_sourcelocations = false,
        .always_print_category_levels = true,
    };

    logging_enable_category(LogCategory::REINDEX);
    Logger logger{std::make_unique<TestLog>(TestLog{}), logging_options};

    auto notifications{std::make_shared<LinearizeKernelNotifications>()};
    auto context = create_context(notifications, chain_type);

    auto chainman_in = create_chainman(in_path, in_path / "blocks", false, false, context);

    auto tip_height = chainman_in->GetChain().Height();
    if (start_height < 0 || start_height > tip_height) {
        std::cout << "Invalid start height range, needs to be between 0 and the current tip, which is: " << tip_height;
    }
    if (end_height < start_height || end_height < 0) {
        std::cout << "Invalid end height range, needs to be greater than start height and greater than 0.";
    }

    std::filesystem::path out_path{out_path_raw};
    auto chainman_out = create_chainman(out_path, out_path, true, true, context);

    std::cout << "In path: " << in_path
              << " , out path: " << out_path
              << " , start height: " << start_height
              << " , end height: " << end_height
              << " , single file: " << single_file
              << std::endl;

    for (const auto entry : chainman_in->GetChain().Entries()) {
        auto height = entry.GetHeight();
        if (height > end_height) {
            break;
        }
        auto block = chainman_in->ReadBlock(entry).value();

        if (height % 100 == 0) std::cout << "Writing block at height: " << height << std::endl;
        chainman_out->WriteBlockToDisk(block, height);
    }

    if (!single_file) return 0;

    // Collect and sort all blk*.dat filenames
    std::vector<std::string> files;
    for (const auto& entry : std::filesystem::directory_iterator(out_path)) {
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

        if (std::filesystem::remove(filename)) {
            std::cout << "Deleted: " << filename << std::endl;
        } else {
            std::cerr << "Failed to delete: " << filename << std::endl;
        }
    }

    output_file.close();

    return 0;
}
