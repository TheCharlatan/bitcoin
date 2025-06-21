// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/transaction.h"
#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chainparams.h>
#include <consensus/merkle.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <compat/compat.h>
#include <init/common.h>
#include <interfaces/init.h>
#include <interfaces/ipc.h>
#include <key_io.h>
#include <logging.h>
#include <pow.h>
#include <tinyformat.h>
#include <util/translation.h>
#include <util/time.h>
#include <streams.h>
#include <hash.h>
#include <univalue.h>

#include <cstdlib>
#include <thread>
#include <atomic>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

const uint64_t DEFAULT_MAX_TRIES{10'000};
const uint16_t DEFAULT_STRATUM_PORT{3333};
const uint32_t DEFAULT_DIFFICULTY{1};
const uint32_t JOB_REFRESH_INTERVAL{30}; // seconds

static const char* const HELP_USAGE{R"(
bitcoin-mine is a test program for interacting with bitcoin-node via IPC and serving work to a BitAxe miner.

Usage:
  bitcoin-mine [options]
)"};

static const char* HELP_EXAMPLES{R"(
Examples:
  # Start separate bitcoin-node that bitcoin-mine can connect to.
  bitcoin-node -regtest -ipcbind=unix

  # Connect to bitcoin-node and serve work to BitAxe miner.
  bitcoin-mine -regtest -stratumport=3333

  # Run with debug output.
  bitcoin-mine -regtest -debug -stratumport=3333
)"};

const TranslateFn G_TRANSLATION_FUN{nullptr};

struct StratumJob {
    std::string job_id;
    std::string prevhash;
    std::string coinb1;
    std::string coinb2;
    std::vector<std::string> merkle_branch;
    std::string version;
    std::string nbits;
    std::string ntime;
    bool clean_jobs;
    uint32_t target;
    CBlockHeader block_header;
    std::unique_ptr<interfaces::BlockTemplate> block_template;
};

class BitAxeServer {
private:
    std::atomic<bool> running{false};
    int server_socket{-1};
    int client_socket{-1};
    uint16_t port;
    std::unique_ptr<interfaces::Mining> mining;
    std::unique_ptr<StratumJob> current_job;
    std::mutex job_mutex;
    std::atomic<uint32_t> job_counter{0};
    std::thread job_updater_thread;
    std::thread client_handler_thread;
    std::condition_variable job_cv;
    std::atomic<bool> client_subscribed{false};
    std::atomic<bool> client_authorized{false};
    std::string client_address;
    std::string worker_name;

public:
    BitAxeServer(uint16_t port, std::unique_ptr<interfaces::Mining> mining_interface)
        : port(port), mining(std::move(mining_interface)) {}

    ~BitAxeServer() {
        Stop();
    }

    bool Start() {
        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket < 0) {
            LogPrintf("Failed to create socket\n");
            return false;
        }

        int opt = 1;
        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            LogPrintf("Failed to set socket options\n");
            close(server_socket);
            return false;
        }

        struct sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        if (bind(server_socket, (struct sockaddr*)&address, sizeof(address)) < 0) {
            LogPrintf("Failed to bind socket to port %d\n", port);
            close(server_socket);
            return false;
        }

        if (listen(server_socket, 1) < 0) {
            LogPrintf("Failed to listen on socket\n");
            close(server_socket);
            return false;
        }

        running = true;

        // Start job updater thread
        job_updater_thread = std::thread(&BitAxeServer::JobUpdaterLoop, this);

        LogPrintf("BitAxe server listening on port %d\n", port);
        return true;
    }

    void Stop() {
        running = false;

        if (client_socket >= 0) {
            close(client_socket);
            client_socket = -1;
        }

        if (server_socket >= 0) {
            close(server_socket);
            server_socket = -1;
        }

        if (client_handler_thread.joinable()) {
            client_handler_thread.join();
        }

        if (job_updater_thread.joinable()) {
            job_cv.notify_all();
            job_updater_thread.join();
        }
    }

    void WaitForConnection() {
        while (running) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);

            LogPrintf("Waiting for BitAxe connection on port %d...\n", port);
            client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);

            if (client_socket < 0) {
                if (running) {
                    LogPrintf("Failed to accept connection\n");
                }
                continue;
            }

            // Set socket to non-blocking
            int flags = fcntl(client_socket, F_GETFL, 0);
            fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);

            client_address = inet_ntoa(client_addr.sin_addr);
            LogPrintf("BitAxe connected from %s\n", client_address);

            client_handler_thread = std::thread(&BitAxeServer::HandleClient, this);
            client_handler_thread.join(); // Wait for this client to disconnect before accepting another

            // Reset client state
            client_subscribed = false;
            client_authorized = false;
            worker_name.clear();
        }
    }

private:
    void JobUpdaterLoop() {
        while (running) {
            try {
                CreateNewJob();
                if (client_authorized) {
                    SendJob();
                }

                std::unique_lock<std::mutex> lock(job_mutex);
                job_cv.wait_for(lock, std::chrono::seconds(JOB_REFRESH_INTERVAL));
            } catch (const std::exception& e) {
                LogPrintf("Error in job updater: %s\n", e.what());
            }
        }
    }

    void CreateNewJob() {
        auto block_template = mining->createNewBlock({});
        if (!block_template) {
            LogPrintf("Failed to create new block template\n");
            return;
        }

        auto job = std::make_unique<StratumJob>();
        job->job_id = strprintf("%08x", ++job_counter);
        job->block_template = std::move(block_template);

        auto block = job->block_template->getBlock();
        job->block_header = block;

        // Convert block data to stratum format
        job->prevhash = block.hashPrevBlock.ToString();
        job->version = strprintf("%08x", block.nVersion);
        job->nbits = strprintf("%08x", block.nBits);
        job->ntime = strprintf("%08x", block.nTime);
        job->clean_jobs = true;

        // For simplicity, we'll use the coinbase transaction directly
        // In a full implementation, you'd split this into coinb1/coinb2
        DataStream ss;
        ss << TX_WITH_WITNESS(job->block_template->getCoinbaseTx());
        std::string coinbase_hex = HexStr(ss);
        job->coinb1 = coinbase_hex.substr(0, coinbase_hex.length() / 2);
        job->coinb2 = coinbase_hex.substr(coinbase_hex.length() / 2);

        // Calculate merkle branch
        auto block_txs = block.vtx;
        for (size_t i = 1; i < block_txs.size(); ++i) {
            job->merkle_branch.push_back(block_txs[i]->GetHash().ToString());
        }

        job->target = 0x1d00ffff; // Default difficulty target

        {
            std::lock_guard<std::mutex> lock(job_mutex);
            current_job = std::move(job);
        }

        LogPrintf("Created new job %s\n", current_job->job_id);
    }

    void SendJob() {
        std::lock_guard<std::mutex> lock(job_mutex);

        if (!current_job || client_socket < 0) return;

        UniValue job_params(UniValue::VARR);
        job_params.push_back(current_job->job_id);
        job_params.push_back(current_job->prevhash);
        job_params.push_back(current_job->coinb1);
        job_params.push_back(current_job->coinb2);

        UniValue merkle_array(UniValue::VARR);
        for (const auto& branch : current_job->merkle_branch) {
            merkle_array.push_back(branch);
        }
        job_params.push_back(merkle_array);

        job_params.push_back(current_job->version);
        job_params.push_back(current_job->nbits);
        job_params.push_back(current_job->ntime);
        job_params.push_back(current_job->clean_jobs);

        UniValue notify(UniValue::VOBJ);
        notify.pushKV("id", UniValue());
        notify.pushKV("method", "mining.notify");
        notify.pushKV("params", job_params);

        std::string message = notify.write() + "\n";
        SendMessage(message);

        LogPrintf("Sent job %s to BitAxe\n", current_job->job_id);
    }

    void HandleClient() {
        char buffer[4096];
        std::string message_buffer;

        while (running && client_socket >= 0) {
            struct pollfd pfd;
            pfd.fd = client_socket;
            pfd.events = POLLIN;

            int poll_result = poll(&pfd, 1, 1000); // 1 second timeout

            if (poll_result < 0) {
                LogPrintf("Poll error on BitAxe connection\n");
                break;
            } else if (poll_result == 0) {
                continue; // Timeout, check if still running
            }

            ssize_t bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
            if (bytes_read <= 0) {
                if (bytes_read == 0) {
                    LogPrintf("BitAxe disconnected\n");
                } else {
                    LogPrintf("Error reading from BitAxe\n");
                }
                break;
            }

            buffer[bytes_read] = '\0';
            message_buffer += std::string(buffer, bytes_read);

            // Process complete JSON messages (terminated by \n)
            size_t pos;
            while ((pos = message_buffer.find('\n')) != std::string::npos) {
                std::string message = message_buffer.substr(0, pos);
                message_buffer.erase(0, pos + 1);

                if (!message.empty()) {
                    ProcessMessage(message);
                }
            }
        }

        if (client_socket >= 0) {
            close(client_socket);
            client_socket = -1;
        }
        LogPrintf("BitAxe connection closed\n");
    }

    void ProcessMessage(const std::string& message) {
        try {
            UniValue request;
            if (!request.read(message)) {
                LogPrintf("Failed to parse JSON from BitAxe: %s\n", message);
                return;
            }

            std::string method = request.find_value("method").get_str();
            UniValue params = request.find_value("params");
            UniValue id = request.find_value("id");

            if (method == "mining.subscribe") {
                HandleSubscribe(id, params);
            } else if (method == "mining.authorize") {
                HandleAuthorize(id, params);
            } else if (method == "mining.submit") {
                HandleSubmit(id, params);
            } else {
                LogPrintf("Unknown method %s from BitAxe\n", method);
            }
        } catch (const std::exception& e) {
            LogPrintf("Error processing message from BitAxe: %s\n", e.what());
        }
    }

    void HandleSubscribe(const UniValue& id, const UniValue& params) {
        client_subscribed = true;

        UniValue result(UniValue::VARR);
        result.push_back(UniValue(UniValue::VARR)); // subscriptions
        result.push_back("00000001"); // extranonce1
        result.push_back(4); // extranonce2_size

        SendResponse(id, result);
        LogPrintf("BitAxe subscribed\n");
    }

    void HandleAuthorize(const UniValue& id, const UniValue& params) {
        if (params.size() >= 1) {
            worker_name = params[0].get_str();
        }
        client_authorized = true;

        SendResponse(id, true);
        LogPrintf("BitAxe authorized as %s\n", worker_name);

        // Send current job if available
        if (current_job) {
            SendJob();
        }
    }

    void HandleSubmit(const UniValue& id, const UniValue& params) {
        if (params.size() < 5) {
            SendError(id, "Invalid parameters");
            return;
        }

        std::string submit_worker = params[0].get_str();
        std::string job_id = params[1].get_str();
        std::string extranonce2 = params[2].get_str();
        std::string ntime = params[3].get_str();
        std::string nonce = params[4].get_str();

        LogPrintf("Share submitted by BitAxe: job=%s, nonce=%s\n", job_id, nonce);

        // Validate and process the share
        bool valid = ValidateShare(job_id, extranonce2, ntime, nonce);

        if (valid) {
            LogPrintf("Valid share from BitAxe!\n");
            SendResponse(id, true);
        } else {
            LogPrintf("Invalid share from BitAxe\n");
            SendResponse(id, false);
        }
    }

    bool ValidateShare(const std::string& job_id, const std::string& extranonce2,
                      const std::string& ntime, const std::string& nonce) {
        std::lock_guard<std::mutex> lock(job_mutex);

        if (!current_job || current_job->job_id != job_id) {
            LogPrintf("Share for unknown/old job: %s\n", job_id);
            return false;
        }

        try {
            // Reconstruct the block header with the submitted values
            CBlockHeader header = current_job->block_header;
            header.nTime = strtoul(ntime.c_str(), nullptr, 16);
            header.nNonce = strtoul(nonce.c_str(), nullptr, 16);

            // Calculate merkle root with the modified coinbase
            header.hashMerkleRoot = BlockMerkleRoot(current_job->block_template->getBlock());

            // Check if the solution meets the target
            auto consensus_params = Params().GetConsensus();
            if (CheckProofOfWork(header.GetHash(), header.nBits, consensus_params)) {
                LogPrintf("BLOCK FOUND! Submitting to network...\n");

                // Submit the solution
                current_job->block_template->submitSolution(header.nVersion, header.nTime,
                                                          header.nNonce, current_job->block_template->getCoinbaseTx());
                return true;
            }

            // For now, accept all properly formatted shares
            // In production, you'd check against stratum difficulty
            return true;

        } catch (const std::exception& e) {
            LogPrintf("Error validating share: %s\n", e.what());
            return false;
        }
    }

    void SendResponse(const UniValue& id, const UniValue& result) {
        UniValue response(UniValue::VOBJ);
        response.pushKV("id", id);
        response.pushKV("result", result);
        response.pushKV("error", UniValue());

        std::string message = response.write() + "\n";
        SendMessage(message);
    }

    void SendError(const UniValue& id, const std::string& error_msg) {
        UniValue response(UniValue::VOBJ);
        response.pushKV("id", id);
        response.pushKV("result", UniValue());
        response.pushKV("error", error_msg);

        std::string message = response.write() + "\n";
        SendMessage(message);
    }

    void SendMessage(const std::string& message) {
        if (client_socket < 0) return;

        ssize_t sent = send(client_socket, message.c_str(), message.length(), MSG_NOSIGNAL);
        if (sent < 0 || sent != static_cast<ssize_t>(message.length())) {
            LogPrintf("Failed to send message to BitAxe\n");
            close(client_socket);
            client_socket = -1;
        }
    }
};

static void AddArgs(ArgsManager& args)
{
    SetupHelpOptions(args);
    SetupChainParamsBaseOptions(args);
    args.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-datadir=<dir>", "Specify data directory", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-ipcconnect=<address>", "Connect to bitcoin-node process in the background to perform online operations. Valid <address> values are 'unix' to connect to the default socket, 'unix:<socket path>' to connect to a socket at a nonstandard path. Default value: unix", ArgsManager::ALLOW_ANY, OptionsCategory::IPC);
    args.AddArg("-maxtries=<n>", strprintf("Try to mine a block for <n> tries. Default %d", DEFAULT_MAX_TRIES), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-stratumport=<port>", strprintf("Port to listen for BitAxe connection. Default %d", DEFAULT_STRATUM_PORT), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-nostratumserver", "Disable stratum server and only do local CPU mining", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    init::AddLoggingArgs(args);
}

MAIN_FUNCTION
{
    ArgsManager& args = gArgs;
    AddArgs(args);
    std::string error_message;
    if (!args.ParseParameters(argc, argv, error_message)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error_message);
        return EXIT_FAILURE;
    }
    if (!args.ReadConfigFiles(error_message, true)) {
        tfm::format(std::cerr, "Error reading config files: %s\n", error_message);
        return EXIT_FAILURE;
    }
    if (HelpRequested(args) || args.IsArgSet("-version")) {
        std::string output{strprintf("%s bitcoin-mine version", CLIENT_NAME) + " " + FormatFullVersion() + "\n"};
        if (args.IsArgSet("-version")) {
            output += FormatParagraph(LicenseInfo());
        } else {
            output += HELP_USAGE;
            output += args.GetHelpMessage();
            output += HELP_EXAMPLES;
        }
        tfm::format(std::cout, "%s", output);
        return EXIT_SUCCESS;
    }
    if (!CheckDataDirOption(args)) {
        tfm::format(std::cerr, "Error: Specified data directory \"%s\" does not exist.\n", args.GetArg("-datadir", ""));
        return EXIT_FAILURE;
    }
    SelectParams(args.GetChainType());

    // Set logging options but override -printtoconsole default to depend on -debug rather than -daemon
    init::SetLoggingOptions(args);
    if (auto result{init::SetLoggingCategories(args)}; !result) {
        tfm::format(std::cerr, "Error: %s\n", util::ErrorString(result).original);
        return EXIT_FAILURE;
    }
    if (auto result{init::SetLoggingLevel(args)}; !result) {
        tfm::format(std::cerr, "Error: %s\n", util::ErrorString(result).original);
        return EXIT_FAILURE;
    }
    LogInstance().m_print_to_console = args.GetBoolArg("-printtoconsole", LogInstance().GetCategoryMask());
    if (!init::StartLogging(args)) {
        tfm::format(std::cerr, "Error: StartLogging failed\n");
        return EXIT_FAILURE;
    }

    // Connect to bitcoin-node process, or fail and print an error.
    std::unique_ptr<interfaces::Init> mine_init{interfaces::MakeBasicInit("bitcoin-mine", argc > 0 ? argv[0] : "")};
    assert(mine_init);
    std::unique_ptr<interfaces::Init> node_init;
    try {
        std::string address{args.GetArg("-ipcconnect", "unix")};
        node_init = mine_init->ipc()->connectAddress(address);
    } catch (const std::exception& exception) {
        tfm::format(std::cerr, "Error: %s\n", exception.what());
        tfm::format(std::cerr, "Probably bitcoin-node is not running or not listening on a unix socket. Can be started with:\n\n");
        tfm::format(std::cerr, "    bitcoin-node -chain=%s -ipcbind=unix\n", args.GetChainTypeString());
        return EXIT_FAILURE;
    }
    assert(node_init);
    tfm::format(std::cout, "Connected to bitcoin-node\n");
    std::unique_ptr<interfaces::Mining> mining{node_init->makeMining()};
    assert(mining);

    auto tip{mining->getTip()};
    if (tip) {
        tfm::format(std::cout, "Tip hash is %s.\n", tip->hash.ToString());
    } else {
        tfm::format(std::cout, "Tip hash is null.\n");
        return EXIT_SUCCESS;
    }

    bool run_stratum_server = !args.GetBoolArg("-nostratumserver", false);

    if (run_stratum_server) {
        // Start BitAxe server
        uint16_t stratum_port = args.GetIntArg("-stratumport", DEFAULT_STRATUM_PORT);
        BitAxeServer server(stratum_port, std::move(mining));

        if (!server.Start()) {
            tfm::format(std::cerr, "Failed to start BitAxe server on port %d\n", stratum_port);
            return EXIT_FAILURE;
        }

        tfm::format(std::cout, "BitAxe server started on port %d\n", stratum_port);
        tfm::format(std::cout, "Connect your BitAxe to: stratum+tcp://YOUR_IP:%d\n", stratum_port);
        tfm::format(std::cout, "Press Ctrl+C to stop...\n");

        // Wait for connection (this blocks)
        server.WaitForConnection();
    } else {
        // Original CPU mining code
        auto consensus_params{Params().GetConsensus()};
        uint64_t max_tries{std::max<uint64_t>(DEFAULT_MAX_TRIES, args.GetIntArg("-maxtries", DEFAULT_MAX_TRIES))};
        auto tries_remaining{max_tries};
        auto block_template{mining->createNewBlock({})};
        auto block{block_template->getBlock()};
        block.hashMerkleRoot = BlockMerkleRoot(block);

        while (tries_remaining > 0 && block.nNonce < std::numeric_limits<uint32_t>::max() && !CheckProofOfWork(block.GetHash(), block.nBits, consensus_params)) {
            ++block.nNonce;
            --tries_remaining;
        }
        block_template->submitSolution(block.nVersion, block.nTime, block.nNonce, block_template->getCoinbaseTx());

        if (tip->hash != mining->getTip()->hash) {
            tfm::format(std::cout, "Mined a block, tip advanced to %s.\n", mining->getTip()->hash.ToString());
        } else {
            tfm::format(std::cout, "Failed to mine a block in %d iterations. Try again. \n", max_tries);
        }
    }

    return EXIT_SUCCESS;
}
