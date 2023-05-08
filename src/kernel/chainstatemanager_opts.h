// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_CHAINSTATEMANAGER_OPTS_H
#define BITCOIN_KERNEL_CHAINSTATEMANAGER_OPTS_H

#include <arith_uint256.h>
#include <dbwrapper.h>
#include <txdb.h>
#include <uint256.h>
#include <util/time.h>

#include <cstdint>
#include <functional>
#include <optional>

class CBlockIndex;
class CChainParams;
enum class SynchronizationState;

static constexpr bool DEFAULT_CHECKPOINTS_ENABLED{true};
static constexpr auto DEFAULT_MAX_TIP_AGE{24h};

namespace kernel {

/**
 * A struct containing callback functions to issue notifications from the
 * `ChainstateManager`. More ergonomically referred to as
 * `ChainstateManager::NotificationCallbacks` due to the using-declaration in
 * `ChainstateManager`.
 */
struct ChainstateManagerNotificationCallbacks {
    const std::function<void(SynchronizationState state, CBlockIndex* index)> notify_block_tip;
    const std::function<void(SynchronizationState state, int64_t height, int64_t timestamp, bool presync)> notify_header_tip;
    const std::function<void(const std::string& title, int nProgress, bool resume_possible)> show_progress;
    const std::function<void(const bilingual_str& warning)> do_warning;
};

/**
 * An options struct for `ChainstateManager`, more ergonomically referred to as
 * `ChainstateManager::Options` due to the using-declaration in
 * `ChainstateManager`.
 */
struct ChainstateManagerOpts {
    const CChainParams& chainparams;
    fs::path datadir;
    const std::function<NodeClock::time_point()> adjusted_time_callback{nullptr};
    std::optional<bool> check_block_index{};
    bool checkpoints_enabled{DEFAULT_CHECKPOINTS_ENABLED};
    //! If set, it will override the minimum work we will assume exists on some valid chain.
    std::optional<arith_uint256> minimum_chain_work{};
    //! If set, it will override the block hash whose ancestors we will assume to have valid scripts without checking them.
    std::optional<uint256> assumed_valid_block{};
    //! If the tip is older than this, the node is considered to be in initial block download.
    std::chrono::seconds max_tip_age{DEFAULT_MAX_TIP_AGE};
    DBOptions block_tree_db{};
    DBOptions coins_db{};
    CoinsViewOptions coins_view{};

    const ChainstateManagerNotificationCallbacks notification_callbacks;
};

} // namespace kernel

#endif // BITCOIN_KERNEL_CHAINSTATEMANAGER_OPTS_H
