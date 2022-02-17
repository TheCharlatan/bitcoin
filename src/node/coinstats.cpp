// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/coinstats.h>

#include <coins.h>
#include <index/coinstatsindex.h>
#include <optional>
#include <validation.h>

namespace node {
//! Calculate statistics about the unspent transaction output set
std::optional<kernel::CCoinsStats> GetUTXOStats(CCoinsView* view, BlockManager& blockman, kernel::CoinStatsHashType hash_type, const std::function<void()>& interruption_point, const CBlockIndex* pindex, bool index_requested)
{
    // Use CoinStatsIndex if it is requested and available and a hash_type of Muhash or None was requested
    if ((hash_type == kernel::CoinStatsHashType::MUHASH || hash_type == kernel::CoinStatsHashType::NONE) && g_coin_stats_index && index_requested) {
        if (pindex) {
            return GetUTXOStatsWithIndex(*g_coin_stats_index, pindex);
        } else {
            return GetUTXOStatsWithIndex(*g_coin_stats_index, view, blockman);
        }
    }

    auto hasher = kernel::MakeUTXOHasher(hash_type);
    return kernel::GetUTXOStatsWithHasher(*hasher, view, blockman, interruption_point);
}
} // namespace node
