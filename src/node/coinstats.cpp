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
std::optional<CCoinsStats> GetUTXOStatsWithIndex(CoinStatsIndex& coin_stats_index, const CBlockIndex* pindex)
{
    CCoinsStats stats = MakeCoinStatsPrefilledWithBlockIndexInfo(pindex);

    stats.index_used = true;
    if (!coin_stats_index.LookUpStats(pindex, stats)) {
        return std::nullopt;
    }

    return stats;
}

std::optional<CCoinsStats> GetUTXOStatsWithIndex(CoinStatsIndex& coin_stats_index, CCoinsView* view, BlockManager& blockman)
{
    CBlockIndex* pindex = WITH_LOCK(cs_main, return blockman.LookupBlockIndex(view->GetBestBlock()));

    return GetUTXOStatsWithIndex(coin_stats_index, pindex);
}

//! Calculate statistics about the unspent transaction output set
std::optional<CCoinsStats> GetUTXOStats(CCoinsView* view, BlockManager& blockman, CoinStatsHashType hash_type, const std::function<void()>& interruption_point, const CBlockIndex* pindex, bool index_requested)
{
    // Use CoinStatsIndex if it is requested and available and a hash_type of Muhash or None was requested
    if ((hash_type == CoinStatsHashType::MUHASH || hash_type == CoinStatsHashType::NONE) && g_coin_stats_index && index_requested) {
        if (pindex) {
            return GetUTXOStatsWithIndex(*g_coin_stats_index, pindex);
        } else {
            return GetUTXOStatsWithIndex(*g_coin_stats_index, view, blockman);
        }
    }

    auto hasher = MakeUTXOHasher(hash_type);
    return GetUTXOStatsWithHasher(*hasher, view, blockman, interruption_point);
}
} // namespace node
