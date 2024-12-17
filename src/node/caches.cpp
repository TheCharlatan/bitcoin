// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/caches.h>

#include <common/args.h>
#include <index/txindex.h>
#include <kernel/caches.h>
#include <logging.h>
#include <util/byte_conversion.h>

#include <algorithm>
#include <optional>
#include <stdexcept>
#include <string>

// Unlike for the UTXO database, for the txindex scenario the leveldb cache make
// a meaningful difference: https://github.com/bitcoin/bitcoin/pull/8273#issuecomment-229601991
//! Max memory allocated to tx index DB specific cache in bytes.
static constexpr size_t MAX_TX_INDEX_CACHE{MiBToBytes(1024)};
//! Max memory allocated to all block filter index caches combined in bytes.
static constexpr size_t MAX_FILTER_INDEX_CACHE{MiBToBytes(1024)};

namespace node {
std::optional<CacheSizes> CalculateCacheSizes(const ArgsManager& args, size_t n_indexes)
{
    int64_t db_cache = args.GetIntArg("-dbcache", DEFAULT_DB_CACHE);

    // negative values are permitted, but interpreted as zero.
    db_cache = std::max(int64_t{0}, db_cache);

    size_t total_cache = 0;
    try {
        total_cache = std::max(MiBToBytes(db_cache), MiBToBytes(MIN_DB_CACHE));
    } catch (const std::out_of_range&) {
        LogError("Cannot allocate more than %d MiB in total for db caches.", std::numeric_limits<size_t>::max() >> 20);
        return std::nullopt;
    }

    IndexCacheSizes index_sizes;
    index_sizes.tx_index = std::min(total_cache / 8, args.GetBoolArg("-txindex", DEFAULT_TXINDEX) ? MAX_TX_INDEX_CACHE : 0);
    total_cache -= index_sizes.tx_index;
    index_sizes.filter_index = 0;
    if (n_indexes > 0) {
        int64_t max_cache = std::min(total_cache / 8, MAX_FILTER_INDEX_CACHE);
        index_sizes.filter_index = max_cache / n_indexes;
        total_cache -= index_sizes.filter_index * n_indexes;
    }
    return {{index_sizes, kernel::CacheSizes{total_cache}}};
}
} // namespace node
