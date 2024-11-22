// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_CACHES_H
#define BITCOIN_KERNEL_CACHES_H

#include <cstdint>

//! -dbcache default (MiB)
static constexpr int64_t DEFAULT_DB_CACHE{450};

//! Max memory allocated to block tree DB specific cache, if no -txindex (MiB)
static constexpr int64_t MAX_BLOCK_DB_CACHE{2};

//! Max memory allocated to coin DB specific cache (MiB)
static constexpr int64_t MAX_COINS_DB_CACHE{8};

namespace kernel {
struct CacheSizes {
    int64_t block_tree_db{MAX_BLOCK_DB_CACHE << 20};
    int64_t coins_db{MAX_COINS_DB_CACHE << 20};
    int64_t coins{(DEFAULT_DB_CACHE << 20) - (MAX_BLOCK_DB_CACHE << 20) - (MAX_COINS_DB_CACHE << 20)};
};
} // namespace kernel

#endif // BITCOIN_KERNEL_CACHES_H
