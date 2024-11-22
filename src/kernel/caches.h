// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_CACHES_H
#define BITCOIN_KERNEL_CACHES_H

#include <txdb.h>
#include <util/check.h>

#include <algorithm>
#include <bit>
#include <cstdint>
#include <limits>

//! Guard against truncation of values before converting.
constexpr size_t MiBToBytes(int64_t mib)
{
    Assert(std::countl_zero(static_cast<uint64_t>(mib)) >= 21); // Ensure signed bit is unset + enough zeros to shift.
    const int64_t bytes{mib << 20};
    Assert(static_cast<uint64_t>(bytes) <= std::numeric_limits<size_t>::max());
    return static_cast<size_t>(bytes);
}

namespace kernel {
struct CacheSizes {
    size_t block_tree_db;
    size_t coins_db;
    size_t coins;

    CacheSizes(size_t total_cache)
    {
        block_tree_db = std::min(total_cache / 8, MiBToBytes(nMaxBlockDBCache));
        total_cache -= block_tree_db;
        coins_db = std::min(total_cache / 2, MiBToBytes(nMaxCoinsDBCache));
        total_cache -= coins_db;
        coins = total_cache; // the rest goes to the coins cache
    }
};
} // namespace kernel

#endif // BITCOIN_KERNEL_CACHES_H
