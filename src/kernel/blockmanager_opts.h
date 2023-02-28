// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BLOCKMANAGER_OPTS_H
#define BITCOIN_KERNEL_BLOCKMANAGER_OPTS_H

namespace kernel {

/**
 * An options struct for `BlockManager`, more ergonomically referred to as
 * `BlockManager::Options` due to the using-declaration in `BlockManager`
 */
struct BlockManagerOpts {
    bool fast_prune{false};
};
} // namespace kernel

#endif // BITCOIN_KERNEL_BLOCKMANAGER_OPTS_H
