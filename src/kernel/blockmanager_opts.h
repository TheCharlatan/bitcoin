// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BLOCKMANAGER_OPTS_H
#define BITCOIN_KERNEL_BLOCKMANAGER_OPTS_H

#include <fs.h>

namespace kernel {

/**
 * An options struct for `BlockManager`, more ergnomically referred to as
 * `BlockManager::Options` due to the using-declartion in `BlockManager`
 */
struct BlockManagerOpts {
    bool fast_prune{false};
    fs::path blocks_dir;
};
} // namespace kernel

#endif // BITCOIN_KERNEL_BLOCKMANAGER_OPTS_H
