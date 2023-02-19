// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BLOCKMANAGER_OPTS_H
#define BITCOIN_KERNEL_BLOCKMANAGER_OPTS_H

#include <fs.h>

namespace kernel {

static constexpr bool DEFAULT_STOPAFTERBLOCKIMPORT{false};

/**
 * An options struct for `BlockManager`, more ergonomically referred to as
 * `BlockManager::Options` due to the using-declaration in `BlockManager`
 */
struct BlockManagerOpts {
    bool fast_prune{false};
    bool stop_after_block_import{DEFAULT_STOPAFTERBLOCKIMPORT};
    fs::path blocks_dir;
};
} // namespace kernel

#endif // BITCOIN_KERNEL_BLOCKMANAGER_OPTS_H
