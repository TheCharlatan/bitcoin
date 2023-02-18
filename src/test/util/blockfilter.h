// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_BLOCKFILTER_H
#define BITCOIN_TEST_UTIL_BLOCKFILTER_H

#include <blockfilter.h>
#include <node/blockstorage.h>
#include <fs.h>

class CBlockIndex;

bool ComputeFilter(const node::BlockManager& blockman, BlockFilterType filter_type, const CBlockIndex* block_index, BlockFilter& filter);

#endif // BITCOIN_TEST_UTIL_BLOCKFILTER_H
