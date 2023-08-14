// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCK_TEMPLATE_H
#define BITCOIN_NODE_BLOCK_TEMPLATE_H

#include <consensus/amount.h>
#include <primitives/block.h>

#include <vector>

namespace node{
struct CBlockTemplate
{
    CBlock block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOpsCost;
    std::vector<unsigned char> vchCoinbaseCommitment;
};
} // namespace node

#endif // BITCOIN_NODE_BLOCK_TEMPLATE_H
