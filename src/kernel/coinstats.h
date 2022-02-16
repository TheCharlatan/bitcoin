// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_COINSTATS_H
#define BITCOIN_KERNEL_COINSTATS_H

#include <kernel/include/coinstats.h>

#include <chain.h>

namespace node {
CCoinsStats MakeCoinStatsPrefilledWithBlockIndexInfo(const CBlockIndex* pindex);
} // namespace node

#endif // BITCOIN_KERNEL_COINSTATS_H
