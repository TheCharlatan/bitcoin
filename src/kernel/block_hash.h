// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BLOCK_HASH_H
#define BITCOIN_KERNEL_BLOCK_HASH_H

/**
 * A type-safe block identifier.
 */
typedef struct {
    unsigned char hash[32];
} kernel_BlockHash;

#endif // BITCOIN_KERNEL_BLOCK_HASH_H
