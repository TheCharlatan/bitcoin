// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_MESSAGESTARTMAGIC_H
#define BITCOIN_KERNEL_MESSAGESTARTMAGIC_H

#include <cstddef>

namespace MessageStartMagic {
static constexpr size_t MESSAGE_START_SIZE = 4;
typedef unsigned char MessageStartChars[MESSAGE_START_SIZE];
} // namespace MessageStartMagic

#endif // BITCOIN_KERNEL_MESSAGESTARTMAGIC_H
