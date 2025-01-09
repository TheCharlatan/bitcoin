// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_BYTE_UNITS_H
#define BITCOIN_UTIL_BYTE_UNITS_H

#include <util/overflow.h>

#include <stdexcept>

//! Overflow-safe conversion of MiB to bytes.
constexpr size_t operator"" _MiB(unsigned long long mebibytes)
{
    auto bytes{CheckedLeftShift<size_t>(static_cast<size_t>(mebibytes), 20)};
    if (!bytes) {
        throw std::overflow_error("mebibytes could not be converted to bytes");
    }
    return *bytes;
}

#endif // BITCOIN_UTIL_BYTE_UNITS_H
