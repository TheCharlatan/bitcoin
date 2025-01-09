// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_BYTE_CONVERSION_H
#define BITCOIN_UTIL_BYTE_CONVERSION_H

#include <tinyformat.h>

#include <cstdint>
#include <limits>
#include <stdexcept>

//! Guard against truncation of values before converting.
constexpr size_t MiBToBytes(int64_t mib)
{
    if (mib < 0) {
        throw std::out_of_range("Value may not be negative.");
    }
    if (static_cast<uint64_t>(mib) > std::numeric_limits<size_t>::max() >> 20) {
        throw std::out_of_range(strprintf("Conversion to bytes of %d does not fit into size_t with maximum value %d.", mib, std::numeric_limits<size_t>::max()));
    }
    return static_cast<size_t>(mib) << 20;
}

#endif // BITCOIN_UTIL_BYTE_CONVERSION_H
