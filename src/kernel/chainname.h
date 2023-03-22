// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_CHAINNAME_H
#define BITCOIN_KERNEL_CHAINNAME_H

#include <string>

namespace kernel {
struct chainname {
static const std::string_view MAIN;
static const std::string_view TESTNET;
static const std::string_view SIGNET;
static const std::string_view REGTEST;
};
} // namespace kernel

#endif // BITCOIN_KERNEL_CHAINNAME_H
