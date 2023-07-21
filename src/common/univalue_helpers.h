// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_UNIVALUE_HELPERS_H
#define BITCOIN_COMMON_UNIVALUE_HELPERS_H

#include <univalue.h> // IWYU pragma: export

#include <string>
#include <vector>

std::vector<unsigned char> ParseHexUV(const UniValue& v, const std::string& strName);

int ParseSighashString(const UniValue& sighash);

#endif // BITCOIN_COMMON_UNIVALUE_HELPERS_H
