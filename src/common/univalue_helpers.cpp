// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/univalue_helpers.h>

#include <core_io.h>
#include <script/interpreter.h>
#include <util/result.h>
#include <util/translation.h>

#include <stdexcept>
#include <string>

int ParseSighashString(const UniValue& sighash)
{
    if (sighash.isNull()) {
        return SIGHASH_DEFAULT;
    }
    auto parsed_sighash = ParseSighash(sighash.get_str());
    if (!parsed_sighash) {
        throw std::runtime_error(util::ErrorString(parsed_sighash).original);
    }
    return parsed_sighash.value();
}
