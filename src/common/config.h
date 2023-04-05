// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_CONFIG_H
#define BITCOIN_COMMON_CONFIG_H

#include <util/fs.h>

#include <iosfwd>
#include <string>

class ArgsManager;

namespace common {
fs::path GetConfigFile(const ArgsManager& args, const fs::path& configuration_file_path);

/**
 * Most paths passed as configuration arguments are treated as relative to
 * the datadir if they are not absolute.
 *
 * @param args Parsed arguments and settings.
 * @param path The path to be conditionally prefixed with datadir.
 * @param net_specific Use network specific datadir variant
 * @return The normalized path.
 */
fs::path AbsPathForConfigVal(const ArgsManager& args, const fs::path& path, bool net_specific = true);

class ConfigFile
{
public:
    static bool ReadConfigStream(ArgsManager& args, std::istream& stream, const std::string& filepath, std::string& error, bool ignore_invalid_keys = false);

    static bool ReadConfigFiles(ArgsManager& args, std::string& error, bool ignore_invalid_keys = false);
};
} // namespace common

#endif // BITCOIN_COMMON_CONFIG_H
