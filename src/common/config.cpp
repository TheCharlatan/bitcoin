// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/config.h>

#include <common/args.h>
#include <logging.h>
#include <sync.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/settings.h>
#include <util/string.h>

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace common {
static bool GetConfigOptions(std::istream& stream, const std::string& filepath, std::string& error, std::vector<std::pair<std::string, std::string>>& options, std::list<SectionInfo>& sections)
{
    std::string str, prefix;
    std::string::size_type pos;
    int linenr = 1;
    while (std::getline(stream, str)) {
        bool used_hash = false;
        if ((pos = str.find('#')) != std::string::npos) {
            str = str.substr(0, pos);
            used_hash = true;
        }
        const static std::string pattern = " \t\r\n";
        str = TrimString(str, pattern);
        if (!str.empty()) {
            if (*str.begin() == '[' && *str.rbegin() == ']') {
                const std::string section = str.substr(1, str.size() - 2);
                sections.emplace_back(SectionInfo{section, filepath, linenr});
                prefix = section + '.';
            } else if (*str.begin() == '-') {
                error = strprintf("parse error on line %i: %s, options in configuration file must be specified without leading -", linenr, str);
                return false;
            } else if ((pos = str.find('=')) != std::string::npos) {
                std::string name = prefix + TrimString(std::string_view{str}.substr(0, pos), pattern);
                std::string_view value = TrimStringView(std::string_view{str}.substr(pos + 1), pattern);
                if (used_hash && name.find("rpcpassword") != std::string::npos) {
                    error = strprintf("parse error on line %i, using # in rpcpassword can be ambiguous and should be avoided", linenr);
                    return false;
                }
                options.emplace_back(name, value);
                if ((pos = name.rfind('.')) != std::string::npos && prefix.length() <= pos) {
                    sections.emplace_back(SectionInfo{name.substr(0, pos), filepath, linenr});
                }
            } else {
                error = strprintf("parse error on line %i: %s", linenr, str);
                if (str.size() >= 2 && str.substr(0, 2) == "no") {
                    error += strprintf(", if you intended to specify a negated option, use %s=1 instead", str);
                }
                return false;
            }
        }
        ++linenr;
    }
    return true;
}

fs::path GetConfigFile(const ArgsManager& args, const fs::path& configuration_file_path)
{
    return AbsPathForConfigVal(args, configuration_file_path, /*net_specific=*/false);
}

fs::path AbsPathForConfigVal(const ArgsManager& args, const fs::path& path, bool net_specific)
{
    if (path.is_absolute()) {
        return path;
    }
    return fsbridge::AbsPathJoin(net_specific ? args.GetDataDirNet() : args.GetDataDirBase(), path);
}

bool ConfigFile::ReadConfigFiles(ArgsManager& args, std::string& error, bool ignore_invalid_keys)
{
    {
        LOCK(args.cs_args);
        args.m_settings.ro_config.clear();
        args.m_config_sections.clear();
    }

    const auto conf_path{args.GetConfigFilePath()};
    std::ifstream stream{conf_path};

    // not ok to have a config file specified that cannot be opened
    if (args.IsArgSet("-conf") && !stream.good()) {
        error = strprintf("specified config file \"%s\" could not be opened.", fs::PathToString(conf_path));
        return false;
    }
    // ok to not have a config file
    if (stream.good()) {
        if (!ReadConfigStream(args, stream, fs::PathToString(conf_path), error, ignore_invalid_keys)) {
            return false;
        }
        // `-includeconf` cannot be included in the command line arguments except
        // as `-noincludeconf` (which indicates that no included conf file should be used).
        bool use_conf_file{true};
        {
            LOCK(args.cs_args);
            if (auto* includes = util::FindKey(args.m_settings.command_line_options, "includeconf")) {
                // ParseParameters() fails if a non-negated -includeconf is passed on the command-line
                assert(util::SettingsSpan(*includes).last_negated());
                use_conf_file = false;
            }
        }
        if (use_conf_file) {
            std::string chain_id = args.GetChainName();
            std::vector<std::string> conf_file_names;

            auto add_includes = [&](const std::string& network, size_t skip = 0) {
                size_t num_values = 0;
                LOCK(args.cs_args);
                if (auto* section = util::FindKey(args.m_settings.ro_config, network)) {
                    if (auto* values = util::FindKey(*section, "includeconf")) {
                        for (size_t i = std::max(skip, util::SettingsSpan(*values).negated()); i < values->size(); ++i) {
                            conf_file_names.push_back((*values)[i].get_str());
                        }
                        num_values = values->size();
                    }
                }
                return num_values;
            };

            // We haven't set m_network yet (that happens in SelectParams()), so manually check
            // for network.includeconf args.
            const size_t chain_includes = add_includes(chain_id);
            const size_t default_includes = add_includes({});

            for (const std::string& conf_file_name : conf_file_names) {
                std::ifstream conf_file_stream{GetConfigFile(args, fs::PathFromString(conf_file_name))};
                if (conf_file_stream.good()) {
                    if (!ReadConfigStream(args, conf_file_stream, conf_file_name, error, ignore_invalid_keys)) {
                        return false;
                    }
                    LogPrintf("Included configuration file %s\n", conf_file_name);
                } else {
                    error = "Failed to include configuration file " + conf_file_name;
                    return false;
                }
            }

            // Warn about recursive -includeconf
            conf_file_names.clear();
            add_includes(chain_id, /* skip= */ chain_includes);
            add_includes({}, /* skip= */ default_includes);
            std::string chain_id_final = args.GetChainName();
            if (chain_id_final != chain_id) {
                // Also warn about recursive includeconf for the chain that was specified in one of the includeconfs
                add_includes(chain_id_final);
            }
            for (const std::string& conf_file_name : conf_file_names) {
                tfm::format(std::cerr, "warning: -includeconf cannot be used from included files; ignoring -includeconf=%s\n", conf_file_name);
            }
        }
    }

    // If datadir is changed in .conf file:
    args.ClearPathCache();
    if (!CheckDataDirOption(args)) {
        error = strprintf("specified data directory \"%s\" does not exist.", args.GetArg("-datadir", ""));
        return false;
    }
    return true;
}

bool ConfigFile::ReadConfigStream(ArgsManager& args, std::istream& stream, const std::string& filepath, std::string& error, bool ignore_invalid_keys)
{
    LOCK(args.cs_args);
    std::vector<std::pair<std::string, std::string>> options;
    if (!GetConfigOptions(stream, filepath, error, options, args.m_config_sections)) {
        return false;
    }
    for (const std::pair<std::string, std::string>& option : options) {
        KeyInfo key = InterpretKey(option.first);
        std::optional<unsigned int> flags = args.GetArgFlags('-' + key.name);
        if (!IsConfSupported(key, error)) return false;
        if (flags) {
            std::optional<util::SettingsValue> value = InterpretValue(key, &option.second, *flags, error);
            if (!value) {
                return false;
            }
            args.m_settings.ro_config[key.section][key.name].push_back(*value);
        } else {
            if (ignore_invalid_keys) {
                LogPrintf("Ignoring unknown configuration value %s\n", option.first);
            } else {
                error = strprintf("Invalid configuration value %s", option.first);
                return false;
            }
        }
    }
    return true;
}
} // namespace common
