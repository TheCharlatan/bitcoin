// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <logging.h>
#include <util/shell.h>
#include <util/string.h>

#include <stdlib.h>
#include <string>

#ifndef WIN32
std::string ShellEscape(const std::string& arg)
{
    std::string escaped = arg;
    ReplaceAll(escaped, "'", "'\"'\"'");
    return "'" + escaped + "'";
}
#endif

#if HAVE_SYSTEM
void runCommand(const std::string& strCommand)
{
    if (strCommand.empty()) return;
#ifndef WIN32
    int nErr = ::system(strCommand.c_str());
#else
    int nErr = ::_wsystem(std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t>().from_bytes(strCommand).c_str());
#endif
    if (nErr)
        LogPrintf("runCommand error: system(%s) returned %d\n", strCommand, nErr);
}
#endif
