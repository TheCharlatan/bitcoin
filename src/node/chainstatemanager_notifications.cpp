// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/chainstatemanager_notifications.h>

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <common/args.h>
#include <common/system.h>
#include <kernel/chainstatemanager_opts.h>
#include <node/interface_ui.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/translation.h>
#include <warnings.h>

#include <cstdint>
#include <functional>
#include <string>
#include <thread>

using kernel::ChainstateManagerNotificationCallbacks;

class CBlockIndex;

namespace node {

static void AlertNotify(const std::string& strMessage)
{
    uiInterface.NotifyAlertChanged();
#if HAVE_SYSTEM
    std::string strCmd = gArgs.GetArg("-alertnotify", "");
    if (strCmd.empty()) return;

    // Alert text should be plain ascii coming from a trusted source, but to
    // be safe we first strip anything not in safeChars, then add single quotes around
    // the whole string before passing it to the shell:
    std::string singleQuote("'");
    std::string safeStatus = SanitizeString(strMessage);
    safeStatus = singleQuote+safeStatus+singleQuote;
    ReplaceAll(strCmd, "%s", safeStatus);

    std::thread t(runCommand, strCmd);
    t.detach(); // thread runs free
#endif
}

static void DoWarning(const bilingual_str& warning)
{
    static bool fWarned = false;
    SetMiscWarning(warning);
    if (!fWarned) {
        AlertNotify(warning.original);
        fWarned = true;
    }
}

ChainstateManagerNotificationCallbacks DefaultChainstateManagerNotifications()
{
    return ChainstateManagerNotificationCallbacks{
        .notify_block_tip = [](SynchronizationState state, CBlockIndex* index) { uiInterface.NotifyBlockTip(state, index); },
        .notify_header_tip = [](SynchronizationState state, int64_t height, int64_t timestamp, bool presync) { uiInterface.NotifyHeaderTip(state, height, timestamp, presync); },
        .show_progress = [](const std::string& title, int nProgress, bool resume_possible) { uiInterface.ShowProgress(title, nProgress, resume_possible); },
        .do_warning = [](const bilingual_str& warning) { DoWarning(warning); },
    };
}
} // namespace node
