// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_SIGNALINTERRUPT_H
#define BITCOIN_UTIL_SIGNALINTERRUPT_H

#ifdef WIN32
#include <util/threadinterrupt.h>
#else
#include <util/tokenpipe.h>
#include <atomic>
#endif

namespace util {
/**
 * Helper class that allows manages an interrupt flag, and allows a thread or
 * signal to interrupt another thread.
 *
 * This class is safe to be used in a signal handler. If sending an interrupt
 * from a signal handler is not neccessary, the more lightweight \ref
 * CThreadInterrupt class can be used instead.
 */
#ifdef WIN32
using SignalInterrupt = CThreadInterrupt;
#else
/** On UNIX-like operating systems use the self-pipe trick.
 */
class SignalInterrupt
{
public:
    SignalInterrupt();
    explicit operator bool() const;
    void operator()();
    void reset();
    void sleep();

private:
    std::atomic<bool> m_flag;
    TokenPipeEnd m_pipe_r;
    TokenPipeEnd m_pipe_w;
};
} // namespace util
#endif

#endif // BITCOIN_UTIL_SIGNALINTERRUPT_H
