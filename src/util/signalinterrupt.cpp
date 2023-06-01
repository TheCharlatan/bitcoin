// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/signalinterrupt.h>

#include <ios>

namespace util {
#ifndef WIN32
SignalInterrupt::SignalInterrupt() : m_flag{false}
{
    std::optional<TokenPipe> pipe = TokenPipe::Make();
    if (!pipe) throw std::ios_base::failure("Could not create TokenPipe");
    m_pipe_r = pipe->TakeReadEnd();
    m_pipe_w = pipe->TakeWriteEnd();
}

SignalInterrupt::operator bool() const
{
    return m_flag.load(std::memory_order_acquire);
}

void SignalInterrupt::reset()
{
    // Cancel existing shutdown by waiting for it, this will reset condition flags and remove
    // the shutdown token from the pipe.
    if (*this) sleep();
    m_flag.store(false, std::memory_order_release);
}

void SignalInterrupt::operator()()
{
    // This must be reentrant and safe for calling in a signal handler, so using a condition variable is not safe.
    // Make sure that the token is only written once even if multiple threads call this concurrently or in
    // case of a reentrant signal.
    if (!m_flag.exchange(true)) {
        // Write an arbitrary byte to the write end of the shutdown pipe.
        int res = m_pipe_w.TokenWrite('x');
        if (res != 0) {
            throw std::ios_base::failure("Could not write interrupt token");
        }
    }
}

void SignalInterrupt::sleep()
{
    int res = m_pipe_r.TokenRead();
    if (res != 'x') {
        throw std::ios_base::failure("Did not read expected interrupt token");
    }
}
#endif
} // namespace util
