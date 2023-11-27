// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_TASK_QUEUE_INTERFACE_H
#define BITCOIN_UTIL_TASK_QUEUE_INTERFACE_H

#include <cstddef>
#include <functional>

namespace util {

class TaskQueueInterface
{
public:
    virtual ~TaskQueueInterface() {}

    /**
     * This is called for each subscriber on each validation interface event.
     * The callback can either be queued for later/asynchronous/threaded
     * processing, or be executed immediately for synchronous processing.
     * Synchronous processing will block validation.
     */
    virtual void AddToProcessQueue(std::function<void()> func) = 0;

    /**
     * This is called to force the processing of all queued events.
     */
    virtual void EmptyQueue() = 0;

    /**
     * Returns the number of queued events.
     */
    virtual size_t CallbacksPending() = 0;
};

} // namespace util

#endif // BITCOIN_UTIL_TASK_QUEUE_INTERFACE_H
