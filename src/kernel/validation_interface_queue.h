// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_VALIDATION_INTERFACE_QUEUE_H
#define BITCOIN_KERNEL_VALIDATION_INTERFACE_QUEUE_H

#include <cstddef>
#include <functional>

class ValidationInterfaceQueue
{
public:
    virtual ~ValidationInterfaceQueue() {}

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

#endif // BITCOIN_KERNEL_VALIDATION_INTERFACE_QUEUE_H
