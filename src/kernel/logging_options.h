// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_LOGGING_OPTIONS_H
#define BITCOIN_KERNEL_LOGGING_OPTIONS_H

/**
 * Options controlling the format of log messages.
 */
typedef struct {
    bool log_timestamps;               //!< Prepend a timestamp to log messages.
    bool log_time_micros;              //!< Log timestamps in microsecond precision.
    bool log_threadnames;              //!< Prepend the name of the thread to log messages.
    bool log_sourcelocations;          //!< Prepend the source location to log messages.
    bool always_print_category_levels; //!< Prepend the log category and level to log messages.
} kernel_LoggingOptions;

#endif // BITCOIN_KERNEL_LOGGING_OPTIONS_H
