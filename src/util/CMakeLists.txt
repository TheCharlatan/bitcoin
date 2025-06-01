# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(bitcoin_util STATIC EXCLUDE_FROM_ALL
  asmap.cpp
  batchpriority.cpp
  bip32.cpp
  bytevectorhash.cpp
  exec.cpp
  exception.cpp
  sock.cpp
  string.cpp
  thread.cpp
  threadinterrupt.cpp
)

target_link_libraries(bitcoin_util
  PRIVATE
    core_interface
    bitcoin_clientversion
    bitcoin_crypto
    bitcoin_kernel_util
    $<$<PLATFORM_ID:Windows>:ws2_32>
)
