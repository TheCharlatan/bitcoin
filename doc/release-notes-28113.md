RPC Wallet
----------

- The `signrawtransactionwithkey`, `signrawtransactionwithwallet`,
  `walletprocesspsbt` and `descriptorprocesspsbt` calls now return more
  specific RPC_INVALID_PARAMETER instead of RPC_MISC_ERROR if their
  sighashtype argument is malformed.
