# This is generated with:
# clang2py src/bitcoinkernel.h -l /home/drgrid/bitcoin/src/.libs/libbitcoinkernel.so > test_wrapper.py
import test_wrapper as cw

def log_printf(msg):
    # prune the trailing newline
    print(cw.string_cast(msg)[:-1])

def block_tip_cb(_, _state, _index):
    pass

def header_tip_cb(_, _state, height, timestamp, presync):
    print(height, timestamp, presync)

def progress_cb(_, title, progress_percent, resume_possible):
    print(cw.string_cast(title), progress_percent, resume_possible)

def warning_cb(_, warning):
    print(cw.string_cast(warning))

def flush_error_cb(_, message):
    print(cw.string_cast(message))

def fatal_error_cb(_, message):
    print(cw.string_cast(message))

def check_error(error):
    if error.code == cw.kernel_ERR_OK:
        return
    if error.code == cw.kernel_ERR_INTERNAL:
        print("Internal validation error:", cw.string_cast(error.message))
        return
    print("Error using API:", cw.string_cast(error.message))
    exit(0)

log_callback = cw.LogCallback(log_printf)
kernel_error = cw.kernel_error(
    code = cw.ctypes.c_uint32(cw.kernel_ERR_OK)
)
cw.c_set_logging_callback_and_start_logging(log_callback, cw.ctypes.byref(kernel_error))
check_error(kernel_error)

kn_callbacks = cw.struct_KernelNotificationInterfaceCallbacks(
    user_data=None,
    block_tip=cw.KNBlockTip(block_tip_cb),
    header_tip=cw.KNHeaderTip(header_tip_cb),
    progress=cw.KNProgress(progress_cb),
    warning=cw.KNWarning(warning_cb),
    flush_error=cw.KNFlushError(flush_error_cb),
    fatal_error=cw.KNFatalError(fatal_error_cb),
)

def dummy_task_runner_insert_cb(_user_data, _data_pointer):
    pass

def dummy_task_runner_flush_cb(_user_data):
    pass

def dummy_task_runner_size_cb(_user_data):
    return 0

tr_callbacks = cw.struct_TaskRunnerCallbacks(
    user_data=None,
    add_to_process_queue=cw.TRInsert(dummy_task_runner_insert_cb),
    empty_queue=cw.TRFlush(dummy_task_runner_flush_cb),
    callbacks_pending=cw.TRSize(dummy_task_runner_size_cb),
)

context_options = cw.c_context_opt_create()
cw.c_context_set_opt(context_options, cw.KernelNotificationInterfaceCallbacksOption, cw.ctypes.byref(kn_callbacks), cw.ctypes.byref(kernel_error))
check_error(kernel_error)
cw.c_context_set_opt(context_options, cw.TaskRunnerCallbacksOption, cw.ctypes.byref(tr_callbacks), cw.ctypes.byref(kernel_error))
check_error(kernel_error)
cw.c_context_set_opt(context_options, cw.ChainTypeOption, cw.ctypes.byref(cw.C_Chain(cw.kernel_SIGNET)), cw.ctypes.byref(kernel_error))
check_error(kernel_error)

context = cw.ctypes.POINTER(cw.C_Context)()
cw.c_context_create(context_options, cw.ctypes.byref(context), cw.ctypes.byref(kernel_error))
check_error(kernel_error)

def block_checked_cb(data, block, state):
    print(state)

vi_cbs = cw.struct_ValidationInterfaceCallbacks(
    user_data=None,
    block_checked=cw.VIBlockChecked(block_checked_cb),
)

validation_interface = cw.ctypes.POINTER(cw.C_ValidationInterface)()
cw.c_validation_interface_create(vi_cbs, cw.ctypes.byref(validation_interface))
cw.c_validation_interface_register(context, validation_interface, kernel_error)
check_error(kernel_error)

reindex = cw.ctypes.c_bool(False)
print("creating chainman")
chainman = cw.ctypes.POINTER(cw.C_ChainstateManager)()
cw.c_chainstate_manager_create(cw.char_pointer_cast("/home/drgrid/.bitcoin/signet"), reindex, context, cw.ctypes.byref(chainman), cw.ctypes.byref(kernel_error))
check_error(kernel_error)
print("importing blocks")
cw.c_import_blocks(chainman, kernel_error)
check_error(kernel_error)
print("validating block")
block = cw.ctypes.POINTER(cw.C_Block)()
cw.c_block_from_str(cw.char_pointer_cast("deadbeef"), cw.ctypes.byref(block), kernel_error)
cw.c_block_destroy(block)
print(kernel_error)
cw.c_block_from_str(cw.char_pointer_cast("010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"), cw.ctypes.byref(block), kernel_error)
cw.c_chainstate_manager_validate_block(chainman, block, kernel_error)
check_error(kernel_error)
cw.c_block_destroy(block)
cw.c_block_from_str(cw.char_pointer_cast("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a008f4d5fae77031e8ad222030101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"), cw.ctypes.byref(block), kernel_error)
cw.c_chainstate_manager_validate_block(chainman, block, kernel_error)
check_error(kernel_error)
cw.c_block_destroy(block)

print("Freeing chainstate resources")
cw.c_chainstate_manager_destroy(chainman, context, kernel_error)
check_error(kernel_error)

print("Deleting validation interface")
cw.c_validation_interface_unregister(context, validation_interface, kernel_error)
check_error(kernel_error)
cw.c_validation_interface_destroy(validation_interface, kernel_error)
check_error(kernel_error)

print("Freeing context resources")
cw.c_context_destroy(context, kernel_error)
check_error(kernel_error)
