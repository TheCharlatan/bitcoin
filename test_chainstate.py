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

def flush_error_cb(_, debug_message):
    print(cw.string_cast(debug_message))

def fatal_error_cb(_, debug_message, user_message):
    print(cw.string_cast(debug_message))
    print(cw.string_cast(user_message))

log_callback = cw.LogCallback(log_printf)
cw.c_set_logging_callback_and_start_logging(log_callback)

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

viq_callbacks = cw.struct_TaskRunnerCallbacks(
    user_data=None,
    add_to_process_queue=cw.TRInsert(dummy_task_runner_insert_cb),
    empty_queue=cw.TRFlush(dummy_task_runner_flush_cb),
    callbacks_pending=cw.TRSize(dummy_task_runner_size_cb),
)

context = cw.c_context_new(kn_callbacks, viq_callbacks)

def block_checked_cb(data, block, state):
    pass

vi_cbs = cw.struct_ValidationInterfaceCallbacks(
    user_data=None,
    block_checked=cw.VIBlockChecked(block_checked_cb),
)

validation_interface = cw.c_create_validation_interface(vi_cbs)
cw.c_register_validation_interface(context, validation_interface)

chainman = cw.c_chainstate_manager_create(cw.char_pointer_cast("/home/drgrid/.bitcoin/signet"), context)
cw.c_chainstate_manager_validate_block(chainman, context, cw.char_pointer_cast("deadbeef"))

