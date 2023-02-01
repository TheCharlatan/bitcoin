#include "stdio.h"
#include "stddef.h"
#include "stdint.h"
#include "stdbool.h"
#include "unistd.h"
#include "bitcoinkernel.h"

void log_printf(const char* message) {
    printf("kernel: %s", message);
}

void KNBlockTipCB(void* _, enum C_SynchronizationState state, void* _index) {
    log_printf("Block tip changed\n");
}

void KNHeaderTipCB(void* _, enum C_SynchronizationState state, int64_t height, int64_t timestamp, bool presync) {
    char buffer[100];
    snprintf(buffer, 100, "Received new header: %ld, %ld. Ready for presync: %d\n", height, timestamp, presync);
    log_printf(buffer);
}

void KNProgressCB(void* _, const char* title, int progress_percent, bool resume_possible) {
    char buffer[200];
    if (title == NULL) {
        snprintf(buffer, 200, "Made progress: %d, resume: %d\n", progress_percent, resume_possible);
    } else {
        snprintf(buffer, 200, "%s, made progress: %d, resume: %d\n", title, progress_percent, resume_possible);
    }
    log_printf(buffer);
}

void KNWarningCB(void* _, const char* warning) {
    log_printf(warning);
}

void KNFlushErrorCB(void* _, const char* debug_message) {
    log_printf(debug_message);
}

void KNFatalErrorCB(void* _, const char* debug_message, const char* user_message) {
    log_printf(debug_message);
    log_printf(user_message);
}

void TRInsertCB(void* _, void* event) {
    c_execute_event(event);
    printf("C runtime: Processed event!\n");
}

void TRFlushCB(void* _){}

size_t TRSizeCB(void* _) { return 0; }

void BlockCheckedCB(void*_, void*_block, void* _stateIn) {}

int main(int argc, char* argv[]) {
    log_printf("Creating logger\n");
    c_set_logging_callback_and_start_logging(log_printf);

    struct KernelNotificationInterfaceCallbacks kn_cbs = {
        .user_data = NULL,
        .block_tip = KNBlockTipCB,
        .header_tip = KNHeaderTipCB,
        .progress = KNProgressCB,
        .warning = KNWarningCB,
        .flush_error = KNFlushErrorCB,
        .fatal_error = KNFatalErrorCB
    };

    struct TaskRunnerCallbacks tr_cbs = {
        .user_data = NULL,
        .insert = TRInsertCB,
        .flush = TRFlushCB,
        .size = TRSizeCB, 
    };

    log_printf("Creating context\n");
    void* context = c_context_new(kn_cbs, tr_cbs);
    if (context == NULL)
    {
        log_printf("Failed to create context\n");
        return -1;
    }
    log_printf("Bitcoin context created\n");

    struct ValidationInterfaceCallbacks vi_cbs = {
        .user_data = NULL,
        .block_checked = BlockCheckedCB,
    };
    void* validation_interface = c_create_validation_interface(vi_cbs);
    c_register_validation_interface(context, validation_interface);

    log_printf("Creating chainstate manager\n");
    void* chainman = c_chainstate_manager_create("/home/drgrid/.bitcoin/signet", context);
    log_printf("Bitcoin chainstate manager created\n");

    if (chainman == NULL) {
        log_printf("Failed to create chainstate manager\n");
        return -1;
    }
    log_printf("created chainstate manager\n");

    void* cursor = c_chainstate_coins_cursor(chainman);
    c_coins_cursor_delete(cursor);

    log_printf("Validating invald Bitcoin block\n");
    c_chainstate_manager_validate_block(chainman, context, "deadbeef");
    log_printf("Validated an invalid Bitcoin block, validating another invalid block.\n");
    c_chainstate_manager_validate_block(chainman, context, "deadbeef");
    log_printf("Validated invald Bitcoin block\n");

    log_printf("Freeing chainstate resources\n");
    c_chainstate_manager_delete(chainman, context);
    log_printf("Freed chainstate resources\n");

    c_unregister_validation_interface(context, validation_interface);
    c_destroy_validation_interface(validation_interface);

    log_printf("Freeing context resources\n");
    c_context_delete(context);
    log_printf("Freed context resources\n");

    return 0;
}
