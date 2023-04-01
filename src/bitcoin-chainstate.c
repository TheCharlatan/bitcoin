#include "stdio.h"
#include "unistd.h"
#include "bitcoinkernel.h"

void log_printf(const char* message) {
    printf("kernel: %s", message);
}

int main(int argc, char* argv[]) {
    // TODO: Using the scheduler here results in an uncaught exception
    log_printf("Creating logger");
    c_set_logging_callback_and_start_logging(log_printf);

    log_printf("Creating bitcoin scheduler\n");
    void* scheduler = c_scheduler_new();
    if (scheduler == NULL) {
        log_printf("Failed to create scheduler\n");
        return -1;
    }
    log_printf("Bitcoin scheduler launched\n");

    log_printf("creating chainstate manager\n");

    void* chainman = c_chainstate_manager_create("/home/drgrid/.bitcoin", scheduler);
    if (chainman == NULL) {
        log_printf("Failed to create chainstate manager\n");
        return -1;
    }
    log_printf("Bitcoin chainstate manager created\n");
    c_chainstate_manager_validate_block(chainman, "deadbeef");
    log_printf("Validating invalid Bitcoin block\n");
    c_chainstate_manager_validate_block(chainman, "deadbeef");
    log_printf("Validating invalid Bitcoin block\n");

    c_chainstate_manager_delete(chainman, scheduler);
    log_printf("Freeing chainstate resources\n");

    return 0;
}
