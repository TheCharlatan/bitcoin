#include "stdio.h"
#include "bitcoin-chainstate-wrapper.h"

int main(int argc, char* argv[]) {
    // TODO: Using the scheduler here results in an uncaught exception
    // void* scheduler = c_scheduler_new();
    printf("Bitcoin scheduler launched\n");
    void* chainman = c_chainstate_manager_create("/home/drgrid/.bitcoin");
    printf("Bitcoin chainstate manager created\n");
    c_chainstate_manager_validate_block(chainman, "deadbeef");
    printf("Validating invald Bitcoin block\n");
    c_chainstate_manager_validate_block(chainman, "deadbeef");
    printf("Validating invald Bitcoin block\n");

    // TODO: We declare a dummy scheduler here, so we can do the cleanup
    void* dummy_scheduler = c_scheduler_new();
    c_chainstate_manager_delete(chainman, dummy_scheduler);
    printf("Freeing chainstate resources\n");
}
