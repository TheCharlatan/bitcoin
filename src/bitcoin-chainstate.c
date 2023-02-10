#include "stdio.h"
#include "unistd.h"
#include "bitcoin-chainstate-wrapper.h"

int main(int argc, char* argv[]) {
    // TODO: Using the scheduler here results in an uncaught exception
    printf("Creating bitcoin scheduler\n");
    void* scheduler = c_scheduler_new();
    printf("Bitcoin scheduler launched\n");
    printf("creating chainstate manager");
    void* chainman = c_chainstate_manager_create("/home/drgrid/.bitcoin");
    printf("Bitcoin chainstate manager created\n");
    c_chainstate_manager_validate_block(chainman, "deadbeef");
    printf("Validating invalid Bitcoin block\n");
    c_chainstate_manager_validate_block(chainman, "deadbeef");
    printf("Validating invalid Bitcoin block\n");

    c_chainstate_manager_delete(chainman, scheduler);
    printf("Freeing chainstate resources\n");
}
