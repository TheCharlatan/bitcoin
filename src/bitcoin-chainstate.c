#include "stdio.h"
#include "bitcoin-chainstate-wrapper.h"

int main(int argc, char* argv[]) {
    struct CScheduler* scheduler = c_scheduler_new();
    struct ChainstateManager* chainman = c_chainstate_manager_create("/home/drgrid/.bitcoin");
    c_chainstate_manager_validate_block(chainman, "deadbeef");
    c_chainstate_manager_delete(chainman, scheduler);
}