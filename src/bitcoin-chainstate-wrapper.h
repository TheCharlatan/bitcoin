#ifndef _BITCOIN_CHAINSTATE_WRAPPER
#define _BITCOIN_CHAINSTATE_WRAPPER

#ifdef __cplusplus
extern "C" {
#endif

void* c_scheduler_new();
void* c_chainstate_manager_create(const char* data_dir);
int c_chainstate_manager_validate_block(void* chainman_, const char* raw_block);
int c_chainstate_manager_delete(void* chainman_, void* scheduler_);

#ifdef __cplusplus
}
#endif

#endif // _BITCOIN_CHAINSTATE_WRAPPER
