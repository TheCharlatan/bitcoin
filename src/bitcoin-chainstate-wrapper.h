#ifndef _BITCOIN_CHAINSTATE_WRAPPER
#define _BITCOIN_CHAINSTATE_WRAPPER

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ChainstateManager ChainstateManager;
typedef struct CScheduler CScheduler;

CScheduler* c_scheduler_new();
ChainstateManager* c_chainstate_manager_create(const char* data_dir);
void c_chainstate_manager_validate_block(ChainstateManager* chainman, const char* raw_block);
void c_chainstate_manager_delete(ChainstateManager* chainman, CScheduler* scheduler);

#ifdef __cplusplus
}
#endif

#endif // _BITCOIN_CHAINSTATE_WRAPPER
