#ifndef _BITCOIN_CHAINSTATE_WRAPPER
#define _BITCOIN_CHAINSTATE_WRAPPER

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*LogCallback)(const char* message);

typedef struct {
    const char* path;
    int reindexing;
    int snapshot_active;
    int active_height;
    int active_ibd;
} ChainstateInfo;

void set_logging_callback_and_start_logging(LogCallback callback);
void* c_scheduler_new();
ChainstateInfo get_chainstate_info(void* chainman_);
void* c_chainstate_manager_create(const char* data_dir, void* scheduler_);
int c_chainstate_manager_validate_block(void* chainman_, const char* raw_block);
int c_chainstate_manager_delete(void* chainman_, void* scheduler_);

#ifdef __cplusplus
}
#endif

#endif // _BITCOIN_CHAINSTATE_WRAPPER
