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
} C_ChainstateInfo;

typedef struct {
    const char* hash;
    unsigned int n;
} C_OutPoint;

typedef struct {
    long int value;
    const char* script_pubkey;
} C_TxOut;

typedef struct {
    C_TxOut out;
    unsigned int is_coinbase;
    unsigned int confirmation_height;
} C_Coin;

void
c_set_logging_callback_and_start_logging(LogCallback callback);
void* c_scheduler_new();
C_ChainstateInfo c_get_chainstate_info(void* chainman_);
void* c_chainstate_manager_create(const char* data_dir, void* scheduler_);
int c_chainstate_manager_validate_block(void* chainman_, const char* raw_block);
int c_chainstate_manager_delete(void* chainman_, void* scheduler_);

void* c_chainstate_coins_cursor(void* chainman_);
void c_coins_cursor_next(void* cursor_);
C_OutPoint c_coins_cursor_get_key(void* cursor_);
C_Coin c_coins_cursor_get_value(void* cursor_);

#ifdef __cplusplus
}
#endif

#endif // _BITCOIN_CHAINSTATE_WRAPPER
