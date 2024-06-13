#include "assert.h"
#include "bitcoinkernel.h"
#include "stdbool.h"
#include "stddef.h"
#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "unistd.h"

void log_printf(const char* message)
{
    printf("kernel: %s", message);
}

void check_error(kernel_error* err)
{
    switch (err->code) {
    case kernel_ERR_OK:
        return;
    default:
        fprintf(stderr, "kernel: Error: %s\n", err->message);
    }
    exit(1);
}

void KNBlockTipCB(void* _, C_SynchronizationState state, void* _index)
{
    log_printf("Block tip changed\n");
}

void KNHeaderTipCB(void* _, C_SynchronizationState state, int64_t height, int64_t timestamp, bool presync)
{
    char buffer[100];
    snprintf(buffer, 100, "Received new header: %ld, %ld. Ready for presync: %d\n", height, timestamp, presync);
    log_printf(buffer);
}

void KNProgressCB(void* _, const char* title, int progress_percent, bool resume_possible)
{
    char buffer[200];
    if (title == NULL) {
        snprintf(buffer, 200, "Made progress: %d, resume: %d\n", progress_percent, resume_possible);
    } else {
        snprintf(buffer, 200, "%s, made progress: %d, resume: %d\n", title, progress_percent, resume_possible);
    }
    log_printf(buffer);
}

void KNWarningCB(void* _, const char* warning)
{
    log_printf(warning);
}

void KNFlushErrorCB(void* _, const char* message)
{
    log_printf(message);
}

void KNFatalErrorCB(void* _, const char* message)
{
    log_printf(message);
}

void TRInsertCB(void* _, C_ValidationEvent* event)
{
    c_execute_event(event);
    printf("C runtime: Processed event!\n");
}

void TRFlushCB(void* _) {}

size_t TRSizeCB(void* _) { return 0; }

void BlockCheckedCB(void* _, const C_BlockPointer* block, C_BlockValidationState stateIn)
{
    kernel_error err;
    err.code = kernel_ERR_OK;

    size_t number_of_transactions = c_number_of_transactions_in_block(block, &err);
    check_error(&err);
    const C_TransactionRef* transaction_ref = c_get_transaction_by_index(block, &err, 0);
    check_error(&err);
    uint32_t locktime = c_transaction_ref_get_locktime(transaction_ref, &err);
    check_error(&err);
    size_t number_of_outputs = c_get_transaction_output_size(transaction_ref, &err);
    check_error(&err);
    const C_TransactionOut* transaction_out = c_get_output_by_index(transaction_ref, &err, 0);
    check_error(&err);
    fprintf(stdout, "tx locktime: %u, number of outputs: %lu\n", locktime, number_of_outputs);
    ByteArray* script_pubkey = NULL;
    c_get_script_pubkey(transaction_out, &script_pubkey, &err);
    check_error(&err);
    fprintf(stdout, "script pubkey size: %lu\n", script_pubkey->len);
    c_byte_array_destroy(script_pubkey);
}

void scan_txs(C_ChainstateManager* chainman, kernel_error* err)
{
    C_BlockIndex* block_index = c_get_genesis_block_index(chainman, err);
    check_error(err);
    // Skip the first block, since there is nothing to scan
    block_index = c_get_next_block_index(chainman, err, block_index);
    check_error(err);
    C_BlockPointer* block_data = NULL;
    C_BlockUndo* undo_data = NULL;

    while (block_index != NULL) {
        c_read_block_data(chainman, block_index, err, &block_data, true, &undo_data, true);
        check_error(err);

        int height = c_get_block_height(block_index, err);
        check_error(err);

        size_t number_txundo_in_block_undo = c_number_of_txundo_in_block_undo(undo_data, err);
        check_error(err);
        size_t number_of_transactions_in_block = c_number_of_transactions_in_block(block_data, err);
        check_error(err);

        int total_inputs = 0;

        for (int i = 0; i < number_of_transactions_in_block; i++) {
            const C_TransactionRef* transaction_ref = c_get_transaction_by_index(block_data, err, i);
            check_error(err);
            size_t n_inputs = c_get_transaction_input_size(transaction_ref, err);
            check_error(err);
            const C_TransactionIn* transaction_input = c_get_input_by_index(transaction_ref, err, n_inputs - 1);
            check_error(err);
            TxInWitness* witness = NULL;
            c_get_tx_in_witness(transaction_input, &witness, err);
            check_error(err);
            c_tx_in_witness_destroy(witness, err);
            check_error(err);
            total_inputs += n_inputs;
        }

        block_index = c_get_next_block_index(chainman, err, block_index);
        check_error(err);
    }
}

int main(int argc, char* argv[])
{
    log_printf("Creating logger\n");

    kernel_error err;
    err.code = kernel_ERR_OK;

    c_set_logging_callback_and_start_logging(log_printf, &err);
    check_error(&err);

    log_printf("Creating context options\n");
    C_ContextOptions* context_opts = c_context_opt_create();
    log_printf("Options created\n");

    KernelNotificationInterfaceCallbacks* kn_cbs = malloc(sizeof(KernelNotificationInterfaceCallbacks));
    kn_cbs->user_data = NULL;
    kn_cbs->block_tip = KNBlockTipCB;
    kn_cbs->header_tip = KNHeaderTipCB;
    kn_cbs->progress = KNProgressCB;
    kn_cbs->warning = KNWarningCB;
    kn_cbs->flush_error = KNFlushErrorCB;
    kn_cbs->fatal_error = KNFatalErrorCB;

    log_printf("Setting kernel notification interface callbacks.\n");
    if (kn_cbs->progress == NULL) {
        log_printf("Lol, none of this is gonna work\n");
        return -1;
    }

    c_context_set_opt(context_opts, KernelNotificationInterfaceCallbacksOption, kn_cbs, &err);
    check_error(&err);
    free(kn_cbs);

    TaskRunnerCallbacks* tr_cbs = malloc(sizeof(TaskRunnerCallbacks));
    tr_cbs->user_data = NULL;
    tr_cbs->insert = TRInsertCB;
    tr_cbs->flush = TRFlushCB;
    tr_cbs->size = TRSizeCB;

    log_printf("Setting task runner callbacks.\n");

    c_context_set_opt(context_opts, TaskRunnerCallbacksOption, tr_cbs, &err);
    check_error(&err);
    free(tr_cbs);

    C_Chain chain = kernel_REGTEST;
    c_context_set_opt(context_opts, ChainTypeOption, &chain, &err);

    log_printf("Creating context.\n");

    C_Context* context = NULL;
    c_context_create(context_opts, &context, &err);
    check_error(&err);
    log_printf("Bitcoin context created\n");

    ValidationInterfaceCallbacks* vi_cbs = malloc(sizeof(ValidationInterfaceCallbacks));
    vi_cbs->user_data = NULL;
    vi_cbs->block_checked = BlockCheckedCB;
    C_ValidationInterface* validation_interface = NULL;
    c_validation_interface_create(*vi_cbs, &validation_interface);
    free(vi_cbs);
    c_validation_interface_register(context, validation_interface, &err);
    check_error(&err);

    log_printf("Creating chainstate manager\n");
    C_ChainstateManager* chainman = NULL;
    c_chainstate_manager_create("/home/drgrid/.bitcoin/regtest", false, context, &chainman, &err);
    check_error(&err);
    log_printf("Bitcoin chainstate manager created\n");

    if (chainman == NULL) {
        log_printf("Failed to create chainstate manager\n");
        return -1;
    }
    log_printf("created chainstate manager\n");

    c_import_blocks(chainman, &err);
    check_error(&err);
    log_printf("Imported blocks\n");

    scan_txs(chainman, &err);

    C_CoinsViewCursor* cursor = NULL;
    c_chainstate_coins_cursor_create(chainman, &cursor, &err);
    check_error(&err);
    while (c_coins_cursor_valid(cursor, &err)) {
        C_OutPoint out = c_coins_cursor_get_key(cursor, &err);
        check_error(&err);
        c_coins_cursor_next(cursor, &err);
    }
    c_coins_cursor_destroy(cursor, &err);
    check_error(&err);

    log_printf("Parsing invald Bitcoin block\n");
    C_Block* block = NULL;
    c_block_from_str(
        "deadbeef",
        &block,
        &err);
    c_block_destroy(block);
    log_printf("Parsed invalid Bitcoin block\n");

    log_printf("Validating mainnet block 1\n");
    c_block_from_str(
        "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000",
        &block,
        &err);
    c_chainstate_manager_validate_block(chainman, block, &err);
    check_error(&err);
    c_block_destroy(block);
    log_printf("Validated invalid Bitcoin block\n");

    log_printf("Validating signet block 0\n");
    c_block_from_str(
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a008f4d5fae77031e8ad222030101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000",
        &block,
        &err);
    c_chainstate_manager_validate_block(chainman, block, &err);
    check_error(&err);
    c_block_destroy(block);
    log_printf("Validated valid, but duplicate Bitcoin block\n");

    log_printf("Freeing chainstate resources\n");
    c_chainstate_manager_destroy(chainman, context, &err);
    check_error(&err);
    log_printf("Freed chainstate resources\n");

    c_validation_interface_unregister(context, validation_interface, &err);
    check_error(&err);
    c_validation_interface_destroy(validation_interface, &err);
    check_error(&err);

    log_printf("Freeing context resources\n");
    c_context_destroy(context, &err);
    check_error(&err);
    log_printf("Freed context resources\n");

    return 0;
}
