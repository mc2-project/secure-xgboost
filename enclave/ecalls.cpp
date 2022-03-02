#include <xgboost/c_api.h>
#include <xgboost/base.h>
#include <xgboost/logging.h>
#include <sys/mount.h>
#include <rabit/c_api.h>

#include "xgboost_t.h"
#include "src/common/common.h"
#include <enclave/attestation.h>
#include "enclave_context.h"

#include <string>

void copy_arr_to_enclave(char* dst[], size_t num, char* src[], size_t lengths[]) {
  for (int i = 0; i < num; i++) {
    size_t nlen = lengths[i];
    check_host_buffer(src[i], nlen);
    dst[i] = strndup(src[i], nlen);
    dst[i][nlen] = '\0';
  }
}

void free_array(char* arr[], size_t len) {
  for (int i = 0; i < len; i++) {
    free(arr[i]);
  }
}

void enclave_init(char** usernames, size_t* username_lengths, size_t num_clients, int log_verbosity) {
  std::vector<std::pair<std::string, std::string> > args;
  args.emplace_back("verbosity", std::to_string(log_verbosity));
  xgboost::ConsoleLogger::Configure(args);

  LOG(DEBUG) << "Ecall: init";
  oe_result_t result;
  if ((result = oe_load_module_host_resolver()) != OE_OK) {
    LOG(FATAL) << "oe_load_module_host_resolver failed with " << oe_result_str(result);
  }
  if ((result = oe_load_module_host_socket_interface()) != OE_OK) {
    LOG(FATAL) << "oe_load_module_host_socket_interface failed with " << oe_result_str(result);
  }
  if ((result = oe_load_module_host_file_system()) != OE_OK) {
    LOG(FATAL) << "oe_load_module_host_file_system failed with " << oe_result_str(result);
  }
  /* Mount the host file system on the root directory. */
  if (mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) != 0) {
    LOG(FATAL) << "Unable to mount host file system on the root directory";
  }
  char* usernames_cpy[num_clients];
  copy_arr_to_enclave(usernames_cpy, num_clients, usernames, username_lengths);

  EnclaveContext::getInstance().set_usernames(usernames_cpy, num_clients);

  free_array(usernames_cpy, num_clients);
}

int enclave_XGDMatrixCreateFromFile(const char *fname, char* username, int silent, DMatrixHandle *out) {
  LOG(DEBUG) << "Ecall: XGDMatrixCreateFromFile";
  return XGDMatrixCreateFromFile(fname, username, silent, out);
}

int enclave_XGDMatrixCreateFromEncryptedFile(const char *fnames[], size_t fname_lengths[], char* usernames[], size_t username_lengths[], bst_ulong num_files, int silent, DMatrixHandle *out) {
  LOG(DEBUG) << "Ecall: XGDMatrixCreateFromEncryptedFile";
  char* fnames_cpy[num_files];
  char* usernames_cpy[num_files];

  copy_arr_to_enclave(fnames_cpy, num_files, (char**)fnames, fname_lengths);
  copy_arr_to_enclave(usernames_cpy, num_files, usernames, username_lengths);

  int ret = XGDMatrixCreateFromEncryptedFile((const char**) fnames_cpy, usernames_cpy, num_files, silent, out);

  free_array(fnames_cpy, num_files);
  free_array(usernames_cpy, num_files);
  return ret;
}

int enclave_XGBoosterCreate(DMatrixHandle dmat_handles[], size_t handle_lengths[], bst_ulong len, BoosterHandle* out) {
  LOG(DEBUG) << "Ecall: XGBoosterCreate";
  // Validate buffers and copy to enclave memory
  DMatrixHandle dmats[len];

  copy_arr_to_enclave(dmats, len, dmat_handles, handle_lengths);

  int ret = XGBoosterCreate(dmats, len, out);

  free_array(dmats, len);
  return ret;
}

int enclave_XGBoosterSetParam(BoosterHandle handle, const char* name, const char* value) {
  LOG(DEBUG) << "Ecall: XGBoosterSetParam";

  int ret = XGBoosterSetParam(handle, name, value);

  return ret;
}

int enclave_XGBoosterUpdateOneIter(BoosterHandle handle, int iter, DMatrixHandle dtrain)  {
  LOG(DEBUG) << "Ecall: XGBoosterUpdateOneIter";

  int ret = XGBoosterUpdateOneIter(handle, iter, dtrain);

  return ret;
}

int enclave_XGBoosterBoostOneIter(BoosterHandle handle, DMatrixHandle dtrain, bst_float *grad, bst_float *hess, xgboost::bst_ulong len) {
  LOG(DEBUG) << "Ecall: XGBoosterBoostOneIter";
  return XGBoosterBoostOneIter(handle, dtrain, grad, hess, len);
}

int enclave_XGBoosterEvalOneIter(BoosterHandle handle, int iter, DMatrixHandle dmat_handles[], size_t handle_lengths[], const char* evnames[], size_t names_lengths[], bst_ulong len, char** out_str) {
  LOG(DEBUG) << "Ecall: XGBoosterEvalOneIter";

  // Validate buffers and copy to enclave memory
  char* dmats[len];
  char* eval_names[len];

  copy_arr_to_enclave(dmats, len, dmat_handles, handle_lengths);
  copy_arr_to_enclave(eval_names, len, (char**)evnames, names_lengths);

  int ret = XGBoosterEvalOneIter(handle, iter, dmats, (const char**) eval_names, len, (const char**) out_str);

  free_array(dmats, len);
  free_array(eval_names, len);
  return ret;
}

int enclave_XGBoosterLoadModel(BoosterHandle handle, const char *fname) {
  LOG(DEBUG) << "Ecall: XGBoosterLoadModel";

  int ret = XGBoosterLoadModel(handle, fname);

  return ret;
}

int enclave_XGBoosterSaveModel(BoosterHandle handle, const char *fname) {
  LOG(DEBUG) << "Ecall: XGBoosterSaveModel";

  int ret = XGBoosterSaveModel(handle, fname);

  return ret;
}

int enclave_XGBoosterDumpModel(BoosterHandle handle,
                       const char* fmap,
                       int with_stats,
                       xgboost::bst_ulong* len,
                       char*** out_models) {
  LOG(DEBUG) << "Ecall: XGBoosterDumpModel";
  return XGBoosterDumpModel(handle, fmap, with_stats, len, (const char***) out_models);
}

int enclave_XGBoosterDumpModelEx(BoosterHandle handle,
                                 const char* fmap,
                                 int with_stats,
                                 const char* format,
                                 xgboost::bst_ulong* len,
                                 char*** out_models,
                                 unsigned char* user_sym_key) {
    LOG(DEBUG) << "Ecall: XGBoosterDumpModelEx";

    int ret = XGBoosterDumpModelEx(handle, fmap, with_stats, format, len, (const char***) out_models, user_sym_key);

    return ret;
}

int enclave_XGBoosterDumpModelWithFeatures(BoosterHandle handle,
                                   unsigned int fnum,
                                   const char** fname,
                                   size_t fname_lengths[],
                                   const char** ftype,
                                   size_t ftype_lengths[],
                                   int with_stats,
                                   xgboost::bst_ulong* len,
                                   char*** out_models) {
  LOG(DEBUG) << "Ecall: XGBoosterDumpModelWithFeatures";

  // Validate buffers and copy to enclave memory
  char* fname_cpy[fnum];
  char* ftype_cpy[fnum];

  copy_arr_to_enclave(fname_cpy, fnum, (char**)fname, fname_lengths);
  copy_arr_to_enclave(ftype_cpy, fnum, (char**)ftype, ftype_lengths);

  int ret = XGBoosterDumpModelWithFeatures(handle, (int) fnum, (const char**) fname_cpy, (const char**) ftype_cpy, with_stats, len, (const char***) out_models);

  free_array(fname_cpy, fnum);
  free_array(ftype_cpy, fnum);
  return ret;
}

int enclave_XGBoosterDumpModelExWithFeatures(BoosterHandle handle,
                                             unsigned int fnum,
                                             const char** fname,
                                             size_t fname_lengths[],
                                             const char** ftype,
                                             size_t ftype_lengths[],
                                             int with_stats,
                                             const char *format,
                                             xgboost::bst_ulong* len,
                                             char*** out_models,
                                             unsigned char* user_sym_key) {
    LOG(DEBUG) << "Ecall: XGBoosterDumpModelExWithFeatures";

    // Validate buffers and copy to enclave memory
    char* fname_cpy[fnum];
    char* ftype_cpy[fnum];
    
    copy_arr_to_enclave(fname_cpy, fnum, (char**)fname, fname_lengths);
    copy_arr_to_enclave(ftype_cpy, fnum, (char**)ftype, ftype_lengths);
    
    int ret = XGBoosterDumpModelExWithFeatures(handle, (int) fnum, (const char**) fname_cpy, (const char**) ftype_cpy, with_stats, format, len, (const char***) out_models);
 
    free_array(fname_cpy, fnum);
    free_array(ftype_cpy, fnum);
    return ret;
}

int enclave_XGBoosterGetModelRaw(BoosterHandle handle, xgboost::bst_ulong *out_len, char **out_dptr) {
  LOG(DEBUG) << "Ecall: XGBoosterGetModelRaw";

  int ret = XGBoosterGetModelRaw(handle, out_len, (const char**)out_dptr);

  return ret;
}

int enclave_XGBoosterLoadModelFromBuffer(BoosterHandle handle, const void* buf, xgboost::bst_ulong len) {
    LOG(DEBUG) << "Ecall: XGBoosterLoadModelFromBuffer";

    int ret = XGBoosterLoadModelFromBuffer(handle, buf, len);

    return ret;
}


int enclave_XGBoosterPredict(BoosterHandle handle, DMatrixHandle dmat, int option_mask, unsigned ntree_limit, int training, bst_ulong *len, uint8_t **out_result) {
  LOG(DEBUG) << "Ecall: XGBoosterPredict";

  int ret = XGBoosterPredict(handle, dmat, option_mask, ntree_limit, training, len, out_result);

  return ret;
}

int enclave_XGDMatrixGetFloatInfo(const DMatrixHandle handle, const char* field, bst_ulong *out_len, bst_float **out_dptr) {
  LOG(DEBUG) << "Ecall: XGDMatrixGetFloatInfo";
  return XGDMatrixGetFloatInfo(handle, field, out_len, (const bst_float**) out_dptr);
}

int enclave_XGDMatrixGetUintInfo(const DMatrixHandle handle, const char* field, bst_ulong *out_len, unsigned **out_dptr) {
  LOG(DEBUG) << "Ecall: XGDMatrixGetFloatInfo";
  return XGDMatrixGetUIntInfo(handle, field, out_len, (const unsigned**) out_dptr);
}

int enclave_XGDMatrixSetFloatInfo(DMatrixHandle handle, const char* field, const bst_float* info, bst_ulong len) {
  LOG(DEBUG) << "Ecall: XGDMatrixSetFloatInfo";
  return XGDMatrixSetFloatInfo(handle, field, info, len);
}

int enclave_XGDMatrixSetUIntInfo(DMatrixHandle handle, const char* field, const unsigned* info, bst_ulong len) {
  LOG(DEBUG) << "Ecall: XGDMatrixSetUIntInfo";
  return XGDMatrixSetUIntInfo(handle, field, info, len);
}

int enclave_XGDMatrixNumRow(const DMatrixHandle handle, bst_ulong *out) {
  LOG(DEBUG) << "Ecall: XGDMatrixNumRow";

  int ret = XGDMatrixNumRow(handle, out);

  return ret;
}

int enclave_XGDMatrixNumCol(const DMatrixHandle handle, bst_ulong *out) {
  LOG(DEBUG) << "Ecall: XGDMatrixNumCol";

  int ret = XGDMatrixNumCol(handle, out);

  return ret;
}

int enclave_XGBoosterGetAttr(BoosterHandle handle, const char* key, char** out, int* success) {
  LOG(DEBUG) << "Ecall: XGBoosterGetAttr";
  return XGBoosterGetAttr(handle, key, (const char** )out, success);
}

int enclave_XGBoosterGetAttrNames(BoosterHandle handle, bst_ulong* out_len, char*** out) {
  LOG(DEBUG) << "Ecall: XGBoosterGetAttrNames";
  return XGBoosterGetAttrNames(handle, out_len, (const char***) out);
}

int enclave_XGDMatrixFree(DMatrixHandle handle) {
  LOG(DEBUG) << "Ecall: XGDMatrixFree";
  return XGDMatrixFree(handle);
}

int enclave_XGBoosterFree(BoosterHandle handle) {
  LOG(DEBUG) << "Ecall: XGBoosterFree";
  return XGBoosterFree(handle);
}

int enclave_get_remote_report_with_pubkey_and_nonce(
        uint8_t** pem_key,
        size_t* key_size,
        uint8_t** nonce,
        size_t* nonce_size,
        char*** client_list,
        size_t* client_list_size,
        uint8_t** remote_report,
        size_t* remote_report_size) {
  LOG(DEBUG) << "Ecall: enclave_get_remote_report_with_pubkey_and_nonce";
  return get_remote_report_with_pubkey_and_nonce(pem_key, key_size, nonce, nonce_size, client_list, client_list_size, remote_report, remote_report_size);
}

int enclave_add_client_key_with_certificate(
        char * cert,
        int cert_len,
        uint8_t* data,
        size_t data_len,
        uint8_t* signature,
        size_t sig_len) {
    LOG(DEBUG) << "Ecall: add_client_key_with_certificate";
    return add_client_key_with_certificate(cert, cert_len, data, data_len, signature, sig_len);
}

int enclave_get_enclave_symm_key(char* username, uint8_t** out, size_t* out_size) {
  LOG(DEBUG) << "Ecall: get_enclave_symm_key";
  return get_enclave_symm_key(username, out, out_size);
}

void enclave_RabitInit(int argc, char **argv, size_t arg_lengths[]) {
  LOG(DEBUG) << "Ecall: RabitInit";

  // Validate buffers and copy to enclave memory
  char* args[argc];
  for (int i = 0; i < argc; i++) {
    char* arg = argv[i];
    size_t len = arg_lengths[i];
    check_host_buffer(arg, len);
    args[i] = strndup(arg, len);
    args[i][len] = '\0';
  }
  RabitInit(argc, args);
  for (int i = 0; i < argc; i++) {
    free(args[i]);
  }
}

void enclave_RabitFinalize() {
  LOG(DEBUG) << "Ecall: RabitFinalize";
  RabitFinalize();
}

int enclave_RabitGetRank() {
  LOG(DEBUG) << "Ecall: RabitGetRank";
  return RabitGetRank();
}

int enclave_RabitIsDistributed() {
  LOG(DEBUG) << "Ecall: RabitIsDistributed";
  return RabitIsDistributed();
}
