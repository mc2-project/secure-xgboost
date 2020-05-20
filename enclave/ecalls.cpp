#include <xgboost/c_api.h>
#include <xgboost/base.h>
#include <xgboost/logging.h>
#include <sys/mount.h>
#include <rabit/c_api.h>

#include "xgboost_t.h"
#include <xgboost/common/common.h>
#include <enclave/attestation.h>

#include <string>

void copy_sigs_to_enclave(uint8_t* dst[], uint8_t* src[], size_t lengths[]) {
  for (int i = 0; i < NUM_CLIENTS; i++) {
    LOG(DEBUG) << "Checking bounds of length " << lengths[i];
    check_host_buffer(src[i], lengths[i]);
    dst[i] = (uint8_t*) malloc(lengths[i] * sizeof(uint8_t));
    memcpy(dst[i], src[i], lengths[i]);
  }
}

void copy_arr_to_enclave(char* dst[], size_t num, char* src[], size_t lengths[]) {
  for (int i = 0; i < num; i++) {
    size_t nlen = lengths[i];
    check_host_buffer(src[i], nlen);
    dst[i] = strndup(src[i], nlen);
    dst[i][nlen] = '\0';
  }
}

void free_sigs(uint8_t* sigs[]) {
  for (int i = 0; i < NUM_CLIENTS; i++) {
    free(sigs[i]);
  }
}

void free_array(char* arr[], size_t len) {
  for (int i = 0; i < len; i++) {
    free(arr[i]);
  }
}

void enclave_init(int log_verbosity) {
  std::vector<std::pair<std::string, std::string> > args;
  args.emplace_back("verbosity", std::to_string(log_verbosity));
  xgboost::ConsoleLogger::Configure(args.cbegin(), args.cend());

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
}

int enclave_XGDMatrixCreateFromFile(const char *fname, int silent, DMatrixHandle *out) {
  LOG(DEBUG) << "Ecall: XGDMatrixCreateFromFile";
  return XGDMatrixCreateFromFile(fname, silent, out);
}

int enclave_XGDMatrixCreateFromEncryptedFile(const char *fnames[], size_t fname_lengths[], char* usernames[], size_t username_lengths[], bst_ulong num_files, int silent, uint8_t* nonce, size_t nonce_size, uint32_t nonce_ctr, DMatrixHandle *out, char **signers, size_t signer_lengths[], uint8_t* signatures[], size_t sig_lengths[], size_t num_sigs) {
  LOG(DEBUG) << "Ecall: XGDMatrixCreateFromEncryptedFile";
  char* fnames_cpy[num_files];
  char* usernames_cpy[num_files];
  char* signers_cpy[NUM_CLIENTS];
  uint8_t* sigs[NUM_CLIENTS];

  copy_arr_to_enclave(fnames_cpy, num_files, (char**)fnames, fname_lengths);
  copy_arr_to_enclave(usernames_cpy, num_files, usernames, username_lengths);
  copy_arr_to_enclave(signers_cpy, NUM_CLIENTS, signers, signer_lengths);
  copy_sigs_to_enclave(sigs, signatures, sig_lengths);

  int ret = XGDMatrixCreateFromEncryptedFile((const char**) fnames_cpy, usernames_cpy, num_files, silent, nonce, nonce_size, nonce_ctr, out, signers_cpy, sigs, sig_lengths);

  free_array(fnames_cpy, num_files);
  free_array(usernames_cpy, num_files);
  free_array(signers_cpy, NUM_CLIENTS);
  free_sigs(sigs);
  return ret;
}

int enclave_XGBoosterCreate(DMatrixHandle dmat_handles[], size_t handle_lengths[], bst_ulong len, uint8_t* nonce, size_t nonce_size, uint32_t nonce_ctr, BoosterHandle* out, char** signers, size_t signer_lengths[], uint8_t* signatures[], size_t sig_lengths[], size_t num_sigs) {
  LOG(DEBUG) << "Ecall: XGBoosterCreate";
  // Validate buffers and copy to enclave memory
  DMatrixHandle dmats[len];
  char* signers_cpy[NUM_CLIENTS];
  uint8_t* sigs[NUM_CLIENTS];

  copy_arr_to_enclave(dmats, len, dmat_handles, handle_lengths);
  copy_arr_to_enclave(signers_cpy, NUM_CLIENTS, signers, signer_lengths);
  copy_sigs_to_enclave(sigs, signatures, sig_lengths);

  int ret = XGBoosterCreate(dmats, len, nonce, nonce_size, nonce_ctr, out, signers_cpy, sigs, sig_lengths);

  free_array(dmats, len);
  free_array(signers_cpy, NUM_CLIENTS);
  free_sigs(sigs);
  return ret;
}

int enclave_XGBoosterSetParam(BoosterHandle handle, const char* name, const char* value, uint8_t* nonce, size_t nonce_size, uint32_t nonce_ctr, char** signers, size_t signer_lengths[], uint8_t* signatures[], size_t sig_lengths[], size_t num_sigs) {
  LOG(DEBUG) << "Ecall: XGBoosterSetParam";
  char* signers_cpy[NUM_CLIENTS];
  uint8_t* sigs[NUM_CLIENTS];

  copy_arr_to_enclave(signers_cpy, NUM_CLIENTS, signers, signer_lengths);
  copy_sigs_to_enclave(sigs, signatures, sig_lengths);

  int ret = XGBoosterSetParam(handle, name, value, nonce, nonce_size, nonce_ctr, signers_cpy, sigs, sig_lengths);

  free_array(signers_cpy, NUM_CLIENTS);
  free_sigs(sigs);
  return ret;
}

int enclave_XGBoosterUpdateOneIter(BoosterHandle handle, int iter, DMatrixHandle dtrain, uint8_t* nonce, size_t nonce_size, uint32_t nonce_ctr, char **signers, size_t signer_lengths[], uint8_t* signatures[], size_t sig_lengths[], size_t num_sigs) {
  LOG(DEBUG) << "Ecall: XGBoosterUpdateOneIter";
  char* signers_cpy[NUM_CLIENTS];
  uint8_t* sigs[NUM_CLIENTS];

  copy_arr_to_enclave(signers_cpy, NUM_CLIENTS, signers, signer_lengths);
  copy_sigs_to_enclave(sigs, signatures, sig_lengths);

  int ret = XGBoosterUpdateOneIter(handle, iter, dtrain, nonce, nonce_size, nonce_ctr, signers_cpy, sigs, sig_lengths);

  free_array(signers_cpy, NUM_CLIENTS);
  free_sigs(sigs);
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

int enclave_XGBoosterLoadModel(BoosterHandle handle, const char *fname, uint8_t* nonce, size_t nonce_size, uint32_t nonce_ctr, char **signers, size_t signer_lengths[], uint8_t* signatures[], size_t sig_lengths[], size_t num_sigs) {
  LOG(DEBUG) << "Ecall: XGBoosterLoadModel";
  char* signers_cpy[NUM_CLIENTS];
  uint8_t* sigs[NUM_CLIENTS];

  copy_arr_to_enclave(signers_cpy, NUM_CLIENTS, signers, signer_lengths);
  copy_sigs_to_enclave(sigs, signatures, sig_lengths);

  int ret = XGBoosterLoadModel(handle, fname, nonce, nonce_size, nonce_ctr, signers_cpy, sigs, sig_lengths);

  free_array(signers_cpy, NUM_CLIENTS);
  free_sigs(sigs);
  return ret;
}

int enclave_XGBoosterSaveModel(BoosterHandle handle, const char *fname, uint8_t *nonce, size_t nonce_size, uint32_t nonce_ctr, char **signers, size_t signer_lengths[], uint8_t* signatures[], size_t sig_lengths[], size_t num_sigs) {
  LOG(DEBUG) << "Ecall: XGBoosterSaveModel";
  char* signers_cpy[NUM_CLIENTS];
  uint8_t* sigs[NUM_CLIENTS];

  copy_arr_to_enclave(signers_cpy, NUM_CLIENTS, signers, signer_lengths);
  copy_sigs_to_enclave(sigs, signatures, sig_lengths);

  int ret = XGBoosterSaveModel(handle, fname, nonce, nonce_size, nonce_ctr, signers_cpy, sigs, sig_lengths);

  free_array(signers_cpy, NUM_CLIENTS);
  free_sigs(sigs);
  return ret;
}

int enclave_XGBoosterDumpModel(BoosterHandle handle,
                       const char* fmap,
                       int with_stats,
                       uint8_t* nonce,
                       size_t nonce_size,
                       uint32_t nonce_ctr,
                       xgboost::bst_ulong* len,
                       char*** out_models) {
  LOG(DEBUG) << "Ecall: XGBoosterDumpModel";
  return XGBoosterDumpModel(handle, fmap, with_stats, nonce, nonce_size, nonce_ctr, len, (const char***) out_models);
}

int enclave_XGBoosterDumpModelEx(BoosterHandle handle,
                                 const char* fmap,
                                 int with_stats,
                                 const char* format,
                                 uint8_t* nonce,
                                 size_t nonce_size,
                                 uint32_t nonce_ctr,
                                 xgboost::bst_ulong* len,
                                 char*** out_models,
                                 char **signers,
                                 size_t signer_lengths[],
                                 uint8_t* signatures[],
                                 size_t sig_lengths[],
                                 size_t num_sigs) {
    LOG(DEBUG) << "Ecall: XGBoosterDumpModelEx";
    char* signers_cpy[NUM_CLIENTS];
    uint8_t* sigs[NUM_CLIENTS];

    copy_arr_to_enclave(signers_cpy, NUM_CLIENTS, signers, signer_lengths);
    copy_sigs_to_enclave(sigs, signatures, sig_lengths);

    int ret = XGBoosterDumpModelEx(handle, fmap, with_stats, format, nonce, nonce_size, nonce_ctr, len, (const char***) out_models, signers_cpy, sigs, sig_lengths);

    free_array(signers_cpy, NUM_CLIENTS);
    free_sigs(sigs);
    return ret;
}

int enclave_XGBoosterDumpModelWithFeatures(BoosterHandle handle,
                                   unsigned int fnum,
                                   const char** fname,
                                   size_t fname_lengths[],
                                   const char** ftype,
                                   size_t ftype_lengths[],
                                   int with_stats,
                                   uint8_t* nonce,
                                   size_t nonce_size,
                                   uint32_t nonce_ctr,
                                   xgboost::bst_ulong* len,
                                   char*** out_models,
                                   char **signers,
                                   size_t signer_lengths[],
                                   uint8_t* signatures[],
                                   size_t sig_lengths[],
                                   size_t num_sigs) {
  LOG(DEBUG) << "Ecall: XGBoosterDumpModelWithFeatures";

  // Validate buffers and copy to enclave memory
  char* fname_cpy[fnum];
  char* ftype_cpy[fnum];

  copy_arr_to_enclave(fname_cpy, fnum, (char**)fname, fname_lengths);
  copy_arr_to_enclave(ftype_cpy, fnum, (char**)ftype, ftype_lengths);

  int ret = XGBoosterDumpModelWithFeatures(handle, (int) fnum, (const char**) fname_cpy, (const char**) ftype_cpy, with_stats, nonce, nonce_size, nonce_ctr, len, (const char***) out_models, signers, signer_lengths, signatures, sig_lengths);

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
                                             uint8_t* nonce,
                                             size_t nonce_size,
                                             uint32_t nonce_ctr,
                                             xgboost::bst_ulong* len,
                                             char*** out_models,
                                             char **signers,
                                             size_t signer_lengths[],
                                             uint8_t* signatures[],
                                             size_t sig_lengths[], size_t num_sigs) {
    LOG(DEBUG) << "Ecall: XGBoosterDumpModelWithFeatures";

    // Validate buffers and copy to enclave memory
    char* fname_cpy[fnum];
    char* ftype_cpy[fnum];
    char* signers_cpy[NUM_CLIENTS];
    uint8_t* sigs[NUM_CLIENTS];

    copy_arr_to_enclave(fname_cpy, fnum, (char**)fname, fname_lengths);
    copy_arr_to_enclave(ftype_cpy, fnum, (char**)ftype, ftype_lengths);
    copy_arr_to_enclave(signers_cpy, NUM_CLIENTS, signers, signer_lengths);
    copy_sigs_to_enclave(sigs, signatures, sig_lengths);

    int ret = XGBoosterDumpModelExWithFeatures(handle, (int) fnum, (const char**) fname_cpy, (const char**) ftype_cpy, with_stats, format, nonce, nonce_size, nonce_ctr, len, (const char***) out_models, signers_cpy, sigs, sig_lengths);

    free_array(fname_cpy, fnum);
    free_array(ftype_cpy, fnum);
    free_array(signers_cpy, NUM_CLIENTS);
    free_sigs(sigs);
    return ret;
}

int enclave_XGBoosterGetModelRaw(BoosterHandle handle, uint8_t* nonce, size_t nonce_size, uint32_t nonce_ctr, xgboost::bst_ulong *out_len, char **out_dptr, char **signers, size_t signer_lengths[], uint8_t* signatures[], size_t sig_lengths[], size_t num_sigs) {
  LOG(DEBUG) << "Ecall: XGBoosterGetModelRaw";
  char* signers_cpy[NUM_CLIENTS];
  uint8_t* sigs[NUM_CLIENTS];

  copy_arr_to_enclave(signers_cpy, NUM_CLIENTS, signers, signer_lengths);
  copy_sigs_to_enclave(sigs, signatures, sig_lengths);

  int ret = XGBoosterGetModelRaw(handle, nonce, nonce_size, nonce_ctr, out_len, (const char**)out_dptr, signers_cpy, sigs, sig_lengths);

  free_array(signers_cpy, NUM_CLIENTS);
  free_sigs(sigs);
  return ret;
}

int enclave_XGBoosterLoadModelFromBuffer(BoosterHandle handle, const void* buf, xgboost::bst_ulong len, char **signers, size_t signer_lengths[], uint8_t* signatures[], size_t sig_lengths[], size_t num_sigs) {
    LOG(DEBUG) << "Ecall: XGBoosterLoadModelFromBuffer";
    char* signers_cpy[NUM_CLIENTS];
    uint8_t* sigs[NUM_CLIENTS];

    copy_arr_to_enclave(signers_cpy, NUM_CLIENTS, signers, signer_lengths);
    copy_sigs_to_enclave(sigs, signatures, sig_lengths);

    int ret = XGBoosterLoadModelFromBuffer(handle, buf, len, signers_cpy, sigs, sig_lengths);

    free_array(signers_cpy, NUM_CLIENTS);
    free_sigs(sigs);
    return ret;
}


int enclave_XGBoosterPredict(BoosterHandle handle, DMatrixHandle dmat, int option_mask, unsigned ntree_limit, uint8_t *nonce, size_t nonce_size, uint32_t nonce_ctr, bst_ulong *len, uint8_t **out_result, char **signers, size_t signer_lengths[], uint8_t* signatures[], size_t sig_lengths[], size_t num_sigs) {
  LOG(DEBUG) << "Ecall: XGBoosterPredict";

  char* signers_cpy[NUM_CLIENTS];
  uint8_t* sigs[NUM_CLIENTS];

  copy_arr_to_enclave(signers_cpy, NUM_CLIENTS, signers, signer_lengths);
  copy_sigs_to_enclave(sigs, signatures, sig_lengths);

  int ret = XGBoosterPredict(handle, dmat, option_mask, ntree_limit, nonce, nonce_size, nonce_ctr, len, out_result, signers_cpy, sigs, sig_lengths);

  free_array(signers_cpy, NUM_CLIENTS);
  free_sigs(sigs);
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

int enclave_XGDMatrixNumRow(const DMatrixHandle handle, uint8_t* nonce, size_t nonce_size, uint32_t nonce_ctr, bst_ulong *out, char** signers, size_t signer_lengths[], uint8_t* signatures[], size_t sig_lengths[], size_t num_sigs) {
  LOG(DEBUG) << "Ecall: XGDMatrixNumRow";
  char* signers_cpy[NUM_CLIENTS];
  uint8_t* sigs[NUM_CLIENTS];

  copy_arr_to_enclave(signers_cpy, NUM_CLIENTS, signers, signer_lengths);
  copy_sigs_to_enclave(sigs, signatures, sig_lengths);

  int ret = XGDMatrixNumRow(handle, nonce, nonce_size, nonce_ctr, out, signers_cpy, sigs, sig_lengths);

  free_array(signers_cpy, NUM_CLIENTS);
  free_sigs(sigs);
  return ret;
}

int enclave_XGDMatrixNumCol(const DMatrixHandle handle, uint8_t* nonce, size_t nonce_size, uint32_t nonce_ctr, bst_ulong *out, char** signers, size_t signer_lengths[], uint8_t* signatures[], size_t sig_lengths[], size_t num_sigs) {
  LOG(DEBUG) << "Ecall: XGDMatrixNumCol";
  char* signers_cpy[NUM_CLIENTS];
  uint8_t* sigs[NUM_CLIENTS];

  copy_arr_to_enclave(signers_cpy, NUM_CLIENTS, signers, signer_lengths);
  copy_sigs_to_enclave(sigs, signatures, sig_lengths);

  int ret = XGDMatrixNumCol(handle, nonce, nonce_size, nonce_ctr, out, signers_cpy, sigs, sig_lengths);

  free_array(signers_cpy, NUM_CLIENTS);
  free_sigs(sigs);
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

int enclave_get_remote_report_with_pubkey(
        uint8_t** pem_key,
        size_t* pem_key_size,
        uint8_t** remote_report,
        size_t* remote_report_size) {
  LOG(DEBUG) << "Ecall: enclave_get_remote_report_with_pubkey";
  return get_remote_report_with_pubkey(pem_key, pem_key_size, remote_report, remote_report_size);
}

int enclave_get_remote_report_with_pubkey_and_nonce(
        uint8_t** pem_key,
        size_t* key_size,
        uint8_t** nonce,
        size_t* nonce_size,
        uint8_t** remote_report,
        size_t* remote_report_size) {
  LOG(DEBUG) << "Ecall: enclave_get_remote_report_with_pubkey_and_nonce";
  return get_remote_report_with_pubkey_and_nonce(pem_key, key_size, nonce, nonce_size, remote_report, remote_report_size);
}

//int enclave_add_client_key(
//        uint8_t* data,
//        size_t data_len,
//        uint8_t* signature,
//        size_t sig_len) {
//    LOG(DEBUG) << "Ecall: add_client_key";
//    return add_client_key(data, data_len, signature, sig_len);
//}

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
