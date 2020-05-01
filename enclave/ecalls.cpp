#include <xgboost/c_api.h>
#include <xgboost/base.h>
#include <xgboost/logging.h>
#include <sys/mount.h>
#include <rabit/c_api.h>

#include "xgboost_t.h"
#include <xgboost/common/common.h>

#include <string>

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

int enclave_XGDMatrixCreateFromEncryptedFile(const char *fnames[], size_t fname_lengths[], char* usernames[], size_t username_lengths[], bst_ulong num_files, int silent, DMatrixHandle *out) {
  LOG(DEBUG) << "Ecall: XGDMatrixCreateFromEncryptedFile";
  char* filenames[num_files];
  char* usrnames[num_files];
  for (int i = 0; i < num_files; i++) {
      const char* fname = fnames[i];
      size_t nlen = fname_lengths[i];
      check_host_buffer(fname, nlen);
      filenames[i] = strndup(fname, nlen);
      filenames[i][nlen] = '\0';

      const char* uname = usernames[i];
      size_t namelen = username_lengths[i];
      check_host_buffer(uname, namelen);
      usrnames[i] = strndup(uname, namelen);
      usrnames[i][namelen] = '\0';
  }
  return XGDMatrixCreateFromEncryptedFile((const char**) filenames, usrnames, num_files, silent, out);
}

int enclave_XGBoosterCreate(DMatrixHandle dmat_handles[], size_t handle_lengths[], bst_ulong len, BoosterHandle* out) {
  LOG(DEBUG) << "Ecall: XGBoosterCreate";

  // Validate buffers and copy to enclave memory
  DMatrixHandle dmats[len];
  for (int i = 0; i < len; i++) {
    char* name = dmat_handles[i];
    size_t nlen = handle_lengths[i];
    check_host_buffer(name, nlen);
    dmats[i] = strndup(name, nlen);
    dmats[i][nlen] = '\0';
  }
  int ret = XGBoosterCreate(dmats, len, out);
  for (int i = 0; i < len; i++) {
    free(dmats[i]);
  }
  return ret;
}

int enclave_XGBoosterSetParam(BoosterHandle handle, const char *name, const char *value) {
  LOG(DEBUG) << "Ecall: XGBoosterSetParam";
  return XGBoosterSetParam(handle, name, value);
}

int enclave_XGBoosterSetParamWithSig(BoosterHandle handle, const char* name, const char* value, const char* username, uint8_t *signature, size_t sig_len){
  LOG(DEBUG) << "Ecall: XGBoosterSetParamWithSig";
  return XGBoosterSetParamWithSig(handle, name, value, username, signature, sig_len);
}

int enclave_XGBoosterUpdateOneIterWithSig(BoosterHandle handle, int iter, DMatrixHandle dtrain, char *username, uint8_t *signature, size_t sig_len) {
  LOG(DEBUG) << "Ecall: XGBoosterUpdateOneIter";
  return XGBoosterUpdateOneIterWithSig(handle, iter, dtrain, username, signature, sig_len);
}

int enclave_XGBoosterUpdateOneIter(BoosterHandle handle, int iter, DMatrixHandle dtrain) {
  LOG(DEBUG) << "Ecall: XGBoosterUpdateOneIter";
  return XGBoosterUpdateOneIter(handle, iter, dtrain);
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
  for (int i = 0; i < len; i++) {
    char* name = dmat_handles[i];
    size_t nlen = handle_lengths[i];
    check_host_buffer(name, nlen);
    dmats[i] = strndup(name, nlen);
    dmats[i][nlen] = '\0';
  }
  for (int i = 0; i < len; i++) {
    const char* name = evnames[i];
    size_t nlen = names_lengths[i];
    check_host_buffer(name, nlen);
    eval_names[i] = strndup(name, nlen);
    eval_names[i][nlen] = '\0';
  }
  int ret = XGBoosterEvalOneIter(handle, iter, dmats, (const char**) eval_names, len, (const char**) out_str);
  for (int i = 0; i < len; i++) {
    free(dmats[i]);
    free(eval_names[i]);
  }
  return ret;
}

int enclave_XGBoosterLoadModel(BoosterHandle handle, const char *fname, char *username) {
  LOG(DEBUG) << "Ecall: XGBoosterLoadModel";
  return XGBoosterLoadModel(handle, fname, username);
}

int enclave_XGBoosterSaveModel(BoosterHandle handle, const char *fname, char *username) {
  LOG(DEBUG) << "Ecall: XGBoosterSaveModel";
  return XGBoosterSaveModel(handle, fname, username);
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
                       char*** out_models) {
  LOG(DEBUG) << "Ecall: XGBoosterDumpModelEx";
  return XGBoosterDumpModelEx(handle, fmap, with_stats, format, len, (const char***) out_models);
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
  size_t name_len;
  size_t type_len;
  for (int i = 0; i < fnum; i++) {
    name_len = fname_lengths[i];
    type_len = ftype_lengths[i];

    check_host_buffer(fname[i], name_len);
    check_host_buffer(ftype[i], type_len);

    fname_cpy[i] = strndup(fname[i], name_len);
    fname_cpy[i][name_len] = '\0';
    ftype_cpy[i] = strndup(ftype[i], type_len);
    ftype_cpy[i][type_len] = '\0';
  }
  int ret = XGBoosterDumpModelWithFeatures(handle, (int) fnum, (const char**) fname_cpy, (const char**) ftype_cpy, with_stats, len, (const char***) out_models);
  for (int i = 0; i < fnum; i++) {
    free(fname_cpy[i]);
    free(ftype_cpy[i]);
  }
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
                                   char*** out_models) {
  LOG(DEBUG) << "Ecall: XGBoosterDumpModelWithFeatures";

  // Validate buffers and copy to enclave memory
  char* fname_cpy[fnum];
  char* ftype_cpy[fnum];
  size_t name_len;
  size_t type_len;
  for (int i = 0; i < fnum; i++) {
    name_len = fname_lengths[i];
    type_len = ftype_lengths[i];

    check_host_buffer(fname[i], name_len);
    check_host_buffer(ftype[i], type_len);

    fname_cpy[i] = strndup(fname[i], name_len);
    fname_cpy[i][name_len] = '\0';
    ftype_cpy[i] = strndup(ftype[i], type_len);
    ftype_cpy[i][type_len] = '\0';
  }
  int ret = XGBoosterDumpModelExWithFeatures(handle, (int) fnum, (const char**) fname_cpy, (const char**) ftype_cpy, with_stats, format, len, (const char***) out_models);
  for (int i = 0; i < fnum; i++) {
    free(fname_cpy[i]);
    free(ftype_cpy[i]);
  }
  return ret;
}
int enclave_XGBoosterGetModelRaw(BoosterHandle handle, xgboost::bst_ulong *out_len, char **out_dptr, char *username) {
  LOG(DEBUG) << "Ecall: XGBoosterSerializeToBuffer";
  return XGBoosterGetModelRaw(handle, out_len, (const char**)out_dptr, username);
}

int enclave_XGBoosterLoadModelFromBuffer(BoosterHandle handle, const void* buf, xgboost::bst_ulong len, char *username) {
  LOG(DEBUG) << "Ecall: XGBoosterLoadModelFromBuffer";
  return XGBoosterLoadModelFromBuffer(handle, buf, len, username);
}

int enclave_XGBoosterPredictWithSig(BoosterHandle handle, DMatrixHandle dmat, int option_mask, unsigned ntree_limit, bst_ulong *len, uint8_t **out_result, char *username, uint8_t *signature,
size_t sig_len) {
  LOG(DEBUG) << "Ecall: XGBoosterPredictWithSig";
  return XGBoosterPredictWithSig(handle, dmat, option_mask, ntree_limit, len, out_result, username, signature, sig_len);
}

int enclave_XGBoosterPredict(BoosterHandle handle, DMatrixHandle dmat, int option_mask, unsigned ntree_limit, bst_ulong *len, uint8_t **out_result, char *username) {
  LOG(DEBUG) << "Ecall: XGBoosterPredict";
  return XGBoosterPredict(handle, dmat, option_mask, ntree_limit, len, out_result, username);
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
  return XGDMatrixNumRow(handle, out);
}

int enclave_XGDMatrixNumCol(const DMatrixHandle handle, bst_ulong *out) {
  LOG(DEBUG) << "Ecall: XGDMatrixNumCol";
  return XGDMatrixNumCol(handle, out);
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
        size_t* key_size,
        uint8_t** remote_report,
        size_t* remote_report_size) {
  LOG(DEBUG) << "Ecall: enclave_get_remote_report_with_pubkey";
  return get_remote_report_with_pubkey(pem_key, key_size, remote_report, remote_report_size);
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
