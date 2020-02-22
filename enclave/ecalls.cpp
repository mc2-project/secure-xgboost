#include <xgboost/c_api.h>
#include <xgboost/base.h>
#include <xgboost/logging.h>
#include <sys/mount.h>
#include <rabit/c_api.h>

#include "xgboost_t.h"
#include "src/common/common.h"

#include <string>

void enclave_init(int log_verbosity) {
  std::vector<std::pair<std::string, std::string> > args;
  args.emplace_back("verbosity", std::to_string(log_verbosity));
  xgboost::ConsoleLogger::Configure(args.cbegin(), args.cend());

  LOG(DEBUG) << "Ecall: init\n";
  oe_result_t result;
  if ((result = oe_load_module_host_resolver()) != OE_OK) {
      fprintf(stdout, "oe_load_module_host_resolver failed with %s\n", oe_result_str(result));
  }
  if ((result = oe_load_module_host_socket_interface()) != OE_OK) {
      fprintf(stdout, "oe_load_module_host_socket_interface failed with %s\n", oe_result_str(result));
  }
  if ((result = oe_load_module_host_file_system()) != OE_OK) {
      fprintf(stdout, "oe_load_module_host_file_system failed with %s\n", oe_result_str(result));
  }
  /* Mount the host file system on the root directory. */
  if (mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) != 0) {
      fprintf(stdout, "Unable to mount host file system on the root directory\n");
  }
  fprintf(stdout, "Loaded all modules\n");
}

int enclave_XGDMatrixCreateFromFile(const char *fname, int silent, DMatrixHandle *out) {
  LOG(DEBUG) << "Ecall: XGDMatrixCreateFromFile";
  return XGDMatrixCreateFromFile(fname, silent, out);
}

int enclave_XGDMatrixCreateFromEncryptedFile(const char *fname, int silent, DMatrixHandle *out) {
  LOG(DEBUG) << "Ecall: XGDMatrixCreateFromEncryptedFile";
  return XGDMatrixCreateFromEncryptedFile(fname, silent, out);
}

int enclave_XGBoosterCreate(const DMatrixHandle dmats[], bst_ulong len, BoosterHandle* out) {
  LOG(DEBUG) << "Ecall: XGBoosterCreate";
  for (int i = 0; i < len; i++) {
      check_enclave_ptr(dmats[i]);
  }
  return XGBoosterCreate(dmats, len, out);
}

int enclave_XGBoosterSetParam(BoosterHandle handle, const char *name, const char *value) {
  LOG(DEBUG) << "Ecall: XGBoosterSetParam";
  check_enclave_ptr(handle);
  return XGBoosterSetParam(handle, name, value);
}

int enclave_XGBoosterUpdateOneIter(BoosterHandle handle, int iter, DMatrixHandle dtrain) {
  LOG(DEBUG) << "Ecall: XGBoosterUpdateOneIter";
  check_enclave_ptr(handle);
  check_enclave_ptr(dtrain);
  return XGBoosterUpdateOneIter(handle, iter, dtrain);
}

int enclave_XGBoosterBoostOneIter(BoosterHandle handle, DMatrixHandle dtrain, bst_float *grad, bst_float *hess, xgboost::bst_ulong len) {
  LOG(DEBUG) << "Ecall: XGBoosterBoostOneIter";
  check_enclave_ptr(handle);
  check_enclave_ptr(dtrain);
  return XGBoosterBoostOneIter(handle, dtrain, grad, hess, len);
}

int enclave_XGBoosterEvalOneIter(BoosterHandle handle, int iter, DMatrixHandle dmats[], const char* evnames[], bst_ulong len, char** out_str) {
  LOG(DEBUG) << "Ecall: XGBoosterEvalOneIter " << strlen(evnames[0]);
  check_enclave_ptr(handle);
  char* eval_names[len];
  for (int i = 0; i < len; i++) {
      check_enclave_ptr(dmats[i]);

      const char* name = evnames[i];
      size_t nlen = strlen(name) + 1;
      check_host_buffer(name, nlen);
      eval_names[i] = strndup(name, nlen);
      eval_names[i][nlen] = '\0';
  }
  return XGBoosterEvalOneIter(handle, iter, dmats, (const char**) eval_names, len, (const char**) out_str);
}

int enclave_XGBoosterLoadModel(BoosterHandle handle, const char *fname) {
  LOG(DEBUG) << "Ecall: XGBoosterLoadModel";
  check_enclave_ptr(handle);
  return XGBoosterLoadModel(handle, fname);
}

int enclave_XGBoosterSaveModel(BoosterHandle handle, const char *fname) {
  LOG(DEBUG) << "Ecall: XGBoosterSaveModel";
  check_enclave_ptr(handle);
  return XGBoosterSaveModel(handle, fname);
}

int enclave_XGBoosterGetModelRaw(BoosterHandle handle, xgboost::bst_ulong *out_len, char **out_dptr) {
  LOG(DEBUG) << "Ecall: XGBoosterSerializeToBuffer";
  check_enclave_ptr(handle);
  return XGBoosterGetModelRaw(handle, out_len, (const char**)out_dptr);
}

int enclave_XGBoosterLoadModelFromBuffer(BoosterHandle handle, const void* buf, xgboost::bst_ulong len) {
  LOG(DEBUG) << "Ecall: XGBoosterLoadModelFromBuffer";
  check_enclave_ptr(handle);
  return XGBoosterLoadModelFromBuffer(handle, buf, len);
}

int enclave_XGBoosterPredict(BoosterHandle handle, DMatrixHandle dmat, int option_mask, unsigned ntree_limit, bst_ulong *len, uint8_t **out_result) {
  LOG(DEBUG) << "Ecall: XGBoosterPredict";
  check_enclave_ptr(handle);
  check_enclave_ptr(dmat);
  return XGBoosterPredict(handle, dmat, option_mask, ntree_limit, len, out_result);
}

int enclave_XGDMatrixGetFloatInfo(const DMatrixHandle handle, const char* field, bst_ulong *out_len, bst_float **out_dptr) {
  LOG(DEBUG) << "Ecall: XGDMatrixGetFloatInfo";
  check_enclave_ptr(handle);
  return XGDMatrixGetFloatInfo(handle, field, out_len, (const bst_float**) out_dptr);
}

int enclave_XGDMatrixGetUintInfo(const DMatrixHandle handle, const char* field, bst_ulong *out_len, unsigned **out_dptr) {
  LOG(DEBUG) << "Ecall: XGDMatrixGetFloatInfo";
  check_enclave_ptr(handle);
  return XGDMatrixGetUIntInfo(handle, field, out_len, (const unsigned**) out_dptr);
}

int enclave_XGDMatrixSetFloatInfo(DMatrixHandle handle, const char* field, const bst_float* info, bst_ulong len) {
  fprintf(stdout, "Ecall: XGDMatrixSetFloatInfo\n");
  check_enclave_ptr(handle);
;  return XGDMatrixSetFloatInfo(handle, field, info, len);
}

int enclave_XGDMatrixSetUIntInfo(DMatrixHandle handle, const char* field, const unsigned* info, bst_ulong len) {
  LOG(DEBUG) << "Ecall: XGDMatrixSetUIntInfo";
  check_enclave_ptr(handle);
  return XGDMatrixSetUIntInfo(handle, field, info, len);
}

int enclave_XGDMatrixNumRow(const DMatrixHandle handle, bst_ulong *out) {
  LOG(DEBUG) << "Ecall: XGDMatrixNumRow";
  check_enclave_ptr(handle);
  return XGDMatrixNumRow(handle, out);
}

int enclave_XGDMatrixNumCol(const DMatrixHandle handle, bst_ulong *out) {
  LOG(DEBUG) << "Ecall: XGDMatrixNumCol";
  check_enclave_ptr(handle);
  return XGDMatrixNumCol(handle, out);
}

int enclave_XGBoosterGetAttr(BoosterHandle handle, const char* key, char** out, int* success) {
    LOG(DEBUG) << "Ecall: XGBoosterGetAttr";
    check_enclave_ptr(handle);
    return XGBoosterGetAttr(handle, key, (const char** )out, success);
}

int enclave_XGBoosterGetAttrNames(BoosterHandle handle, bst_ulong* out_len, char*** out) {
    LOG(DEBUG) << "Ecall: XGBoosterGetAttrNames";
    check_enclave_ptr(handle);
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
  fprintf(stdout, "Ecall: enclave_get_remote_report_with_pubkey\n");
  return get_remote_report_with_pubkey(pem_key, key_size, remote_report, remote_report_size);
}

int enclave_verify_remote_report_and_set_pubkey(
        uint8_t* pem_key,
        size_t key_size,
        uint8_t* remote_report,
        size_t remote_report_size) {
  fprintf(stdout, "Ecall: verify_remote_report_and_set_pubkey\n");
  return verify_remote_report_and_set_pubkey(pem_key, key_size, remote_report, remote_report_size);
}

//int enclave_add_client_key(
//    char* fname,
//    uint8_t* data,
//    size_t data_len,
//    uint8_t* signature,
//    size_t sig_len) {
//  fprintf(stdout, "Ecall: add_client_key\n");
//  return add_client_key(fname, data, data_len, signature, sig_len);
//}

int enclave_add_client_key(
        uint8_t* data,
        size_t data_len,
        uint8_t* signature,
        size_t sig_len) {
    fprintf(stdout, "Ecall: add_client_key\n");
    return add_client_key(data, data_len, signature, sig_len);
}

// FIXME: check bounds
void enclave_RabitInit(int argc, char **argv) {
  fprintf(stdout, "Ecall: RabitInit\n");
  RabitInit(argc, argv);
}

void enclave_RabitFinalize() {
  fprintf(stdout, "Ecall: RabitFinalize\n");
  RabitFinalize();
}

int enclave_RabitIsDistributed() {
  fprintf(stdout, "Ecall: RabitIsDistributed\n");
  return RabitIsDistributed();
}

void enclave_RabitTrackerPrint(const char *msg) {
  fprintf(stdout, "Ecall: TrackerPrint\n");
  RabitTrackerPrint(msg);
}
