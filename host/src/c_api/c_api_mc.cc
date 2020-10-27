// Copyright (c) 2014 by Contributors
// Modifications Copyright (c) 2020 by Secure XGBoost Contributors
#include <rabit/rabit.h>
#include <rabit/c_api.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <vector>
#include <string>
#include <memory>

#include "xgboost/base.h"
#include "xgboost/data.h"
#include "xgboost/host_device_vector.h"
#include "xgboost/learner.h"
#include "xgboost/c_api_mc.h"
#include "xgboost/logging.h"
#include "xgboost/version_config.h"
#include "xgboost/json.h"

#include "xgboost/c_api/c_api_error.h"
#include "../enclave/src/common/io.h"
#include "../enclave/src/data/adapter.h"
#include "../enclave/src/data/simple_dmatrix.h"
#include "../enclave/src/data/proxy_dmatrix.h"

#include <openenclave/host.h>
#include "xgboost_mc_u.h"
#include <enclave/crypto.h>
#include <enclave/attestation.h>
#include <enclave/enclave.h>

#include <mbedtls/entropy.h>    // mbedtls_entropy_context
#include <mbedtls/ctr_drbg.h>   // mbedtls_ctr_drbg_context
#include <mbedtls/cipher.h>     // MBEDTLS_CIPHER_ID_AES
#include <mbedtls/gcm.h>        // mbedtls_gcm_context

#include <dmlc/base64.h>

#define safe_ecall(call) {                                      \
if (!Enclave::getInstance().getEnclave()) {                     \
  fprintf(                                                      \
      stderr,                                                   \
      "Enclave not initialized\n");                             \
  return 1;                                                     \
}                                                               \
oe_result_t result = (call);                                    \
if (result != OE_OK) {                                          \
  fprintf(                                                      \
      stderr,                                                   \
      "Ecall failed: result=%u (%s)\n",                         \
      result,                                                   \
      oe_result_str(result));                                   \
  oe_terminate_enclave(Enclave::getInstance().getEnclave());    \
  return result;                                                \
}                                                               \
return Enclave::getInstance().enclave_ret;                      \
}

void get_str_lengths(char** arr, size_t size, size_t* lengths) {
  for (int i = 0; i < size; i++) {
    lengths[i] = strlen(arr[i]);
  }
}

using namespace xgboost; // NOLINT(*);

XGB_DLL void XGBoostVersion(int* major, int* minor, int* patch) {
  if (major) {
    *major = XGBOOST_VER_MAJOR;
  }
  if (minor) {
    *minor = XGBOOST_VER_MINOR;
  }
  if (patch) {
    *patch = XGBOOST_VER_PATCH;
  }
}

XGB_DLL int XGBRegisterLogCallback(void (*callback)(const char*)) {
  API_BEGIN();
  LogCallbackRegistry* registry = LogCallbackRegistryStore::Get();
  registry->Register(callback);
  API_END();
}

int XGDMatrixCreateFromFile(const char *fname,
                            int silent,
                            DMatrixHandle *out) {
    safe_ecall(enclave_XGDMatrixCreateFromFile(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, fname, silent, out));
}

int XGDMatrixCreateFromEncryptedFile(const char *fnames[],
                                     char* usernames[],
                                     xgboost::bst_ulong num_files,
                                     int silent,
                                     uint8_t *nonce,
                                     size_t nonce_size,
                                     uint32_t nonce_ctr,
                                     DMatrixHandle *out,
                                     uint8_t** out_sig,
                                     size_t *out_sig_length,
                                     char **signers,
                                     uint8_t* signatures[],
                                     size_t* sig_lengths) {
    size_t fname_lengths[num_files];
    size_t username_lengths[num_files];
    int NUM_CLIENTS = Enclave::getInstance().get_num_clients();
    size_t signer_lengths[NUM_CLIENTS];

    get_str_lengths((char**)fnames, num_files, fname_lengths);
    get_str_lengths(usernames, num_files, username_lengths);
    get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

    safe_ecall(enclave_XGDMatrixCreateFromEncryptedFile(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, (const char**) fnames, fname_lengths, usernames, username_lengths, num_files, silent, nonce, nonce_size, nonce_ctr, out, out_sig, out_sig_length, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGDMatrixFree(DMatrixHandle handle) {
    safe_ecall(enclave_XGDMatrixFree(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle));
}

XGB_DLL int XGDMatrixSetFloatInfo(DMatrixHandle handle,
                          const char* field,
                          const bst_float* info,
                          xgboost::bst_ulong len) {

  safe_ecall(enclave_XGDMatrixSetFloatInfo(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, field, info, len));
}

XGB_DLL int XGDMatrixSetUIntInfo(DMatrixHandle handle,
                         const char* field,
                         const unsigned* info,
                         xgboost::bst_ulong len) {
  safe_ecall(enclave_XGDMatrixSetUIntInfo(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, field, info, len));
}

XGB_DLL int XGDMatrixGetFloatInfo(const DMatrixHandle handle,
                                  const char* field,
                                  xgboost::bst_ulong* out_len,
                                  const bst_float** out_dptr) {
    safe_ecall(enclave_XGDMatrixGetFloatInfo(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, field, out_len, (bst_float**) out_dptr));
}

XGB_DLL int XGDMatrixGetUIntInfo(const DMatrixHandle handle,
                                 const char *field,
                                 xgboost::bst_ulong *out_len,
                                 const unsigned **out_dptr) {
  safe_ecall(enclave_XGDMatrixGetUintInfo(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, field, out_len, (unsigned**) out_dptr));
}

XGB_DLL int XGDMatrixNumRow(const DMatrixHandle handle,
                            uint8_t* nonce,
                            size_t nonce_size,
                            uint32_t nonce_ctr,
                            xgboost::bst_ulong *out,
                            uint8_t** out_sig,
                            size_t *out_sig_length,
                            char **signers,
                            uint8_t* signatures[],
                            size_t* sig_lengths) {
  int NUM_CLIENTS = Enclave::getInstance().get_num_clients();
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

  safe_ecall(enclave_XGDMatrixNumRow(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, nonce, nonce_size, nonce_ctr, out, out_sig, out_sig_length, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGDMatrixNumCol(const DMatrixHandle handle,
                            uint8_t* nonce,
                            size_t nonce_size,
                            uint32_t nonce_ctr,
                            xgboost::bst_ulong *out,
                            uint8_t** out_sig,
                            size_t *out_sig_length,
                            char **signers,
                            uint8_t* signatures[],
                            size_t* sig_lengths) {                          
  int NUM_CLIENTS = Enclave::getInstance().get_num_clients();
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

  safe_ecall(enclave_XGDMatrixNumCol(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, nonce, nonce_size, nonce_ctr, out, out_sig, out_sig_length, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

// xgboost implementation

XGB_DLL int XGBCreateEnclave(const char *enclave_image, char** usernames, size_t num_clients, int log_verbosity) {
  if (!Enclave::getInstance().getEnclave()) {
    size_t username_lengths[num_clients];
    get_str_lengths(usernames, num_clients, username_lengths);

    oe_result_t result;

    uint32_t flags = 0;
#ifdef __ENCLAVE_DEBUG__
    flags |= OE_ENCLAVE_FLAG_DEBUG;
#endif
#ifdef __ENCLAVE_SIMULATION__
    flags |= OE_ENCLAVE_FLAG_SIMULATE;
#endif

    oe_enclave_t** enclave = Enclave::getInstance().getEnclaveRef();
    // Create the enclave
    result = oe_create_xgboost_mc_enclave(
        enclave_image, OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, enclave);
    if (result != OE_OK) {
      fprintf(
          stderr,
          "oe_create_enclave(): result=%u (%s)\n",
          result,
          oe_result_str(result));
      oe_terminate_enclave(Enclave::getInstance().getEnclave());
      return Enclave::getInstance().enclave_ret;
    }
    Enclave::getInstance().set_num_clients(num_clients);
    safe_ecall(enclave_init(Enclave::getInstance().getEnclave(), usernames, username_lengths, num_clients, log_verbosity));
  }
  return 0;
}

XGB_DLL int XGBoosterCreate(const DMatrixHandle dmats[],
                    xgboost::bst_ulong len,
                    uint8_t *nonce,
                    size_t nonce_size,
                    uint32_t nonce_ctr,
                    BoosterHandle *out,
                    uint8_t** out_sig,
                    size_t *out_sig_length,
                    char **signers,
                    uint8_t* signatures[],
                    size_t* sig_lengths) {
  int NUM_CLIENTS = Enclave::getInstance().get_num_clients();
  size_t handle_lengths[len];
  size_t signer_lengths[NUM_CLIENTS];

  get_str_lengths((char**)dmats, len, handle_lengths);
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

  safe_ecall(enclave_XGBoosterCreate(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, const_cast<char**>(dmats), handle_lengths, len, nonce, nonce_size, nonce_ctr, out, out_sig, out_sig_length, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGBoosterFree(BoosterHandle handle) {
    safe_ecall(enclave_XGBoosterFree(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle));
}

XGB_DLL int XGBoosterSetParam(BoosterHandle handle,
                              const char *name,
                              const char *value,
                              uint8_t *nonce,
                              size_t nonce_size,
                              uint32_t nonce_ctr, 
                              uint8_t** out_sig,
                              size_t *out_sig_length,
                              char **signers,
                              uint8_t* signatures[],
                              size_t* sig_lengths) {
  int NUM_CLIENTS = Enclave::getInstance().get_num_clients();
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

    safe_ecall(enclave_XGBoosterSetParam(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, name, value, nonce, nonce_size, nonce_ctr, out_sig, out_sig_length, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGBoosterUpdateOneIter(BoosterHandle handle,
                                   int iter,
                                   DMatrixHandle dtrain,
                                   uint8_t* nonce,
                                   size_t nonce_size,
                                   uint32_t nonce_ctr,
                                   uint8_t** out_sig,
                                   size_t *out_sig_length,
                                   char **signers,
                                   uint8_t* signatures[],
                                   size_t* sig_lengths) {
  int NUM_CLIENTS = Enclave::getInstance().get_num_clients();
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

    safe_ecall(enclave_XGBoosterUpdateOneIter(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, iter, dtrain, nonce, nonce_size, nonce_ctr, out_sig, out_sig_length, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGBoosterBoostOneIter(BoosterHandle handle,
                                  DMatrixHandle dtrain,
                                  bst_float *grad,
                                  bst_float *hess,
                                  xgboost::bst_ulong len) {
  safe_ecall(enclave_XGBoosterBoostOneIter(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, dtrain, grad, hess, len));
}

XGB_DLL int XGBoosterEvalOneIter(BoosterHandle handle,
                                 int iter,
                                 DMatrixHandle dmats[],
                                 const char* evnames[],
                                 xgboost::bst_ulong len,
                                 const char** out_str) {
  size_t handle_lengths[len];
  size_t name_lengths[len];

  get_str_lengths(dmats, len, handle_lengths);
  get_str_lengths((char**)evnames, len, name_lengths);

  safe_ecall(enclave_XGBoosterEvalOneIter(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, iter, dmats, handle_lengths, evnames, name_lengths, len, (char**) out_str));
}

XGB_DLL int XGBoosterPredict(BoosterHandle handle,
                             DMatrixHandle dmat,
                             int option_mask,
                             unsigned ntree_limit,
                             int training,
                             uint8_t *nonce,
                             size_t nonce_size,
                             uint32_t nonce_ctr,
                             xgboost::bst_ulong *len,
                             uint8_t **out_result,
                             uint8_t** out_sig,
                             size_t *out_sig_length,
                             char **signers,
                             uint8_t* signatures[],
                             size_t* sig_lengths) {
  int NUM_CLIENTS = Enclave::getInstance().get_num_clients();
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

    safe_ecall(enclave_XGBoosterPredict(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, dmat, option_mask, ntree_limit, training, nonce, nonce_size, nonce_ctr, len, out_result, out_sig, out_sig_length, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGBoosterLoadModel(BoosterHandle handle, const char* fname, uint8_t* nonce, size_t nonce_size, uint32_t nonce_ctr, uint8_t** out_sig, size_t* out_sig_length, char** signers, uint8_t* signatures[], size_t* sig_lengths) {
  int NUM_CLIENTS = Enclave::getInstance().get_num_clients();
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

  safe_ecall(enclave_XGBoosterLoadModel(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, fname, nonce, nonce_size, nonce_ctr, out_sig, out_sig_length, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGBoosterSaveModel(BoosterHandle handle, const char* fname, uint8_t* nonce, size_t nonce_size, uint32_t nonce_ctr, uint8_t** out_sig, size_t* out_sig_length, char** signers, uint8_t* signatures[], size_t* sig_lengths) {
  int NUM_CLIENTS = Enclave::getInstance().get_num_clients();
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

  safe_ecall(enclave_XGBoosterSaveModel(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, fname, nonce, nonce_size, nonce_ctr, out_sig, out_sig_length, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGBoosterLoadModelFromBuffer(BoosterHandle handle,
                                         const void* buf,
                                         xgboost::bst_ulong len,
                                         uint8_t** out_sig,
                                         size_t *out_sig_length,
                                         char** signers,
                                         uint8_t* signatures[],
                                         size_t* sig_lengths) {
  int NUM_CLIENTS = Enclave::getInstance().get_num_clients();
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

  safe_ecall(enclave_XGBoosterLoadModelFromBuffer(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, buf, len, out_sig, out_sig_length, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGBoosterGetModelRaw(BoosterHandle handle,
                                 uint8_t* nonce,
                                 size_t nonce_size,
                                 uint32_t nonce_ctr,
                                 bst_ulong *out_len,
                                 const char **out_dptr,
                                 uint8_t** out_sig,
                                 size_t *out_sig_length,
                                 char** signers,
                                 uint8_t* signatures[],
                                 size_t* sig_lengths) {
  int NUM_CLIENTS = Enclave::getInstance().get_num_clients();
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

  safe_ecall(enclave_XGBoosterGetModelRaw(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, nonce, nonce_size, nonce_ctr, out_len, (char**)out_dptr, out_sig, out_sig_length, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGBoosterDumpModel(BoosterHandle handle,
                       const char* fmap,
                       int with_stats,
                       uint8_t* nonce,
                       size_t nonce_size,
                       uint32_t nonce_ctr,
                       xgboost::bst_ulong* len,
                       const char*** out_models) {
  safe_ecall(enclave_XGBoosterDumpModel(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, fmap, with_stats, nonce, nonce_size, nonce_ctr, len, (char***) out_models));
}

XGB_DLL int XGBoosterDumpModelEx(BoosterHandle handle,
                                 const char* fmap,
                                 int with_stats,
                                 const char *format,
                                 uint8_t *nonce,
                                 size_t nonce_size,
                                 uint32_t nonce_ctr,
                                 xgboost::bst_ulong* len,
                                 const char*** out_models,
                                 uint8_t** out_sig,
                                 size_t *out_sig_length,
                                 char** signers,
                                 uint8_t* signatures[],
                                 size_t* sig_lengths){
  int NUM_CLIENTS = Enclave::getInstance().get_num_clients();
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

  safe_ecall(enclave_XGBoosterDumpModelEx(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, fmap, with_stats, format, nonce, nonce_size, nonce_ctr, len, (char***) out_models, out_sig, out_sig_length, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}


XGB_DLL int XGBoosterDumpModelWithFeatures(BoosterHandle handle,
                                   int fnum,
                                   const char** fname,
                                   const char** ftype,
                                   int with_stats,
                                   uint8_t* nonce,
                                   size_t nonce_size,
                                   uint32_t nonce_ctr,
                                   xgboost::bst_ulong* len,
                                   const char*** out_models,
                                   uint8_t** out_sig,
                                   size_t *out_sig_length,
                                   char **signers,
                                   size_t signer_lengths[],
                                   uint8_t* signatures[],
                                   size_t* sig_lengths) {
  size_t fname_lengths[fnum];
  size_t ftype_lengths[fnum];

  get_str_lengths((char**)fname, fnum, fname_lengths);
  get_str_lengths((char**)ftype, fnum, ftype_lengths);

  int NUM_CLIENTS = Enclave::getInstance().get_num_clients();
  safe_ecall(enclave_XGBoosterDumpModelWithFeatures(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, (unsigned int) fnum, fname, fname_lengths, ftype, ftype_lengths, with_stats, nonce, nonce_size, nonce_ctr, len, (char***) out_models, out_sig, out_sig_length, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGBoosterDumpModelExWithFeatures(BoosterHandle handle,
                                             int fnum,
                                             const char** fname,
                                             const char** ftype,
                                             int with_stats,
                                             const char *format,
                                             uint8_t *nonce,
                                             size_t nonce_size,
                                             uint32_t nonce_ctr,
                                             xgboost::bst_ulong* len,
                                             const char*** out_models,
                                             uint8_t** out_sig,
                                             size_t *out_sig_length,
                                             char **signers,
                                             uint8_t* signatures[],
                                             size_t* sig_lengths) {
    size_t fname_lengths[fnum];
    size_t ftype_lengths[fnum];
    int NUM_CLIENTS = Enclave::getInstance().get_num_clients();
    size_t signer_lengths[NUM_CLIENTS];

    get_str_lengths((char**)fname, fnum, fname_lengths);
    get_str_lengths((char**)ftype, fnum, ftype_lengths);
    get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

    safe_ecall(enclave_XGBoosterDumpModelExWithFeatures(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, (unsigned int) fnum, fname, fname_lengths, ftype, ftype_lengths, with_stats, format, nonce, nonce_size, nonce_ctr, len, (char***) out_models, out_sig, out_sig_length, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}


XGB_DLL int XGBoosterGetAttr(BoosterHandle handle,
                     const char* key,
                     const char** out,
                     int* success) {
  safe_ecall(enclave_XGBoosterGetAttr(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, key, (char**)out, success));
}

/* TODO(rishabhp): Enable this
 *
 * XGB_DLL int XGBoosterSetAttr(BoosterHandle handle,
 *                      const char* key,
 *                      const char* value) {
 *   auto* bst = static_cast<Booster*>(handle);
 *   API_BEGIN();
 *   CHECK_HANDLE();
 *   if (value == nullptr) {
 *     bst->learner()->DelAttr(key);
 *   } else {
 *     bst->learner()->SetAttr(key, value);
 *   }
 *   API_END();
 * }
 */

XGB_DLL int XGBoosterGetAttrNames(BoosterHandle handle,
                     xgboost::bst_ulong* out_len,
                     const char*** out) {
  safe_ecall(enclave_XGBoosterGetAttrNames(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, out_len, (char***)out));
}

/* TODO(rishabhp): Enable this
 *
 * XGB_DLL int XGBoosterLoadRabitCheckpoint(BoosterHandle handle,
 *                                  int* version) {
 *   API_BEGIN();
 *   CHECK_HANDLE();
 *   auto* bst = static_cast<Booster*>(handle);
 *   *version = rabit::LoadCheckPoint(bst->learner());
 *   if (*version != 0) {
 *     bst->Intialize();
 *   }
 *   API_END();
 * }
 *
 * XGB_DLL int XGBoosterSaveRabitCheckpoint(BoosterHandle handle) {
 *   API_BEGIN();
 *   CHECK_HANDLE();
 *   auto* bst = static_cast<Booster*>(handle);
 *   if (bst->learner()->AllowLazyCheckPoint()) {
 *     rabit::LazyCheckPoint(bst->learner());
 *   } else {
 *     rabit::CheckPoint(bst->learner());
 *   }
 *   API_END();
 * }
 *
 * [> hidden method; only known to C++ test suite <]
 * const std::map<std::string, std::string>&
 * QueryBoosterConfigurationArguments(BoosterHandle handle) {
 *   CHECK_HANDLE();
 *   auto* bst = static_cast<Booster*>(handle);
 *   bst->LazyInit();
 *   return bst->learner()->GetConfigurationArguments();
 * }
 */

// force link rabit
static DMLC_ATTRIBUTE_UNUSED int XGBOOST_LINK_RABIT_C_API_ = RabitLinkTag();


int ocall_rabit__GetRank() {
    return rabit::GetRank();
}

int ocall_rabit__GetWorldSize() {
    return rabit::GetWorldSize();
}

int ocall_rabit__IsDistributed() {
    return rabit::IsDistributed();
}

XGB_DLL int get_remote_report_with_pubkey_and_nonce(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** nonce,
    size_t* nonce_size,
    uint8_t** remote_report,
    size_t* remote_report_size) {
  safe_ecall(enclave_get_remote_report_with_pubkey_and_nonce(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, pem_key, key_size, nonce, nonce_size, remote_report, remote_report_size));
}

bool verify_mrsigner(
    char* siging_public_key_buf,
    size_t siging_public_key_buf_size,
    uint8_t* signer_id_buf,
    size_t signer_id_buf_size) {
  mbedtls_pk_context ctx;
  mbedtls_pk_type_t pk_type;
  mbedtls_rsa_context* rsa_ctx = NULL;
  uint8_t* modulus = NULL;
  size_t modulus_size = 0;
  int res = 0;
  bool ret = false;
  unsigned char* signer = NULL;

  signer = (unsigned char*)malloc(signer_id_buf_size);
  if (signer == NULL) {
    printf("Out of memory\n");
    goto exit;
  }

  mbedtls_pk_init(&ctx);
  res = mbedtls_pk_parse_public_key(
      &ctx,
      (const unsigned char*)siging_public_key_buf,
      siging_public_key_buf_size);
  if (res != 0) {
    printf("mbedtls_pk_parse_public_key failed with %d\n", res);
    goto exit;
  }

  pk_type = mbedtls_pk_get_type(&ctx);
  if (pk_type != MBEDTLS_PK_RSA) {
    printf("mbedtls_pk_get_type had incorrect type: %d\n", res);
    goto exit;
  }

  rsa_ctx = mbedtls_pk_rsa(ctx);
  modulus_size = mbedtls_rsa_get_len(rsa_ctx);
  modulus = (uint8_t*)malloc(modulus_size);
  if (modulus == NULL) {
    printf("malloc for modulus failed with size %zu:\n", modulus_size);
    goto exit;
  }

  res = mbedtls_rsa_export_raw(
      rsa_ctx, modulus, modulus_size, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
  if (res != 0) {
    printf("mbedtls_rsa_export failed with %d\n", res);
    goto exit;
  }

  // Reverse the modulus and compute sha256 on it.
  for (size_t i = 0; i < modulus_size / 2; i++) {
    uint8_t tmp = modulus[i];
    modulus[i] = modulus[modulus_size - 1 - i];
    modulus[modulus_size - 1 - i] = tmp;
  }

  // Calculate the MRSIGNER value which is the SHA256 hash of the
  // little endian representation of the public key modulus. This value
  // is populated by the signer_id sub-field of a parsed oe_report_t's
  // identity field.
  if (compute_sha256(modulus, modulus_size, signer) != 0) {
    goto exit;
  }

  if (memcmp(signer, signer_id_buf, signer_id_buf_size) != 0) {
    printf("mrsigner is not equal!\n");
    for (int i = 0; i < signer_id_buf_size; i++) {
      printf(
          "0x%x - 0x%x\n", (uint8_t)signer[i], (uint8_t)signer_id_buf[i]);
    }
    goto exit;
  }

  ret = true;

exit:
  if (signer)
    free(signer);

  if (modulus != NULL)
    free(modulus);

  mbedtls_pk_free(&ctx);
  return ret;
}
/**
 * Attest the given remote report and accompanying data. It consists of the
 * following three steps:
 *
 * 1) The remote report is first attested using the oe_verify_report API. This
 * ensures the authenticity of the enclave that generated the remote report.
 * 2) Next, to establish trust of the enclave that  generated the remote report,
 * the mrsigner, product_id, isvsvn values are checked to  see if they are
 * predefined trusted values.
 * 3) Once the enclave's trust has been established, the validity of
 * accompanying data is ensured by comparing its SHA256 digest against the
 * report_data field.
 */
bool attest_remote_report(
    const uint8_t* remote_report,
    size_t remote_report_size,
    const uint8_t* data,
    size_t data_size) {
  bool ret = false;
  uint8_t sha256[32];
  oe_report_t parsed_report = {0};
  oe_result_t result = OE_OK;

  // 1)  Validate the report's trustworthiness
  // Verify the remote report to ensure its authenticity.
  result = oe_verify_report(NULL, remote_report, remote_report_size, &parsed_report);
  if (result != OE_OK) {
    LOG(FATAL) << "Remote attestation failed. Remote report verification failed.";
  }

  // 2) validate the enclave identity's signed_id is the hash of the public
  // signing key that was used to sign an enclave. Check that the enclave was
  // signed by an trusted entity.
  if (!verify_mrsigner(
        (char*)MRSIGNER_PUBLIC_KEY,
        sizeof(MRSIGNER_PUBLIC_KEY),
        parsed_report.identity.signer_id,
        sizeof(parsed_report.identity.signer_id))) {
    LOG(FATAL) << "Remote attestation failed. MRSIGNER value not equal."; 
  }

  //FIXME add verification for mrenclave

  // check the enclave's product id and security version
  // see enc.conf for values specified when signing the enclave.
  if (parsed_report.identity.product_id[0] != 1) {
    LOG(FATAL) << "Remote attestation failed. Enclave product ID check failed.";
  }

  if (parsed_report.identity.security_version < 1) {
    LOG(FATAL) << "Remote attestation failed. Enclave security version check failed.";
  }

  // 3) Validate the report data
  //    The report_data has the hash value of the report data
  if (compute_sha256(data, data_size, sha256) != 0) {
    LOG(FATAL) << "Remote attestation failed. Report data hash validation failed. There is likely a client list mismatch.";
  }

  if (memcmp(parsed_report.report_data, sha256, sizeof(sha256)) != 0) {
    LOG(FATAL) << "Remote attestation failed. SHA256 mismatch.";
  }
  return true;
}

XGB_DLL int verify_remote_report_and_set_pubkey(
    uint8_t* pem_key,
    size_t pem_key_size,
    uint8_t* remote_report,
    size_t remote_report_size) {
  API_BEGIN();
  // Attest the remote report and accompanying key.
  size_t data_size = pem_key_size;
  uint8_t data[pem_key_size];
  memcpy(data, pem_key, pem_key_size);
  attest_remote_report(remote_report, remote_report_size, data, data_size);
  API_END();
}

XGB_DLL int verify_remote_report_and_set_pubkey_and_nonce(
    uint8_t* pem_key,
    size_t key_size,
    uint8_t* nonce,
    size_t nonce_size,
    char** usernames,
    size_t num_users,
    uint8_t* remote_report,
    size_t remote_report_size) {
  API_BEGIN();
  // Attest the remote report and accompanying key.
  size_t total_len = 0;
  for (int i = 0; i < num_users; i++) {
    total_len += strlen(usernames[i]) + 1;
  }

  size_t report_data_size = key_size + nonce_size + total_len;
  uint8_t report_data[report_data_size];
  memcpy(report_data, pem_key, CIPHER_PK_SIZE);
  memcpy(report_data + CIPHER_PK_SIZE, nonce, CIPHER_IV_SIZE);
  uint8_t* ptr = report_data + CIPHER_PK_SIZE + CIPHER_IV_SIZE;
  for (int i = 0; i < num_users; i++) {
    size_t len = strlen(usernames[i]) + 1;
    memcpy(ptr, usernames[i], len);
    ptr += len;
  }
  attest_remote_report(remote_report, remote_report_size, report_data, report_data_size);
  API_END();
}

XGB_DLL int add_client_key_with_certificate(char * cert,int cert_len, uint8_t* data, size_t data_len, uint8_t* signature, size_t sig_len) {
  safe_ecall(enclave_add_client_key_with_certificate(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret,cert,cert_len,data, data_len, signature, sig_len));
}

XGB_DLL int get_enclave_symm_key(char *username, uint8_t** out, size_t* out_size) {
  safe_ecall(enclave_get_enclave_symm_key(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, username, out, out_size));
}

XGB_DLL int verify_signature(uint8_t* pem_key, size_t key_size, uint8_t* data, size_t data_len, uint8_t* signature, size_t sig_len) {
  API_BEGIN();
  int res = -1;
  mbedtls_pk_context m_pk_context;
  mbedtls_pk_init(&m_pk_context);

  // Read the given public key.
  res = mbedtls_pk_parse_public_key(&m_pk_context, pem_key, key_size);
  if (res != 0) {
    mbedtls_pk_free(&m_pk_context);
    LOG(FATAL) << "mbedtls_pk_parse_public_key failed.";
  }

  verifySignature(m_pk_context, data, data_len, signature, sig_len);
  mbedtls_pk_free( &m_pk_context );
  API_END();
}


XGB_DLL int encrypt_data_with_pk(char* data, size_t len, uint8_t* pem_key, size_t key_size, uint8_t* encrypted_data, size_t* encrypted_data_size) {
  API_BEGIN();
  bool result = false;
  mbedtls_pk_context key;
  int res = -1;

  mbedtls_ctr_drbg_context m_ctr_drbg_context;
  mbedtls_entropy_context m_entropy_context;
  mbedtls_pk_context m_pk_context;
  mbedtls_ctr_drbg_init(&m_ctr_drbg_context);
  mbedtls_entropy_init(&m_entropy_context);
  mbedtls_pk_init(&m_pk_context);
  res = mbedtls_ctr_drbg_seed(
      &m_ctr_drbg_context, mbedtls_entropy_func, &m_entropy_context, NULL, 0);
  res = mbedtls_pk_setup(
      &m_pk_context, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

  mbedtls_rsa_context* rsa_context;

  mbedtls_pk_init(&key);

  // Read the given public key.
  key_size = strlen((const char*)pem_key) + 1; // Include ending '\0'.
  res = mbedtls_pk_parse_public_key(&key, pem_key, key_size);

  if (res != 0) {
    mbedtls_pk_free(&key);
    LOG(FATAL) << "mbedtls_pk_parse_public_key failed.";
  }

  rsa_context = mbedtls_pk_rsa(key);
  rsa_context->padding = MBEDTLS_RSA_PKCS_V21;
  rsa_context->hash_id = MBEDTLS_MD_SHA256;

  // Encrypt the data.
  res = mbedtls_rsa_pkcs1_encrypt(
      rsa_context,
      //mbedtls_pk_rsa(key),
      mbedtls_ctr_drbg_random,
      &m_ctr_drbg_context,
      MBEDTLS_RSA_PUBLIC,
      len,
      (const unsigned char*) data,
      (unsigned char*) encrypted_data);
  if (res != 0) {
    mbedtls_pk_free(&key);
    LOG(FATAL) << "mbedtls_rsa_pkcs1_encrypt failed.";
  }

  *encrypted_data_size = mbedtls_pk_rsa(key)->len;

  mbedtls_pk_free( &m_pk_context );
  mbedtls_ctr_drbg_free( &m_ctr_drbg_context );
  mbedtls_entropy_free( &m_entropy_context );
  API_END();
}

XGB_DLL int sign_data_with_keyfile(char *keyfile, uint8_t* data, size_t data_size, uint8_t* signature, size_t* sig_len) {
  API_BEGIN();
  mbedtls_pk_context pk;
  mbedtls_pk_init( &pk );

  int ret;
  if((ret = mbedtls_pk_parse_keyfile( &pk, keyfile, "")) != 0) {
    LOG(FATAL) << "signing failed -- mbedtls_pk_parse_public_keyfile returned " << ret;
  }

  ret = sign_data(pk, data, data_size, signature, sig_len);
  API_END();
}

XGB_DLL int decrypt_predictions(char* key, uint8_t* encrypted_preds, size_t num_preds, bst_float** preds) {
    API_BEGIN();
    size_t len = num_preds*sizeof(float);
    unsigned char* iv = (unsigned char*)encrypted_preds;
    unsigned char* tag = iv + CIPHER_IV_SIZE;
    unsigned char* data = tag + CIPHER_TAG_SIZE;
    unsigned char* output = (unsigned char*) malloc(len);

    decrypt_symm(
            (uint8_t*) key,
            data,
            len,
            iv,
            tag,
            NULL,
            0,
            output);
    *preds = reinterpret_cast<float*>(output);
    API_END();
}

XGB_DLL int decrypt_enclave_key(char* key, uint8_t* encrypted_key, size_t len, uint8_t** out_key) {
  API_BEGIN();
  unsigned char* iv = (unsigned char*)encrypted_key;
  unsigned char* tag = iv + CIPHER_IV_SIZE;
  unsigned char* data = tag + CIPHER_TAG_SIZE;
  unsigned char* output = (unsigned char*) malloc(len);

  decrypt_symm(
      (uint8_t*) key,
      data,
      len,
      iv,
      tag,
      NULL,
      0,
      output);
  *out_key = reinterpret_cast<uint8_t*>(output);
  API_END();
}

XGB_DLL int decrypt_dump(char* key, char** models, xgboost::bst_ulong length) {
  API_BEGIN();
  mbedtls_gcm_context gcm;


  mbedtls_gcm_init(&gcm);
  int ret = mbedtls_gcm_setkey(&gcm,      // GCM context to be initialized
          MBEDTLS_CIPHER_ID_AES,          // cipher to use (a 128-bit block cipher)
          (const unsigned char*) key,     // encryption key
          CIPHER_KEY_SIZE * 8);           // key bits (must be 128, 192, or 256)
  if (ret != 0) {
    LOG(FATAL) << "mbedtls_gcm_setkey failed to set the key for AES cipher - returned " << -ret;
  }

  const char* total_encrypted;
  int out_len;
  for (int i = 0; i < length; i++) {
    total_encrypted = models[i];

    char* p = const_cast<char*>(total_encrypted);
    int iv_pos = 0;
    while(*p != '\0' && *p != ',') {
        p++;
        iv_pos++;
    }
    p++;
    int tag_pos = iv_pos + 1;
    while(*p != '\0' && *p != ',') {
        p++;
        tag_pos++;
    }
    size_t out_len;
    unsigned char tag[CIPHER_TAG_SIZE];
    unsigned char iv[CIPHER_IV_SIZE];

    char* ct = (char *) malloc(strlen(total_encrypted) * sizeof(char));

    out_len = dmlc::data::base64_decode(total_encrypted, iv_pos, (char *) iv);
    out_len = dmlc::data::base64_decode(total_encrypted + iv_pos + 1, tag_pos - iv_pos, (char *) tag);
    out_len = dmlc::data::base64_decode(total_encrypted + tag_pos + 1, strlen(total_encrypted) - tag_pos, ct);

    unsigned char* decrypted = (unsigned char*) malloc((out_len + 1) * sizeof(char));
    int ret = decrypt_symm(
            &gcm,
            (const unsigned char*) ct,
            out_len,
            iv,
            tag,
            NULL,
            0,
            decrypted
            );
    decrypted[out_len] = '\0';
    free(ct);
    if (ret != 0) {
      LOG(FATAL) << "mbedtls_gcm_auth_decrypt failed with error " << -ret;
    }
    models[i] = (char*) decrypted;
  }
  API_END();
}

// Input, output, key
XGB_DLL int encrypt_file(char* fname, char* e_fname, char* k_fname) {
    API_BEGIN();
    char key[CIPHER_KEY_SIZE];
    std::ifstream keyfile;
    keyfile.open(k_fname);
    keyfile.read(key, CIPHER_KEY_SIZE);
    keyfile.close();
    encrypt_file_with_keybuf(fname, e_fname, key);
    API_END();
}

XGB_DLL int encrypt_file_with_keybuf(char* fname, char* e_fname, char* key) {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_gcm_context gcm;

    unsigned char iv[CIPHER_IV_SIZE];
    unsigned char tag[CIPHER_TAG_SIZE];

    // Initialize the entropy pool and the random source
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    // Initialize GCM context (just makes references valid) - makes the context ready for mbedtls_gcm_setkey()
    mbedtls_gcm_init(&gcm);
    // The personalization string should be unique to your application in order to add some
    // personalized starting randomness to your random sources.
    std::string pers = "aes generate key for MC^2";
    // CTR_DRBG initial seeding Seed and setup entropy source for future reseeds
    int ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)pers.c_str(), pers.length() );
    if( ret != 0 )
    {
        LOG(FATAL) << "mbedtls_ctr_drbg_seed() failed - returned " << -ret;
    }

    // Initialize the GCM context with our key and desired cipher
    ret = mbedtls_gcm_setkey(&gcm,     // GCM context to be initialized
            MBEDTLS_CIPHER_ID_AES,     // cipher to use (a 128-bit block cipher)
            (unsigned char*) key,      // encryption key
            CIPHER_KEY_SIZE * 8);      // key bits (must be 128, 192, or 256)
    if( ret != 0 ) {
        LOG(FATAL) << "mbedtls_gcm_setkey failed to set the key for AES cipher - returned " << -ret;
    }

    std::ifstream infile(fname);
    std::ofstream myfile;
    myfile.open(e_fname);

    std::string line;
    uint64_t index = 0;
    uint64_t total = 0;

    // Count total number of lines in file
    while (std::getline(infile, line)) {
      // Ignore empty lines
      if (std::all_of(line.begin(), line.end(), isspace))
        continue;
      total++;
    }
    infile.close();

    infile.open(fname);
    while (std::getline(infile, line)) {
        // Ignore empty lines
        if (std::all_of(line.begin(), line.end(), isspace))
            continue;

        index++;
        size_t length = strlen(line.c_str());

        // We use `<index>,<total>` as additional authenticated data to prevent tampering across lines
        std::stringstream ss;
        ss << index << "," << total;
        std::string ss_str = ss.str();

        unsigned char* encrypted = (unsigned char*) malloc(length*sizeof(char));
        ret = encrypt_symm(
                &gcm,
                &ctr_drbg,
                (const unsigned char*)line.c_str(),
                length,
                (unsigned char*)ss_str.c_str(),
                ss_str.length(),
                encrypted,
                iv,
                tag
                );
        if( ret != 0 ) {
            LOG(FATAL) << "mbedtls_gcm_crypt_and_tag failed to encrypt the data - returned " << -ret;
        }
        std::string encoded = dmlc::data::base64_encode(iv, CIPHER_IV_SIZE);
        myfile
            << index << ","
            << total << ","
            << dmlc::data::base64_encode(iv, CIPHER_IV_SIZE) << ","
            << dmlc::data::base64_encode(tag, CIPHER_TAG_SIZE) << ","
            << dmlc::data::base64_encode(encrypted, length) << "\n";
        free(encrypted);
    }
    infile.close();
    myfile.close();
}

XGB_DLL int decrypt_file_with_keybuf(char* fname, char* d_fname, char* key) {
    API_BEGIN();
    mbedtls_gcm_context gcm;

    // Initialize GCM context (just makes references valid) - makes the context ready for mbedtls_gcm_setkey()
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm,      // GCM context to be initialized
            MBEDTLS_CIPHER_ID_AES,          // cipher to use (a 128-bit block cipher)
            (const unsigned char*)key,      // encryption key
            CIPHER_KEY_SIZE * 8);           // key bits (must be 128, 192, or 256)
    if( ret != 0 ) {
        LOG(FATAL) << "mbedtls_gcm_setkey failed to set the key for AES cipher - returned " << -ret;
    }

    std::ifstream infile(fname);
    std::ofstream myfile;
    myfile.open(d_fname);

    std::string line;
    while (std::getline(infile, line)) {
        const char* data = line.c_str();
        int index_pos = 0;
        int total_pos = 0;
        int iv_pos = 0;
        int tag_pos = 0;
        int len = line.length();

        for (int i = 0; i < len; i++) {
          if (data[i] == ',') {
            index_pos = i;
            break;
          }
        }
        for (int i = index_pos + 1; i < len; i++) {
          if (data[i] == ',') {
            total_pos = i;
            break;
          }
        }
        for (int i = total_pos + 1; i < len; i++) {
          if (data[i] == ',') {
            iv_pos = i;
            break;
          }
        }
        for (int i = iv_pos + 1; i < len; i++) {
          if (data[i] == ',') {
            tag_pos = i;
            break;
          }
        }
        CHECK_LT(0, index_pos);
        CHECK_LT(index_pos, total_pos);
        CHECK_LT(total_pos, iv_pos);
        CHECK_LT(iv_pos, tag_pos);

        char *aad_str = (char*) malloc (total_pos + 1);
        memcpy(aad_str, data, total_pos);
        aad_str[total_pos] = 0;

        size_t out_len;
        char tag[CIPHER_TAG_SIZE];
        char iv[CIPHER_IV_SIZE];

        char* ct = (char *) malloc(line.size() * sizeof(char));

        out_len = dmlc::data::base64_decode(data + total_pos + 1, iv_pos - total_pos, iv);
        CHECK_EQ(out_len, CIPHER_IV_SIZE);
        out_len = dmlc::data::base64_decode(data + iv_pos + 1, tag_pos - iv_pos, tag);
        CHECK_EQ(out_len, CIPHER_TAG_SIZE);
        out_len = dmlc::data::base64_decode(data + tag_pos + 1, line.size() - tag_pos, ct);

        unsigned char* decrypted = (unsigned char*) malloc((out_len + 1) * sizeof(char));
        int ret = decrypt_symm(
                &gcm,
                (const unsigned char*)ct,
                out_len,
                (unsigned char*)iv,
                (unsigned char*)tag,
                (unsigned char*)aad_str,
                strlen(aad_str),
                decrypted);
        decrypted[out_len] = '\0';
        free(ct);
        if (ret != 0) {
            LOG(FATAL) << "mbedtls_gcm_auth_decrypt failed with error " << -ret;
        }
        myfile << decrypted << "\n";
    }
    infile.close();
    myfile.close();
    API_END();
}
