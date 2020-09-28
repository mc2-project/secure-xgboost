// Copyright (c) 2014-2020 by Contributors
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
#include "xgboost/c_api.h"
#include "xgboost/logging.h"
#include "xgboost/version_config.h"
#include "xgboost/json.h"

#include "xgboost/c_api/c_api_error.h"
#include "../enclave/src/common/io.h"
#include "../enclave/src/data/adapter.h"
#include "../enclave/src/data/simple_dmatrix.h"
#include "../enclave/src/data/proxy_dmatrix.h"

#include <openenclave/host.h>
#include "xgboost_u.h"
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
														char* username,
                            int silent,
                            DMatrixHandle *out) {
    safe_ecall(enclave_XGDMatrixCreateFromFile(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, fname, username, silent, out));
}

int XGDMatrixCreateFromEncryptedFile(const char *fnames[],
                                     char* usernames[],
                                     xgboost::bst_ulong num_files,
                                     int silent,
                                     DMatrixHandle *out) {
    size_t fname_lengths[num_files];
    size_t username_lengths[num_files];

    get_str_lengths((char**)fnames, num_files, fname_lengths);
    get_str_lengths(usernames, num_files, username_lengths);

    safe_ecall(enclave_XGDMatrixCreateFromEncryptedFile(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, (const char**) fnames, fname_lengths, usernames, username_lengths, num_files, silent, out));
}

/*
 *XGB_DLL int XGDMatrixCreateFromDataIter(
 *    void *data_handle,                  // a Java iterator
 *    XGBCallbackDataIterNext *callback,  // C++ callback defined in xgboost4j.cpp
 *    const char *cache_info, DMatrixHandle *out) {
 *  API_BEGIN();
 *
 *  std::string scache;
 *  if (cache_info != nullptr) {
 *    scache = cache_info;
 *  }
 *  xgboost::data::IteratorAdapter<DataIterHandle, XGBCallbackDataIterNext,
 *                                 XGBoostBatchCSR> adapter(data_handle, callback);
 *  *out = new std::shared_ptr<DMatrix> {
 *    DMatrix::Create(
 *        &adapter, std::numeric_limits<float>::quiet_NaN(),
 *        1, scache
 *    )
 *  };
 *  API_END();
 *}
 *
 *#ifndef XGBOOST_USE_CUDA
 *XGB_DLL int XGDMatrixCreateFromArrayInterfaceColumns(char const* c_json_strs,
 *                                                     bst_float missing,
 *                                                     int nthread,
 *                                                     DMatrixHandle* out) {
 *  API_BEGIN();
 *  common::AssertGPUSupport();
 *  API_END();
 *}
 *
 *XGB_DLL int XGDMatrixCreateFromArrayInterface(char const* c_json_strs,
 *                                              bst_float missing,
 *                                              int nthread,
 *                                              DMatrixHandle* out) {
 *  API_BEGIN();
 *  common::AssertGPUSupport();
 *  API_END();
 *}
 *
 *#endif
 *
 * // Create from data iterator
 *XGB_DLL int XGProxyDMatrixCreate(DMatrixHandle* out) {
 *  API_BEGIN();
 *  *out = new std::shared_ptr<xgboost::DMatrix>(new xgboost::data::DMatrixProxy);;
 *  API_END();
 *}
 *
 *XGB_DLL int
 *XGDeviceQuantileDMatrixSetDataCudaArrayInterface(DMatrixHandle handle,
 *                                                 char const *c_interface_str) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  auto p_m = static_cast<std::shared_ptr<xgboost::DMatrix> *>(handle);
 *  CHECK(p_m);
 *  auto m =   static_cast<xgboost::data::DMatrixProxy*>(p_m->get());
 *  CHECK(m) << "Current DMatrix type does not support set data.";
 *  m->SetData(c_interface_str);
 *  API_END();
 *}
 *
 *XGB_DLL int
 *XGDeviceQuantileDMatrixSetDataCudaColumnar(DMatrixHandle handle,
 *                                           char const *c_interface_str) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  auto p_m = static_cast<std::shared_ptr<xgboost::DMatrix> *>(handle);
 *  CHECK(p_m);
 *  auto m =   static_cast<xgboost::data::DMatrixProxy*>(p_m->get());
 *  CHECK(m) << "Current DMatrix type does not support set data.";
 *  m->SetData(c_interface_str);
 *  API_END();
 *}
 *
 *XGB_DLL int XGDeviceQuantileDMatrixCreateFromCallback(
 *    DataIterHandle iter, DMatrixHandle proxy, DataIterResetCallback *reset,
 *    XGDMatrixCallbackNext *next, float missing, int nthread,
 *    int max_bin, DMatrixHandle *out) {
 *  API_BEGIN();
 *  *out = new std::shared_ptr<xgboost::DMatrix>{
 *    xgboost::DMatrix::Create(iter, proxy, reset, next, missing, nthread, max_bin)};
 *  API_END();
 *}
 * // End Create from data iterator
 *
 *XGB_DLL int XGDMatrixCreateFromCSREx(const size_t* indptr,
 *                                     const unsigned* indices,
 *                                     const bst_float* data,
 *                                     size_t nindptr,
 *                                     size_t nelem,
 *                                     size_t num_col,
 *                                     DMatrixHandle* out) {
 *  API_BEGIN();
 *  data::CSRAdapter adapter(indptr, indices, data, nindptr - 1, nelem, num_col);
 *  *out = new std::shared_ptr<DMatrix>(DMatrix::Create(&adapter, std::nan(""), 1));
 *  API_END();
 *}
 *
 *XGB_DLL int XGDMatrixCreateFromCSCEx(const size_t* col_ptr,
 *                                     const unsigned* indices,
 *                                     const bst_float* data,
 *                                     size_t nindptr,
 *                                     size_t nelem,
 *                                     size_t num_row,
 *                                     DMatrixHandle* out) {
 *  API_BEGIN();
 *  data::CSCAdapter adapter(col_ptr, indices, data, nindptr - 1, num_row);
 *  *out = new std::shared_ptr<DMatrix>(DMatrix::Create(&adapter, std::nan(""), 1));
 *  API_END();
 *}
 *
 *XGB_DLL int XGDMatrixCreateFromMat(const bst_float* data,
 *                                   xgboost::bst_ulong nrow,
 *                                   xgboost::bst_ulong ncol, bst_float missing,
 *                                   DMatrixHandle* out) {
 *  API_BEGIN();
 *  data::DenseAdapter adapter(data, nrow, ncol);
 *  *out = new std::shared_ptr<DMatrix>(DMatrix::Create(&adapter, missing, 1));
 *  API_END();
 *}
 *
 *XGB_DLL int XGDMatrixCreateFromMat_omp(const bst_float* data,  // NOLINT
 *                                       xgboost::bst_ulong nrow,
 *                                       xgboost::bst_ulong ncol,
 *                                       bst_float missing, DMatrixHandle* out,
 *                                       int nthread) {
 *  API_BEGIN();
 *  data::DenseAdapter adapter(data, nrow, ncol);
 *  *out = new std::shared_ptr<DMatrix>(DMatrix::Create(&adapter, missing, nthread));
 *  API_END();
 *}
 *
 *XGB_DLL int XGDMatrixCreateFromDT(void** data, const char** feature_stypes,
 *                                  xgboost::bst_ulong nrow,
 *                                  xgboost::bst_ulong ncol, DMatrixHandle* out,
 *                                  int nthread) {
 *  API_BEGIN();
 *  data::DataTableAdapter adapter(data, feature_stypes, nrow, ncol);
 *  *out = new std::shared_ptr<DMatrix>(
 *      DMatrix::Create(&adapter, std::nan(""), nthread));
 *  API_END();
 *}
 *
 *XGB_DLL int XGDMatrixSliceDMatrix(DMatrixHandle handle,
 *                                  const int* idxset,
 *                                  xgboost::bst_ulong len,
 *                                  DMatrixHandle* out) {
 *  return XGDMatrixSliceDMatrixEx(handle, idxset, len, out, 0);
 *}
 *
 *XGB_DLL int XGDMatrixSliceDMatrixEx(DMatrixHandle handle,
 *                                    const int* idxset,
 *                                    xgboost::bst_ulong len,
 *                                    DMatrixHandle* out,
 *                                    int allow_groups) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  if (!allow_groups) {
 *    CHECK_EQ(static_cast<std::shared_ptr<DMatrix>*>(handle)
 *                 ->get()
 *                 ->Info()
 *                 .group_ptr_.size(),
 *             0U)
 *        << "slice does not support group structure";
 *  }
 *  DMatrix* dmat = static_cast<std::shared_ptr<DMatrix>*>(handle)->get();
 *  *out = new std::shared_ptr<DMatrix>(
 *      dmat->Slice({idxset, static_cast<std::size_t>(len)}));
 *  API_END();
 *}
 */

XGB_DLL int XGDMatrixFree(DMatrixHandle handle) {
  safe_ecall(enclave_XGDMatrixFree(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle));
}

/*
 *XGB_DLL int XGDMatrixSaveBinary(DMatrixHandle handle, const char* fname,
 *                                int silent) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  auto dmat = static_cast<std::shared_ptr<DMatrix>*>(handle)->get();
 *  if (data::SimpleDMatrix* derived = dynamic_cast<data::SimpleDMatrix*>(dmat)) {
 *    derived->SaveToLocalFile(fname);
 *  } else {
 *    LOG(FATAL) << "binary saving only supported by SimpleDMatrix";
 *  }
 *  API_END();
 *}
 */
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

/*
 *XGB_DLL int XGDMatrixSetInfoFromInterface(DMatrixHandle handle,
 *                                          char const* field,
 *                                          char const* interface_c_str) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  static_cast<std::shared_ptr<DMatrix>*>(handle)
 *      ->get()->Info().SetInfo(field, interface_c_str);
 *  API_END();
 *}
 */

/*
 *XGB_DLL int XGDMatrixSetStrFeatureInfo(DMatrixHandle handle, const char *field,
 *                                       const char **c_info,
 *                                       const xgboost::bst_ulong size) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  auto &info = static_cast<std::shared_ptr<DMatrix> *>(handle)->get()->Info();
 *  info.SetFeatureInfo(field, c_info, size);
 *  API_END();
 *}
 *
 *XGB_DLL int XGDMatrixGetStrFeatureInfo(DMatrixHandle handle, const char *field,
 *                                       xgboost::bst_ulong *len,
 *                                       const char ***out_features) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  auto m = *static_cast<std::shared_ptr<DMatrix>*>(handle);
 *  auto &info = static_cast<std::shared_ptr<DMatrix> *>(handle)->get()->Info();
 *
 *  std::vector<const char *> &charp_vecs = m->GetThreadLocal().ret_vec_charp;
 *  std::vector<std::string> &str_vecs = m->GetThreadLocal().ret_vec_str;
 *
 *  info.GetFeatureInfo(field, &str_vecs);
 *
 *  charp_vecs.resize(str_vecs.size());
 *  for (size_t i = 0; i < str_vecs.size(); ++i) {
 *    charp_vecs[i] = str_vecs[i].c_str();
 *  }
 *  *out_features = dmlc::BeginPtr(charp_vecs);
 *  *len = static_cast<xgboost::bst_ulong>(charp_vecs.size());
 *  API_END();
 *}
 *
 *XGB_DLL int XGDMatrixSetGroup(DMatrixHandle handle,
 *                              const unsigned* group,
 *                              xgboost::bst_ulong len) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  LOG(WARNING) << "XGDMatrixSetGroup is deprecated, use `XGDMatrixSetUIntInfo` instead.";
 *  static_cast<std::shared_ptr<DMatrix>*>(handle)
 *      ->get()->Info().SetInfo("group", group, xgboost::DataType::kUInt32, len);
 *  API_END();
 *}
 */

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
    xgboost::bst_ulong *out) {
  safe_ecall(enclave_XGDMatrixNumRow(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, out));
}

XGB_DLL int XGDMatrixNumCol(const DMatrixHandle handle,
    xgboost::bst_ulong *out) {
  safe_ecall(enclave_XGDMatrixNumCol(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, out));
}

// xgboost implementation
//
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
    result = oe_create_xgboost_enclave(
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
    BoosterHandle *out) {
  size_t handle_lengths[len];
  get_str_lengths((char**)dmats, len, handle_lengths);

  safe_ecall(enclave_XGBoosterCreate(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, const_cast<char**>(dmats), handle_lengths, len, out));
}

XGB_DLL int XGBoosterFree(BoosterHandle handle) {
  safe_ecall(enclave_XGBoosterFree(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle));
}

XGB_DLL int XGBoosterSetParam(BoosterHandle handle,
    const char *name,
    const char *value) {
  safe_ecall(enclave_XGBoosterSetParam(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, name, value));
}

/*
 *XGB_DLL int XGBoosterGetNumFeature(BoosterHandle handle,
 *                                   xgboost::bst_ulong *out) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  *out = static_cast<Learner*>(handle)->GetNumFeature();
 *  API_END();
 *}
 *
 *XGB_DLL int XGBoosterLoadJsonConfig(BoosterHandle handle, char const* json_parameters) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  std::string str {json_parameters};
 *  Json config { Json::Load(StringView{str.c_str(), str.size()}) };
 *  static_cast<Learner*>(handle)->LoadConfig(config);
 *  API_END();
 *}
 *
 *XGB_DLL int XGBoosterSaveJsonConfig(BoosterHandle handle,
 *                                    xgboost::bst_ulong *out_len,
 *                                    char const** out_str) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  Json config { Object() };
 *  auto* learner = static_cast<Learner*>(handle);
 *  learner->Configure();
 *  learner->SaveConfig(&config);
 *  std::string& raw_str = learner->GetThreadLocal().ret_str;
 *  Json::Dump(config, &raw_str);
 *  *out_str = raw_str.c_str();
 *  *out_len = static_cast<xgboost::bst_ulong>(raw_str.length());
 *  API_END();
 *}
 */

XGB_DLL int XGBoosterUpdateOneIter(BoosterHandle handle,
    int iter,
    DMatrixHandle dtrain) {
  safe_ecall(enclave_XGBoosterUpdateOneIter(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, iter, dtrain));
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
    xgboost::bst_ulong *len,
    uint8_t **out_result) {
  safe_ecall(enclave_XGBoosterPredict(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, dmat, option_mask, ntree_limit, training, len, out_result));
}

// A hidden API as cache id is not being supported yet.
/*
 *XGB_DLL int XGBoosterPredictFromDense(BoosterHandle handle, float *values,
 *                                      xgboost::bst_ulong n_rows,
 *                                      xgboost::bst_ulong n_cols,
 *                                      float missing,
 *                                      unsigned iteration_begin,
 *                                      unsigned iteration_end,
 *                                      char const* c_type,
 *                                      xgboost::bst_ulong cache_id,
 *                                      xgboost::bst_ulong *out_len,
 *                                      const float **out_result) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  CHECK_EQ(cache_id, 0) << "Cache ID is not supported yet";
 *  auto *learner = static_cast<xgboost::Learner *>(handle);
 *
 *  std::shared_ptr<xgboost::data::DenseAdapter> x{
 *    new xgboost::data::DenseAdapter(values, n_rows, n_cols)};
 *  HostDeviceVector<float>* p_predt { nullptr };
 *  std::string type { c_type };
 *  learner->InplacePredict(x, type, missing, &p_predt);
 *  CHECK(p_predt);
 *
 *  *out_result = dmlc::BeginPtr(p_predt->HostVector());
 *  *out_len = static_cast<xgboost::bst_ulong>(p_predt->Size());
 *  API_END();
 *}
 */

// A hidden API as cache id is not being supported yet.
/*
 *XGB_DLL int XGBoosterPredictFromCSR(BoosterHandle handle,
 *                                    const size_t* indptr,
 *                                    const unsigned* indices,
 *                                    const bst_float* data,
 *                                    size_t nindptr,
 *                                    size_t nelem,
 *                                    size_t num_col,
 *                                    float missing,
 *                                    unsigned iteration_begin,
 *                                    unsigned iteration_end,
 *                                    char const *c_type,
 *                                    xgboost::bst_ulong cache_id,
 *                                    xgboost::bst_ulong *out_len,
 *                                    const float **out_result) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  CHECK_EQ(cache_id, 0) << "Cache ID is not supported yet";
 *  auto *learner = static_cast<xgboost::Learner *>(handle);
 *
 *  std::shared_ptr<xgboost::data::CSRAdapter> x{
 *    new xgboost::data::CSRAdapter(indptr, indices, data, nindptr - 1, nelem, num_col)};
 *  HostDeviceVector<float>* p_predt { nullptr };
 *  std::string type { c_type };
 *  learner->InplacePredict(x, type, missing, &p_predt);
 *  CHECK(p_predt);
 *
 *  *out_result = dmlc::BeginPtr(p_predt->HostVector());
 *  *out_len = static_cast<xgboost::bst_ulong>(p_predt->Size());
 *  API_END();
 *}
 *
 *#if !defined(XGBOOST_USE_CUDA)
 *XGB_DLL int XGBoosterPredictFromArrayInterfaceColumns(BoosterHandle handle,
 *                                                      char const* c_json_strs,
 *                                                      float missing,
 *                                                      unsigned iteration_begin,
 *                                                      unsigned iteration_end,
 *                                                      char const* c_type,
 *                                                      xgboost::bst_ulong cache_id,
 *                                                      xgboost::bst_ulong *out_len,
 *                                                      float const** out_result) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  common::AssertGPUSupport();
 *  API_END();
 *}
 *XGB_DLL int XGBoosterPredictFromArrayInterface(BoosterHandle handle,
 *                                               char const* c_json_strs,
 *                                               float missing,
 *                                               unsigned iteration_begin,
 *                                               unsigned iteration_end,
 *                                               char const* c_type,
 *                                               xgboost::bst_ulong cache_id,
 *                                               xgboost::bst_ulong *out_len,
 *                                               const float **out_result) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  common::AssertGPUSupport();
 *  API_END();
 *}
 *#endif  // !defined(XGBOOST_USE_CUDA)
 */

XGB_DLL int XGBoosterLoadModel(BoosterHandle handle, const char* fname) {
  safe_ecall(enclave_XGBoosterLoadModel(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, fname));
}

XGB_DLL int XGBoosterSaveModel(BoosterHandle handle, const char* fname)  {
  safe_ecall(enclave_XGBoosterSaveModel(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, fname));
}

XGB_DLL int XGBoosterLoadModelFromBuffer(BoosterHandle handle,
    const void* buf,
    xgboost::bst_ulong len) {
  safe_ecall(enclave_XGBoosterLoadModelFromBuffer(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, buf, len));
}

XGB_DLL int XGBoosterGetModelRaw(BoosterHandle handle,
    bst_ulong *out_len,
    const char **out_dptr) {
  safe_ecall(enclave_XGBoosterGetModelRaw(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, out_len, (char**)out_dptr));
}

// The following two functions are `Load` and `Save` for memory based
// serialization methods. E.g. Python pickle.
/*
 *XGB_DLL int XGBoosterSerializeToBuffer(BoosterHandle handle,
 *                                       xgboost::bst_ulong *out_len,
 *                                       const char **out_dptr) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  auto *learner = static_cast<Learner*>(handle);
 *  std::string &raw_str = learner->GetThreadLocal().ret_str;
 *  raw_str.resize(0);
 *  common::MemoryBufferStream fo(&raw_str);
 *  learner->Configure();
 *  learner->Save(&fo);
 *  *out_dptr = dmlc::BeginPtr(raw_str);
 *  *out_len = static_cast<xgboost::bst_ulong>(raw_str.length());
 *  API_END();
 *}
 *
 *XGB_DLL int XGBoosterUnserializeFromBuffer(BoosterHandle handle,
 *                                           const void *buf,
 *                                           xgboost::bst_ulong len) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  common::MemoryFixSizeBuffer fs((void*)buf, len);  // NOLINT(*)
 *  static_cast<Learner*>(handle)->Load(&fs);
 *  API_END();
 *}
 */

/*
 *XGB_DLL int XGBoosterLoadRabitCheckpoint(BoosterHandle handle,
 *                                         int* version) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  auto* bst = static_cast<Learner*>(handle);
 *  *version = rabit::LoadCheckPoint(bst);
 *  if (*version != 0) {
 *    bst->Configure();
 *  }
 *  API_END();
 *}
 *
 *XGB_DLL int XGBoosterSaveRabitCheckpoint(BoosterHandle handle) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  auto* learner = static_cast<Learner*>(handle);
 *  learner->Configure();
 *  if (learner->AllowLazyCheckPoint()) {
 *    rabit::LazyCheckPoint(learner);
 *  } else {
 *    rabit::CheckPoint(learner);
 *  }
 *  API_END();
 *}
 */

/*
 *inline void XGBoostDumpModelImpl(BoosterHandle handle, const FeatureMap &fmap,
 *                                 int with_stats, const char *format,
 *                                 xgboost::bst_ulong *len,
 *                                 const char ***out_models) {
 *  auto *bst = static_cast<Learner*>(handle);
 *  std::vector<std::string>& str_vecs = bst->GetThreadLocal().ret_vec_str;
 *  std::vector<const char*>& charp_vecs = bst->GetThreadLocal().ret_vec_charp;
 *  str_vecs = bst->DumpModel(fmap, with_stats != 0, format);
 *  charp_vecs.resize(str_vecs.size());
 *  for (size_t i = 0; i < str_vecs.size(); ++i) {
 *    charp_vecs[i] = str_vecs[i].c_str();
 *  }
 *  *out_models = dmlc::BeginPtr(charp_vecs);
 *  *len = static_cast<xgboost::bst_ulong>(charp_vecs.size());
 *}
 */

XGB_DLL int XGBoosterDumpModel(BoosterHandle handle,
    const char* fmap,
    int with_stats,
    xgboost::bst_ulong* len,
    const char*** out_models) {
  safe_ecall(enclave_XGBoosterDumpModel(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, fmap, with_stats, len, (char***) out_models));
}

XGB_DLL int XGBoosterDumpModelEx(BoosterHandle handle,
    const char* fmap,
    int with_stats,
    const char *format,
    xgboost::bst_ulong* len,
    const char*** out_models) {
  safe_ecall(enclave_XGBoosterDumpModelEx(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, fmap, with_stats, format, len, (char***) out_models));
}


XGB_DLL int XGBoosterDumpModelWithFeatures(BoosterHandle handle,
    int fnum,
    const char** fname,
    const char** ftype,
    int with_stats,
    xgboost::bst_ulong* len,
    const char*** out_models) {
  size_t fname_lengths[fnum];
  size_t ftype_lengths[fnum];

  get_str_lengths((char**)fname, fnum, fname_lengths);
  get_str_lengths((char**)ftype, fnum, ftype_lengths);

  safe_ecall(enclave_XGBoosterDumpModelWithFeatures(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, (unsigned int) fnum, fname, fname_lengths, ftype, ftype_lengths, with_stats, len, (char***) out_models));
}

XGB_DLL int XGBoosterDumpModelExWithFeatures(BoosterHandle handle,
    int fnum,
    const char** fname,
    const char** ftype,
    int with_stats,
    const char *format,
    xgboost::bst_ulong* len,
    const char*** out_models) {
  size_t fname_lengths[fnum];
  size_t ftype_lengths[fnum];

  get_str_lengths((char**)fname, fnum, fname_lengths);
  get_str_lengths((char**)ftype, fnum, ftype_lengths);

  safe_ecall(enclave_XGBoosterDumpModelExWithFeatures(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, (unsigned int) fnum, fname, fname_lengths, ftype, ftype_lengths, with_stats, format, len, (char***) out_models));
}


XGB_DLL int XGBoosterGetAttr(BoosterHandle handle,
    const char* key,
    const char** out,
    int* success) {
  safe_ecall(enclave_XGBoosterGetAttr(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, key, (char**)out, success));
}

/*
 *XGB_DLL int XGBoosterSetAttr(BoosterHandle handle,
 *                             const char* key,
 *                             const char* value) {
 *  API_BEGIN();
 *  CHECK_HANDLE();
 *  auto* bst = static_cast<Learner*>(handle);
 *  if (value == nullptr) {
 *    bst->DelAttr(key);
 *  } else {
 *    bst->SetAttr(key, value);
 *  }
 *  API_END();
 *}
 */

XGB_DLL int XGBoosterGetAttrNames(BoosterHandle handle,
                                  xgboost::bst_ulong* out_len,
                                  const char*** out) {
  safe_ecall(enclave_XGBoosterGetAttrNames(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, out_len, (char***)out));
}

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
    std::cout << "oe_verify_report failed " << oe_result_str(result) << std::endl;
    goto exit;
  }

  // 2) validate the enclave identity's signed_id is the hash of the public
  // signing key that was used to sign an enclave. Check that the enclave was
  // signed by an trusted entity.
  if (!verify_mrsigner(
        (char*)MRSIGNER_PUBLIC_KEY,
        sizeof(MRSIGNER_PUBLIC_KEY),
        parsed_report.identity.signer_id,
        sizeof(parsed_report.identity.signer_id))) {
    std::cout << "failed:mrsigner not equal!" << std::endl;
    goto exit;
  }

  //FIXME add verification for mrenclave

  // check the enclave's product id and security version
  // see enc.conf for values specified when signing the enclave.
  if (parsed_report.identity.product_id[0] != 1) {
    std::cout << "identity.product_id checking failed." << std::endl;
    goto exit;
  }

  if (parsed_report.identity.security_version < 1) {
    std::cout << "identity.security_version checking failed." << std::endl;
    goto exit;
  }

  // 3) Validate the report data
  //    The report_data has the hash value of the report data
  if (compute_sha256(data, data_size, sha256) != 0) {
    std::cout << "hash validation failed." << std::endl;
    goto exit;
  }

  if (memcmp(parsed_report.report_data, sha256, sizeof(sha256)) != 0) {
    std::cout << "SHA256 mismatch." << std::endl;
    goto exit;
  }
  ret = true;
  std::cout << "remote attestation succeeded." << std::endl;
exit:
  return ret;
}

XGB_DLL int verify_remote_report_and_set_pubkey(
    uint8_t* pem_key,
    size_t pem_key_size,
    uint8_t* remote_report,
    size_t remote_report_size) {
  // Attest the remote report and accompanying key.
  size_t data_size = pem_key_size;
  uint8_t data[pem_key_size];
  memcpy(data, pem_key, pem_key_size);
  if (!attest_remote_report(remote_report, remote_report_size, data, data_size)) {
    std::cout << "verify_report_and_set_pubkey failed." << std::endl;
    return -1;
  } else {
    std::cout << "verify_report_and_set_pubkey succeeded." << std::endl;
    return 0;
  }
}

XGB_DLL int verify_remote_report_and_set_pubkey_and_nonce(
    uint8_t* pem_key,
    size_t key_size,
    uint8_t* nonce,
    size_t nonce_size,
    uint8_t* remote_report,
    size_t remote_report_size) {
  // Attest the remote report and accompanying key.
  size_t key_and_nonce_size = key_size + nonce_size;
  uint8_t key_and_nonce[key_and_nonce_size];
  memcpy(key_and_nonce, pem_key, CIPHER_PK_SIZE);
  memcpy(key_and_nonce + CIPHER_PK_SIZE, nonce, CIPHER_IV_SIZE);
  if (!attest_remote_report(remote_report, remote_report_size, key_and_nonce, key_and_nonce_size)) {
    std::cout << "verify_report_and_set_pubkey_and_nonce failed." << std::endl;
    return -1;
  }
  std::cout << "verify_report_and_set_pubkey_and_nonce succeeded." << std::endl;
  return 0;
}

XGB_DLL int add_client_key_with_certificate(char * cert,int cert_len, uint8_t* data, size_t data_len, uint8_t* signature, size_t sig_len) {
  safe_ecall(enclave_add_client_key_with_certificate(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret,cert,cert_len,data, data_len, signature, sig_len));
}

XGB_DLL int get_enclave_symm_key(char *username, uint8_t** out, size_t* out_size) {
  safe_ecall(enclave_get_enclave_symm_key(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, username, out, out_size));
}

XGB_DLL int verify_signature(uint8_t* pem_key, size_t key_size, uint8_t* data, size_t data_len, uint8_t* signature, size_t sig_len) {
  int res = -1;
  mbedtls_pk_context m_pk_context;
  mbedtls_pk_init(&m_pk_context);

  // Read the given public key.
  res = mbedtls_pk_parse_public_key(&m_pk_context, pem_key, key_size);
  if (res != 0) {
    std::cout << "mbedtls_pk_parse_public_key failed.\n";
    mbedtls_pk_free(&m_pk_context);
    return res;
  }

  res = verifySignature(m_pk_context, data, data_len, signature, sig_len);
  mbedtls_pk_free( &m_pk_context );
  return res;
}


XGB_DLL int encrypt_data_with_pk(char* data, size_t len, uint8_t* pem_key, size_t key_size, uint8_t* encrypted_data, size_t* encrypted_data_size) {
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
    std::cout << "mbedtls_pk_parse_public_key failed.\n";
    mbedtls_pk_free(&key);
    return res;
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
    std::cout << "mbedtls_rsa_pkcs1_encrypt failed\n";
    mbedtls_pk_free(&key);
    return res;
  }

  *encrypted_data_size = mbedtls_pk_rsa(key)->len;

  mbedtls_pk_free( &m_pk_context );
  mbedtls_ctr_drbg_free( &m_ctr_drbg_context );
  mbedtls_entropy_free( &m_entropy_context );
  return 0;
}

XGB_DLL int sign_data_with_keyfile(char *keyfile, uint8_t* data, size_t data_size, uint8_t* signature, size_t* sig_len) {
  mbedtls_pk_context pk;
  mbedtls_pk_init( &pk );

  int ret;
  if((ret = mbedtls_pk_parse_keyfile( &pk, keyfile, "")) != 0) {
    LOG(FATAL) <<"signing failed -- mbedtls_pk_parse_public_keyfile returned" << ret;
  }

  ret = sign_data(pk, data, data_size, signature, sig_len);
  return ret;
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
  return 0;
  API_END()
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
  return 0;
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
    //printf( "mbedtls_gcm_setkey failed to set the key for AES cipher - returned -0x%04x\n", -ret );
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
  return 0;
  API_END();
}

// Input, output, key
XGB_DLL int encrypt_file(char* fname, char* e_fname, char* k_fname) {
  char key[CIPHER_KEY_SIZE];
  std::ifstream keyfile;
  keyfile.open(k_fname);
  keyfile.read(key, CIPHER_KEY_SIZE);
  keyfile.close();
  return encrypt_file_with_keybuf(fname, e_fname, key);
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
    //printf( "mbedtls_ctr_drbg_seed() failed - returned -0x%04x\n", -ret );
    LOG(FATAL) << "mbedtls_ctr_drbg_seed() failed - returned " << -ret;
  }

  // Initialize the GCM context with our key and desired cipher
  ret = mbedtls_gcm_setkey(&gcm,     // GCM context to be initialized
      MBEDTLS_CIPHER_ID_AES,     // cipher to use (a 128-bit block cipher)
      (unsigned char*) key,      // encryption key
      CIPHER_KEY_SIZE * 8);      // key bits (must be 128, 192, or 256)
  if( ret != 0 ) {
    //printf( "mbedtls_gcm_setkey failed to set the key for AES cipher - returned -0x%04x\n", -ret );
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
      //printf( "mbedtls_gcm_crypt_and_tag failed to encrypt the data - returned -0x%04x\n", -ret );
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
  return 0;
}

XGB_DLL int decrypt_file_with_keybuf(char* fname, char* d_fname, char* key) {
  mbedtls_gcm_context gcm;

  // Initialize GCM context (just makes references valid) - makes the context ready for mbedtls_gcm_setkey()
  mbedtls_gcm_init(&gcm);
  int ret = mbedtls_gcm_setkey(&gcm,      // GCM context to be initialized
      MBEDTLS_CIPHER_ID_AES,          // cipher to use (a 128-bit block cipher)
      (const unsigned char*)key,      // encryption key
      CIPHER_KEY_SIZE * 8);           // key bits (must be 128, 192, or 256)
  if( ret != 0 ) {
    //printf( "mbedtls_gcm_setkey failed to set the key for AES cipher - returned -0x%04x\n", -ret );
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
}
