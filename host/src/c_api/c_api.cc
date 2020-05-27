// A
// Copyright (c) 2014 by Contributors

#include <xgboost/data.h>
#include <xgboost/learner.h>
#include <xgboost/c_api.h>
#include <xgboost/logging.h>

#include <dmlc/thread_local.h>
#include <rabit/rabit.h>
#include <rabit/c_api.h>

#include <cstdio>
#include <cstring>
#include <algorithm>
#include <vector>
#include <string>
#include <memory>

#include <xgboost/c_api/c_api_error.h>
#include <xgboost/data/simple_csr_source.h>
#include <xgboost/common/math.h>
#include <xgboost/common/io.h>
#include <xgboost/common/group_data.h>

#include <openenclave/host.h>
#include "xgboost_u.h"
#include <enclave/crypto.h>
#include <enclave/attestation.h>
#include <enclave/enclave.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dmlc/base64.h>

#include <mbedtls/entropy.h>    // mbedtls_entropy_context
#include <mbedtls/ctr_drbg.h>   // mbedtls_ctr_drbg_context
#include <mbedtls/cipher.h>     // MBEDTLS_CIPHER_ID_AES
#include <mbedtls/gcm.h>        // mbedtls_gcm_context

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

/*
 * namespace xgboost {
 * // booster wrapper for backward compatible reason.
 * class Booster {
 *  public:
 *   explicit Booster(const std::vector<std::shared_ptr<DMatrix> >& cache_mats)
 *       : configured_(false),
 *         initialized_(false),
 *         learner_(Learner::Create(cache_mats)) {}
 *
 *   inline Learner* learner() {  // NOLINT
 *     return learner_.get();
 *   }
 *
 *   inline void SetParam(const std::string& name, const std::string& val) {
 *     auto it = std::find_if(cfg_.begin(), cfg_.end(),
 *       [&name, &val](decltype(*cfg_.begin()) &x) {
 *         if (name == "eval_metric") {
 *           return x.first == name && x.second == val;
 *         }
 *         return x.first == name;
 *       });
 *     if (it == cfg_.end()) {
 *       cfg_.emplace_back(name, val);
 *     } else {
 *       (*it).second = val;
 *     }
 *     if (configured_) {
 *       learner_->Configure(cfg_);
 *     }
 *   }
 *
 *   inline void LazyInit() {
 *     if (!configured_) {
 *       LoadSavedParamFromAttr();
 *       learner_->Configure(cfg_);
 *       configured_ = true;
 *     }
 *     if (!initialized_) {
 *       learner_->InitModel();
 *       initialized_ = true;
 *     }
 *   }
 *
 *   inline void LoadSavedParamFromAttr() {
 *     // Locate saved parameters from learner attributes
 *     const std::string prefix = "SAVED_PARAM_";
 *     for (const std::string& attr_name : learner_->GetAttrNames()) {
 *       if (attr_name.find(prefix) == 0) {
 *         const std::string saved_param = attr_name.substr(prefix.length());
 *         if (std::none_of(cfg_.begin(), cfg_.end(),
 *                          [&](const std::pair<std::string, std::string>& x)
 *                              { return x.first == saved_param; })) {
 *           // If cfg_ contains the parameter already, skip it
 *           //   (this is to allow the user to explicitly override its value)
 *           std::string saved_param_value;
 *           CHECK(learner_->GetAttr(attr_name, &saved_param_value));
 *           cfg_.emplace_back(saved_param, saved_param_value);
 *         }
 *       }
 *     }
 *   }
 *
 *   inline void LoadModel(dmlc::Stream* fi) {
 *     learner_->Load(fi);
 *     initialized_ = true;
 *   }
 *
 *   bool IsInitialized() const { return initialized_; }
 *   void Intialize() { initialized_ = true; }
 *
 *  private:
 *   bool configured_;
 *   bool initialized_;
 *   std::unique_ptr<Learner> learner_;
 *   std::vector<std::pair<std::string, std::string> > cfg_;
 * };
 *
 * // declare the data callback.
 * XGB_EXTERN_C int XGBoostNativeDataIterSetData(
 *     void *handle, XGBoostBatchCSR batch);
 *
 * [>! \brief Native data iterator that takes callback to return data <]
 * class NativeDataIter : public dmlc::Parser<uint32_t> {
 *  public:
 *   NativeDataIter(DataIterHandle data_handle,
 *                  XGBCallbackDataIterNext* next_callback)
 *       :  at_first_(true), bytes_read_(0),
 *          data_handle_(data_handle), next_callback_(next_callback) {
 *   }
 *
 *   // override functions
 *   void BeforeFirst() override {
 *     CHECK(at_first_) << "cannot reset NativeDataIter";
 *   }
 *
 *   bool Next() override {
 *     if ((*next_callback_)(
 *             data_handle_,
 *             XGBoostNativeDataIterSetData,
 *             this) != 0) {
 *       at_first_ = false;
 *       return true;
 *     } else {
 *       return false;
 *     }
 *   }
 *
 *   const dmlc::RowBlock<uint32_t>& Value() const override {
 *     return block_;
 *   }
 *
 *   size_t BytesRead() const override {
 *     return bytes_read_;
 *   }
 *
 *   // callback to set the data
 *   void SetData(const XGBoostBatchCSR& batch) {
 *     offset_.clear();
 *     label_.clear();
 *     weight_.clear();
 *     index_.clear();
 *     value_.clear();
 *     offset_.insert(offset_.end(), batch.offset, batch.offset + batch.size + 1);
 *     if (batch.label != nullptr) {
 *       label_.insert(label_.end(), batch.label, batch.label + batch.size);
 *     }
 *     if (batch.weight != nullptr) {
 *       weight_.insert(weight_.end(), batch.weight, batch.weight + batch.size);
 *     }
 *     if (batch.index != nullptr) {
 *       index_.insert(index_.end(), batch.index + offset_[0], batch.index + offset_.back());
 *     }
 *     if (batch.value != nullptr) {
 *       value_.insert(value_.end(), batch.value + offset_[0], batch.value + offset_.back());
 *     }
 *     if (offset_[0] != 0) {
 *       size_t base = offset_[0];
 *       for (size_t& item : offset_) {
 *         item -= base;
 *       }
 *     }
 *     block_.size = batch.size;
 *     block_.offset = dmlc::BeginPtr(offset_);
 *     block_.label = dmlc::BeginPtr(label_);
 *     block_.weight = dmlc::BeginPtr(weight_);
 *     block_.qid = nullptr;
 *     block_.field = nullptr;
 *     block_.index = dmlc::BeginPtr(index_);
 *     block_.value = dmlc::BeginPtr(value_);
 *     bytes_read_ += offset_.size() * sizeof(size_t) +
 *         label_.size() * sizeof(dmlc::real_t) +
 *         weight_.size() * sizeof(dmlc::real_t) +
 *         index_.size() * sizeof(uint32_t) +
 *         value_.size() * sizeof(dmlc::real_t);
 *   }
 *
 *  private:
 *   // at the beinning.
 *   bool at_first_;
 *   // bytes that is read.
 *   size_t bytes_read_;
 *   // handle to the iterator,
 *   DataIterHandle data_handle_;
 *   // call back to get the data.
 *   XGBCallbackDataIterNext* next_callback_;
 *   // internal offset
 *   std::vector<size_t> offset_;
 *   // internal label data
 *   std::vector<dmlc::real_t> label_;
 *   // internal weight data
 *   std::vector<dmlc::real_t> weight_;
 *   // internal index.
 *   std::vector<uint32_t> index_;
 *   // internal value.
 *   std::vector<dmlc::real_t> value_;
 *   // internal Rowblock
 *   dmlc::RowBlock<uint32_t> block_;
 * };
 *
 * int XGBoostNativeDataIterSetData(
 *     void *handle, XGBoostBatchCSR batch) {
 *   API_BEGIN();
 *   static_cast<xgboost::NativeDataIter*>(handle)->SetData(batch);
 *   API_END();
 * }
 * }  // namespace xgboost
 */

using namespace xgboost; // NOLINT(*);

/*! \brief entry to to easily hold returning information */
struct XGBAPIThreadLocalEntry {
  /*! \brief result holder for returning string */
  std::string ret_str;
  /*! \brief result holder for returning strings */
  std::vector<std::string> ret_vec_str;
  /*! \brief result holder for returning string pointers */
  std::vector<const char *> ret_vec_charp;
  /*! \brief returning float vector. */
  std::vector<bst_float> ret_vec_float;
  /*! \brief temp variable of gradient pairs. */
  std::vector<GradientPair> tmp_gpair;
};

// define the threadlocal store.
using XGBAPIThreadLocalStore = dmlc::ThreadLocalStore<XGBAPIThreadLocalEntry>;

int XGBRegisterLogCallback(void (*callback)(const char*)) {
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
                                     char **signers,
                                     uint8_t* signatures[],
                                     size_t* sig_lengths) {
    size_t fname_lengths[num_files];
    size_t username_lengths[num_files];
    size_t signer_lengths[NUM_CLIENTS];

    get_str_lengths((char**)fnames, num_files, fname_lengths);
    get_str_lengths(usernames, num_files, username_lengths);
    get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

    safe_ecall(enclave_XGDMatrixCreateFromEncryptedFile(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, (const char**) fnames, fname_lengths, usernames, username_lengths, num_files, silent, nonce, nonce_size, nonce_ctr, out, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}


/* TODO(rishabhp): Enable this
 *
 * int XGDMatrixCreateFromDataIter(
 *     void* data_handle,
 *     XGBCallbackDataIterNext* callback,
 *     const char *cache_info,
 *     DMatrixHandle *out) {
 *   API_BEGIN();
 *
 *   std::string scache;
 *   if (cache_info != nullptr) {
 *     scache = cache_info;
 *   }
 *   NativeDataIter parser(data_handle, callback);
 *   *out = new std::shared_ptr<DMatrix>(DMatrix::Create(&parser, scache));
 *   API_END();
 * }
 *
 * XGB_DLL int XGDMatrixCreateFromCSREx(const size_t* indptr,
 *                                      const unsigned* indices,
 *                                      const bst_float* data,
 *                                      size_t nindptr,
 *                                      size_t nelem,
 *                                      size_t num_col,
 *                                      DMatrixHandle* out) {
 *   std::unique_ptr<data::SimpleCSRSource> source(new data::SimpleCSRSource());
 *
 *   API_BEGIN();
 *   data::SimpleCSRSource& mat = *source;
 *   auto& offset_vec = mat.page_.offset.HostVector();
 *   auto& data_vec = mat.page_.data.HostVector();
 *   offset_vec.reserve(nindptr);
 *   data_vec.reserve(nelem);
 *   offset_vec.resize(1);
 *   offset_vec[0] = 0;
 *   size_t num_column = 0;
 *   for (size_t i = 1; i < nindptr; ++i) {
 *     for (size_t j = indptr[i - 1]; j < indptr[i]; ++j) {
 *       if (!common::CheckNAN(data[j])) {
 *         // automatically skip nan.
 *         data_vec.emplace_back(Entry(indices[j], data[j]));
 *         num_column = std::max(num_column, static_cast<size_t>(indices[j] + 1));
 *       }
 *     }
 *     offset_vec.push_back(mat.page_.data.Size());
 *   }
 *
 *   mat.info.num_col_ = num_column;
 *   if (num_col > 0) {
 *     CHECK_LE(mat.info.num_col_, num_col)
 *         << "num_col=" << num_col << " vs " << mat.info.num_col_;
 *     mat.info.num_col_ = num_col;
 *   }
 *   mat.info.num_row_ = nindptr - 1;
 *   mat.info.num_nonzero_ = mat.page_.data.Size();
 *   *out = new std::shared_ptr<DMatrix>(DMatrix::Create(std::move(source)));
 *   API_END();
 * }
 *
 * XGB_DLL int XGDMatrixCreateFromCSCEx(const size_t* col_ptr,
 *                                      const unsigned* indices,
 *                                      const bst_float* data,
 *                                      size_t nindptr,
 *                                      size_t nelem,
 *                                      size_t num_row,
 *                                      DMatrixHandle* out) {
 *   std::unique_ptr<data::SimpleCSRSource> source(new data::SimpleCSRSource());
 *
 *   API_BEGIN();
 *   // FIXME: User should be able to control number of threads
 *   const int nthread = omp_get_max_threads();
 *   data::SimpleCSRSource& mat = *source;
 *   auto& offset_vec = mat.page_.offset.HostVector();
 *   auto& data_vec = mat.page_.data.HostVector();
 *   common::ParallelGroupBuilder<Entry> builder(&offset_vec, &data_vec);
 *   builder.InitBudget(0, nthread);
 *   size_t ncol = nindptr - 1;  // NOLINT(*)
 *   #pragma omp parallel for schedule(static)
 *   for (omp_ulong i = 0; i < static_cast<omp_ulong>(ncol); ++i) {  // NOLINT(*)
 *     int tid = omp_get_thread_num();
 *     for (size_t j = col_ptr[i]; j < col_ptr[i+1]; ++j) {
 *       if (!common::CheckNAN(data[j])) {
 *         builder.AddBudget(indices[j], tid);
 *       }
 *     }
 *   }
 *   builder.InitStorage();
 *   #pragma omp parallel for schedule(static)
 *   for (omp_ulong i = 0; i < static_cast<omp_ulong>(ncol); ++i) {  // NOLINT(*)
 *     int tid = omp_get_thread_num();
 *     for (size_t j = col_ptr[i]; j < col_ptr[i+1]; ++j) {
 *       if (!common::CheckNAN(data[j])) {
 *         builder.Push(indices[j],
 *                      Entry(static_cast<bst_uint>(i), data[j]),
 *                      tid);
 *       }
 *     }
 *   }
 *   mat.info.num_row_ = mat.page_.offset.Size() - 1;
 *   if (num_row > 0) {
 *     CHECK_LE(mat.info.num_row_, num_row);
 *     // provision for empty rows at the bottom of matrix
 *     auto& offset_vec = mat.page_.offset.HostVector();
 *     for (uint64_t i = mat.info.num_row_; i < static_cast<uint64_t>(num_row); ++i) {
 *       offset_vec.push_back(offset_vec.back());
 *     }
 *     mat.info.num_row_ = num_row;
 *     CHECK_EQ(mat.info.num_row_, offset_vec.size() - 1);  // sanity check
 *   }
 *   mat.info.num_col_ = ncol;
 *   mat.info.num_nonzero_ = nelem;
 *   *out  = new std::shared_ptr<DMatrix>(DMatrix::Create(std::move(source)));
 *   API_END();
 * }
 *
 * XGB_DLL int XGDMatrixCreateFromMat(const bst_float* data,
 *                                    xgboost::bst_ulong nrow,
 *                                    xgboost::bst_ulong ncol,
 *                                    bst_float missing,
 *                                    DMatrixHandle* out) {
 *   std::unique_ptr<data::SimpleCSRSource> source(new data::SimpleCSRSource());
 *
 *   API_BEGIN();
 *   data::SimpleCSRSource& mat = *source;
 *   auto& offset_vec = mat.page_.offset.HostVector();
 *   auto& data_vec = mat.page_.data.HostVector();
 *   offset_vec.resize(1+nrow);
 *   bool nan_missing = common::CheckNAN(missing);
 *   mat.info.num_row_ = nrow;
 *   mat.info.num_col_ = ncol;
 *   const bst_float* data0 = data;
 *
 *   // count elements for sizing data
 *   data = data0;
 *   for (xgboost::bst_ulong i = 0; i < nrow; ++i, data += ncol) {
 *     xgboost::bst_ulong nelem = 0;
 *     for (xgboost::bst_ulong j = 0; j < ncol; ++j) {
 *       if (common::CheckNAN(data[j])) {
 *         CHECK(nan_missing)
 *           << "There are NAN in the matrix, however, you did not set missing=NAN";
 *       } else {
 *         if (nan_missing || data[j] != missing) {
 *           ++nelem;
 *         }
 *       }
 *     }
 *     offset_vec[i+1] = offset_vec[i] + nelem;
 *   }
 *   data_vec.resize(mat.page_.data.Size() + offset_vec.back());
 *
 *   data = data0;
 *   for (xgboost::bst_ulong i = 0; i < nrow; ++i, data += ncol) {
 *     xgboost::bst_ulong matj = 0;
 *     for (xgboost::bst_ulong j = 0; j < ncol; ++j) {
 *       if (common::CheckNAN(data[j])) {
 *       } else {
 *         if (nan_missing || data[j] != missing) {
 *           data_vec[offset_vec[i] + matj] = Entry(j, data[j]);
 *           ++matj;
 *         }
 *       }
 *     }
 *   }
 *
 *   mat.info.num_nonzero_ = mat.page_.data.Size();
 *   *out  = new std::shared_ptr<DMatrix>(DMatrix::Create(std::move(source)));
 *   API_END();
 * }
 *
 * void PrefixSum(size_t *x, size_t N) {
 *   size_t *suma;
 * #pragma omp parallel
 *   {
 *     const int ithread = omp_get_thread_num();
 *     const int nthreads = omp_get_num_threads();
 * #pragma omp single
 *     {
 *       suma = new size_t[nthreads+1];
 *       suma[0] = 0;
 *     }
 *     size_t sum = 0;
 *     size_t offset = 0;
 * #pragma omp for schedule(static)
 *     for (omp_ulong i = 0; i < N; i++) {
 *       sum += x[i];
 *       x[i] = sum;
 *     }
 *     suma[ithread+1] = sum;
 * #pragma omp barrier
 *     for (omp_ulong i = 0; i < static_cast<omp_ulong>(ithread+1); i++) {
 *       offset += suma[i];
 *     }
 * #pragma omp for schedule(static)
 *     for (omp_ulong i = 0; i < N; i++) {
 *       x[i] += offset;
 *     }
 *   }
 *   delete[] suma;
 * }
 *
 * XGB_DLL int XGDMatrixCreateFromMat_omp(const bst_float* data,  // NOLINT
 *                                        xgboost::bst_ulong nrow,
 *                                        xgboost::bst_ulong ncol,
 *                                        bst_float missing, DMatrixHandle* out,
 *                                        int nthread) {
 *   // avoid openmp unless enough data to be worth it to avoid overhead costs
 *   if (nrow*ncol <= 10000*50) {
 *     return(XGDMatrixCreateFromMat(data, nrow, ncol, missing, out));
 *   }
 *
 *   API_BEGIN();
 *   const int nthreadmax = std::max(omp_get_num_procs() / 2 - 1, 1);
 *   //  const int nthreadmax = omp_get_max_threads();
 *   if (nthread <= 0) nthread=nthreadmax;
 *   int nthread_orig = omp_get_max_threads();
 *   omp_set_num_threads(nthread);
 *
 *   std::unique_ptr<data::SimpleCSRSource> source(new data::SimpleCSRSource());
 *   data::SimpleCSRSource& mat = *source;
 *   auto& offset_vec = mat.page_.offset.HostVector();
 *   auto& data_vec = mat.page_.data.HostVector();
 *   offset_vec.resize(1+nrow);
 *   mat.info.num_row_ = nrow;
 *   mat.info.num_col_ = ncol;
 *
 *   // Check for errors in missing elements
 *   // Count elements per row (to avoid otherwise need to copy)
 *   bool nan_missing = common::CheckNAN(missing);
 *   std::vector<int> badnan;
 *   badnan.resize(nthread, 0);
 *
 * #pragma omp parallel num_threads(nthread)
 *   {
 *     int ithread  = omp_get_thread_num();
 *
 *     // Count elements per row
 * #pragma omp for schedule(static)
 *     for (omp_ulong i = 0; i < nrow; ++i) {
 *       xgboost::bst_ulong nelem = 0;
 *       for (xgboost::bst_ulong j = 0; j < ncol; ++j) {
 *         if (common::CheckNAN(data[ncol*i + j]) && !nan_missing) {
 *           badnan[ithread] = 1;
 *         } else if (common::CheckNAN(data[ncol * i + j])) {
 *         } else if (nan_missing || data[ncol * i + j] != missing) {
 *           ++nelem;
 *         }
 *       }
 *       offset_vec[i+1] = nelem;
 *     }
 *   }
 *   // Inform about any NaNs and resize data matrix
 *   for (int i = 0; i < nthread; i++) {
 *     CHECK(!badnan[i]) << "There are NAN in the matrix, however, you did not set missing=NAN";
 *   }
 *
 *   // do cumulative sum (to avoid otherwise need to copy)
 *   PrefixSum(&offset_vec[0], offset_vec.size());
 *   data_vec.resize(mat.page_.data.Size() + offset_vec.back());
 *
 *   // Fill data matrix (now that know size, no need for slow push_back())
 * #pragma omp parallel num_threads(nthread)
 *   {
 * #pragma omp for schedule(static)
 *     for (omp_ulong i = 0; i < nrow; ++i) {
 *       xgboost::bst_ulong matj = 0;
 *       for (xgboost::bst_ulong j = 0; j < ncol; ++j) {
 *         if (common::CheckNAN(data[ncol * i + j])) {
 *         } else if (nan_missing || data[ncol * i + j] != missing) {
 *           data_vec[offset_vec[i] + matj] =
 *               Entry(j, data[ncol * i + j]);
 *           ++matj;
 *         }
 *       }
 *     }
 *   }
 *   // restore omp state
 *   omp_set_num_threads(nthread_orig);
 *
 *   mat.info.num_nonzero_ = mat.page_.data.Size();
 *   *out  = new std::shared_ptr<DMatrix>(DMatrix::Create(std::move(source)));
 *   API_END();
 * }
 *
 * enum class DTType : uint8_t {
 *   kFloat32 = 0,
 *   kFloat64 = 1,
 *   kBool8 = 2,
 *   kInt32 = 3,
 *   kInt8 = 4,
 *   kInt16 = 5,
 *   kInt64 = 6,
 *   kUnknown = 7
 * };
 *
 * DTType DTGetType(std::string type_string) {
 *   if (type_string == "float32") {
 *     return DTType::kFloat32;
 *   } else if (type_string == "float64") {
 *     return DTType::kFloat64;
 *   } else if (type_string == "bool8") {
 *     return DTType::kBool8;
 *   } else if (type_string == "int32") {
 *     return DTType::kInt32;
 *   } else if (type_string == "int8") {
 *     return DTType::kInt8;
 *   } else if (type_string == "int16") {
 *     return DTType::kInt16;
 *   } else if (type_string == "int64") {
 *     return DTType::kInt64;
 *   } else {
 *     LOG(FATAL) << "Unknown data table type.";
 *     return DTType::kUnknown;
 *   }
 * }
 *
 * float DTGetValue(void* column, DTType dt_type, size_t ridx) {
 *   float missing = std::numeric_limits<float>::quiet_NaN();
 *   switch (dt_type) {
 *     case DTType::kFloat32: {
 *       float val = reinterpret_cast<float*>(column)[ridx];
 *       return std::isfinite(val) ? val : missing;
 *     }
 *     case DTType::kFloat64: {
 *       double val = reinterpret_cast<double*>(column)[ridx];
 *       return std::isfinite(val) ? static_cast<float>(val) : missing;
 *     }
 *     case DTType::kBool8: {
 *       bool val = reinterpret_cast<bool*>(column)[ridx];
 *       return static_cast<float>(val);
 *     }
 *     case DTType::kInt32: {
 *       int32_t val = reinterpret_cast<int32_t*>(column)[ridx];
 *       return val != (-2147483647 - 1) ? static_cast<float>(val) : missing;
 *     }
 *     case DTType::kInt8: {
 *       int8_t val = reinterpret_cast<int8_t*>(column)[ridx];
 *       return val != -128 ? static_cast<float>(val) : missing;
 *     }
 *     case DTType::kInt16: {
 *       int16_t val = reinterpret_cast<int16_t*>(column)[ridx];
 *       return val != -32768 ? static_cast<float>(val) : missing;
 *     }
 *     case DTType::kInt64: {
 *       int64_t val = reinterpret_cast<int64_t*>(column)[ridx];
 *       return val != -9223372036854775807 - 1 ? static_cast<float>(val)
 *                                              : missing;
 *     }
 *     default: {
 *       LOG(FATAL) << "Unknown data table type.";
 *       return 0.0f;
 *     }
 *   }
 * }
 *
 * XGB_DLL int XGDMatrixCreateFromDT(void** data, const char** feature_stypes,
 *                                   xgboost::bst_ulong nrow,
 *                                   xgboost::bst_ulong ncol, DMatrixHandle* out,
 *                                   int nthread) {
 *   // avoid openmp unless enough data to be worth it to avoid overhead costs
 *   if (nrow * ncol <= 10000 * 50) {
 *     nthread = 1;
 *   }
 *
 *   API_BEGIN();
 *   const int nthreadmax = std::max(omp_get_num_procs() / 2 - 1, 1);
 *   if (nthread <= 0) nthread = nthreadmax;
 *   int nthread_orig = omp_get_max_threads();
 *   omp_set_num_threads(nthread);
 *
 *   std::unique_ptr<data::SimpleCSRSource> source(new data::SimpleCSRSource());
 *   data::SimpleCSRSource& mat = *source;
 *   mat.page_.offset.Resize(1 + nrow);
 *   mat.info.num_row_ = nrow;
 *   mat.info.num_col_ = ncol;
 *
 *   auto& page_offset = mat.page_.offset.HostVector();
 * #pragma omp parallel num_threads(nthread)
 *   {
 *     // Count elements per row, column by column
 *     for (auto j = 0u; j < ncol; ++j) {
 *       DTType dtype = DTGetType(feature_stypes[j]);
 * #pragma omp for schedule(static)
 *       for (omp_ulong i = 0; i < nrow; ++i) {
 *         float val = DTGetValue(data[j], dtype, i);
 *         if (!std::isnan(val)) {
 *           page_offset[i + 1]++;
 *         }
 *       }
 *     }
 *   }
 *   // do cumulative sum (to avoid otherwise need to copy)
 *   PrefixSum(&page_offset[0], page_offset.size());
 *
 *   mat.page_.data.Resize(mat.page_.data.Size() + page_offset.back());
 *
 *   auto& page_data = mat.page_.data.HostVector();
 *
 *   // Fill data matrix (now that know size, no need for slow push_back())
 *   std::vector<size_t> position(nrow);
 * #pragma omp parallel num_threads(nthread)
 *   {
 *     for (xgboost::bst_ulong j = 0; j < ncol; ++j) {
 *       DTType dtype = DTGetType(feature_stypes[j]);
 * #pragma omp for schedule(static)
 *       for (omp_ulong i = 0; i < nrow; ++i) {
 *         float val = DTGetValue(data[j], dtype, i);
 *         if (!std::isnan(val)) {
 *           page_data[page_offset[i] + position[i]] = Entry(j, val);
 *           position[i]++;
 *         }
 *       }
 *     }
 *   }
 *
 *   // restore omp state
 *   omp_set_num_threads(nthread_orig);
 *
 *   mat.info.num_nonzero_ = mat.page_.data.Size();
 *   *out = new std::shared_ptr<DMatrix>(DMatrix::Create(std::move(source)));
 *   API_END();
 * }
 *
 * XGB_DLL int XGDMatrixSliceDMatrix(DMatrixHandle handle,
 *                                   const int* idxset,
 *                                   xgboost::bst_ulong len,
 *                                   DMatrixHandle* out) {
 *   std::unique_ptr<data::SimpleCSRSource> source(new data::SimpleCSRSource());
 *
 *   API_BEGIN();
 *   CHECK_HANDLE();
 *   data::SimpleCSRSource src;
 *   src.CopyFrom(static_cast<std::shared_ptr<DMatrix>*>(handle)->get());
 *   data::SimpleCSRSource& ret = *source;
 *
 *   CHECK_EQ(src.info.group_ptr_.size(), 0U)
 *       << "slice does not support group structure";
 *
 *   ret.Clear();
 *   ret.info.num_row_ = len;
 *   ret.info.num_col_ = src.info.num_col_;
 *
 *   auto iter = &src;
 *   iter->BeforeFirst();
 *   CHECK(iter->Next());
 *
 *   const auto& batch = iter->Value();
 *   const auto& src_labels = src.info.labels_.ConstHostVector();
 *   const auto& src_weights = src.info.weights_.ConstHostVector();
 *   const auto& src_base_margin = src.info.base_margin_.ConstHostVector();
 *   auto& ret_labels = ret.info.labels_.HostVector();
 *   auto& ret_weights = ret.info.weights_.HostVector();
 *   auto& ret_base_margin = ret.info.base_margin_.HostVector();
 *   auto& offset_vec = ret.page_.offset.HostVector();
 *   auto& data_vec = ret.page_.data.HostVector();
 *
 *   for (xgboost::bst_ulong i = 0; i < len; ++i) {
 *     const int ridx = idxset[i];
 *     auto inst = batch[ridx];
 *     CHECK_LT(static_cast<xgboost::bst_ulong>(ridx), batch.Size());
 *     data_vec.insert(data_vec.end(), inst.data(),
 *                     inst.data() + inst.size());
 *     offset_vec.push_back(offset_vec.back() + inst.size());
 *     ret.info.num_nonzero_ += inst.size();
 *
 *     if (src_labels.size() != 0) {
 *       ret_labels.push_back(src_labels[ridx]);
 *     }
 *     if (src_weights.size() != 0) {
 *       ret_weights.push_back(src_weights[ridx]);
 *     }
 *     if (src_base_margin.size() != 0) {
 *       ret_base_margin.push_back(src_base_margin[ridx]);
 *     }
 *     if (src.info.root_index_.size() != 0) {
 *       ret.info.root_index_.push_back(src.info.root_index_[ridx]);
 *     }
 *   }
 *   *out = new std::shared_ptr<DMatrix>(DMatrix::Create(std::move(source)));
 *   API_END();
 * }
 */


XGB_DLL int XGDMatrixFree(DMatrixHandle handle) {
    safe_ecall(enclave_XGDMatrixFree(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle));
}

/* TODO(rishabhp): Enable this
 *
 * XGB_DLL int XGDMatrixSaveBinary(DMatrixHandle handle,
 *                                 const char* fname,
 *                                 int silent) {
 *   API_BEGIN();
 *   CHECK_HANDLE();
 *   static_cast<std::shared_ptr<DMatrix>*>(handle)->get()->SaveToLocalFile(fname);
 *   API_END();
 * }
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

/* TODO(rishabhp): Enable this
 *
 * XGB_DLL int XGDMatrixSetGroup(DMatrixHandle handle,
 *                               const unsigned* group,
 *                               xgboost::bst_ulong len) {
 *   API_BEGIN();
 *   CHECK_HANDLE();
 *   auto *pmat = static_cast<std::shared_ptr<DMatrix>*>(handle);
 *   MetaInfo& info = pmat->get()->Info();
 *   info.group_ptr_.resize(len + 1);
 *   info.group_ptr_[0] = 0;
 *   for (uint64_t i = 0; i < len; ++i) {
 *     info.group_ptr_[i + 1] = info.group_ptr_[i] + group[i];
 *   }
 *   API_END();
 * }
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
                            uint8_t* nonce,
                            size_t nonce_size,
                            uint32_t nonce_ctr,
                            xgboost::bst_ulong *out,
                            char **signers,
                            uint8_t* signatures[],
                            size_t* sig_lengths) {
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

  safe_ecall(enclave_XGDMatrixNumRow(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, nonce, nonce_size, nonce_ctr, out, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGDMatrixNumCol(const DMatrixHandle handle,
                            uint8_t* nonce,
                            size_t nonce_size,
                            uint32_t nonce_ctr,
                            xgboost::bst_ulong *out,
                            char **signers,
                            uint8_t* signatures[],
                            size_t* sig_lengths) {                          
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

  safe_ecall(enclave_XGDMatrixNumCol(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, nonce, nonce_size, nonce_ctr, out, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

// xgboost implementation

XGB_DLL int XGBCreateEnclave(const char *enclave_image, int log_verbosity) {
  if (!Enclave::getInstance().getEnclave()) {
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
    safe_ecall(enclave_init(Enclave::getInstance().getEnclave(), log_verbosity));
  }
  return 0;
}

XGB_DLL int XGBoosterCreate(const DMatrixHandle dmats[],
                    xgboost::bst_ulong len,
                    uint8_t *nonce,
                    size_t nonce_size,
                    uint32_t nonce_ctr,
                    BoosterHandle *out,
                    char **signers,
                    uint8_t* signatures[],
                    size_t* sig_lengths) {
  size_t handle_lengths[len];
  size_t signer_lengths[NUM_CLIENTS];

  get_str_lengths((char**)dmats, len, handle_lengths);
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

  safe_ecall(enclave_XGBoosterCreate(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, const_cast<char**>(dmats), handle_lengths, len, nonce, nonce_size, nonce_ctr, out, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
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
                              char **signers,
                              uint8_t* signatures[],
                              size_t* sig_lengths) {
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

    safe_ecall(enclave_XGBoosterSetParam(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, name, value, nonce, nonce_size, nonce_ctr, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGBoosterUpdateOneIter(BoosterHandle handle,
                                   int iter,
                                   DMatrixHandle dtrain,
                                   uint8_t* nonce,
                                   size_t nonce_size,
                                   uint32_t nonce_ctr,
                                   char **signers,
                                   uint8_t* signatures[],
                                   size_t* sig_lengths) {
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

    safe_ecall(enclave_XGBoosterUpdateOneIter(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, iter, dtrain, nonce, nonce_size, nonce_ctr, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
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
                             uint8_t *nonce,
                             size_t nonce_size,
                             uint32_t nonce_ctr,
                             xgboost::bst_ulong *len,
                             uint8_t **out_result,
                             char **signers,
                             uint8_t* signatures[],
                             size_t* sig_lengths) {
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

    safe_ecall(enclave_XGBoosterPredict(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, dmat, option_mask, ntree_limit, nonce, nonce_size, nonce_ctr, len, out_result, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGBoosterLoadModel(BoosterHandle handle, const char* fname, uint8_t* nonce, size_t nonce_size, uint32_t nonce_ctr, char** signers, uint8_t* signatures[], size_t* sig_lengths) {
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

  safe_ecall(enclave_XGBoosterLoadModel(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, fname, nonce, nonce_size, nonce_ctr, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGBoosterSaveModel(BoosterHandle handle, const char* fname, uint8_t* nonce, size_t nonce_size, uint32_t nonce_ctr, char** signers, uint8_t* signatures[], size_t* sig_lengths) {
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

  safe_ecall(enclave_XGBoosterSaveModel(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, fname, nonce, nonce_size, nonce_ctr, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGBoosterLoadModelFromBuffer(BoosterHandle handle,
                                         const void* buf,
                                         xgboost::bst_ulong len,
                                         char** signers,
                                         uint8_t* signatures[],
                                         size_t* sig_lengths) {
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

  safe_ecall(enclave_XGBoosterLoadModelFromBuffer(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, buf, len, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

XGB_DLL int XGBoosterGetModelRaw(BoosterHandle handle,
                                 uint8_t* nonce,
                                 size_t nonce_size,
                                 uint32_t nonce_ctr,
                                 bst_ulong *out_len,
                                 const char **out_dptr,
                                 char** signers,
                                 uint8_t* signatures[],
                                 size_t* sig_lengths) {
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

  safe_ecall(enclave_XGBoosterGetModelRaw(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, nonce, nonce_size, nonce_ctr, out_len, (char**)out_dptr, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
}

/* TODO(rishabhp): Enable this
 *
 * inline void XGBoostDumpModelImpl(
 *     BoosterHandle handle,
 *     const FeatureMap& fmap,
 *     int with_stats,
 *     const char *format,
 *     xgboost::bst_ulong* len,
 *     const char*** out_models) {
 *   std::vector<std::string>& str_vecs = XGBAPIThreadLocalStore::Get()->ret_vec_str;
 *   std::vector<const char*>& charp_vecs = XGBAPIThreadLocalStore::Get()->ret_vec_charp;
 *   auto *bst = static_cast<Booster*>(handle);
 *   bst->LazyInit();
 *   str_vecs = bst->learner()->DumpModel(fmap, with_stats != 0, format);
 *   charp_vecs.resize(str_vecs.size());
 *   for (size_t i = 0; i < str_vecs.size(); ++i) {
 *     charp_vecs[i] = str_vecs[i].c_str();
 *   }
 *   *out_models = dmlc::BeginPtr(charp_vecs);
 *   *len = static_cast<xgboost::bst_ulong>(charp_vecs.size());
 * }
 */

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
                                 char** signers,
                                 uint8_t* signatures[],
                                 size_t* sig_lengths){
  size_t signer_lengths[NUM_CLIENTS];
  get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

  safe_ecall(enclave_XGBoosterDumpModelEx(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, fmap, with_stats, format, nonce, nonce_size, nonce_ctr, len, (char***) out_models, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
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
                                   char **signers,
                                   size_t signer_lengths[],
                                   uint8_t* signatures[],
                                   size_t* sig_lengths) {
  size_t fname_lengths[fnum];
  size_t ftype_lengths[fnum];

  get_str_lengths((char**)fname, fnum, fname_lengths);
  get_str_lengths((char**)ftype, fnum, ftype_lengths);

  safe_ecall(enclave_XGBoosterDumpModelWithFeatures(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, (unsigned int) fnum, fname, fname_lengths, ftype, ftype_lengths, with_stats, nonce, nonce_size, nonce_ctr, len, (char***) out_models, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
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
                                             char **signers,
                                             uint8_t* signatures[],
                                             size_t* sig_lengths) {
    size_t fname_lengths[fnum];
    size_t ftype_lengths[fnum];
    size_t signer_lengths[NUM_CLIENTS];

    get_str_lengths((char**)fname, fnum, fname_lengths);
    get_str_lengths((char**)ftype, fnum, ftype_lengths);
    get_str_lengths(signers, NUM_CLIENTS, signer_lengths);

    safe_ecall(enclave_XGBoosterDumpModelExWithFeatures(Enclave::getInstance().getEnclave(), &Enclave::getInstance().enclave_ret, handle, (unsigned int) fnum, fname, fname_lengths, ftype, ftype_lengths, with_stats, format, nonce, nonce_size, nonce_ctr, len, (char***) out_models, signers, signer_lengths, signatures, sig_lengths, NUM_CLIENTS));
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
  memcpy(key_and_nonce, pem_key, CIPHER_KEY_SIZE);
  memcpy(key_and_nonce + CIPHER_KEY_SIZE, nonce, CIPHER_IV_SIZE);
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

XGB_DLL int sign_data(char *keyfile, uint8_t* data, size_t data_size, uint8_t* signature, size_t* sig_len) {
  mbedtls_pk_context pk;
  mbedtls_entropy_context m_entropy_context;
  mbedtls_ctr_drbg_context m_ctr_drbg_context;

  mbedtls_entropy_init( &m_entropy_context );
  mbedtls_pk_init( &pk );
  mbedtls_ctr_drbg_init( &m_ctr_drbg_context );

  unsigned char hash[32];
  int ret = 1;

  ret = mbedtls_ctr_drbg_seed(&m_ctr_drbg_context, mbedtls_entropy_func, &m_entropy_context, NULL, 0);

  if((ret = mbedtls_pk_parse_keyfile( &pk, keyfile, "")) != 0) {
    printf( " failed\n  ! Could not read key from '%s'\n", keyfile);
    printf( "  ! mbedtls_pk_parse_public_keyfile returned %d\n\n", ret );
    return ret;
  }
  if(!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
    printf( " failed\n  ! Key is not an RSA key\n" );
    return ret;
  }

  mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256 );

  if((ret = compute_sha256(data, data_size, hash)) != 0) {
    printf( " failed\n  ! Could not hash\n\n");
    return ret;
  }

  if((ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 0, signature, sig_len, mbedtls_ctr_drbg_random, &m_ctr_drbg_context)) != 0) {
    printf( " failed\n  ! mbedtls_pk_sign returned %d\n\n", ret );
    return ret;
  }
  return 0;
}

XGB_DLL int decrypt_predictions(char* key, uint8_t* encrypted_preds, size_t num_preds, bst_float** preds) {
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
}

XGB_DLL int decrypt_enclave_key(char* key, uint8_t* encrypted_key, size_t len, uint8_t** out_key) {

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
}

XGB_DLL int decrypt_dump(char* key, char** models, xgboost::bst_ulong length) {
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
