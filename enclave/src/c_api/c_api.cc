// Copyright (c) 2014 by Contributors


#include <xgboost/data.h>
#include <xgboost/learner.h>
#include <xgboost/c_api.h>
#include <xgboost/logging.h>

#include <dmlc/thread_local.h>
#include <dmlc/base64.h>
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

#include <xgboost/common/common.h>
#include "xgboost_t.h"
#include <enclave/crypto.h>
#include "enclave_context.h"

namespace xgboost {
// booster wrapper for backward compatible reason.
class Booster {
 public:
  explicit Booster(const std::vector<std::shared_ptr<DMatrix> >& cache_mats)
      : configured_(false),
        initialized_(false),
        learner_(Learner::Create(cache_mats)) {}

  inline Learner* learner() {  // NOLINT
    Learner* l = learner_.get();
    return l;
  }

  inline void SetParam(const std::string& name, const std::string& val) {
    auto it = std::find_if(cfg_.begin(), cfg_.end(),
      [&name, &val](decltype(*cfg_.begin()) &x) {
        if (name == "eval_metric") {
          return x.first == name && x.second == val;
        }
        return x.first == name;
      });
    if (it == cfg_.end()) {
      cfg_.emplace_back(name, val);
    } else {
      (*it).second = val;
    }
    if (configured_) {
      learner_->Configure(cfg_);
    }
  }

  inline void LazyInit() {
    if (!configured_) {
      LoadSavedParamFromAttr();
      learner_->Configure(cfg_);
      configured_ = true;
    }
    if (!initialized_) {
      learner_->InitModel();
      initialized_ = true;
    }
  }

  inline void LoadSavedParamFromAttr() {
    // Locate saved parameters from learner attributes
    const std::string prefix = "SAVED_PARAM_";
    //learner_->print();
    for (const std::string& attr_name : learner_->GetAttrNames()) {
      if (attr_name.find(prefix) == 0) {
        const std::string saved_param = attr_name.substr(prefix.length());
        if (std::none_of(cfg_.begin(), cfg_.end(),
                         [&](const std::pair<std::string, std::string>& x)
                             { return x.first == saved_param; })) {
          // If cfg_ contains the parameter already, skip it
          //   (this is to allow the user to explicitly override its value)
          std::string saved_param_value;
          CHECK(learner_->GetAttr(attr_name, &saved_param_value));
          cfg_.emplace_back(saved_param, saved_param_value);
        }
      }
    }
  }

  inline void LoadModel(dmlc::Stream* fi) {
    learner_->Load(fi);
    initialized_ = true;
  }

  bool IsInitialized() const { return initialized_; }
  void Intialize() { initialized_ = true; }

 private:
  bool configured_;
  bool initialized_;
  std::unique_ptr<Learner> learner_;
  std::vector<std::pair<std::string, std::string> > cfg_;
};

/* TODO(rishabhp): Enable this
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
 */
}  // namespace xgboost

using namespace xgboost; // NOLINT(*);

/**
 * Generate a remote report for the given data. The SHA256 digest of the data is
 * stored in the report_data field of the generated remote report.
 */
bool generate_remote_report(
    const uint8_t* data,
    const size_t data_size,
    uint8_t** remote_report_buf,
    size_t* remote_report_buf_size) {
  bool ret = false;
  uint8_t sha256[32];
  oe_result_t result = OE_OK;
  uint8_t* temp_buf = NULL;

  // Compute the sha256 hash of given data.
  if (compute_sha256(data, data_size, sha256) != 0) {
    LOG(INFO) << "compute_sha256 failed";
    return false;
  }

  // To generate a remote report that can be attested remotely by an enclave
  // running  on a different platform, pass the
  // OE_REPORT_FLAGS_REMOTE_ATTESTATION option. This uses the trusted
  // quoting enclave to generate the report based on this enclave's local
  // report.
  // To generate a remote report that just needs to be attested by another
  // enclave running on the same platform, pass 0 instead. This uses the
  // EREPORT instruction to generate this enclave's local report.
  // Both kinds of reports can be verified using the oe_verify_report
  // function.
  result = oe_get_report(
      OE_REPORT_FLAGS_REMOTE_ATTESTATION,
      sha256, // Store sha256 in report_data field
      sizeof(sha256),
      NULL, // opt_params must be null
      0,
      &temp_buf,
      remote_report_buf_size);
  if (result != OE_OK) {
    LOG(INFO) << "oe_get_report failed.";
    return false;
  }
  *remote_report_buf = temp_buf;
  LOG(INFO) << "generate_remote_report succeeded.";
  return true;
}

/**
 * Return the public key of this enclave along with the enclave's remote report.
 * The enclave that receives the key will use the remote report to attest this
 * enclave.
 */
int get_remote_report_with_pubkey(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size) {

  uint8_t* report = NULL;
  size_t report_size = 0;
  uint8_t* key_buf = NULL;
  int ret = 1;

  uint8_t* public_key = EnclaveContext::getInstance().get_public_key();

#ifdef __ENCLAVE_SIMULATION__
  key_buf = (uint8_t*)oe_host_malloc(CIPHER_PK_SIZE);
  if (key_buf == NULL) {
    ret = OE_OUT_OF_MEMORY;
    return ret;
  }
  memcpy(key_buf, public_key, CIPHER_PK_SIZE);

  *pem_key = key_buf;
  *key_size = CIPHER_PK_SIZE;

  ret = 0;
#else
  if (generate_remote_report(public_key, CIPHER_PK_SIZE, &report, &report_size)) {
    // Allocate memory on the host and copy the report over.
    *remote_report = (uint8_t*)oe_host_malloc(report_size);
    if (*remote_report == NULL) {
      ret = OE_OUT_OF_MEMORY;
      if (report)
        oe_free_report(report);
      return ret;
    }
    memcpy(*remote_report, report, report_size);
    *remote_report_size = report_size;
    oe_free_report(report);

    key_buf = (uint8_t*)oe_host_malloc(CIPHER_PK_SIZE);
    if (key_buf == NULL) {
      ret = OE_OUT_OF_MEMORY;
      if (report)
        oe_free_report(report);
      if (*remote_report)
        oe_host_free(*remote_report);
      return ret;
    }
    memcpy(key_buf, public_key, CIPHER_PK_SIZE);

    *pem_key = key_buf;
    *key_size = CIPHER_PK_SIZE;

    ret = 0;
    LOG(INFO) << "get_remote_report_with_pubkey succeeded";
  } else {
    LOG(FATAL) << "get_remote_report_with_pubkey failed.";
  }
#endif
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

  // While attesting, the remote report being attested must not be tampered
  // with. Ensure that it has been copied over to the enclave.
  if (!oe_is_within_enclave(remote_report, remote_report_size)) {
    LOG(FATAL) << "Cannot attest remote report in host memory. Unsafe.";
  }

  // 1)  Validate the report's trustworthiness
  // Verify the remote report to ensure its authenticity.
  result = oe_verify_report(remote_report, remote_report_size, &parsed_report);
  if (result != OE_OK) {
    LOG(FATAL) << "oe_verify_report failed " << oe_result_str(result);
  }

  // 2) validate the enclave identity's signed_id is the hash of the public
  // signing key that was used to sign an enclave. Check that the enclave was
  // signed by an trusted entity.
  // FIXME Enable this check
  /*if (memcmp(parsed_report.identity.signer_id, m_enclave_mrsigner, 32) != 0) {
    LOG(FATAL) << "identity.signer_id checking failed."

    LOG(INFO)<< "identity.signer_id " << parsed_report.identity.signer_id;

    for (int i = 0; i < 32; i++) {
    TRACE_ENCLAVE(
    "m_enclave_mrsigner[%d]=0x%0x\n",
    i,
    (uint8_t)m_enclave_mrsigner[i]);
    }

    TRACE_ENCLAVE("\n\n\n");

    for (int i = 0; i < 32; i++)
    {
    TRACE_ENCLAVE(
    "parsedReport.identity.signer_id)[%d]=0x%0x\n",
    i,
    (uint8_t)parsed_report.identity.signer_id[i]);
    }
    TRACE_ENCLAVE("m_enclave_mrsigner %s", m_enclave_mrsigner);
    goto exit;
    }*/

  // FIXME add verification for MRENCLAVE

  // Check the enclave's product id and security version
  // See enc.conf for values specified when signing the enclave.
  if (parsed_report.identity.product_id[0] != 1) {
    LOG(FATAL) << "identity.product_id checking failed.";
  }

  if (parsed_report.identity.security_version < 1) {
    LOG(FATAL) << "identity.security_version checking failed.";
  }

  // 3) Validate the report data
  //    The report_data has the hash value of the report data
  if (compute_sha256(data, data_size, sha256) != 0) {
    LOG(FATAL) << "hash validation failed.";
  }

  if (memcmp(parsed_report.report_data, sha256, sizeof(sha256)) != 0) {
    LOG(FATAL) << "SHA256 mismatch.";
  }
  ret = true;
  LOG(INFO) << "remote attestation succeeded.";
  return ret;
}

int verify_remote_report_and_set_pubkey(
    uint8_t* pem_key,
    size_t key_size,
    uint8_t* remote_report,
    size_t remote_report_size) {

  // Attest the remote report and accompanying key.
  if (attest_remote_report(remote_report, remote_report_size, pem_key, key_size)) {
    // FIXME save the pubkey passed by the other enclave
    //memcpy(m_crypto->get_the_other_enclave_public_key(), pem_key, key_size);
  } else {
    LOG(INFO) << "verify_report_and_set_pubkey failed.";
    return -1;
  }
  LOG(INFO) << "verify_report_and_set_pubkey succeeded.";
  return 0;
}

//int add_client_key(uint8_t* data, size_t len, uint8_t* signature, size_t sig_len) {
//    if (EnclaveContext::getInstance().decrypt_and_save_client_key(data, len, signature, sig_len))
//      return 0;
//    return -1;
//}

int add_client_key_with_certificate(char * cert,
        int cert_len,
        uint8_t* data,
        size_t data_len,
        uint8_t* signature,
        size_t sig_len) {
    if (EnclaveContext::getInstance().decrypt_and_save_client_key_with_certificate(cert, cert_len,data, data_len, signature, sig_len))
      return 0;
    return -1;

}

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

int XGDMatrixCreateFromEncryptedFile(const char *fnames[],
        char* usernames[],
        xgboost::bst_ulong num_files,
        int silent,
        DMatrixHandle *out) {
    API_BEGIN();
    LOG(DEBUG) << "File: " << std::string(fnames[0]);
    bool load_row_split = false;
    if (rabit::IsDistributed()) {
        LOG(INFO) << "XGBoost distributed mode detected, "
            << "will split data among workers";
        load_row_split = true;
    }
    // FIXME consistently use uint8_t* for key bytes
    char* keys[num_files];
    std::vector<const std::string> fnames_vector;
    for (xgboost::bst_ulong i = 0; i < num_files; ++i) {
        char key[CIPHER_KEY_SIZE];
        EnclaveContext::getInstance().get_client_key((uint8_t*) key, usernames[i]);
        keys[i] = (char*) malloc(sizeof(char) * CIPHER_KEY_SIZE);
        memcpy(keys[i], key, CIPHER_KEY_SIZE);
        fnames_vector.push_back(std::string(fnames[i]));
    }
    void *mat = new std::shared_ptr<DMatrix>(DMatrix::Load(fnames_vector, silent != 0, load_row_split, true, keys));
    char* out_str  = EnclaveContext::getInstance().add_dmatrix(mat);
    *out = oe_host_strndup(out_str, strlen(out_str));
    free(out_str);
    for (int i = 0; i < num_files; ++i) {
        free(keys[i]);
    }
    API_END();
}

int XGDMatrixCreateFromFile(const char *fname,
        int silent,
        DMatrixHandle *out) {
    API_BEGIN();
    bool load_row_split = false;
    if (rabit::IsDistributed()) {
        LOG(INFO) << "XGBoost distributed mode detected, "
            << "will split data among workers";
        load_row_split = true;
    }
    void *mat = new std::shared_ptr<DMatrix>(DMatrix::Load(fname, silent != 0, load_row_split, false, NULL));
    char* out_str  = EnclaveContext::getInstance().add_dmatrix(mat);
    *out = oe_host_strndup(out_str, strlen(out_str));
    free(out_str);
    API_END();
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
  API_BEGIN();
  CHECK_HANDLE();
#ifdef __ENCLAVE__
  void* mat = EnclaveContext::getInstance().get_dmatrix(handle);
  delete static_cast<std::shared_ptr<DMatrix>*>(mat);
  EnclaveContext::getInstance().del_dmatrix(handle);
#else
  delete static_cast<std::shared_ptr<DMatrix>*>(handle);
#endif
  API_END();
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
  API_BEGIN();
  CHECK_HANDLE();
#ifdef __ENCLAVE__
  void* mat = EnclaveContext::getInstance().get_dmatrix(handle);
  static_cast<std::shared_ptr<DMatrix>*>(mat)
      ->get()->Info().SetInfo(field, info, kFloat32, len);
#else
  static_cast<std::shared_ptr<DMatrix>*>(handle)
    ->get()->Info().SetInfo(field, info, kFloat32, len);
#endif
  API_END();
}

XGB_DLL int XGDMatrixSetUIntInfo(DMatrixHandle handle,
                         const char* field,
                         const unsigned* info,
                         xgboost::bst_ulong len) {
  API_BEGIN();
  CHECK_HANDLE();
#ifdef __ENCLAVE__
  void* mat = EnclaveContext::getInstance().get_dmatrix(handle);
  static_cast<std::shared_ptr<DMatrix>*>(mat)
      ->get()->Info().SetInfo(field, info, kUInt32, len);
#else
  static_cast<std::shared_ptr<DMatrix>*>(handle)
    ->get()->Info().SetInfo(field, info, kUInt32, len);
#endif
  API_END();
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
  API_BEGIN();
  CHECK_HANDLE();
#ifdef __ENCLAVE__
  void* mat = EnclaveContext::getInstance().get_dmatrix(handle);
  const MetaInfo& info = static_cast<std::shared_ptr<DMatrix>*>(mat)->get()->Info();
#else
  const MetaInfo& info = static_cast<std::shared_ptr<DMatrix>*>(handle)->get()->Info();
#endif
  const std::vector<bst_float>* vec = nullptr;
  if (!std::strcmp(field, "label")) {
    vec = &info.labels_.HostVector();
  } else if (!std::strcmp(field, "weight")) {
    vec = &info.weights_.HostVector();
  } else if (!std::strcmp(field, "base_margin")) {
    vec = &info.base_margin_.HostVector();
  } else {
    LOG(FATAL) << "Unknown float field name " << field;
  }
  *out_len = static_cast<xgboost::bst_ulong>(vec->size());  // NOLINT
  bst_float* result = (bst_float*) oe_host_malloc(vec->size() * sizeof(bst_float));
  memcpy(result, dmlc::BeginPtr(*vec), *out_len * sizeof(bst_float));
  *out_dptr = result;
  API_END();
}

XGB_DLL int XGDMatrixGetUIntInfo(const DMatrixHandle handle,
                                 const char *field,
                                 xgboost::bst_ulong *out_len,
                                 const unsigned **out_dptr) {
  API_BEGIN();
  CHECK_HANDLE();
#ifdef __ENCLAVE__
  void* mat = EnclaveContext::getInstance().get_dmatrix(handle);
  const MetaInfo& info = static_cast<std::shared_ptr<DMatrix>*>(mat)->get()->Info();
#else
  const MetaInfo& info = static_cast<std::shared_ptr<DMatrix>*>(handle)->get()->Info();
#endif
  const std::vector<unsigned>* vec = nullptr;
  if (!std::strcmp(field, "root_index")) {
    vec = &info.root_index_;
    *out_len = static_cast<xgboost::bst_ulong>(vec->size());
    unsigned* result = (unsigned*) oe_host_malloc(vec->size() * sizeof(unsigned));
    memcpy(result, dmlc::BeginPtr(*vec), *out_len * sizeof(unsigned));
    *out_dptr = result;
  } else {
    LOG(FATAL) << "Unknown uint field name " << field;
  }
  API_END();
}

XGB_DLL int XGDMatrixNumRow(const DMatrixHandle handle,
                            xgboost::bst_ulong *out) {
  API_BEGIN();
  CHECK_HANDLE();
#ifdef __ENCLAVE__
  void* mat = EnclaveContext::getInstance().get_dmatrix(handle);
  *out = static_cast<xgboost::bst_ulong>(
      static_cast<std::shared_ptr<DMatrix>*>(mat)->get()->Info().num_row_);
#else
  *out = static_cast<xgboost::bst_ulong>(
      static_cast<std::shared_ptr<DMatrix>*>(handle)->get()->Info().num_row_);
#endif
  API_END();
}

XGB_DLL int XGDMatrixNumCol(const DMatrixHandle handle,
                            xgboost::bst_ulong *out) {
  API_BEGIN();
  CHECK_HANDLE();
#ifdef __ENCLAVE__
  void* mat = EnclaveContext::getInstance().get_dmatrix(handle);
  *out = static_cast<size_t>(
      static_cast<std::shared_ptr<DMatrix>*>(mat)->get()->Info().num_col_);
#else
  *out = static_cast<size_t>(
      static_cast<std::shared_ptr<DMatrix>*>(handle)->get()->Info().num_col_);
#endif
  API_END();
}

// xgboost implementation
XGB_DLL int XGBoosterCreate(const DMatrixHandle dmats[],
                    xgboost::bst_ulong len,
                    BoosterHandle *out) {
  API_BEGIN();
  std::vector<std::shared_ptr<DMatrix> > mats;
  for (xgboost::bst_ulong i = 0; i < len; ++i) {
#ifdef __ENCLAVE__
    void* mat = EnclaveContext::getInstance().get_dmatrix(dmats[i]);
    LOG(DEBUG) << "Got matrix";
    mats.push_back(*static_cast<std::shared_ptr<DMatrix>*>(mat));
    LOG(DEBUG) << "Pushed matrix";
#else
    mats.push_back(*static_cast<std::shared_ptr<DMatrix>*>(dmats[i]));
#endif
  }
#ifdef __ENCLAVE__
  void* booster = new Booster(mats);
  char* out_str = EnclaveContext::getInstance().add_booster(booster);
  *out = oe_host_strndup(out_str, strlen(out_str));
  free(out_str);
#else
  *out = new Booster(mats);
#endif
  API_END();
}

XGB_DLL int XGBoosterFree(BoosterHandle handle) {
  API_BEGIN();
  CHECK_HANDLE();
#ifdef __ENCLAVE__
  void* bst = EnclaveContext::getInstance().get_booster(handle);
  delete static_cast<Booster*>(bst);
  EnclaveContext::getInstance().del_dmatrix(handle);
#else
  delete static_cast<Booster*>(handle);
#endif
  API_END();
}

XGB_DLL int XGBoosterSetParamWithSig(BoosterHandle handle,
                                    const char *name,
                                    const char *value,
                                    const char *username,
                                    uint8_t *signature,
                                    size_t sig_len){
    API_BEGIN();
    CHECK_HANDLE();
    // TODO Add signature checking

    size_t data_len = strlen(name) + strlen(value) + 2 ;
    uint8_t data[data_len + 1];
    memcpy((uint8_t *)data, name, strlen(name));
    data[strlen(name)] = (uint8_t) ',';
    memcpy((uint8_t *)data+strlen(name)+1,value,strlen(value)+1);
    data[data_len] = 0;
    bool verified = EnclaveContext::getInstance().verifySignatureWithUserName(data, data_len, signature, sig_len, (char *)username);
    // TODO Add Multi User Verification + Add Verification for a list of signatures
    if(verified){
      void* bst = EnclaveContext::getInstance().get_booster(handle);
      static_cast<Booster*>(bst)->SetParam(name, value);
    }
    API_END();
}
XGB_DLL int XGBoosterSetParam(BoosterHandle handle,
                              const char *name,
                              const char *value) {
  API_BEGIN();
  CHECK_HANDLE();
  void* bst = EnclaveContext::getInstance().get_booster(handle);
  static_cast<Booster*>(bst)->SetParam(name, value);
  API_END();
}


XGB_DLL int XGBoosterUpdateOneIterWithSig(BoosterHandle handle,
                                   int iter,
                                   DMatrixHandle dtrain,
                                   char *username,
                                   uint8_t *signature,
                                   size_t sig_len){
API_BEGIN();
CHECK_HANDLE();
std::ostringstream oss;
oss << "booster_handle " << handle << " iteration " << iter << " train_data_handle " << dtrain;
const char* buff = strdup(oss.str().c_str());
bool verified = EnclaveContext::getInstance().verifySignatureWithUserName((uint8_t*)buff, strlen(buff), signature, sig_len, (char *)username);
// TODO Add Multi User Verification + Add Verification for a list of signatures
free((void*)buff); // prevent memory leak
if(verified){
  return XGBoosterUpdateOneIter(handle, iter, dtrain);
}
API_END()
                                   }

XGB_DLL int XGBoosterUpdateOneIter(BoosterHandle handle,
                                   int iter,
                                   DMatrixHandle dtrain) {
  API_BEGIN();
  CHECK_HANDLE();
#ifdef __ENCLAVE__
  auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
  auto *dtr =
    static_cast<std::shared_ptr<DMatrix>*>(EnclaveContext::getInstance().get_dmatrix(dtrain));
#else
  auto* bst = static_cast<Booster*>(handle);
  auto *dtr =
    static_cast<std::shared_ptr<DMatrix>*>(dtrain);
#endif
  bst->LazyInit();
  bst->learner()->UpdateOneIter(iter, dtr->get());
  API_END();
}

XGB_DLL int XGBoosterBoostOneIter(BoosterHandle handle,
                                  DMatrixHandle dtrain,
                                  bst_float *grad,
                                  bst_float *hess,
                                  xgboost::bst_ulong len) {
  HostDeviceVector<GradientPair> tmp_gpair;
  API_BEGIN();
  CHECK_HANDLE();
#ifdef __ENCLAVE__
  auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
  auto *dtr =
    static_cast<std::shared_ptr<DMatrix>*>(EnclaveContext::getInstance().get_dmatrix(dtrain));
#else
  auto* bst = static_cast<Booster*>(handle);
  auto* dtr =
      static_cast<std::shared_ptr<DMatrix>*>(dtrain);
#endif
  tmp_gpair.Resize(len);
  std::vector<GradientPair>& tmp_gpair_h = tmp_gpair.HostVector();
  for (xgboost::bst_ulong i = 0; i < len; ++i) {
    tmp_gpair_h[i] = GradientPair(grad[i], hess[i]);
  }

  bst->LazyInit();
  bst->learner()->BoostOneIter(0, dtr->get(), &tmp_gpair);
  API_END();
}

XGB_DLL int XGBoosterEvalOneIter(BoosterHandle handle,
                                 int iter,
                                 DMatrixHandle dmats[],
                                 const char* evnames[],
                                 xgboost::bst_ulong len,
                                 const char** out_str) {
  std::string& eval_str = XGBAPIThreadLocalStore::Get()->ret_str;
  API_BEGIN();
  CHECK_HANDLE();
#ifdef __ENCLAVE__
  auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
#else
  auto* bst = static_cast<Booster*>(handle);
#endif
  std::vector<DMatrix*> data_sets;
  std::vector<std::string> data_names;

  for (xgboost::bst_ulong i = 0; i < len; ++i) {
#ifdef __ENCLAVE__
    data_sets.push_back(static_cast<std::shared_ptr<DMatrix>*>(
          EnclaveContext::getInstance().get_dmatrix(dmats[i]))->get());
#else
    data_sets.push_back(static_cast<std::shared_ptr<DMatrix>*>(dmats[i])->get());
#endif
    data_names.emplace_back(evnames[i]);
  }

  bst->LazyInit();
  eval_str = bst->learner()->EvalOneIter(iter, data_sets, data_names);
  *out_str = oe_host_strndup(eval_str.c_str(), eval_str.length());
  API_END();
}

XGB_DLL int XGBoosterPredictWithSig(BoosterHandle handle,
                             DMatrixHandle dmat,
                             int option_mask,
                             unsigned ntree_limit,
                             xgboost::bst_ulong *len,
                             uint8_t **out_result,
                             char* username,
                             uint8_t *signature,
                             size_t sig_len) {
  API_BEGIN();
  CHECK_HANDLE();
  std::ostringstream oss;
  oss << "booster_handle " << handle << " data_handle " << dmat << " option_mask " << option_mask << " ntree_limit " << ntree_limit;
  const char* buff = strdup(oss.str().c_str());
  bool verified = EnclaveContext::getInstance().verifySignatureWithUserName((uint8_t*)buff, strlen(buff), signature, sig_len, (char *)username);
  // TODO Add Multi User Verification + Add Verification for a list of signatures
  free((void*)buff); // prevent memory leak
  if(verified){
    return XGBoosterPredict(handle, dmat, option_mask, ntree_limit, len, out_result, username);
  }
  API_END();
}




// FIXME out_result should be bst_float
XGB_DLL int XGBoosterPredict(BoosterHandle handle,
                             DMatrixHandle dmat,
                             int option_mask,
                             unsigned ntree_limit,
                             xgboost::bst_ulong *len,
                            uint8_t **out_result,
                            char* username) {
  std::vector<bst_float>&preds =
    XGBAPIThreadLocalStore::Get()->ret_vec_float;
  API_BEGIN();
  CHECK_HANDLE();
#ifdef __ENCLAVE__
  auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
#else
  auto *bst = static_cast<Booster*>(handle);
#endif
  bst->LazyInit();
  HostDeviceVector<bst_float> tmp_preds;
  bst->learner()->Predict(
#ifdef __ENCLAVE__
      static_cast<std::shared_ptr<DMatrix>*>(EnclaveContext::getInstance().get_dmatrix(dmat))->get(),
#else
      static_cast<std::shared_ptr<DMatrix>*>(dmat)->get(),
#endif
      (option_mask & 1) != 0,
      &tmp_preds, ntree_limit,
      (option_mask & 2) != 0,
      (option_mask & 4) != 0,
      (option_mask & 8) != 0,
      (option_mask & 16) != 0);
  preds = tmp_preds.HostVector();
  unsigned char key[CIPHER_KEY_SIZE];
  EnclaveContext::getInstance().get_client_key((uint8_t*)key, username);

  int preds_len = preds.size()*sizeof(float);
  size_t buf_len = CIPHER_IV_SIZE + CIPHER_TAG_SIZE + preds_len;
  unsigned char* buf  = (unsigned char*) malloc(buf_len);

  unsigned char* iv = buf;
  unsigned char* tag = buf + CIPHER_IV_SIZE;
  unsigned char* output = tag + CIPHER_TAG_SIZE;

  encrypt_symm(
          key,
          (const unsigned char*)dmlc::BeginPtr(preds),
          preds_len,
          NULL,
          0,
          output,
          iv,
          tag);

  unsigned char* host_buf  = (unsigned char*) oe_host_malloc(buf_len);
  memcpy(host_buf, buf, buf_len);
  free(buf);
  *len = static_cast<xgboost::bst_ulong>(preds.size());
  *out_result = (uint8_t*)host_buf;
  API_END();
}

XGB_DLL int XGBoosterLoadModel(BoosterHandle handle, const char* fname, char* username) {
  API_BEGIN();
  CHECK_HANDLE();
  std::unique_ptr<dmlc::Stream> fi(dmlc::Stream::Create(fname, "r"));
  size_t buf_len;
  fi->Read(&buf_len, sizeof(size_t));

  std::string& raw_str = XGBAPIThreadLocalStore::Get()->ret_str;
  raw_str.resize(buf_len);
  char* buf = dmlc::BeginPtr(raw_str);
  fi->Read(buf, buf_len);

  XGBoosterLoadModelFromBuffer(handle, buf, buf_len, username);
  API_END();
}

XGB_DLL int XGBoosterSaveModel(BoosterHandle handle, const char* fname, char *username) {
  API_BEGIN();
  CHECK_HANDLE();
  std::string& raw_str = XGBAPIThreadLocalStore::Get()->ret_str;
  raw_str.resize(0);

  common::MemoryBufferStream fo(&raw_str);
  auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
  bst->LazyInit();
  bst->learner()->Save(&fo);

  size_t buf_len = CIPHER_IV_SIZE + CIPHER_TAG_SIZE + raw_str.length();
  unsigned char* buf  = (unsigned char*) malloc(buf_len);

  unsigned char* iv = buf;
  unsigned char* tag = buf + CIPHER_IV_SIZE;
  unsigned char* output = tag + CIPHER_TAG_SIZE;
  unsigned char key[CIPHER_KEY_SIZE];
  EnclaveContext::getInstance().get_client_key((uint8_t*)key, username);

  encrypt_symm(
      key,
      (const unsigned char*)dmlc::BeginPtr(raw_str),
      raw_str.length(),
      NULL,
      0,
      output,
      iv,
      tag);

  std::unique_ptr<dmlc::Stream> fs(dmlc::Stream::Create(fname, "w"));
  fs->Write(&buf_len, sizeof(size_t));
  fs->Write(buf, buf_len);
  free(buf);
  API_END();
}

XGB_DLL int XGBoosterLoadModelFromBuffer(BoosterHandle handle,
                                 const void* buf,
                                 xgboost::bst_ulong len,
                                 char *username) {
  API_BEGIN();
  CHECK_HANDLE();
  len -= (CIPHER_IV_SIZE + CIPHER_TAG_SIZE);

  unsigned char* iv = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(buf));
  unsigned char* tag = iv + CIPHER_IV_SIZE;
  unsigned char* data = tag + CIPHER_TAG_SIZE;
  unsigned char* output = (unsigned char*) malloc (len);
  unsigned char key[CIPHER_KEY_SIZE];
  EnclaveContext::getInstance().get_client_key((uint8_t*)key, username);

  decrypt_symm(
      key,
      data,
      len,
      iv,
      tag,
      NULL,
      0,
      output);

  common::MemoryFixSizeBuffer fs((void*)output, len);  // NOLINT(*)
  static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle))->LoadModel(&fs);
  free(output);
  API_END();
}

XGB_DLL int XGBoosterGetModelRaw(BoosterHandle handle,
                         xgboost::bst_ulong* out_len,
                         const char** out_dptr,
                         char* username) {
  std::string& raw_str = XGBAPIThreadLocalStore::Get()->ret_str;
  raw_str.resize(0);

  API_BEGIN();
  CHECK_HANDLE();
  common::MemoryBufferStream fo(&raw_str);
#ifdef __ENCLAVE__
  auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
#else
  auto *bst = static_cast<Booster*>(handle);
#endif
  bst->LazyInit();
  bst->learner()->Save(&fo);
  int buf_len = CIPHER_IV_SIZE + CIPHER_TAG_SIZE + raw_str.length();
  unsigned char* buf  = (unsigned char*) malloc(buf_len);

  unsigned char* iv = buf;
  unsigned char* tag = buf + CIPHER_IV_SIZE;
  unsigned char* output = tag + CIPHER_TAG_SIZE;
  unsigned char key[CIPHER_KEY_SIZE];
  EnclaveContext::getInstance().get_client_key((uint8_t*)key, username);

  encrypt_symm(
      key,
      (const unsigned char*)dmlc::BeginPtr(raw_str),
      raw_str.length(),
      NULL,
      0,
      output,
      iv,
      tag);

  unsigned char* host_buf  = (unsigned char*) oe_host_malloc(buf_len);
  memcpy(host_buf, buf, buf_len);
  free(buf);
  *out_dptr = (const char*)host_buf;
  *out_len = static_cast<xgboost::bst_ulong>(raw_str.length()) + CIPHER_IV_SIZE + CIPHER_TAG_SIZE;
  API_END();
}

inline void XGBoostDumpModelImpl(
    BoosterHandle handle,
    const FeatureMap& fmap,
    int with_stats,
    const char *format,
    xgboost::bst_ulong* len,
    const char*** out_models) {
  std::vector<std::string>& str_vecs = XGBAPIThreadLocalStore::Get()->ret_vec_str;
#ifdef __ENCLAVE__
  auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
#else
  auto *bst = static_cast<Booster*>(handle);
#endif
  bst->LazyInit();
  str_vecs = bst->learner()->DumpModel(fmap, with_stats != 0, format);
  /* Write *out_models to user memory instead */
  unsigned char** usr_addr_model = (unsigned char**) oe_host_malloc(str_vecs.size() * sizeof(char*));

  int length;
  unsigned char* encrypted;
  unsigned char iv[CIPHER_IV_SIZE];
  unsigned char tag[CIPHER_TAG_SIZE];
  unsigned char key[CIPHER_KEY_SIZE];

  //TODO: ADD Multi client support for dump model, current fix, just dummy char pointer
  char *username;
  EnclaveContext::getInstance().get_client_key((uint8_t*) key, username);
  for (size_t i = 0; i < str_vecs.size(); ++i) {
    length = str_vecs[i].length();
    encrypted = (unsigned char*) malloc(length * sizeof(char));

    /* Encrypt */
    encrypt_symm(
        key,
        (const unsigned char*) dmlc::BeginPtr(str_vecs[i]),
        str_vecs[i].length(),
        NULL,
        0,
        encrypted,
        iv,
        tag);

    /* Base64 encode */
    std::string total_encoded = "";
    total_encoded.append(dmlc::data::base64_encode(iv, CIPHER_IV_SIZE));
    total_encoded.append(",");
    total_encoded.append(dmlc::data::base64_encode(tag, CIPHER_TAG_SIZE));
    total_encoded.append(",");
    total_encoded.append(dmlc::data::base64_encode(encrypted, length));
    total_encoded.append("\n");

    usr_addr_model[i] = (unsigned char*) oe_host_malloc(total_encoded.length() + 1);
    memcpy(usr_addr_model[i], total_encoded.c_str(), total_encoded.length() + 1);
    free(encrypted);
  }
  *out_models = (const char **) usr_addr_model;
  *len = static_cast<xgboost::bst_ulong>(str_vecs.size());
}
XGB_DLL int XGBoosterDumpModel(BoosterHandle handle,
                       const char* fmap,
                       int with_stats,
                       xgboost::bst_ulong* len,
                       const char*** out_models) {
  return XGBoosterDumpModelEx(handle, fmap, with_stats, "text", len, out_models);
}
XGB_DLL int XGBoosterDumpModelEx(BoosterHandle handle,
                       const char* fmap,
                       int with_stats,
                       const char *format,
                       xgboost::bst_ulong* len,
                       const char*** out_models) {
  API_BEGIN();
  CHECK_HANDLE();
  FeatureMap featmap;
  if (strlen(fmap) != 0) {
    std::unique_ptr<dmlc::Stream> fs(
        dmlc::Stream::Create(fmap, "r"));
    dmlc::istream is(fs.get());
    featmap.LoadText(is);
  }
  XGBoostDumpModelImpl(handle, featmap, with_stats, format, len, out_models);
  API_END();
}

XGB_DLL int XGBoosterDumpModelWithFeatures(BoosterHandle handle,
                                   int fnum,
                                   const char** fname,
                                   const char** ftype,
                                   int with_stats,
                                   xgboost::bst_ulong* len,
                                   const char*** out_models) {
  return XGBoosterDumpModelExWithFeatures(handle, fnum, fname, ftype, with_stats,
                                   "text", len, out_models);
}
XGB_DLL int XGBoosterDumpModelExWithFeatures(BoosterHandle handle,
                                   int fnum,
                                   const char** fname,
                                   const char** ftype,
                                   int with_stats,
                                   const char *format,
                                   xgboost::bst_ulong* len,
                                   const char*** out_models) {
  API_BEGIN();
  CHECK_HANDLE();
  FeatureMap featmap;
  for (int i = 0; i < fnum; ++i) {
    featmap.PushBack(i, fname[i], ftype[i]);
  }
  XGBoostDumpModelImpl(handle, featmap, with_stats, format, len, out_models);
  API_END();
}

XGB_DLL int XGBoosterGetAttr(BoosterHandle handle,
                     const char* key,
                     const char** out,
                     int* success) {
#ifdef __ENCLAVE__
  auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
#else
  auto* bst = static_cast<Booster*>(handle);
#endif
  std::string& ret_str = XGBAPIThreadLocalStore::Get()->ret_str;
  API_BEGIN();
  CHECK_HANDLE();
  if (bst->learner()->GetAttr(key, &ret_str)) {
    *out = ret_str.c_str();
    *success = 1;
  } else {
    *out = nullptr;
    *success = 0;
  }
  API_END();
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
  std::vector<std::string>& str_vecs = XGBAPIThreadLocalStore::Get()->ret_vec_str;
  std::vector<const char*>& charp_vecs = XGBAPIThreadLocalStore::Get()->ret_vec_charp;
#ifdef __ENCLAVE__
  auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
#else
  auto *bst = static_cast<Booster*>(handle);
#endif
  API_BEGIN();
  CHECK_HANDLE();
  str_vecs = bst->learner()->GetAttrNames();
  charp_vecs.resize(str_vecs.size());
  for (size_t i = 0; i < str_vecs.size(); ++i) {
    charp_vecs[i] = str_vecs[i].c_str();
  }
  *out = dmlc::BeginPtr(charp_vecs);
  *out_len = static_cast<xgboost::bst_ulong>(charp_vecs.size());
  API_END();
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
 *
 * // force link rabit
 * static DMLC_ATTRIBUTE_UNUSED int XGBOOST_LINK_RABIT_C_API_ = RabitLinkTag();
 */
