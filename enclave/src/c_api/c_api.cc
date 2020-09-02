// Copyright (c) 2014 by Contributors
// Modifications Copyright (c) 2020 by Secure XGBoost Contributors


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
#include "../common/math.h"
#include "../common/io.h"

#include "xgboost_t.h"
#include <enclave/crypto.h>
#include "enclave_context.h"

using namespace xgboost; // NOLINT(*);

using Booster = Learner;

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
 * Return the public key of this enclave along with the enclave's remote report
 * and a sequence number to be used by clients.
 * The enclave that receives the key will use the remote report to attest this
 * enclave.
 */
int get_remote_report_with_pubkey_and_nonce(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** nonce,
    size_t* nonce_size,
    uint8_t** remote_report,
    size_t* remote_report_size) {

  uint8_t* report = NULL;
  size_t report_size = 0;
  uint8_t* key_buf = NULL;
  int ret = 1;
  uint8_t* public_key = EnclaveContext::getInstance().get_public_key();
  uint8_t* enclave_nonce = EnclaveContext::getInstance().get_nonce();

#ifdef __ENCLAVE_SIMULATION__
  key_buf = (uint8_t*)oe_host_malloc(CIPHER_PK_SIZE);
  if (key_buf == NULL) {
    ret = OE_OUT_OF_MEMORY;
    return ret;
  }
  memcpy(key_buf, public_key, CIPHER_PK_SIZE);

  *pem_key = key_buf;
  *key_size = CIPHER_PK_SIZE;

  uint8_t* nonce_buf = (uint8_t*)oe_host_malloc(CIPHER_IV_SIZE);
  if (nonce_buf == NULL) {
    ret = OE_OUT_OF_MEMORY;
    return ret;
  }
  memcpy(nonce_buf, enclave_nonce, CIPHER_IV_SIZE);

  *nonce = nonce_buf;
  *nonce_size = CIPHER_IV_SIZE;

  ret = 0;

#else
  uint8_t report_data[CIPHER_PK_SIZE + CIPHER_IV_SIZE];
  memcpy(report_data, public_key, CIPHER_PK_SIZE);
  memcpy(report_data + CIPHER_PK_SIZE, enclave_nonce, CIPHER_IV_SIZE);
  if (generate_remote_report(report_data, CIPHER_PK_SIZE + CIPHER_IV_SIZE, &report, &report_size)) {
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

    uint8_t* nonce_buf = (uint8_t*)oe_host_malloc(CIPHER_IV_SIZE);
    if (nonce_buf == NULL) {
      ret = OE_OUT_OF_MEMORY;
      if (report)
        oe_free_report(report);
      if (*remote_report)
        oe_host_free(*remote_report);
      return ret;
    }
    memcpy(nonce_buf, enclave_nonce, CIPHER_IV_SIZE);

    *nonce = nonce_buf;
    *nonce_size = CIPHER_IV_SIZE;

    ret = 0;
    LOG(INFO) << "get_remote_report_with_pubkey succeeded";
  } else {
    LOG(FATAL) << "get_remote_report_with_pubkey failed.";
  }
#endif
  return ret;
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
    API_BEGIN();
    EnclaveContext::getInstance().decrypt_and_save_client_key_with_certificate(cert, cert_len, data, data_len, signature, sig_len);
    API_END();
}

int get_enclave_symm_key(char* username, uint8_t** out, size_t* out_size) {
  API_BEGIN();
  unsigned char key[CIPHER_KEY_SIZE];
  EnclaveContext::getInstance().get_client_key((uint8_t*)key, username);
  uint8_t* pt = EnclaveContext::getInstance().get_symm_key();

  size_t buf_len = CIPHER_IV_SIZE + CIPHER_TAG_SIZE + CIPHER_KEY_SIZE;
  unsigned char* buf  = (unsigned char*) malloc(buf_len);

  unsigned char* iv = buf;
  unsigned char* tag = buf + CIPHER_IV_SIZE;
  unsigned char* output = tag + CIPHER_TAG_SIZE;

  encrypt_symm(
      key,
      (const unsigned char*)pt,
      CIPHER_KEY_SIZE,
      NULL,
      0,
      output,
      iv,
      tag);

  unsigned char* host_buf  = (unsigned char*) oe_host_malloc(buf_len);
  memcpy(host_buf, buf, buf_len);
  free(buf);
  *out = (uint8_t*)host_buf;
  *out_size = CIPHER_KEY_SIZE;

  API_END();
}

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
	bool load_row_split = false;
	if (rabit::IsDistributed()) {
		LOG(INFO) << "XGBoost distributed mode detected, "
			<< "will split data among workers";
		load_row_split = true;
	}

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
	char* out_str  = EnclaveContext::getInstance().add_dmatrix(mat, usernames, num_files);
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
	char* out_str  = EnclaveContext::getInstance().add_dmatrix(mat, NULL, 0);
	*out = oe_host_strndup(out_str, strlen(out_str));
	free(out_str);
	API_END();
}

XGB_DLL int XGDMatrixFree(DMatrixHandle handle) {
	API_BEGIN();
	CHECK_HANDLE();
	void* mat = EnclaveContext::getInstance().get_dmatrix(handle);
	delete static_cast<std::shared_ptr<DMatrix>*>(mat);
	EnclaveContext::getInstance().del_dmatrix(handle);
	API_END();
}

XGB_DLL int XGDMatrixSetFloatInfo(DMatrixHandle handle,
                          const char* field,
                          const bst_float* info,
                          xgboost::bst_ulong len) {
  API_BEGIN();
  CHECK_HANDLE();
  void* mat = EnclaveContext::getInstance().get_dmatrix(handle);
  static_cast<std::shared_ptr<DMatrix>*>(mat)
      ->get()->Info().SetInfo(field, info, xgboost::DataType::kFloat32, len);
  API_END();
}

XGB_DLL int XGDMatrixSetUIntInfo(DMatrixHandle handle,
                         const char* field,
                         const unsigned* info,
                         xgboost::bst_ulong len) {
  API_BEGIN();
  CHECK_HANDLE();
  void* mat = EnclaveContext::getInstance().get_dmatrix(handle);
  static_cast<std::shared_ptr<DMatrix>*>(mat)
      ->get()->Info().SetInfo(field, info, xgboost::DataType::kUInt32, len);
  API_END();
}

XGB_DLL int XGDMatrixGetFloatInfo(const DMatrixHandle handle,
                                  const char* field,
                                  xgboost::bst_ulong* out_len,
                                  const bst_float** out_dptr) {
  API_BEGIN();
  CHECK_HANDLE();
  void* mat = EnclaveContext::getInstance().get_dmatrix(handle);
  const MetaInfo& info = static_cast<std::shared_ptr<DMatrix>*>(mat)->get()->Info();
  info.GetInfo(field, out_len, DataType::kFloat32, reinterpret_cast<void const**>(out_dptr));

  bst_float* result = (bst_float*) oe_host_malloc(*out_len * sizeof(bst_float));
  memcpy(result, *out_dptr, *out_len * sizeof(bst_float));
  *out_dptr = result;
  API_END();
}

XGB_DLL int XGDMatrixGetUIntInfo(const DMatrixHandle handle,
                                 const char *field,
                                 xgboost::bst_ulong *out_len,
                                 const unsigned **out_dptr) {
  API_BEGIN();
  CHECK_HANDLE();
  void* mat = EnclaveContext::getInstance().get_dmatrix(handle);
  const MetaInfo& info = static_cast<std::shared_ptr<DMatrix>*>(mat)->get()->Info();
  info.GetInfo(field, out_len, DataType::kUInt32, reinterpret_cast<void const**>(out_dptr));

  unsigned* result = (unsigned*) oe_host_malloc(*out_len * sizeof(unsigned));
  memcpy(result, *out_dptr, *out_len * sizeof(unsigned));
  *out_dptr = result;
  API_END();
}

XGB_DLL int XGDMatrixNumRow(const DMatrixHandle handle,
                            xgboost::bst_ulong *out) {
  API_BEGIN();
  CHECK_HANDLE();

  void* mat = EnclaveContext::getInstance().get_dmatrix(handle);
  *out = static_cast<xgboost::bst_ulong>(
      static_cast<std::shared_ptr<DMatrix>*>(mat)->get()->Info().num_row_);

  API_END();
}

XGB_DLL int XGDMatrixNumCol(const DMatrixHandle handle,
                            xgboost::bst_ulong *out) {
  API_BEGIN();
  CHECK_HANDLE();

  void* mat = EnclaveContext::getInstance().get_dmatrix(handle);
  *out = static_cast<size_t>(
      static_cast<std::shared_ptr<DMatrix>*>(mat)->get()->Info().num_col_);

  API_END();
}

// xgboost implementation
XGB_DLL int XGBoosterCreate(const DMatrixHandle dmats[],
                    xgboost::bst_ulong len,
                    BoosterHandle *out) {
  API_BEGIN();

  std::vector<std::shared_ptr<DMatrix> > mats;
  for (xgboost::bst_ulong i = 0; i < len; ++i) {
    void* mat = EnclaveContext::getInstance().get_dmatrix(dmats[i]);
    LOG(DEBUG) << "Got matrix";
    mats.push_back(*static_cast<std::shared_ptr<DMatrix>*>(mat));
    LOG(DEBUG) << "Pushed matrix";
  }
  void* booster = Learner::Create(mats);
  char* out_str = EnclaveContext::getInstance().add_booster(booster);
  *out = oe_host_strndup(out_str, strlen(out_str));

  free(out_str);
  API_END();
}

XGB_DLL int XGBoosterFree(BoosterHandle handle) {
  API_BEGIN();
  CHECK_HANDLE();
  void* bst = EnclaveContext::getInstance().get_booster(handle);
  delete static_cast<Booster*>(bst);
  EnclaveContext::getInstance().del_dmatrix(handle);
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


XGB_DLL int XGBoosterUpdateOneIter(BoosterHandle handle,
                                   int iter,
                                   DMatrixHandle dtrain) {
  API_BEGIN();
  CHECK_HANDLE();

  auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
  auto *dtr =
    static_cast<std::shared_ptr<DMatrix>*>(EnclaveContext::getInstance().get_dmatrix(dtrain));
  bst->UpdateOneIter(iter, *dtr);

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
  auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
  auto *dtr =
    static_cast<std::shared_ptr<DMatrix>*>(EnclaveContext::getInstance().get_dmatrix(dtrain));
  tmp_gpair.Resize(len);
  std::vector<GradientPair>& tmp_gpair_h = tmp_gpair.HostVector();
  for (xgboost::bst_ulong i = 0; i < len; ++i) {
    tmp_gpair_h[i] = GradientPair(grad[i], hess[i]);
  }

  bst->BoostOneIter(0, *dtr, &tmp_gpair);
  API_END();
}

XGB_DLL int XGBoosterEvalOneIter(BoosterHandle handle,
                                 int iter,
                                 DMatrixHandle dmats[],
                                 const char* evnames[],
                                 xgboost::bst_ulong len,
                                 const char** out_str) {
  API_BEGIN();
  CHECK_HANDLE();
  auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
	std::string& eval_str = bst->GetThreadLocal().ret_str;
	std::vector<std::shared_ptr<DMatrix>> data_sets;
  std::vector<std::string> data_names;

  for (xgboost::bst_ulong i = 0; i < len; ++i) {
		void* mat = EnclaveContext::getInstance().get_dmatrix(dmats[i]);
		data_sets.push_back(*static_cast<std::shared_ptr<DMatrix>*>(mat));
    data_names.emplace_back(evnames[i]);
  }

  eval_str = bst->EvalOneIter(iter, data_sets, data_names);
  *out_str = oe_host_strndup(eval_str.c_str(), eval_str.length());
  API_END();
}

XGB_DLL int XGBoosterPredict(BoosterHandle handle,
                             DMatrixHandle dmat,
                             int option_mask,
                             unsigned ntree_limit,
                             int training,
                             xgboost::bst_ulong *len,
                             uint8_t **out_result) {
  API_BEGIN();
  CHECK_HANDLE();

  auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
  auto& entry = bst->GetThreadLocal().prediction_entry;
	void* mat = EnclaveContext::getInstance().get_dmatrix(dmat);
  bst->Predict(
			*static_cast<std::shared_ptr<DMatrix>*>(mat),
      (option_mask & 1) != 0,
      &entry.predictions, ntree_limit,
			static_cast<bool>(training),
      (option_mask & 2) != 0,
      (option_mask & 4) != 0,
      (option_mask & 8) != 0,
      (option_mask & 16) != 0);
	std::vector<bst_float>&preds = entry.predictions.HostVector();
  unsigned char key[CIPHER_KEY_SIZE];
  std::vector<std::string> owners = EnclaveContext::getInstance().get_dmatrix_owners(dmat);
  if (owners.size() != 1) {
    LOG(FATAL) << "Cannot run prediction on data owned by multiple users";
  }
  EnclaveContext::getInstance().get_client_key((uint8_t*)key, (char*)owners[0].c_str());

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
  *len = static_cast<xgboost::bst_ulong>(preds.size());
  *out_result = (uint8_t*)host_buf;

  free(buf);
  API_END();
}

// TODO(rishabh): Server can replace file contents
XGB_DLL int XGBoosterLoadModel(BoosterHandle handle, const char* fname) {
    API_BEGIN();
    CHECK_HANDLE();

    // TODO(rishabh): Support JSON
    if (common::FileExtension(fname) == "json") {
      LOG(FATAL) << "Loading from JSON not yet supported";
    } else {
      std::unique_ptr<dmlc::Stream> fi(dmlc::Stream::Create(fname, "r"));
      size_t buf_len;
      fi->Read(&buf_len, sizeof(size_t));

			auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
			std::string& raw_str = bst->GetThreadLocal().ret_str;
      raw_str.resize(buf_len);
      char* buf = dmlc::BeginPtr(raw_str);
      fi->Read(buf, buf_len);

      buf_len -= (CIPHER_IV_SIZE + CIPHER_TAG_SIZE);

      unsigned char* iv = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(buf));
      unsigned char* tag = iv + CIPHER_IV_SIZE;
      unsigned char* data = tag + CIPHER_TAG_SIZE;
      unsigned char* output = (unsigned char*) malloc (buf_len);
      unsigned char* key = EnclaveContext::getInstance().get_symm_key();

      decrypt_symm(
          key,
          data,
          buf_len,
          iv,
          tag,
          NULL,
          0,
          output);

      common::MemoryFixSizeBuffer fs((void*)output, buf_len);  // NOLINT(*)

      static_cast<Booster*>(bst)->LoadModel(&fs);
      free(output);
    }

    API_END();
}

XGB_DLL int XGBoosterSaveModel(BoosterHandle handle, const char* fname) {
    API_BEGIN();
    CHECK_HANDLE();

    if (common::FileExtension(fname) == "json") {
      LOG(FATAL) << "Loading from JSON not yet supported";
    } else {
			auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
			std::string& raw_str = bst->GetThreadLocal().ret_str;
      raw_str.resize(0);

      common::MemoryBufferStream fo(&raw_str);
      bst->Save(&fo);

      size_t buf_len = CIPHER_IV_SIZE + CIPHER_TAG_SIZE + raw_str.length();
      unsigned char* buf  = (unsigned char*) malloc(buf_len);

      unsigned char* iv = buf;
      unsigned char* tag = buf + CIPHER_IV_SIZE;
      unsigned char* output = tag + CIPHER_TAG_SIZE;
      unsigned char* key = EnclaveContext::getInstance().get_symm_key();

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
    }

    API_END();
}

// TODO(rishabh): Add nonce + output signatures
XGB_DLL int XGBoosterLoadModelFromBuffer(BoosterHandle handle,
                                         const void* buf,
                                         xgboost::bst_ulong len) {
    API_BEGIN();
    CHECK_HANDLE();

    len -= (CIPHER_IV_SIZE + CIPHER_TAG_SIZE);

    unsigned char* iv = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(buf));
    unsigned char* tag = iv + CIPHER_IV_SIZE;
    unsigned char* data = tag + CIPHER_TAG_SIZE;
    unsigned char* output = (unsigned char*) malloc (len);
    unsigned char* key = EnclaveContext::getInstance().get_symm_key();

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
                                 const char** out_dptr) {
    API_BEGIN();
    CHECK_HANDLE();

    auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
		std::string& raw_str = bst->GetThreadLocal().ret_str;
		raw_str.resize(0);
		common::MemoryBufferStream fo(&raw_str);
    bst->Configure();
    bst->SaveModel(&fo);
    int buf_len = CIPHER_IV_SIZE + CIPHER_TAG_SIZE + raw_str.length();
    unsigned char* buf  = (unsigned char*) malloc(buf_len);

    unsigned char* iv = buf;
    unsigned char* tag = buf + CIPHER_IV_SIZE;
    unsigned char* output = tag + CIPHER_TAG_SIZE;
    unsigned char* key = EnclaveContext::getInstance().get_symm_key();

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
    *out_dptr = (const char*)host_buf;
    *out_len = static_cast<xgboost::bst_ulong>(raw_str.length()) + CIPHER_IV_SIZE + CIPHER_TAG_SIZE;

    free(buf);
    API_END();
}

inline void XGBoostDumpModelImpl(
    BoosterHandle handle,
    const FeatureMap& fmap,
    int with_stats,
    const char *format,
    xgboost::bst_ulong* len,
    const char*** out_models) {
  auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
	std::vector<std::string>& str_vecs = bst->GetThreadLocal().ret_vec_str;
  str_vecs = bst->DumpModel(fmap, with_stats != 0, format);
  /* Write *out_models to user memory instead */
  unsigned char** usr_addr_model = (unsigned char**) oe_host_malloc(str_vecs.size() * sizeof(char*));

  int length;
  unsigned char* encrypted;
  unsigned char iv[CIPHER_IV_SIZE];
  unsigned char tag[CIPHER_TAG_SIZE];
  unsigned char* key;

  key = EnclaveContext::getInstance().get_symm_key();
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

// TODO(rishabhp): Enable this
XGB_DLL int XGBoosterDumpModel(BoosterHandle handle,
                       const char* fmap,
                       int with_stats,
                       xgboost::bst_ulong* len,
                       const char*** out_models) {
  LOG(FATAL) << "XGBoosterDumpModel not supported";
  //return XGBoosterDumpModelEx(handle, fmap, with_stats, "text", len, out_models);
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

// TODO(rishabhp): Enable this
XGB_DLL int XGBoosterDumpModelWithFeatures(BoosterHandle handle,
                                   int fnum,
                                   const char** fname,
                                   const char** ftype,
                                   int with_stats,
                                   xgboost::bst_ulong* len,
                                   const char*** out_models) {
  LOG(FATAL) << "XGBoosterDumpModelWithFeatures not supported";
}

/* redundant definition
XGB_DLL int XGBoosterGetAttr(BoosterHandle handle,
                     const char* key,
                     const char** out,
                     int* success) {
  auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
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
*/

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
  auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
	std::string& ret_str = bst->GetThreadLocal().ret_str;
  API_BEGIN();
  CHECK_HANDLE();
  if (bst->GetAttr(key, &ret_str)) {
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
	auto* bst = static_cast<Booster*>(EnclaveContext::getInstance().get_booster(handle));
  std::vector<std::string>& str_vecs = bst->GetThreadLocal().ret_vec_str;
  std::vector<const char*>& charp_vecs = bst->GetThreadLocal().ret_vec_charp;
  API_BEGIN();
  CHECK_HANDLE();
  str_vecs = bst->GetAttrNames();
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
