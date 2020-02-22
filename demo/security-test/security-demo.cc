/*!
 * \file security-demo.c
 * \brief A simple example of how an enclave protects memory. 
 */

#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <xgboost/c_api.h>
#include <xgboost/data.h>

#ifdef __SGX__
#include <xgboost/crypto.h>
#include <openenclave/host.h>

static char test_key[CIPHER_KEY_SIZE] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
};

bool check_simulate_opt(int* argc, char* argv[]) {
  for (int i = 0; i < *argc; i++) {
    if (strcmp(argv[i], "--simulate") == 0) {
      std::cout << "Running in simulation mode" << std::endl;
      memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char*));
      (*argc)--;
      return true;
    }
  }
  return false;
}
#endif

#define safe_xgboost(call) {                                            \
int err = (call);                                                       \
if (err != 0) {                                                         \
  fprintf(stderr, "%s:%d: error in %s: %s\n", __FILE__, __LINE__, #call, XGBGetLastError()); \
  exit(1);                                                              \
}                                                                       \
}

int main(int argc, char** argv) {

#ifdef __SGX__
  for (int i = 0; i < argc; i++) {
    if (strcmp(argv[i], "--encrypt") == 0) {
      encrypt_file_with_keybuf("../data/agaricus.txt.train", "train.encrypted", test_key);
      encrypt_file_with_keybuf("../data/agaricus.txt.test", "test.encrypted", test_key);
      return 0;
    }
  }

  uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
  bool simulate = false;
  if (check_simulate_opt(&argc, argv)) {
    simulate = true;
    flags |= OE_ENCLAVE_FLAG_SIMULATE;
  }

  std::cout << "Creating enclave\n";
  int log_verbosity = 1;
  XGBCreateEnclave(argv[1], flags, log_verbosity);
  
  oe_result_t result;
  int ret = 1;

  std::string fname1("/home/xgb/secure-xgboost/demo/c-api/train.encrypted");
  std::string fname2("/home/xgb/secure-xgboost/demo/c-api/test.encrypted");
#endif

  int silent = 1;
  int use_gpu = 0; // set to 1 to use the GPU for training
  
  // load the data
  DMatrixHandle dtrain, dtest;
#ifdef __SGX__
  safe_xgboost(XGDMatrixCreateFromEncryptedFile((const char*)fname1.c_str(), silent, &dtrain));
  safe_xgboost(XGDMatrixCreateFromEncryptedFile((const char*)fname2.c_str(), silent, &dtest));
#else
  safe_xgboost(XGDMatrixCreateFromFile("../data/agaricus.txt.train", silent, &dtrain));
  safe_xgboost(XGDMatrixCreateFromFile("../data/agaricus.txt.test", silent, &dtest));
#endif
  std::cout << "Data loaded" << std::endl;

  bst_ulong training_label_len = 0;
  const float* training_labels = NULL;
  const xgboost::MetaInfo& info = static_cast<std::shared_ptr<xgboost::DMatrix>*>(dtrain)->get()->Info();
  const std::vector<float>* vec = nullptr;
  vec = &info.labels_.HostVector();
  training_labels = dmlc::BeginPtr(*vec);
  std::cout << "Printing out training data labels...\n";
  for (int i = 0; i < 20; ++i) {
      printf("%1.4f ", training_labels[i]);
  }
  printf("\n");
  static_cast<std::shared_ptr<xgboost::DMatrix>*>(dtrain)->get()->Info();

  safe_xgboost(XGDMatrixFree(dtrain));
  safe_xgboost(XGDMatrixFree(dtest));
  return 0;
}
