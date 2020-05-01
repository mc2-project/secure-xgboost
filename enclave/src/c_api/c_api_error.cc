/*!
 *  Copyright (c) 2015 by Contributors
 * \file c_api_error.cc
 * \brief C error handling
 */
#include <xgboost/c_api/c_api_error.h>

#if false  // FIXME: Should we enable this within enclave?
#include <dmlc/thread_local.h>

struct XGBAPIErrorEntry {
  std::string last_error;
};

using XGBAPIErrorStore = dmlc::ThreadLocalStore<XGBAPIErrorEntry>;

const char *XGBGetLastError() {
  return XGBAPIErrorStore::Get()->last_error.c_str();
}

void XGBAPISetLastError(const char* msg) {
  XGBAPIErrorStore::Get()->last_error = msg;
}
#else 
// Enclave thread locals get erased on an enclave exit
// So we save the error message at the host instead
#include "xgboost_t.h"

void XGBAPISetLastError(const char* msg) {
  // FIXME: safe ocall
  host_XGBAPISetLastError(msg);
}

#endif
