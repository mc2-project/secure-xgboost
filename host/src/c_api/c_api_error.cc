/*!
 *  Copyright (c) 2015 by Contributors
 *  Modifications Copyright (c) 2020 by Secure XGBoost Contributors
 * \file c_api_error.cc
 * \brief C error handling
 */
#include <dmlc/thread_local.h>
#include <xgboost/c_api/c_api_error.h>

#ifdef __ENCLAVE_CONSENSUS__
#include "xgboost_mc_u.h"
#else
#include "xgboost_u.h"
#endif

struct XGBAPIErrorEntry {
  std::string last_error;
};

using XGBAPIErrorStore = dmlc::ThreadLocalStore<XGBAPIErrorEntry>;

XGB_DLL const char *XGBGetLastError() {
  return XGBAPIErrorStore::Get()->last_error.c_str();
}

void XGBAPISetLastError(const char* msg) {
  XGBAPIErrorStore::Get()->last_error = msg;
}

void host_XGBAPISetLastError(const char* msg) {
	XGBAPISetLastError(msg);
}
