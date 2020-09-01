/*
 * Modifications Copyright 2020 by Secure XGBoost Contributors
 */
#ifdef __ENCLAVE_OBLIVIOUS__
#include "quantile.h"

namespace xgboost {
namespace common {
namespace {

#ifdef __ENCLAVE_OBLIVIOUS__
constexpr bool kEnableObliviousCombine = true;
constexpr bool kEnableObliviousPrune = true;
constexpr bool kEnableObliviousDebugCheck = false;
constexpr bool kEnableOblivious = true;
#else
constexpr bool kEnableObliviousCombine = false;
constexpr bool kEnableObliviousPrune = false;
constexpr bool kEnableObliviousDebugCheck = false;
constexpr bool kEnableOblivious = false;
#endif

} // namespace

bool ObliviousSetCombineEnabled() {
  return kEnableObliviousCombine;
}

bool ObliviousEnabled() {
  return kEnableOblivious;
}

bool ObliviousSetPruneEnabled() {
  return kEnableObliviousPrune;
}

bool ObliviousDebugCheckEnabled() {
  return kEnableObliviousDebugCheck;
}

}  // namespace common
}  // namespace xgboost
#endif  // __ENCLAVE_OBLIVIOUS__ 
