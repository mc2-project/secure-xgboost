/*
 * Modifications Copyright 2020 by Secure XGBoost Contributors
 */
#include "quantile.h"

namespace xgboost {
namespace common {
namespace {

#ifdef __ENCLAVE_OBLIVIOUS__
constexpr bool kEnableObliviousCombine = true;
constexpr bool kEnableObliviousPrune = true;
// FIXME will setting to true work after the changes for padding?
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
