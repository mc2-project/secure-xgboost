#include <src/common/obl_primitives.h>
#include <src/common/quantile.h>
#include <stdlib.h>

#include <algorithm>
#include <iostream>
#include <vector>

#include "arr_A.h"
using namespace xgboost::common;

int main(int argc, char* argv[]) {
  WXQuantileSketch<float, float>::SummaryContainer out;
  WXQuantileSketch<float, float> sketchs;
  sketchs.Init(64, 1.0);
  sketchs.limit_size = 50;
  sketchs.nlevel = 3;
  sketchs.inqueue.queue.resize(sketchs.limit_size * 2);
  for (size_t i = 0; i < 100; i++) {
    sketchs.inqueue.Push(V[i], 1);
  }

  WXQuantileSketch<float, float>::SummaryContainer sa;
  WXQuantileSketch<float, float>::SummaryContainer sb;
  sa.Reserve(sketchs.inqueue.queue.size());
  sb.Reserve(sketchs.inqueue.queue.size());
  out.Reserve(sketchs.inqueue.queue.size());
  // test for MakeSummaryOblivious
  sketchs.inqueue.MakeSummaryOblivious(&out);
  sb.CopyFromSize(out, 30);
  sa.CopyFromSize(out, 30);
  // test fo ObliviousSetPrune
   out.ObliviousSetPrune(out,10);
  // test for ObliviousSetCombine
   out.ObliviousSetCombine(sa,sb);
}
