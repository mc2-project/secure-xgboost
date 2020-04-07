#include <xgboost/common/obl_primitives.h>
#include <iostream>
#include <algorithm>
#include <stdlib.h>
#include <vector>
#include "arr_A.h"

void sort(std::vector<int> &V, char* algo, size_t n) {
    if (!strcmp(algo, "S")) {
        std::sort(V.begin(), V.end());
    } else {
        ObliviousSort(V.begin(), V.end());
    }
}

int main(int argc, char* argv[]) {
    sort (V, argv[1], 1000);
}
