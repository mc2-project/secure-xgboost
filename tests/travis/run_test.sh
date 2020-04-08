#!/bin/bash

#make -f dmlc-core/scripts/packages.mk lz4
#
#source $HOME/miniconda/bin/activate
#
#if [ ${TASK} == "python_sdist_test" ]; then
#    set -e
#
#    conda activate python3
#    python --version
#    conda install numpy scipy
#
#    make pippack
#    python -m pip install xgboost-*.tar.gz -v --user
#    python -c 'import xgboost' || exit -1
#fi
#
#if [ ${TASK} == "python_test" ]; then
#    set -e
#    # Build/test
#    rm -rf build
#    mkdir build && cd build
#    cmake .. -DUSE_OPENMP=ON -DCMAKE_VERBOSE_MAKEFILE=ON
#    make -j$(nproc)
#    cd ..
#
#    echo "-------------------------------"
#    conda activate python3
#    python --version
#    conda install numpy scipy pandas matplotlib scikit-learn dask
#
#    python -m pip install graphviz pytest pytest-cov codecov
#    python -m pip install datatable
#    python -m pytest -v --fulltrace -s tests/python --cov=python-package/xgboost || exit -1
#    codecov
#fi
#
#if [ ${TASK} == "java_test" ]; then
#    export RABIT_MOCK=ON
#    conda activate python3
#    cd jvm-packages
#    mvn -q clean install -DskipTests -Dmaven.test.skip
#    mvn -q test
#fi

if [ ${TASK} == "lint" ]; then
    mkdir build && cd build
    cmake ..
    make lint || exit -1
    cd ..
    rm -rf build
fi

if [ ${TASK} == "cmake_test" ]; then
    set -e

    # Build/test without obliviousness
    rm -rf build
    mkdir build && cd build
    cmake .. -DOE_DEBUG=1 -DSIMULATE=ON -DOBLIVIOUS=OFF -DUSE_AVX2=OFF
    make -j4
    cd ..
    rm -rf build

    # Build/test with obliviousness, without AVX
    mkdir build && cd build
    cmake .. -DOE_DEBUG=1 -DSIMULATE=ON -DOBLIVIOUS=ON -DUSE_AVX2=OFF
    make -j4
    cd ..
    rm -rf build

    # Build/test with obliviousness and AVX
    mkdir build && cd build
    cmake .. -DOE_DEBUG=1 -DSIMULATE=ON -DOBLIVIOUS=ON -DUSE_AVX2=ON
    make -j4
    cd ..
    rm -rf build
fi
