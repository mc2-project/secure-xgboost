#!/bin/bash

# make -f dmlc-core/scripts/packages.mk lz4

source $HOME/miniconda/bin/activate

if [ ${TASK} == "python_test" ]; then
    set -e
    # Build/test without oblviousness and AVX
    rm -rf build
    mkdir build && cd build
    cmake .. ${CMAKE_COMMON_FLAGS} -DOBLIVIOUS=OFF -DUSE_AVX2=OFF
    make -j4
    cd ..
    rm -rf build

    echo "-------------------------------"
    conda activate python3
    python --version
    # conda install numpy pandas sklearn numproto grpcio grpcio-tools kubernetes

    # Installing the python package
    cd ../../python-package
    python3 setup.py install
    cd ../ # Back in mc2-xgboost directory

    # Install python dependencies
    python -m pip install graphviz pytest pytest-cov codecov
    python -m pip install datatable
    python -m pip install numpy pandas sklearn numproto grpcio grpcio-tools kubernetes

    # Start python tests
    python -m pytest -v --fulltrace -s tests/python --cov=python-package/xgboost || exit -1
    codecov
fi

if [ ${TASK} == "cmake_test" ]; then
    set -e

    CMAKE_COMMON_FLAGS='-DOE_DEBUG=1 -DSIMULATE=ON -DLVI_MITIGATION=OFF'
    # Build/test without obliviousness
    rm -rf build
    mkdir build && cd build
    cmake .. ${CMAKE_COMMON_FLAGS} -DOBLIVIOUS=OFF -DUSE_AVX2=OFF
    make -j4
    cd ..
    rm -rf build

    # Build/test with obliviousness, without AVX
    mkdir build && cd build
    cmake .. ${CMAKE_COMMON_FLAGS} -DOBLIVIOUS=ON -DUSE_AVX2=OFF
    make -j4
    cd ..
    rm -rf build

    # Build/test with obliviousness and AVX
    mkdir build && cd build
    cmake .. ${CMAKE_COMMON_FLAGS} -DOBLIVIOUS=ON -DUSE_AVX2=ON
    make -j4
    cd ..
    rm -rf build
fi
