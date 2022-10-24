# Secure XGBoost

[![Build Status](https://travis-ci.org/mc2-project/secure-xgboost.svg?branch=master)](https://travis-ci.org/mc2-project/secure-xgboost)
![Documentation Status](https://github.com/mc2-project/secure-xgboost/actions/workflows/docs.yml/badge.svg)
![Contributions welcome](https://img.shields.io/badge/contributions-welcome-orange.svg)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[<img src="https://img.shields.io/badge/slack-contact%20us-blueviolet?logo=slack">](https://join.slack.com/t/mc2-project/shared_invite/zt-rt3kxyy8-GS4KA0A351Ysv~GKwy8NEQ)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](CODE_OF_CONDUCT.md)

Secure XGBoost is a library that leverages secure enclaves and data-oblivious algorithms to enable the **collaborative training of and inference using [XGBoost](https://github.com/dmlc/xgboost) models on encrypted data**. 

Data owners can use Secure XGBoost to train a model on a remote server, e.g., the cloud, _without_ revealing the underlying data to the remote server. Collaborating data owners can use the library to jointly train a model on their collective data without exposing their individual data to each other.
![Alt Text](doc/images/workflow.gif)

This project is currently under development as part of the broader [**MC<sup>2</sup>** effort](https://github.com/mc2-project/mc2) (i.e., **M**ultiparty **C**ollaboration and **C**oopetition) by the UC Berkeley [RISE Lab](https://rise.cs.berkeley.edu/).

**NOTE:** The Secure XGBoost library is a research prototype, and has not yet received independent code review. 

## Table of Contents
* [Installation](#installation)
* [Docker build for local development](#docker-build-for-local-development)
* [Usage](#usage)
* [Documentation](#documentation)
* [Additional Resources](#additional-resources)
* [Getting Involved](#getting-involved)

## Installation
The following instructions will create an environment from scratch. Note that Secure XGBoost has only been tested on Ubuntu 18.04, so **we recommend that you install everything on Ubuntu 18.04**.

1. Install the Open Enclave SDK (0.17.1) and the Intel SGX DCAP driver by following [these instructions](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md). In Step 3 of the instructions, install Open Enclave version 0.17.1 by specifying the version:

    ```sh
    sudo apt -y install clang-8 libssl-dev gdb libsgx-enclave-common libsgx-quote-ex libprotobuf10 libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client open-enclave=0.17.1

    ```

2. Configure the required environment variables.

    ```sh
    source /opt/openenclave/share/openenclave/openenclaverc
    ```

3. Install CMake and other Secure XGBoost dependencies.

    ```sh
    wget https://github.com/Kitware/CMake/releases/download/v3.15.6/cmake-3.15.6-Linux-x86_64.sh
    sudo bash cmake-3.15.6-Linux-x86_64.sh --skip-license --prefix=/usr/local

    sudo apt-get install -y libmbedtls-dev python3-pip
    pip3 install numpy pandas sklearn numproto grpcio grpcio-tools requests
    ```

4. Clone Secure XGBoost.

    ```sh
    git clone https://github.com/mc2-project/secure-xgboost.git
    ```

5. Before building, you may choose to configure the [build parameters](https://mc2-project.github.io/secure-xgboost/build.html#building-the-targets) in `CMakeLists.txt`, e.g., whether to perform training and inference obliviously. In particular, if running Secure XGBoost on a machine without enclave support, you'll have to set the `OE_DEBUG` parameter to `1` and the `SIMULATE` parameter to `ON`. 

6. Build Secure XGBoost and install the Python package.

    ```sh
    cd secure-xgboost
    mkdir build

    cd build
    cmake ..
    make -j4

    cd ../python-package
    sudo python3 setup.py install
    ```

## Docker build for local development
You can use the provided [Docker image](https://hub.docker.com/repository/docker/mc2project/ubuntu-oe0.9) if you want to run everything in simulation mode locally. 

1. Clone Secure XGBoost.

    ```sh
    git clone https://github.com/mc2-project/secure-xgboost.git
    ``` 

2. Pull the Docker image.
    ```sh
    docker pull mc2project/ubuntu-oe0.9:v1
    ```

3. Run the Docker image with the cloned directory mounted to the container's `/root/secure-xgboost/` directory [using the `-v` flag](https://stackoverflow.com/questions/23439126/how-to-mount-a-host-directory-in-a-docker-container) when starting the container.

    ```sh
    docker run -it -v <path/to/secure-xgboost>:/root/secure-xgboost mc2project/ubuntu-oe0.9:v1 /bin/bash
    ```

4. Install Open Enclave within the image.
    ```sh
    sudo apt update
    sudo apt -y install open-enclave
    ```

5. Before building, you may choose to configure the [build parameters](https://mc2-project.github.io/secure-xgboost/build.html#building-the-targets) in `CMakeLists.txt`, e.g., whether to perform training and inference obliviously. In particular, if running Secure XGBoost on a machine without enclave support, you'll have to set the `OE_DEBUG` parameter to `1` and the `SIMULATE` parameter to `ON`. 

6. Build Secure XGBoost and install the Python package.

    ```sh
    cd secure-xgboost
    mkdir build

    cd build
    cmake ..
    make -j4

    cd ../python-package
    sudo python3 setup.py install
    ```


## Usage
To use Secure XGBoost, replace the XGBoost import.

```python
# import xgboost as xgb
import securexgboost as xgb
```

For ease of use, the Secure XGBoost API mirrors that of XGBoost as much as possible. While the below block demonstrates usage on a single machine, Secure XGBoost is meant for the client-server model of computation. More information can be found [here](https://mc2-project.github.io/secure-xgboost/about.html#system-architecture).

**Note**: If running Secure XGBoost in simulation mode, pass in `verify=False` to the `attest()` function.

```python
# Generate a key and use it to encrypt data
KEY_FILE = "key.txt"
xgb.generate_client_key(KEY_FILE)
xgb.encrypt_file("demo/data/agaricus.txt.train", "demo/data/train.enc", KEY_FILE)
xgb.encrypt_file("demo/data/agaricus.txt.test", "demo/data/test.enc", KEY_FILE)

# Initialize client and connect to enclave
xgb.init_client(user_name="user1",
				sym_key_file="key.txt",
				priv_key_file="config/user1.pem",
				cert_file="config/user1.crt")
xgb.init_server(enclave_image="build/enclave/xgboost_enclave.signed", client_list=["user1"])

# Remote attestation to authenticate enclave
# If running in simulation mode, pass in `verify=False` below
xgb.attest(verify=True)

# Load the encrypted data and associate it with your user
dtrain = xgb.DMatrix({"user1": "/path/to/secure-xgboost/demo/data/train.enc"})
dtest = xgb.DMatrix({"user1": "/path/to/secure-xgboost/demo/data/test.enc"})

params = {
	"objective": "binary:logistic",
	"gamma": "0.1",
	"max_depth": "3"
}

# Train a model 
num_rounds = 5
booster = xgb.train(params, dtrain, num_rounds)

# Get encrypted predictions and decrypt them
predictions, num_preds = booster.predict(dtest)
```

## Documentation
For more background on enclaves and data-obliviousness, additional tutorials, and more details on build parameters and usage, please refer to the [documentation](https://mc2-project.github.io/secure-xgboost/).

## Additional Resources
* [CCS PPMLP Paper](https://arxiv.org/pdf/2010.02524.pdf)
* [Blog Post](https://towardsdatascience.com/secure-collaborative-xgboost-on-encrypted-data-ac7bc0ec7741)
* RISE Camp 2020 [Tutorial](https://github.com/mc2-project/risecamp/tree/risecamp2020) and [Walkthrough](https://youtu.be/-kK-YCjqABs?t=312)

## Getting Involved
* mc2-dev@googlegroups.com: For questions and general discussion
* [Slack](https://join.slack.com/t/mc2-project/shared_invite/zt-rt3kxyy8-GS4KA0A351Ysv~GKwy8NEQ): A more informal setting for discussion
* [GitHub Issues](https://github.com/mc2-project/secure-xgboost/issues): For bug reports and feature requests.
* [Pull Requests](https://github.com/mc2-project/secure-xgboost/pulls): For code contributions.
