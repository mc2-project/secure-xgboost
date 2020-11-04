# Secure XGBoost

[![Build Status](https://travis-ci.org/mc2-project/secure-xgboost.svg?branch=master)](https://travis-ci.org/mc2-project/secure-xgboost)
[![Documentation Status](https://readthedocs.org/projects/secure-xgboost/badge/?version=latest)](https://secure-xgboost.readthedocs.io/en/latest/?badge=latest)
![Contributions welcome](https://img.shields.io/badge/contributions-welcome-orange.svg)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Secure XGBoost is a library that leverages secure enclaves and data-oblivious algorithms to enable the **collaborative training of and inference using [XGBoost](https://github.com/dmlc/xgboost) models on encrypted data**. 

Data owners can use Secure XGBoost to train a model on a remote server, e.g., the cloud, _without_ revealing the underlying data to the remote server. Collaborating data owners can use the library to jointly train a model on their collective data without exposing their individual data to each other.
![Alt Text](doc/images/workflow.gif)

This project is currently under development as part of the broader [**MC<sup>2</sup>** effort](https://github.com/mc2-project/mc2) (i.e., **M**ultiparty **C**ollaboration and **C**oopetition) by the UC Berkeley [RISE Lab](https://rise.cs.berkeley.edu/).

**NOTE:** The Secure XGBoost library is a research prototype, and has not yet received independent code review. 

## Table of Contents
* [Background](#background)
* [Installation](#installation)
* [Usage](#usage)
* [Documentation](#documentation)
* [Getting Involved](#getting-involved)

## Background
### Secure Enclaves
Secure enclaves are a recent advance in computer processor technology that enables the creation of a secure region of memory (called an enclave) on an otherwise untrusted machine. Any data or software placed within the enclave is isolated from the rest of the system. No other process on the same processor – not even privileged software such as the OS or the hypervisor – can access that memory. Examples of secure enclave technology include Intel SGX, ARM TrustZone, and AMD Memory Encryption.

Moreover, enclaves typically support a feature called remote attestation. This feature enables clients to cryptographically verify that an enclave in the cloud is running trusted, unmodified code.

Secure XGBoost builds upon the Open Enclave SDK – an open source SDK that provides a single unified abstraction across different enclave technologies. The use of Open Enclave enables our library to be compatible with many different enclave backends, such as Intel SGX and OP-TEE.

### Data-Oblivious Algorithms
On top of enclaves, Secure XGBoost adds a second layer of security that additionally protects the data and computation against a large class of attacks on enclaves.

Researchers have shown that attackers may be able to learn sensitive information about the data within SGX enclaves by leveraging auxiliary sources of leakage (or “side-channels”), even though they can’t directly observe the data. Memory access patterns are an example of such a side-channel.

In Secure XGBoost, we design and implement data-oblivious algorithms for model training and inference. At a high level, our algorithms produce an identical sequence of memory accesses, regardless of the input data. As a result, the memory access patterns reveal no information about the underlying data to the attacker.

Unfortunately, the extra security comes at the cost of performance. If such attacks fall outside the users’ threat model, they can disable this extra protection.

## Installation
1. Install the Open Enclave SDK (0.12.0) and the Intel SGX DCAP driver by following [these instructions](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md). In Step 3 of the instructions, install Open Enclave version 0.12.0 by specifying the version:

    ```sh
    sudo apt -y install clang-7 libssl-dev gdb libsgx-enclave-common libsgx-enclave-common-dev libprotobuf10 libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client open-enclave=0.12.0
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
    pip3 install numpy pandas sklearn numproto grpcio grpcio-tools   
    ```

4. Clone Secure XGBoost.

    ```sh
    git clone https://github.com/mc2-project/secure-xgboost.git
    ```

5. Before building, you may choose to configure the [build parameters](https://secure-xgboost.readthedocs.io/en/latest/build.html#building-the-targets) in `CMakeLists.txt`, e.g., whether to perform training and inference obliviously. In particular, if running Secure XGBoost on a machine without enclave support, you'll have to set the `SIMULATE` parameter to `ON`. 

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

For ease of use, the Secure XGBoost API mirrors that of XGBoost as much as possible. While the below block demonstrates usage on a single machine, Secure XGBoost is meant for the client-server model of computation. More information can be found [here](https://secure-xgboost.readthedocs.io/en/latest/about.html#system-architecture).

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
dtrain = xgb.DMatrix({"user1": "demo/data/train.enc"})
dtest = xgb.DMatrix({"user1": "demo/data/test.enc"})

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
For additional tutorials and more details on build parameters and usage, please refer to the [documentation](https://secure-xgboost.readthedocs.io/en/latest/).

## Getting Involved
* mc2-dev@googlegroups.com: For questions and general discussion
* [GitHub Issues](https://github.com/mc2-project/secure-xgboost/issues): For bug reports and feature requests.
* [Pull Requests](https://github.com/mc2-project/secure-xgboost/pulls): For code contributions.
