# Secure XGBoost

[![Build Status](https://travis-ci.org/mc2-project/secure-xgboost.svg?branch=master)](https://travis-ci.org/mc2-project/secure-xgboost)
[![Documentation Status](https://readthedocs.org/projects/secure-xgboost/badge/?version=latest)](https://secure-xgboost.readthedocs.io/en/latest/?badge=latest)
![Contributions welcome](https://img.shields.io/badge/contributions-welcome-orange.svg)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Overview
Secure XGBoost is a library that enables **collaborative training and inference of [XGBoost](https://github.com/dmlc/xgboost) models on encrypted data**. by leveraging hardware enclaves and data-oblivious algorithms. 

In a nutshell, data owners can use Secure XGBoost to train a model on a remote server _without_ revealing the underlying data to the remote server. Furthermore, multiple data owners can use the library to _collaboratively_ train a model on their collective data, without exposing their individual data to each other.
![Alt Text](doc/images/workflow.gif)

This project is currently under development as part of the broader [**MC<sup>2</sup>** effort](https://github.com/mc2-project/mc2) (i.e., **M**ultiparty **C**ollaboration and **C**oopetition) by the UC Berkeley [RISE Lab](https://rise.cs.berkeley.edu/).

**NOTE:** The Secure XGBoost library is a research prototype, and has not yet received independent code review. Please feel free to reach out to us if you would like to use Secure XGBoost for your applications. We also welcome contributions to the project.

## Table of Contents
[Installation](#installation)
[Usage](#usage)
[Documentation](#documentation)
[Contact](#contact)

## Installation
1. Install the Open Enclave SDK (0.8 or higher) and the Intel SGX DCAP driver by following [these instructions](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md). Then configure the required environment variables.

	```sh
	source /opt/openenclave/share/openenclave/openenclaverc
	```

2. Install CMake and other Secure XGBoost dependencies.

	```sh
	wget https://github.com/Kitware/CMake/releases/download/v3.15.6/cmake-3.15.6-Linux-x86_64.sh
	sudo bash cmake-3.15.6-Linux-x86_64.sh --skip-license --prefix=/usr/local

	sudo apt-get install -y libmbedtls-dev python3-pip
	pip3 install numpy pandas sklearn numproto grpcio grpcio-tools   
	```

3. Clone Secure XGBoost.

	```sh
	git clone https://github.com/mc2-project/secure-xgboost.git
	```

4. Before building, you may choose to configure the [build parameters](https://secure-xgboost.readthedocs.io/en/latest/build.html#building-the-targets) in `CMakeLists.txt`, e.g., whether to perform training and inference obliviously. In particular, if running Secure XGBoost on a machine without enclave support, you'll have to set the `SIMULATE` parameter to `ON`. 

5. Build Secure XGBoost and install the Python package.

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
For ease of use, the Secure XGBoost API mirrors that of XGBoost as much as possible.

```python
# Replace the XGBoost import with securexgboost
# import xgboost as xgb
import securexgboost as xgb

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
xgb.init_server(enclave_image="build/enclave/xgboost_enclave.signed")

# Remote attestation to authenticate enclave
xgb.attest()

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

## Contact
If you would like to know more about our project or have questions, please contact us at:
* Rishabh Poddar (rishabhp@eecs.berkeley.edu)
* Chester Leung (chester@eecs.berkeley.edu)
* Wenting Zheng (wzheng@eecs.berkeley.edu)
