
You will need at least two machines: one for the enclave server (on which the model will be trained and executed), and another for the client (i.e., the data owner).

To start, follow the installation instructions below and set up both machines identically. For simplicity, the instructions currently assume that both machines support SGX. (We plan to do away with this requirement in the future.)

# Installation

## Install the Open Enclave SDK (version 0.7) on Ubuntu 18.04
Follow the instructions [here](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md).
You may also acquire a VM with the required features from [Azure Confidential Compute](https://azure.microsoft.com/en-us/solutions/confidential-compute/); in this case, however, you may need to manually upgrade the SDK installed in the VM to version 0.7:
```
sudo apt -y install open-enclave
```

Configure environment variables for Open Enclave SDK for Linux:
```
source /opt/openenclave/share/openenclave/openenclaverc
```

## Install secure XGBoost dependencies
```
sudo apt-get install -y libmbedtls-dev python3-pip
pip3 install numpy pandas sklearn numproto grpcio grpcio-tools kubernetes
```
Install ```cmake >= v3.11```. E.g., the following commands install ```cmake v3.15.6```.
```
wget https://github.com/Kitware/CMake/releases/download/v3.15.6/cmake-3.15.6-Linux-x86_64.sh
sudo bash cmake-3.15.6-Linux-x86_64.sh --skip-license --prefix=/usr/local
```

## Download and build secure XGBoost
```
git clone -b sgx-dev --recursive https://github.com/mc2-project/secure-xgboost.git
cd secure-xgboost
mkdir -p build 

pushd build
cmake ..
make -j4
popd

mkdir enclave/build
pushd enclave/build
cmake ..
make -j4
popd

pushd python-package
sudo python3 setup.py install
popd
```

## Sanity Check
This sanity check ensures that setup was done properly. There is a script, `enclave-api-demo.py`, that loads data, trains a model, and serves predictions at `demo/enclave/`. The example uses encrypted versions of the `agaricus.txt.train` and `agaricus.txt.test` data files from `demo/data/`. The encrypted data was generated using `demo/c-api/encrypt.cc`, with a key of all zeros.

Note that you may have to change the paths to the built enclave or to the data files in the script. You can run the script with the following:
```
python3 demo/enclave/enclave-api-demo.py
```
After running the script, you should see something similar to the following printed to the console:
```
Model Predictions:
[18523750] DEBUG: /home/xgb/secure-xgboost/enclave/ecalls.cpp:52: Ecall: XGBoosterPredict
[0.02386593 0.9543875  0.02386593 0.02386593 0.04897502 0.10559791
 0.9543875  0.02876541 0.9543875  0.02423424 0.9543875  0.02876541
 0.02340852 0.02386593 0.02340852 0.02920706 0.02876541 0.9543875
 0.04897502 0.02876541]


True Labels:
[18523750] DEBUG: /home/xgb/secure-xgboost/enclave/ecalls.cpp:59: Ecall: XGDMatrixGetFloatInfo
[0. 1. 0. 0. 0. 0. 1. 0. 1. 0. 1. 0. 0. 0. 0. 0. 0. 1. 0. 0.]
[18523750] DEBUG: /home/xgb/secure-xgboost/enclave/ecalls.cpp:65: Ecall: XGDMatrixFree
[18523750] DEBUG: /home/xgb/secure-xgboost/enclave/ecalls.cpp:65: Ecall: XGDMatrixFree
[18523750] DEBUG: /home/xgb/secure-xgboost/enclave/ecalls.cpp:70: Ecall: XGBoosterFree
[18523750] ======== Enclave Monitor: Learner ========
[18523750] EvalOneIter: 0.002s, 10 calls @ 200us
[18523750] GetGradient: 0.014s, 10 calls @ 1400us
[18523750] PredictRaw: 0.009s, 10 calls @ 900us
[18523750] UpdateOneIter: 0.174s, 10 calls @ 17400us
[18523750] ======== Enclave Monitor: GBTree ========
[18523750] BoostNewTrees: 0.112s, 10 calls @ 11200us
[18523750] CommitModel: 0.039s, 10 calls @ 3900us
[18523750] ======== Enclave Monitor: Quantile::Builder ========
[18523750] ApplySplit: 0.008s, 59 calls @ 135us
[18523750] BuildHist: 0.015s, 69 calls @ 217us
[18523750] BuildLocalHistograms: 0.018s, 40 calls @ 450us
[18523750] BuildNodeStats: 0.005s, 40 calls @ 125us
[18523750] EvaluateSplit: 0.006s, 128 calls @ 46us
[18523750] InitData: 0s, 10 calls @ 0us
[18523750] InitNewNode: 0.004s, 128 calls @ 31us
[18523750] SubtractionTrick: 0.002s, 59 calls @ 33us
[18523750] SyncHistograms: 0.002s, 40 calls @ 50us
[18523750] Update: 0.04s, 10 calls @ 4000us
[18523750] ======== Enclave Monitor:  ========
```

# Quickstart
We provide an example that mirrors a potential real life situation. This is for users who want to remotely start a XGBoost job, i.e. there's a distinction between the server (the machine running training) and the client (a machine to which the user has direct access, but on which no computation is actually happening).


## Example 1
This is an example of a scenario in which a party outsources all computation to a server with an enclave. This scenario can be extended to one in which *multiple* parties outsource all computation to the same central enclave, meaning that they collaborate by sending their data to the same location, at which a XGBoost model is trained over all parties' data.

In this example, the enclave server will start an RPC server to listen for client requests. The client will make three requests to the server: a request for remote attestation, a request to transfer the key used to the training data, and finally a request to start the XGBoost job.

This assumes that the client will have told the server what code to run -- the code to run in this example can be found in the `xgb_load_train_predict()` function in `remote_attestation_server.py`. 

First, perform [server setup](server/).
Next, perform [client setup](client/).

After server and client setup, the client should have initiated training on the server. 


# API
For XGBoost functionality (and additional functionality) we currently support, please look at our API [here](API.md)
