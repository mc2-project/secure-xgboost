
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
git clone --recursive https://github.com/mc2-project/mc2-xgboost.git
cd secure-xgboost
mkdir -p build 

pushd build
cmake ..
make -j4
popd

pushd python-package
sudo python3 setup.py install
popd
```

## Sanity Check
This sanity check ensures that setup was done properly. There is a script, `secure-xgboost-demo.py`, that loads data, trains a model, and serves predictions at `demo/python/basic/`. The example uses encrypted versions of the `agaricus.txt.train` and `agaricus.txt.test` data files from `demo/data/`. 

Note that you may have to change the paths to the built enclave or to the data files in the script. You can run the script with the following:
```
python3 demo/python/basic/secure-xgboost-demo.py
```
After running the script, you should see something similar to the following printed to the console:
```
Creating enclave
Loaded all modules
Remote attestation
Ecall: enclave_get_remote_report_with_pubkey
remote attestation succeeded.
verify_report_and_set_pubkey succeeded.
Creating training matrix
Creating test matrix
Beginning Training
Ecall: RabitIsDistributed
[0]	train-error:0.014433	test-error:0.016139
Ecall: RabitIsDistributed
[1]	train-error:0.014433	test-error:0.016139
Ecall: RabitIsDistributed
[2]	train-error:0.014433	test-error:0.016139
Ecall: RabitIsDistributed
[3]	train-error:0.008598	test-error:0.009932
Ecall: RabitIsDistributed
[4]	train-error:0.001228	test-error:0


Model Predictions:
[0.10455427 0.8036663  0.10455427 ... 0.89609396 0.10285233 0.89609396]
```

# Quickstart
We provide an example that mirrors a potential real life situation. This is for users who want to remotely start a XGBoost job, i.e. there's a distinction between the server (the machine running training) and the client (a machine to which the user has direct access, but on which no computation is actually happening).


## Example 1
This is an example of a scenario in which a party outsources all computation to a server with an enclave. This scenario can be extended to one in which *multiple* parties outsource all computation to the same central enclave, meaning that they collaborate by sending their data to the same location, at which a XGBoost model is trained over all parties' data.

In this example, the enclave server will start an RPC server to listen for client requests. The client will make three requests to the server: a request for remote attestation, a request to transfer the key used to the training data, and finally a request to start the XGBoost job.

This assumes that the client will have told the server what code to run -- the code to run in this example can be found in the `xgb_load_train_predict()` function in `remote_attestation_server.py`. 

First, perform [server setup](demo/python/remote-control/server/).
Next, perform [client setup](demo/python/remote-control/client/).

After server and client setup, the client should have initiated training on the server. 


# API
For XGBoost functionality (and additional functionality) we currently support, please look at our API [here](API.md)
