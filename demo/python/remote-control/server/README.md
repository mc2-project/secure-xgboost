## Server Setup Instructions

In this example we'll need to start an RPC process on the server to listen for client calls. The RPC server listens for client calls to perform remote attestation, to accept the keys used to encrypt the data that will be used to train a model, and to start the XGBoost job.

### 1. Set PYTHONPATH
Set the `$PYTHONPATH` environment variable to the `secure-xgboost/rpc` directory. You can also add in this your bashrc.

`export PYTHONPATH=/path/to/secure-xgboost/rpc/`

### 2. Start RPC server

On the server with the enclave, start the RPC server to begin listening for client requests.

```
python3 server/enclave_serve.py
```
The code run by the server once the client makes the final call is in the `xgb_load_train_predict()` function in `server/remote_attestation_server.py`. In this example, data is decrypted and loaded into a `DMatrix`, a model is trained, and predictions are made. Note that in the `xgb_load_train_predict()` function, you need to specify from which location to load your data in in the `DMatrix` constructor. Choose a path, edit the path in the constructor, and remember it, as you will need this path as part of the client setup.

Once the console outputs "Waiting for remote attestation...", proceed to the [client](../client) setup.
