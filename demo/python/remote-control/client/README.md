# Client Setup Instructions
We'll be setting up the client so that it's ready to remotely initiate a job on its own data. **Before doing this setup, ensure that you've already setup the [server](../server)**
This setup will involve encrypting data on the client, transferring the data to the server, then initiating the XGBoost code. The code run by the server once the client makes the final call is in the `xgb_load_train_predict()` function in `server/remote_attestation_server.py`. In this example, data is decrypted and loaded into a `DMatrix` and a model is trained.

`cd` into the `client` directory to begin setup.

### 1. Set PYTHONPATH
Set the `$PYTHONPATH` environment variable to the `secure-xgboost/rpc` directory. You can also add in this your bashrc.

`export PYTHONPATH=/path/to/secure-xgboost/rpc/`

### 2. Encrypt data locally.

Use the `encrypt.py` script to generate a key and encrypt the sample data. It will output three files: `key.txt`, `train.enc`, and `test.enc`. 

```
python3 encrypt.py
```

### 3. Send encrypted data to the server

We assume that there will be a mechanism to transfer the encrypted data to the server. For the purposes of this demo, the user can try, for example, `scp` to simulate this transfer. Note that you will have to `scp` the files to the location you specified in the `DMatrix` constructor in the server setup.

### 4. Make client calls

On the client, make the aforementioned calls to the server. 
The `remote_attestation_client.py` script takes in 3 arguments: the IP address of the server, the path to the generated key, and the path to the keypair. We've included a sample keypair for this example.

```
python3 remote_attestation_client.py --ip-addr 13.80.151.7 --key key.txt --keypair keypair.pem
```


