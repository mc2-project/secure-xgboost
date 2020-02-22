# API
Our implementation currently supports some XGBoost core data structure ([DMatrix](https://xgboost.readthedocs.io/en/latest/python/python_api.html#xgboost.DMatrix) and [Booster](https://xgboost.readthedocs.io/en/latest/python/python_api.html#xgboost.Booster)) methods.

We also support some additional enclave and cryptography specific functions. We've added the `Enclave` and `CryptoUtils` classes to the existing XGBoost library.

Below we list the functions we currently support. Please follow the respective links for each class for details about each function.

## Enclave
**Enclave(path_to_enclave, flags, create_enclave=True)**

> Constructor for enclave

> Params:
> * path_to_enclave: string
>> * path to built enclave
> * flags: int
>> * This is a bitwise OR of two OpenEnclaves-specific flags, `OE_ENCLAVE_FLAG_DEBUG = 1` and `OE_ENCLAVE_FLAG_SIMULATE = 2`. If you want to run in debug mode with actual hardware, pass `OE_ENCLAVE_FLAG_DEBUG` in. If you want to run non-debug simulation mode, pass `OE_ENCLAVE_FLAG_SIMULATE`. If you want to run in debug simulation mode, pass `OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SIMULATE`.
> * create_enclave: boolean
>> * whether you want to start an enclave. For example, if you just want to perform remote attestation as a client, there's no need to start an enclave on your client machine, but you will need to instantiate an enclave object to call the remote attestation methods.

**Enclave.get_remote_report_with_pubkey()** 

> Retrieve the attestation report from the enclave

> *Note: This function should be called by the client (but run on the server) to perform remote attestation.*

**Enclave.verify_remote_report_and_set_pubkey()** 

> Using the retrieved attestation report, verify that the enclave can be trusted.

> *Note: this function should be run on the client after calling `get_remote_report_with_pubkey()`.* 


## CryptoUtils
You can find example usage of the CryptoUtils class in `rpc/remote_attestation_client.py` and `rpc/remote_attestation_server.py`. For now, the CryptoUtils class is only necessary if you're adopting the client/server model of computation.

### Client Functions
The below functions would normally be run on the client.

**encrypt_data_with_pk(data, data_len, key, key_size)**

> Encrypt data to be transferred to server

**sign_data(keypair, data, data_size)**

> Sign data to be transferred to server

### Server Functions
The below functions would normally be run on the server.

**add_client_key(data_filename, key, key_size, signature, signature_length)**

> Store the key used to encrypt a specific data file and check that the key was sent by the client

## DMatrix
[**DMatrix(data)**](https://xgboost.readthedocs.io/en/latest/python/python_api.html#xgboost.DMatrix)
* Constructor for DMatrix class

[**DMatrix.get_float_info()**](https://xgboost.readthedocs.io/en/latest/python/python_api.html#xgboost.DMatrix.get_float_info)

[**DMatrix.get_label()**](https://xgboost.readthedocs.io/en/latest/python/python_api.html#xgboost.DMatrix.get_label)

## Booster
[**Booster()**](https://xgboost.readthedocs.io/en/latest/python/python_api.html#xgboost.Booster)
* Constructor for Booster class

[**Booster.set_param()**](https://xgboost.readthedocs.io/en/latest/python/python_api.html#xgboost.Booster.set_param)

[**Booster.update()**](https://xgboost.readthedocs.io/en/latest/python/python_api.html#xgboost.Booster.update)

[**Booster.eval_set()**](https://xgboost.readthedocs.io/en/latest/python/python_api.html#xgboost.Booster.eval_set)

[**Booster.predict()**](https://xgboost.readthedocs.io/en/latest/python/python_api.html#xgboost.Booster.predict)

We are continuing to add support for more functions. If you'd like any specific functions, please file an issue. 
