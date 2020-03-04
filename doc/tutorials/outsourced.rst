######################
Outsourced Computation
######################

Secure XGBoost is tailored toward an outsourced computation model -- one in which a client with sensitive data wants to outsource computation on the sensitive data to an untrusted server with a trusted hardware enclave. This tutorial provides an example of such a scenario. 

In this example, the client will encrypt data and send it to the untrusted server. The data remains encrypted until it is loaded inside the enclave, at which point it can be decrypted. The server will then train a model on the training data *inside the enclave* and serve predictions, *also inside the enclave*. The predictions will then be encrypted, pushed out of the enclave, and sent over the network back to the client. The client can then decrypt the predictions.

The enclave server will start an RPC server to listen for client requests. The client will make three requests to the server: 

1. A request for remote attestation

   The response will contain an attestation report that the client can use to authenticate the enclave and verify that it's running the proper code, and a public key whose corresponding private key is known by the enclave.
   
2. A request to transfer the symmetric key used to encrypt all client data

   Before transferring the key, the client will first encrypt the symmetric key with the enclave's public key, sign the ciphertext with its own public key, and then send both the ciphertext of the symmetric key and the signature to the server.
   
3. A request to start the XGBoost job

   This assumes that the client will have told the server what code to run -- the code to run in this example can be found in the ``xgb_load_train_predict()`` function in ``server/remote_attestation_server.py``. If the code includes inference, the response will contain predictions encrypted with the symmetric key used to encrypt the client data. The client can then decrypt these predictions locally. 

The relevant code is located at ``demo/python/remote-control``.

************
Server Setup
************

First setup a machine that will act as the untrusted server. This tutorial will work regardless of whether there's an enclave available, as OpenEnclave supports a simulation mode. However, if your server machine doesn't have an enclave available, you'll need to enable simulation mode by going into ``demo/python/remote-control/server/enclave_serve.py``, uncommenting the line to create an enclave in simulation mode, and commenting out the line to run in hardware mode. 

We'll need to start an RPC process on the server to listen for client calls. 

1. **Set $PYTHONPATH**

   Set the ``$PYTHONPATH`` environment variable to the ``mc2-xgboost/rpc`` directory. You can also add this to your bashrc.

   .. code-block:: bash

      export PYTHONPATH=/path/to/mc2-xgboost/rpc/


2. **Start RPC server**

   On the server, create the enclave and the RPC server to begin listening for client requests.

   .. code-block:: bash

      python3 demo/python/remote-control/server/enclave_serve.py


   The code run by the server once the client makes the final call is in the ``xgb_load_train_predict()`` function in ``demo/python/remote-control/server/remote_attestation_server.py``. Note that in the ``xgb_load_train_predict()`` function, you need to specify from which location to load your data in in the DMatrix constructor. Choose a path, edit the path in the constructor, and remember it, as you will need this path as part of the client setup.

   Once the console outputs "Waiting for remote attestation...", proceed to client setup.

************
Client Setup
************

We'll be setting up the client so that it's ready to remotely initiate a job on its own data. **Before doing this setup, ensure that you've already setup the server.**

This setup will involve encrypting data on the client, transferring the data to the server, then initiating the XGBoost code. 

``cd`` into the ``demo/python/remote-control/client`` directory to begin setup.

1. **Set $PYTHONPATH**

   Set the ``$PYTHONPATH`` environment variable to the ``mc2-xgboost/rpc`` directory. You can also add in this your bashrc.

   .. code-block:: bash

      export PYTHONPATH=/path/to/mc2-xgboost/rpc/


2. **Encrypt data locally.**

   Use the ``encrypt.py`` script to generate a key and encrypt the sample data (``demo/data/agaricus.txt.train`` and ``demo/data/agaricus.txt.test``). It will output three files: 

      * ``key.txt`` : the key used to encrypt the data

      * ``train.enc`` : an encrypted version of the training data

      * ``test.enc``  : an encrypted version of the test data

   Run the following to encrypt.

   .. code-block:: bash

      python3 encrypt.py


3. **Send encrypted data to the server**

   We assume that there will be a mechanism to transfer the encrypted data to the server. For the purposes of this demo, the user can try, for example, ``scp`` to simulate this transfer. Note that you will have to ``scp`` the files to the location you specified in the ``DMatrix`` constructor in the server setup.


4. **Make client calls**

   On the client, make the aforementioned calls to the server. The ``remote_attestation_client.py`` script takes in 3 arguments: the IP address of the server, the path to the generated key, and the path to the keypair. We've included a sample keypair for this example.

   .. code-block:: bash

      python3 remote_attestation_client.py --ip-addr <server-ip> --key key.txt --keypair keypair.pem

