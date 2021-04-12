######################
Outsourced Computation
######################

Secure XGBoost is tailored toward an outsourced computation model -- one in which a client with sensitive data wants to outsource computation on the sensitive data to an untrusted server with a trusted hardware enclave. This tutorial provides an example of such a scenario. 

In this example, the enclave server first starts an RPC server to listen for the orchestrator, and the orchestrator starts an RPC server to listen for client requests. The client encrypts data and sends it to the untrusted server. The data remains encrypted until loaded inside the enclave, at which point it can be decrypted. The client sends commands (the APIs to invoke) to the orchestrator, which relays them to server. The server then trains a model on the training data *inside the enclave* and serves predictions, *also inside the enclave*. The predictions are then encrypted, pushed out of the enclave, and sent over the network back to the client. The client lastly decrypts the predictions.

The relevant code is located at ``demo/python/remote-control``.

************
Server Setup
************

First setup a machine that will act as the untrusted server. 

We'll need to start an RPC process on the server to listen for the orchestrator. 


1. **Start RPC server**

   On the server, create the enclave and the RPC server to begin listening. 

   .. code-block:: bash

      python3 demo/python/remote-control/server/enclave_serve.py


   Once the console outputs "Waiting for client...", proceed to orchestrator setup.


******************
Orchestrator Setup
******************

Next setup a machine that will act as the RPC orchestrator.

Modify the ``nodes`` argument in the ``xgb.serve()`` function in the ``demo/python/remote-control/start_orchestrator.py`` script to reflect the IP address of the server. The ``port`` argument tells the RPC orchestrator which port to listen for client commands on.

.. code-block:: bash

   xgb.serve(all_users=["user1"], nodes=["<SERVER_IP>"], port=50052)

Run the script to start the orchestrator.

.. code-block:: bash
   
   python3 demo/python/remote-control/start_orchestrator.py

************
Client Setup
************

We'll be setting up the client so that it's ready to remotely initiate a job on its own data. **Before doing this setup, ensure that you've already setup the server and the orchestrator.**

This setup will involve encrypting data on the client, transferring the data to the server, then initiating the XGBoost code. 

``cd`` into the ``demo/python/remote-control/client`` directory to begin setup.

1. **Encrypt data locally.**

   Use the ``encrypt.py`` script to generate a key and encrypt the sample data (``demo/data/agaricus.txt.train`` and ``demo/data/agaricus.txt.test``). It will output three files: 

   * ``demo/python/remote-control/client/key.txt`` : the key used to encrypt the data
   * ``demo/python/remote-control/data/train.enc`` : an encrypted version of the training data
   * ``demo/python/remote-control/data/test.enc``  : an encrypted version of the test data

   Run the following to encrypt.

   .. code-block:: bash

      python3 encrypt.py


2. **Send encrypted data to the server**

   We assume that there will be a mechanism to transfer the encrypted data to the server. For the purposes of this demo, the user can try, for example, ``scp`` to perform this transfer. 

   If simulating a client/server setup locally, think of the ``demo/python/remote-control/data/`` directory as external storage mounted to both the client and server machines. 


3. **Make client calls**

   On the client, send commands to the server by running ``client.py``. The ``client.py`` script takes in 4 arguments: the IP address of the server, the path to the generated key, the path to the user's private key, and the path to the user's certificate. We've included a sample private key and certificate for this example.

   .. code-block:: bash

      python3 client.py --ip-addr <orchestrator-ip> --symmkey key.txt --privkey ../../../data/userkeys/private_user_1.pem --cert ../../../data/usercrts/user1.crt --port 50052

   ``client.py`` takes in 5 arguments:

   * ``--ip-addr`` : IP address of the orchestrator
   * ``--symmkey`` : path to the client's symmetric key
   * ``--privkey`` : path to the client's private key
   * ``--cert`` : path to the client's certificate
   * ``--port`` : port on which the orchestrator is listening

   For convenience, we added a script ``run.sh`` in this directory that runs this command. It takes in one argument: the orchestrator IP. 

   .. code-block:: bash

      ./run.sh <orchestrator-ip>
