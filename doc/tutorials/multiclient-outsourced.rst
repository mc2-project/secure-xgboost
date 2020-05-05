##################################
Multiclient Outsourced Computation
##################################

Secure XGBoost is tailored toward an outsourced computation model -- one in which multiple clients with sensitive data want to outsource joint computation on their sensitive data to an untrusted server with a trusted hardware enclave. This tutorial provides an example of such a scenario. 

In the multiclient setting, Secure XGBoost contains a mechanism for consensus. It requires that all parties agree to run a certain command before actually performing that command. For example, if Party A wants to train a model on Party A and Party B's data, Secure XGBoost requires that both Party A and Party B submit a command to the enclave before proceeding to train the model. In a similar fashion, if Party A wants to load its data, Party B must also agree and allow Party A to do so.

In this example, there are three parties: two clients, who each own sensitive data; and an untrusted server running an enclave. Each party holds distinct data that they want to aggregate. The demo consists of the following steps: 

   1. The enclave server first starts an RPC server to listen for client requests. 

   2. Each client encrypts its data and sends it to the untrusted server along with its respective symmetric key used to encrypt the data. 
         
   3. To ensure that all parties are ready to commence computation, the enclave waits for both parties to make requests before proceeding. The enclave then loads the sensitive data, decrypts it, and trains a model on both clients' data. 
         
   4. The enclave serves predictions for each client's test data, encrypts the predictions, and sends them back to each client.

   5. Each client decrypts its received predictions.

The relevant code is located at ``demo/python/multiclient-remote-control``.

************
Server Setup
************

First setup a machine that will act as the untrusted server. 

We'll need to start an RPC process on the server to listen for client calls. 


1. **Start RPC server**

   On the server, create the enclave and the RPC server to begin listening for client requests.

   .. code-block:: bash

      python3 demo/python/multiclient-remote-control/server/enclave_serve.py


   Once the console outputs "Waiting for client...", proceed to client setup.

**************
Client 1 Setup
**************

**Before doing this setup, ensure that you've already setup the server.**

This setup will involve encrypting data on client 1, transferring the data to the server, and telling the server that client 1 is ready. 

``cd`` into the ``demo/python/multiclient-remote-control/client1`` directory to begin setup.

1. **Encrypt data locally.**

   Use the ``encrypt.py`` script to generate a key and encrypt sample data (``demo/data/1_2agaricus.txt.train`` and ``demo/data/agaricus.txt.test``). It will output three files: 

      * ``demo/python/multiclient-remote-control/client1/key1.txt`` : the key used to encrypt the data

      * ``demo/python/multiclient-remote-control/data/c1_train.enc`` : an encrypted version of client 1's training data

      * ``demo/python/multiclient-remote-control/data/c1_test.enc``  : an encrypted version of client 1's test data

   Run the following to encrypt.

   .. code-block:: bash

      python3 encrypt.py


2. **Send encrypted data to the server**

   We assume that there will be a mechanism to transfer the encrypted data to the server. For the purposes of this demo, the user can try, for example, ``scp`` to simulate this transfer. 

   If simulating a client/server setup locally, think of the ``demo/python/multiclient-remote-control/data/`` directory as external storage mounted to both the client and server machines. 


3. **Make client calls**

   On the client, send commands to the server by running ``client1.py``. The ``client1.py`` script takes in 4 arguments: the IP address of the server, the path to the generated key, the path to the user's private key, and the path to the user's certificate. We've included a sample private key and certificate for this example.

   .. code-block:: bash

      python3 client1.py --ip-addr <server-ip> --symmkey key1.txt --privkey ../../../data/userkeys/private_user_1.pem --cert ../../../data/usercrts/user1.crt

   For convenience, we added a script ``run.sh`` in this directory that runs this command. It takes in one argument: the server IP. 

   **Note that the server will not load data, train a model, or serve predictions just yet -- the consensus mechanism forces the enclave to wait for client 2 to submit commands before doing anything.**



**************
Client 2 Setup
**************

This setup will involve encrypting data on client 2, transferring the data to the server, and telling the server that client 2 is ready. 

``cd`` into the ``demo/python/multiclient-remote-control/client2`` directory to begin setup.

1. **Encrypt data locally.**

   Use the ``encrypt.py`` script to generate a key and encrypt sample data (``demo/data/2_2agaricus.txt.train`` and ``demo/data/agaricus.txt.test``). It will output three files: 

      * ``demo/python/multiclient-remote-control/client2/key2.txt`` : the key used to encrypt the data

      * ``demo/python/multiclient-remote-control/data/c2_train.enc`` : an encrypted version of client 2's training data

      * ``demo/python/multiclient-remote-control/data/c2_test.enc``  : an encrypted version of client 2's test data

   Run the following to encrypt.

   .. code-block:: bash

      python3 encrypt.py


2. **Send encrypted data to the server**

   We assume that there will be a mechanism to transfer the encrypted data to the server. For the purposes of this demo, the user can try, for example, ``scp`` to simulate this transfer. 

   If simulating a client/server setup locally, think of the ``demo/python/multiclient-remote-control/data/`` directory as external storage mounted to both the client and server machines. 


3. **Make client calls**

   On client 2, send commands to the server by running ``client2.py``. The ``client2.py`` script takes in 4 arguments: the IP address of the server, the path to the generated key, the path to the user's private key, and the path to the user's certificate. We've included a sample private key and certificate for this example.

   .. code-block:: bash

      python3 client2.py --ip-addr <server-ip> --symmkey key2.txt --privkey ../../../data/userkeys/private_user_2.pem --cert ../../../data/usercrts/user2.crt

   For convenience, we added a script ``run.sh`` in this directory that runs this command. It takes in one argument: the server IP. 


Once you have submitted commands from client 2, the enclave will load each client's data, train a model, and send encrypted predictions back to each client.
