##############################################
Multiclient Outsourced Distributed Computation
##############################################

Secure XGBoost is tailored toward an outsourced computation model -- one in which multiple clients with sensitive data want to outsource joint computation on their sensitive data to the untrusted cloud. This tutorial provides an example of such a scenario. 

In the multiclient setting, Secure XGBoost contains a mechanism for consensus. It requires that all parties agree to invoke a certain API before actually running that function. For example, if Party A wants to train a model on Party A and Party B's data, Secure XGBoost requires that both Party A and Party B submit a command to the enclave before proceeding to train the model. In a similar fashion, if Party A wants to load its data, Party B must also agree and allow Party A to do so.

In this example, there are five entities: two clients, who each own sensitive data; an RPC orchestrator; and two untrusted servers, each running an enclave, who communicate to perform distributed computation. Each party holds distinct data that they want to aggregate. The demo consists of the following steps: 

   1. The orchestrator starts an RPC server and creates an enclave at each node (each untrusted server) in the cluster. 

   2. The orchestrator starts an RPC server to listen for client requests.

   3. Each client encrypts its data and sends it to the untrusted servers. 

   4. Each client attests the enclaves to ensure that the proper code has been loaded inside every enclave.
         
   5. To ensure that all parties are ready to commence computation, the orchestrator waits for both parties to make the same request before proceeding. Once both parties have submitted a command, the orchestrator relays the command to the enclave cluster.

   6. Clients make requests to load data, train a model, and serve encrypted predictions.
         
   7. Each client decrypts its received predictions.

The relevant code is located at ``demo/python/multiclient-cluster-remote-control``.

*************
Cluster Setup
*************

First, set up machines that will act as the untrusted servers. We'll need to start an RPC process on each server to listen for client calls. 

1. On the orchestrator machine, modify ``demo/python/multiclient-cluster-remote-control/hosts.config`` to contain the IP addresses of the nodes in your cluster. For example, if the nodes in your cluster have IP addresses of ``13.95.157.223`` and ``40.68.135.193``, your ``hosts.config`` should look like the following.

   .. code-block:: none

      13.95.157.223:22
      40.68.135.193:22

2. For distributed computation, Secure XGBoost assumes that the orchestrator has SSH access to all nodes in the cluster. You can grant access by pasting the orchestrator's SSH public key (likely found at ``~/.ssh/id_rsa.pub``) into each node's ``~/.ssh/authorized_keys`` file. If the orchestrator machine does not yet have a SSH keypair, create it:

   .. code-block:: bash

      ssh-keygen -t rsa -b 4096


3. Start the RPC servers on all machines. 

      .. code-block:: bash

         mc2-xgboost/host/dmlc-core/tracker/dmlc-submit --cluster ssh --host-file hosts.config --num-workers <num_workers_in_cluster> --worker-memory 4g python3 server/enclave_serve.py


******************
Orchestrator Setup
******************

Next set up the RPC orchestrator.

1. Modify the ``nodes`` argument in the ``xgb.serve()`` function in the ``demo/python/remote-control/start_orchestrator.py`` script to reflect the IP address of the nodes in the cluster. The ``port`` argument tells the RPC orchestrator which port to listen for client commands on. Note that ``start_orchestrator.py`` contains code that will automatically parse ``hosts.config`` for the node IPs, so you may not have to do this step.

   .. code-block:: bash

      xgb.serve(all_users=["user1", "user2"], nodes=["<SERVER_IP_1>", "<SERVER_IP_2"], port=50052)

2. Run the script to start the orchestrator.

   .. code-block:: bash

      python3 demo/python/multiclient-cluster-remote-control/orchestrator/start_orchestrator.py

**************
Client 1 Setup
**************

**Before doing this setup, ensure that you've already setup the server.**

This setup will involve encrypting data on client 1, transferring the data to the server, and telling the orchestrator that client 1 is ready. 

``cd`` into the ``demo/python/multiclient-cluster-remote-control/client1`` directory to begin setup.

1. **Encrypt data locally.**

   Use the ``encrypt.py`` script to generate a key and encrypt sample data (``demo/data/1_2agaricus.txt.train`` and ``demo/data/agaricus.txt.test``). It will output three files: 

   * ``demo/python/multiclient-cluster-remote-control/client1/key1.txt`` : the key used to encrypt the data

   * ``demo/python/multiclient-cluster-remote-control/data/c1_train.enc`` : an encrypted version of client 1's training data

   * ``demo/python/multiclient-cluster-remote-control/data/c1_test.enc``  : an encrypted version of client 1's test data

   Run the following to encrypt.

   .. code-block:: bash

      python3 encrypt.py


2. **Send encrypted data to the server**

   We assume that there will be a mechanism to transfer the encrypted data to the server. For the purposes of this demo, the user can try, for example, ``scp`` to simulate this transfer. 


3. **Make client calls**

   On the client, send commands to the orchestrator by running ``client1.py``. The ``client1.py`` script takes in 5 arguments: the IP address of the orchestrator, the path to the generated key, the path to the user's private key, the path to the user's certificate, and the port on which the orchestartor is running. We've included a sample private key and certificate for this example.

   .. code-block:: bash

      python3 client1.py --ip-addr <orchestrator-ip> --symmkey key1.txt --privkey ../../../data/userkeys/private_user_1.pem --cert ../../../data/usercrts/user1.crt --port 50052

   ``client.py`` takes in 5 arguments:

      * ``--ip-addr`` : IP address of the orchestrator
      * ``--symmkey`` : path to the client's symmetric key
      * ``--privkey`` : path to the client's private key
      * ``--cert`` : path to the client's certificate
      * ``--port`` : port on which the orchestrator is listening

For convenience, we added a script ``run.sh`` in this directory that runs this command. It takes in one argument: the orchestrator IP. 

**Note that the server will not load data, train a model, or serve predictions just yet -- the consensus mechanism forces the orchestrator to wait for client 2 to submit commands before relaying commands to the cluster.**


**************
Client 2 Setup
**************

This setup will involve encrypting data on client 2, transferring the data to the server, and telling the orchestrator that client 2 is ready. 

``cd`` into the ``demo/python/multiclient-cluster-remote-control/client2`` directory to begin setup.

1. **Encrypt data locally.**

   Use the ``encrypt.py`` script to generate a key and encrypt sample data (``demo/data/2_2agaricus.txt.train`` and ``demo/data/agaricus.txt.test``). It will output three files: 

   * ``demo/python/multiclient-cluster-remote-control/client2/key2.txt`` : the key used to encrypt the data

   * ``demo/python/multiclient-cluster-remote-control/data/c2_train.enc`` : an encrypted version of client 2's training data

   * ``demo/python/multiclient-cluster-remote-control/data/c2_test.enc``  : an encrypted version of client 2's test data

   Run the following to encrypt.

   .. code-block:: bash

      python3 encrypt.py


2. **Send encrypted data to the server**

   We assume that there will be a mechanism to transfer the encrypted data to the server. For the purposes of this demo, the user can try, for example, ``scp`` to simulate this transfer. 


3. **Make client calls**

   On client 2, send commands to the server by running ``client2.py``. Like ``client1.py``, ``client2.py`` takes in 5 arguments: the IP address of the server, the path to the generated key, the path to the user's private key, the path to the user's certificate, and the port on which the orchestrator is running. We've included a sample private key and certificate for this example.

   .. code-block:: bash

   python3 client2.py --ip-addr <server-ip> --symmkey key2.txt --privkey ../../../data/userkeys/private_user_2.pem --cert ../../../data/usercrts/user2.crt --port 50052

For convenience, we added a script ``run.sh`` in this directory that runs this command. It takes in one argument: the orchestrator IP. 


Once you have submitted commands from client 2, the orchestrator will relay commands to the cluster. The enclave cluster will load the two parties' data, train a model over both parties' data, and serve encrypted predictions back to each party. 


***************
Troubleshooting
***************
1. **Permission denied**

   This may be symptomatic of an SSH authentication error. Be sure that the SSH public key of the machine running the tracker is in the ``~/.ssh/authorized_hosts`` file of each node in the cluster.

   2. **Hung connection**

   If the tracker is hung after logging a statement similar to ``start listen on ...``, the tracker may be hung listening for an initial signal from a node in the cluster. Ensure that ports 9000-9100 are open on each machine.


