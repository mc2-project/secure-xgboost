##########################
Distributed Secure XGBoost
##########################

Secure XGBoost is horizontally scalable -- if you want to train on more data, you can simply add more machines to the enclave cluster. Of course, the presence of an enclave cluster means that training will happen in a distributed manner. XGBoost itself already supports distributed training, and this project has adopted the native distributed training/inference logic and made it more secure.

All communication within the cluster is encrypted and happens over TLS. Each communication channel begins and ends inside an enclave, so data communicated between enclaves is never exposed to an untrusted host. 

This tutorial demonstrates how to run Distributed Secure XGBoost but is for development or testing purposes. Please refer to :ref:`multiclient-distributed-label` for a tutorial decoupling the client and enclave cluster. The tutorial code is located at ``demo/python/distributed/``.

1. Modify ``demo/python/distributed/hosts.config`` to contain the IP addresses of the nodes in your cluster. For example, if the nodes in your cluster have IP addresses of ``13.95.157.223`` and ``40.68.135.193``, your ``hosts.config`` should look like the following.

   .. code-block:: none
      
      13.95.157.223:22
      40.68.135.193:22

2. Ensure that ``distr-training.py`` is identical and at the same path on every machine in the cluster. 

3. Start computation. This will start the tracker and subsequently the job.

   .. code-block:: bash

      secure-xgboost/host/dmlc-core/tracker/dmlc-submit --cluster ssh --host-file hosts.config --num-workers <num_nodes_in_cluster> --worker-memory 4g python3 distr-training.py


   The command takes in the following arguments:

         * ``--cluster`` : how the cluster is set up. In Secure XGBoost we leverage SSH for intra-cluster communication. 

         * ``--host-file`` : the path to the file containing the IP addresses / ports of all nodes in the cluster. 

         * ``--num-workers``  : the number of nodes in the cluster

         * ``--worker-memory`` : the amount of memory to allocate to the job on each machine.


   Ensure that each node in the cluster has authorized the SSH public key of the machine running the tracker, as the tracker in Distributed Secure XGBoost leverages SSH public keys to set up the topology.

   Note that this tutorial can also be run locally by simulating the cluster on one machine. To do this, type in the following command.

   .. code-block:: bash

      secure-xgboost/host/dmlc-core/tracker/dmlc-submit --cluster local --num-workers <num_nodes_in_cluster> --worker-memory 1g python3 distr-training.py

