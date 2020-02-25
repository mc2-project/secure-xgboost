##########################
Distributed Secure XGBoost
##########################

Secure XGBoost is horizontally scalable -- if you want to train on more data, you can simply add more machines to the enclave cluster. Of course, the presence of an enclave cluster means that training will happen in a distributed manner. XGBoost itself already supports distributed training, and this project has adopted the native distributed training/inference logic and made it more secure.

In the distributed setting, the nodes in the cluster are logically arranged in either a tree or ring structure, depending on the size of the data. In Secure XGBoost, remote attestation must be performed on each enclave to authenticate it and verify that it's running the proper code. Here, each enclave attests all of its neighboring enclaves. Thus, in the :doc: `outsourced computation model </outsourced>`, the client just has to attest the cluster master, and all other attestation will happen within the cluster.

Additionally, all communication within the cluster is encrypted and happening over TLS.
