##########################
Distributed Secure XGBoost
##########################

Secure XGBoost is horizontally scalable -- if you want to train on more data, you can simply add more machines to the enclave cluster. Of course, the presence of an enclave cluster means that training will happen in a distributed manner. XGBoost itself already supports distributed training, and this project has adopted the native distributed training/inference logic and made it more secure.

In the distributed setting, nodes logically communicate with each other in either a tree or ring structure (depending on the data size), with one node designated as the master. For security purposes in the :doc: `outsourced computation model </outsourced>`, the client should authenticate each enclave and verify that it's running the proper code by attesting each enclave in the cluster. However, to simplify the process for the client, Secure XGBoost leverages inter-enclave attestation -- when the cluster is initialized, each enclave attests its neighbors. Therefore, instead of having to attest each enclave separately, the client only needs to attest the master. 

Additionally, all communication within the cluster is encrypted and happens over TLS. Each communication channel begins and ends inside an enclave, so data communicated between enclaves are never exposed to an untrusted host. 
