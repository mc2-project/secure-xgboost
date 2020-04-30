####################
About Secure XGBoost
####################

**Secure XGBoost** enables collaborative `gradient boosting <https://en.wikipedia.org/wiki/Gradient_boosting>`_ in the multiparty setting, leveraging `hardware enclaves <https://inst.eecs.berkeley.edu/~cs261/fa18/slides/Hardware_Enclaves.pdf>`_ and `data oblivious algorithms <https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_ohrimenko.pdf>`_ to securely perform this joint computation. In particular, multiple parties can collaborate to compute a joint model on their sensitive data without revealing the contents of the data. 

For example, one can imagine a group of banks that wants to jointly train an anti-money laundering machine learning model. This would require each bank to share its customer data. However, legal policies and privacy concerns prevent banks from sharing customer data in plaintext -- they should not revealto another bank, for example, the amount in a customer's savings account or a customer's recent transactions. Therefore, banks must jointly compute on all their sensitive data without explicitly sharing the data itself. This scenario can be generalized to a wide number of other industries in which parties may not want to share data because of data privacy laws or business competition: hospitals developing a disease diagnosis model, telecom companies predicting link failures, etc. 

.. image:: images/coopetition.png
   :scale: 80%
   :alt: Coopetition
   :align: center

With Secure XGBoost, a party or mutually distrustful federation can outsource computation on sensitive data to an untrusted cloud service without concern for information leakage. Secure XGBoost takes the encrypted sensitive data that is transferred to the untrusted cloud and loads it into a secure enclave, where it is then decrypted and computed upon. Enclaves provide a trusted execution environment that protects the confidentiality and integrity of all code and data loaded within the enclave, even in the presence of a malicious host that has compromised the entire software stack outside the enclave (i.e., the operating system, the hypervisor, or other processes on the same machine). Since sensitive data sent over the network is encrypted and not seen in plaintext until it's inside a trusted enclave, the data of any party is not seen by any other entity. 

.. image:: images/parties.png
   :scale: 40%
   :alt: Architecture 
   :align: center

Unfortunately, enclaves are vulnerable to side-channel attacks, and researchers have shown that attackers can infer a significant amount of information about the data within the enclave by simply observing the memory access patterns of the enclave program [`1 <https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/MSR-TR-2015-70.pdf>`_, `2 <https://www.ieee-security.org/TC/SP2015/papers-archived/6949a640.pdf>`_]. Attackers can observe these access patterns in a variety of ways, such as snooping on the memory bus, monitoring the page table, or via cache-timing attacks.

To address this problem, Secure XGBoost provides the option of "data-oblivious" training and inference -- it leverages specially-designed algorithms whose memory access patterns are independent of the input data, and hence, do not leak any information about the data within the enclave. Data-oblivious algorithms prevent all side-channel attacks induced by access-pattern leakage, and add another layer of security to the system.
