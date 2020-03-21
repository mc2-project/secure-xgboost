#####################
Secure XGBoost Documentation
#####################

**Secure XGBoost** is a secure library based off the popular `XGBoost <https://github.com/dmlc/xgboost>`_ project that supports scalable, distributed, and efficient `gradient boosting <https://en.wikipedia.org/wiki/Gradient_boosting>`_. In addition to offering the efficiency, flexibility, and portability that vanilla XGBoost does to solve a variety of problems, Secure XGBoost enables secure collaborative learning by leveraging `hardware enclaves <https://inst.eecs.berkeley.edu/~cs261/fa18/slides/Hardware_Enclaves.pdf>`_ and `oblivious algorithms <https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_ohrimenko.pdf>`_. This project allows multiple parties to each share their sensitive data to perform joint computation *without revealing the contents of the data*.

For example, one can imagine a group of banks that want to jointly train an anti-money laundering machine learning model. This would require each bank to share its customer data. However, legal policies and privacy concerns prevent banks from sharing customer data in plaintext -- they should not reveal, for example, the amount in a customer's savings account or a customer's recent transactions to another bank. Therefore, banks must jointly compute on all their sensitive data without explicitly sharing the data itself. This scenario can be generalized to a wide number of other industries in which parties may not want to share data because of data privacy laws or business competition: hospitals developing a disease diagnosis model, telecom companies predicting link failures, etc. 

With Secure XGBoost, a party or mutually distrustful federation can outsource computation on sensitive data to an untrusted cloud service without concern for information leakage. Secure XGBoost takes the encrypted sensitive data that is transferred to the untrusted cloud and loads it into a secure enclave, where it is then decrypted and computed upon. Assuming trust in the hardware vendor, enclaves provide a trusted execution environment even in the presence of a malicious host that has compromised nearly the entire software stack, including the operating system, the hypervisor, and other processes on the same machine. Since sensitive data sent over the network is encrypted and not seen in plaintext until it's inside a trusted enclave, the data of any party is not seen by any other entity. Furthermore, all computation happens inside an enclave, so all intermediate calculations that could otherwise leak some attributes of the data are also hidden.

Unfortunately, enclaves have been shown to be vulnerable to side channel attacks. Prior work has shown that significant information can be inferred just from side channels [`1 <https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/MSR-TR-2015-70.pdf>`_, `2 <https://www.ieee-security.org/TC/SP2015/papers-archived/6949a640.pdf>`_]. As a result, Secure XGBoost provides the option of oblivious training and inference, leveraging algorithms that execute independently of input data and therefore do not leak access patterns. Oblivious algorithms protect against many side channel attacks, adding another layer of security to the system. 

This project is currently under development as part of the broader `Multiparty Collaboration and Coopetition effort <https://github.com/mc2-project/mc2>`_ by the UC Berkeley `RISE Lab <https://rise.cs.berkeley.edu/>`_. 

Secure XGBoost is open source, and we welcome contributions to our work `here <https://github.com/mc2-project/mc2-xgboost>`_.

********
Contents
********

.. toctree::
  :maxdepth: 2
  :titlesonly:

  build
  get_started
  tutorials/index
  parameter
  Python package <python/index>
